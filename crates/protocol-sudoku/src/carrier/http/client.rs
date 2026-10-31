use super::{
    codec::{self, Mode},
    transport::{HttpClient, small_body},
};
use crate::{carrier::Opened, handshake::EarlyClient, scope::Scope};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::BodyExt;
use kerlico_core::{CancellationToken, Error, Result};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::PollSender;

enum Upload {
    Data(Bytes),
    Flush(oneshot::Sender<io::Result<()>>),
    Fin(oneshot::Sender<io::Result<()>>),
}
struct DownloadWriter {
    inner: DuplexStream,
    failed: Arc<AtomicBool>,
    normal: bool,
}
impl Drop for DownloadWriter {
    fn drop(&mut self) {
        if !self.normal {
            self.failed.store(true, Ordering::Release);
        }
    }
}
pub(crate) struct SplitIo {
    reader: DuplexStream,
    sender: PollSender<Upload>,
    cancel: CancellationToken,
    failed: Arc<AtomicBool>,
    ack: Option<oneshot::Receiver<io::Result<()>>>,
    write_closed: bool,
    write_failed: bool,
    read_closed: bool,
}
impl Drop for SplitIo {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "Sudoku HTTP会话已关闭")
}
impl SplitIo {
    fn acknowledged(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(ack) = self.ack.as_mut() {
            let result = ready!(Pin::new(ack).poll(cx));
            self.ack = None;
            let result = result.unwrap_or_else(|_| Err(broken()));
            if result.is_err() {
                self.write_failed = true;
            }
            return Poll::Ready(result);
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for SplitIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_closed || output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = output.filled().len();
        match ready!(Pin::new(&mut this.reader).poll_read(cx, output)) {
            Ok(()) => {
                if output.filled().len() == before {
                    if this.failed.load(Ordering::Acquire) {
                        return Poll::Ready(Err(broken()));
                    }
                    this.read_closed = true;
                }
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}
impl AsyncWrite for SplitIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed || this.write_failed || this.cancel.is_cancelled() {
            return Poll::Ready(Err(broken()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.acknowledged(cx))?;
        ready!(this.sender.poll_reserve(cx)).map_err(|_| broken())?;
        let count = bytes.len().min(32 * 1024);
        this.sender
            .send_item(Upload::Data(Bytes::copy_from_slice(&bytes[..count])))
            .map_err(|_| broken())?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_failed || this.cancel.is_cancelled() {
            return Poll::Ready(Err(broken()));
        }
        if this.ack.is_some() {
            return this.acknowledged(cx);
        }
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        ready!(this.sender.poll_reserve(cx)).map_err(|_| broken())?;
        let (ack, received) = oneshot::channel();
        this.sender
            .send_item(Upload::Flush(ack))
            .map_err(|_| broken())?;
        this.ack = Some(received);
        this.acknowledged(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_failed || this.cancel.is_cancelled() {
            return Poll::Ready(Err(broken()));
        }
        if this.write_closed {
            return this.acknowledged(cx);
        }
        ready!(this.acknowledged(cx))?;
        ready!(this.sender.poll_reserve(cx)).map_err(|_| broken())?;
        let (ack, received) = oneshot::channel();
        this.sender
            .send_item(Upload::Fin(ack))
            .map_err(|_| broken())?;
        this.write_closed = true;
        this.ack = Some(received);
        this.acknowledged(cx)
    }
}

async fn post(
    client: &HttpClient,
    mode: Mode,
    token: &str,
    control: Option<&str>,
    sequence: Option<u64>,
    body: Bytes,
) -> Result<StatusCode> {
    let mut query = format!("token={token}");
    if let Some(control) = control {
        query.push_str(&format!("&{control}=1"));
    }
    if let Some(sequence) = sequence {
        query.push_str(&format!("&seq={sequence}"));
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        let response = client
            .request(
                Method::POST,
                "/api/v1/upload",
                &query,
                mode.label(),
                body,
                Some(mode.content_type()),
            )
            .await?;
        small_body(response, 4096).await.map(|(status, _)| status)
    })
    .await
    .map_err(|_| Error::Timeout)?
}
async fn upload(
    client: Arc<HttpClient>,
    mode: Mode,
    token: String,
    sequences: bool,
    mut requests: mpsc::Receiver<Upload>,
) -> Result<()> {
    let mut sequence = 1u64;
    while let Some(request) = requests.recv().await {
        match request {
            Upload::Data(bytes) => {
                let encoded = Bytes::from(mode.encode(&bytes));
                let mut attempts = 0;
                loop {
                    let result = post(
                        &client,
                        mode,
                        &token,
                        None,
                        sequences.then_some(sequence),
                        encoded.clone(),
                    )
                    .await;
                    let retry = match result {
                        Ok(status) if status == StatusCode::OK => false,
                        Ok(status) if status.is_server_error() && sequences && attempts < 1 => true,
                        Ok(_) => return Err(Error::Rejected),
                        Err(Error::Io(_) | Error::Timeout) if sequences && attempts < 1 => true,
                        Err(error) => return Err(error),
                    };
                    if !retry {
                        break;
                    }
                    attempts += 1;
                }
                sequence = sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
            }
            Upload::Flush(ack) => {
                let _ = ack.send(Ok(()));
            }
            Upload::Fin(ack) => {
                let result = post(&client, mode, &token, Some("fin"), None, Bytes::new()).await;
                let success = matches!(result, Ok(StatusCode::OK));
                let _ = ack.send(if success { Ok(()) } else { Err(broken()) });
                if !success {
                    return Err(Error::Protocol("Sudoku HTTP上传EOF未确认"));
                }
                return Ok(());
            }
        }
    }
    Err(Error::Cancelled)
}

async fn deliver_line(line: &[u8], writer: &mut DuplexStream) -> Result<()> {
    if line.is_empty() {
        return Ok(());
    }
    let bytes = STANDARD
        .decode(line.strip_suffix(b"\r").unwrap_or(line))
        .map_err(|_| crate::invalid())?;
    writer.write_all(&bytes).await?;
    Ok(())
}
async fn download(
    client: Arc<HttpClient>,
    mode: Mode,
    token: String,
    mut writer: DownloadWriter,
    mut ready: Option<oneshot::Sender<Result<()>>>,
) -> Result<()> {
    loop {
        let mut response = client
            .request(
                Method::GET,
                "/stream",
                &format!("token={token}"),
                mode.label(),
                Bytes::new(),
                None,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(Error::Rejected);
        }
        if let Some(ready) = ready.take() {
            let _ = ready.send(Ok(()));
        }
        let mut eof = false;
        let mut read_any = false;
        let mut line = Vec::new();
        while let Some(frame) = response.body_mut().frame().await {
            let frame = frame.map_err(|_| Error::Io(io::Error::other("Sudoku HTTP下载中断")))?;
            if let Some(trailers) = frame.trailers_ref() {
                eof = trailers
                    .get("x-sudoku-stream-eof")
                    .is_some_and(|v| v.as_bytes() == b"1");
                continue;
            }
            if let Ok(data) = frame.into_data() {
                if !data.is_empty() {
                    read_any = true;
                }
                if mode == Mode::Stream {
                    writer.inner.write_all(&data).await?;
                } else {
                    for &byte in data.iter() {
                        if byte == b'\n' {
                            deliver_line(&line, &mut writer.inner).await?;
                            line.clear();
                        } else {
                            if line.len() >= 64 * 1024 {
                                return Err(Error::ResourceLimit);
                            }
                            line.push(byte);
                        }
                    }
                }
            }
        }
        if !line.is_empty() {
            deliver_line(&line, &mut writer.inner).await?;
        }
        if eof {
            writer.inner.shutdown().await?;
            writer.normal = true;
            return Ok(());
        }
        // 只在完整HTTP响应正常结束后续拉；部分响应失败不能重放下行。
        if !read_any {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

pub(crate) async fn connect(
    client: Arc<HttpClient>,
    scope: &Scope,
    mode: Mode,
    early: &EarlyClient,
    private_transport: bool,
) -> Result<Opened> {
    let query = format!("ed={}", URL_SAFE_NO_PAD.encode(&early.request));
    let (status, body) = small_body(
        client
            .request(
                Method::GET,
                "/session",
                &query,
                mode.label(),
                Bytes::new(),
                None,
            )
            .await?,
        4096,
    )
    .await?;
    if status != StatusCode::OK {
        return Err(Error::Rejected);
    }
    let authorization = codec::authorization(&body)?;
    let codec::Authorization {
        token,
        early: early_response,
        sequences,
    } = authorization;
    let (reader, writer) = tokio::io::duplex(64 * 1024);
    let (sender, requests) = mpsc::channel(8);
    let (ready, received) = oneshot::channel();
    let cancel = scope.cancel.child_token();
    let failed = Arc::new(AtomicBool::new(false));
    let monitored = cancel.clone();
    let writer = DownloadWriter {
        inner: writer,
        failed: failed.clone(),
        normal: false,
    };
    let parent = scope.cancel.clone();
    let upload_client = client.clone();
    let download_client = client.clone();
    let upload_token = token.clone();
    let download_token = token.clone();
    scope.spawn(async move {
        {
            let sending=upload(upload_client,mode,upload_token,sequences,requests);let receiving=download(download_client,mode,download_token,writer,Some(ready));tokio::pin!(sending);tokio::pin!(receiving);let mut up=false;let mut down=false;
            loop {
                tokio::select!{biased;_=monitored.cancelled()=>break,_=parent.cancelled()=>break,result=&mut sending,if !up=>{up=true;if result.is_err(){break;}},result=&mut receiving,if !down=>{down=true;if result.is_err(){break;}}}
                if up&&down{break;}
            }
        }
        // 取消逻辑流后仍在所属Scope内完成有界控制清理，不创建游离任务。
        if !parent.is_cancelled(){let _=tokio::time::timeout(Duration::from_millis(300),post(&client,mode,&token,Some("close"),None,Bytes::new())).await;}
        if private_transport{client.cancel.cancel();}
    });
    let stream = SplitIo {
        reader,
        sender: PollSender::new(sender),
        cancel: cancel.clone(),
        failed,
        ack: None,
        write_closed: false,
        write_failed: false,
        read_closed: false,
    };
    match received.await {
        Ok(Ok(())) => Ok(Opened {
            stream: Box::new(stream),
            early_response,
        }),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(Error::Protocol("Sudoku HTTP下载未就绪")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn rejected_fin_stays_failed_across_shutdown_and_flush() {
        for failure in [io::ErrorKind::ConnectionAborted, io::ErrorKind::TimedOut] {
            let (reader, mut writer) = tokio::io::duplex(16);
            let (sender, mut receiving) = mpsc::channel(8);
            let mut stream = SplitIo {
                reader,
                sender: PollSender::new(sender),
                cancel: CancellationToken::new(),
                failed: Arc::new(AtomicBool::new(false)),
                ack: None,
                write_closed: false,
                write_failed: false,
                read_closed: false,
            };
            let actor = tokio::spawn(async move {
                match receiving.recv().await {
                    Some(Upload::Fin(ack)) => {
                        let _ = ack.send(Err(io::Error::new(failure, "合成FIN确认失败")));
                    }
                    _ => panic!("预期FIN控制"),
                };
            });
            assert!(stream.shutdown().await.is_err());
            assert!(stream.shutdown().await.is_err());
            assert!(stream.flush().await.is_err());
            assert!(stream.write_all(b"after-fin").await.is_err());
            writer.write_all(b"known-tail").await.unwrap();
            writer.shutdown().await.unwrap();
            let mut tail = Vec::new();
            stream.read_to_end(&mut tail).await.unwrap();
            assert_eq!(&tail, b"known-tail");
            actor.await.unwrap();
        }
    }
}
