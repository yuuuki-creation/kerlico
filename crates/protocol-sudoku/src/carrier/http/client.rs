use super::{
    codec::{self, Mode},
    transport::{HttpClient, small_body},
};
use crate::{carrier::Opened, handshake::EarlyClient, scope::Scope};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::{Bytes, BytesMut};
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
        let count = bytes.len().min(64 * 1024);
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
        Poll::Ready(Ok(()))
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
    let mut held = None;
    loop {
        let request = match held.take() {
            Some(request) => request,
            None => match requests.recv().await {
                Some(request) => request,
                None => break,
            },
        };
        match request {
            Upload::Data(bytes) => {
                // 上传一问一答，吞吐是单次请求量除以 RTT；上一个请求在途时排队的写入并进这一次。
                let mut batch = BytesMut::from(&bytes[..]);
                while let Ok(next) = requests.try_recv() {
                    match next {
                        Upload::Data(more) if batch.len() + more.len() <= mode.max_batch() => {
                            batch.extend_from_slice(&more);
                        }
                        other => {
                            held = Some(other);
                            break;
                        }
                    }
                }
                let encoded = if mode == Mode::Stream {
                    batch.freeze()
                } else {
                    Bytes::from(mode.encode(&batch))
                };
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
            Upload::Fin(ack) => {
                let mut attempts = 0;
                let result = loop {
                    let result = post(&client, mode, &token, Some("fin"), None, Bytes::new()).await;
                    let retry = match &result {
                        Ok(status) => status.is_server_error(),
                        Err(Error::Io(_) | Error::Timeout) => true,
                        Err(_) => false,
                    };
                    if !retry || attempts == 1 {
                        break result;
                    }
                    // FIN是同一token上的幂等控制；响应丢失只重确认，不重放业务数据。
                    attempts += 1;
                };
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
    let (reader, writer) = tokio::io::duplex(256 * 1024);
    let (sender, requests) = mpsc::channel(16);
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
    async fn lost_fin_response_is_reconfirmed_without_repeating_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut requests = Vec::new();
            for index in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                    assert!(header.len() <= 4096);
                }
                let header = String::from_utf8(header).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                requests.push((header.lines().next().unwrap().to_owned(), body));
                if index != 1 {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                }
                stream.shutdown().await.unwrap();
            }
            requests
        });
        let config = serde_json::from_value::<crate::config::OutOptions>(serde_json::json!({
            "server": {"host": "127.0.0.1", "port": address.port()},
            "protocol": {"key": "synthetic-fin-response-loss-seed"},
            "http_mask": {"mode": "stream"}
        }))
        .unwrap()
        .prepare()
        .unwrap();
        let owner = kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("fin-response-loss").unwrap(),
            CancellationToken::new(),
        );
        let scope = Scope::node(&owner.cancel(), owner);
        let client = HttpClient::new(
            &config,
            Arc::new(crate::carrier::endpoint::Endpoint::new(
                config.server.clone(),
            )),
            scope.clone(),
            false,
        );
        let (sender, receiver) = mpsc::channel(8);
        sender
            .send(Upload::Data(Bytes::from_static(b"payload-once")))
            .await
            .unwrap();
        let (ack, received) = oneshot::channel();
        sender.send(Upload::Fin(ack)).await.unwrap();
        let uploaded = tokio::time::timeout(
            Duration::from_secs(2),
            upload(
                client,
                Mode::Stream,
                "synthetic-token".into(),
                true,
                receiver,
            ),
        )
        .await
        .unwrap();
        let confirmed = received.await.unwrap();
        scope.shutdown().await;
        if uploaded.is_err() || confirmed.is_err() {
            peer.abort();
            let _ = peer.await;
            panic!("已提交FIN的响应丢失后应再次取得确认：upload={uploaded:?}, ack={confirmed:?}");
        }
        let requests = tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(requests[0].1, b"payload-once");
        assert!(requests[0].0.contains("seq=1"));
        assert!(
            requests[1..]
                .iter()
                .all(|(head, body)| head.contains("fin=1") && body.is_empty())
        );
    }

    /// 官方节点的下载响应声明 keep-alive，写完 EOF 尾部就关闭连接。这里把关闭推迟到下一个请求到达，
    /// 让复用这条连接的竞争必然发生：下一个请求收不到响应。
    async fn serve_like_official(mut stream: tokio::net::TcpStream, reused: Arc<AtomicBool>) {
        let mut served_pull = false;
        loop {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                match stream.read_u8().await {
                    Ok(byte) => header.push(byte),
                    Err(_) => return,
                }
            }
            if served_pull {
                reused.store(true, Ordering::SeqCst);
                return;
            }
            if String::from_utf8_lossy(&header).starts_with("GET ") {
                served_pull = true;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sudoku-Stream-EOF\r\nConnection: keep-alive\r\n\r\n0\r\nX-Sudoku-Stream-EOF: 1\r\n\r\n",
                    )
                    .await
                    .unwrap();
            } else {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                return;
            }
        }
    }

    #[tokio::test]
    async fn finished_pull_connection_is_not_reused_for_next_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let reused = Arc::new(AtomicBool::new(false));
        let observed = reused.clone();
        let peer = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(serve_like_official(stream, observed.clone()));
            }
        });
        let config = serde_json::from_value::<crate::config::OutOptions>(serde_json::json!({
            "server": {"host": "127.0.0.1", "port": address.port()},
            "protocol": {"key": "synthetic-pull-reuse-seed"},
            "http_mask": {"mode": "stream"}
        }))
        .unwrap()
        .prepare()
        .unwrap();
        let owner = kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("pull-reuse").unwrap(),
            CancellationToken::new(),
        );
        let scope = Scope::node(&owner.cancel(), owner);
        let client = HttpClient::new(
            &config,
            Arc::new(crate::carrier::endpoint::Endpoint::new(
                config.server.clone(),
            )),
            scope.clone(),
            true,
        );
        let (mut received, writer) = tokio::io::duplex(1024);
        let writer = DownloadWriter {
            inner: writer,
            failed: Arc::new(AtomicBool::new(false)),
            normal: false,
        };
        tokio::time::timeout(
            Duration::from_secs(2),
            download(
                client.clone(),
                Mode::Stream,
                "synthetic-token".into(),
                writer,
                None,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let mut downlink = Vec::new();
        received.read_to_end(&mut downlink).await.unwrap();
        assert!(downlink.is_empty());
        // hyper 在响应体读完后才把连接放回连接池；等它放回，复用才可能发生。
        tokio::time::sleep(Duration::from_millis(50)).await;
        let status = tokio::time::timeout(
            Duration::from_secs(2),
            post(
                &client,
                Mode::Stream,
                "other-token",
                Some("fin"),
                None,
                Bytes::new(),
            ),
        )
        .await
        .unwrap();
        scope.shutdown().await;
        peer.abort();
        assert!(!reused.load(Ordering::SeqCst), "下载结束的连接不应被复用");
        assert_eq!(status.unwrap(), StatusCode::OK);
    }

    #[tokio::test]
    async fn queued_writes_share_one_upload_request_up_to_the_batch_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                }
                let header = String::from_utf8(header).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let fin = header.lines().next().unwrap().contains("fin=1");
                requests.push((header.lines().next().unwrap().to_owned(), body));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
                if fin {
                    return requests;
                }
            }
        });
        let config = serde_json::from_value::<crate::config::OutOptions>(serde_json::json!({
            "server": {"host": "127.0.0.1", "port": address.port()},
            "protocol": {"key": "synthetic-upload-batch-seed"},
            "http_mask": {"mode": "stream"}
        }))
        .unwrap()
        .prepare()
        .unwrap();
        let owner = kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("upload-batch").unwrap(),
            CancellationToken::new(),
        );
        let scope = Scope::node(&owner.cancel(), owner);
        let client = HttpClient::new(
            &config,
            Arc::new(crate::carrier::endpoint::Endpoint::new(
                config.server.clone(),
            )),
            scope.clone(),
            false,
        );
        const WRITES: usize = 12;
        const SIZE: usize = 32 * 1024;
        let (sender, receiver) = mpsc::channel(WRITES + 1);
        let mut expected = Vec::new();
        for index in 0..WRITES {
            let bytes = vec![index as u8; SIZE];
            expected.extend_from_slice(&bytes);
            sender.send(Upload::Data(Bytes::from(bytes))).await.unwrap();
        }
        let (ack, _confirmed) = oneshot::channel();
        sender.send(Upload::Fin(ack)).await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            upload(
                client,
                Mode::Stream,
                "synthetic-token".into(),
                true,
                receiver,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let requests = tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        scope.shutdown().await;
        let (fin, uploads) = requests.split_last().unwrap();
        assert!(fin.0.contains("fin=1") && fin.1.is_empty());
        assert_eq!(
            uploads
                .iter()
                .map(|(_, body)| body.len())
                .collect::<Vec<_>>(),
            vec![Mode::Stream.max_batch(), 4 * SIZE],
            "排队的写入应合并，单次不超过批量上限"
        );
        assert!(uploads[0].0.contains("seq=1") && uploads[1].0.contains("seq=2"));
        let uploaded: Vec<u8> = uploads.iter().flat_map(|(_, body)| body.clone()).collect();
        assert_eq!(uploaded, expected);
    }

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
