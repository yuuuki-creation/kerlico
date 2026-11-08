//! HTTP DATA 到字节流的有界适配；写入等待流控，shutdown 在最后一段之后发 FIN。
use bytes::{Buf, Bytes};
use kerlico_core::{BoxFuture, BoxStream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub type H3ClientSend = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub type H3ServerSend = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub type H3Server = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub enum Writer {
    H2(h2::SendStream<Bytes>),
    Client(H3ClientSend),
    Server(H3ServerSend),
}
pub enum Reader {
    H2(h2::RecvStream),
    Client(h3::client::RequestStream<h3_quinn::RecvStream, Bytes>),
    Server(h3::server::RequestStream<h3_quinn::RecvStream, Bytes>),
}
fn error() -> io::Error {
    io::Error::other("HTTP DATA流失败")
}
impl Writer {
    async fn data(&mut self, mut bytes: Bytes) -> io::Result<()> {
        match self {
            Self::H2(send) => {
                while !bytes.is_empty() {
                    send.reserve_capacity(bytes.len());
                    let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .ok_or_else(error)?
                        .map_err(|_| error())?;
                    if capacity == 0 {
                        continue;
                    }
                    let count = capacity.min(bytes.len());
                    send.send_data(bytes.split_to(count), false)
                        .map_err(|_| error())?;
                }
                Ok(())
            }
            Self::Client(send) => send.send_data(bytes).await.map_err(|_| error()),
            Self::Server(send) => send.send_data(bytes).await.map_err(|_| error()),
        }
    }
    async fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::H2(send) => send.send_data(Bytes::new(), true).map_err(|_| error()),
            Self::Client(send) => send.finish().await.map_err(|_| error()),
            Self::Server(send) => send.finish().await.map_err(|_| error()),
        }
    }
}
impl Reader {
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        match self {
            Self::H2(recv) => match ready!(recv.poll_data(cx)) {
                Some(Ok(bytes)) => {
                    recv.flow_control()
                        .release_capacity(bytes.len())
                        .map_err(|_| error())?;
                    Poll::Ready(Ok(Some(bytes)))
                }
                Some(Err(_)) => Poll::Ready(Err(error())),
                None => Poll::Ready(Ok(None)),
            },
            Self::Client(recv) => Poll::Ready(
                ready!(recv.poll_recv_data(cx))
                    .map(|v| {
                        v.map(|mut b| {
                            let n = b.remaining();
                            b.copy_to_bytes(n)
                        })
                    })
                    .map_err(|_| error()),
            ),
            Self::Server(recv) => Poll::Ready(
                ready!(recv.poll_recv_data(cx))
                    .map(|v| {
                        v.map(|mut b| {
                            let n = b.remaining();
                            b.copy_to_bytes(n)
                        })
                    })
                    .map_err(|_| error()),
            ),
        }
    }
}
type Pending = BoxFuture<'static, (Writer, io::Result<()>)>;
pub struct BodyIo {
    writer: Option<Writer>,
    reader: Reader,
    pending: Option<Pending>,
    buffer: Bytes,
    closing: bool,
    closed: bool,
}
impl BodyIo {
    pub fn boxed(writer: Writer, reader: Reader) -> BoxStream {
        Box::new(Self {
            writer: Some(writer),
            reader,
            pending: None,
            buffer: Bytes::new(),
            closing: false,
            closed: false,
        })
    }
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(future) = &mut self.pending {
            let (writer, result) = ready!(future.as_mut().poll(cx));
            self.pending = None;
            self.writer = Some(writer);
            result?;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for BodyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut read_any = false;
        while buf.remaining() > 0 {
            if !this.buffer.is_empty() {
                let count = buf.remaining().min(this.buffer.len());
                buf.put_slice(&this.buffer.split_to(count));
                read_any = true;
                continue;
            }
            match this.reader.poll_data(cx) {
                Poll::Ready(Ok(Some(bytes))) => this.buffer = bytes,
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => {
                    return if read_any {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(err))
                    };
                }
                Poll::Pending => {
                    return if read_any {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for BodyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.poll_pending(cx))?;
        if let Some(Writer::H2(send)) = &mut this.writer {
            let want = buf.len().min(262144);
            let cap = send.capacity();
            if cap < want {
                send.reserve_capacity(want - cap);
            }
            let capacity = match ready!(send.poll_capacity(cx)) {
                Some(Ok(cap)) => cap,
                Some(Err(_)) | None => return Poll::Ready(Err(error())),
            };
            if capacity == 0 {
                return Poll::Pending;
            }
            let count = capacity.min(want);
            let bytes = Bytes::copy_from_slice(&buf[..count]);
            send.send_data(bytes, false).map_err(|_| error())?;
            return Poll::Ready(Ok(count));
        }
        let count = buf.len().min(262144);
        let bytes = Bytes::copy_from_slice(&buf[..count]);
        let mut writer = this.writer.take().ok_or_else(error)?;
        // 此次写入先取得有界缓冲所有权；后续 write/flush/shutdown 都等待该段真正提交。
        this.pending = Some(Box::pin(async move {
            let result = writer.data(bytes).await;
            (writer, result)
        }));
        let _ = this.poll_pending(cx)?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_pending(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_pending(cx))?;
        if let Some(Writer::H2(send)) = &mut this.writer {
            send.send_data(Bytes::new(), true).map_err(|_| error())?;
            this.closing = true;
            this.closed = true;
            return Poll::Ready(Ok(()));
        }
        if !this.closing {
            this.closing = true;
            let mut writer = this.writer.take().ok_or_else(error)?;
            this.pending = Some(Box::pin(async move {
                let result = writer.finish().await;
                (writer, result)
            }));
        }
        ready!(this.poll_pending(cx))?;
        this.closed = true;
        Poll::Ready(Ok(()))
    }
}
