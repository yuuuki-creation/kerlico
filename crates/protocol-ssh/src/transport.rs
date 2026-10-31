use kerlico_core::{BoxFuture, CancellationToken};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

pub(crate) struct ConnectionGuard(pub CancellationToken);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) struct Transport {
    stream: TcpStream,
    read_cancel: BoxFuture<'static, ()>,
    write_cancel: BoxFuture<'static, ()>,
}
fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "SSH 连接已回收")
}
impl Transport {
    pub fn new(stream: TcpStream, cancel: &CancellationToken) -> Self {
        Self {
            stream,
            read_cancel: Box::pin(cancel.clone().cancelled_owned()),
            write_cancel: Box::pin(cancel.clone().cancelled_owned()),
        }
    }
}
impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut this.stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut this.stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
