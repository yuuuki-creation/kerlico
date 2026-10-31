use kerlico_core::{BoxFuture, BoxStream, CancellationToken};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 每方向注册实际唤醒，不依赖额外的驻留驱动任务。
pub(crate) struct Cancellable {
    inner: BoxStream,
    read_cancel: BoxFuture<'static, ()>,
    write_cancel: BoxFuture<'static, ()>,
}

impl Cancellable {
    pub fn new(inner: BoxStream, cancel: &CancellationToken) -> Self {
        Self {
            inner,
            read_cancel: Box::pin(cancel.clone().cancelled_owned()),
            write_cancel: Box::pin(cancel.clone().cancelled_owned()),
        }
    }
}
fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "Relay 连接已取消")
}
impl AsyncRead for Cancellable {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(stopped()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for Cancellable {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(stopped()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(stopped()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(stopped()));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
