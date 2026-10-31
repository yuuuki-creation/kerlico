//! QUIC FIN 独立关闭写端；流名额与所属客户端状态随返回流回收。
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::OwnedSemaphorePermit,
};
struct Owner {
    state: Arc<crate::client::Connection>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.state.touch();
    }
}
pub(crate) struct QuicIo {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
    _owner: Option<Owner>,
}
impl QuicIo {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            _owner: None,
        }
    }
    pub fn with_owner(
        mut self,
        state: Arc<crate::client::Connection>,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        self._owner = Some(Owner {
            state,
            _permit: permit,
        });
        self
    }
}
impl AsyncRead for QuicIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, out)
    }
}
impl AsyncWrite for QuicIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}
