use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct Stream {
    pub send: quinn::SendStream,
    pub receive: quinn::RecvStream,
    pub prefix: Bytes,
    pub _owner: Arc<dyn Send + Sync>,
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let count = output.remaining().min(this.prefix.len());
            output.put_slice(&this.prefix[..count]);
            this.prefix.advance(count);
            return Poll::Ready(Ok(()));
        }
        AsyncRead::poll_read(Pin::new(&mut this.receive), cx, output)
            .map_err(|_| io::Error::other("Hysteria2 QUIC 读取失败"))
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, bytes)
            .map_err(|_| io::Error::other("Hysteria2 QUIC 写入失败"))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
            .map_err(|_| io::Error::other("Hysteria2 QUIC 刷新失败"))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
            .map_err(|_| io::Error::other("Hysteria2 QUIC 关闭失败"))
    }
}
