//! TLS 接收按记录边界读取，Vision Direct 按方向切换到底层载体。
use kerlico_core::BoxStream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_transport::TransportStream;

pub(crate) struct RecordAligned {
    inner: BoxStream,
    header: [u8; 5],
    position: usize,
    remaining: usize,
}
impl RecordAligned {
    pub fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            header: [0; 5],
            position: 0,
            remaining: 0,
        }
    }
}
impl AsyncRead for RecordAligned {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.remaining == 0 {
            let mut bytes = [0; 5];
            let mut buffer = ReadBuf::new(&mut bytes[..(5 - this.position).min(out.remaining())]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let count = buffer.filled().len();
                    this.header[this.position..this.position + count]
                        .copy_from_slice(buffer.filled());
                    out.put_slice(buffer.filled());
                    this.position += count;
                    if this.position == 5 {
                        this.remaining =
                            u16::from_be_bytes([this.header[3], this.header[4]]) as usize;
                        this.position = 0;
                    }
                    Poll::Ready(Ok(()))
                }
            }
        } else {
            let max = this.remaining.min(out.remaining());
            let mut buffer = ReadBuf::new(out.initialize_unfilled_to(max));
            match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let count = buffer.filled().len();
                    this.remaining -= count;
                    out.advance(count);
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}
impl AsyncWrite for RecordAligned {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) struct ServerTls(pub tokio_rustls::server::TlsStream<RecordAligned>);
impl AsyncRead for ServerTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, out)
    }
}
impl AsyncWrite for ServerTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
impl TransportStream for ServerTls {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        use std::io::Read;
        match this.0.get_mut().1.reader().read(out.initialize_unfilled()) {
            Ok(count) if count > 0 => {
                out.advance(count);
                return Poll::Ready(Ok(()));
            }
            Err(error) if error.kind() != io::ErrorKind::WouldBlock => {
                return Poll::Ready(Err(error));
            }
            _ => {}
        }
        Pin::new(&mut this.0.get_mut().0.inner).poll_read(cx, out)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.0).poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        Pin::new(&mut this.0.get_mut().0.inner).poll_write(cx, bytes)
    }
    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0.get_mut().0.inner).poll_flush(cx)
    }
    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0.get_mut().0.inner).poll_shutdown(cx)
    }
}

pub(crate) struct Plain(pub BoxStream);
impl AsyncRead for Plain {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, out)
    }
}
impl AsyncWrite for Plain {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
impl TransportStream for Plain {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, out)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, bytes)
    }
}
