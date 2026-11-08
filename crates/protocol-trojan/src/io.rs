//! 载体活动监测，取消和空闲期限由协议生命周期持有。
use kerlico_core::{BoxStream, Error, Result};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};
pub(crate) struct Activity {
    inner: BoxStream,
    active: Arc<AtomicBool>,
}
pub(crate) fn observe(inner: BoxStream) -> (BoxStream, Arc<AtomicBool>) {
    let active = Arc::new(AtomicBool::new(false));
    (
        Box::new(Activity {
            inner,
            active: active.clone(),
        }),
        active,
    )
}
pub(crate) async fn bounded<T>(
    future: impl Future<Output = Result<T>>,
    active: Arc<AtomicBool>,
    idle: Duration,
    cancel: kerlico_core::CancellationToken,
) -> Result<T> {
    tokio::pin!(future);
    let timer = tokio::time::sleep(idle);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            result = &mut future => return result,
            _ = &mut timer => {
                if active.swap(false, Ordering::Relaxed) {
                    timer.as_mut().reset(Instant::now() + idle);
                } else {
                    return Err(Error::Timeout);
                }
            },
        }
    }
}
impl AsyncRead for Activity {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, out);
        if matches!(result, Poll::Ready(Ok(()))) && out.filled().len() > before {
            this.active.store(true, Ordering::Relaxed);
        }
        result
    }
}
impl AsyncWrite for Activity {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Ok(n)) if n>0) {
            this.active.store(true, Ordering::Relaxed);
        }
        result
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(result, Poll::Ready(Ok(n)) if n>0) {
            this.active.store(true, Ordering::Relaxed);
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) struct ServerTls(pub tokio_rustls::server::TlsStream<BoxStream>);
impl AsyncRead for ServerTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let poll = Pin::new(&mut this.0).poll_read(cx, out);
        if matches!(poll, Poll::Ready(Ok(()))) && out.filled().len() > before {
            while out.remaining() >= 16384 {
                let prev = out.filled().len();
                match Pin::new(&mut this.0).poll_read(cx, out) {
                    Poll::Ready(Ok(())) if out.filled().len() > prev => {}
                    _ => break,
                }
            }
        }
        poll
    }
}
impl AsyncWrite for ServerTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Pin::new(&mut this.0).poll_write(cx, bytes);
        }
        let limit = bytes.len().min(65536);
        let mut total = 0;
        while total < limit {
            match Pin::new(&mut this.0).poll_write(cx, &bytes[total..limit]) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(n)) => total += n,
                Poll::Ready(Err(_)) if total > 0 => return Poll::Ready(Ok(total)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending if total > 0 => return Poll::Ready(Ok(total)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(total))
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
