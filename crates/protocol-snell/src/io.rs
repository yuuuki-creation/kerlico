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
    activity: Arc<AtomicBool>,
}
pub(crate) fn observe(inner: BoxStream) -> (BoxStream, Arc<AtomicBool>) {
    let activity = Arc::new(AtomicBool::new(false));
    (
        Box::new(Activity {
            inner,
            activity: activity.clone(),
        }),
        activity,
    )
}
pub(crate) async fn bounded<T>(
    future: impl Future<Output = Result<T>>,
    activity: Arc<AtomicBool>,
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
                if activity.swap(false, Ordering::Relaxed) {
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
            this.activity.store(true, Ordering::Relaxed);
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
            this.activity.store(true, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
