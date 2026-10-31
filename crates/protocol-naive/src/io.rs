//! 有界流桥；关闭写端保留读取，释放整个对象才取消双向任务。
use futures_util::task::AtomicWaker;
use kerlico_core::{BoxStream, CancellationToken};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
struct Completion {
    failure: Mutex<Option<io::ErrorKind>>,
    finished: AtomicBool,
    write_finished: AtomicBool,
    reader: AtomicWaker,
    writer: AtomicWaker,
    accepted: AtomicU64,
    transmitted: AtomicU64,
}
#[derive(Clone)]
pub(crate) struct ReadCompletion(Arc<Completion>);
impl ReadCompletion {
    pub fn finish_read(&self, result: &io::Result<()>) {
        if let Err(error) = result
            && let Ok(mut failure) = self.0.failure.lock()
        {
            *failure = Some(error.kind());
        }
        self.0.finished.store(true, Ordering::Release);
        self.0.reader.wake();
    }
    fn finish_write(&self, result: &io::Result<()>) {
        if let Err(error) = result
            && let Ok(mut failure) = self.0.failure.lock()
        {
            *failure = Some(error.kind());
        }
        self.0.write_finished.store(true, Ordering::Release);
        self.0.writer.wake();
    }
    pub fn advance_write(&self, count: usize) {
        self.0
            .transmitted
            .fetch_add(count as u64, Ordering::Release);
        self.0.writer.wake();
    }
    pub async fn writing(&self, future: impl Future<Output = io::Result<()>>) -> io::Result<()> {
        let result = future.await;
        self.finish_write(&result);
        result
    }
}
pub(crate) struct Managed {
    inner: DuplexStream,
    cancel: CancellationToken,
    completion: Arc<Completion>,
    _hold: Option<Box<dyn Send + Sync>>,
}
impl Drop for Managed {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Managed {
    fn error(&self) -> Option<io::Error> {
        if self.cancel.is_cancelled() {
            return Some(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Naive流已取消",
            ));
        }
        self.completion
            .failure
            .lock()
            .ok()?
            .as_ref()
            .map(|kind| io::Error::new(*kind, "Naive 载体流读取、写入或分帧失败"))
    }
}
impl AsyncRead for Managed {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.completion.reader.register(cx.waker());
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() == before && buffer.remaining() > 0 => {
                this.completion.reader.register(cx.waker());
                if !this.completion.finished.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
                Poll::Ready(this.error().map_or(Ok(()), Err))
            }
            result => result,
        }
    }
}
impl AsyncWrite for Managed {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.completion.writer.register(cx.waker());
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(count)) = &result {
            this.completion
                .accepted
                .fetch_add(*count as u64, Ordering::Release);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        this.completion.writer.register(cx.waker());
        if this.completion.transmitted.load(Ordering::Acquire)
            >= this.completion.accepted.load(Ordering::Acquire)
        {
            return Poll::Ready(Ok(()));
        }
        if this.completion.write_finished.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Naive流在排空前结束",
            )));
        }
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        this.completion.writer.register(cx.waker());
        if !this.completion.write_finished.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        Poll::Ready(this.error().map_or(Ok(()), Err))
    }
}
pub(crate) fn spawn<F, Fut>(
    parent: CancellationToken,
    hold: Option<Box<dyn Send + Sync>>,
    task: F,
) -> BoxStream
where
    F: FnOnce(DuplexStream, ReadCompletion) -> Fut + Send + 'static,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let (inner, peer) = tokio::io::duplex(crate::config::BUFFER);
    let cancel = parent.child_token();
    let completion = Arc::new(Completion {
        failure: Mutex::new(None),
        finished: AtomicBool::new(false),
        write_finished: AtomicBool::new(false),
        reader: AtomicWaker::new(),
        writer: AtomicWaker::new(),
        accepted: AtomicU64::new(0),
        transmitted: AtomicU64::new(0),
    });
    let worker_cancel = cancel.clone();
    let worker_completion = ReadCompletion(completion.clone());
    let read_completion = worker_completion.clone();
    tokio::spawn(async move {
        let result = tokio::select! { biased; _=worker_cancel.cancelled()=>Err(io::Error::new(io::ErrorKind::ConnectionAborted,"Naive流已取消")), result=task(peer,read_completion)=>result };
        worker_completion.finish_read(&result);
        worker_completion.finish_write(&result);
    });
    Box::new(Managed {
        inner,
        cancel,
        completion,
        _hold: hold,
    })
}
pub(crate) fn failed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Naive 载体或分帧不合法")
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn shutdown_waits_for_encoder_drain_and_preserves_reverse_read() {
        let drain = Arc::new(tokio::sync::Notify::new());
        let reverse = Arc::new(tokio::sync::Notify::new());
        let worker_drain = drain.clone();
        let worker_reverse = reverse.clone();
        let mut stream = spawn(
            CancellationToken::new(),
            None,
            move |peer, complete| async move {
                let (mut reader, mut writer) = tokio::io::split(peer);
                let incoming = async {
                    let result = async {
                        worker_reverse.notified().await;
                        writer.write_all(b"tail").await?;
                        writer.shutdown().await
                    }
                    .await;
                    complete.finish_read(&result);
                    result
                };
                let outgoing = complete.writing(async {
                    let mut bytes = Vec::new();
                    reader.read_to_end(&mut bytes).await?;
                    assert_eq!(bytes, b"queued");
                    worker_drain.notified().await;
                    complete.advance_write(bytes.len());
                    Ok(())
                });
                tokio::try_join!(incoming, outgoing)?;
                Ok(())
            },
        );
        stream.write_all(b"queued").await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), stream.shutdown())
                .await
                .is_err()
        );
        drain.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), stream.shutdown())
            .await
            .unwrap()
            .unwrap();
        reverse.notify_one();
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_to_end(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(bytes, b"tail");
    }
}
#[cfg(test)]
mod flush_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn flush_waits_until_encoder_accepts_all_prior_bytes() {
        let release = Arc::new(tokio::sync::Notify::new());
        let worker_release = release.clone();
        let mut stream = spawn(
            CancellationToken::new(),
            None,
            move |mut peer, progress| async move {
                let mut bytes = [0; 3];
                peer.read_exact(&mut bytes).await?;
                assert_eq!(&bytes, b"abc");
                worker_release.notified().await;
                progress.advance_write(3);
                std::future::pending::<io::Result<()>>().await
            },
        );
        stream.write_all(b"abc").await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), stream.flush())
                .await
                .is_err()
        );
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), stream.flush())
            .await
            .unwrap()
            .unwrap();
    }
}
#[cfg(test)]
mod cancel_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn pending_read_and_next_write_report_permanent_cancellation() {
        let cancel = CancellationToken::new();
        let mut stream = spawn(cancel.clone(), None, |peer, _| async move {
            let _peer = peer;
            std::future::pending::<io::Result<()>>().await
        });
        let trigger = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            cancel.cancel();
        });
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            stream.write_all(b"after cancel").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        trigger.await.unwrap();
    }
}
