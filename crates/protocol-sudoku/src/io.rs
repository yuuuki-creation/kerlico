use kerlico_core::{BoxFuture, CancellationToken};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Waiters {
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// 缓冲层的read也会推进write；下层只能看到这一共享waker，不能覆盖真实写调用者。
#[derive(Default)]
pub(crate) struct DuplexWake {
    waiters: Mutex<Waiters>,
}
impl DuplexWake {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }
    pub fn reader(self: &Arc<Self>, caller: &Waker) -> Waker {
        let mut waiters = self.waiters.lock().unwrap();
        if waiters.reader.as_ref().is_none_or(|old|!old.will_wake(caller)) {
            waiters.reader = Some(caller.clone());
        }
        Waker::from(self.clone())
    }
    pub fn writer(self: &Arc<Self>, caller: &Waker) -> Waker {
        let mut waiters = self.waiters.lock().unwrap();
        if waiters.writer.as_ref().is_none_or(|old|!old.will_wake(caller)) {
            waiters.writer = Some(caller.clone());
        }
        Waker::from(self.clone())
    }
    pub fn wake_writer(&self) {
        let writer = self.waiters.lock().unwrap().writer.clone();
        if let Some(writer) = writer { writer.wake(); }
    }
    pub fn wake_reader(&self) {
        let reader = self.waiters.lock().unwrap().reader.clone();
        if let Some(reader) = reader { reader.wake(); }
    }
    pub fn wake_both(&self) {
        let (reader,writer) = {
            let waiters = self.waiters.lock().unwrap();
            (waiters.reader.clone(),waiters.writer.clone())
        };
        // 不持锁唤醒，允许调用者的waker同步转发至另一个缓冲层。
        if let Some(reader) = reader.as_ref() { reader.wake_by_ref(); }
        if let Some(writer) = writer
            && reader.as_ref().is_none_or(|reader|!reader.will_wake(&writer))
        {
            writer.wake();
        }
    }
}
impl Wake for DuplexWake {
    fn wake(self: Arc<Self>) { self.wake_both(); }
    fn wake_by_ref(self: &Arc<Self>) { self.wake_both(); }
}

pub(crate) struct CancelIo<T> {
    inner: T,
    reader: BoxFuture<'static, ()>,
    writer: BoxFuture<'static, ()>,
}
impl<T> CancelIo<T> {
    pub fn new(inner: T, cancel: &CancellationToken) -> Self {
        Self {
            inner,
            reader: Box::pin(cancel.clone().cancelled_owned()),
            writer: Box::pin(cancel.clone().cancelled_owned()),
        }
    }
}
fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "Sudoku会话已取消")
}
impl<T: AsyncRead + Unpin> AsyncRead for CancelIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.reader.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for CancelIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.writer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.writer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.writer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub(crate) struct CancelOnDrop(pub CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) struct Prefix {
    pub inner: kerlico_core::BoxStream,
    pub bytes: Vec<u8>,
    pub used: usize,
}
impl AsyncRead for Prefix {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.used < this.bytes.len() {
            let count = buffer.remaining().min(this.bytes.len() - this.used);
            buffer.put_slice(&this.bytes[this.used..this.used + count]);
            this.used += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Prefix {
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

#[derive(Clone)]
pub(crate) struct SharedIo(pub std::sync::Arc<std::sync::Mutex<kerlico_core::BoxStream>>);
impl SharedIo {
    pub fn new(inner: kerlico_core::BoxStream) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(inner)))
    }
}
impl AsyncRead for SharedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut stream = self.0.lock().unwrap();
        Pin::new(&mut *stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for SharedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut stream = self.0.lock().unwrap();
        Pin::new(&mut *stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stream = self.0.lock().unwrap();
        Pin::new(&mut *stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stream = self.0.lock().unwrap();
        Pin::new(&mut *stream).poll_shutdown(cx)
    }
}
