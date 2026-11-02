use kerlico_core::BoxStream;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct Candidates(Arc<Mutex<State>>);
struct State {
    stream: BoxStream,
    bytes: Vec<u8>,
    written: usize,
    accepted: bool,
    waiters: Vec<Waker>,
}
pub(crate) struct Candidate {
    state: Arc<Mutex<State>>,
    read: usize,
    written: usize,
}
impl Candidates {
    pub fn new(stream: BoxStream) -> Self {
        Self(Arc::new(Mutex::new(State {
            stream,
            bytes: Vec::new(),
            written: 0,
            accepted: false,
            waiters: Vec::new(),
        })))
    }
    pub fn reader(&self) -> Candidate {
        Candidate {
            state: self.0.clone(),
            read: 0,
            written: 0,
        }
    }
    pub fn prefix(&self, size: usize) -> io::Result<Vec<u8>> {
        let state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("候选输入锁已失效"))?;
        state
            .bytes
            .get(..size)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
    pub fn accept(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.accepted = true;
            state.waiters.clear();
        }
    }
}
impl AsyncRead for Candidate {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = this
            .state
            .lock()
            .map_err(|_| io::Error::other("候选输入锁已失效"))?;
        if this.read < state.bytes.len() {
            let n = (state.bytes.len() - this.read).min(out.remaining());
            out.put_slice(&state.bytes[this.read..this.read + n]);
            this.read += n;
            return Poll::Ready(Ok(()));
        }
        if state.accepted {
            return Pin::new(&mut state.stream).poll_read(cx, out);
        }
        if state.bytes.len() >= 262144 {
            return Poll::Ready(Err(io::Error::other("认证首部超过限制")));
        }
        if !state.waiters.iter().any(|w| w.will_wake(cx.waker())) {
            state.waiters.push(cx.waker().clone());
        }
        let size = out.remaining().min(16384).min(262144 - state.bytes.len());
        let mut bytes = vec![0; size];
        let mut buffer = ReadBuf::new(&mut bytes);
        match Pin::new(&mut state.stream).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let bytes = buffer.filled();
                state.bytes.extend_from_slice(bytes);
                out.put_slice(bytes);
                this.read += bytes.len();
                for waiter in state.waiters.drain(..) {
                    waiter.wake();
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}
impl AsyncWrite for Candidate {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut state = this
            .state
            .lock()
            .map_err(|_| io::Error::other("候选输出锁已失效"))?;
        if this.written < state.written {
            let n = (state.written - this.written).min(bytes.len());
            this.written += n;
            return Poll::Ready(Ok(n));
        }
        match Pin::new(&mut state.stream).poll_write(cx, bytes) {
            Poll::Ready(Ok(n)) => {
                this.written += n;
                state.written += n;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("候选输出锁已失效"))?;
        Pin::new(&mut state.stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("候选输出锁已失效"))?;
        if !state.accepted {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut state.stream).poll_shutdown(cx)
    }
}
