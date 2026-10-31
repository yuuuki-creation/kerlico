use crate::wire;
use kerlico_core::{BoxStream, CancellationToken};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 部分官方节点合并响应与首个业务回包；写方向不等待响应，读方向先校验。
pub(crate) struct DeferredResponse {
    inner: BoxStream,
    cancel: CancellationToken,
    deadline: Pin<Box<tokio::time::Sleep>>,
    head: [u8; 4],
    head_used: usize,
    extensions: Option<Vec<u8>>,
    extensions_used: usize,
    ready: bool,
}
impl DeferredResponse {
    pub fn new(inner: BoxStream, cancel: CancellationToken, timeout: Duration) -> Self {
        Self {
            inner,
            cancel,
            deadline: Box::pin(tokio::time::sleep(timeout)),
            head: [0; 4],
            head_used: 0,
            extensions: None,
            extensions_used: 0,
            ready: false,
        }
    }
    fn fail(&self, kind: io::ErrorKind) -> Poll<io::Result<()>> {
        self.cancel.cancel();
        Poll::Ready(Err(io::Error::new(kind, "Relay 延迟响应未通过校验")))
    }
    fn write_budget(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if !self.ready && self.deadline.as_mut().poll(cx).is_ready() {
            self.cancel.cancel();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Relay 延迟响应超过建立预算",
            ));
        }
        Ok(())
    }
    fn handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.ready {
            return Poll::Ready(Ok(()));
        }
        if self.deadline.as_mut().poll(cx).is_ready() {
            return self.fail(io::ErrorKind::TimedOut);
        }
        while self.head_used < 4 {
            let mut buffer = ReadBuf::new(&mut self.head[self.head_used..]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buffer))?;
            let n = buffer.filled().len();
            if n == 0 {
                return self.fail(io::ErrorKind::UnexpectedEof);
            }
            self.head_used += n;
        }
        if self.head[0] != 1 {
            return self.fail(io::ErrorKind::InvalidData);
        }
        match self.head[1] {
            0 => {}
            2 | 3 => return self.fail(io::ErrorKind::PermissionDenied),
            4 => return self.fail(io::ErrorKind::TimedOut),
            5..=7 => return self.fail(io::ErrorKind::ConnectionRefused),
            _ => return self.fail(io::ErrorKind::InvalidData),
        }
        if self.extensions.is_none() {
            self.extensions = Some(vec![
                0;
                u16::from_be_bytes([self.head[2], self.head[3]])
                    as usize
            ]);
        }
        let extensions = self.extensions.as_mut().unwrap();
        while self.extensions_used < extensions.len() {
            let mut buffer = ReadBuf::new(&mut extensions[self.extensions_used..]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buffer))?;
            let n = buffer.filled().len();
            if n == 0 {
                return self.fail(io::ErrorKind::UnexpectedEof);
            }
            self.extensions_used += n;
        }
        if wire::features_valid(extensions).is_err() {
            return self.fail(io::ErrorKind::InvalidData);
        }
        self.extensions = None;
        self.ready = true;
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for DeferredResponse {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match ready!(this.handshake(cx)) {
            Ok(()) => Pin::new(&mut this.inner).poll_read(cx, buffer),
            Err(error) => {
                this.cancel.cancel();
                Poll::Ready(Err(error))
            }
        }
    }
}
impl AsyncWrite for DeferredResponse {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_budget(cx)?;
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_budget(cx)?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_budget(cx)?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
