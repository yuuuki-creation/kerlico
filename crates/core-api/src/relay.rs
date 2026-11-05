//! 带取消与空闲预算的双向流转发，保留半关闭后的反向数据。
use crate::{
    BoxStream, CancellationToken, Error, FlowFailure, FlowOutcome, IoStream, Result, TcpFlow,
    TcpFlowIo,
};
use std::{
    io::IoSlice,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};

/// 双向转发两条流；任一读端 EOF 会关闭相对写端并继续接收反向数据。
///
/// 只有成功的非空读写推进空闲预算，刷新和关闭本身不算活动。
/// 取消、超时或 I/O 错误会结束转发并释放两条流；已写出的数据不会撤回。
/// 最终目标是否收到半关闭取决于载体及出站能力，不能由此函数单独保证。
pub async fn relay_tcp(
    a: BoxStream,
    b: TcpFlow,
    idle_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    let (mut io, completion) = b.into_parts();
    let result = relay_tcp_io(a, &mut io, idle_timeout, cancel).await;
    completion.finish(match &result {
        Ok(()) => FlowOutcome::DuplexEof,
        Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
    });
    result
}

/// 借用已拆分的业务 I/O 转发；本函数不创建或消费完成权。
/// 父会话所有者须先报告本次真实退出结果，再取消或释放仍存活的 I/O 与子任务。
pub async fn relay_tcp_io(
    mut front: BoxStream,
    io: &mut TcpFlowIo,
    idle_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    copy_streams(front.as_mut(), io, idle_timeout, cancel).await
}

/// 转发载体或掩护流；不得接收业务访问返回的 typed flow。
pub async fn relay_streams(
    mut a: BoxStream,
    mut b: BoxStream,
    idle_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    copy_streams(a.as_mut(), b.as_mut(), idle_timeout, cancel).await
}

pub fn stream_supports_splice(stream: &dyn IoStream) -> bool {
    #[cfg(target_os = "linux")]
    {
        let any = stream as &dyn std::any::Any;
        if any.is::<tokio::net::TcpStream>() {
            return true;
        }
        if let Some(boxed) = any.downcast_ref::<crate::SpliceBox>() {
            return boxed.0.supports_splice();
        }
        if let Some(flow) = any.downcast_ref::<TcpFlowIo>() {
            return stream_supports_splice(flow.inner_ref());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = stream;
    false
}

pub fn as_splice_io(stream: &mut dyn IoStream) -> Option<&mut dyn crate::SpliceIo> {
    #[cfg(target_os = "linux")]
    {
        if !stream_supports_splice(stream) {
            return None;
        }
        let any = stream as &mut dyn std::any::Any;
        if any.is::<tokio::net::TcpStream>() {
            return any
                .downcast_mut::<tokio::net::TcpStream>()
                .map(|tcp| tcp as &mut dyn crate::SpliceIo);
        }
        if any.is::<crate::SpliceBox>() {
            return any
                .downcast_mut::<crate::SpliceBox>()
                .map(|boxed| &mut *boxed.0);
        }
        if any.is::<TcpFlowIo>() {
            return any
                .downcast_mut::<TcpFlowIo>()
                .and_then(|flow| as_splice_io(flow.inner_mut()));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = stream;
    None
}

impl crate::SpliceIo for tokio::net::TcpStream {
    #[cfg(target_os = "linux")]
    fn poll_splice_to_pipe(
        &mut self,
        cx: &mut Context<'_>,
        pipe_wr: std::os::fd::BorrowedFd<'_>,
        max_len: usize,
    ) -> Poll<std::io::Result<usize>> {
        loop {
            std::task::ready!(self.poll_read_ready(cx))?;
            match self.try_io(tokio::io::Interest::READABLE, || {
                rustix::pipe::splice(
                    &*self,
                    None,
                    pipe_wr,
                    None,
                    max_len,
                    rustix::pipe::SpliceFlags::MOVE | rustix::pipe::SpliceFlags::NONBLOCK,
                )
                .map_err(std::io::Error::from)
            }) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn poll_splice_from_pipe(
        &mut self,
        cx: &mut Context<'_>,
        pipe_rd: std::os::fd::BorrowedFd<'_>,
        max_len: usize,
    ) -> Poll<std::io::Result<usize>> {
        loop {
            std::task::ready!(self.poll_write_ready(cx))?;
            match self.try_io(tokio::io::Interest::WRITABLE, || {
                rustix::pipe::splice(
                    pipe_rd,
                    None,
                    &*self,
                    None,
                    max_len,
                    rustix::pipe::SpliceFlags::MOVE | rustix::pipe::SpliceFlags::NONBLOCK,
                )
                .map_err(std::io::Error::from)
            }) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct SpliceDirection {
    pipe_rd: std::os::fd::OwnedFd,
    pipe_wr: std::os::fd::OwnedFd,
    buffered: usize,
    read_done: bool,
    shutdown_done: bool,
}

#[cfg(target_os = "linux")]
impl SpliceDirection {
    fn new() -> std::io::Result<Self> {
        let (pipe_rd, pipe_wr) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .map_err(std::io::Error::from)?;
        let _ = rustix::pipe::fcntl_setpipe_size(&pipe_wr, 512 * 1024);
        Ok(Self {
            pipe_rd,
            pipe_wr,
            buffered: 0,
            read_done: false,
            shutdown_done: false,
        })
    }

    fn poll_forward(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut dyn crate::SpliceIo,
        writer: &mut dyn crate::SpliceIo,
        active: &AtomicBool,
    ) -> Poll<std::io::Result<()>> {
        let mut budget = 64usize;
        loop {
            while self.buffered > 0 {
                let n = std::task::ready!(writer.poll_splice_from_pipe(
                    cx,
                    std::os::fd::AsFd::as_fd(&self.pipe_rd),
                    self.buffered,
                ))?;
                if n == 0 {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                self.buffered -= n;
                active.store(true, Ordering::Relaxed);
            }
            if self.read_done {
                if !self.shutdown_done {
                    std::task::ready!(Pin::new(&mut *writer).poll_flush(cx))?;
                    std::task::ready!(Pin::new(&mut *writer).poll_shutdown(cx))?;
                    self.shutdown_done = true;
                }
                return Poll::Ready(Ok(()));
            }
            if budget == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            budget -= 1;
            let n = std::task::ready!(reader.poll_splice_to_pipe(
                cx,
                std::os::fd::AsFd::as_fd(&self.pipe_wr),
                512 * 1024,
            ))?;
            if n == 0 {
                self.read_done = true;
            } else {
                self.buffered += n;
                active.store(true, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct BidirectionalSplice<'a> {
    a: &'a mut dyn crate::SpliceIo,
    b: &'a mut dyn crate::SpliceIo,
    a_to_b: SpliceDirection,
    b_to_a: SpliceDirection,
    active: &'a AtomicBool,
}

#[cfg(target_os = "linux")]
impl std::future::Future for BidirectionalSplice<'_> {
    type Output = std::io::Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let a_to_b = this.a_to_b.poll_forward(cx, this.a, this.b, this.active)?;
        let b_to_a = this.b_to_a.poll_forward(cx, this.b, this.a, this.active)?;
        if a_to_b.is_ready() && b_to_a.is_ready() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

async fn copy_streams(
    a: &mut dyn IoStream,
    b: &mut dyn IoStream,
    idle_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    if stream_supports_splice(a)
        && stream_supports_splice(b)
        && let (Ok(a_to_b), Ok(b_to_a)) = (SpliceDirection::new(), SpliceDirection::new())
    {
        let a_splice = as_splice_io(a).expect("checked supports_splice");
        let b_splice = as_splice_io(b).expect("checked supports_splice");
        let active = AtomicBool::new(false);
        let copy = BidirectionalSplice {
            a: a_splice,
            b: b_splice,
            a_to_b,
            b_to_a,
            active: &active,
        };
        tokio::pin!(copy);
        let timer = tokio::time::sleep(idle_timeout);
        tokio::pin!(timer);
        return loop {
            tokio::select! {
                biased;
                _=cancel.cancelled()=>break Err(Error::Cancelled),
                result=&mut copy=>break result.map_err(|error| {
                    let error = Error::Io(error);
                    if FlowFailure::from_error(&error) == FlowFailure::Cancelled {
                        Error::Cancelled
                    } else {
                        error
                    }
                }),
                _=&mut timer=>{
                    if active.swap(false, Ordering::Relaxed) {
                        timer.as_mut().reset(Instant::now() + idle_timeout);
                    } else {
                        break Err(Error::Timeout);
                    }
                },
            }
        };
    }

    let active = AtomicBool::new(false);
    let mut a = ActiveIo {
        inner: a,
        active: &active,
    };
    let mut b = ActiveIo {
        inner: b,
        active: &active,
    };
    let copy = tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, 256 * 1024, 256 * 1024);
    tokio::pin!(copy);
    let timer = tokio::time::sleep(idle_timeout);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _=cancel.cancelled()=>return Err(Error::Cancelled),
            result=&mut copy=>return result.map(|_|()).map_err(|error| {
                let error = Error::Io(error);
                if FlowFailure::from_error(&error) == FlowFailure::Cancelled {
                    Error::Cancelled
                } else {
                    error
                }
            }),
            _=&mut timer=>{
                if active.swap(false, Ordering::Relaxed) {
                    timer.as_mut().reset(Instant::now() + idle_timeout);
                } else {
                    return Err(Error::Timeout);
                }
            },
        }
    }
}

struct ActiveIo<'a> {
    inner: &'a mut dyn IoStream,
    active: &'a AtomicBool,
}
impl AsyncRead for ActiveIo<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let previous = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > previous {
            this.active.store(true, Ordering::Relaxed);
        }
        result
    }
}
impl AsyncWrite for ActiveIo<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buffer);
        if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
            this.active.store(true, Ordering::Relaxed);
        }
        result
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
            this.active.store(true, Ordering::Relaxed);
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
