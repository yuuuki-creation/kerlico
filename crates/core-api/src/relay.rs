//! 带取消与空闲预算的双向流转发，保留半关闭后的反向数据。
use crate::{
    BoxStream, CancellationToken, Error, FlowFailure, FlowOutcome, IoStream, Result, TcpFlow,
    TcpFlowIo,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
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

async fn copy_streams(
    a: &mut dyn IoStream,
    b: &mut dyn IoStream,
    idle_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    let (activity, mut observed) = watch::channel(Instant::now());
    let mut a = ActiveIo {
        inner: a,
        activity: activity.clone(),
    };
    let mut b = ActiveIo { inner: b, activity };
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
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
            changed=observed.changed()=>{ if changed.is_ok() { timer.as_mut().reset(*observed.borrow_and_update()+idle_timeout); } },
            _=&mut timer=>return Err(Error::Timeout),
        }
    }
}

struct ActiveIo<'a> {
    inner: &'a mut dyn IoStream,
    activity: watch::Sender<Instant>,
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
            this.activity.send_replace(Instant::now());
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
        if matches!(result,Poll::Ready(Ok(count)) if count>0) {
            this.activity.send_replace(Instant::now());
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
