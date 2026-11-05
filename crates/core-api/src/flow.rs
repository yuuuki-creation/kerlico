//! 业务 I/O 与唯一完成权；报告终因不等于所有 I/O 已释放。

use crate::{
    Address, AddressedDatagram, BoxFuture, BoxStream, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Result,
};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowFailure {
    Timeout,
    Cancelled,
    Failed,
}
impl FlowFailure {
    pub fn from_error(error: &Error) -> Self {
        match error {
            Error::Timeout => Self::Timeout,
            Error::Cancelled => Self::Cancelled,
            Error::Io(error) => Self::from_io_error(error),
            _ => Self::Failed,
        }
    }

    /// 只识别类型明确的取消或超时来源；不按系统 I/O 错误种类推断业务终因。
    pub fn from_io_error(error: &io::Error) -> Self {
        match error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<Error>())
        {
            Some(Error::Cancelled) => Self::Cancelled,
            Some(Error::Timeout) => Self::Timeout,
            _ => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowOutcome {
    DuplexEof,
    ProtocolEnd,
    ClosedByCaller,
    Failed(FlowFailure),
}

/// 只能消费一次的终因报告权。未报告的普通释放记为 `ClosedByCaller`。
/// panic 展开时未报告的释放记为 `Failed(FlowFailure::Failed)`。
#[must_use]
pub struct FlowCompletion {
    report: Option<Box<dyn FnOnce(FlowOutcome) + Send + 'static>>,
}
impl FlowCompletion {
    fn new(report: impl FnOnce(FlowOutcome) + Send + 'static) -> Self {
        Self {
            report: Some(Box::new(report)),
        }
    }
    pub fn finish(mut self, outcome: FlowOutcome) {
        if let Some(report) = self.report.take() {
            report(outcome);
        }
    }
}
impl Drop for FlowCompletion {
    fn drop(&mut self) {
        if let Some(report) = self.report.take() {
            report(if std::thread::panicking() {
                FlowOutcome::Failed(FlowFailure::Failed)
            } else {
                FlowOutcome::ClosedByCaller
            });
        }
    }
}

/// 建立操作持有唯一完成权，成功时将它移入业务流；显式结束先报告再释放建链资源。
#[must_use]
pub struct FlowOpen<'a, T> {
    state: OpenState<'a, T>,
}
type OpenFactory<'a, T> = Box<dyn FnOnce() -> Result<FlowOpen<'a, T>> + Send + 'a>;
enum OpenState<'a, T> {
    Deferred(OpenFactory<'a, T>),
    Opening(Box<dyn Opening<T> + 'a>),
    Done,
}
trait Opening<T>: Send {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<T>>;
    fn finish(&mut self, outcome: FlowOutcome);
}
struct TrackedOpening<'a, I, T> {
    completion: Option<FlowCompletion>,
    future: BoxFuture<'a, Result<I>>,
    ready: fn(I, FlowCompletion) -> T,
}
impl<I, T> Opening<T> for TrackedOpening<'_, I, T> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<T>> {
        let result = ready!(self.future.as_mut().poll(cx));
        let completion = self.completion.take().expect("建立完成权只移交一次");
        Poll::Ready(match result {
            Ok(io) => Ok((self.ready)(io, completion)),
            Err(error) => {
                completion.finish(FlowOutcome::Failed(FlowFailure::from_error(&error)));
                Err(error)
            }
        })
    }
    fn finish(&mut self, outcome: FlowOutcome) {
        if let Some(completion) = self.completion.take() {
            completion.finish(outcome);
        }
    }
}
impl<'a, T: 'a> FlowOpen<'a, T> {
    /// 首次 poll 才调用工厂；当前 Dispatcher 在该工厂内执行准入和账本建立。
    pub fn deferred(factory: impl FnOnce() -> Result<Self> + Send + 'a) -> Self {
        Self {
            state: OpenState::Deferred(Box::new(factory)),
        }
    }
    fn tracked<I: 'a>(
        future: BoxFuture<'a, Result<I>>,
        report: impl FnOnce(FlowOutcome) + Send + 'static,
        ready: fn(I, FlowCompletion) -> T,
    ) -> Self {
        Self {
            state: OpenState::Opening(Box::new(TrackedOpening {
                completion: Some(FlowCompletion::new(report)),
                future,
                ready,
            })),
        }
    }
}
impl<T> FlowOpen<'_, T> {
    /// 消费本次建立操作，先调用已有报告回调，再释放建立 future。
    /// 尚未 poll 的 Deferred 不调用工厂；typed 构造器已进入 Opening，即使未 poll 也报告。
    pub fn finish(mut self, outcome: FlowOutcome) {
        if let OpenState::Opening(opening) = &mut self.state {
            opening.finish(outcome);
        }
    }
}
impl<T> Future for FlowOpen<'_, T> {
    type Output = Result<T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = &mut self.get_mut().state;
        loop {
            match state {
                OpenState::Deferred(_) => {
                    let OpenState::Deferred(factory) = std::mem::replace(state, OpenState::Done)
                    else {
                        unreachable!()
                    };
                    match factory() {
                        Ok(opening) => *state = opening.state,
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                OpenState::Opening(opening) => {
                    let result = ready!(opening.poll(cx));
                    *state = OpenState::Done;
                    return Poll::Ready(result);
                }
                OpenState::Done => panic!("已结束的建立操作不能再次 poll"),
            }
        }
    }
}
impl<'a> FlowOpen<'a, TcpFlow> {
    /// 可信调度器提供已计量 I/O 和唯一报告回调；本构造器不授予身份或创建账本。
    pub fn tcp(
        future: BoxFuture<'a, Result<OpenedTcp>>,
        report: impl FnOnce(FlowOutcome) + Send + 'static,
    ) -> Self {
        Self::tracked(future, report, |opened, completion| {
            TcpFlow::with_completion(opened.stream, opened.info, completion)
        })
    }
}
impl<'a> FlowOpen<'a, FixedUdpFlow> {
    /// 固定 UDP 建立与返回流共用同一个报告回调，不增加计量层。
    pub fn fixed_udp(
        future: BoxFuture<'a, Result<DatagramChannel>>,
        report: impl FnOnce(FlowOutcome) + Send + 'static,
    ) -> Self {
        Self::tracked(future, report, FixedUdpFlow::with_completion)
    }
}
impl<'a> FlowOpen<'a, UdpAssociation> {
    /// 多目标 UDP 建立与返回关联共用同一个报告回调，不增加计量层。
    pub fn association(
        future: BoxFuture<'a, Result<DatagramAssociation>>,
        report: impl FnOnce(FlowOutcome) + Send + 'static,
    ) -> Self {
        Self::tracked(future, report, UdpAssociation::with_completion)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindEvidence {
    LocalSocket,
    PeerReported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetBind {
    Known {
        endpoint: Destination,
        evidence: BindEvidence,
    },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConnectInfo {
    target_bind: TargetBind,
}
impl TcpConnectInfo {
    pub fn target_bind(&self) -> &TargetBind {
        &self.target_bind
    }
    pub fn unknown() -> Self {
        Self {
            target_bind: TargetBind::Unknown,
        }
    }
    pub fn local_bound(address: SocketAddr) -> Self {
        if address.port() == 0 || address.ip().to_canonical().is_unspecified() {
            return Self::unknown();
        }
        match Destination::new(&address.ip().to_string(), address.port()) {
            Ok(endpoint) => Self {
                target_bind: TargetBind::Known {
                    endpoint,
                    evidence: BindEvidence::LocalSocket,
                },
            },
            Err(_) => Self::unknown(),
        }
    }
    pub fn peer_reported_bound(endpoint: Destination) -> Self {
        if matches!(endpoint.address(), Address::Ip(ip) if ip.to_canonical().is_unspecified()) {
            return Self::unknown();
        }
        Self {
            target_bind: TargetBind::Known {
                endpoint,
                evidence: BindEvidence::PeerReported,
            },
        }
    }
}

/// 后端返回业务目标连接的绑定证据。代理载体地址不得代填。
pub struct OpenedTcp {
    pub stream: BoxStream,
    pub info: TcpConnectInfo,
}

/// 调度器唯一计量的 TCP 流；拆分后完成权仍属于实际会话所有者。
pub struct TcpFlow {
    completion: Option<FlowCompletion>,
    io: Option<TcpFlowIo>,
    info: TcpConnectInfo,
}
pub struct TcpFlowIo {
    inner: BoxStream,
}
impl TcpFlowIo {
    pub(crate) fn inner_ref(&self) -> &dyn crate::IoStream {
        self.inner.as_ref()
    }
    pub(crate) fn inner_mut(&mut self) -> &mut dyn crate::IoStream {
        self.inner.as_mut()
    }
}
impl TcpFlow {
    pub fn info(&self) -> &TcpConnectInfo {
        &self.info
    }
    pub fn tracked(
        io: BoxStream,
        info: TcpConnectInfo,
        report: impl FnOnce(FlowOutcome) + Send + 'static,
    ) -> Self {
        Self::with_completion(io, info, FlowCompletion::new(report))
    }
    fn with_completion(io: BoxStream, info: TcpConnectInfo, completion: FlowCompletion) -> Self {
        Self {
            completion: Some(completion),
            io: Some(TcpFlowIo { inner: io }),
            info,
        }
    }
    pub fn into_parts(mut self) -> (TcpFlowIo, FlowCompletion) {
        (
            self.io.take().expect("业务 I/O 只移交一次"),
            self.completion.take().expect("完成权只移交一次"),
        )
    }
    pub fn finish(mut self, outcome: FlowOutcome) {
        self.completion
            .take()
            .expect("完成权只报告一次")
            .finish(outcome);
    }
}
impl Drop for TcpFlow {
    fn drop(&mut self) {
        drop(self.completion.take());
    }
}
impl AsyncRead for TcpFlow {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().io.as_mut().expect("业务 I/O 尚未移交")).poll_read(cx, buf)
    }
}
impl AsyncWrite for TcpFlow {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().io.as_mut().expect("业务 I/O 尚未移交")).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().io.as_mut().expect("业务 I/O 尚未移交"))
            .poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.io
            .as_ref()
            .expect("业务 I/O 尚未移交")
            .is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().io.as_mut().expect("业务 I/O 尚未移交")).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().io.as_mut().expect("业务 I/O 尚未移交")).poll_shutdown(cx)
    }
}
impl AsyncRead for TcpFlowIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for TcpFlowIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
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

pub struct FixedUdpFlow {
    completion: Option<FlowCompletion>,
    halves: Option<(FixedUdpSender, FixedUdpReceiver)>,
}
pub struct FixedUdpSender {
    inner: Box<dyn DatagramSender>,
}
pub struct FixedUdpReceiver {
    inner: Box<dyn DatagramReceiver>,
}
impl FixedUdpFlow {
    pub fn tracked(
        channel: DatagramChannel,
        report: impl FnOnce(FlowOutcome) + Send + 'static,
    ) -> Self {
        Self::with_completion(channel, FlowCompletion::new(report))
    }
    fn with_completion(channel: DatagramChannel, completion: FlowCompletion) -> Self {
        Self {
            completion: Some(completion),
            halves: Some((
                FixedUdpSender {
                    inner: channel.sender,
                },
                FixedUdpReceiver {
                    inner: channel.receiver,
                },
            )),
        }
    }
    pub fn into_parts(mut self) -> (FixedUdpSender, FixedUdpReceiver, FlowCompletion) {
        let (send, recv) = self.halves.take().expect("UDP 半部只移交一次");
        (
            send,
            recv,
            self.completion.take().expect("完成权只移交一次"),
        )
    }
    pub fn finish(mut self, outcome: FlowOutcome) {
        self.completion
            .take()
            .expect("完成权只报告一次")
            .finish(outcome);
    }
}
impl Drop for FixedUdpFlow {
    fn drop(&mut self) {
        drop(self.completion.take());
    }
}
impl DatagramSender for FixedUdpSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.inner.send(packet)
    }
}
impl DatagramReceiver for FixedUdpReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        self.inner.peer_addr()
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        self.inner.recv()
    }
}

pub struct UdpAssociation {
    completion: Option<FlowCompletion>,
    halves: Option<(AssociationSender, AssociationReceiver)>,
}
pub struct AssociationSender {
    inner: Box<dyn DatagramAssociationSender>,
}
pub struct AssociationReceiver {
    inner: Box<dyn DatagramAssociationReceiver>,
}
impl UdpAssociation {
    pub fn tracked(
        channel: DatagramAssociation,
        report: impl FnOnce(FlowOutcome) + Send + 'static,
    ) -> Self {
        Self::with_completion(channel, FlowCompletion::new(report))
    }
    fn with_completion(channel: DatagramAssociation, completion: FlowCompletion) -> Self {
        Self {
            completion: Some(completion),
            halves: Some((
                AssociationSender {
                    inner: channel.sender,
                },
                AssociationReceiver {
                    inner: channel.receiver,
                },
            )),
        }
    }
    pub fn into_parts(mut self) -> (AssociationSender, AssociationReceiver, FlowCompletion) {
        let (send, recv) = self.halves.take().expect("UDP 半部只移交一次");
        (
            send,
            recv,
            self.completion.take().expect("完成权只移交一次"),
        )
    }
    pub fn finish(mut self, outcome: FlowOutcome) {
        self.completion
            .take()
            .expect("完成权只报告一次")
            .finish(outcome);
    }
}
impl Drop for UdpAssociation {
    fn drop(&mut self) {
        drop(self.completion.take());
    }
}
impl DatagramAssociationSender for AssociationSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        self.inner.send_to(packet, target)
    }
}
impl DatagramAssociationReceiver for AssociationReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        self.inner.recv_from()
    }
}
