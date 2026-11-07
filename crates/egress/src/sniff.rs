//! 全部入站共用的嗅探阶段：在路由前读取客户端首段或首批数据报，补全域名与协议后再建立出站。
//!
//! TCP 返回惰性流：客户端写入先缓冲并嗅探，判定或超时后才路由并拨号，随后回放缓冲。
//! UDP 在首个（或 QUIC 首批）数据报到达时判定；多目标关联按首个目标路由，与 Mihomo 按来源建 NAT 一致。

use crate::Dispatcher;
use kerlico_config::Network;
use kerlico_core::{
    Address, AddressedDatagram, AssociationSender, BoxFuture, ConnectContext,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramReceiver, DatagramSender,
    Destination, Error, FixedUdpSender, FlowCompletion, FlowOutcome, OriginalTarget, Result,
    SessionIdentity, SetLookup, SniffPolicy, TcpFlow, TcpFlowIo,
};
use kerlico_net::sniff::{SniffProtocol, SniffResult, Sniffed, UdpSniffer, sniff_tcp};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
    time::Sleep,
};

/// Mihomo `maxSniffBufferSize`。
const MAX_TCP_PREFIX: usize = 64 * 1024;
/// QUIC ClientHello 分片等待的数据报上限。
const MAX_UDP_BUFFERED: usize = 8;

/// 一次连接的嗅探安排：按尝试顺序的协议、需要覆盖目标的协议与等待时长。
#[derive(Clone, Debug)]
pub(crate) struct SniffPlan {
    protocols: Vec<SniffProtocol>,
    overrides: Vec<SniffProtocol>,
    timeout: Duration,
}

impl SniffPlan {
    /// 入站策略优先；未命中时再看路由 `sniff` 动作（只用于路由，不覆盖目标）。
    pub(crate) fn decide(
        dispatcher: &Dispatcher,
        identity: &SessionIdentity,
        original: &OriginalTarget,
        network: Network,
    ) -> Option<Self> {
        let fits = |p: &SniffProtocol| match network {
            Network::Tcp => p.tcp(),
            Network::Udp => p.udp(),
        };
        let policy = identity.sniff_policy();
        let port = original.target().port();
        let mapped = match original.target().address() {
            Address::Ip(_) => original.sniffed_domain(),
            Address::Domain(_) => None,
        };
        if policy.wants(
            original.target(),
            mapped,
            identity.observed_source().map(|addr| addr.ip()),
            &dispatcher.routes,
        ) {
            let order: Vec<SniffProtocol> = if policy.sniffers.is_empty() {
                SniffProtocol::ALL.to_vec()
            } else {
                policy
                    .sniffers
                    .iter()
                    .filter_map(|rule| SniffProtocol::parse(&rule.protocol))
                    .collect()
            };
            let mut plan = Self {
                protocols: Vec::new(),
                overrides: Vec::new(),
                timeout: policy.effective_timeout(),
            };
            for protocol in order.into_iter().filter(fits) {
                if let Some(overrides) = policy.sniffer(protocol.as_str(), port) {
                    plan.protocols.push(protocol);
                    if overrides {
                        plan.overrides.push(protocol);
                    }
                }
            }
            if !plan.protocols.is_empty() {
                return Some(plan);
            }
        }
        if !dispatcher.routes.has_sniff_rules() {
            return None;
        }
        let (decision, _, _) =
            dispatcher.evaluate_route(identity, Some((original, network)), &crate::RuleIps::NONE);
        let (names, timeout) = decision.sniff?;
        let protocols: Vec<SniffProtocol> = if names.is_empty() {
            SniffProtocol::ALL.to_vec()
        } else {
            names
                .iter()
                .filter_map(|name| SniffProtocol::parse(name))
                .collect()
        };
        let protocols: Vec<SniffProtocol> = protocols.into_iter().filter(fits).collect();
        (!protocols.is_empty()).then(|| Self {
            protocols,
            overrides: Vec::new(),
            timeout: if timeout.is_zero() {
                Duration::from_millis(300)
            } else {
                timeout
            },
        })
    }

    /// 写入嗅探结果；`skip-domain` 命中的域名整体丢弃，协议名保留供 `protocol` 规则使用。
    pub(crate) fn apply(
        &self,
        policy: &SniffPolicy,
        sets: &dyn SetLookup,
        original: OriginalTarget,
        result: Option<SniffResult>,
    ) -> OriginalTarget {
        let Some(result) = result else {
            return original;
        };
        let domain = result
            .domain
            .filter(|domain| !policy.skips_domain(domain, sets));
        let mut original = original;
        if let Some(domain) = &domain
            && self.overrides.contains(&result.protocol)
            && let Ok(target) = Destination::new(domain, original.target().port())
        {
            original = original.with_target(target);
        }
        original.with_sniffed(domain, Some(result.protocol.as_str().to_owned()))
    }

    pub(crate) fn udp_sniffer(&self) -> UdpSniffer {
        UdpSniffer::new(&self.protocols)
    }
}

/// 内层真实流的完成权；外层流的报告回调从这里转交。
pub(crate) type CompletionSlot = Arc<Mutex<Option<FlowCompletion>>>;

pub(crate) fn finish_slot(slot: &CompletionSlot, outcome: FlowOutcome) {
    let completion = slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(completion) = completion {
        completion.finish(outcome);
    }
}

fn store_slot(slot: &CompletionSlot, completion: FlowCompletion) {
    *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(completion);
}

/// 嗅探结束后的建立沿用原取消域，期限从此刻重新计算。
pub(crate) fn later_context(context: &ConnectContext) -> ConnectContext {
    context.new_operation(context.timeout)
}

pub(crate) type TcpOpener =
    Box<dyn FnOnce(Option<SniffResult>) -> BoxFuture<'static, Result<TcpFlow>> + Send>;

enum TcpState {
    Sniffing {
        prefix: Vec<u8>,
        deadline: Pin<Box<Sleep>>,
        open: TcpOpener,
    },
    Opening {
        future: BoxFuture<'static, Result<TcpFlow>>,
        prefix: Vec<u8>,
    },
    Ready {
        io: TcpFlowIo,
        prefix: Vec<u8>,
        sent: usize,
    },
    Failed,
}

pub(crate) struct SniffingStream {
    state: TcpState,
    protocols: Vec<SniffProtocol>,
    slot: CompletionSlot,
}

impl SniffingStream {
    pub(crate) fn new(plan: &SniffPlan, open: TcpOpener, slot: CompletionSlot) -> Self {
        Self {
            state: TcpState::Sniffing {
                prefix: Vec::new(),
                deadline: Box::pin(tokio::time::sleep(plan.timeout)),
                open,
            },
            protocols: plan.protocols.clone(),
            slot,
        }
    }

    fn conclude(&mut self, result: Option<SniffResult>) {
        let state = std::mem::replace(&mut self.state, TcpState::Failed);
        self.state = match state {
            TcpState::Sniffing { prefix, open, .. } => TcpState::Opening {
                future: open(result),
                prefix,
            },
            other => other,
        };
    }

    /// 推进到已建立且缓冲已回放；嗅探中只登记超时唤醒。
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                TcpState::Sniffing { deadline, .. } => {
                    ready!(deadline.as_mut().poll(cx));
                    self.conclude(None);
                }
                TcpState::Opening { future, prefix } => match ready!(future.as_mut().poll(cx)) {
                    Ok(flow) => {
                        let (io, completion) = flow.into_parts();
                        store_slot(&self.slot, completion);
                        let prefix = std::mem::take(prefix);
                        self.state = TcpState::Ready {
                            io,
                            prefix,
                            sent: 0,
                        };
                    }
                    Err(error) => {
                        self.state = TcpState::Failed;
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                },
                TcpState::Ready { io, prefix, sent } => {
                    while *sent < prefix.len() {
                        let n = ready!(Pin::new(&mut *io).poll_write(cx, &prefix[*sent..]))?;
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        *sent += n;
                    }
                    if !prefix.is_empty() {
                        *prefix = Vec::new();
                        *sent = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                TcpState::Failed => {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
                }
            }
        }
    }

    fn io(&mut self) -> &mut TcpFlowIo {
        match &mut self.state {
            TcpState::Ready { io, .. } => io,
            _ => unreachable!("poll_ready 已返回就绪"),
        }
    }
}

impl AsyncRead for SniffingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_ready(cx))?;
        Pin::new(this.io()).poll_read(cx, buf)
    }
}

impl AsyncWrite for SniffingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let TcpState::Sniffing { prefix, .. } = &mut this.state {
            let take = buf.len().min(MAX_TCP_PREFIX - prefix.len());
            prefix.extend_from_slice(&buf[..take]);
            match sniff_tcp(prefix, &this.protocols) {
                Sniffed::Found(result) => this.conclude(Some(result)),
                Sniffed::NeedMore if prefix.len() < MAX_TCP_PREFIX => {}
                Sniffed::NeedMore | Sniffed::Miss => this.conclude(None),
            }
            if let Poll::Ready(Err(error)) = this.poll_ready(cx) {
                return Poll::Ready(Err(error));
            }
            return Poll::Ready(Ok(take));
        }
        ready!(this.poll_ready(cx))?;
        Pin::new(this.io()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, TcpState::Sniffing { .. }) {
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_ready(cx))?;
        Pin::new(this.io()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, TcpState::Sniffing { .. }) {
            this.conclude(None);
        }
        ready!(this.poll_ready(cx))?;
        Pin::new(this.io()).poll_shutdown(cx)
    }
}

/// 首个目标数据报的嗅探进度。
struct PendingUdp {
    sniffer: Option<UdpSniffer>,
    buffered: Vec<(Vec<u8>, Destination)>,
}

impl PendingUdp {
    fn new(plan: Option<&SniffPlan>) -> Self {
        Self {
            sniffer: plan.map(SniffPlan::udp_sniffer),
            buffered: Vec::new(),
        }
    }

    /// `None` 表示继续缓冲等待分片；否则返回可以建立时的嗅探结果。
    fn push(
        &mut self,
        packet: &[u8],
        target: &Destination,
        first: &Destination,
    ) -> Option<Option<SniffResult>> {
        self.buffered.push((packet.to_vec(), target.clone()));
        let Some(sniffer) = self.sniffer.as_mut() else {
            return Some(None);
        };
        if target != first {
            return Some(None);
        }
        match sniffer.push(packet) {
            Sniffed::Found(result) => Some(Some(result)),
            Sniffed::NeedMore if self.buffered.len() < MAX_UDP_BUFFERED => None,
            Sniffed::NeedMore | Sniffed::Miss => Some(None),
        }
    }
}

/// 固定目标 UDP：首批数据报嗅探后才建立出站。
pub(crate) struct LazyFixedSender {
    dispatcher: Arc<Dispatcher>,
    identity: SessionIdentity,
    context: ConnectContext,
    original: Option<OriginalTarget>,
    plan: SniffPlan,
    pending: PendingUdp,
    open: Option<FixedUdpSender>,
    receiver: Option<oneshot::Sender<kerlico_core::FixedUdpReceiver>>,
    slot: CompletionSlot,
}

impl LazyFixedSender {
    pub(crate) fn new(
        dispatcher: Arc<Dispatcher>,
        identity: SessionIdentity,
        context: ConnectContext,
        original: OriginalTarget,
        plan: SniffPlan,
        slot: CompletionSlot,
    ) -> (Self, LazyFixedReceiver) {
        let (tx, rx) = oneshot::channel();
        let target = original.target().clone();
        let pending = PendingUdp::new(Some(&plan));
        (
            Self {
                dispatcher,
                identity,
                context,
                original: Some(original),
                plan,
                pending,
                open: None,
                receiver: Some(tx),
                slot,
            },
            LazyFixedReceiver {
                target,
                rx,
                inner: None,
            },
        )
    }
}

impl DatagramSender for LazyFixedSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(sender) = self.open.as_mut() {
                return sender.send(packet).await;
            }
            let original = self.original.take().ok_or(Error::Cancelled)?;
            let first = original.target().clone();
            let Some(result) = self.pending.push(packet, &first, &first) else {
                self.original = Some(original);
                return Ok(());
            };
            let original = self.plan.apply(
                self.identity.sniff_policy(),
                &self.dispatcher.routes,
                original,
                result,
            );
            let flow = self
                .dispatcher
                .udp(&self.identity, original, &self.context)?
                .await?;
            let (mut sender, receiver, completion) = flow.into_parts();
            store_slot(&self.slot, completion);
            if let Some(tx) = self.receiver.take() {
                let _ = tx.send(receiver);
            }
            for (packet, _) in std::mem::take(&mut self.pending.buffered) {
                sender.send(&packet).await?;
            }
            self.open = Some(sender);
            Ok(())
        })
    }
}

pub(crate) struct LazyFixedReceiver {
    target: Destination,
    rx: oneshot::Receiver<kerlico_core::FixedUdpReceiver>,
    inner: Option<kerlico_core::FixedUdpReceiver>,
}

impl DatagramReceiver for LazyFixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        match &self.inner {
            Some(inner) => inner.peer_addr(),
            None => Some(self.target.clone()),
        }
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.inner.is_none() {
                match (&mut self.rx).await {
                    Ok(inner) => self.inner = Some(inner),
                    Err(_) => return Ok(None),
                }
            }
            self.inner.as_mut().expect("已建立").recv().await
        })
    }
}

/// 多目标关联：按首个目标（含嗅探结果）路由一次，之后全部目标走同一出口。
pub(crate) struct LazyAssociationSender {
    dispatcher: Arc<Dispatcher>,
    identity: SessionIdentity,
    context: ConnectContext,
    first: Option<(OriginalTarget, Option<SniffPlan>)>,
    pending: Option<PendingUdp>,
    open: Option<AssociationSender>,
    receiver: Option<oneshot::Sender<kerlico_core::AssociationReceiver>>,
    /// 关联建立前被劫持的 DNS 查询在本地应答，回包经此送给接收端。
    hijacked: mpsc::Sender<AddressedDatagram>,
    slot: CompletionSlot,
}

impl LazyAssociationSender {
    pub(crate) fn new(
        dispatcher: Arc<Dispatcher>,
        identity: SessionIdentity,
        context: ConnectContext,
        slot: CompletionSlot,
    ) -> (Self, LazyAssociationReceiver) {
        let (tx, rx) = oneshot::channel();
        let (hijacked, answers) = mpsc::channel(16);
        (
            Self {
                dispatcher,
                identity,
                context,
                first: None,
                pending: None,
                open: None,
                receiver: Some(tx),
                hijacked,
                slot,
            },
            LazyAssociationReceiver {
                rx,
                inner: None,
                answers,
            },
        )
    }
}

impl DatagramAssociationSender for LazyAssociationSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(sender) = self.open.as_mut() {
                return sender.send_to(packet, target).await;
            }
            // 同 Mihomo，劫持的 DNS 不建立出站：只有 DNS 的来源不占出站 socket。
            if self.first.is_none() && self.dispatcher.hijacks_dns(&self.identity, target) {
                let reply = self.dispatcher.resolver.exchange_dns_packet(packet).await?;
                let _ = self.hijacked.send((target.clone(), reply)).await;
                return Ok(());
            }
            if self.first.is_none() {
                let original = self
                    .dispatcher
                    .enrich_original(OriginalTarget::from_destination(target.clone()));
                let plan =
                    SniffPlan::decide(&self.dispatcher, &self.identity, &original, Network::Udp);
                self.pending = Some(PendingUdp::new(plan.as_ref()));
                self.first = Some((original, plan));
            }
            let (original, plan) = self.first.as_ref().expect("首个目标已记录");
            let first = original.target().clone();
            // 首个目标建立失败后关联不再重试。
            let Some(pending) = self.pending.as_mut() else {
                return Err(Error::Rejected);
            };
            let Some(result) = pending.push(packet, target, &first) else {
                return Ok(());
            };
            let original = match plan {
                Some(plan) => plan.apply(
                    self.identity.sniff_policy(),
                    &self.dispatcher.routes,
                    original.clone(),
                    result,
                ),
                None => original.clone(),
            };
            let buffered = self.pending.take().map(|p| p.buffered).unwrap_or_default();
            let association = self
                .dispatcher
                .association(&self.identity, Some(original), &self.context)?
                .await?;
            let (mut sender, receiver, completion) = association.into_parts();
            store_slot(&self.slot, completion);
            if let Some(tx) = self.receiver.take() {
                let _ = tx.send(receiver);
            }
            for (packet, target) in buffered {
                sender.send_to(&packet, &target).await?;
            }
            self.open = Some(sender);
            Ok(())
        })
    }
}

pub(crate) struct LazyAssociationReceiver {
    rx: oneshot::Receiver<kerlico_core::AssociationReceiver>,
    inner: Option<kerlico_core::AssociationReceiver>,
    answers: mpsc::Receiver<AddressedDatagram>,
}

impl DatagramAssociationReceiver for LazyAssociationReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            if self.inner.is_none() {
                tokio::select! { biased;
                    Some(answer) = self.answers.recv() => return Ok(Some(answer)),
                    opened = &mut self.rx => match opened {
                        Ok(inner) => self.inner = Some(inner),
                        Err(_) => return Ok(self.answers.try_recv().ok()),
                    },
                }
            }
            if let Ok(answer) = self.answers.try_recv() {
                return Ok(Some(answer));
            }
            self.inner.as_mut().expect("已建立").recv_from().await
        })
    }
}
