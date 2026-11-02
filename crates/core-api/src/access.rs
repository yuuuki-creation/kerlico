//! 入站只能从真实鉴别或显式本地信任边界取得业务访问能力。

use crate::{
    CancellationToken, ConnectContext, CredentialIssuer, Destination, Error, FixedUdpFlow,
    FlowOpen, InboundContext, PeerLease, Result, Source, TcpFlow, UdpAssociation, Verified,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetPolicy {
    Local,
    Remote,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FamilyMode {
    V4Only,
    V6Only,
    DualV4Preferred,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OriginalTarget {
    target: Destination,
    representation: String,
}
impl OriginalTarget {
    pub fn new(host: &str, port: u16) -> Result<Self> {
        Ok(Self {
            target: Destination::new(host, port)?,
            representation: host.to_owned(),
        })
    }
    pub fn from_destination(target: Destination) -> Self {
        Self {
            representation: target.host(),
            target,
        }
    }
    pub fn target(&self) -> &Destination {
        &self.target
    }
    pub fn representation(&self) -> &str {
        &self.representation
    }
}

#[derive(Clone)]
pub struct SessionIdentity {
    source: Source,
    observed: Option<SocketAddr>,
    cancel: CancellationToken,
    node_cancel: CancellationToken,
    peer_lease: Option<PeerLease>,
    admission: Arc<AtomicBool>,
}
impl SessionIdentity {
    pub fn source(&self) -> &Source {
        &self.source
    }
    pub fn observed_source(&self) -> Option<SocketAddr> {
        self.observed
    }
    pub fn cancel(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub fn node_cancel(&self) -> CancellationToken {
        self.node_cancel.clone()
    }
    pub fn peer_lease(&self) -> Option<PeerLease> {
        self.peer_lease.clone()
    }
    /// 调度器的成功读取是本次请求准入点；已接纳操作仍归节点任务所有者回收。
    pub fn is_accepting(&self) -> bool {
        self.admission.load(Ordering::Acquire)
    }
}

/// 由唯一调度器实现的扩展边界。协议业务只调用 `PeerSession`。
pub trait SessionDispatcher: Send + Sync {
    fn supports_udp_association(&self, identity: &SessionIdentity) -> bool;
    fn connect_tcp<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        target: OriginalTarget,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, TcpFlow>;
    fn connect_udp<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        target: OriginalTarget,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, FixedUdpFlow>;
    fn associate_udp<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, UdpAssociation>;
}

#[derive(Clone)]
pub struct IngressBinding {
    issuer: CredentialIssuer,
    local: bool,
    dispatcher: Arc<dyn SessionDispatcher>,
    association: bool,
    node_cancel: CancellationToken,
    admission: Arc<AtomicBool>,
    carrier: crate::carrier::CarrierCounter,
}
impl IngressBinding {
    pub fn assemble(
        issuer: CredentialIssuer,
        local: bool,
        dispatcher: Arc<dyn SessionDispatcher>,
        association: bool,
    ) -> Self {
        Self {
            issuer,
            local,
            dispatcher,
            association,
            node_cancel: CancellationToken::new(),
            admission: Arc::new(AtomicBool::new(true)),
            carrier: crate::carrier::CarrierCounter::default(),
        }
    }
    /// 只登记本节点实际交接的载体字节；不记用户业务量，也不推算设备开销。
    pub fn record_carrier(&self, sent_bytes: u64, received_bytes: u64) {
        self.carrier.record(sent_bytes, received_bytes);
    }
    pub fn carrier_usage(&self) -> crate::CarrierUsage {
        self.carrier.snapshot()
    }
    pub fn authenticated<T>(
        &self,
        verified: Verified<T>,
        context: &InboundContext,
    ) -> Result<(PeerSession, T)> {
        if context.cancel.is_cancelled()
            || self.node_cancel.is_cancelled()
            || !self.admission.load(Ordering::Acquire)
        {
            return Err(Error::Cancelled);
        }
        let (source, decoded) = self.issuer.accept(verified)?;
        Ok((self.session(source, context), decoded))
    }
    pub fn local(&self, context: &InboundContext) -> Result<PeerSession> {
        if !self.local {
            return Err(Error::Rejected);
        }
        if context.cancel.is_cancelled()
            || self.node_cancel.is_cancelled()
            || !self.admission.load(Ordering::Acquire)
        {
            return Err(Error::Cancelled);
        }
        Ok(self.session(
            Source::Local {
                node: self.issuer.node().clone(),
            },
            context,
        ))
    }
    fn session(&self, source: Source, context: &InboundContext) -> PeerSession {
        PeerSession {
            identity: SessionIdentity {
                source,
                observed: context.peer_addr,
                cancel: context.cancel.clone(),
                node_cancel: self.node_cancel.clone(),
                peer_lease: context.peer_lease.clone(),
                admission: self.admission.clone(),
            },
            dispatcher: self.dispatcher.clone(),
        }
    }
    pub fn supports_udp_association(&self) -> bool {
        self.association
    }
    pub fn node_cancel(&self) -> CancellationToken {
        self.node_cancel.clone()
    }
    /// 幂等停止新 peer 以及 TCP 流、固定 UDP 流和多目标 UDP 关联的创建，不能重新开放。
    /// 既有 I/O 不取消，已接纳关联仍可向首次目标 `send_to`。
    pub fn stop_admission(&self) {
        self.admission.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
pub struct PeerSession {
    identity: SessionIdentity,
    dispatcher: Arc<dyn SessionDispatcher>,
}
impl PeerSession {
    pub fn source(&self) -> &Source {
        self.identity.source()
    }
    pub fn cancel(&self) -> CancellationToken {
        self.identity.cancel()
    }
    pub fn supports_udp_association(&self) -> bool {
        self.dispatcher.supports_udp_association(&self.identity)
    }
    pub fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, TcpFlow> {
        self.open_tcp(OriginalTarget::from_destination(target.clone()), context)
    }
    pub fn open_tcp<'a>(
        &'a self,
        target: OriginalTarget,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, TcpFlow> {
        self.dispatcher.connect_tcp(&self.identity, target, context)
    }
    pub fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, FixedUdpFlow> {
        self.open_udp(OriginalTarget::from_destination(target.clone()), context)
    }
    pub fn open_udp<'a>(
        &'a self,
        target: OriginalTarget,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, FixedUdpFlow> {
        self.dispatcher.connect_udp(&self.identity, target, context)
    }
    pub fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, UdpAssociation> {
        self.dispatcher.associate_udp(&self.identity, context)
    }
}
