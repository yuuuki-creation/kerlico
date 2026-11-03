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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SniffPolicy {
    pub enabled: bool,
    pub protocols: Vec<String>,
    pub override_destination: bool,
    pub route_only: bool,
    pub parse_pure_ip: bool,
    pub timeout: std::time::Duration,
    pub domains_excluded: Vec<String>,
    pub force_domain: Vec<String>,
    pub sniff_ports: std::collections::BTreeMap<String, Vec<(u16, u16)>>,
}

impl SniffPolicy {
    pub fn effective_timeout(&self) -> std::time::Duration {
        if self.timeout.is_zero() {
            std::time::Duration::from_millis(300)
        } else {
            self.timeout
        }
    }

    pub fn allows_protocol(&self, proto: &str, port: u16) -> bool {
        let proto_lower = proto.to_ascii_lowercase();
        let allowed_by_list = self.protocols.is_empty()
            || self.protocols.iter().any(|p| {
                let p = p.to_ascii_lowercase();
                p == proto_lower
                    || (proto_lower == "tls" && (p == "https" || p == "ssl"))
                    || p == "fakedns+others"
            });
        if !allowed_by_list {
            return false;
        }
        if let Some(ranges) = self
            .sniff_ports
            .get(&proto_lower)
            .or_else(|| self.sniff_ports.get(&proto.to_ascii_uppercase()))
            && !ranges.is_empty()
        {
            return ranges
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&port));
        }
        true
    }

    pub fn should_sniff_target(&self, target: &Destination) -> bool {
        if !self.enabled {
            return false;
        }
        match target.address() {
            crate::Address::Ip(_) => true,
            crate::Address::Domain(domain) => {
                self.force_domain.is_empty()
                    || self
                        .force_domain
                        .iter()
                        .any(|pattern| wildcard_domain_match(pattern, domain))
            }
        }
    }

    pub fn should_override(&self, domain: &str) -> bool {
        if !self.override_destination || self.route_only {
            return false;
        }
        !self
            .domains_excluded
            .iter()
            .any(|pattern| wildcard_domain_match(pattern, domain))
    }
}

fn wildcard_domain_match(pattern: &str, domain: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let d = domain
        .trim()
        .strip_suffix('.')
        .unwrap_or(domain)
        .to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    if p == "*" || p == "+" || p == "." {
        return true;
    }
    if let Some(rest) = p.strip_prefix("+.") {
        return d == rest
            || d.strip_suffix(rest)
                .is_some_and(|prefix| prefix.ends_with('.'));
    }
    if let Some(rest) = p.strip_prefix("*.") {
        return d
            .strip_suffix(rest)
            .is_some_and(|prefix| prefix.ends_with('.'));
    }
    if let Some(rest) = p.strip_prefix('.') {
        return d == rest
            || d.strip_suffix(rest)
                .is_some_and(|prefix| prefix.ends_with('.'));
    }
    p == d
        || d.strip_suffix(&p)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OriginalTarget {
    target: Destination,
    representation: String,
    sniffed_domain: Option<String>,
    sniffed_protocol: Option<String>,
}
impl OriginalTarget {
    pub fn new(host: &str, port: u16) -> Result<Self> {
        Ok(Self {
            target: Destination::new(host, port)?,
            representation: host.to_owned(),
            sniffed_domain: None,
            sniffed_protocol: None,
        })
    }
    pub fn from_destination(target: Destination) -> Self {
        Self {
            representation: target.host(),
            target,
            sniffed_domain: None,
            sniffed_protocol: None,
        }
    }
    pub fn with_target(mut self, target: Destination) -> Self {
        self.target = target;
        self
    }
    pub fn with_sniffed(mut self, domain: Option<String>, protocol: Option<String>) -> Self {
        if domain.is_some() {
            self.sniffed_domain = domain;
        }
        if protocol.is_some() {
            self.sniffed_protocol = protocol;
        }
        self
    }
    pub fn target(&self) -> &Destination {
        &self.target
    }
    pub fn representation(&self) -> &str {
        &self.representation
    }
    pub fn sniffed_domain(&self) -> Option<&str> {
        self.sniffed_domain.as_deref()
    }
    pub fn sniffed_protocol(&self) -> Option<&str> {
        self.sniffed_protocol.as_deref()
    }
}

#[derive(Clone)]
pub struct SessionIdentity {
    source: Source,
    observed: Option<SocketAddr>,
    sniff_policy: SniffPolicy,
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
    pub fn sniff_policy(&self) -> &SniffPolicy {
        &self.sniff_policy
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
    sniff_policy: SniffPolicy,
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
            sniff_policy: SniffPolicy::default(),
            dispatcher,
            association,
            node_cancel: CancellationToken::new(),
            admission: Arc::new(AtomicBool::new(true)),
            carrier: crate::carrier::CarrierCounter::default(),
        }
    }
    pub fn with_sniff_policy(mut self, sniff_policy: SniffPolicy) -> Self {
        self.sniff_policy = sniff_policy;
        self
    }
    pub fn sniff_policy(&self) -> &SniffPolicy {
        &self.sniff_policy
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
                sniff_policy: self.sniff_policy.clone(),
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
    pub fn with_observed_source(&self, addr: SocketAddr) -> Self {
        let mut next = self.clone();
        next.identity.observed = Some(addr);
        next
    }
    pub fn sniff_policy(&self) -> &SniffPolicy {
        self.identity.sniff_policy()
    }
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
