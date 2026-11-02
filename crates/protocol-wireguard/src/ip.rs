//! 与加密载体分离的用户态 IP 数据面。调用方负责握手、身份、分配地址及载体生命周期。

pub use crate::config::Limits as StackLimits;
pub use crate::config::Network;
use crate::{
    config::{Addresses, target},
    crypto::CryptoPeer,
    packet::{FragmentBudget, IpPacket, Reassembler, control_reply},
    queue::PacketBudget,
    server::RuntimePeer,
    stack::SharedStack,
    tcp::TcpStream,
    udp,
};
use boringtun::{
    noise::{Packet, TunnResult, handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    x25519::{PublicKey, StaticSecret},
};
use kerlico_core::{
    CancellationToken, ConnectContext, DatagramAssociation, DatagramChannel, Destination, Error,
    InboundContext, NodeEvent, OpenedTcp, PeerSession, Result, TcpConnectInfo,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

#[derive(Clone)]
pub struct StackOptions {
    pub addresses: Vec<IpAddr>,
    pub allowed_ips: Vec<String>,
    pub mtu: usize,
    pub limits: StackLimits,
}
impl StackOptions {
    fn prepare(
        &self,
        cancel: CancellationToken,
    ) -> Result<(Arc<SharedStack>, Vec<Network>, Reassembler)> {
        self.limits.validate()?;
        if !(1280..=9000).contains(&self.mtu)
            || self.allowed_ips.is_empty()
            || self.allowed_ips.len() > 256
        {
            return Err(Error::Config("IP数据面MTU或允许范围不合法".into()));
        }
        let allowed = self
            .allowed_ips
            .iter()
            .map(|network| Network::parse(network))
            .collect::<Result<Vec<_>>>()?;
        for (index, network) in allowed.iter().enumerate() {
            if allowed[..index].iter().any(|other| network.overlaps(other)) {
                return Err(Error::Config("IP数据面允许范围不能重复或重叠".into()));
            }
        }
        let stack = SharedStack::with_options(
            Addresses::parse(self.addresses.clone())?,
            self.limits.clone(),
            self.mtu,
            cancel,
            Arc::new(Notify::new()),
            allowed.clone(),
            PacketBudget::new(self.limits.queue_packets, self.limits.queue_bytes),
        )?;
        let fragments = Reassembler::new(FragmentBudget::new(
            self.limits.fragment_packets,
            self.limits.fragment_bytes,
        ));
        Ok((stack, allowed, fragments))
    }
}

struct ClientInner {
    stack: Arc<SharedStack>,
    fragments: Mutex<Reassembler>,
}
impl Drop for ClientInner {
    fn drop(&mut self) {
        self.stack.cancel.cancel();
        self.stack.close();
    }
}
#[derive(Clone)]
pub struct ClientTunnel(Arc<ClientInner>);
impl ClientTunnel {
    pub fn new(options: StackOptions, cancel: CancellationToken) -> Result<Self> {
        let (stack, _, fragments) = options.prepare(cancel.child_token())?;
        Ok(Self(Arc::new(ClientInner {
            stack,
            fragments: Mutex::new(fragments),
        })))
    }
    pub async fn connect_tcp(
        &self,
        remote: &Destination,
        context: &ConnectContext,
    ) -> Result<OpenedTcp> {
        let remote = target(remote)?;
        if !self.0.stack.allows(remote.ip()) {
            return Err(Error::Rejected);
        }
        let stream = TcpStream::connect(self.0.stack.clone(), remote, context).await?;
        let info = TcpConnectInfo::local_bound(stream.local_addr());
        Ok(OpenedTcp {
            stream: Box::new(stream),
            info,
        })
    }
    pub fn connect_udp(
        &self,
        remote: &Destination,
        context: &ConnectContext,
    ) -> Result<DatagramChannel> {
        udp::fixed(self.0.stack.clone(), remote, context)
    }
    pub fn associate_udp(&self, context: &ConnectContext) -> Result<DatagramAssociation> {
        udp::association(self.0.stack.clone(), context)
    }
    pub fn receive(&self, bytes: &[u8]) -> Result<()> {
        let packet = IpPacket::parse(bytes)?;
        if !self.0.stack.allows(packet.source) || !self.0.stack.addresses.contains(packet.target) {
            return Err(Error::Rejected);
        }
        let mut fragments = self
            .0
            .fragments
            .lock()
            .map_err(|_| Error::Protocol("IP分片状态已损坏"))?;
        let Some(bytes) = fragments.accept(bytes, Instant::now())? else {
            return Ok(());
        };
        let packet = IpPacket::parse(&bytes)?;
        match packet.protocol {
            6 => self.0.stack.input_tcp(bytes),
            17 => self.0.stack.receive_udp(&packet),
            1 | 58 => {
                if let Some(reply) = control_reply(&bytes, &self.0.stack.addresses)? {
                    self.0.stack.queue_packet(reply)?;
                }
                Ok(())
            }
            _ => Err(Error::Unsupported("IP数据面不提供该协议")),
        }
    }
    pub async fn next_packet(&self) -> Result<Vec<u8>> {
        next_packet(&self.0.stack).await
    }
    pub fn close(&self) {
        self.0.stack.cancel.cancel();
        self.0.stack.close();
    }
    pub fn active_flows(&self) -> usize {
        self.0.stack.flow_count()
    }
}

/// 单个对端的 WireGuard 会话。调用方决定密文走哪条路径。
pub struct PeerCrypto(CryptoPeer);
pub struct PeerPackets {
    pub plain: Option<Vec<u8>>,
    pub network: Vec<Vec<u8>>,
}
impl PeerCrypto {
    /// `index` 是本端唯一的 24 位对端序号，[`packet_owner`] 返回同一数值。
    pub fn new(private: [u8; 32], public: [u8; 32], index: u32) -> Self {
        Self(CryptoPeer::standalone(
            StaticSecret::from(private),
            PublicKey::from(public),
            index,
        ))
    }
    /// `source` 仅用于握手限速的来源判断。
    pub fn receive(&mut self, source: SocketAddr, packet: &[u8]) -> Result<PeerPackets> {
        let received = self.0.receive(source, packet)?;
        Ok(PeerPackets {
            plain: received.plain,
            network: received.network,
        })
    }
    /// 无会话时缓存明文并返回握手发起。
    pub fn encrypt(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0.encapsulate(packet)
    }
    pub fn tick(&mut self) -> Option<Vec<u8>> {
        self.0.tick()
    }
}
pub enum PacketRoute {
    /// 握手发起方的静态公钥，已由本端私钥解密认证。
    Initiator([u8; 32]),
    /// 接收方序号，等于 [`PeerCrypto::new`] 的 `index`。
    Index(u32),
    /// 握手超过限速且未带有效 MAC2：把 cookie 回复原路发回，对端证明地址后重试。
    CookieReply(Vec<u8>),
}
/// 与 WireGuard 服务端入站相同的每秒握手上限。
const HANDSHAKE_LIMIT: u64 = 100;
/// 判断无来源身份的 UDP 密文属于哪个对端。握手在 DH 之前先校验 MAC1 并限速。
pub struct PacketClassifier {
    secret: StaticSecret,
    public: PublicKey,
    limiter: RateLimiter,
}
impl PacketClassifier {
    pub fn new(private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret);
        let limiter = RateLimiter::new(&public, HANDSHAKE_LIMIT);
        Self {
            secret,
            public,
            limiter,
        }
    }
    /// `source` 是外层来源地址，用于 cookie。
    pub fn classify(&self, source: IpAddr, packet: &[u8]) -> Option<PacketRoute> {
        let mut cookie = [0; 64];
        let parsed = match self
            .limiter
            .verify_packet(Some(source), packet, &mut cookie)
        {
            Ok(parsed) => parsed,
            Err(TunnResult::WriteToNetwork(reply)) => {
                return Some(PacketRoute::CookieReply(reply.to_vec()));
            }
            Err(_) => return None,
        };
        match parsed {
            Packet::HandshakeInit(packet) => {
                let half = parse_handshake_anon(&self.secret, &self.public, &packet).ok()?;
                Some(PacketRoute::Initiator(half.peer_static_public))
            }
            Packet::HandshakeResponse(packet) => Some(PacketRoute::Index(packet.receiver_idx >> 8)),
            Packet::PacketCookieReply(packet) => Some(PacketRoute::Index(packet.receiver_idx >> 8)),
            Packet::PacketData(packet) => Some(PacketRoute::Index(packet.receiver_idx >> 8)),
        }
    }
    /// 每秒归零限速计数；调用方的定时器可以更频繁地调用。
    pub fn reset_count(&self) {
        self.limiter.reset_count();
    }
}

pub struct ServerTunnel {
    peer: Mutex<(RuntimePeer, Reassembler)>,
    allowed: Vec<Network>,
    stack: Arc<SharedStack>,
}
impl ServerTunnel {
    /// `access` 必须由外层协议完成真实鉴权后取得，不能从 IP 包中的身份字段创建。
    pub fn new(
        options: StackOptions,
        access: PeerSession,
        mut context: InboundContext,
    ) -> Result<Self> {
        if !access.supports_udp_association() {
            return Err(Error::Unsupported("IP节点需要多目标UDP出站"));
        }
        let lease = context.stream_budget.try_acquire()?;
        context.cancel = context.cancel.child_token();
        let (stack, allowed, fragments) = options.prepare(context.cancel.clone())?;
        context.events.record(NodeEvent::Accepted);
        let peer = RuntimePeer::from_tunnel(stack.clone(), access, context, lease);
        Ok(Self {
            peer: Mutex::new((peer, fragments)),
            allowed,
            stack,
        })
    }
    pub fn receive(&self, bytes: &[u8]) -> Result<()> {
        let mut state = self
            .peer
            .lock()
            .map_err(|_| Error::Protocol("IP节点状态已损坏"))?;
        let (peer, fragments) = &mut *state;
        peer.receive(&self.allowed, fragments, bytes)
    }
    pub async fn next_packet(&self) -> Result<Vec<u8>> {
        next_packet(&self.stack).await
    }
    pub fn close(&self) {
        self.stack.cancel.cancel();
        self.stack.close();
    }
    pub fn active_flows(&self) -> usize {
        self.peer.lock().map_or(0, |state| state.0.active_flows())
    }
}
impl Drop for ServerTunnel {
    fn drop(&mut self) {
        self.close();
    }
}
async fn next_packet(stack: &SharedStack) -> Result<Vec<u8>> {
    let mut timer = tokio::time::interval(Duration::from_millis(20));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        stack.poll()?;
        if let Some(packet) = stack.drain(1)?.pop() {
            return Ok(packet);
        }
        tokio::select! { biased;
            _ = stack.cancel.cancelled() => return Err(Error::Cancelled),
            _ = stack.notify.notified() => {},
            _ = timer.tick() => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    /// 返回响应方私钥、发起方公钥和一个发给响应方的握手发起包。
    fn handshake_init() -> ([u8; 32], [u8; 32], Vec<u8>) {
        let responder = [1; 32];
        let responder_public = *PublicKey::from(&StaticSecret::from(responder)).as_bytes();
        let initiator = [2; 32];
        let initiator_public = *PublicKey::from(&StaticSecret::from(initiator)).as_bytes();
        let mut peer = PeerCrypto::new(initiator, responder_public, 1);
        let init = peer.encrypt(&[0x45; 20]).unwrap().unwrap();
        (responder, initiator_public, init)
    }

    #[test]
    fn handshake_with_a_bad_mac1_is_dropped_before_any_diffie_hellman() {
        let (responder, initiator_public, init) = handshake_init();
        let classifier = PacketClassifier::new(responder);
        assert!(matches!(
            classifier.classify(SOURCE, &init),
            Some(PacketRoute::Initiator(public)) if public == initiator_public
        ));
        let mut forged = init.clone();
        let mac1 = forged.len() - 32;
        forged[mac1] ^= 1;
        assert!(classifier.classify(SOURCE, &forged).is_none());
    }

    #[test]
    fn handshake_flood_gets_cookie_replies_instead_of_diffie_hellman() {
        let (responder, _, init) = handshake_init();
        let classifier = PacketClassifier::new(responder);
        for _ in 0..HANDSHAKE_LIMIT {
            assert!(matches!(
                classifier.classify(SOURCE, &init),
                Some(PacketRoute::Initiator(_))
            ));
        }
        assert!(matches!(
            classifier.classify(SOURCE, &init),
            Some(PacketRoute::CookieReply(reply)) if reply[0] == 3
        ));
    }
}
