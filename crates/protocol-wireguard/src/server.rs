mod flows;

use crate::{
    carrier::Carrier,
    client::send,
    config::{CommonOptions, PeerConfig, PeerOptions, Prepared, destination},
    crypto::{CryptoPeer, Identified, PeerIndex},
    packet::{FragmentBudget, IpPacket, Reassembler, control_reply, tcp_reset, unreachable},
    queue::PacketBudget,
    stack::SharedStack,
    tcp::TcpStream,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, CredentialManifest, CredentialSet, CredentialSlot, Error, InboundContext,
    InboundProtocol, IngressBinding, NodeEvent, PeerSession, Result, StreamLease,
    is_peer_path_error,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
    time::MissedTickBehavior,
};

/// 单UDP入口的原生WireGuard多成员节点工厂。
pub struct WireGuardNodeFactory;
struct WireGuardNode {
    prepared: Prepared,
    credentials: CredentialSet<PeerConfig>,
}
impl NodeFactory for WireGuardNodeFactory {
    fn kind(&self) -> &'static str {
        "wireguard"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Options {
            tunnel: CommonOptions,
            #[serde(default)]
            level: u32,
        }
        if input.is_local() || input.native_credentials().is_empty() {
            return Err(Error::Config("WireGuard节点必须配置独立认证成员".into()));
        }
        let options: Options = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("WireGuard节点字段不合法".into()))?;
        let _ = options.level;
        let prepared = options.tunnel.prepare()?;
        let mut peers: Vec<PeerConfig> = Vec::new();
        let mut keys = HashSet::new();
        for value in input.native_credentials() {
            let options: PeerOptions = serde_json::from_value(value.clone())
                .map_err(|_| Error::Config("WireGuard成员字段不合法".into()))?;
            let peer = options.prepare()?;
            let _ = peer.level;
            prepared.validate_peer(&peer)?;
            if !keys.insert(peer.public_key)
                || peers.iter().any(|other| {
                    peer.allowed
                        .iter()
                        .any(|a| other.allowed.iter().any(|b| a.overlaps(b)))
                })
                || prepared
                    .addresses
                    .iter()
                    .any(|address| peer.allows(address))
            {
                return Err(Error::Config(
                    "WireGuard成员公钥及来源范围必须独立，不能包含节点接口地址".into(),
                ));
            }
            peers.push(peer);
        }
        Ok(Arc::new(WireGuardNode {
            prepared,
            credentials: input.credentials(peers)?,
        }))
    }
}
fn fingerprint(domain: &[u8], key: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(key);
    hash.finalize().into()
}
impl InboundProtocol for WireGuardNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        manifest.protection(
            "wireguard",
            fingerprint(b"wireguard-static", self.prepared.public_key.as_bytes()),
        );
        for (index, (_, peer)) in self.credentials.rows().enumerate() {
            manifest.authentication(
                "wireguard",
                index,
                fingerprint(b"wireguard-static", &peer.public_key),
            );
            if let Some(key) = &peer.preshared_key {
                manifest.protection("wireguard", fingerprint(b"wireguard-psk", &**key));
            }
        }
        manifest
    }
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn supports_tcp(&self) -> bool {
        false
    }
    fn supports_udp(&self) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        _: BoxStream,
        _: IngressBinding,
        _: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("WireGuard节点仅接受UDP载体")) })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.run(socket, ingress, context))
    }
}

struct Peer {
    slot: CredentialSlot,
    config: PeerConfig,
    crypto: CryptoPeer,
    fragments: Reassembler,
    runtime: Option<RuntimePeer>,
    sent_in_window: usize,
}
pub(crate) struct RuntimePeer {
    stack: Arc<SharedStack>,
    access: PeerSession,
    context: InboundContext,
    udp: HashMap<SocketAddr, UdpFlow>,
    last_seen: Instant,
    _lease: StreamLease,
}
struct UdpFlow {
    sender: mpsc::Sender<flows::PendingDatagram>,
    used: Instant,
}
impl RuntimePeer {
    pub(crate) fn from_tunnel(
        stack: Arc<SharedStack>,
        access: PeerSession,
        context: InboundContext,
        lease: StreamLease,
    ) -> Self {
        Self {
            stack,
            access,
            context,
            udp: HashMap::new(),
            last_seen: Instant::now(),
            _lease: lease,
        }
    }
    pub(crate) fn receive(
        &mut self,
        allowed: &[crate::config::Network],
        fragments: &mut Reassembler,
        bytes: &[u8],
    ) -> Result<()> {
        self.udp.retain(|_, flow| !flow.sender.is_closed());
        self.last_seen = Instant::now();
        accept_packet(self, allowed, fragments, bytes)
    }
    pub(crate) fn active_flows(&self) -> usize {
        self.stack.flow_count()
            + self
                .udp
                .values()
                .filter(|flow| !flow.sender.is_closed())
                .count()
    }
}
impl Drop for RuntimePeer {
    fn drop(&mut self) {
        self.context.cancel.cancel();
        self.stack.close();
        self.context.events.record(NodeEvent::Completed);
    }
}

impl WireGuardNode {
    async fn run(
        &self,
        socket: Arc<UdpSocket>,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        if !ingress.supports_udp_association() {
            return Err(Error::Unsupported("WireGuard节点需要真实多目标UDP关联"));
        }
        let configs = self
            .credentials
            .rows()
            .map(|(_, config)| config.clone())
            .collect::<Vec<_>>();
        let index = PeerIndex::new(&self.prepared, &configs);
        let fragment_budget = FragmentBudget::new(
            self.prepared.limits.fragment_packets,
            self.prepared.limits.fragment_bytes,
        );
        let budget = PacketBudget::new(
            self.prepared.limits.queue_packets,
            self.prepared.limits.queue_bytes,
        );
        let notify = Arc::new(Notify::new());
        let carrier = Carrier::Node(ingress.clone());
        let mut peers = self
            .credentials
            .rows()
            .enumerate()
            .map(|(number, (slot, config))| Peer {
                slot,
                config: config.clone(),
                crypto: CryptoPeer::new(
                    &self.prepared,
                    config,
                    number as u32 + 1,
                    None,
                    index.limiter.clone(),
                ),
                fragments: Reassembler::new(fragment_budget.clone()),
                runtime: None,
                sent_in_window: 0,
            })
            .collect::<Vec<_>>();
        let sock_ref = socket2::SockRef::from(&*socket);
        let _ = sock_ref.set_recv_buffer_size(8 * 1024 * 1024);
        let _ = sock_ref.set_send_buffer_size(8 * 1024 * 1024);
        let (rx_tx, mut rx_rx) =
            tokio::sync::mpsc::channel::<std::io::Result<(Vec<u8>, SocketAddr)>>(4096);
        let rx_socket = socket.clone();
        let rx_cancel = context.cancel.clone();
        tokio::spawn(async move {
            let mut input = vec![0; 65536];
            loop {
                let first = tokio::select! {
                    biased;
                    _ = rx_cancel.cancelled() => break,
                    res = rx_socket.recv_from(&mut input) => match res {
                        Ok((count, source)) => Ok((input[..count].to_vec(), source)),
                        Err(error) => Err(error),
                    },
                };
                let is_fatal = first.as_ref().is_err_and(|e| !is_peer_path_error(e));
                if rx_tx.send(first).await.is_err() || is_fatal {
                    break;
                }
                for _ in 0..64 {
                    match rx_socket.try_recv_from(&mut input) {
                        Ok((count, source)) => {
                            if rx_tx
                                .try_send(Ok((input[..count].to_vec(), source)))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        });
        let mut timer = tokio::time::interval(Duration::from_millis(1));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut tick_mod = 0u8;
        loop {
            tokio::select! { biased;
                _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                _ = timer.tick() => {
                    for peer in &mut peers {
                        peer.sent_in_window = 0;
                    }
                    tick_mod = tick_mod.wrapping_add(1);
                    if tick_mod & 15 == 0 {
                        index.limiter.reset_count();
                        for peer in &mut peers {
                            peer.fragments.expire(Instant::now());
                            if let Some(packet) = peer.crypto.tick()
                                && let Some(endpoint) = peer.crypto.endpoint
                            { send_or_drop(&socket, endpoint, &packet, &context, &carrier).await; }
                        }
                    }
                }
                maybe_pkt = rx_rx.recv() => {
                    let Some(result) = maybe_pkt else { return Err(Error::Cancelled); };
                    let mut next_pkt = match result {
                        Ok(value) => Some(value),
                        Err(error) if is_peer_path_error(&error) => { context.events.record(NodeEvent::Dropped); None }
                        Err(error) => return Err(error.into()),
                    };
                    let mut batch = 0usize;
                    while let Some((pkt, source)) = next_pkt {
                        let count = pkt.len();
                        carrier.record(0, count);
                        if let Ok(identified) = index.identify(source, &pkt) {
                            match identified {
                                Identified::Cookie(packet) => {
                                    send_or_drop(&socket, source, &packet, &context, &carrier).await;
                                }
                                Identified::Peer(selected) => {
                                    let peer = &mut peers[selected];
                                    peer.sent_in_window = peer.sent_in_window.saturating_sub(1);
                                    if let Ok(received) = peer.crypto.receive(source, &pkt) {
                                        for packet in received.network {
                                            send_or_drop(&socket, source, &packet, &context, &carrier).await;
                                        }
                                        if received.authenticated {
                                            if peer.runtime.is_none() {
                                                let runtime = self.admit_peer(peer, source, &ingress, &context, notify.clone(), budget.clone());
                                                match runtime {
                                                    Ok(runtime) => peer.runtime = Some(runtime),
                                                    Err(_) => { context.events.record(NodeEvent::Dropped); }
                                                }
                                            }
                                            if let Some(runtime) = &mut peer.runtime {
                                                runtime.last_seen = Instant::now();
                                            }
                                        }
                                        if let Some(bytes) = received.plain
                                            && let Some(runtime) = &mut peer.runtime
                                            && let Err(error) = accept_packet(runtime, &peer.config.allowed, &mut peer.fragments, &bytes)
                                        {
                                            runtime.context.events.record(if matches!(error, Error::Cancelled) { NodeEvent::Failed } else { NodeEvent::Dropped });
                                        }
                                    } else {
                                        context.events.record(NodeEvent::Dropped);
                                    }
                                }
                            }
                        } else {
                            context.events.record(NodeEvent::Dropped);
                        }
                        batch += 1;
                        if batch >= 64 {
                            break;
                        }
                        next_pkt = match rx_rx.try_recv() {
                            Ok(Ok(v)) => Some(v),
                            Ok(Err(error)) if is_peer_path_error(&error) => { context.events.record(NodeEvent::Dropped); None }
                            Ok(Err(error)) => return Err(error.into()),
                            Err(_) => None,
                        };
                    }
                }
                _ = notify.notified() => {}
            }
            for peer in &mut peers {
                let Some(runtime) = &mut peer.runtime else {
                    continue;
                };
                runtime.udp.retain(|_, flow| !flow.sender.is_closed());
                if runtime.context.cancel.is_cancelled() {
                    peer.runtime = None;
                    continue;
                }
                let budget = if peer.crypto.ready() {
                    32usize.saturating_sub(peer.sent_in_window)
                } else {
                    1
                };
                runtime.stack.poll_with_budget(budget)?;
                if runtime.stack.has_output()
                    && !peer.crypto.ready()
                    && let Some(packet) = peer.crypto.initiate()
                    && let Some(endpoint) = peer.crypto.endpoint
                {
                    send_or_drop(&socket, endpoint, &packet, &context, &carrier).await;
                }
                if peer.crypto.ready() {
                    for packet in runtime.stack.drain(usize::MAX)? {
                        peer.sent_in_window += 1;
                        if !peer.config.allows(IpPacket::parse(&packet)?.target) {
                            continue;
                        }
                        if let Some(packet) = peer.crypto.encrypt(&packet)?
                            && let Some(endpoint) = peer.crypto.endpoint
                        {
                            send_or_drop(&socket, endpoint, &packet, &context, &carrier).await;
                        }
                    }
                }
                if runtime.udp.is_empty()
                    && runtime.stack.flow_count() == 0
                    && runtime.last_seen.elapsed() >= self.prepared.limits.udp_idle()
                {
                    peer.runtime = None;
                }
            }
        }
    }
    fn admit_peer(
        &self,
        peer: &Peer,
        source: SocketAddr,
        ingress: &IngressBinding,
        context: &InboundContext,
        notify: Arc<Notify>,
        budget: PacketBudget,
    ) -> Result<RuntimePeer> {
        let lease = context.stream_budget.try_acquire()?;
        let mut peer_context = context.clone();
        peer_context.cancel = context.cancel.child_token();
        peer_context.peer_addr = Some(source);
        let verified = self.credentials.verified(&peer.slot, ())?;
        let (access, ()) = ingress.authenticated(verified, &peer_context)?;
        let stack = SharedStack::new(
            &self.prepared,
            peer_context.cancel.clone(),
            notify,
            peer.config.allowed.clone(),
            budget,
        )?;
        context.events.record(NodeEvent::Accepted);
        Ok(RuntimePeer {
            stack,
            access,
            context: peer_context,
            udp: HashMap::new(),
            last_seen: Instant::now(),
            _lease: lease,
        })
    }
}

/// 目的地址来自远端（来源端口可为 0，路径可不可达），发送失败只损失这一个数据报。
async fn send_or_drop(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    packet: &[u8],
    context: &InboundContext,
    carrier: &Carrier,
) {
    if send(socket, endpoint, packet, &context.cancel, carrier)
        .await
        .is_err()
    {
        context.events.record(NodeEvent::Dropped);
    }
}

fn accept_packet(
    peer: &mut RuntimePeer,
    allowed: &[crate::config::Network],
    fragments: &mut Reassembler,
    bytes: &[u8],
) -> Result<()> {
    let packet = IpPacket::parse(bytes)?;
    if !allowed
        .iter()
        .any(|network| network.contains(packet.source))
    {
        return Err(Error::Rejected);
    }
    peer.stack.addresses.for_target(packet.target)?;
    let Some(bytes) = fragments.accept(bytes, Instant::now())? else {
        return Ok(());
    };
    let packet = IpPacket::parse(&bytes)?;
    match packet.protocol {
        6 => accept_tcp(peer, bytes),
        17 => accept_udp(peer, &packet),
        1 | 58 => {
            if let Some(reply) = control_reply(&bytes, &peer.stack.addresses)? {
                peer.stack.queue_packet(reply)?;
            }
            Ok(())
        }
        _ => {
            if let Some(reply) = unreachable(&bytes, &peer.stack.addresses)? {
                peer.stack.queue_packet(reply)?;
            }
            Err(Error::Unsupported("WireGuard节点不转发该IP协议"))
        }
    }
}
fn flow_table_full(peer: &RuntimePeer) -> bool {
    peer.stack.flow_count() + peer.udp.len()
        >= peer.stack.limits.max_flows.min(peer.context.max_streams)
}
/// 流表满时腾出一个位置：先回收只剩挥手的已关闭 TCP 流，再让最久未用的 UDP 来源让位
/// （DNS 这类一次性查询每次换来源端口，等空闲超时才释放会挡住所有新流）。
/// 被移除的 UDP 流在通道关闭后结束并归还会话额度。
fn make_room(peer: &mut RuntimePeer) -> bool {
    if peer.stack.reclaim_closed_tcp() {
        return true;
    }
    if let Some(oldest) = peer
        .udp
        .iter()
        .min_by_key(|(_, flow)| flow.used)
        .map(|(source, _)| *source)
    {
        peer.udp.remove(&oldest);
        return true;
    }
    false
}
fn accept_tcp(peer: &mut RuntimePeer, bytes: Vec<u8>) -> Result<()> {
    let packet = IpPacket::parse(&bytes)?;
    let tuple = packet.tcp_tuple()?;
    if peer.stack.contains_tcp(&tuple) {
        return peer.stack.input_tcp(bytes);
    }
    if packet.tcp_syn()?.is_none() {
        if let Some(reset) = tcp_reset(&bytes)? {
            peer.stack.queue_packet(reset)?;
        }
        return Ok(());
    }
    if flow_table_full(peer) && !make_room(peer) {
        if let Some(reset) = tcp_reset(&bytes)? {
            peer.stack.queue_packet(reset)?;
        }
        return Err(Error::ResourceLimit);
    }
    let lease = peer.context.stream_budget.try_acquire()?;
    let stream = TcpStream::accept(peer.stack.clone(), tuple, peer.context.cancel.clone())?;
    peer.stack.input_tcp(bytes)?;
    peer.stack.poll()?;
    let access = if peer.context.peer_addr.is_none() {
        peer.access.with_observed_source(tuple.source)
    } else {
        peer.access.clone()
    };
    let context = peer.context.clone();
    let target_addr = if peer.stack.addresses.contains(tuple.target.ip()) {
        let local_ip = if tuple.target.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        };
        SocketAddr::new(local_ip, tuple.target.port())
    } else {
        tuple.target
    };
    let target = destination(target_addr)?;
    let events = context.events.clone();
    let owner = context.tasks.clone();
    owner.spawn(async move {
        flows::tcp(stream, access, target, context, lease).await;
    })?;
    events.record(NodeEvent::Accepted);
    Ok(())
}
fn accept_udp(peer: &mut RuntimePeer, packet: &IpPacket<'_>) -> Result<()> {
    let (tuple, payload) = packet.udp()?;
    if payload.len() > peer.context.max_datagram_size {
        return Err(Error::ResourceLimit);
    }
    let mut pending = flows::PendingDatagram {
        target: tuple.target,
        packet: peer.stack.budget.packet(payload.to_vec(), false)?,
    };
    if let Some(flow) = peer.udp.get_mut(&tuple.source) {
        match flow.sender.try_send(pending) {
            Ok(()) => {
                flow.used = Instant::now();
                return Ok(());
            }
            Err(mpsc::error::TrySendError::Full(_)) => return Err(Error::ResourceLimit),
            Err(mpsc::error::TrySendError::Closed(packet)) => pending = packet,
        }
        peer.udp.remove(&tuple.source);
    }
    if flow_table_full(peer) && !make_room(peer) {
        return Err(Error::ResourceLimit);
    }
    let lease = peer.context.stream_budget.try_acquire()?;
    let (sender, packets) = mpsc::channel(peer.stack.limits.queue_packets);
    sender.try_send(pending).map_err(|_| Error::ResourceLimit)?;
    let stack = peer.stack.clone();
    let access = if peer.context.peer_addr.is_none() {
        peer.access.with_observed_source(tuple.source)
    } else {
        peer.access.clone()
    };
    let context = peer.context.clone();
    let events = context.events.clone();
    let owner = context.tasks.clone();
    owner.spawn(async move {
        flows::udp(stack, tuple.source, packets, access, context, lease).await;
    })?;
    peer.udp.insert(
        tuple.source,
        UdpFlow {
            sender,
            used: Instant::now(),
        },
    );
    events.record(NodeEvent::Accepted);
    Ok(())
}
