//! 单任务数据面：持有全部对端会话与路径状态，在隧道、UDP、DERP 与 netmap 之间转发。

use crate::{
    config::Prepared,
    control::LocalState,
    derp::{self, Received, RegionHandle},
    disco::{self, DERP_MAGIC_IP, Message},
    keys::{DiscoKey, NodeKey, Secret},
    netmap::{DerpMap, DerpRegion, NetMap, Routes},
    stun,
};
use kerlico_core::{Error, Result, ServiceContext};
use kerlico_wireguard::ip::{ClientTunnel, PacketClassifier, PacketRoute, PeerCrypto};
use rand::{RngCore, rngs::OsRng};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket, lookup_host},
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval, timeout},
};

/// 与上游 magicsock 相同的路径节奏。
const PING_INTERVAL: Duration = Duration::from_secs(5);
const TRUST_DIRECT: Duration = Duration::from_millis(6500);
const SESSION_ACTIVE: Duration = Duration::from_secs(45);
const STUN_INTERVAL: Duration = Duration::from_secs(25);
const HOME_PROBE: Duration = Duration::from_secs(3);
const HOME_RETRY: Duration = Duration::from_secs(30);
const MAX_CANDIDATES: usize = 32;
const INBOUND_QUEUE: usize = 1024;

struct DirectPath {
    address: SocketAddr,
    latency: Duration,
    trusted_until: Instant,
}

struct Peer {
    crypto: PeerCrypto,
    index: u32,
    disco: Option<DiscoKey>,
    home_derp: Option<i32>,
    /// netmap 给出的端点。
    advertised: Vec<SocketAddr>,
    /// 经 CallMeMaybe 或对端 Ping 来源学到的端点。
    learned: Vec<SocketAddr>,
    direct: Option<DirectPath>,
    pings: HashMap<[u8; 12], (SocketAddr, Instant)>,
    last_ping: Option<Instant>,
    last_active: Option<Instant>,
}
impl Peer {
    fn live_direct(&self, now: Instant) -> Option<SocketAddr> {
        self.direct
            .as_ref()
            .filter(|path| path.trusted_until > now)
            .map(|path| path.address)
    }
    fn candidates(&self) -> Vec<SocketAddr> {
        let mut seen = HashSet::new();
        self.advertised
            .iter()
            .chain(&self.learned)
            .copied()
            .filter(|address| seen.insert(*address))
            .take(MAX_CANDIDATES)
            .collect()
    }
    fn learn(&mut self, addresses: impl IntoIterator<Item = SocketAddr>) {
        for address in addresses {
            if !self.learned.contains(&address) {
                if self.learned.len() == MAX_CANDIDATES {
                    self.learned.remove(0);
                }
                self.learned.push(address);
            }
        }
    }
}

/// 收到数据包的路径；决定回复走哪里。
#[derive(Clone, Copy)]
enum Origin {
    Udp(SocketAddr),
    Derp { region: i32, source: NodeKey },
}

/// 后台探测结果；探测不阻塞数据面。
struct HomeChoice {
    region: i32,
    stun_target: Option<SocketAddr>,
    local_ip: Option<IpAddr>,
}

pub struct Dataplane {
    pub prepared: Prepared,
    pub node: Secret,
    pub disco: Secret,
    pub tunnel: ClientTunnel,
    pub host: ServiceContext,
    pub udp4: Option<UdpSocket>,
    pub udp6: Option<UdpSocket>,
    pub netmap: watch::Receiver<Option<Arc<NetMap>>>,
    pub local: watch::Sender<LocalState>,
    pub routes: watch::Sender<Routes>,
    pub addresses: Vec<IpAddr>,
}

struct State {
    peers: HashMap<NodeKey, Peer>,
    by_index: HashMap<u32, NodeKey>,
    by_disco: HashMap<DiscoKey, NodeKey>,
    next_index: u32,
    routes: Routes,
    derp_map: DerpMap,
    regions: BTreeMap<i32, RegionHandle>,
    home: Option<i32>,
    home_probing: bool,
    last_home_probe: Option<Instant>,
    home_sender: mpsc::Sender<Option<HomeChoice>>,
    derp_sender: mpsc::Sender<Received>,
    stun_target: Option<SocketAddr>,
    stun_probe: StunProbe,
    last_stun: Option<Instant>,
    classifier: PacketClassifier,
}

/// 唯一在途的 STUN 请求。回应决定上报给控制面的端点，所以只接受被询问的服务器对这次请求的回应。
#[derive(Default)]
struct StunProbe(Option<(SocketAddr, [u8; 12])>);
impl StunProbe {
    fn start(&mut self, target: SocketAddr) -> [u8; 12] {
        let mut tx = [0; 12];
        OsRng.fill_bytes(&mut tx);
        self.0 = Some((target, tx));
        tx
    }
    fn accept(&mut self, source: SocketAddr, packet: &[u8]) -> Option<SocketAddr> {
        let (tx, mapped) = stun::parse_response(packet)?;
        if self.0 != Some((source, tx)) {
            return None;
        }
        self.0 = None;
        Some(mapped)
    }
}

impl Dataplane {
    pub async fn run(mut self) -> Result<()> {
        let cancel = self.host.cancel();
        let (derp_sender, mut derp_receiver) = mpsc::channel(INBOUND_QUEUE);
        let (home_sender, mut home_receiver) = mpsc::channel(1);
        let mut state = State {
            peers: HashMap::new(),
            by_index: HashMap::new(),
            by_disco: HashMap::new(),
            next_index: 1,
            routes: Routes::default(),
            derp_map: DerpMap::default(),
            regions: BTreeMap::new(),
            home: None,
            home_probing: false,
            last_home_probe: None,
            home_sender,
            derp_sender,
            stun_target: None,
            stun_probe: StunProbe::default(),
            last_stun: None,
            classifier: PacketClassifier::new(self.node.bytes()),
        };
        self.reconcile(&mut state).await?;
        let mut timer = interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut buffer4 = vec![0; 65536];
        let mut buffer6 = vec![0; 65536];
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = timer.tick() => self.tick(&mut state).await,
                changed = self.netmap.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    self.reconcile(&mut state).await?;
                }
                choice = home_receiver.recv() => {
                    let Some(choice) = choice else { return Ok(()) };
                    self.on_home(&mut state, choice);
                }
                received = derp_receiver.recv() => {
                    let Some(received) = received else { return Ok(()) };
                    self.on_derp(&mut state, received).await;
                }
                received = receive(self.udp4.as_ref(), &mut buffer4) => {
                    if let Ok((count, source)) = received {
                        self.on_udp(&mut state, source, &buffer4[..count]).await;
                    }
                }
                received = receive(self.udp6.as_ref(), &mut buffer6) => {
                    if let Ok((count, source)) = received {
                        self.on_udp(&mut state, source, &buffer6[..count]).await;
                    }
                }
                packet = self.tunnel.next_packet() => self.outgoing(&mut state, &packet?).await,
            }
        }
    }

    async fn outgoing(&self, state: &mut State, packet: &[u8]) {
        let Some(key) = ip_destination(packet).and_then(|ip| state.routes.lookup(ip)) else {
            return;
        };
        let Some(peer) = state.peers.get_mut(&key) else {
            return;
        };
        peer.last_active = Some(Instant::now());
        // 没有会话时 boringtun 缓存该包并返回握手发起。
        if let Ok(Some(wire)) = peer.crypto.encrypt(packet) {
            self.send_wire(state, key, wire).await;
        }
        self.heartbeat(state, key).await;
    }

    async fn on_derp(&self, state: &mut State, received: Received) {
        let Received {
            region,
            source,
            packet,
        } = received;
        if disco::is_disco(&packet) {
            self.on_disco(state, Origin::Derp { region, source }, &packet)
                .await;
        } else {
            let magic = SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), region as u16);
            self.on_wireguard(state, source, magic, &packet).await;
        }
    }

    async fn on_udp(&self, state: &mut State, source: SocketAddr, packet: &[u8]) {
        self.host.record_carrier(0, packet.len() as u64);
        if disco::is_disco(packet) {
            self.on_disco(state, Origin::Udp(canonical(source)), packet)
                .await;
        } else if stun::is_stun(packet) {
            self.on_stun(state, canonical(source), packet);
        } else {
            let key = match state.classifier.classify(source.ip(), packet) {
                Some(PacketRoute::Initiator(public)) => Some(NodeKey(public)),
                Some(PacketRoute::Index(index)) => state.by_index.get(&index).copied(),
                Some(PacketRoute::CookieReply(cookie)) => {
                    self.send_udp(source, &cookie).await;
                    None
                }
                None => None,
            };
            if let Some(key) = key {
                self.on_wireguard(state, key, canonical(source), packet)
                    .await;
            }
        }
    }

    async fn on_wireguard(
        &self,
        state: &mut State,
        key: NodeKey,
        source: SocketAddr,
        packet: &[u8],
    ) {
        let Some(peer) = state.peers.get_mut(&key) else {
            return;
        };
        let Ok(received) = peer.crypto.receive(source, packet) else {
            return;
        };
        peer.last_active = Some(Instant::now());
        for wire in received.network {
            self.send_wire(state, key, wire).await;
        }
        if let Some(plain) = received.plain
            && ip_source(&plain).and_then(|ip| state.routes.lookup(ip)) == Some(key)
        {
            let _ = self.tunnel.receive(&plain);
        }
    }

    async fn on_disco(&self, state: &mut State, origin: Origin, packet: &[u8]) {
        // 解封要做一次 DH；发送方公钥是明文，先按 netmap 过滤，陌生来源不消耗数据面。
        let Some(&key) = disco::sender(packet).and_then(|sender| state.by_disco.get(&sender))
        else {
            return;
        };
        let Some((sender, message)) = disco::open(&self.disco, packet) else {
            return;
        };
        match (message, origin) {
            (Message::Ping { tx, node }, Origin::Udp(source)) if node == key => {
                self.send_disco_udp(sender, source, &Message::Pong { tx, source })
                    .await;
                if let Some(peer) = state.peers.get_mut(&key) {
                    peer.learn([source]);
                }
            }
            (Message::Ping { tx, .. }, Origin::Derp { region, source }) if source == key => {
                let magic = SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), region as u16);
                let pong = Message::Pong { tx, source: magic };
                if let Ok(sealed) = disco::seal(&self.disco, &sender, &pong) {
                    self.send_derp(state, key, sealed);
                }
            }
            (Message::Pong { tx, .. }, Origin::Udp(source)) => {
                let Some(peer) = state.peers.get_mut(&key) else {
                    return;
                };
                if peer
                    .pings
                    .get(&tx)
                    .is_some_and(|(sent_to, _)| *sent_to == source)
                    && let Some((_, sent)) = peer.pings.remove(&tx)
                {
                    let now = Instant::now();
                    let latency = now - sent;
                    let keep_current = peer.direct.as_ref().is_some_and(|path| {
                        path.address != source
                            && path.trusted_until > now
                            && path.latency <= latency
                    });
                    if !keep_current {
                        peer.direct = Some(DirectPath {
                            address: source,
                            latency,
                            trusted_until: now + TRUST_DIRECT,
                        });
                    }
                }
            }
            (Message::CallMeMaybe { endpoints }, Origin::Derp { source, .. }) if source == key => {
                if let Some(peer) = state.peers.get_mut(&key) {
                    peer.learn(endpoints);
                    peer.last_ping = None;
                }
                self.heartbeat(state, key).await;
            }
            _ => {}
        }
    }

    fn on_stun(&self, state: &mut State, source: SocketAddr, packet: &[u8]) {
        let Some(mapped) = state.stun_probe.accept(source, packet) else {
            return;
        };
        self.local.send_if_modified(|local| {
            let stun = vec![mapped];
            let changed = local.stun != stun;
            local.stun = stun;
            changed
        });
    }

    /// 有业务活动时周期探测直连端点，并经 DERP 请对端反向探测以打洞。
    async fn heartbeat(&self, state: &mut State, key: NodeKey) {
        if !self.prepared.direct {
            return;
        }
        let now = Instant::now();
        let Some(peer) = state.peers.get_mut(&key) else {
            return;
        };
        let Some(disco_key) = peer.disco else {
            return;
        };
        if peer
            .last_ping
            .is_some_and(|last| now - last < PING_INTERVAL)
        {
            return;
        }
        peer.last_ping = Some(now);
        let node = NodeKey(self.node.public());
        let mut pings = Vec::new();
        for address in peer.candidates() {
            let mut tx = [0; 12];
            OsRng.fill_bytes(&mut tx);
            peer.pings.insert(tx, (address, now));
            pings.push((address, Message::Ping { tx, node }));
        }
        let direct_is_live = peer.live_direct(now).is_some();
        for (address, ping) in pings {
            self.send_disco_udp(disco_key, address, &ping).await;
        }
        if !direct_is_live {
            let endpoints: Vec<_> = self.local.borrow().endpoints().collect();
            if !endpoints.is_empty()
                && let Ok(sealed) =
                    disco::seal(&self.disco, &disco_key, &Message::CallMeMaybe { endpoints })
            {
                self.send_derp(state, key, sealed);
            }
        }
    }

    async fn send_disco_udp(&self, peer: DiscoKey, address: SocketAddr, message: &Message) {
        if let Ok(sealed) = disco::seal(&self.disco, &peer, message) {
            self.send_udp(address, &sealed).await;
        }
    }

    async fn send_wire(&self, state: &mut State, key: NodeKey, wire: Vec<u8>) {
        let direct = state
            .peers
            .get(&key)
            .and_then(|peer| peer.live_direct(Instant::now()));
        match direct {
            Some(address) => self.send_udp(address, &wire).await,
            None => self.send_derp(state, key, wire),
        }
    }

    async fn send_udp(&self, address: SocketAddr, packet: &[u8]) {
        let socket = if address.is_ipv4() {
            &self.udp4
        } else {
            &self.udp6
        };
        if let Some(socket) = socket
            && let Ok(count) = socket.send_to(packet, address).await
        {
            self.host.record_carrier(count as u64, 0);
        }
    }

    fn send_derp(&self, state: &mut State, key: NodeKey, packet: Vec<u8>) {
        let Some(region) = state.peers.get(&key).and_then(|peer| peer.home_derp) else {
            return;
        };
        if let Some(handle) = self.region(state, region) {
            handle.send(key, packet);
        }
    }

    fn region<'a>(&self, state: &'a mut State, region: i32) -> Option<&'a RegionHandle> {
        let definition = state.derp_map.regions.get(&region)?.clone();
        if !state.regions.contains_key(&region) {
            let handle = derp::spawn_region(
                &self.host,
                &self.prepared,
                definition,
                self.node.clone(),
                state.home == Some(region),
                state.derp_sender.clone(),
            )
            .ok()?;
            state.regions.insert(region, handle);
        }
        state.regions.get(&region)
    }

    async fn tick(&self, state: &mut State) {
        let now = Instant::now();
        state.classifier.reset_count();
        let mut outgoing = Vec::new();
        let mut active = Vec::new();
        for (key, peer) in &mut state.peers {
            if let Some(wire) = peer.crypto.tick() {
                outgoing.push((*key, wire));
            }
            peer.pings
                .retain(|_, (_, sent)| now - *sent < PING_INTERVAL);
            if peer
                .last_active
                .is_some_and(|last| now - last < SESSION_ACTIVE)
            {
                active.push(*key);
            }
        }
        for (key, wire) in outgoing {
            self.send_wire(state, key, wire).await;
        }
        for key in active {
            self.heartbeat(state, key).await;
        }
        if state.home.is_none()
            && state
                .last_home_probe
                .is_none_or(|last| now - last >= HOME_RETRY)
        {
            self.probe_home(state);
        }
        if let (Some(target), Some(socket)) = (state.stun_target, &self.udp4)
            && state
                .last_stun
                .is_none_or(|last| now - last >= STUN_INTERVAL)
        {
            state.last_stun = Some(now);
            let tx = state.stun_probe.start(target);
            let _ = socket.send_to(&stun::request(&tx), target).await;
        }
    }

    async fn reconcile(&mut self, state: &mut State) -> Result<()> {
        let Some(map) = self.netmap.borrow_and_update().clone() else {
            return Ok(());
        };
        if map.own_addresses() != self.addresses {
            return Err(Error::Protocol("Tailscale节点地址已变化，需要重启出站"));
        }
        let mut seen = HashSet::new();
        for node in map.usable_peers() {
            let Some(key) = node.key else { continue };
            seen.insert(key);
            let peer = state.peers.entry(key).or_insert_with(|| {
                let index = state.next_index;
                state.next_index += 1;
                Peer {
                    crypto: state.classifier.peer(key.0, index),
                    index,
                    disco: None,
                    home_derp: None,
                    advertised: Vec::new(),
                    learned: Vec::new(),
                    direct: None,
                    pings: HashMap::new(),
                    last_ping: None,
                    last_active: None,
                }
            });
            let disco = node.disco.filter(|disco| !disco.is_zero());
            if peer.disco != disco {
                peer.direct = None;
                peer.learned.clear();
                peer.disco = disco;
            }
            peer.home_derp = node.derp_region();
            peer.advertised = node.endpoints.clone();
        }
        state.peers.retain(|key, _| seen.contains(key));
        state.by_index = state
            .peers
            .iter()
            .map(|(key, peer)| (peer.index, *key))
            .collect();
        state.by_disco = state
            .peers
            .iter()
            .filter_map(|(key, peer)| Some((peer.disco?, *key)))
            .collect();
        state.routes = map.routes(&self.prepared.routes);
        self.routes.send_replace(state.routes.clone());
        if map.derp != state.derp_map {
            state.derp_map = map.derp.clone();
            let regions = &state.derp_map.regions;
            state
                .regions
                .retain(|id, handle| regions.get(id) == Some(handle.region()));
            if state.home.is_some_and(|home| !regions.contains_key(&home)) {
                state.home = None;
            }
            match state.home {
                Some(home) => {
                    self.region(state, home);
                }
                None => self.probe_home(state),
            }
        }
        Ok(())
    }

    fn probe_home(&self, state: &mut State) {
        if state.home_probing {
            return;
        }
        let regions: Vec<DerpRegion> = state
            .derp_map
            .regions
            .values()
            .filter(|region| !region.avoid && !region.no_home)
            .cloned()
            .collect();
        if regions.is_empty() {
            return;
        }
        let sender = state.home_sender.clone();
        let spawned = self.host.spawn(async move {
            let _ = sender.send(probe_regions(regions).await).await;
        });
        if spawned.is_ok() {
            state.home_probing = true;
            state.last_home_probe = Some(Instant::now());
        }
    }

    fn on_home(&self, state: &mut State, choice: Option<HomeChoice>) {
        state.home_probing = false;
        let Some(choice) = choice else { return };
        if state.home.is_some() || !state.derp_map.regions.contains_key(&choice.region) {
            return;
        }
        // 已作为对端区域连接的句柄未声明首选，需要按首选重建。
        state.regions.remove(&choice.region);
        state.home = Some(choice.region);
        self.region(state, choice.region);
        state.stun_target = self.udp4.as_ref().and(choice.stun_target);
        state.last_stun = None;
        let port = self
            .udp4
            .as_ref()
            .and_then(|socket| socket.local_addr().ok());
        let local = match (choice.local_ip, port) {
            (Some(ip), Some(bound)) => vec![SocketAddr::new(ip, bound.port())],
            _ => Vec::new(),
        };
        self.local.send_modify(|local_state| {
            local_state.home_derp = choice.region;
            local_state.local = local;
        });
    }
}

async fn receive(socket: Option<&UdpSocket>, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => std::future::pending().await,
    }
}

/// 以 TCP 建连耗时代替上游 netcheck 的 STUN 延迟，先建连者作为首选区域。
async fn probe_regions(regions: Vec<DerpRegion>) -> Option<HomeChoice> {
    let mut probes = JoinSet::new();
    for region in regions {
        let Some(node) = region.nodes.into_iter().find(|node| !node.stun_only) else {
            continue;
        };
        let id = region.id;
        probes.spawn(async move {
            let port = node.tls_port()?;
            for host in node.dial_hosts() {
                let connect = TcpStream::connect((host.as_str(), port));
                if matches!(timeout(HOME_PROBE, connect).await, Ok(Ok(_))) {
                    return Some((id, node));
                }
            }
            None
        });
    }
    let (region, node) = loop {
        if let Ok(Some(found)) = probes.join_next().await? {
            break found;
        }
    };
    let target = (
        node.dial_hosts().first()?.clone(),
        node.stun_port().unwrap_or(3478),
    );
    let resolved = timeout(HOME_PROBE, lookup_host(target))
        .await
        .ok()
        .and_then(std::result::Result::ok)
        .and_then(|mut addresses| addresses.find(SocketAddr::is_ipv4));
    let local_ip = match resolved {
        Some(target) => outbound_ip(target).await,
        None => None,
    };
    Some(HomeChoice {
        region,
        stun_target: resolved.filter(|_| node.stun_port().is_some()),
        local_ip,
    })
}

/// 不发送数据的已连接 UDP 套接字由路由表选出本机对外地址。
async fn outbound_ip(target: SocketAddr) -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    socket.connect(target).await.ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

fn ip_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => {
            let octets: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 => {
            let octets: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}
fn ip_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => {
            let octets: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 => {
            let octets: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_headers_yield_source_and_destination() {
        let mut v4 = vec![0x45; 20];
        v4[12..16].copy_from_slice(&[100, 64, 0, 1]);
        v4[16..20].copy_from_slice(&[100, 64, 0, 2]);
        assert_eq!(ip_source(&v4), Some("100.64.0.1".parse().unwrap()));
        assert_eq!(ip_destination(&v4), Some("100.64.0.2".parse().unwrap()));
        let mut v6 = vec![0x60; 40];
        v6[8..24].copy_from_slice(&"fd7a::1".parse::<Ipv6Addr>().unwrap().octets());
        v6[24..40].copy_from_slice(&"fd7a::2".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(ip_source(&v6), Some("fd7a::1".parse().unwrap()));
        assert_eq!(ip_destination(&v6), Some("fd7a::2".parse().unwrap()));
        assert_eq!(ip_destination(&[0x45; 8]), None);
    }

    fn stun_response(tx: &[u8; 12]) -> Vec<u8> {
        let mut packet = vec![1, 1, 0, 12, 0x21, 0x12, 0xa4, 0x42];
        packet.extend_from_slice(tx);
        packet.extend_from_slice(&[0, 0x20, 0, 8, 0, 1, 0xc7, 0x86, 0x69, 0x57, 0x85, 0x6f]);
        packet
    }

    #[test]
    fn stun_response_counts_only_for_the_outstanding_request_from_its_server() {
        let server: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:3478".parse().unwrap();
        let mut probe = StunProbe::default();
        assert_eq!(probe.accept(server, &stun_response(&[0; 12])), None);
        let tx = probe.start(server);
        assert_ne!(tx, [0; 12]);
        assert_eq!(probe.accept(server, &stun_response(&[0; 12])), None);
        assert_eq!(probe.accept(other, &stun_response(&tx)), None);
        let mapped = "72.69.33.45:59028".parse().unwrap();
        assert_eq!(probe.accept(server, &stun_response(&tx)), Some(mapped));
        assert_eq!(probe.accept(server, &stun_response(&tx)), None);
    }
}
