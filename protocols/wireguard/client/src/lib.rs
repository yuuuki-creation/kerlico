use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};

use kerlico_shared::runtime::{Network, ResolutionSource, RuntimeContext};
use kerlico_shared::{
    Association, ClientEntry, DataPlane, Destination, InboundStream, OpenError, Packet, PeerAddr,
    PlaneFault, Settings, Transport,
};
use kerlico_wg::{Datagrams, IpNet, LinkPeer, PacketLink, PeerKeys, Pipe, Reserved, Tunnel};

#[cfg(feature = "tun-device")]
pub const CLIENT: ClientEntry =
    ClientEntry::PacketTunnel(connect, Some(run_tun), associate_landing);
#[cfg(not(feature = "tun-device"))]
pub const CLIENT: ClientEntry = ClientEntry::PacketTunnel(connect, None, associate_landing);

struct WireguardPlane(PacketLink);

impl DataPlane for WireguardPlane {
    fn send(&mut self, packet: Packet) -> Result<(), PlaneFault> {
        self.0.send(packet.into_bytes()).map_err(plane_error)
    }

    fn recv(&mut self) -> Result<Packet, PlaneFault> {
        let packet = self
            .0
            .recv_for(Duration::from_millis(200))
            .map_err(plane_error)?;
        Packet::from_ip_packet(packet).map_err(|_| PlaneFault::Transport)
    }
}

pub fn connect(peer: &PeerAddr, settings: &Settings) -> Result<Box<dyn DataPlane>, OpenError> {
    let (link, _) = open_link(peer.host(), peer.port(), settings)?;
    Ok(Box::new(WireguardPlane(link)))
}

struct PreparedLink {
    socket: UdpSocket,
    dual: bool,
    peers: Vec<LinkPeer>,
    mtu: u16,
    reserved: Reserved,
}

fn open_link(host: &str, port: u16, settings: &Settings) -> Result<(PacketLink, u16), OpenError> {
    let prepared = prepare_link(host, port, settings)?;
    let link = PacketLink::start_peers(
        prepared.socket,
        prepared.dual,
        prepared.peers,
        usize::from(prepared.mtu),
        prepared.reserved,
    )
    .map_err(link_error)?;
    Ok((link, prepared.mtu))
}

fn prepare_link(host: &str, port: u16, settings: &Settings) -> Result<PreparedLink, OpenError> {
    if settings.keys().any(|key| {
        !matches!(
            key,
            "privateKey"
                | "secretKey"
                | "publicKey"
                | "presharedKey"
                | "preSharedKey"
                | "persistentKeepalive"
                | "keepAlive"
                | "allowedIPs"
                | "mtu"
                | "reserved"
                | "localAddresses"
                | "peers"
        )
    }) {
        return Err(OpenError::Settings);
    }
    let private = key(setting(settings, "privateKey", "secretKey")?.ok_or(OpenError::Settings)?)?;
    let mtu: u16 = settings
        .optional_text("mtu")?
        .unwrap_or("1420")
        .parse()
        .map_err(|_| OpenError::Settings)?;
    let reserved = match settings.optional_text("reserved")? {
        Some(value) => {
            let bytes: Vec<u8> = serde_json::from_str(value).map_err(|_| OpenError::Settings)?;
            if bytes.is_empty() {
                Reserved::Standard
            } else {
                Reserved::Xray(bytes.try_into().map_err(|_| OpenError::Settings)?)
            }
        }
        None => Reserved::Standard,
    };
    let peer_field = |name: &str| {
        matches!(
            name,
            "publicKey"
                | "presharedKey"
                | "preSharedKey"
                | "persistentKeepalive"
                | "keepAlive"
                | "allowedIPs"
        )
    };
    let runtime = settings.runtime().map(Arc::as_ref);
    let mut peers = Vec::new();
    if let Some(value) = settings.optional_text("peers")? {
        if settings.keys().any(peer_field) {
            return Err(OpenError::Settings);
        }
        let list: Vec<serde_json::Map<String, serde_json::Value>> =
            serde_json::from_str(value).map_err(|_| OpenError::Settings)?;
        if list.is_empty() || list.len() > 32 {
            return Err(OpenError::Settings);
        }
        for (index, object) in list.into_iter().enumerate() {
            let mut peer = Settings::default();
            for (name, value) in &object {
                if name != "endpoint" && !peer_field(name.as_str()) {
                    return Err(OpenError::Settings);
                }
                peer.insert_json(name, value)
                    .map_err(|_| OpenError::Settings)?;
            }
            let endpoint = peer
                .optional_text("endpoint")?
                .map(PeerAddr::parse)
                .transpose()
                .map_err(|_| OpenError::Settings)?;
            let (host, port) = if let Some(endpoint) = &endpoint {
                (endpoint.host(), endpoint.port())
            } else if index == 0 {
                (host, port)
            } else {
                return Err(OpenError::Settings);
            };
            peers.push(resolve_peer(host, port, &peer, private, runtime)?);
        }
    } else {
        peers.push(resolve_peer(host, port, settings, private, runtime)?);
    }
    let (socket, dual, endpoints) = carrier(&peers, runtime)?;
    let peers = peers
        .into_iter()
        .zip(endpoints)
        .map(|(peer, endpoint)| LinkPeer {
            endpoint,
            keys: peer.keys,
            allowed: peer.allowed,
        })
        .collect();
    Ok(PreparedLink {
        socket,
        dual,
        peers,
        mtu,
        reserved,
    })
}

fn link_error(error: io::Error) -> OpenError {
    if error.kind() == io::ErrorKind::InvalidInput {
        OpenError::Settings
    } else {
        OpenError::Transport
    }
}

fn key(value: &str) -> Result<[u8; 32], OpenError> {
    kerlico_wireguard::key(value).map_err(|_| OpenError::Settings)
}

struct ResolvedPeer {
    keys: PeerKeys,
    allowed: Vec<IpNet>,
    addresses: Vec<SocketAddr>,
}

fn resolve_peer(
    host: &str,
    port: u16,
    peer: &Settings,
    private: [u8; 32],
    runtime: Option<&RuntimeContext>,
) -> Result<ResolvedPeer, OpenError> {
    let keys = PeerKeys {
        private,
        public: key(peer.text("publicKey")?)?,
        preshared: setting(peer, "presharedKey", "preSharedKey")?
            .map(key)
            .transpose()?,
        keepalive: setting(peer, "persistentKeepalive", "keepAlive")?
            .unwrap_or("0")
            .parse()
            .map_err(|_| OpenError::Settings)?,
    };
    let cidrs: Vec<String> = serde_json::from_str(
        peer.optional_text("allowedIPs")?
            .unwrap_or(r#"["0.0.0.0/0","::/0"]"#),
    )
    .map_err(|_| OpenError::Settings)?;
    let allowed = kerlico_wireguard::prefixes(&cidrs).map_err(|_| OpenError::Settings)?;
    let addresses = if host.contains(':') && host.contains('%') {
        let host = host.trim_matches(['[', ']']);
        vec![kerlico_wg::parse_endpoint(&format!("[{host}]:{port}")).map_err(|_| OpenError::Settings)?]
    } else {
        match runtime {
            Some(runtime) => runtime.network.lookup_ip(host, port, None, ResolutionSource::System),
            None => kerlico_outbound::lookup_system_addresses(host, port),
        }.map_err(|_| OpenError::Transport)?
    };
    if addresses.is_empty() {
        return Err(OpenError::Transport);
    }
    Ok(ResolvedPeer {
        keys,
        allowed,
        addresses,
    })
}

fn carrier(
    peers: &[ResolvedPeer],
    runtime: Option<&RuntimeContext>,
) -> Result<(UdpSocket, bool, Vec<SocketAddr>), OpenError> {
    let first = peers.first().ok_or(OpenError::Settings)?.addresses[0];
    let network = runtime.map(|runtime| runtime.network.as_ref() as &dyn Network);
    if let Ok(socket) = kerlico_outbound::open_tunnel_datagram(network, first, true) {
        return Ok((
            socket,
            true,
            peers.iter().map(|peer| peer.addresses[0]).collect(),
        ));
    }
    // Some hosts disable an address family. Use one native socket if every peer
    // has a candidate in the same family; do not fall back to one socket per peer.
    for v4 in [first.is_ipv4(), !first.is_ipv4()] {
        let endpoints: Option<Vec<_>> = peers
            .iter()
            .map(|peer| {
                peer.addresses
                    .iter()
                    .copied()
                    .find(|address| address.is_ipv4() == v4)
            })
            .collect();
        if let Some(endpoints) = endpoints {
            if let Ok(socket) = kerlico_outbound::open_tunnel_datagram(network, endpoints[0], false)
            {
                return Ok((socket, false, endpoints));
            }
        }
    }
    Err(OpenError::Transport)
}

fn setting<'a>(
    settings: &'a Settings,
    first: &str,
    second: &str,
) -> Result<Option<&'a str>, OpenError> {
    match (
        settings.optional_text(first)?,
        settings.optional_text(second)?,
    ) {
        (Some(_), Some(_)) => Err(OpenError::Settings),
        (left, right) => Ok(left.or(right)),
    }
}

#[cfg(feature = "tun-device")]
fn run_tun(peer: &PeerAddr, settings: &Settings, name: &str) -> Result<(), OpenError> {
    let link = prepare_link(peer.host(), peer.port(), settings)?;
    let endpoint = link.peers.first().ok_or(OpenError::Settings)?.endpoint;
    let dual = link.dual;
    let runtime = settings.runtime().cloned();
    kerlico_wg::run_tun(
        name,
        link.mtu,
        link.socket,
        dual,
        link.peers,
        link.reserved,
        move |port| {
            let network = runtime
                .as_ref()
                .map(|runtime| runtime.network.as_ref() as &dyn Network);
            kerlico_outbound::open_tunnel_datagram_at(network, endpoint, dual, port)
        },
    )
    .map_err(link_error)
}

fn plane_error(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => PlaneFault::Again,
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    destination: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    let runtime = settings.runtime().ok_or(OpenError::Settings)?;
    let targets = runtime
        .network
        .lookup_ip(
            destination.host(),
            destination.port(),
            None,
            ResolutionSource::Configured,
        )
        .map_err(|_| OpenError::Transport)?;
    let tunnel = cached_landing(host, port, settings, runtime)?;
    for target in targets {
        let attempt = match destination.transport() {
            Transport::Tcp => tunnel.connect_tcp(target),
            Transport::Udp => tunnel.connect_udp(target),
        };
        if let Ok(pipe) = attempt {
            return Ok(Box::new(LandingFlow {
                pipe,
                _tunnel: tunnel,
            }));
        }
    }
    Err(OpenError::Transport)
}

fn associate_landing(
    host: &str,
    port: u16,
    settings: &Settings,
) -> Result<Box<dyn Association>, OpenError> {
    let runtime = settings.runtime().ok_or(OpenError::Settings)?;
    let tunnel = cached_landing(host, port, settings, runtime)?;
    let datagrams = tunnel
        .associate_all_udp()
        .map_err(|_| OpenError::Transport)?;
    Ok(Box::new(TunnelAssociation {
        datagrams,
        _tunnel: tunnel,
        network: runtime.network.clone(),
        resolved: Mutex::default(),
        closed: AtomicBool::new(false),
    }))
}

type CachedTarget = (Instant, Vec<SocketAddr>);
struct TunnelAssociation {
    datagrams: Datagrams,
    _tunnel: Arc<Tunnel>,
    network: Arc<dyn Network>,
    resolved: Mutex<HashMap<(String, u16), CachedTarget>>,
    closed: AtomicBool,
}

impl TunnelAssociation {
    fn targets(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let cache_key = (host.to_ascii_lowercase(), port);
        let mut resolved = self.resolved.lock().expect("WireGuard UDP DNS");
        resolved.retain(|_, (since, _)| since.elapsed() < Duration::from_secs(60));
        if let Some((_, addresses)) = resolved.get(&cache_key) {
            return Ok(addresses.clone());
        }
        let addresses = self
            .network
            .lookup_ip(host, port, None, ResolutionSource::Configured)?;
        if !addresses.is_empty() && resolved.len() < 64 {
            resolved.insert(cache_key, (Instant::now(), addresses.clone()));
        }
        Ok(addresses)
    }
}

impl Association for TunnelAssociation {
    fn send_to(&self, _: SocketAddr, host: &str, port: u16, data: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let Ok(targets) = self.targets(host, port) else {
            return Ok(());
        };
        for target in targets {
            match self.datagrams.send_to(target, data) {
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                result => return result,
            }
        }
        Ok(())
    }

    fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let (source, data) = self.datagrams.recv_for(wait)?;
        Ok((source.ip().to_string(), source.port(), data))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

struct LandingFlow {
    pipe: Pipe,
    _tunnel: Arc<Tunnel>,
}

impl InboundStream for LandingFlow {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        match self.pipe.read(buf).map_err(plane_error) {
            Err(PlaneFault::Again) => {
                std::thread::sleep(Duration::from_millis(5));
                self.pipe.read(buf).map_err(plane_error)
            }
            result => result,
        }
    }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.pipe.write(buf).map_err(plane_error)
    }
    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        Ok(self.pipe.finish())
    }
}

struct CachedLanding {
    server: Weak<RuntimeContext>,
    settings: Settings,
    peer: (String, u16),
    tunnel: Arc<Tunnel>,
}

fn tunnel_cache() -> &'static Mutex<Vec<CachedLanding>> {
    static TUNNELS: OnceLock<Mutex<Vec<CachedLanding>>> = OnceLock::new();
    TUNNELS.get_or_init(|| {
        let _ = std::thread::Builder::new()
            .name("kerlico-wireguard-land-cache".into())
            .spawn(|| loop {
                std::thread::sleep(Duration::from_secs(5));
                if let Some(cache) = TUNNELS.get() {
                    if let Ok(mut cache) = cache.lock() {
                        cache.retain(|entry| entry.server.strong_count() != 0);
                    }
                }
            });
        Mutex::default()
    })
}

fn cached_landing(
    host: &str,
    port: u16,
    settings: &Settings,
    runtime: &Arc<RuntimeContext>,
) -> Result<Arc<Tunnel>, OpenError> {
    let mut tunnels = tunnel_cache().lock().map_err(|_| OpenError::Transport)?;
    let owner = Arc::downgrade(runtime);
    let settings_key = settings.without_runtime();
    tunnels.retain(|entry| entry.server.strong_count() != 0 && entry.tunnel.is_running());
    if let Some(entry) = tunnels.iter().find(|entry| {
        entry.server.ptr_eq(&owner)
            && entry.settings == settings_key
            && entry.peer.0 == host
            && entry.peer.1 == port
    }) {
        return Ok(entry.tunnel.clone());
    }
    if tunnels.len() >= 64 {
        return Err(OpenError::Again);
    }
    let values: Vec<String> =
        serde_json::from_str(settings.text("localAddresses")?).map_err(|_| OpenError::Settings)?;
    let mut addresses = Vec::<IpAddr>::new();
    for value in values {
        let addr = value
            .parse()
            .or_else(|_| value.parse::<IpNet>().map(|net| net.addr()))
            .map_err(|_| OpenError::Settings)?;
        if addresses
            .iter()
            .any(|address| address.is_ipv4() == addr.is_ipv4())
            || addr.is_unspecified()
            || addr.is_multicast()
        {
            return Err(OpenError::Settings);
        }
        addresses.push(addr);
    }
    let (link, mtu) = open_link(host, port, settings)?;
    let tunnel = Arc::new(
        Tunnel::from_link(addresses, usize::from(mtu), link).map_err(|_| OpenError::Transport)?,
    );
    tunnels.push(CachedLanding {
        server: owner,
        settings: settings_key,
        peer: (host.to_owned(), port),
        tunnel: tunnel.clone(),
    });
    Ok(tunnel)
}
