//! AnyTLS client: the upstream behind the local SOCKS5/HTTP entry and the landing client share
//! one session pool, kept the way mihomo's `session.Client` keeps it.

mod config;
mod ech_dns;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use kerlico_anytls::session::{Session, Stream as WireStream};
use kerlico_anytls::tls::{ClientTransport, HANDSHAKE_TIMEOUT};
use kerlico_anytls::{jls, password_hash, rest, shadow, Family, Scheme, SchemeCell, Target, UOT_V2};
use kerlico_shared::runtime::{NetworkConnection, NetworkDial, NetworkRoute, RuntimeContext};
use kerlico_shared::{
    Association, ClientEntry, Destination, InboundStream, OpenError, PeerAddr, PlaneFault, Settings, Stream,
    Transport, Upstream,
};

/// The client leaf runs the local SOCKS5/HTTP entry in front of AnyTLS.
pub const CLIENT: ClientEntry = ClientEntry::ProxyWithDatagramLanding(upstream);

fn upstream(peer: &PeerAddr, settings: &Settings) -> Result<Arc<dyn Upstream>, OpenError> {
    let client = if settings.runtime().is_some() {
        cached_client(peer.host(), peer.port(), settings)?
    } else {
        Client::new(peer.host(), peer.port(), settings)?
    };
    Ok(Arc::new(client))
}

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(500);

/// One configured server. Clones share the pool; `close` ends every session.
#[derive(Clone)]
pub struct Client {
    pool: Arc<Pool>,
}

struct Pool {
    host: String,
    port: u16,
    runtime: Option<Weak<RuntimeContext>>,
    sni: String,
    carrier: Carrier,
    password: [u8; 32],
    metadata: String,
    padding: SchemeCell,
    udp: bool,
    idle_timeout: Duration,
    check_interval: Duration,
    min_idle: usize,
    disable_reuse: bool,
    state: Mutex<PoolState>,
}

enum Carrier {
    Tls(ClientTransport),
    Jls(jls::Client),
    Shadow(shadow::Client),
    Rest(rest::Client),
}

#[derive(Default)]
struct PoolState {
    /// Idle sessions by sequence number; the newest is reused first.
    idle: BTreeMap<u64, (Session, Instant)>,
    sessions: HashMap<u64, Session>,
    counter: u64,
    closed: bool,
    housekeeping: bool,
}

impl Client {
    pub fn new(host: &str, port: u16, settings: &Settings) -> Result<Self, OpenError> {
        let plan = config::Plan::parse(host, settings)?;
        let runtime = settings.runtime().map(Arc::downgrade);
        let carrier = if let Some(jls) = &plan.jls {
            Carrier::Jls(jls::Client::new(
                &jls.username, &jls.password, plan.alpn_given.then_some(plan.tls.alpn.as_slice()),
                &plan.tls.client_fingerprint,
            ).map_err(|_| OpenError::Settings)?)
        } else if let Some(rest) = &plan.rest {
            Carrier::Rest(rest::Client::new(&rest.password, &rest.version_hint, &rest.restls_script, &plan.tls)
                .map_err(|_| OpenError::Settings)?)
        } else if let Some(shadow) = &plan.shadow {
            let version = shadow::Version::parse(shadow.version).map_err(|_| OpenError::Settings)?;
            Carrier::Shadow(shadow::Client::new(version, &shadow.password, &plan.tls, plan.alpn_given)
                .map_err(|_| OpenError::Settings)?)
        } else {
            Carrier::Tls(ClientTransport::new(&plan.tls, ech_dns::provider(&plan.tls, &runtime))
                .map_err(|_| OpenError::Settings)?)
        };
        let pool = Arc::new(Pool {
            host: host.to_string(),
            port,
            runtime,
            sni: plan.sni,
            carrier,
            password: password_hash(&plan.password),
            metadata: plan.metadata,
            padding: SchemeCell::new(Scheme::default_scheme()),
            udp: plan.udp,
            idle_timeout: plan.idle_timeout,
            check_interval: plan.check_interval,
            min_idle: plan.min_idle,
            disable_reuse: plan.disable_reuse,
            state: Mutex::new(PoolState::default()),
        });
        Ok(Self { pool })
    }

    /// A stream to `host:port` (mihomo `CreateProxy`): the SOCKS address goes first.
    pub fn open_stream(&self, host: &str, port: u16) -> io::Result<ClientStream> {
        validate_target(host, port)?;
        let stream = self.pool.stream()?;
        let mut addr = Vec::with_capacity(host.len() + 4);
        Target::new(host, port).encode(Family::Socks, &mut addr)?;
        stream.write(&addr)?;
        Ok(ClientStream(stream))
    }

    /// A UDP-over-TCP stream (sing UoT v2, not connected: every packet names its address), only
    /// with `udp: true` as in mihomo.
    pub fn associate(&self) -> io::Result<ClientAssoc> {
        if !self.pool.udp {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "udp is not enabled for this anytls proxy"));
        }
        let stream = self.pool.stream()?;
        let mut addr = Vec::new();
        Target::new(UOT_V2, 0).encode(Family::Socks, &mut addr)?;
        stream.write(&addr)?;
        Ok(ClientAssoc { stream, state: Mutex::new(AssocState { requested: false }), rx: Mutex::new(Vec::new()) })
    }

    pub fn close(&self) {
        let sessions: Vec<Session> = {
            let mut state = self.pool.state.lock().expect("pool");
            state.closed = true;
            state.idle.clear();
            state.sessions.drain().map(|(_, session)| session).collect()
        };
        for session in sessions {
            session.close();
        }
    }

    /// Sessions this client holds open, busy or idle.
    pub fn session_count(&self) -> usize {
        self.pool.state.lock().expect("pool").sessions.len()
    }

    pub fn idle_count(&self) -> usize {
        self.pool.state.lock().expect("pool").idle.len()
    }

    /// The MD5 of the padding scheme in use; the server may have replaced the default.
    pub fn padding_md5(&self) -> String {
        self.pool.padding.load().md5().to_string()
    }
}

impl Pool {
    fn stream(self: &Arc<Self>) -> io::Result<WireStream> {
        let reused = {
            let mut state = self.state.lock().expect("pool");
            if state.closed {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "anytls client closed"));
            }
            if self.disable_reuse {
                None
            } else {
                state.idle.pop_last().map(|(seq, (session, _))| (seq, session))
            }
        };
        let (seq, session) = match reused {
            Some(found) => found,
            None => self.create()?,
        };
        let stream = match session.open_stream() {
            Ok(stream) => stream,
            Err(error) => {
                session.close();
                return Err(error);
            }
        };
        let pool = Arc::downgrade(self);
        let back = session.clone();
        stream.set_close_hook(Box::new(move || {
            if let Some(pool) = pool.upgrade() {
                pool.release(seq, back);
            }
        }));
        Ok(stream)
    }

    /// The stream ended: the session goes back to the idle pool, or closes when reuse is off.
    fn release(&self, seq: u64, session: Session) {
        if session.is_closed() {
            return;
        }
        let mut state = self.state.lock().expect("pool");
        if self.disable_reuse || state.closed || !state.sessions.contains_key(&seq) {
            drop(state);
            session.close();
            return;
        }
        state.idle.insert(seq, (session, Instant::now()));
    }

    fn dial(&self) -> io::Result<TcpStream> {
        let Some(runtime) = &self.runtime else {
            return kerlico_outbound::connect_system_tcp(&self.host, self.port, DIAL_TIMEOUT);
        };
        let runtime = runtime.upgrade().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "anytls runtime was dropped")
        })?;
        let request = NetworkDial {
            host: self.host.clone(),
            port: self.port,
            transport: Transport::Tcp,
            addresses: Vec::new(),
            route: NetworkRoute::Direct,
            timeout: DIAL_TIMEOUT,
            socket_factory: None,
            race: None,
        };
        match runtime.network.connect(&request)? {
            NetworkConnection::Tcp(tcp) => Ok(tcp),
            _ => Err(io::Error::new(io::ErrorKind::Unsupported, "anytls requires a native TCP carrier")),
        }
    }

    fn create(self: &Arc<Self>) -> io::Result<(u64, Session)> {
        let tcp = self.dial()?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let link = match &self.carrier {
            Carrier::Tls(tls) => tls.connect(tcp, &self.sni)?,
            Carrier::Jls(jls) => jls.connect(tcp, &self.sni)?,
            Carrier::Shadow(shadow) => shadow.connect(tcp, &self.sni)?,
            Carrier::Rest(rest) => rest.connect(tcp, &self.sni)?,
        };
        let session = Session::client(link, self.padding.clone(), &self.metadata, &self.password)?;
        let seq = {
            let mut state = self.state.lock().expect("pool");
            if state.closed {
                drop(state);
                session.close();
                return Err(io::Error::new(io::ErrorKind::NotConnected, "anytls client closed"));
            }
            state.counter += 1;
            let seq = state.counter;
            state.sessions.insert(seq, session.clone());
            if !self.disable_reuse && !state.housekeeping {
                state.housekeeping = true;
                let pool = Arc::downgrade(self);
                thread::Builder::new().name("anytls-pool".into()).spawn(move || housekeeping(pool)).map_err(io::Error::other)?;
            }
            seq
        };
        let pool = Arc::downgrade(self);
        session.set_on_close(Box::new(move || {
            if let Some(pool) = pool.upgrade() {
                let mut state = pool.state.lock().expect("pool");
                state.idle.remove(&seq);
                state.sessions.remove(&seq);
            }
        }));
        Ok((seq, session))
    }

    /// mihomo `idleCleanupExpTime`: from the newest idle session down, those idle longer than the
    /// timeout close, except that the first `min-idle-session` are kept and their clock restarts.
    fn idle_cleanup(&self, now: Instant) {
        let expired_before = now.checked_sub(self.idle_timeout);
        let mut close = Vec::new();
        {
            let mut state = self.state.lock().expect("pool");
            let mut active = 0;
            let mut drop_keys = Vec::new();
            for (seq, (_, since)) in state.idle.iter_mut().rev() {
                if !expired_before.is_some_and(|limit| *since < limit) {
                    active += 1;
                    continue;
                }
                if active < self.min_idle {
                    *since = now;
                    active += 1;
                    continue;
                }
                drop_keys.push(*seq);
            }
            for seq in drop_keys {
                if let Some((session, _)) = state.idle.remove(&seq) {
                    close.push(session);
                }
            }
        }
        for session in close {
            session.close();
        }
    }

    /// A reused session whose SYN went unanswered for three seconds is closed, as mihomo does.
    fn check_synack(&self, now: Instant) {
        let late: Vec<Session> = {
            let state = self.state.lock().expect("pool");
            state
                .sessions
                .values()
                .filter(|session| session.synack_deadline().is_some_and(|deadline| deadline <= now))
                .cloned()
                .collect()
        };
        for session in late {
            session.close();
        }
    }
}

fn housekeeping(pool: Weak<Pool>) {
    let mut last_cleanup = Instant::now();
    loop {
        thread::sleep(TICK);
        let Some(pool) = pool.upgrade() else { return };
        if pool.state.lock().expect("pool").closed {
            return;
        }
        let now = Instant::now();
        pool.check_synack(now);
        if now.duration_since(last_cleanup) >= pool.check_interval {
            last_cleanup = now;
            pool.idle_cleanup(now);
        }
    }
}

fn validate_target(host: &str, port: u16) -> io::Result<()> {
    if port == 0 || host.is_empty() || host.len() > 255 || host.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid target address"));
    }
    Ok(())
}

/// One TCP stream through the server.
pub struct ClientStream(WireStream);

impl ClientStream {
    pub fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        self.0.read_for(buf, wait)
    }

    pub fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.0.write(buf)
    }

    pub fn close(&self) {
        self.0.close();
    }

    pub fn session(&self) -> Session {
        self.0.session()
    }
}

struct AssocState {
    requested: bool,
}

/// One UDP association over a UoT stream.
pub struct ClientAssoc {
    stream: WireStream,
    state: Mutex<AssocState>,
    rx: Mutex<Vec<u8>>,
}

impl ClientAssoc {
    /// `uot.LazyConn`: the first packet carries the request, whose destination is that packet's.
    pub fn send_to(&self, host: &str, port: u16, payload: &[u8]) -> io::Result<()> {
        let len = u16::try_from(payload.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?;
        let target = Target::new(host, port);
        let mut packet = Vec::with_capacity(2 * target.encoded_len() + 3 + payload.len());
        let mut state = self.state.lock().expect("assoc");
        if !state.requested {
            packet.push(0);
            target.encode(Family::Socks, &mut packet)?;
        }
        target.encode(Family::Uot, &mut packet)?;
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(payload);
        self.stream.write(&packet)?;
        state.requested = true;
        Ok(())
    }

    /// One datagram and the address it came from.
    pub fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)> {
        let deadline = Instant::now() + wait;
        let mut rx = self.rx.lock().expect("assoc");
        let mut buf = vec![0u8; 65536 + 300];
        loop {
            if let Some((target, used)) = Target::decode(&rx, Family::Uot)? {
                if let Some(len) = rx.get(used..used + 2) {
                    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
                    if rx.len() >= used + 2 + len {
                        let payload = rx[used + 2..used + 2 + len].to_vec();
                        rx.drain(..used + 2 + len);
                        return Ok((target.host, target.port, payload));
                    }
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let n = self.stream.read_for(&mut buf, deadline - now)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            rx.extend_from_slice(&buf[..n]);
        }
    }

    pub fn close(&self) {
        self.stream.close();
    }
}

impl Upstream for Client {
    fn open_stream(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        Ok(Box::new(Client::open_stream(self, host, port)?))
    }

    fn associate(&self) -> io::Result<Box<dyn Association>> {
        Ok(Box::new(Client::associate(self)?))
    }

    fn close(&self) {
        Client::close(self);
    }
}

impl Stream for ClientStream {
    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        ClientStream::read_for(self, buf, wait)
    }

    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        ClientStream::write_all(self, buf)
    }

    fn close(&self) {
        ClientStream::close(self);
    }
}

impl Association for ClientAssoc {
    fn send_to(&self, _source: SocketAddr, host: &str, port: u16, payload: &[u8]) -> io::Result<()> {
        ClientAssoc::send_to(self, host, port, payload)
    }

    fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)> {
        ClientAssoc::recv_for(self, wait)
    }

    fn close(&self) {
        ClientAssoc::close(self);
    }
}

// ---------------------------------------------------------------------------------------------
// Landing

/// The outbound module's landing call. Clients are cached by server and settings.
pub fn land(host: &str, port: u16, settings: &Settings, destination: &Destination) -> Result<Box<dyn InboundStream>, OpenError> {
    let client = cached_client(host, port, settings)?;
    match destination.transport() {
        Transport::Tcp => {
            let stream = client
                .open_stream(destination.host(), destination.port())
                .map_err(|_| OpenError::Transport)?;
            Ok(Box::new(Relay { stream, _client: client }))
        }
        Transport::Udp => {
            let assoc = client.associate().map_err(|_| OpenError::Transport)?;
            Ok(Box::new(DatagramRelay {
                assoc,
                host: destination.host().to_string(),
                port: destination.port(),
                _client: client,
            }))
        }
    }
}

const RELAY_WAIT: Duration = Duration::from_millis(200);

struct Relay {
    stream: ClientStream,
    _client: Client,
}

impl InboundStream for Relay {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.stream.read_for(buf, RELAY_WAIT).map_err(map_io)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.stream.write_all(buf).map_err(map_io)?;
        Ok(buf.len())
    }
}

struct DatagramRelay {
    assoc: ClientAssoc,
    host: String,
    port: u16,
    _client: Client,
}

impl InboundStream for DatagramRelay {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        let (_, _, payload) = self.assoc.recv_for(RELAY_WAIT).map_err(map_io)?;
        if payload.len() > buf.len() {
            return Err(PlaneFault::Transport);
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok(payload.len())
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.assoc.send_to(&self.host, self.port, buf).map_err(map_io)?;
        Ok(buf.len())
    }
}

fn map_io(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => PlaneFault::Again,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

struct CacheEntry {
    host: String,
    port: u16,
    settings: Settings,
    client: Client,
    seen: Instant,
}

const CACHE_CAPACITY: usize = 64;
const CACHE_IDLE: Duration = Duration::from_secs(60);

fn cache() -> &'static Mutex<Vec<CacheEntry>> {
    static CACHE: OnceLock<Mutex<Vec<CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Vec::new()))
}

fn idle(entry: &CacheEntry) -> bool {
    Arc::strong_count(&entry.client.pool) == 1 && entry.client.session_count() == entry.client.idle_count()
}

fn cached_client(host: &str, port: u16, settings: &Settings) -> Result<Client, OpenError> {
    let owner = Arc::downgrade(settings.runtime().ok_or(OpenError::Settings)?);
    let key = settings.without_runtime();
    let mut entries = cache().lock().map_err(|_| OpenError::Transport)?;
    let now = Instant::now();
    entries.retain(|entry| {
        let live = entry.client.pool.runtime.as_ref().is_some_and(|owner| owner.strong_count() > 0);
        let keep = live && (!idle(entry) || now.duration_since(entry.seen) < CACHE_IDLE);
        if !keep {
            entry.client.close();
        }
        keep
    });
    if let Some(entry) = entries.iter_mut().find(|entry| {
        entry.host == host && entry.port == port && entry.settings == key
            && entry.client.pool.runtime.as_ref().is_some_and(|runtime| runtime.ptr_eq(&owner))
    }) {
        entry.seen = now;
        return Ok(entry.client.clone());
    }
    if entries.len() == CACHE_CAPACITY {
        let candidate = entries.iter().enumerate().filter(|(_, entry)| idle(entry)).min_by_key(|(_, entry)| entry.seen).map(|(index, _)| index);
        match candidate {
            Some(index) => entries.remove(index).client.close(),
            None => return Err(OpenError::Again),
        }
    }
    let client = Client::new(host, port, settings)?;
    entries.push(CacheEntry { host: host.to_string(), port, settings: key, client: client.clone(), seen: now });
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_shared::runtime::{AddressFamily, GeoIpCatalog, GeoIpSet, Network, ResolutionSource};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct TestNetwork(AtomicUsize);

    impl Network for TestNetwork {
        fn lookup_ip(
            &self,
            _: &str,
            _: u16,
            _: Option<AddressFamily>,
            _: ResolutionSource,
        ) -> io::Result<Vec<SocketAddr>> {
            panic!("the server runtime owns carrier resolution");
        }

        fn connect(&self, request: &NetworkDial) -> io::Result<NetworkConnection> {
            assert_eq!(request.host, "peer.invalid");
            assert_eq!(request.port, 443);
            assert_eq!(request.transport, Transport::Tcp);
            assert_eq!(request.route, NetworkRoute::Direct);
            assert!(request.addresses.is_empty());
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(io::ErrorKind::ConnectionRefused.into())
        }
    }

    impl GeoIpCatalog for TestNetwork {
        fn load(&self, _: &str, _: &str) -> io::Result<GeoIpSet> {
            panic!("the protocol doesn't resolve GeoIP");
        }
    }

    #[test]
    fn landing_uses_the_owning_runtime() {
        let mut settings = Settings::default();
        settings.insert_text("password", "p");
        let target = Destination::new("origin.invalid", 80, Transport::Tcp).unwrap();
        assert!(matches!(land("peer.invalid", 443, &settings, &target), Err(OpenError::Settings)));

        let network = Arc::new(TestNetwork::default());
        let runtime = || Arc::new(RuntimeContext { network: network.clone(), geoip: network.clone(), dispatch: None });
        let first = runtime();
        settings.set_runtime(first.clone());
        let client = cached_client("peer.invalid", 443, &settings).unwrap();
        assert!(matches!(land("peer.invalid", 443, &settings, &target), Err(OpenError::Transport)));
        assert_eq!(network.0.load(Ordering::Relaxed), 1);

        settings.set_runtime(runtime());
        let other = cached_client("peer.invalid", 443, &settings).unwrap();
        assert!(!Arc::ptr_eq(&client.pool, &other.pool));
        drop(first);
        assert_eq!(client.pool.dial().unwrap_err().kind(), io::ErrorKind::NotConnected);
        assert_eq!(network.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn entry_rejects_unknown_keys() {
        let peer = PeerAddr::parse("127.0.0.1:2000").unwrap();
        let mut settings = Settings::default();
        settings.insert_text("password", "p");
        assert!(upstream(&peer, &settings).is_ok());
        settings.insert_text("tfo", "true");
        assert!(upstream(&peer, &settings).is_err());
    }

    #[test]
    fn udp_needs_the_udp_flag() {
        let mut settings = Settings::default();
        settings.insert_text("password", "p");
        let client = Client::new("127.0.0.1", 1, &settings).unwrap();
        assert_eq!(client.associate().err().map(|error| error.kind()), Some(io::ErrorKind::Unsupported));
    }
}
