//! AnyTLS inbound: TLS, the password, then one `Handoff` per stream and per UDP destination.

use std::collections::HashMap;
use std::io::{self, Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use kerlico_anytls::session::{Flow, Inbound, Leg, Opened, Session, Stream};
use kerlico_anytls::tls::{ServerTransport, HANDSHAKE_TIMEOUT};
use kerlico_anytls::{jls, password_hash, rest, shadow, Scheme, SchemeCell};
use kerlico_shared::runtime::{FallbackRate, Network, NetworkConnection, NetworkDial, NetworkRoute};
use kerlico_shared::{
    Accept, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError, PeerAddr, PlaneFault, Settings, Transport,
    UserEmail,
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};

const WAIT: Duration = Duration::from_millis(200);

type Users = Arc<RwLock<HashMap<[u8; 32], UserEmail>>>;

pub struct AnyTlsInbound {
    tag: NodeTag,
    users: Users,
    ready: Receiver<Ready>,
    control: Arc<Control>,
    accept_loop: Option<thread::JoinHandle<()>>,
}

enum Ready {
    Stream(Opened),
    Fallback(Destination, FallbackFlow),
}

struct Control {
    closed: AtomicBool,
    listener: TcpListener,
    next: AtomicU64,
    connections: Mutex<HashMap<u64, TcpStream>>,
}

impl Drop for AnyTlsInbound {
    fn drop(&mut self) {
        self.control.closed.store(true, Ordering::Release);
        let _ = SockRef::from(&self.control.listener).shutdown(std::net::Shutdown::Both);
        if let Some(task) = self.accept_loop.take() {
            let _ = task.join();
        }
        for (_, tcp) in self.control.connections.lock().expect("connections").drain() {
            let _ = tcp.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Accept for AnyTlsInbound {
    /// `password` is the account; mihomo's `users` maps a name to it. Two accounts cannot share a
    /// password, since the password is what the server looks the user up by.
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        if account.keys().any(|key| key != "password") {
            return Err(OpenError::Settings);
        }
        let password = account.text("password")?;
        if password.is_empty() {
            return Err(OpenError::Settings);
        }
        let hash = password_hash(password);
        let mut users = self.users.write().expect("users");
        if users.get(&hash).is_some_and(|owner| owner != email) {
            return Err(OpenError::Settings);
        }
        users.retain(|_, owner| owner != email);
        users.insert(hash, email.clone());
        Ok(())
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let mut users = self.users.write().expect("users");
        let before = users.len();
        users.retain(|_, owner| owner != email);
        if users.len() == before {
            return Err(OpenError::Settings);
        }
        Ok(())
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        loop {
            let opened = match self.ready.try_recv() {
                Ok(Ready::Stream(opened)) => opened,
                Ok(Ready::Fallback(dest, flow)) => {
                    let email = UserEmail::parse("fallback").expect("fallback account");
                    return Ok(Handoff::new(self.tag.clone(), email, dest, Box::new(flow)));
                }
                Err(TryRecvError::Empty) => return Err(OpenError::Again),
                Err(TryRecvError::Disconnected) => return Err(OpenError::Transport),
            };
            // A user removed after the session started gets no new streams.
            let Some(email) = self.users.read().expect("users").get(&opened.user).cloned() else {
                continue;
            };
            let transport = match opened.flow {
                Flow::Tcp(_) => Transport::Tcp,
                Flow::Udp(_) => Transport::Udp,
            };
            let Ok(destination) = Destination::new(opened.target.host.clone(), opened.target.port, transport) else {
                continue;
            };
            let (stream, group): (Box<dyn InboundStream>, _) = match opened.flow {
                Flow::Tcp(stream) => (Box::new(TcpFlow(stream)), None),
                Flow::Udp(leg) => {
                    let group = leg.datagram_session().cloned();
                    (Box::new(UdpFlow(leg)), group)
                }
            };
            let mut handoff = Handoff::new(self.tag.clone(), email, destination, stream);
            if transport == Transport::Udp {
                handoff.set_peer(opened.peer);
            }
            if let Some(group) = group {
                handoff.set_datagram_session(group);
            }
            return Ok(handoff);
        }
    }
}

struct TcpFlow(Stream);

struct FallbackFlow {
    tcp: TcpStream,
    prefix: Mutex<Cursor<Vec<u8>>>,
    upload: FallbackRate,
    download: FallbackRate,
}

impl FallbackFlow {
    fn new(tcp: TcpStream, prefix: Vec<u8>, rate: u64) -> io::Result<Self> {
        tcp.set_read_timeout(Some(WAIT))?;
        tcp.set_write_timeout(Some(WAIT))?;
        Ok(Self {
            tcp,
            prefix: Mutex::new(Cursor::new(prefix)),
            upload: FallbackRate::new(rate),
            download: FallbackRate::new(rate),
        })
    }
}

impl InboundStream for FallbackFlow {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        let limit = self.upload.limit(buf.len());
        let buf = &mut buf[..limit];
        let prefix = self.prefix.lock().expect("fallback prefix").read(buf).map_err(map_io)?;
        let n = if prefix > 0 { prefix } else { (&self.tcp).read(buf).map_err(map_io)? };
        self.upload.wait(n);
        Ok(n)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        let n = (&self.tcp).write(&buf[..self.download.limit(buf.len())]).map_err(map_io)?;
        self.download.wait(n);
        Ok(n)
    }
}

impl InboundStream for TcpFlow {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.0.read_for(buf, WAIT).map_err(map_io)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.0.write(buf).map_err(map_io)?;
        Ok(buf.len())
    }
}

/// One whole datagram per call; `Ok(0)` is an empty datagram.
struct UdpFlow(Leg);

impl InboundStream for UdpFlow {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.0.recv_for(buf, WAIT).map_err(map_io)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.0.send(buf).map_err(map_io)?;
        Ok(buf.len())
    }

    fn write_datagram_to_user(&self, buf: &[u8], source: SocketAddr) -> Result<usize, PlaneFault> {
        self.0.send_from(source, buf).map_err(map_io)?;
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

struct Listener {
    users: Users,
    ready: Arc<Mutex<Sender<Ready>>>,
}

impl Inbound for Listener {
    fn authenticate(&self, hash: &[u8; 32]) -> bool {
        self.users.read().expect("users").contains_key(hash)
    }

    fn open(&self, opened: Opened) {
        let _ = self.ready.lock().expect("ready").send(Ready::Stream(opened));
    }
}

struct Node {
    carrier: Arc<Carrier>,
    padding: SchemeCell,
}

enum Carrier {
    Tls(ServerTransport),
    Jls { security: jls::Server, dest: Destination, rate: u64 },
    Shadow(ShadowServer),
    Rest(RestServer),
}

struct RestServer {
    config: rest::Config,
    peer: PeerAddr,
    network: Arc<dyn Network>,
    rate: u64,
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct RestConfig {
    enable: bool,
    dest: String,
    password: String,
    min_record_len: usize,
    restls_script: String,
    rate_limit: u64,
    proxy: String,
}

impl RestConfig {
    fn carrier(self, settings: &Settings) -> Result<Carrier, OpenError> {
        if !self.proxy.is_empty() && !self.proxy.eq_ignore_ascii_case("direct") {
            return Err(OpenError::Settings);
        }
        let peer = PeerAddr::parse(&self.dest).or_else(|_| {
            let dest = self.dest.trim_start_matches('[').trim_end_matches(']');
            if dest.parse::<std::net::Ipv6Addr>().is_ok() {
                PeerAddr::parse(&format!("[{dest}]:443"))
            } else {
                PeerAddr::parse(&format!("{dest}:443"))
            }
        }).map_err(|_| OpenError::Settings)?;
        let config = rest::Config::new(&self.password, &self.restls_script, self.min_record_len)
            .map_err(|_| OpenError::Settings)?;
        Ok(Carrier::Rest(RestServer {
            config, peer, network: settings.runtime().ok_or(OpenError::Settings)?.network.clone(), rate: self.rate_limit,
        }))
    }
}

impl RestServer {
    fn accept(&self, mut tcp: TcpStream, ready: &Mutex<Sender<Ready>>) -> io::Result<Option<kerlico_anytls::tls::Established>> {
        let hello = shadow::record(&mut tcp)?;
        if !self.config.candidate(&hello) {
            let dest = Destination::new(self.peer.host(), self.peer.port(), Transport::Tcp)
                .map_err(|_| io::ErrorKind::InvalidInput)?;
            send_fallback(ready, dest, tcp, hello, self.rate)?;
            return Ok(None);
        }
        let target = connect_handshake(&*self.network, &self.peer)?;
        rest::accept(tcp, target, &hello, &self.config, |client, target| self.network.relay_connected_tcp(client, target, self.rate))
    }
}

fn connect_handshake(network: &dyn Network, peer: &PeerAddr) -> io::Result<TcpStream> {
    let connection = network.connect(&NetworkDial {
        host: peer.host().to_owned(), port: peer.port(), transport: Transport::Tcp, addresses: Vec::new(),
        route: NetworkRoute::Direct, timeout: HANDSHAKE_TIMEOUT, socket_factory: None, race: None,
    })?;
    match connection {
        NetworkConnection::Tcp(target) => Ok(target),
        _ => Err(io::Error::new(io::ErrorKind::Unsupported, "TLS handshake target needs a native carrier")),
    }
}

struct ShadowServer {
    version: shadow::Version,
    password: String,
    users: Vec<ShadowUser>,
    network: Arc<dyn Network>,
    handshake: Option<PeerAddr>,
    by_name: HashMap<String, PeerAddr>,
    strict: bool,
    wildcard: Wildcard,
}

enum Wildcard {
    Off,
    Authenticated,
    Any,
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct ShadowConfig {
    enable: bool,
    version: u8,
    password: String,
    users: Vec<ShadowUser>,
    handshake: ShadowTarget,
    handshake_for_server_name: HashMap<String, ShadowTarget>,
    strict_mode: bool,
    wildcard_sni: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowUser {
    #[serde(default, rename = "name")]
    _name: String,
    password: String,
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShadowTarget {
    dest: String,
    proxy: String,
}

impl ShadowTarget {
    fn peer(self) -> Result<PeerAddr, OpenError> {
        if !self.proxy.is_empty() && !self.proxy.eq_ignore_ascii_case("direct") {
            return Err(OpenError::Settings);
        }
        PeerAddr::parse(&self.dest).map_err(|_| OpenError::Settings)
    }
}

impl ShadowConfig {
    fn carrier(self, settings: &Settings) -> Result<Carrier, OpenError> {
        let version = shadow::Version::parse(self.version).map_err(|_| OpenError::Settings)?;
        let wildcard = match self.wildcard_sni.as_str() {
            "" | "off" => Wildcard::Off,
            "authed" => Wildcard::Authenticated,
            "all" => Wildcard::Any,
            _ => return Err(OpenError::Settings),
        };
        let v3 = matches!(version, shadow::Version::V3);
        if v3 && (self.users.is_empty() || self.users.iter().any(|user| user.password.is_empty())) {
            return Err(OpenError::Settings);
        }
        let handshake = if v3 && !matches!(wildcard, Wildcard::Off) && self.handshake.dest.is_empty() {
            None
        } else {
            Some(self.handshake.peer()?)
        };
        let network = settings.runtime().ok_or(OpenError::Settings)?.network.clone();
        let by_name = self.handshake_for_server_name.into_iter()
            .map(|(name, target)| Ok((name, target.peer()?))).collect::<Result<_, OpenError>>()?;
        Ok(Carrier::Shadow(ShadowServer {
            version, password: self.password, users: self.users, network, handshake, by_name,
            strict: self.strict_mode, wildcard,
        }))
    }
}

impl ShadowServer {
    fn accept(&self, mut tcp: TcpStream, ready: &Mutex<Sender<Ready>>) -> io::Result<Option<kerlico_anytls::tls::Established>> {
        let first = if matches!(self.version, shadow::Version::V1) {
            Vec::new()
        } else {
            shadow::record(&mut tcp)?
        };
        let v3 = matches!(self.version, shadow::Version::V3);
        let name = shadow::server_name(&first);
        let password = v3.then(|| shadow::find_password(&first, self.users.iter().map(|user| user.password.as_str()))).flatten();
        let direct_name = v3 && (matches!(self.wildcard, Wildcard::Any)
            || (matches!(self.wildcard, Wildcard::Authenticated) && password.is_some()));
        let wildcard = name.filter(|_| direct_name)
            .and_then(|name| PeerAddr::parse(&format!("{name}:443")).ok());
        let peer = name.and_then(|name| self.by_name.get(name)).or(wildcard.as_ref()).or(self.handshake.as_ref())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ShadowTLS handshake has no target"))?;
        if v3 && password.is_none() {
            let dest = Destination::new(peer.host(), peer.port(), Transport::Tcp).map_err(|_| io::ErrorKind::InvalidInput)?;
            send_fallback(ready, dest, tcp, first, 0)?;
            return Ok(None);
        }
        let target = connect_handshake(&*self.network, peer)?;
        let fallback = |client: &TcpStream, target: &TcpStream| self.network.relay_connected_tcp(client, target, 0);
        if let Some(password) = password {
            shadow::accept_v3(tcp, target, &first, password, self.strict, fallback)
        } else {
            shadow::accept(tcp, target, first, self.version, &self.password, fallback)
        }
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct JlsConfig {
    enable: bool,
    users: Vec<JlsUser>,
    sni: String,
    dest: String,
    alpn: Option<Vec<String>>,
    proxy: String,
    rate_limit: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JlsUser {
    username: String,
    password: String,
}

impl JlsConfig {
    fn carrier(self) -> Result<Carrier, OpenError> {
        if !self.proxy.is_empty() {
            // Kerlico's node rules pick the exit for fallbacks.
            return Err(OpenError::Settings);
        }
        let peer = PeerAddr::parse(&self.dest).map_err(|_| OpenError::Settings)?;
        let sni = if self.sni.is_empty() { peer.host() } else { &self.sni };
        let dest = Destination::new(peer.host(), peer.port(), Transport::Tcp).map_err(|_| OpenError::Settings)?;
        let key = rcgen::generate_simple_self_signed(vec![sni.to_owned()]).map_err(|_| OpenError::Settings)?;
        let users: Vec<_> = self.users.iter().map(|user| (user.username.as_str(), user.password.as_str())).collect();
        let security = jls::Server::new(sni, &users, self.alpn.as_deref(), key.cert.der().clone(),
            key.key_pair.serialize_der().try_into().map_err(|_| OpenError::Settings)?)
            .map_err(|_| OpenError::Settings)?;
        Ok(Carrier::Jls { security, dest, rate: self.rate_limit })
    }
}

/// Node settings are mihomo's listener fields: `certificate` and `private-key` (PEM or a file),
/// optional `padding-scheme` and client authentication policy.
fn node(settings: &Settings) -> Result<Node, OpenError> {
    for key in settings.keys() {
        if !matches!(key, "certificate" | "private-key" | "padding-scheme" | "allow-insecure" | "client-auth-type" | "client-auth-cert" | "ech-key" | "jls-config" | "shadow-tls" | "res-tls") {
            return Err(OpenError::Settings);
        }
    }
    let allow_insecure = match settings.optional_text("allow-insecure")? {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err(OpenError::Settings),
    };
    let certificate = settings.optional_text("certificate")?.filter(|value| !value.is_empty());
    let private_key = settings.optional_text("private-key")?.filter(|value| !value.is_empty());
    let client_auth = settings.optional_text("client-auth-type")?.unwrap_or_default();
    let client_ca = settings.optional_text("client-auth-cert")?.filter(|value| !value.is_empty());
    let ech = settings.optional_text("ech-key")?.filter(|value| !value.is_empty());
    let jls = settings.optional_text("jls-config")?.map(serde_json::from_str::<JlsConfig>)
        .transpose().map_err(|_| OpenError::Settings)?.filter(|config| config.enable);
    let shadow = settings.optional_text("shadow-tls")?.map(serde_json::from_str::<ShadowConfig>)
        .transpose().map_err(|_| OpenError::Settings)?.filter(|config| config.enable);
    let rest = settings.optional_text("res-tls")?.map(serde_json::from_str::<RestConfig>)
        .transpose().map_err(|_| OpenError::Settings)?.filter(|config| config.enable);
    let tls_settings = !client_auth.is_empty() || client_ca.is_some() || ech.is_some();
    let carrier = match (certificate, private_key, jls, shadow, rest) {
        (Some(cert), Some(key), None, None, None) => Carrier::Tls(ServerTransport::new(cert, key, client_auth, client_ca, ech)
            .map_err(|_| OpenError::Settings)?),
        (None, None, None, None, None) if allow_insecure && !tls_settings => Carrier::Tls(ServerTransport::Plain),
        (None, None, Some(jls), None, None) if !tls_settings => jls.carrier()?,
        (None, None, None, Some(shadow), None) if !tls_settings => shadow.carrier(settings)?,
        (None, None, None, None, Some(rest)) if !tls_settings => rest.carrier(settings)?,
        _ => return Err(OpenError::Settings),
    };
    let scheme = match settings.optional_text("padding-scheme")? {
        None | Some("") => Scheme::default_scheme(),
        Some(text) => Scheme::parse(text.as_bytes()).ok_or(OpenError::Settings)?,
    };
    Ok(Node { carrier: Arc::new(carrier), padding: SchemeCell::new(scheme) })
}

pub fn listen(tag: &NodeTag, bind: &ListenAddr, settings: &Settings) -> Result<Box<dyn Accept>, OpenError> {
    let node = node(settings)?;
    let listener = bind_tcp(bind.socket_addr()).map_err(|_| OpenError::Transport)?;
    let users: Users = Arc::new(RwLock::new(HashMap::new()));
    let (ready_tx, ready) = mpsc::channel();
    let control = Arc::new(Control {
        closed: AtomicBool::new(false),
        listener,
        next: AtomicU64::new(0),
        connections: Mutex::new(HashMap::new()),
    });
    let ready_tx = Arc::new(Mutex::new(ready_tx));
    let inbound: Arc<dyn Inbound> = Arc::new(Listener { users: Arc::clone(&users), ready: ready_tx.clone() });
    let task = {
        let control = Arc::clone(&control);
        thread::Builder::new()
            .name("anytls-accept".into())
            .spawn(move || accept_loop(control, node, inbound, ready_tx))
            .map_err(|_| OpenError::Transport)?
    };
    Ok(Box::new(AnyTlsInbound { tag: tag.clone(), users, ready, control, accept_loop: Some(task) }))
}

fn accept_loop(control: Arc<Control>, node: Node, inbound: Arc<dyn Inbound>, ready: Arc<Mutex<Sender<Ready>>>) {
    while !control.closed.load(Ordering::Acquire) {
        let tcp = match control.listener.accept() {
            Ok((tcp, _)) => tcp,
            Err(_) if control.closed.load(Ordering::Acquire) => return,
            Err(_) => {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        let id = control.next.fetch_add(1, Ordering::Relaxed);
        if let Ok(clone) = tcp.try_clone() {
            control.connections.lock().expect("connections").insert(id, clone);
        }
        let control = Arc::clone(&control);
        let carrier = Arc::clone(&node.carrier);
        let padding = node.padding.clone();
        let inbound = Arc::clone(&inbound);
        let ready = ready.clone();
        let spawned = thread::Builder::new().name("anytls-conn".into()).spawn(move || {
            let _ = serve(tcp, &carrier, padding, inbound, &ready);
            control.connections.lock().expect("connections").remove(&id);
        });
        if spawned.is_err() {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// mihomo has no deadline for the handshake and the password; this one shares ten seconds.
fn serve(tcp: TcpStream, config: &Carrier, padding: SchemeCell, inbound: Arc<dyn Inbound>, ready: &Mutex<Sender<Ready>>) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let link = match config {
        Carrier::Tls(tls) => tls.accept(tcp)?,
        Carrier::Shadow(shadow) => match shadow.accept(tcp, ready)? {
            Some(link) => link,
            None => return Ok(()),
        },
        Carrier::Rest(rest) => match rest.accept(tcp, ready)? {
            Some(link) => link,
            None => return Ok(()),
        },
        Carrier::Jls { security, dest, rate } => match security.accept(tcp)? {
            jls::Accepted::Authenticated(link) => link,
            jls::Accepted::Fallback(tcp, prefix) => {
                return send_fallback(ready, dest.clone(), tcp, prefix, *rate);
            }
        }
    };
    Session::serve(link, padding, inbound)
}

fn send_fallback(
    ready: &Mutex<Sender<Ready>>, dest: Destination, tcp: TcpStream, prefix: Vec<u8>, rate: u64,
) -> io::Result<()> {
    let flow = FallbackFlow::new(tcp, prefix, rate)?;
    let _ = ready.lock().expect("ready").send(Ready::Fallback(dest, flow));
    Ok(())
}

fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?,
        SocketAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_only_v6(true)?;
            socket
        }
    };
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(TcpListener::from(socket))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_settings_follow_the_mihomo_names() {
        let mut settings = Settings::default();
        settings.insert_text("certificate", "x");
        settings.insert_text("private-key", "y");
        assert!(node(&settings).is_err(), "not PEM and not a file");
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        settings.insert_text("certificate", key.cert.pem());
        settings.insert_text("private-key", key.key_pair.serialize_pem());
        assert!(node(&settings).is_ok());
        settings.insert_text("padding-scheme", "garbage");
        assert!(node(&settings).is_err());
        settings.insert_text("padding-scheme", "stop=2\n1=10-20");
        assert!(node(&settings).is_ok());
        settings.insert_text("allow-insecure", "true");
        assert!(matches!(node(&settings).unwrap().carrier.as_ref(), Carrier::Tls(ServerTransport::Kernel(_))));
        settings.insert_text("allow-insecure", "false");
        settings.insert_text("shadow-tls", "{\"enable\":true}");
        assert!(node(&settings).is_err());
    }

    #[test]
    fn plaintext_must_be_explicit_and_cannot_disable_a_tls_auth_policy() {
        let mut settings = Settings::default();
        assert!(node(&settings).is_err());
        settings.insert_text("allow-insecure", "true");
        assert!(matches!(node(&settings).unwrap().carrier.as_ref(), Carrier::Tls(ServerTransport::Plain)));
        settings.insert_text("client-auth-type", "require-any");
        assert!(node(&settings).is_err());
    }
}
