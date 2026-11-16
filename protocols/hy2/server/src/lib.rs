use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use kerlico_hy2::masquerade::{HysteriaMasquerade, MasqueradeSocket, MasqueradeTarget};
use kerlico_hy2::{auth::ReceiveRate, datagram, quic, split_address, tcp};
use kerlico_shared::runtime::{NetworkConnection, NetworkDial, NetworkRoute};
use kerlico_shared::{
    Accept, DatagramSession, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError,
    PlaneFault, Settings, Transport, UserEmail,
};
use kerlico_tls::advanced::{advanced_quic_server_config, AdvancedTlsOptions, TlsCertificate};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;

const POLL: Duration = Duration::from_millis(200);
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_UDP_FLOWS: usize = 1024;

type Users = Arc<RwLock<HashMap<UserEmail, Vec<u8>>>>;

struct Node {
    endpoint: quinn::Endpoint,
    users: Users,
    incoming: mpsc::Receiver<Handoff>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.endpoint.close(quinn::VarInt::from_u32(0x100), b"");
    }
}

impl Accept for Node {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        let value = account.text("password")?;
        if value.is_empty()
            || http::HeaderValue::from_str(value).is_err()
            || account.keys().any(|key| key != "password")
        {
            return Err(OpenError::Settings);
        }
        let mut users = self.users.write().expect("Hy2 users");
        if users.values().any(|other| other == value.as_bytes()) || users.contains_key(email) {
            return Err(OpenError::Settings);
        }
        users.insert(email.clone(), value.as_bytes().to_vec());
        Ok(())
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        self.users
            .write()
            .expect("Hy2 users")
            .remove(email)
            .map(|_| ())
            .ok_or(OpenError::Settings)
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        self.incoming.blocking_recv().ok_or(OpenError::Transport)
    }
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    if settings.keys().any(|key| {
        !matches!(
            key,
            "certificate"
                | "privateKey"
                | "certificateFile"
                | "privateKeyFile"
                | "udp"
                | "udpIdleTimeout"
                | "receiveRate"
                | "sendRate"
                | "tls"
                | "obfs"
                | "quicParams"
                | "masquerade"
        )
    }) {
        return Err(OpenError::Settings);
    }
    let tls: serde_json::Value =
        serde_json::from_str(settings.optional_text("tls")?.unwrap_or("{}"))
            .map_err(|_| OpenError::Settings)?;
    let mut tls =
        AdvancedTlsOptions::from_json(&tls, vec!["h3".into()]).map_err(|_| OpenError::Settings)?;
    let pem = |key| {
        settings
            .optional_text(key)
            .map(|v| v.unwrap_or_default().to_owned())
    };
    let identity = TlsCertificate {
        certificate: pem("certificate")?,
        key: pem("privateKey")?,
        certificate_file: pem("certificateFile")?,
        key_file: pem("privateKeyFile")?,
        ..Default::default()
    };
    if !identity.certificate.is_empty() || !identity.certificate_file.is_empty() {
        tls.certificates.push(identity);
    }
    let crypto = advanced_quic_server_config(&tls).map_err(|_| OpenError::Settings)?;
    let udp = match settings.optional_text("udp")? {
        None | Some("true") => true,
        Some("false") => false,
        _ => return Err(OpenError::Settings),
    };
    let udp_idle = settings
        .optional_text("udpIdleTimeout")?
        .unwrap_or("60")
        .parse::<u64>()
        .map_err(|_| OpenError::Settings)?;
    if !(1..=600).contains(&udp_idle) {
        return Err(OpenError::Settings);
    }
    let udp_idle = Duration::from_secs(udp_idle);
    let options = settings
        .optional_text("quicParams")?
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| OpenError::Settings)?;
    let options = quic::QuicOptions::parse(options.as_ref()).map_err(|_| OpenError::Settings)?;
    let rate = match settings.optional_text("receiveRate")? {
        Some("auto") => ReceiveRate::Auto,
        Some(value) => ReceiveRate::BytesPerSecond(value.parse().map_err(|_| OpenError::Settings)?),
        None => ReceiveRate::BytesPerSecond(options.receive_rate()),
    };
    let send_rate = settings
        .optional_text("sendRate")?
        .unwrap_or("0")
        .parse()
        .map_err(|_| OpenError::Settings)?;
    let mut config = quinn::ServerConfig::with_crypto(crypto);
    config.transport_config(
        options
            .hy2_transport(false)
            .map_err(|_| OpenError::Settings)?,
    );
    let socket = quic::listen_socket(bind.socket_addr()).map_err(|_| OpenError::Transport)?;
    let obfs = settings
        .optional_text("obfs")?
        .map(kerlico_hy2::obfs::Salamander::parse)
        .transpose()
        .map_err(|_| OpenError::Settings)?;
    let mut masquerade = HysteriaMasquerade::parse(settings.optional_text("masquerade")?)
        .map_err(|_| OpenError::Settings)?;
    if let Some(runtime) = settings.runtime() {
        let network = runtime.network.clone();
        masquerade = masquerade.with_dialer(Arc::new(move |target| match target {
            MasqueradeTarget::Tcp { host, port } => {
                let carrier = network.connect(&NetworkDial {
                    host: host.clone(),
                    port: *port,
                    addresses: Vec::new(),
                    transport: Transport::Tcp,
                    route: NetworkRoute::Direct,
                    timeout: quic::HANDSHAKE_TIMEOUT,
                    socket_factory: None,
                    race: None,
                })?;
                match carrier {
                    NetworkConnection::Tcp(socket) => Ok(MasqueradeSocket::Tcp(socket)),
                    _ => Err(io::ErrorKind::Unsupported.into()),
                }
            }
            #[cfg(unix)]
            MasqueradeTarget::Unix(path) => network
                .connect_unix_socket(path)
                .map(MasqueradeSocket::Unix),
            #[cfg(not(unix))]
            MasqueradeTarget::Unix(_) => Err(io::ErrorKind::Unsupported.into()),
        }));
    }
    let endpoint = quic::endpoint(socket, options.endpoint(false), Some(config), obfs.as_ref())
        .map_err(|_| OpenError::Transport)?;
    let users = Users::default();
    let credentials = users.clone();
    let (ready, incoming) = mpsc::channel(128);
    let udp_ready = ready.clone();
    let udp_tag = tag.clone();
    let config = Arc::new(quic::Server {
        authenticate: Arc::new(move |password| {
            credentials
                .read()
                .expect("Hy2 users")
                .iter()
                .find(|(_, value)| bool::from(password.ct_eq(value)))
                .map(|(email, _)| email.clone())
        }),
        on_authenticated: Arc::new(move |conn, user: &UserEmail, peer_rate| {
            let peer_rate = if rate == ReceiveRate::Auto {
                ReceiveRate::Auto
            } else {
                ReceiveRate::BytesPerSecond(peer_rate)
            };
            options.hy2_authenticate(conn, peer_rate, send_rate, false);
            if udp {
                tokio::spawn(serve_udp(
                    conn.clone(),
                    user.clone(),
                    udp_tag.clone(),
                    udp_ready.clone(),
                    udp_idle,
                ));
            }
        }),
        fallback: Arc::new(move |request, peer, stream| {
            let masquerade = masquerade.clone();
            Box::pin(async move {
                let _ = masquerade.serve(request, peer, stream).await;
            })
        }),
        receive_rate: rate,
        udp,
    });
    let listener = endpoint.clone();
    let node = tag.clone();
    quic::runtime()
        .map_err(|_| OpenError::Transport)?
        .spawn(async move {
            let (tx, mut streams) = mpsc::channel(128);
            tokio::spawn(async move {
                while let Some(stream) = streams.recv().await {
                    tokio::spawn(serve_tcp(stream, node.clone(), ready.clone()));
                }
            });
            while let Some(attempt) = listener.accept().await {
                let config = config.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = attempt.await {
                        config.serve(conn, tx).await;
                    }
                });
            }
        });
    Ok(Box::new(Node {
        endpoint,
        users,
        incoming,
    }))
}

async fn serve_tcp(mut stream: quic::Tcp<UserEmail>, node: NodeTag, ready: mpsc::Sender<Handoff>) {
    let address =
        match tokio::time::timeout(quic::HANDSHAKE_TIMEOUT, tcp::read_request(&mut stream.recv))
            .await
        {
            Ok(Ok(address)) => address,
            _ => {
                if let Ok(frame) = tcp::response(false, "invalid destination") {
                    let _ = stream.send.write_all(&frame).await;
                }
                let _ = stream.send.finish();
                return;
            }
        };
    let (host, port) = split_address(&address).expect("parsed Hy2 destination");
    let Ok(dest) = Destination::new(host, port, Transport::Tcp) else {
        return;
    };
    let mut handoff = Handoff::new(
        node,
        stream.user,
        dest,
        Box::new(TcpFlow {
            pipe: quic::Duplex::new(stream.recv, stream.send),
            replied: AtomicBool::new(false),
        }),
    );
    handoff.set_peer(stream.peer);
    let _ = ready.send(handoff).await;
}

struct TcpFlow {
    pipe: quic::Duplex,
    replied: AtomicBool,
}

impl InboundStream for TcpFlow {
    fn report_connect(&self, result: Result<(), OpenError>) -> Result<(), PlaneFault> {
        if self.replied.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let frame = tcp::response(
            result.is_ok(),
            if result.is_ok() { "" } else { "connect failed" },
        )
        .map_err(map_io)?;
        self.pipe.write(&frame, SEND_TIMEOUT).map_err(map_io)?;
        if result.is_err() {
            self.pipe.finish().map_err(map_io)?;
        }
        Ok(())
    }
    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        self.pipe.finish().map(|_| true).map_err(map_io)
    }
    fn read_from_user(&self, data: &mut [u8]) -> Result<usize, PlaneFault> {
        self.pipe.read(data, POLL).map_err(map_io)
    }
    fn write_to_user(&self, data: &[u8]) -> Result<usize, PlaneFault> {
        self.pipe
            .write(data, SEND_TIMEOUT)
            .map(|_| data.len())
            .map_err(map_io)
    }
}

struct UdpFlow {
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    connection: quinn::Connection,
    session: u32,
    address: String,
    packet: Arc<AtomicU16>,
    activity: Arc<Mutex<Instant>>,
}

impl InboundStream for UdpFlow {
    fn read_from_user(&self, data: &mut [u8]) -> Result<usize, PlaneFault> {
        let mut inbound = self.inbound.lock().expect("Hy2 UDP receive");
        let packet = quic::block(POLL, async {
            inbound
                .recv()
                .await
                .ok_or(io::Error::from(io::ErrorKind::BrokenPipe))
        })
        .map_err(map_io)?;
        let out = data.get_mut(..packet.len()).ok_or(PlaneFault::Transport)?;
        out.copy_from_slice(&packet);
        Ok(out.len())
    }
    fn write_to_user(&self, data: &[u8]) -> Result<usize, PlaneFault> {
        self.reply(&self.address, data)
    }
    fn write_datagram_to_user(&self, data: &[u8], source: SocketAddr) -> Result<usize, PlaneFault> {
        self.reply(&source.to_string(), data)
    }
}

impl UdpFlow {
    fn reply(&self, source: &str, data: &[u8]) -> Result<usize, PlaneFault> {
        *self.activity.lock().expect("Hy2 UDP activity") = Instant::now();
        quic::send_datagram(&self.connection, self.session, &self.packet, source, data)
            .map(|_| data.len())
            .map_err(map_io)
    }
}

struct UdpPipe {
    sender: mpsc::Sender<Vec<u8>>,
    activity: Arc<Mutex<Instant>>,
}

struct UdpSession {
    group: Arc<DatagramSession>,
    packet: Arc<AtomicU16>,
    targets: HashMap<String, UdpPipe>,
}

impl UdpSession {
    fn new() -> Self {
        Self {
            group: Arc::new(DatagramSession::new(true)),
            packet: Arc::new(AtomicU16::new(1)),
            targets: HashMap::new(),
        }
    }
}

async fn serve_udp(
    connection: quinn::Connection,
    user: UserEmail,
    tag: NodeTag,
    ready: mpsc::Sender<Handoff>,
    idle: Duration,
) {
    let mut fragments = datagram::Reassembler::default();
    let mut tick = tokio::time::interval(idle.min(Duration::from_secs(5)));
    let mut sessions = HashMap::<u32, UdpSession>::new();
    let mut flow_count = 0;
    loop {
        tokio::select! {
            _ = tick.tick() => sessions.retain(|_, session| {
                let before = session.targets.len();
                session.targets.retain(|_, flow| !flow.sender.is_closed() && flow.activity.lock().expect("Hy2 UDP activity").elapsed() < idle);
                flow_count -= before - session.targets.len();
                !session.targets.is_empty()
            }),
            wire = connection.read_datagram() => {
                let Ok(wire) = wire else { return; };
                let Ok(piece) = datagram::Packet::read(&wire) else { continue; };
                let now = Instant::now();
                let Some(datagram::Datagram { session, address, payload }) = fragments.push(piece, now) else { continue; };
                let existing = sessions.get(&session).and_then(|group| group.targets.get(&address));
                if let Some(flow) = existing.filter(|flow| !flow.sender.is_closed()) {
                    *flow.activity.lock().expect("Hy2 UDP activity") = now;
                    let _ = flow.sender.try_send(payload);
                    continue;
                }
                if flow_count >= MAX_UDP_FLOWS && existing.is_none() { continue; }
                let (host, port) = split_address(&address).expect("parsed Hy2 destination");
                let Ok(destination) = Destination::new(host, port, Transport::Udp) else { continue; };
                let (sender, inbound) = mpsc::channel(64);
                let _ = sender.try_send(payload);
                let activity = Arc::new(Mutex::new(now));
                let group = sessions.entry(session).or_insert_with(UdpSession::new);
                let mut handoff = Handoff::new(tag.clone(), user.clone(), destination, Box::new(UdpFlow {
                    inbound: Mutex::new(inbound), connection: connection.clone(), session,
                    address: address.clone(), packet: group.packet.clone(), activity: activity.clone(),
                }));
                handoff.set_peer(connection.remote_address());
                handoff.set_datagram_session(group.group.clone());
                if ready.try_send(handoff).is_ok() {
                    if group.targets.insert(address, UdpPipe { sender, activity }).is_none() {
                        flow_count += 1;
                    }
                } else if group.targets.is_empty() {
                    sessions.remove(&session);
                }
            }
        }
    }
}

fn map_io(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => PlaneFault::Again,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}
