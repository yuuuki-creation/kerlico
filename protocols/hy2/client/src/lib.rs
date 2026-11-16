use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use futures_util::{stream::FuturesUnordered, StreamExt};
use kerlico_hy2::{datagram, format_address, quic, split_address, tcp};
use kerlico_shared::runtime::{
    Network, NetworkConnection, NetworkDial, NetworkRoute, ResolutionSource, RuntimeContext,
};
use kerlico_shared::{Association, ClientEntry, Stream, Upstream};
use kerlico_shared::{
    Destination, InboundStream, OpenError, PeerAddr, PlaneFault, Settings, Transport,
};
use kerlico_tls::advanced::{advanced_quic_client_config, AdvancedTlsOptions};

const POLL: Duration = Duration::from_millis(200);
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

pub const CLIENT: ClientEntry = ClientEntry::ProxyWithDatagramLanding(upstream);

fn upstream(peer: &PeerAddr, settings: &Settings) -> Result<Arc<dyn Upstream>, OpenError> {
    landing_client(peer.host(), peer.port(), settings).map(|client| client as Arc<dyn Upstream>)
}

pub struct Client {
    config: Config,
    active: Mutex<Option<Arc<Connection>>>,
    stopped: AtomicBool,
}

struct Config {
    host: String,
    port: u16,
    name: String,
    password: String,
    receive_rate: u64,
    send_rate: u64,
    quic: quic::QuicOptions,
    crypto: Arc<dyn quinn::crypto::ClientConfig>,
    network: Option<Arc<dyn Network>>,
    obfs: Option<kerlico_hy2::obfs::Salamander>,
    hop: Option<quic::hop::Hops>,
}

struct Connection {
    endpoint: quinn::Endpoint,
    quic: quinn::Connection,
    udp: bool,
    next: AtomicU64,
    associations: Mutex<HashMap<u32, mpsc::SyncSender<datagram::Datagram>>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.endpoint.close(quinn::VarInt::from_u32(0x100), b"");
    }
}

impl Client {
    pub fn new(host: &str, port: u16, settings: &Settings) -> Result<Self, OpenError> {
        if settings.keys().any(|key| {
            !matches!(
                key,
                "password"
                    | "serverName"
                    | "allowInsecure"
                    | "receiveRate"
                    | "sendRate"
                    | "tls"
                    | "address"
                    | "port"
                    | "obfs"
                    | "quicParams"
                    | "hopPorts"
                    | "hopInterval"
            )
        }) {
            return Err(OpenError::Settings);
        }
        format_address(host, port).map_err(|_| OpenError::Settings)?;
        let password = settings.text("password")?;
        if password.is_empty() || http::HeaderValue::from_str(password).is_err() {
            return Err(OpenError::Settings);
        }
        let name = settings.optional_text("serverName")?.unwrap_or(host);
        if name.is_empty() {
            return Err(OpenError::Settings);
        }
        let options = settings
            .optional_text("quicParams")?
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| OpenError::Settings)?;
        let options =
            quic::QuicOptions::parse(options.as_ref()).map_err(|_| OpenError::Settings)?;
        let receive_rate = settings
            .optional_text("receiveRate")?
            .map(str::parse)
            .transpose()
            .map_err(|_| OpenError::Settings)?
            .unwrap_or_else(|| options.receive_rate());
        let send_rate = settings
            .optional_text("sendRate")?
            .unwrap_or("0")
            .parse()
            .map_err(|_| OpenError::Settings)?;
        let tls = serde_json::from_str(settings.optional_text("tls")?.unwrap_or("{}"))
            .map_err(|_| OpenError::Settings)?;
        let mut tls = AdvancedTlsOptions::from_json(&tls, vec!["h3".into()])
            .map_err(|_| OpenError::Settings)?;
        tls.allow_insecure = match settings.optional_text("allowInsecure")? {
            None => tls.allow_insecure,
            Some("true") => true,
            Some("false") => false,
            _ => return Err(OpenError::Settings),
        };
        let crypto = advanced_quic_client_config(&tls, options.chrome_parrot(true))
            .map_err(|_| OpenError::Settings)?;
        let obfs = settings
            .optional_text("obfs")?
            .map(kerlico_hy2::obfs::Salamander::parse)
            .transpose()
            .map_err(|_| OpenError::Settings)?;
        let interval = settings.optional_text("hopInterval")?;
        let hop = match settings.optional_text("hopPorts")? {
            Some(ports) => {
                Some(quic::hop::Hops::parse(ports, interval).map_err(|_| OpenError::Settings)?)
            }
            None if interval.is_none() => None,
            None => return Err(OpenError::Settings),
        };
        Ok(Self {
            config: Config {
                host: host.into(),
                port,
                name: name.into(),
                password: password.into(),
                receive_rate,
                send_rate,
                quic: options,
                crypto,
                network: settings.runtime().map(|runtime| runtime.network.clone()),
                obfs,
                hop,
            },
            active: Mutex::new(None),
            stopped: AtomicBool::new(false),
        })
    }

    fn connection(&self) -> io::Result<Arc<Connection>> {
        let mut active = self.active.lock().expect("Hy2 client connection");
        if self.stopped.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if let Some(conn) = active
            .as_ref()
            .filter(|conn| conn.quic.close_reason().is_none())
        {
            return Ok(conn.clone());
        }
        let conn = self.config.connect()?;
        *active = Some(conn.clone());
        Ok(conn)
    }
}

impl Config {
    fn connect(&self) -> io::Result<Arc<Connection>> {
        let addresses = match &self.network {
            Some(network) => {
                network.lookup_ip(&self.host, self.port, None, ResolutionSource::Configured)?
            }
            None => kerlico_outbound::lookup_system_addresses(&self.host, self.port)?,
        };
        let mut seen = std::collections::HashSet::new();
        let (endpoint, quic, udp) = quic::block(quic::HANDSHAKE_TIMEOUT, async {
            let mut attempts = FuturesUnordered::new();
            for (index, peer) in addresses
                .into_iter()
                .filter(|addr| seen.insert(*addr))
                .take(8)
                .enumerate()
            {
                attempts.push(async move {
                    if index > 0 {
                        tokio::time::sleep(Duration::from_millis(250 * index as u64)).await;
                    }
                    self.connect_to(peer).await
                });
            }
            let mut last = io::Error::from(io::ErrorKind::AddrNotAvailable);
            while let Some(result) = attempts.next().await {
                match result {
                    Ok(connected) => return Ok(connected),
                    Err(error) => last = error,
                }
            }
            Err(last)
        })?;
        let connection = Arc::new(Connection {
            endpoint,
            quic,
            udp,
            next: AtomicU64::new(1),
            associations: Mutex::new(HashMap::new()),
        });
        if udp {
            let weak = Arc::downgrade(&connection);
            let transport = connection.quic.clone();
            quic::runtime()?.spawn(async move {
                let mut pending = datagram::Reassembler::default();
                while let Ok(wire) = transport.read_datagram().await {
                    let Some(connection) = weak.upgrade() else {
                        return;
                    };
                    let Ok(packet) = datagram::Packet::read(&wire) else {
                        continue;
                    };
                    let mut associations =
                        connection.associations.lock().expect("Hy2 associations");
                    let Some(sender) = associations.get(&packet.session) else {
                        continue;
                    };
                    if let Some(data) = pending.push(packet, Instant::now()) {
                        if matches!(
                            sender.try_send(data),
                            Err(mpsc::TrySendError::Disconnected(_))
                        ) {
                            associations.remove(&packet.session);
                        }
                    }
                }
                if let Some(conn) = weak.upgrade() {
                    conn.associations.lock().expect("Hy2 associations").clear();
                }
            });
        }
        Ok(connection)
    }

    async fn connect_to(
        &self,
        peer: SocketAddr,
    ) -> io::Result<(quinn::Endpoint, quinn::Connection, bool)> {
        let mut config = quinn::ClientConfig::new(self.crypto.clone());
        config.transport_config(self.quic.hy2_transport(true)?);
        self.quic.configure_client(&mut config);
        let mut endpoint = if let Some(hops) = &self.hop {
            let network = self.network.clone();
            let host = self.host.clone();
            let dial: quic::hop::Dial = Arc::new(move |remote| {
                let socket = open_datagram(network.as_deref(), &host, remote)?;
                socket.set_read_timeout(Some(Duration::from_millis(12)))?;
                socket.set_write_timeout(Some(Duration::from_millis(200)))?;
                Ok(Arc::new(socket))
            });
            let packets = hops.clone().open(peer, false, dial)?;
            quic::packet_endpoint(packets, self.quic.endpoint(true), None, self.obfs.as_ref())?
        } else {
            let socket = open_datagram(self.network.as_deref(), &self.host, peer)?;
            quic::endpoint(socket, self.quic.endpoint(true), None, self.obfs.as_ref())?
        };
        endpoint.set_default_client_config(config);
        let result: io::Result<_> = async {
            let conn = endpoint
                .connect(peer, &self.name)
                .map_err(io::Error::other)?
                .await?;
            let (udp, rate) =
                quic::client_authenticate(&conn, &self.password, self.receive_rate).await?;
            self.quic
                .hy2_authenticate(&conn, rate, self.send_rate, true);
            Ok((conn, udp))
        }
        .await;
        match result {
            Ok((conn, udp)) => Ok((endpoint, conn, udp)),
            Err(error) => {
                endpoint.close(quinn::VarInt::from_u32(0x100), b"");
                Err(error)
            }
        }
    }
}

fn open_datagram(
    network: Option<&dyn Network>,
    host: &str,
    peer: SocketAddr,
) -> io::Result<std::net::UdpSocket> {
    let Some(network) = network else {
        return kerlico_outbound::open_system_datagram(peer, quic::HANDSHAKE_TIMEOUT);
    };
    let request = NetworkDial {
        host: host.to_owned(),
        port: peer.port(),
        transport: Transport::Udp,
        addresses: vec![peer],
        route: NetworkRoute::Direct,
        timeout: quic::HANDSHAKE_TIMEOUT,
        socket_factory: None,
        race: None,
    };
    let NetworkConnection::Udp(socket) = network.open_datagram(&request)? else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Hy2 requires a native UDP socket",
        ));
    };
    Ok(socket)
}

impl Upstream for Client {
    fn open_stream(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        let frame = tcp::request(&format_address(host, port)?)?;
        let connection = self.connection()?;
        let (send, recv) = quic::block(quic::HANDSHAKE_TIMEOUT, async {
            let (mut send, mut recv) = connection.quic.open_bi().await?;
            send.write_all(&frame).await?;
            let (ok, _) = tcp::read_response(&mut recv).await?;
            if !ok {
                return Err(io::ErrorKind::ConnectionRefused.into());
            }
            Ok((send, recv))
        })?;
        Ok(Box::new(TcpFlow {
            pipe: quic::Duplex::new(recv, send),
            _connection: connection,
        }))
    }

    fn associate(&self) -> io::Result<Box<dyn Association>> {
        let connection = self.connection()?;
        if !connection.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Hy2 peer disabled UDP",
            ));
        }
        let id = u32::try_from(connection.next.fetch_add(1, Ordering::Relaxed))
            .map_err(|_| io::Error::other("Hy2 UDP session IDs exhausted"))?;
        let (tx, rx) = mpsc::sync_channel(64);
        connection
            .associations
            .lock()
            .expect("Hy2 associations")
            .insert(id, tx);
        Ok(Box::new(UdpFlow {
            connection,
            rx: Mutex::new(rx),
            closed: AtomicBool::new(false),
            id,
            packet: AtomicU16::new(1),
        }))
    }

    fn close(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(active) = self.active.lock().expect("Hy2 client connection").take() {
            active.endpoint.close(quinn::VarInt::from_u32(0x100), b"");
            active
                .associations
                .lock()
                .expect("Hy2 associations")
                .clear();
        }
    }
}

struct TcpFlow {
    pipe: quic::Duplex,
    _connection: Arc<Connection>,
}

impl Stream for TcpFlow {
    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        self.pipe.read(buf, wait)
    }
    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.pipe.write(buf, SEND_TIMEOUT)
    }
    fn finish_write(&self) -> io::Result<()> {
        self.pipe.finish()
    }
    fn supports_half_close(&self) -> bool {
        true
    }
    fn close(&self) {
        self.pipe.close();
    }
}

struct UdpFlow {
    connection: Arc<Connection>,
    rx: Mutex<mpsc::Receiver<datagram::Datagram>>,
    closed: AtomicBool,
    id: u32,
    packet: AtomicU16,
}

impl Association for UdpFlow {
    fn send_to(
        &self,
        _source: SocketAddr,
        host: &str,
        port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let Ok(address) = format_address(host, port) else {
            return Ok(());
        };
        quic::send_datagram(
            &self.connection.quic,
            self.id,
            &self.packet,
            &address,
            payload,
        )
    }
    fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let packet = self
            .rx
            .lock()
            .expect("Hy2 UDP receiver")
            .recv_timeout(wait)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
            })?;
        let (host, port) = split_address(&packet.address)?;
        Ok((host.to_owned(), port, packet.payload))
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.connection
            .associations
            .lock()
            .expect("Hy2 associations")
            .remove(&self.id);
    }
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.close();
    }
}

struct LandingEntry {
    host: String,
    port: u16,
    settings: Settings,
    owner: Weak<RuntimeContext>,
    client: Arc<Client>,
    seen: Instant,
}

fn landing_client(host: &str, port: u16, settings: &Settings) -> Result<Arc<Client>, OpenError> {
    const IDLE: Duration = Duration::from_secs(60);
    const CAPACITY: usize = 64;
    static CLIENTS: OnceLock<Mutex<Vec<LandingEntry>>> = OnceLock::new();
    let Some(owner) = settings.runtime().map(Arc::downgrade) else {
        return Client::new(host, port, settings).map(Arc::new);
    };
    let key = settings.without_runtime();
    let now = Instant::now();
    let mut entries = CLIENTS
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| OpenError::Transport)?;
    let idle = |entry: &LandingEntry| Arc::strong_count(&entry.client) == 1;
    entries.retain(|entry| {
        entry.owner.strong_count() != 0 && (!idle(entry) || now.duration_since(entry.seen) < IDLE)
    });
    if let Some(entry) = entries.iter_mut().find(|entry| {
        entry.host == host
            && entry.port == port
            && entry.settings == key
            && entry.owner.ptr_eq(&owner)
    }) {
        entry.seen = now;
        return Ok(entry.client.clone());
    }
    if entries.len() == CAPACITY {
        let (index, _) = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| idle(entry))
            .min_by_key(|(_, entry)| entry.seen)
            .ok_or(OpenError::Again)?;
        entries.swap_remove(index);
    }
    let client = Arc::new(Client::new(host, port, settings)?);
    entries.push(LandingEntry {
        host: host.to_owned(),
        port,
        settings: key,
        owner,
        client: client.clone(),
        seen: now,
    });
    Ok(client)
}

pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    destination: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    let client = landing_client(host, port, settings)?;
    let flow = match destination.transport() {
        Transport::Tcp => LandFlow::Tcp(
            client
                .open_stream(destination.host(), destination.port())
                .map_err(|_| OpenError::Transport)?,
        ),
        Transport::Udp => LandFlow::Udp(
            client.associate().map_err(|_| OpenError::Transport)?,
            destination.clone(),
        ),
    };
    Ok(Box::new(Land {
        flow,
        _client: client,
    }))
}

struct Land {
    flow: LandFlow,
    _client: Arc<Client>,
}
enum LandFlow {
    Tcp(Box<dyn Stream>),
    Udp(Box<dyn Association>, Destination),
}

impl InboundStream for Land {
    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        match &self.flow {
            LandFlow::Tcp(stream) => stream.finish_write().map(|_| true).map_err(map_io),
            LandFlow::Udp(..) => Ok(false),
        }
    }
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        match &self.flow {
            LandFlow::Tcp(stream) => stream.read_for(buf, POLL).map_err(map_io),
            LandFlow::Udp(udp, _) => {
                let (_, _, data) = udp.recv_for(POLL).map_err(map_io)?;
                let out = buf.get_mut(..data.len()).ok_or(PlaneFault::Transport)?;
                out.copy_from_slice(&data);
                Ok(out.len())
            }
        }
    }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        match &self.flow {
            LandFlow::Tcp(stream) => stream.write_all(buf),
            LandFlow::Udp(udp, dest) => udp.send_to(
                SocketAddr::from(([0, 0, 0, 0], 0)),
                dest.host(),
                dest.port(),
                buf,
            ),
        }
        .map(|_| buf.len())
        .map_err(map_io)
    }
}

fn map_io(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => PlaneFault::Again,
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}
