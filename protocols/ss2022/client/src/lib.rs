mod tcp;
mod udp_sessions;

use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use kerlico_shared::runtime::{
    Network, NetworkConnection, NetworkDial, NetworkRoute, ResolutionSource,
};
use kerlico_shared::{
    Association, ClientEntry, Destination, InboundStream, OpenError, PeerAddr, PlaneFault,
    Settings, Stream, Transport, Upstream,
};
use kerlico_ss2022::{
    address, block, config, context, map_io, method, relay, remote, target, udp_wire_limit,
    TcpFlow, FLOW_WAIT, OPEN_WAIT,
};
use rand_core::{OsRng, RngCore};
use relay::udprelay::{crypto_io, options::UdpSocketControlData};

pub const CLIENT: ClientEntry = ClientEntry::ProxyWithDatagramLanding(upstream);

fn upstream(peer: &PeerAddr, settings: &Settings) -> Result<Arc<dyn Upstream>, OpenError> {
    Ok(Arc::new(Client::new(peer.host(), peer.port(), settings)?))
}

struct Client {
    host: String,
    port: u16,
    config: Arc<config::ServerConfig>,
    context: context::SharedContext,
    network: Option<Arc<dyn Network>>,
    udp: bool,
    closed: Arc<AtomicBool>,
    tcp: Mutex<Vec<Weak<TcpFlow>>>,
}

impl Client {
    fn new(host: &str, port: u16, settings: &Settings) -> Result<Self, OpenError> {
        if settings
            .keys()
            .any(|name| !matches!(name, "method" | "password" | "udp" | "address" | "port"))
        {
            return Err(OpenError::Settings);
        }
        address(host, port).map_err(|_| OpenError::Settings)?;
        let kind = method(settings.text("method")?)?;
        let config = remote(kind, settings.text("password")?, host, port)?;
        let udp = match settings.optional_text("udp")? {
            None | Some("true") => true,
            Some("false") => false,
            _ => return Err(OpenError::Settings),
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            config: Arc::new(config),
            context: context::Context::new_shared(config::ServerType::Local),
            network: settings.runtime().map(|runtime| runtime.network.clone()),
            udp,
            closed: Arc::new(AtomicBool::new(false)),
            tcp: Mutex::new(Vec::new()),
        })
    }

    fn dial(&self, transport: Transport, addresses: Vec<SocketAddr>) -> NetworkDial {
        NetworkDial {
            host: self.host.clone(),
            port: self.port,
            transport,
            addresses,
            route: NetworkRoute::Direct,
            timeout: OPEN_WAIT,
            socket_factory: None,
            race: None,
        }
    }

    fn check(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }

    fn tcp_socket(&self) -> io::Result<TcpStream> {
        if let Some(network) = &self.network {
            match network.connect(&self.dial(Transport::Tcp, Vec::new()))? {
                NetworkConnection::Tcp(socket) => Ok(socket),
                _ => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Shadowsocks requires a native TCP carrier",
                )),
            }
        } else {
            kerlico_outbound::connect_system_tcp(&self.host, self.port, OPEN_WAIT)
        }
    }

    fn udp_socket(&self) -> io::Result<(UdpSocket, SocketAddr)> {
        let addresses = match &self.network {
            Some(network) => {
                network.lookup_ip(&self.host, self.port, None, ResolutionSource::Configured)?
            }
            None => kerlico_outbound::lookup_system_addresses(&self.host, self.port)?,
        };
        let mut last = io::Error::from(io::ErrorKind::AddrNotAvailable);
        for peer in addresses {
            let result = if let Some(network) = &self.network {
                network
                    .open_datagram(&self.dial(Transport::Udp, vec![peer]))
                    .and_then(|socket| match socket {
                        NetworkConnection::Udp(socket) => Ok(socket),
                        _ => Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "Shadowsocks requires a native UDP carrier",
                        )),
                    })
            } else {
                kerlico_outbound::open_system_datagram(peer, OPEN_WAIT)
            };
            match result {
                Ok(socket) => return Ok((socket, peer)),
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}

impl Upstream for Client {
    fn open_stream(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        self.check()?;
        let destination = address(host, port)?;
        let socket = self.tcp_socket()?;
        socket.set_nodelay(true)?;
        socket.set_nonblocking(true)?;
        let control = socket.try_clone()?;
        let context = self.context.clone();
        let stream = block(OPEN_WAIT, async {
            let socket = tokio::net::TcpStream::from_std(socket)?;
            tcp::ClientStream::start(socket, context, &self.config, &destination).await
        })?;
        let flow = Arc::new(TcpFlow::new(control, stream));
        let mut tcp = self.tcp.lock().expect("Shadowsocks live TCP");
        self.check()?;
        tcp.retain(|entry| entry.strong_count() != 0);
        if tcp.len() >= 4096 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        tcp.push(Arc::downgrade(&flow));
        Ok(Box::new(Tcp(flow)))
    }

    fn associate(&self) -> io::Result<Box<dyn Association>> {
        self.check()?;
        if !self.udp {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let (socket, peer) = self.udp_socket()?;
        socket.set_write_timeout(Some(FLOW_WAIT))?;
        let mut id = [0u8; 8];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| io::Error::other("cannot generate Shadowsocks session ID"))?;
        Ok(Box::new(Udp {
            socket,
            peer,
            config: self.config.clone(),
            context: self.context.clone(),
            id: u64::from_ne_bytes(id),
            next: AtomicU64::new(0),
            receive: Mutex::default(),
            closed: AtomicBool::new(false),
            parent: self.closed.clone(),
        }))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for flow in self
            .tcp
            .lock()
            .expect("Shadowsocks live TCP")
            .drain(..)
            .filter_map(|weak| weak.upgrade())
        {
            flow.close();
        }
    }
}

struct Tcp(Arc<TcpFlow>);

impl Stream for Tcp {
    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        self.0.read(buf, wait)
    }
    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.0.write(buf)
    }
    fn close(&self) {
        self.0.close();
    }
    fn supports_half_close(&self) -> bool {
        true
    }
    fn finish_write(&self) -> io::Result<()> {
        self.0.finish()
    }
}

#[derive(Default)]
struct UdpReceive {
    bytes: Vec<u8>,
    servers: udp_sessions::ServerSessions,
}

struct Udp {
    socket: UdpSocket,
    peer: SocketAddr,
    config: Arc<config::ServerConfig>,
    context: context::SharedContext,
    id: u64,
    next: AtomicU64,
    receive: Mutex<UdpReceive>,
    closed: AtomicBool,
    parent: Arc<AtomicBool>,
}

impl Udp {
    fn check(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) || self.parent.load(Ordering::Acquire) {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

impl Association for Udp {
    fn send_to(&self, _: SocketAddr, host: &str, port: u16, payload: &[u8]) -> io::Result<()> {
        self.check()?;
        let Ok(addr) = address(host, port) else {
            return Ok(());
        };
        let limit = udp_wire_limit(self.peer);
        if payload.len() > limit {
            return Ok(());
        }
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.id;
        control.packet_id = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        let mut out = BytesMut::new();
        crypto_io::encrypt_client_payload(
            &self.context,
            self.config.method(),
            self.config.key(),
            &addr,
            &control,
            self.config.identity_keys(),
            payload,
            &mut out,
        );
        if out.len() > limit {
            return Ok(());
        }
        self.socket.send_to(&out, self.peer).map(|_| ())
    }

    fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)> {
        let mut rx = self.receive.lock().expect("Shadowsocks UDP receive");
        let UdpReceive { bytes, servers } = &mut *rx;
        bytes.resize(65_536, 0);
        let start = Instant::now();
        loop {
            self.check()?;
            let remaining = wait.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.socket
                .set_read_timeout(Some(remaining.min(FLOW_WAIT)))?;
            let (n, from) = match self.socket.recv_from(bytes) {
                Ok(packet) => packet,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error),
            };
            if from != self.peer {
                continue;
            }
            let Ok((n, address, Some(control))) = crypto_io::decrypt_server_payload(
                &self.context,
                self.config.method(),
                self.config.key(),
                &mut bytes[..n],
            ) else {
                continue;
            };
            if control.client_session_id != self.id || control.server_session_id == self.id {
                continue;
            }
            let (host, port) = target(&address);
            if kerlico_ss2022::address(&host, port).is_err() {
                continue;
            }
            if !servers.accept(control.server_session_id, control.packet_id, Instant::now()) {
                continue;
            }
            return Ok((host, port, bytes[..n].to_vec()));
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

enum Landing {
    Tcp(Box<dyn Stream>),
    Udp(Box<dyn Association>, Destination),
}

pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    dest: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    let client = Client::new(host, port, settings)?;
    Ok(Box::new(match dest.transport() {
        Transport::Tcp => Landing::Tcp(
            client
                .open_stream(dest.host(), dest.port())
                .map_err(|_| OpenError::Transport)?,
        ),
        Transport::Udp => Landing::Udp(
            client.associate().map_err(|_| OpenError::Transport)?,
            dest.clone(),
        ),
    }))
}

impl InboundStream for Landing {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        match self {
            Self::Tcp(tcp) => tcp.read_for(buf, FLOW_WAIT).map_err(map_io),
            Self::Udp(udp, _) => {
                let (_, _, data) = udp.recv_for(FLOW_WAIT).map_err(map_io)?;
                buf.get_mut(..data.len())
                    .ok_or(PlaneFault::Transport)?
                    .copy_from_slice(&data);
                Ok(data.len())
            }
        }
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        match self {
            Self::Tcp(tcp) => tcp.write_all(buf),
            Self::Udp(udp, dest) => udp.send_to(
                SocketAddr::from(([0, 0, 0, 0], 0)),
                dest.host(),
                dest.port(),
                buf,
            ),
        }
        .map(|_| buf.len())
        .map_err(map_io)
    }

    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        match self {
            Self::Tcp(tcp) => tcp.finish_write().map(|_| true).map_err(map_io),
            Self::Udp(..) => Ok(false),
        }
    }
}
