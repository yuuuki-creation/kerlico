//! SOCKS5 client for the local proxy and server landing roles.

use kerlico_shared::runtime::{
    Network, NetworkConnection, NetworkDial, NetworkRoute, ResolutionSource,
};
use kerlico_shared::{
    Association, ClientEntry, Destination, InboundStream, OpenError, PeerAddr, PlaneFault,
    Settings, Stream, Transport, Upstream,
};
use kerlico_socks::{decode, decode_udp, encode, invalid, Address};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

pub const CLIENT: ClientEntry = ClientEntry::ProxyWithDatagramLanding(upstream);

const OPEN_WAIT: Duration = Duration::from_secs(10);
const FLOW_WAIT: Duration = Duration::from_millis(200);
const MAX_WIRE: usize = 65_507;

#[derive(Default)]
struct Connections {
    closed: bool,
    sockets: Vec<Weak<TcpStream>>,
}

struct Client {
    endpoint: Address,
    credentials: Option<(String, String)>,
    network: Option<Arc<dyn Network>>,
    live: Mutex<Connections>,
}

fn upstream(peer: &PeerAddr, settings: &Settings) -> Result<Arc<dyn Upstream>, OpenError> {
    Ok(Arc::new(Client::new(peer.host(), peer.port(), settings)?))
}

impl Client {
    fn new(host: &str, port: u16, settings: &Settings) -> Result<Self, OpenError> {
        if host.is_empty()
            || port == 0
            || settings
                .keys()
                .any(|key| !matches!(key, "user" | "pass" | "address" | "port"))
        {
            return Err(OpenError::Settings);
        }
        let credentials = match (
            settings.optional_text("user")?,
            settings.optional_text("pass")?,
        ) {
            (None, None) => None,
            (Some(user), Some(pass))
                if (1..=255).contains(&user.len()) && (1..=255).contains(&pass.len()) =>
            {
                Some((user.to_owned(), pass.to_owned()))
            }
            _ => return Err(OpenError::Settings),
        };
        Ok(Self {
            endpoint: Address {
                host: host.to_owned(),
                port,
            },
            credentials,
            network: settings.runtime().map(|runtime| runtime.network.clone()),
            live: Mutex::new(Connections::default()),
        })
    }

    fn dial(address: &Address, transport: Transport, addresses: Vec<SocketAddr>) -> NetworkDial {
        NetworkDial {
            host: address.host.clone(),
            port: address.port,
            transport,
            addresses,
            route: NetworkRoute::Direct,
            timeout: OPEN_WAIT,
            socket_factory: None,
            race: None,
        }
    }

    fn connect(&self, command: u8, address: &Address) -> io::Result<(Arc<TcpStream>, Address)> {
        if self.live.lock().expect("SOCKS5 connections").closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let socket = if let Some(network) = &self.network {
            let NetworkConnection::Tcp(socket) =
                network.connect(&Self::dial(&self.endpoint, Transport::Tcp, Vec::new()))?
            else {
                return Err(io::ErrorKind::Unsupported.into());
            };
            socket
        } else {
            kerlico_outbound::connect_system_tcp(
                &self.endpoint.host,
                self.endpoint.port,
                OPEN_WAIT,
            )?
        };
        socket.set_read_timeout(Some(OPEN_WAIT))?;
        socket.set_write_timeout(Some(OPEN_WAIT))?;
        socket.set_nodelay(true)?;
        let socket = Arc::new(socket);
        {
            let mut live = self.live.lock().expect("SOCKS5 connections");
            if live.closed {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            live.sockets.retain(|socket| socket.strong_count() != 0);
            live.sockets.push(Arc::downgrade(&socket));
        }
        let mut stream = &*socket;
        let method = if self.credentials.is_some() { 2 } else { 0 };
        stream.write_all(&[5, 1, method])?;
        let mut answer = [0; 2];
        stream.read_exact(&mut answer)?;
        if answer != [5, method] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 authentication method refused",
            ));
        }
        if let Some((user, pass)) = &self.credentials {
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.extend([1, user.len() as u8]);
            auth.extend(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend(pass.as_bytes());
            stream.write_all(&auth)?;
            stream.read_exact(&mut answer)?;
            if answer != [1, 0] {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 authentication failed",
                ));
            }
        }
        let mut request = vec![5, command, 0];
        encode(&mut request, address)?;
        stream.write_all(&request)?;
        let relay = read_reply(stream)?;
        stream.set_read_timeout(Some(FLOW_WAIT))?;
        Ok((socket, relay))
    }

    fn tcp(&self, host: &str, port: u16) -> io::Result<Plain> {
        if port == 0 {
            return Err(invalid());
        }
        let (socket, _) = self.connect(
            1,
            &Address {
                host: host.into(),
                port,
            },
        )?;
        Ok(Plain(socket))
    }
}

impl Upstream for Client {
    fn open_stream(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        Ok(Box::new(self.tcp(host, port)?))
    }

    fn associate(&self) -> io::Result<Box<dyn Association>> {
        let (control, mut relay) = self.connect(
            3,
            &Address {
                host: "0.0.0.0".into(),
                port: 0,
            },
        )?;
        if relay.port == 0 {
            return Err(invalid());
        }
        if relay
            .host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_unspecified())
        {
            relay.host = control.peer_addr()?.ip().to_string();
        }
        let addresses = if let Some(network) = &self.network {
            network.lookup_ip(&relay.host, relay.port, None, ResolutionSource::Configured)?
        } else {
            kerlico_outbound::lookup_system_addresses(&relay.host, relay.port)?
        };
        let endpoint = addresses
            .first()
            .copied()
            .ok_or(io::ErrorKind::AddrNotAvailable)?;
        let socket = if let Some(network) = &self.network {
            let NetworkConnection::Udp(socket) =
                network.open_datagram(&Self::dial(&relay, Transport::Udp, vec![endpoint]))?
            else {
                return Err(io::ErrorKind::Unsupported.into());
            };
            socket
        } else {
            kerlico_outbound::open_system_datagram(endpoint, OPEN_WAIT)?
        };
        socket.connect(endpoint)?;
        control.set_nonblocking(true)?;
        Ok(Box::new(Datagram {
            control,
            socket,
            receive: Mutex::new(vec![0; MAX_WIRE + 1]),
        }))
    }

    fn close(&self) {
        let mut live = self.live.lock().expect("SOCKS5 connections");
        live.closed = true;
        for socket in live.sockets.drain(..).filter_map(|socket| socket.upgrade()) {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

fn read_reply(mut stream: &TcpStream) -> io::Result<Address> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 5 || header[2] != 0 {
        return Err(invalid());
    }
    if header[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "SOCKS5 request refused",
        ));
    }
    let mut bytes = [0; 259];
    bytes[0] = header[3];
    let (offset, length) = match header[3] {
        1 => (1, 6),
        4 => (1, 18),
        3 => {
            stream.read_exact(&mut bytes[1..2])?;
            (2, usize::from(bytes[1]) + 2)
        }
        _ => return Err(invalid()),
    };
    stream.read_exact(&mut bytes[offset..offset + length])?;
    decode(&bytes[..offset + length]).map(|(address, _)| address)
}

struct Plain(Arc<TcpStream>);
impl Stream for Plain {
    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        if wait.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.0.set_read_timeout(Some(wait))?;
        (&*self.0).read(buf)
    }
    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        (&*self.0).write_all(buf)
    }
    fn finish_write(&self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }
    fn supports_half_close(&self) -> bool {
        true
    }
    fn close(&self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

struct Datagram {
    control: Arc<TcpStream>,
    socket: UdpSocket,
    receive: Mutex<Vec<u8>>,
}

impl Datagram {
    fn check(&self) -> io::Result<()> {
        match self.control.peek(&mut [0]) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Ok(_) => Err(io::ErrorKind::BrokenPipe.into()),
            Err(error) => Err(error),
        }
    }
}

impl Association for Datagram {
    fn send_to(&self, _: SocketAddr, host: &str, port: u16, payload: &[u8]) -> io::Result<()> {
        self.check()?;
        if port == 0 || payload.len() > MAX_WIRE {
            return Ok(());
        }
        let mut wire = Vec::with_capacity(payload.len() + 22);
        wire.extend([0, 0, 0]);
        if encode(
            &mut wire,
            &Address {
                host: host.into(),
                port,
            },
        )
        .is_err()
            || wire.len() + payload.len() > MAX_WIRE
        {
            return Ok(());
        }
        wire.extend_from_slice(payload);
        self.socket.send(&wire)?;
        Ok(())
    }

    fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)> {
        let started = Instant::now();
        let mut bytes = self.receive.lock().expect("SOCKS5 datagrams");
        loop {
            self.check()?;
            let remaining = wait.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.socket
                .set_read_timeout(Some(remaining.min(FLOW_WAIT)))?;
            let n = match self.socket.recv(&mut bytes) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                result => result?,
            };
            if n <= MAX_WIRE {
                if let Ok((address, payload)) = decode_udp(&bytes[..n]) {
                    if address.port != 0 {
                        return Ok((address.host, address.port, payload.to_vec()));
                    }
                }
            }
        }
    }

    fn close(&self) {
        let _ = self.control.shutdown(Shutdown::Both);
    }
}

fn map_io(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
            PlaneFault::Again
        }
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    target: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    let client = Client::new(host, port, settings)?;
    Ok(Box::new(match target.transport() {
        Transport::Tcp => Landing::Tcp(
            client
                .tcp(target.host(), target.port())
                .map_err(|_| OpenError::Transport)?,
        ),
        Transport::Udp => Landing::Udp(
            client.associate().map_err(|_| OpenError::Transport)?,
            target.clone(),
        ),
    }))
}

enum Landing {
    Tcp(Plain),
    Udp(Box<dyn Association>, Destination),
}

impl InboundStream for Landing {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        match self {
            Self::Tcp(stream) => stream.read_for(buf, FLOW_WAIT).map_err(map_io),
            Self::Udp(association, _) => {
                let (_, _, data) = association.recv_for(FLOW_WAIT).map_err(map_io)?;
                buf.get_mut(..data.len())
                    .ok_or(PlaneFault::Transport)?
                    .copy_from_slice(&data);
                Ok(data.len())
            }
        }
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        match self {
            Self::Tcp(stream) => stream.write_all(buf),
            Self::Udp(association, target) => {
                association.send_to(([0; 4], 0).into(), target.host(), target.port(), buf)
            }
        }
        .map_err(map_io)?;
        Ok(buf.len())
    }

    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        match self {
            Self::Tcp(stream) => stream.finish_write().map(|()| true).map_err(map_io),
            Self::Udp(..) => Ok(false),
        }
    }
}
