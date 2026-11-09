//! Services supplied by the owning application to protocol transports.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use crate::{OutboundChoice, Transport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionSource {
    Configured,
    System,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SrvRecord {
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

/// Creates and configures an unconnected native socket. Only the outbound
/// owner binds and connects it. Protocol-specific options remain with the protocol.
pub trait SocketFactory: fmt::Debug + Send + Sync {
    fn open(&self, peer: SocketAddr, transport: Transport) -> io::Result<socket2::Socket>;
    fn requires_native_socket(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRoute {
    /// An unproxied carrier connects directly using the native socket.
    Direct,
    /// DNS, metadata, and explicit carrier selectors use the five-exit policy.
    Selected(OutboundChoice),
}

#[derive(Clone, Debug)]
pub struct NetworkDial {
    pub host: String,
    pub port: u16,
    pub transport: Transport,
    pub addresses: Vec<SocketAddr>,
    pub route: NetworkRoute,
    pub socket_factory: Option<Arc<dyn SocketFactory>>,
    pub timeout: Duration,
    pub race: Option<ConnectRace>,
}

#[derive(Clone, Copy, Debug)]
pub struct ConnectRace {
    pub delay: Duration,
    pub max_concurrent: usize,
}

impl NetworkDial {
    pub fn direct(peer: SocketAddr, transport: Transport) -> Self {
        Self {
            host: peer.ip().to_string(),
            port: peer.port(),
            transport,
            addresses: vec![peer],
            route: NetworkRoute::Direct,
            socket_factory: None,
            timeout: Duration::from_secs(10),
            race: None,
        }
    }
}

/// A connected carrier. Native descriptors stay available to QUIC and the
/// asynchronous transport layers; WARP and landing retain their real transport.
pub enum NetworkConnection {
    Tcp(TcpStream),
    Udp(UdpSocket),
    Stream(Box<dyn NetworkStream>),
}

pub trait NetworkStream: Read + Write + Send {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()>;
    fn split(self: Box<Self>) -> io::Result<NetworkPair>;
}

pub trait NetworkRead: Read + Send {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()>;
}
pub trait NetworkWrite: Write + Send {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()>;
}
pub type NetworkPair = (Box<dyn NetworkRead>, Box<dyn NetworkWrite>);

impl NetworkConnection {
    pub fn split(self) -> io::Result<NetworkPair> {
        match self {
            Self::Tcp(socket) => Ok((
                Box::new(TcpHalf(socket.try_clone()?)),
                Box::new(TcpHalf(socket)),
            )),
            Self::Udp(socket) => Ok((
                Box::new(UdpHalf(socket.try_clone()?)),
                Box::new(UdpHalf(socket)),
            )),
            Self::Stream(stream) => stream.split(),
        }
    }
    pub fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Tcp(socket) => {
                socket.set_read_timeout(Some(timeout))?;
                socket.set_write_timeout(Some(timeout))
            }
            Self::Udp(socket) => {
                socket.set_read_timeout(Some(timeout))?;
                socket.set_write_timeout(Some(timeout))
            }
            Self::Stream(stream) => stream.set_timeout(timeout),
        }
    }
}

struct TcpHalf(TcpStream);
impl Read for TcpHalf {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Write for TcpHalf {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl NetworkRead for TcpHalf {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.0.set_read_timeout(Some(timeout))
    }
}
impl NetworkWrite for TcpHalf {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.0.set_write_timeout(Some(timeout))
    }
}
struct UdpHalf(UdpSocket);
impl Read for UdpHalf {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.recv(bytes)
    }
}
impl Write for UdpHalf {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.send(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl NetworkRead for UdpHalf {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.0.set_read_timeout(Some(timeout))
    }
}
impl NetworkWrite for UdpHalf {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.0.set_write_timeout(Some(timeout))
    }
}

impl Read for NetworkConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(bytes),
            Self::Udp(s) => s.recv(bytes),
            Self::Stream(s) => s.read(bytes),
        }
    }
}
impl Write for NetworkConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(bytes),
            Self::Udp(s) => s.send(bytes),
            Self::Stream(s) => s.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Udp(_) => Ok(()),
            Self::Stream(s) => s.flush(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub http2: bool,
    pub dial: NetworkDial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// DNS and physical connection ownership stay in the embedding application.
/// The methods have defaults so a host can provide only the capabilities it owns.
pub trait Network: fmt::Debug + Send + Sync {
    fn lookup_ip(
        &self,
        host: &str,
        port: u16,
        family: Option<AddressFamily>,
        source: ResolutionSource,
    ) -> io::Result<Vec<SocketAddr>>;
    fn lookup_srv(&self, _name: &str) -> io::Result<Vec<SrvRecord>> {
        Err(unsupported("SRV lookup"))
    }
    fn lookup_txt(&self, _name: &str) -> io::Result<Vec<String>> {
        Err(unsupported("TXT lookup"))
    }
    fn connect(&self, _request: &NetworkDial) -> io::Result<NetworkConnection> {
        Err(unsupported("transport dial"))
    }
    fn open_datagram(&self, request: &NetworkDial) -> io::Result<NetworkConnection> {
        self.connect(request)
    }
    fn connect_unix(&self, _path: &std::path::Path) -> io::Result<NetworkConnection> {
        Err(unsupported("Unix stream dial"))
    }
    fn exchange_dns(&self, _request: &NetworkDial, _message: &[u8]) -> io::Result<Vec<u8>> {
        Err(unsupported("DNS exchange"))
    }
    fn exchange_http(&self, _request: &HttpRequest) -> io::Result<HttpResponse> {
        Err(unsupported("HTTP exchange"))
    }
}

#[derive(Clone)]
pub struct GeoIpSet {
    pub has_ipv4: bool,
    pub has_ipv6: bool,
    contains: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>,
}

impl GeoIpSet {
    pub fn new(
        has_ipv4: bool,
        has_ipv6: bool,
        contains: impl Fn(IpAddr) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            has_ipv4,
            has_ipv6,
            contains: Arc::new(contains),
        }
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        (self.contains)(ip)
    }
}

pub trait GeoIpCatalog: fmt::Debug + Send + Sync {
    fn load(&self, file: &str, category: &str) -> io::Result<GeoIpSet>;
}

#[derive(Debug)]
pub struct RuntimeContext {
    pub network: Arc<dyn Network>,
    pub geoip: Arc<dyn GeoIpCatalog>,
}

fn unsupported(service: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("host does not provide {service}"),
    )
}
