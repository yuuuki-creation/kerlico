//! Adapters from application-owned services to VLESS transport callbacks.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kerlico_shared::runtime::{self as host, Network, NetworkDial, NetworkRoute, RuntimeContext};
use kerlico_shared::{OutboundChoice, Transport};

use crate::socket::{self, DialPlan, SocketKind, SocketOptions, SocketRole, TransportResolver};
use crate::{TlsNetwork, TlsNetworkRequest, TlsNetworkResponse};

pub struct OwnerTls {
    pub network: Arc<dyn TlsNetwork>,
    pub cache: Arc<crate::AdvancedTlsClientCache>,
}

struct TlsOwner {
    owner: std::sync::Weak<RuntimeContext>,
    tls: Arc<OwnerTls>,
}

pub fn owner_tls(context: &Arc<RuntimeContext>) -> Arc<OwnerTls> {
    static OWNERS: std::sync::OnceLock<std::sync::Mutex<Vec<TlsOwner>>> =
        std::sync::OnceLock::new();
    let owner = Arc::downgrade(context);
    let mut owners = OWNERS
        .get_or_init(Default::default)
        .lock()
        .expect("transport TLS owners");
    owners.retain(|entry| entry.owner.strong_count() != 0);
    if let Some(entry) = owners.iter().find(|entry| entry.owner.ptr_eq(&owner)) {
        return entry.tls.clone();
    }
    let tls = Arc::new(OwnerTls {
        network: Arc::new(MetadataNetwork::new(context)),
        cache: Arc::new(crate::AdvancedTlsClientCache::new()),
    });
    owners.push(TlsOwner {
        owner,
        tls: tls.clone(),
    });
    tls
}

#[derive(Clone, Debug)]
pub struct Resolver(pub Arc<dyn Network>);

impl TransportResolver for Resolver {
    fn lookup_ip(
        &self,
        name: &str,
        port: u16,
        family: Option<socket::AddressFamily>,
        source: socket::ResolutionSource,
    ) -> io::Result<Vec<SocketAddr>> {
        self.0.lookup_ip(
            name,
            port,
            family.map(|family| match family {
                socket::AddressFamily::V4 => host::AddressFamily::V4,
                socket::AddressFamily::V6 => host::AddressFamily::V6,
            }),
            match source {
                socket::ResolutionSource::Configured => host::ResolutionSource::Configured,
                socket::ResolutionSource::System => host::ResolutionSource::System,
            },
        )
    }
    fn lookup_srv(&self, name: &str) -> io::Result<Vec<socket::SrvRecord>> {
        self.0.lookup_srv(name).map(|records| {
            records
                .into_iter()
                .map(|record| socket::SrvRecord {
                    target: record.target,
                    port: record.port,
                    priority: record.priority,
                    weight: record.weight,
                })
                .collect()
        })
    }
    fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>> {
        self.0.lookup_txt(name)
    }
}

#[derive(Debug)]
pub struct CarrierSocketFactory(pub SocketOptions);
impl host::SocketFactory for CarrierSocketFactory {
    fn open(&self, peer: SocketAddr, transport: Transport) -> io::Result<socket2::Socket> {
        self.0.open(
            if transport == Transport::Tcp {
                SocketKind::Tcp
            } else {
                SocketKind::Udp
            },
            SocketRole::Dialer,
            peer,
        )
    }
    fn requires_native_socket(&self) -> bool {
        self.0.requires_native_socket()
    }
}

#[derive(Clone, Debug)]
pub struct CarrierNetwork {
    pub network: Arc<dyn Network>,
    pub options: SocketOptions,
    endpoint: Option<(SocketAddr, NetworkDial)>,
}

impl CarrierNetwork {
    pub fn new(network: Arc<dyn Network>, options: SocketOptions) -> Self { Self { network, options, endpoint: None } }

    pub fn endpoint(&self, host: &str, port: u16) -> io::Result<(Arc<Self>, SocketAddr)> {
        let request = self.request(host, port, Transport::Udp)?;
        let peer = match request.addresses.first().copied() {
            Some(peer) => peer,
            None if request.route == NetworkRoute::Selected(OutboundChoice::Manual(kerlico_shared::Exit::Landing)) => SocketAddr::new(std::net::Ipv4Addr::new(192, 0, 2, 1).into(), request.port),
            None => return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "carrier target has no address")),
        };
        let mut carrier = self.clone();
        carrier.endpoint = Some((peer, request));
        Ok((Arc::new(carrier), peer))
    }

    pub fn peer_is_synthetic(&self, peer: SocketAddr) -> bool {
        self.endpoint.as_ref().is_some_and(|(logical, request)| logical.ip() == peer.ip() && request.addresses.is_empty()
            && request.route == NetworkRoute::Selected(OutboundChoice::Manual(kerlico_shared::Exit::Landing)))
    }

    pub fn request(&self, host: &str, port: u16, transport: Transport) -> io::Result<NetworkDial> {
        plan_dial(self.network.clone(), &self.options, host, port, transport, NetworkRoute::Direct)
    }

    pub fn connect(&self, host: &str, port: u16, transport: Transport) -> io::Result<host::NetworkConnection> {
        self.network.connect(&self.request(host, port, transport)?)
    }

    pub fn tcp(&self, host: &str, port: u16) -> io::Result<host::NetworkConnection> { self.connect(host, port, Transport::Tcp) }

    pub fn masquerade_dialer(self: &Arc<Self>) -> crate::MasqueradeDialer {
        let carrier = self.clone();
        Arc::new(move |target| {
            let connection = match target {
                crate::MasqueradeTarget::Tcp { host, port } => carrier.tcp(host, *port)?,
                crate::MasqueradeTarget::Unix(path) => carrier.network.connect_unix(path)?,
            };
            Ok(crate::MasqueradeSocket::Network(connection))
        })
    }

    pub fn resolve(&self, host: &str, port: u16, family: Option<socket::AddressFamily>) -> io::Result<Vec<SocketAddr>> {
        let plan = self.options.plan(host, port, SocketKind::Tcp, family, &Resolver(self.network.clone()))?;
        match plan {
            DialPlan::Direct(plan) => Ok(plan.addresses().to_vec()),
            DialPlan::Proxy(plan) => Resolver(self.network.clone()).lookup_ip(&plan.host, plan.port, family, socket::ResolutionSource::Configured),
        }
    }

    pub fn open_udp(&self, peer: SocketAddr) -> io::Result<host::NetworkConnection> {
        if let Some((logical, request)) = &self.endpoint { if logical.ip() == peer.ip() {
            let mut request = request.clone();
            request.port = peer.port();
            for address in &mut request.addresses { address.set_port(peer.port()); }
            return self.network.open_datagram(&request);
        } }
        self.network.open_datagram(&self.request(&peer.ip().to_string(), peer.port(), Transport::Udp)?)
    }

    pub fn packet(&self, peer: SocketAddr) -> io::Result<Arc<dyn crate::finalmask::PacketIo>> {
        self.packet_with_timeout(peer, Duration::from_millis(50))
    }

    pub fn packet_with_timeout(&self, peer: SocketAddr, poll: Duration) -> io::Result<Arc<dyn crate::finalmask::PacketIo>> {
        packet_connection(self.open_udp(peer)?, peer, poll)
    }

    pub fn packet_target(&self, name: &str, port: u16, poll: Duration) -> io::Result<(Arc<dyn crate::finalmask::PacketIo>, SocketAddr)> {
        let (carrier, peer) = self.endpoint(name, port)?;
        Ok((carrier.packet_with_timeout(peer, poll)?, peer))
    }
}

pub fn packet_connection(connection: host::NetworkConnection, peer: SocketAddr, poll: Duration) -> io::Result<Arc<dyn crate::finalmask::PacketIo>> {
    match connection {
        host::NetworkConnection::Udp(socket) => {
            socket.set_read_timeout(Some(poll))?;
            socket.set_write_timeout(Some(Duration::from_secs(1)))?;
            Ok(Arc::new(socket))
        }
        host::NetworkConnection::Tcp(_) => Err(io::Error::new(io::ErrorKind::InvalidInput, "packet carrier requires UDP")),
        connection => {
            let (mut read, mut write) = connection.split()?;
            read.set_timeout(poll)?;
            write.set_timeout(Duration::from_secs(1))?;
            Ok(Arc::new(ProxyPackets { peer, read: std::sync::Mutex::new(read), write: std::sync::Mutex::new(write) }))
        }
    }
}

struct ProxyPackets {
    peer: SocketAddr,
    read: std::sync::Mutex<Box<dyn host::NetworkRead>>,
    write: std::sync::Mutex<Box<dyn host::NetworkWrite>>,
}
impl crate::finalmask::PacketIo for ProxyPackets {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(if self.peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().expect("packet bind"))
    }
    fn recv_from(&self, bytes: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Ok((self.read.lock().expect("packet reader").read(bytes)?, self.peer))
    }
    fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> io::Result<usize> {
        if peer != self.peer { return Err(io::Error::new(io::ErrorKind::Unsupported, "connected proxy packet carrier cannot change its peer")); }
        self.write.lock().expect("packet writer").write(bytes)
    }
}

/// Keep this Arc stable beside the owner's TLS configuration cache. It holds
/// only the Network callback, so it cannot keep the RuntimeContext owner alive.
#[derive(Clone, Debug)]
pub struct MetadataNetwork(pub Arc<dyn Network>);

impl MetadataNetwork {
    pub fn new(context: &RuntimeContext) -> Self {
        Self(context.network.clone())
    }

    fn dial(
        &self,
        host: &str,
        port: u16,
        transport: Transport,
        settings: &Option<serde_json::Value>,
    ) -> io::Result<NetworkDial> {
        let options = SocketOptions::parse(
            settings
                .as_ref()
                .map(serde_json::Value::to_string)
                .as_deref(),
        )?;
        plan_dial(self.0.clone(), &options, host, port, transport, NetworkRoute::Selected(OutboundChoice::Default))
    }
}

fn plan_dial(network: Arc<dyn Network>, options: &SocketOptions, host: &str, port: u16, transport: Transport, default_route: NetworkRoute) -> io::Result<NetworkDial> {
        let kind = if transport == Transport::Tcp {
            SocketKind::Tcp
        } else {
            SocketKind::Udp
        };
        let plan = options.plan(host, port, kind, None, &Resolver(network.clone()))?;
        let mut race = None;
        let (host, port, addresses, route) = match plan {
            DialPlan::Direct(plan) => {
                race = plan
                    .connect_race()
                    .map(|(delay, max_concurrent)| host::ConnectRace {
                        delay,
                        max_concurrent,
                    });
                (
                    host.to_owned(),
                    port,
                    plan.addresses().to_vec(),
                    default_route,
                )
            }
            DialPlan::Proxy(plan) => {
                let choice = OutboundChoice::parse(&plan.selector).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "sockopt.dialerProxy must name an existing exit or default",
                    )
                })?;
                let addresses = if choice == OutboundChoice::Manual(kerlico_shared::Exit::Landing) { Vec::new() } else {
                    let family = match choice {
                        OutboundChoice::Manual(kerlico_shared::Exit::NativeV4 | kerlico_shared::Exit::WarpV4) => Some(host::AddressFamily::V4),
                        OutboundChoice::Manual(kerlico_shared::Exit::NativeV6 | kerlico_shared::Exit::WarpV6) => Some(host::AddressFamily::V6),
                        _ => None,
                    };
                    network.lookup_ip(&plan.host, plan.port, family, host::ResolutionSource::Configured)?
                };
                (
                    plan.host,
                    plan.port,
                    addresses,
                    NetworkRoute::Selected(choice),
                )
            }
        };
        Ok(NetworkDial {
            host,
            port,
            transport,
            addresses,
            route,
            socket_factory: Some(Arc::new(CarrierSocketFactory(options.clone()))),
            timeout: Duration::from_secs(10),
            race,
        })
}

impl TlsNetwork for MetadataNetwork {
    fn exchange(&self, request: &TlsNetworkRequest) -> io::Result<TlsNetworkResponse> {
        match request {
            TlsNetworkRequest::Dns {
                server,
                tcp,
                message,
                socket_settings,
            } => {
                let url = url::Url::parse(&format!("dns://{server}")).map_err(io::Error::other)?;
                let host = url
                    .host_str()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "DNS metadata server lacks a host",
                        )
                    })?
                    .trim_matches(['[', ']']);
                let dial = self.dial(
                    host,
                    url.port().unwrap_or(53),
                    if *tcp { Transport::Tcp } else { Transport::Udp },
                    socket_settings,
                )?;
                Ok(TlsNetworkResponse {
                    status: 0,
                    body: self.0.exchange_dns(&dial, message)?,
                })
            }
            TlsNetworkRequest::Http {
                url,
                method,
                headers,
                body,
                http2,
                socket_settings,
            } => {
                let parsed = url::Url::parse(url).map_err(io::Error::other)?;
                let host = parsed
                    .host_str()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "HTTP metadata URL lacks a host",
                        )
                    })?
                    .trim_matches(['[', ']']);
                let port = parsed.port_or_known_default().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "HTTP metadata URL lacks a port",
                    )
                })?;
                let dial = self.dial(host, port, Transport::Tcp, socket_settings)?;
                let response = self.0.exchange_http(&host::HttpRequest {
                    url: url.clone(),
                    method: method.clone(),
                    headers: headers.clone(),
                    body: body.clone(),
                    http2: *http2,
                    dial,
                })?;
                Ok(TlsNetworkResponse {
                    status: response.status,
                    body: response.body,
                })
            }
        }
    }
}

pub fn parse_finalmask(
    json: &str,
    context: Option<&Arc<RuntimeContext>>,
    provider: Option<Arc<dyn TlsNetwork>>,
) -> io::Result<crate::finalmask::FinalMask> {
    let owner = context.map(owner_tls);
    let provider = provider.or_else(|| owner.as_ref().map(|owner| owner.network.clone()));
    let masks = crate::finalmask::FinalMask::parse_with_cache(
        json,
        |file, category| {
            let context = context.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "finalmask GeoIP requires an application catalog",
                )
            })?;
            let set = context.geoip.load(file, category)?;
            Ok(crate::finalmask::GeoIpMatcher::new(
                set.has_ipv4,
                set.has_ipv6,
                move |ip| set.contains(ip),
            ))
        },
        provider,
        owner.map(|owner| owner.cache.clone()),
    )?;
    Ok(if let Some(context) = context { masks.with_network(Arc::new(CarrierNetwork::new(context.network.clone(), SocketOptions::default()))) } else { masks })
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    pub struct NamedNetwork {
        pub peer: SocketAddr,
        pub connections: AtomicUsize,
        pub names: std::sync::Mutex<Vec<String>>,
    }
    impl NamedNetwork {
        pub fn new(peer: SocketAddr) -> Arc<Self> { Arc::new(Self { peer, connections: AtomicUsize::new(0), names: Default::default() }) }
        pub fn carrier(self: &Arc<Self>) -> CarrierNetwork { CarrierNetwork::new(self.clone(), SocketOptions::default()) }
    }
    impl Network for NamedNetwork {
        fn lookup_ip(&self, host: &str, _: u16, _: Option<host::AddressFamily>, _: host::ResolutionSource) -> io::Result<Vec<SocketAddr>> {
            self.names.lock().unwrap().push(host.into()); Ok(vec![self.peer])
        }
        fn connect(&self, request: &NetworkDial) -> io::Result<host::NetworkConnection> {
            self.connections.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.route, NetworkRoute::Direct);
            assert_eq!(request.addresses, [self.peer]);
            Ok(host::NetworkConnection::Stream(Box::new(TestStream(std::net::TcpStream::connect(self.peer)?))))
        }
    }
    struct TestStream(std::net::TcpStream);
    impl Read for TestStream { fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> { self.0.read(bytes) } }
    impl Write for TestStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.0.write(bytes) }
        fn flush(&mut self) -> io::Result<()> { self.0.flush() }
    }
    impl host::NetworkStream for TestStream {
        fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> { self.0.set_read_timeout(Some(timeout))?; self.0.set_write_timeout(Some(timeout)) }
        fn split(self: Box<Self>) -> io::Result<host::NetworkPair> { host::NetworkConnection::Tcp(self.0).split() }
    }
}
