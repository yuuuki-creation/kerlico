//! Protocol carriers and metadata requests use the same owned exit boundary.

mod http;
#[cfg(feature = "system-dns")]
mod system_dns;
#[cfg(feature = "system-dns")]
pub use system_dns::exchange_system_dns;

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kerlico_shared::runtime::{
    FallbackRate, HttpRequest, HttpResponse, Network, NetworkConnection, NetworkDial, NetworkRoute,
    SocketFactory,
};
use kerlico_shared::{Destination, InboundStream, OpenError, PlaneFault, Transport};
use socket2::{Domain, Protocol, Socket, Type};

use crate::{select_exit, BytePipe, Exit, Native, Outbound, Reachability};

thread_local! { static IN_LANDING: Cell<bool> = const { Cell::new(false) }; }

impl Outbound {
    pub fn relay_connected_tcp(&self, client: &TcpStream, target: &TcpStream, rate_bits: u64) -> io::Result<()> {
        const IDLE: Duration = Duration::from_secs(300);
        fn copy(mut source: &TcpStream, mut sink: &TcpStream, seen: &std::sync::Mutex<Instant>, rate_bits: u64) -> io::Result<()> {
            let pace = FallbackRate::new(rate_bits);
            let mut buffer = vec![0; pace.limit(64 * 1024)];
            let result = (|| loop {
                match source.read(&mut buffer) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        *seen.lock().expect("TCP relay activity") = Instant::now();
                        pace.wait(n);
                        sink.write_all(&buffer[..n])?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
                        && seen.lock().expect("TCP relay activity").elapsed() < IDLE => continue,
                    Err(error) => return Err(error),
                }
            })();
            match result {
                Ok(_) => { let _ = sink.shutdown(std::net::Shutdown::Write); Ok(()) }
                Err(error) => {
                    let _ = source.shutdown(std::net::Shutdown::Both);
                    let _ = sink.shutdown(std::net::Shutdown::Both);
                    Err(error)
                }
            }
        }
        for socket in [client, target] {
            socket.set_read_timeout(Some(Duration::from_secs(1)))?;
            socket.set_write_timeout(Some(Duration::from_secs(30)))?;
        }
        let seen = std::sync::Mutex::new(Instant::now());
        std::thread::scope(|scope| {
            let down = scope.spawn(|| copy(target, client, &seen, rate_bits));
            let up = copy(client, target, &seen, rate_bits);
            let down = down.join().map_err(|_| io::Error::other("TCP relay thread failed"))?;
            up.and(down)
        })
    }

    /// A path starting with `@` names a Linux abstract socket, as in Go.
    pub fn connect_unix_transport(&self, path: &std::path::Path) -> io::Result<NetworkConnection> {
        #[cfg(unix)]
        { Ok(NetworkConnection::Stream(Box::new(UnixStream(self.connect_unix_socket(path)?)))) }
        #[cfg(not(unix))]
        { let _ = path; Err(io::Error::new(io::ErrorKind::Unsupported, "Unix origin sockets are unavailable on this platform")) }
    }

    #[cfg(unix)]
    pub fn connect_unix_socket(&self, path: &std::path::Path) -> io::Result<std::os::unix::net::UnixStream> {
        #[cfg(target_os = "linux")]
        if let Some(name) = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()).strip_prefix(b"@") {
            let address = <std::os::unix::net::SocketAddr as std::os::linux::net::SocketAddrExt>::from_abstract_name(name)?;
            return std::os::unix::net::UnixStream::connect_addr(&address);
        }
        std::os::unix::net::UnixStream::connect(path)
    }
    pub fn open_datagram_transport(&self, request: &NetworkDial, native: Native) -> io::Result<NetworkConnection> {
        if request.transport != Transport::Udp { return Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram socket requires UDP")); }
        let exit = selected_exit(request, native)?;
        if matches!(exit, Exit::NativeV4 | Exit::NativeV6) {
            let peer = request.addresses.iter().copied().find(|peer| peer.is_ipv4() == exit.is_v4())
                .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "datagram socket has no peer address"))?;
            open_native_udp(request, peer, false)
        } else { self.connect_transport(request, native) }
    }
    /// Opens an already resolved transport request. This does not select a
    /// fallback exit after failure, and does not resolve destination names.
    pub fn connect_transport(
        &self,
        request: &NetworkDial,
        native: Native,
    ) -> io::Result<NetworkConnection> {
        let exit = selected_exit(request, native)?;
        if matches!(exit, Exit::WarpV4 | Exit::WarpV6 | Exit::Landing)
            && request
                .socket_factory
                .as_ref()
                .is_some_and(|factory| factory.requires_native_socket())
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native socket options cannot be applied to a WARP or landing carrier",
            ));
        }
        if exit == Exit::Landing {
            let recursive = IN_LANDING.with(|active| active.replace(true));
            if recursive {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "recursive landing carrier",
                ));
            }
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    IN_LANDING.with(|active| active.set(false));
                }
            }
            let _reset = Reset;
            let dial = self
                .landing_dial()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "landing is not installed")
                })?;
            let destination = Destination::new(&request.host, request.port, request.transport)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid carrier destination")
                })?;
            let stream = dial(&destination).map_err(open_error)?;
            return Ok(NetworkConnection::Stream(Box::new(LandingStream {
                stream: Arc::from(stream),
                timeout: request.timeout,
            })));
        }
        let peer = request
            .addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == exit.is_v4())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "carrier has no address in the selected family",
                )
            })?;
        match exit {
            Exit::NativeV4 | Exit::NativeV6 => {
                if request.race.is_some() {
                    race_native(request, exit)
                } else {
                    open_native(request, peer)
                }
            }
            Exit::WarpV4 | Exit::WarpV6 => {
                let device = self.warp.get().map_err(open_error)?;
                let pipe = match request.transport {
                    Transport::Tcp => device.connect_tcp(peer),
                    Transport::Udp => device.connect_udp(peer),
                }
                .map_err(open_error)?;
                Ok(NetworkConnection::Stream(Box::new(WarpStream {
                    pipe: Arc::from(pipe),
                    timeout: request.timeout,
                })))
            }
            Exit::Landing => unreachable!(),
        }
    }

    pub fn exchange_dns_transport(
        &self,
        request: &NetworkDial,
        message: &[u8],
        native: Native,
    ) -> io::Result<Vec<u8>> {
        exchange_dns(request.transport, message, || self.connect_transport(request, native))
    }

    pub fn exchange_http_transport(
        &self,
        request: &HttpRequest,
        native: Native,
    ) -> io::Result<HttpResponse> {
        if request.dial.transport != Transport::Tcp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP metadata requires TCP",
            ));
        }
        let stream = self.connect_transport(&request.dial, native)?;
        http::exchange(request.clone(), stream)
    }
}

/// A standalone client can use the OS resolver and connect without server exit selection.
pub fn connect_system_tcp(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let bare = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(host);
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address for the server");
    for peer in (bare, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&peer, timeout) {
            Ok(tcp) => return Ok(tcp),
            Err(error) => last = error,
        }
    }
    Err(last)
}

pub fn lookup_system_addresses(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    (host.trim_matches(['[', ']']), port).to_socket_addrs().map(Iterator::collect)
}

pub fn connect_system_peer(peer: SocketAddr, transport: Transport, timeout: Duration) -> io::Result<NetworkConnection> {
    open_native_udp(&system_peer_request(peer, transport, timeout), peer, true)
}

/// An unconnected socket lets the QUIC transport address its peer directly.
pub fn open_system_datagram(peer: SocketAddr, timeout: Duration) -> io::Result<UdpSocket> {
    let request = system_peer_request(peer, Transport::Udp, timeout);
    match open_native_udp(&request, peer, false)? {
        NetworkConnection::Udp(socket) => Ok(socket),
        _ => unreachable!("UDP requested"),
    }
}

fn system_peer_request(peer: SocketAddr, transport: Transport, timeout: Duration) -> NetworkDial {
    NetworkDial {
        host: peer.ip().to_string(), port: peer.port(), transport, addresses: vec![peer],
        route: NetworkRoute::Direct, timeout, socket_factory: None, race: None,
    }
}

/// Opens one unconnected carrier for an IP tunnel. A dual-stack carrier uses the same port
/// for both families and can keep it when an authenticated peer moves to the other family.
pub fn open_tunnel_datagram(
    network: Option<&dyn Network>,
    peer: SocketAddr,
    dual_stack: bool,
) -> io::Result<UdpSocket> {
    open_tunnel_datagram_at(network, peer, dual_stack, 0)
}

/// Reopens an IP tunnel carrier on a previously assigned local port.
pub fn open_tunnel_datagram_at(
    network: Option<&dyn Network>,
    peer: SocketAddr,
    dual_stack: bool,
    local_port: u16,
) -> io::Result<UdpSocket> {
    let peer = if dual_stack {
        match peer {
            SocketAddr::V4(addr) => (addr.ip().to_ipv6_mapped(), addr.port()).into(),
            _ => peer,
        }
    } else {
        peer
    };
    let mut request = NetworkDial::direct(peer, Transport::Udp);
    if dual_stack || local_port != 0 {
        request.socket_factory = Some(Arc::new(TunnelUdp { dual_stack, local_port }));
    }
    let connection = match network {
        Some(network) => network.open_datagram(&request),
        None => open_native_udp(&request, peer, false),
    }?;
    match connection {
        NetworkConnection::Udp(socket) => Ok(socket),
        _ => Err(io::Error::new(io::ErrorKind::Unsupported, "tunnel needs a native UDP socket")),
    }
}

#[derive(Debug)]
struct TunnelUdp {
    dual_stack: bool,
    local_port: u16,
}

impl SocketFactory for TunnelUdp {
    fn open(&self, peer: SocketAddr, transport: Transport) -> io::Result<Socket> {
        if transport != Transport::Udp {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.dual_stack {
            dual_stack_udp_socket()
        } else {
            Socket::new(Domain::for_address(peer), Type::DGRAM, Some(Protocol::UDP))
        }
    }

    fn udp_bind_port(&self) -> u16 {
        self.local_port
    }
}

pub(crate) fn dual_stack_udp_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    Ok(socket)
}

fn exchange_dns(
    transport: Transport,
    message: &[u8],
    connect: impl FnOnce() -> io::Result<NetworkConnection>,
) -> io::Result<Vec<u8>> {
    if message.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS message exceeds 65535 bytes",
        ));
    }
    let mut stream = connect()?;
    if transport == Transport::Tcp {
        stream.write_all(&(message.len() as u16).to_be_bytes())?;
    }
    stream.write_all(message)?;
    stream.flush()?;
    if transport == Transport::Tcp {
        let mut length = [0; 2];
        stream.read_exact(&mut length)?;
        let mut body = vec![0; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut body)?;
        Ok(body)
    } else {
        let mut body = vec![0; u16::MAX as usize];
        let length = stream.read(&mut body)?;
        body.truncate(length);
        Ok(body)
    }
}

#[cfg(unix)]
struct UnixStream(std::os::unix::net::UnixStream);
#[cfg(unix)]
impl Read for UnixStream { fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> { self.0.read(bytes) } }
#[cfg(unix)]
impl Write for UnixStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.0.write(bytes) }
    fn flush(&mut self) -> io::Result<()> { self.0.flush() }
}
#[cfg(unix)]
impl kerlico_shared::runtime::NetworkStream for UnixStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> { self.0.set_read_timeout(Some(timeout))?; self.0.set_write_timeout(Some(timeout)) }
    fn set_nonblocking(&self, enabled: bool) -> io::Result<()> { self.0.set_nonblocking(enabled) }
    fn split(self: Box<Self>) -> io::Result<kerlico_shared::runtime::NetworkPair> { Ok((Box::new(Self(self.0.try_clone()?)), self)) }
}
#[cfg(unix)]
impl kerlico_shared::runtime::NetworkRead for UnixStream { fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> { self.0.set_read_timeout(Some(timeout)) } }
#[cfg(unix)]
impl kerlico_shared::runtime::NetworkWrite for UnixStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> { self.0.set_write_timeout(Some(timeout)) }
    fn shutdown(&mut self) -> io::Result<()> { self.0.shutdown(std::net::Shutdown::Write) }
}

fn selected_exit(request: &NetworkDial, native: Native) -> io::Result<Exit> {
    if request.port == 0 || request.host.is_empty() || request.timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid carrier destination or timeout",
        ));
    }
    let NetworkRoute::Selected(choice) = request.route else {
        return match request.addresses.first() {
            Some(peer) if peer.is_ipv4() => Ok(Exit::NativeV4),
            Some(_) => Ok(Exit::NativeV6),
            None => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "unresolved direct carrier",
            )),
        };
    };
    let reach = if request.addresses.iter().any(SocketAddr::is_ipv4) {
        Reachability::HasV4
    } else if request.addresses.is_empty() {
        Reachability::None
    } else {
        Reachability::V6Only
    };
    select_exit(choice, reach, native)
        .map_err(|_| io::Error::new(io::ErrorKind::AddrNotAvailable, "unresolved carrier"))
}

fn open_native(request: &NetworkDial, peer: SocketAddr) -> io::Result<NetworkConnection> {
    open_native_udp(request, peer, true)
}

fn open_native_udp(request: &NetworkDial, peer: SocketAddr, connected: bool) -> io::Result<NetworkConnection> {
    let socket = if let Some(factory) = &request.socket_factory {
        factory.open(peer, request.transport)?
    } else {
        let (kind, protocol) = match request.transport {
            Transport::Tcp => (Type::STREAM, Protocol::TCP),
            Transport::Udp => (Type::DGRAM, Protocol::UDP),
        };
        Socket::new(Domain::for_address(peer), kind, Some(protocol))?
    };
    socket.set_read_timeout(Some(request.timeout))?;
    socket.set_write_timeout(Some(request.timeout))?;
    match request.transport {
        Transport::Tcp => {
            socket.connect_timeout(&peer.into(), request.timeout)?;
            if let Err(error) = socket.set_tcp_nodelay(true) {
                if error.kind() != io::ErrorKind::Unsupported {
                    return Err(error);
                }
            }
            Ok(NetworkConnection::Tcp(TcpStream::from(socket)))
        }
        Transport::Udp => {
            let port = request
                .socket_factory
                .as_ref()
                .map_or(0, |factory| factory.udp_bind_port());
            let bind = if peer.is_ipv4() {
                SocketAddr::from(([0; 4], port))
            } else {
                SocketAddr::from(([0; 8], port))
            };
            socket.bind(&bind.into())?;
            if connected { socket.connect(&peer.into())?; }
            Ok(NetworkConnection::Udp(UdpSocket::from(socket)))
        }
    }
}

fn race_native(request: &NetworkDial, exit: Exit) -> io::Result<NetworkConnection> {
    let race = request.race.expect("racing request");
    if race.delay.is_zero() || race.max_concurrent == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "carrier race needs a delay and concurrency limit",
        ));
    }
    let candidates: Vec<_> = request
        .addresses
        .iter()
        .copied()
        .filter(|peer| request.route == NetworkRoute::Direct || peer.is_ipv4() == exit.is_v4())
        .collect();
    let (send, receive) = std::sync::mpsc::channel();
    let deadline = Instant::now() + request.timeout;
    let mut next_launch = Instant::now();
    let mut next = 0;
    let mut active = 0;
    let mut error = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "carrier has no address in the selected family",
    );
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "carrier connect race timed out",
            ));
        }
        if next < candidates.len()
            && active < race.max_concurrent
            && (active == 0 || now >= next_launch)
        {
            let peer = candidates[next];
            next += 1;
            active += 1;
            let mut request = request.clone();
            request.timeout = deadline.saturating_duration_since(now);
            let send = send.clone();
            std::thread::spawn(move || {
                let _ = send.send(open_native(&request, peer));
            });
            next_launch = now + race.delay;
        }
        if active == 0 && next == candidates.len() {
            return Err(error);
        }
        let wake = if next < candidates.len() && active < race.max_concurrent {
            next_launch.min(deadline)
        } else {
            deadline
        };
        match receive.recv_timeout(wake.saturating_duration_since(Instant::now())) {
            Ok(Ok(connection)) => return Ok(connection),
            Ok(Err(failed)) => {
                active -= 1;
                error = failed;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(error),
        }
    }
}

#[derive(Clone)]
struct WarpStream {
    pipe: Arc<dyn BytePipe + Send>,
    timeout: Duration,
}
impl kerlico_shared::runtime::NetworkStream for WarpStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }
    fn split(self: Box<Self>) -> io::Result<kerlico_shared::runtime::NetworkPair> {
        Ok((Box::new((*self).clone()), self))
    }
}
impl kerlico_shared::runtime::NetworkRead for WarpStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }
}
impl kerlico_shared::runtime::NetworkWrite for WarpStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }
}
impl Read for WarpStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        retry(self.timeout, || {
            self.pipe.read_pipe(bytes).map_err(open_error)
        })
    }
}
impl Write for WarpStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        retry(self.timeout, || {
            self.pipe.write_pipe(bytes).map_err(open_error)
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Clone)]
struct LandingStream {
    stream: Arc<dyn InboundStream>,
    timeout: Duration,
}
impl kerlico_shared::runtime::NetworkStream for LandingStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }
    fn split(self: Box<Self>) -> io::Result<kerlico_shared::runtime::NetworkPair> {
        Ok((Box::new((*self).clone()), self))
    }
}
impl kerlico_shared::runtime::NetworkRead for LandingStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }
}
impl kerlico_shared::runtime::NetworkWrite for LandingStream {
    fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }
}
impl Read for LandingStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        retry(self.timeout, || match self.stream.read_from_user(bytes) {
            Err(PlaneFault::Closed) => Ok(0),
            result => result.map_err(plane_error),
        })
    }
}
impl Write for LandingStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        retry(self.timeout, || {
            self.stream.write_to_user(bytes).map_err(plane_error)
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn retry<T>(timeout: Duration, mut action: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let started = Instant::now();
    loop {
        match action() {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && started.elapsed() < timeout =>
            {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "carrier timed out"))
            }
            result => return result,
        }
    }
}
fn open_error(error: OpenError) -> io::Error {
    io::Error::new(
        match error {
            OpenError::Again => io::ErrorKind::WouldBlock,
            OpenError::Settings => io::ErrorKind::InvalidInput,
            OpenError::Transport => io::ErrorKind::ConnectionAborted,
        },
        "carrier transport",
    )
}
fn plane_error(error: PlaneFault) -> io::Error {
    io::Error::new(
        match error {
            PlaneFault::Again => io::ErrorKind::WouldBlock,
            PlaneFault::Closed => io::ErrorKind::UnexpectedEof,
            PlaneFault::Transport => io::ErrorKind::ConnectionAborted,
        },
        "landing carrier",
    )
}

#[cfg(test)]
mod tests;
