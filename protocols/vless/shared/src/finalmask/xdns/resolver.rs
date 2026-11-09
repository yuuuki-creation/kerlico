use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::TlsNetwork;

use super::super::{invalid, retryable, PacketIo, UdpDial, UDP_SIZE};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_millis(50);
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) trait Resolver: Send + Sync {
    fn send(&self, query: &[u8]) -> io::Result<()>;
    fn recv(&self, reply: &mut [u8], alive: &AtomicBool) -> io::Result<usize>;
    fn close(&self) {}
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ResolverConfig {
    addrs: Vec<String>,
    worker: u16,
    tls_config: Option<Value>,
    quic_config: Option<Value>,
}

#[derive(Clone)]
pub(super) enum Config {
    Udp(String, u16),
    Tcp(String, u16),
    Https {
        url: Url,
        workers: u16,
        tls: Option<Value>,
        quic: Option<Value>,
    },
}

impl ResolverConfig {
    pub(super) fn resolvers(self) -> io::Result<Vec<Config>> {
        self.addrs
            .into_iter()
            .map(|address| {
                let url = if address.contains("://") {
                    Url::parse(&address)
                } else {
                    Url::parse(&format!("udp://{address}"))
                }
                .map_err(invalid)?;
                let host = url
                    .host_str()
                    .ok_or_else(|| invalid("XDNS resolver requires a host"))?
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned();
                let port = url.port().unwrap_or(53);
                if port == 0 {
                    return Err(invalid("XDNS resolver port cannot be zero"));
                }
                Ok(match url.scheme() {
                    "udp" => Config::Udp(host, port),
                    "tcp" => Config::Tcp(host, port),
                    "https" => Config::Https {
                        url,
                        workers: if self.worker == 0 { 32 } else { self.worker },
                        tls: self.tls_config.clone(),
                        quic: self.quic_config.clone(),
                    },
                    _ => return Err(invalid("XDNS resolver scheme must be udp, tcp, or https")),
                })
            })
            .collect()
    }
}

impl Config {
    pub(super) fn connect(
        &self,
        dial: UdpDial,
        network: Option<Arc<dyn TlsNetwork>>,
        carrier: Option<Arc<crate::runtime::CarrierNetwork>>,
        cache: Option<Arc<crate::AdvancedTlsClientCache>>,
    ) -> io::Result<Arc<dyn Resolver>> {
        match self {
            Self::Udp(host, port) => {
                let (socket, peer) = if let Some(carrier) = &carrier { carrier.packet_target(host, *port, READ_TIMEOUT)? }
                    else { dial_first(host, *port, None, |peer| dial(peer))? };
                let dial = if let Some(carrier) = carrier { let host = host.clone(); let port = *port; Arc::new(move |_| carrier.packet_target(&host, port, READ_TIMEOUT).map(|pair| pair.0)) as UdpDial } else { dial };
                Ok(Arc::new(Udp {
                    dial,
                    peer,
                    conn: Mutex::new(Some(socket)),
                }))
            }
            Self::Tcp(host, port) => {
                let (conn, host, port) = if let Some(carrier) = &carrier { (Tcp::dial(host, *port, Some(carrier))?, host.clone(), *port) }
                    else { let (conn, peer) = dial_first(host, *port, None, |peer| Tcp::dial(&peer.ip().to_string(), peer.port(), None))?; (conn, peer.ip().to_string(), peer.port()) };
                Ok(Arc::new(Tcp {
                    host,
                    port,
                    conn: Mutex::new(Some(conn)),
                    carrier,
                }))
            }
            Self::Https {
                url,
                workers,
                tls,
                quic,
            } => {
                let tls = tls
                    .clone()
                    .ok_or_else(|| invalid("XDNS DoH resolver requires tlsConfig"))?;
                super::doh::open(url.clone(), *workers, tls, quic.clone(), network, carrier, cache)
            }
        }
    }
}

fn dial_first<T>(
    host: &str,
    port: u16,
    carrier: Option<&crate::runtime::CarrierNetwork>,
    dial: impl Fn(SocketAddr) -> io::Result<T>,
) -> io::Result<(T, SocketAddr)> {
    let mut result = Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "XDNS resolver has no address",
    ));
    let addresses = if let Some(carrier) = carrier { carrier.resolve(host, port, None)? } else { (host, port).to_socket_addrs()?.collect() };
    for addr in addresses {
        match dial(addr) {
            Ok(conn) => return Ok((conn, addr)),
            Err(error) => result = Err(error),
        }
    }
    result
}

struct Udp {
    dial: UdpDial,
    peer: SocketAddr,
    conn: Mutex<Option<Arc<dyn PacketIo>>>,
}

impl Udp {
    fn socket(&self) -> io::Result<Arc<dyn PacketIo>> {
        let mut conn = self.conn.lock().expect("XDNS UDP resolver");
        if let Some(socket) = conn.as_ref() {
            return Ok(socket.clone());
        }
        let socket = (self.dial)(self.peer)?;
        *conn = Some(socket.clone());
        Ok(socket)
    }

    fn forget(&self, socket: &Arc<dyn PacketIo>) {
        let mut conn = self.conn.lock().expect("XDNS UDP resolver");
        if conn.as_ref().is_some_and(|conn| Arc::ptr_eq(conn, socket)) {
            *conn = None;
        }
    }
}

impl Resolver for Udp {
    fn send(&self, query: &[u8]) -> io::Result<()> {
        let socket = self.socket()?;
        match socket.send_to(query, self.peer) {
            Ok(n) if n == query.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial XDNS resolver query",
            )),
            Err(error) => {
                if !retryable(&error) {
                    self.forget(&socket);
                }
                Err(error)
            }
        }
    }

    fn recv(&self, reply: &mut [u8], alive: &AtomicBool) -> io::Result<usize> {
        let socket = self.socket()?;
        while alive.load(Ordering::Acquire) {
            match socket.recv_from(reply) {
                Ok((len, peer)) if peer == self.peer => return Ok(len),
                Ok(_) => {}
                Err(error) => {
                    if !retryable(&error) {
                        self.forget(&socket);
                    }
                    return Err(error);
                }
            }
        }
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

struct TcpConn {
    read: Mutex<Box<dyn kerlico_shared::runtime::NetworkRead>>,
    write: Mutex<Box<dyn kerlico_shared::runtime::NetworkWrite>>,
    control: Option<TcpStream>,
}

struct Tcp {
    host: String,
    port: u16,
    conn: Mutex<Option<Arc<TcpConn>>>,
    carrier: Option<Arc<crate::runtime::CarrierNetwork>>,
}

impl Tcp {
    fn dial(host: &str, port: u16, carrier: Option<&crate::runtime::CarrierNetwork>) -> io::Result<Arc<TcpConn>> {
        let connection = if let Some(carrier) = carrier { carrier.tcp(host, port)? }
            else { let peer = SocketAddr::new(host.parse().map_err(invalid)?, port); kerlico_shared::runtime::NetworkConnection::Tcp(TcpStream::connect_timeout(&peer, CONNECT_TIMEOUT)?) };
        let control = match &connection { kerlico_shared::runtime::NetworkConnection::Tcp(socket) => Some(socket.try_clone()?), _ => None };
        let (mut read, mut write) = connection.split()?;
        read.set_timeout(READ_TIMEOUT)?;
        write.set_timeout(WRITE_TIMEOUT)?;
        Ok(Arc::new(TcpConn {
            read: Mutex::new(read),
            write: Mutex::new(write),
            control,
        }))
    }

    fn socket(&self) -> io::Result<Arc<TcpConn>> {
        let mut conn = self.conn.lock().expect("XDNS TCP resolver");
        if let Some(socket) = conn.as_ref() {
            return Ok(socket.clone());
        }
        let socket = Self::dial(&self.host, self.port, self.carrier.as_deref())?;
        *conn = Some(socket.clone());
        Ok(socket)
    }

    fn forget(&self, socket: &Arc<TcpConn>) {
        let mut conn = self.conn.lock().expect("XDNS TCP resolver");
        if conn.as_ref().is_some_and(|conn| Arc::ptr_eq(conn, socket)) {
            if let Some(control) = &socket.control { let _ = control.shutdown(Shutdown::Both); }
            *conn = None;
        }
    }
}

impl Resolver for Tcp {
    fn send(&self, query: &[u8]) -> io::Result<()> {
        let socket = self.socket()?;
        let mut wire = Vec::with_capacity(query.len() + 2);
        wire.extend_from_slice(&u16::try_from(query.len()).map_err(invalid)?.to_be_bytes());
        wire.extend_from_slice(query);
        let result = socket
            .write
            .lock()
            .expect("XDNS resolver writer")
            .write_all(&wire);
        if result.is_err() {
            // A fresh connection owns the next query if this length-prefixed
            // message was interrupted halfway through a write.
            self.forget(&socket);
        }
        result
    }

    fn recv(&self, reply: &mut [u8], alive: &AtomicBool) -> io::Result<usize> {
        let socket = self.socket()?;
        let mut stream = socket.read.lock().expect("XDNS resolver reader");
        let result = read_frame(&mut **stream, reply, alive);
        if result.is_err() {
            self.forget(&socket);
        }
        result
    }

    fn close(&self) {
        if let Some(socket) = self.conn.lock().expect("XDNS TCP resolver").take() {
            if let Some(control) = &socket.control { let _ = control.shutdown(Shutdown::Both); }
        }
    }
}

fn read_frame(stream: &mut (impl Read + ?Sized), reply: &mut [u8], alive: &AtomicBool) -> io::Result<usize> {
    loop {
        let mut prefix = [0; 2];
        read_full(stream, &mut prefix, alive)?;
        let len = usize::from(u16::from_be_bytes(prefix));
        if len == 0 {
            continue;
        }
        if len > reply.len() {
            let mut remaining = len;
            let mut discard = [0; UDP_SIZE];
            while remaining > 0 {
                let n = remaining.min(discard.len());
                read_full(stream, &mut discard[..n], alive)?;
                remaining -= n;
            }
            continue;
        }
        read_full(stream, &mut reply[..len], alive)?;
        return Ok(len);
    }
}

fn read_full(stream: &mut (impl Read + ?Sized), mut out: &mut [u8], alive: &AtomicBool) -> io::Result<()> {
    while !out.is_empty() && alive.load(Ordering::Acquire) {
        match stream.read(out) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => out = &mut out[n..],
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
    }
    if out.is_empty() {
        Ok(())
    } else {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_dns_uses_context_lookup_and_connected_stream() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let network = crate::runtime::testing::NamedNetwork::new(peer);
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut prefix = [0; 2]; socket.read_exact(&mut prefix).unwrap();
            let mut body = vec![0; u16::from_be_bytes(prefix) as usize]; socket.read_exact(&mut body).unwrap();
            assert_eq!(body, b"owned DNS");
            socket.write_all(&prefix).unwrap(); socket.write_all(&body).unwrap();
        });
        let resolver = Config::Tcp("resolver.invalid".into(), peer.port()).connect(Arc::new(|_| panic!("TCP cannot use UDP fallback")), None, Some(Arc::new(network.carrier())), None).unwrap();
        resolver.send(b"owned DNS").unwrap();
        let mut response = [0; 64];
        let n = resolver.recv(&mut response, &AtomicBool::new(true)).unwrap();
        assert_eq!(&response[..n], b"owned DNS"); resolver.close(); server.join().unwrap();
        assert_eq!(network.connections.load(Ordering::SeqCst), 1);
        assert_eq!(*network.names.lock().unwrap(), ["resolver.invalid"]);
    }
}
