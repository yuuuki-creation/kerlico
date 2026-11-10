//! HTTP/3 streams and the Hysteria 2 stream transport over QUIC.

mod congestion;
mod hysteria;
mod masked;
mod masquerade;
mod options;
#[cfg(test)]
mod option_tests;

pub use masquerade::{HysteriaMasquerade, MasqueradeDialer, MasqueradeSocket, MasqueradeTarget};
pub use options::{QuicCarrier, QuicOptions};

use crate::finalmask::FinalMask;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{HeaderMap, Request, Response, Uri};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, TokioRuntime, VarInt};
use rustls::{ClientConfig, ServerConfig};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{runtime::Runtime, sync::mpsc, time::timeout};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const HYSTERIA_STREAM: u64 = 0x401;
const HYSTERIA_PREFIX: [u8; 2] = (HYSTERIA_STREAM as u16 | (1 << 14)).to_be_bytes();
const HYSTERIA_AUTH_OK: u16 = 233;
const HYSTERIA_HOST: &str = "hysteria";
const HYSTERIA_PATH: &str = "/auth";
const HYSTERIA_AUTH: &str = "hysteria-auth";
const HYSTERIA_PADDING: &str = "hysteria-padding";
const HYSTERIA_RATE: &str = "hysteria-cc-rx";

fn runtime() -> io::Result<&'static Runtime> {
    static RUNTIME: OnceLock<io::Result<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|err| io::Error::new(err.kind(), err.to_string()))
}

fn block<T>(limit: Duration, future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    runtime()?.block_on(with_timeout(limit, future))
}

async fn with_timeout<T>(
    limit: Duration,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    timeout(limit, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC operation timed out"))?
}

fn udp_socket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() { socket.set_only_v6(true)?; }
    socket.bind(&addr.into())?;
    let socket: std::net::UdpSocket = socket.into();
    socket.set_read_timeout(Some(Duration::from_millis(50)))?;
    socket.set_write_timeout(Some(Duration::from_millis(200)))?;
    Ok(socket)
}

fn endpoint(addr: SocketAddr, server: Option<quinn::ServerConfig>, masks: &FinalMask, peer: Option<SocketAddr>, options: &QuicOptions) -> io::Result<Endpoint> {
    let config = options.endpoint(peer.is_some());
    let carrier = masks.network().cloned();
    if !masks.has_udp() {
        if let (Some(carrier), Some(peer)) = (&carrier, peer) {
            let connection = carrier.open_udp(peer)?;
            let _guard = runtime()?.enter();
            return match connection {
                kerlico_shared::runtime::NetworkConnection::Udp(socket) => Endpoint::new(config, server, socket, Arc::new(TokioRuntime)),
                connection => Endpoint::new_with_abstract_socket(config, server, masked::MaskedSocket::new(crate::runtime::packet_connection(connection, peer, Duration::from_millis(50))?)?, Arc::new(TokioRuntime)),
            };
        }
    }
    let listener = |local| -> io::Result<Arc<dyn crate::finalmask::PacketIo>> {
        if let Some(carrier) = &carrier {
            let socket = carrier.options.open(crate::socket::SocketKind::Udp, crate::socket::SocketRole::Listener, local)?;
            socket.bind(&local.into())?;
            let socket = std::net::UdpSocket::from(socket);
            socket.set_read_timeout(Some(Duration::from_millis(50)))?;
            socket.set_write_timeout(Some(Duration::from_millis(200)))?;
            Ok(Arc::new(socket))
        } else { Ok(Arc::new(udp_socket(local)?)) }
    };
    if masks.has_udp() {
        let packets = if let Some(peer) = peer {
            let carrier = carrier.clone();
            masks.udp_client(peer, move |actual| {
                if let Some(carrier) = &carrier { return carrier.packet(actual); }
                let local = if actual.is_ipv6() { SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0) } else { SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0) };
                Ok(Arc::new(udp_socket(local)?))
            })?
        } else { masks.udp_server(addr, listener)? };
        let _guard = runtime()?.enter();
        Endpoint::new_with_abstract_socket(config, server, masked::MaskedSocket::new(packets)?, Arc::new(TokioRuntime))
    } else {
        let socket = if let Some(carrier) = carrier {
            let socket = carrier.options.open(crate::socket::SocketKind::Udp, crate::socket::SocketRole::Listener, addr)?;
            socket.bind(&addr.into())?;
            std::net::UdpSocket::from(socket)
        } else { udp_socket(addr)? };
        let _guard = runtime()?.enter();
        Endpoint::new(config, server, socket, Arc::new(TokioRuntime))
    }
}

struct QuicListener<T> {
    endpoint: Endpoint,
    incoming: Mutex<mpsc::Receiver<T>>,
}

impl<T: Send + 'static> QuicListener<T> {
    fn bind<F, Fut>(addr: SocketAddr, config: Arc<ServerConfig>, masks: &FinalMask, serve: F) -> io::Result<Self>
    where
        F: Fn(Connection, mpsc::Sender<T>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut config = (*config).clone();
        config.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicServerConfig::try_from(config).map_err(io::Error::other)?;
        let options = QuicOptions::parse(masks.quic_params())?;
        Self::bind_crypto(addr, Arc::new(crypto), masks, &options, QuicCarrier::Xhttp, serve)
    }

    fn bind_crypto<F, Fut>(addr: SocketAddr, crypto: Arc<dyn quinn::crypto::ServerConfig>, masks: &FinalMask, options: &QuicOptions, carrier: QuicCarrier, serve: F) -> io::Result<Self>
    where F: Fn(Connection, mpsc::Sender<T>) -> Fut + Clone + Send + 'static, Fut: Future<Output = ()> + Send + 'static {
        let mut config = quinn::ServerConfig::with_crypto(crypto);
        config.transport_config(options.transport(carrier, false, 0)?);

        let rt = runtime()?;
        let endpoint = endpoint(addr, Some(config), masks, None, options)?;
        let listener = endpoint.clone();
        let (tx, rx) = mpsc::channel(128);
        rt.spawn(async move {
            while let Some(incoming) = listener.accept().await {
                let tx = tx.clone();
                let serve = serve.clone();
                tokio::spawn(async move {
                    if let Ok(Ok(conn)) = timeout(HANDSHAKE_TIMEOUT, incoming).await {
                        serve(conn, tx).await;
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            incoming: Mutex::new(rx),
        })
    }

    fn accept(&self) -> io::Result<T> {
        self.incoming
            .lock()
            .expect("QUIC listener")
            .blocking_recv()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "QUIC listener closed"))
    }
}

impl<T> Drop for QuicListener<T> {
    fn drop(&mut self) {
        self.endpoint.close(VarInt::from_u32(0x100), b"");
    }
}

type ClientSend = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ClientRecv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type ServerSend = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ServerRecv = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

struct H3Client {
    _endpoint: Endpoint,
    conn: Connection,
    request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

#[derive(Clone)]
pub struct H3Conn(Arc<H3Client>);

impl H3Conn {
    pub fn is_closed(&self) -> bool { self.0.conn.close_reason().is_some() }

    pub fn connect(
        remote: SocketAddr,
        config: Arc<ClientConfig>,
        server_name: &str,
    ) -> io::Result<Self> {
        Self::connect_masked(remote, config, server_name, &FinalMask::default())
    }

    pub fn connect_masked(remote: SocketAddr, config: Arc<ClientConfig>, server_name: &str, masks: &FinalMask) -> io::Result<Self> {
        let mut config = (*config).clone();
        config.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicClientConfig::try_from(config).map_err(io::Error::other)?;
        Self::connect_crypto_masked(remote, Arc::new(crypto), server_name, masks)
    }

    pub fn connect_crypto_masked(remote: SocketAddr, crypto: Arc<dyn quinn::crypto::ClientConfig>, server_name: &str, masks: &FinalMask) -> io::Result<Self> {
        let options = QuicOptions::parse(masks.quic_params())?;
        Self::connect_crypto_with_options(remote, crypto, server_name, masks, &options, QuicCarrier::Xhttp, 0)
    }

    pub fn connect_crypto_with_options(
        remote: SocketAddr,
        crypto: Arc<dyn quinn::crypto::ClientConfig>,
        server_name: &str,
        masks: &FinalMask,
        options: &QuicOptions,
        carrier: QuicCarrier,
        xmux_keepalive: i64,
    ) -> io::Result<Self> {
        let mut config = quinn::ClientConfig::new(crypto);
        config.transport_config(options.transport(carrier, true, xmux_keepalive)?);
        options.configure_client(&mut config);

        let ip = if remote.is_ipv6() {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            };
        let mut endpoint = endpoint(SocketAddr::new(ip, 0), None, masks, Some(remote), options)?;
        endpoint.set_default_client_config(config);
        let connecting = {
            let _guard = runtime()?.enter();
            endpoint.connect(remote, server_name).map_err(io::Error::other)?
        };
        block(HANDSHAKE_TIMEOUT, async {
            let conn = connecting.await?;
            let (mut driver, request) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(async move { driver.wait_idle().await });
            Ok(Self(Arc::new(H3Client {
                _endpoint: endpoint,
                conn,
                request,
            })))
        })
    }

    /// Opens a carrier request. GET and HEAD end their request bodies immediately.
    pub fn open(
        &self,
        method: &str,
        path: &str,
        authority: &str,
        scheme: &str,
        extra: &[(&str, &str)],
        wait: bool,
    ) -> io::Result<H3Stream> {
        let mut stream = self.request(method, path, authority, scheme, extra, false)?;
        stream.success_only = true;
        if matches!(method, "GET" | "HEAD") {
            stream.finish_write()?;
        }
        if wait {
            stream.check_status()?;
        }
        Ok(stream)
    }

    /// Opens a request with a writable body regardless of its method.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        authority: &str,
        scheme: &str,
        extra: &[(&str, &str)],
        wait: bool,
    ) -> io::Result<H3Stream> {
        let uri = Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query(path)
            .build()
            .map_err(io::Error::other)?;
        let mut request = Request::builder().method(method).uri(uri);
        for &(name, value) in extra {
            request = request.header(name, value);
        }
        let request = request.body(()).map_err(io::Error::other)?;
        let mut sender = self.0.request.clone();
        let stream = block(HANDSHAKE_TIMEOUT, async {
            sender.send_request(request).await.map_err(io::Error::other)
        })?;
        let (send, recv) = stream.split();
        let stream = H3Stream::new(
            H3Recv::Client(recv, None),
            H3Send::Client(send),
            Some(self.clone()),
        );
        if wait {
            stream.response_status()?;
        }
        Ok(stream)
    }
}

pub struct H3Listener(QuicListener<(SocketAddr, H3Stream)>);

impl H3Listener {
    pub fn bind(addr: SocketAddr, config: Arc<ServerConfig>) -> io::Result<Self> {
        QuicListener::bind(addr, config, &FinalMask::default(), |conn, sender| serve_h3(conn, sender, None)).map(Self)
    }

    pub fn bind_with_header_limit(addr: SocketAddr, config: Arc<ServerConfig>, limit: u64) -> io::Result<Self> {
        Self::bind_masked(addr, config, limit, &FinalMask::default())
    }

    pub fn bind_masked(addr: SocketAddr, config: Arc<ServerConfig>, limit: u64, masks: &FinalMask) -> io::Result<Self> {
        QuicListener::bind(addr, config, masks, move |conn, sender| serve_h3(conn, sender, Some(limit))).map(Self)
    }

    pub fn bind_crypto_masked(addr: SocketAddr, config: Arc<dyn quinn::crypto::ServerConfig>, limit: u64, masks: &FinalMask) -> io::Result<Self> {
        let options = QuicOptions::parse(masks.quic_params())?;
        QuicListener::bind_crypto(addr, config, masks, &options, QuicCarrier::Xhttp, move |conn, sender| serve_h3(conn, sender, Some(limit))).map(Self)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.endpoint.local_addr()
    }

    pub fn accept(&self) -> io::Result<(SocketAddr, H3Stream)> {
        self.0.accept()
    }
}

async fn serve_h3(conn: Connection, incoming: mpsc::Sender<(SocketAddr, H3Stream)>, limit: Option<u64>) {
    let peer = conn.remote_address();
    let mut builder = h3::server::builder();
    if let Some(limit) = limit {
        builder.max_field_section_size(limit);
    }
    let Ok(mut h3) = builder.build(h3_quinn::Connection::new(conn)).await else {
        return;
    };
    while let Ok(Some(request)) = h3.accept().await {
        let incoming = incoming.clone();
        tokio::spawn(async move {
            if let Ok(Ok((request, stream))) =
                timeout(HANDSHAKE_TIMEOUT, request.resolve_request()).await
            {
                let (send, recv) = stream.split();
                let stream =
                    H3Stream::new(H3Recv::Server(recv, request), H3Send::Server(send), None);
                let _ = incoming.send((peer, stream)).await;
            }
        });
    }
}

enum H3Recv {
    Client(ClientRecv, Option<Response<()>>),
    Server(ServerRecv, Request<()>),
}

impl H3Recv {
    async fn response(&mut self) -> io::Result<&Response<()>> {
        let Self::Client(stream, response) = self else {
            return Err(io::Error::other("HTTP/3 stream is a server request"));
        };
        while response.is_none() {
            let head = stream.recv_response().await.map_err(io::Error::other)?;
            if !head.status().is_informational() {
                *response = Some(head);
            }
        }
        Ok(response.as_ref().expect("HTTP/3 response"))
    }

    fn header(&self, name: &str) -> Option<String> {
        let headers: &HeaderMap = match self {
            Self::Client(_, response) => {
                let response = response.as_ref()?;
                if name == ":status" {
                    return Some(response.status().as_str().to_owned());
                }
                response.headers()
            }
            Self::Server(_, request) => {
                let uri = request.uri();
                let value = match name {
                    ":authority" => uri.authority().map(|authority| authority.as_str()),
                    ":method" => Some(request.method().as_str()),
                    ":path" => uri.path_and_query().map(|path| path.as_str()),
                    ":scheme" => uri.scheme_str(),
                    "cookie" => {
                        let values = request.headers().get_all("cookie");
                        let mut values = values.iter().filter_map(|value| value.to_str().ok());
                        let mut combined = values.next()?.to_owned();
                        for value in values {
                            combined.push_str("; ");
                            combined.push_str(value);
                        }
                        return Some(combined);
                    }
                    _ => request.headers().get(name)?.to_str().ok(),
                };
                return value.map(str::to_owned);
            }
        };
        headers.get(name)?.to_str().ok().map(str::to_owned)
    }

    async fn recv_data(&mut self) -> io::Result<Option<Bytes>> {
        match self {
            Self::Client(stream, _) => stream
                .recv_data()
                .await
                .map(|chunk| chunk.map(|mut chunk| chunk.copy_to_bytes(chunk.remaining()))),
            Self::Server(stream, _) => stream
                .recv_data()
                .await
                .map(|chunk| chunk.map(|mut chunk| chunk.copy_to_bytes(chunk.remaining()))),
        }
        .map_err(io::Error::other)
    }
}

struct H3Reader {
    stream: H3Recv,
    data: Bytes,
    eof: bool,
}

enum H3Send {
    Client(ClientSend),
    Server(ServerSend),
}

impl H3Send {
    async fn send_data(&mut self, data: Bytes) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.send_data(data).await,
            Self::Server(stream) => stream.send_data(data).await,
        }
        .map_err(io::Error::other)
    }

    async fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.finish().await,
            Self::Server(stream) => stream.finish().await,
        }
        .map_err(io::Error::other)
    }

    fn reset(&mut self) {
        let code = h3::error::Code::H3_REQUEST_CANCELLED;
        match self {
            Self::Client(stream) => stream.stop_stream(code),
            Self::Server(stream) => stream.stop_stream(code),
        }
    }
}

struct H3Writer {
    stream: H3Send,
    replied: bool,
    finished: bool,
}

pub struct H3Stream {
    read: Mutex<H3Reader>,
    write: Mutex<H3Writer>,
    timeout: Mutex<Duration>,
    success_only: bool,
    _client: Option<H3Conn>,
}

impl H3Stream {
    fn new(read: H3Recv, write: H3Send, client: Option<H3Conn>) -> Self {
        Self {
            read: Mutex::new(H3Reader {
                stream: read,
                data: Bytes::new(),
                eof: false,
            }),
            write: Mutex::new(H3Writer {
                stream: write,
                replied: false,
                finished: false,
            }),
            timeout: Mutex::new(IO_TIMEOUT),
            success_only: false,
            _client: client,
        }
    }

    pub fn set_timeout(&self, timeout: Duration) {
        *self.timeout.lock().expect("HTTP/3 timeout") = timeout;
    }

    fn limit(&self) -> Duration {
        *self.timeout.lock().expect("HTTP/3 timeout")
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.read.lock().expect("HTTP/3 reader").stream.header(name)
    }

    pub fn response_status(&self) -> io::Result<u16> {
        let mut read = self.read.lock().expect("HTTP/3 reader");
        block(self.limit(), async {
            Ok(read.stream.response().await?.status().as_u16())
        })
    }

    fn check_status(&self) -> io::Result<()> {
        ensure_success(self.response_status()?)
    }

    pub fn reply(&self) -> io::Result<()> {
        self.reply_with(200, &[])
    }

    pub fn reply_end(&self) -> io::Result<()> {
        self.reply()?;
        self.finish_write()
    }

    pub fn reply_with(&self, status: u16, headers: &[(&str, &str)]) -> io::Result<()> {
        let mut response = Response::builder().status(status);
        for &(name, value) in headers {
            response = response.header(name, value);
        }
        let response = response.body(()).map_err(io::Error::other)?;
        let mut write = self.write.lock().expect("HTTP/3 writer");
        if write.finished || write.replied {
            return Err(io::Error::other("HTTP/3 response already sent"));
        }
        let H3Send::Server(stream) = &mut write.stream else {
            return Err(io::Error::other("HTTP/3 stream is a client request"));
        };
        let result = block(self.limit(), async {
            stream
                .send_response(response)
                .await
                .map_err(io::Error::other)
        });
        write.replied = true;
        if result.is_err() {
            write.stream.reset();
            write.finished = true;
        }
        result
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut read = self.read.lock().expect("HTTP/3 reader");
        block(self.limit(), async {
            if matches!(read.stream, H3Recv::Client(..)) {
                let status = read.stream.response().await?.status();
                if self.success_only {
                    ensure_success(status.as_u16())?;
                }
            }
            while read.data.is_empty() && !read.eof {
                match read.stream.recv_data().await? {
                    Some(data) => read.data = data,
                    None => read.eof = true,
                }
            }
            let len = buf.len().min(read.data.remaining());
            read.data.copy_to_slice(&mut buf[..len]);
            Ok(len)
        })
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut write = self.write.lock().expect("HTTP/3 writer");
        if write.finished || matches!(write.stream, H3Send::Server(_)) && !write.replied {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/3 write side unavailable",
            ));
        }
        let result = block(
            self.limit(),
            write.stream.send_data(Bytes::copy_from_slice(buf)),
        );
        if result.is_err() {
            write.stream.reset();
            write.finished = true;
        }
        result.map(|()| buf.len())
    }

    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    /// Ends the request body and waits for the response headers.
    pub fn finish(&self, buf: &[u8]) -> io::Result<()> {
        self.write(buf)?;
        self.finish_write()?;
        let status = self.response_status()?;
        if status == 200 {
            Ok(())
        } else {
            Err(io::Error::other(format!("HTTP/3 response status {status}")))
        }
    }

    pub fn finish_write(&self) -> io::Result<()> {
        let mut write = self.write.lock().expect("HTTP/3 writer");
        if write.finished {
            return Ok(());
        }
        let result = block(self.limit(), write.stream.finish());
        write.finished = true;
        match result {
            Err(error) if peer_stopped(&error).is_some() => Ok(()),
            Err(error) => {
                write.stream.reset();
                Err(error)
            }
            Ok(()) => Ok(()),
        }
    }
}

/// The code of the peer's STOP_SENDING. A server may stop reading a request it has answered
/// (RFC 9114 section 4.1), so the request counts as finished and the response, which the
/// client must not discard, decides the exchange.
fn peer_stopped(error: &io::Error) -> Option<h3::error::Code> {
    match error.get_ref().and_then(|cause| cause.downcast_ref::<h3::error::StreamError>()) {
        Some(h3::error::StreamError::RemoteTerminate { code, .. }) => Some(*code),
        _ => None,
    }
}

impl Read for H3Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        H3Stream::read(self, buf)
    }
}

impl Write for H3Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        H3Stream::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        H3Stream::flush(self)
    }
}

fn ensure_success(status: u16) -> io::Result<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!("HTTP/3 response status {status}")))
    }
}

type HysteriaIncoming = (SocketAddr, HysteriaRead, HysteriaWrite);

pub struct HysteriaListener(QuicListener<HysteriaIncoming>);

impl HysteriaListener {
    pub fn bind(addr: SocketAddr, config: Arc<ServerConfig>, auth: &str) -> io::Result<Self> {
        Self::bind_masked(addr, config, auth, &FinalMask::default())
    }

    pub fn bind_masked(addr: SocketAddr, config: Arc<ServerConfig>, auth: &str, masks: &FinalMask) -> io::Result<Self> {
        let mut config = (*config).clone();
        config.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicServerConfig::try_from(config).map_err(io::Error::other)?;
        Self::bind_crypto_masked(addr, Arc::new(crypto), auth, masks)
    }

    pub fn bind_crypto_masked(addr: SocketAddr, config: Arc<dyn quinn::crypto::ServerConfig>, auth: &str, masks: &FinalMask) -> io::Result<Self> {
        Self::bind_crypto_with_masquerade(addr, config, auth, masks, HysteriaMasquerade::default())
    }

    pub fn bind_crypto_with_masquerade(
        addr: SocketAddr,
        config: Arc<dyn quinn::crypto::ServerConfig>,
        auth: &str,
        masks: &FinalMask,
        masquerade: HysteriaMasquerade,
    ) -> io::Result<Self> {
        if auth.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Hysteria auth is empty"));
        }
        let auth: Arc<str> = Arc::from(auth);
        let options = Arc::new(QuicOptions::parse(masks.quic_params())?);
        let options_for_conn = options.clone();
        QuicListener::bind_crypto(addr, config, masks, &options, QuicCarrier::Hysteria, move |conn, incoming| {
            hysteria::serve(conn, incoming, auth.clone(), options_for_conn.clone(), masquerade.clone())
        }).map(Self)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.endpoint.local_addr()
    }

    pub fn accept(&self) -> io::Result<HysteriaIncoming> {
        self.0.accept()
    }
}

fn hysteria_padding() -> io::Result<String> {
    const CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut random = [0; 2048];
    getrandom::getrandom(&mut random).map_err(|err| io::Error::other(err.to_string()))?;
    let len = 256 + usize::from(u16::from_be_bytes([random[0], random[1]])) % 1792;
    Ok(random[..len]
        .iter()
        .map(|&byte| CHARACTERS[usize::from(byte) % CHARACTERS.len()] as char)
        .collect())
}

pub fn connect_hysteria(
    remote: SocketAddr,
    config: Arc<ClientConfig>,
    server_name: &str,
    auth: &str,
) -> io::Result<(HysteriaRead, HysteriaWrite)> {
    connect_hysteria_masked(remote, config, server_name, auth, &FinalMask::default())
}

pub fn connect_hysteria_masked(remote: SocketAddr, config: Arc<ClientConfig>, server_name: &str, auth: &str, masks: &FinalMask) -> io::Result<(HysteriaRead, HysteriaWrite)> {
    let mut config = (*config).clone();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicClientConfig::try_from(config).map_err(io::Error::other)?;
    connect_hysteria_crypto_masked(remote, Arc::new(crypto), server_name, auth, masks)
}

pub fn connect_hysteria_crypto_masked(remote: SocketAddr, config: Arc<dyn quinn::crypto::ClientConfig>, server_name: &str, auth: &str, masks: &FinalMask) -> io::Result<(HysteriaRead, HysteriaWrite)> {
    if auth.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "Hysteria auth is empty")); }
    let options = QuicOptions::parse(masks.quic_params())?;
    let conn = H3Conn::connect_crypto_with_options(remote, config, server_name, masks, &options, QuicCarrier::Hysteria, 0)?;
    hysteria_stream(conn, auth, &options)
}

fn hysteria_stream(conn: H3Conn, auth: &str, options: &QuicOptions) -> io::Result<(HysteriaRead, HysteriaWrite)> {
    let padding = hysteria_padding()?;
    let rate = options.receive_rate().to_string();
    let request = conn.open(
        "POST",
        HYSTERIA_PATH,
        HYSTERIA_HOST,
        "https",
        &[
            (HYSTERIA_AUTH, auth),
            (HYSTERIA_RATE, &rate),
            (HYSTERIA_PADDING, &padding),
        ],
        false,
    )?;
    request.set_timeout(HANDSHAKE_TIMEOUT);
    request.finish_write()?;
    if request.response_status()? != HYSTERIA_AUTH_OK {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hysteria authentication failed",
        ));
    }
    let peer_rate = request.header(HYSTERIA_RATE).and_then(|value| value.parse().ok()).unwrap_or(0);
    options.authenticate(&conn.0.conn, peer_rate);
    let (write, read) = block(HANDSHAKE_TIMEOUT, async {
        let (mut write, read) = conn.0.conn.open_bi().await?;
        write.write_all(&HYSTERIA_PREFIX).await?;
        Ok((write, read))
    })?;
    Ok(hysteria_pair(read, write, Some(conn)))
}

fn hysteria_pair(
    read: quinn::RecvStream,
    write: quinn::SendStream,
    client: Option<H3Conn>,
) -> (HysteriaRead, HysteriaWrite) {
    (
        HysteriaRead {
            read,
            timeout: IO_TIMEOUT,
            _client: client.clone(),
        },
        HysteriaWrite {
            write,
            timeout: IO_TIMEOUT,
            _client: client,
        },
    )
}

pub struct HysteriaRead {
    read: quinn::RecvStream,
    timeout: Duration,
    _client: Option<H3Conn>,
}

impl HysteriaRead {
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
}

impl Read for HysteriaRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        block(self.timeout, async {
            Ok(self.read.read(buf).await?.unwrap_or(0))
        })
    }
}

pub struct HysteriaWrite {
    write: quinn::SendStream,
    timeout: Duration,
    _client: Option<H3Conn>,
}

impl HysteriaWrite {
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn finish(&mut self) -> io::Result<()> {
        self.write.finish().map_err(io::Error::other)
    }
}

impl Write for HysteriaWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        block(self.timeout, async { Ok(self.write.write(buf).await?) })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{client_config, server_config};
    use std::{sync::mpsc, thread};

    pub(super) fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server = server_config(&cert.cert.pem(), &cert.key_pair.serialize_pem(), &[]).unwrap();
        let client = client_config(&[], true).unwrap();
        (client, server)
    }

    #[test]
    fn h3_reads_after_timeout_and_half_close() {
        let (client, server) = configs();
        let listener = H3Listener::bind("127.0.0.1:0".parse().unwrap(), server).unwrap();
        let addr = listener.local_addr().unwrap();
        let (done, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (_, mut stream) = listener.accept().unwrap();
            assert_eq!(stream.header(":path").as_deref(), Some("/stream?key=value"));
            stream.reply().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.finish_write().unwrap();
            wait.recv_timeout(HANDSHAKE_TIMEOUT).unwrap();
        });

        let conn = H3Conn::connect(addr, client, "localhost").unwrap();
        let mut stream = conn
            .open("POST", "/stream?key=value", "localhost", "https", &[], true)
            .unwrap();
        stream.set_timeout(Duration::from_millis(20));
        assert_eq!(
            stream.read(&mut [0; 4]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        stream.set_timeout(HANDSHAKE_TIMEOUT);
        stream.write_all(b"ping").unwrap();
        stream.finish_write().unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"pong");
        done.send(()).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn h3_generic_requests_read_error_status_and_body() {
        let (client, server) = configs();
        let listener = H3Listener::bind("[::1]:0".parse().unwrap(), server).unwrap();
        let addr = listener.local_addr().unwrap();
        let (done, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (_, mut stream) = listener.accept().unwrap();
            assert_eq!(stream.header(":method").as_deref(), Some("GET"));
            let mut body = Vec::new();
            stream.read_to_end(&mut body).unwrap();
            assert_eq!(body, b"request");
            stream.reply_with(409, &[("retry-after", "3")]).unwrap();
            stream.write_all(b"conflict").unwrap();
            stream.finish_write().unwrap();
            wait.recv_timeout(HANDSHAKE_TIMEOUT).unwrap();
        });
        let conn = H3Conn::connect(addr, client, "localhost").unwrap();
        let mut request = conn
            .request("GET", "/resource", "localhost", "https", &[], false)
            .unwrap();
        request.write_all(b"request").unwrap();
        request.finish_write().unwrap();
        assert_eq!(request.response_status().unwrap(), 409);
        assert_eq!(request.header("retry-after").as_deref(), Some("3"));
        let mut body = Vec::new();
        request.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"conflict");
        done.send(()).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn hysteria_authenticates_before_the_byte_stream() {
        let (client, server) = configs();
        let listener =
            HysteriaListener::bind("127.0.0.1:0".parse().unwrap(), server, "secret").unwrap();
        let addr = listener.local_addr().unwrap();
        let (done, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (_, mut read, mut write) = listener.accept().unwrap();
            let mut body = Vec::new();
            read.read_to_end(&mut body).unwrap();
            assert_eq!(body, b"ping");
            write.write_all(b"pong").unwrap();
            write.finish().unwrap();
            wait.recv_timeout(HANDSHAKE_TIMEOUT).unwrap();
        });
        let denied = connect_hysteria(addr, client.clone(), "localhost", "wrong");
        assert!(matches!(denied, Err(err) if err.kind() == io::ErrorKind::PermissionDenied));
        let (mut read, mut write) = connect_hysteria(addr, client, "localhost", "secret").unwrap();
        write.write_all(b"ping").unwrap();
        write.finish().unwrap();
        let mut body = Vec::new();
        read.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"pong");
        done.send(()).unwrap();
        worker.join().unwrap();
    }
}
