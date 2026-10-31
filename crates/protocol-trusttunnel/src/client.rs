//! 每个出站独享有界物理池；故障不重放业务、不回退节点或直连。
use crate::{
    config::{self, ClientOptions, Limits, Transport},
    io::{BodyIo, HeldIo, Reader, Writer},
    protocol,
};
use bytes::Bytes;
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result,
};
use serde_json::Value;
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tokio::{
    io::AsyncReadExt,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};
pub struct TrustTunnelFactory;
type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
enum Sender {
    H2(h2::client::SendRequest<Bytes>),
    H3(H3Sender),
}
pub(crate) struct Carrier {
    sender: Sender,
    slots: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
    last: Mutex<Instant>,
    driver: Mutex<Option<JoinHandle<()>>>,
    quic: Option<(quinn::Endpoint, quinn::Connection)>,
    socket: Option<crate::socket::Close>,
}
impl Carrier {
    pub fn touch(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = Instant::now();
        }
    }
    fn age(&self) -> std::time::Duration {
        self.last.lock().map(|v| v.elapsed()).unwrap_or_default()
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.slots.close();
        if let Some((endpoint, connection)) = &self.quic {
            connection.close(0x100u32.into(), b"");
            endpoint.close(0x100u32.into(), b"");
        }
        if let Some(socket) = &self.socket {
            socket.close();
        }
        if let Ok(mut driver) = self.driver.lock()
            && let Some(driver) = driver.take()
        {
            driver.abort();
        }
    }
    async fn open(&self, authority: &str, auth: &str) -> Result<BoxStream> {
        let uri = http::Uri::builder()
            .authority(authority)
            .build()
            .map_err(|_| protocol())?;
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(uri)
            .header("user-agent", "linux kerlico")
            .header("proxy-authorization", auth)
            .body(())
            .map_err(|_| protocol())?;
        let control = authority == "_check";
        match &self.sender {
            Sender::H2(sender) => {
                let mut sender = sender.clone().ready().await.map_err(|_| protocol())?;
                let (response, send) = sender
                    .send_request(request, control)
                    .map_err(|_| protocol())?;
                let response = response.await.map_err(|_| protocol())?;
                if response.status() != http::StatusCode::OK {
                    if response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                        self.close();
                    }
                    return Err(Error::Rejected);
                }
                Ok(BodyIo::boxed(
                    Writer::H2(send),
                    Reader::H2(response.into_body()),
                ))
            }
            Sender::H3(sender) => {
                let mut sender = sender.clone();
                let mut stream = sender.send_request(request).await.map_err(|_| protocol())?;
                if control {
                    stream.finish().await.map_err(|_| protocol())?;
                }
                let response = stream.recv_response().await.map_err(|_| protocol())?;
                if response.status() != http::StatusCode::OK {
                    if response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                        self.close();
                    }
                    return Err(Error::Rejected);
                }
                let (send, recv) = stream.split();
                Ok(BodyIo::boxed(Writer::Client(send), Reader::Client(recv)))
            }
        }
    }
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.close();
        if let Ok(driver) = self.driver.get_mut()
            && let Some(driver) = driver.take()
        {
            driver.abort();
        }
    }
}
struct Pool {
    carriers: Vec<Arc<Carrier>>,
}
struct Client {
    server: Destination,
    auth: String,
    tls: Arc<rustls::ClientConfig>,
    name: String,
    transport: Transport,
    limits: Limits,
    udp: bool,
    udp_slots: Arc<Semaphore>,
    app: String,
    all: Arc<Semaphore>,
    h1: Arc<Semaphore>,
    pool: tokio::sync::Mutex<Pool>,
}
impl OutboundFactory for TrustTunnelFactory {
    fn kind(&self) -> &'static str {
        "trusttunnel"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn Outbound>> {
        let options: ClientOptions =
            serde_json::from_value(value.clone()).map_err(|_| crate::invalid())?;
        options.auth.validate()?;
        options.limits.validate()?;
        if options.app_name.len() > 255 || options.app_name.chars().any(char::is_control) {
            return Err(crate::invalid());
        }
        let (tls, name) = config::client_tls(options.tls, options.transport)?;
        Ok(Arc::new(Client {
            server: options.server.destination()?,
            auth: options.auth.header(),
            tls,
            name,
            transport: options.transport,
            udp: options.udp,
            udp_slots: Arc::new(Semaphore::new(options.limits.max_udp_flows)),
            app: options.app_name,
            all: Arc::new(Semaphore::new(options.limits.max_streams)),
            h1: Arc::new(Semaphore::new(options.limits.max_connections)),
            limits: options.limits,
            pool: tokio::sync::Mutex::new(Pool {
                carriers: Vec::new(),
            }),
        }))
    }
}
impl Client {
    async fn tls(&self) -> Result<BoxStream> {
        let stream =
            tokio::net::TcpStream::connect((self.server.host().as_str(), self.server.port()))
                .await?;
        stream.set_nodelay(true)?;
        let name = rustls::pki_types::ServerName::try_from(self.name.clone())
            .map_err(|_| crate::invalid())?;
        let stream = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, stream)
            .await?;
        let actual = stream.get_ref().1.alpn_protocol();
        let expected = self.transport.alpn();
        // 旧 H1 对端可不发送 ALPN；H2/H3 必须协商到明确版本。
        if actual != Some(expected[0].as_slice())
            && !(self.transport == Transport::H1 && actual.is_none())
        {
            return Err(protocol());
        }
        Ok(Box::new(stream))
    }
    async fn make(&self) -> Result<Arc<Carrier>> {
        let closed = Arc::new(AtomicBool::new(false));
        let mark = closed.clone();
        let mut quic = None;
        let mut socket_close = None;
        let (sender, driver) = if self.transport == Transport::H2 {
            let io = self.tls().await?;
            let (sender, connection) = h2::client::Builder::new()
                .initial_window_size(131072)
                .initial_connection_window_size(2*1024*1024)
                .max_header_list_size(16384)
                .handshake(io)
                .await
                .map_err(|_| protocol())?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
                mark.store(true, Ordering::Relaxed);
            });
            (Sender::H2(sender), driver)
        } else {
            let mut peers: Vec<SocketAddr> =
                tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
                    .await?
                    .collect();
            peers.sort_by_key(SocketAddr::is_ipv6);
            let peer = peers.first().copied().ok_or(Error::InvalidAddress)?;
            let bind: SocketAddr = if peer.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            }
            .parse()
            .map_err(|_| crate::invalid())?;
            let socket = std::net::UdpSocket::bind(bind)?;
            socket.set_nonblocking(true)?;
            let (socket, close) = crate::socket::wrap(socket)?;
            socket_close = Some(close);
            let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*self.tls).clone())
                .map_err(|_| crate::invalid())?;
            let mut config = quinn::ClientConfig::new(Arc::new(crypto));
            config.transport_config(self.limits.quic(0)?);
            endpoint.set_default_client_config(config);
            let connection = endpoint
                .connect(peer, &self.name)
                .map_err(|_| crate::invalid())?
                .await
                .map_err(|_| protocol())?;
            let (mut driver, sender) = h3::client::builder()
                .max_field_section_size(16384)
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(|_| protocol())?;
            let conn = connection.clone();
            let driver = tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                mark.store(true, Ordering::Relaxed);
                conn.close(0x100u32.into(), b"");
            });
            quic = Some((endpoint, connection));
            (Sender::H3(sender), driver)
        };
        let slots = self
            .limits
            .max_streams
            .div_ceil(self.limits.max_connections);
        let carrier = Arc::new(Carrier {
            sender,
            slots: Arc::new(Semaphore::new(slots)),
            closed,
            last: Mutex::new(Instant::now()),
            driver: Mutex::new(Some(driver)),
            quic,
            socket: socket_close,
        });
        let weak = Arc::downgrade(&carrier);
        let idle = self.limits.idle();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval((idle / 4).clamp(
                std::time::Duration::from_millis(20),
                std::time::Duration::from_secs(1),
            ));
            loop {
                ticks.tick().await;
                let Some(carrier) = weak.upgrade() else {
                    break;
                };
                if carrier.closed.load(Ordering::Relaxed) {
                    break;
                }
                if carrier.slots.available_permits() == slots && carrier.age() >= idle {
                    carrier.close();
                    break;
                }
            }
        });
        Ok(carrier)
    }
    async fn carrier(&self) -> Result<(Arc<Carrier>, OwnedSemaphorePermit)> {
        let mut pool = self.pool.lock().await;
        pool.carriers.retain(|c| !c.closed.load(Ordering::Relaxed));
        for carrier in &pool.carriers {
            if let Ok(slot) = carrier.slots.clone().try_acquire_owned() {
                if carrier.age() >= std::time::Duration::from_millis(self.limits.health_check_ms) {
                    let mut health = carrier.open("_check", &self.auth).await?;
                    let mut bytes = [0; 1];
                    if health.read(&mut bytes).await? != 0 {
                        carrier.close();
                        return Err(protocol());
                    }
                    carrier.touch();
                }
                return Ok((carrier.clone(), slot));
            }
        }
        if pool.carriers.len() >= self.limits.max_connections {
            return Err(Error::ResourceLimit);
        }
        let carrier = self.make().await?;
        let slot = carrier
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        pool.carriers.push(carrier.clone());
        Ok((carrier, slot))
    }
    async fn open(&self, authority: &str, context: &ConnectContext) -> Result<BoxStream> {
        context
            .run(async {
                let all = self
                    .all
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Error::ResourceLimit)?;
                if self.transport == Transport::H1 {
                    // H1 没有池内多流，每条 CONNECT 都是独立物理连接。
                    let slot = self
                        .h1_slots()
                        .try_acquire_owned()
                        .map_err(|_| Error::ResourceLimit)?;
                    let io =
                        crate::http1::connect(self.tls().await?, authority, &self.auth).await?;
                    return Ok(HeldIo::boxed(io, None, slot, Some(all)));
                }
                let (carrier, slot) = self.carrier().await?;
                let io = match carrier.open(authority, &self.auth).await {
                    Ok(io) => io,
                    Err(error) => {
                        if !matches!(error, Error::Rejected) {
                            carrier.close();
                        }
                        return Err(error);
                    }
                };
                carrier.touch();
                Ok(HeldIo::boxed(io, Some(carrier), slot, Some(all)))
            })
            .await
    }
    fn h1_slots(&self) -> Arc<Semaphore> {
        self.h1.clone()
    }
}
impl Outbound for Client {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: self.udp,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move { self.open(&target.to_string(), context).await })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            if !self.udp {
                return Err(Error::Unsupported("TrustTunnel UDP 已关闭"));
            }
            crate::udp::literal(target)?;
            let udp_slot = self
                .udp_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?;
            let io = self.open("_udp2", context).await?;
            crate::udp::channel(
                io,
                target.clone(),
                self.app.clone(),
                self.limits.idle(),
                context.cancel.clone(),
                udp_slot,
            )
        })
    }
}
