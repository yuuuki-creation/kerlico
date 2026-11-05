//! 每个出站独享有界物理池；故障不重放业务、不回退节点或直连。
use crate::{
    config::{self, ClientOptions, Limits, Transport},
    held::HeldIo,
    protocol,
};
use bytes::Bytes;
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, ResourceKey, Result, ServiceContext, ServiceTask, TargetPolicy,
};
use kerlico_http_carrier::{BodyIo, Reader, Writer};
use serde_json::Value;
use std::{
    collections::HashMap,
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
    driver: Mutex<Option<ServiceTask<()>>>,
    maintenance: Mutex<Option<ServiceTask<()>>>,
    quic: Option<(quinn::Endpoint, quinn::Connection)>,
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
        if let Ok(driver) = self.driver.lock()
            && let Some(driver) = driver.as_ref()
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
            && let Some(driver) = driver.as_ref()
        {
            driver.abort();
        }
    }
}
struct Pool {
    carriers: Vec<Arc<Carrier>>,
    connecting: usize,
}
type MemberPool = tokio::sync::Mutex<Pool>;
struct Client {
    server: Destination,
    auth: String,
    tls: Arc<rustls::ClientConfig>,
    name: String,
    transport: Transport,
    h2_allow_missing_alpn: bool,
    limits: Limits,
    udp: bool,
    udp_slots: Arc<Semaphore>,
    app: String,
    all: Arc<Semaphore>,
    h1: Arc<Semaphore>,
    pool: tokio::sync::Mutex<HashMap<ResourceKey, Arc<MemberPool>>>,
    host: ServiceContext,
}
impl OutboundFactory for TrustTunnelFactory {
    fn kind(&self) -> &'static str {
        "trusttunnel"
    }
    fn compile(&self, value: &Value) -> Result<OutboundPlan> {
        let options: ClientOptions =
            serde_json::from_value(value.clone()).map_err(|_| crate::invalid())?;
        options.auth.validate()?;
        options.limits.validate()?;
        if options.app_name.len() > 255 || options.app_name.chars().any(char::is_control) {
            return Err(crate::invalid());
        }
        let h2_allow_missing_alpn = options.tls.h2_allow_missing_alpn;
        if h2_allow_missing_alpn && value.get("transport").and_then(Value::as_str) != Some("h2") {
            return Err(crate::invalid());
        }
        let (tls, name) = config::client_tls(options.tls, options.transport)?;
        let server = options.server.destination()?;
        if options.transport == Transport::H3 {
            options.limits.quic(0)?;
        }
        let capabilities = Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: options.udp,
        };
        Ok(OutboundPlan::new(
            capabilities,
            false,
            TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(Client {
                        server,
                        auth: options.auth.header(),
                        tls,
                        name,
                        transport: options.transport,
                        h2_allow_missing_alpn,
                        udp: options.udp,
                        udp_slots: Arc::new(Semaphore::new(options.limits.max_udp_flows)),
                        app: options.app_name,
                        all: Arc::new(Semaphore::new(options.limits.max_streams)),
                        h1: Arc::new(Semaphore::new(options.limits.max_connections)),
                        limits: options.limits,
                        pool: tokio::sync::Mutex::new(HashMap::new()),
                        host,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
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
        if actual != Some(expected[0].as_slice())
            && !(actual.is_none()
                && (self.transport == Transport::H1
                    || self.transport == Transport::H2 && self.h2_allow_missing_alpn))
        {
            return Err(protocol());
        }
        Ok(Box::new(stream))
    }
    async fn make(&self) -> Result<Arc<Carrier>> {
        let closed = Arc::new(AtomicBool::new(false));
        let mark = closed.clone();
        let mut quic = None;
        let (sender, driver) = if self.transport == Transport::H2 {
            let io = self.tls().await?;
            let (sender, connection) = h2::client::Builder::new()
                .initial_window_size(16 * 1024 * 1024)
                .initial_connection_window_size(64 * 1024 * 1024)
                .max_frame_size(65536)
                .max_send_buffer_size(4 * 1024 * 1024)
                .max_header_list_size(16384)
                .handshake(io)
                .await
                .map_err(|_| protocol())?;
            let driver = self.host.spawn_tracked(async move {
                let _ = connection.await;
                mark.store(true, Ordering::Relaxed);
            })?;
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
            let sock_ref = socket2::SockRef::from(&socket);
            let _ = sock_ref.set_recv_buffer_size(8 * 1024 * 1024);
            let _ = sock_ref.set_send_buffer_size(8 * 1024 * 1024);
            socket.set_nonblocking(true)?;
            let mut endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                socket,
                kerlico_http_carrier::runtime::ServiceRuntime::new(self.host.clone()),
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
            let driver = self.host.spawn_tracked(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                mark.store(true, Ordering::Relaxed);
                conn.close(0x100u32.into(), b"");
            })?;
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
            maintenance: Mutex::new(None),
            quic,
        });
        let weak = Arc::downgrade(&carrier);
        let idle = self.limits.idle();
        let cancel = self.host.cancel();
        let maintenance = self.host.spawn_tracked(async move {
            let mut ticks = tokio::time::interval((idle / 4).clamp(
                std::time::Duration::from_millis(20),
                std::time::Duration::from_secs(1),
            ));
            loop {
                tokio::select! { biased; _=cancel.cancelled()=>break, _=ticks.tick()=>{} }
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
        })?;
        *carrier.maintenance.lock().map_err(|_| protocol())? = Some(maintenance);
        Ok(carrier)
    }
    async fn carrier(
        &self,
        context: &ConnectContext,
    ) -> Result<(Arc<Carrier>, OwnedSemaphorePermit)> {
        let bucket = {
            let mut pools = self.pool.lock().await;
            pools
                .entry(context.resource_key().clone())
                .or_insert_with(|| {
                    Arc::new(tokio::sync::Mutex::new(Pool {
                        carriers: Vec::new(),
                        connecting: 0,
                    }))
                })
                .clone()
        };
        let slots = self
            .limits
            .max_streams
            .div_ceil(self.limits.max_connections);
        let mut should_make = false;
        let picked = {
            let mut pool = bucket.lock().await;
            pool.carriers.retain(|c| !c.closed.load(Ordering::Relaxed));
            let mut idle = None;
            for carrier in &pool.carriers {
                if carrier.slots.available_permits() == slots
                    && let Ok(slot) = carrier.slots.clone().try_acquire_owned()
                {
                    idle = Some((carrier.clone(), slot));
                    break;
                }
            }
            if let Some(pair) = idle {
                Some(pair)
            } else if pool.carriers.len() + pool.connecting < self.limits.max_connections {
                pool.connecting += 1;
                should_make = true;
                None
            } else if let Some(carrier) = pool
                .carriers
                .iter()
                .max_by_key(|c| c.slots.available_permits())
                .cloned()
                && let Ok(slot) = carrier.slots.clone().try_acquire_owned()
            {
                Some((carrier, slot))
            } else if pool.carriers.len() < self.limits.max_connections {
                pool.connecting += 1;
                should_make = true;
                None
            } else {
                None
            }
        };
        if let Some((carrier, slot)) = picked {
            if carrier.age() >= std::time::Duration::from_millis(self.limits.health_check_ms) {
                let mut health = carrier.open("_check", &self.auth).await?;
                let mut bytes = [0; 1];
                if health.read(&mut bytes).await? != 0 {
                    carrier.close();
                    return Err(protocol());
                }
                carrier.touch();
            }
            return Ok((carrier, slot));
        }
        if should_make {
            let made = self.make().await;
            let mut pool = bucket.lock().await;
            pool.connecting = pool.connecting.saturating_sub(1);
            let carrier = made?;
            let slot = carrier
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?;
            pool.carriers.push(carrier.clone());
            return Ok((carrier, slot));
        }
        Err(Error::ResourceLimit)
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
                let (carrier, slot) = self.carrier(context).await?;
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
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.host.cancel().cancel();
            let buckets = { std::mem::take(&mut *self.pool.lock().await) };
            for bucket in buckets.into_values() {
                let carriers = { std::mem::take(&mut bucket.lock().await.carriers) };
                for carrier in carriers {
                    carrier.close();
                    let driver = carrier.driver.lock().ok().and_then(|mut task| task.take());
                    let maintenance = carrier
                        .maintenance
                        .lock()
                        .ok()
                        .and_then(|mut task| task.take());
                    for task in [driver, maintenance].into_iter().flatten() {
                        task.abort();
                        let _ = task.await;
                    }
                    if let Some((endpoint, _)) = &carrier.quic {
                        let _ = tokio::time::timeout(
                            kerlico_core::QUIC_CLOSE_GRACE,
                            endpoint.wait_idle(),
                        )
                        .await;
                    }
                }
            }
            Ok(())
        })
    }
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
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            self.open(&target.to_string(), context)
                .await
                .map(|stream| kerlico_core::OpenedTcp {
                    stream,
                    info: kerlico_core::TcpConnectInfo::unknown(),
                })
        })
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

#[cfg(test)]
mod alpn_tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn material() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["tt.example.invalid".into()]).unwrap();
        (cert.cert.pem(), cert.signing_key.serialize_pem())
    }
    async fn peer(
        alpn: Option<&[u8]>,
        version: &str,
        cert: &str,
        key: &str,
        reject: bool,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let input = serde_json::from_value(
            json!({"certificate_pem":cert,"private_key_pem":key,"version":version}),
        )
        .unwrap();
        let mut tls = config::server_tls(input, Transport::H2).unwrap();
        Arc::make_mut(&mut tls).alpn_protocols = alpn.into_iter().map(<[u8]>::to_vec).collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(tls) = tokio_rustls::TlsAcceptor::from(tls).accept(socket).await else {
                return;
            };
            let Ok(mut connection) = h2::server::handshake(tls).await else {
                return;
            };
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    joined = tasks.join_next(), if !tasks.is_empty() => { if joined.is_some_and(|result| result.is_err()) { break; } },
                    request = connection.accept() => {
                        let Some(Ok((request, mut reply))) = request else { break; };
                        if reject {
                            let _ = reply.send_response(http::Response::builder().status(407).body(()).unwrap(), true);
                            continue;
                        }
                        let udp = request.uri().authority().is_some_and(|a| a.as_str() == "_udp2");
                        let send = reply.send_response(http::Response::builder().status(200).body(()).unwrap(), false).unwrap();
                        let mut io = BodyIo::boxed(Writer::H2(send), Reader::H2(request.into_body()));
                        tasks.spawn(async move {
                            if udp {
                                while let Ok(Some(packet)) = crate::udp::read(&mut io, true, crate::udp::MAX_PAYLOAD).await {
                                    let reply = crate::udp::encode(packet.target, packet.source, None, &packet.data, crate::udp::MAX_PAYLOAD).unwrap();
                                    if io.write_all(&reply).await.is_err() || io.flush().await.is_err() { break; }
                                }
                            } else {
                                let mut bytes = [0; 1024];
                                while let Ok(n) = io.read(&mut bytes).await {
                                    if n == 0 { break; }
                                    if io.write_all(&bytes[..n]).await.is_err() || io.flush().await.is_err() { break; }
                                }
                            }
                        });
                    }
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        (address, task)
    }
    fn options(address: SocketAddr, cert: &str, version: &str, compatible: bool) -> Value {
        json!({"transport":"h2","server":{"host":"127.0.0.1","port":address.port()},"auth":{"username":"test","password":"fixture-password"},"tls":{"server_name":"tt.example.invalid","ca_pem":cert,"version":version,"h2_allow_missing_alpn":compatible}})
    }
    async fn close(
        outbound: Arc<dyn Outbound>,
        host: ServiceContext,
        task: tokio::task::JoinHandle<()>,
    ) {
        outbound.shutdown().await.unwrap();
        assert!(
            host.shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
                .await
                .is_clean()
        );
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn authenticated_h2_without_alpn_is_strict_by_default_and_explicitly_compatible() {
        let (cert, key) = material();
        for version in ["tls12", "tls13"] {
            for compatible in [false, true] {
                let (address, task) = peer(None, version, &cert, &key, false).await;
                let host = ServiceContext::new(kerlico_core::OutId::parse("alpn-test").unwrap());
                let outbound = TrustTunnelFactory
                    .compile(&options(address, &cert, version, compatible))
                    .unwrap()
                    .start(host.clone())
                    .await
                    .unwrap();
                let context = ConnectContext::new(Duration::from_secs(2));
                let target = Destination::new("192.0.2.10", 443).unwrap();
                let result = outbound.connect_tcp(&target, &context).await;
                if compatible {
                    let mut io = result.unwrap().stream;
                    io.write_all(b"h2-compatible").await.unwrap();
                    io.flush().await.unwrap();
                    let mut reply = [0; 13];
                    context
                        .run(async {
                            io.read_exact(&mut reply).await?;
                            Ok(())
                        })
                        .await
                        .unwrap();
                    assert_eq!(&reply, b"h2-compatible");
                    drop(io);
                    let mut udp = outbound
                        .connect_udp(&Destination::new("192.0.2.10", 53).unwrap(), &context)
                        .await
                        .unwrap();
                    udp.sender.send(b"").await.unwrap();
                    assert_eq!(
                        context.run(udp.receiver.recv()).await.unwrap(),
                        Some(Vec::new())
                    );
                    udp.sender.send(b"datagram").await.unwrap();
                    assert_eq!(
                        context.run(udp.receiver.recv()).await.unwrap(),
                        Some(b"datagram".to_vec())
                    );
                    drop(udp);
                } else {
                    assert!(result.is_err());
                }
                close(outbound, host, task).await;
            }
        }
    }
    #[tokio::test]
    async fn compatibility_keeps_wrong_alpn_certificate_name_and_authentication_rejected() {
        let (cert, key) = material();
        let (untrusted, _) = material();
        for compatible in [false, true] {
            for failure in ["alpn", "certificate", "name", "authentication"] {
                let (address, task) = peer(
                    if failure == "alpn" {
                        Some(b"http/1.1")
                    } else {
                        Some(b"h2")
                    },
                    "tls13",
                    &cert,
                    &key,
                    failure == "authentication",
                )
                .await;
                let mut value = options(address, &cert, "tls13", compatible);
                if failure == "certificate" {
                    value["tls"]["ca_pem"] = json!(untrusted);
                }
                if failure == "name" {
                    value["tls"]["server_name"] = json!("other.example.invalid");
                }
                let host =
                    ServiceContext::new(kerlico_core::OutId::parse("negative-alpn-test").unwrap());
                let outbound = TrustTunnelFactory
                    .compile(&value)
                    .unwrap()
                    .start(host.clone())
                    .await
                    .unwrap();
                assert!(
                    outbound
                        .connect_tcp(
                            &Destination::new("192.0.2.10", 443).unwrap(),
                            &ConnectContext::new(Duration::from_secs(2))
                        )
                        .await
                        .is_err()
                );
                close(outbound, host, task).await;
            }
        }
    }
    #[test]
    fn missing_alpn_compatibility_requires_explicit_h2_configuration() {
        let (cert, _) = material();
        for transport in [None, Some("h1"), Some("h3")] {
            let mut value = options("127.0.0.1:443".parse().unwrap(), &cert, "tls13", true);
            if let Some(transport) = transport {
                value["transport"] = json!(transport);
            } else {
                value.as_object_mut().unwrap().remove("transport");
            }
            assert!(TrustTunnelFactory.compile(&value).is_err());
        }
    }
}
