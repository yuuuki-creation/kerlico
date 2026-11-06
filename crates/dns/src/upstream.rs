//! 上游传输：UDP（截断转 TCP）、TCP、DoT、DoH（HTTP/2、HTTP/3）、DoQ、系统解析器与固定 RCODE。
//! 每个上游可经命名出站或路由拨号；上游主机名先经 `default-nameserver` 引导解析。

use crate::{
    matcher::invalid,
    server::{Endpoint, H3Mode, Kind, ServerDef, TlsOpts, Via},
    wire,
};
use bytes::{Buf, Bytes};
use kerlico_core::{Address, BoxFuture, BoxStream, DatagramChannel, Destination, Error, Result};
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::Mutex,
};
use tokio_rustls::TlsConnector;

/// 由装配方提供的上游拨号能力：经命名出站或按路由为 DNS 上游建立连接。
pub trait DnsDialer: Send + Sync {
    /// 出站或代理组名称是否存在。
    fn knows(&self, outbound: &str) -> bool;
    fn connect_tcp<'a>(
        &'a self,
        via: &'a Via,
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<BoxStream>>;
    fn connect_udp<'a>(
        &'a self,
        via: &'a Via,
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<DatagramChannel>>;
    /// 直连上游套接字的拨号选项（全局路由标记、出口网卡等）。
    fn sockets(&self) -> kerlico_core::DialerOptions {
        kerlico_core::DialerOptions::default()
    }
}

pub(crate) type DialerSlot = Arc<OnceLock<Arc<dyn DnsDialer>>>;

/// 同一解析器内上游共享的网络参数。
pub(crate) struct Net {
    pub timeout: Duration,
    pub dialer: DialerSlot,
    pub bootstrap: Option<Arc<Bootstrap>>,
}

fn io_err(msg: &'static str) -> Error {
    Error::Io(std::io::Error::other(msg))
}

struct NoVerify(Arc<CryptoProvider>);

impl std::fmt::Debug for NoVerify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoVerify")
    }
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config(opts: &TlsOpts, alpn: &[&[u8]], tls13_only: bool) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = &opts.ca_pem {
        let certs = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| invalid())?;
        if certs.is_empty() {
            return Err(invalid());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| invalid())?;
        }
    }
    let builder = ClientConfig::builder_with_provider(provider.clone());
    let builder = if tls13_only {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .map_err(|_| invalid())?;
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    if opts.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerify(provider)));
    }
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

fn server_name(opts: &TlsOpts, endpoint: &Endpoint) -> Result<ServerName<'static>> {
    let name = opts.sni.clone().unwrap_or_else(|| endpoint.host_name());
    ServerName::try_from(name).map_err(|_| invalid())
}

fn quic_config(opts: &TlsOpts, alpn: &[u8]) -> Result<quinn::ClientConfig> {
    let tls = tls_config(opts, &[alpn], true)?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| invalid())?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Duration::from_secs(30).try_into().ok());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

struct H2Doh {
    connector: TlsConnector,
    name: ServerName<'static>,
    session: Mutex<Option<h2::client::SendRequest<Bytes>>>,
}

struct H3Session {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

struct QuicDial {
    config: quinn::ClientConfig,
    sni: String,
}

struct Doh {
    endpoint: Endpoint,
    uri: String,
    headers: Vec<(String, String)>,
    h3: H3Mode,
    h2: H2Doh,
    quic: Option<QuicDial>,
    h3_session: Mutex<Option<H3Session>>,
}

struct Doq {
    endpoint: Endpoint,
    dial: QuicDial,
    session: Mutex<Option<(quinn::Endpoint, quinn::Connection)>>,
}

enum Transport {
    Udp(Endpoint),
    Tcp(Endpoint),
    Tls(Endpoint, TlsConnector, ServerName<'static>),
    Https(Box<Doh>),
    Quic(Box<Doq>),
    System(Vec<SocketAddr>),
    Rcode(u8),
}

pub(crate) struct Upstream {
    pub tag: String,
    transport: Transport,
    via: Via,
    ecs: Option<(wire::ClientSubnet, bool)>,
    net: Arc<Net>,
}

fn system_nameservers() -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().split('%').next()?.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

impl Upstream {
    pub(crate) fn new(def: &ServerDef, net: Arc<Net>, prefer_h3: bool) -> Result<Self> {
        let quic_via_proxy = || {
            if def.via != Via::Direct {
                Err(Error::Config("DoQ 与 DoH3 上游不支持经出站拨号".into()))
            } else {
                Ok(())
            }
        };
        let transport = match &def.kind {
            Kind::Udp(ep) => Transport::Udp(ep.clone()),
            Kind::Tcp(ep) => Transport::Tcp(ep.clone()),
            Kind::Tls(ep, opts) => Transport::Tls(
                ep.clone(),
                TlsConnector::from(Arc::new(tls_config(opts, &[], false)?)),
                server_name(opts, ep)?,
            ),
            Kind::Https {
                endpoint,
                path,
                headers,
                tls,
                h3,
            } => {
                let h3 = match h3 {
                    H3Mode::Off if prefer_h3 && def.via == Via::Direct => H3Mode::Prefer,
                    other => *other,
                };
                if h3 == H3Mode::Only {
                    quic_via_proxy()?;
                }
                let authority = match &endpoint.host {
                    Address::Ip(IpAddr::V6(v6)) => format!("[{v6}]:{}", endpoint.port),
                    _ if endpoint.port == 443 => endpoint.host_name(),
                    _ => format!("{}:{}", endpoint.host_name(), endpoint.port),
                };
                let quic = match h3 {
                    H3Mode::Off => None,
                    _ => Some(QuicDial {
                        config: quic_config(tls, b"h3")?,
                        sni: tls.sni.clone().unwrap_or_else(|| endpoint.host_name()),
                    }),
                };
                Transport::Https(Box::new(Doh {
                    endpoint: endpoint.clone(),
                    uri: format!("https://{authority}{path}"),
                    headers: headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    h3,
                    h2: H2Doh {
                        connector: TlsConnector::from(Arc::new(tls_config(tls, &[b"h2"], false)?)),
                        name: server_name(tls, endpoint)?,
                        session: Mutex::new(None),
                    },
                    quic,
                    h3_session: Mutex::new(None),
                }))
            }
            Kind::Quic(ep, opts) => {
                quic_via_proxy()?;
                Transport::Quic(Box::new(Doq {
                    endpoint: ep.clone(),
                    dial: QuicDial {
                        config: quic_config(opts, b"doq")?,
                        sni: opts.sni.clone().unwrap_or_else(|| ep.host_name()),
                    },
                    session: Mutex::new(None),
                }))
            }
            Kind::System => Transport::System(system_nameservers()),
            Kind::Rcode(code) => Transport::Rcode(*code),
            Kind::FakeIp { .. } => return Err(invalid()),
        };
        Ok(Self {
            tag: def.tag.clone(),
            transport,
            via: def.via.clone(),
            ecs: def.ecs,
            net,
        })
    }

    /// 发送查询并返回校验过问题段、ID 已恢复为查询 ID 的应答。
    pub(crate) async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        let question = wire::parse_question(query)?;
        let request = match &self.ecs {
            Some((subnet, replace)) => {
                wire::with_client_subnet(query, subnet, *replace).ok_or_else(invalid)?
            }
            None => query.to_vec(),
        };
        let id = wire::id(query);
        let mut reply = tokio::time::timeout(self.net.timeout, self.exchange_raw(&request))
            .await
            .map_err(|_| Error::Timeout)??;
        if reply.len() < 12 || reply[2] & 0x80 == 0 {
            return Err(Error::Protocol("DNS 上游应答不合法"));
        }
        if let Ok(rq) = wire::parse_question(&reply)
            && (rq.name != question.name || rq.qtype != question.qtype)
        {
            return Err(Error::Protocol("DNS 上游应答问题不匹配"));
        }
        wire::set_id(&mut reply, id);
        Ok(reply)
    }

    async fn exchange_raw(&self, query: &[u8]) -> Result<Vec<u8>> {
        match &self.transport {
            Transport::Udp(ep) => {
                let reply = self.udp(ep, query).await?;
                if wire::is_truncated(&reply) {
                    return self.stream_exchange(self.tcp(ep).await?, query).await;
                }
                Ok(reply)
            }
            Transport::Tcp(ep) => self.stream_exchange(self.tcp(ep).await?, query).await,
            Transport::Tls(ep, connector, name) => {
                let stream = self.tcp(ep).await?;
                let tls = connector
                    .connect(name.clone(), stream)
                    .await
                    .map_err(|_| io_err("DoT 握手失败"))?;
                self.stream_exchange(tls, query).await
            }
            Transport::Https(doh) => match doh.h3 {
                H3Mode::Off => self.doh_h2(doh, query).await,
                H3Mode::Only => self.doh_h3(doh, query).await,
                H3Mode::Prefer => match self.doh_h3(doh, query).await {
                    Ok(reply) => Ok(reply),
                    Err(_) => self.doh_h2(doh, query).await,
                },
            },
            Transport::Quic(doq) => self.doq(doq, query).await,
            Transport::System(servers) => self.system(servers, query).await,
            Transport::Rcode(code) => {
                let q = wire::parse_question(query)?;
                Ok(wire::reply(query, &q, *code, &[], 0))
            }
        }
    }

    async fn addrs(&self, ep: &Endpoint) -> Result<Vec<SocketAddr>> {
        match &ep.host {
            Address::Ip(ip) => Ok(vec![SocketAddr::new(*ip, ep.port)]),
            Address::Domain(name) => {
                let ips = match &self.net.bootstrap {
                    Some(bootstrap) => bootstrap.resolve(name).await?,
                    None => tokio::net::lookup_host((name.as_str(), ep.port))
                        .await?
                        .map(|a| a.ip())
                        .collect(),
                };
                if ips.is_empty() {
                    return Err(Error::InvalidAddress);
                }
                Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, ep.port))
                    .collect())
            }
        }
    }

    fn dialer(&self) -> Result<Arc<dyn DnsDialer>> {
        self.net
            .dialer
            .get()
            .cloned()
            .ok_or_else(|| Error::Config("DNS 上游经出站拨号需要出站调度器".into()))
    }

    /// 直连上游的套接字选项；调度器装配前（`bind` 之前）为默认值。
    fn sockets(&self) -> kerlico_core::DialerOptions {
        self.net
            .dialer
            .get()
            .map(|dialer| dialer.sockets())
            .unwrap_or_default()
    }

    async fn tcp(&self, ep: &Endpoint) -> Result<BoxStream> {
        if self.via != Via::Direct {
            return self
                .dialer()?
                .connect_tcp(&self.via, &ep.destination()?)
                .await;
        }
        let mut last = Error::InvalidAddress;
        let sockets = self.sockets();
        for addr in self.addrs(ep).await? {
            match sockets.connect_addr(addr).await {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(Box::new(stream));
                }
                Err(e) => last = Error::Io(e),
            }
        }
        Err(last)
    }

    async fn stream_exchange<S>(&self, mut stream: S, query: &[u8]) -> Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let len = u16::try_from(query.len()).map_err(|_| invalid())?;
        let mut frame = Vec::with_capacity(query.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(query);
        stream.write_all(&frame).await?;
        stream.flush().await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut reply).await?;
        Ok(reply)
    }

    async fn udp(&self, ep: &Endpoint, query: &[u8]) -> Result<Vec<u8>> {
        let id = wire::id(query);
        if self.via != Via::Direct {
            let mut channel = self
                .dialer()?
                .connect_udp(&self.via, &ep.destination()?)
                .await?;
            channel.sender.send(query).await?;
            loop {
                let reply = channel
                    .receiver
                    .recv()
                    .await?
                    .ok_or(io_err("DNS 上游 UDP 通道已关闭"))?;
                if reply.len() >= 12 && wire::id(&reply) == id {
                    return Ok(reply);
                }
            }
        }
        let addr = *self.addrs(ep).await?.first().ok_or(Error::InvalidAddress)?;
        udp_direct(&self.sockets(), addr, query).await
    }

    async fn system(&self, servers: &[SocketAddr], query: &[u8]) -> Result<Vec<u8>> {
        let mut last = io_err("系统 DNS 不可用");
        for addr in servers {
            match udp_direct(&self.sockets(), *addr, query).await {
                Ok(reply) => return Ok(reply),
                Err(e) => last = e,
            }
        }
        if !servers.is_empty() {
            return Err(last);
        }
        let q = wire::parse_question(query)?;
        if !matches!(q.qtype, wire::TYPE_A | wire::TYPE_AAAA) {
            return Ok(wire::reply(query, &q, wire::RCODE_NOERROR, &[], 0));
        }
        let ips: Vec<wire::Synth> = tokio::net::lookup_host((q.name.as_str(), 0))
            .await?
            .map(|a| wire::Synth::Ip(a.ip()))
            .collect();
        Ok(wire::reply(query, &q, wire::RCODE_NOERROR, &ips, 60))
    }

    async fn doh_h2(&self, doh: &Doh, query: &[u8]) -> Result<Vec<u8>> {
        let mut body = query.to_vec();
        wire::set_id(&mut body, 0);
        let cached = doh.h2.session.lock().await.clone();
        if let Some(send) = cached
            && let Ok(reply) = self.h2_request(doh, send, &body).await
        {
            return Ok(reply);
        }
        let stream = self.tcp(&doh.endpoint).await?;
        let tls = doh
            .h2
            .connector
            .connect(doh.h2.name.clone(), stream)
            .await
            .map_err(|_| io_err("DoH 握手失败"))?;
        let (send, connection) = h2::client::handshake(tls)
            .await
            .map_err(|_| io_err("DoH HTTP/2 握手失败"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        *doh.h2.session.lock().await = Some(send.clone());
        self.h2_request(doh, send, &body).await
    }

    async fn h2_request(
        &self,
        doh: &Doh,
        send: h2::client::SendRequest<Bytes>,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let mut send = send.ready().await.map_err(|_| io_err("DoH 连接不可用"))?;
        let request = doh_request(doh)?;
        let (response, mut tx) = send
            .send_request(request, false)
            .map_err(|_| io_err("DoH 请求发送失败"))?;
        tx.send_data(Bytes::copy_from_slice(body), true)
            .map_err(|_| io_err("DoH 请求发送失败"))?;
        let response = response.await.map_err(|_| io_err("DoH 响应失败"))?;
        if !response.status().is_success() {
            return Err(Error::Protocol("DoH 响应状态异常"));
        }
        let mut rx = response.into_body();
        let mut out = Vec::new();
        while let Some(chunk) = rx.data().await {
            let chunk = chunk.map_err(|_| io_err("DoH 响应读取失败"))?;
            let _ = rx.flow_control().release_capacity(chunk.len());
            out.extend_from_slice(&chunk);
            if out.len() > 65535 {
                return Err(Error::Protocol("DoH 响应过长"));
            }
        }
        Ok(out)
    }

    async fn doh_h3(&self, doh: &Doh, query: &[u8]) -> Result<Vec<u8>> {
        let dial = doh.quic.as_ref().ok_or_else(invalid)?;
        let mut body = query.to_vec();
        wire::set_id(&mut body, 0);
        let mut guard = doh.h3_session.lock().await;
        if guard
            .as_ref()
            .is_some_and(|s| s.connection.close_reason().is_some())
        {
            *guard = None;
        }
        if guard.is_none() {
            let (endpoint, connection) = self.quic_connect(&doh.endpoint, dial).await?;
            let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(|_| io_err("DoH3 握手失败"))?;
            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });
            *guard = Some(H3Session {
                send,
                connection,
                _endpoint: endpoint,
            });
        }
        let mut send = guard.as_ref().ok_or_else(invalid)?.send.clone();
        drop(guard);
        let request = doh_request(doh)?;
        let mut stream = send
            .send_request(request)
            .await
            .map_err(|_| io_err("DoH3 请求失败"))?;
        stream
            .send_data(Bytes::from(body))
            .await
            .map_err(|_| io_err("DoH3 请求失败"))?;
        stream.finish().await.map_err(|_| io_err("DoH3 请求失败"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|_| io_err("DoH3 响应失败"))?;
        if !response.status().is_success() {
            return Err(Error::Protocol("DoH3 响应状态异常"));
        }
        let mut out = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|_| io_err("DoH3 响应读取失败"))?
        {
            while chunk.has_remaining() {
                let part = chunk.chunk();
                out.extend_from_slice(part);
                let n = part.len();
                chunk.advance(n);
            }
            if out.len() > 65535 {
                return Err(Error::Protocol("DoH3 响应过长"));
            }
        }
        Ok(out)
    }

    async fn quic_connect(
        &self,
        ep: &Endpoint,
        dial: &QuicDial,
    ) -> Result<(quinn::Endpoint, quinn::Connection)> {
        let addr = *self.addrs(ep).await?.first().ok_or(Error::InvalidAddress)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            self.sockets().udp_socket_for(addr)?,
            Arc::new(quinn::TokioRuntime),
        )?;
        let connection = endpoint
            .connect_with(dial.config.clone(), addr, &dial.sni)
            .map_err(|_| invalid())?
            .await
            .map_err(|_| io_err("QUIC 握手失败"))?;
        Ok((endpoint, connection))
    }

    async fn doq(&self, doq: &Doq, query: &[u8]) -> Result<Vec<u8>> {
        let mut guard = doq.session.lock().await;
        if guard
            .as_ref()
            .is_some_and(|(_, c)| c.close_reason().is_some())
        {
            *guard = None;
        }
        if guard.is_none() {
            *guard = Some(self.quic_connect(&doq.endpoint, &doq.dial).await?);
        }
        let connection = guard.as_ref().ok_or_else(invalid)?.1.clone();
        drop(guard);
        let (mut tx, mut rx) = connection
            .open_bi()
            .await
            .map_err(|_| io_err("DoQ 流打开失败"))?;
        let mut body = query.to_vec();
        wire::set_id(&mut body, 0);
        let len = u16::try_from(body.len()).map_err(|_| invalid())?;
        let mut frame = Vec::with_capacity(body.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        tx.write_all(&frame)
            .await
            .map_err(|_| io_err("DoQ 发送失败"))?;
        tx.finish().map_err(|_| io_err("DoQ 发送失败"))?;
        let data = rx
            .read_to_end(65537)
            .await
            .map_err(|_| io_err("DoQ 接收失败"))?;
        if data.len() < 2 + 12 {
            return Err(Error::Protocol("DoQ 应答过短"));
        }
        let n = usize::from(u16::from_be_bytes([data[0], data[1]]));
        data.get(2..2 + n)
            .map(<[u8]>::to_vec)
            .ok_or(Error::Protocol("DoQ 应答长度不符"))
    }
}

fn doh_request(doh: &Doh) -> Result<http::Request<()>> {
    let mut builder = http::Request::builder()
        .method("POST")
        .uri(&doh.uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message");
    for (k, v) in &doh.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    builder.body(()).map_err(|_| invalid())
}

async fn udp_direct(
    sockets: &kerlico_core::DialerOptions,
    addr: SocketAddr,
    query: &[u8],
) -> Result<Vec<u8>> {
    let socket = UdpSocket::from_std(sockets.udp_socket_for(addr)?)?;
    socket.connect(addr).await?;
    socket.send(query).await?;
    let id = wire::id(query);
    let mut buf = vec![0u8; 65535];
    loop {
        let n = socket.recv(&mut buf).await?;
        if n >= 12 && wire::id(&buf[..n]) == id {
            return Ok(buf[..n].to_vec());
        }
    }
}

/// `default-nameserver`：只用 IP 上游，为上游主机名解析 A/AAAA 并按 TTL 缓存。
pub(crate) struct Bootstrap {
    servers: Vec<Upstream>,
    cache: std::sync::Mutex<std::collections::HashMap<String, (Vec<IpAddr>, Instant)>>,
}

impl Bootstrap {
    pub(crate) fn new(servers: Vec<Upstream>) -> Self {
        Self {
            servers,
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// 返回装箱 future：引导解析经上游交换，上游交换又可能需要引导解析。
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
        Box::pin(self.resolve_inner(host))
    }

    async fn resolve_inner(&self, host: &str) -> Result<Vec<IpAddr>> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();
        if let Some((ips, exp)) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            && *exp > now
        {
            return Ok(ips.clone());
        }
        let mut out = Vec::new();
        let mut ttl = 60;
        for qtype in [wire::TYPE_A, wire::TYPE_AAAA] {
            let query = wire::build_query(rand_id(), &key, qtype)?;
            if let Ok(reply) = exchange_first(self.servers.iter(), &query).await {
                ttl = ttl.min(wire::min_ttl(&reply.message).unwrap_or(60).max(1));
                out.extend(wire::answer_ips(&reply.message));
            }
            if !out.is_empty() {
                break;
            }
        }
        if out.is_empty() {
            return Err(io_err("default-nameserver 无法解析上游主机名"));
        }
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(
            key,
            (out.clone(), now + Duration::from_secs(u64::from(ttl))),
        );
        Ok(out)
    }
}

pub(crate) fn rand_id() -> u16 {
    rand::random()
}

/// 一组上游的应答；`cacheable` 为假时不进缓存（`rcode://` 与全组无地址的回退应答）。
pub(crate) struct GroupReply {
    pub message: Vec<u8>,
    pub server: String,
    pub cacheable: bool,
}

/// 并发查询一组上游，与 Mihomo `batchExchange` 一致：组内有 `rcode://` 时直接用它；
/// SERVFAIL、REFUSED 与出错视为失败；A/AAAA 无地址的应答只在全组都无地址时采用。
pub(crate) async fn exchange_first<'a, I>(servers: I, query: &[u8]) -> Result<GroupReply>
where
    I: IntoIterator<Item = &'a Upstream>,
{
    use futures_util::stream::{FuturesUnordered, StreamExt};
    let servers: Vec<&Upstream> = servers.into_iter().collect();
    if let Some(rcode) = servers
        .iter()
        .find(|s| matches!(s.transport, Transport::Rcode(_)))
    {
        return Ok(GroupReply {
            message: rcode.exchange(query).await?,
            server: rcode.tag.clone(),
            cacheable: false,
        });
    }
    let wants_ip = wire::parse_question(query)
        .is_ok_and(|q| matches!(q.qtype, wire::TYPE_A | wire::TYPE_AAAA));
    let mut pending: FuturesUnordered<_> = servers
        .iter()
        .map(|server| async move { (server.tag.clone(), server.exchange(query).await) })
        .collect();
    if pending.is_empty() {
        return Err(Error::Config("DNS 上游组为空".into()));
    }
    let mut last = io_err("DNS 上游查询失败");
    let mut no_ip = None;
    while let Some((tag, result)) = pending.next().await {
        match result {
            Ok(reply)
                if matches!(
                    wire::rcode(&reply),
                    wire::RCODE_SERVFAIL | wire::RCODE_REFUSED
                ) =>
            {
                last = io_err("DNS 上游返回 SERVFAIL 或 REFUSED");
            }
            Ok(reply) if wants_ip && wire::answer_ips(&reply).is_empty() => {
                no_ip.get_or_insert((reply, tag));
            }
            Ok(message) => {
                return Ok(GroupReply {
                    message,
                    server: tag,
                    cacheable: true,
                });
            }
            Err(e) => last = e,
        }
    }
    match no_ip {
        Some((message, server)) => Ok(GroupReply {
            message,
            server,
            cacheable: false,
        }),
        None => Err(last),
    }
}
