//! HTTP/3 CONNECT-IP（RFC 9484）服务端入站；复用用户态 IP 数据面与可信会话分流。
use crate::{
    capsule::{self, Address, Capsule, Route},
    protocol,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, NodeEvent, PeerSession, Result,
};
use kerlico_http_carrier::{
    BodyIo, Reader, Writer,
    runtime::{NodeDrain, NodeRuntime, spawn_owned},
};
use kerlico_wireguard::ip::{Network, ServerTunnel, StackLimits, StackOptions};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{net::UdpSocket, task::JoinSet};

const QUIC_PATH_MTU: u16 = 1350;
const DATAGRAM_BUFFER: usize = 2 * 1024 * 1024;
const MAX_PEM: usize = 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum AddressSpec {
    One(String),
    Many(Vec<String>),
}
impl Default for AddressSpec {
    fn default() -> Self {
        Self::Many(vec!["10.0.0.2/32".into(), "fd00::2/128".into()])
    }
}
impl AddressSpec {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(one) => vec![one],
            Self::Many(many) => many,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeOptions {
    tls: ServerTls,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    address: AddressSpec,
    #[serde(default, alias = "advertise-routes")]
    advertise_routes: Vec<String>,
    #[serde(default = "default_mtu")]
    mtu: usize,
    #[serde(default)]
    limits: StackLimits,
}
fn default_mtu() -> usize {
    1280
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerTls {
    certificate_pem: Option<String>,
    private_key_pem: Option<String>,
    certificate_file: Option<String>,
    private_key_file: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCredential {
    #[serde(alias = "email")]
    username: String,
    #[serde(alias = "pass")]
    password: String,
    #[serde(default)]
    #[allow(dead_code)]
    level: Option<u32>,
}

fn node_invalid() -> Error {
    Error::Config("MASQUE 节点配置或凭据不合法".into())
}

fn pem_material(inline: Option<String>, file: Option<String>) -> Result<String> {
    match (inline, file) {
        (Some(value), None) if !value.is_empty() && value.len() <= MAX_PEM => Ok(value),
        (None, Some(path)) if !path.is_empty() => {
            if std::fs::metadata(&path).map_err(|_| node_invalid())?.len() > MAX_PEM as u64 {
                return Err(node_invalid());
            }
            std::fs::read_to_string(path).map_err(|_| node_invalid())
        }
        _ => Err(node_invalid()),
    }
}

fn server_quic_config(tls: ServerTls, idle: Duration) -> Result<quinn::ServerConfig> {
    let certs_pem = pem_material(tls.certificate_pem, tls.certificate_file)?;
    let key_pem = pem_material(tls.private_key_pem, tls.private_key_file)?;
    let certs = rustls_pemfile::certs(&mut Cursor::new(certs_pem))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| node_invalid())?;
    if certs.is_empty() {
        return Err(node_invalid());
    }
    let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem))
        .map_err(|_| node_invalid())?
        .ok_or_else(node_invalid)?;
    let mut tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| node_invalid())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| node_invalid())?;
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    tls_cfg.max_early_data_size = 0;
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_cfg).map_err(|_| node_invalid())?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(64u32.into());
    transport.max_concurrent_uni_streams(16u32.into());
    transport.initial_mtu(QUIC_PATH_MTU);
    transport.min_mtu(QUIC_PATH_MTU);
    transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    transport.datagram_send_buffer_size(DATAGRAM_BUFFER);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(idle).map_err(|_| node_invalid())?,
    ));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

fn parse_host_ip(cidr_or_ip: &str) -> Result<IpAddr> {
    let raw = cidr_or_ip.trim();
    if let Some((addr_str, prefix_str)) = raw.split_once('/') {
        let ip: IpAddr = addr_str.parse().map_err(|_| node_invalid())?;
        let prefix: u8 = prefix_str.parse().map_err(|_| node_invalid())?;
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(node_invalid());
        }
        Ok(match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let host = if prefix < 32 && (bits & ((1u32 << (32 - prefix)) - 1)) == 0 {
                    Ipv4Addr::from(bits | 2)
                } else {
                    v4
                };
                IpAddr::V4(host)
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let host = if prefix < 128 && (bits & ((1u128 << (128 - prefix)) - 1)) == 0 {
                    Ipv6Addr::from(bits | 2)
                } else {
                    v6
                };
                IpAddr::V6(host)
            }
        })
    } else {
        raw.parse().map_err(|_| node_invalid())
    }
}

fn parse_cidr_route(cidr: &str) -> Result<Route> {
    let _validated = Network::parse(cidr).map_err(|_| node_invalid())?;
    let (addr_str, prefix_str) = cidr.trim().split_once('/').ok_or_else(node_invalid)?;
    let ip: IpAddr = addr_str.parse().map_err(|_| node_invalid())?;
    let prefix: u8 = prefix_str.parse().map_err(|_| node_invalid())?;
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(node_invalid());
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let start = Ipv4Addr::from(u32::from(v4) & mask);
            let end = Ipv4Addr::from((u32::from(v4) & mask) | !mask);
            Ok(Route {
                start: IpAddr::V4(start),
                end: IpAddr::V4(end),
                protocol: 0,
            })
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err(node_invalid());
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let start = Ipv6Addr::from(u128::from(v6) & mask);
            let end = Ipv6Addr::from((u128::from(v6) & mask) | !mask);
            Ok(Route {
                start: IpAddr::V6(start),
                end: IpAddr::V6(end),
                protocol: 0,
            })
        }
    }
}

pub struct MasqueNode {
    credentials: CredentialSet<[u8; 32]>,
    tls: ServerTlsClone,
    path: Option<String>,
    client_v4: Option<Ipv4Addr>,
    client_v6: Option<Ipv6Addr>,
    stack_options: StackOptions,
    advertised_routes: Vec<Route>,
}

#[derive(Clone)]
struct ServerTlsClone {
    certificate_pem: Option<String>,
    private_key_pem: Option<String>,
    certificate_file: Option<String>,
    private_key_file: Option<String>,
}
impl From<ServerTls> for ServerTlsClone {
    fn from(value: ServerTls) -> Self {
        Self {
            certificate_pem: value.certificate_pem,
            private_key_pem: value.private_key_pem,
            certificate_file: value.certificate_file,
            private_key_file: value.private_key_file,
        }
    }
}
impl From<ServerTlsClone> for ServerTls {
    fn from(value: ServerTlsClone) -> Self {
        Self {
            certificate_pem: value.certificate_pem,
            private_key_pem: value.private_key_pem,
            certificate_file: value.certificate_file,
            private_key_file: value.private_key_file,
        }
    }
}

impl MasqueNode {
    pub fn from_options(input: &NodeBuildContext) -> Result<Self> {
        let options: NodeOptions =
            serde_json::from_value(input.options().clone()).map_err(|_| node_invalid())?;
        if let Some(path) = &options.path
            && (!path.starts_with('/') || path.len() > 256)
        {
            return Err(node_invalid());
        }
        let raw_addrs = options.address.into_vec();
        if raw_addrs.is_empty() || raw_addrs.len() > 2 {
            return Err(node_invalid());
        }
        let mut client_v4 = None;
        let mut client_v6 = None;
        for item in &raw_addrs {
            match parse_host_ip(item)? {
                IpAddr::V4(v4) => {
                    if v4.is_unspecified() || client_v4.replace(v4).is_some() {
                        return Err(node_invalid());
                    }
                }
                IpAddr::V6(v6) => {
                    if v6.is_unspecified() || client_v6.replace(v6).is_some() {
                        return Err(node_invalid());
                    }
                }
            }
        }
        let mut server_addresses = Vec::new();
        let mut allowed_ips = Vec::new();
        if let Some(v4) = client_v4 {
            let server_v4 = if v4 == Ipv4Addr::new(10, 0, 0, 1) {
                Ipv4Addr::new(10, 0, 0, 254)
            } else {
                Ipv4Addr::new(10, 0, 0, 1)
            };
            server_addresses.push(IpAddr::V4(server_v4));
            allowed_ips.push(format!("{v4}/32"));
        }
        if let Some(v6) = client_v6 {
            let default_srv: Ipv6Addr = "fd00::1".parse().expect("有效 IPv6");
            let alt_srv: Ipv6Addr = "fd00::fe".parse().expect("有效 IPv6");
            let server_v6 = if v6 == default_srv {
                alt_srv
            } else {
                default_srv
            };
            server_addresses.push(IpAddr::V6(server_v6));
            allowed_ips.push(format!("{v6}/128"));
        }
        let stack_options = StackOptions {
            addresses: server_addresses,
            allowed_ips,
            mtu: options.mtu,
            limits: options.limits,
        };
        stack_options.validate()?;
        let mut advertised_routes = Vec::new();
        for cidr in &options.advertise_routes {
            advertised_routes.push(parse_cidr_route(cidr)?);
        }
        advertised_routes.sort_by_key(|r| (r.start.is_ipv6(), r.protocol, r.start));

        let tls_clone = ServerTlsClone::from(options.tls);
        server_quic_config(tls_clone.clone().into(), Duration::from_secs(30))?;

        let hashes = input
            .native_credentials()
            .iter()
            .map(|value| {
                let cred: NativeCredential =
                    serde_json::from_value(value.clone()).map_err(|_| node_invalid())?;
                if cred.username.is_empty()
                    || cred.username.contains(':')
                    || cred.password.is_empty()
                {
                    return Err(node_invalid());
                }
                let header = format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{}", cred.username, cred.password))
                );
                Ok(Sha256::digest(header.as_bytes()).into())
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;

        Ok(Self {
            credentials: input.credentials(hashes)?,
            tls: tls_clone,
            path: options.path,
            client_v4,
            client_v6,
            stack_options,
            advertised_routes,
        })
    }

    async fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        access: IngressBinding,
        mut context: InboundContext,
    ) -> Result<()> {
        if !access.supports_udp_association() {
            return Err(Error::Unsupported("MASQUE 节点需要多目标 UDP 关联能力"));
        }
        context.local_addr = socket.local_addr().ok();
        let quic = server_quic_config(self.tls.clone().into(), context.idle_timeout)?;
        let duplicated = socket2::SockRef::from(socket.as_ref()).try_clone()?;
        let standard: std::net::UdpSocket = duplicated.into();
        let runtime = NodeRuntime::new(&context.cancel, context.tasks.clone());
        let _runtime_guard = runtime.guard();
        context.cancel = runtime.cancel();
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quic),
            standard,
            runtime.clone(),
        )?;
        let mut connections = JoinSet::new();
        let mut maintenance = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                biased;
                _ = context.cancel.cancelled() => break,
                _ = maintenance.tick() => {
                    if context.stream_budget.is_closed() && connections.is_empty() {
                        break;
                    }
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    runtime.observe(&result);
                    if result.is_some_and(|res| res.is_err()) {
                        context.events.record(NodeEvent::Failed);
                    }
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    if context.stream_budget.is_closed() {
                        incoming.refuse();
                        context.events.record(NodeEvent::Dropped);
                        continue;
                    }
                    let mut conn_ctx = context.clone();
                    let access = access.clone();
                    let credentials = self.credentials.clone();
                    let path = self.path.clone();
                    let client_v4 = self.client_v4;
                    let client_v6 = self.client_v6;
                    let stack_options = self.stack_options.clone();
                    let advertised_routes = self.advertised_routes.clone();
                    spawn_owned(
                        context.tasks.clone(),
                        context.events.clone(),
                        &mut connections,
                        async move {
                            let result = async {
                                let connection = tokio::time::timeout(conn_ctx.connect_timeout, incoming)
                                    .await
                                    .map_err(|_| Error::Timeout)?
                                    .map_err(|_| protocol())?;
                                conn_ctx.peer_addr = Some(connection.remote_address());
                                handle_connection(
                                    connection,
                                    access,
                                    conn_ctx.clone(),
                                    credentials,
                                    path,
                                    client_v4,
                                    client_v6,
                                    stack_options,
                                    advertised_routes,
                                )
                                .await
                            }
                            .await;
                            if result.is_err() {
                                conn_ctx.events.record(NodeEvent::Failed);
                            }
                        },
                        |_| (),
                    )?;
                }
            }
        }
        let deadline = tokio::time::Instant::now() + context.drain_timeout;
        if runtime
            .shutdown_at(endpoint, &mut connections, deadline)
            .await?
            == NodeDrain::Forced
        {
            context.events.record(NodeEvent::ForcedCleanup);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    connection: quinn::Connection,
    access: IngressBinding,
    context: InboundContext,
    credentials: CredentialSet<[u8; 32]>,
    expected_path: Option<String>,
    client_v4: Option<Ipv4Addr>,
    client_v6: Option<Ipv6Addr>,
    stack_options: StackOptions,
    advertised_routes: Vec<Route>,
) -> Result<()> {
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> = h3::server::builder()
        .max_field_section_size(16384)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|_| protocol())?;

    let Some(resolver) = h3_conn.accept().await.map_err(|_| protocol())? else {
        return Ok(());
    };
    let (request, mut stream) = resolver.resolve_request().await.map_err(|_| protocol())?;
    let is_connect_ip = request.method() == http::Method::CONNECT
        && request.extensions().get::<h3::ext::Protocol>() == Some(&h3::ext::Protocol::CONNECT_IP);
    let path_ok = match &expected_path {
        Some(expected) => request.uri().path().starts_with(expected.as_str()),
        None => true,
    };
    if !is_connect_ip || !path_ok {
        let resp = http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(())
            .map_err(|_| protocol())?;
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return Err(Error::Rejected);
    }

    let peer_session: PeerSession = if credentials.is_empty() {
        access.local(&context)?
    } else {
        let auth_hdr = request
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Rejected)?;
        let digest: [u8; 32] = Sha256::digest(auth_hdr.as_bytes()).into();
        let verified = credentials.verify(&digest, |expected, actual| {
            Ok(bool::from(actual.ct_eq(expected)).then_some(*expected))
        });
        let Ok(token) = verified else {
            let resp = http::Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .body(())
                .map_err(|_| protocol())?;
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
            return Err(Error::Rejected);
        };
        access.authenticated(token, &context)?.0
    };

    let quarter_stream_id = stream.id().index();
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())
        .map_err(|_| protocol())?;
    stream
        .send_response(response)
        .await
        .map_err(|_| protocol())?;
    let (send, recv) = stream.split();
    let mut io = BodyIo::boxed(Writer::Server(send), Reader::Server(recv));

    if !advertised_routes.is_empty() {
        capsule::write_route_advertisement(&mut io, &advertised_routes).await?;
    }

    let tunnel = Arc::new(ServerTunnel::new(
        stack_options,
        peer_session,
        context.clone(),
    )?);
    let cancel = context.cancel.child_token();

    loop {
        match capsule::read(&mut io).await? {
            Some(Capsule::AddressRequest(requested)) => {
                let mut assigned = Vec::with_capacity(requested.len());
                for req in requested {
                    if req.ip.is_ipv4() {
                        if let Some(v4) = client_v4 {
                            assigned.push(Address {
                                request_id: req.request_id,
                                ip: IpAddr::V4(v4),
                                prefix_len: 32,
                            });
                        } else {
                            assigned.push(Address::unspecified(req.request_id, true));
                        }
                    } else if let Some(v6) = client_v6 {
                        assigned.push(Address {
                            request_id: req.request_id,
                            ip: IpAddr::V6(v6),
                            prefix_len: 128,
                        });
                    } else {
                        assigned.push(Address::unspecified(req.request_id, false));
                    }
                }
                capsule::write_address_assign(&mut io, &assigned).await?;
                break;
            }
            Some(Capsule::Ignored | Capsule::AddressAssign(_) | Capsule::RouteAdvertisement(_)) => {
            }
            None => return Err(protocol()),
        }
    }

    let up_tunnel = tunnel.clone();
    let up_conn = connection.clone();
    let down_tunnel = tunnel.clone();
    let down_conn = connection.clone();

    tokio::select! {
        biased;
        _ = cancel.cancelled() => {}
        _ = server_download(down_tunnel, down_conn, quarter_stream_id) => {}
        _ = server_upload(up_tunnel, up_conn, quarter_stream_id) => {}
        _ = drain_control_capsules(&mut io) => {}
    }
    cancel.cancel();
    tunnel.close();
    connection.close(0x100u32.into(), b"");
    Ok(())
}

async fn drain_control_capsules(io: &mut BoxStream) -> Result<()> {
    while let Some(_capsule) = capsule::read(io).await? {}
    Ok(())
}

async fn server_upload(
    tunnel: Arc<ServerTunnel>,
    connection: quinn::Connection,
    quarter: u64,
) -> Result<()> {
    loop {
        let packet = tunnel.next_packet().await?;
        match connection
            .send_datagram_wait(capsule::encode_datagram(quarter, &packet))
            .await
        {
            Ok(()) | Err(quinn::SendDatagramError::TooLarge) => {}
            Err(_) => return Err(protocol()),
        }
    }
}

async fn server_download(
    tunnel: Arc<ServerTunnel>,
    connection: quinn::Connection,
    quarter: u64,
) -> Result<()> {
    loop {
        let datagram = connection.read_datagram().await.map_err(|_| protocol())?;
        if let Some(packet) = capsule::decode_datagram(quarter, &datagram) {
            let _ = tunnel.receive(packet);
        }
    }
}

impl InboundProtocol for MasqueNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (index, (_, hash)) in self.credentials.rows().enumerate() {
            manifest.authentication("masque", index, *hash);
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn supports_tcp(&self) -> bool {
        false
    }
    fn supports_udp(&self) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        _stream: BoxStream,
        _ingress: IngressBinding,
        _context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("MASQUE 节点仅使用 QUIC/UDP 监听")) })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve_udp(socket, ingress, context))
    }
}

pub struct MasqueNodeFactory;
impl NodeFactory for MasqueNodeFactory {
    fn kind(&self) -> &'static str {
        "masque"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(MasqueNode::from_options(input)?))
    }
}
