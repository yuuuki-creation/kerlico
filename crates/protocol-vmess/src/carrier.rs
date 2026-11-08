//! VMess 载体只传递字节；不处理 UUID 或网站出口。
enum LayerPlan {
    Raw,
    WebSocket(WebSocketConfig),
    HttpUpgrade(HttpUpgradeConfig),
    Grpc(GrpcConfig),
}
impl LayerPlan {
    fn start(&self) -> TransportLayer {
        match self {
            Self::Raw => TransportLayer::Raw,
            Self::WebSocket(config) => TransportLayer::WebSocket(config.clone()),
            Self::HttpUpgrade(config) => TransportLayer::HttpUpgrade(config.clone()),
            Self::Grpc(config) => TransportLayer::Grpc(GrpcTransport::new(config.clone())),
        }
    }
}
use kerlico_core::{BoxStream, Destination, Error, Result};
use serde::Deserialize;
use std::{io::Cursor, sync::Arc};
use xray_transport::stream::{
    Authority, GrpcConfig, GrpcTransport, HttpUpgradeConfig, TransportLayer, WebSocketConfig,
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, TlsClientConfig, TlsConnector, TransportDialer,
};

/// xray 载体的 TCP 一律经 `d` 建立：有 detour 时交给上游出站，否则对全部候选做 Happy Eyeballs。
async fn dial_resolved(
    d: &kerlico_core::DialerOptions,
    target: xray_routing::Target,
    candidates: Vec<std::net::SocketAddr>,
) -> std::result::Result<BoxedTransportStream, xray_transport::TransportError> {
    let chained = |e: Error| xray_transport::TransportError::ChainedOutbound(e.to_string());
    let stream: BoxStream = if d.has_detour() || candidates.is_empty() {
        let host = match &target.addr {
            xray_routing::TargetAddr::Ip(ip) => ip.to_string(),
            xray_routing::TargetAddr::Domain(domain) => domain.clone(),
        };
        let dest = Destination::new(&host, target.port).map_err(chained)?;
        d.connect(&dest).await.map_err(chained)?
    } else {
        let (tcp, _) = kerlico_core::dialer::happy_eyeballs(
            candidates,
            d.fallback_delay(),
            |peer| async move { Ok(d.connect_addr(peer).await?) },
        )
        .await
        .map_err(chained)?;
        Box::new(tcp)
    };
    Ok(Box::new(BridgedStream(stream)))
}

#[derive(Clone, Deserialize, Default)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Transport {
    #[default]
    #[serde(alias = "raw")]
    Tcp,
    Ws {
        #[serde(default = "path")]
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    Httpupgrade {
        #[serde(default = "path")]
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    Grpc {
        #[serde(default)]
        service_name: String,
        #[serde(default)]
        authority: Option<String>,
        #[serde(default)]
        multi_mode: bool,
        #[serde(default, alias = "grpc-user-agent", alias = "user-agent")]
        user_agent: Option<String>,
    },
}
fn path() -> String {
    "/".into()
}
impl Transport {
    pub fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Tcp => true,
            Self::Ws { path, host } | Self::Httpupgrade { path, host } => {
                path.starts_with('/')
                    && path.len() <= 4096
                    && path.parse::<http::uri::PathAndQuery>().is_ok()
                    && !path.chars().any(|v| v.is_control() || v.is_whitespace())
                    && host.as_ref().is_none_or(|v| v.parse::<Authority>().is_ok())
            }
            Self::Grpc {
                service_name,
                authority,
                user_agent,
                ..
            } => {
                service_name.len() <= 1024
                    && !service_name
                        .chars()
                        .any(|v| v.is_control() || v.is_whitespace() || "/?#".contains(v))
                    && authority
                        .as_ref()
                        .is_none_or(|v| v.parse::<Authority>().is_ok())
                    && GrpcConfig::resolve_user_agent(user_agent.as_deref()).is_ok()
            }
        };
        if !valid {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn raw(&self) -> bool {
        matches!(self, Self::Tcp)
    }
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Grpc { .. } => vec![b"h2".to_vec()],
            Self::Ws { .. } | Self::Httpupgrade { .. } => vec![b"http/1.1".to_vec()],
            Self::Tcp => Vec::new(),
        }
    }
    fn layer(&self, default_host: String) -> Result<LayerPlan> {
        Ok(match self {
            Self::Tcp => LayerPlan::Raw,
            Self::Ws { path, host } => LayerPlan::WebSocket(WebSocketConfig {
                path: path.clone(),
                host: host.clone().unwrap_or(default_host),
                headers: Vec::new(),
                early_data_bytes: 0,
                heartbeat_period_secs: 0,
            }),
            Self::Httpupgrade { path, host } => LayerPlan::HttpUpgrade(HttpUpgradeConfig {
                path: path.clone(),
                host: host.clone().unwrap_or(default_host),
                headers: Vec::new(),
            }),
            Self::Grpc {
                service_name,
                authority,
                multi_mode,
                user_agent,
            } => LayerPlan::Grpc(GrpcConfig {
                service_name: service_name.clone(),
                authority: authority
                    .clone()
                    .unwrap_or(default_host)
                    .parse()
                    .map_err(|_| invalid())?,
                multi_mode: *multi_mode,
                user_agent: match user_agent {
                    Some(ua) => {
                        GrpcConfig::resolve_user_agent(Some(ua.as_str())).map_err(|_| invalid())?
                    }
                    None => http::HeaderValue::from_static("kerlico"),
                },
                idle_timeout_secs: 30,
                health_check_timeout_secs: 10,
                permit_without_stream: false,
                initial_windows_size: 4 * 1024 * 1024,
            }),
        })
    }
}
#[derive(Deserialize, Default)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ClientSecurity {
    #[default]
    None,
    Tls {
        #[serde(default)]
        server_name: Option<String>,
        #[serde(default)]
        ca_pem: Option<String>,
        #[serde(default, alias = "allow_insecure", alias = "skip_cert_verify")]
        insecure: bool,
        /// uTLS ClientHello 指纹，对应 Mihomo `client-fingerprint`。
        #[serde(default)]
        fingerprint: Option<String>,
    },
}
#[derive(Deserialize, Default)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ServerSecurity {
    #[default]
    None,
    Tls {
        #[serde(default)]
        certificate_pem: Option<String>,
        #[serde(default)]
        private_key_pem: Option<String>,
        #[serde(default)]
        certificate_file: Option<String>,
        #[serde(default)]
        private_key_file: Option<String>,
    },
}
fn invalid() -> Error {
    Error::Config("VMess 载体或 TLS 配置不合法".into())
}
struct BridgedStream(BoxStream);

impl tokio::io::AsyncRead for BridgedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BridgedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl xray_transport::TransportStream for BridgedStream {
    fn poll_read_direct(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(self, cx, output)
    }
    fn poll_write_direct(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        input: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(self, cx, input)
    }
}

pub(crate) struct Client {
    server: Destination,
    dialer: TransportDialer,
    connector: ConnectorConfig,
    layer: LayerPlan,
    resources:
        std::sync::Mutex<std::collections::HashMap<kerlico_core::ResourceKey, TransportLayer>>,
    owner: Option<xray_transport::lifecycle::TaskOwner>,
    has_detour: bool,
}
impl Client {
    pub fn start(mut self, host: &kerlico_core::ServiceContext) -> Result<Self> {
        let owner = xray_transport::lifecycle::TaskOwner::new();
        let stop = host.cancel();
        let waiting = owner.clone();
        let guard = owner.abort_on_drop();
        host.spawn(async move {
            let _guard = guard;
            tokio::select! {_=stop.cancelled()=>{},_=waiting.failed()=>{stop.cancel();}}
            waiting.shutdown().await;
        })?;
        self.owner = Some(owner);

        Ok(self)
    }

    pub fn build(
        server: Destination,
        security: ClientSecurity,
        transport: Transport,
    ) -> Result<Self> {
        transport.validate()?;
        let mut dialer = TransportDialer::system().map_err(|_| invalid())?;
        let (connector, host) = match security {
            ClientSecurity::None => (ConnectorConfig::Tcp, server.to_string()),
            ClientSecurity::Tls {
                server_name,
                ca_pem,
                insecure,
                fingerprint,
            } => {
                let name = server_name.unwrap_or_else(|| server.host());
                xray_transport::validate_tls_server_name(&name).map_err(|_| invalid())?;
                let alpn: Vec<String> = transport
                    .alpn()
                    .into_iter()
                    .map(|v| String::from_utf8_lossy(&v).into_owned())
                    .collect();
                let tls = kerlico_net::TlsClientOptions {
                    protocol: "VMess",
                    server_name: &name,
                    ca_pem: ca_pem.as_deref(),
                    insecure,
                    fingerprint: fingerprint.as_deref(),
                    alpn: &alpn,
                }
                .client_config()?;
                dialer = TransportDialer::with_tls_connector(
                    TlsConnector::with_pinned_client_config(Arc::new(tls)),
                );
                let config = TlsClientConfig {
                    server_name: name.clone(),
                    allow_insecure: false,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn: transport
                        .alpn()
                        .into_iter()
                        .map(|v| String::from_utf8(v).unwrap())
                        .collect(),
                    fingerprint: None,
                };
                (ConnectorConfig::Tls(config), name)
            }
        };
        let layer = transport.layer(host)?;
        let compile_dialer = kerlico_core::current_compile_dialer();
        let has_detour = compile_dialer.has_detour();
        let d = compile_dialer;
        dialer =
            dialer.with_resolved_tcp_connector(Arc::new(xray_transport::FnResolvedTcpConnector(
                move |target: xray_routing::Target, candidates: Vec<std::net::SocketAddr>| {
                    let d = d.clone();
                    async move { dial_resolved(&d, target, candidates).await }
                },
            )));
        Ok(Self {
            server,
            dialer,
            connector,
            layer,
            resources: std::sync::Mutex::new(std::collections::HashMap::new()),
            owner: None,
            has_detour,
        })
    }
    pub async fn shutdown(&self) -> Result<()> {
        let owner = self.owner.as_ref().ok_or_else(invalid)?;
        owner.close_admission();
        self.resources.lock().map_err(|_| invalid())?.clear();
        owner.shutdown().await;
        if owner.failed_tasks() > 0 {
            return Err(Error::Protocol("载体后台任务异常退出"));
        }
        Ok(())
    }
    pub async fn open(&self, context: &kerlico_core::ConnectContext) -> Result<BoxStream> {
        let owner = self.owner.as_ref().ok_or_else(invalid)?;
        if owner.is_closed() {
            return Err(Error::Cancelled);
        }
        if owner.is_closed() {
            return Err(Error::Cancelled);
        }
        owner.scope(self.open_scoped(context)).await
    }
    async fn open_scoped(&self, context: &kerlico_core::ConnectContext) -> Result<BoxStream> {
        let layer = {
            let mut resources = self.resources.lock().map_err(|_| invalid())?;
            resources
                .entry(context.resource_key().clone())
                .or_insert_with(|| self.layer.start())
                .clone()
        };
        let candidates = if self.has_detour {
            Vec::new()
        } else {
            kerlico_core::lookup_host((self.server.host().as_str(), self.server.port()))
                .await?
                .take(32)
                .collect::<Vec<_>>()
        };
        let target = xray_routing::Target::new(
            match self.server.address() {
                kerlico_core::Address::Ip(ip) => xray_routing::TargetAddr::Ip(*ip),
                kerlico_core::Address::Domain(name) => {
                    xray_routing::TargetAddr::Domain(name.clone())
                }
            },
            self.server.port(),
            xray_routing::Network::Tcp,
        );
        let mut stream = self
            .dialer
            .connect_stream(&self.connector, &layer, &target, &candidates, None)
            .await
            .map_err(|_| Error::Protocol("VMess 载体建立失败"))?;
        stream.release_record_alignment();
        Ok(Box::new(ClientIo(
            self.owner.as_ref().ok_or_else(invalid)?.wrap(stream),
        )))
    }
}
struct ClientIo(BoxedTransportStream);
impl tokio::io::AsyncRead for ClientIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, out)
    }
}
impl tokio::io::AsyncWrite for ClientIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, b)
    }
    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
pub(crate) fn server_tls(
    security: ServerSecurity,
    transport: &Transport,
) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    let ServerSecurity::Tls {
        certificate_pem,
        private_key_pem,
        certificate_file,
        private_key_file,
    } = security
    else {
        return Ok(None);
    };
    fn read(inline: Option<String>, file: Option<String>) -> Result<String> {
        match (inline, file) {
            (Some(value), None) if value.len() <= 1024 * 1024 => Ok(value),
            (None, Some(path)) => {
                if std::fs::metadata(&path).map_err(|_| invalid())?.len() > 1024 * 1024 {
                    return Err(invalid());
                }
                std::fs::read_to_string(path).map_err(|_| invalid())
            }
            _ => Err(invalid()),
        }
    }
    let cert = read(certificate_pem, certificate_file)?;
    let key = read(private_key_pem, private_key_file)?;
    let certs =
        rustls_pemfile::certs(&mut Cursor::new(cert)).collect::<std::io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(invalid());
    }
    let key = rustls_pemfile::private_key(&mut Cursor::new(key))?.ok_or_else(invalid)?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| invalid())?;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.alpn_protocols = transport.alpn();
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
}
