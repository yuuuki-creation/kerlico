//! 客户端载体不解释 Trojan 认证或数据帧。
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

use crate::{
    config::{ClientSecurity, Transport},
    invalid,
};
use kerlico_core::{Address, BoxStream, Destination, Error, Result};
use std::{io::Cursor, sync::Arc};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::stream::{
    GrpcConfig, GrpcTransport, HttpUpgradeConfig, TransportLayer, WebSocketConfig,
};
use xray_transport::{ConnectorConfig, TlsClientConfig, TlsConnector, TransportDialer};

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

pub(crate) struct Carrier {
    server: Destination,
    connector: ConnectorConfig,
    layer: LayerPlan,
    resources:
        std::sync::Mutex<std::collections::HashMap<kerlico_core::ResourceKey, TransportLayer>>,
    owner: Option<xray_transport::lifecycle::TaskOwner>,
    dialer: TransportDialer,
    has_detour: bool,
}
impl Carrier {
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
        let mut dialer = TransportDialer::system().map_err(|_| invalid())?;
        let connector = match security {
            ClientSecurity::None => {
                if !server.is_loopback() {
                    return Err(Error::Config(
                        "未启用 TLS 的 Trojan 仅允许回环服务器".into(),
                    ));
                }
                ConnectorConfig::Tcp
            }
            ClientSecurity::Tls {
                server_name,
                ca_pem,
            } => {
                let name = server_name.unwrap_or_else(|| server.host());
                xray_transport::validate_tls_server_name(&name).map_err(|_| invalid())?;
                let mut roots = rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                );
                if let Some(pem) = ca_pem {
                    if pem.len() > 1024 * 1024 {
                        return Err(invalid());
                    }
                    let certs = rustls_pemfile::certs(&mut Cursor::new(pem))
                        .collect::<std::io::Result<Vec<_>>>()
                        .map_err(|_| invalid())?;
                    if certs.is_empty() {
                        return Err(invalid());
                    }
                    for cert in certs {
                        roots.add(cert).map_err(|_| invalid())?;
                    }
                }
                let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|_| invalid())?
                .with_root_certificates(roots)
                .with_no_client_auth();
                config.resumption = rustls::client::Resumption::disabled();
                config.alpn_protocols = transport.alpn();
                dialer = TransportDialer::with_tls_connector(
                    TlsConnector::with_pinned_client_config(Arc::new(config)),
                );
                ConnectorConfig::Tls(TlsClientConfig {
                    server_name: name,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn: transport
                        .alpn()
                        .into_iter()
                        .map(|s| String::from_utf8_lossy(&s).into_owned())
                        .collect(),
                    fingerprint: None,
                })
            }
        };
        let authority = match &connector {
            ConnectorConfig::Tls(tls) => tls.server_name.clone(),
            _ => match server.address() {
                Address::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
                _ => server.host(),
            },
        };
        let layer = match transport {
            Transport::Tcp => LayerPlan::Raw,
            Transport::Ws {
                path,
                host,
                headers,
                early_data_bytes,
            } => LayerPlan::WebSocket(WebSocketConfig {
                path,
                host: host.unwrap_or(authority),
                headers,
                early_data_bytes,
                heartbeat_period_secs: 0,
            }),
            Transport::Httpupgrade {
                path,
                host,
                headers,
            } => LayerPlan::HttpUpgrade(HttpUpgradeConfig {
                path,
                host: host.unwrap_or(authority),
                headers,
            }),
            Transport::Grpc {
                service_name,
                authority: host,
                multi_mode,
                user_agent,
            } => LayerPlan::Grpc(GrpcConfig {
                service_name,
                authority: host.unwrap_or(authority).parse().map_err(|_| invalid())?,
                multi_mode,
                user_agent: GrpcConfig::resolve_user_agent(user_agent.as_deref())
                    .map_err(|_| invalid())?,
                idle_timeout_secs: 0,
                health_check_timeout_secs: 0,
                permit_without_stream: false,
                initial_windows_size: 0,
            }),
        };
        let compile_dialer = kerlico_core::current_compile_dialer();
        let has_detour = compile_dialer.has_detour();
        if !compile_dialer.is_default() {
            let d = compile_dialer.clone();
            dialer = dialer.with_resolved_tcp_connector(Arc::new(
                xray_transport::FnResolvedTcpConnector(
                    move |target: Target, candidates: Vec<std::net::SocketAddr>| {
                        let d = d.clone();
                        async move {
                            let dest = if d.has_detour() {
                                let host = match &target.addr {
                                    TargetAddr::Ip(ip) => ip.to_string(),
                                    TargetAddr::Domain(domain) => domain.clone(),
                                };
                                Destination::new(&host, target.port).map_err(|e| {
                                    xray_transport::TransportError::ChainedOutbound(e.to_string())
                                })?
                            } else {
                                let first = candidates.first().copied().ok_or_else(|| {
                                    xray_transport::TransportError::ChainedOutbound(
                                        "无可用候选地址".into(),
                                    )
                                })?;
                                Destination::new(&first.ip().to_string(), first.port()).map_err(
                                    |e| {
                                        xray_transport::TransportError::ChainedOutbound(
                                            e.to_string(),
                                        )
                                    },
                                )?
                            };
                            let stream =
                                kerlico_net::TcpConnector::connect_raw_with_dialer(&dest, &d)
                                    .await
                                    .map_err(|e| {
                                        xray_transport::TransportError::ChainedOutbound(
                                            e.to_string(),
                                        )
                                    })?;
                            Ok(Box::new(BridgedStream(stream))
                                as xray_transport::BoxedTransportStream)
                        }
                    },
                ),
            ));
        }
        Ok(Self {
            server,
            connector,
            layer,
            resources: std::sync::Mutex::new(std::collections::HashMap::new()),
            owner: None,
            dialer,
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
        let target = Target::new(
            match self.server.address() {
                Address::Ip(ip) => TargetAddr::Ip(*ip),
                Address::Domain(name) => TargetAddr::Domain(name.clone()),
            },
            self.server.port(),
            Network::Tcp,
        );
        let candidates: Vec<_> = if self.has_detour {
            Vec::new()
        } else {
            let mut list: Vec<_> =
                tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
                    .await?
                    .collect();
            list.sort_by_key(|address| address.is_ipv6());
            list.dedup();
            list.truncate(32);
            list
        };
        let stream = self
            .dialer
            .connect_stream(&self.connector, &layer, &target, &candidates, None)
            .await
            .map_err(|_| Error::Protocol("Trojan 载体建立失败"))?;
        Ok(Box::new(
            self.owner.as_ref().ok_or_else(invalid)?.wrap(stream),
        ))
    }
}
