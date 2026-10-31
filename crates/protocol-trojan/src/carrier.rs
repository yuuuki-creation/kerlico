//! 客户端载体不解释 Trojan 认证或数据帧。

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

pub(crate) struct Carrier {
    server: Destination,
    connector: ConnectorConfig,
    layer: TransportLayer,
    dialer: TransportDialer,
}
impl Carrier {
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
            Transport::Tcp => TransportLayer::Raw,
            Transport::Ws {
                path,
                host,
                headers,
                early_data_bytes,
            } => TransportLayer::WebSocket(WebSocketConfig {
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
            } => TransportLayer::HttpUpgrade(HttpUpgradeConfig {
                path,
                host: host.unwrap_or(authority),
                headers,
            }),
            Transport::Grpc {
                service_name,
                authority: host,
                multi_mode,
            } => TransportLayer::Grpc(GrpcTransport::new(GrpcConfig {
                service_name,
                authority: host.unwrap_or(authority).parse().map_err(|_| invalid())?,
                multi_mode,
                user_agent: http::HeaderValue::from_static("grpc-go/1.81.0"),
                idle_timeout_secs: 0,
                health_check_timeout_secs: 0,
                permit_without_stream: false,
                initial_windows_size: 0,
            })),
        };
        Ok(Self {
            server,
            connector,
            layer,
            dialer,
        })
    }
    pub async fn open(&self) -> Result<BoxStream> {
        let target = Target::new(
            match self.server.address() {
                Address::Ip(ip) => TargetAddr::Ip(*ip),
                Address::Domain(name) => TargetAddr::Domain(name.clone()),
            },
            self.server.port(),
            Network::Tcp,
        );
        let mut candidates: Vec<_> =
            tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
                .await?
                .collect();
        candidates.sort_by_key(|address| address.is_ipv6());
        candidates.dedup();
        candidates.truncate(32);
        let stream = self
            .dialer
            .connect_stream(&self.connector, &self.layer, &target, &candidates, None)
            .await
            .map_err(|_| Error::Protocol("Trojan 载体建立失败"))?;
        Ok(Box::new(stream))
    }
}
