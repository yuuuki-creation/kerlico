//! VMess 载体只传递字节；不处理 UUID 或网站出口。
use kerlico_core::{BoxStream, Destination, Error, Result};
use serde::Deserialize;
use std::{io::Cursor, sync::Arc};
use xray_transport::stream::{
    Authority, GrpcConfig, GrpcTransport, HeaderValue, HttpUpgradeConfig, TransportLayer,
    WebSocketConfig,
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, TlsClientConfig, TlsConnector, TransportDialer,
};

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
                ..
            } => {
                service_name.len() <= 1024
                    && !service_name
                        .chars()
                        .any(|v| v.is_control() || v.is_whitespace() || "/?#".contains(v))
                    && authority
                        .as_ref()
                        .is_none_or(|v| v.parse::<Authority>().is_ok())
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
    fn layer(&self, default_host: String) -> Result<TransportLayer> {
        Ok(match self {
            Self::Tcp => TransportLayer::Raw,
            Self::Ws { path, host } => TransportLayer::WebSocket(WebSocketConfig {
                path: path.clone(),
                host: host.clone().unwrap_or(default_host),
                headers: Vec::new(),
                early_data_bytes: 0,
                heartbeat_period_secs: 0,
            }),
            Self::Httpupgrade { path, host } => TransportLayer::HttpUpgrade(HttpUpgradeConfig {
                path: path.clone(),
                host: host.clone().unwrap_or(default_host),
                headers: Vec::new(),
            }),
            Self::Grpc {
                service_name,
                authority,
                multi_mode,
            } => TransportLayer::Grpc(GrpcTransport::new(GrpcConfig {
                service_name: service_name.clone(),
                authority: authority
                    .clone()
                    .unwrap_or(default_host)
                    .parse()
                    .map_err(|_| invalid())?,
                multi_mode: *multi_mode,
                user_agent: HeaderValue::from_static("kerlico"),
                idle_timeout_secs: 30,
                health_check_timeout_secs: 10,
                permit_without_stream: false,
                initial_windows_size: 0,
            })),
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
pub(crate) struct Client {
    server: Destination,
    dialer: TransportDialer,
    connector: ConnectorConfig,
    layer: TransportLayer,
}
impl Client {
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
            } => {
                let name = server_name.unwrap_or_else(|| server.host());
                xray_transport::validate_tls_server_name(&name).map_err(|_| invalid())?;
                let mut roots = rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                );
                if let Some(pem) = ca_pem {
                    let certs = rustls_pemfile::certs(&mut Cursor::new(pem))
                        .collect::<std::io::Result<Vec<_>>>()?;
                    if certs.is_empty() {
                        return Err(invalid());
                    }
                    for cert in certs {
                        roots.add(cert).map_err(|_| invalid())?;
                    }
                }
                let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|_| invalid())?
                .with_root_certificates(roots)
                .with_no_client_auth();
                tls.alpn_protocols = transport.alpn();
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
        Ok(Self {
            server,
            dialer,
            connector,
            layer,
        })
    }
    pub async fn open(&self) -> Result<BoxStream> {
        let candidates = tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
            .await?
            .take(32)
            .collect::<Vec<_>>();
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
        let stream = self
            .dialer
            .connect_stream(&self.connector, &self.layer, &target, &candidates, None)
            .await
            .map_err(|_| Error::Protocol("VMess 载体建立失败"))?;
        Ok(Box::new(ClientIo(stream)))
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
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| invalid())?;
    config.alpn_protocols = transport.alpn();
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
}
