//! 载体只负责安全连接及传输封装；VLESS 身份、flow 和包编码在上层处理。

use crate::profile::{Family, HttpVersion, Security, Transport, XhttpMode, XhttpSettings};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kerlico_core::{Address, Destination, Error, Result};
use std::{io::Cursor, net::SocketAddr, sync::Arc};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::stream::{
    Authority, GrpcConfig, GrpcTransport, HeaderMap, HeaderValue, HttpUpgradeConfig,
    TransportLayer, WebSocketConfig, XhttpConfig, XhttpConfigInput,
    XhttpEndpoint, XhttpHttpVersion, XhttpModeSelection, XhttpRange, XhttpScheme, XhttpTransport,
    XhttpXmuxPolicy,
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, RealityClientConfig, RealityRuntimeEngine,
    RustlsRealityTlsSessionProvider, TlsClientConfig, TlsConnector, TransportDialer,
};

pub(crate) fn target(value: &Destination, udp: bool) -> Target {
    Target::new(
        match value.address() {
            Address::Ip(ip) => TargetAddr::Ip(*ip),
            Address::Domain(s) => TargetAddr::Domain(s.clone()),
        },
        value.port(),
        if udp { Network::Udp } else { Network::Tcp },
    )
}

pub(crate) struct Carrier {
    server: Destination,
    connector: ConnectorConfig,
    transport: TransportLayer,
    dialer: TransportDialer,
    download: Option<Box<Carrier>>,
    storage: Option<Arc<crate::xdrive::Transport>>,
    quic_tls: Option<Arc<rustls::ClientConfig>>,
    family: Family,
}

fn invalid() -> Error {
    Error::Config("VLESS 传输或安全选项不合法".into())
}
fn io_failure() -> Error {
    Error::Protocol("VLESS 载体建立失败")
}

impl Carrier {
    pub fn build(
        server: Destination,
        security: Security,
        transport: Transport,
        encrypted: bool,
        family: Family,
    ) -> Result<Self> {
        if let Transport::Xdrive { settings } = transport {
            if !encrypted || !matches!(family, Family::Auto) {
                return Err(Error::Config(
                    "XDRIVE 必须使用 Encryption，地址族由存储 endpoint 决定".into(),
                ));
            }
            let ca = match security {
                Security::None => None,
                Security::Tls {
                    server_name,
                    ca_pem,
                    alpn,
                    fingerprint,
                } => {
                    if server_name.is_some() || !alpn.is_empty() || fingerprint.is_some() {
                        return Err(Error::Config(
                            "XDRIVE 的 HTTP 身份由存储 endpoint 配置".into(),
                        ));
                    }
                    ca_pem
                }
                Security::Reality { .. } => return Err(Error::Unsupported("XDRIVE REALITY")),
            };
            let storage = crate::xdrive::Transport::new(settings, ca.as_deref())?;
            return Ok(Self {
                server,
                connector: ConnectorConfig::Tcp,
                transport: TransportLayer::Raw,
                dialer: TransportDialer::system().map_err(|_| invalid())?,
                download: None,
                storage: Some(storage),
                quic_tls: None,
                family,
            });
        }
        if let Address::Ip(ip) = server.address()
            && !family.accepts(*ip)
        {
            return Err(Error::Config("节点地址不属于指定载体地址族".into()));
        }
        let quic_tls = match &security {
            Security::Tls { ca_pem, .. } => Some(quic_config(ca_pem.as_deref())?),
            _ => None,
        };
        let raw = matches!(transport, Transport::Tcp);
        let reality = matches!(security, Security::Reality { .. });
        if reality
            && matches!(
                transport,
                Transport::Ws { .. } | Transport::Httpupgrade { .. }
            )
        {
            return Err(Error::Config("REALITY 不支持 WS 或 HTTPUpgrade".into()));
        }
        if matches!(security, Security::None) && !encrypted && !server.is_loopback() {
            return Err(Error::Config(
                "无传输安全且未启用 Encryption 时只允许回环服务器".into(),
            ));
        }
        let mut dialer = TransportDialer::system().map_err(|_| invalid())?;
        let connector = match security {
            Security::None => ConnectorConfig::Tcp,
            Security::Reality {
                server_name,
                public_key,
                short_id,
                fingerprint,
                mldsa65_verify,
            } => {
                xray_transport::validate_tls_server_name(&server_name).map_err(|_| invalid())?;
                let key = URL_SAFE_NO_PAD.decode(public_key).map_err(|_| invalid())?;
                let public_key: [u8; 32] = key.try_into().map_err(|_| invalid())?;
                if public_key == [0; 32] || short_id.len() > 16 || short_id.len() % 2 != 0 {
                    return Err(invalid());
                }
                let short_id = short_id
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| {
                        let s = std::str::from_utf8(c).map_err(|_| invalid())?;
                        u8::from_str_radix(s, 16).map_err(|_| invalid())
                    })
                    .collect::<Result<Vec<_>>>()?;
                ConnectorConfig::Reality(RealityClientConfig {
                    server_name,
                    public_key,
                    short_id,
                    fingerprint,
                    spider_x: "/".into(),
                    mldsa65_verify: mldsa65_verify
                        .map(|value| URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid()))
                        .transpose()?
                        .map(|bytes| {
                            if bytes.len() == 1952 {
                                Ok(bytes)
                            } else {
                                Err(invalid())
                            }
                        })
                        .transpose()?,
                })
            }
            Security::Tls {
                server_name,
                ca_pem,
                mut alpn,
                fingerprint,
            } => {
                let name = server_name.unwrap_or_else(|| server.host());
                xray_transport::validate_tls_server_name(&name).map_err(|_| invalid())?;
                if alpn.iter().any(|s| s.is_empty() || s.len() > 255) {
                    return Err(invalid());
                }
                if let Transport::Xhttp { settings } = &transport {
                    alpn = match settings.http_version {
                        HttpVersion::H1 => vec!["http/1.1".into()],
                        HttpVersion::H2 => vec!["h2".into()],
                        HttpVersion::H3 => vec!["h3".into()],
                        HttpVersion::Auto => alpn,
                    };
                }
                if let Some(pem) = ca_pem {
                    if fingerprint.as_deref().is_some_and(|s| s != "unsafe") {
                        return Err(Error::Config(
                            "自定义 CA 当前不能与 TLS 指纹整形一起使用".into(),
                        ));
                    }
                    let mut roots = rustls::RootCertStore::from_iter(
                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                    );
                    let certs = rustls_pemfile::certs(&mut Cursor::new(pem))
                        .collect::<std::io::Result<Vec<_>>>()?;
                    if certs.is_empty() {
                        return Err(invalid());
                    }
                    for cert in certs {
                        roots.add(cert).map_err(|_| invalid())?;
                    }
                    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
                        rustls::crypto::aws_lc_rs::default_provider(),
                    ));
                    let mut config = if raw {
                        builder.with_protocol_versions(&[&rustls::version::TLS13])
                    } else {
                        builder.with_safe_default_protocol_versions()
                    }
                    .map_err(|_| invalid())?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                    config.alpn_protocols = if matches!(transport, Transport::Grpc { .. }) {
                        vec![b"h2".to_vec()]
                    } else if matches!(
                        transport,
                        Transport::Ws { .. } | Transport::Httpupgrade { .. }
                    ) {
                        vec![b"http/1.1".to_vec()]
                    } else if matches!(transport, Transport::Xhttp { .. }) && alpn.is_empty() {
                        vec![b"h2".to_vec()]
                    } else {
                        alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
                    };
                    dialer = TransportDialer::with_tls_connector(
                        TlsConnector::with_pinned_client_config(Arc::new(config)),
                    )
                    .with_reality_engine(Arc::new(RealityRuntimeEngine::new(Arc::new(
                        RustlsRealityTlsSessionProvider::new(),
                    ))));
                }
                let config = TlsClientConfig {
                    server_name: name,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn,
                    fingerprint,
                };
                // 配置检查不拨号，及早拒绝未知或无法协商的指纹。
                dialer
                    .tls_connector()
                    .client_config_for(&config)
                    .map_err(|_| invalid())?;
                ConnectorConfig::Tls(config)
            }
        };
        let authority = match &connector {
            ConnectorConfig::Tls(c) => c.server_name.clone(),
            ConnectorConfig::Reality(c) => c.server_name.clone(),
            ConnectorConfig::Tcp => match server.address() {
                Address::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
                _ => server.host(),
            },
        };
        let mut download = None;
        let layer = match transport {
            Transport::Tcp => TransportLayer::Raw,
            Transport::Xdrive { .. } => return Err(invalid()),
            Transport::Ws {
                path,
                host,
                headers,
                early_data_bytes,
                heartbeat_period_secs,
            } => {
                validate_http(&path, host.as_deref(), &headers)?;
                TransportLayer::WebSocket(WebSocketConfig {
                    path,
                    host: host.unwrap_or(authority),
                    headers,
                    early_data_bytes,
                    heartbeat_period_secs,
                })
            }
            Transport::Httpupgrade {
                path,
                host,
                headers,
            } => {
                validate_http(&path, host.as_deref(), &headers)?;
                TransportLayer::HttpUpgrade(HttpUpgradeConfig {
                    path,
                    host: host.unwrap_or(authority),
                    headers,
                })
            }
            Transport::Grpc {
                service_name,
                authority: host,
                multi_mode,
                idle_timeout_secs,
                health_check_timeout_secs,
                permit_without_stream,
                initial_window_size,
            } => {
                if service_name.len() > 1024 || service_name.chars().any(char::is_control) {
                    return Err(invalid());
                }
                let authority: Authority =
                    host.unwrap_or(authority).parse().map_err(|_| invalid())?;
                TransportLayer::Grpc(GrpcTransport::new(GrpcConfig {
                    service_name,
                    authority,
                    multi_mode,
                    user_agent: HeaderValue::from_static("grpc-go/1.81.0"),
                    idle_timeout_secs,
                    health_check_timeout_secs,
                    permit_without_stream,
                    initial_windows_size: initial_window_size,
                }))
            }
            Transport::Xhttp { mut settings } => {
                if let Some(mut down) = settings.download.take() {
                    if settings.mode == XhttpMode::StreamOne || down.xhttp.download.is_some() {
                        return Err(invalid());
                    }
                    if !matches!(connector, ConnectorConfig::Tcp)
                        && matches!(down.security, Security::None)
                    {
                        return Err(invalid());
                    }
                    if reality && settings.mode == XhttpMode::Auto {
                        settings.mode = XhttpMode::StreamUp;
                    }
                    down.xhttp.download = None;
                    download = Some(Box::new(Self::build(
                        down.server.destination()?,
                        down.security,
                        Transport::Xhttp {
                            settings: down.xhttp,
                        },
                        encrypted,
                        down.server_family,
                    )?));
                }
                TransportLayer::Xhttp(xhttp(settings, &connector, &authority)?)
            }
        };
        Ok(Self {
            server,
            connector,
            transport: layer,
            dialer,
            download,
            storage: None,
            quic_tls,
            family,
        })
    }

    fn mode_dial(
        &self,
        transport: &XhttpTransport,
        candidates: &[SocketAddr],
    ) -> Result<xray_transport::stream::xhttp_transport_test_only::XhttpModeDial> {
        use xray_transport::stream::{
            xhttp_h3_test_only::{H3ConnectConfig, connect_h3_candidates},
            xhttp_transport_test_only::XhttpModeDial,
        };
        let candidates = candidates.to_vec();
        if transport.http_version() == XhttpHttpVersion::Http3 {
            let ConnectorConfig::Tls(config) = &self.connector else {
                return Err(invalid());
            };
            let server_name = config.server_name.clone();
            let tls = self.quic_tls.clone().ok_or_else(invalid)?;
            let quic = transport.h3_quic_config().clone();
            return Ok(XhttpModeDial::Http3(Arc::new(move || {
                let server_name = server_name.clone();
                let tls = tls.clone();
                let candidates = candidates.clone();
                let quic = quic.clone();
                Box::pin(async move {
                    let remote_addr = *candidates.first().ok_or(
                        xray_transport::stream::xhttp_h3_test_only::H3Error::NoResolvedCandidate,
                    )?;
                    connect_h3_candidates(
                        H3ConnectConfig {
                            remote_addr,
                            server_name,
                            tls_config: tls,
                            socket_protector: None,
                            quic,
                        },
                        &candidates,
                        None,
                    )
                    .await
                })
            })));
        }
        let dialer = self.dialer.clone();
        let mut config = self.connector.clone();
        let server = target(&self.server, false);
        if let ConnectorConfig::Tls(tls) = &mut config {
            if transport.http_version() == XhttpHttpVersion::Http1 {
                tls.alpn = vec!["http/1.1".into()];
            } else if tls.alpn.is_empty() {
                tls.alpn = vec!["h2".into()];
            }
        }
        Ok(XhttpModeDial::Stream(Arc::new(move || {
            let dialer = dialer.clone();
            let config = config.clone();
            let server = server.clone();
            let candidates = candidates.clone();
            Box::pin(async move {
                dialer
                    .connect_resolved(&config, &server, &candidates, None)
                    .await
            })
        })))
    }

    pub async fn open(&self) -> Result<BoxedTransportStream> {
        if let Some(storage) = &self.storage {
            return storage.open().await;
        }
        let server = target(&self.server, false);
        let candidates: Vec<SocketAddr> =
            tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
                .await?
                .filter(|address| self.family.accepts(address.ip()))
                .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
                .collect();
        if let Some(down) = &self.download {
            let down_candidates: Vec<_> =
                tokio::net::lookup_host((down.server.host().as_str(), down.server.port()))
                    .await?
                    .filter(|address| down.family.accepts(address.ip()))
                    .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
                    .collect();
            let (TransportLayer::Xhttp(up), TransportLayer::Xhttp(download)) =
                (&self.transport, &down.transport)
            else {
                return Err(invalid());
            };
            up.open_split_stream_with_dials(
                self.mode_dial(up, &candidates)?,
                download,
                down.mode_dial(download, &down_candidates)?,
            )
            .await
            .map_err(|_| io_failure())
        } else {
            self.dialer
                .connect_stream(&self.connector, &self.transport, &server, &candidates, None)
                .await
                .map_err(|_| io_failure())
        }
    }
}

fn validate_http(path: &str, host: Option<&str>, headers: &[(String, String)]) -> Result<()> {
    if !path.starts_with('/') || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(invalid());
    }
    if host.is_some_and(|s| s.parse::<Authority>().is_err()) || headers.len() > 64 {
        return Err(invalid());
    }
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.chars().any(|c| c.is_control() && c != '\t')
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn xhttp(
    settings: XhttpSettings,
    security: &ConnectorConfig,
    authority: &str,
) -> Result<XhttpTransport> {
    let reality = matches!(security, ConnectorConfig::Reality(_));
    let version = match (security, settings.http_version) {
        (ConnectorConfig::Reality(_), HttpVersion::Auto | HttpVersion::H2) => {
            XhttpHttpVersion::Http2
        }
        (ConnectorConfig::Reality(_), _) => return Err(invalid()),
        (ConnectorConfig::Tcp, HttpVersion::Auto | HttpVersion::H1) => XhttpHttpVersion::Http1,
        (ConnectorConfig::Tcp, _) => return Err(invalid()),
        (_, HttpVersion::H1) => XhttpHttpVersion::Http1,
        (_, HttpVersion::H3) => XhttpHttpVersion::Http3,
        (_, HttpVersion::H2) => XhttpHttpVersion::Http2,
        (ConnectorConfig::Tls(c), HttpVersion::Auto) => match c.alpn.as_slice() {
            [s] if s == "h3" => XhttpHttpVersion::Http3,
            [s] if s == "http/1.1" => XhttpHttpVersion::Http1,
            _ => XhttpHttpVersion::Http2,
        },
    };
    validate_http(&settings.path, settings.host.as_deref(), &settings.headers)?;
    let mut headers = HeaderMap::new();
    for (name, value) in settings.headers {
        headers.add(&name, &value);
    }
    let mut input = XhttpConfigInput {
        path: settings.path,
        headers,
        is_reality: reality,
        no_grpc_header: settings.no_grpc_header,
        mode: match settings.mode {
            XhttpMode::Auto => XhttpModeSelection::Auto,
            XhttpMode::PacketUp => XhttpModeSelection::PacketUp,
            XhttpMode::StreamUp => XhttpModeSelection::StreamUp,
            XhttpMode::StreamOne => XhttpModeSelection::StreamOne,
        },
        ..Default::default()
    };
    fn range(n: u32) -> Result<XhttpRange> {
        Ok(XhttpRange::exact(i32::try_from(n).map_err(|_| invalid())?))
    }
    if let Some(n) = settings.max_post_bytes {
        input.sc_max_each_post_bytes = range(n)?;
    }
    if let Some(n) = settings.min_post_interval_ms {
        input.sc_min_posts_interval_ms = range(n)?;
    }
    if let Some(n) = settings.max_buffered_posts {
        input.sc_max_buffered_posts = n.into();
    }
    if let Some([a, b]) = settings.padding_bytes {
        input.x_padding_bytes = XhttpRange {
            from: i32::try_from(a).map_err(|_| invalid())?,
            to: i32::try_from(b).map_err(|_| invalid())?,
        };
    }
    let config = XhttpConfig::normalize(input).map_err(|_| invalid())?;
    let endpoint = XhttpEndpoint::new(
        if matches!(security, ConnectorConfig::Tcp) {
            XhttpScheme::Http
        } else {
            XhttpScheme::Https
        },
        settings.host.unwrap_or_else(|| authority.into()),
    )
    .map_err(|_| invalid())?;
    XhttpTransport::new(config, endpoint, version, XhttpXmuxPolicy::default())
        .map_err(|_| invalid())
}

fn quic_config(ca: Option<&str>) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ca) = ca {
        for cert in
            rustls_pemfile::certs(&mut Cursor::new(ca)).collect::<std::io::Result<Vec<_>>>()?
        {
            roots.add(cert).map_err(|_| invalid())?;
        }
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| invalid())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(config))
}
