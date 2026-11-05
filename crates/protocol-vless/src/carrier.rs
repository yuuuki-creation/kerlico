//! 载体只负责安全连接及传输封装；VLESS 身份、flow 和包编码在上层处理。

use crate::profile::{Family, HttpVersion, Security, Transport, XhttpMode, XhttpSettings};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kerlico_core::{Address, Destination, Error, Result};
use std::{io::Cursor, net::SocketAddr, sync::Arc};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::stream::{
    Authority, GrpcConfig, GrpcTransport, HeaderMap, HttpUpgradeConfig, TransportLayer,
    WebSocketConfig, XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpHttpVersion,
    XhttpMetadataPlacement, XhttpModeSelection, XhttpPaddingMethod, XhttpPaddingPlacement,
    XhttpRange, XhttpScheme, XhttpTransport, XhttpUplinkDataPlacement, XhttpXmuxPolicy,
    xhttp_h3_test_only::{H3Congestion, H3QuicConfig},
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, CustomTlsClientOptions, RealityClientConfig,
    RealityRuntimeEngine, RustlsRealityTlsSessionProvider, TlsClientConfig, TlsConnector,
    TransportDialer, build_custom_tls_client_config,
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

enum LayerPlan {
    Raw,
    WebSocket(WebSocketConfig),
    HttpUpgrade(HttpUpgradeConfig),
    Grpc(GrpcConfig),
    Xhttp {
        config: Box<XhttpConfig>,
        endpoint: XhttpEndpoint,
        version: XhttpHttpVersion,
        xmux: XhttpXmuxPolicy,
        h3_quic: H3QuicConfig,
    },
}
impl LayerPlan {
    fn start(&self) -> Result<TransportLayer> {
        Ok(match self {
            Self::Raw => TransportLayer::Raw,
            Self::WebSocket(config) => TransportLayer::WebSocket(config.clone()),
            Self::HttpUpgrade(config) => TransportLayer::HttpUpgrade(config.clone()),
            Self::Grpc(config) => TransportLayer::Grpc(GrpcTransport::new(config.clone())),
            Self::Xhttp {
                config,
                endpoint,
                version,
                xmux,
                h3_quic,
            } => TransportLayer::Xhttp(
                XhttpTransport::new_with_h3_quic(
                    config.as_ref().clone(),
                    endpoint.clone(),
                    *version,
                    *xmux,
                    h3_quic.clone(),
                )
                .map_err(|_| invalid())?,
            ),
        })
    }
}

pub(crate) struct Carrier {
    server: Destination,
    connector: ConnectorConfig,
    transport: LayerPlan,
    dialer: TransportDialer,
    dialer_opts: kerlico_core::DialerOptions,
    download: Option<Box<Carrier>>,
    storage: Option<crate::xdrive::Plan>,
    storage_resources: std::sync::Mutex<
        std::collections::HashMap<kerlico_core::ResourceKey, Arc<crate::xdrive::Transport>>,
    >,
    quic_tls: Option<Arc<rustls::ClientConfig>>,
    family: Family,
    resources:
        std::sync::Mutex<std::collections::HashMap<kerlico_core::ResourceKey, TransportLayer>>,
    owner: Option<xray_transport::lifecycle::TaskOwner>,
}

fn invalid() -> Error {
    Error::Config("VLESS 传输或安全选项不合法".into())
}
fn io_failure() -> Error {
    Error::Protocol("VLESS 载体建立失败")
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
        if let Some(download) = self.download.take() {
            self.download = Some(Box::new((*download).start(host)?));
        }
        Ok(self)
    }

    pub fn build(
        server: Destination,
        security: Security,
        transport: Transport,
        encrypted: bool,
        family: Family,
        mut fragment_input: Option<crate::profile::TcpFragmentInput>,
    ) -> Result<Self> {
        let dialer_opts = kerlico_core::current_compile_dialer();
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
                    ..
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
            let storage = crate::xdrive::Transport::compile(settings, ca.as_deref())?;
            return Ok(Self {
                server,
                connector: ConnectorConfig::Tcp,
                transport: LayerPlan::Raw,
                dialer: TransportDialer::system().map_err(|_| invalid())?,
                dialer_opts,
                download: None,
                storage: Some(storage),
                storage_resources: std::sync::Mutex::new(std::collections::HashMap::new()),
                quic_tls: None,
                family,
                resources: std::sync::Mutex::new(std::collections::HashMap::new()),
                owner: None,
            });
        }
        if let Address::Ip(ip) = server.address()
            && !family.accepts(*ip)
        {
            return Err(Error::Config("节点地址不属于指定载体地址族".into()));
        }
        let quic_tls = match &security {
            Security::Tls {
                ca_pem,
                certificate_path,
                use_system_ca,
                allow_insecure,
                pinned_peer_cert_sha256,
                certificate_public_key_sha256,
                verify_peer_cert_by_name,
                ..
            } => Some(quic_config(
                ca_pem.as_deref(),
                certificate_path.as_deref(),
                use_system_ca.unwrap_or(true),
                *allow_insecure,
                pinned_peer_cert_sha256,
                certificate_public_key_sha256,
                verify_peer_cert_by_name,
            )?),
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
                certificate_path,
                use_system_ca,
                allow_insecure,
                pinned_peer_cert_sha256,
                certificate_public_key_sha256,
                verify_peer_cert_by_name,
                ech_config,
                query_server_name,
                fragment: tls_fragment,
                record_fragment,
                fragment_fallback_delay,
                mut alpn,
                fingerprint,
            } => {
                let name = server_name
                    .or(query_server_name)
                    .unwrap_or_else(|| server.host());
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
                if tls_fragment == Some(true)
                    && fragment_input.as_ref().is_none_or(|f| f.packets.is_empty())
                {
                    let delay_ms = i32::try_from(fragment_fallback_delay.unwrap_or(15))
                        .map_err(|_| invalid())?;
                    let entry = fragment_input.get_or_insert_with(Default::default);
                    entry.packets = "tlshello".into();
                    entry.length = Some(crate::profile::RangeOrExactInput::Range([100, 200]));
                    entry.delay = Some(crate::profile::RangeOrExactInput::Exact(delay_ms));
                }
                let cert_pins = decode_sha256_pins(&pinned_peer_cert_sha256)?;
                let spki_pins = decode_sha256_pins(&certificate_public_key_sha256)?;
                let ech_bytes = ech_config
                    .as_deref()
                    .map(decode_ech_config_bytes)
                    .transpose()?;
                let custom_ca_der =
                    load_custom_ca_der(ca_pem.as_deref(), certificate_path.as_deref())?;
                let needs_custom_config = !custom_ca_der.is_empty()
                    || use_system_ca == Some(false)
                    || !spki_pins.is_empty()
                    || ech_bytes.is_some()
                    || record_fragment == Some(true);
                if needs_custom_config {
                    if !custom_ca_der.is_empty()
                        && fingerprint.as_deref().is_some_and(|s| s != "unsafe")
                    {
                        return Err(Error::Config(
                            "自定义 CA 当前不能与 TLS 指纹整形一起使用".into(),
                        ));
                    }
                    let effective_alpn = if matches!(transport, Transport::Grpc { .. }) {
                        vec!["h2".to_owned()]
                    } else if matches!(
                        transport,
                        Transport::Ws { .. } | Transport::Httpupgrade { .. }
                    ) {
                        vec!["http/1.1".to_owned()]
                    } else if matches!(transport, Transport::Xhttp { .. }) && alpn.is_empty() {
                        vec!["h2".to_owned()]
                    } else {
                        alpn.clone()
                    };
                    let tls13_only = raw && custom_ca_der.is_empty() && fingerprint.is_none();
                    let custom_config = build_custom_tls_client_config(&CustomTlsClientOptions {
                        allow_insecure,
                        use_system_ca: use_system_ca.unwrap_or(true),
                        custom_ca_der,
                        pinned_peer_cert_sha256: cert_pins,
                        pinned_public_key_sha256: spki_pins,
                        verify_peer_cert_by_name,
                        ech_config_list: ech_bytes,
                        record_fragment: record_fragment == Some(true),
                        alpn: effective_alpn,
                        fingerprint: fingerprint.clone(),
                        tls13_only,
                    })
                    .map_err(|_| invalid())?;
                    dialer = TransportDialer::with_tls_connector(
                        TlsConnector::with_pinned_client_config(Arc::new(custom_config)),
                    )
                    .with_reality_engine(Arc::new(RealityRuntimeEngine::new(Arc::new(
                        RustlsRealityTlsSessionProvider::new(),
                    ))));
                    let config = TlsClientConfig {
                        server_name: name,
                        allow_insecure: false,
                        pinned_peer_cert_sha256: Vec::new(),
                        verify_peer_cert_by_name: Vec::new(),
                        alpn,
                        fingerprint,
                    };
                    dialer
                        .tls_connector()
                        .client_config_for(&config)
                        .map_err(|_| invalid())?;
                    ConnectorConfig::Tls(config)
                } else {
                    let config = TlsClientConfig {
                        server_name: name,
                        allow_insecure,
                        pinned_peer_cert_sha256: cert_pins,
                        verify_peer_cert_by_name,
                        alpn,
                        fingerprint,
                    };
                    dialer
                        .tls_connector()
                        .client_config_for(&config)
                        .map_err(|_| invalid())?;
                    ConnectorConfig::Tls(config)
                }
            }
        };
        if !dialer_opts.is_default() {
            let opts = dialer_opts.clone();
            let server_dest = server.clone();
            dialer = dialer.with_resolved_tcp_connector(Arc::new(
                xray_transport::FnResolvedTcpConnector(
                    move |target: Target, candidates: Vec<SocketAddr>| {
                        let opts = opts.clone();
                        let server_dest = server_dest.clone();
                        async move {
                            let dest = if let Some(addr) = candidates.first()
                                && opts.detour.is_none()
                            {
                                Destination::new(&addr.ip().to_string(), addr.port())
                                    .unwrap_or(server_dest)
                            } else {
                                match &target.addr {
                                    TargetAddr::Ip(ip) => {
                                        Destination::new(&ip.to_string(), target.port)
                                            .unwrap_or(server_dest)
                                    }
                                    TargetAddr::Domain(d) => {
                                        Destination::new(d, target.port).unwrap_or(server_dest)
                                    }
                                }
                            };
                            let stream =
                                kerlico_net::TcpConnector::connect_raw_with_dialer(&dest, &opts)
                                    .await
                                    .map_err(|e| {
                                        xray_transport::TransportError::ChainedOutbound(
                                            e.to_string(),
                                        )
                                    })?;
                            Ok(Box::new(DialerTransportStream(stream)) as BoxedTransportStream)
                        }
                    },
                ),
            ));
        }
        if let Some(frag) = &fragment_input
            && !frag.packets.is_empty()
        {
            match frag.packets.as_str() {
                "tlshello" | "1-1" | "1-2" | "1-3" => {}
                other => {
                    if let Some((a, b)) = other.split_once('-') {
                        let start: u64 = a.parse().map_err(|_| invalid())?;
                        let end: u64 = b.parse().map_err(|_| invalid())?;
                        if start == 0 || start > end {
                            return Err(invalid());
                        }
                    } else {
                        return Err(invalid());
                    }
                }
            }
            let (length_min, length_max) = frag
                .length
                .map(crate::profile::RangeOrExactInput::to_u64_pair)
                .transpose()?
                .unwrap_or((100, 200));
            let (delay_min_ms, delay_max_ms) = frag
                .delay
                .map(crate::profile::RangeOrExactInput::to_u64_pair)
                .transpose()?
                .unwrap_or((10, 20));
            let (max_split_min, max_split_max) = frag
                .max_split
                .map(crate::profile::RangeOrExactInput::to_u64_pair)
                .transpose()?
                .unwrap_or((0, 0));
            let tcp_frag = xray_transport::TcpFragmentConfig::new(
                std::iter::once(
                    u32::try_from(length_min).map_err(|_| invalid())?
                        ..=u32::try_from(length_max).map_err(|_| invalid())?,
                )
                .collect(),
                std::iter::once(
                    u32::try_from(delay_min_ms).map_err(|_| invalid())?
                        ..=u32::try_from(delay_max_ms).map_err(|_| invalid())?,
                )
                .collect(),
                u32::try_from(max_split_min).map_err(|_| invalid())?
                    ..=u32::try_from(max_split_max).map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?;
            dialer = dialer.with_tcp_fragment(Arc::new(tcp_frag));
        }
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
            Transport::Tcp => LayerPlan::Raw,
            Transport::Xdrive { .. } => return Err(invalid()),
            Transport::Ws {
                path,
                host,
                headers,
                early_data_bytes,
                heartbeat_period_secs,
            } => {
                validate_http(&path, host.as_deref(), &headers)?;
                LayerPlan::WebSocket(WebSocketConfig {
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
                LayerPlan::HttpUpgrade(HttpUpgradeConfig {
                    path,
                    host: host.unwrap_or(authority),
                    headers,
                })
            }
            Transport::Grpc {
                service_name,
                authority: host,
                multi_mode,
                user_agent,
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
                let user_agent =
                    GrpcConfig::resolve_user_agent(user_agent.as_deref()).map_err(|_| invalid())?;
                LayerPlan::Grpc(GrpcConfig {
                    service_name,
                    authority,
                    multi_mode,
                    user_agent,
                    idle_timeout_secs,
                    health_check_timeout_secs,
                    permit_without_stream,
                    initial_windows_size: if initial_window_size == 0 {
                        4 * 1024 * 1024
                    } else {
                        initial_window_size
                    },
                })
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
                    if down.xhttp.xmux.is_none() {
                        down.xhttp.xmux = down.xmux.take();
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
                        fragment_input.clone(),
                    )?));
                }
                xhttp(settings, &connector, &authority, fragment_input.as_ref())?
            }
        };
        Ok(Self {
            server,
            connector,
            transport: layer,
            dialer,
            dialer_opts,
            download,
            storage: None,
            storage_resources: std::sync::Mutex::new(std::collections::HashMap::new()),
            quic_tls,
            family,
            resources: std::sync::Mutex::new(std::collections::HashMap::new()),
            owner: None,
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

    pub async fn shutdown(&self) -> Result<()> {
        let owner = self.owner.as_ref().ok_or_else(invalid)?;
        owner.close_admission();
        self.resources.lock().map_err(|_| invalid())?.clear();
        self.storage_resources
            .lock()
            .map_err(|_| invalid())?
            .clear();
        if let Some(down) = &self.download {
            Box::pin(down.shutdown()).await?;
        }
        owner.shutdown().await;
        if owner.failed_tasks() > 0 {
            return Err(Error::Protocol("载体后台任务异常退出"));
        }
        Ok(())
    }
    fn resource(&self, context: &kerlico_core::ConnectContext) -> Result<TransportLayer> {
        let mut resources = self.resources.lock().map_err(|_| invalid())?;
        if let Some(layer) = resources.get(context.resource_key()) {
            return Ok(layer.clone());
        }
        let layer = self.transport.start()?;
        resources.insert(context.resource_key().clone(), layer.clone());
        Ok(layer)
    }
    pub async fn open(
        &self,
        context: &kerlico_core::ConnectContext,
        host: &kerlico_core::ServiceContext,
    ) -> Result<BoxedTransportStream> {
        let owner = self.owner.as_ref().ok_or_else(invalid)?;
        if owner.is_closed() {
            return Err(Error::Cancelled);
        }
        if owner.is_closed() {
            return Err(Error::Cancelled);
        }
        let stream = owner.scope(self.open_scoped(context, host)).await?;
        Ok(owner.wrap(stream))
    }
    async fn open_scoped(
        &self,
        context: &kerlico_core::ConnectContext,
        host: &kerlico_core::ServiceContext,
    ) -> Result<BoxedTransportStream> {
        let transport = self.resource(context)?;
        if let Some(plan) = &self.storage {
            let storage = {
                let mut resources = self.storage_resources.lock().map_err(|_| invalid())?;
                if let Some(storage) = resources.get(context.resource_key()) {
                    storage.clone()
                } else {
                    let storage = plan.start()?;
                    resources.insert(context.resource_key().clone(), storage.clone());
                    storage
                }
            };
            return storage.open(host).await;
        }
        let server = target(&self.server, false);
        let candidates: Vec<SocketAddr> = match tokio::net::lookup_host((
            self.server.host().as_str(),
            self.server.port(),
        ))
        .await
        {
            Ok(addrs) => addrs
                .filter(|address| self.family.accepts(address.ip()))
                .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
                .collect(),
            Err(_) if self.dialer_opts.detour.is_some() => {
                vec![SocketAddr::from(([127, 0, 0, 1], self.server.port()))]
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(down) = &self.download {
            let down_candidates: Vec<_> =
                tokio::net::lookup_host((down.server.host().as_str(), down.server.port()))
                    .await?
                    .filter(|address| down.family.accepts(address.ip()))
                    .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
                    .collect();
            let down_transport = down.resource(context)?;
            let (TransportLayer::Xhttp(up), TransportLayer::Xhttp(download)) =
                (&transport, &down_transport)
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
                .connect_stream(&self.connector, &transport, &server, &candidates, None)
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
    fragment_input: Option<&crate::profile::TcpFragmentInput>,
) -> Result<LayerPlan> {
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
        x_padding_obfs_mode: settings.x_padding_obfs_mode,
        mode: match settings.mode {
            XhttpMode::Auto => XhttpModeSelection::Auto,
            XhttpMode::PacketUp => XhttpModeSelection::PacketUp,
            XhttpMode::StreamUp => XhttpModeSelection::StreamUp,
            XhttpMode::StreamOne => XhttpModeSelection::StreamOne,
        },
        ..Default::default()
    };
    if let Some(key) = settings.x_padding_key {
        input.x_padding_key = key;
    }
    if let Some(header) = settings.x_padding_header {
        input.x_padding_header = header;
    }
    if let Some(placement) = settings.x_padding_placement {
        input.x_padding_placement = match placement.as_str() {
            "cookie" => XhttpPaddingPlacement::Cookie,
            "header" => XhttpPaddingPlacement::Header,
            "query" => XhttpPaddingPlacement::Query,
            "query-in-header" | "query_in_header" => XhttpPaddingPlacement::QueryInHeader,
            _ => return Err(invalid()),
        };
    }
    if let Some(method) = settings.x_padding_method {
        input.x_padding_method = match method.as_str() {
            "repeat-x" | "repeat_x" => XhttpPaddingMethod::RepeatX,
            "tokenish" => XhttpPaddingMethod::Tokenish,
            _ => return Err(invalid()),
        };
    }
    if let Some(method) = settings.uplink_http_method {
        input.uplink_http_method = method;
    }
    if let Some(placement) = settings.session_placement {
        input.session_placement = parse_metadata_placement(&placement)?;
    }
    if let Some(key) = settings.session_key {
        input.session_key = key;
    }
    if let Some(placement) = settings.seq_placement {
        input.seq_placement = parse_metadata_placement(&placement)?;
    }
    if let Some(key) = settings.seq_key {
        input.seq_key = key;
    }
    if let Some(placement) = settings.uplink_data_placement {
        input.uplink_data_placement = match placement.as_str() {
            "auto" => XhttpUplinkDataPlacement::Auto,
            "body" => XhttpUplinkDataPlacement::Body,
            "cookie" => XhttpUplinkDataPlacement::Cookie,
            "header" => XhttpUplinkDataPlacement::Header,
            _ => return Err(invalid()),
        };
    }
    if let Some(key) = settings.uplink_data_key {
        input.uplink_data_key = key;
    }
    fn range(n: u32) -> Result<XhttpRange> {
        Ok(XhttpRange::exact(i32::try_from(n).map_err(|_| invalid())?))
    }
    if let Some(n) = settings.uplink_chunk_size {
        input.uplink_chunk_size = range(n)?;
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
    if let Some([a, b]) = settings.sc_stream_up_server_secs {
        input.sc_stream_up_server_secs = XhttpRange {
            from: i32::try_from(a).map_err(|_| invalid())?,
            to: i32::try_from(b).map_err(|_| invalid())?,
        };
    }
    if let Some([a, b]) = settings.padding_bytes {
        input.x_padding_bytes = XhttpRange {
            from: i32::try_from(a).map_err(|_| invalid())?,
            to: i32::try_from(b).map_err(|_| invalid())?,
        };
    }
    input.h2_stream_receive_window = Some(16 * 1024 * 1024);
    let mut xmux = XhttpXmuxPolicy::default();
    if let Some(xmux_cfg) = settings.xmux {
        if let Some(v) = xmux_cfg.max_concurrency {
            xmux.max_concurrency = v.to_xhttp_range();
            if xmux_cfg.max_connections.is_none() {
                xmux.max_connections = XhttpRange::exact(0);
            }
        }
        if let Some(v) = xmux_cfg.max_connections {
            xmux.max_connections = v.to_xhttp_range();
        }
        if let Some(v) = xmux_cfg.c_max_reuse_times {
            xmux.c_max_reuse_times = v.to_xhttp_range();
        }
        if let Some(v) = xmux_cfg.h_max_request_times {
            xmux.h_max_request_times = v.to_xhttp_range();
        }
        if let Some(v) = xmux_cfg.h_max_reusable_secs {
            xmux.h_max_reusable_secs = v.to_xhttp_range();
        }
        if let Some(v) = xmux_cfg.h_keep_alive_period {
            xmux.h_keep_alive_period_secs = v;
        }
    } else {
        xmux.max_concurrency = XhttpRange::exact(1);
        xmux.max_connections = XhttpRange::exact(0);
    }
    let mut h3_quic = H3QuicConfig::default();
    if let Some(frag) = fragment_input
        && let Some(bps) = frag.brutal_up.or(frag.brutal_down)
        && bps > 0
    {
        h3_quic.congestion = H3Congestion::ForceBrutal {
            bytes_per_second: bps,
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
    Ok(LayerPlan::Xhttp {
        config: Box::new(config),
        endpoint,
        version,
        xmux,
        h3_quic,
    })
}

fn parse_metadata_placement(s: &str) -> Result<XhttpMetadataPlacement> {
    match s {
        "path" => Ok(XhttpMetadataPlacement::Path),
        "cookie" => Ok(XhttpMetadataPlacement::Cookie),
        "header" => Ok(XhttpMetadataPlacement::Header),
        "query" => Ok(XhttpMetadataPlacement::Query),
        _ => Err(invalid()),
    }
}

fn decode_sha256_pins(values: &[String]) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::with_capacity(values.len());
    for raw in values {
        let trimmed = raw.trim().replace(':', "");
        let bytes = if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            trimmed
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| {
                    let s = std::str::from_utf8(c).map_err(|_| invalid())?;
                    u8::from_str_radix(s, 16).map_err(|_| invalid())
                })
                .collect::<Result<Vec<u8>>>()?
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(&trimmed)
                .or_else(|_| URL_SAFE_NO_PAD.decode(&trimmed))
                .map_err(|_| invalid())?
        };
        let pin: [u8; 32] = bytes.try_into().map_err(|_| invalid())?;
        out.push(pin);
    }
    Ok(out)
}

fn decode_ech_config_bytes(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim();
    if trimmed.contains("-----BEGIN") {
        let body: String = trimmed
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        return base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .map_err(|_| invalid());
    }
    if trimmed.len().is_multiple_of(2) && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return trimmed
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                let s = std::str::from_utf8(c).map_err(|_| invalid())?;
                u8::from_str_radix(s, 16).map_err(|_| invalid())
            })
            .collect();
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| invalid())
}

fn load_custom_ca_der(
    ca_pem: Option<&str>,
    certificate_path: Option<&str>,
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    if let Some(pem) = ca_pem {
        let certs =
            rustls_pemfile::certs(&mut Cursor::new(pem)).collect::<std::io::Result<Vec<_>>>()?;
        if certs.is_empty() {
            return Err(invalid());
        }
        for cert in certs {
            out.push(cert.as_ref().to_vec());
        }
    }
    if let Some(path) = certificate_path {
        let pem = std::fs::read_to_string(path).map_err(|_| invalid())?;
        let certs =
            rustls_pemfile::certs(&mut Cursor::new(pem)).collect::<std::io::Result<Vec<_>>>()?;
        if certs.is_empty() {
            return Err(invalid());
        }
        for cert in certs {
            out.push(cert.as_ref().to_vec());
        }
    }
    Ok(out)
}

struct DialerTransportStream(kerlico_core::BoxStream);
impl tokio::io::AsyncRead for DialerTransportStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for DialerTransportStream {
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
impl xray_transport::TransportStream for DialerTransportStream {
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

fn quic_config(
    ca: Option<&str>,
    cert_path: Option<&str>,
    use_system_ca: bool,
    allow_insecure: bool,
    cert_pins: &[String],
    spki_pins: &[String],
    verify_names: &[String],
) -> Result<Arc<rustls::ClientConfig>> {
    let custom_ca_der = load_custom_ca_der(ca, cert_path)?;
    let pinned_peer_cert_sha256 = decode_sha256_pins(cert_pins)?;
    let pinned_public_key_sha256 = decode_sha256_pins(spki_pins)?;
    let config = build_custom_tls_client_config(&CustomTlsClientOptions {
        allow_insecure,
        use_system_ca,
        custom_ca_der,
        pinned_peer_cert_sha256,
        pinned_public_key_sha256,
        verify_peer_cert_by_name: verify_names.to_vec(),
        ech_config_list: None,
        record_fragment: false,
        alpn: vec!["h3".to_owned()],
        fingerprint: None,
        tls13_only: true,
    })
    .map_err(|_| invalid())?;
    Ok(Arc::new(config))
}
