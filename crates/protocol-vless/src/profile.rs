//! 组合配置在协议边界校验，核心调度不感知具体传输或安全类型。

use crate::{UserId, carrier::Carrier, payload};
use hmac::{Hmac, Mac};
use kerlico_config::{OutboundPlan, TargetSpec};
use kerlico_core::{
    BoxFuture, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel, Destination,
    Error, Outbound, Result,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use xray_vless_encryption::{Client, Encryption};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Options {
    pub server: TargetSpec,
    #[serde(default)]
    pub server_family: Family,
    pub uuid: String,
    #[serde(default)]
    pub transport: TransportInput,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub splice: Option<bool>,
    #[serde(default = "none")]
    pub encryption: String,
    #[serde(default)]
    pub security: Security,
    #[serde(default)]
    pub packet_encoding: PacketEncoding,
    #[serde(default)]
    pub mux: Option<MuxOptions>,
    #[serde(default, alias = "mux_option")]
    pub multiplex: Option<kerlico_net::sing_mux::SingMuxOutboundConfig>,
    #[serde(default, alias = "finalmask")]
    pub fragment: Option<TcpFragmentInput>,
    #[serde(default)]
    pub brutal_down: Option<u64>,
    #[serde(default)]
    pub brutal_up: Option<u64>,
    #[serde(default)]
    pub udp_hop: Option<UdpHopInput>,
    #[serde(default)]
    pub reverse: Option<crate::inbound::ReverseConfig>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct TcpFragmentInput {
    #[serde(default)]
    pub packets: String,
    #[serde(default, alias = "lengths")]
    pub length: Option<RangeOrExactInput>,
    #[serde(default, alias = "delays")]
    pub delay: Option<RangeOrExactInput>,
    #[serde(default)]
    pub max_split: Option<RangeOrExactInput>,
    #[serde(default)]
    pub brutal_down: Option<u64>,
    #[serde(default)]
    pub brutal_up: Option<u64>,
    #[serde(default)]
    pub udp_hop: Option<UdpHopInput>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub(crate) struct UdpHopInput {
    #[serde(default)]
    pub remote_ports: Vec<u16>,
    #[serde(default)]
    pub remote_ips: Vec<std::net::IpAddr>,
    #[serde(default)]
    pub interval: Option<u64>,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(untagged)]
pub(crate) enum RangeOrExactInput {
    Exact(i32),
    Range([i32; 2]),
}

impl RangeOrExactInput {
    pub fn to_xhttp_range(self) -> xray_transport::stream::XhttpRange {
        match self {
            Self::Exact(v) => xray_transport::stream::XhttpRange::exact(v),
            Self::Range([a, b]) => xray_transport::stream::XhttpRange { from: a, to: b },
        }
    }
    pub fn to_u64_pair(self) -> Result<(u64, u64)> {
        match self {
            Self::Exact(v) => {
                let u = u64::try_from(v).map_err(|_| Error::Config("分片范围不合法".into()))?;
                Ok((u, u))
            }
            Self::Range([a, b]) => {
                let ua = u64::try_from(a).map_err(|_| Error::Config("分片范围不合法".into()))?;
                let ub = u64::try_from(b).map_err(|_| Error::Config("分片范围不合法".into()))?;
                Ok((ua, ub))
            }
        }
    }
}

#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct XmuxSettings {
    #[serde(default)]
    pub max_concurrency: Option<RangeOrExactInput>,
    #[serde(default)]
    pub max_connections: Option<RangeOrExactInput>,
    #[serde(default)]
    pub c_max_reuse_times: Option<RangeOrExactInput>,
    #[serde(default)]
    pub h_max_request_times: Option<RangeOrExactInput>,
    #[serde(default)]
    pub h_max_reusable_secs: Option<RangeOrExactInput>,
    #[serde(default)]
    pub h_keep_alive_period: Option<i64>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MuxOptions {
    enabled: bool,
    tcp: bool,
    udp: bool,
    concurrency: usize,
    max_connections: usize,
}
impl Default for MuxOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            tcp: true,
            udp: true,
            concurrency: 8,
            max_connections: 4,
        }
    }
}

fn none() -> String {
    "none".into()
}
fn slash() -> String {
    "/".into()
}
fn chrome() -> String {
    "chrome".into()
}

#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PacketEncoding {
    #[default]
    Udp,
    Xudp,
    Packetaddr,
}

#[derive(Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Family {
    #[default]
    Auto,
    Ipv4,
    Ipv6,
}
impl Family {
    pub fn accepts(self, ip: std::net::IpAddr) -> bool {
        match self {
            Self::Auto => true,
            Self::Ipv4 => ip.to_canonical().is_ipv4(),
            Self::Ipv6 => ip.to_canonical().is_ipv6(),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum TransportInput {
    Name(String),
    Detailed(Box<Transport>),
}
impl Default for TransportInput {
    fn default() -> Self {
        Self::Name("tcp".into())
    }
}
impl TransportInput {
    pub fn normalize(self) -> Result<Transport> {
        match self {
            Self::Name(name) if matches!(name.as_str(), "tcp" | "raw") => Ok(Transport::Tcp),
            Self::Name(_) => Err(Error::Config(
                "非 TCP 传输必须使用带 type 的选项对象".into(),
            )),
            Self::Detailed(transport) => Ok(*transport),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Transport {
    #[serde(alias = "raw")]
    Tcp,
    Ws {
        #[serde(default = "slash")]
        path: String,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        headers: Vec<(String, String)>,
        #[serde(default)]
        early_data_bytes: u32,
        #[serde(default)]
        heartbeat_period_secs: u32,
    },
    Httpupgrade {
        #[serde(default = "slash")]
        path: String,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    Grpc {
        #[serde(default)]
        service_name: String,
        #[serde(default)]
        authority: Option<String>,
        #[serde(default)]
        multi_mode: bool,
        #[serde(default, alias = "grpc-user-agent", alias = "grpc_user_agent")]
        user_agent: Option<String>,
        #[serde(default)]
        idle_timeout_secs: u32,
        #[serde(default)]
        health_check_timeout_secs: u32,
        #[serde(default)]
        permit_without_stream: bool,
        #[serde(default)]
        initial_window_size: u32,
    },
    Xhttp {
        settings: XhttpSettings,
    },
    Xdrive {
        settings: crate::xdrive::Settings,
    },
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct XhttpSettings {
    #[serde(default = "slash")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: XhttpMode,
    #[serde(default)]
    pub http_version: HttpVersion,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub no_grpc_header: bool,
    #[serde(default, alias = "sc_max_each_post_bytes")]
    pub max_post_bytes: Option<u32>,
    #[serde(default, alias = "sc_min_posts_interval_ms")]
    pub min_post_interval_ms: Option<u32>,
    #[serde(default, alias = "sc_max_buffered_posts")]
    pub max_buffered_posts: Option<u32>,
    #[serde(default)]
    pub sc_stream_up_server_secs: Option<[u32; 2]>,
    #[serde(default, alias = "x_padding_bytes")]
    pub padding_bytes: Option<[u32; 2]>,
    #[serde(default)]
    pub x_padding_obfs_mode: bool,
    #[serde(default)]
    pub x_padding_key: Option<String>,
    #[serde(default)]
    pub x_padding_header: Option<String>,
    #[serde(default)]
    pub x_padding_placement: Option<String>,
    #[serde(default)]
    pub x_padding_method: Option<String>,
    #[serde(default)]
    pub uplink_http_method: Option<String>,
    #[serde(default)]
    pub session_placement: Option<String>,
    #[serde(default)]
    pub session_key: Option<String>,
    #[serde(default)]
    pub seq_placement: Option<String>,
    #[serde(default)]
    pub seq_key: Option<String>,
    #[serde(default)]
    pub uplink_data_placement: Option<String>,
    #[serde(default)]
    pub uplink_data_key: Option<String>,
    #[serde(default)]
    pub uplink_chunk_size: Option<u32>,
    #[serde(default, alias = "reuse_settings")]
    pub xmux: Option<XmuxSettings>,
    #[serde(default)]
    pub download: Option<Box<Download>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Download {
    pub server: TargetSpec,
    #[serde(default)]
    pub server_family: Family,
    #[serde(default)]
    pub security: Security,
    pub xhttp: XhttpSettings,
    #[serde(default, alias = "reuse_settings")]
    pub xmux: Option<XmuxSettings>,
}

#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum XhttpMode {
    #[default]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum HttpVersion {
    #[default]
    Auto,
    H1,
    H2,
    H3,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Security {
    Tls {
        #[serde(default)]
        server_name: Option<String>,
        #[serde(default)]
        ca_pem: Option<String>,
        #[serde(default, alias = "ca_file")]
        certificate_path: Option<String>,
        #[serde(default)]
        use_system_ca: Option<bool>,
        #[serde(default, alias = "insecure", alias = "skip_cert_verify")]
        allow_insecure: bool,
        #[serde(default, alias = "certificate_sha256", alias = "cert_sha256")]
        pinned_peer_cert_sha256: Vec<String>,
        #[serde(default)]
        certificate_public_key_sha256: Vec<String>,
        #[serde(default, alias = "name_cert_verify")]
        verify_peer_cert_by_name: Vec<String>,
        #[serde(default, alias = "ech_config_list")]
        ech_config: Option<String>,
        #[serde(default)]
        query_server_name: Option<String>,
        #[serde(default)]
        fragment: Option<bool>,
        #[serde(default)]
        record_fragment: Option<bool>,
        #[serde(default)]
        fragment_fallback_delay: Option<u64>,
        #[serde(default)]
        alpn: Vec<String>,
        #[serde(default)]
        fingerprint: Option<String>,
    },
    Reality {
        server_name: String,
        public_key: String,
        #[serde(default)]
        short_id: String,
        #[serde(default = "chrome")]
        fingerprint: String,
        #[serde(default)]
        mldsa65_verify: Option<String>,
    },
    None,
}
impl Default for Security {
    fn default() -> Self {
        Self::Tls {
            server_name: None,
            ca_pem: None,
            certificate_path: None,
            use_system_ca: None,
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            certificate_public_key_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            ech_config: None,
            query_server_name: None,
            fragment: None,
            record_fragment: None,
            fragment_fallback_delay: None,
            alpn: Vec::new(),
            fingerprint: None,
        }
    }
}

struct ProfileOutbound {
    carrier: Carrier,
    user: UserId,
    vision: bool,
    udp443: bool,
    encoding: PacketEncoding,
    encryption: Option<xray_vless_encryption::ClientConfig>,
    mux: Option<(usize, usize)>,
    sing_mux: Option<kerlico_net::sing_mux::SingMuxClient>,
    resources: Mutex<HashMap<kerlico_core::ResourceKey, Arc<Resources>>>,
    host: kerlico_core::ServiceContext,
    mux_tcp: bool,
    mux_udp: bool,
    reverse_tag: Option<String>,
}

pub(crate) fn compile(value: &Value) -> Result<OutboundPlan> {
    let options: Options = serde_json::from_value(value.clone())
        .map_err(|_| Error::Config("VLESS 配置字段不合法".into()))?;
    let reverse_tag = options.reverse.map(|r| r.tag);
    if reverse_tag.as_deref().is_some_and(|t| t.trim().is_empty()) {
        return Err(Error::Config("VLESS reverse tag 不能为空".into()));
    }
    let user = UserId::parse(&options.uuid)?;
    let _splice = options.splice.unwrap_or(false)
        || matches!(
            options.flow.as_str(),
            "xtls-rprx-vision-splice" | "xtls-rprx-vision-udp443-splice"
        );
    let vision = match options.flow.as_str() {
        "" => false,
        "xtls-rprx-vision"
        | "xtls-rprx-vision-udp443"
        | "xtls-rprx-vision-splice"
        | "xtls-rprx-vision-udp443-splice" => true,
        _ => return Err(Error::Unsupported("VLESS flow")),
    };
    let encryption: Encryption = options
        .encryption
        .parse()
        .map_err(|_| Error::Config("VLESS Encryption 参数不合法".into()))?;
    let transport = options.transport.normalize()?;
    let storage_carrier = matches!(transport, Transport::Xdrive { .. });
    if storage_carrier && (vision || encryption.is_none()) {
        return Err(Error::Config(
            "XDRIVE 要求 Encryption 且不能使用 Vision".into(),
        ));
    }
    if vision
        && encryption.is_none()
        && (!matches!(transport, Transport::Tcp) || matches!(options.security, Security::None))
    {
        return Err(Error::Config(
            "Vision 要求直接 TLS/REALITY，或先启用 VLESS Encryption".into(),
        ));
    }
    if vision && options.packet_encoding == PacketEncoding::Packetaddr {
        return Err(Error::Config("Vision 的 UDP 必须使用 XUDP".into()));
    }
    let mut mux = None;
    let mut mux_tcp = false;
    let mut mux_udp = false;
    if let Some(settings) = options.mux
        && settings.enabled
    {
        if !(1..=256).contains(&settings.concurrency)
            || !(1..=32).contains(&settings.max_connections)
            || (!settings.tcp && !settings.udp)
        {
            return Err(Error::Config("Mux 并发或连接池参数不合法".into()));
        }
        if settings.tcp && matches!(transport, Transport::Xhttp { .. }) {
            return Err(Error::Config(
                "XHTTP 的 Mux 仅支持 UDP；TCP 使用载体自己的 XMUX".into(),
            ));
        }
        if vision && settings.tcp {
            return Err(Error::Config(
                "Vision 不能复用 TCP 业务；可仅启用 Mux UDP".into(),
            ));
        }
        if settings.udp && options.packet_encoding == PacketEncoding::Packetaddr {
            return Err(Error::Config("packetaddr 与 Mux UDP 必须分开配置".into()));
        }
        mux = Some((settings.concurrency, settings.max_connections));
        mux_tcp = settings.tcp;
        mux_udp = settings.udp;
    }
    if storage_carrier && (!mux_tcp || !mux_udp) {
        return Err(Error::Config("XDRIVE 必须显式启用 TCP/UDP Mux".into()));
    }
    let sing_mux = options.multiplex.and_then(|cfg| {
        if cfg.enabled {
            Some(kerlico_net::sing_mux::SingMuxClient::new(cfg))
        } else {
            None
        }
    });
    let mut fragment = options.fragment;
    if options.brutal_down.is_some() || options.brutal_up.is_some() || options.udp_hop.is_some() {
        let entry = fragment.get_or_insert_with(TcpFragmentInput::default);
        if options.brutal_down.is_some() {
            entry.brutal_down = options.brutal_down;
        }
        if options.brutal_up.is_some() {
            entry.brutal_up = options.brutal_up;
        }
        if options.udp_hop.is_some() {
            entry.udp_hop = options.udp_hop;
        }
    }
    let carrier = Carrier::build(
        options.server.destination()?,
        options.security,
        transport,
        !encryption.is_none(),
        options.server_family,
        fragment,
    )?;
    let udp443 = matches!(
        options.flow.as_str(),
        "xtls-rprx-vision-udp443" | "xtls-rprx-vision-udp443-splice"
    );
    let encoding = if vision {
        PacketEncoding::Xudp
    } else {
        options.packet_encoding
    };
    let encryption = encryption.client().cloned();
    Ok(OutboundPlan::new(
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: true,
        },
        true,
        kerlico_core::TargetPolicy::Remote,
        move |host| {
            Box::pin(async move {
                Ok(Arc::new(ProfileOutbound {
                    carrier: carrier.start(&host)?,
                    user,
                    vision,
                    udp443,
                    encoding,
                    encryption,
                    mux,
                    sing_mux,
                    mux_tcp,
                    mux_udp,
                    reverse_tag,
                    resources: Mutex::new(HashMap::new()),
                    host,
                }) as Arc<dyn Outbound>)
            })
        },
    ))
}

struct Resources {
    encryption: Option<Client>,
    mux: Option<crate::mux::Pool>,
    xudp_key: [u8; 32],
}
/// 同一本机来源到同一目标的 Global ID 跨载体不变，服务端才能接回原 UDP 会话。
/// Xray 只按来源取值（common/xudp/xudp.go GetGlobalID）；这里每个目标一条通道，
/// 同来源的第二个目标若共用 ID，会把第一条通道从服务端摘下，因此目标也参与计算。
fn xudp_global_id(
    key: &[u8; 32],
    source: Option<std::net::SocketAddr>,
    target: &Destination,
) -> [u8; 8] {
    let Some(source) = source else {
        return rand::random();
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC 接受任意密钥长度");
    mac.update(source.to_string().as_bytes());
    mac.update(&[0]);
    mac.update(target.to_string().as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut id = [0; 8];
    id.copy_from_slice(&digest[..8]);
    id
}
impl ProfileOutbound {
    fn resources(&self, context: &ConnectContext) -> Result<Arc<Resources>> {
        let mut resources = self.resources.lock().map_err(|_| Error::Rejected)?;
        Ok(resources
            .entry(context.resource_key().clone())
            .or_insert_with(|| {
                Arc::new(Resources {
                    encryption: self.encryption.clone().map(Client::new),
                    mux: self.mux.map(|(concurrency, maximum)| {
                        crate::mux::Pool::new(concurrency, maximum, self.host.clone())
                    }),
                    xudp_key: rand::random(),
                })
            })
            .clone())
    }
}

impl Outbound for ProfileOutbound {
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let resources =
                std::mem::take(&mut *self.resources.lock().map_err(|_| Error::Rejected)?);
            for resource in resources.into_values() {
                if let Some(mux) = &resource.mux {
                    mux.shutdown().await?;
                }
            }
            self.carrier.shutdown().await?;
            Ok(())
        })
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: true,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            let resources = self.resources(context)?;
            let target = Destination::new("v1.mux.cool", 666)?;
            let encoding = if self.encoding == PacketEncoding::Packetaddr {
                PacketEncoding::Packetaddr
            } else {
                PacketEncoding::Xudp
            };
            let global_id = xudp_global_id(&resources.xudp_key, context.udp_source(), &target);
            context
                .run(async {
                    if let Some(sing_mux) = &self.sing_mux
                        && !sing_mux.only_tcp()
                    {
                        return sing_mux
                            .associate_udp(|mux_dest| async move {
                                let carrier = self.carrier.open(context, &self.host).await?;
                                payload::open(
                                    carrier,
                                    resources.encryption.as_ref(),
                                    self.user,
                                    &mux_dest,
                                    self.vision,
                                    false,
                                    self.encoding,
                                )
                                .await
                            })
                            .await;
                    }
                    if self.mux_udp {
                        return resources
                            .mux
                            .as_ref()
                            .ok_or(Error::Protocol("Mux 配置不可用"))?
                            .associate_udp(
                                &target,
                                (self.encoding == PacketEncoding::Xudp).then_some(global_id),
                                self.vision,
                                self.udp443,
                                async {
                                    let carrier = self.carrier.open(context, &self.host).await?;
                                    payload::open(
                                        carrier,
                                        resources.encryption.as_ref(),
                                        self.user,
                                        &target,
                                        self.vision,
                                        true,
                                        PacketEncoding::Xudp,
                                    )
                                    .await
                                },
                            )
                            .await;
                    }
                    let carrier = self.carrier.open(context, &self.host).await?;
                    let stream = payload::open(
                        carrier,
                        resources.encryption.as_ref(),
                        self.user,
                        &target,
                        self.vision,
                        true,
                        encoding,
                    )
                    .await?;
                    payload::association(
                        stream,
                        &target,
                        encoding,
                        global_id,
                        self.vision,
                        self.udp443,
                    )
                })
                .await
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            let resources = self.resources(context)?;
            context
                .run(async {
                    if let Some(rev_tag) = &self.reverse_tag
                        && let Some(claimed) = crate::inbound::claim_reverse_stream(rev_tag).await
                    {
                        return Ok(claimed);
                    }
                    if let Some(sing_mux) = &self.sing_mux {
                        return sing_mux
                            .connect_tcp(target, |mux_dest| async move {
                                let carrier = self.carrier.open(context, &self.host).await?;
                                payload::open(
                                    carrier,
                                    resources.encryption.as_ref(),
                                    self.user,
                                    &mux_dest,
                                    self.vision,
                                    false,
                                    self.encoding,
                                )
                                .await
                            })
                            .await
                            .map(|o| o.stream);
                    }
                    if self.mux_tcp {
                        return resources
                            .mux
                            .as_ref()
                            .ok_or(Error::Protocol("Mux 配置不可用"))?
                            .tcp(target, async {
                                let carrier = self.carrier.open(context, &self.host).await?;
                                payload::open(
                                    carrier,
                                    resources.encryption.as_ref(),
                                    self.user,
                                    target,
                                    false,
                                    true,
                                    PacketEncoding::Xudp,
                                )
                                .await
                            })
                            .await;
                    }
                    let carrier = self.carrier.open(context, &self.host).await?;
                    payload::open(
                        carrier,
                        resources.encryption.as_ref(),
                        self.user,
                        target,
                        self.vision,
                        false,
                        self.encoding,
                    )
                    .await
                })
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
            let resources = self.resources(context)?;
            if self.vision && !self.udp443 && target.port() == 443 {
                return Err(Error::Rejected);
            }
            if self.encoding == PacketEncoding::Packetaddr
                && matches!(target.address(), kerlico_core::Address::Domain(_))
            {
                return Err(Error::Unsupported("packetaddr 域名目标"));
            }
            let global_id = xudp_global_id(&resources.xudp_key, context.udp_source(), target);
            context
                .run(async {
                    if let Some(sing_mux) = &self.sing_mux
                        && !sing_mux.only_tcp()
                    {
                        return sing_mux
                            .connect_udp(target, |mux_dest| async move {
                                let carrier = self.carrier.open(context, &self.host).await?;
                                payload::open(
                                    carrier,
                                    resources.encryption.as_ref(),
                                    self.user,
                                    &mux_dest,
                                    self.vision,
                                    false,
                                    self.encoding,
                                )
                                .await
                            })
                            .await;
                    }
                    if self.mux_udp {
                        return resources
                            .mux
                            .as_ref()
                            .ok_or(Error::Protocol("Mux 配置不可用"))?
                            .udp(
                                target,
                                (self.encoding == PacketEncoding::Xudp).then_some(global_id),
                                async {
                                    let carrier = self.carrier.open(context, &self.host).await?;
                                    payload::open(
                                        carrier,
                                        resources.encryption.as_ref(),
                                        self.user,
                                        target,
                                        self.vision,
                                        true,
                                        PacketEncoding::Xudp,
                                    )
                                    .await
                                },
                            )
                            .await;
                    }
                    let carrier = self.carrier.open(context, &self.host).await?;
                    let stream = payload::open(
                        carrier,
                        resources.encryption.as_ref(),
                        self.user,
                        target,
                        self.vision,
                        true,
                        self.encoding,
                    )
                    .await?;
                    payload::datagrams(stream, target, self.encoding, global_id)
                })
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xudp_global_id_follows_source_and_target() {
        let key = [7; 32];
        let source: std::net::SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let other: std::net::SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let dns = Destination::new("192.0.2.1", 53).unwrap();
        let ntp = Destination::new("192.0.2.1", 123).unwrap();
        let id = xudp_global_id(&key, Some(source), &dns);
        assert_eq!(id, xudp_global_id(&key, Some(source), &dns));
        assert_ne!(id, xudp_global_id(&key, Some(other), &dns));
        assert_ne!(id, xudp_global_id(&key, Some(source), &ntp));
        assert_ne!(id, xudp_global_id(&[8; 32], Some(source), &dns));
        assert_ne!(
            xudp_global_id(&key, None, &dns),
            xudp_global_id(&key, None, &dns)
        );
    }

    #[test]
    fn vless_outbound_compiles_extended_m2_transport_tls_and_mux_options() {
        let opts = serde_json::json!({
            "server": {"host": "127.0.0.1", "port": 10443},
            "uuid": "00000000-0000-4000-8000-000000000001",
            "flow": "xtls-rprx-vision",
            "splice": true,
            "fragment": {
                "packets": "tlshello",
                "length": [50, 150],
                "delay": [5, 15],
                "max_split": [2, 8]
            },
            "security": {
                "type": "tls",
                "server_name": "example.com",
                "allow_insecure": false,
                "use_system_ca": true,
                "pinned_peer_cert_sha256": ["0101010101010101010101010101010101010101010101010101010101010101"],
                "certificate_public_key_sha256": ["0202020202020202020202020202020202020202020202020202020202020202"],
                "verify_peer_cert_by_name": ["alt.example.com"],
                "fragment": true,
                "record_fragment": true,
                "fragment_fallback_delay": 15
            }
        });
        let plan = compile(&opts).unwrap();
        assert!(plan.capabilities().tcp);

        let xhttp_opts = serde_json::json!({
            "server": {"host": "127.0.0.1", "port": 10443},
            "uuid": "00000000-0000-4000-8000-000000000001",
            "multiplex": {
                "enabled": true,
                "protocol": "yamux",
                "max_connections": 2,
                "padding": true
            },
            "security": {
                "type": "tls",
                "server_name": "example.com",
                "allow_insecure": true
            },
            "transport": {
                "type": "xhttp",
                "settings": {
                    "path": "/xhttp",
                    "mode": "stream-up",
                    "http_version": "h2",
                    "x_padding_obfs_mode": true,
                    "x_padding_key": "pad",
                    "x_padding_placement": "query",
                    "x_padding_method": "repeat-x",
                    "uplink_http_method": "POST",
                    "session_placement": "header",
                    "session_key": "X-Session",
                    "seq_placement": "header",
                    "seq_key": "X-Seq",
                    "uplink_data_placement": "body",
                    "xmux": {
                        "max_connections": 2,
                        "c_max_reuse_times": 32,
                        "h_max_request_times": [50, 100],
                        "h_max_reusable_secs": [600, 1200],
                        "h_keep_alive_period": 15
                    }
                }
            }
        });
        let xhttp_plan = compile(&xhttp_opts).unwrap();
        assert!(xhttp_plan.capabilities().tcp);
        assert!(xhttp_plan.capabilities().udp);
    }
}
