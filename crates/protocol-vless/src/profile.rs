//! 组合配置在协议边界校验，核心调度不感知具体传输或安全类型。

use crate::{UserId, carrier::Carrier, payload};
use kerlico_config::TargetSpec;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
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
    #[serde(default = "none")]
    pub encryption: String,
    #[serde(default)]
    pub security: Security,
    #[serde(default)]
    pub packet_encoding: PacketEncoding,
    #[serde(default)]
    pub mux: Option<MuxOptions>,
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
    #[serde(default)]
    pub max_post_bytes: Option<u32>,
    #[serde(default)]
    pub min_post_interval_ms: Option<u32>,
    #[serde(default)]
    pub max_buffered_posts: Option<u32>,
    #[serde(default)]
    pub padding_bytes: Option<[u32; 2]>,
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
    encryption: Option<Client>,
    mux: Option<crate::mux::Pool>,
    mux_tcp: bool,
    mux_udp: bool,
}

pub(crate) fn build(value: &Value) -> Result<Arc<dyn Outbound>> {
    let options: Options = serde_json::from_value(value.clone())
        .map_err(|_| Error::Config("VLESS 配置字段不合法".into()))?;
    let user = UserId::parse(&options.uuid)?;
    let vision = match options.flow.as_str() {
        "" => false,
        "xtls-rprx-vision" | "xtls-rprx-vision-udp443" => true,
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
        if settings.tcp&&matches!(transport,Transport::Xhttp{..}){return Err(Error::Config("XHTTP 的 Mux 仅支持 UDP；TCP 使用载体自己的 XMUX".into()));}
        if vision && settings.tcp {
            return Err(Error::Config(
                "Vision 不能复用 TCP 业务；可仅启用 Mux UDP".into(),
            ));
        }
        if settings.udp && options.packet_encoding == PacketEncoding::Packetaddr {
            return Err(Error::Config("packetaddr 与 Mux UDP 必须分开配置".into()));
        }
        mux = Some(crate::mux::Pool::new(
            settings.concurrency,
            settings.max_connections,
        ));
        mux_tcp = settings.tcp;
        mux_udp = settings.udp;
    }
    if storage_carrier && (!mux_tcp || !mux_udp) {
        return Err(Error::Config("XDRIVE 必须显式启用 TCP/UDP Mux".into()));
    }
    let carrier = Carrier::build(
        options.server.destination()?,
        options.security,
        transport,
        !encryption.is_none(),
        options.server_family,
    )?;
    Ok(Arc::new(ProfileOutbound {
        carrier,
        user,
        vision,
        udp443: options.flow == "xtls-rprx-vision-udp443",
        encoding: if vision {
            PacketEncoding::Xudp
        } else {
            options.packet_encoding
        },
        encryption: encryption.client().cloned().map(Client::new),
        mux,
        mux_tcp,
        mux_udp,
    }))
}

impl Outbound for ProfileOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    if self.mux_tcp {
                        return self
                            .mux
                            .as_ref()
                            .ok_or(Error::Protocol("Mux 配置不可用"))?
                            .tcp(target, async {
                                let carrier = self.carrier.open().await?;
                                payload::open(
                                    carrier,
                                    self.encryption.as_ref(),
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
                    let carrier = self.carrier.open().await?;
                    payload::open(
                        carrier,
                        self.encryption.as_ref(),
                        self.user,
                        target,
                        self.vision,
                        false,
                        self.encoding,
                    )
                    .await
                })
                .await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            if self.vision && !self.udp443 && target.port() == 443 {
                return Err(Error::Rejected);
            }
            if self.encoding == PacketEncoding::Packetaddr
                && matches!(target.address(), kerlico_core::Address::Domain(_))
            {
                return Err(Error::Unsupported("packetaddr 域名目标"));
            }
            context
                .run(async {
                    if self.mux_udp {
                        return self
                            .mux
                            .as_ref()
                            .ok_or(Error::Protocol("Mux 配置不可用"))?
                            .udp(target, self.encoding == PacketEncoding::Xudp, async {
                                let carrier = self.carrier.open().await?;
                                payload::open(
                                    carrier,
                                    self.encryption.as_ref(),
                                    self.user,
                                    target,
                                    self.vision,
                                    true,
                                    PacketEncoding::Xudp,
                                )
                                .await
                            })
                            .await;
                    }
                    let carrier = self.carrier.open().await?;
                    let stream = payload::open(
                        carrier,
                        self.encryption.as_ref(),
                        self.user,
                        target,
                        self.vision,
                        true,
                        self.encoding,
                    )
                    .await?;
                    payload::datagrams(stream, target, self.encoding)
                })
                .await
        })
    }
}
