//! 组合配置在协议边界校验，核心调度不感知具体传输或安全类型。

use crate::{UserId, carrier::Carrier, payload};
use hmac::{Hmac, Mac};
use kerlico_config::{OutboundPlan, TargetSpec};
use kerlico_core::{
    BoxFuture, Capabilities, ConnectContext, DatagramChannel, Destination, Error, Outbound, Result,
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
    encryption: Option<xray_vless_encryption::ClientConfig>,
    mux: Option<(usize, usize)>,
    resources: Mutex<HashMap<kerlico_core::ResourceKey, Arc<Resources>>>,
    host: kerlico_core::ServiceContext,
    mux_tcp: bool,
    mux_udp: bool,
}

pub(crate) fn compile(value: &Value) -> Result<OutboundPlan> {
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
    let carrier = Carrier::build(
        options.server.destination()?,
        options.security,
        transport,
        !encryption.is_none(),
        options.server_family,
    )?;
    let udp443 = options.flow == "xtls-rprx-vision-udp443";
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
        false,
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
                    mux_tcp,
                    mux_udp,
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
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            let resources = self.resources(context)?;
            context
                .run(async {
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
}
