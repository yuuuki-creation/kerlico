//! 服务端入站配置：原始字段（sing-box 拼写，保留旧别名）与校验后的运行计划。

use super::registry::{AddressPool, Registry, Topology};
use crate::{
    data::DataCipher,
    tls::{
        ClientAuth, ClientCertPolicy, NameCheck, ServerTls, TlsVersion, UsageCheck,
        parse_certificates, parse_crls, parse_fingerprint, parse_private_key, server_config,
    },
    wrap::{AuthDigest, CryptV2ServerKey, ReplayConfig, StaticKey, WrapKeys},
};
use kerlico_core::{Error, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    One(String),
    Many(Vec<String>),
}
impl StringOrVec {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v,
        }
    }
    fn join_pem(&self) -> String {
        match self {
            Self::One(s) => s.clone(),
            Self::Many(v) => v.join("\n"),
        }
    }
    /// 单个字符串按 OpenVPN 习惯以冒号分隔。
    fn split_list(self) -> Vec<String> {
        match self {
            Self::One(s) => s
                .split(':')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect(),
            Self::Many(v) => v,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrU64 {
    Num(u64),
    Text(String),
}
impl StringOrU64 {
    pub fn to_secs(&self) -> Result<u64> {
        let invalid = || Error::Config("OpenVPN 时长不合法，需为秒数或带 s/m/h 后缀".into());
        let text = match self {
            Self::Num(value) => return Ok(*value),
            Self::Text(text) => text.trim(),
        };
        if let Ok(value) = text.parse::<u64>() {
            return Ok(value);
        }
        let (number, unit) = text.split_at(text.len().saturating_sub(1));
        let number: u64 = number.trim().parse().map_err(|_| invalid())?;
        match unit {
            "s" => Ok(number),
            "m" => Ok(number * 60),
            "h" => Ok(number * 3600),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyX509Name {
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlWrapConfig {
    #[serde(rename = "type", alias = "mode")]
    pub kind: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, alias = "key-path")]
    pub key_path: Option<String>,
    #[serde(default)]
    pub direction: Option<Value>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default, alias = "force-cookie")]
    pub force_cookie: bool,
    #[serde(default, alias = "v2-metadata-max-age")]
    pub v2_metadata_max_age: Option<StringOrU64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, alias = "certificate_pem")]
    pub certificate: Option<StringOrVec>,
    #[serde(default, alias = "certificate-path")]
    pub certificate_path: Option<String>,
    #[serde(default, alias = "private_key_pem")]
    pub key: Option<StringOrVec>,
    #[serde(default, alias = "key-path", alias = "private_key_path")]
    pub key_path: Option<String>,
    #[serde(default, alias = "extra-certs-pem")]
    pub extra_certs_pem: Option<StringOrVec>,
    #[serde(default, alias = "extra-certs-path")]
    pub extra_certs_path: Option<String>,
    #[serde(default, alias = "ca", alias = "ca_pem", alias = "client-certificate")]
    pub client_certificate: Option<StringOrVec>,
    #[serde(
        default,
        alias = "ca_path",
        alias = "ca-path",
        alias = "client-certificate-path"
    )]
    pub client_certificate_path: Option<String>,
    #[serde(
        default,
        alias = "verify-client-certificate",
        alias = "verify_client_cert",
        alias = "verify-client-cert",
        alias = "client_authentication",
        alias = "client-authentication"
    )]
    pub verify_client_certificate: Option<String>,
    #[serde(default, alias = "peer-fingerprint")]
    pub peer_fingerprint: Option<StringOrVec>,
    #[serde(default, alias = "client-name")]
    pub client_name: Option<String>,
    #[serde(default, alias = "client-name-type")]
    pub client_name_type: Option<String>,
    #[serde(default, alias = "verify-x509-name")]
    pub verify_x509_name: Option<VerifyX509Name>,
    #[serde(default, alias = "remote-certificate-tls", alias = "remote-cert-tls")]
    pub remote_certificate_tls: Option<String>,
    #[serde(default, alias = "remote-certificate-eku", alias = "remote-cert-eku")]
    pub remote_certificate_eku: Option<String>,
    #[serde(default, alias = "remote-certificate-ku", alias = "remote-cert-ku")]
    pub remote_certificate_ku: Option<StringOrVec>,
    #[serde(default, alias = "crl-path")]
    pub crl_path: Option<String>,
    #[serde(default, alias = "crl", alias = "crl-pem")]
    pub crl_pem: Option<String>,
    #[serde(
        default,
        alias = "version-min",
        alias = "min_version",
        alias = "min-version"
    )]
    pub version_min: Option<String>,
    #[serde(
        default,
        alias = "version-max",
        alias = "max_version",
        alias = "max-version"
    )]
    pub version_max: Option<String>,
    #[serde(default)]
    pub cipher: Option<StringOrVec>,
    #[serde(default, alias = "cipher-suites")]
    pub cipher_suites: Vec<String>,
    #[serde(default, alias = "curve_preferences", alias = "curve-preferences")]
    pub groups: Option<StringOrVec>,
    #[serde(default, alias = "export-keying-material")]
    pub export_keying_material: Option<bool>,
    #[serde(default, alias = "control-wrap")]
    pub control_wrap: Option<ControlWrapConfig>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepaliveConfig {
    pub interval: Option<StringOrU64>,
    pub timeout: Option<StringOrU64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServerGroup {
    #[serde(default)]
    pub priority: i32,
    pub addresses: Vec<String>,
    #[serde(default, alias = "resolve-domains")]
    pub resolve_domains: Vec<String>,
    #[serde(default)]
    pub dnssec: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushOptions {
    #[serde(default, alias = "redirect-gateway")]
    pub redirect_gateway: Option<Value>,
    #[serde(default, alias = "redirect-gateway-flags")]
    pub redirect_gateway_flags: Vec<String>,
    #[serde(default, alias = "route")]
    pub routes: Vec<String>,
    #[serde(default, alias = "route-ipv6")]
    pub route_ipv6: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default, alias = "dns-servers")]
    pub dns_servers: Vec<DnsServerGroup>,
    #[serde(default, alias = "search-domains")]
    pub search_domains: Vec<String>,
    #[serde(
        default,
        alias = "dhcp_option",
        alias = "dhcp-option",
        alias = "dhcp-options"
    )]
    pub dhcp_options: Vec<String>,
    #[serde(default, alias = "block-outside-dns")]
    pub block_outside_dns: bool,
    #[serde(default, alias = "ping", alias = "ping-interval")]
    pub ping_interval: Option<StringOrU64>,
    #[serde(default, alias = "ping-restart")]
    pub ping_restart: Option<StringOrU64>,
    #[serde(default)]
    pub raw: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerUserConfig {
    #[serde(alias = "username")]
    pub name: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub address: Option<StringOrVec>,
    #[serde(default)]
    pub push: Option<PushOptions>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerOptions {
    #[serde(default)]
    pub address: Option<StringOrVec>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub network: Option<StringOrVec>,
    #[serde(default, alias = "data-ciphers", alias = "ciphers")]
    pub data_ciphers: Vec<String>,
    #[serde(default, alias = "data-ciphers-fallback")]
    pub data_ciphers_fallback: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default, alias = "static-key")]
    pub static_key: Option<Value>,
    #[serde(default, alias = "static-key-path")]
    pub static_key_path: Option<Value>,
    #[serde(
        default,
        alias = "key_direction",
        alias = "key-direction",
        alias = "static-key-direction"
    )]
    pub static_key_direction: Option<Value>,
    #[serde(default)]
    pub cipher: Option<Value>,
    #[serde(default, alias = "peer-address")]
    pub peer_address: Option<Value>,
    #[serde(default, alias = "peer-address-ipv6")]
    pub peer_address_ipv6: Option<Value>,
    #[serde(default)]
    pub remote: Option<Value>,
    #[serde(default, alias = "remote-port")]
    pub remote_port: Option<Value>,
    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,
    #[serde(default)]
    pub users: Vec<ServerUserConfig>,
    #[serde(default, alias = "duplicate-cn")]
    pub duplicate_cn: bool,
    #[serde(default)]
    pub topology: Option<String>,
    #[serde(default, alias = "tun-mtu", alias = "tun_mtu")]
    pub mtu: Option<usize>,
    #[serde(default, alias = "mss-fix", alias = "mssfix")]
    pub mss_fix: Option<u16>,
    #[serde(default)]
    pub keepalive: Option<KeepaliveConfig>,
    #[serde(
        default,
        alias = "ping_interval",
        alias = "ping-interval",
        alias = "ping_secs"
    )]
    pub ping: Option<StringOrU64>,
    #[serde(default, alias = "ping-restart", alias = "ping_restart_secs")]
    pub ping_restart: Option<StringOrU64>,
    #[serde(
        default,
        alias = "renegotiate-interval",
        alias = "renegotiate_seconds",
        alias = "renegotiate-seconds",
        alias = "reneg_secs"
    )]
    pub renegotiate_interval: Option<StringOrU64>,
    #[serde(default, alias = "renegotiate-disabled")]
    pub renegotiate_disabled: bool,
    #[serde(default, alias = "renegotiate-bytes")]
    pub renegotiate_bytes: Option<u64>,
    #[serde(default, alias = "renegotiate-packets")]
    pub renegotiate_packets: Option<u64>,
    #[serde(default, alias = "handshake-window")]
    pub handshake_window: Option<StringOrU64>,
    #[serde(default, alias = "transition-window")]
    pub transition_window: Option<StringOrU64>,
    #[serde(default, alias = "replay-window")]
    pub replay_window: Option<u32>,
    #[serde(default, alias = "replay-window-time")]
    pub replay_window_time: Option<StringOrU64>,
    #[serde(default, alias = "max-clients")]
    pub max_clients: Option<usize>,
    #[serde(default, alias = "username-as-common-name")]
    pub username_as_common_name: bool,
    #[serde(default, alias = "verify-client-cert-not-required")]
    pub verify_client_cert_not_required: bool,
    #[serde(default)]
    pub push: Option<PushOptions>,
    #[serde(default)]
    pub route: Vec<String>,
    #[serde(default, alias = "route-ipv6")]
    pub route_ipv6: Vec<String>,
    #[serde(default, alias = "redirect-gateway")]
    pub redirect_gateway: Option<Value>,
    #[serde(default, alias = "dhcp-option")]
    pub dhcp_option: Vec<String>,
}

fn config_error(message: impl Into<String>) -> Error {
    Error::Config(format!("OpenVPN 入站：{}", message.into()))
}

fn read_text(inline: Option<String>, path: Option<&str>, what: &str) -> Result<Option<String>> {
    match (inline, path) {
        (Some(_), Some(_)) => Err(config_error(format!("{what} 的内容与路径只能二选一"))),
        (Some(text), None) => Ok(Some(text)),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map(Some)
            .map_err(|_| config_error(format!("无法读取 {what} 文件"))),
        (None, None) => Ok(None),
    }
}

/// 一个会话在握手、保活、换钥与数据通道上使用的参数，节点内同一载体的会话共享。
#[derive(Clone)]
pub(crate) struct SessionSettings {
    pub tcp: bool,
    pub ciphers: Vec<DataCipher>,
    pub fallback: Option<DataCipher>,
    pub allow_ekm: bool,
    pub ping: Option<Duration>,
    pub ping_restart: Option<Duration>,
    pub push_ping: Option<u64>,
    pub push_ping_restart: Option<u64>,
    pub handshake_window: Duration,
    pub transition_window: Duration,
    pub reneg_interval: Option<Duration>,
    pub reneg_bytes: Option<u64>,
    pub reneg_packets: Option<u64>,
    pub replay: ReplayConfig,
    pub mtu: usize,
    pub username_as_common_name: bool,
    pub push_lines: Vec<String>,
}

/// 用户级推送：追加在节点推送之后，`ping` 类数值覆盖节点值。
#[derive(Clone, Debug, Default)]
pub(crate) struct UserPush {
    pub lines: Vec<String>,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
}

pub(crate) struct UserPlan {
    pub fixed_slot: Option<u32>,
    pub push: UserPush,
}

pub(crate) enum NodeWrap {
    Fixed(Box<WrapKeys>),
    CryptV2 {
        key: Box<CryptV2ServerKey>,
        max_age: Option<Duration>,
    },
}

pub(crate) struct Plan {
    pub udp: bool,
    pub tcp: bool,
    pub tls: Arc<rustls::ServerConfig>,
    pub server_fingerprint: [u8; 32],
    pub wrap: NodeWrap,
    pub registry: Arc<Registry>,
    pub settings: SessionSettings,
    pub users: Vec<ServerUserConfig>,
    pub user_plans: BTreeMap<String, UserPlan>,
}

/// 上游 `keepalive 10 60` 是最常见的服务端配置；未配置保活时按它运行，UDP 会话才能在客户端消失后释放地址。
const DEFAULT_KEEPALIVE: (u64, u64) = (10, 60);

fn optional_secs(value: Option<&StringOrU64>) -> Result<Option<u64>> {
    value.map(StringOrU64::to_secs).transpose()
}

fn nonzero(secs: u64) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs))
}

fn route_line(text: &str, family_v6: bool) -> Result<String> {
    let invalid = || config_error(format!("推送路由不合法：{text}"));
    let text = text.trim();
    if let Some((address, prefix)) = text.split_once('/') {
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        return match address.parse::<IpAddr>().map_err(|_| invalid())? {
            IpAddr::V4(address) if prefix <= 32 && !family_v6 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Ok(format!(
                    "route {} {}",
                    std::net::Ipv4Addr::from(u32::from(address) & mask),
                    std::net::Ipv4Addr::from(mask)
                ))
            }
            IpAddr::V6(_) if prefix <= 128 => Ok(format!("route-ipv6 {text}")),
            _ => Err(invalid()),
        };
    }
    let mut fields = text.split_ascii_whitespace();
    match (fields.next(), fields.next(), fields.next()) {
        (Some(network), mask, None) if !family_v6 => {
            network
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| invalid())?;
            match mask {
                Some(mask) => {
                    mask.parse::<std::net::Ipv4Addr>().map_err(|_| invalid())?;
                    Ok(format!("route {network} {mask}"))
                }
                None => Ok(format!("route {network}")),
            }
        }
        (Some(network), None, None) => {
            network
                .parse::<std::net::Ipv6Addr>()
                .map_err(|_| invalid())?;
            Ok(format!("route-ipv6 {network}/128"))
        }
        _ => Err(invalid()),
    }
}

fn plain_option(text: &str, what: &str) -> Result<String> {
    let text = text.trim();
    if text.is_empty() || text.contains([',', '\0', '\n']) {
        return Err(config_error(format!(
            "{what} 不能为空，也不能含逗号或换行：{text}"
        )));
    }
    Ok(text.to_owned())
}

/// 推送选项转成 `PUSH_REPLY` 项，并返回其中声明的 `ping`、`ping-restart`。
fn push_lines(push: &PushOptions) -> Result<(Vec<String>, Option<u64>, Option<u64>)> {
    let mut lines = Vec::new();
    let mut flags: Vec<String> = Vec::new();
    match &push.redirect_gateway {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => flags.push(String::new()),
        Some(Value::String(text)) => flags.push(text.clone()),
        Some(_) => {
            return Err(config_error(
                "push.redirect_gateway 只能是布尔值或 flag 字符串",
            ));
        }
    }
    if !flags.is_empty() || !push.redirect_gateway_flags.is_empty() {
        if flags.is_empty() {
            return Err(config_error(
                "push.redirect_gateway_flags 需要启用 push.redirect_gateway",
            ));
        }
        let mut words: Vec<String> = flags
            .iter()
            .flat_map(|text| text.split_ascii_whitespace().map(str::to_owned))
            .chain(push.redirect_gateway_flags.iter().cloned())
            .collect();
        if words.is_empty() {
            words.push("def1".to_owned());
        }
        lines.push(plain_option(
            &format!("redirect-gateway {}", words.join(" ")),
            "redirect-gateway",
        )?);
    }
    for route in &push.routes {
        lines.push(route_line(route, false)?);
    }
    for route in &push.route_ipv6 {
        lines.push(route_line(route, true)?);
    }
    for server in &push.dns {
        match server
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| config_error(format!("push.dns 不是 IP 地址：{server}")))?
        {
            IpAddr::V4(address) => lines.push(format!("dhcp-option DNS {address}")),
            IpAddr::V6(address) => lines.push(format!("dhcp-option DNS6 {address}")),
        }
    }
    for option in &push.dhcp_options {
        lines.push(format!(
            "dhcp-option {}",
            plain_option(option, "push.dhcp_options")?
        ));
    }
    for group in &push.dns_servers {
        let prefix = format!("dns server {}", group.priority);
        if group.addresses.is_empty() {
            return Err(config_error("push.dns_servers 每组至少需要一个地址"));
        }
        let addresses: Vec<String> = group
            .addresses
            .iter()
            .map(|address| plain_option(address, "push.dns_servers.addresses"))
            .collect::<Result<_>>()?;
        lines.push(format!("{prefix} address {}", addresses.join(" ")));
        if !group.resolve_domains.is_empty() {
            let domains: Vec<String> = group
                .resolve_domains
                .iter()
                .map(|domain| plain_option(domain, "push.dns_servers.resolve_domains"))
                .collect::<Result<_>>()?;
            lines.push(format!("{prefix} resolve-domains {}", domains.join(" ")));
        }
        if let Some(dnssec) = &group.dnssec {
            let dnssec = dnssec.to_ascii_lowercase();
            if !matches!(dnssec.as_str(), "yes" | "optional" | "no") {
                return Err(config_error(
                    "push.dns_servers.dnssec 只能是 yes、optional、no",
                ));
            }
            lines.push(format!("{prefix} dnssec {dnssec}"));
        }
        if let Some(transport) = &group.transport {
            let transport = match transport.to_ascii_lowercase().as_str() {
                "plain" => "plain",
                "dot" => "DoT",
                "doh" => "DoH",
                _ => {
                    return Err(config_error(
                        "push.dns_servers.transport 只能是 plain、dot、doh",
                    ));
                }
            };
            lines.push(format!("{prefix} transport {transport}"));
        }
        if let Some(sni) = &group.sni {
            lines.push(format!(
                "{prefix} sni {}",
                plain_option(sni, "push.dns_servers.sni")?
            ));
        }
    }
    if !push.search_domains.is_empty() {
        let domains: Vec<String> = push
            .search_domains
            .iter()
            .map(|domain| plain_option(domain, "push.search_domains"))
            .collect::<Result<_>>()?;
        lines.push(format!("dns search-domains {}", domains.join(" ")));
    }
    if push.block_outside_dns {
        lines.push("block-outside-dns".to_owned());
    }
    for raw in &push.raw {
        lines.push(plain_option(raw, "push.raw")?);
    }
    Ok((
        lines,
        optional_secs(push.ping_interval.as_ref())?,
        optional_secs(push.ping_restart.as_ref())?,
    ))
}

fn parse_policy(
    options: &ServerOptions,
    tls: &ServerTlsConfig,
    trust: bool,
) -> Result<ClientCertPolicy> {
    let explicit = match tls
        .verify_client_certificate
        .as_deref()
        .map(str::to_ascii_lowercase)
    {
        None => None,
        Some(text) => Some(match text.as_str() {
            "none" | "no" | "false" => ClientCertPolicy::None,
            "optional" => ClientCertPolicy::Optional,
            "require" | "required" | "true" => ClientCertPolicy::Require,
            _ => {
                return Err(config_error(
                    "tls.verify_client_certificate 只能是 require、optional、none",
                ));
            }
        }),
    };
    let policy = match (explicit, options.verify_client_cert_not_required) {
        (Some(policy), false) => policy,
        (None, true) | (Some(ClientCertPolicy::None), true) => ClientCertPolicy::None,
        (Some(_), true) => {
            return Err(config_error(
                "verify_client_cert_not_required 与 tls.verify_client_certificate 冲突",
            ));
        }
        (None, false) if trust => ClientCertPolicy::Require,
        (None, false) => ClientCertPolicy::None,
    };
    if policy != ClientCertPolicy::None && !trust {
        return Err(config_error(
            "校验客户端证书需要 tls.client_certificate、tls.client_certificate_path 或 tls.peer_fingerprint",
        ));
    }
    Ok(policy)
}

fn client_auth(options: &ServerOptions, tls: &ServerTlsConfig) -> Result<ClientAuth> {
    let ca = read_text(
        tls.client_certificate.as_ref().map(StringOrVec::join_pem),
        tls.client_certificate_path.as_deref(),
        "tls.client_certificate",
    )?;
    let authorities = ca
        .as_deref()
        .map(parse_certificates)
        .transpose()?
        .unwrap_or_default();
    let fingerprints = tls
        .peer_fingerprint
        .clone()
        .map(StringOrVec::into_vec)
        .unwrap_or_default()
        .iter()
        .map(|text| parse_fingerprint(text))
        .collect::<Result<Vec<_>>>()?;
    let policy = parse_policy(
        options,
        tls,
        !authorities.is_empty() || !fingerprints.is_empty(),
    )?;
    let crl = read_text(tls.crl_pem.clone(), tls.crl_path.as_deref(), "tls.crl")?;
    let crls = crl
        .as_deref()
        .map(parse_crls)
        .transpose()?
        .unwrap_or_default();
    if !crls.is_empty() && authorities.is_empty() {
        return Err(config_error("tls.crl 需要配合客户端 CA 使用"));
    }
    let name = match (&tls.client_name, &tls.verify_x509_name) {
        (Some(_), Some(_)) => {
            return Err(config_error("tls.client_name 与 tls.verify_x509_name 冲突"));
        }
        (Some(name), None) => Some((name.clone(), tls.client_name_type.clone())),
        (None, Some(legacy)) => Some((legacy.name.clone(), legacy.kind.clone())),
        (None, None) => None,
    };
    let name = name
        .map(|(name, kind)| match kind.as_deref().unwrap_or("name") {
            "name" => Ok(NameCheck::Name(name)),
            "name-prefix" | "name_prefix" => Ok(NameCheck::Prefix(name)),
            "subject" => Ok(NameCheck::Subject(name)),
            _ => Err(config_error(
                "tls.client_name_type 只能是 name、name-prefix、subject",
            )),
        })
        .transpose()?;
    let (usage, key_usage) = match (
        tls.remote_certificate_tls
            .as_deref()
            .map(str::to_ascii_lowercase),
        &tls.remote_certificate_eku,
    ) {
        (Some(_), Some(_)) => {
            return Err(config_error(
                "tls.remote_certificate_tls 与 tls.remote_certificate_eku 冲突",
            ));
        }
        (None, Some(eku)) => (Some(parse_eku(eku)), None),
        (Some(kind), None) => match kind.as_str() {
            "client" => (Some(UsageCheck::ClientAuth), Some(Vec::new())),
            "server" => (Some(UsageCheck::ServerAuth), Some(Vec::new())),
            "none" => (None, None),
            _ => {
                return Err(config_error(
                    "tls.remote_certificate_tls 只能是 client、server、none",
                ));
            }
        },
        (None, None) => (Some(UsageCheck::ClientAuth), Some(Vec::new())),
    };
    let key_usage = match &tls.remote_certificate_ku {
        None => key_usage,
        Some(masks) => Some(
            masks
                .clone()
                .into_vec()
                .iter()
                .map(|mask| {
                    u16::from_str_radix(mask.trim().trim_start_matches("0x"), 16).map_err(|_| {
                        config_error(format!("tls.remote_certificate_ku 不合法：{mask}"))
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    };
    Ok(ClientAuth {
        policy,
        authorities,
        crls,
        fingerprints,
        name,
        usage,
        key_usage,
    })
}

fn parse_eku(text: &str) -> UsageCheck {
    match text.trim() {
        "TLS Web Client Authentication" | "clientAuth" | "1.3.6.1.5.5.7.3.2" => {
            UsageCheck::ClientAuth
        }
        "TLS Web Server Authentication" | "serverAuth" | "1.3.6.1.5.5.7.3.1" => {
            UsageCheck::ServerAuth
        }
        oid => UsageCheck::Oid(oid.to_owned()),
    }
}

fn direction(value: Option<&Value>) -> Result<Option<u8>> {
    let invalid = || config_error("tls.control_wrap.direction 只能是 server、client、0、1");
    match value {
        None | Some(Value::Null) => Ok(Some(0)),
        Some(Value::Number(number)) => match number.as_u64() {
            Some(0) => Ok(Some(0)),
            Some(1) => Ok(Some(1)),
            _ => Err(invalid()),
        },
        Some(Value::String(text)) => match text.trim().to_ascii_lowercase().as_str() {
            "0" | "server" | "normal" => Ok(Some(0)),
            "1" | "client" | "inverse" => Ok(Some(1)),
            "" | "bidirectional" | "both" => Ok(None),
            _ => Err(invalid()),
        },
        Some(_) => Err(invalid()),
    }
}

fn node_wrap(options: &ServerOptions, tls: &ServerTlsConfig) -> Result<NodeWrap> {
    let Some(wrap) = &tls.control_wrap else {
        return Ok(NodeWrap::Fixed(Box::new(WrapKeys::Plain)));
    };
    let kind = wrap.kind.to_ascii_lowercase().replace('-', "_");
    if kind == "none" {
        return Ok(NodeWrap::Fixed(Box::new(WrapKeys::Plain)));
    }
    let key = read_text(
        wrap.key.clone(),
        wrap.key_path.as_deref(),
        "tls.control_wrap.key",
    )?
    .ok_or_else(|| config_error("tls.control_wrap 需要 key 或 key_path"))?;
    if kind != "tls_auth" && wrap.direction.is_some() {
        return Err(config_error("tls.control_wrap.direction 只用于 tls_auth"));
    }
    if kind != "tls_crypt_v2" && (wrap.force_cookie || wrap.v2_metadata_max_age.is_some()) {
        return Err(config_error(
            "force_cookie 与 v2_metadata_max_age 只用于 tls_crypt_v2",
        ));
    }
    match kind.as_str() {
        "tls_auth" => {
            let digest_name = wrap
                .auth
                .as_deref()
                .or(options.auth.as_deref())
                .unwrap_or("SHA1");
            let digest = AuthDigest::parse(digest_name)
                .ok_or_else(|| config_error(format!("不支持的 tls_auth 摘要：{digest_name}")))?;
            Ok(NodeWrap::Fixed(Box::new(WrapKeys::auth(
                &StaticKey::parse(&key)?,
                digest,
                direction(wrap.direction.as_ref())?,
            ))))
        }
        "tls_crypt" => Ok(NodeWrap::Fixed(Box::new(WrapKeys::crypt_server(
            &StaticKey::parse(&key)?,
        )))),
        "tls_crypt_v2" => {
            if wrap.force_cookie {
                return Err(config_error(
                    "tls_crypt_v2 的 force_cookie（无状态 HMAC cookie）尚未实现",
                ));
            }
            Ok(NodeWrap::CryptV2 {
                key: Box::new(CryptV2ServerKey::parse(&key)?),
                max_age: optional_secs(wrap.v2_metadata_max_age.as_ref())?.and_then(nonzero),
            })
        }
        _ => Err(config_error(
            "tls.control_wrap.type 只能是 tls_auth、tls_crypt、tls_crypt_v2",
        )),
    }
}

fn server_tls(options: &ServerOptions, tls: &ServerTlsConfig) -> Result<(ServerTls, [u8; 32])> {
    let certificate = read_text(
        tls.certificate.as_ref().map(StringOrVec::join_pem),
        tls.certificate_path.as_deref(),
        "tls.certificate",
    )?;
    let key = read_text(
        tls.key.as_ref().map(StringOrVec::join_pem),
        tls.key_path.as_deref(),
        "tls.key",
    )?;
    let (Some(certificate), Some(key)) = (certificate, key) else {
        return Err(config_error("TLS 模式必须配置服务端证书与私钥"));
    };
    let mut chain = parse_certificates(&certificate)?;
    let fingerprint = crate::tls::fingerprint(chain[0].as_ref());
    if let Some(extra) = read_text(
        tls.extra_certs_pem.as_ref().map(StringOrVec::join_pem),
        tls.extra_certs_path.as_deref(),
        "tls.extra_certs",
    )? {
        chain.extend(parse_certificates(&extra)?);
    }
    let version = |text: Option<&str>, default| match text {
        None => Ok(default),
        Some(text) => TlsVersion::parse(text)
            .ok_or_else(|| config_error(format!("TLS 版本只能是 1.2 或 1.3：{text}"))),
    };
    let mut suites: Vec<String> = tls
        .cipher
        .clone()
        .map(StringOrVec::split_list)
        .unwrap_or_default();
    suites.extend(tls.cipher_suites.iter().cloned());
    Ok((
        ServerTls {
            chain,
            key: parse_private_key(&key)?,
            client: client_auth(options, tls)?,
            min_version: version(tls.version_min.as_deref(), TlsVersion::V12)?,
            max_version: version(tls.version_max.as_deref(), TlsVersion::V13)?,
            suites,
            groups: tls
                .groups
                .clone()
                .map(StringOrVec::split_list)
                .unwrap_or_default(),
        },
        fingerprint,
    ))
}

fn parse_ciphers(options: &ServerOptions) -> Result<(Vec<DataCipher>, Option<DataCipher>)> {
    let parse = |name: &str| {
        DataCipher::parse(name).ok_or_else(|| {
            config_error(format!(
                "数据通道只支持 AES-128-GCM、AES-256-GCM、CHACHA20-POLY1305：{name}"
            ))
        })
    };
    let mut ciphers = Vec::new();
    for name in options.data_ciphers.iter().flat_map(|text| text.split(':')) {
        let cipher = parse(name.trim())?;
        if !ciphers.contains(&cipher) {
            ciphers.push(cipher);
        }
    }
    if ciphers.is_empty() {
        ciphers = DataCipher::ALL.to_vec();
    }
    let fallback = options
        .data_ciphers_fallback
        .as_deref()
        .map(parse)
        .transpose()?;
    Ok((ciphers, fallback))
}

impl Plan {
    pub fn build(options: ServerOptions, users: Vec<ServerUserConfig>) -> Result<Self> {
        match options
            .mode
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("tls") => {}
            Some("static_key" | "static-key") => {
                return Err(config_error(
                    "static_key 模式（无 TLS 的预共享密钥数据通道）尚未实现，请使用 tls 模式",
                ));
            }
            Some(other) => return Err(config_error(format!("mode 只能是 tls：{other}"))),
        }
        if [
            &options.static_key,
            &options.static_key_path,
            &options.static_key_direction,
            &options.cipher,
            &options.peer_address,
            &options.peer_address_ipv6,
            &options.remote,
            &options.remote_port,
        ]
        .iter()
        .any(|field| field.is_some())
        {
            return Err(config_error(
                "static_key、key_direction、cipher、peer_address、remote 等字段只属于尚未实现的 static_key 模式",
            ));
        }
        let tls_options = options
            .tls
            .clone()
            .filter(|tls| tls.enabled)
            .ok_or_else(|| config_error("TLS 模式必须配置并启用 tls"))?;

        let mut udp = false;
        let mut tcp = false;
        for net in options
            .network
            .clone()
            .map(StringOrVec::into_vec)
            .unwrap_or_else(|| vec!["udp".to_owned()])
        {
            match net.to_ascii_lowercase().as_str() {
                "udp" => udp = true,
                "tcp" => tcp = true,
                _ => return Err(config_error(format!("network 只能是 udp 或 tcp：{net}"))),
            }
        }
        if let Some(mss) = options.mss_fix
            && !(64..=9000).contains(&mss)
        {
            return Err(config_error("mss_fix 需在 64 到 9000 之间"));
        }
        let mtu = options.mtu.unwrap_or(1500);
        if !(576..=9000).contains(&mtu) {
            return Err(config_error("mtu 需在 576 到 9000 之间"));
        }

        let topology = match &options.topology {
            None => Topology::Subnet,
            Some(text) => Topology::parse(text)
                .ok_or_else(|| config_error("topology 只能是 subnet、net30、p2p"))?,
        };
        let prefixes = options
            .address
            .clone()
            .map(StringOrVec::into_vec)
            .unwrap_or_else(|| vec!["10.8.0.1/24".to_owned()]);
        let pool = AddressPool::new(topology, &prefixes)?;

        let (ciphers, fallback) = parse_ciphers(&options)?;
        let (server_tls, server_fingerprint) = server_tls(&options, &tls_options)?;
        let client_policy = server_tls.client.policy;
        let wrap = node_wrap(&options, &tls_options)?;
        let tls = server_config(server_tls)?;

        let mut raw_users = options.users.clone();
        raw_users.extend(users);
        if raw_users.is_empty() {
            return Err(config_error("至少需要一个成员凭据"));
        }
        let mut user_plans = BTreeMap::new();
        let mut reserved = BTreeSet::new();
        for user in &raw_users {
            if user.name.trim().is_empty() {
                return Err(config_error("用户名不能为空"));
            }
            if user.password.is_empty() && client_policy != ClientCertPolicy::Require {
                return Err(config_error(format!(
                    "用户 {} 没有口令，只能用证书 CN 登录，需要 tls.verify_client_certificate 为 require",
                    user.name
                )));
            }
            let mut fixed_slot = None;
            for address in user
                .address
                .clone()
                .map(StringOrVec::into_vec)
                .unwrap_or_default()
            {
                let host = address.split('/').next().unwrap_or_default().trim();
                let address: IpAddr = host
                    .parse()
                    .map_err(|_| config_error(format!("用户固定地址不合法：{address}")))?;
                let slot = pool
                    .slot_of(address)
                    .ok_or_else(|| config_error(format!("用户固定地址不在地址池内：{address}")))?;
                if fixed_slot.is_some_and(|existing| existing != slot) {
                    return Err(config_error(
                        "同一用户的 IPv4 与 IPv6 固定地址须对应同一地址池位置",
                    ));
                }
                fixed_slot = Some(slot);
            }
            if let Some(slot) = fixed_slot
                && !reserved.insert(slot)
            {
                return Err(config_error("不同用户不能使用同一个固定地址"));
            }
            let push = match &user.push {
                None => UserPush::default(),
                Some(push) => {
                    let (lines, ping, ping_restart) = push_lines(push)?;
                    UserPush {
                        lines,
                        ping,
                        ping_restart,
                    }
                }
            };
            if user_plans
                .insert(user.name.clone(), UserPlan { fixed_slot, push })
                .is_some()
            {
                return Err(config_error(format!("用户名重复：{}", user.name)));
            }
        }

        let mut push = options.push.clone().unwrap_or_default();
        push.routes.extend(options.route.iter().cloned());
        push.route_ipv6.extend(options.route_ipv6.iter().cloned());
        push.dhcp_options
            .extend(options.dhcp_option.iter().cloned());
        if options.redirect_gateway.is_some() {
            if push.redirect_gateway.is_some() {
                return Err(config_error(
                    "redirect_gateway 与 push.redirect_gateway 冲突",
                ));
            }
            push.redirect_gateway.clone_from(&options.redirect_gateway);
        }
        let (push_lines, explicit_push_ping, explicit_push_restart) = push_lines(&push)?;

        let (keep_interval, keep_timeout) = match &options.keepalive {
            None => DEFAULT_KEEPALIVE,
            Some(keepalive) => (
                optional_secs(keepalive.interval.as_ref())?.unwrap_or(DEFAULT_KEEPALIVE.0),
                optional_secs(keepalive.timeout.as_ref())?.unwrap_or(DEFAULT_KEEPALIVE.1),
            ),
        };
        let ping = optional_secs(options.ping.as_ref())?.unwrap_or(keep_interval);
        // 上游 keepalive 在服务端使用两倍超时，给推送给客户端的超时留出余量。
        let ping_restart =
            optional_secs(options.ping_restart.as_ref())?.unwrap_or(keep_timeout * 2);
        let push_ping = explicit_push_ping.unwrap_or(keep_interval);
        let push_ping_restart = explicit_push_restart.unwrap_or(keep_timeout);

        let reneg_interval = if options.renegotiate_disabled {
            if options.renegotiate_interval.is_some() {
                return Err(config_error(
                    "renegotiate_disabled 与 renegotiate_interval 冲突",
                ));
            }
            None
        } else {
            nonzero(optional_secs(options.renegotiate_interval.as_ref())?.unwrap_or(3600))
        };
        let replay_size = options.replay_window.unwrap_or(64);
        if !(1..=65536).contains(&replay_size) {
            return Err(config_error("replay_window 需在 1 到 65536 之间"));
        }
        let max_clients = options.max_clients.unwrap_or(1024);
        if max_clients == 0 {
            return Err(config_error("max_clients 至少为 1"));
        }

        let settings = SessionSettings {
            tcp: false,
            ciphers,
            fallback,
            allow_ekm: tls_options.export_keying_material != Some(false),
            ping: nonzero(ping),
            ping_restart: nonzero(ping_restart),
            push_ping: (push_ping > 0).then_some(push_ping),
            push_ping_restart: (push_ping_restart > 0).then_some(push_ping_restart),
            handshake_window: Duration::from_secs(
                optional_secs(options.handshake_window.as_ref())?
                    .unwrap_or(60)
                    .max(1),
            ),
            transition_window: Duration::from_secs(
                optional_secs(options.transition_window.as_ref())?.unwrap_or(3600),
            ),
            reneg_interval,
            reneg_bytes: options.renegotiate_bytes.filter(|bytes| *bytes > 0),
            reneg_packets: options.renegotiate_packets.filter(|packets| *packets > 0),
            replay: ReplayConfig {
                size: replay_size,
                max_delay: Some(Duration::from_secs(
                    optional_secs(options.replay_window_time.as_ref())?.unwrap_or(15),
                )),
            },
            mtu,
            username_as_common_name: options.username_as_common_name,
            push_lines,
        };
        Ok(Self {
            udp,
            tcp,
            tls,
            server_fingerprint,
            wrap,
            registry: Registry::new(pool, reserved, max_clients, options.duplicate_cn),
            settings,
            users: raw_users,
            user_plans,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn push_options_render_routes_dns_gateway_and_search_domains() {
        let push: PushOptions = serde_json::from_value(json!({
            "redirect_gateway": true,
            "redirect_gateway_flags": ["def1", "bypass-dhcp"],
            "routes": ["192.0.2.0/24", "198.51.100.7 255.255.255.255", "fd00:1::/64"],
            "dns": ["1.1.1.1", "2606:4700:4700::1111"],
            "dns_servers": [{ "priority": 1, "addresses": ["9.9.9.9", "[2620:fe::fe]:53"], "transport": "dot", "sni": "dns.quad9.net", "resolve_domains": ["corp.example"] }],
            "search_domains": ["corp.example"],
            "dhcp_options": ["DOMAIN corp.example"],
            "block_outside_dns": true,
            "ping_interval": "5s",
            "ping_restart": 30
        }))
        .unwrap();
        let (lines, ping, restart) = push_lines(&push).unwrap();
        assert_eq!(
            lines,
            [
                "redirect-gateway def1 bypass-dhcp",
                "route 192.0.2.0 255.255.255.0",
                "route 198.51.100.7 255.255.255.255",
                "route-ipv6 fd00:1::/64",
                "dhcp-option DNS 1.1.1.1",
                "dhcp-option DNS6 2606:4700:4700::1111",
                "dhcp-option DOMAIN corp.example",
                "dns server 1 address 9.9.9.9 [2620:fe::fe]:53",
                "dns server 1 resolve-domains corp.example",
                "dns server 1 transport DoT",
                "dns server 1 sni dns.quad9.net",
                "dns search-domains corp.example",
                "block-outside-dns",
            ]
        );
        assert_eq!((ping, restart), (Some(5), Some(30)));
        let bare: PushOptions =
            serde_json::from_value(json!({ "redirect_gateway": true })).unwrap();
        assert_eq!(push_lines(&bare).unwrap().0, ["redirect-gateway def1"]);
        let bad: PushOptions = serde_json::from_value(json!({ "raw": ["a,b"] })).unwrap();
        assert!(
            push_lines(&bad).is_err(),
            "a comma would split the pushed option"
        );
    }
}
