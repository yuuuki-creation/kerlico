use kerlico_core::{Destination, Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shadowsocks::{ServerConfig, config::ServerAddr, crypto::CipherKind};
use std::net::SocketAddr;

pub const AEAD_METHODS: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "aes-128-ccm",
    "aes-256-ccm",
    "aes-128-gcm-siv",
    "aes-256-gcm-siv",
    "xchacha20-ietf-poly1305",
    "sm4-gcm",
    "sm4-ccm",
];
pub const LEGACY_METHODS: &[&str] = &[
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb1",
    "aes-128-cfb8",
    "aes-128-cfb128",
    "aes-192-cfb1",
    "aes-192-cfb8",
    "aes-192-cfb128",
    "aes-256-cfb1",
    "aes-256-cfb8",
    "aes-256-cfb128",
    "aes-128-ofb",
    "aes-192-ofb",
    "aes-256-ofb",
    "camellia-128-ctr",
    "camellia-192-ctr",
    "camellia-256-ctr",
    "camellia-128-cfb1",
    "camellia-128-cfb8",
    "camellia-128-cfb128",
    "camellia-192-cfb1",
    "camellia-192-cfb8",
    "camellia-192-cfb128",
    "camellia-256-cfb1",
    "camellia-256-cfb8",
    "camellia-256-cfb128",
    "camellia-128-ofb",
    "camellia-192-ofb",
    "camellia-256-ofb",
    "chacha20-ietf",
    "rc4-md5",
    "rc4",
    "table",
];
#[derive(Deserialize)]
pub(crate) struct ClientOptions {
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default, alias = "udp-over-tcp")]
    pub udp_over_tcp: Option<bool>,
    #[serde(default, alias = "udp-over-tcp-version")]
    pub udp_over_tcp_version: Option<u8>,
    #[serde(default)]
    pub multiplex: Option<kerlico_net::sing_mux::SingMuxOutboundConfig>,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default, alias = "plugin-opts")]
    pub plugin_opts: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra_plugin_opts: std::collections::BTreeMap<String, serde_json::Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeOptions {
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub allow_insecure: bool,
}
fn method(name: &str, allow_insecure: bool) -> Result<CipherKind> {
    if name.starts_with("2022-") {
        return Err(Error::Config("SS2022 必须使用独立 ss2022 模块".into()));
    }
    let alias = name
        .strip_suffix("-cfb")
        .map(|base| format!("{base}-cfb128"));
    if !AEAD_METHODS.contains(&name)
        && !LEGACY_METHODS.contains(&name)
        && !matches!(name, "none" | "plain")
        && !alias
            .as_deref()
            .is_some_and(|value| LEGACY_METHODS.contains(&value))
    {
        return Err(Error::Config("Shadowsocks 方法不在支持范围".into()));
    }
    let cipher: CipherKind = name
        .parse()
        .map_err(|_| Error::Config("Shadowsocks 方法不在支持范围".into()))?;
    if !cipher.is_aead() && !allow_insecure {
        return Err(Error::Config(
            "旧式流方法或 none 必须显式允许不安全模式".into(),
        ));
    }
    Ok(cipher)
}
fn server(
    addr: ServerAddr,
    password: String,
    name: &str,
    allow_insecure: bool,
) -> Result<ServerConfig> {
    let method = method(name, allow_insecure)?;
    if password.len() > 4096 || (method != CipherKind::NONE && password.is_empty()) {
        return Err(Error::Config(
            "Shadowsocks password 为空或超过长度上限".into(),
        ));
    }
    ServerConfig::new(addr, password, method)
        .map_err(|_| Error::Config("Shadowsocks 密码或方法不合法".into()))
}
pub(crate) struct PreparedClient {
    pub config: ServerConfig,
    pub target: Destination,
    pub uot_version: Option<u8>,
    pub multiplex: Option<kerlico_net::sing_mux::SingMuxOutboundConfig>,
    pub plugin: Option<crate::plugin::Plugin>,
}
pub(crate) fn client(options: ClientOptions) -> Result<PreparedClient> {
    for k in options.extra_plugin_opts.keys() {
        if !k.starts_with("plugin-opts-") && !k.starts_with("plugin_opts_") {
            return Err(Error::Config("Shadowsocks 出站字段不合法".into()));
        }
    }
    let has_opts = options.plugin_opts.is_some() || !options.extra_plugin_opts.is_empty();
    let plugin = match options.plugin {
        Some(name) => Some(name),
        None if has_opts => Some("obfs".to_owned()),
        None => None,
    }
    .map(|name| {
        let opts = crate::plugin::PluginOpts::from_value_and_flattened(
            options.plugin_opts.as_ref(),
            &options.extra_plugin_opts,
        )?;
        crate::plugin::Plugin::parse(&name, opts)
    })
    .transpose()?;
    let target = Destination::new(&options.server, options.port)?;
    let config = server(
        ServerAddr::DomainName(target.host(), target.port()),
        options.password,
        &options.method,
        options.allow_insecure,
    )?;
    if let Some(v) = options.udp_over_tcp_version
        && !matches!(v, 1 | 2)
    {
        return Err(Error::Config(
            "Shadowsocks udp_over_tcp_version 仅支持 1 或 2".into(),
        ));
    }
    let uot_version = match (options.udp_over_tcp, options.udp_over_tcp_version) {
        (Some(false), _) => None,
        (Some(true), v) => Some(v.unwrap_or(2)),
        (None, Some(v)) => Some(v),
        (None, None) => None,
    };
    if let Some(mux) = &options.multiplex {
        mux.validate()?;
    }
    let multiplex = options.multiplex.filter(|m| m.enabled);
    Ok(PreparedClient {
        config,
        target,
        uot_version,
        multiplex,
        plugin,
    })
}
pub(crate) fn node(options: NodeOptions) -> Result<(ServerConfig, Vec<[u8; 32]>)> {
    let password = options.password.clone();
    let config = server(
        ServerAddr::SocketAddr("127.0.0.1:1".parse::<SocketAddr>().expect("固定地址合法")),
        options.password,
        &options.method,
        options.allow_insecure,
    )?;
    if config.method() == CipherKind::NONE {
        return Ok((config, Vec::new()));
    }
    // 同时拒绝同密码跨方法复用与不同文本产生同一实际 key 的情况。
    let mut key_hash = Sha256::new();
    key_hash.update(b"shadowsocks/key\0");
    key_hash.update(config.key());
    let mut fingerprints = vec![key_hash.finalize().into()];
    let mut password_hash = Sha256::new();
    password_hash.update(b"shadowsocks/password\0");
    password_hash.update(password.as_bytes());
    fingerprints.push(password_hash.finalize().into());
    Ok((config, fingerprints))
}
