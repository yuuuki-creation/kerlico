use crate::{
    codec::{
        layout::Mode,
        record::Method,
        table::{GridOrder, Pair},
    },
    key::Material,
    replay::Replay,
};
use kerlico_config::TargetSpec;
use kerlico_core::{Destination, Error, Result};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

fn yes() -> bool {
    true
}
fn padding_min() -> u8 {
    10
}
fn padding_max() -> u8 {
    30
}
fn streams() -> usize {
    32
}
fn pool_size() -> usize {
    4
}
fn idle() -> u64 {
    30000
}
fn http_sessions() -> usize {
    64
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtocolOptions {
    key: String,
    #[serde(default)]
    aead: Method,
    #[serde(default)]
    table_type: String,
    #[serde(default = "padding_min")]
    padding_min: u8,
    #[serde(default = "padding_max")]
    padding_max: u8,
    #[serde(default = "yes")]
    pure_downlink: bool,
    #[serde(default)]
    custom_tables: Vec<String>,
    #[serde(default = "yes")]
    udp_enabled: bool,
    #[serde(default)]
    allow_insecure: bool,
}
pub(crate) struct Protocol {
    pub material: Material,
    pub method: Method,
    pub client_tables: Vec<Arc<Pair>>,
    pub server_tables: Vec<Arc<Pair>>,
    pub padding_min: u8,
    pub padding_max: u8,
    pub pure_downlink: bool,
    pub udp_enabled: bool,
    pub replay: Mutex<Replay>,
}
impl Protocol {
    pub fn features(&self) -> u32 {
        if self.udp_enabled {
            crate::wire::kip::FEATURES
        } else {
            crate::wire::kip::FEATURES & !4
        }
    }
}
impl ProtocolOptions {
    fn prepare(self) -> Result<Arc<Protocol>> {
        if self.padding_min > self.padding_max
            || self.padding_max > 100
            || self.custom_tables.len() > 16
        {
            return Err(Error::Config("Sudoku padding或轮换表数量不合法".into()));
        }
        if (self.aead == Method::None) != self.allow_insecure {
            return Err(Error::Config(
                "Sudoku none必须单独明确允许不安全兼容".into(),
            ));
        }
        let material = Material::parse(&self.key)?;
        let mode = Mode::parse(&self.table_type)?;
        let patterns: Vec<_> = if self.custom_tables.is_empty() {
            vec![String::new()]
        } else {
            self.custom_tables
                .iter()
                .map(|s| s.trim().to_ascii_lowercase().replace(' ', ""))
                .collect()
        };
        if mode == Mode::Ascii && patterns.iter().any(|s| !s.is_empty()) {
            return Err(Error::Config("全ASCII方向不接受无效的自定义布局".into()));
        }
        let order = Arc::new(GridOrder::new(&material.seed));
        let build = |patterns: &[String]| -> Result<Vec<Arc<Pair>>> {
            let mut tables = Vec::new();
            let mut hints = HashMap::new();
            for pattern in patterns {
                let pair = Pair::new(&material.seed, mode, pattern, order.clone())?;
                if let Some(previous) = hints.get(&pair.hint) {
                    if previous == pattern {
                        continue;
                    }
                    return Err(Error::Config("Sudoku轮换表hint冲突".into()));
                }
                hints.insert(pair.hint, pattern.clone());
                tables.push(Arc::new(pair));
            }
            Ok(tables)
        };
        let client_tables = build(&patterns)?;
        let mut server_patterns = patterns;
        if !mode.ascii(true) && !server_patterns[0].is_empty() {
            server_patterns.insert(0, String::new());
        }
        let server_tables = build(&server_patterns)?;
        Ok(Arc::new(Protocol {
            material,
            method: self.aead,
            client_tables,
            server_tables,
            padding_min: self.padding_min,
            padding_max: self.padding_max,
            pure_downlink: self.pure_downlink,
            udp_enabled: self.udp_enabled,
            replay: Mutex::new(Replay::new(4096)),
        }))
    }
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CarrierMode {
    Raw,
    #[default]
    Legacy,
    Stream,
    Poll,
    Auto,
    Ws,
}
impl CarrierMode {
    pub fn http(self) -> bool {
        matches!(self, Self::Stream | Self::Poll | Self::Auto | Self::Ws)
    }
    pub fn split(self) -> bool {
        matches!(self, Self::Stream | Self::Poll | Self::Auto)
    }
}
#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Multiplex {
    #[default]
    Off,
    Auto,
    On,
}
#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HttpVersion {
    #[default]
    Auto,
    H1,
    H2,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientTls {
    pub server_name: String,
    pub ca_pem: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerTls {
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientMask {
    #[serde(default)]
    pub mode: CarrierMode,
    pub tls: Option<ClientTls>,
    pub host: Option<String>,
    #[serde(default)]
    pub path_root: String,
    #[serde(default)]
    pub http_version: HttpVersion,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerMask {
    #[serde(default)]
    pub mode: CarrierMode,
    pub tls: Option<ServerTls>,
    #[serde(default)]
    pub path_root: String,
}
fn root(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    let value = value.trim_matches('/');
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Config("Sudoku path_root只能是单个有界路径段".into()));
    }
    Ok(format!("/{value}"))
}
pub(crate) fn safe_host(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 259
        || value.bytes().any(|b| {
            !b.is_ascii()
                || b.is_ascii_control()
                || b.is_ascii_whitespace()
                || b == b'/'
                || b == b'\\'
                || b == b'@'
        })
        || value.parse::<http::uri::Authority>().is_err()
    {
        return Err(Error::Config("Sudoku HTTP Host不合法".into()));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutOptions {
    server: TargetSpec,
    pub protocol: ProtocolOptions,
    #[serde(default)]
    http_mask: ClientMask,
    #[serde(default)]
    multiplex: Multiplex,
    #[serde(default = "streams")]
    max_mux_streams: usize,
    #[serde(default = "pool_size")]
    max_pool_sessions: usize,
    #[serde(default = "idle")]
    pool_idle_ms: u64,
}
pub(crate) struct OutConfig {
    pub server: Destination,
    pub protocol: Arc<Protocol>,
    pub mask: ClientMask,
    pub multiplex: Multiplex,
    pub max_streams: usize,
    pub max_pool: usize,
    pub idle: Duration,
}
impl OutOptions {
    pub fn prepare(mut self) -> Result<OutConfig> {
        let server = self.server.destination()?;
        let protocol = self.protocol.prepare()?;
        if protocol.method == Method::None && !server.is_loopback() {
            return Err(Error::Config("Sudoku none出站只能使用字面回环端点".into()));
        }
        if self.http_mask.tls.is_some() && !self.http_mask.mode.http() {
            return Err(Error::Config("raw/legacy不接受HTTP TLS开关".into()));
        }
        if self.http_mask.mode == CarrierMode::Raw
            && (self.http_mask.host.is_some()
                || !self.http_mask.path_root.is_empty()
                || self.http_mask.http_version != HttpVersion::Auto)
        {
            return Err(Error::Config("raw载体不接受无效HTTP字段".into()));
        }
        if self.multiplex == Multiplex::Auto && !self.http_mask.mode.split() {
            return Err(Error::Config("HTTP transport复用仅适用于split载体".into()));
        }
        if self.http_mask.http_version == HttpVersion::H2
            && (!self.http_mask.mode.split() || self.http_mask.tls.is_none())
        {
            return Err(Error::Config("强制HTTP/2仅适用于TLS split载体".into()));
        }
        if let Some(host) = self.http_mask.host.as_deref() {
            safe_host(host)?;
        }
        if let Some(tls) = self.http_mask.tls.as_ref() {
            let _ = kerlico_net::TcpConnector::tls(&tls.server_name, tls.ca_pem.as_deref())?;
        }
        self.http_mask.path_root = root(&self.http_mask.path_root)?;
        if !(1..=1024).contains(&self.max_mux_streams)
            || !(1..=16).contains(&self.max_pool_sessions)
            || !(100..=300000).contains(&self.pool_idle_ms)
        {
            return Err(Error::Config("Sudoku出站池预算不合法".into()));
        }
        Ok(OutConfig {
            server,
            protocol,
            mask: self.http_mask,
            multiplex: self.multiplex,
            max_streams: self.max_mux_streams,
            max_pool: self.max_pool_sessions,
            idle: Duration::from_millis(self.pool_idle_ms),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoverFallback {
    pub server: TargetSpec,
    pub host: String,
    pub tls: Option<ClientTls>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeOptions {
    protocol: ProtocolOptions,
    #[serde(default)]
    http_mask: ServerMask,
    #[serde(default = "streams")]
    max_mux_streams: usize,
    #[serde(default = "http_sessions")]
    max_http_sessions: usize,
    #[serde(default = "idle")]
    http_session_ttl_ms: u64,
    cover_fallback: Option<CoverFallback>,
}
pub(crate) struct NodeConfig {
    pub protocol: Arc<Protocol>,
    pub mask: ServerMask,
    pub max_streams: usize,
    pub max_http_sessions: usize,
    pub http_ttl: Duration,
    pub fallback: Option<CoverFallback>,
}
impl NodeOptions {
    pub fn prepare(mut self) -> Result<NodeConfig> {
        let protocol = self.protocol.prepare()?;
        self.http_mask.path_root = root(&self.http_mask.path_root)?;
        if self.http_mask.tls.is_some() && !self.http_mask.mode.http() {
            return Err(Error::Config("raw/legacy节点不接受HTTP TLS开关".into()));
        }
        if !self.http_mask.mode.http() && !self.http_mask.path_root.is_empty() {
            return Err(Error::Config("raw/legacy节点不使用HTTP路径门槛".into()));
        }
        if !(1..=1024).contains(&self.max_mux_streams)
            || !(1..=1024).contains(&self.max_http_sessions)
            || !(100..=300000).contains(&self.http_session_ttl_ms)
        {
            return Err(Error::Config("Sudoku节点会话预算不合法".into()));
        }
        if let Some(fallback) = self.cover_fallback.as_ref() {
            fallback.server.destination()?;
            safe_host(&fallback.host)?;
            if let Some(tls) = fallback.tls.as_ref() {
                let _ = kerlico_net::TcpConnector::tls(&tls.server_name, tls.ca_pem.as_deref())?;
            }
        }
        Ok(NodeConfig {
            protocol,
            mask: self.http_mask,
            max_streams: self.max_mux_streams,
            max_http_sessions: self.max_http_sessions,
            http_ttl: Duration::from_millis(self.http_session_ttl_ms),
            fallback: self.cover_fallback,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn unknown_inapplicable_options_and_unsafe_remote_modes_are_rejected() {
        let base = json!({"server":{"host":"127.0.0.1","port":10443},"protocol":{"key":"synthetic-sudoku-config-seed"}});
        assert!(
            serde_json::from_value::<OutOptions>(base.clone())
                .unwrap()
                .prepare()
                .is_ok()
        );
        for patch in [
            json!({"unknown":true}),
            json!({"multiplex":"auto"}),
            json!({"max_mux_streams":0}),
            json!({"max_pool_sessions":17}),
            json!({"http_mask":{"mode":"raw","tls":{"server_name":"test.invalid"}}}),
            json!({"http_mask":{"mode":"ws","http_version":"h2"}}),
            json!({"http_mask":{"mode":"poll","path_root":"nested/path"}}),
            json!({"protocol":{"key":"synthetic-sudoku-config-seed","aead":"none"}}),
            json!({"protocol":{"key":"synthetic-sudoku-config-seed","allow_insecure":true}}),
        ] {
            let mut value = base.clone();
            for (k, v) in patch.as_object().unwrap() {
                value[k] = v.clone();
            }
            let parsed = serde_json::from_value::<OutOptions>(value);
            assert!(parsed.is_err() || parsed.unwrap().prepare().is_err());
        }
        let mut value = base;
        value["protocol"]["aead"] = json!("none");
        value["protocol"]["allow_insecure"] = json!(true);
        assert!(
            serde_json::from_value::<OutOptions>(value.clone())
                .unwrap()
                .prepare()
                .is_ok()
        );
        value["server"]["host"] = json!("localhost");
        assert!(
            serde_json::from_value::<OutOptions>(value)
                .unwrap()
                .prepare()
                .is_err()
        );
        for host in ["valid.invalid", "[::1]:443", "127.0.0.1:80"] {
            assert!(safe_host(host).is_ok());
        }
        for host in [
            "bad\r\nInjected: true",
            "a/b",
            "user@host",
            "host with-space",
        ] {
            assert!(safe_host(host).is_err());
        }
    }
}
