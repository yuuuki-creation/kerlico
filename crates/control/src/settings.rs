//! `GET /configs` 的 Mihomo 形状与 `PATCH /configs` 的字段改写。
//!
//! 运行配置以规范化后的配置值保存；`mode` 与 `log-level` 即时生效，监听相关字段写入配置值后整体重载。

use kerlico_config::RunMode;
use kerlico_core::{
    Error, Result,
    log::{self, LogLevel},
};
use serde_json::{Map, Value, json};

/// Mihomo 字段名与配置值中可能出现的别名，改写时先删别名再写入首个名字。
const LISTEN_FIELDS: [&[&str]; 10] = [
    &["port", "http-port"],
    &["socks-port", "socks_port"],
    &["mixed-port", "mixed_port"],
    &["redir-port", "redir_port"],
    &["tproxy-port", "tproxy_port"],
    &["allow-lan", "allow_lan"],
    &["bind-address", "bind_address"],
    &["lan-allowed-ips", "lan_allowed_ips"],
    &["lan-disallowed-ips", "lan_disallowed_ips"],
    &["interface-name", "interface_name", "bind-interface"],
];
const PORT_FIELDS: [&str; 5] = [
    "port",
    "socks-port",
    "mixed-port",
    "redir-port",
    "tproxy-port",
];
const LOG_LEVEL_ALIASES: [&str; 3] = ["level", "loglevel", "log-level"];

/// 校验后的 `PATCH /configs` 请求体。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigPatch {
    pub mode: Option<RunMode>,
    pub log_level: Option<LogLevel>,
    /// 需要重建入站监听的字段，键为 Mihomo 名字；端口 0 表示关闭该入站。
    listen: Map<String, Value>,
    tun: Option<Map<String, Value>>,
    pub ignored: Vec<String>,
}

impl ConfigPatch {
    pub fn parse(body: &Value) -> Result<Self> {
        let object = body
            .as_object()
            .ok_or_else(|| Error::Config("PATCH /configs 请求体须为对象".into()))?;
        let mut patch = Self::default();
        for (key, value) in object {
            match key.as_str() {
                "mode" => {
                    let raw = value.as_str().unwrap_or_default();
                    patch.mode = Some(
                        RunMode::parse(raw)
                            .ok_or_else(|| Error::Config(format!("mode 不合法：{raw}")))?,
                    );
                }
                "log-level" => {
                    let raw = value.as_str().unwrap_or_default();
                    patch.log_level = Some(
                        LogLevel::parse(raw)
                            .ok_or_else(|| Error::Config(format!("log-level 不合法：{raw}")))?,
                    );
                }
                "tun" => {
                    let tun = value
                        .as_object()
                        .ok_or_else(|| Error::Config("tun 须为对象".into()))?;
                    patch.tun = Some(tun.clone());
                }
                name if PORT_FIELDS.contains(&name) => {
                    let port = value
                        .as_u64()
                        .and_then(|port| u16::try_from(port).ok())
                        .ok_or_else(|| Error::Config(format!("{name} 须为 0 至 65535")))?;
                    patch.listen.insert(name.to_owned(), json!(port));
                }
                "allow-lan" => {
                    value
                        .as_bool()
                        .ok_or_else(|| Error::Config("allow-lan 须为布尔值".into()))?;
                    patch.listen.insert(key.clone(), value.clone());
                }
                "bind-address" | "interface-name" => {
                    value
                        .as_str()
                        .ok_or_else(|| Error::Config(format!("{key} 须为字符串")))?;
                    patch.listen.insert(key.clone(), value.clone());
                }
                "lan-allowed-ips" | "lan-disallowed-ips" => {
                    value
                        .as_array()
                        .filter(|items| items.iter().all(Value::is_string))
                        .ok_or_else(|| Error::Config(format!("{key} 须为字符串数组")))?;
                    patch.listen.insert(key.clone(), value.clone());
                }
                _ => patch.ignored.push(key.clone()),
            }
        }
        Ok(patch)
    }

    /// 改动入站监听时需要重建引擎；只改 `mode`、`log-level` 时就地生效。
    pub fn restarts(&self) -> bool {
        !self.listen.is_empty() || self.tun.is_some()
    }

    /// 把本次改动写进运行配置值，之后的重载（含提供者更新触发的重载）沿用这些值。
    pub fn apply(&self, config: &mut Value) {
        let Some(root) = config.as_object_mut() else {
            return;
        };
        if let Some(mode) = self.mode {
            root.insert("mode".into(), json!(mode.as_str()));
        }
        if let Some(level) = self.log_level {
            let nested = root
                .get_mut("log")
                .and_then(Value::as_object_mut)
                .and_then(|log| {
                    let key = LOG_LEVEL_ALIASES.iter().find(|k| log.contains_key(**k))?;
                    log.insert((*key).to_owned(), json!(level.as_str()));
                    Some(())
                });
            if nested.is_none() {
                root.remove("log_level");
                root.insert("log-level".into(), json!(level.as_str()));
            }
        }
        for aliases in LISTEN_FIELDS {
            let Some(value) = self.listen.get(aliases[0]) else {
                continue;
            };
            for alias in aliases {
                root.remove(*alias);
            }
            if value.as_u64() != Some(0) {
                root.insert(aliases[0].to_owned(), value.clone());
            }
        }
        if let Some(tun) = &self.tun {
            let target = root
                .entry("tun")
                .or_insert_with(|| Value::Object(Map::new()));
            if !target.is_object() {
                *target = Value::Object(Map::new());
            }
            if let Some(target) = target.as_object_mut() {
                for (key, value) in tun {
                    target.insert(key.clone(), value.clone());
                }
                if let Some(enable) = target.remove("enabled") {
                    target.entry("enable").or_insert(enable);
                }
            }
        }
    }
}

fn field<'a>(root: &'a Map<String, Value>, aliases: &[&str]) -> Option<&'a Value> {
    aliases.iter().find_map(|alias| root.get(*alias))
}

fn port(root: &Map<String, Value>, aliases: &[&str]) -> u64 {
    field(root, aliases).and_then(Value::as_u64).unwrap_or(0)
}

/// Mihomo `GET /configs` 的字段；`mode` 与 `log-level` 读运行值，其余读运行配置。
pub fn configs_json(config: &Value, mode: RunMode) -> Value {
    let empty = Map::new();
    let root = config.as_object().unwrap_or(&empty);
    let allow_lan = field(root, LISTEN_FIELDS[5])
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let tun = root.get("tun").and_then(Value::as_object);
    let tun_enabled = tun.is_some_and(|tun| {
        tun.get("enable")
            .or_else(|| tun.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(true)
    });
    let tun_text = |key: &str, fallback: &str| {
        tun.and_then(|tun| tun.get(key))
            .and_then(Value::as_str)
            .unwrap_or(fallback)
            .to_owned()
    };
    let strings = |aliases: &[&str]| field(root, aliases).cloned().unwrap_or_else(|| json!([]));
    let sniffing = root
        .get("sniffer")
        .and_then(|s| s.get("enable"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "port": port(root, LISTEN_FIELDS[0]),
        "socks-port": port(root, LISTEN_FIELDS[1]),
        "mixed-port": port(root, LISTEN_FIELDS[2]),
        "redir-port": port(root, LISTEN_FIELDS[3]),
        "tproxy-port": port(root, LISTEN_FIELDS[4]),
        "allow-lan": allow_lan,
        "bind-address": field(root, LISTEN_FIELDS[6]).and_then(Value::as_str).unwrap_or("*"),
        "lan-allowed-ips": strings(LISTEN_FIELDS[7]),
        "lan-disallowed-ips": strings(LISTEN_FIELDS[8]),
        "interface-name": field(root, LISTEN_FIELDS[9]).and_then(Value::as_str).unwrap_or(""),
        "routing-mark": field(root, &["routing-mark", "routing_mark"]).and_then(Value::as_u64).unwrap_or(0),
        "mode": mode.as_str(),
        "log-level": log::level().as_str(),
        "ipv6": true,
        "sniffing": sniffing,
        "tcp-concurrent": false,
        "unified-delay": false,
        "geodata-mode": field(root, &["geodata-mode", "geodata_mode"]).and_then(Value::as_bool).unwrap_or(false),
        "geo-auto-update": field(root, &["geo-auto-update", "geo_auto_update"]).and_then(Value::as_bool).unwrap_or(false),
        "geo-update-interval": field(root, &["geo-update-interval", "geo_update_interval"]).and_then(Value::as_u64).unwrap_or(24),
        "geox-url": field(root, &["geox-url", "geox_url"]).cloned().unwrap_or_else(|| json!({})),
        "tun": {
            "enable": tun_enabled,
            "device": tun_text("device", ""),
            "stack": tun_text("stack", "system"),
            "dns-hijack": tun.and_then(|t| t.get("dns-hijack")).cloned().unwrap_or_else(|| json!([])),
            "auto-route": tun.and_then(|t| t.get("auto-route")).and_then(Value::as_bool).unwrap_or(false),
            "auto-detect-interface": tun.and_then(|t| t.get("auto-detect-interface")).and_then(Value::as_bool).unwrap_or(false),
        },
        "authentication": [],
        "skip-auth-prefixes": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_rewrites_aliases_drops_zero_ports_and_merges_tun() {
        let mut config = json!({
            "mixed_port": 7890, "socks-port": 7891, "allow_lan": false,
            "log": {"loglevel": "warning"}, "tun": {"enable": true, "stack": "gvisor"}
        });
        let patch = ConfigPatch::parse(&json!({
            "mixed-port": 7899, "socks-port": 0, "allow-lan": true,
            "mode": "Global", "log-level": "debug", "tun": {"enable": false}, "ipv6": false
        }))
        .unwrap();
        assert!(patch.restarts());
        assert_eq!(patch.ignored, ["ipv6"]);
        patch.apply(&mut config);
        assert_eq!(
            config,
            json!({
                "mixed-port": 7899, "allow-lan": true, "mode": "global",
                "log": {"loglevel": "debug"}, "tun": {"enable": false, "stack": "gvisor"}
            })
        );
        let shape = configs_json(&config, RunMode::Global);
        assert_eq!(shape["mixed-port"], 7899);
        assert_eq!(shape["socks-port"], 0);
        assert_eq!(shape["allow-lan"], true);
        assert_eq!(shape["mode"], "global");
        assert_eq!(shape["tun"]["enable"], false);
        assert_eq!(shape["tun"]["stack"], "gvisor");
    }

    #[test]
    fn mode_and_level_alone_apply_in_place_and_bad_values_are_rejected() {
        let patch = ConfigPatch::parse(&json!({"mode": "direct", "log-level": "warn"})).unwrap();
        assert!(!patch.restarts());
        assert_eq!(patch.mode, Some(RunMode::Direct));
        assert_eq!(patch.log_level, Some(LogLevel::Warning));
        let mut config = json!({"log_level": "info"});
        patch.apply(&mut config);
        assert_eq!(config, json!({"mode": "direct", "log-level": "warning"}));
        assert!(ConfigPatch::parse(&json!({"mode": "script"})).is_err());
        assert!(ConfigPatch::parse(&json!({"mixed-port": 70000})).is_err());
        assert!(ConfigPatch::parse(&json!([])).is_err());
    }
}
