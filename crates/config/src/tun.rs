//! TUN 节点对全局配置的影响：出站防回环标记、出口网卡与限定本节点的 DNS 劫持规则。

use crate::NodeSpec;
use kerlico_core::{Error, InterfaceBinding, Result};
use kerlico_routing::{Network, RuleSpec};
use serde_json::Value;
use std::net::IpAddr;

/// 与 sing-box `auto_redirect_output_mark` 默认值一致。
const DEFAULT_OUTPUT_MARK: u32 = 0x2024;

fn option<'a>(node: &'a NodeSpec, keys: &[&str]) -> Option<&'a Value> {
    let map = node.options.as_object()?;
    keys.iter().find_map(|key| map.get(*key))
}

fn flag(node: &NodeSpec, keys: &[&str]) -> Option<bool> {
    option(node, keys).and_then(Value::as_bool)
}

fn auto_route(node: &NodeSpec) -> bool {
    flag(node, &["auto_route", "auto-route"]).unwrap_or(false)
        || option(
            node,
            &["auto_system_routing_table", "auto-system-routing-table"],
        )
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
}

fn tun_nodes<'a>(nodes: impl Iterator<Item = &'a NodeSpec>) -> impl Iterator<Item = &'a NodeSpec> {
    nodes.filter(|n| n.kind == "tun")
}

fn parse_mark(value: &Value) -> Result<u32> {
    let mark = match value {
        Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        Value::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => s.parse().ok(),
            }
        }
        _ => None,
    };
    mark.filter(|m| *m != 0)
        .ok_or_else(|| Error::Config("TUN auto_redirect_output_mark 不合法".into()))
}

/// 未显式配置 `routing-mark` 时，开启 auto-route 的 TUN 给全部出站套接字一个默认标记，
/// TUN 策略规则据此放行 kerlico 自身流量，避免回环进 TUN。仅 Linux 有 fwmark。
pub(crate) fn bypass_mark<'a>(nodes: impl Iterator<Item = &'a NodeSpec>) -> Result<Option<u32>> {
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    let Some(node) = tun_nodes(nodes).find(|n| auto_route(n)) else {
        return Ok(None);
    };
    match option(
        node,
        &["auto_redirect_output_mark", "auto-redirect-output-mark"],
    ) {
        Some(value) => parse_mark(value).map(Some),
        None => Ok(Some(DEFAULT_OUTPUT_MARK)),
    }
}

/// TUN 的 `auto_outbounds_interface` 指名网卡时绑定该网卡；开启 auto-route 且未关闭
/// `auto_detect_interface` 时返回 `AutoDetect`，排除列表由调用方补全。
pub(crate) fn interface<'a>(nodes: impl Iterator<Item = &'a NodeSpec>) -> Option<InterfaceBinding> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let mut auto = false;
    for node in tun_nodes(nodes) {
        if let Some(name) = option(
            node,
            &["auto_outbounds_interface", "auto-outbounds-interface"],
        )
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty() && !n.eq_ignore_ascii_case("auto"))
        {
            return Some(InterfaceBinding::Named(name.to_owned()));
        }
        let detect = flag(node, &["auto_detect_interface", "auto-detect-interface"]);
        auto |= detect.unwrap_or_else(|| auto_route(node));
    }
    auto.then(|| InterfaceBinding::AutoDetect {
        exclude: Vec::new(),
    })
}

/// `dns-hijack` 条目：`any:53`、`tcp://any:53`、`udp://8.8.8.8:53`、`[2001:db8::1]:53`。
struct Hijack {
    network: Option<Network>,
    ip: Option<IpAddr>,
    port: u16,
}

impl Hijack {
    fn parse(raw: &str) -> Result<Self> {
        let invalid = || Error::Config(format!("TUN dns_hijack 条目不合法：{raw}"));
        let text = raw.trim();
        let (network, rest) = match text.split_once("://") {
            Some(("udp", rest)) => (Some(Network::Udp), rest),
            Some(("tcp", rest)) => (Some(Network::Tcp), rest),
            Some(("any", rest)) => (None, rest),
            Some(_) => return Err(invalid()),
            None => (None, text),
        };
        let (host, port) = rest.rsplit_once(':').ok_or_else(invalid)?;
        let port: u16 = port.parse().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }
        let host = host.trim();
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let ip = match host.to_ascii_lowercase().as_str() {
            "" | "any" | "*" | "0.0.0.0" | "::" => None,
            other => Some(other.parse::<IpAddr>().map_err(|_| invalid())?),
        };
        Ok(Self { network, ip, port })
    }

    fn rule(&self, tag: &str) -> RuleSpec {
        RuleSpec {
            action: Some("hijack-dns".into()),
            node: vec![tag.to_owned()],
            network: self.network,
            ip_cidr: self.ip.map(|ip| ip.to_string()).into_iter().collect(),
            port: vec![self.port],
            ..Default::default()
        }
    }
}

/// 把每个 TUN 节点的 `dns_hijack` 与 `dns_mode: hijack` 编译为只匹配该节点来源的 `hijack-dns` 规则。
pub(crate) fn dns_hijack_rules<'a>(
    nodes: impl Iterator<Item = &'a NodeSpec>,
) -> Result<Vec<RuleSpec>> {
    let mut rules = Vec::new();
    for node in tun_nodes(nodes) {
        if let Some(entries) = option(node, &["dns_hijack", "dns-hijack"]) {
            let entries = entries
                .as_array()
                .ok_or_else(|| Error::Config("TUN dns_hijack 须为数组".into()))?;
            for entry in entries {
                let text = entry
                    .as_str()
                    .ok_or_else(|| Error::Config("TUN dns_hijack 条目须为字符串".into()))?;
                rules.push(Hijack::parse(text)?.rule(&node.tag));
            }
        }
        let mode = option(node, &["dns_mode", "dns-mode"]).and_then(Value::as_str);
        match mode.map(|m| m.trim().to_ascii_lowercase()).as_deref() {
            None | Some("disabled" | "none" | "off" | "native") => {}
            Some("hijack") => {
                let addresses: Vec<IpAddr> = option(node, &["dns_address", "dns-address", "dns"])
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|v| v.as_str()?.parse().ok()).collect())
                    .unwrap_or_default();
                if addresses.is_empty() {
                    rules.push(
                        Hijack {
                            network: None,
                            ip: None,
                            port: 53,
                        }
                        .rule(&node.tag),
                    );
                }
                for ip in addresses {
                    rules.push(
                        Hijack {
                            network: None,
                            ip: Some(ip),
                            port: 53,
                        }
                        .rule(&node.tag),
                    );
                }
            }
            Some(_) => return Err(Error::Config("TUN dns_mode 不合法".into())),
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(options: Value) -> NodeSpec {
        serde_json::from_value(json!({
            "tag": "tun-in", "type": "tun", "listen": "127.0.0.1:0",
            "outbound": "direct", "options": options,
        }))
        .unwrap()
    }

    #[test]
    fn dns_hijack_entries_become_node_scoped_rules() {
        let n = node(json!({"dns-hijack": ["any:53", "tcp://any:53", "udp://[2001:db8::1]:5353"]}));
        let rules = dns_hijack_rules([&n].into_iter()).unwrap();
        assert_eq!(rules.len(), 3);
        assert!(rules.iter().all(|r| r.node == ["tun-in"]));
        assert_eq!(rules[0].network, None);
        assert_eq!(rules[1].network, Some(Network::Tcp));
        assert_eq!(rules[2].ip_cidr, ["2001:db8::1"]);
        assert_eq!(rules[2].port, [5353]);
        assert!(
            dns_hijack_rules([&node(json!({"dns_hijack": ["ftp://x:53"]}))].into_iter()).is_err()
        );
        let mode = node(json!({"dns_mode": "hijack", "dns_address": ["10.0.0.53"]}));
        assert_eq!(
            dns_hijack_rules([&mode].into_iter()).unwrap()[0].ip_cidr,
            ["10.0.0.53"]
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn auto_route_defaults_mark_and_interface_detection() {
        let on = node(json!({"auto-route": true}));
        assert_eq!(
            bypass_mark([&on].into_iter()).unwrap(),
            Some(DEFAULT_OUTPUT_MARK)
        );
        assert!(matches!(
            interface([&on].into_iter()),
            Some(InterfaceBinding::AutoDetect { .. })
        ));
        let off = node(json!({"auto-route": true, "auto-detect-interface": false,
                              "auto-redirect-output-mark": "0x99"}));
        assert_eq!(bypass_mark([&off].into_iter()).unwrap(), Some(0x99));
        assert_eq!(interface([&off].into_iter()), None);
        let plain = node(json!({}));
        assert_eq!(bypass_mark([&plain].into_iter()).unwrap(), None);
    }
}
