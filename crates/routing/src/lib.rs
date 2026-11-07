//! 按目标、网络、节点、用户、来源、协议、规则集与 GeoData 选择命名出站或执行路由动作。

pub mod domain_set;
pub mod geodata;
pub mod ip_set;
pub mod mmdb;
pub mod mrs;
pub mod ruleset;
pub mod srs;
mod succinct;

pub use domain_set::{DomainRule, DomainSet};
pub use geodata::{
    GeoConfigSpec, GeoData, GeoFile, GeoIpMode, GeoIpRef, GeoNeeds, GeoPart, GeoSiteRef, GeoSlot,
    GeoxUrlSpec, export_geoip_ruleset, export_geosite_ruleset, is_private_ip,
};
pub use ip_set::IpSet;
pub use mrs::{Behavior, MrsPayload};
pub use ruleset::{
    CompiledHeadlessRule, CompiledRuleSet, DetectedFormat, HeadlessRuleSpec, LogicalMode,
    MihomoFormat, RemoteRuleSet, RuleProviderSpec, RuleSetFile, RuleSetFormat, RuleSetSource,
    RuleSetSpec, SingBoxFormat, SourceRuleSetFile, compile_ruleset_to_mrs, compile_ruleset_to_srs,
    convert_adguard_lines, decompile_ruleset_bytes, decompile_with_behavior, default_cache_path,
    detect_format, parse_ruleset_bytes, parse_update_interval, ruleset_to_mihomo_lines,
};

use arc_swap::ArcSwap;
use kerlico_core::{Address, Cidr, Destination, Error, NodeId, OutId, Result, Source, UserId};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResolveStrategy {
    #[serde(alias = "prefer-ipv4")]
    PreferIpv4,
    #[serde(alias = "prefer-ipv6")]
    PreferIpv6,
    #[serde(alias = "ipv4-only")]
    Ipv4Only,
    #[serde(alias = "ipv6-only")]
    Ipv6Only,
}

impl ResolveStrategy {
    pub fn filter_ips(self, ips: &[IpAddr]) -> Vec<IpAddr> {
        match self {
            Self::Ipv4Only => ips
                .iter()
                .copied()
                .filter(|ip| ip.to_canonical().is_ipv4())
                .collect(),
            Self::Ipv6Only => ips
                .iter()
                .copied()
                .filter(|ip| ip.to_canonical().is_ipv6())
                .collect(),
            Self::PreferIpv4 => {
                let mut v4: Vec<IpAddr> = ips
                    .iter()
                    .copied()
                    .filter(|ip| ip.to_canonical().is_ipv4())
                    .collect();
                let v6: Vec<IpAddr> = ips
                    .iter()
                    .copied()
                    .filter(|ip| ip.to_canonical().is_ipv6())
                    .collect();
                v4.extend(v6);
                v4
            }
            Self::PreferIpv6 => {
                let mut v6: Vec<IpAddr> = ips
                    .iter()
                    .copied()
                    .filter(|ip| ip.to_canonical().is_ipv6())
                    .collect();
                let v4: Vec<IpAddr> = ips
                    .iter()
                    .copied()
                    .filter(|ip| ip.to_canonical().is_ipv4())
                    .collect();
                v6.extend(v4);
                v6
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn parse(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(invalid());
        }
        if let Some((a, b)) = trimmed.split_once(':').or_else(|| trimmed.split_once('-')) {
            let start = if a.trim().is_empty() {
                1
            } else {
                a.trim().parse::<u16>().map_err(|_| invalid())?
            };
            let end = if b.trim().is_empty() {
                65535
            } else {
                b.trim().parse::<u16>().map_err(|_| invalid())?
            };
            if start == 0 || end == 0 || start > end {
                return Err(invalid());
            }
            Ok(Self { start, end })
        } else {
            let p = trimmed.parse::<u16>().map_err(|_| invalid())?;
            if p == 0 {
                return Err(invalid());
            }
            Ok(Self { start: p, end: p })
        }
    }

    pub fn contains(self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

/// 匹配域名通配符（支持 `*`、`**`、`?` 以及 Clash `.`、`*`、`+` 前缀语法）。
pub fn wildcard_domain_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let h = host
        .trim()
        .strip_suffix('.')
        .unwrap_or(host)
        .to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    if p == "*" || p == "**" || p == "+" || p == "." {
        return true;
    }
    if let Some(rest) = p.strip_prefix("+.") {
        return h == rest || h.strip_suffix(rest).is_some_and(|pre| pre.ends_with('.'));
    }
    if let Some(rest) = p.strip_prefix('.') {
        return h == rest || h.strip_suffix(rest).is_some_and(|pre| pre.ends_with('.'));
    }
    if !p.contains('*') && !p.contains('?') {
        return p == h;
    }
    // 将通配符转为正则：`**` 匹配跨级任意字符，`*` 匹配单级非 `.` 字符（除非是 `*.` 前缀匹配子域）
    if let Some(rest) = p.strip_prefix("*.")
        && !rest.contains('*')
        && !rest.contains('?')
    {
        return h.strip_suffix(rest).is_some_and(|pre| pre.ends_with('.'));
    }
    let mut regex_str = String::from("^");
    let chars: Vec<char> = p.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '*' {
            if i + 1 < chars.len() && chars[i + 1] == '*' {
                regex_str.push_str(".*");
                i += 2;
            } else {
                regex_str.push_str("[^.]*");
                i += 1;
            }
        } else if chars[i] == '?' {
            regex_str.push_str("[^.]");
            i += 1;
        } else {
            for esc in regex::escape(&chars[i].to_string()).chars() {
                regex_str.push(esc);
            }
            i += 1;
        }
    }
    regex_str.push('$');
    Regex::new(&regex_str).is_ok_and(|re| re.is_match(&h))
}

/// 同一字段内任一值命中即可，不同字段须同时满足；支持逻辑组合与路由动作。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    #[serde(default, alias = "outbound_tag", alias = "outbound-tag")]
    pub outbound: String,
    #[serde(default, alias = "balancer-tag", alias = "balancerTag")]
    pub balancer_tag: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default, alias = "override-address")]
    pub override_address: Option<String>,
    #[serde(default, alias = "override-port")]
    pub override_port: Option<u16>,
    #[serde(default)]
    pub strategy: Option<ResolveStrategy>,
    #[serde(default)]
    pub sniffer: Vec<String>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default, alias = "domain-suffix")]
    pub domain_suffix: Vec<String>,
    #[serde(default, alias = "domain-keyword")]
    pub domain_keyword: Vec<String>,
    #[serde(
        default,
        alias = "domain-regex",
        alias = "domain_regexp",
        alias = "domain-regexp"
    )]
    pub domain_regex: Vec<String>,
    #[serde(default, alias = "domain-wildcard")]
    pub domain_wildcard: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default, alias = "ip-cidr")]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub geoip: Vec<String>,
    /// 目标 IP 所属自治系统号（Mihomo `IP-ASN`），查 `ASN.mmdb`（旧名 `GeoLite2-ASN.mmdb`）。
    #[serde(default, alias = "ip-asn")]
    pub ip_asn: Vec<u32>,
    #[serde(
        default,
        alias = "source-geoip",
        alias = "src_geoip",
        alias = "src-geoip"
    )]
    pub source_geoip: Vec<String>,
    #[serde(
        default,
        alias = "source-ip-asn",
        alias = "src_ip_asn",
        alias = "src-ip-asn"
    )]
    pub source_ip_asn: Vec<u32>,
    #[serde(
        default,
        alias = "ip-is-private",
        alias = "geoip_private",
        alias = "geoip-private"
    )]
    pub ip_is_private: bool,
    #[serde(default, alias = "ip-version")]
    pub ip_version: Option<u8>,
    #[serde(default)]
    pub port: Vec<u16>,
    #[serde(default, alias = "port-range")]
    pub port_range: Vec<String>,
    #[serde(
        default,
        alias = "source-ip-cidr",
        alias = "src_ip_cidr",
        alias = "src-ip-cidr",
        alias = "source_ip",
        alias = "source-ip"
    )]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, alias = "source-port")]
    pub source_port: Vec<u16>,
    #[serde(default, alias = "source-port-range")]
    pub source_port_range: Vec<String>,
    #[serde(default)]
    pub network: Option<Network>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(
        default,
        alias = "rule-set",
        alias = "domain_set",
        alias = "domain-set"
    )]
    pub rule_set: Vec<String>,
    #[serde(default, alias = "not")]
    pub invert: bool,
    #[serde(
        default,
        rename = "type",
        alias = "logical_type",
        alias = "logical-type"
    )]
    pub logical_type: Option<String>,
    #[serde(
        default,
        rename = "mode",
        alias = "logical_mode",
        alias = "logical-mode"
    )]
    pub logical_mode: Option<String>,
    #[serde(
        default,
        rename = "rules",
        alias = "logical_rules",
        alias = "logical-rules"
    )]
    pub logical_rules: Vec<RuleSpec>,
    #[serde(default)]
    pub node: Vec<String>,
    #[serde(default)]
    pub user: Vec<String>,
    #[serde(default, alias = "process-name")]
    pub process_name: Vec<String>,
    #[serde(default, alias = "process-path")]
    pub process_path: Vec<String>,
    #[serde(
        default,
        alias = "process-name-regex",
        alias = "process_name_regexp",
        alias = "process-name-regexp"
    )]
    pub process_name_regex: Vec<String>,
    #[serde(
        default,
        alias = "process-path-regex",
        alias = "process_path_regexp",
        alias = "process-path-regexp"
    )]
    pub process_path_regex: Vec<String>,
    #[serde(default, alias = "sub-rule")]
    pub sub_rule: Option<String>,
    #[serde(default, alias = "in-type", alias = "inbound-type")]
    pub in_type: Vec<String>,
    #[serde(default, alias = "in-port", alias = "inbound-port")]
    pub in_port: Vec<u16>,
    #[serde(default)]
    pub dscp: Vec<u8>,
    #[serde(default)]
    pub uid: Vec<u32>,
    /// Mihomo IP 类规则（`IP-CIDR`、`GEOIP`、含 IP 的 `RULE-SET`）未写 `no-resolve` 时为真：
    /// 目标是域名时先经 DNS 解析，再用解析结果匹配；不改变发往远端的目标。
    #[serde(
        default,
        alias = "resolve-ip",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub resolve_ip: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteAction {
    Route {
        outbound: Option<OutId>,
        balancer_tag: Option<String>,
        override_address: Option<String>,
        override_port: Option<u16>,
    },
    RouteOptions {
        override_address: Option<String>,
        override_port: Option<u16>,
    },
    Resolve {
        strategy: ResolveStrategy,
    },
    Sniff {
        sniffer: Vec<String>,
        timeout: Duration,
    },
    SubRule {
        name: String,
    },
    HijackDns,
    Reject,
}

/// 规则在 Clash API 中的展示形式：Mihomo 规则类型名与匹配载荷。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuleLabel {
    pub kind: String,
    pub payload: String,
}

impl RuleLabel {
    pub fn matched_final() -> Self {
        Self {
            kind: "Match".into(),
            payload: String::new(),
        }
    }

    /// 单字段规则直接取该字段；多字段规则按 sing-box 语义是逻辑与，展示为 `AND`。
    fn of(spec: &RuleSpec) -> Self {
        if spec.logical_type.is_some() {
            let kind = spec
                .logical_mode
                .as_deref()
                .unwrap_or("and")
                .trim()
                .to_ascii_uppercase();
            let payload = spec
                .logical_rules
                .iter()
                .map(|child| Self::of(child).nested())
                .collect::<Vec<_>>()
                .join(",");
            return Self { kind, payload }.inverted(spec.invert);
        }
        let mut parts = Vec::new();
        let mut push = |kind: &str, values: Vec<String>| {
            if !values.is_empty() {
                parts.push(Self {
                    kind: kind.into(),
                    payload: values.join(","),
                });
            }
        };
        let text = |values: &[String]| values.to_vec();
        // Mihomo 的 GEOIP 载荷总以小写国家代码展示。
        let lower = |values: &[String]| values.iter().map(|v| v.to_ascii_lowercase()).collect();
        let shown = |values: &[u16]| values.iter().map(u16::to_string).collect::<Vec<_>>();
        push("Domain", text(&spec.domain));
        push("DomainSuffix", text(&spec.domain_suffix));
        push("DomainKeyword", text(&spec.domain_keyword));
        push("DomainRegex", text(&spec.domain_regex));
        push("DomainWildcard", text(&spec.domain_wildcard));
        push("GeoSite", text(&spec.geosite));
        push("IPCIDR", text(&spec.ip_cidr));
        push("GeoIP", lower(&spec.geoip));
        push("IPASN", spec.ip_asn.iter().map(u32::to_string).collect());
        push("SrcGeoIP", lower(&spec.source_geoip));
        push(
            "SrcIPASN",
            spec.source_ip_asn.iter().map(u32::to_string).collect(),
        );
        if spec.ip_is_private {
            push("GeoIP", vec!["private".into()]);
        }
        push(
            "IPVersion",
            spec.ip_version.iter().map(u8::to_string).collect(),
        );
        let mut dst_ports = shown(&spec.port);
        dst_ports.extend(spec.port_range.iter().cloned());
        push("DstPort", dst_ports);
        push("SrcIPCIDR", text(&spec.source_ip_cidr));
        let mut src_ports = shown(&spec.source_port);
        src_ports.extend(spec.source_port_range.iter().cloned());
        push("SrcPort", src_ports);
        push(
            "Network",
            spec.network
                .iter()
                .map(|n| match n {
                    Network::Tcp => "tcp".to_owned(),
                    Network::Udp => "udp".to_owned(),
                })
                .collect(),
        );
        push("Protocol", text(&spec.protocol));
        push("RuleSet", text(&spec.rule_set));
        push("InName", text(&spec.node));
        push("InUser", text(&spec.user));
        push("ProcessName", text(&spec.process_name));
        push("ProcessPath", text(&spec.process_path));
        push("ProcessNameRegex", text(&spec.process_name_regex));
        push("ProcessPathRegex", text(&spec.process_path_regex));
        push("InType", text(&spec.in_type));
        push("InPort", shown(&spec.in_port));
        push("DSCP", spec.dscp.iter().map(u8::to_string).collect());
        push("Uid", spec.uid.iter().map(u32::to_string).collect());
        let label = match parts.len() {
            0 => Self::matched_final(),
            1 => parts.remove(0),
            _ => Self {
                kind: "AND".into(),
                payload: parts.iter().map(Self::nested).collect::<Vec<_>>().join(","),
            },
        };
        label.inverted(spec.invert)
    }

    fn nested(&self) -> String {
        format!("({},{})", self.kind, self.payload)
    }

    fn inverted(self, invert: bool) -> Self {
        if invert {
            Self {
                kind: "NOT".into(),
                payload: self.nested(),
            }
        } else {
            self
        }
    }
}

/// 顶层规则表的一行：展示标签、动作目标与命中统计。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleEntry {
    pub label: RuleLabel,
    pub proxy: String,
    pub stats: RuleStats,
}

/// Mihomo `RuleWrapper` 的统计：顶层规则每次参与路由求值时计一次命中或未命中，
/// 时间为 Unix 毫秒，从未发生时为 0。路由表重新编译（重载配置）后归零。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuleStats {
    pub hit_count: u64,
    pub hit_at_ms: u64,
    pub miss_count: u64,
    pub miss_at_ms: u64,
}

#[derive(Debug, Default)]
struct RuleCounter {
    hit_count: AtomicU64,
    hit_at_ms: AtomicU64,
    miss_count: AtomicU64,
    miss_at_ms: AtomicU64,
}

impl RuleCounter {
    fn record(&self, hit: bool) {
        let now = kerlico_core::log::unix_ms();
        if hit {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
            self.hit_at_ms.store(now, Ordering::Relaxed);
        } else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            self.miss_at_ms.store(now, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> RuleStats {
        RuleStats {
            hit_count: self.hit_count.load(Ordering::Relaxed),
            hit_at_ms: self.hit_at_ms.load(Ordering::Relaxed),
            miss_count: self.miss_count.load(Ordering::Relaxed),
            miss_at_ms: self.miss_at_ms.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
struct Rule {
    action: RouteAction,
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    domain_regex: Vec<Regex>,
    domain_wildcard: Vec<String>,
    geosite: Vec<GeoSiteRef>,
    ip_cidr: Vec<Cidr>,
    geoip: Vec<GeoIpRef>,
    ip_asn: Vec<u32>,
    source_geoip: Vec<GeoIpRef>,
    source_ip_asn: Vec<u32>,
    ip_is_private: bool,
    ip_version: Option<u8>,
    port: Vec<u16>,
    port_range: Vec<PortRange>,
    source_ip_cidr: Vec<Cidr>,
    source_port: Vec<u16>,
    source_port_range: Vec<PortRange>,
    network: Option<Network>,
    protocol: Vec<String>,
    rule_set: Vec<String>,
    process_name: Vec<String>,
    process_path: Vec<String>,
    process_name_regex: Vec<Regex>,
    process_path_regex: Vec<Regex>,
    invert: bool,
    logical: Option<(LogicalMode, Vec<Rule>)>,
    node: Vec<NodeId>,
    user: Vec<UserId>,
    label: RuleLabel,
    resolve_ip: bool,
}

fn parse_duration_opt(raw: Option<&str>, default_ms: u64) -> Result<Duration> {
    let Some(s) = raw else {
        return Ok(Duration::from_millis(default_ms));
    };
    let trimmed = s.trim();
    if let Some(ms) = trimmed.strip_suffix("ms") {
        let v: u64 = ms.trim().parse().map_err(|_| invalid())?;
        if v == 0 {
            return Err(invalid());
        }
        return Ok(Duration::from_millis(v));
    }
    if let Some(sec) = trimmed.strip_suffix('s') {
        let v: u64 = sec.trim().parse().map_err(|_| invalid())?;
        if v == 0 {
            return Err(invalid());
        }
        return Ok(Duration::from_secs(v));
    }
    let v: u64 = trimmed.parse().map_err(|_| invalid())?;
    if v == 0 {
        return Err(invalid());
    }
    Ok(Duration::from_millis(v))
}

impl Rule {
    fn compile(spec: &RuleSpec) -> Result<Self> {
        Self::compile_inner(spec, false)
    }

    fn compile_inner(spec: &RuleSpec, is_child: bool) -> Result<Self> {
        if !spec.in_type.is_empty()
            || !spec.in_port.is_empty()
            || !spec.dscp.is_empty()
            || !spec.uid.is_empty()
        {
            return Err(Error::Config(
                "路由条件 in_type、in_port、dscp、uid 尚未支持".into(),
            ));
        }
        let action = if is_child {
            RouteAction::Route {
                outbound: None,
                balancer_tag: None,
                override_address: None,
                override_port: None,
            }
        } else if let Some(sub) = spec
            .sub_rule
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            RouteAction::SubRule {
                name: sub.to_owned(),
            }
        } else {
            let act_name = spec.action.as_deref().unwrap_or("route");
            match act_name {
                "route" => {
                    let outbound = if spec.outbound.is_empty() {
                        None
                    } else {
                        Some(OutId::parse(&spec.outbound)?)
                    };
                    let balancer_tag = spec
                        .balancer_tag
                        .as_deref()
                        .filter(|s| !s.trim().is_empty())
                        .map(ToOwned::to_owned);
                    if outbound.is_none() && balancer_tag.is_none() {
                        return Err(invalid());
                    }
                    if let Some(addr) = &spec.override_address {
                        Destination::new(addr, 1).map_err(|_| invalid())?;
                    }
                    if spec.override_port == Some(0) {
                        return Err(invalid());
                    }
                    RouteAction::Route {
                        outbound,
                        balancer_tag,
                        override_address: spec.override_address.clone(),
                        override_port: spec.override_port,
                    }
                }
                "sub-rule" => {
                    let name = spec
                        .sub_rule
                        .as_deref()
                        .or((!spec.outbound.is_empty()).then_some(spec.outbound.as_str()))
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .ok_or_else(invalid)?
                        .to_owned();
                    RouteAction::SubRule { name }
                }
                "route-options" => {
                    if spec.override_address.is_none() && spec.override_port.is_none() {
                        return Err(invalid());
                    }
                    if let Some(addr) = &spec.override_address {
                        Destination::new(addr, 1).map_err(|_| invalid())?;
                    }
                    if spec.override_port == Some(0) {
                        return Err(invalid());
                    }
                    RouteAction::RouteOptions {
                        override_address: spec.override_address.clone(),
                        override_port: spec.override_port,
                    }
                }
                "resolve" => RouteAction::Resolve {
                    strategy: spec.strategy.unwrap_or(ResolveStrategy::PreferIpv4),
                },
                "sniff" => RouteAction::Sniff {
                    sniffer: spec
                        .sniffer
                        .iter()
                        .map(|s| s.trim().to_ascii_lowercase())
                        .collect(),
                    timeout: parse_duration_opt(spec.timeout.as_deref(), 300)?,
                },
                "hijack-dns" => RouteAction::HijackDns,
                "reject" => RouteAction::Reject,
                _ => return Err(invalid()),
            }
        };

        if let Some(ltype) = &spec.logical_type {
            if !ltype.eq_ignore_ascii_case("logical") {
                return Err(invalid());
            }
            let mode_str = spec.logical_mode.as_deref().ok_or_else(invalid)?;
            let mode = LogicalMode::parse(mode_str)?;
            if spec.logical_rules.is_empty() {
                return Err(invalid());
            }
            let children = spec
                .logical_rules
                .iter()
                .map(|c| Self::compile_inner(c, true))
                .collect::<Result<Vec<_>>>()?;
            return Ok(Self {
                label: RuleLabel::of(spec),
                resolve_ip: spec.resolve_ip,
                action,
                domain: Vec::new(),
                domain_suffix: Vec::new(),
                domain_keyword: Vec::new(),
                domain_regex: Vec::new(),
                domain_wildcard: Vec::new(),
                geosite: Vec::new(),
                ip_cidr: Vec::new(),
                geoip: Vec::new(),
                ip_asn: Vec::new(),
                source_geoip: Vec::new(),
                source_ip_asn: Vec::new(),
                ip_is_private: false,
                ip_version: None,
                port: Vec::new(),
                port_range: Vec::new(),
                source_ip_cidr: Vec::new(),
                source_port: Vec::new(),
                source_port_range: Vec::new(),
                network: spec.network,
                protocol: Vec::new(),
                rule_set: Vec::new(),
                process_name: Vec::new(),
                process_path: Vec::new(),
                process_name_regex: Vec::new(),
                process_path_regex: Vec::new(),
                invert: spec.invert,
                logical: Some((mode, children)),
                node: spec
                    .node
                    .iter()
                    .map(|v| NodeId::parse(v))
                    .collect::<Result<_>>()?,
                user: spec
                    .user
                    .iter()
                    .map(|v| UserId::parse(v))
                    .collect::<Result<_>>()?,
            });
        }

        if let Some(ver) = spec.ip_version
            && ver != 4
            && ver != 6
        {
            return Err(invalid());
        }

        let rule = Self {
            label: RuleLabel::of(spec),
            resolve_ip: spec.resolve_ip,
            action,
            domain: spec
                .domain
                .iter()
                .map(|v| domain(v))
                .collect::<Result<_>>()?,
            domain_suffix: spec
                .domain_suffix
                .iter()
                .map(|v| domain(v.strip_prefix('.').unwrap_or(v)))
                .collect::<Result<_>>()?,
            domain_keyword: spec
                .domain_keyword
                .iter()
                .map(|v| v.to_ascii_lowercase())
                .collect(),
            domain_regex: spec
                .domain_regex
                .iter()
                .map(|v| Regex::new(v).map_err(|_| invalid()))
                .collect::<Result<_>>()?,
            domain_wildcard: spec
                .domain_wildcard
                .iter()
                .map(|v| {
                    if v.trim().is_empty() {
                        Err(invalid())
                    } else {
                        Ok(v.trim().to_ascii_lowercase())
                    }
                })
                .collect::<Result<_>>()?,
            geosite: spec
                .geosite
                .iter()
                .map(|v| GeoSiteRef::parse(v))
                .collect::<Result<_>>()?,
            ip_cidr: spec
                .ip_cidr
                .iter()
                .map(|v| Cidr::parse(v).map_err(|_| invalid()))
                .collect::<Result<_>>()?,
            geoip: spec
                .geoip
                .iter()
                .map(|v| GeoIpRef::parse(v))
                .collect::<Result<_>>()?,
            ip_asn: spec.ip_asn.clone(),
            source_geoip: spec
                .source_geoip
                .iter()
                .map(|v| GeoIpRef::parse(v))
                .collect::<Result<_>>()?,
            source_ip_asn: spec.source_ip_asn.clone(),
            ip_is_private: spec.ip_is_private,
            ip_version: spec.ip_version,
            port: spec.port.clone(),
            port_range: spec
                .port_range
                .iter()
                .map(|v| PortRange::parse(v))
                .collect::<Result<_>>()?,
            source_ip_cidr: spec
                .source_ip_cidr
                .iter()
                .map(|v| Cidr::parse(v).map_err(|_| invalid()))
                .collect::<Result<_>>()?,
            source_port: spec.source_port.clone(),
            source_port_range: spec
                .source_port_range
                .iter()
                .map(|v| PortRange::parse(v))
                .collect::<Result<_>>()?,
            network: spec.network,
            protocol: spec
                .protocol
                .iter()
                .map(|v| v.trim().to_ascii_lowercase())
                .collect(),
            rule_set: spec.rule_set.clone(),
            process_name: spec
                .process_name
                .iter()
                .map(|v| {
                    let t = v.trim();
                    if t.is_empty() {
                        Err(invalid())
                    } else {
                        Ok(t.to_ascii_lowercase())
                    }
                })
                .collect::<Result<_>>()?,
            process_path: spec
                .process_path
                .iter()
                .map(|v| {
                    let t = v.trim();
                    if t.is_empty() {
                        Err(invalid())
                    } else {
                        Ok(t.to_owned())
                    }
                })
                .collect::<Result<_>>()?,
            process_name_regex: spec
                .process_name_regex
                .iter()
                .map(|v| Regex::new(v).map_err(|_| invalid()))
                .collect::<Result<_>>()?,
            process_path_regex: spec
                .process_path_regex
                .iter()
                .map(|v| Regex::new(v).map_err(|_| invalid()))
                .collect::<Result<_>>()?,
            invert: spec.invert,
            logical: None,
            node: spec
                .node
                .iter()
                .map(|v| NodeId::parse(v))
                .collect::<Result<_>>()?,
            user: spec
                .user
                .iter()
                .map(|v| UserId::parse(v))
                .collect::<Result<_>>()?,
        };
        let empty = rule.domain.is_empty()
            && rule.domain_suffix.is_empty()
            && rule.domain_keyword.is_empty()
            && rule.domain_regex.is_empty()
            && rule.domain_wildcard.is_empty()
            && rule.geosite.is_empty()
            && rule.ip_cidr.is_empty()
            && rule.geoip.is_empty()
            && rule.ip_asn.is_empty()
            && rule.source_geoip.is_empty()
            && rule.source_ip_asn.is_empty()
            && !rule.ip_is_private
            && rule.ip_version.is_none()
            && rule.port.is_empty()
            && rule.port_range.is_empty()
            && rule.source_ip_cidr.is_empty()
            && rule.source_port.is_empty()
            && rule.source_port_range.is_empty()
            && rule.network.is_none()
            && rule.protocol.is_empty()
            && rule.rule_set.is_empty()
            && rule.process_name.is_empty()
            && rule.process_path.is_empty()
            && rule.process_name_regex.is_empty()
            && rule.process_path_regex.is_empty()
            && rule.node.is_empty()
            && rule.user.is_empty()
            && !matches!(
                rule.action,
                RouteAction::Sniff { .. }
                    | RouteAction::Resolve { .. }
                    | RouteAction::SubRule { .. }
            );
        if empty
            || rule
                .domain_keyword
                .iter()
                .any(|keyword| keyword.is_empty() || !keyword.is_ascii())
        {
            return Err(invalid());
        }
        Ok(rule)
    }

    /// 是否为匹配需要目标 IP：`resolve_ip` 且规则本身（或其规则集、子条件）含 IP 条件。
    fn wants_ip(&self, sets: &HashMap<String, RuleSetSlot>) -> bool {
        self.resolve_ip && self.has_ip_conditions(sets)
    }

    fn has_ip_conditions(&self, sets: &HashMap<String, RuleSetSlot>) -> bool {
        !self.ip_cidr.is_empty()
            || !self.geoip.is_empty()
            || self.ip_is_private
            || self.ip_version.is_some()
            || self.rule_set.iter().any(|tag| {
                sets.get(tag)
                    .is_some_and(|slot| !slot.load().cidr_strings().is_empty())
            })
            || self
                .logical
                .as_ref()
                .is_some_and(|(_, children)| children.iter().any(|c| c.has_ip_conditions(sets)))
    }

    fn has_process_rules(&self) -> bool {
        if !self.process_name.is_empty()
            || !self.process_path.is_empty()
            || !self.process_name_regex.is_empty()
            || !self.process_path_regex.is_empty()
        {
            return true;
        }
        if let Some((_, children)) = &self.logical {
            return children.iter().any(Self::has_process_rules);
        }
        false
    }

    fn collect_geo(&self, needs: &mut GeoNeeds) {
        for site in &self.geosite {
            needs.add_site(site);
        }
        for ip in self.geoip.iter().chain(&self.source_geoip) {
            needs.add_ip(ip);
        }
        needs.asn |= !self.ip_asn.is_empty() || !self.source_ip_asn.is_empty();
        if let Some((_, children)) = &self.logical {
            for child in children {
                child.collect_geo(needs);
            }
        }
    }

    fn matches_ctx(
        &self,
        ctx: &RouteContext<'_>,
        sets: &HashMap<String, RuleSetSlot>,
        geo: &GeoData,
    ) -> bool {
        if let Some((mode, children)) = &self.logical {
            let child_hit = match mode {
                LogicalMode::And => children.iter().all(|c| c.matches_ctx(ctx, sets, geo)),
                LogicalMode::Or => children.iter().any(|c| c.matches_ctx(ctx, sets, geo)),
            };
            let hit = if self.invert { !child_hit } else { child_hit };
            return hit
                && self.network.is_none_or(|value| value == ctx.network)
                && (self.node.is_empty() || self.node.contains(ctx.source.node()))
                && (self.user.is_empty()
                    || ctx
                        .source
                        .user()
                        .is_some_and(|user| self.user.contains(&user)));
        }

        let mut candidate_hosts = Vec::with_capacity(2);
        if let Address::Domain(name) = ctx.target.address() {
            candidate_hosts.push(name.strip_suffix('.').unwrap_or(name));
        }
        if let Some(sniffed) = ctx.sniffed_domain {
            let s = sniffed.strip_suffix('.').unwrap_or(sniffed);
            if !candidate_hosts.contains(&s) {
                candidate_hosts.push(s);
            }
        }
        let lowered_hosts: Vec<std::borrow::Cow<'_, str>> = candidate_hosts
            .iter()
            .map(|h| {
                if h.bytes().any(|b| b.is_ascii_uppercase()) {
                    std::borrow::Cow::Owned(h.to_ascii_lowercase())
                } else {
                    std::borrow::Cow::Borrowed(*h)
                }
            })
            .collect();

        let mut candidate_ips = Vec::with_capacity(1 + ctx.resolved_ips.len());
        if let Address::Ip(ip) = ctx.target.address() {
            candidate_ips.push(ip.to_canonical());
        }
        for &ip in ctx.resolved_ips {
            let c = ip.to_canonical();
            if !candidate_ips.contains(&c) {
                candidate_ips.push(c);
            }
        }

        let has_domain_cond = !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.domain_wildcard.is_empty()
            || !self.geosite.is_empty();
        let has_ip_cond = !self.ip_cidr.is_empty()
            || !self.geoip.is_empty()
            || !self.ip_asn.is_empty()
            || self.ip_is_private
            || self.ip_version.is_some();
        let has_ruleset_cond = !self.rule_set.is_empty();

        let name_hit = candidate_hosts.iter().any(|&host| {
            self.domain.iter().any(|value| value == host)
                || self.domain_suffix.iter().any(|value| {
                    host == value
                        || host
                            .strip_suffix(value.as_str())
                            .is_some_and(|rest| rest.ends_with('.'))
                })
                || self
                    .domain_keyword
                    .iter()
                    .any(|value| host.contains(value.as_str()))
                || self.domain_regex.iter().any(|re| re.is_match(host))
                || self
                    .domain_wildcard
                    .iter()
                    .any(|w| wildcard_domain_matches(w, host))
        }) || lowered_hosts
            .iter()
            .any(|host| self.geosite.iter().any(|site| geo.site_matches(site, host)));

        let ip_hit = candidate_ips.iter().any(|&ip| {
            self.ip_cidr.iter().any(|cidr| cidr.contains(ip))
                || self.geoip.iter().any(|code| geo.ip_matches(code, ip))
                || self.ip_asn.iter().any(|&asn| geo.asn_matches(asn, ip))
                || (self.ip_is_private && geodata::is_private_ip(ip))
                || self
                    .ip_version
                    .is_some_and(|ver| matches!((ver, ip), (4, IpAddr::V4(_)) | (6, IpAddr::V6(_))))
        });

        let ruleset_hit = self.rule_set.iter().any(|tag| {
            sets.get(tag).is_some_and(|slot| {
                slot.load().matches_with_process(
                    &candidate_hosts,
                    &candidate_ips,
                    ctx.target.port(),
                    ctx.network,
                    ctx.source_addr,
                    ctx.process_name,
                    ctx.process_path,
                )
            })
        });

        // 域名条件、CIDR/GeoIP 与 rule_set 都描述目标匹配，任一命中即满足目标条件。
        let target_ok = (!has_domain_cond && !has_ip_cond && !has_ruleset_cond)
            || name_hit
            || ip_hit
            || ruleset_hit;

        let port_ok = (self.port.is_empty() && self.port_range.is_empty())
            || self.port.contains(&ctx.target.port())
            || self
                .port_range
                .iter()
                .any(|r| r.contains(ctx.target.port()));

        let src_ip_ok = self.source_ip_cidr.is_empty()
            || ctx.source_addr.is_some_and(|sa| {
                self.source_ip_cidr
                    .iter()
                    .any(|c| c.contains(sa.ip().to_canonical()))
            });

        let src_port_ok = (self.source_port.is_empty() && self.source_port_range.is_empty())
            || ctx.source_addr.is_some_and(|sa| {
                self.source_port.contains(&sa.port())
                    || self.source_port_range.iter().any(|r| r.contains(sa.port()))
            });

        let src_geo_ok = (self.source_geoip.is_empty() && self.source_ip_asn.is_empty())
            || ctx.source_addr.is_some_and(|sa| {
                let ip = sa.ip().to_canonical();
                self.source_geoip
                    .iter()
                    .any(|code| geo.ip_matches(code, ip))
                    || self
                        .source_ip_asn
                        .iter()
                        .any(|&asn| geo.asn_matches(asn, ip))
            });

        let proto_ok = self.protocol.is_empty()
            || ctx.protocol.is_some_and(|p| {
                self.protocol
                    .iter()
                    .any(|item| item == &p.to_ascii_lowercase())
            });

        let proc_name_ok = (self.process_name.is_empty() && self.process_name_regex.is_empty())
            || ctx
                .process_name
                .or_else(|| {
                    ctx.process_path
                        .and_then(|p| p.rsplit(['/', '\\']).next().filter(|s| !s.is_empty()))
                })
                .is_some_and(|pn| {
                    let lower = pn.to_ascii_lowercase();
                    self.process_name.iter().any(|item| item == &lower)
                        || self.process_name_regex.iter().any(|re| re.is_match(pn))
                });

        let proc_path_ok = (self.process_path.is_empty() && self.process_path_regex.is_empty())
            || ctx.process_path.is_some_and(|pp| {
                self.process_path.iter().any(|item| item == pp)
                    || self.process_path_regex.iter().any(|re| re.is_match(pp))
            });

        let core_match = target_ok
            && port_ok
            && src_ip_ok
            && src_port_ok
            && src_geo_ok
            && proto_ok
            && proc_name_ok
            && proc_path_ok
            && self.network.is_none_or(|value| value == ctx.network)
            && (self.node.is_empty() || self.node.contains(ctx.source.node()))
            && (self.user.is_empty()
                || ctx
                    .source
                    .user()
                    .is_some_and(|user| self.user.contains(&user)));

        if self.invert { !core_match } else { core_match }
    }
}

fn invalid() -> Error {
    Error::Config("路由规则不合法".into())
}

fn domain(value: &str) -> Result<String> {
    match Destination::new(value, 1).map_err(|_| invalid())?.address() {
        Address::Domain(name) => Ok(name.strip_suffix('.').unwrap_or(name).to_owned()),
        Address::Ip(_) => Err(invalid()),
    }
}

#[derive(Clone, Copy)]
pub struct RouteContext<'a> {
    pub target: &'a Destination,
    pub resolved_ips: &'a [IpAddr],
    pub network: Network,
    pub source: &'a Source,
    pub source_addr: Option<SocketAddr>,
    pub protocol: Option<&'a str>,
    pub sniffed_domain: Option<&'a str>,
    pub process_name: Option<&'a str>,
    pub process_path: Option<&'a str>,
}

/// 规则求值是否允许为 IP 规则解析域名目标。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// 不解析（控制面测试、DNS 劫持判定等同步场景）。
    Never,
    /// 遇到需要 IP 的规则时停止，由调用方解析。
    Pending,
    /// 已解析（可能为空），`resolved_ips` 只对该顶层序号起的规则可见。
    From(usize),
}

impl<'a> RouteContext<'a> {
    fn without_resolved_ips(&self) -> Self {
        Self {
            resolved_ips: &[],
            ..*self
        }
    }

    pub fn simple(target: &'a Destination, network: Network, source: &'a Source) -> Self {
        Self {
            target,
            resolved_ips: &[],
            network,
            source,
            source_addr: None,
            protocol: None,
            sniffed_domain: None,
            process_name: None,
            process_path: None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteDecision {
    pub outbound: Option<OutId>,
    pub balancer_tag: Option<String>,
    pub hijack_dns: bool,
    pub reject: bool,
    pub override_address: Option<String>,
    pub override_port: Option<u16>,
    pub resolve_strategy: Option<ResolveStrategy>,
    /// `Resolution::Pending` 求值停在此顶层规则，需要先解析目标域名。
    pub resolve_at: Option<usize>,
    pub sniff: Option<(Vec<String>, Duration)>,
    /// 产生终结动作的规则；命中最终出站时为 `Match`。
    pub rule: Option<RuleLabel>,
}

/// 运行中规则集的替换点：路由表的各个克隆共享同一槽，刷新任务整体换入新编译结果，匹配无锁读取。
#[derive(Clone, Debug)]
pub struct RuleSetSlot(Arc<ArcSwap<CompiledRuleSet>>);

impl RuleSetSlot {
    pub fn new(set: CompiledRuleSet) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(set)))
    }

    pub fn load(&self) -> Arc<CompiledRuleSet> {
        self.0.load_full()
    }

    pub fn replace(&self, set: CompiledRuleSet) {
        self.0.store(Arc::new(set));
    }
}

/// 一次求值在规则树中的位置：嵌套深度、所属顶层规则序号、解析模式与是否计入统计。
#[derive(Clone, Copy)]
struct Scope {
    depth: usize,
    top: usize,
    mode: Resolution,
    record: bool,
}

/// 按配置顺序匹配，非终结动作（`sniff`、`resolve`、`route-options`）累积后继续，首条终结动作生效。
#[derive(Clone, Debug, Default)]
pub struct RouteTable {
    rules: Vec<Rule>,
    /// 每条顶层规则一个计数器，末尾一个给最终出站（`Match` 行）；克隆共享。
    counters: Arc<[RuleCounter]>,
    sets: HashMap<String, RuleSetSlot>,
    geo: GeoSlot,
    sub_rules: HashMap<String, Vec<Rule>>,
    final_outbound: Option<OutId>,
}

/// DNS 策略与嗅探器的 `rule-set:`、`geosite:`、`geoip:` 条目读运行中的规则集与 `GeoSlot`，
/// 刷新后换入的新数据立即生效。
impl kerlico_core::SetLookup for RouteTable {
    fn has_rule_set(&self, tag: &str) -> bool {
        RouteTable::has_rule_set(self, tag)
    }
    fn rule_set_matches_domain(&self, tag: &str, host: &str) -> bool {
        self.rule_set(tag)
            .is_some_and(|slot| slot.load().matches(&[host], &[], 0, Network::Udp, None))
    }
    fn rule_set_matches_ip(&self, tag: &str, ip: IpAddr) -> bool {
        self.rule_set(tag)
            .is_some_and(|slot| slot.load().matches(&[], &[ip], 0, Network::Udp, None))
    }
    fn geosite_matches(&self, code: &str, host: &str) -> bool {
        GeoSiteRef::parse(code).is_ok_and(|site| self.geo.load().site_matches(&site, host))
    }
    fn geoip_matches(&self, code: &str, ip: IpAddr) -> bool {
        GeoIpRef::parse(code).is_ok_and(|geoip| self.geo.load().ip_matches(&geoip, ip))
    }
}

impl RouteTable {
    pub fn compile(specs: &[RuleSpec]) -> Result<Self> {
        Self::compile_with_sets(specs, HashMap::new())
    }

    pub fn compile_with_sets(
        specs: &[RuleSpec],
        sets: HashMap<String, CompiledRuleSet>,
    ) -> Result<Self> {
        let rules: Vec<Rule> = specs.iter().map(Rule::compile).collect::<Result<_>>()?;
        Ok(Self {
            counters: (0..=rules.len()).map(|_| RuleCounter::default()).collect(),
            rules,
            sets: sets
                .into_iter()
                .map(|(tag, set)| (tag, RuleSetSlot::new(set)))
                .collect(),
            geo: GeoSlot::default(),
            sub_rules: HashMap::new(),
            final_outbound: None,
        })
    }

    pub fn with_sub_rules(
        mut self,
        sub_rules: &std::collections::BTreeMap<String, Vec<RuleSpec>>,
    ) -> Result<Self> {
        for (name, specs) in sub_rules {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(invalid());
            }
            let compiled = specs
                .iter()
                .map(Rule::compile)
                .collect::<Result<Vec<_>>>()?;
            self.sub_rules.insert(trimmed.to_owned(), compiled);
        }
        for rule in &self.rules {
            if let RouteAction::SubRule { name } = &rule.action
                && !self.sub_rules.contains_key(name)
            {
                return Err(Error::Config(format!(
                    "路由规则引用的 sub-rule 不存在：{name}"
                )));
            }
        }
        Ok(self)
    }

    /// 按规则引用的 Geo 分类与 GEOIP 数据来源建立 Geo 槽；须在规则与 sub-rule 编译完成后调用。
    pub fn with_geo_mode(self, mode: GeoIpMode) -> Self {
        self.with_geo(mode, &GeoNeeds::default())
    }

    /// 同 [`Self::with_geo_mode`]，并把路由规则之外（如 DNS 策略）引用的 Geo 数据并入同一槽。
    pub fn with_geo(mut self, mode: GeoIpMode, extra: &GeoNeeds) -> Self {
        let mut needs = self.geo_needs();
        for site in extra.sites.values() {
            needs.add_site(site);
        }
        needs.ip_codes.extend(extra.ip_codes.iter().cloned());
        needs.asn |= extra.asn;
        self.geo = GeoSlot::new(mode, needs);
        self
    }

    pub fn geo_needs(&self) -> GeoNeeds {
        let mut needs = GeoNeeds::default();
        for rule in self.rules.iter().chain(self.sub_rules.values().flatten()) {
            rule.collect_geo(&mut needs);
        }
        needs
    }

    pub fn geo(&self) -> &GeoSlot {
        &self.geo
    }

    pub fn with_final_outbound(mut self, final_outbound: Option<OutId>) -> Self {
        self.final_outbound = final_outbound;
        self
    }

    pub fn has_rule_set(&self, tag: &str) -> bool {
        self.sets.contains_key(tag)
    }

    pub fn rule_set(&self, tag: &str) -> Option<&RuleSetSlot> {
        self.sets.get(tag)
    }

    /// 是否配置了任何规则；无规则时流量只走节点绑定出站。
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }

    pub fn has_sniff_rules(&self) -> bool {
        self.rules
            .iter()
            .chain(self.sub_rules.values().flatten())
            .any(|r| matches!(r.action, RouteAction::Sniff { .. }))
    }

    pub fn has_hijack_dns(&self) -> bool {
        self.rules
            .iter()
            .chain(self.sub_rules.values().flatten())
            .any(|r| matches!(r.action, RouteAction::HijackDns))
    }

    pub fn has_process_rules(&self) -> bool {
        self.rules
            .iter()
            .chain(self.sub_rules.values().flatten())
            .any(Rule::has_process_rules)
            || self
                .sets
                .values()
                .any(|slot| slot.load().has_process_rules())
    }

    pub fn referenced_rule_sets(&self) -> Vec<&str> {
        fn collect<'a>(rule: &'a Rule, out: &mut Vec<&'a str>) {
            for s in &rule.rule_set {
                out.push(s.as_str());
            }
            if let Some((_, children)) = &rule.logical {
                for c in children {
                    collect(c, out);
                }
            }
        }
        let mut out = Vec::new();
        for rule in self.rules.iter().chain(self.sub_rules.values().flatten()) {
            collect(rule, &mut out);
        }
        out
    }

    pub fn rule_set_cidrs(&self, tag: &str) -> Vec<String> {
        self.sets
            .get(tag)
            .map(|slot| slot.load().cidr_strings())
            .unwrap_or_default()
    }

    pub fn select(
        &self,
        target: &Destination,
        network: Network,
        source: &Source,
    ) -> Option<&OutId> {
        let ctx = RouteContext::simple(target, network, source);
        let geo = self.geo.load();
        self.select_in_slice(&self.rules, &ctx, &geo, 0)
            .or(self.final_outbound.as_ref())
    }

    fn select_in_slice<'a>(
        &'a self,
        rules: &'a [Rule],
        ctx: &RouteContext<'_>,
        geo: &GeoData,
        depth: usize,
    ) -> Option<&'a OutId> {
        if depth > 8 {
            return None;
        }
        for rule in rules {
            if rule.matches_ctx(ctx, &self.sets, geo) {
                match &rule.action {
                    RouteAction::Route {
                        outbound: Some(out),
                        ..
                    } => return Some(out),
                    RouteAction::SubRule { name } => {
                        if let Some(sub) = self.sub_rules.get(name)
                            && let Some(out) = self.select_in_slice(sub, ctx, geo, depth + 1)
                        {
                            return Some(out);
                        }
                    }
                    RouteAction::HijackDns | RouteAction::Reject => return None,
                    _ => {}
                }
            }
        }
        None
    }

    /// 不触发解析：IP 规则只匹配目标本身的 IP 与 `resolved_ips`。
    pub fn evaluate(&self, ctx: &RouteContext<'_>) -> RouteDecision {
        self.evaluate_with(ctx, Resolution::Never)
    }

    /// 同 [`Self::evaluate_with`]，并把本次求值计入顶层规则的命中统计；
    /// 每条流只在决定出站时调用一次。
    pub fn evaluate_recorded(&self, ctx: &RouteContext<'_>, mode: Resolution) -> RouteDecision {
        self.evaluate_inner(ctx, mode, true)
    }

    /// 是否有规则可能要求解析域名目标（Mihomo IP 规则或 `resolve` 动作）。
    pub fn has_resolving_rules(&self) -> bool {
        self.rules
            .iter()
            .chain(self.sub_rules.values().flatten())
            .any(|r| r.resolve_ip || matches!(r.action, RouteAction::Resolve { .. }))
    }

    /// `Resolution::Pending` 下遇到需要 IP 的规则即停止并在 `resolve_at` 给出顶层规则序号；
    /// 调用方解析后以 `Resolution::From(序号)` 重算，解析结果只对该序号起的规则可见。
    pub fn evaluate_with(&self, ctx: &RouteContext<'_>, mode: Resolution) -> RouteDecision {
        self.evaluate_inner(ctx, mode, false)
    }

    fn evaluate_inner(
        &self,
        ctx: &RouteContext<'_>,
        mode: Resolution,
        record: bool,
    ) -> RouteDecision {
        let mut decision = RouteDecision::default();
        let geo = self.geo.load();
        let scope = Scope {
            depth: 0,
            top: 0,
            mode,
            record,
        };
        let matched_terminal = self.evaluate_slice(&self.rules, ctx, &geo, &mut decision, scope);
        if decision.resolve_at.is_some() {
            return decision;
        }
        if !matched_terminal && decision.outbound.is_none() {
            decision.outbound = self.final_outbound.clone();
            if decision.outbound.is_some() {
                decision.rule = Some(RuleLabel::matched_final());
                if record && let Some(counter) = self.counters.get(self.rules.len()) {
                    counter.record(true);
                }
            }
        }
        decision
    }

    fn evaluate_slice(
        &self,
        rules: &[Rule],
        ctx: &RouteContext<'_>,
        geo: &GeoData,
        decision: &mut RouteDecision,
        scope: Scope,
    ) -> bool {
        let Scope {
            depth,
            top,
            mode,
            record,
        } = scope;
        if depth > 8 {
            return false;
        }
        let pending = mode == Resolution::Pending
            && matches!(ctx.target.address(), Address::Domain(_))
            && ctx.resolved_ips.is_empty();
        let hidden = ctx.without_resolved_ips();
        for (index, rule) in rules.iter().enumerate() {
            let top = if depth == 0 { index } else { top };
            if pending && rule.wants_ip(&self.sets) {
                decision.resolve_at = Some(top);
                return true;
            }
            let visible = match mode {
                Resolution::From(from) if top < from => &hidden,
                _ => ctx,
            };
            let counter = self.counters.get(top).filter(|_| record && depth == 0);
            if !rule.matches_ctx(visible, &self.sets, geo) {
                if let Some(counter) = counter {
                    counter.record(false);
                }
                continue;
            }
            // SUB-RULE 同 Mihomo，只在子规则命中时算命中，见下方分支。
            if let Some(counter) = counter
                && !matches!(rule.action, RouteAction::SubRule { .. })
            {
                counter.record(true);
            }
            match &rule.action {
                RouteAction::Sniff { sniffer, timeout } => {
                    if decision.sniff.is_none() {
                        decision.sniff = Some((sniffer.clone(), *timeout));
                    }
                }
                RouteAction::Resolve { strategy } => {
                    if decision.resolve_strategy.is_none() {
                        decision.resolve_strategy = Some(*strategy);
                    }
                    if pending {
                        decision.resolve_at = Some(if depth == 0 { top + 1 } else { top });
                        return true;
                    }
                }
                RouteAction::RouteOptions {
                    override_address,
                    override_port,
                } => {
                    if override_address.is_some() {
                        decision.override_address = override_address.clone();
                    }
                    if override_port.is_some() {
                        decision.override_port = *override_port;
                    }
                }
                RouteAction::SubRule { name } => {
                    let inner = Scope {
                        depth: depth + 1,
                        top,
                        mode,
                        record,
                    };
                    let hit = self
                        .sub_rules
                        .get(name)
                        .is_some_and(|sub| self.evaluate_slice(sub, visible, geo, decision, inner));
                    if let Some(counter) = counter {
                        counter.record(hit);
                    }
                    if hit {
                        return true;
                    }
                }
                RouteAction::HijackDns => {
                    decision.hijack_dns = true;
                    decision.rule = Some(rule.label.clone());
                    return true;
                }
                RouteAction::Reject => {
                    decision.reject = true;
                    decision.rule = Some(rule.label.clone());
                    return true;
                }
                RouteAction::Route {
                    outbound,
                    balancer_tag,
                    override_address,
                    override_port,
                } => {
                    decision.outbound = outbound.clone();
                    decision.balancer_tag = balancer_tag.clone();
                    if override_address.is_some() {
                        decision.override_address = override_address.clone();
                    }
                    if override_port.is_some() {
                        decision.override_port = *override_port;
                    }
                    decision.rule = Some(rule.label.clone());
                    return true;
                }
            }
        }
        false
    }

    /// 顶层规则按配置顺序展开，最终出站以 `Match` 行收尾。
    pub fn rules(&self) -> Vec<RuleEntry> {
        let mut out: Vec<RuleEntry> = self
            .rules
            .iter()
            .zip(self.counters.iter())
            .map(|(rule, counter)| RuleEntry {
                stats: counter.snapshot(),
                label: rule.label.clone(),
                proxy: match &rule.action {
                    RouteAction::Route {
                        outbound,
                        balancer_tag,
                        ..
                    } => outbound
                        .as_ref()
                        .map(ToString::to_string)
                        .or_else(|| balancer_tag.clone())
                        .unwrap_or_default(),
                    RouteAction::RouteOptions { .. } => "route-options".into(),
                    RouteAction::Resolve { .. } => "resolve".into(),
                    RouteAction::Sniff { .. } => "sniff".into(),
                    RouteAction::SubRule { name } => name.clone(),
                    RouteAction::HijackDns => "hijack-dns".into(),
                    RouteAction::Reject => "REJECT".into(),
                },
            })
            .collect();
        if let Some(final_outbound) = &self.final_outbound {
            out.push(RuleEntry {
                label: RuleLabel::matched_final(),
                proxy: final_outbound.to_string(),
                stats: self
                    .counters
                    .get(self.rules.len())
                    .map(RuleCounter::snapshot)
                    .unwrap_or_default(),
            });
        }
        out
    }

    pub fn outbounds(&self) -> impl Iterator<Item = &OutId> {
        self.rules
            .iter()
            .chain(self.sub_rules.values().flatten())
            .filter_map(|rule| match &rule.action {
                RouteAction::Route {
                    outbound: Some(out),
                    ..
                } => Some(out),
                _ => None,
            })
            .chain(self.final_outbound.iter())
    }

    pub fn nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.rules
            .iter()
            .chain(self.sub_rules.values().flatten())
            .flat_map(|rule| &rule.node)
    }

    pub fn users(&self) -> impl Iterator<Item = &UserId> {
        self.rules
            .iter()
            .chain(self.sub_rules.values().flatten())
            .flat_map(|rule| &rule.user)
    }
}

/// 将 Clash / Mihomo 经典规则字符串解析为 `RuleSpec` 或默认出站（`MATCH` / `FINAL`）。
pub fn parse_clash_rule_line(line: &str) -> Result<(Option<RuleSpec>, Option<String>)> {
    let trimmed = line.trim().trim_start_matches('-').trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok((None, None));
    }
    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("AND,") || upper.starts_with("OR,") || upper.starts_with("NOT,") {
        let (mode_raw, rest) = trimmed.split_once(',').ok_or_else(invalid)?;
        let (cond_part, target) = rest.rsplit_once(',').ok_or_else(invalid)?;
        let mode_upper = mode_raw.trim().to_ascii_uppercase();
        let inner = cond_part
            .trim()
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or(cond_part.trim());
        let mut child_specs = Vec::new();
        let mut depth = 0i32;
        let mut start = 0usize;
        for (idx, ch) in inner.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    let seg = inner[start..idx].trim();
                    if !seg.is_empty() {
                        child_specs.push(parse_clash_condition_expr(seg)?);
                    }
                    start = idx + 1;
                }
                _ => {}
            }
        }
        let tail = inner[start..].trim();
        if !tail.is_empty() {
            child_specs.push(parse_clash_condition_expr(tail)?);
        }
        let mut spec = RuleSpec {
            logical_type: Some("logical".into()),
            logical_mode: Some(if mode_upper == "OR" {
                "or".into()
            } else {
                "and".into()
            }),
            invert: mode_upper == "NOT",
            resolve_ip: child_specs
                .iter()
                .any(|c| !c.ip_cidr.is_empty() || !c.geoip.is_empty() || c.ip_is_private),
            logical_rules: child_specs,
            ..Default::default()
        };
        apply_clash_target(&mut spec, target.trim());
        return Ok((Some(spec), None));
    }
    if upper.starts_with("SUB-RULE,") {
        let (_, rest) = trimmed.split_once(',').ok_or_else(invalid)?;
        let (cond_part, sub_name) = rest.rsplit_once(',').ok_or_else(invalid)?;
        let mut spec = parse_clash_condition_expr(cond_part.trim())?;
        spec.action = Some("sub-rule".into());
        spec.sub_rule = Some(sub_name.trim().to_owned());
        return Ok((Some(spec), None));
    }
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return Err(invalid());
    }
    let kind = parts[0].to_ascii_uppercase();
    if matches!(kind.as_str(), "MATCH" | "FINAL") {
        return Ok((None, Some(parts[1].to_owned())));
    }
    if parts.len() < 3 {
        return Err(invalid());
    }
    let val = parts[1];
    let target = parts[2];
    let mut spec = build_clash_single_condition(&kind, val)?;
    spec.resolve_ip = matches!(kind.as_str(), "IP-CIDR" | "IP-CIDR6" | "GEOIP" | "RULE-SET")
        && !parts[3..]
            .iter()
            .any(|opt| opt.eq_ignore_ascii_case("no-resolve"));
    apply_clash_target(&mut spec, target);
    Ok((Some(spec), None))
}

fn parse_clash_condition_expr(expr: &str) -> Result<RuleSpec> {
    let inner = expr
        .trim()
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(expr.trim());
    let (kind, val) = inner.split_once(',').ok_or_else(invalid)?;
    build_clash_single_condition(&kind.trim().to_ascii_uppercase(), val.trim())
}

fn build_clash_single_condition(kind: &str, val: &str) -> Result<RuleSpec> {
    let mut spec = RuleSpec::default();
    match kind {
        "DOMAIN" => spec.domain.push(val.to_owned()),
        "DOMAIN-SUFFIX" => spec.domain_suffix.push(val.to_owned()),
        "DOMAIN-KEYWORD" => spec.domain_keyword.push(val.to_owned()),
        "DOMAIN-REGEX" => spec.domain_regex.push(val.to_owned()),
        "DOMAIN-WILDCARD" => spec.domain_wildcard.push(val.to_owned()),
        "GEOSITE" => spec.geosite.push(val.to_owned()),
        "IP-ASN" => spec.ip_asn.push(parse_asn(val)?),
        "SRC-IP-ASN" => spec.source_ip_asn.push(parse_asn(val)?),
        "SRC-GEOIP" => spec.source_geoip.push(val.to_owned()),
        // Mihomo 只把 `lan` 当作内置判定，`private` 与其他代码一样查 GeoIP 数据。
        "GEOIP" => spec.geoip.push(val.to_owned()),
        "IP-CIDR" | "IP-CIDR6" => spec.ip_cidr.push(val.to_owned()),
        "SRC-IP-CIDR" => spec.source_ip_cidr.push(val.to_owned()),
        "DST-PORT" => {
            if val.contains('-') || val.contains(':') {
                spec.port_range.push(val.replace('-', ":"));
            } else {
                spec.port.push(val.parse().map_err(|_| invalid())?);
            }
        }
        "SRC-PORT" => {
            if val.contains('-') || val.contains(':') {
                spec.source_port_range.push(val.replace('-', ":"));
            } else {
                spec.source_port.push(val.parse().map_err(|_| invalid())?);
            }
        }
        "IN-PORT" => spec.in_port.push(val.parse().map_err(|_| invalid())?),
        "IN-TYPE" => spec.in_type.push(val.to_owned()),
        "IN-NAME" => spec.node.push(val.to_owned()),
        "IN-USER" => spec.user.push(val.to_owned()),
        "PROCESS-NAME" => spec.process_name.push(val.to_owned()),
        "PROCESS-PATH" => spec.process_path.push(val.to_owned()),
        "PROCESS-NAME-REGEX" => spec.process_name_regex.push(val.to_owned()),
        "PROCESS-PATH-REGEX" => spec.process_path_regex.push(val.to_owned()),
        "RULE-SET" => spec.rule_set.push(val.to_owned()),
        "NETWORK" => {
            spec.network = Some(match val.to_ascii_lowercase().as_str() {
                "tcp" => Network::Tcp,
                "udp" => Network::Udp,
                _ => return Err(invalid()),
            });
        }
        "UID" => spec.uid.push(val.parse().map_err(|_| invalid())?),
        "DSCP" => spec.dscp.push(val.parse().map_err(|_| invalid())?),
        _ => return Err(invalid()),
    }
    Ok(spec)
}

fn parse_asn(val: &str) -> Result<u32> {
    let val = val.trim();
    let digits = val
        .strip_prefix("AS")
        .or_else(|| val.strip_prefix("as"))
        .unwrap_or(val);
    digits.parse().map_err(|_| invalid())
}

fn apply_clash_target(spec: &mut RuleSpec, target: &str) {
    if target.eq_ignore_ascii_case("REJECT") || target.eq_ignore_ascii_case("REJECT-DROP") {
        spec.action = Some("reject".into());
    } else {
        spec.outbound = target.to_owned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const USER: &str = "00000000-0000-4000-8000-000000000001";

    fn table(rules: serde_json::Value) -> RouteTable {
        RouteTable::compile(&serde_json::from_value::<Vec<RuleSpec>>(rules).unwrap()).unwrap()
    }
    fn local(node: &str) -> Source {
        Source::Local {
            node: NodeId::parse(node).unwrap(),
        }
    }
    fn pick(
        table: &RouteTable,
        host: &str,
        port: u16,
        network: Network,
        source: &Source,
    ) -> Option<String> {
        table
            .select(&Destination::new(host, port).unwrap(), network, source)
            .map(ToString::to_string)
    }

    #[test]
    fn rule_labels_use_mihomo_type_names_and_payloads() {
        for (line, kind, payload) in [
            ("PROCESS-NAME,curl,DIRECT", "ProcessName", "curl"),
            ("GEOIP,CN,DIRECT", "GeoIP", "cn"),
            ("GEOIP,US,DIRECT,no-resolve", "GeoIP", "us"),
        ] {
            let (spec, _) = parse_clash_rule_line(line).unwrap();
            let label = RuleLabel::of(&spec.unwrap());
            assert_eq!(
                (label.kind.as_str(), label.payload.as_str()),
                (kind, payload),
                "{line}"
            );
        }
    }

    #[test]
    fn unsupported_conditions_are_rejected_instead_of_matching_everything() {
        for line in [
            "IN-PORT,7890,REJECT",
            "IN-TYPE,SOCKS,REJECT",
            "UID,1000,REJECT",
            "DSCP,4,REJECT",
        ] {
            let (spec, _) = parse_clash_rule_line(line).unwrap();
            assert!(
                RouteTable::compile(&[spec.unwrap()]).is_err(),
                "{line} must not compile into a match-all rule"
            );
        }
    }

    #[test]
    fn clash_geoip_private_reads_geo_data_and_lan_stays_builtin() {
        let table = RouteTable::compile(&[
            parse_clash_rule_line("GEOIP,private,priv")
                .unwrap()
                .0
                .unwrap(),
            parse_clash_rule_line("GEOIP,LAN,lan").unwrap().0.unwrap(),
        ])
        .unwrap()
        .with_geo_mode(GeoIpMode::Mmdb);
        let codes = &table.geo().needs().ip_codes;
        assert!(codes.contains("private") && !codes.contains("lan"));
        let source = local("n");
        assert_eq!(
            pick(&table, "10.0.0.1", 443, Network::Tcp, &source).as_deref(),
            Some("lan"),
            "没有 GeoIP 数据时 private 不命中"
        );
        assert_eq!(pick(&table, "100.64.0.1", 443, Network::Tcp, &source), None);
    }

    #[test]
    fn recorded_evaluation_counts_top_level_rules_like_mihomo() {
        let mut subs = std::collections::BTreeMap::new();
        subs.insert(
            "sub".to_owned(),
            vec![
                parse_clash_rule_line("DST-PORT,80,inner")
                    .unwrap()
                    .0
                    .unwrap(),
            ],
        );
        let table = RouteTable::compile(&[
            parse_clash_rule_line("SUB-RULE,(NETWORK,tcp),sub")
                .unwrap()
                .0
                .unwrap(),
            parse_clash_rule_line("DOMAIN,a.test,a").unwrap().0.unwrap(),
        ])
        .unwrap()
        .with_sub_rules(&subs)
        .unwrap()
        .with_final_outbound(Some(OutId::parse("last").unwrap()));
        let source = local("n");
        let run = |host: &str, port: u16| {
            let target = Destination::new(host, port).unwrap();
            let ctx = RouteContext::simple(&target, Network::Tcp, &source);
            table.evaluate_recorded(&ctx, Resolution::Never)
        };
        run("a.test", 80);
        run("a.test", 443);
        run("b.test", 443);
        let target = Destination::new("a.test", 443).unwrap();
        table.evaluate(&RouteContext::simple(&target, Network::Tcp, &source));
        let counts: Vec<(u64, u64)> = table
            .rules()
            .iter()
            .map(|row| (row.stats.hit_count, row.stats.miss_count))
            .collect();
        assert_eq!(
            counts,
            [(1, 2), (1, 1), (1, 0)],
            "SUB-RULE 子规则未命中算未命中"
        );
        assert!(table.rules()[0].stats.hit_at_ms > 0);
    }

    #[test]
    fn domain_conditions_match_exact_suffix_and_keyword() {
        let table = table(json!([
            {"outbound":"exact","domain":["Example.COM"]},
            {"outbound":"suffix","domain_suffix":[".example.org"]},
            {"outbound":"keyword","domain_keyword":["TRACK"]},
        ]));
        let source = local("n");
        assert_eq!(
            pick(&table, "example.com", 443, Network::Tcp, &source).as_deref(),
            Some("exact")
        );
        assert_eq!(
            pick(&table, "www.example.com", 443, Network::Tcp, &source),
            None
        );
        assert_eq!(
            pick(&table, "example.org.", 443, Network::Tcp, &source).as_deref(),
            Some("suffix")
        );
        assert_eq!(
            pick(&table, "a.example.org", 443, Network::Tcp, &source).as_deref(),
            Some("suffix")
        );
        assert_eq!(
            pick(&table, "badexample.org", 443, Network::Tcp, &source),
            None
        );
        assert_eq!(
            pick(&table, "ads.tracker.net", 443, Network::Tcp, &source).as_deref(),
            Some("keyword")
        );
    }

    #[test]
    fn cidr_matches_literal_addresses_and_never_domains() {
        let table = table(json!([
            {"outbound":"v4","ip_cidr":["10.0.0.0/8"]},
            {"outbound":"v6","ip_cidr":["2001:db8::/32"]},
            {"outbound":"all","ip_cidr":["0.0.0.0/0"]},
        ]));
        let source = local("n");
        assert_eq!(
            pick(&table, "10.1.2.3", 80, Network::Tcp, &source).as_deref(),
            Some("v4")
        );
        assert_eq!(
            pick(&table, "::ffff:10.1.2.3", 80, Network::Tcp, &source).as_deref(),
            Some("v4")
        );
        assert_eq!(
            pick(&table, "2001:db8::1", 80, Network::Tcp, &source).as_deref(),
            Some("v6")
        );
        assert_eq!(
            pick(&table, "11.0.0.1", 80, Network::Tcp, &source).as_deref(),
            Some("all")
        );
        assert_eq!(pick(&table, "2001:db9::1", 80, Network::Tcp, &source), None);
        assert_eq!(pick(&table, "ten.example", 80, Network::Tcp, &source), None);
    }

    #[test]
    fn fields_combine_with_and_and_first_match_wins() {
        let table = table(json!([
            {"outbound":"a","domain_suffix":["example.com"],"port":[443],"network":"tcp"},
            {"outbound":"b","domain_suffix":["example.com"]},
            {"outbound":"c","domain_suffix":["example.com"]},
        ]));
        let source = local("n");
        assert_eq!(
            pick(&table, "example.com", 443, Network::Tcp, &source).as_deref(),
            Some("a")
        );
        assert_eq!(
            pick(&table, "example.com", 80, Network::Tcp, &source).as_deref(),
            Some("b")
        );
        assert_eq!(
            pick(&table, "example.com", 443, Network::Udp, &source).as_deref(),
            Some("b")
        );
    }

    #[test]
    fn node_and_user_conditions_use_the_trusted_source() {
        let table = table(json!([
            {"outbound":"user","user":[USER]},
            {"outbound":"node","node":["edge"]},
        ]));
        let user = Source::User {
            node: NodeId::parse("other").unwrap(),
            user: UserId::parse(USER).unwrap(),
            credential_epoch: 1,
        };
        assert_eq!(
            pick(&table, "example.com", 1, Network::Tcp, &user).as_deref(),
            Some("user")
        );
        assert_eq!(
            pick(&table, "example.com", 1, Network::Tcp, &local("edge")).as_deref(),
            Some("node")
        );
        assert_eq!(
            pick(&table, "example.com", 1, Network::Tcp, &local("other")),
            None
        );
    }

    #[test]
    fn rejects_rules_that_could_not_be_intended() {
        for rule in [
            json!({"outbound":"a"}),
            json!({"outbound":"a","domain":["10.0.0.1"]}),
            json!({"outbound":"a","domain_keyword":[""]}),
            json!({"outbound":"a","ip_cidr":["10.0.0.0/33"]}),
            json!({"outbound":"a","ip_cidr":["example.com/8"]}),
            json!({"outbound":"a","ip_cidr":["10.0.0.0/"]}),
            json!({"outbound":"a","ip_cidr":["::ffff:10.0.0.0/104"]}),
            json!({"outbound":"a","domain_keyword":["例子"]}),
            json!({"outbound":"bad
tag","port":[1]}),
        ] {
            let spec: RuleSpec = serde_json::from_value(rule).unwrap();
            assert!(RouteTable::compile(&[spec]).is_err());
        }
    }

    #[test]
    fn extended_m3_rules_actions_logical_ruleset_and_geodata_work() {
        let set_spec: RuleSetSpec = serde_json::from_value(json!({
            "tag": "corp-set",
            "type": "inline",
            "rules": [
                {
                    "domain_suffix": ["corp.internal"],
                    "port_range": ["8000:9000"]
                }
            ]
        }))
        .unwrap();
        let mut sets = HashMap::new();
        sets.insert(
            "corp-set".into(),
            set_spec.source().unwrap().compile(None).unwrap(),
        );

        let specs: Vec<RuleSpec> = serde_json::from_value(json!([
            {
                "action": "sniff",
                "sniffer": ["tls", "http"],
                "timeout": "250ms"
            },
            {
                "action": "resolve",
                "strategy": "prefer_ipv4"
            },
            {
                "port": [53],
                "action": "hijack-dns"
            },
            {
                "ip_is_private": true,
                "action": "route-options",
                "override_address": "10.0.0.254",
                "override_port": 8443
            },
            {
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"geosite": ["google"]},
                    {"protocol": ["tls"]}
                ],
                "outbound": "proxy-google"
            },
            {
                "rule_set": ["corp-set"],
                "outbound": "corp-vpn"
            },
            {
                "domain_wildcard": ["*.wild.*.example.com"],
                "source_ip_cidr": ["192.168.1.0/24"],
                "outbound": "wild-out"
            }
        ]))
        .unwrap();

        let table = RouteTable::compile_with_sets(&specs, sets)
            .unwrap()
            .with_geo_mode(GeoIpMode::Mmdb);
        let site = geodata::fixture::geosite(&[("google", &[(2, "google.com", &[])])]);
        table
            .geo()
            .install(table.geo().compile(GeoFile::GeoSite, &site).unwrap());
        let source = local("n");

        // 1. DNS Hijack on port 53
        let dns_target = Destination::new("8.8.8.8", 53).unwrap();
        let dns_dec = table.evaluate(&RouteContext::simple(&dns_target, Network::Udp, &source));
        assert!(dns_dec.hijack_dns);
        assert!(dns_dec.sniff.is_some());
        assert_eq!(dns_dec.resolve_strategy, Some(ResolveStrategy::PreferIpv4));

        // 2. Logical AND (geosite:google + protocol:tls)
        let google_target = Destination::new("www.google.com", 443).unwrap();
        let google_dec = table.evaluate(&RouteContext {
            target: &google_target,
            resolved_ips: &[],
            network: Network::Tcp,
            source: &source,
            source_addr: None,
            protocol: Some("tls"),
            sniffed_domain: None,
            process_name: None,
            process_path: None,
        });
        assert_eq!(
            google_dec
                .outbound
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("proxy-google")
        );

        // 3. Rule-set match + route-options accumulation
        let corp_target = Destination::new("10.1.1.5", 8080).unwrap();
        let corp_dec = table.evaluate(&RouteContext {
            target: &corp_target,
            resolved_ips: &[],
            network: Network::Tcp,
            source: &source,
            source_addr: None,
            protocol: None,
            sniffed_domain: Some("api.corp.internal"),
            process_name: None,
            process_path: None,
        });
        assert_eq!(corp_dec.override_address.as_deref(), Some("10.0.0.254"));
        assert_eq!(corp_dec.override_port, Some(8443));
        assert_eq!(
            corp_dec
                .outbound
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("corp-vpn")
        );

        // 4. Domain wildcard + source_ip_cidr
        let wild_target = Destination::new("a.wild.b.example.com", 443).unwrap();
        let wild_dec = table.evaluate(&RouteContext {
            target: &wild_target,
            resolved_ips: &[],
            network: Network::Tcp,
            source: &source,
            source_addr: Some("192.168.1.50:55000".parse().unwrap()),
            protocol: None,
            sniffed_domain: None,
            process_name: None,
            process_path: None,
        });
        assert_eq!(
            wild_dec
                .outbound
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("wild-out")
        );
    }

    #[test]
    fn process_rules_sub_rules_and_clash_rule_parser_work() {
        let lines = [
            "PROCESS-NAME,curl,direct-curl",
            "PROCESS-PATH,/usr/bin/git,git-proxy",
            "SUB-RULE,(NETWORK,tcp),tcp-sub",
            "AND,((DOMAIN-SUFFIX,github.com),(DST-PORT,443)),gh-out",
            "MATCH,final-out",
        ];
        let mut rules = Vec::new();
        let mut final_out = None;
        for line in lines {
            let (r, f) = parse_clash_rule_line(line).unwrap();
            if let Some(spec) = r {
                rules.push(spec);
            }
            if let Some(fin) = f {
                final_out = Some(OutId::parse(&fin).unwrap());
            }
        }
        let mut sub_rules = std::collections::BTreeMap::new();
        let (sub1, _) = parse_clash_rule_line("DOMAIN-SUFFIX,sub.example.com,sub-out").unwrap();
        sub_rules.insert("tcp-sub".to_owned(), vec![sub1.unwrap()]);

        let table = RouteTable::compile(&rules)
            .unwrap()
            .with_sub_rules(&sub_rules)
            .unwrap()
            .with_final_outbound(final_out);
        let source = local("n");
        let target = Destination::new("sub.example.com", 443).unwrap();

        let dec_curl = table.evaluate(&RouteContext {
            target: &target,
            resolved_ips: &[],
            network: Network::Tcp,
            source: &source,
            source_addr: None,
            protocol: None,
            sniffed_domain: None,
            process_name: Some("CURL"),
            process_path: None,
        });
        assert_eq!(
            dec_curl
                .outbound
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("direct-curl")
        );

        let dec_sub = table.evaluate(&RouteContext {
            target: &target,
            resolved_ips: &[],
            network: Network::Tcp,
            source: &source,
            source_addr: None,
            protocol: None,
            sniffed_domain: None,
            process_name: Some("other"),
            process_path: None,
        });
        assert_eq!(
            dec_sub
                .outbound
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("sub-out")
        );
    }

    #[test]
    fn mihomo_ip_rules_request_resolution_unless_no_resolve() {
        let specs: Vec<RuleSpec> = [
            "DOMAIN,named.test,out-name",
            "IP-CIDR,192.0.2.0/24,out-skip,no-resolve",
            "IP-CIDR,10.0.0.0/8,out-ip",
            "DOMAIN-SUFFIX,test,out-tail",
        ]
        .iter()
        .map(|l| parse_clash_rule_line(l).unwrap().0.unwrap())
        .collect();
        assert!(!specs[1].resolve_ip && specs[2].resolve_ip);
        let table = RouteTable::compile(&specs).unwrap();
        assert!(table.has_resolving_rules());
        let source = local("node-a");
        let target = Destination::new("x.test", 443).unwrap();
        let ctx = RouteContext::simple(&target, Network::Tcp, &source);
        let first = table.evaluate_with(&ctx, Resolution::Pending);
        assert_eq!(
            first.resolve_at,
            Some(2),
            "停在第一条未写 no-resolve 的 IP 规则"
        );
        assert!(first.outbound.is_none());
        let ips = ["10.1.2.3".parse().unwrap()];
        let resolved = RouteContext {
            resolved_ips: &ips,
            ..ctx
        };
        let second = table.evaluate_with(&resolved, Resolution::From(2));
        assert_eq!(
            second.outbound.as_ref().map(ToString::to_string).as_deref(),
            Some("out-ip")
        );
        let skipped = ["192.0.2.1".parse().unwrap()];
        let hidden = RouteContext {
            resolved_ips: &skipped,
            ..ctx
        };
        let third = table.evaluate_with(&hidden, Resolution::From(2));
        assert_eq!(
            third.outbound.as_ref().map(ToString::to_string).as_deref(),
            Some("out-tail"),
            "解析结果对停止点之前的 no-resolve 规则不可见"
        );
        let failed = table.evaluate_with(&ctx, Resolution::From(2));
        assert_eq!(
            failed.outbound.as_ref().map(ToString::to_string).as_deref(),
            Some("out-tail")
        );
        assert_eq!(
            table
                .evaluate(&ctx)
                .outbound
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("out-tail")
        );
        let named = Destination::new("named.test", 443).unwrap();
        let ctx = RouteContext::simple(&named, Network::Tcp, &source);
        assert_eq!(
            table.evaluate_with(&ctx, Resolution::Pending).resolve_at,
            None
        );
    }
}
