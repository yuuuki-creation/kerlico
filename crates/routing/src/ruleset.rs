//! 规则集（sing-box `rule_set` / Mihomo `rule-providers`）、无头规则与各文件格式的解码。
//!
//! 支持的文件格式：sing-box 源格式 JSON 与二进制 `.srs`（版本 1–5），Mihomo `yaml`、`text`
//! 与二进制 `.mrs`；Mihomo behavior 为 `domain`、`ipcidr`、`classical`。

use crate::{
    Network, PortRange,
    domain_set::DomainSet,
    ip_set::{IpSet, IpSetBuilder, parse_prefix},
    mrs::{self, Behavior, MrsPayload},
    srs, wildcard_domain_matches,
};
use kerlico_core::{Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(untagged)]
pub enum StringOrVec {
    #[default]
    Empty,
    Single(String),
    List(Vec<String>),
}

impl StringOrVec {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::Empty => Vec::new(),
            Self::Single(s) => vec![s],
            Self::List(v) => v,
        }
    }
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Self::Empty => Vec::new(),
            Self::Single(s) => vec![s.clone()],
            Self::List(v) => v.clone(),
        }
    }
    fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Single(_) => false,
            Self::List(v) => v.is_empty(),
        }
    }
}

/// sing-box `query_type`：数字或记录类型名。
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum DnsQueryType {
    Code(u16),
    Name(String),
}

impl DnsQueryType {
    pub fn code(&self) -> Result<u16> {
        const NAMES: [(&str, u16); 12] = [
            ("A", 1),
            ("NS", 2),
            ("CNAME", 5),
            ("SOA", 6),
            ("PTR", 12),
            ("MX", 15),
            ("TXT", 16),
            ("AAAA", 28),
            ("SRV", 33),
            ("SVCB", 64),
            ("HTTPS", 65),
            ("ANY", 255),
        ];
        match self {
            Self::Code(code) => Ok(*code),
            Self::Name(name) => NAMES
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name.trim()))
                .map(|(_, code)| *code)
                .ok_or_else(|| Error::Config(format!("query_type 不支持：{name}"))),
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeadlessRuleSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<DnsQueryType>,
    #[serde(default, skip_serializing_if = "StringOrVec::is_empty")]
    pub network: StringOrVec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(
        default,
        alias = "domain-suffix",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_suffix: Vec<String>,
    #[serde(
        default,
        alias = "domain-keyword",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_keyword: Vec<String>,
    #[serde(
        default,
        alias = "domain-regex",
        alias = "domain_regexp",
        alias = "domain-regexp",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_regex: Vec<String>,
    #[serde(
        default,
        alias = "domain-wildcard",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_wildcard: Vec<String>,
    #[serde(
        default,
        alias = "source-ip-cidr",
        alias = "src_ip_cidr",
        alias = "src-ip-cidr",
        alias = "source_ip",
        alias = "source-ip",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, alias = "ip-cidr", skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    #[serde(default, alias = "source-port", skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u16>,
    #[serde(
        default,
        alias = "source-port-range",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub source_port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    #[serde(default, alias = "port-range", skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    #[serde(default, alias = "process-name", skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    #[serde(default, alias = "process-path", skip_serializing_if = "Vec::is_empty")]
    pub process_path: Vec<String>,
    #[serde(
        default,
        alias = "process-name-regex",
        alias = "process_name_regexp",
        alias = "process-name-regexp",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub process_name_regex: Vec<String>,
    #[serde(
        default,
        alias = "process-path-regex",
        alias = "process_path_regexp",
        alias = "process-path-regexp",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub process_path_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_name_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi_ssid: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi_bssid: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub network_is_expensive: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub network_is_constrained: bool,
    #[serde(default, alias = "not", skip_serializing_if = "is_false")]
    pub invert: bool,
    #[serde(
        default,
        rename = "type",
        alias = "logical_type",
        alias = "logical-type",
        skip_serializing_if = "Option::is_none"
    )]
    pub logical_type: Option<String>,
    #[serde(
        default,
        rename = "mode",
        alias = "logical_mode",
        alias = "logical-mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub logical_mode: Option<String>,
    #[serde(
        default,
        rename = "rules",
        alias = "logical_rules",
        alias = "logical-rules",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub logical_rules: Vec<HeadlessRuleSpec>,
}

fn default_inline() -> String {
    "inline".into()
}

fn default_classical() -> String {
    "classical".into()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSpec {
    pub tag: String,
    #[serde(default = "default_inline", rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, alias = "update-interval", alias = "interval")]
    pub update_interval: Option<String>,
    #[serde(default, alias = "download-detour", alias = "proxy")]
    pub download_detour: Option<String>,
    #[serde(default)]
    pub rules: Vec<HeadlessRuleSpec>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleProviderSpec {
    #[serde(default, alias = "tag")]
    pub name: Option<String>,
    #[serde(default = "default_inline", rename = "type")]
    pub kind: String,
    #[serde(default = "default_classical")]
    pub behavior: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, alias = "update_interval", alias = "update-interval")]
    pub interval: Option<u64>,
    #[serde(default, alias = "rules")]
    pub payload: Vec<String>,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default, alias = "size-limit")]
    pub size_limit: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceRuleSetFile {
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default)]
    pub rules: Vec<HeadlessRuleSpec>,
}

fn default_version() -> u8 {
    1
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalMode {
    And,
    Or,
}

impl LogicalMode {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "and" => Ok(Self::And),
            "or" => Ok(Self::Or),
            _ => Err(Error::Config("逻辑规则 mode 仅支持 and 或 or".into())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledHeadlessRule {
    pub domains: DomainSet,
    pub domain_wildcard: Vec<String>,
    pub ip_cidr: IpSet,
    pub port: Vec<u16>,
    pub port_range: Vec<PortRange>,
    pub source_ip_cidr: IpSet,
    pub source_port: Vec<u16>,
    pub source_port_range: Vec<PortRange>,
    pub networks: Vec<Network>,
    pub process_name: Vec<String>,
    pub process_path: Vec<String>,
    pub process_name_regex: Vec<Regex>,
    pub process_path_regex: Vec<Regex>,
    /// 含 DNS 查询类型、安卓包名、Wi-Fi 或网络类型条件；路由连接没有这些信息，规则不命中（同 sing-box）。
    pub platform_only: bool,
    pub invert: bool,
    pub logical: Option<(LogicalMode, Vec<CompiledHeadlessRule>)>,
}

fn build_domain_set(spec: &HeadlessRuleSpec) -> Result<DomainSet> {
    let mut builder = crate::domain_set::DomainSetBuilder::default();
    for d in &spec.domain {
        builder.insert_full(validate_domain_entry(d)?);
    }
    for d in &spec.domain_suffix {
        match d.trim().strip_prefix('.') {
            Some(rest) => builder.insert_subdomain(validate_domain_entry(rest)?),
            None => builder.insert_suffix(validate_domain_entry(d)?),
        }
    }
    for kw in &spec.domain_keyword {
        if kw.is_empty() {
            return Err(Error::Config("无头规则 domain_keyword 不能为空".into()));
        }
        builder.insert_keyword(kw);
    }
    for re in &spec.domain_regex {
        Regex::new(re).map_err(|_| Error::Config(format!("无头规则 domain_regex 不合法：{re}")))?;
        builder.insert_regex(re.clone());
    }
    builder.build()
}

fn validate_domain_entry(value: &str) -> Result<&str> {
    let d = value.trim().trim_end_matches('.');
    if d.is_empty() || d.parse::<IpAddr>().is_ok() {
        return Err(Error::Config(format!("规则集域名不合法：{value}")));
    }
    Ok(d)
}

fn ip_set(items: &[String], field: &str) -> Result<IpSet> {
    let mut builder = IpSetBuilder::default();
    for raw in items {
        builder
            .add_cidr(raw)
            .map_err(|_| Error::Config(format!("无头规则 {field} 不合法：{raw}")))?;
    }
    Ok(builder.build())
}

fn regexes(items: &[String], field: &str) -> Result<Vec<Regex>> {
    items
        .iter()
        .map(|re| Regex::new(re).map_err(|_| Error::Config(format!("无头规则 {field} 不合法"))))
        .collect()
}

impl CompiledHeadlessRule {
    pub fn compile(spec: &HeadlessRuleSpec) -> Result<Self> {
        let logical = match &spec.logical_type {
            Some(ltype) => {
                if !ltype.eq_ignore_ascii_case("logical") {
                    return Err(Error::Config("无头规则 type 仅支持 logical".into()));
                }
                let mode = LogicalMode::parse(
                    spec.logical_mode
                        .as_deref()
                        .ok_or_else(|| Error::Config("逻辑无头规则缺少 mode".into()))?,
                )?;
                if spec.logical_rules.is_empty() {
                    return Err(Error::Config("逻辑无头规则 rules 不能为空".into()));
                }
                let children = spec
                    .logical_rules
                    .iter()
                    .map(Self::compile)
                    .collect::<Result<Vec<_>>>()?;
                Some((mode, children))
            }
            None => None,
        };
        let mut networks = Vec::new();
        for net_str in spec.network.as_vec() {
            match net_str.trim().to_ascii_lowercase().as_str() {
                "tcp" => networks.push(Network::Tcp),
                "udp" => networks.push(Network::Udp),
                _ => return Err(Error::Config("无头规则 network 仅支持 tcp 或 udp".into())),
            }
        }
        for t in &spec.query_type {
            t.code()?;
        }
        let mut domain_wildcard = Vec::with_capacity(spec.domain_wildcard.len());
        for w in &spec.domain_wildcard {
            if w.trim().is_empty() {
                return Err(Error::Config("无头规则 domain_wildcard 不能为空".into()));
            }
            domain_wildcard.push(w.trim().to_ascii_lowercase());
        }
        Ok(Self {
            domains: build_domain_set(spec)?,
            domain_wildcard,
            ip_cidr: ip_set(&spec.ip_cidr, "ip_cidr")?,
            port: spec.port.clone(),
            port_range: spec
                .port_range
                .iter()
                .map(|r| PortRange::parse(r))
                .collect::<Result<_>>()?,
            source_ip_cidr: ip_set(&spec.source_ip_cidr, "source_ip_cidr")?,
            source_port: spec.source_port.clone(),
            source_port_range: spec
                .source_port_range
                .iter()
                .map(|r| PortRange::parse(r))
                .collect::<Result<_>>()?,
            networks,
            process_name: spec
                .process_name
                .iter()
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
                .collect(),
            process_path: spec
                .process_path
                .iter()
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .collect(),
            process_name_regex: regexes(&spec.process_name_regex, "process_name_regex")?,
            process_path_regex: regexes(&spec.process_path_regex, "process_path_regex")?,
            platform_only: !spec.query_type.is_empty()
                || !spec.package_name.is_empty()
                || !spec.package_name_regex.is_empty()
                || !spec.wifi_ssid.is_empty()
                || !spec.wifi_bssid.is_empty()
                || !spec.network_type.is_empty()
                || spec.network_is_expensive
                || spec.network_is_constrained,
            invert: spec.invert,
            logical,
        })
    }

    pub fn matches(
        &self,
        hosts: &[&str],
        ips: &[IpAddr],
        port: u16,
        network: Network,
        source_addr: Option<SocketAddr>,
    ) -> bool {
        self.matches_with_process(hosts, ips, port, network, source_addr, None, None)
    }

    /// `hosts` 须为小写、无结尾点；[`CompiledRuleSet`] 的匹配入口负责转换。
    #[allow(clippy::too_many_arguments)]
    pub fn matches_with_process(
        &self,
        hosts: &[&str],
        ips: &[IpAddr],
        port: u16,
        network: Network,
        source_addr: Option<SocketAddr>,
        process_name: Option<&str>,
        process_path: Option<&str>,
    ) -> bool {
        if let Some((mode, children)) = &self.logical {
            let hit = match mode {
                LogicalMode::And => children.iter().all(|c| {
                    c.matches_with_process(
                        hosts,
                        ips,
                        port,
                        network,
                        source_addr,
                        process_name,
                        process_path,
                    )
                }),
                LogicalMode::Or => children.iter().any(|c| {
                    c.matches_with_process(
                        hosts,
                        ips,
                        port,
                        network,
                        source_addr,
                        process_name,
                        process_path,
                    )
                }),
            };
            return hit != self.invert;
        }

        let has_domain_cond = !self.domains.is_empty() || !self.domain_wildcard.is_empty();
        let has_ip_cond = !self.ip_cidr.is_empty();
        let domain_hit = hosts.iter().any(|&host| {
            self.domains.matches(host)
                || self
                    .domain_wildcard
                    .iter()
                    .any(|w| wildcard_domain_matches(w, host))
        });
        let ip_hit = ips.iter().any(|&ip| self.ip_cidr.contains(ip));

        let target_ok = (!has_domain_cond && !has_ip_cond) || domain_hit || ip_hit;
        let port_ok = (self.port.is_empty() && self.port_range.is_empty())
            || self.port.contains(&port)
            || self.port_range.iter().any(|r| r.contains(port));
        let net_ok = self.networks.is_empty() || self.networks.contains(&network);
        let src_ip_ok = self.source_ip_cidr.is_empty()
            || source_addr.is_some_and(|sa| self.source_ip_cidr.contains(sa.ip()));
        let src_port_ok = (self.source_port.is_empty() && self.source_port_range.is_empty())
            || source_addr.is_some_and(|sa| {
                self.source_port.contains(&sa.port())
                    || self.source_port_range.iter().any(|r| r.contains(sa.port()))
            });
        let proc_name_ok = (self.process_name.is_empty() && self.process_name_regex.is_empty())
            || process_name.is_some_and(|pn| {
                let lower = pn.to_ascii_lowercase();
                self.process_name.iter().any(|item| item == &lower)
                    || self.process_name_regex.iter().any(|re| re.is_match(pn))
            });
        let proc_path_ok = (self.process_path.is_empty() && self.process_path_regex.is_empty())
            || process_path.is_some_and(|pp| {
                self.process_path.iter().any(|item| item == pp)
                    || self.process_path_regex.iter().any(|re| re.is_match(pp))
            });

        let raw = !self.platform_only
            && target_ok
            && port_ok
            && net_ok
            && src_ip_ok
            && src_port_ok
            && proc_name_ok
            && proc_path_ok;
        raw != self.invert
    }

    pub fn has_process_rules(&self) -> bool {
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

    fn entry_count(&self) -> usize {
        let own = self.domains.len()
            + self.domain_wildcard.len()
            + self.ip_cidr.range_count()
            + usize::from(
                self.logical.is_none() && self.domains.is_empty() && self.ip_cidr.is_empty(),
            );
        match &self.logical {
            Some((_, children)) => children.iter().map(Self::entry_count).sum(),
            None => own,
        }
    }
}

/// sing-box 规则集文件格式；`format` 缺省时按内容判断（`SRS` 开头为二进制）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingBoxFormat {
    Auto,
    Source,
    Binary,
}

/// Mihomo rule-provider 文件格式；缺省为 `yaml`（同 Mihomo）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MihomoFormat {
    Yaml,
    Text,
    Mrs,
}

impl MihomoFormat {
    pub fn parse(raw: Option<&str>) -> Result<Self> {
        match raw.map(|f| f.trim().to_ascii_lowercase()).as_deref() {
            None | Some("" | "yaml") => Ok(Self::Yaml),
            Some("text") => Ok(Self::Text),
            Some("mrs") => Ok(Self::Mrs),
            Some(other) => Err(Error::Config(format!(
                "rule-provider format 不支持：{other}（支持 yaml、text、mrs）"
            ))),
        }
    }
}

/// 规则集文件内容的格式与解释方式。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetFormat {
    SingBox(SingBoxFormat),
    Mihomo {
        behavior: Behavior,
        format: MihomoFormat,
    },
}

impl RuleSetFormat {
    pub fn decode(self, bytes: &[u8]) -> Result<Vec<CompiledHeadlessRule>> {
        let specs = match self {
            Self::SingBox(format) => {
                let binary = match format {
                    SingBoxFormat::Auto => bytes.starts_with(srs::MAGIC),
                    SingBoxFormat::Source => false,
                    SingBoxFormat::Binary => true,
                };
                if binary {
                    srs::read(bytes)?.rules
                } else {
                    parse_source_json(bytes)?.rules
                }
            }
            Self::Mihomo { behavior, format } => match format {
                MihomoFormat::Mrs => {
                    let (domains, ip_cidr) =
                        mrs::read_compiled(bytes, Some(behavior), wildcard_regex)?;
                    return Ok(vec![CompiledHeadlessRule {
                        domains,
                        domain_wildcard: Vec::new(),
                        ip_cidr,
                        port: Vec::new(),
                        port_range: Vec::new(),
                        source_ip_cidr: IpSet::default(),
                        source_port: Vec::new(),
                        source_port_range: Vec::new(),
                        networks: Vec::new(),
                        process_name: Vec::new(),
                        process_path: Vec::new(),
                        process_name_regex: Vec::new(),
                        process_path_regex: Vec::new(),
                        platform_only: false,
                        invert: false,
                        logical: None,
                    }]);
                }
                MihomoFormat::Yaml | MihomoFormat::Text => {
                    let text = std::str::from_utf8(bytes)
                        .map_err(|_| Error::Config("rule-provider 文件不是 UTF-8 文本".into()))?;
                    let lines = if format == MihomoFormat::Yaml {
                        yaml_payload(text)?
                    } else {
                        text_lines(text)
                    };
                    provider_lines(&lines, behavior)?
                }
            },
        };
        specs.iter().map(CompiledHeadlessRule::compile).collect()
    }
}

fn parse_source_json(bytes: &[u8]) -> Result<SourceRuleSetFile> {
    let parsed: SourceRuleSetFile = serde_json::from_slice(bytes)
        .map_err(|e| Error::Config(format!("源格式规则集 JSON 不合法：{e}")))?;
    if !(1..=srs::MAX_VERSION).contains(&parsed.version) {
        return Err(Error::Config("规则集 version 不受支持".into()));
    }
    Ok(parsed)
}

/// Mihomo `text` 格式：逐行，忽略空行与 `#`、`//` 注释。
pub fn text_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(str::to_owned)
        .collect()
}

/// Mihomo `yaml` 格式：顶层 `payload:`（或 `rules:`）下的列表项；没有该键时报错（同 Mihomo）。
pub fn yaml_payload(text: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut in_payload = false;
    let mut found = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let indented = raw.starts_with([' ', '\t']);
        if !indented && !line.starts_with('-') {
            let (key, rest) = line.split_once(':').unwrap_or((line, ""));
            in_payload = matches!(key.trim(), "payload" | "rules");
            found |= in_payload;
            let rest = rest.trim();
            if in_payload && rest.starts_with('[') {
                let inner = rest.trim_start_matches('[').trim_end_matches(']');
                out.extend(
                    split_flow(inner)
                        .into_iter()
                        .map(|item| unquote(&item))
                        .filter(|s| !s.is_empty()),
                );
                in_payload = false;
            }
            continue;
        }
        if in_payload && let Some(item) = line.strip_prefix('-') {
            let value = unquote(item);
            if !value.is_empty() {
                out.push(value);
            }
        }
    }
    if !found {
        return Err(Error::Config("yaml rule-provider 缺少 payload".into()));
    }
    Ok(out)
}

fn split_flow(inner: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for c in inner.chars() {
        match (quote, c) {
            (None, '\'' | '"') => {
                quote = Some(c);
                current.push(c);
            }
            (Some(q), c) if c == q => {
                quote = None;
                current.push(c);
            }
            (None, ',') => items.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    items.push(current);
    items
}

fn unquote(item: &str) -> String {
    let item = item.trim();
    if let Some(rest) = item.strip_prefix('\'') {
        let mut out = String::new();
        let mut chars = rest.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                    out.push('\'');
                    continue;
                }
                break;
            }
            out.push(c);
        }
        return out;
    }
    if let Some(rest) = item.strip_prefix('"') {
        return rest
            .split('"')
            .next()
            .unwrap_or_default()
            .replace("\\\\", "\\");
    }
    let bare = match item.find(" #") {
        Some(idx) => &item[..idx],
        None => item,
    };
    bare.trim().to_owned()
}

/// Mihomo domain behavior 的写法转为无头规则：`+.d` 为后缀，`.d` 仅子域，含 `*` 的转为正则。
pub fn mihomo_domains_to_headless(patterns: &[String]) -> HeadlessRuleSpec {
    let mut spec = HeadlessRuleSpec::default();
    for pattern in patterns {
        if pattern.contains('*') {
            spec.domain_regex.push(wildcard_regex(pattern));
        } else if let Some(rest) = pattern.strip_prefix("+.") {
            spec.domain_suffix.push(rest.to_owned());
        } else if pattern.starts_with('.') {
            spec.domain_suffix.push(pattern.clone());
        } else {
            spec.domain.push(pattern.clone());
        }
    }
    spec
}

/// `*` 匹配恰好一级非空标签（Mihomo `DomainSet.Has` 语义）。
fn wildcard_regex(pattern: &str) -> String {
    let (prefix, core) = if let Some(rest) = pattern.strip_prefix("+.") {
        (r"^(?:.+\.)?", rest)
    } else if let Some(rest) = pattern.strip_prefix('.') {
        (r"^.+\.", rest)
    } else {
        ("^", pattern)
    };
    let labels: Vec<String> = core
        .split('.')
        .map(|label| {
            if label == "*" {
                "[^.]+".to_owned()
            } else {
                regex::escape(label)
            }
        })
        .collect();
    format!("{prefix}{}$", labels.join(r"\."))
}

/// 无头规则还原为 Mihomo domain 写法；关键字与正则无法表示时返回错误。
pub fn headless_to_mihomo_domains(rules: &[HeadlessRuleSpec]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for rule in rules {
        if !rule.domain_keyword.is_empty()
            || !rule.domain_regex.is_empty()
            || !rule.domain_wildcard.is_empty()
            || !rule.ip_cidr.is_empty()
            || rule.logical_type.is_some()
            || rule.invert
        {
            return Err(Error::Config(
                "Mihomo domain 规则集只能表示 domain 与 domain_suffix".into(),
            ));
        }
        out.extend(rule.domain.iter().cloned());
        for suffix in &rule.domain_suffix {
            if suffix.starts_with('.') {
                out.push(suffix.clone());
            } else {
                out.push(format!("+.{suffix}"));
            }
        }
    }
    Ok(out)
}

pub fn mrs_to_headless(payload: MrsPayload) -> HeadlessRuleSpec {
    match payload {
        MrsPayload::Domain(patterns) => mihomo_domains_to_headless(&patterns),
        MrsPayload::IpCidr(set) => HeadlessRuleSpec {
            ip_cidr: set.prefixes(),
            ..Default::default()
        },
    }
}

/// Mihomo rule-provider 条目；无效条目跳过（同 Mihomo 只记警告）。
pub fn provider_lines(lines: &[String], behavior: Behavior) -> Result<Vec<HeadlessRuleSpec>> {
    match behavior {
        Behavior::Domain => {
            let patterns: Vec<String> = lines
                .iter()
                .filter_map(|l| mrs::valid_domain_pattern(l))
                .collect();
            Ok(vec![mihomo_domains_to_headless(&patterns)])
        }
        Behavior::IpCidr => Ok(vec![HeadlessRuleSpec {
            ip_cidr: lines
                .iter()
                .filter(|l| parse_prefix(l).is_ok())
                .cloned()
                .collect(),
            ..Default::default()
        }]),
        Behavior::Classical => classical_lines(lines),
    }
}

/// Mihomo behavior 写法（`domain`/`ipcidr`）的条目集合，供写出 `.mrs`。
pub fn provider_mrs_payload(lines: &[String], behavior: Behavior) -> Result<MrsPayload> {
    match behavior {
        Behavior::Domain => Ok(MrsPayload::Domain(
            lines
                .iter()
                .filter_map(|l| mrs::valid_domain_pattern(l))
                .collect(),
        )),
        Behavior::IpCidr => {
            let mut builder = IpSetBuilder::default();
            for line in lines {
                if let Ok((addr, len)) = parse_prefix(line) {
                    builder.add_prefix(addr, len);
                }
            }
            Ok(MrsPayload::IpCidr(builder.build()))
        }
        Behavior::Classical => Err(Error::Config("classical 规则集不能写出 mrs".into())),
    }
}

/// classical 每行是一条独立规则：只含目标条件的行合并为一条，其余每行一条。
fn classical_lines(lines: &[String]) -> Result<Vec<HeadlessRuleSpec>> {
    let mut targets = HeadlessRuleSpec::default();
    let mut others = Vec::new();
    for raw in lines {
        let mut parts = raw.split(',').map(str::trim);
        let (Some(kind), Some(val)) = (parts.next(), parts.next()) else {
            continue;
        };
        let val = val.to_owned();
        let mut single = HeadlessRuleSpec::default();
        match kind.to_ascii_uppercase().as_str() {
            "DOMAIN" => targets.domain.push(val),
            "DOMAIN-SUFFIX" => targets
                .domain_suffix
                .push(val.trim_start_matches('.').to_owned()),
            "DOMAIN-KEYWORD" => targets.domain_keyword.push(val),
            "DOMAIN-REGEX" => {
                if Regex::new(&val).is_ok() {
                    targets.domain_regex.push(val);
                }
            }
            "DOMAIN-WILDCARD" => targets.domain_wildcard.push(val),
            "IP-CIDR" | "IP-CIDR6" => {
                if parse_prefix(&val).is_ok() {
                    targets.ip_cidr.push(val);
                }
            }
            "SRC-IP-CIDR" => {
                if parse_prefix(&val).is_ok() {
                    single.source_ip_cidr.push(val);
                }
            }
            "DST-PORT" => match port_value(&val) {
                Some(Ok(p)) => single.port.push(p),
                Some(Err(range)) => single.port_range.push(range),
                None => continue,
            },
            "SRC-PORT" => match port_value(&val) {
                Some(Ok(p)) => single.source_port.push(p),
                Some(Err(range)) => single.source_port_range.push(range),
                None => continue,
            },
            "PROCESS-NAME" => single.process_name.push(val),
            "PROCESS-PATH" => single.process_path.push(val),
            "PROCESS-NAME-REGEX" => single.process_name_regex.push(val),
            "PROCESS-PATH-REGEX" => single.process_path_regex.push(val),
            "NETWORK" => single.network = StringOrVec::Single(val),
            "RULE-SET" | "SUB-RULE" | "MATCH" => {
                return Err(Error::Config(format!("classical 规则集不支持 {kind}")));
            }
            other => {
                return Err(Error::Config(format!(
                    "classical 规则类型尚未支持：{other}"
                )));
            }
        }
        if CompiledHeadlessRule::compile(&single).is_ok() && !is_blank(&single) {
            others.push(single);
        }
    }
    let mut out = Vec::new();
    if !is_blank(&targets) {
        out.push(targets);
    }
    out.extend(others);
    Ok(out)
}

fn is_blank(spec: &HeadlessRuleSpec) -> bool {
    serde_json::to_value(spec).is_ok_and(|v| v.as_object().is_some_and(|m| m.is_empty()))
}

fn port_value(val: &str) -> Option<std::result::Result<u16, String>> {
    if val.contains('-') || val.contains(':') {
        let range = val.replace('-', ":");
        PortRange::parse(&range).ok().map(|_| Err(range))
    } else {
        val.parse().ok().map(Ok)
    }
}

/// 规则集文件的下载来源；`interval` 为零时只在缓存缺失时下载。
#[derive(Clone, Debug)]
pub struct RemoteRuleSet {
    pub url: String,
    pub interval: Duration,
    pub detour: Option<String>,
    pub size_limit: Option<u64>,
}

/// 规则集的文件来源：本地文件，或远程内容的缓存文件。
#[derive(Clone, Debug)]
pub struct RuleSetFile {
    pub path: PathBuf,
    pub remote: Option<RemoteRuleSet>,
}

/// 一个规则集的内联规则、文件来源与解码方式；启动和每次刷新都用它把文件字节编译为规则集。
#[derive(Clone, Debug)]
pub struct RuleSetSource {
    pub tag: String,
    pub format: RuleSetFormat,
    inline: Vec<CompiledHeadlessRule>,
    pub file: Option<RuleSetFile>,
}

impl RuleSetSource {
    /// 内联规则加上文件内容；`file` 为 `None` 表示文件内容尚不可用。
    pub fn compile(&self, file: Option<&[u8]>) -> Result<CompiledRuleSet> {
        let mut rules = self.inline.clone();
        if let Some(bytes) = file {
            rules.extend(self.format.decode(bytes)?);
        }
        Ok(CompiledRuleSet {
            tag: self.tag.clone(),
            rules,
        })
    }
}

/// 远程资源未给 `path` 时的默认缓存位置：`<dir>/<name>`，名称中路径分隔符等字符替换为 `_`。
pub fn default_cache_path(dir: &str, name: &str) -> PathBuf {
    let file: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let file = match file.trim_start_matches('.') {
        "" => "_".to_owned(),
        trimmed => trimmed.to_owned(),
    };
    PathBuf::from(dir).join(file)
}

fn http_url(url: Option<&str>, what: &str) -> Result<String> {
    let url = url
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| Error::Config(format!("{what} 缺少 url")))?;
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(Error::Config(format!("{what} url 必须为 http/https")));
    }
    Ok(url.to_owned())
}

/// sing-box `update_interval` 语法：`1d`、`12h`、`30m`、`90s` 及组合 `1h30m`；纯数字按秒。
pub fn parse_update_interval(raw: &str) -> Result<Duration> {
    let invalid = || Error::Config(format!("update_interval 不合法：{raw}"));
    let raw = raw.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }
    let mut total = 0u64;
    let mut digits = String::new();
    for c in raw.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c {
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => return Err(invalid()),
        };
        let value: u64 = digits.parse().map_err(|_| invalid())?;
        total = value
            .checked_mul(unit)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(invalid)?;
        digits.clear();
    }
    if !digits.is_empty() || raw.is_empty() {
        return Err(invalid());
    }
    Ok(Duration::from_secs(total))
}

fn sing_box_format(raw: Option<&str>) -> Result<SingBoxFormat> {
    match raw.map(|f| f.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") => Ok(SingBoxFormat::Auto),
        Some("source" | "json") => Ok(SingBoxFormat::Source),
        Some("binary" | "srs") => Ok(SingBoxFormat::Binary),
        Some(other) => Err(Error::Config(format!(
            "rule_set format 不支持：{other}（支持 source、binary）"
        ))),
    }
}

impl RuleSetSpec {
    pub fn source(&self) -> Result<RuleSetSource> {
        let tag = self.tag.trim();
        if tag.is_empty() {
            return Err(Error::Config("rule_set tag 不能为空".into()));
        }
        let inline = self
            .rules
            .iter()
            .map(CompiledHeadlessRule::compile)
            .collect::<Result<Vec<_>>>()?;
        let file = match self.kind.trim().to_ascii_lowercase().as_str() {
            "inline" => {
                if inline.is_empty() {
                    return Err(Error::Config("inline rule_set 必须包含 rules".into()));
                }
                None
            }
            "local" => Some(RuleSetFile {
                path: self
                    .path
                    .as_deref()
                    .map(PathBuf::from)
                    .ok_or_else(|| Error::Config("local rule_set 缺少 path".into()))?,
                remote: None,
            }),
            "remote" => Some(RuleSetFile {
                path: self
                    .path
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| default_cache_path("rules", tag)),
                remote: Some(RemoteRuleSet {
                    url: http_url(self.url.as_deref(), "remote rule_set")?,
                    interval: parse_update_interval(
                        self.update_interval.as_deref().unwrap_or("1d"),
                    )?,
                    detour: self.download_detour.clone(),
                    size_limit: None,
                }),
            }),
            _ => return Err(Error::Config("rule_set type 不合法".into())),
        };
        Ok(RuleSetSource {
            tag: tag.to_owned(),
            format: RuleSetFormat::SingBox(sing_box_format(self.format.as_deref())?),
            inline,
            file,
        })
    }
}

impl RuleProviderSpec {
    pub fn source(&self, default_name: &str) -> Result<RuleSetSource> {
        let tag = self
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(default_name.trim())
            .to_owned();
        if tag.is_empty() {
            return Err(Error::Config("rule-provider name 不能为空".into()));
        }
        let behavior = Behavior::parse(&self.behavior)?;
        let format = MihomoFormat::parse(self.format.as_deref())?;
        if format == MihomoFormat::Mrs && behavior == Behavior::Classical {
            return Err(Error::Config(
                "mrs 格式只支持 domain 与 ipcidr behavior".into(),
            ));
        }
        let inline = if self.payload.is_empty() {
            Vec::new()
        } else {
            provider_lines(&self.payload, behavior)?
                .iter()
                .map(CompiledHeadlessRule::compile)
                .collect::<Result<_>>()?
        };
        let path = self.path.as_deref().map(PathBuf::from);
        let file = match self.kind.trim().to_ascii_lowercase().as_str() {
            "inline" => path.map(|path| RuleSetFile { path, remote: None }),
            "file" | "local" => Some(RuleSetFile {
                path: path.ok_or_else(|| Error::Config("file rule-provider 缺少 path".into()))?,
                remote: None,
            }),
            "http" | "remote" => Some(RuleSetFile {
                path: path.unwrap_or_else(|| default_cache_path("rules", &tag)),
                remote: Some(RemoteRuleSet {
                    url: http_url(self.url.as_deref(), "http rule-provider")?,
                    interval: Duration::from_secs(self.interval.unwrap_or(0)),
                    detour: self.proxy.clone(),
                    size_limit: self.size_limit.filter(|limit| *limit > 0),
                }),
            }),
            _ => return Err(Error::Config("rule-provider type 不合法".into())),
        };
        Ok(RuleSetSource {
            tag,
            format: RuleSetFormat::Mihomo { behavior, format },
            inline,
            file,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct CompiledRuleSet {
    pub tag: String,
    pub rules: Vec<CompiledHeadlessRule>,
}

fn lower_hosts<'a>(hosts: &[&'a str]) -> Vec<Cow<'a, str>> {
    hosts
        .iter()
        .map(|h| {
            let h = h.strip_suffix('.').unwrap_or(h);
            if h.bytes().any(|b| b.is_ascii_uppercase()) {
                Cow::Owned(h.to_ascii_lowercase())
            } else {
                Cow::Borrowed(h)
            }
        })
        .collect()
}

impl CompiledRuleSet {
    pub fn has_process_rules(&self) -> bool {
        self.rules
            .iter()
            .any(CompiledHeadlessRule::has_process_rules)
    }

    /// 条目数：域名、网段与其他条件规则各计一条，对应 Mihomo `ruleCount`。
    pub fn entry_count(&self) -> usize {
        self.rules
            .iter()
            .map(CompiledHeadlessRule::entry_count)
            .sum()
    }

    pub fn matches(
        &self,
        hosts: &[&str],
        ips: &[IpAddr],
        port: u16,
        network: Network,
        source_addr: Option<SocketAddr>,
    ) -> bool {
        self.matches_with_process(hosts, ips, port, network, source_addr, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn matches_with_process(
        &self,
        hosts: &[&str],
        ips: &[IpAddr],
        port: u16,
        network: Network,
        source_addr: Option<SocketAddr>,
        process_name: Option<&str>,
        process_path: Option<&str>,
    ) -> bool {
        let lowered = lower_hosts(hosts);
        let hosts: Vec<&str> = lowered.iter().map(|h| h.as_ref()).collect();
        self.rules.iter().any(|r| {
            r.matches_with_process(
                &hosts,
                ips,
                port,
                network,
                source_addr,
                process_name,
                process_path,
            )
        })
    }

    pub fn cidr_strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for r in &self.rules {
            collect_cidrs(r, &mut out);
        }
        out
    }
}

fn collect_cidrs(rule: &CompiledHeadlessRule, out: &mut Vec<String>) {
    out.extend(rule.ip_cidr.prefixes());
    if let Some((_, children)) = &rule.logical {
        for c in children {
            collect_cidrs(c, out);
        }
    }
}

/// 识别规则集文件内容的格式：`SRS` 开头为 sing-box 二进制，zstd 帧为 Mihomo `.mrs`，
/// 以 `{` 开头为 sing-box 源格式，其余按 Mihomo 文本（含 `payload:` 时为 yaml）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectedFormat {
    Srs,
    Mrs,
    Json,
    Yaml,
    Text,
}

pub fn detect_format(bytes: &[u8]) -> DetectedFormat {
    if bytes.starts_with(srs::MAGIC) {
        return DetectedFormat::Srs;
    }
    if bytes.starts_with(mrs::ZSTD_MAGIC) {
        return DetectedFormat::Mrs;
    }
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]);
    let head = text.trim_start();
    if head.starts_with('{') {
        DetectedFormat::Json
    } else if text.lines().any(|l| {
        matches!(
            l.split(':').next().map(str::trim),
            Some("payload" | "rules")
        ) && !l.starts_with([' ', '\t', '-'])
    }) {
        DetectedFormat::Yaml
    } else {
        DetectedFormat::Text
    }
}

/// 读取任意支持格式的规则集文件为 sing-box 源格式；Mihomo 文本需给出 behavior，缺省按 classical。
pub fn decompile_ruleset_bytes(bytes: &[u8]) -> Result<SourceRuleSetFile> {
    decompile_with_behavior(bytes, None)
}

pub fn decompile_with_behavior(
    bytes: &[u8],
    behavior: Option<Behavior>,
) -> Result<SourceRuleSetFile> {
    let rules = match detect_format(bytes) {
        DetectedFormat::Srs => return srs::read(bytes),
        DetectedFormat::Json => return parse_source_json(bytes),
        DetectedFormat::Mrs => vec![mrs_to_headless(mrs::read(bytes, behavior)?)],
        format @ (DetectedFormat::Yaml | DetectedFormat::Text) => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| Error::Config("规则集文件不是 UTF-8 文本".into()))?;
            let lines = if format == DetectedFormat::Yaml {
                yaml_payload(text)?
            } else {
                text_lines(text)
            };
            provider_lines(&lines, behavior.unwrap_or(Behavior::Classical))?
        }
    };
    Ok(SourceRuleSetFile { version: 2, rules })
}

/// 按格式提示编译规则集文件：`source`/`json`、`binary`/`srs`、`mrs`、`yaml`、`text`，缺省自动识别。
pub fn parse_ruleset_bytes(
    bytes: &[u8],
    format: Option<&str>,
    behavior: Option<&str>,
) -> Result<Vec<CompiledHeadlessRule>> {
    let behavior = behavior.map(Behavior::parse).transpose()?;
    let format = match format.map(|f| f.trim().to_ascii_lowercase()).as_deref() {
        Some("source" | "json") => RuleSetFormat::SingBox(SingBoxFormat::Source),
        Some("binary" | "srs") => RuleSetFormat::SingBox(SingBoxFormat::Binary),
        Some(f @ ("mrs" | "yaml" | "text")) => RuleSetFormat::Mihomo {
            behavior: behavior.unwrap_or(match f {
                "mrs" => mrs_behavior(bytes)?,
                _ => Behavior::Classical,
            }),
            format: MihomoFormat::parse(Some(f))?,
        },
        Some(other) => return Err(Error::Config(format!("规则集格式不支持：{other}"))),
        None => match detect_format(bytes) {
            DetectedFormat::Srs | DetectedFormat::Json => {
                RuleSetFormat::SingBox(SingBoxFormat::Auto)
            }
            DetectedFormat::Mrs => RuleSetFormat::Mihomo {
                behavior: behavior.map_or_else(|| mrs_behavior(bytes), Ok)?,
                format: MihomoFormat::Mrs,
            },
            DetectedFormat::Yaml => RuleSetFormat::Mihomo {
                behavior: behavior.unwrap_or(Behavior::Classical),
                format: MihomoFormat::Yaml,
            },
            DetectedFormat::Text => RuleSetFormat::Mihomo {
                behavior: behavior.unwrap_or(Behavior::Classical),
                format: MihomoFormat::Text,
            },
        },
    };
    format.decode(bytes)
}

fn mrs_behavior(bytes: &[u8]) -> Result<Behavior> {
    Ok(mrs::read(bytes, None)?.behavior())
}

/// 写出 sing-box 二进制规则集（版本取 `source.version`）。
pub fn compile_ruleset_to_srs(source: &SourceRuleSetFile) -> Result<Vec<u8>> {
    for r in &source.rules {
        CompiledHeadlessRule::compile(r)?;
    }
    srs::write(source)
}

/// 写出 Mihomo `.mrs`：只含网段的规则集写为 ipcidr，只含域名与后缀的写为 domain。
pub fn compile_ruleset_to_mrs(source: &SourceRuleSetFile) -> Result<Vec<u8>> {
    let ip_only = !source.rules.is_empty()
        && source.rules.iter().all(|r| {
            let mut probe = r.clone();
            probe.ip_cidr.clear();
            !r.ip_cidr.is_empty() && is_blank(&probe)
        });
    if ip_only {
        let cidrs: Vec<&str> = source
            .rules
            .iter()
            .flat_map(|r| r.ip_cidr.iter().map(String::as_str))
            .collect();
        let payload = MrsPayload::IpCidr(IpSet::from_cidrs(cidrs.iter().copied())?);
        return mrs::write_counted(&payload, cidrs.len());
    }
    mrs::write(&MrsPayload::Domain(headless_to_mihomo_domains(
        &source.rules,
    )?))
}

/// 规则集转为 Mihomo 条目文本（每行一条）；只能表示 domain 或 ipcidr behavior。
pub fn ruleset_to_mihomo_lines(source: &SourceRuleSetFile) -> Result<(Behavior, Vec<String>)> {
    let bytes = compile_ruleset_to_mrs(source)?;
    Ok(match mrs::read(&bytes, None)? {
        MrsPayload::Domain(patterns) => (Behavior::Domain, patterns),
        MrsPayload::IpCidr(set) => (Behavior::IpCidr, set.prefixes()),
    })
}

pub fn convert_adguard_lines(text: &str) -> Result<SourceRuleSetFile> {
    let mut positive = HeadlessRuleSpec::default();
    let mut negative = HeadlessRuleSpec::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }
        let (target_spec, rule) = if let Some(rest) = line.strip_prefix("@@") {
            (&mut negative, rest.trim())
        } else {
            (&mut positive, line)
        };
        let core = rule.split('$').next().unwrap_or(rule).trim();
        if let Some(after_bars) = core.strip_prefix("||") {
            let domain = after_bars
                .trim_end_matches('^')
                .trim_end_matches('/')
                .trim();
            if !domain.is_empty() {
                if domain.contains('*') {
                    target_spec.domain_wildcard.push(domain.to_owned());
                } else {
                    target_spec.domain_suffix.push(domain.to_owned());
                }
            }
        } else if core.starts_with('/') && core.ends_with('/') && core.len() > 2 {
            target_spec
                .domain_regex
                .push(core[1..core.len() - 1].to_owned());
        } else if let Some(host_part) = core
            .strip_prefix("0.0.0.0 ")
            .or_else(|| core.strip_prefix("127.0.0.1 "))
        {
            let domain = host_part.split_whitespace().next().unwrap_or("").trim();
            if !domain.is_empty() && domain != "localhost" {
                target_spec.domain.push(domain.to_owned());
            }
        } else if !core.contains('/') && core.contains('.') {
            let clean = core.trim_matches('|').trim_end_matches('^').trim();
            if !clean.is_empty() {
                target_spec.domain.push(clean.to_owned());
            }
        }
    }
    let mut rules = Vec::new();
    if !is_blank(&negative) {
        negative.invert = true;
        rules.push(negative);
    }
    if !is_blank(&positive) {
        rules.push(positive);
    }
    Ok(SourceRuleSetFile { version: 2, rules })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(rules: &[CompiledHeadlessRule], target: &str) -> bool {
        let set = CompiledRuleSet {
            tag: "t".into(),
            rules: rules.to_vec(),
        };
        match target.parse::<IpAddr>() {
            Ok(ip) => set.matches(&[], &[ip], 443, Network::Tcp, None),
            Err(_) => set.matches(&[target], &[], 443, Network::Tcp, None),
        }
    }

    #[test]
    fn mihomo_yaml_domain_provider_follows_mihomo_patterns() {
        let yaml = "# c\npayload:\n  - '+.example.com'\n  - \".sub.example.org\"\n  - exact.example.net # note\n  - '*.wild.example'\n  - 'bad..domain'\n";
        let rules = RuleSetFormat::Mihomo {
            behavior: Behavior::Domain,
            format: MihomoFormat::Yaml,
        }
        .decode(yaml.as_bytes())
        .unwrap();
        assert!(hit(&rules, "example.com"));
        assert!(hit(&rules, "a.b.example.com"));
        assert!(!hit(&rules, "sub.example.org"));
        assert!(hit(&rules, "x.sub.example.org"));
        assert!(hit(&rules, "EXACT.example.net."));
        assert!(!hit(&rules, "a.exact.example.net"));
        assert!(hit(&rules, "one.wild.example"));
        assert!(!hit(&rules, "two.one.wild.example"));
        assert!(!hit(&rules, "wild.example"));
    }

    #[test]
    fn yaml_without_payload_is_rejected_and_text_ipcidr_skips_invalid_lines() {
        assert!(yaml_payload("- a.com\n").is_err());
        assert_eq!(
            yaml_payload("payload: ['a.com', \"b.com\"]").unwrap(),
            ["a.com", "b.com"]
        );
        let rules = RuleSetFormat::Mihomo {
            behavior: Behavior::IpCidr,
            format: MihomoFormat::Text,
        }
        .decode(b"// c\n1.0.1.0/24\nnot-an-ip\n240e::/18\n")
        .unwrap();
        assert!(hit(&rules, "1.0.1.200"));
        assert!(hit(&rules, "240e::1"));
        assert!(!hit(&rules, "1.0.2.1"));
    }

    #[test]
    fn classical_lines_are_independent_rules() {
        let rules = RuleSetFormat::Mihomo {
            behavior: Behavior::Classical,
            format: MihomoFormat::Text,
        }
        .decode(b"DOMAIN-SUFFIX,a.example\nDST-PORT,8443\nIP-CIDR,10.0.0.0/8,no-resolve\n")
        .unwrap();
        assert!(hit(&rules, "x.a.example"), "域名行不受端口行约束");
        assert!(hit(&rules, "10.1.1.1"));
        assert!(!hit(&rules, "b.example"));
    }

    #[test]
    fn sing_box_suffix_with_leading_dot_matches_only_subdomains() {
        let rules = parse_ruleset_bytes(
            br#"{"version":2,"rules":[{"domain_suffix":[".only-sub.example","both.example"]}]}"#,
            None,
            None,
        )
        .unwrap();
        assert!(!hit(&rules, "only-sub.example"));
        assert!(hit(&rules, "a.only-sub.example"));
        assert!(hit(&rules, "both.example"));
    }

    #[test]
    fn platform_only_items_never_match_routing_connections() {
        let rules = parse_ruleset_bytes(
            br#"{"version":3,"rules":[{"domain":["a.example"],"network_type":["wifi"]}]}"#,
            None,
            None,
        )
        .unwrap();
        assert!(!hit(&rules, "a.example"));
        let inverted = parse_ruleset_bytes(
            br#"{"version":1,"rules":[{"domain":["b.example"],"package_name":["x"],"invert":true}]}"#,
            None,
            None,
        )
        .unwrap();
        assert!(hit(&inverted, "b.example"), "条件不成立后再取反");
    }

    #[test]
    fn converts_between_srs_mrs_and_source() {
        let source: SourceRuleSetFile = serde_json::from_str(
            r#"{"version":2,"rules":[{"domain":["a.example"],"domain_suffix":["b.example",".c.example"]}]}"#,
        )
        .unwrap();
        let srs = compile_ruleset_to_srs(&source).unwrap();
        let mrs = compile_ruleset_to_mrs(&source).unwrap();
        for bytes in [&srs, &mrs] {
            let back = decompile_ruleset_bytes(bytes).unwrap();
            assert_eq!(back.rules[0].domain, ["a.example"]);
            let mut suffixes = back.rules[0].domain_suffix.clone();
            suffixes.sort();
            assert_eq!(suffixes, [".c.example", "b.example"]);
        }
        let (behavior, lines) = ruleset_to_mihomo_lines(&source).unwrap();
        assert_eq!(behavior, Behavior::Domain);
        assert_eq!(lines, ["a.example", "+.b.example", ".c.example"]);
        let ip: SourceRuleSetFile =
            serde_json::from_str(r#"{"version":1,"rules":[{"ip_cidr":["1.0.0.0/8"]}]}"#).unwrap();
        let (behavior, lines) = ruleset_to_mihomo_lines(&ip).unwrap();
        assert_eq!(
            (behavior, lines),
            (Behavior::IpCidr, vec!["1.0.0.0/8".to_owned()])
        );
    }
}
