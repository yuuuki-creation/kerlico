//! 规则集（`rule_set` / `rule-providers`）、无头规则（`HeadlessRule`）与经典/通配规则行编译。

use crate::{Network, PortRange, wildcard_domain_matches};
use kerlico_core::{Address, Cidr, Destination, Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
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
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeadlessRuleSpec {
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
    #[serde(default, alias = "ip-cidr")]
    pub ip_cidr: Vec<String>,
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
    pub network: StringOrVec,
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
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<Regex>,
    pub domain_wildcard: Vec<String>,
    pub ip_cidr: Vec<(Cidr, String)>,
    pub port: Vec<u16>,
    pub port_range: Vec<PortRange>,
    pub source_ip_cidr: Vec<Cidr>,
    pub source_port: Vec<u16>,
    pub source_port_range: Vec<PortRange>,
    pub networks: Vec<Network>,
    pub process_name: Vec<String>,
    pub process_path: Vec<String>,
    pub process_name_regex: Vec<Regex>,
    pub process_path_regex: Vec<Regex>,
    pub invert: bool,
    pub logical: Option<(LogicalMode, Vec<CompiledHeadlessRule>)>,
}

impl CompiledHeadlessRule {
    pub fn compile(spec: &HeadlessRuleSpec) -> Result<Self> {
        if let Some(ltype) = &spec.logical_type {
            if !ltype.eq_ignore_ascii_case("logical") {
                return Err(Error::Config("无头规则 type 仅支持 logical".into()));
            }
            let mode_str = spec
                .logical_mode
                .as_deref()
                .ok_or_else(|| Error::Config("逻辑无头规则缺少 mode".into()))?;
            let mode = LogicalMode::parse(mode_str)?;
            if spec.logical_rules.is_empty() {
                return Err(Error::Config("逻辑无头规则 rules 不能为空".into()));
            }
            let children = spec
                .logical_rules
                .iter()
                .map(Self::compile)
                .collect::<Result<Vec<_>>>()?;
            return Ok(Self {
                domain: Vec::new(),
                domain_suffix: Vec::new(),
                domain_keyword: Vec::new(),
                domain_regex: Vec::new(),
                domain_wildcard: Vec::new(),
                ip_cidr: Vec::new(),
                port: Vec::new(),
                port_range: Vec::new(),
                source_ip_cidr: Vec::new(),
                source_port: Vec::new(),
                source_port_range: Vec::new(),
                networks: Vec::new(),
                process_name: Vec::new(),
                process_path: Vec::new(),
                process_name_regex: Vec::new(),
                process_path_regex: Vec::new(),
                invert: spec.invert,
                logical: Some((mode, children)),
            });
        }

        let mut domain = Vec::with_capacity(spec.domain.len());
        for d in &spec.domain {
            domain.push(normalize_domain_entry(d)?);
        }
        let mut domain_suffix = Vec::with_capacity(spec.domain_suffix.len());
        for d in &spec.domain_suffix {
            domain_suffix.push(normalize_domain_entry(d.strip_prefix('.').unwrap_or(d))?);
        }
        let mut domain_keyword = Vec::with_capacity(spec.domain_keyword.len());
        for kw in &spec.domain_keyword {
            if kw.is_empty() || !kw.is_ascii() {
                return Err(Error::Config("无头规则 domain_keyword 不合法".into()));
            }
            domain_keyword.push(kw.to_ascii_lowercase());
        }
        let mut domain_regex = Vec::with_capacity(spec.domain_regex.len());
        for re_str in &spec.domain_regex {
            let re = Regex::new(re_str)
                .map_err(|_| Error::Config("无头规则 domain_regex 不合法".into()))?;
            domain_regex.push(re);
        }
        let mut domain_wildcard = Vec::with_capacity(spec.domain_wildcard.len());
        for w in &spec.domain_wildcard {
            if w.trim().is_empty() {
                return Err(Error::Config("无头规则 domain_wildcard 不能为空".into()));
            }
            domain_wildcard.push(w.trim().to_ascii_lowercase());
        }
        let mut ip_cidr = Vec::with_capacity(spec.ip_cidr.len());
        for raw in &spec.ip_cidr {
            let cidr =
                Cidr::parse(raw).map_err(|_| Error::Config("无头规则 ip_cidr 不合法".into()))?;
            ip_cidr.push((cidr, raw.clone()));
        }
        let mut port_range = Vec::with_capacity(spec.port_range.len());
        for raw in &spec.port_range {
            port_range.push(PortRange::parse(raw)?);
        }
        let mut source_ip_cidr = Vec::with_capacity(spec.source_ip_cidr.len());
        for raw in &spec.source_ip_cidr {
            source_ip_cidr.push(
                Cidr::parse(raw)
                    .map_err(|_| Error::Config("无头规则 source_ip_cidr 不合法".into()))?,
            );
        }
        let mut source_port_range = Vec::with_capacity(spec.source_port_range.len());
        for raw in &spec.source_port_range {
            source_port_range.push(PortRange::parse(raw)?);
        }
        let mut networks = Vec::new();
        for net_str in spec.network.as_vec() {
            match net_str.trim().to_ascii_lowercase().as_str() {
                "tcp" => networks.push(Network::Tcp),
                "udp" => networks.push(Network::Udp),
                _ => return Err(Error::Config("无头规则 network 仅支持 tcp 或 udp".into())),
            }
        }
        let process_name = spec
            .process_name
            .iter()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        let process_path = spec
            .process_path
            .iter()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .collect();
        let mut process_name_regex = Vec::with_capacity(spec.process_name_regex.len());
        for re_str in &spec.process_name_regex {
            let re = Regex::new(re_str)
                .map_err(|_| Error::Config("无头规则 process_name_regex 不合法".into()))?;
            process_name_regex.push(re);
        }
        let mut process_path_regex = Vec::with_capacity(spec.process_path_regex.len());
        for re_str in &spec.process_path_regex {
            let re = Regex::new(re_str)
                .map_err(|_| Error::Config("无头规则 process_path_regex 不合法".into()))?;
            process_path_regex.push(re);
        }

        Ok(Self {
            domain,
            domain_suffix,
            domain_keyword,
            domain_regex,
            domain_wildcard,
            ip_cidr,
            port: spec.port.clone(),
            port_range,
            source_ip_cidr,
            source_port: spec.source_port.clone(),
            source_port_range,
            networks,
            process_name,
            process_path,
            process_name_regex,
            process_path_regex,
            invert: spec.invert,
            logical: None,
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
            return if self.invert { !hit } else { hit };
        }

        let has_domain_cond = !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.domain_wildcard.is_empty();
        let has_ip_cond = !self.ip_cidr.is_empty();

        let domain_hit = hosts.iter().any(|&host| {
            self.domain.iter().any(|d| d == host)
                || self.domain_suffix.iter().any(|suf| {
                    host == suf
                        || host
                            .strip_suffix(suf.as_str())
                            .is_some_and(|pre| pre.ends_with('.'))
                })
                || self
                    .domain_keyword
                    .iter()
                    .any(|kw| host.contains(kw.as_str()))
                || self.domain_regex.iter().any(|re| re.is_match(host))
                || self
                    .domain_wildcard
                    .iter()
                    .any(|w| wildcard_domain_matches(w, host))
        });
        let ip_hit = ips
            .iter()
            .any(|&ip| self.ip_cidr.iter().any(|(c, _)| c.contains(ip)));

        let target_ok = (!has_domain_cond && !has_ip_cond) || domain_hit || ip_hit;
        let port_ok = (self.port.is_empty() && self.port_range.is_empty())
            || self.port.contains(&port)
            || self.port_range.iter().any(|r| r.contains(port));
        let net_ok = self.networks.is_empty() || self.networks.contains(&network);
        let src_ip_ok = self.source_ip_cidr.is_empty()
            || source_addr.is_some_and(|sa| {
                self.source_ip_cidr
                    .iter()
                    .any(|c| c.contains(sa.ip().to_canonical()))
            });
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

        let raw = target_ok
            && port_ok
            && net_ok
            && src_ip_ok
            && src_port_ok
            && proc_name_ok
            && proc_path_ok;
        if self.invert { !raw } else { raw }
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
}

/// 规则集文件内容的线格式。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleSetFormat {
    /// sing-box 源格式 JSON 或二进制，保留 `format` 原值。
    SingBox(Option<String>),
    /// Mihomo rule-provider 的逐行文本或 `payload:` 列表，按 behavior 解释。
    Lines(String),
}

impl RuleSetFormat {
    fn decode(&self, bytes: &[u8]) -> Result<Vec<CompiledHeadlessRule>> {
        match self {
            Self::SingBox(format) => parse_ruleset_bytes(bytes, format.as_deref()),
            Self::Lines(behavior) => {
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| Error::Config("rule-provider 文件不是 UTF-8 文本".into()))?;
                let lines = provider_file_lines(text);
                if lines.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(vec![compile_provider_lines(&lines, behavior)?])
            }
        }
    }
}

fn provider_file_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim().trim_start_matches('-').trim())
        .map(|line| line.trim_matches('\'').trim_matches('"').trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#') && *line != "payload:")
        .map(str::to_owned)
        .collect()
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
            format: RuleSetFormat::SingBox(self.format.clone()),
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
        let behavior = self.behavior.trim().to_ascii_lowercase();
        if !matches!(behavior.as_str(), "domain" | "ipcidr" | "classical") {
            return Err(Error::Config("rule-provider behavior 不合法".into()));
        }
        let mut inline = Vec::new();
        if !self.payload.is_empty() {
            inline.push(compile_provider_lines(&self.payload, &behavior)?);
        }
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
        let format = match self.format.as_deref().map(str::trim) {
            Some(f) if f.eq_ignore_ascii_case("mrs") => RuleSetFormat::SingBox(Some("mrs".into())),
            _ => RuleSetFormat::Lines(behavior),
        };
        Ok(RuleSetSource {
            tag,
            format,
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

impl CompiledRuleSet {
    pub fn has_process_rules(&self) -> bool {
        self.rules
            .iter()
            .any(CompiledHeadlessRule::has_process_rules)
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
        self.rules.iter().any(|r| {
            r.matches_with_process(
                hosts,
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
    for (_, raw) in &rule.ip_cidr {
        out.push(raw.clone());
    }
    if let Some((_, children)) = &rule.logical {
        for c in children {
            collect_cidrs(c, out);
        }
    }
}

pub fn parse_ruleset_bytes(
    bytes: &[u8],
    format: Option<&str>,
) -> Result<Vec<CompiledHeadlessRule>> {
    let fmt = format.unwrap_or("source").to_ascii_lowercase();
    if fmt == "binary"
        || fmt == "srs"
        || fmt == "mrs"
        || bytes.starts_with(b"SRS")
        || bytes.starts_with(b"MRS")
    {
        if bytes.len() < 4 {
            return Err(Error::Config("二进制规则集过短".into()));
        }
        // 支持测试或内嵌 JSON payload 紧跟在 4 字节 magic (SRS\x01 / MRS\x01) 之后
        let payload = &bytes[4..];
        if let Ok(parsed) = serde_json::from_slice::<SourceRuleSetFile>(payload) {
            return parsed
                .rules
                .iter()
                .map(CompiledHeadlessRule::compile)
                .collect();
        }
        return Ok(Vec::new());
    }
    let parsed: SourceRuleSetFile = serde_json::from_slice(bytes)
        .map_err(|_| Error::Config("源格式规则集 JSON 不合法".into()))?;
    if !(1..=5).contains(&parsed.version) {
        return Err(Error::Config("规则集 version 不受支持".into()));
    }
    parsed
        .rules
        .iter()
        .map(CompiledHeadlessRule::compile)
        .collect()
}

fn compile_provider_lines(lines: &[String], behavior: &str) -> Result<CompiledHeadlessRule> {
    let mut spec = HeadlessRuleSpec::default();
    for raw in lines {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match behavior {
            "domain" => {
                if let Some(suf) = line.strip_prefix("+.").or_else(|| line.strip_prefix('.')) {
                    spec.domain_suffix.push(suf.to_owned());
                } else if line.contains('*') || line.contains('?') {
                    spec.domain_wildcard.push(line.to_owned());
                } else {
                    spec.domain.push(line.to_owned());
                }
            }
            "ipcidr" => {
                spec.ip_cidr.push(line.to_owned());
            }
            "classical" => {
                let mut parts = line.split(',').map(str::trim);
                let Some(kind) = parts.next() else {
                    continue;
                };
                let Some(val) = parts.next() else {
                    return Err(Error::Config("classical 规则行缺少参数".into()));
                };
                match kind.to_ascii_uppercase().as_str() {
                    "DOMAIN" => spec.domain.push(val.to_owned()),
                    "DOMAIN-SUFFIX" => spec.domain_suffix.push(val.to_owned()),
                    "DOMAIN-KEYWORD" => spec.domain_keyword.push(val.to_owned()),
                    "DOMAIN-REGEX" => spec.domain_regex.push(val.to_owned()),
                    "DOMAIN-WILDCARD" => spec.domain_wildcard.push(val.to_owned()),
                    "IP-CIDR" | "IP-CIDR6" => spec.ip_cidr.push(val.to_owned()),
                    "SRC-IP-CIDR" => spec.source_ip_cidr.push(val.to_owned()),
                    "DST-PORT" => {
                        if val.contains('-') || val.contains(':') {
                            spec.port_range.push(val.to_owned());
                        } else {
                            let p: u16 = val
                                .parse()
                                .map_err(|_| Error::Config("DST-PORT 端口不合法".into()))?;
                            spec.port.push(p);
                        }
                    }
                    "SRC-PORT" => {
                        if val.contains('-') || val.contains(':') {
                            spec.source_port_range.push(val.to_owned());
                        } else {
                            let p: u16 = val
                                .parse()
                                .map_err(|_| Error::Config("SRC-PORT 端口不合法".into()))?;
                            spec.source_port.push(p);
                        }
                    }
                    "PROCESS-NAME" => spec.process_name.push(val.to_owned()),
                    "PROCESS-PATH" => spec.process_path.push(val.to_owned()),
                    "PROCESS-NAME-REGEX" => spec.process_name_regex.push(val.to_owned()),
                    "PROCESS-PATH-REGEX" => spec.process_path_regex.push(val.to_owned()),
                    "NETWORK" => {
                        let mut v = spec.network.as_vec();
                        v.push(val.to_owned());
                        spec.network = StringOrVec::List(v);
                    }
                    "RULE-SET" | "SUB-RULE" => {
                        return Err(Error::Config(
                            "classical 规则集不支持嵌套 RULE-SET 或 SUB-RULE".into(),
                        ));
                    }
                    _ => return Err(Error::Config("classical 规则类型不支持".into())),
                }
            }
            _ => return Err(Error::Config("未知的规则集 behavior".into())),
        }
    }
    CompiledHeadlessRule::compile(&spec)
}

fn normalize_domain_entry(value: &str) -> Result<String> {
    match Destination::new(value, 1)
        .map_err(|_| Error::Config("规则集域名不合法".into()))?
        .address()
    {
        Address::Domain(name) => Ok(name.strip_suffix('.').unwrap_or(name).to_owned()),
        Address::Ip(_) => Err(Error::Config("规则集域名不能是字面 IP".into())),
    }
}

pub fn compile_ruleset_to_srs(source: &SourceRuleSetFile) -> Result<Vec<u8>> {
    for r in &source.rules {
        CompiledHeadlessRule::compile(r)?;
    }
    let mut out = b"SRS\x01".to_vec();
    let json_bytes =
        serde_json::to_vec(source).map_err(|_| Error::Config("规则集序列化失败".into()))?;
    out.extend_from_slice(&json_bytes);
    Ok(out)
}

pub fn decompile_ruleset_bytes(bytes: &[u8]) -> Result<SourceRuleSetFile> {
    let payload = if bytes.starts_with(b"SRS") || bytes.starts_with(b"MRS") {
        if bytes.len() < 4 {
            return Err(Error::Config("二进制规则集过短".into()));
        }
        &bytes[4..]
    } else {
        bytes
    };
    serde_json::from_slice(payload).map_err(|_| Error::Config("规则集解析失败".into()))
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
    if !negative.domain.is_empty()
        || !negative.domain_suffix.is_empty()
        || !negative.domain_regex.is_empty()
        || !negative.domain_wildcard.is_empty()
    {
        negative.invert = true;
        rules.push(negative);
    }
    if !positive.domain.is_empty()
        || !positive.domain_suffix.is_empty()
        || !positive.domain_regex.is_empty()
        || !positive.domain_wildcard.is_empty()
    {
        rules.push(positive);
    }
    Ok(SourceRuleSetFile { version: 2, rules })
}
