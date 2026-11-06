//! 策略组（`select`、`url-test`、`fallback`、`load-balance`、`balancer`）、代理提供者（`proxy-providers`）与日志配置。

use crate::{OutboundSpec, format::parse_yaml_with_anchors};
use kerlico_core::{Error, OutId, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogSpec {
    pub disabled: bool,
    #[serde(alias = "loglevel", alias = "log-level")]
    pub level: Option<String>,
    #[serde(alias = "access")]
    pub output: Option<String>,
    pub error: Option<String>,
    pub timestamp: bool,
    pub structured: bool,
}

impl LogSpec {
    pub fn normalized_level(&self, global_override: Option<&str>) -> Result<String> {
        let raw = self
            .level
            .as_deref()
            .or(global_override)
            .unwrap_or(if self.disabled { "silent" } else { "info" });
        let lower = raw.trim().to_ascii_lowercase();
        match lower.as_str() {
            "trace" | "debug" | "info" | "warn" | "warning" | "error" | "fatal" | "panic"
            | "silent" | "none" => Ok(if lower == "warn" {
                "warning".into()
            } else if lower == "none" {
                "silent".into()
            } else {
                lower
            }),
            _ => Err(Error::Config(format!("日志级别不合法：{raw}"))),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthCheckSpec {
    #[serde(alias = "enabled")]
    pub enable: bool,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub timeout: Option<u64>,
    pub lazy: Option<bool>,
    #[serde(alias = "expected-status")]
    pub expected_status: Option<Value>,
}

/// `proxy-name` 的一条正则替换规则，语义同 Mihomo `override.proxy-name`。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyNameRule {
    pub pattern: String,
    #[serde(default)]
    pub target: String,
}

/// `proxy-providers.<name>.override`。字段语义同 Mihomo：对每个通过过滤的成员，先把这些字段
/// 覆盖写入原始代理映射，再走与手写代理相同的逐类型映射。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyProviderOverrideSpec {
    pub tfo: Option<bool>,
    pub mptcp: Option<bool>,
    pub udp: Option<bool>,
    #[serde(alias = "udp-over-tcp")]
    pub udp_over_tcp: Option<bool>,
    pub up: Option<Value>,
    pub down: Option<Value>,
    #[serde(alias = "dialer-proxy", alias = "detour")]
    pub dialer_proxy: Option<String>,
    #[serde(alias = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    #[serde(alias = "name-cert-verify")]
    pub name_cert_verify: Option<String>,
    #[serde(alias = "interface-name")]
    pub interface_name: Option<String>,
    #[serde(alias = "routing-mark")]
    pub routing_mark: Option<u64>,
    #[serde(alias = "ip-version")]
    pub ip_version: Option<String>,
    #[serde(alias = "additional-prefix")]
    pub additional_prefix: Option<String>,
    #[serde(alias = "additional-suffix")]
    pub additional_suffix: Option<String>,
    #[serde(alias = "proxy-name")]
    pub proxy_name: Vec<ProxyNameRule>,
}

impl ProxyProviderOverrideSpec {
    fn compile(&self) -> Result<CompiledOverride<'_>> {
        let mut names = Vec::with_capacity(self.proxy_name.len());
        for rule in &self.proxy_name {
            let re = regex::Regex::new(&rule.pattern).map_err(|e| {
                Error::Config(format!(
                    "override.proxy-name 正则不合法：{}：{e}",
                    rule.pattern
                ))
            })?;
            names.push((re, braced_numeric_refs(&rule.target)));
        }
        let fields: Vec<(&'static str, Value)> = [
            ("tfo", self.tfo.map(Value::from)),
            ("mptcp", self.mptcp.map(Value::from)),
            ("udp", self.udp.map(Value::from)),
            ("udp-over-tcp", self.udp_over_tcp.map(Value::from)),
            ("up", self.up.clone()),
            ("down", self.down.clone()),
            ("dialer-proxy", self.dialer_proxy.clone().map(Value::from)),
            ("skip-cert-verify", self.skip_cert_verify.map(Value::from)),
            (
                "name-cert-verify",
                self.name_cert_verify.clone().map(Value::from),
            ),
            (
                "interface-name",
                self.interface_name.clone().map(Value::from),
            ),
            ("routing-mark", self.routing_mark.map(Value::from)),
            ("ip-version", self.ip_version.clone().map(Value::from)),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .collect();
        Ok(CompiledOverride {
            spec: self,
            names,
            fields,
        })
    }
}

/// 把 `$1` 写成 `${1}`：Mihomo（regexp2）的数字引用只取数字，而 `regex` 会把 `$1_x` 读成名为 `1_x` 的组。
fn braced_numeric_refs(target: &str) -> String {
    let mut out = String::with_capacity(target.len());
    let mut chars = target.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
        } else if chars.peek() == Some(&'$') {
            out.push_str("$$");
            chars.next();
        } else if chars.peek().is_some_and(char::is_ascii_digit) {
            out.push_str("${");
            while let Some(d) = chars.next_if(char::is_ascii_digit) {
                out.push(d);
            }
            out.push('}');
        } else {
            out.push('$');
        }
    }
    out
}

struct CompiledOverride<'a> {
    spec: &'a ProxyProviderOverrideSpec,
    names: Vec<(regex::Regex, String)>,
    fields: Vec<(&'static str, Value)>,
}

impl CompiledOverride<'_> {
    /// 先覆盖字段，再依次做 `proxy-name` 替换、加前缀、加后缀（与 Mihomo `override.Apply` 同序）。
    /// Mihomo 代理映射的字段随后交由逐类型映射校验；kerlico 原生出站只接受名称改写。
    fn apply(&self, member: &mut Value) -> Result<()> {
        let Value::Object(map) = member else {
            return Ok(());
        };
        let native = map.contains_key("tag") || map.contains_key("options");
        let name_key = if map.contains_key("tag") {
            "tag"
        } else {
            "name"
        };
        if native && let Some((key, _)) = self.fields.first() {
            return Err(Error::Config(format!(
                "proxy-provider 成员 {} 是 kerlico 原生出站，不支持 override 字段 {key}",
                map.get(name_key).and_then(Value::as_str).unwrap_or("?")
            )));
        }
        for (key, value) in &self.fields {
            map.insert((*key).to_owned(), value.clone());
        }
        let Some(Value::String(name)) = map.get_mut(name_key) else {
            return Ok(());
        };
        for (re, target) in &self.names {
            *name = re.replace_all(name, target.as_str()).into_owned();
        }
        if let Some(prefix) = &self.spec.additional_prefix {
            name.insert_str(0, prefix);
        }
        if let Some(suffix) = &self.spec.additional_suffix {
            name.push_str(suffix);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyProviderSpec {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    pub path: Option<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    #[serde(alias = "detour")]
    pub proxy: Option<String>,
    #[serde(alias = "size-limit")]
    pub size_limit: Option<u64>,
    pub header: BTreeMap<String, Value>,
    pub payload: Vec<Value>,
    pub filter: Option<String>,
    #[serde(alias = "exclude-filter")]
    pub exclude_filter: Option<String>,
    #[serde(alias = "exclude-type")]
    pub exclude_type: Option<String>,
    #[serde(default, rename = "override")]
    pub override_opts: Option<ProxyProviderOverrideSpec>,
    #[serde(alias = "health-check")]
    pub health_check: HealthCheckSpec,
    #[serde(alias = "health-check-enable")]
    pub health_check_enable: Option<bool>,
    #[serde(alias = "health-check-url")]
    pub health_check_url: Option<String>,
    #[serde(alias = "health-check-interval")]
    pub health_check_interval: Option<u64>,
    #[serde(alias = "health-check-timeout")]
    pub health_check_timeout: Option<u64>,
    #[serde(alias = "health-check-lazy")]
    pub health_check_lazy: Option<bool>,
    #[serde(alias = "health-check-expected-status")]
    pub health_check_expected_status: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct CompiledProxyProvider {
    pub name: String,
    pub kind: String,
    pub path: Option<String>,
    pub url: Option<String>,
    pub interval: u64,
    pub proxy: Option<String>,
    pub size_limit: Option<u64>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub exclude_type: Option<String>,
    pub health_check_enable: bool,
    pub health_check_url: String,
    pub health_check_interval: u64,
    pub health_check_timeout_ms: u64,
    pub health_check_lazy: bool,
    pub health_check_expected_status: String,
    pub proxies: Vec<OutId>,
}

impl ProxyProviderSpec {
    pub fn compile(&self, key_name: &str) -> Result<(CompiledProxyProvider, Vec<OutboundSpec>)> {
        let name = self.name.as_deref().unwrap_or(key_name).trim().to_owned();
        if name.is_empty() {
            return Err(Error::Config("proxy-provider 名称不能为空".into()));
        }
        let kind = if self.kind.trim().is_empty() {
            if !self.payload.is_empty() {
                "inline".to_owned()
            } else if self.url.is_some() {
                "http".to_owned()
            } else {
                "file".to_owned()
            }
        } else {
            self.kind.trim().to_ascii_lowercase()
        };
        if !matches!(kind.as_str(), "file" | "http" | "inline") {
            return Err(Error::Config(format!("proxy-provider 类型不支持：{kind}")));
        }
        if kind == "http" && self.url.as_deref().unwrap_or("").trim().is_empty() {
            return Err(Error::Config("http proxy-provider 必须配置 url".into()));
        }
        if kind == "file"
            && self.path.as_deref().unwrap_or("").trim().is_empty()
            && self.payload.is_empty()
        {
            return Err(Error::Config("file proxy-provider 必须配置 path".into()));
        }
        let mut headers = BTreeMap::new();
        for (hk, hv) in &self.header {
            let vals = match hv {
                Value::String(s) => vec![s.clone()],
                Value::Array(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
                _ => {
                    return Err(Error::Config(
                        "proxy-provider header 值须为字符串或数组".into(),
                    ));
                }
            };
            headers.insert(hk.clone(), vals);
        }

        let mut members = Vec::new();
        for item in &self.payload {
            if let Some(s) = item.as_str() {
                members.extend(parse_subscription_members(s)?);
            } else {
                members.push(item.clone());
            }
        }
        let path = match self.path.as_deref().map(str::trim) {
            Some(path) if !path.is_empty() => Some(path.to_owned()),
            _ if kind == "http" => Some(
                kerlico_routing::default_cache_path("proxies", &name)
                    .to_string_lossy()
                    .into_owned(),
            ),
            _ => None,
        };
        if kind != "inline"
            && let Some(path) = &path
            && let Some(bytes) = crate::resource::read_cached(std::path::Path::new(path))?
        {
            if bytes.len() as u64 > crate::resource::size_limit(self.size_limit) {
                return Err(Error::Config("proxy-provider 文件超过 size-limit".into()));
            }
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| Error::Config("proxy-provider 文件不是 UTF-8".into()))?;
            members.extend(parse_subscription_members(text)?);
        }

        let mut members = filter_members(
            members,
            self.filter.as_deref(),
            self.exclude_filter.as_deref(),
            self.exclude_type.as_deref(),
        )?;
        if let Some(ov) = &self.override_opts {
            let ov = ov.compile()?;
            for member in &mut members {
                ov.apply(member)?;
            }
        }
        let filtered = members
            .into_iter()
            .map(value_to_outbound_spec)
            .collect::<Result<Vec<_>>>()?;
        let mut proxy_ids = Vec::with_capacity(filtered.len());
        for spec in &filtered {
            proxy_ids.push(OutId::parse(&spec.tag)?);
        }

        let hc_enable = self.health_check_enable.unwrap_or(self.health_check.enable);
        let hc_url = self
            .health_check_url
            .clone()
            .or_else(|| self.health_check.url.clone())
            .unwrap_or_else(|| "https://cp.cloudflare.com/generate_204".into());
        let hc_interval = self
            .health_check_interval
            .or(self.health_check.interval)
            .unwrap_or(300);
        let hc_timeout = self
            .health_check_timeout
            .or(self.health_check.timeout)
            .unwrap_or(5000);
        let hc_lazy = self
            .health_check_lazy
            .or(self.health_check.lazy)
            .unwrap_or(true);
        let hc_expected = self
            .health_check_expected_status
            .as_ref()
            .or(self.health_check.expected_status.as_ref())
            .map(expected_status_to_string)
            .unwrap_or_else(|| "204".into());

        Ok((
            CompiledProxyProvider {
                name,
                kind,
                path,
                url: self.url.clone(),
                interval: self.interval.unwrap_or(3600),
                proxy: self.proxy.clone(),
                size_limit: self.size_limit,
                headers,
                filter: self.filter.clone(),
                exclude_filter: self.exclude_filter.clone(),
                exclude_type: self.exclude_type.clone(),
                health_check_enable: hc_enable,
                health_check_url: hc_url,
                health_check_interval: hc_interval,
                health_check_timeout_ms: hc_timeout,
                health_check_lazy: hc_lazy,
                health_check_expected_status: hc_expected,
                proxies: proxy_ids,
            },
            filtered,
        ))
    }
}

pub fn expected_status_to_string(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.trim().to_owned(),
        _ => "204".into(),
    }
}

fn matches_pattern(pat: &str, text: &str) -> Result<bool> {
    if pat.contains('[') && !pat.contains(']') || pat.contains('(') && !pat.contains(')') {
        return Err(Error::Config(format!("正则表达式括号不闭合：{pat}")));
    }
    let (case_insensitive, cleaned) = match pat.strip_prefix("(?i)") {
        Some(rest) => (true, rest),
        None => (false, pat),
    };
    let clean = cleaned.trim_start_matches('(').trim_end_matches(')');
    let hay = if case_insensitive {
        text.to_ascii_lowercase()
    } else {
        text.to_owned()
    };
    for branch in clean.split('|') {
        let b = if case_insensitive {
            branch.to_ascii_lowercase()
        } else {
            branch.to_owned()
        };
        if b.is_empty() {
            continue;
        }
        let anchored_start = b.starts_with('^');
        let anchored_end = b.ends_with('$');
        let core = b.trim_start_matches('^').trim_end_matches('$');
        let matched = match (anchored_start, anchored_end) {
            (true, true) => hay == core,
            (true, false) => hay.starts_with(core),
            (false, true) => hay.ends_with(core),
            (false, false) => hay.contains(core),
        };
        if matched {
            return Ok(true);
        }
    }
    Ok(false)
}

fn member_name(member: &Value) -> &str {
    member
        .get("name")
        .or_else(|| member.get("tag"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn member_kind(member: &Value) -> String {
    let raw = member.get("type").and_then(Value::as_str).unwrap_or("");
    normalize_outbound_kind(raw)
}

/// 在原始成员（Mihomo 映射或 kerlico 原生条目）上按名称与类型过滤，名称取改写之前的原名。
fn filter_members(
    members: Vec<Value>,
    filter: Option<&str>,
    exclude_filter: Option<&str>,
    exclude_type: Option<&str>,
) -> Result<Vec<Value>> {
    let include_pat = filter.map(str::trim).filter(|s| !s.is_empty());
    if let Some(p) = include_pat {
        let _ = matches_pattern(p, "")?;
    }
    let exclude_pat = exclude_filter.map(str::trim).filter(|s| !s.is_empty());
    if let Some(p) = exclude_pat {
        let _ = matches_pattern(p, "")?;
    }
    let excluded_types: Vec<String> = exclude_type
        .unwrap_or("")
        .split('|')
        .map(normalize_outbound_kind)
        .filter(|s| !s.is_empty())
        .collect();

    let mut out = Vec::new();
    for member in members {
        let name = member_name(&member);
        if let Some(pat) = include_pat
            && !matches_pattern(pat, name)?
        {
            continue;
        }
        if let Some(pat) = exclude_pat
            && matches_pattern(pat, name)?
        {
            continue;
        }
        if excluded_types.contains(&member_kind(&member)) {
            continue;
        }
        out.push(member);
    }
    Ok(out)
}

pub fn parse_subscription_content(content: &str) -> Result<Vec<OutboundSpec>> {
    parse_subscription_members(content)?
        .into_iter()
        .map(value_to_outbound_spec)
        .collect()
}

/// 解析订阅内容为未映射的原始成员：Mihomo 代理映射、kerlico 原生条目或分享链接解析结果。
fn parse_subscription_members(content: &str) -> Result<Vec<Value>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    // 1. Try JSON object or array
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        return Ok(extract_members_from_value(val));
    }
    // 2. Try Base64 decoding if no whitespace/newlines or looks like base64
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if !trimmed.contains("://")
        && !trimmed.contains("proxies:")
        && let Some(decoded) = decode_base64_any(&compact)
        && let Ok(decoded_str) = String::from_utf8(decoded)
        && (decoded_str.contains("://") || decoded_str.contains("proxies:"))
    {
        return parse_subscription_members(&decoded_str);
    }
    // 3. Try URI lines if any line contains `://`
    if trimmed.lines().any(|l| l.trim().contains("://")) {
        let mut members = Vec::new();
        for (idx, line) in trimmed.lines().enumerate() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            members.push(crate::share_link::parse(l, idx + 1)?);
        }
        if !members.is_empty() {
            return Ok(members);
        }
    }
    // 4. Try YAML
    if let Ok(val) = parse_yaml_with_anchors(trimmed) {
        return Ok(extract_members_from_value(val));
    }
    Ok(Vec::new())
}

fn extract_members_from_value(val: Value) -> Vec<Value> {
    match val {
        Value::Array(items) => items,
        Value::Object(mut map) => {
            if let Some(Value::Array(items)) =
                map.remove("proxies").or_else(|| map.remove("outbounds"))
            {
                items
            } else if map.contains_key("name") || map.contains_key("tag") {
                vec![Value::Object(map)]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

fn value_to_outbound_spec(val: Value) -> Result<OutboundSpec> {
    let (tag, kind, options) = crate::mihomo::member_outbound(val)?;
    Ok(OutboundSpec {
        tag: sanitize_tag(&tag),
        kind,
        options,
    })
}

pub(crate) fn normalize_outbound_kind(kind: &str) -> String {
    match kind.trim().to_ascii_lowercase().as_str() {
        "ss" => "shadowsocks".into(),
        "ssr" => "shadowsocksr".into(),
        "hy2" => "hysteria2".into(),
        "hy" | "hysteria" => "hysteria1".into(),
        "wg" => "wireguard".into(),
        "socks5" => "socks".into(),
        other => other.into(),
    }
}

fn sanitize_tag(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            s.push(ch);
        } else if ch.is_whitespace() || ch == '.' || ch == ':' {
            s.push('-');
        }
    }
    let trimmed = s.trim_matches('-');
    if trimmed.is_empty() {
        "proxy-node".into()
    } else if trimmed.len() > 64 {
        trimmed[..64].to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn decode_base64_any(s: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut out = Vec::with_capacity(cleaned.len() * 3 / 4);
    for chunk in cleaned.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let mut vals = [0u32; 4];
        for (idx, &b) in chunk.iter().enumerate() {
            vals[idx] = match b {
                b'A'..=b'Z' => u32::from(b - b'A'),
                b'a'..=b'z' => u32::from(b - b'a' + 26),
                b'0'..=b'9' => u32::from(b - b'0' + 52),
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                _ => return None,
            };
        }
        let triple = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push(((triple >> 16) & 0xff) as u8);
        if chunk.len() > 2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if chunk.len() > 3 {
            out.push((triple & 0xff) as u8);
        }
    }
    Some(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyGroupKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    Balancer,
}

impl ProxyGroupKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "select" | "selector" => Some(Self::Select),
            "url-test" | "urltest" | "url_test" => Some(Self::UrlTest),
            "fallback" => Some(Self::Fallback),
            "load-balance" | "loadbalance" | "load_balance" | "load-balancing" => {
                Some(Self::LoadBalance)
            }
            "balancer" => Some(Self::Balancer),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "Selector",
            Self::UrlTest => "URLTest",
            Self::Fallback => "Fallback",
            Self::LoadBalance => "LoadBalance",
            Self::Balancer => "Balancer",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceStrategy {
    #[default]
    ConsistentHashing,
    RoundRobin,
    StickySessions,
    Random,
    LeastPing,
    LeastLoad,
}

impl LoadBalanceStrategy {
    pub fn from_value(v: Option<&Value>) -> Result<Self> {
        let Some(v) = v else {
            return Ok(Self::ConsistentHashing);
        };
        let s = match v {
            Value::String(s) => s.as_str(),
            Value::Object(map) => map.get("type").and_then(Value::as_str).unwrap_or("random"),
            _ => return Err(Error::Config("负载均衡 strategy 格式不合法".into())),
        };
        match s.trim().to_ascii_lowercase().as_str() {
            "consistent-hashing" | "consistent_hashing" | "consistenthashing" => {
                Ok(Self::ConsistentHashing)
            }
            "round-robin" | "round_robin" | "roundrobin" => Ok(Self::RoundRobin),
            "sticky-sessions" | "sticky_sessions" | "stickysessions" => Ok(Self::StickySessions),
            "random" => Ok(Self::Random),
            "least-ping" | "least_ping" | "leastping" => Ok(Self::LeastPing),
            "least-load" | "least_load" | "leastload" => Ok(Self::LeastLoad),
            other => Err(Error::Config(format!("不支持的负载均衡策略：{other}"))),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyGroupSpec {
    #[serde(alias = "tag")]
    pub name: String,
    #[serde(rename = "type", alias = "protocol")]
    pub kind: String,
    #[serde(alias = "outbounds")]
    pub proxies: Vec<String>,
    #[serde(rename = "use")]
    pub use_providers: Vec<String>,
    #[serde(alias = "include-all")]
    pub include_all: bool,
    #[serde(alias = "include-all-proxies")]
    pub include_all_proxies: bool,
    #[serde(alias = "include-all-providers")]
    pub include_all_providers: bool,
    pub filter: Option<String>,
    #[serde(alias = "exclude-filter")]
    pub exclude_filter: Option<String>,
    #[serde(alias = "exclude-type")]
    pub exclude_type: Option<String>,
    #[serde(alias = "default", alias = "default-selected")]
    pub default_selected: Option<String>,
    pub url: Option<String>,
    pub interval: Option<Value>,
    pub tolerance: Option<u32>,
    pub timeout: Option<Value>,
    #[serde(alias = "idle-timeout")]
    pub idle_timeout: Option<Value>,
    pub lazy: Option<bool>,
    #[serde(alias = "max-failed-times")]
    pub max_failed_times: Option<u32>,
    #[serde(alias = "expected-status")]
    pub expected_status: Option<Value>,
    #[serde(alias = "disable-udp")]
    pub disable_udp: bool,
    #[serde(alias = "empty-fallback")]
    pub empty_fallback: bool,
    #[serde(alias = "interrupt-exist-connections")]
    pub interrupt_exist_connections: bool,
    pub strategy: Option<Value>,
    #[serde(alias = "hash-key")]
    pub hash_key: Vec<String>,
    pub selector: Vec<String>,
    #[serde(alias = "fallback-tag", alias = "fallbackTag")]
    pub fallback_tag: Option<String>,
    pub hidden: bool,
    pub icon: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BalancerSpec {
    pub tag: String,
    pub selector: Vec<String>,
    pub strategy: Option<Value>,
    #[serde(alias = "fallback-tag", alias = "fallbackTag")]
    pub fallback_tag: Option<String>,
}

impl BalancerSpec {
    pub fn to_group_spec(&self) -> ProxyGroupSpec {
        ProxyGroupSpec {
            name: self.tag.clone(),
            kind: "balancer".into(),
            selector: self.selector.clone(),
            strategy: self.strategy.clone(),
            fallback_tag: self.fallback_tag.clone(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledProxyGroup {
    pub id: OutId,
    pub kind: ProxyGroupKind,
    pub candidates: Vec<OutId>,
    pub default_selected: Option<OutId>,
    pub fallback_outbound: Option<OutId>,
    pub url: String,
    pub interval_secs: u64,
    pub tolerance_ms: u32,
    pub timeout_ms: u64,
    pub idle_timeout_secs: u64,
    pub lazy: bool,
    pub max_failed_times: u32,
    pub expected_status: String,
    pub disable_udp: bool,
    pub empty_fallback: bool,
    pub interrupt_exist_connections: bool,
    pub strategy: LoadBalanceStrategy,
    pub hash_key: Vec<String>,
    pub hidden: bool,
    pub icon: Option<String>,
}

fn parse_secs_value(v: Option<&Value>, default_secs: u64) -> Result<u64> {
    let Some(v) = v else {
        return Ok(default_secs);
    };
    match v {
        Value::Number(n) => n
            .as_u64()
            .filter(|x| *x > 0)
            .ok_or_else(|| Error::Config("时长秒数必须大于 0".into())),
        Value::String(s) => {
            let t = s.trim();
            if let Some(m) = t.strip_suffix('m') {
                Ok(m.trim()
                    .parse::<u64>()
                    .map_err(|_| Error::Config("时长格式不合法".into()))?
                    * 60)
            } else if let Some(h) = t.strip_suffix('h') {
                Ok(h.trim()
                    .parse::<u64>()
                    .map_err(|_| Error::Config("时长格式不合法".into()))?
                    * 3600)
            } else if let Some(sec) = t.strip_suffix('s') {
                sec.trim()
                    .parse::<u64>()
                    .map_err(|_| Error::Config("时长格式不合法".into()))
            } else {
                t.parse::<u64>()
                    .map_err(|_| Error::Config("时长格式不合法".into()))
            }
        }
        _ => Err(Error::Config("时长字段须为整数或字符串".into())),
    }
}

fn parse_ms_value(v: Option<&Value>, default_ms: u64) -> Result<u64> {
    let Some(v) = v else {
        return Ok(default_ms);
    };
    match v {
        Value::Number(n) => n
            .as_u64()
            .filter(|x| *x > 0)
            .ok_or_else(|| Error::Config("超时毫秒数必须大于 0".into())),
        Value::String(s) => {
            let t = s.trim();
            if let Some(ms) = t.strip_suffix("ms") {
                ms.trim()
                    .parse::<u64>()
                    .map_err(|_| Error::Config("超时格式不合法".into()))
            } else if let Some(sec) = t.strip_suffix('s') {
                Ok(sec
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| Error::Config("超时格式不合法".into()))?
                    * 1000)
            } else {
                t.parse::<u64>()
                    .map_err(|_| Error::Config("超时格式不合法".into()))
            }
        }
        _ => Err(Error::Config("超时字段须为整数或字符串".into())),
    }
}

impl ProxyGroupSpec {
    pub fn compile(
        &self,
        static_outbounds: &[(OutId, String)],
        providers: &BTreeMap<String, CompiledProxyProvider>,
    ) -> Result<CompiledProxyGroup> {
        let id = OutId::parse(&self.name)?;
        let kind = ProxyGroupKind::parse(&self.kind)
            .ok_or_else(|| Error::Config(format!("不支持的策略组类型：{}", self.kind)))?;

        let include_pat = self
            .filter
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(pat) = include_pat {
            let _ = matches_pattern(pat, "")?;
        }
        let exclude_pat = self
            .exclude_filter
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(pat) = exclude_pat {
            let _ = matches_pattern(pat, "")?;
        }
        let excluded_types: Vec<String> = self
            .exclude_type
            .as_deref()
            .unwrap_or("")
            .split('|')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let type_map: HashMap<&OutId, &str> = static_outbounds
            .iter()
            .map(|(oid, kind)| (oid, kind.as_str()))
            .collect();

        let mut candidates = Vec::new();
        for p in &self.proxies {
            let oid = OutId::parse(p)?;
            if !candidates.contains(&oid) {
                candidates.push(oid);
            }
        }
        if self.include_all || self.include_all_proxies {
            for (oid, _) in static_outbounds {
                if *oid != id && !candidates.contains(oid) {
                    candidates.push(oid.clone());
                }
            }
        }
        let mut provider_names = self.use_providers.clone();
        if self.include_all || self.include_all_providers {
            for k in providers.keys() {
                if !provider_names.contains(k) {
                    provider_names.push(k.clone());
                }
            }
        }
        for pname in &provider_names {
            let prov = providers.get(pname).ok_or_else(|| {
                Error::Config(format!(
                    "策略组 {} 引用的 proxy-provider {} 不存在",
                    self.name, pname
                ))
            })?;
            for oid in &prov.proxies {
                if !candidates.contains(oid) {
                    candidates.push(oid.clone());
                }
            }
        }
        if !self.selector.is_empty() {
            for (oid, _) in static_outbounds {
                if *oid == id {
                    continue;
                }
                let tag_str = oid.as_str();
                if self
                    .selector
                    .iter()
                    .any(|sel| tag_str == sel || tag_str.starts_with(sel))
                    && !candidates.contains(oid)
                {
                    candidates.push(oid.clone());
                }
            }
        }

        // Apply filter, exclude_filter, exclude_type
        candidates.retain(|oid| {
            let name = oid.as_str();
            if let Some(pat) = include_pat
                && !matches_pattern(pat, name).unwrap_or(false)
            {
                return false;
            }
            if let Some(pat) = exclude_pat
                && matches_pattern(pat, name).unwrap_or(false)
            {
                return false;
            }
            if !excluded_types.is_empty()
                && let Some(k) = type_map.get(oid)
                && excluded_types.iter().any(|t| t == &k.to_ascii_lowercase())
            {
                return false;
            }
            true
        });

        // 提供者内容可能尚未下载；成员为空的组像 Mihomo COMPATIBLE 一样拒绝连接，内容到达后随引擎重建填入。
        if candidates.is_empty() && !self.empty_fallback && provider_names.is_empty() {
            return Err(Error::Config(format!(
                "策略组 {} 候选节点为空且未开启 empty-fallback",
                self.name
            )));
        }

        let default_selected = match &self.default_selected {
            Some(s) => Some(OutId::parse(s)?),
            None => candidates.first().cloned(),
        };
        let fallback_outbound = match &self.fallback_tag {
            Some(s) => Some(OutId::parse(s)?),
            None => None,
        };
        let strategy = LoadBalanceStrategy::from_value(self.strategy.as_ref())?;

        Ok(CompiledProxyGroup {
            id,
            kind,
            candidates,
            default_selected,
            fallback_outbound,
            url: self
                .url
                .clone()
                .unwrap_or_else(|| "https://cp.cloudflare.com/generate_204".into()),
            interval_secs: parse_secs_value(self.interval.as_ref(), 300)?,
            tolerance_ms: self.tolerance.unwrap_or(50),
            timeout_ms: parse_ms_value(self.timeout.as_ref(), 5000)?,
            idle_timeout_secs: parse_secs_value(self.idle_timeout.as_ref(), 1800)?,
            lazy: self.lazy.unwrap_or(true),
            max_failed_times: self.max_failed_times.unwrap_or(5),
            expected_status: self
                .expected_status
                .as_ref()
                .map(expected_status_to_string)
                .unwrap_or_else(|| "204".into()),
            disable_udp: self.disable_udp,
            empty_fallback: self.empty_fallback,
            interrupt_exist_connections: self.interrupt_exist_connections,
            strategy,
            hash_key: self.hash_key.clone(),
            hidden: self.hidden,
            icon: self.icon.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_share_links_and_applies_provider_name_and_dialer_overrides() {
        let vmess_json = r#"{"v":"2","ps":"HK%20Node","add":"hk.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","scy":"auto","net":"ws","type":"none","host":"hk.example.com","path":"/ws","tls":"tls","sni":"hk.example.com"}"#;
        let vmess_b64 = "eyJ2IjoiMiIsInBzIjoiSEslMjBOb2RlIiwiYWRkIjoiaGsuZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiIxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiaGsuZXhhbXBsZS5jb20iLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIiwic25pIjoiaGsuZXhhbXBsZS5jb20ifQ==";
        let _ = vmess_json;
        let at = '@';
        let uri_list = format!(
            "vmess://{vmess_b64}\n\
             vless://22222222-2222-2222-2222-222222222222{at}jp.example.com:8443?security=reality&sni=www.microsoft.com&pbk=pubkey123&sid=0102#JP-Reality\n\
             hy2://secretpass{at}us.example.com:443?sni=us.example.com&mport=20000-30000#US-Hy2\n\
             tuic://33333333-3333-3333-3333-333333333333:tuicpass{at}sg.example.com:443?sni=sg.example.com&congestion_control=bbr#SG-Tuic"
        );
        let prov = ProxyProviderSpec {
            kind: "inline".into(),
            payload: vec![Value::String(uri_list)],
            override_opts: Some(ProxyProviderOverrideSpec {
                additional_prefix: Some("Sub-".into()),
                additional_suffix: Some("-V1".into()),
                dialer_proxy: Some("upstream-detour".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (compiled, specs) = prov.compile("my-sub").unwrap();
        assert_eq!(compiled.proxies.len(), 4);
        assert_eq!(specs[0].tag, "Sub-HK-Node-V1");
        assert_eq!(specs[0].kind, "vmess");
        assert_eq!(specs[0].options["dialer-proxy"], "upstream-detour");
        assert_eq!(specs[1].tag, "Sub-JP-Reality-V1");
        assert_eq!(specs[1].kind, "vless");
        assert_eq!(specs[2].tag, "Sub-US-Hy2-V1");
        assert_eq!(specs[2].kind, "hysteria2");
        assert_eq!(specs[2].options["ports"], "20000-30000");
        assert_eq!(specs[3].tag, "Sub-SG-Tuic-V1");
        assert_eq!(specs[3].kind, "tuic");
    }
}
