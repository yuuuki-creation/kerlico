//! `dns` 配置段：同时接受 Mihomo（短横线键）与 sing-box（下划线键）写法，未知键报错。

use crate::fakeip::{CacheFileSpec, FakeDnsInput};
use kerlico_core::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsTlsSpec {
    #[serde(default, alias = "server-name", alias = "sni")]
    pub server_name: Option<String>,
    #[serde(default, alias = "allow_insecure", alias = "skip-cert-verify")]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default, alias = "ca-pem")]
    pub ca_pem: Option<String>,
    #[serde(default, alias = "certificate-path", alias = "ca-file")]
    pub certificate_path: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServerSpec {
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default, alias = "type")]
    pub protocol: Option<String>,
    #[serde(default, alias = "address")]
    pub server: Option<String>,
    #[serde(default, alias = "port", alias = "server-port")]
    pub server_port: Option<u16>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub tls: Option<DnsTlsSpec>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default, alias = "proxy")]
    pub detour: Option<String>,
    #[serde(default, alias = "client-subnet")]
    pub client_subnet: Option<String>,
    #[serde(default, alias = "inet4-range")]
    pub inet4_range: Option<String>,
    #[serde(default, alias = "inet6-range")]
    pub inet6_range: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DnsServerInput {
    Url(String),
    Structured(Box<DnsServerSpec>),
}

impl From<&str> for DnsServerInput {
    fn from(s: &str) -> Self {
        Self::Url(s.to_owned())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DnsQueryTypeInput {
    Code(u16),
    Name(String),
}

impl DnsQueryTypeInput {
    pub fn to_code(&self) -> Result<u16> {
        match self {
            Self::Code(0) => Err(crate::matcher::invalid()),
            Self::Code(c) => Ok(*c),
            Self::Name(name) => crate::wire::type_code(name).ok_or_else(crate::matcher::invalid),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRuleSpec {
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
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default, alias = "query-type")]
    pub query_type: Vec<DnsQueryTypeInput>,
    #[serde(default, alias = "rule-set")]
    pub rule_set: Vec<String>,
    #[serde(default, alias = "not")]
    pub invert: bool,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default, alias = "no-drop")]
    pub no_drop: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DnsPolicyValue {
    Single(String),
    List(Vec<String>),
}

impl DnsPolicyValue {
    pub fn servers(&self) -> Vec<&str> {
        match self {
            Self::Single(s) => s.split(',').map(str::trim).collect(),
            Self::List(list) => list.iter().map(String::as_str).collect(),
        }
    }
}

/// `nameserver-policy`：对象（键按字母序，域名通配取最具体者）或单键对象数组
/// （按书写顺序，与 Mihomo 相同；Mihomo YAML 解析时自动转为此形式）。
#[derive(Clone, Debug, Default)]
pub struct DnsPolicyMap {
    pub entries: Vec<(String, DnsPolicyValue)>,
    pub ordered: bool,
}

impl DnsPolicyMap {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'de> Deserialize<'de> for DnsPolicyMap {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Map(BTreeMap<String, DnsPolicyValue>),
            List(Vec<BTreeMap<String, DnsPolicyValue>>),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Map(map) => Self {
                entries: map.into_iter().collect(),
                ordered: false,
            },
            Raw::List(items) => Self {
                entries: items.into_iter().flatten().collect(),
                ordered: true,
            },
        })
    }
}

impl Serialize for DnsPolicyMap {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let items: Vec<BTreeMap<&str, &DnsPolicyValue>> = self
            .entries
            .iter()
            .map(|(k, v)| BTreeMap::from([(k.as_str(), v)]))
            .collect();
        items.serialize(s)
    }
}

/// hosts 值：单个 IP、IP 列表或另一个域名（别名）。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HostsValue {
    One(String),
    Many(Vec<String>),
}

/// Mihomo `fallback-filter`。`geoip` 默认开启、`geoip-code` 默认 `CN`。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackFilterSpec {
    #[serde(default)]
    pub geoip: Option<bool>,
    #[serde(default, alias = "geoip-code")]
    pub geoip_code: Option<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub ipcidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
}

/// DNS 解析器、规则、缓存、Fake-IP 与监听配置。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSpec {
    /// `false` 时不装配 DNS 模块，`Local` 出网改用系统解析器。
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default, alias = "nameserver")]
    pub servers: Vec<DnsServerInput>,
    #[serde(default)]
    pub fallback: Vec<DnsServerInput>,
    #[serde(default, alias = "fallback-filter")]
    pub fallback_filter: Option<FallbackFilterSpec>,
    #[serde(default, alias = "default-nameserver")]
    pub default_nameserver: Vec<DnsServerInput>,
    #[serde(default, alias = "direct-nameserver")]
    pub direct_nameserver: Vec<DnsServerInput>,
    #[serde(default, alias = "direct-nameserver-follow-policy")]
    pub direct_nameserver_follow_policy: bool,
    #[serde(default)]
    pub hosts: BTreeMap<String, HostsValue>,
    #[serde(default, alias = "use-hosts")]
    pub use_hosts: Option<bool>,
    #[serde(default, alias = "use-system-hosts")]
    pub use_system_hosts: Option<bool>,
    #[serde(default, alias = "final", alias = "final-server")]
    pub final_server: Option<String>,
    #[serde(default, alias = "reverse-mapping")]
    pub reverse_mapping: bool,
    #[serde(default)]
    pub rules: Vec<DnsRuleSpec>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub ipv6: Option<bool>,
    #[serde(default, alias = "ipv6-timeout")]
    pub ipv6_timeout: Option<u64>,
    /// sing-box `strategy`：`prefer_ipv4`、`prefer_ipv6`、`ipv4_only`、`ipv6_only`。
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default, alias = "prefer-h3")]
    pub prefer_h3: bool,
    #[serde(default, alias = "respect-rules")]
    pub respect_rules: bool,
    #[serde(default, alias = "cache-algorithm")]
    pub cache_algorithm: Option<String>,
    #[serde(default, alias = "cache-max-size", alias = "cache_capacity")]
    pub cache_max_size: Option<usize>,
    #[serde(default, alias = "optimistic-cache")]
    pub optimistic_cache: Option<bool>,
    #[serde(default, alias = "disable-cache")]
    pub disable_cache: bool,
    #[serde(default, alias = "client-subnet")]
    pub client_subnet: Option<String>,
    #[serde(default, alias = "enhanced-mode")]
    pub enhanced_mode: Option<String>,
    #[serde(
        default,
        alias = "fake-ip-range",
        alias = "inet4_range",
        alias = "inet4-range"
    )]
    pub fake_ip_range: Option<String>,
    #[serde(
        default,
        alias = "fake-ip-range6",
        alias = "inet6_range",
        alias = "inet6-range"
    )]
    pub fake_ip_range6: Option<String>,
    #[serde(default, alias = "fake-ip-ttl")]
    pub fake_ip_ttl: Option<u32>,
    #[serde(default, alias = "fake-ip-filter")]
    pub fake_ip_filter: Vec<String>,
    #[serde(default, alias = "fake-ip-filter-mode")]
    pub fake_ip_filter_mode: Option<String>,
    #[serde(default)]
    pub fakedns: Option<FakeDnsInput>,
    #[serde(default, alias = "nameserver-policy")]
    pub nameserver_policy: DnsPolicyMap,
    #[serde(default, alias = "proxy-server-nameserver")]
    pub proxy_server_nameserver: Vec<DnsServerInput>,
    #[serde(default, alias = "proxy-server-nameserver-policy")]
    pub proxy_server_nameserver_policy: DnsPolicyMap,
    #[serde(default, alias = "cache-file")]
    pub cache_file: Option<CacheFileSpec>,
}

/// DNS 配置引用的 Geo 分类与规则集；装配方据此加载数据。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsReferences {
    pub geosite: Vec<String>,
    pub geoip: Vec<String>,
    pub rule_sets: Vec<String>,
}

impl DnsReferences {
    fn condition(&mut self, raw: &str) {
        let t = raw.trim();
        let lower = t.to_ascii_lowercase();
        if let Some(code) = lower.strip_prefix("geosite:") {
            self.geosite.push(code.trim().to_owned());
        } else if lower.starts_with("rule-set:") || lower.starts_with("rule_set:") {
            self.rule_sets
                .push(t["rule-set:".len()..].trim().to_owned());
        }
    }
}

impl DnsSpec {
    /// `nameserver-policy`、fake-ip-filter、DNS 规则与 fallback-filter 引用的 Geo 分类和规则集。
    pub fn references(&self) -> DnsReferences {
        let mut out = DnsReferences::default();
        for map in [
            &self.nameserver_policy,
            &self.proxy_server_nameserver_policy,
        ] {
            for (key, _) in &map.entries {
                for part in key.split(',') {
                    out.condition(part);
                }
            }
        }
        for item in &self.fake_ip_filter {
            out.condition(item);
        }
        for rule in &self.rules {
            out.geosite
                .extend(rule.geosite.iter().map(|g| g.trim().to_owned()));
            out.rule_sets
                .extend(rule.rule_set.iter().map(|r| r.trim().to_owned()));
        }
        if !self.fallback.is_empty() {
            let filter = self.fallback_filter.clone().unwrap_or_default();
            out.geosite
                .extend(filter.geosite.iter().map(|g| g.trim().to_owned()));
            if filter.geoip != Some(false) {
                out.geoip.push(
                    filter
                        .geoip_code
                        .unwrap_or_else(|| "CN".into())
                        .to_ascii_lowercase(),
                );
            }
        }
        out.geosite.sort();
        out.geosite.dedup();
        out.rule_sets.sort();
        out.rule_sets.dedup();
        out
    }

    /// 是否启用 DNS 模块；只写 `enable: false` 时由调用方改用系统解析器。
    pub fn enabled(&self) -> bool {
        self.enable != Some(false)
    }

    /// 编译整个管线以检查配置，不读取 Fake-IP 持久化文件、不建立连接。
    pub fn validate(&self) -> Result<()> {
        crate::pipeline::Inner::build(self, false).map(|_| ())
    }
}
