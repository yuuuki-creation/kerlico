//! 为 `Local` 路径与内部 DNS 处理解析网站域名：支持静态 `hosts`、UDP/TCP/DoT/DoH、Fake-IP 双栈地址池、DNS 规则动作与反向映射。

pub mod cache_file;
pub mod fakeip;
pub use fakeip::{CacheFileSpec, FakeDnsInput, FakeDnsPoolSpec, FakeIpPool, ReverseMappingCache};

use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use kerlico_core::{Address, Destination, Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

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
    #[serde(default, alias = "proxy", alias = "interface")]
    pub detour: Option<String>,
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
            Self::Code(0) => Err(invalid()),
            Self::Code(c) => Ok(*c),
            Self::Name(name) => match name.trim().to_ascii_uppercase().as_str() {
                "A" => Ok(1),
                "NS" => Ok(2),
                "CNAME" => Ok(5),
                "SOA" => Ok(6),
                "PTR" => Ok(12),
                "MX" => Ok(15),
                "TXT" => Ok(16),
                "AAAA" => Ok(28),
                "SRV" => Ok(33),
                "SVCB" => Ok(64),
                "HTTPS" => Ok(65),
                "ANY" => Ok(255),
                other => other.parse::<u16>().map_err(|_| invalid()),
            },
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
    pub fn first_server(&self) -> Option<&str> {
        match self {
            Self::Single(s) => Some(s.as_str()),
            Self::List(list) => list.first().map(String::as_str),
        }
    }
}

/// DNS 解析器与规则/Fake-IP/监听配置。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSpec {
    #[serde(default, alias = "nameserver")]
    pub servers: Vec<DnsServerInput>,
    #[serde(default)]
    pub hosts: BTreeMap<String, Vec<IpAddr>>,
    #[serde(default, alias = "final", alias = "final-server")]
    pub final_server: Option<String>,
    #[serde(default, alias = "reverse-mapping")]
    pub reverse_mapping: bool,
    #[serde(default)]
    pub rules: Vec<DnsRuleSpec>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
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
    #[serde(default)]
    pub fakedns: Option<FakeDnsInput>,
    #[serde(default, alias = "nameserver-policy")]
    pub nameserver_policy: BTreeMap<String, DnsPolicyValue>,
    #[serde(default, alias = "proxy-server-nameserver")]
    pub proxy_server_nameserver: Vec<DnsServerInput>,
    #[serde(default, alias = "proxy-server-nameserver-policy")]
    pub proxy_server_nameserver_policy: BTreeMap<String, DnsPolicyValue>,
    #[serde(default, alias = "cache-file")]
    pub cache_file: Option<CacheFileSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Transport {
    Udp,
    Tcp,
    Tls(String),
    Https {
        url: String,
        headers: BTreeMap<String, String>,
        insecure: bool,
        local: bool,
    },
    FakeIp {
        v4_range: Option<String>,
        v6_range: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedServer {
    tag: String,
    transport: Transport,
    address: Option<SocketAddr>,
    domains: Vec<String>,
    detour: Option<String>,
}

fn invalid() -> Error {
    Error::Config("DNS 配置不合法".into())
}

fn parse_duration_str(raw: &str) -> Result<Duration> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(invalid());
    }
    if let Some(ms) = s.strip_suffix("ms") {
        let v: u64 = ms.trim().parse().map_err(|_| invalid())?;
        if v == 0 {
            return Err(invalid());
        }
        return Ok(Duration::from_millis(v));
    }
    if let Some(sec) = s.strip_suffix('s') {
        let v: u64 = sec.trim().parse().map_err(|_| invalid())?;
        if v == 0 {
            return Err(invalid());
        }
        return Ok(Duration::from_secs(v));
    }
    let v: u64 = s.parse().map_err(|_| invalid())?;
    if v == 0 {
        return Err(invalid());
    }
    Ok(Duration::from_secs(v))
}

fn parse_socket_or_ip(authority: &str, default_port: u16) -> Result<SocketAddr> {
    let address = authority
        .parse::<SocketAddr>()
        .or_else(|_| {
            let ip = match authority
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                Some(bracketed) => bracketed.parse::<Ipv6Addr>().map(IpAddr::V6),
                None => authority.parse::<IpAddr>(),
            };
            ip.map(|ip| SocketAddr::new(ip, default_port))
        })
        .map_err(|_| invalid())?;
    if address.port() == 0 {
        return Err(invalid());
    }
    Ok(address)
}

#[cfg(test)]
fn parse_server(text: &str) -> Result<(Transport, SocketAddr)> {
    let parsed = parse_server_url(text, 0)?;
    let addr = parsed.address.ok_or_else(invalid)?;
    Ok((parsed.transport, addr))
}

fn parse_server_url(text: &str, index: usize) -> Result<ParsedServer> {
    let trimmed = text.trim();
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "fakedns" | "fakeip" | "fake-ip"
    ) {
        return Ok(ParsedServer {
            tag: format!("fakeip-{index}"),
            transport: Transport::FakeIp {
                v4_range: None,
                v6_range: None,
            },
            address: None,
            domains: Vec::new(),
            detour: None,
        });
    }
    let (scheme, rest) = trimmed.split_once("://").ok_or_else(invalid)?;
    let (authority_and_path, fragment) = match rest.split_once('#') {
        Some((a, f)) => (a, Some(f)),
        None => (rest, None),
    };
    let scheme_lower = scheme.to_ascii_lowercase();
    match scheme_lower.as_str() {
        "udp" | "tcp" => {
            let mut detour = None;
            if let Some(frag) = fragment {
                if let Some(val) = frag
                    .strip_prefix("detour=")
                    .or_else(|| frag.strip_prefix("proxy="))
                    .or_else(|| frag.strip_prefix("interface="))
                {
                    if val.is_empty() {
                        return Err(invalid());
                    }
                    detour = Some(val.to_owned());
                } else {
                    return Err(invalid());
                }
            }
            let addr = parse_socket_or_ip(authority_and_path, 53)?;
            let transport = if scheme_lower == "udp" {
                Transport::Udp
            } else {
                Transport::Tcp
            };
            Ok(ParsedServer {
                tag: format!("{scheme_lower}-{index}"),
                transport,
                address: Some(addr),
                domains: Vec::new(),
                detour,
            })
        }
        "tls" => {
            let frag = fragment.ok_or_else(invalid)?;
            if frag.is_empty() {
                return Err(invalid());
            }
            let (sni, detour) = match frag.split_once('&') {
                Some((sni, extra)) => (sni, Some(extra.to_owned())),
                None => (frag, None),
            };
            if sni.is_empty() {
                return Err(invalid());
            }
            let addr = parse_socket_or_ip(authority_and_path, 853)?;
            Ok(ParsedServer {
                tag: format!("tls-{index}"),
                transport: Transport::Tls(sni.to_owned()),
                address: Some(addr),
                domains: Vec::new(),
                detour,
            })
        }
        "https" | "https+local" | "https-local" | "doh" => {
            let local = matches!(scheme_lower.as_str(), "https+local" | "https-local");
            let (authority, path_part) = match authority_and_path.split_once('/') {
                Some((a, p)) => (a, format!("/{p}")),
                None => (authority_and_path, "/dns-query".to_owned()),
            };
            if authority.is_empty() {
                return Err(invalid());
            }
            let addr = parse_socket_or_ip(authority, 443).ok();
            if addr.is_none() {
                // 若 authority 不是字面 IP，校验其为合法域名或 host:port
                let (h, p) = match authority.rsplit_once(':') {
                    Some((h, p_str)) if !h.contains(':') => {
                        let port: u16 = p_str.parse().map_err(|_| invalid())?;
                        (h, port)
                    }
                    _ => (authority, 443),
                };
                Destination::new(h, p).map_err(|_| invalid())?;
            }
            let detour = fragment.filter(|f| !f.is_empty()).map(ToOwned::to_owned);
            let url = format!("https://{authority}{path_part}");
            Ok(ParsedServer {
                tag: format!("doh-{index}"),
                transport: Transport::Https {
                    url,
                    headers: BTreeMap::new(),
                    insecure: false,
                    local,
                },
                address: addr,
                domains: Vec::new(),
                detour,
            })
        }
        _ => Err(invalid()),
    }
}

fn parse_server_input(input: &DnsServerInput, index: usize) -> Result<ParsedServer> {
    match input {
        DnsServerInput::Url(url) => parse_server_url(url, index),
        DnsServerInput::Structured(spec) => {
            let tag = spec
                .tag
                .clone()
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| format!("dns-{index}"));
            let proto = spec
                .protocol
                .as_deref()
                .unwrap_or("udp")
                .to_ascii_lowercase();
            let mut domains = Vec::with_capacity(spec.domains.len());
            for d in &spec.domains {
                if d.trim().is_empty() {
                    return Err(invalid());
                }
                domains.push(d.trim().to_ascii_lowercase());
            }
            match proto.as_str() {
                "fakeip" | "fakedns" | "fake-ip" => Ok(ParsedServer {
                    tag,
                    transport: Transport::FakeIp {
                        v4_range: spec.inet4_range.clone(),
                        v6_range: spec.inet6_range.clone(),
                    },
                    address: None,
                    domains,
                    detour: None,
                }),
                "https" | "doh" | "https-local" | "https+local" => {
                    let host = spec.server.as_deref().ok_or_else(invalid)?;
                    let port = spec.server_port.unwrap_or(443);
                    if port == 0 {
                        return Err(invalid());
                    }
                    let dest = Destination::new(host, port).map_err(|_| invalid())?;
                    let addr = match dest.address() {
                        Address::Ip(ip) => Some(SocketAddr::new(*ip, port)),
                        Address::Domain(_) => None,
                    };
                    let raw_path = spec.path.as_deref().unwrap_or("/dns-query");
                    if !raw_path.starts_with('/') {
                        return Err(invalid());
                    }
                    let authority = match dest.address() {
                        Address::Ip(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
                        _ if port == 443 => dest.host(),
                        _ => format!("{}:{port}", dest.host()),
                    };
                    let url = format!("https://{authority}{raw_path}");
                    let insecure = spec.tls.as_ref().is_some_and(|t| t.insecure);
                    let local = matches!(proto.as_str(), "https-local" | "https+local");
                    Ok(ParsedServer {
                        tag,
                        transport: Transport::Https {
                            url,
                            headers: spec.headers.clone(),
                            insecure,
                            local,
                        },
                        address: addr,
                        domains,
                        detour: spec.detour.clone(),
                    })
                }
                "udp" | "tcp" | "tls" => {
                    let host = spec.server.as_deref().ok_or_else(invalid)?;
                    let default_port = if proto == "tls" { 853 } else { 53 };
                    let port = spec.server_port.unwrap_or(default_port);
                    let addr = parse_socket_or_ip(host, port)?;
                    let transport = match proto.as_str() {
                        "udp" => Transport::Udp,
                        "tcp" => Transport::Tcp,
                        "tls" => {
                            let sni = spec
                                .tls
                                .as_ref()
                                .and_then(|t| t.server_name.clone())
                                .unwrap_or_else(|| addr.ip().to_string());
                            Transport::Tls(sni)
                        }
                        _ => unreachable!(),
                    };
                    Ok(ParsedServer {
                        tag,
                        transport,
                        address: Some(addr),
                        domains,
                        detour: spec.detour.clone(),
                    })
                }
                _ => Err(invalid()),
            }
        }
    }
}

fn normalize(host: &str) -> Result<String> {
    match Destination::new(host, 1).map_err(|_| invalid())?.address() {
        Address::Domain(name) => Ok(name.strip_suffix('.').unwrap_or(name).to_owned()),
        Address::Ip(_) => Err(invalid()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CompiledDnsAction {
    Route { server: String },
    Reject { drop: bool, no_drop: bool },
}

struct CompiledDnsRule {
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    domain_regex: Vec<Regex>,
    query_type: Vec<u16>,
    rule_set: Vec<String>,
    invert: bool,
    action: CompiledDnsAction,
    reject_window: Mutex<VecDeque<Instant>>,
}

impl CompiledDnsRule {
    fn compile(spec: &DnsRuleSpec, default_server: &str) -> Result<Self> {
        let domain = spec
            .domain
            .iter()
            .map(|d| normalize(d))
            .collect::<Result<Vec<_>>>()?;
        let domain_suffix = spec
            .domain_suffix
            .iter()
            .map(|d| normalize(d.strip_prefix('.').unwrap_or(d)))
            .collect::<Result<Vec<_>>>()?;
        let domain_keyword = spec
            .domain_keyword
            .iter()
            .map(|k| {
                if k.is_empty() || !k.is_ascii() {
                    Err(invalid())
                } else {
                    Ok(k.to_ascii_lowercase())
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let domain_regex = spec
            .domain_regex
            .iter()
            .map(|r| Regex::new(r).map_err(|_| invalid()))
            .collect::<Result<Vec<_>>>()?;
        let query_type = spec
            .query_type
            .iter()
            .map(DnsQueryTypeInput::to_code)
            .collect::<Result<Vec<_>>>()?;
        let action_name = spec.action.as_deref().unwrap_or("route");
        let action = match action_name {
            "route" => CompiledDnsAction::Route {
                server: spec
                    .server
                    .clone()
                    .unwrap_or_else(|| default_server.to_owned()),
            },
            "reject" => {
                let method = spec.method.as_deref().unwrap_or("default");
                let drop = match method {
                    "default" => false,
                    "drop" => true,
                    _ => return Err(invalid()),
                };
                CompiledDnsAction::Reject {
                    drop,
                    no_drop: spec.no_drop,
                }
            }
            _ => return Err(invalid()),
        };
        Ok(Self {
            domain,
            domain_suffix,
            domain_keyword,
            domain_regex,
            query_type,
            rule_set: spec.rule_set.clone(),
            invert: spec.invert,
            action,
            reject_window: Mutex::new(VecDeque::new()),
        })
    }

    fn matches(&self, qname: &str, qtype: u16) -> bool {
        let host = qname.strip_suffix('.').unwrap_or(qname);
        let has_domain_cond = !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.rule_set.is_empty();
        let domain_hit = !has_domain_cond
            || self.domain.iter().any(|d| d == host)
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
                .rule_set
                .iter()
                .any(|set_name| host.contains(&set_name.to_ascii_lowercase()));
        let qtype_hit = self.query_type.is_empty() || self.query_type.contains(&qtype);
        let raw = domain_hit && qtype_hit;
        if self.invert { !raw } else { raw }
    }

    fn should_drop_on_reject(&self, base_drop: bool, no_drop: bool) -> bool {
        if base_drop {
            return true;
        }
        if no_drop {
            return false;
        }
        // 30 秒内触发达到 50 次自动切换为 drop
        let now = Instant::now();
        let mut win = self.reject_window.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(&front) = win.front() {
            if now.duration_since(front) > Duration::from_secs(30) {
                win.pop_front();
            } else {
                break;
            }
        }
        win.push_back(now);
        win.len() >= 50
    }
}

impl DnsSpec {
    pub fn validate(&self) -> Result<()> {
        let has_any = !self.servers.is_empty()
            || !self.hosts.is_empty()
            || self.fakedns.is_some()
            || self.enhanced_mode.is_some()
            || !self.proxy_server_nameserver.is_empty()
            || self.listen.is_some();
        if !has_any {
            return Err(invalid());
        }
        for (idx, server) in self.servers.iter().enumerate() {
            parse_server_input(server, idx)?;
        }
        for (idx, server) in self.proxy_server_nameserver.iter().enumerate() {
            parse_server_input(server, idx)?;
        }
        for (host, addresses) in &self.hosts {
            normalize(host)?;
            if addresses.is_empty() {
                return Err(invalid());
            }
        }
        if let Some(timeout) = &self.timeout {
            parse_duration_str(timeout)?;
        }
        if let Some(mode) = &self.enhanced_mode {
            match mode.to_ascii_lowercase().as_str() {
                "normal" | "redir-host" | "fake-ip" | "fakeip" => {}
                _ => return Err(invalid()),
            }
        }
        for rule in &self.rules {
            CompiledDnsRule::compile(rule, "default")?;
        }
        Ok(())
    }
}

struct DoHUpstream {
    client: reqwest::Client,
    url: String,
    headers: BTreeMap<String, String>,
}

enum UpstreamBackend {
    Hickory(Box<TokioResolver>),
    DoH(DoHUpstream),
    FakeIp,
}

pub struct DnsResolver {
    default_upstream: Option<TokioResolver>,
    tagged_upstreams: HashMap<String, UpstreamBackend>,
    final_tag: Option<String>,
    hosts: BTreeMap<String, Vec<IpAddr>>,
    rules: Vec<CompiledDnsRule>,
    policy_servers: Vec<(String, String)>,
    proxy_resolver: Option<TokioResolver>,
    fakeip_pool: Option<Arc<FakeIpPool>>,
    fakeip_enabled_by_default: bool,
    reverse_mapping: Option<Arc<ReverseMappingCache>>,
    timeout: Duration,
    listen: Option<SocketAddr>,
}

impl DnsResolver {
    /// 需要在 Tokio 运行时内调用。
    pub fn new(spec: &DnsSpec) -> Result<Self> {
        spec.validate()?;
        let hosts = spec
            .hosts
            .iter()
            .map(|(host, addresses)| Ok((normalize(host)?, addresses.clone())))
            .collect::<Result<_>>()?;
        let timeout = match &spec.timeout {
            Some(t) => parse_duration_str(t)?,
            None => Duration::from_secs(10),
        };

        let mut hickory_servers = Vec::new();
        let mut tagged_upstreams = HashMap::new();
        let mut server_domain_rules = Vec::new();
        let mut fakeip_v4_from_server = None;
        let mut fakeip_v6_from_server = None;
        let mut has_fakeip_server = false;
        let mut first_tag = None;

        for (idx, item) in spec.servers.iter().enumerate() {
            let parsed = parse_server_input(item, idx)?;
            if first_tag.is_none() {
                first_tag = Some(parsed.tag.clone());
            }
            for dom in &parsed.domains {
                server_domain_rules.push((dom.clone(), parsed.tag.clone()));
            }
            match parsed.transport {
                Transport::Udp | Transport::Tcp | Transport::Tls(_) => {
                    let address = parsed.address.ok_or_else(invalid)?;
                    let mut connection = match &parsed.transport {
                        Transport::Udp => ConnectionConfig::udp(),
                        Transport::Tcp => ConnectionConfig::tcp(),
                        Transport::Tls(name) => ConnectionConfig::tls(Arc::from(name.as_str())),
                        _ => unreachable!(),
                    };
                    connection.port = address.port();
                    let ns_cfg = NameServerConfig::new(address.ip(), true, vec![connection]);
                    hickory_servers.push(ns_cfg.clone());
                    let mut single_builder = TokioResolver::builder_with_config(
                        ResolverConfig::from_name_servers(vec![ns_cfg]),
                        TokioRuntimeProvider::default(),
                    );
                    single_builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
                    single_builder.options_mut().use_hosts_file = ResolveHosts::Never;
                    single_builder.options_mut().timeout = timeout;
                    let single_resolver = single_builder.build().map_err(|_| invalid())?;
                    tagged_upstreams.insert(
                        parsed.tag,
                        UpstreamBackend::Hickory(Box::new(single_resolver)),
                    );
                }
                Transport::Https {
                    url,
                    headers,
                    insecure,
                    ..
                } => {
                    let client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(insecure)
                        .timeout(timeout)
                        .build()
                        .map_err(|_| invalid())?;
                    tagged_upstreams.insert(
                        parsed.tag,
                        UpstreamBackend::DoH(DoHUpstream {
                            client,
                            url,
                            headers,
                        }),
                    );
                }
                Transport::FakeIp { v4_range, v6_range } => {
                    has_fakeip_server = true;
                    if v4_range.is_some() {
                        fakeip_v4_from_server = v4_range;
                    }
                    if v6_range.is_some() {
                        fakeip_v6_from_server = v6_range;
                    }
                    tagged_upstreams.insert(parsed.tag, UpstreamBackend::FakeIp);
                }
            }
        }

        let default_upstream = if hickory_servers.is_empty() {
            None
        } else {
            let mut builder = TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(hickory_servers),
                TokioRuntimeProvider::default(),
            );
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            builder.options_mut().use_hosts_file = ResolveHosts::Never;
            builder.options_mut().timeout = timeout;
            Some(builder.build().map_err(|_| invalid())?)
        };

        let proxy_resolver = if spec.proxy_server_nameserver.is_empty() {
            None
        } else {
            let mut proxy_ns = Vec::new();
            for (idx, item) in spec.proxy_server_nameserver.iter().enumerate() {
                let parsed = parse_server_input(item, idx)?;
                if let Some(address) = parsed.address {
                    let mut connection = match parsed.transport {
                        Transport::Tcp => ConnectionConfig::tcp(),
                        Transport::Tls(name) => ConnectionConfig::tls(Arc::from(name)),
                        _ => ConnectionConfig::udp(),
                    };
                    connection.port = address.port();
                    proxy_ns.push(NameServerConfig::new(address.ip(), true, vec![connection]));
                }
            }
            if proxy_ns.is_empty() {
                None
            } else {
                let mut builder = TokioResolver::builder_with_config(
                    ResolverConfig::from_name_servers(proxy_ns),
                    TokioRuntimeProvider::default(),
                );
                builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
                builder.options_mut().use_hosts_file = ResolveHosts::Never;
                builder.options_mut().timeout = timeout;
                Some(builder.build().map_err(|_| invalid())?)
            }
        };

        // 解析 Fake-IP 配置
        let enhanced_fakeip = spec
            .enhanced_mode
            .as_deref()
            .is_some_and(|m| matches!(m.to_ascii_lowercase().as_str(), "fake-ip" | "fakeip"));
        let enhanced_redir = spec
            .enhanced_mode
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case("redir-host"));
        let mut fakedns_v4 = spec.fake_ip_range.clone().or(fakeip_v4_from_server);
        let mut fakedns_v6 = spec.fake_ip_range6.clone().or(fakeip_v6_from_server);
        let mut pool_size = 65535usize;
        let mut fakedns_enabled =
            enhanced_fakeip || has_fakeip_server || fakedns_v4.is_some() || fakedns_v6.is_some();

        if let Some(fakedns) = &spec.fakedns {
            match fakedns {
                FakeDnsInput::Bool(b) => {
                    fakedns_enabled |= *b;
                }
                FakeDnsInput::Single(pool) => {
                    fakedns_enabled = true;
                    pool_size = pool.pool_size;
                    if pool.ip_pool.contains(':') {
                        fakedns_v6 = Some(pool.ip_pool.clone());
                    } else {
                        fakedns_v4 = Some(pool.ip_pool.clone());
                    }
                }
                FakeDnsInput::Multi(pools) => {
                    fakedns_enabled = !pools.is_empty();
                    for pool in pools {
                        pool_size = pool.pool_size;
                        if pool.ip_pool.contains(':') {
                            fakedns_v6 = Some(pool.ip_pool.clone());
                        } else {
                            fakedns_v4 = Some(pool.ip_pool.clone());
                        }
                    }
                }
            }
        }

        let fakeip_pool = if fakedns_enabled {
            if fakedns_v4.is_none() && fakedns_v6.is_none() {
                fakedns_v4 = Some("198.18.0.0/15".into());
                fakedns_v6 = Some("fc00::/18".into());
            }
            let persistence_path = spec.cache_file.as_ref().and_then(|c| {
                if c.enabled && c.store_fakeip {
                    Some(PathBuf::from(c.path.as_deref().unwrap_or("cache.db")))
                } else {
                    None
                }
            });
            Some(Arc::new(FakeIpPool::new(
                fakedns_v4.as_deref(),
                fakedns_v6.as_deref(),
                pool_size,
                spec.fake_ip_ttl.unwrap_or(1),
                spec.fake_ip_filter.clone(),
                persistence_path,
            )?))
        } else {
            None
        };

        let reverse_mapping = if spec.reverse_mapping || enhanced_redir || fakedns_enabled {
            Some(Arc::new(ReverseMappingCache::new()))
        } else {
            None
        };

        let fallback_tag = spec
            .final_server
            .clone()
            .or(first_tag)
            .unwrap_or_else(|| "default".into());
        let mut rules = Vec::with_capacity(spec.rules.len());
        for r in &spec.rules {
            rules.push(CompiledDnsRule::compile(r, &fallback_tag)?);
        }

        let mut policy_servers = server_domain_rules;
        for (pattern, val) in &spec.nameserver_policy {
            if let Some(s) = val.first_server() {
                policy_servers.push((pattern.clone(), s.to_owned()));
            }
        }

        Ok(Self {
            default_upstream,
            tagged_upstreams,
            final_tag: spec.final_server.clone(),
            hosts,
            rules,
            policy_servers,
            proxy_resolver,
            fakeip_pool,
            fakeip_enabled_by_default: enhanced_fakeip || spec.fakedns.is_some(),
            reverse_mapping,
            timeout,
            listen: spec.listen,
        })
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn fake_ip_pool(&self) -> Option<&Arc<FakeIpPool>> {
        self.fakeip_pool.as_ref()
    }

    pub fn lookup_fake_ip(&self, ip: IpAddr) -> Option<String> {
        self.fakeip_pool.as_ref()?.lookup_domain(ip)
    }

    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        self.fakeip_pool.as_ref().is_some_and(|p| p.contains(ip))
    }

    pub fn lookup_reverse_mapping(&self, ip: IpAddr) -> Option<String> {
        self.reverse_mapping.as_ref()?.lookup(ip)
    }

    pub fn flush_fake_ip(&self) -> Result<()> {
        if let Some(pool) = &self.fakeip_pool {
            pool.flush()?;
        }
        Ok(())
    }

    pub async fn resolve_proxy_host(&self, host: &str) -> Result<Vec<IpAddr>> {
        let key = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if let Some(addresses) = self.hosts.get(&key) {
            return Ok(addresses.clone());
        }
        if let Some(proxy_res) = &self.proxy_resolver {
            let lookup = proxy_res
                .lookup_ip(format!("{key}."))
                .await
                .map_err(|_| Error::Io(std::io::Error::other("代理节点 DNS 查询失败")))?;
            return Ok(lookup.iter().collect());
        }
        self.resolve(&key).await
    }

    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let key = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if let Some(addresses) = self.hosts.get(&key) {
            if let Some(rev) = &self.reverse_mapping {
                rev.record(&key, addresses, Duration::from_secs(60));
            }
            return Ok(addresses.clone());
        }
        let upstream = self
            .default_upstream
            .as_ref()
            .ok_or(Error::InvalidAddress)?;
        let lookup = upstream
            .lookup_ip(format!("{key}."))
            .await
            .map_err(|_| Error::Io(std::io::Error::other("DNS 查询失败")))?;
        let ips: Vec<IpAddr> = lookup.iter().collect();
        if let Some(rev) = &self.reverse_mapping {
            rev.record(&key, &ips, Duration::from_secs(60));
        }
        Ok(ips)
    }

    pub async fn exchange_packet(&self, request: &[u8]) -> Result<Vec<u8>> {
        exchange_wire_query(request, Some(self)).await
    }

    fn select_rule_action(
        &self,
        domain: &str,
        qtype: u16,
    ) -> Option<(&CompiledDnsRule, &CompiledDnsAction)> {
        for rule in &self.rules {
            if rule.matches(domain, qtype) {
                return Some((rule, &rule.action));
            }
        }
        None
    }

    fn matches_policy_server(&self, domain: &str) -> Option<&str> {
        for (pattern, server) in &self.policy_servers {
            if fakeip::wildcard_match(pattern, domain) {
                return Some(server.as_str());
            }
        }
        None
    }

    async fn query_tagged_server(
        &self,
        tag: &str,
        domain: &str,
        qtype: u16,
        raw_request: &[u8],
    ) -> Result<Option<(Vec<IpAddr>, u32)>> {
        if matches!(
            tag.to_ascii_lowercase().as_str(),
            "fakedns" | "fakeip" | "fake-ip"
        ) {
            return Ok(self.try_allocate_fake_ip(domain, qtype));
        }
        if let Some(backend) = self.tagged_upstreams.get(tag) {
            match backend {
                UpstreamBackend::FakeIp => return Ok(self.try_allocate_fake_ip(domain, qtype)),
                UpstreamBackend::Hickory(resolver) => {
                    let lookup = resolver
                        .lookup_ip(format!("{domain}."))
                        .await
                        .map_err(|_| Error::Io(std::io::Error::other("DNS 上游查询失败")))?;
                    let ips: Vec<IpAddr> = lookup.iter().collect();
                    if let Some(rev) = &self.reverse_mapping {
                        rev.record(domain, &ips, Duration::from_secs(60));
                    }
                    return Ok(Some((ips, 60)));
                }
                UpstreamBackend::DoH(doh) => {
                    let mut req = doh
                        .client
                        .post(&doh.url)
                        .header("content-type", "application/dns-message")
                        .header("accept", "application/dns-message")
                        .body(raw_request.to_vec());
                    for (k, v) in &doh.headers {
                        req = req.header(k, v);
                    }
                    let resp = req
                        .send()
                        .await
                        .map_err(|_| Error::Io(std::io::Error::other("DoH 查询失败")))?;
                    if !resp.status().is_success() {
                        return Err(Error::Protocol("DoH 响应状态异常"));
                    }
                    let body = resp
                        .bytes()
                        .await
                        .map_err(|_| Error::Io(std::io::Error::other("DoH 响应读取失败")))?;
                    let ips = extract_ips_from_wire_response(&body);
                    if let Some(rev) = &self.reverse_mapping {
                        rev.record(domain, &ips, Duration::from_secs(60));
                    }
                    return Ok(Some((ips, 60)));
                }
            }
        }
        Ok(None)
    }

    fn try_allocate_fake_ip(&self, domain: &str, qtype: u16) -> Option<(Vec<IpAddr>, u32)> {
        let pool = self.fakeip_pool.as_ref()?;
        if pool.should_skip(domain) {
            return None;
        }
        match qtype {
            1 => pool
                .allocate_v4(domain)
                .map(|v4| (vec![IpAddr::V4(v4)], pool.ttl())),
            28 => pool
                .allocate_v6(domain)
                .map(|v6| (vec![IpAddr::V6(v6)], pool.ttl())),
            _ => None,
        }
    }
}

fn extract_ips_from_wire_response(packet: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let Ok((_, _, mut pos)) = parse_question(packet) else {
        return out;
    };
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    for _ in 0..ancount {
        if pos >= packet.len() {
            break;
        }
        // 跳过压缩指针或标签名
        while pos < packet.len() {
            let b = packet[pos];
            if b == 0 {
                pos += 1;
                break;
            }
            if (b & 0xc0) == 0xc0 {
                pos += 2;
                break;
            }
            pos += 1 + usize::from(b);
        }
        if pos + 10 > packet.len() {
            break;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        let Some(rdata) = packet.get(pos..pos + rdlen) else {
            break;
        };
        pos += rdlen;
        if rtype == 1 && rdata.len() == 4 {
            out.push(IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]));
        } else if rtype == 28
            && rdata.len() == 16
            && let Ok(octets) = <[u8; 16]>::try_from(rdata)
        {
            out.push(IpAddr::from(octets));
        }
    }
    out
}

fn parse_question(packet: &[u8]) -> Result<(String, u16, usize)> {
    if packet.len() < 12 || packet.len() > 4096 {
        return Err(Error::Protocol("DNS 报文长度不合法"));
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return Err(Error::Protocol("DNS 查询缺少问题段"));
    }
    let mut cursor = 12usize;
    let mut labels = Vec::new();
    loop {
        if cursor >= packet.len() {
            return Err(Error::Protocol("DNS 域名标签截断"));
        }
        let len = usize::from(packet[cursor]);
        cursor += 1;
        if len == 0 {
            break;
        }
        if (len & 0xc0) != 0 || len > 63 || cursor + len > packet.len() {
            return Err(Error::Protocol("DNS 问题段标签不合法"));
        }
        let label = std::str::from_utf8(&packet[cursor..cursor + len])
            .map_err(|_| Error::Protocol("DNS 域名标签非 ASCII"))?;
        labels.push(label.to_ascii_lowercase());
        cursor += len;
    }
    if cursor + 4 > packet.len() || labels.is_empty() {
        return Err(Error::Protocol("DNS 问题尾部截断"));
    }
    let qtype = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    let qclass = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
    if qclass != 1 {
        return Err(Error::Protocol("DNS 仅支持 IN 类查询"));
    }
    Ok((labels.join("."), qtype, cursor + 4))
}

fn build_dns_reply(
    request: &[u8],
    question_end: usize,
    qtype: u16,
    rcode: u8,
    ips: &[IpAddr],
    ttl: u32,
) -> Vec<u8> {
    let rd = request[2] & 0x01;
    let mut reply = Vec::with_capacity(512);
    reply.extend_from_slice(&request[0..2]);
    reply.push(0x80 | rd);
    reply.push(0x80 | (rcode & 0x0f));
    reply.extend_from_slice(&1u16.to_be_bytes());
    let matched: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|ip| matches!((qtype, ip), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))))
        .take(16)
        .collect();
    let ancount = if rcode == 0 { matched.len() as u16 } else { 0 };
    reply.extend_from_slice(&ancount.to_be_bytes());
    reply.extend_from_slice(&[0, 0, 0, 0]);
    reply.extend_from_slice(&request[12..question_end]);
    if rcode == 0 {
        for ip in matched {
            reply.extend_from_slice(&[0xc0, 0x0c]);
            reply.extend_from_slice(&qtype.to_be_bytes());
            reply.extend_from_slice(&1u16.to_be_bytes());
            reply.extend_from_slice(&ttl.to_be_bytes());
            match ip {
                IpAddr::V4(v4) => {
                    reply.extend_from_slice(&4u16.to_be_bytes());
                    reply.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    reply.extend_from_slice(&16u16.to_be_bytes());
                    reply.extend_from_slice(&v6.octets());
                }
            }
        }
    }
    reply
}

pub async fn exchange_wire_query(
    request: &[u8],
    resolver: Option<&DnsResolver>,
) -> Result<Vec<u8>> {
    let (domain, qtype, question_end) = parse_question(request)?;
    if let Some(res) = resolver {
        // 1. 静态 hosts 优先
        if let Some(addresses) = res.hosts.get(&domain) {
            if let Some(rev) = &res.reverse_mapping {
                rev.record(&domain, addresses, Duration::from_secs(60));
            }
            return Ok(build_dns_reply(
                request,
                question_end,
                qtype,
                0,
                addresses,
                60,
            ));
        }

        // 2. 评估 DNS 规则
        let mut selected_server: Option<String> = None;
        if let Some((rule, action)) = res.select_rule_action(&domain, qtype) {
            match action {
                CompiledDnsAction::Reject { drop, no_drop } => {
                    if rule.should_drop_on_reject(*drop, *no_drop) {
                        return Err(Error::Rejected);
                    }
                    // RCODE = 5 (REFUSED)
                    return Ok(build_dns_reply(request, question_end, qtype, 5, &[], 0));
                }
                CompiledDnsAction::Route { server } => {
                    selected_server = Some(server.clone());
                }
            }
        }

        if selected_server.is_none()
            && let Some(policy_srv) = res.matches_policy_server(&domain)
        {
            selected_server = Some(policy_srv.to_owned());
        }

        // 3. 若显式选择了某台服务器（如 fakeip 或 DoH）
        if let Some(tag) = selected_server.as_deref()
            && let Some((ips, ttl)) = res
                .query_tagged_server(tag, &domain, qtype, request)
                .await?
        {
            return Ok(build_dns_reply(request, question_end, qtype, 0, &ips, ttl));
        }

        // 4. 若启用了全局 Fake-IP（且未命中 filter）
        if res.fakeip_enabled_by_default
            && matches!(qtype, 1 | 28)
            && let Some((ips, ttl)) = res.try_allocate_fake_ip(&domain, qtype)
        {
            return Ok(build_dns_reply(request, question_end, qtype, 0, &ips, ttl));
        }

        // 5. 若配置了 final_tag
        if let Some(final_tag) = res.final_tag.as_deref()
            && let Some((ips, ttl)) = res
                .query_tagged_server(final_tag, &domain, qtype, request)
                .await?
        {
            return Ok(build_dns_reply(request, question_end, qtype, 0, &ips, ttl));
        }
    }

    let resolved = match qtype {
        1 | 28 => match resolver {
            Some(resolver) => resolver.resolve(&domain).await,
            None => tokio::net::lookup_host((domain.as_str(), 0))
                .await
                .map(|iter| iter.map(|addr| addr.ip()).collect::<Vec<_>>())
                .map_err(Error::Io),
        },
        _ => Ok(Vec::new()),
    };
    match resolved {
        Ok(ips) => Ok(build_dns_reply(request, question_end, qtype, 0, &ips, 60)),
        // RCODE = 2 (SERVFAIL)
        Err(_) => Ok(build_dns_reply(request, question_end, qtype, 2, &[], 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::UdpSocket;

    fn spec(value: serde_json::Value) -> DnsSpec {
        serde_json::from_value(value).unwrap()
    }

    /// 对任意查询回答一条 A 记录，AAAA 查询返回空答案。
    async fn fake_upstream() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let question_end = buffer[12..length]
                    .iter()
                    .position(|byte| *byte == 0)
                    .map(|index| 12 + index + 5)
                    .unwrap();
                let is_a = buffer[question_end - 4..question_end - 2] == [0, 1];
                let mut reply = buffer[..question_end].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                reply[6..12].copy_from_slice(&[0, u8::from(is_a), 0, 0, 0, 0]);
                if is_a {
                    reply.extend_from_slice(&[
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7,
                    ]);
                }
                socket.send_to(&reply, peer).await.unwrap();
            }
        });
        address
    }

    #[test]
    fn rejects_malformed_specs() {
        for value in [
            json!({}),
            json!({"servers":["1.1.1.1"]}),
            json!({"servers":["udp://dns.example:53"]}),
            json!({"servers":["udp://1.1.1.1:0"]}),
            json!({"servers":["tls://1.1.1.1"]}),
            json!({"servers":["udp://1.1.1.1#name"]}),
            json!({"servers":["tcp://[2001:db8::1"]}),
            json!({"servers":["tcp://2001:db8::1]"]}),
            json!({"servers":["tcp://[192.0.2.1]"]}),
            json!({"hosts":{"10.0.0.1":["10.0.0.2"]}}),
            json!({"hosts":{"a.example":[]}}),
        ] {
            assert!(spec(value).validate().is_err());
        }
        assert!(
            spec(json!({"servers":["udp://1.1.1.1","tcp://[2606:4700:4700::1111]:53","tls://1.1.1.1#cloudflare-dns.com"]}))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn bracketed_ipv6_without_port_uses_the_default_port() {
        assert_eq!(
            parse_server("tcp://[2001:db8::1]").unwrap(),
            (Transport::Tcp, "[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse_server("tcp://2001:db8::1").unwrap(),
            (Transport::Tcp, "[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse_server("tls://[2001:db8::1]#dns.example").unwrap(),
            (
                Transport::Tls("dns.example".into()),
                "[2001:db8::1]:853".parse().unwrap()
            )
        );
    }

    /// 需要私有挂载命名空间，把测试名字写进该空间的 `/etc/hosts`：
    /// `unshare -m sh -c 'echo "203.0.113.9 shadowed.example" > "$H"; mount --bind "$H" /etc/hosts; cargo test -p kerlico-dns --offline -- --ignored'`
    #[tokio::test]
    #[ignore = "需要 root，并在私有挂载命名空间内改写 /etc/hosts"]
    async fn system_hosts_file_does_not_override_configured_upstreams() {
        let hosts = std::fs::read_to_string("/etc/hosts").unwrap();
        assert!(
            hosts.contains("shadowed.example"),
            "未按说明准备 hosts 文件"
        );
        let upstream = fake_upstream().await;
        let resolver =
            DnsResolver::new(&spec(json!({"servers":[format!("udp://{upstream}")]}))).unwrap();
        assert_eq!(
            resolver.resolve("shadowed.example").await.unwrap(),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn hosts_win_and_unknown_hosts_fail_without_upstream() {
        let resolver =
            DnsResolver::new(&spec(json!({"hosts":{"Svc.Internal":["10.0.0.5"]}}))).unwrap();
        assert_eq!(
            resolver.resolve("svc.internal").await.unwrap(),
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        assert!(resolver.resolve("other.internal").await.is_err());
    }

    #[tokio::test]
    async fn queries_the_configured_upstream() {
        let upstream = fake_upstream().await;
        let resolver =
            DnsResolver::new(&spec(json!({"servers":[format!("udp://{upstream}")]}))).unwrap();
        assert_eq!(
            resolver.resolve("www.example.com").await.unwrap(),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn exchange_packet_answers_wire_query_from_hosts() {
        let resolver =
            DnsResolver::new(&spec(json!({"hosts":{"svc.internal":["10.0.0.5"]}}))).unwrap();
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b's', b'v',
            b'c', 8, b'i', b'n', b't', b'e', b'r', b'n', b'a', b'l', 0, 0, 1, 0, 1,
        ];
        let reply = resolver.exchange_packet(&query).await.unwrap();
        assert_eq!(&reply[0..2], &[0x12, 0x34]);
        assert_eq!(&reply[6..8], &[0x00, 0x01]);
        assert_eq!(&reply[reply.len() - 4..], &[10, 0, 0, 5]);
    }

    #[tokio::test]
    async fn dns_rules_fakeip_doh_and_reverse_mapping_work() {
        let resolver = DnsResolver::new(&spec(json!({
            "servers": [
                "https://1.1.1.1/dns-query#proxy-out",
                {
                    "tag": "doh-custom",
                    "type": "https",
                    "server": "dns.google",
                    "server_port": 443,
                    "path": "/dns-query",
                    "headers": {"X-Custom": "1"},
                    "tls": {"server_name": "dns.google", "insecure": false},
                    "domains": ["google.com"]
                },
                {
                    "tag": "fake-srv",
                    "type": "fakeip",
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18"
                }
            ],
            "hosts": {
                "real.example": ["203.0.113.10"]
            },
            "reverse_mapping": true,
            "enhanced_mode": "fake-ip",
            "fake_ip_ttl": 3,
            "fake_ip_filter": ["+.bypass.example"],
            "final": "fake-srv",
            "timeout": "5s",
            "rules": [
                {
                    "domain_suffix": ["ads.example"],
                    "query_type": ["A", 28],
                    "action": "reject",
                    "method": "default",
                    "no_drop": true
                },
                {
                    "domain_regex": ["^drop\\..*"],
                    "action": "reject",
                    "method": "drop"
                },
                {
                    "domain_keyword": ["fake"],
                    "action": "route",
                    "server": "fake-srv"
                }
            ]
        })))
        .unwrap();

        // 1. Reject default -> RCODE = 5 (REFUSED)
        let ads_query = [
            0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'a', b'd',
            b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
        ];
        let ads_reply = resolver.exchange_packet(&ads_query).await.unwrap();
        assert_eq!(ads_reply[3] & 0x0f, 5);

        // 2. Reject drop -> Error::Rejected
        let drop_query = [
            0xaa, 0xbc, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 4, b'd', b'r',
            b'o', b'p', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
        ];
        assert!(matches!(
            resolver.exchange_packet(&drop_query).await,
            Err(Error::Rejected)
        ));

        // 3. Fake-IP allocation + IP-to-domain lookup
        let fake_query = [
            0x11, 0x22, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 4, b'f', b'a',
            b'k', b'e', 3, b'o', b'r', b'g', 0, 0, 1, 0, 1,
        ];
        let fake_reply = resolver.exchange_packet(&fake_query).await.unwrap();
        let ip_bytes: [u8; 4] = fake_reply[fake_reply.len() - 4..].try_into().unwrap();
        let fake_ip = IpAddr::from(ip_bytes);
        assert!(resolver.is_fake_ip(fake_ip));
        assert_eq!(
            resolver.lookup_fake_ip(fake_ip).as_deref(),
            Some("fake.org")
        );

        // 4. Reverse mapping from real hosts lookup
        let real_ips = resolver.resolve("real.example").await.unwrap();
        assert_eq!(
            resolver.lookup_reverse_mapping(real_ips[0]).as_deref(),
            Some("real.example")
        );
    }
}
