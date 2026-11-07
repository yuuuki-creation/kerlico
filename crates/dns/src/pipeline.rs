//! 查询管线与 [`DnsResolver`]。

use crate::{
    DnsPolicyValue, DnsRuleSpec, DnsServerInput, DnsSpec, FakeIpPool, ReverseMappingCache,
    cache::{self, DnsCache, Key, Scope},
    fakeip::FakeDnsInput,
    hosts::{HostEntry, Hosts},
    matcher::{Condition, ConditionTable, NoSets, SetLookup, Sets, invalid},
    server::{self, ServerDef, Via},
    upstream::{self, Bootstrap, DialerSlot, DnsDialer, GroupReply, Net, Upstream},
    wire::{self, Question, Synth},
};
use kerlico_core::{Error, Result};
use regex::Regex;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

/// 查询来自哪个使用方；决定是否允许 Fake-IP 与使用哪组上游。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    /// DNS 报文：劫持、`dns.listen`、DNS 出站。允许 Fake-IP。
    Wire,
    /// `Local` 出网与路由规则所需的真实地址；有 `direct-nameserver` 时用它。
    Local,
    /// 代理节点服务器域名；有 `proxy-server-nameserver` 时用它。
    ProxyServer,
    /// 控制面 `/dns/query`：主解析器，不分配 Fake-IP。
    Query,
}

/// 应答出自哪一组上游。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupKind {
    Rule,
    Policy,
    Main,
    Fallback,
    ProxyServer,
    Direct,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnswerSource {
    Hosts,
    FakeIp,
    Rejected,
    /// `ipv6: false` 时 AAAA 查询的空应答。
    Ipv6Disabled,
    Cache {
        server: String,
        stale: bool,
    },
    Upstream {
        group: GroupKind,
        server: String,
    },
}

#[derive(Clone, Debug)]
pub struct DnsAnswer {
    pub message: Vec<u8>,
    pub source: AnswerSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Strategy {
    PreferV4,
    PreferV6,
    V4Only,
    V6Only,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DnsAction {
    Route(String),
    Reject { drop: bool, no_drop: bool },
}

struct DnsRule {
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    domain_regex: Vec<Regex>,
    geosite: Vec<String>,
    query_type: Vec<u16>,
    rule_set: Vec<String>,
    invert: bool,
    action: DnsAction,
    reject_window: Mutex<VecDeque<Instant>>,
}

fn plain_domain(raw: &str) -> Result<String> {
    match crate::matcher::DomainPattern::parse(raw)? {
        crate::matcher::DomainPattern::Exact(name) => Ok(name),
        _ => Err(invalid()),
    }
}

impl DnsRule {
    fn compile(spec: &DnsRuleSpec) -> Result<Self> {
        let action = match spec.action.as_deref().unwrap_or("route") {
            "route" => DnsAction::Route(spec.server.clone().ok_or_else(invalid)?),
            "reject" => DnsAction::Reject {
                drop: match spec.method.as_deref().unwrap_or("default") {
                    "default" => false,
                    "drop" => true,
                    _ => return Err(invalid()),
                },
                no_drop: spec.no_drop,
            },
            _ => return Err(invalid()),
        };
        Ok(Self {
            domain: spec
                .domain
                .iter()
                .map(|d| plain_domain(d))
                .collect::<Result<_>>()?,
            domain_suffix: spec
                .domain_suffix
                .iter()
                .map(|d| plain_domain(d.strip_prefix('.').unwrap_or(d)))
                .collect::<Result<_>>()?,
            domain_keyword: spec
                .domain_keyword
                .iter()
                .map(|k| {
                    if k.is_empty() || !k.is_ascii() {
                        Err(invalid())
                    } else {
                        Ok(k.to_ascii_lowercase())
                    }
                })
                .collect::<Result<_>>()?,
            domain_regex: spec
                .domain_regex
                .iter()
                .map(|r| Regex::new(r).map_err(|_| invalid()))
                .collect::<Result<_>>()?,
            geosite: spec.geosite.iter().map(|g| g.trim().to_owned()).collect(),
            query_type: spec
                .query_type
                .iter()
                .map(crate::DnsQueryTypeInput::to_code)
                .collect::<Result<_>>()?,
            rule_set: spec.rule_set.iter().map(|s| s.trim().to_owned()).collect(),
            invert: spec.invert,
            action,
            reject_window: Mutex::new(VecDeque::new()),
        })
    }

    fn matches(&self, host: &str, qtype: u16, sets: &dyn SetLookup) -> bool {
        let has_domain = !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.geosite.is_empty()
            || !self.rule_set.is_empty();
        let domain_hit = !has_domain
            || self.domain.iter().any(|d| d == host)
            || self.domain_suffix.iter().any(|s| {
                host == s
                    || host
                        .strip_suffix(s.as_str())
                        .is_some_and(|p| p.ends_with('.'))
            })
            || self
                .domain_keyword
                .iter()
                .any(|k| host.contains(k.as_str()))
            || self.domain_regex.iter().any(|r| r.is_match(host))
            || self.geosite.iter().any(|g| sets.geosite_matches(g, host))
            || self
                .rule_set
                .iter()
                .any(|t| sets.rule_set_matches_domain(t, host));
        let hit = domain_hit && (self.query_type.is_empty() || self.query_type.contains(&qtype));
        hit != self.invert
    }

    /// 30 秒内触发 50 次后自动改为丢弃，除非 `no_drop`。
    fn drops(&self, drop: bool, no_drop: bool) -> bool {
        if drop {
            return true;
        }
        if no_drop {
            return false;
        }
        let now = Instant::now();
        let mut win = self.reject_window.lock().unwrap_or_else(|e| e.into_inner());
        while win
            .front()
            .is_some_and(|f| now.duration_since(*f) > Duration::from_secs(30))
        {
            win.pop_front();
        }
        win.push_back(now);
        win.len() >= 50
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(raw: &str) -> Result<Self> {
        let (ip, prefix) = raw.trim().split_once('/').ok_or_else(invalid)?;
        let net: IpAddr = ip.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        if prefix > if net.is_ipv4() { 32 } else { 128 } {
            return Err(invalid());
        }
        Ok(Self { net, prefix })
    }
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

#[derive(Default)]
struct FallbackFilter {
    geoip: Option<String>,
    ipcidr: Vec<Cidr>,
    domains: ConditionTable<()>,
}

impl FallbackFilter {
    /// Mihomo：IP 不属于 `geoip-code` 且非私有，或落在 `ipcidr` 内，则改用 fallback 结果。
    fn ip_needs_fallback(&self, ip: IpAddr, sets: &dyn SetLookup) -> bool {
        self.geoip
            .as_deref()
            .is_some_and(|code| !sets.geoip_matches(code, ip) && !is_private(ip))
            || self.ipcidr.iter().any(|c| c.contains(ip))
    }
}

#[derive(Clone)]
struct PolicyTarget {
    label: String,
    servers: Vec<Arc<Upstream>>,
    fake: bool,
}

struct FakeIp {
    pool: Arc<FakeIpPool>,
    filter: ConditionTable<()>,
    whitelist: bool,
    global: bool,
}

enum Target {
    Up(Arc<Upstream>),
    Fake,
}

pub(crate) struct Inner {
    hosts: Hosts,
    use_hosts: bool,
    rules: Vec<DnsRule>,
    targets: HashMap<String, Target>,
    main: Vec<Arc<Upstream>>,
    fallback: Vec<Arc<Upstream>>,
    fallback_filter: FallbackFilter,
    policy: ConditionTable<PolicyTarget>,
    proxy_servers: Vec<Arc<Upstream>>,
    proxy_policy: ConditionTable<PolicyTarget>,
    direct_servers: Vec<Arc<Upstream>>,
    direct_follow_policy: bool,
    fake: Option<FakeIp>,
    ipv6: bool,
    ipv6_timeout: Duration,
    strategy: Strategy,
    cache: Option<DnsCache>,
    reverse: Option<Arc<ReverseMappingCache>>,
    timeout: Duration,
    listen: Option<SocketAddr>,
    sets: OnceLock<Sets>,
    dialer: DialerSlot,
    outbounds: Vec<String>,
    rule_sets: Vec<String>,
}

fn parse_duration(raw: &str) -> Result<Duration> {
    let s = raw.trim();
    let (num, unit) = match s.strip_suffix("ms") {
        Some(n) => (n, 1),
        None => (s.strip_suffix('s').unwrap_or(s), 1000),
    };
    let v: u64 = num.trim().parse().map_err(|_| invalid())?;
    if v == 0 {
        return Err(invalid());
    }
    Ok(Duration::from_millis(v * unit))
}

fn parse_listen(raw: &str) -> Result<SocketAddr> {
    let t = raw.trim();
    if let Some(port) = t.strip_prefix(':') {
        return Ok(SocketAddr::from((
            [0, 0, 0, 0],
            port.parse::<u16>().map_err(|_| invalid())?,
        )));
    }
    t.parse::<SocketAddr>().map_err(|_| invalid())
}

struct Builder<'a> {
    spec: &'a DnsSpec,
    net: Arc<Net>,
    respect_rules: bool,
    outbounds: Vec<String>,
    targets: HashMap<String, Target>,
    fake_ranges: (Option<String>, Option<String>),
    has_fake_server: bool,
}

impl Builder<'_> {
    fn upstream(&mut self, def: &ServerDef, routed: bool) -> Result<Arc<Upstream>> {
        let mut def = def.clone();
        if routed && self.respect_rules && def.via == Via::Direct {
            def.via = Via::Rules;
        }
        if let Via::Outbound(name) = &def.via
            && !self.outbounds.contains(name)
        {
            self.outbounds.push(name.clone());
        }
        let net = self.net.clone();
        if def.ecs.is_none()
            && let Some(raw) = &self.spec.client_subnet
        {
            def.ecs = Some((raw.parse()?, false));
        }
        Ok(Arc::new(Upstream::new(&def, net, self.spec.prefer_h3)?))
    }

    fn group(
        &mut self,
        inputs: &[DnsServerInput],
        name: &str,
        routed: bool,
    ) -> Result<Vec<Arc<Upstream>>> {
        let mut out = Vec::with_capacity(inputs.len());
        for (i, input) in inputs.iter().enumerate() {
            let def = server::parse_input(input, name, i)?;
            if def.is_fake() {
                return Err(invalid());
            }
            out.push(self.upstream(&def, routed)?);
        }
        Ok(out)
    }

    /// 策略值：已有上游标签或上游 URL 列表。
    fn policy_target(
        &mut self,
        label: &str,
        value: &DnsPolicyValue,
        routed: bool,
    ) -> Result<PolicyTarget> {
        let mut servers = Vec::new();
        let mut fake = false;
        for item in value.servers() {
            match self.targets.get(item) {
                Some(Target::Up(u)) => servers.push(u.clone()),
                Some(Target::Fake) => fake = true,
                None => {
                    let def = server::parse_url(item, item.to_owned())?;
                    if def.is_fake() {
                        fake = true;
                        continue;
                    }
                    servers.push(self.upstream(&def, routed)?);
                }
            }
        }
        if servers.is_empty() && !fake {
            return Err(invalid());
        }
        Ok(PolicyTarget {
            label: label.to_owned(),
            servers,
            fake,
        })
    }

    fn policy_table(
        &mut self,
        map: &crate::spec::DnsPolicyMap,
        routed: bool,
    ) -> Result<ConditionTable<PolicyTarget>> {
        let mut table = if map.ordered {
            ConditionTable::ordered()
        } else {
            ConditionTable::default()
        };
        for (key, value) in &map.entries {
            let target = self.policy_target(key, value, routed)?;
            for part in key.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                table.push(Condition::parse(part)?, target.clone());
            }
        }
        Ok(table)
    }
}

impl Inner {
    pub(crate) fn build(spec: &DnsSpec, load_state: bool) -> Result<Self> {
        let timeout = spec
            .timeout
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .unwrap_or(Duration::from_secs(5));
        let dialer: DialerSlot = Arc::new(OnceLock::new());
        let bootstrap_net = Arc::new(Net {
            timeout,
            dialer: dialer.clone(),
            bootstrap: None,
        });
        let mut bootstrap = Vec::new();
        for (i, input) in spec.default_nameserver.iter().enumerate() {
            let def = server::parse_input(input, "default", i)?;
            if def.is_fake() || def.via != Via::Direct {
                return Err(invalid());
            }
            if let server::Kind::Udp(ep)
            | server::Kind::Tcp(ep)
            | server::Kind::Tls(ep, _)
            | server::Kind::Quic(ep, _) = &def.kind
                && matches!(ep.host, kerlico_core::Address::Domain(_))
            {
                return Err(Error::Config("default-nameserver 只能使用 IP 地址".into()));
            }
            bootstrap.push(Upstream::new(&def, bootstrap_net.clone(), spec.prefer_h3)?);
        }
        let net = Arc::new(Net {
            timeout,
            dialer: dialer.clone(),
            bootstrap: (!bootstrap.is_empty()).then(|| Arc::new(Bootstrap::new(bootstrap))),
        });
        if spec.respect_rules && spec.proxy_server_nameserver.is_empty() {
            return Err(Error::Config(
                "respect-rules 需要同时配置 proxy-server-nameserver".into(),
            ));
        }
        let mut b = Builder {
            spec,
            net,
            respect_rules: spec.respect_rules,
            outbounds: Vec::new(),
            targets: HashMap::new(),
            fake_ranges: (None, None),
            has_fake_server: false,
        };

        let mut main = Vec::new();
        let mut server_domains = Vec::new();
        for (i, input) in spec.servers.iter().enumerate() {
            let def = server::parse_input(input, "dns", i)?;
            for d in &def.domains {
                server_domains.push((d.clone(), def.tag.clone()));
            }
            if let server::Kind::FakeIp { v4, v6 } = &def.kind {
                b.has_fake_server = true;
                if v4.is_some() {
                    b.fake_ranges.0 = v4.clone();
                }
                if v6.is_some() {
                    b.fake_ranges.1 = v6.clone();
                }
                b.targets.entry(def.tag.clone()).or_insert(Target::Fake);
                continue;
            }
            let up = b.upstream(&def, true)?;
            b.targets
                .entry(def.tag.clone())
                .or_insert_with(|| Target::Up(up.clone()));
            main.push(up);
        }
        for name in ["fakeip", "fakedns", "fake-ip"] {
            b.targets.entry(name.into()).or_insert(Target::Fake);
        }
        if let Some(tag) = &spec.final_server {
            match b.targets.get(tag) {
                Some(Target::Up(up)) => main = vec![up.clone()],
                Some(Target::Fake) => return Err(invalid()),
                None => {
                    let def = server::parse_url(tag, tag.clone())?;
                    main = vec![b.upstream(&def, true)?];
                }
            }
        }
        if main.is_empty() {
            let def = server::parse_url("system", "system".into())?;
            main.push(b.upstream(&def, false)?);
        }
        let fallback = b.group(&spec.fallback, "fallback", true)?;
        let fallback_filter = match &spec.fallback_filter {
            _ if fallback.is_empty() => FallbackFilter::default(),
            filter => {
                let f = filter.clone().unwrap_or_default();
                let mut domains = ConditionTable::default();
                for d in &f.domain {
                    domains.push(Condition::parse(d)?, ());
                }
                for g in &f.geosite {
                    domains.push(Condition::Geosite(g.trim().to_owned()), ());
                }
                FallbackFilter {
                    geoip: f
                        .geoip
                        .unwrap_or(true)
                        .then(|| f.geoip_code.clone().unwrap_or_else(|| "CN".into())),
                    ipcidr: f
                        .ipcidr
                        .iter()
                        .map(|c| Cidr::parse(c))
                        .collect::<Result<_>>()?,
                    domains,
                }
            }
        };

        let mut policy = b.policy_table(&spec.nameserver_policy, true)?;
        for (domain, tag) in server_domains {
            let target = match b.targets.get(&tag) {
                Some(Target::Up(u)) => PolicyTarget {
                    label: tag.clone(),
                    servers: vec![u.clone()],
                    fake: false,
                },
                _ => PolicyTarget {
                    label: tag.clone(),
                    servers: Vec::new(),
                    fake: true,
                },
            };
            policy.push(Condition::parse(&domain)?, target);
        }
        let proxy_servers = b.group(&spec.proxy_server_nameserver, "proxy-server", false)?;
        let proxy_policy = b.policy_table(&spec.proxy_server_nameserver_policy, false)?;
        let direct_servers = b.group(&spec.direct_nameserver, "direct", false)?;

        let mut rules = Vec::with_capacity(spec.rules.len());
        for r in &spec.rules {
            let rule = DnsRule::compile(r)?;
            if let DnsAction::Route(tag) = &rule.action
                && !b.targets.contains_key(tag)
            {
                return Err(Error::Config(format!("DNS 规则引用的上游 {tag} 不存在")));
            }
            rules.push(rule);
        }

        let fake = Self::fake_ip(spec, &b, load_state)?;
        let enhanced_redir = spec
            .enhanced_mode
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case("redir-host"));
        let reverse = (spec.reverse_mapping || enhanced_redir || fake.is_some())
            .then(|| Arc::new(ReverseMappingCache::new()));

        let strategy = match spec
            .strategy
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("prefer_ipv4") | Some("prefer-ipv4") => Strategy::PreferV4,
            Some("prefer_ipv6") | Some("prefer-ipv6") => Strategy::PreferV6,
            Some("ipv4_only") | Some("ipv4-only") => Strategy::V4Only,
            Some("ipv6_only") | Some("ipv6-only") => Strategy::V6Only,
            Some(_) => return Err(invalid()),
        };
        let algorithm = match spec
            .cache_algorithm
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("lru") => cache::Algorithm::Lru,
            Some("arc") => cache::Algorithm::Arc,
            Some(_) => return Err(invalid()),
        };
        let cache = (!spec.disable_cache).then(|| {
            DnsCache::new(
                spec.cache_max_size.unwrap_or(4096),
                algorithm,
                spec.optimistic_cache.unwrap_or(true),
            )
        });

        let mut rule_sets: Vec<String> = rules.iter().flat_map(|r| r.rule_set.clone()).collect();
        rule_sets.extend(policy.rule_sets().map(str::to_owned));
        rule_sets.extend(proxy_policy.rule_sets().map(str::to_owned));
        if let Some(f) = &fake {
            rule_sets.extend(f.filter.rule_sets().map(str::to_owned));
        }

        let hosts = Hosts::build(&spec.hosts, spec.use_system_hosts.unwrap_or(true))?;
        Ok(Self {
            hosts,
            use_hosts: spec.use_hosts.unwrap_or(true),
            rules,
            main,
            fallback,
            fallback_filter,
            policy,
            proxy_servers,
            proxy_policy,
            direct_servers,
            direct_follow_policy: spec.direct_nameserver_follow_policy,
            fake,
            ipv6: spec.ipv6.unwrap_or(true) && strategy != Strategy::V4Only,
            ipv6_timeout: Duration::from_millis(spec.ipv6_timeout.unwrap_or(100)),
            strategy,
            cache,
            reverse,
            timeout,
            listen: spec.listen.as_deref().map(parse_listen).transpose()?,
            sets: OnceLock::new(),
            dialer,
            outbounds: b.outbounds,
            rule_sets,
            targets: b.targets,
        })
    }

    fn fake_ip(spec: &DnsSpec, b: &Builder<'_>, load_state: bool) -> Result<Option<FakeIp>> {
        let mode = spec.enhanced_mode.as_deref().map(str::to_ascii_lowercase);
        match mode.as_deref() {
            None | Some("normal") | Some("redir-host") | Some("fake-ip") | Some("fakeip") => {}
            Some(_) => return Err(invalid()),
        }
        let enhanced_fake = matches!(mode.as_deref(), Some("fake-ip") | Some("fakeip"));
        let mut v4 = spec.fake_ip_range.clone().or(b.fake_ranges.0.clone());
        let mut v6 = spec.fake_ip_range6.clone().or(b.fake_ranges.1.clone());
        let mut pool_size = 4096usize;
        let mut enabled = enhanced_fake || b.has_fake_server || v4.is_some() || v6.is_some();
        match &spec.fakedns {
            Some(FakeDnsInput::Bool(on)) => enabled |= *on,
            Some(FakeDnsInput::Single(pool)) => {
                enabled = true;
                pool_size = pool.pool_size;
                if pool.ip_pool.contains(':') {
                    v6 = Some(pool.ip_pool.clone());
                } else {
                    v4 = Some(pool.ip_pool.clone());
                }
            }
            Some(FakeDnsInput::Multi(pools)) => {
                enabled = !pools.is_empty();
                for pool in pools {
                    pool_size = pool.pool_size;
                    if pool.ip_pool.contains(':') {
                        v6 = Some(pool.ip_pool.clone());
                    } else {
                        v4 = Some(pool.ip_pool.clone());
                    }
                }
            }
            None => {}
        }
        if !enabled {
            return Ok(None);
        }
        if v4.is_none() && v6.is_none() {
            v4 = Some("198.18.0.0/15".into());
            v6 = Some("fc00::/18".into());
        }
        let persistence = spec
            .cache_file
            .as_ref()
            .filter(|c| load_state && c.enabled && c.store_fakeip)
            .map(|c| PathBuf::from(c.path.as_deref().unwrap_or("cache.db")));
        let pool = FakeIpPool::new(
            v4.as_deref(),
            v6.as_deref(),
            pool_size,
            spec.fake_ip_ttl.unwrap_or(1),
            Vec::new(),
            persistence,
        )?;
        let mut filter = ConditionTable::default();
        for item in &spec.fake_ip_filter {
            filter.push(Condition::parse(item)?, ());
        }
        let whitelist = match spec
            .fake_ip_filter_mode
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("blacklist") => false,
            Some("whitelist") => true,
            Some(_) => return Err(invalid()),
        };
        Ok(Some(FakeIp {
            pool: Arc::new(pool),
            filter,
            whitelist,
            global: enhanced_fake || spec.fakedns.is_some(),
        }))
    }

    fn sets(&self) -> &dyn SetLookup {
        match self.sets.get() {
            Some(s) => s.as_ref(),
            None => &NoSets,
        }
    }

    fn scope(&self, purpose: Purpose) -> Scope {
        match purpose {
            Purpose::Local if !self.direct_servers.is_empty() => Scope::Direct,
            Purpose::ProxyServer if !self.proxy_servers.is_empty() => Scope::ProxyServer,
            _ => Scope::Main,
        }
    }

    fn fake_allowed(&self, fake: &FakeIp, host: &str) -> bool {
        let listed = fake.filter.lookup(host, self.sets()).is_some();
        listed == fake.whitelist
    }

    /// Fake-IP 应答：A/AAAA 分配地址（缺对应网段时空应答），HTTPS/SVCB 空应答，其他类型不处理。
    fn fake_answer(&self, query: &[u8], q: &Question) -> Option<Vec<u8>> {
        let pool = &self.fake.as_ref()?.pool;
        let ips: Vec<Synth> = match q.qtype {
            wire::TYPE_A => pool
                .allocate_v4(&q.name)
                .map(|v4| Synth::Ip(IpAddr::V4(v4)))
                .into_iter()
                .collect(),
            wire::TYPE_AAAA => pool
                .allocate_v6(&q.name)
                .map(|v6| Synth::Ip(IpAddr::V6(v6)))
                .into_iter()
                .collect(),
            wire::TYPE_HTTPS | wire::TYPE_SVCB => Vec::new(),
            _ => return None,
        };
        Some(wire::reply(query, q, wire::RCODE_NOERROR, &ips, pool.ttl()))
    }

    fn record_reverse(&self, host: &str, message: &[u8]) {
        if let Some(rev) = &self.reverse {
            let ips = wire::answer_ips(message);
            if !ips.is_empty() {
                let ttl = wire::min_ttl(message).unwrap_or(60).max(1);
                rev.record(host, &ips, Duration::from_secs(u64::from(ttl)));
            }
        }
    }

    async fn answer(self: &Arc<Self>, query: &[u8], purpose: Purpose) -> Result<DnsAnswer> {
        let q = wire::parse_question(query)?;
        let ip_query = matches!(q.qtype, wire::TYPE_A | wire::TYPE_AAAA);

        if self.use_hosts && ip_query {
            match self.hosts.resolve(&q.name) {
                Some(HostEntry::Ips(ips)) => {
                    let synth: Vec<Synth> = ips.iter().map(|ip| Synth::Ip(*ip)).collect();
                    let message = wire::reply(query, &q, wire::RCODE_NOERROR, &synth, 10);
                    self.record_reverse(&q.name, &message);
                    return Ok(DnsAnswer {
                        message,
                        source: AnswerSource::Hosts,
                    });
                }
                Some(HostEntry::Alias(target)) => {
                    let alias = wire::build_query(wire::id(query), &target, q.qtype)?;
                    let aq = wire::parse_question(&alias)?;
                    let inner = self.answer_after_hosts(&alias, &aq, purpose).await?;
                    let ips: Vec<Synth> = wire::answer_ips(&inner.message)
                        .into_iter()
                        .map(Synth::Ip)
                        .collect();
                    let ttl = wire::min_ttl(&inner.message).unwrap_or(10);
                    let message = wire::reply(query, &q, wire::rcode(&inner.message), &ips, ttl);
                    return Ok(DnsAnswer {
                        message,
                        source: inner.source,
                    });
                }
                None => {}
            }
        }
        self.answer_after_hosts(query, &q, purpose).await
    }

    /// hosts 之后的步骤；别名链已在 hosts 表内走完，这里不再查 hosts。
    async fn answer_after_hosts(
        self: &Arc<Self>,
        query: &[u8],
        q: &Question,
        purpose: Purpose,
    ) -> Result<DnsAnswer> {
        let mut selected: Option<(Arc<Upstream>, String)> = None;
        if let Some(rule) = self
            .rules
            .iter()
            .find(|r| r.matches(&q.name, q.qtype, self.sets()))
        {
            match &rule.action {
                DnsAction::Reject { drop, no_drop } => {
                    if purpose != Purpose::Wire || rule.drops(*drop, *no_drop) {
                        return Err(Error::Rejected);
                    }
                    return Ok(DnsAnswer {
                        message: wire::reply(query, q, wire::RCODE_REFUSED, &[], 0),
                        source: AnswerSource::Rejected,
                    });
                }
                DnsAction::Route(tag) => match self.targets.get(tag) {
                    Some(Target::Fake) if purpose == Purpose::Wire => {
                        if let Some(message) = self.fake_answer(query, q) {
                            return Ok(DnsAnswer {
                                message,
                                source: AnswerSource::FakeIp,
                            });
                        }
                    }
                    Some(Target::Up(up)) => selected = Some((up.clone(), tag.clone())),
                    _ => {}
                },
            }
        }

        if purpose == Purpose::Wire
            && selected.is_none()
            && let Some(fake) = &self.fake
            && fake.global
            && self.fake_allowed(fake, &q.name)
            && let Some(message) = self.fake_answer(query, q)
        {
            return Ok(DnsAnswer {
                message,
                source: AnswerSource::FakeIp,
            });
        }

        if q.qtype == wire::TYPE_AAAA && !self.ipv6 {
            return Ok(DnsAnswer {
                message: wire::reply(query, q, wire::RCODE_NOERROR, &[], 0),
                source: AnswerSource::Ipv6Disabled,
            });
        }

        let key = Key {
            name: q.name.clone(),
            qtype: q.qtype,
            scope: self.scope(purpose),
        };
        if let Some(cache) = &self.cache
            && let Some(hit) = cache.get(&key, Instant::now())
        {
            if hit.stale {
                let me = self.clone();
                let query = query.to_vec();
                let key = key.clone();
                let selected = selected.clone();
                tokio::spawn(async move {
                    if let Ok((reply, _)) = me.exchange(&query, selected, purpose).await {
                        me.store(key, &reply);
                    }
                });
            }
            let mut message = hit.message;
            wire::set_id(&mut message, wire::id(query));
            return Ok(DnsAnswer {
                message,
                source: AnswerSource::Cache {
                    server: hit.server,
                    stale: hit.stale,
                },
            });
        }

        let (reply, group) = self.exchange(query, selected, purpose).await?;
        self.store(key, &reply);
        self.record_reverse(&q.name, &reply.message);
        Ok(DnsAnswer {
            message: reply.message,
            source: AnswerSource::Upstream {
                group,
                server: reply.server,
            },
        })
    }

    fn store(&self, key: Key, reply: &GroupReply) {
        if let Some(cache) = &self.cache
            && reply.cacheable
            && matches!(
                wire::rcode(&reply.message),
                wire::RCODE_NOERROR | wire::RCODE_NXDOMAIN
            )
        {
            cache.put(key, &reply.message, &reply.server, Instant::now());
        }
    }

    async fn exchange(
        &self,
        query: &[u8],
        selected: Option<(Arc<Upstream>, String)>,
        purpose: Purpose,
    ) -> Result<(GroupReply, GroupKind)> {
        let q = wire::parse_question(query)?;
        if let Some((up, _)) = selected {
            return Ok((
                upstream::exchange_first([up.as_ref()], query).await?,
                GroupKind::Rule,
            ));
        }
        match self.scope(purpose) {
            Scope::ProxyServer => {
                if let Some(p) = self.proxy_policy.lookup(&q.name, self.sets())
                    && !p.servers.is_empty()
                {
                    return Ok((group(&p.servers, query).await?, GroupKind::Policy));
                }
                return Ok((
                    group(&self.proxy_servers, query).await?,
                    GroupKind::ProxyServer,
                ));
            }
            Scope::Direct if !self.direct_follow_policy => {
                return Ok((group(&self.direct_servers, query).await?, GroupKind::Direct));
            }
            Scope::Direct => {
                if let Some(p) = self.policy.lookup(&q.name, self.sets())
                    && !p.servers.is_empty()
                {
                    return Ok((group(&p.servers, query).await?, GroupKind::Policy));
                }
                return Ok((group(&self.direct_servers, query).await?, GroupKind::Direct));
            }
            Scope::Main => {}
        }
        if let Some(p) = self.policy.lookup(&q.name, self.sets()) {
            if p.fake
                && purpose == Purpose::Wire
                && p.servers.is_empty()
                && let Some(message) = self.fake_answer(query, &q)
            {
                return Ok((
                    GroupReply {
                        message,
                        server: p.label.clone(),
                        cacheable: false,
                    },
                    GroupKind::Policy,
                ));
            }
            if !p.servers.is_empty() {
                return Ok((group(&p.servers, query).await?, GroupKind::Policy));
            }
        }
        let ip_query = matches!(q.qtype, wire::TYPE_A | wire::TYPE_AAAA);
        if !ip_query || self.fallback.is_empty() {
            return Ok((group(&self.main, query).await?, GroupKind::Main));
        }
        if self
            .fallback_filter
            .domains
            .lookup(&q.name, self.sets())
            .is_some()
        {
            return Ok((group(&self.fallback, query).await?, GroupKind::Fallback));
        }
        let fallback = group(&self.fallback, query);
        tokio::pin!(fallback);
        let main = group(&self.main, query);
        tokio::pin!(main);
        let (main_result, fallback_done) = tokio::select! {
            biased;
            m = &mut main => (m, None),
            f = &mut fallback => {
                let m = (&mut main).await;
                (m, Some(f))
            }
        };
        if let Ok(reply) = &main_result {
            let ips = wire::answer_ips(&reply.message);
            if !ips.is_empty()
                && ips
                    .iter()
                    .all(|ip| !self.fallback_filter.ip_needs_fallback(*ip, self.sets()))
            {
                return main_result.map(|r| (r, GroupKind::Main));
            }
        }
        let fallback_result = match fallback_done {
            Some(f) => f,
            None => fallback.await,
        };
        fallback_result.map(|r| (r, GroupKind::Fallback))
    }

    async fn lookup_ips(self: &Arc<Self>, host: &str, purpose: Purpose) -> Result<Vec<IpAddr>> {
        let host = host.trim_end_matches('.');
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let want_a = self.strategy != Strategy::V6Only;
        let want_aaaa = self.ipv6;
        let ips_of = |r: Result<DnsAnswer>| -> Result<Vec<IpAddr>> {
            r.map(|a| wire::answer_ips(&a.message))
        };
        let aaaa = want_aaaa.then(|| {
            let me = self.clone();
            let query = wire::build_query(upstream::rand_id(), host, wire::TYPE_AAAA);
            tokio::spawn(async move { me.answer(&query?, purpose).await })
        });
        let a = if want_a {
            let query = wire::build_query(upstream::rand_id(), host, wire::TYPE_A)?;
            Some(ips_of(self.answer(&query, purpose).await))
        } else {
            None
        };
        let v6 = match aaaa {
            None => Ok(Vec::new()),
            Some(task) => {
                let has_v4 = a
                    .as_ref()
                    .is_some_and(|r| r.as_ref().is_ok_and(|v| !v.is_empty()));
                let joined = if has_v4 {
                    match tokio::time::timeout(self.ipv6_timeout, task).await {
                        Ok(j) => j,
                        Err(_) => return Ok(a.and_then(Result::ok).unwrap_or_default()),
                    }
                } else {
                    task.await
                };
                ips_of(joined.map_err(|_| Error::Cancelled)?)
            }
        };
        let v4 = a.unwrap_or(Ok(Vec::new()));
        if let (Err(Error::Rejected), _) | (_, Err(Error::Rejected)) = (&v4, &v6) {
            return Err(Error::Rejected);
        }
        let (v4, v6) = (v4.unwrap_or_default(), v6.unwrap_or_default());
        let mut out = match self.strategy {
            Strategy::PreferV6 | Strategy::V6Only => [v6, v4].concat(),
            _ => [v4, v6].concat(),
        };
        out.retain(|ip| match ip {
            IpAddr::V4(_) => want_a,
            IpAddr::V6(_) => want_aaaa,
        });
        if out.is_empty() {
            return Err(Error::Io(std::io::Error::other("DNS 查询没有可用地址")));
        }
        Ok(out)
    }
}

async fn group(servers: &[Arc<Upstream>], query: &[u8]) -> Result<GroupReply> {
    upstream::exchange_first(servers.iter().map(Arc::as_ref), query).await
}

/// DNS 管线的唯一入口；克隆共享同一份缓存、Fake-IP 池与连接。
#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<Inner>,
}

impl DnsResolver {
    pub fn new(spec: &DnsSpec) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Inner::build(spec, true)?),
        })
    }

    /// 只有系统上游的解析器，供未配置 `dns` 段的 DNS 出站使用。
    pub fn system() -> Result<Self> {
        Self::new(&DnsSpec {
            servers: vec![DnsServerInput::Url("system".into())],
            use_system_hosts: Some(true),
            ..Default::default()
        })
    }

    /// 注入规则集与 Geo 查询、上游拨号能力，并校验引用的规则集与出站存在。只生效一次。
    pub fn bind(&self, sets: Sets, dialer: Option<Arc<dyn DnsDialer>>) -> Result<()> {
        for tag in &self.inner.rule_sets {
            if !sets.has_rule_set(tag) {
                return Err(Error::Config(format!("DNS 配置引用的规则集 {tag} 不存在")));
            }
        }
        if let Some(d) = &dialer {
            for name in &self.inner.outbounds {
                if !d.knows(name) {
                    return Err(Error::Config(format!("DNS 上游引用的出站 {name} 不存在")));
                }
            }
        }
        let _ = self.inner.sets.set(sets);
        if let Some(d) = dialer {
            let _ = self.inner.dialer.set(d);
        }
        Ok(())
    }

    /// 需要出站拨号（`#代理`、`detour`、`respect-rules`）的上游所引用的出站名。
    pub fn referenced_outbounds(&self) -> &[String] {
        &self.inner.outbounds
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.inner.listen
    }

    pub fn timeout(&self) -> Duration {
        self.inner.timeout
    }

    pub fn fake_ip_pool(&self) -> Option<&Arc<FakeIpPool>> {
        self.inner.fake.as_ref().map(|f| &f.pool)
    }

    pub fn lookup_fake_ip(&self, ip: IpAddr) -> Option<String> {
        self.inner.fake.as_ref()?.pool.lookup_domain(ip)
    }

    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        self.inner
            .fake
            .as_ref()
            .is_some_and(|f| f.pool.contains(ip))
    }

    pub fn lookup_reverse_mapping(&self, ip: IpAddr) -> Option<String> {
        self.inner.reverse.as_ref()?.lookup(ip)
    }

    pub fn flush_fake_ip(&self) -> Result<()> {
        if let Some(f) = &self.inner.fake {
            f.pool.flush()?;
        }
        Ok(())
    }

    pub fn flush_cache(&self) {
        if let Some(cache) = &self.inner.cache {
            cache.clear();
        }
    }

    /// `Local` 出网与路由规则使用的真实地址，不分配 Fake-IP。
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.inner.lookup_ips(host, Purpose::Local).await
    }

    /// 代理节点服务器域名的地址，优先 `proxy-server-nameserver`。
    pub async fn resolve_proxy_host(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.inner.lookup_ips(host, Purpose::ProxyServer).await
    }

    /// 报文入口；`reject` 规则的丢弃方式返回 `Error::Rejected`，上游全部失败时回 SERVFAIL。
    pub async fn exchange_packet(&self, request: &[u8]) -> Result<Vec<u8>> {
        let q = wire::parse_question(request)?;
        match self.inner.answer(request, Purpose::Wire).await {
            Ok(a) => Ok(a.message),
            Err(Error::Rejected) => Err(Error::Rejected),
            Err(_) => Ok(wire::reply(request, &q, wire::RCODE_SERVFAIL, &[], 0)),
        }
    }

    /// 带来源的查询，供控制面与差分测试使用。
    pub async fn query(&self, request: &[u8], purpose: Purpose) -> Result<DnsAnswer> {
        self.inner.answer(request, purpose).await
    }
}

#[cfg(test)]
#[path = "pipeline_tests.rs"]
mod tests;
