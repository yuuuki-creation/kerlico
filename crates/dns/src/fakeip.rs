//! Fake-IP 双栈地址池、LRU 淘汰、缓存文件持久化与真实 DNS 反向映射表。

use kerlico_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheFileSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, alias = "store-fakeip", alias = "store-fake-ip")]
    pub store_fakeip: bool,
    #[serde(default, alias = "store-selected")]
    pub store_selected: bool,
    #[serde(default, alias = "cache-id")]
    pub cache_id: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_pool_size() -> usize {
    65535
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FakeDnsPoolSpec {
    #[serde(default = "default_v4_pool", alias = "ipPool", alias = "ip-pool")]
    pub ip_pool: String,
    #[serde(default = "default_pool_size", alias = "poolSize", alias = "pool-size")]
    pub pool_size: usize,
}

impl Default for FakeDnsPoolSpec {
    fn default() -> Self {
        Self {
            ip_pool: default_v4_pool(),
            pool_size: default_pool_size(),
        }
    }
}

fn default_v4_pool() -> String {
    "198.18.0.0/15".into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FakeDnsInput {
    Bool(bool),
    Single(FakeDnsPoolSpec),
    Multi(Vec<FakeDnsPoolSpec>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V4Range {
    network: u32,
    broadcast: u32,
    first_usable: u32,
    last_usable: u32,
}

impl V4Range {
    pub fn parse(cidr: &str) -> Result<Self> {
        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| Error::Config("Fake-IP IPv4 网段缺少前缀长度".into()))?;
        let ip: Ipv4Addr = addr_str
            .parse()
            .map_err(|_| Error::Config("Fake-IP IPv4 地址不合法".into()))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| Error::Config("Fake-IP IPv4 前缀不合法".into()))?;
        if !(8..=30).contains(&prefix) {
            return Err(Error::Config("Fake-IP IPv4 前缀必须在 8..=30 之间".into()));
        }
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let network = u32::from(ip) & mask;
        let broadcast = network | !mask;
        // 与 Mihomo 一致从 .4 起分配：.0–.3 是默认 TUN 地址 198.18.0.1/30 所在网段；
        // 网段太小时退回只预留 network (.0) 与 gateway (.1)。
        let last_usable = broadcast.saturating_sub(1);
        let first_usable = if network.saturating_add(4) <= last_usable {
            network + 4
        } else {
            network.saturating_add(2)
        };
        if first_usable > last_usable {
            return Err(Error::Config("Fake-IP IPv4 地址池容量不足".into()));
        }
        Ok(Self {
            network,
            broadcast,
            first_usable,
            last_usable,
        })
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let bits = u32::from(ip);
        bits >= self.network && bits <= self.broadcast
    }

    fn capacity(self) -> u64 {
        u64::from(self.last_usable - self.first_usable) + 1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V6Range {
    network: u128,
    mask: u128,
    first_offset: u64,
    max_offset: u64,
}

impl V6Range {
    pub fn parse(cidr: &str) -> Result<Self> {
        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| Error::Config("Fake-IP IPv6 网段缺少前缀长度".into()))?;
        let ip: Ipv6Addr = addr_str
            .parse()
            .map_err(|_| Error::Config("Fake-IP IPv6 地址不合法".into()))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| Error::Config("Fake-IP IPv6 前缀不合法".into()))?;
        if !(8..=120).contains(&prefix) {
            return Err(Error::Config("Fake-IP IPv6 前缀必须在 8..=120 之间".into()));
        }
        let mask = !0u128 << (128 - prefix);
        let network = u128::from(ip) & mask;
        let host_bits = (128 - prefix).min(62);
        let max_offset = (1u64 << host_bits).saturating_sub(2);
        Ok(Self {
            network,
            mask,
            first_offset: 2,
            max_offset,
        })
    }

    pub fn contains(self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) & self.mask) == self.network
    }

    fn address_at(self, offset: u64) -> Ipv6Addr {
        Ipv6Addr::from(self.network | u128::from(offset))
    }
}

#[derive(Default, Deserialize)]
struct PersistedFakeIpStore {
    #[serde(default)]
    v4: BTreeMap<String, Ipv4Addr>,
    #[serde(default)]
    v6: BTreeMap<String, Ipv6Addr>,
}

struct LruMapRef<'a, A>(&'a HashMap<String, (A, u64)>);

impl<A: Serialize> Serialize for LruMapRef<'_, A> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, (ip, _)) in self.0 {
            map.serialize_entry(k, ip)?;
        }
        map.end()
    }
}

#[derive(Serialize)]
struct PersistedFakeIpStoreRef<'a> {
    v4: LruMapRef<'a, Ipv4Addr>,
    v6: LruMapRef<'a, Ipv6Addr>,
}

struct LruTable<A> {
    domain_to_ip: HashMap<String, (A, u64)>,
    ip_to_domain: HashMap<A, String>,
    order: BTreeMap<u64, String>,
    seq: u64,
}

impl<A: Copy + Eq + std::hash::Hash> LruTable<A> {
    fn new() -> Self {
        Self {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
            order: BTreeMap::new(),
            seq: 0,
        }
    }

    fn len(&self) -> usize {
        self.domain_to_ip.len()
    }

    fn contains_ip(&self, ip: &A) -> bool {
        self.ip_to_domain.contains_key(ip)
    }

    fn insert(&mut self, domain: String, ip: A) {
        self.seq += 1;
        let s = self.seq;
        if let Some((old_ip, old_seq)) = self.domain_to_ip.insert(domain.clone(), (ip, s)) {
            self.order.remove(&old_seq);
            if old_ip != ip {
                self.ip_to_domain.remove(&old_ip);
            }
        }
        self.ip_to_domain.insert(ip, domain.clone());
        self.order.insert(s, domain);
    }

    fn get_and_touch(&mut self, domain: &str) -> Option<A> {
        let (ip, old_seq) = *self.domain_to_ip.get(domain)?;
        self.seq += 1;
        let s = self.seq;
        if let Some(dom) = self.order.remove(&old_seq) {
            if let Some(entry) = self.domain_to_ip.get_mut(domain) {
                entry.1 = s;
            }
            self.order.insert(s, dom);
        }
        Some(ip)
    }

    fn lookup_ip_and_touch(&mut self, ip: &A) -> Option<String> {
        let dom = self.ip_to_domain.get(ip)?.clone();
        let _ = self.get_and_touch(&dom);
        Some(dom)
    }

    fn pop_oldest(&mut self) -> Option<(String, A)> {
        let (_, dom) = self.order.pop_first()?;
        let (ip, _) = self.domain_to_ip.remove(&dom)?;
        self.ip_to_domain.remove(&ip);
        Some((dom, ip))
    }

    fn clear(&mut self) {
        self.domain_to_ip.clear();
        self.ip_to_domain.clear();
        self.order.clear();
    }
}

struct PoolState {
    v4_cursor: u32,
    v6_cursor: u64,
    v4: LruTable<Ipv4Addr>,
    v6: LruTable<Ipv6Addr>,
    dirty_count: usize,
    last_persisted: Option<Instant>,
}

const PERSIST_MIN_INTERVAL: Duration = Duration::from_secs(5);
const PERSIST_EAGER_LIMIT: usize = 32;

pub struct FakeIpPool {
    v4_range: Option<V4Range>,
    v6_range: Option<V6Range>,
    pool_size: usize,
    ttl: u32,
    filter: Vec<String>,
    persistence_path: Option<PathBuf>,
    state: Mutex<PoolState>,
}

impl FakeIpPool {
    pub fn new(
        v4_cidr: Option<&str>,
        v6_cidr: Option<&str>,
        pool_size: usize,
        ttl: u32,
        filter: Vec<String>,
        persistence_path: Option<PathBuf>,
    ) -> Result<Self> {
        let v4_range = v4_cidr.map(V4Range::parse).transpose()?;
        let v6_range = v6_cidr.map(V6Range::parse).transpose()?;
        if v4_range.is_none() && v6_range.is_none() {
            return Err(Error::Config(
                "Fake-IP 池至少需要配置 IPv4 或 IPv6 网段".into(),
            ));
        }
        let pool_size = pool_size.clamp(1, 1_000_000);
        let ttl = ttl.max(1);
        let mut state = PoolState {
            v4_cursor: v4_range.map_or(0, |r| r.first_usable),
            v6_cursor: v6_range.map_or(0, |r| r.first_offset),
            v4: LruTable::new(),
            v6: LruTable::new(),
            dirty_count: 0,
            last_persisted: None,
        };
        if let Some(path) = &persistence_path
            && let Some(persisted) =
                crate::cache_file::load::<PersistedFakeIpStore>(path, crate::cache_file::FAKEIP)
        {
            if let Some(r4) = v4_range {
                for (dom, ip) in persisted.v4 {
                    if r4.contains(ip) && state.v4.len() < pool_size {
                        state.v4.insert(dom, ip);
                    }
                }
            }
            if let Some(r6) = v6_range {
                for (dom, ip) in persisted.v6 {
                    if r6.contains(ip) && state.v6.len() < pool_size {
                        state.v6.insert(dom, ip);
                    }
                }
            }
        }
        Ok(Self {
            v4_range,
            v6_range,
            pool_size,
            ttl,
            filter,
            persistence_path,
            state: Mutex::new(state),
        })
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn should_skip(&self, domain: &str) -> bool {
        let d = domain
            .trim()
            .strip_suffix('.')
            .unwrap_or(domain)
            .to_ascii_lowercase();
        self.filter
            .iter()
            .any(|pattern| wildcard_match(pattern, &d))
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => self.v4_range.is_some_and(|r| r.contains(v4)),
            IpAddr::V6(v6) => self.v6_range.is_some_and(|r| r.contains(v6)),
        }
    }

    pub fn allocate_v4(&self, domain: &str) -> Option<Ipv4Addr> {
        let range = self.v4_range?;
        let key = domain
            .trim()
            .strip_suffix('.')
            .unwrap_or(domain)
            .to_ascii_lowercase();
        if key.is_empty() || self.should_skip(&key) {
            return None;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = state.v4.get_and_touch(&key) {
            return Some(existing);
        }
        let max_cap = usize::try_from(range.capacity())
            .unwrap_or(self.pool_size)
            .min(self.pool_size);
        while state.v4.len() >= max_cap {
            if state.v4.pop_oldest().is_none() {
                break;
            }
        }
        for _ in 0..=range.capacity() {
            let candidate = Ipv4Addr::from(state.v4_cursor);
            state.v4_cursor = if state.v4_cursor >= range.last_usable {
                range.first_usable
            } else {
                state.v4_cursor + 1
            };
            if !state.v4.contains_ip(&candidate) {
                state.v4.insert(key, candidate);
                self.maybe_persist_locked(&mut state);
                return Some(candidate);
            }
        }
        None
    }

    pub fn allocate_v6(&self, domain: &str) -> Option<Ipv6Addr> {
        let range = self.v6_range?;
        let key = domain
            .trim()
            .strip_suffix('.')
            .unwrap_or(domain)
            .to_ascii_lowercase();
        if key.is_empty() || self.should_skip(&key) {
            return None;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = state.v6.get_and_touch(&key) {
            return Some(existing);
        }
        while state.v6.len() >= self.pool_size {
            if state.v6.pop_oldest().is_none() {
                break;
            }
        }
        for _ in 0..=self.pool_size {
            let candidate = range.address_at(state.v6_cursor);
            state.v6_cursor = if state.v6_cursor >= range.max_offset {
                range.first_offset
            } else {
                state.v6_cursor + 1
            };
            if !state.v6.contains_ip(&candidate) {
                state.v6.insert(key, candidate);
                self.maybe_persist_locked(&mut state);
                return Some(candidate);
            }
        }
        None
    }

    pub fn lookup_domain(&self, ip: IpAddr) -> Option<String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match ip.to_canonical() {
            IpAddr::V4(v4) => state.v4.lookup_ip_and_touch(&v4),
            IpAddr::V6(v6) => state.v6.lookup_ip_and_touch(&v6),
        }
    }

    pub fn flush(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.v4.clear();
        state.v6.clear();
        self.persist_locked(&mut state);
        Ok(())
    }

    fn maybe_persist_locked(&self, state: &mut PoolState) {
        if self.persistence_path.is_none() {
            return;
        }
        state.dirty_count += 1;
        let total = state.v4.len() + state.v6.len();
        let now = Instant::now();
        if total <= PERSIST_EAGER_LIMIT
            || state.dirty_count >= 512
            || state
                .last_persisted
                .is_none_or(|last| now.duration_since(last) >= PERSIST_MIN_INTERVAL)
        {
            self.persist_locked(state);
        }
    }

    fn persist_locked(&self, state: &mut PoolState) {
        let Some(path) = &self.persistence_path else {
            return;
        };
        let store = PersistedFakeIpStoreRef {
            v4: LruMapRef(&state.v4.domain_to_ip),
            v6: LruMapRef(&state.v6.domain_to_ip),
        };
        let _ = crate::cache_file::store(path, crate::cache_file::FAKEIP, &store);
        state.dirty_count = 0;
        state.last_persisted = Some(Instant::now());
    }
}

impl Drop for FakeIpPool {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock()
            && state.dirty_count > 0
        {
            self.persist_locked(&mut state);
        }
    }
}

pub fn wildcard_match(pattern: &str, domain: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let d = domain
        .trim()
        .strip_suffix('.')
        .unwrap_or(domain)
        .to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    if p == "*" || p == "+" || p == "." {
        return true;
    }
    if let Some(rest) = p.strip_prefix("+.") {
        return d == rest || d.strip_suffix(rest).is_some_and(|pre| pre.ends_with('.'));
    }
    if let Some(rest) = p.strip_prefix("*.") {
        return d.strip_suffix(rest).is_some_and(|pre| pre.ends_with('.'));
    }
    if let Some(rest) = p.strip_prefix('.') {
        return d == rest || d.strip_suffix(rest).is_some_and(|pre| pre.ends_with('.'));
    }
    p == d
}

pub struct ReverseMappingCache {
    entries: Mutex<HashMap<IpAddr, (String, Instant)>>,
}

impl Default for ReverseMappingCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReverseMappingCache {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn record(&self, domain: &str, ips: &[IpAddr], ttl: Duration) {
        let clean = domain
            .trim()
            .strip_suffix('.')
            .unwrap_or(domain)
            .to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }
        let expires = Instant::now() + ttl.max(Duration::from_secs(1));
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= 16384 {
            let now = Instant::now();
            map.retain(|_, (_, exp)| *exp > now);
        }
        for &ip in ips {
            map.insert(ip.to_canonical(), (clean.clone(), expires));
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let now = Instant::now();
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = ip.to_canonical();
        if let Some((domain, expires)) = map.get(&key) {
            if *expires > now {
                return Some(domain.clone());
            }
            map.remove(&key);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_fake_ip_skips_default_tun_subnet_like_mihomo() {
        let pool = FakeIpPool::new(Some("198.18.0.1/16"), None, 16, 1, Vec::new(), None).unwrap();
        assert_eq!(
            pool.allocate_v4("a.example"),
            Some(Ipv4Addr::new(198, 18, 0, 4))
        );
        let tiny = FakeIpPool::new(Some("198.18.0.0/30"), None, 16, 1, Vec::new(), None).unwrap();
        assert_eq!(
            tiny.allocate_v4("a.example"),
            Some(Ipv4Addr::new(198, 18, 0, 2))
        );
    }

    #[test]
    fn fakeip_pool_allocates_dual_stack_evicts_lru_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("fakeip-cache.json");
        let pool = FakeIpPool::new(
            Some("198.18.0.0/29"),
            Some("fc00::/64"),
            2,
            5,
            vec!["+.lan".into(), "*.local".into()],
            Some(cache_path.clone()),
        )
        .unwrap();

        assert!(pool.allocate_v4("router.lan").is_none());
        assert!(pool.allocate_v4("printer.local").is_none());

        let ip1 = pool.allocate_v4("a.example.com").unwrap();
        assert_eq!(pool.allocate_v4("A.Example.COM."), Some(ip1));
        assert_eq!(
            pool.lookup_domain(IpAddr::V4(ip1)).as_deref(),
            Some("a.example.com")
        );

        let ip2 = pool.allocate_v4("b.example.com").unwrap();
        assert_ne!(ip1, ip2);

        // Pool size is 2; touching ip1 makes ip2 the oldest entry
        let _ = pool.lookup_domain(IpAddr::V4(ip1));
        let ip3 = pool.allocate_v4("c.example.com").unwrap();
        assert!(pool.lookup_domain(IpAddr::V4(ip2)).is_none());
        assert_eq!(
            pool.lookup_domain(IpAddr::V4(ip1)).as_deref(),
            Some("a.example.com")
        );
        assert_eq!(
            pool.lookup_domain(IpAddr::V4(ip3)).as_deref(),
            Some("c.example.com")
        );

        let ip6 = pool.allocate_v6("v6.example.com").unwrap();
        assert!(pool.contains(IpAddr::V6(ip6)));
        assert_eq!(
            pool.lookup_domain(IpAddr::V6(ip6)).as_deref(),
            Some("v6.example.com")
        );

        // Reload from persisted cache file
        drop(pool);
        let reloaded = FakeIpPool::new(
            Some("198.18.0.0/29"),
            Some("fc00::/64"),
            2,
            5,
            Vec::new(),
            Some(cache_path),
        )
        .unwrap();
        assert_eq!(
            reloaded.lookup_domain(IpAddr::V4(ip1)).as_deref(),
            Some("a.example.com")
        );
        assert_eq!(
            reloaded.lookup_domain(IpAddr::V6(ip6)).as_deref(),
            Some("v6.example.com")
        );
    }
}
