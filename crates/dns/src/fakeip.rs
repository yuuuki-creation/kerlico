//! Fake-IP 双栈地址池、LRU 淘汰、缓存文件持久化与真实 DNS 反向映射表。

use kerlico_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
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
        // 预留 network (.0)、gateway (.1) 与 broadcast
        let first_usable = network.saturating_add(2);
        let last_usable = broadcast.saturating_sub(1);
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

#[derive(Default, Serialize, Deserialize)]
struct PersistedFakeIpStore {
    #[serde(default)]
    v4: BTreeMap<String, Ipv4Addr>,
    #[serde(default)]
    v6: BTreeMap<String, Ipv6Addr>,
}

struct PoolState {
    v4_cursor: u32,
    v6_cursor: u64,
    domain_to_v4: HashMap<String, Ipv4Addr>,
    v4_to_domain: HashMap<Ipv4Addr, String>,
    v4_lru: VecDeque<String>,
    domain_to_v6: HashMap<String, Ipv6Addr>,
    v6_to_domain: HashMap<Ipv6Addr, String>,
    v6_lru: VecDeque<String>,
}

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
            domain_to_v4: HashMap::new(),
            v4_to_domain: HashMap::new(),
            v4_lru: VecDeque::new(),
            domain_to_v6: HashMap::new(),
            v6_to_domain: HashMap::new(),
            v6_lru: VecDeque::new(),
        };
        if let Some(path) = &persistence_path
            && let Ok(bytes) = std::fs::read(path)
            && let Ok(persisted) = serde_json::from_slice::<PersistedFakeIpStore>(&bytes)
        {
            if let Some(r4) = v4_range {
                for (dom, ip) in persisted.v4 {
                    if r4.contains(ip) && state.domain_to_v4.len() < pool_size {
                        state.domain_to_v4.insert(dom.clone(), ip);
                        state.v4_to_domain.insert(ip, dom.clone());
                        state.v4_lru.push_back(dom);
                    }
                }
            }
            if let Some(r6) = v6_range {
                for (dom, ip) in persisted.v6 {
                    if r6.contains(ip) && state.domain_to_v6.len() < pool_size {
                        state.domain_to_v6.insert(dom.clone(), ip);
                        state.v6_to_domain.insert(ip, dom.clone());
                        state.v6_lru.push_back(dom);
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
        if let Some(&existing) = state.domain_to_v4.get(&key) {
            touch_lru(&mut state.v4_lru, &key);
            return Some(existing);
        }
        let max_cap = usize::try_from(range.capacity())
            .unwrap_or(self.pool_size)
            .min(self.pool_size);
        while state.domain_to_v4.len() >= max_cap {
            if let Some(old_dom) = state.v4_lru.pop_front()
                && let Some(old_ip) = state.domain_to_v4.remove(&old_dom)
            {
                state.v4_to_domain.remove(&old_ip);
            } else {
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
            if !state.v4_to_domain.contains_key(&candidate) {
                state.domain_to_v4.insert(key.clone(), candidate);
                state.v4_to_domain.insert(candidate, key.clone());
                state.v4_lru.push_back(key);
                self.persist_locked(&state);
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
        if let Some(&existing) = state.domain_to_v6.get(&key) {
            touch_lru(&mut state.v6_lru, &key);
            return Some(existing);
        }
        while state.domain_to_v6.len() >= self.pool_size {
            if let Some(old_dom) = state.v6_lru.pop_front()
                && let Some(old_ip) = state.domain_to_v6.remove(&old_dom)
            {
                state.v6_to_domain.remove(&old_ip);
            } else {
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
            if !state.v6_to_domain.contains_key(&candidate) {
                state.domain_to_v6.insert(key.clone(), candidate);
                state.v6_to_domain.insert(candidate, key.clone());
                state.v6_lru.push_back(key);
                self.persist_locked(&state);
                return Some(candidate);
            }
        }
        None
    }

    pub fn lookup_domain(&self, ip: IpAddr) -> Option<String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let dom = state.v4_to_domain.get(&v4)?.clone();
                touch_lru(&mut state.v4_lru, &dom);
                Some(dom)
            }
            IpAddr::V6(v6) => {
                let dom = state.v6_to_domain.get(&v6)?.clone();
                touch_lru(&mut state.v6_lru, &dom);
                Some(dom)
            }
        }
    }

    pub fn flush(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.domain_to_v4.clear();
        state.v4_to_domain.clear();
        state.v4_lru.clear();
        state.domain_to_v6.clear();
        state.v6_to_domain.clear();
        state.v6_lru.clear();
        self.persist_locked(&state);
        Ok(())
    }

    fn persist_locked(&self, state: &PoolState) {
        let Some(path) = &self.persistence_path else {
            return;
        };
        let store = PersistedFakeIpStore {
            v4: state
                .domain_to_v4
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            v6: state
                .domain_to_v6
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
        };
        let _ = write_json_atomic(path, &store);
    }
}

fn write_json_atomic(path: &Path, store: &PersistedFakeIpStore) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec(store).map_err(std::io::Error::other)?;
    std::fs::write(path, data)
}

fn touch_lru(queue: &mut VecDeque<String>, key: &str) {
    if let Some(pos) = queue.iter().position(|item| item == key) {
        queue.remove(pos);
    }
    queue.push_back(key.to_owned());
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
