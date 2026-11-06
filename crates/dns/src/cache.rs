//! 上游应答缓存：按 (名称, 类型, 解析器) 存放，遵守最小 TTL，支持 LRU 与 ARC 淘汰；
//! 乐观模式下过期条目仍返回（TTL 置 1）并由调用方后台刷新，与 Mihomo 一致。

use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Algorithm {
    Lru,
    Arc,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Key {
    pub name: String,
    pub qtype: u16,
    pub scope: Scope,
}

/// 互相独立的解析器各用一份缓存视图，对应 Mihomo 的主解析器、代理节点解析器与直连解析器。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Scope {
    Main,
    ProxyServer,
    Direct,
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub message: Vec<u8>,
    pub server: String,
    pub expires: Instant,
}

pub(crate) struct Hit {
    pub message: Vec<u8>,
    pub server: String,
    pub stale: bool,
}

/// 按访问次序排列的键表：`tick` 越大越新。
struct Order<K> {
    ticks: HashMap<K, u64>,
    by_tick: BTreeMap<u64, K>,
}

impl<K: Clone + Eq + Hash> Order<K> {
    fn new() -> Self {
        Self {
            ticks: HashMap::new(),
            by_tick: BTreeMap::new(),
        }
    }
    fn len(&self) -> usize {
        self.ticks.len()
    }
    fn contains(&self, key: &K) -> bool {
        self.ticks.contains_key(key)
    }
    fn touch(&mut self, key: K, tick: u64) {
        if let Some(old) = self.ticks.insert(key.clone(), tick) {
            self.by_tick.remove(&old);
        }
        self.by_tick.insert(tick, key);
    }
    fn remove(&mut self, key: &K) -> bool {
        match self.ticks.remove(key) {
            Some(t) => {
                self.by_tick.remove(&t);
                true
            }
            None => false,
        }
    }
    fn pop_oldest(&mut self) -> Option<K> {
        let (_, key) = self.by_tick.pop_first()?;
        self.ticks.remove(&key);
        Some(key)
    }
}

/// ARC（Megiddo & Modha）：T1 最近一次、T2 多次访问；B1/B2 只记被淘汰的键用于调整目标 `p`。
struct ArcState<K> {
    t1: Order<K>,
    t2: Order<K>,
    b1: Order<K>,
    b2: Order<K>,
    p: usize,
}

struct Store<K, V> {
    capacity: usize,
    algorithm: Algorithm,
    values: HashMap<K, V>,
    lru: Order<K>,
    arc: ArcState<K>,
    tick: u64,
}

impl<K: Clone + Eq + Hash, V> Store<K, V> {
    fn new(capacity: usize, algorithm: Algorithm) -> Self {
        Self {
            capacity: capacity.max(1),
            algorithm,
            values: HashMap::new(),
            lru: Order::new(),
            arc: ArcState {
                t1: Order::new(),
                t2: Order::new(),
                b1: Order::new(),
                b2: Order::new(),
                p: 0,
            },
            tick: 0,
        }
    }

    fn next(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    fn get(&mut self, key: &K) -> Option<&V> {
        if !self.values.contains_key(key) {
            return None;
        }
        let tick = self.next();
        match self.algorithm {
            Algorithm::Lru => self.lru.touch(key.clone(), tick),
            Algorithm::Arc => {
                self.arc.t1.remove(key);
                self.arc.t2.touch(key.clone(), tick);
            }
        }
        self.values.get(key)
    }

    fn put(&mut self, key: K, value: V) {
        let tick = self.next();
        match self.algorithm {
            Algorithm::Lru => {
                self.lru.touch(key.clone(), tick);
                self.values.insert(key, value);
                while self.values.len() > self.capacity {
                    match self.lru.pop_oldest() {
                        Some(old) => {
                            self.values.remove(&old);
                        }
                        None => break,
                    }
                }
            }
            Algorithm::Arc => self.arc_put(key, value, tick),
        }
    }

    fn arc_replace(&mut self, in_b2: bool) {
        let a = &mut self.arc;
        let t1 = a.t1.len();
        if t1 > 0 && (t1 > a.p || (in_b2 && t1 == a.p)) {
            if let Some(old) = a.t1.pop_oldest() {
                self.values.remove(&old);
                a.b1.touch(old, self.tick);
            }
        } else if let Some(old) = a.t2.pop_oldest() {
            self.values.remove(&old);
            a.b2.touch(old, self.tick);
        }
    }

    fn arc_put(&mut self, key: K, value: V, tick: u64) {
        let c = self.capacity;
        if self.arc.t1.contains(&key) || self.arc.t2.contains(&key) {
            self.arc.t1.remove(&key);
            self.arc.t2.touch(key.clone(), tick);
            self.values.insert(key, value);
            return;
        }
        if self.arc.b1.contains(&key) {
            let delta = (self.arc.b2.len() / self.arc.b1.len()).max(1);
            self.arc.p = (self.arc.p + delta).min(c);
            self.arc_replace(false);
            self.arc.b1.remove(&key);
            self.arc.t2.touch(key.clone(), tick);
            self.values.insert(key, value);
            return;
        }
        if self.arc.b2.contains(&key) {
            let delta = (self.arc.b1.len() / self.arc.b2.len()).max(1);
            self.arc.p = self.arc.p.saturating_sub(delta);
            self.arc_replace(true);
            self.arc.b2.remove(&key);
            self.arc.t2.touch(key.clone(), tick);
            self.values.insert(key, value);
            return;
        }
        let l1 = self.arc.t1.len() + self.arc.b1.len();
        let total = l1 + self.arc.t2.len() + self.arc.b2.len();
        if l1 >= c {
            if self.arc.t1.len() < c {
                self.arc.b1.pop_oldest();
                self.arc_replace(false);
            } else if let Some(old) = self.arc.t1.pop_oldest() {
                self.values.remove(&old);
            }
        } else if total >= c {
            if total >= 2 * c {
                self.arc.b2.pop_oldest();
            }
            self.arc_replace(false);
        }
        self.arc.t1.touch(key.clone(), tick);
        self.values.insert(key, value);
    }

    #[cfg(test)]
    fn contains(&self, key: &K) -> bool {
        self.values.contains_key(key)
    }
}

pub(crate) struct DnsCache {
    store: Mutex<Store<Key, Entry>>,
    optimistic: bool,
}

impl DnsCache {
    pub(crate) fn new(capacity: usize, algorithm: Algorithm, optimistic: bool) -> Self {
        Self {
            store: Mutex::new(Store::new(capacity, algorithm)),
            optimistic,
        }
    }

    /// 命中时返回 TTL 已改为剩余秒数的报文；过期条目只在乐观模式下返回且 `stale` 为真。
    pub(crate) fn get(&self, key: &Key, now: Instant) -> Option<Hit> {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let entry = store.get(key)?.clone();
        drop(store);
        let stale = entry.expires <= now;
        if stale && !self.optimistic {
            return None;
        }
        let mut message = entry.message;
        let remaining = if stale {
            1
        } else {
            u32::try_from(entry.expires.duration_since(now).as_secs().max(1)).unwrap_or(u32::MAX)
        };
        crate::wire::set_ttls(&mut message, remaining);
        Some(Hit {
            message,
            server: entry.server,
            stale,
        })
    }

    /// 按报文最小 TTL 存放；SERVFAIL 存 1 秒；TTL 为 0 或没有记录的应答不缓存。
    pub(crate) fn put(&self, key: Key, message: &[u8], server: &str, now: Instant) {
        let ttl = if crate::wire::rcode(message) == crate::wire::RCODE_SERVFAIL {
            Some(1)
        } else {
            crate::wire::min_ttl(message)
        };
        let Some(ttl) = ttl.filter(|t| *t > 0) else {
            return;
        };
        let entry = Entry {
            message: message.to_vec(),
            server: server.to_owned(),
            expires: now + Duration::from_secs(u64::from(ttl)),
        };
        self.store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key, entry);
    }

    pub(crate) fn clear(&self) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let (capacity, algorithm) = (store.capacity, store.algorithm);
        *store = Store::new(capacity, algorithm);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_evicts_least_recent() {
        let mut s = Store::new(2, Algorithm::Lru);
        s.put(1, "a");
        s.put(2, "b");
        assert!(s.get(&1).is_some());
        s.put(3, "c");
        assert!(s.contains(&1) && s.contains(&3) && !s.contains(&2));
    }

    #[test]
    fn arc_keeps_frequent_entries_through_a_scan() {
        let mut s = Store::new(4, Algorithm::Arc);
        for k in [1, 2] {
            s.put(k, k);
            assert!(s.get(&k).is_some());
        }
        for k in 100..120 {
            s.put(k, k);
        }
        assert!(
            s.contains(&1) && s.contains(&2),
            "频繁访问的键在一次扫描后仍保留"
        );
        assert!(s.values.len() <= 4);

        let mut lru = Store::new(4, Algorithm::Lru);
        for k in [1, 2] {
            lru.put(k, k);
            assert!(lru.get(&k).is_some());
        }
        for k in 100..120 {
            lru.put(k, k);
        }
        assert!(!lru.contains(&1), "同样的序列下 LRU 淘汰频繁键");
    }
}
