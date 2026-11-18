//! Ciphertext replay cache.
//! A repeat from the same UDP peer is a retransmission. Any other repeat is rejected.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV6};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const CAPACITY: usize = 100_000;
const EXPIRE: Duration = Duration::from_secs(6 * 60);

const IPV4: u64 = 1 << 48;
const IPV6: u64 = 1 << 63;

#[derive(Default)]
struct Sources {
    ipv6: HashMap<SocketAddrV6, u64>,
}

impl Sources {
    fn tag_v4(peer: std::net::SocketAddrV4) -> u64 {
        IPV4 | (u64::from(u32::from(*peer.ip())) << 16) | u64::from(peer.port())
    }

    fn remember(&mut self, peer: Option<SocketAddr>) -> u64 {
        match peer {
            None => 0,
            Some(SocketAddr::V4(addr)) => Self::tag_v4(addr),
            Some(SocketAddr::V6(addr)) => {
                let next = IPV6 | self.ipv6.len() as u64;
                *self.ipv6.entry(addr).or_insert(next)
            }
        }
    }

    fn matches(&self, owner: u64, peer: Option<SocketAddr>) -> bool {
        match peer {
            None => false,
            Some(SocketAddr::V4(addr)) => owner == Self::tag_v4(addr),
            Some(SocketAddr::V6(addr)) => self.ipv6.get(&addr) == Some(&owner),
        }
    }
}

struct Generation {
    entries: HashMap<u64, u64>,
    sources: Sources,
    started: Instant,
}

impl Generation {
    fn clear(&mut self) {
        self.entries.clear();
        self.sources.ipv6.clear();
    }
}

struct Cache {
    current: Generation,
    previous: Generation,
}

impl Cache {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            current: Generation {
                entries: HashMap::new(),
                sources: Sources::default(),
                started: now,
            },
            previous: Generation {
                entries: HashMap::new(),
                sources: Sources::default(),
                started: now,
            },
        }
    }

    fn reject(&mut self, sample: &[u8], peer: Option<SocketAddr>) -> bool {
        let now = Instant::now();
        if now.duration_since(self.current.started) > EXPIRE * 2 {
            self.current.clear();
            self.previous.clear();
            self.current.started = now;
        } else if self.current.entries.len() >= CAPACITY
            || now.duration_since(self.current.started) > EXPIRE
        {
            std::mem::swap(&mut self.current, &mut self.previous);
            self.current.clear();
            self.current.started = now;
        }
        let signature = fnv(sample);
        match self.current.entries.entry(signature) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                !self.current.sources.matches(*entry.get(), peer)
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                if let Some(&owner) = self.previous.entries.get(&signature) {
                    return !self.previous.sources.matches(owner, peer);
                }
                entry.insert(self.current.sources.remember(peer));
                false
            }
        }
    }
}

fn fnv(sample: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in sample {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn cache() -> std::sync::MutexGuard<'static, Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE
        .get_or_init(|| Mutex::new(Cache::new()))
        .lock()
        .expect("replay")
}

/// `peer` is the UDP source. TCP passes `None`, so a repeated prefix is rejected.
pub fn reject(sample: &[u8], peer: Option<SocketAddr>) -> bool {
    if sample.is_empty() {
        return false;
    }
    cache().reject(sample, peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn rotation_keeps_previous_sources_for_one_generation() {
        let mut cache = Cache::new();
        assert!(!cache.reject(b"first", None));
        cache.current.started -= EXPIRE + Duration::from_secs(1);
        assert!(cache.reject(b"first", None));
        assert!(!cache.reject(b"second", None));
        cache.current.started -= EXPIRE + Duration::from_secs(1);
        assert!(cache.reject(b"second", None));
        assert!(!cache.reject(b"first", None));
    }

    #[test]
    fn ipv6_sources_keep_scope_and_port_across_rotations() {
        let mut cache = Cache::new();
        let ip = "fe80::5".parse().unwrap();
        let peer = |port, zone| Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, zone)));
        assert!(!cache.reject(b"v6", peer(3, 2)));
        cache.current.started -= EXPIRE + Duration::from_secs(1);
        assert!(!cache.reject(b"new-generation", peer(4, 9)));
        assert!(!cache.reject(b"v6", peer(3, 2)));
        assert!(cache.reject(b"v6", peer(3, 9)));
        assert!(cache.reject(b"v6", peer(4, 2)));
        assert!(cache.reject(b"v6", None));
        assert!(cache.reject(b"v6", Some("127.0.0.1:3".parse().unwrap())));
    }

    #[test]
    fn same_udp_peer_may_retransmit() {
        let mut cache = Cache::new();
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(!cache.reject(b"abc", Some(peer)));
        assert!(!cache.reject(b"abc", Some(peer)));
        let other: SocketAddr = "127.0.0.1:10".parse().unwrap();
        assert!(cache.reject(b"abc", Some(other)));
        assert!(cache.reject(b"abc", None));
    }
}
