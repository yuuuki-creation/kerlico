//! Ciphertext replay cache.
//! A repeat from the same UDP peer is a retransmission. Any other repeat is rejected.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const CAPACITY: usize = 100_000;
const EXPIRE: Duration = Duration::from_secs(6 * 60);

struct Generation {
    entries: HashMap<u64, Option<SocketAddr>>,
    started: Instant,
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
                started: now,
            },
            previous: Generation {
                entries: HashMap::new(),
                started: now,
            },
        }
    }

    fn reject(&mut self, sample: &[u8], peer: Option<SocketAddr>) -> bool {
        let now = Instant::now();
        if now.duration_since(self.current.started) > EXPIRE * 2 {
            self.current.entries.clear();
            self.previous.entries.clear();
            self.current.started = now;
        } else if self.current.entries.len() >= CAPACITY || now.duration_since(self.current.started) > EXPIRE {
            self.previous = Generation {
                entries: std::mem::take(&mut self.current.entries),
                started: self.current.started,
            };
            self.current.started = now;
        }
        let signature = fnv(sample);
        let existing = self
            .current
            .entries
            .get(&signature)
            .copied()
            .or_else(|| self.previous.entries.get(&signature).copied());
        if let Some(existing) = existing {
            return existing.is_none() || peer.is_none() || existing != peer;
        }
        self.current.entries.insert(signature, peer);
        false
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
    CACHE.get_or_init(|| Mutex::new(Cache::new())).lock().expect("replay")
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
