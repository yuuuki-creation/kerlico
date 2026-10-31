use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio::time::Instant;

/// UDP 成功解码后记录 salt/IV；满额时拒绝新包，避免通过抢占缓存重放旧包。
pub(crate) struct ReplayCache {
    entries: HashMap<Vec<u8>, Instant>,
    order: VecDeque<(Vec<u8>, Instant)>,
    capacity: usize,
    lifetime: Duration,
}
impl ReplayCache {
    pub(crate) fn new() -> Self {
        Self::with_limits(65_536, Duration::from_secs(120))
    }
    fn with_limits(capacity: usize, lifetime: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            lifetime,
        }
    }
    pub(crate) fn accept(&mut self, nonce: &[u8]) -> bool {
        // none、table 与 rc4 没有随机 nonce；不能把相同业务包视为协议重放。
        if nonce.is_empty() {
            return true;
        }
        let now = Instant::now();
        while self
            .order
            .front()
            .is_some_and(|(_, seen)| now.duration_since(*seen) >= self.lifetime)
        {
            let (nonce, _) = self.order.pop_front().expect("队首存在");
            self.entries.remove(&nonce);
        }
        if self.entries.contains_key(nonce) || self.entries.len() >= self.capacity {
            return false;
        }
        self.entries.insert(nonce.to_vec(), now);
        self.order.push_back((nonce.to_vec(), now));
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_cache_does_not_evict_live_nonces() {
        let mut cache = ReplayCache::with_limits(2, Duration::from_secs(120));
        assert!(cache.accept(&[1]));
        assert!(!cache.accept(&[1]));
        assert!(cache.accept(&[2]));
        assert!(!cache.accept(&[3]));
        assert!(!cache.accept(&[1]));
        assert!(cache.accept(&[]));
    }
    #[tokio::test]
    async fn expired_nonces_release_capacity() {
        let mut cache = ReplayCache::with_limits(1, Duration::from_millis(5));
        assert!(cache.accept(&[1]));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(cache.accept(&[2]));
    }
}
