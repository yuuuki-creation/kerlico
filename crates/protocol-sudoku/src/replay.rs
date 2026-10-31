use kerlico_core::{Error, Result};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub(crate) struct Replay {
    entries: HashMap<[u8; 16], Instant>,
    maximum: usize,
}
impl Replay {
    pub fn new(maximum: usize) -> Self {
        Self {
            entries: HashMap::new(),
            maximum,
        }
    }
    pub fn allow(&mut self, nonce: [u8; 16], now: Instant) -> Result<()> {
        self.entries
            .retain(|_, time| now.saturating_duration_since(*time) < Duration::from_secs(121));
        if self.entries.contains_key(&nonce) {
            return Err(Error::Rejected);
        }
        if self.entries.len() >= self.maximum {
            return Err(Error::ResourceLimit);
        }
        self.entries.insert(nonce, now);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identities_do_not_split_nonce_replay_domain_and_live_entries_are_not_evicted() {
        let mut replay = Replay::new(2);
        let now = Instant::now();
        replay.allow([1; 16], now).unwrap();
        replay.allow([2; 16], now).unwrap();
        assert!(matches!(replay.allow([1; 16], now), Err(Error::Rejected)));
        assert!(matches!(
            replay.allow([3; 16], now),
            Err(Error::ResourceLimit)
        ));
        assert!(
            replay
                .allow([3; 16], now + Duration::from_secs(120))
                .is_err()
        );
        replay
            .allow([3; 16], now + Duration::from_secs(121))
            .unwrap();
    }
}
