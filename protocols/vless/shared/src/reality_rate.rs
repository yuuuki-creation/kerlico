use std::{
    io::{self, Read},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealityRateLimit {
    #[serde(default)]
    pub after_bytes: u64,
    #[serde(default)]
    pub bytes_per_sec: u64,
    #[serde(default)]
    pub burst_bytes_per_sec: u64,
}

pub struct RealityRateLimitedRead<R> {
    inner: R,
    budget: Budget,
}

impl<R> RealityRateLimitedRead<R> {
    pub fn new(inner: R, limit: RealityRateLimit) -> Self {
        Self {
            inner,
            budget: Budget::new(limit, Instant::now()),
        }
    }
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for RealityRateLimitedRead<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(output)?;
        let delay = self.budget.charge(count, Instant::now());
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        Ok(count)
    }
}

struct Budget {
    rate: f64,
    capacity: f64,
    tokens: f64,
    after: u64,
    at: Instant,
}
impl Budget {
    fn new(limit: RealityRateLimit, at: Instant) -> Self {
        let capacity = limit.burst_bytes_per_sec.max(limit.bytes_per_sec) as f64;
        Self {
            rate: limit.bytes_per_sec as f64,
            capacity,
            tokens: capacity,
            after: limit.after_bytes,
            at,
        }
    }
    fn charge(&mut self, bytes: usize, now: Instant) -> Duration {
        if bytes == 0 || self.rate == 0.0 {
            return Duration::ZERO;
        }
        if self.after != 0 {
            // Xray exempts the entire read that crosses afterBytes.
            self.after = self.after.saturating_sub(bytes as u64);
            return Duration::ZERO;
        }
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.at).as_secs_f64() * self.rate)
            .min(self.capacity);
        self.at = now;
        if bytes as f64 <= self.tokens {
            self.tokens -= bytes as f64;
            Duration::ZERO
        } else {
            let delay = Duration::from_secs_f64((bytes as f64 - self.tokens) / self.rate);
            self.tokens = 0.0;
            self.at = now + delay;
            delay
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fallback_limit_has_initial_allowance_burst_and_refill() {
        let at = Instant::now();
        let mut budget = Budget::new(
            RealityRateLimit {
                after_bytes: 10,
                bytes_per_sec: 100,
                burst_bytes_per_sec: 200,
            },
            at,
        );
        assert_eq!(budget.charge(20, at), Duration::ZERO);
        assert_eq!(budget.charge(200, at), Duration::ZERO);
        assert_eq!(budget.charge(50, at), Duration::from_millis(500));
        assert_eq!(
            budget.charge(50, at + Duration::from_secs(1)),
            Duration::ZERO
        );
        assert_eq!(
            budget.charge(300, at + Duration::from_secs(10)),
            Duration::from_secs(1)
        );
        let mut disabled = Budget::new(RealityRateLimit::default(), at);
        assert_eq!(disabled.charge(usize::MAX, at), Duration::ZERO);
    }
}
