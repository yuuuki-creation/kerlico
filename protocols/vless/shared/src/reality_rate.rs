use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RealityRateLimit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}

impl RealityRateLimit {
    /// Reads Xray's `{afterBytes, bytesPerSec, burstBytesPerSec}` object. Go
    /// matches JSON keys case-insensitively, ignores unknown keys and leaves a
    /// field zero for `null`.
    pub fn parse(json: &str) -> Option<Self> {
        let serde_json::Value::Object(fields) = serde_json::from_str(json).ok()? else {
            return None;
        };
        let mut limit = Self::default();
        for (name, value) in fields {
            let field = match name.to_ascii_lowercase().as_str() {
                "afterbytes" => &mut limit.after_bytes,
                "bytespersec" => &mut limit.bytes_per_sec,
                "burstbytespersec" => &mut limit.burst_bytes_per_sec,
                _ => continue,
            };
            if !value.is_null() {
                *field = value.as_u64()?;
            }
        }
        Some(limit)
    }

    pub fn is_limited(&self) -> bool {
        self.bytes_per_sec != 0
    }
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

/// Xray meters each read of `io.Copy`'s 32 KiB buffer. A larger read would
/// widen the share exempted with the read that crosses `afterBytes`.
const METERED_READ: usize = 32 * 1024;
/// Xray reads the target into a 17 KiB buffer while it waits for the handshake.
const FIRST_TARGET_READ: usize = 17 * 1024;

impl<R: Read> Read for RealityRateLimitedRead<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let limit = output.len().min(METERED_READ);
        let count = self.inner.read(&mut output[..limit])?;
        let delay = self.budget.charge(count, Instant::now());
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        Ok(count)
    }
}

/// Meters bytes before they are written, so a reader of the other end sees
/// the same pacing as Xray's metered reads of the target.
pub struct RealityRateLimitedWrite<W> {
    inner: W,
    budget: Budget,
    metered: bool,
    paid: usize,
}

impl<W> RealityRateLimitedWrite<W> {
    pub fn new(inner: W, limit: RealityRateLimit) -> Self {
        Self {
            inner,
            budget: Budget::new(limit, Instant::now()),
            metered: false,
            paid: 0,
        }
    }
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

impl<W: Write> Write for RealityRateLimitedWrite<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return self.inner.write(input);
        }
        // Xray writes its first read of the target before it wraps the target
        // in the limiter.
        if !self.metered {
            self.metered = true;
            return self.inner.write(&input[..input.len().min(FIRST_TARGET_READ)]);
        }
        if self.paid == 0 {
            let input = &input[..input.len().min(METERED_READ)];
            let delay = self.budget.charge(input.len(), Instant::now());
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            self.paid = input.len();
        }
        let count = self.inner.write(&input[..input.len().min(self.paid)])?;
        self.paid -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
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

    #[test]
    fn limits_parse_like_go_json() {
        let limit = RealityRateLimit::parse(
            r#"{"AfterBytes":1,"bytesPerSec":2,"BURSTBYTESPERSEC":null,"other":"x"}"#,
        );
        assert_eq!(
            limit,
            Some(RealityRateLimit { after_bytes: 1, bytes_per_sec: 2, burst_bytes_per_sec: 0 })
        );
        assert_eq!(RealityRateLimit::parse(r#"{"bytesPerSec":-1}"#), None);
        assert_eq!(RealityRateLimit::parse(r#"{"bytesPerSec":1e3}"#), None);
        assert_eq!(RealityRateLimit::parse("[]"), None);
    }

    #[derive(Default)]
    struct Partial(Vec<u8>);
    impl Write for Partial {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let count = input.len().min(3);
            self.0.extend_from_slice(&input[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_limit_skips_the_first_write_and_pays_once_per_retried_buffer() {
        let limit = RealityRateLimit { after_bytes: 0, bytes_per_sec: 1000, burst_bytes_per_sec: 0 };
        let mut writer = RealityRateLimitedWrite::new(Partial::default(), limit);
        assert_eq!(writer.write(b"flight").unwrap(), 3);
        let started = Instant::now();
        let mut rest: &[u8] = &[7; 1500];
        while !rest.is_empty() {
            let count = writer.write(rest).unwrap();
            rest = &rest[count..];
        }
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(450), "1500 bytes after a 1000-byte burst took {elapsed:?}");
        assert!(elapsed < Duration::from_millis(1500), "a retried buffer was charged again: {elapsed:?}");
        assert_eq!(writer.inner_mut().0.len(), 1503);
    }
}
