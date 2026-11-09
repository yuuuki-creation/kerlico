use crate::{Duration, Instant};

/// Measure how much of the receive window the application consumes per RTT.
#[derive(Debug, Default)]
pub(super) struct WindowEpoch(Option<(Instant, u64)>);

impl WindowEpoch {
    pub(super) fn start(&mut self, now: Instant) {
        self.0.get_or_insert((now, 0));
    }

    pub(super) fn reset(&mut self, now: Instant, consumed: u64) {
        self.0 = Some((now, consumed));
    }

    pub(super) fn grow(
        &mut self,
        now: Instant,
        rtt: Duration,
        consumed: u64,
        window: u64,
        limit: u64,
    ) -> u64 {
        let Some((started, offset)) = self.0 else {
            return window;
        };
        let read = consumed.saturating_sub(offset);
        if read <= window / 2 || rtt.is_zero() {
            return window;
        }
        self.reset(now, consumed);
        let target = 4.0 * read as f64 / window as f64 * rtt.as_secs_f64();
        if now.saturating_duration_since(started).as_secs_f64() < target {
            window.saturating_mul(2).min(limit).max(window)
        } else {
            window
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_only_if_consumption_is_fast_and_stops_at_the_ceiling() {
        let start = Instant::now();
        let rtt = Duration::from_millis(20);
        let mut epoch = WindowEpoch::default();
        epoch.start(start);
        let t1 = start + Duration::from_millis(5);
        let first = epoch.grow(t1, rtt, 12_288, 16_384, 49_152);
        assert_eq!(first, 32_768);
        let t2 = t1 + Duration::from_millis(10);
        assert_eq!(epoch.grow(t2, rtt, 32_768, first, 49_152), 49_152);
        assert_eq!(epoch.grow(t2 + rtt, rtt, 65_536, 49_152, 49_152), 49_152);
        assert_eq!(epoch.grow(t2 + rtt * 8, rtt, 98_304, 49_152, 98_304), 49_152);
    }
}
