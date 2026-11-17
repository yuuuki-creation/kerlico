use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

pub(super) const ACK_DELAY: Duration = Duration::from_millis(1);

/// One wakeup deadline for a link. After waking, its sessions offer their next
/// deadlines again. A new earlier deadline cannot be lost while the timer waits.
#[derive(Default)]
pub(super) struct Timer {
    state: Mutex<(Option<Instant>, bool)>,
    ready: Condvar,
    task: tokio::sync::Notify,
}

impl Timer {
    pub fn at(&self, deadline: Instant) {
        let mut state = self.state.lock().expect("UDP timer");
        if !state.1 && state.0.is_none_or(|previous| deadline < previous) {
            state.0 = Some(deadline);
            self.ready.notify_one();
            self.task.notify_one();
        }
    }

    pub fn close(&self) {
        self.state.lock().expect("UDP timer").1 = true;
        self.ready.notify_one();
        self.task.notify_one();
    }

    pub async fn wait_async(&self, maintenance: Instant) -> bool {
        loop {
            let changed = self.task.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let deadline = {
                let mut state = self.state.lock().expect("UDP timer");
                if state.1 {
                    return false;
                }
                let deadline = state.0.unwrap_or(maintenance).min(maintenance);
                if deadline <= Instant::now() {
                    if state.0.is_some_and(|at| at <= Instant::now()) {
                        state.0 = None;
                    }
                    return true;
                }
                deadline
            };
            tokio::select! {
                _ = &mut changed => {},
                _ = tokio::time::sleep_until(deadline.into()) => {},
            }
        }
    }

    pub fn wait(&self, maintenance: Instant) -> bool {
        let mut state = self.state.lock().expect("UDP timer");
        loop {
            if state.1 {
                return false;
            }
            let deadline = state.0.unwrap_or(maintenance).min(maintenance);
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                if state.0.is_some_and(|at| at <= Instant::now()) {
                    state.0 = None;
                }
                return true;
            }
            state = self.ready.wait_timeout(state, left).expect("UDP timer").0;
        }
    }
}

/// RTT samples obey Karn's rule: callers exclude packets sent more than once.
/// Loss decreases the congestion window once per recovery interval, rather than
/// once for every packet in the same lost burst.
pub(super) struct Recovery {
    mean: Option<Duration>,
    deviation: Duration,
    threshold: u32,
    credit: u32,
    until: Option<u32>,
}

impl Recovery {
    pub fn new(maximum: u32) -> Self {
        Self {
            mean: None,
            deviation: Duration::ZERO,
            threshold: maximum,
            credit: 0,
            until: None,
        }
    }

    pub fn sample(&mut self, elapsed: Duration) {
        if elapsed.is_zero() {
            return;
        }
        if let Some(mean) = self.mean {
            self.deviation = self
                .deviation
                .saturating_mul(3)
                .saturating_add(mean.abs_diff(elapsed))
                / 4;
            self.mean = Some(mean.saturating_mul(7).saturating_add(elapsed) / 8);
        } else {
            self.mean = Some(elapsed);
            self.deviation = elapsed / 2;
        }
    }

    pub fn timeout(&self, transmissions: u8) -> Duration {
        let initial = self.mean.map_or(Duration::from_secs(2), |mean| {
            mean.saturating_add(
                self.deviation
                    .saturating_mul(4)
                    .max(Duration::from_millis(10)),
            )
            .saturating_add(ACK_DELAY)
            .mul_f64(1.5)
        });
        initial
            .min(Duration::from_secs(10))
            .mul_f64(1.5_f64.powi(i32::from(transmissions.min(20))))
            .min(Duration::from_secs(10))
    }

    pub fn acknowledged(&mut self, next: u32, count: u32, mut window: u32, maximum: u32) -> u32 {
        if let Some(end) = self.until {
            if next.wrapping_sub(end) < (1 << 31) {
                self.until = None;
            } else {
                return window;
            }
        }
        let fast = count.min(self.threshold.saturating_sub(window));
        window = window.saturating_add(fast).min(maximum);
        self.credit = self.credit.saturating_add(count - fast);
        while window < maximum && self.credit >= window.max(1) {
            self.credit -= window.max(1);
            window += 1;
        }
        window
    }

    pub fn lost(&mut self, next_send: u32, window: u32, minimum: u32, timeout: bool) -> u32 {
        if self.until.is_some() {
            return window;
        }
        self.until = Some(next_send);
        self.threshold = (window / 2).max(minimum);
        self.credit = 0;
        if timeout {
            minimum
        } else {
            self.threshold
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn rtt_adapts_and_retransmission_backoff_is_bounded() {
        let mut r = Recovery::new(4096);
        assert_eq!(r.timeout(1), Duration::from_secs(3));
        for _ in 0..40 {
            r.sample(Duration::from_millis(2));
        }
        assert!(r.timeout(1) >= Duration::from_millis(20));
        assert!(r.timeout(1) < Duration::from_millis(35));
        assert!(r.timeout(2) > r.timeout(1));
        assert_eq!(r.timeout(20), Duration::from_secs(10));
    }

    #[test]
    fn a_lost_burst_reduces_once_and_ack_recovery_crosses_wrap() {
        let mut r = Recovery::new(4096);
        assert_eq!(r.lost(2, 128, 16, false), 64);
        for _ in 0..20 {
            assert_eq!(r.lost(3, 64, 16, true), 64);
        }
        assert_eq!(r.acknowledged(u32::MAX, 64, 64, 4096), 64);
        assert_eq!(r.acknowledged(1, 64, 64, 4096), 64);
        assert_eq!(r.acknowledged(2, 64, 64, 4096), 65);
        assert_eq!(r.lost(10, 65, 16, true), 16);
        assert_eq!(r.acknowledged(10, 1, 16, 4096), 17);
    }

    #[test]
    fn timer_accepts_early_notifications_and_close_interrupts_wait() {
        let timer = Arc::new(Timer::default());
        timer.at(Instant::now());
        assert!(timer.wait(Instant::now() + Duration::from_secs(1)));
        let wait = timer.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            tx.send(wait.wait(Instant::now() + Duration::from_secs(30)))
                .unwrap();
        });
        timer.close();
        assert!(!rx.recv_timeout(Duration::from_secs(1)).unwrap());
        join.join().unwrap();
    }

    #[test]
    fn earlier_deadline_interrupts_a_long_wait() {
        let timer = Arc::new(Timer::default());
        timer.at(Instant::now() + Duration::from_secs(30));
        let wait = timer.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            tx.send(wait.wait(Instant::now() + Duration::from_secs(30)))
                .unwrap();
        });
        timer.at(Instant::now());
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        timer.close();
        join.join().unwrap();
    }
}
