//! 由流量驱动登录的出站共用的退避状态。

use crate::{Error, Result};
use std::time::{Duration, Instant};

/// 服务端常按错误凭据累计封禁分；凭据属于整个命名出站，所以限速不能按来源分开。
const REJECTED_DELAY: Duration = Duration::from_secs(60);
const MIN_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(60);

/// 一个命名出站的登录退避。调用方应持有同一把锁完成“检查、登录、记录”，让并发来源串行等待结论。
/// 调用方取消或超时而未完成的登录不产生结论，不计入退避。
#[derive(Default)]
pub struct LoginBackoff {
    retry_at: Option<Instant>,
    rejected: bool,
    failures: u32,
}
impl LoginBackoff {
    pub fn check(&self, now: Instant) -> Result<()> {
        match self.retry_at {
            Some(at) if now < at && self.rejected => Err(Error::Rejected),
            Some(at) if now < at => Err(Error::Protocol("出站登录失败，退避期内不重试")),
            _ => Ok(()),
        }
    }
    pub fn record<T>(&mut self, now: Instant, outcome: &Result<T>) {
        let delay = match outcome {
            Ok(_) => {
                *self = Self::default();
                return;
            }
            Err(Error::Cancelled) => return,
            Err(Error::Rejected) => REJECTED_DELAY,
            Err(_) => MIN_DELAY
                .saturating_mul(1 << self.failures.min(6))
                .min(MAX_DELAY),
        };
        self.rejected = matches!(outcome, Err(Error::Rejected));
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(now + delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure() -> Result<()> {
        Err(Error::Protocol("测试"))
    }

    #[test]
    fn rejection_blocks_for_sixty_seconds_with_the_rejection_error() {
        let start = Instant::now();
        let mut backoff = LoginBackoff::default();
        assert!(backoff.check(start).is_ok());
        backoff.record::<()>(start, &Err(Error::Rejected));
        let last = start + Duration::from_secs(59);
        assert!(matches!(backoff.check(last), Err(Error::Rejected)));
        assert!(backoff.check(start + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn other_failures_double_up_to_the_limit_and_success_clears_them() {
        let start = Instant::now();
        let mut backoff = LoginBackoff::default();
        for seconds in [1, 2, 4, 8, 16, 32, 60, 60] {
            backoff.record(start, &failure());
            let last = start + Duration::from_secs(seconds - 1);
            assert!(matches!(backoff.check(last), Err(Error::Protocol(_))));
            assert!(backoff.check(start + Duration::from_secs(seconds)).is_ok());
        }
        backoff.record(start, &Ok(()));
        assert!(backoff.check(start).is_ok());
        backoff.record(start, &failure());
        assert!(backoff.check(start + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn cancelled_login_leaves_the_state_unchanged() {
        let start = Instant::now();
        let mut backoff = LoginBackoff::default();
        backoff.record::<()>(start, &Err(Error::Cancelled));
        assert!(backoff.check(start).is_ok());
    }
}
