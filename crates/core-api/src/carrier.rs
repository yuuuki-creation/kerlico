use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// 当前所有者确认交接的载体字节，独立于用户业务量和设备网卡总量。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CarrierUsage {
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub saturated: bool,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    saturated: AtomicBool,
}

#[derive(Clone, Default)]
pub(crate) struct CarrierCounter(Arc<Counters>);

impl CarrierCounter {
    pub(crate) fn record(&self, sent: u64, received: u64) {
        self.add(&self.0.sent, sent);
        self.add(&self.0.received, received);
    }

    fn add(&self, counter: &AtomicU64, bytes: u64) {
        let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            Some(current.checked_add(bytes).unwrap_or_else(|| {
                self.0.saturated.store(true, Ordering::Release);
                u64::MAX
            }))
        });
    }

    pub(crate) fn snapshot(&self) -> CarrierUsage {
        CarrierUsage {
            sent_bytes: self.0.sent.load(Ordering::Acquire),
            received_bytes: self.0.received.load(Ordering::Acquire),
            saturated: self.0.saturated.load(Ordering::Acquire),
        }
    }
}
