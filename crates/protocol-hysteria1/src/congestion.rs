//! 标准控制器保留自身拥塞反馈，独立的每连接状态限制协商后的发送 pacing。
use crate::config::Congestion;
use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
pub(crate) struct Factory {
    inner: Arc<dyn ControllerFactory + Send + Sync>,
}
impl Factory {
    pub fn new(kind: Congestion) -> Self {
        let inner: Arc<dyn ControllerFactory + Send + Sync> = match kind {
            Congestion::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
            Congestion::Newreno => Arc::new(quinn::congestion::NewRenoConfig::default()),
            Congestion::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
        };
        Self { inner }
    }
}
impl ControllerFactory for Factory {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(Paced {
            inner: self.inner.clone().build(now, mtu),
            limit: Arc::new(AtomicU64::new(0)),
        })
    }
}
struct Paced {
    inner: Box<dyn Controller>,
    limit: Arc<AtomicU64>,
}
impl Controller for Paced {
    fn on_sent(&mut self, now: Instant, bytes: u64, number: u64) {
        self.inner.on_sent(now, bytes, number)
    }
    fn on_sent_with_in_flight(
        &mut self,
        now: Instant,
        bytes: u64,
        number: u64,
        flight: u64,
        limited: bool,
    ) -> u64 {
        self.inner
            .on_sent_with_in_flight(now, bytes, number, flight, limited)
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        limited: bool,
        rtt: &RttEstimator,
    ) {
        self.inner.on_ack(now, sent, bytes, limited, rtt)
    }
    fn on_ack_with_token(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        limited: bool,
        rtt: &RttEstimator,
        token: u64,
    ) {
        self.inner
            .on_ack_with_token(now, sent, bytes, limited, rtt, token)
    }
    fn on_rtt_sample(&mut self, now: Instant, rtt: Duration, limited: bool) {
        self.inner.on_rtt_sample(now, rtt, limited)
    }
    fn on_end_acks(&mut self, now: Instant, flight: u64, limited: bool, largest: Option<u64>) {
        self.inner.on_end_acks(now, flight, limited, largest)
    }
    fn on_congestion_event(&mut self, now: Instant, sent: Instant, persistent: bool, lost: u64) {
        self.inner.on_congestion_event(now, sent, persistent, lost)
    }
    fn on_mtu_update(&mut self, mtu: u16) {
        self.inner.on_mtu_update(mtu)
    }
    fn window(&self) -> u64 {
        self.inner.window()
    }
    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }
    fn pacing_rate(&self) -> Option<u64> {
        let cap = self.limit.load(Ordering::Relaxed);
        if cap == 0 {
            self.inner.pacing_rate()
        } else {
            Some(self.inner.pacing_rate().map_or(cap, |rate| rate.min(cap)))
        }
    }
    fn metrics(&self) -> ControllerMetrics {
        let mut value = self.inner.metrics();
        value.pacing_rate = self.pacing_rate().map(|rate| rate.saturating_mul(8));
        value
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            limit: self.limit.clone(),
        })
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
pub(crate) fn negotiated(connection: &quinn::Connection, bps: u64) -> kerlico_core::Result<()> {
    let controller = connection
        .congestion_state()
        .into_any()
        .downcast::<Paced>()
        .map_err(|_| crate::protocol())?;
    controller.limit.store(bps, Ordering::Relaxed);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiated_rate_is_not_shared_between_connections() {
        let factory = Arc::new(Factory::new(Congestion::Cubic));
        let one = factory.clone().build(Instant::now(), 1200);
        let two = factory.build(Instant::now(), 1200);
        let copy = one.clone_box().into_any().downcast::<Paced>().unwrap();
        copy.limit.store(123456, Ordering::Relaxed);
        assert_eq!(one.pacing_rate(), Some(123456));
        assert_eq!(two.pacing_rate(), None);
        assert!(one.window() > 0);
    }
}
