use quinn::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use std::any::Any;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum BbrProfile {
    Conservative,
    #[default]
    Standard,
    Aggressive,
}

impl BbrProfile {
    pub(super) fn parse(value: &str) -> io::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "" | "standard" => Ok(Self::Standard),
            "conservative" => Ok(Self::Conservative),
            "aggressive" => Ok(Self::Aggressive),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown QUIC BBR profile")),
        }
    }
}

pub(super) fn bbr(profile: BbrProfile, debug: bool) -> Arc<dyn ControllerFactory + Send + Sync> {
    let mut config = BbrConfig::default();
    config.xray_profile(
        match profile {
            BbrProfile::Conservative => quinn::congestion::BbrProfile::Conservative,
            BbrProfile::Standard => quinn::congestion::BbrProfile::Standard,
            BbrProfile::Aggressive => quinn::congestion::BbrProfile::Aggressive,
        },
        debug,
    );
    Arc::new(config)
}

pub(super) struct BrutalConfig {
    bytes_per_second: u64,
    compensate_loss: bool,
    debug: bool,
}

impl BrutalConfig {
    pub(super) fn new(bytes_per_second: u64, compensate_loss: bool, debug: bool) -> Self {
        Self { bytes_per_second, compensate_loss, debug }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal {
            config: self,
            start: now,
            mtu: current_mtu.into(),
            rtt: Duration::ZERO,
            ack_fraction: 1.0,
            slots: [Slot::default(); 5],
            last_log: None,
        })
    }
}

#[derive(Clone, Copy, Default)]
struct Slot {
    second: u64,
    acknowledged: u64,
    lost: u64,
}

#[derive(Clone)]
struct Brutal {
    config: Arc<BrutalConfig>,
    start: Instant,
    mtu: u64,
    rtt: Duration,
    ack_fraction: f64,
    slots: [Slot; 5],
    last_log: Option<Instant>,
}

impl Brutal {
    fn second(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.start).as_secs()
    }

    fn record(&mut self, now: Instant, acknowledged: u64, lost: u64) {
        if !self.config.compensate_loss {
            return;
        }
        let second = self.second(now);
        let slot = &mut self.slots[(second % 5) as usize];
        if slot.second != second {
            *slot = Slot { second, ..Slot::default() };
        }
        slot.acknowledged = slot.acknowledged.saturating_add(acknowledged);
        slot.lost = slot.lost.saturating_add(lost);
    }

    fn update_ack_fraction(&mut self, now: Instant) {
        let oldest = self.second(now).saturating_sub(4);
        let mut acknowledged = 0u64;
        let mut lost = 0u64;
        for slot in self.slots.iter().filter(|slot| slot.second >= oldest) {
            acknowledged = acknowledged.saturating_add(slot.acknowledged);
            lost = lost.saturating_add(slot.lost);
        }
        let total = acknowledged.saturating_add(lost);
        self.ack_fraction = if total < 50 { 1.0 } else { (acknowledged as f64 / total as f64).max(0.8) };
        if self.config.debug && self.last_log.is_none_or(|last| now.saturating_duration_since(last).as_secs() >= 2) {
            self.last_log = Some(now);
            eprintln!(
                "[BrutalSender] ACK rate {:.2} (ACK {acknowledged}, lost {lost}, RTT {} ms, {} bytes/s)",
                self.ack_fraction, self.rtt.as_millis(), self.pacing_bps(),
            );
        }
    }

    fn pacing_bps(&self) -> u64 {
        (self.config.bytes_per_second as f64 / self.ack_fraction) as u64
    }
}

impl Controller for Brutal {
    fn on_ack(&mut self, now: Instant, _: Instant, _: u64, _: bool, _: &RttEstimator) {
        self.record(now, 1, 0);
    }

    fn on_end_acks(&mut self, now: Instant, _: u64, _: bool, _: Option<u64>) {
        self.update_ack_fraction(now);
    }

    fn on_packets_lost(&mut self, now: Instant, packets: u64) {
        self.record(now, 0, packets);
        self.update_ack_fraction(now);
    }

    fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: u64) {}

    fn on_rtt_update(&mut self, rtt: &RttEstimator) {
        self.rtt = rtt.get();
    }

    fn on_mtu_update(&mut self, mtu: u16) {
        self.mtu = mtu.into();
    }

    fn pacing_rate(&self, _: &RttEstimator) -> Option<u64> {
        Some(self.pacing_bps())
    }

    fn can_send(&self, in_flight: u64, _: u64) -> bool {
        in_flight <= self.window()
    }

    fn window(&self) -> u64 {
        if self.rtt.is_zero() {
            return self.initial_window();
        }
        ((self.pacing_bps() as f64 * self.rtt.as_secs_f64() * 2.0) as u64).max(self.mtu)
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.pacing_bps().saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        10_240
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
