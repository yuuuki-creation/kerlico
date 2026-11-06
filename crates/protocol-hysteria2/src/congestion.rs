//! Hysteria2 拥塞控制：握手前用配置的控制器（BBR 或 NewReno），带宽协商出发送速率后切换为 Brutal。
//!
//! Brutal 与 apernet/hysteria `core/internal/congestion/brutal` 相同：按固定速率发送，按最近 5 秒的
//! 确认率放大发送速率补偿丢包，确认率下限 0.8，拥塞窗口为两倍 BDP。窗口下限为 10240 字节而非上游的
//! 一个数据报：RTT 远小于对端延迟确认时间（回环、同机房）时，单包窗口会让发送等待延迟确认，速率塌到
//! 远低于协商值；发送速率仍由 pacing 决定。

use quinn::congestion::{Controller, ControllerFactory};
use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const SLOTS: usize = 5;
const MIN_SAMPLES: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const WINDOW_MULTIPLIER: f64 = 2.0;
const MIN_WINDOW: u64 = 10240;

/// 发送方向的带宽协商结果，字节每秒。`0` 表示未协商，沿用配置的控制器。
#[derive(Clone, Default)]
pub(crate) struct SendRate(Arc<AtomicU64>);
impl SendRate {
    pub(crate) fn set(&self, bytes_per_second: u64) {
        self.0.store(bytes_per_second, Ordering::Relaxed);
    }
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// 客户端：服务端回复 `auto` 或本端未设上行时用 BBR；否则取 min(服务端接收上限, 本端上行)，
/// 服务端接收上限为 0 时取本端上行。
pub(crate) fn client_send_rate(server_rx: Option<u64>, client_up: u64) -> u64 {
    match server_rx {
        None => 0,
        Some(rx) if rx == 0 || rx > client_up => client_up,
        Some(rx) => rx,
    }
}

/// 服务端：忽略客户端带宽时用 BBR；否则取客户端下行，并以服务端上行为上限。
pub(crate) fn server_send_rate(client_rx: u64, server_up: u64, ignore_client: bool) -> u64 {
    if ignore_client {
        0
    } else if server_up > 0 && client_rx > server_up {
        server_up
    } else {
        client_rx
    }
}

pub(crate) struct SwitchFactory {
    fallback: Arc<dyn ControllerFactory + Send + Sync>,
    rate: SendRate,
}
impl SwitchFactory {
    pub(crate) fn new(fallback: Arc<dyn ControllerFactory + Send + Sync>, rate: SendRate) -> Self {
        Self { fallback, rate }
    }
}
impl ControllerFactory for SwitchFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Switch {
            fallback: self.fallback.clone().build(now, current_mtu),
            brutal: None,
            rate: self.rate.clone(),
            mtu: current_mtu,
            origin: now,
        })
    }
}

struct Switch {
    fallback: Box<dyn Controller>,
    brutal: Option<Brutal>,
    rate: SendRate,
    mtu: u16,
    origin: Instant,
}
impl Switch {
    fn active(&mut self) -> Option<&mut Brutal> {
        let rate = self.rate.get();
        if rate == 0 {
            self.brutal = None;
        } else {
            match &mut self.brutal {
                Some(brutal) => brutal.rate = rate,
                None => self.brutal = Some(Brutal::new(rate, self.mtu, self.origin)),
            }
        }
        self.brutal.as_mut()
    }
}
impl Controller for Switch {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.fallback.on_sent(now, bytes, last_packet_number);
    }
    fn on_sent_with_in_flight(
        &mut self,
        now: Instant,
        bytes: u64,
        last_packet_number: u64,
        in_flight: u64,
        app_limited: bool,
    ) -> u64 {
        self.fallback
            .on_sent_with_in_flight(now, bytes, last_packet_number, in_flight, app_limited)
    }
    fn on_ack_with_token(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
        token: u64,
    ) {
        if let Some(brutal) = self.active() {
            brutal.on_ack(now, rtt.get());
        }
        self.fallback
            .on_ack_with_token(now, sent, bytes, app_limited, rtt, token);
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        if let Some(brutal) = self.active() {
            brutal.on_ack(now, rtt.get());
        }
        self.fallback.on_ack(now, sent, bytes, app_limited, rtt);
    }
    fn on_rtt_sample(&mut self, now: Instant, rtt: Duration, app_limited: bool) {
        self.fallback.on_rtt_sample(now, rtt, app_limited);
    }
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if let Some(brutal) = self.active() {
            brutal.update_ack_rate(now);
        }
        self.fallback
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if let Some(brutal) = self.active() {
            brutal.on_loss(now, lost_bytes);
        }
        self.fallback
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }
    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        if let Some(brutal) = &mut self.brutal {
            brutal.mtu = u64::from(new_mtu);
        }
        self.fallback.on_mtu_update(new_mtu);
    }
    fn window(&self) -> u64 {
        match (&self.brutal, self.rate.get()) {
            (Some(brutal), rate) if rate != 0 => brutal.window(),
            _ => self.fallback.window(),
        }
    }
    fn pacing_rate(&self) -> Option<u64> {
        match (&self.brutal, self.rate.get()) {
            (Some(brutal), rate) if rate != 0 => Some(brutal.pacing_rate()),
            _ => self.fallback.pacing_rate(),
        }
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            fallback: self.fallback.clone_box(),
            brutal: self.brutal.clone(),
            rate: self.rate.clone(),
            mtu: self.mtu,
            origin: self.origin,
        })
    }
    fn initial_window(&self) -> u64 {
        self.fallback.initial_window()
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Clone, Copy, Default)]
struct Slot {
    second: u64,
    acked: u64,
    lost: u64,
}

#[derive(Clone)]
pub(crate) struct Brutal {
    rate: u64,
    mtu: u64,
    rtt: Duration,
    origin: Instant,
    slots: [Slot; SLOTS],
    ack_rate: f64,
}
impl Brutal {
    fn new(rate: u64, mtu: u16, origin: Instant) -> Self {
        Self {
            rate,
            mtu: u64::from(mtu),
            rtt: Duration::ZERO,
            origin,
            slots: [Slot::default(); SLOTS],
            ack_rate: 1.0,
        }
    }
    /// 秒序号从 1 开始，0 留给未使用的槽。
    fn second(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.origin).as_secs() + 1
    }
    fn slot(&mut self, now: Instant) -> &mut Slot {
        let second = self.second(now);
        let slot = &mut self.slots[(second % SLOTS as u64) as usize];
        if slot.second != second {
            *slot = Slot {
                second,
                acked: 0,
                lost: 0,
            };
        }
        slot
    }
    fn on_ack(&mut self, now: Instant, rtt: Duration) {
        self.rtt = rtt;
        self.slot(now).acked += 1;
    }
    fn on_loss(&mut self, now: Instant, lost_bytes: u64) {
        if lost_bytes == 0 {
            return;
        }
        let packets = lost_bytes.div_ceil(self.mtu.max(1));
        self.slot(now).lost += packets;
        self.update_ack_rate(now);
    }
    fn update_ack_rate(&mut self, now: Instant) {
        let oldest = self.second(now).saturating_sub(SLOTS as u64);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|slot| slot.second != 0 && slot.second >= oldest)
            .fold((0, 0), |(a, l), slot| (a + slot.acked, l + slot.lost));
        self.ack_rate = if acked + lost < MIN_SAMPLES {
            1.0
        } else {
            (acked as f64 / (acked + lost) as f64).max(MIN_ACK_RATE)
        };
    }
    pub(crate) fn pacing_rate(&self) -> u64 {
        (self.rate as f64 / self.ack_rate) as u64
    }
    pub(crate) fn window(&self) -> u64 {
        let window = self.rate as f64 * self.rtt.as_secs_f64() * WINDOW_MULTIPLIER / self.ack_rate;
        (window as u64).max(MIN_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brutal(rate: u64) -> (Brutal, Instant) {
        let origin = Instant::now();
        (Brutal::new(rate, 1200, origin), origin)
    }

    #[test]
    fn paces_at_the_configured_rate_without_loss() {
        let (mut b, origin) = brutal(12_500_000);
        assert_eq!(b.pacing_rate(), 12_500_000);
        assert_eq!(b.window(), MIN_WINDOW);
        for _ in 0..100 {
            b.on_ack(origin, Duration::from_millis(100));
        }
        b.update_ack_rate(origin);
        assert_eq!(b.pacing_rate(), 12_500_000);
        assert_eq!(b.window(), 2_500_000);
    }

    #[test]
    fn compensates_loss_by_the_ack_rate() {
        let (mut b, origin) = brutal(10_000_000);
        for _ in 0..90 {
            b.on_ack(origin, Duration::from_millis(50));
        }
        b.on_loss(origin, 10 * 1200);
        assert_eq!(b.pacing_rate(), (10_000_000f64 / 0.9) as u64);
        assert_eq!(b.window(), (10_000_000f64 * 0.05 * 2.0 / 0.9) as u64);
    }

    #[test]
    fn ack_rate_has_a_floor_and_needs_enough_samples() {
        let (mut b, origin) = brutal(1_000_000);
        for _ in 0..10 {
            b.on_ack(origin, Duration::from_millis(10));
        }
        b.on_loss(origin, 30 * 1200);
        assert_eq!(b.pacing_rate(), 1_000_000, "40 个样本不足 50，不补偿");
        b.on_loss(origin, 30 * 1200);
        assert_eq!(b.pacing_rate(), 1_250_000, "确认率下限 0.8");
    }

    #[test]
    fn samples_older_than_five_seconds_expire() {
        let (mut b, origin) = brutal(1_000_000);
        for _ in 0..50 {
            b.on_ack(origin, Duration::from_millis(10));
        }
        b.on_loss(origin, 50 * 1200);
        assert_eq!(b.pacing_rate(), 1_250_000);
        let later = origin + Duration::from_secs(6);
        b.update_ack_rate(later);
        assert_eq!(b.pacing_rate(), 1_000_000);
    }

    #[test]
    fn window_has_a_floor_for_tiny_bdp() {
        let (mut b, origin) = brutal(1000);
        b.on_ack(origin, Duration::from_millis(1));
        assert_eq!(b.window(), MIN_WINDOW);
    }

    #[test]
    fn negotiation_follows_upstream_rules() {
        assert_eq!(client_send_rate(None, 1000), 0, "auto 用 BBR");
        assert_eq!(client_send_rate(Some(0), 1000), 1000);
        assert_eq!(client_send_rate(Some(500), 1000), 500);
        assert_eq!(client_send_rate(Some(5000), 1000), 1000);
        assert_eq!(client_send_rate(Some(500), 0), 0, "本端未设 up 用 BBR");
        assert_eq!(client_send_rate(Some(0), 0), 0);
        assert_eq!(server_send_rate(800, 0, false), 800);
        assert_eq!(server_send_rate(800, 500, false), 500);
        assert_eq!(server_send_rate(0, 500, false), 0);
        assert_eq!(server_send_rate(800, 500, true), 0);
    }

    #[test]
    fn switch_moves_between_fallback_and_brutal() {
        let rate = SendRate::default();
        let factory = Arc::new(SwitchFactory::new(
            Arc::new(quinn::congestion::NewRenoConfig::default()),
            rate.clone(),
        ));
        let mut controller = factory.build(Instant::now(), 1200);
        let reno = controller.window();
        assert_eq!(controller.pacing_rate(), None);
        rate.set(5_000_000);
        controller.on_end_acks(Instant::now(), 0, false, None);
        assert_eq!(controller.pacing_rate(), Some(5_000_000));
        assert_eq!(controller.window(), MIN_WINDOW);
        rate.set(0);
        assert_eq!(controller.window(), reno);
    }
}
