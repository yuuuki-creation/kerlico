//! TUIC 客户端动态 UDP 端口跳跃包装器（`HoppingSocket`）。

use quinn::{AsyncUdpSocket, Runtime, UdpPoller, udp};
use rand::Rng;
use std::{
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    ops::RangeInclusive,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

struct HoppingState {
    current_port: u16,
    last_hop: Instant,
    next_interval: Duration,
}

pub(crate) struct HoppingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    base_peer: SocketAddr,
    ranges: Vec<RangeInclusive<u16>>,
    interval_min: Duration,
    interval_max: Duration,
    state: Mutex<HoppingState>,
}

impl std::fmt::Debug for HoppingSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TuicHoppingSocket")
    }
}

impl HoppingSocket {
    fn sample_interval(&self) -> Duration {
        if self.interval_max <= self.interval_min {
            return self.interval_min;
        }
        let min_ms = self.interval_min.as_millis() as u64;
        let max_ms = self.interval_max.as_millis() as u64;
        Duration::from_millis(rand::thread_rng().gen_range(min_ms..=max_ms))
    }

    pub(crate) fn pick_port(&self) -> u16 {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.last_hop.elapsed() >= state.next_interval && !self.ranges.is_empty() {
            let mut rng = rand::thread_rng();
            let range = &self.ranges[rng.gen_range(0..self.ranges.len())];
            state.current_port = rng.gen_range(range.clone());
            state.last_hop = Instant::now();
            state.next_interval = self.sample_interval();
        }
        state.current_port
    }
}

impl AsyncUdpSocket for HoppingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        let mut destination = transmit.destination;
        if destination.ip() == self.base_peer.ip() {
            destination.set_port(self.pick_port());
        }
        let rewritten = udp::Transmit {
            destination,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&rewritten)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = std::task::ready!(self.inner.poll_recv(cx, buffers, meta))?;
        for item in &mut meta[..count] {
            if item.addr.ip() == self.base_peer.ip() {
                item.addr.set_port(self.base_peer.port());
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

pub(crate) fn wrap_hopping(
    socket: UdpSocket,
    hop: Option<(SocketAddr, Vec<RangeInclusive<u16>>, Duration, Duration)>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    let mut inner: Arc<dyn AsyncUdpSocket> = quinn::TokioRuntime.wrap_udp_socket(socket)?;
    if let Some((base_peer, ranges, interval_min, interval_max)) = hop
        && !ranges.is_empty()
    {
        let mut rng = rand::thread_rng();
        let range_index = rng.gen_range(0..ranges.len());
        let initial_port = rng.gen_range(ranges[range_index].clone());
        let initial_interval = if interval_max > interval_min {
            Duration::from_millis(
                rng.gen_range(interval_min.as_millis() as u64..=interval_max.as_millis() as u64),
            )
        } else {
            interval_min
        };
        inner = Arc::new(HoppingSocket {
            inner,
            base_peer,
            ranges,
            interval_min,
            interval_max,
            state: Mutex::new(HoppingState {
                current_port: initial_port,
                last_hop: Instant::now(),
                next_interval: initial_interval,
            }),
        });
    }
    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tuic_hopping_socket_rotates_port_within_configured_ranges() {
        let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.set_nonblocking(true).unwrap();
        let inner = quinn::TokioRuntime.wrap_udp_socket(raw).unwrap();
        let ranges = vec![30000..=30005, 40000..=40005];
        let hop = HoppingSocket {
            inner,
            base_peer: "127.0.0.1:8443".parse().unwrap(),
            ranges: ranges.clone(),
            interval_min: Duration::from_millis(10),
            interval_max: Duration::from_millis(10),
            state: Mutex::new(HoppingState {
                current_port: 30000,
                last_hop: Instant::now() - Duration::from_millis(50),
                next_interval: Duration::from_millis(10),
            }),
        };
        let picked = hop.pick_port();
        assert!(ranges.iter().any(|r| r.contains(&picked)));
    }
}
