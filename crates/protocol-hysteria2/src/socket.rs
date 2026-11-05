use blake2::{Blake2b, Digest, digest::consts::U32};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller, udp};
use rand::{Rng, RngCore};
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
struct HoppingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    base_peer: SocketAddr,
    ranges: Vec<RangeInclusive<u16>>,
    interval_min: Duration,
    interval_max: Duration,
    state: Mutex<HoppingState>,
}
impl std::fmt::Debug for HoppingSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Hysteria2HoppingSocket")
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
    fn pick_port(&self) -> u16 {
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

struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Arc<String>,
    send: Mutex<Vec<u8>>,
    receive: Mutex<Vec<u8>>,
}
impl std::fmt::Debug for Salamander {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Hysteria2SalamanderSocket")
    }
}
fn mask(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hash = Blake2b::<U32>::new();
    hash.update(password.as_bytes());
    hash.update(salt);
    hash.finalize().into()
}
pub(crate) fn wrap(
    socket: UdpSocket,
    password: Option<Arc<String>>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    wrap_hopping(socket, password, None)
}
pub(crate) fn wrap_hopping(
    socket: UdpSocket,
    password: Option<Arc<String>>,
    hop: Option<(SocketAddr, Vec<RangeInclusive<u16>>, Duration, Duration)>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    let sock_ref = socket2::SockRef::from(&socket);
    let _ = sock_ref.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = sock_ref.set_send_buffer_size(8 * 1024 * 1024);
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
    Ok(match password {
        None => inner,
        Some(password) => Arc::new(Salamander {
            inner,
            password,
            send: Mutex::new(Vec::with_capacity(1500)),
            receive: Mutex::new(vec![0; 65536]),
        }),
    })
}
impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.contents.len() > 65499
            || transmit
                .segment_size
                .is_some_and(|size| size == 0 || transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salamander 数据报超出单包边界",
            ));
        }
        let mut salt = [0; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = mask(&self.password, &salt);
        let mut buffer = self
            .send
            .lock()
            .map_err(|_| io::Error::other("Salamander 状态不可用"))?;
        buffer.resize(transmit.contents.len() + 8, 0);
        buffer[..8].copy_from_slice(&salt);
        for (i, byte) in transmit.contents.iter().enumerate() {
            buffer[i + 8] = byte ^ key[i % 32];
        }
        self.inner.try_send(&udp::Transmit {
            contents: &buffer,
            segment_size: None,
            ..*transmit
        })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        output: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let _ = &self.receive;
        let count = std::task::ready!(self.inner.poll_recv(cx, output, meta))?;
        for i in 0..count {
            let info = &mut meta[i];
            let buf = &mut output[i];
            let length = info.len.min(buf.len());
            let stride = info.stride.max(1);
            if stride <= 8 {
                info.len = 0;
                info.stride = 1;
                continue;
            }
            let mut written = 0;
            for start in (0..length).step_by(stride) {
                let end = (start + stride).min(length);
                if end - start <= 8 {
                    continue;
                }
                let key = mask(&self.password, &buf[start..start + 8]);
                for index in start + 8..end {
                    buf[written] = buf[index] ^ key[(index - start - 8) % 32];
                    written += 1;
                }
            }
            info.len = written;
            info.stride = if written == 0 { 1 } else { stride - 8 };
        }
        Poll::Ready(Ok(count))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
