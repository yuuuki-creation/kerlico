//! JLS 传输回退；本项目补充有界资源许可、错误传播与可主动回收的状态。
use crate::{AsyncUdpSocket, Runtime, UdpSender, udp_transmit};
use bytes::BytesMut;
use proto::{ConnectionError, EcnCodepoint, Transmit};
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use udp::RecvMeta;
const RATE_LIMIT_CYCLE: Duration = Duration::from_millis(10);
pub(crate) const JLS_FORWARD_BATCH: usize = 2;
const JLS_FORWARD_BUFFER: usize = JLS_FORWARD_BATCH * 65536;
/// 转发持有的外部资源许可；销毁最后一个引用时归还。
pub type JlsForwardPermit = Arc<dyn Send + Sync>;
/// 节点/全局预算工厂，拒绝新资源时返回 None。
pub type JlsForwardPermitFactory = Arc<dyn Fn() -> Option<JlsForwardPermit> + Send + Sync>;
#[derive(Clone)]
/// JLS 未认证传输回退的有界配置。
pub struct JlsForwardConfig {
    /// 最多同时保留的回退来源。
    pub max_connections: usize,
    /// 来源闲置回收期限。
    pub idle_timeout: Duration,
    /// 由宿主提供的资源预算。
    pub permit_factory: Option<JlsForwardPermitFactory>,
}
impl Default for JlsForwardConfig {
    fn default() -> Self {
        Self {
            max_connections: 32,
            idle_timeout: Duration::from_secs(30),
            permit_factory: None,
        }
    }
}
impl fmt::Debug for JlsForwardConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JlsForwardConfig")
            .field("max_connections", &self.max_connections)
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}
pub(crate) fn bind_upstream_socket(
    upstream_addr: &str,
) -> Result<(std::net::UdpSocket, SocketAddr), ConnectionError> {
    let upstream = upstream_addr
        .to_socket_addrs()
        .map_err(|error| ConnectionError::JlsForwardError(error.to_string()))?
        .next()
        .ok_or_else(|| ConnectionError::JlsForwardError("JLS 上游解析没有结果".into()))?;
    let bind = if upstream.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = std::net::UdpSocket::bind(bind)
        .map_err(|error| ConnectionError::JlsForwardError(error.to_string()))?;
    // 普通回退只接受显式上游的 UDP 响应，禁止其他来源借用回退 socket。
    socket
        .connect(upstream)
        .map_err(|error| ConnectionError::JlsForwardError(error.to_string()))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| ConnectionError::JlsForwardError(error.to_string()))?;
    Ok((socket, upstream))
}
pub(crate) fn insert_forward_conn(
    state: &mut JlsState,
    runtime: &dyn Runtime,
    transmits: Vec<Transmit>,
    response_buffer: &[u8],
    upstream_addr: &str,
    remote: SocketAddr,
    now: Instant,
    downstream: Pin<Box<dyn UdpSender>>,
) -> Result<(), ConnectionError> {
    state.prune(now);
    if state.upstream_connections.contains_key(&remote) {
        return Ok(());
    }
    if state.upstream_connections.len() >= state.config.max_connections {
        return Err(ConnectionError::JlsForwardError(
            "JLS 回退来源达到上限".into(),
        ));
    }
    let permit = match &state.config.permit_factory {
        Some(factory) => factory()
            .ok_or_else(|| ConnectionError::JlsForwardError("JLS 回退资源预算耗尽".into()))?,
        None => Arc::new(()),
    };
    let (socket, upstream) = bind_upstream_socket(upstream_addr)?;
    let socket = runtime
        .wrap_udp_socket(socket)
        .map_err(|error| ConnectionError::JlsForwardError(error.to_string()))?;
    let mut sender = socket.create_sender();
    let socket_sender = socket.create_sender();
    let bytes_per_cycle = ((state.rate_bps as u128) * RATE_LIMIT_CYCLE.as_millis() / 8000)
        .min(usize::MAX as u128) as usize;
    state.upstream_connections.insert(
        remote,
        JlsForwardConnection {
            upstream_socket: socket,
            upstream_addr: upstream,
            from_upstream: vec![0; JLS_FORWARD_BUFFER].into(),
            active_time: now,
            send_limiter: JlsRateLimiter::new(RATE_LIMIT_CYCLE, bytes_per_cycle),
            recv_limiter: JlsRateLimiter::new(RATE_LIMIT_CYCLE, bytes_per_cycle),
            upstream_sender: socket_sender,
            downstream,
            to_upstream: ForwardQueue::new(),
            to_client: ForwardQueue::new(),
            _permit: permit.clone(),
        },
    );
    if !transmits.is_empty() {
        let buffer = response_buffer.to_vec();
        let mut deadline = runtime.new_timer(now + Duration::from_secs(5));
        runtime.spawn(Box::pin(async move {
            let _permit = permit;
            let sending = async move {
                let mut position = 0;
                for mut transmit in transmits {
                    transmit.destination = upstream;
                    if position + transmit.size > buffer.len() {
                        break;
                    }
                    let value =
                        udp_transmit(&transmit, &buffer[position..position + transmit.size]);
                    let _ = std::future::poll_fn(|cx| sender.as_mut().poll_send(&value, cx)).await;
                    position += transmit.size;
                }
            };
            let mut sending = std::pin::pin!(sending);
            std::future::poll_fn(|cx| {
                if deadline.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(());
                }
                sending.as_mut().poll(cx)
            })
            .await;
        }));
    }
    Ok(())
}
pub(crate) struct JlsForwardConnection {
    pub(crate) upstream_socket: Box<dyn AsyncUdpSocket>,
    pub(crate) upstream_addr: SocketAddr,
    pub(crate) from_upstream: Box<[u8]>,
    pub(crate) active_time: Instant,
    pub(crate) send_limiter: JlsRateLimiter,
    pub(crate) recv_limiter: JlsRateLimiter,
    upstream_sender: Pin<Box<dyn UdpSender>>,
    downstream: Pin<Box<dyn UdpSender>>,
    to_upstream: ForwardQueue,
    to_client: ForwardQueue,
    _permit: JlsForwardPermit,
}
impl fmt::Debug for JlsForwardConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JlsForwardConnection")
            .field("active_time", &self.active_time)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Default)]
pub(crate) struct JlsState {
    pub(crate) upstream_connections: HashMap<SocketAddr, JlsForwardConnection>,
    pub(crate) rate_bps: u64,
    pub(crate) config: JlsForwardConfig,
}
impl JlsState {
    pub(crate) fn new(rate_bps: u64) -> Self {
        Self {
            upstream_connections: HashMap::new(),
            rate_bps,
            config: JlsForwardConfig::default(),
        }
    }
    pub(crate) fn prune(&mut self, now: Instant) {
        let timeout = self.config.idle_timeout;
        self.upstream_connections
            .retain(|_, entry| now.saturating_duration_since(entry.active_time) < timeout);
    }
    pub(crate) fn handle_jls_forward(
        &mut self,
        buf: &BytesMut,
        meta: &RecvMeta,
        now: Instant,
    ) -> bool {
        self.prune(now);
        if let Some(conn) = self.upstream_connections.get_mut(&meta.addr) {
            conn.active_time = now;
            conn.to_upstream.push(buf, meta);
            true
        } else {
            false
        }
    }
}
#[derive(Debug)]
pub(crate) struct JlsRateLimiter {
    updated: Instant,
    credit: u128,
    cycle_period: Duration,
    pub bytes_per_cycle: usize,
    capacity: u128,
}
impl JlsRateLimiter {
    pub(crate) fn new(cycle_period: Duration, bytes_per_cycle: usize) -> Self {
        let capacity = bytes_per_cycle.max(65535) as u128 * cycle_period.as_nanos();
        Self {
            updated: Instant::now(),
            credit: capacity,
            cycle_period,
            bytes_per_cycle,
            capacity,
        }
    }
    pub(crate) fn should_send(&mut self, data_size: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        self.updated = now;
        self.credit = self
            .credit
            .saturating_add(elapsed.saturating_mul(self.bytes_per_cycle as u128))
            .min(self.capacity);
        let cost = data_size as u128 * self.cycle_period.as_nanos();
        if cost > self.credit {
            return false;
        }
        self.credit -= cost;
        true
    }
    fn refund(&mut self, size: usize) {
        self.credit = self
            .credit
            .saturating_add(size as u128 * self.cycle_period.as_nanos())
            .min(self.capacity);
    }
}

struct ForwardPacket {
    bytes: Vec<u8>,
    ecn: Option<EcnCodepoint>,
    segment_size: Option<usize>,
}
struct ForwardQueue {
    packets: VecDeque<ForwardPacket>,
    bytes: usize,
}
impl ForwardQueue {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            bytes: 0,
        }
    }
    fn push(&mut self, bytes: &[u8], meta: &RecvMeta) {
        if self.packets.len() >= 32 || self.bytes + bytes.len() > 256 * 1024 {
            return;
        }
        self.bytes += bytes.len();
        self.packets.push_back(ForwardPacket {
            bytes: bytes.to_vec(),
            ecn: meta
                .ecn
                .map(|value| EcnCodepoint::from_bits(value as u8).unwrap()),
            segment_size: (meta.stride < meta.len).then_some(meta.stride),
        });
    }
    fn flush(
        &mut self,
        sender: &mut Pin<Box<dyn UdpSender>>,
        limiter: &mut JlsRateLimiter,
        target: SocketAddr,
        cx: &mut std::task::Context<'_>,
        now: Instant,
    ) -> std::task::Poll<io::Result<()>> {
        while let Some(front) = self.packets.front() {
            let size = front.bytes.len();
            if !limiter.should_send(size, now) {
                self.packets.pop_front();
                self.bytes -= size;
                continue;
            }
            let transmit = Transmit {
                destination: target,
                ecn: front.ecn,
                size,
                segment_size: front.segment_size,
                src_ip: None,
            };
            let value = udp_transmit(&transmit, &front.bytes);
            match sender.as_mut().poll_send(&value, cx) {
                std::task::Poll::Pending => {
                    limiter.refund(size);
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Err(error)) => {
                    limiter.refund(size);
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Ready(Ok(())) => {
                    self.packets.pop_front();
                    self.bytes -= size;
                }
            }
        }
        std::task::Poll::Ready(Ok(()))
    }
}
impl JlsForwardConnection {
    pub(crate) fn flush_upstream(
        &mut self,
        cx: &mut std::task::Context<'_>,
        now: Instant,
    ) -> std::task::Poll<io::Result<()>> {
        self.to_upstream.flush(
            &mut self.upstream_sender,
            &mut self.send_limiter,
            self.upstream_addr,
            cx,
            now,
        )
    }
    pub(crate) fn flush_client(
        &mut self,
        remote: SocketAddr,
        cx: &mut std::task::Context<'_>,
        now: Instant,
    ) -> std::task::Poll<io::Result<()>> {
        self.to_client.flush(
            &mut self.downstream,
            &mut self.recv_limiter,
            remote,
            cx,
            now,
        )
    }
    pub(crate) fn queue_client(&mut self, bytes: &[u8], meta: &RecvMeta) {
        self.to_client.push(bytes, meta);
    }
}
