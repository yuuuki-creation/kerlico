//! 命名出站与其后台会话：连接载体、驱动状态机、把解密后的 IP 包交给用户态 IP 数据面。

use crate::{
    config::{ClientOptions, Prepared, Proto},
    push::PushedConfig,
    session::{Event, Session},
};
use bytes::Bytes;
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    Address, BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, OpenedTcp, Outbound, Result, ServiceContext,
    ServiceFailure, ServiceStatus, TargetPolicy,
};
use kerlico_wireguard::ip::{ClientTunnel, StackLimits, StackOptions};
use serde_json::Value;
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, tcp::WriteHalf},
    sync::watch,
    time::MissedTickBehavior,
};

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: true,
    udp: true,
};
const TICK: Duration = Duration::from_millis(250);
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// 发送队列连续这么久没有清空，说明对端不再读取 TCP；服务端未推送 `ping-restart` 时这是唯一的恢复途径。
const SEND_STALL: Duration = Duration::from_secs(60);

pub struct OpenVpnFactory;
impl OutboundFactory for OpenVpnFactory {
    fn kind(&self) -> &'static str {
        "openvpn"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: ClientOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("OpenVPN 出站字段不合法".into()))?;
        let prepared = options.prepare()?;
        Ok(OutboundPlan::new(
            CAPABILITIES,
            true,
            TargetPolicy::Local,
            move |host| Box::pin(start(prepared, host)),
        ))
    }
}

/// 后台会话发布的当前隧道；断线重连期间为空，并保留上次失败原因供等待方报告。
#[derive(Default)]
struct TunnelState {
    tunnel: Option<ClientTunnel>,
    failure: Option<ServiceFailure>,
}

struct OpenVpnOutbound {
    state: watch::Receiver<TunnelState>,
    cancel: CancellationToken,
    status: ServiceStatus,
}
impl Drop for OpenVpnOutbound {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl OpenVpnOutbound {
    async fn tunnel(&self, context: &ConnectContext) -> Result<ClientTunnel> {
        if let Some(failure) = self.status.failure() {
            return Err(failure.error());
        }
        let mut state = self.state.clone();
        let waited = context
            .run(async {
                let current = state.wait_for(|state| state.tunnel.is_some()).await;
                match current {
                    Ok(current) => current.tunnel.clone().ok_or(Error::Cancelled),
                    Err(_) => Err(self
                        .status
                        .failure()
                        .map_or(Error::Cancelled, ServiceFailure::error)),
                }
            })
            .await;
        match waited {
            Err(Error::Timeout) => Err(self
                .state
                .borrow()
                .failure
                .map_or(Error::Timeout, ServiceFailure::error)),
            other => other,
        }
    }
}
impl Outbound for OpenVpnOutbound {
    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.cancel.cancel();
            self.status
                .failure()
                .map_or(Ok(()), |failure| Err(failure.error()))
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        remote: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            self.tunnel(context)
                .await?
                .connect_tcp(remote, context)
                .await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        remote: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move { self.tunnel(context).await?.connect_udp(remote, context) })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move { self.tunnel(context).await?.associate_udp(context) })
    }
}

async fn start(prepared: Prepared, host: ServiceContext) -> Result<Arc<dyn Outbound>> {
    let cancel = host.cancel().child_token();
    let (publish, state) = watch::channel(TunnelState::default());
    let status = host.status();
    host.spawn(supervise(prepared, host.clone(), cancel.clone(), publish))?;
    Ok(Arc::new(OpenVpnOutbound {
        state,
        cancel,
        status,
    }))
}

/// 断线后按退避重连。`Error::Rejected` 表示服务端拒绝认证或要求停止，重试只会锁账户，所以终止服务。
async fn supervise(
    prepared: Prepared,
    host: ServiceContext,
    cancel: CancellationToken,
    publish: watch::Sender<TunnelState>,
) {
    let mut backoff = MIN_BACKOFF;
    let mut attempt = 0usize;
    loop {
        let result = run_session(&prepared, attempt, &host, &cancel, &publish).await;
        attempt = attempt.wrapping_add(1);
        publish.send_modify(|state| {
            if let Some(tunnel) = state.tunnel.take() {
                tunnel.close();
                backoff = MIN_BACKOFF;
            }
        });
        let error = match result {
            Ok(()) | Err(Error::Cancelled) => return,
            Err(error) => error,
        };
        if matches!(error, Error::Rejected) {
            host.fail(ServiceFailure::Rejected);
            cancel.cancel();
            return;
        }
        publish.send_modify(|state| state.failure = Some(service_failure(error)));
        tokio::select! { biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
fn service_failure(error: Error) -> ServiceFailure {
    match error {
        Error::Timeout => ServiceFailure::Timeout,
        Error::Rejected => ServiceFailure::Rejected,
        Error::InvalidAddress => ServiceFailure::InvalidAddress,
        Error::ResourceLimit => ServiceFailure::ResourceLimit,
        Error::Protocol(message) | Error::Unsupported(message) => ServiceFailure::Protocol(message),
        Error::Io(error) => ServiceFailure::Io(error.kind(), "OpenVPN 载体运行失败"),
        _ => ServiceFailure::Protocol("OpenVPN 出站运行失败"),
    }
}

async fn run_session(
    prepared: &Prepared,
    attempt: usize,
    host: &ServiceContext,
    cancel: &CancellationToken,
    publish: &watch::Sender<TunnelState>,
) -> Result<()> {
    let handshake = prepared.settings.handshake;
    let mut link = tokio::select! { biased;
        _ = cancel.cancelled() => return Ok(()),
        link = tokio::time::timeout(handshake, Link::connect(prepared, attempt, host.clone())) => {
            link.map_err(|_| Error::Timeout)??
        }
    };
    let mut session = Session::new(prepared.settings.clone(), Instant::now())?;
    let mut tunnel: Option<ClientTunnel> = None;
    let mut timer = tokio::time::interval(TICK);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        for wire in session.take_outbox() {
            link.queue(wire)?;
        }
        for event in session.take_events() {
            match event {
                Event::Up(config) => {
                    let opened = open_tunnel(prepared, &config, cancel)?;
                    tunnel = Some(opened.clone());
                    publish.send_modify(|state| {
                        state.tunnel = Some(opened);
                        state.failure = None;
                    });
                }
                Event::Packet(mut packet) => {
                    if let Some(mss) = prepared.mss_fix {
                        clamp_tcp_mss(&mut packet, mss);
                    }
                    if let Some(tunnel) = &tunnel {
                        let _ = tunnel.receive(&packet);
                    }
                }
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            event = link.next() => {
                if let LinkEvent::Received(wire) = event? {
                    session.receive(Instant::now(), &wire)?;
                }
            }
            packet = next_packet(tunnel.as_ref()), if link.idle() => {
                let mut packet = packet?;
                if let Some(mss) = prepared.mss_fix {
                    clamp_tcp_mss(&mut packet, mss);
                }
                session.send_packet(Instant::now(), &packet)?;
            }
            _ = timer.tick() => {
                let now = Instant::now();
                if link.stalled(now) {
                    return Err(Error::Timeout);
                }
                session.tick(now)?;
            }
        }
    }
}

fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) {
    let version = packet.first().map(|b| b >> 4).unwrap_or(0);
    let tcp_offset = match version {
        4 if packet.len() >= 40 && packet[9] == 6 => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl + 20 {
                return;
            }
            ihl
        }
        6 if packet.len() >= 60 && packet[6] == 6 => 40,
        _ => return,
    };
    let tcp = &mut packet[tcp_offset..];
    if tcp[13] & 0x02 == 0 {
        return;
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset <= 20 || tcp.len() < data_offset {
        return;
    }
    let mut idx = 20;
    while idx < data_offset {
        match tcp[idx] {
            0 => break,
            1 => idx += 1,
            kind => {
                if idx + 1 >= data_offset {
                    break;
                }
                let len = usize::from(tcp[idx + 1]);
                if len < 2 || idx + len > data_offset {
                    break;
                }
                if kind == 2 && len == 4 {
                    let old_mss = u16::from_be_bytes([tcp[idx + 2], tcp[idx + 3]]);
                    if old_mss > max_mss {
                        tcp[idx + 2..idx + 4].copy_from_slice(&max_mss.to_be_bytes());
                        let old_csum = u16::from_be_bytes([tcp[16], tcp[17]]);
                        let sum = u32::from(!old_csum) + u32::from(!old_mss) + u32::from(max_mss);
                        let folded = (sum & 0xffff) + (sum >> 16);
                        let new_csum = !((folded + (folded >> 16)) as u16);
                        tcp[16..18].copy_from_slice(&new_csum.to_be_bytes());
                    }
                    return;
                }
                idx += len;
            }
        }
    }
}
async fn next_packet(tunnel: Option<&ClientTunnel>) -> Result<Vec<u8>> {
    match tunnel {
        Some(tunnel) => tunnel.next_packet().await,
        None => std::future::pending().await,
    }
}
fn open_tunnel(
    prepared: &Prepared,
    config: &PushedConfig,
    cancel: &CancellationToken,
) -> Result<ClientTunnel> {
    let mut addresses = Vec::new();
    let mut allowed = Vec::new();
    if let Some(address) = config.address_v4 {
        addresses.push(IpAddr::V4(address));
        allowed.push("0.0.0.0/0".to_owned());
    }
    if let Some(address) = config.address_v6 {
        addresses.push(IpAddr::V6(address));
        allowed.push("::/0".to_owned());
    }
    ClientTunnel::new(
        StackOptions {
            addresses,
            allowed_ips: prepared.allowed_ips.clone().unwrap_or(allowed),
            mtu: prepared.mtu,
            limits: StackLimits::default(),
        },
        cancel.clone(),
    )
}

enum Carrier {
    Udp { socket: UdpSocket, buffer: Vec<u8> },
    Tcp { stream: TcpStream, buffer: Vec<u8> },
}
enum LinkEvent {
    Received(Vec<u8>),
    Drained,
}
/// 单任务同时推进收发：TCP 背压时仍继续读取和走定时器，发送队列留到下次调用继续。
struct Link {
    carrier: Carrier,
    pending: VecDeque<Bytes>,
    pending_since: Option<Instant>,
    host: ServiceContext,
}
impl Link {
    fn new(carrier: Carrier, host: ServiceContext) -> Self {
        Self {
            carrier,
            pending: VecDeque::new(),
            pending_since: None,
            host,
        }
    }
    async fn connect(prepared: &Prepared, attempt: usize, host: ServiceContext) -> Result<Self> {
        let (remote, proto) = &prepared.remotes[attempt % prepared.remotes.len()];
        let endpoint = resolve(remote, prepared.bind).await?;
        let bind = prepared.bind.unwrap_or_else(|| {
            let any = if endpoint.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            SocketAddr::new(any, 0)
        });
        match proto {
            Proto::Udp => {
                let socket = UdpSocket::bind(bind).await?;
                socket.connect(endpoint).await?;
                let buffer = vec![0; 65536];
                Ok(Self::new(Carrier::Udp { socket, buffer }, host))
            }
            Proto::Tcp => {
                let socket = if endpoint.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()?
                } else {
                    tokio::net::TcpSocket::new_v6()?
                };
                if prepared.bind.is_some() {
                    socket.bind(bind)?;
                }
                let stream = socket.connect(endpoint).await?;
                stream.set_nodelay(true)?;
                let buffer = Vec::with_capacity(65538);
                Ok(Self::new(Carrier::Tcp { stream, buffer }, host))
            }
        }
    }
    fn idle(&self) -> bool {
        self.pending.is_empty()
    }
    fn stalled(&self, now: Instant) -> bool {
        self.pending_since
            .is_some_and(|since| now.duration_since(since) >= SEND_STALL)
    }
    fn queue(&mut self, packet: Vec<u8>) -> Result<()> {
        let frame = match self.carrier {
            Carrier::Udp { .. } => packet,
            Carrier::Tcp { .. } => {
                let length =
                    u16::try_from(packet.len()).map_err(|_| Error::Protocol("OpenVPN 包过大"))?;
                let mut frame = Vec::with_capacity(2 + packet.len());
                frame.extend_from_slice(&length.to_be_bytes());
                frame.extend_from_slice(&packet);
                frame
            }
        };
        self.host.record_carrier(frame.len() as u64, 0);
        self.pending.push_back(frame.into());
        self.pending_since.get_or_insert_with(Instant::now);
        Ok(())
    }
    /// 可被 `select!` 取消：TCP 已读字节留在 `buffer`，未写完的帧留在 `pending` 的队首。
    async fn next(&mut self) -> Result<LinkEvent> {
        let Self {
            carrier,
            pending,
            pending_since,
            host,
        } = self;
        match carrier {
            Carrier::Udp { socket, buffer } => {
                tokio::select! {
                    sent = drain_udp(socket, pending), if !pending.is_empty() => {
                        sent?;
                        *pending_since = None;
                        Ok(LinkEvent::Drained)
                    }
                    count = socket.recv(buffer) => {
                        let count = count?;
                        host.record_carrier(0, count as u64);
                        Ok(LinkEvent::Received(buffer[..count].to_vec()))
                    }
                }
            }
            Carrier::Tcp { stream, buffer } => loop {
                if let Some((length, rest)) = buffer.split_first_chunk::<2>() {
                    let length = usize::from(u16::from_be_bytes(*length));
                    if rest.len() >= length {
                        let packet = rest[..length].to_vec();
                        buffer.drain(..2 + length);
                        return Ok(LinkEvent::Received(packet));
                    }
                }
                let (mut reader, mut writer) = stream.split();
                tokio::select! {
                    sent = drain_tcp(&mut writer, pending), if !pending.is_empty() => {
                        sent?;
                        *pending_since = None;
                        return Ok(LinkEvent::Drained);
                    }
                    count = reader.read_buf(buffer) => {
                        let count = count?;
                        if count == 0 {
                            return Err(Error::Protocol("OpenVPN 服务端关闭了 TCP 连接"));
                        }
                        host.record_carrier(0, count as u64);
                    }
                }
            },
        }
    }
}
async fn drain_udp(socket: &UdpSocket, pending: &mut VecDeque<Bytes>) -> std::io::Result<()> {
    while let Some(packet) = pending.front() {
        socket.send(packet).await?;
        pending.pop_front();
    }
    Ok(())
}
async fn drain_tcp(
    writer: &mut WriteHalf<'_>,
    pending: &mut VecDeque<Bytes>,
) -> std::io::Result<()> {
    while let Some(frame) = pending.front_mut() {
        writer.write_all_buf(frame).await?;
        pending.pop_front();
    }
    Ok(())
}
async fn resolve(remote: &Destination, bind: Option<SocketAddr>) -> Result<SocketAddr> {
    let mut addresses: Vec<SocketAddr> = match remote.address() {
        Address::Ip(ip) => vec![SocketAddr::new(*ip, remote.port())],
        Address::Domain(domain) => kerlico_core::lookup_host((domain.as_str(), remote.port()))
            .await?
            .collect(),
    };
    addresses.retain(|address| {
        !address.ip().is_multicast()
            && !address.ip().is_unspecified()
            && bind.is_none_or(|bind| bind.is_ipv4() == address.is_ipv4())
    });
    addresses.sort_by_key(SocketAddr::is_ipv6);
    addresses.into_iter().next().ok_or(Error::InvalidAddress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{net::TcpListener, time::timeout};

    /// 对端完全不读时，发送队列写不完，读取仍要继续，并在时限后判定停滞。
    #[tokio::test]
    async fn tcp_backpressure_does_not_stop_reads_and_is_detected_as_a_stall() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let buffer = Vec::with_capacity(65538);
        let mut link = Link::new(Carrier::Tcp { stream, buffer }, ServiceContext::for_test());
        for _ in 0..2048 {
            link.queue(vec![0; 60000]).unwrap();
        }
        let blocked = timeout(Duration::from_millis(200), link.next()).await;
        assert!(blocked.is_err(), "send buffers should be full by now");
        assert!(!link.idle());

        peer.write_all(&[0, 3, b'a', b'b', b'c']).await.unwrap();
        let event = timeout(Duration::from_secs(5), link.next()).await.unwrap();
        assert!(matches!(event, Ok(LinkEvent::Received(wire)) if wire == b"abc"));

        assert!(!link.stalled(Instant::now()));
        assert!(link.stalled(Instant::now() + SEND_STALL));
    }

    #[tokio::test]
    async fn drained_queue_clears_the_stall_clock() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let buffer = Vec::with_capacity(65538);
        let mut link = Link::new(Carrier::Tcp { stream, buffer }, ServiceContext::for_test());
        link.queue(b"abc".to_vec()).unwrap();
        let event = timeout(Duration::from_secs(5), link.next()).await.unwrap();
        assert!(matches!(event, Ok(LinkEvent::Drained)));
        assert!(link.idle());
        assert!(!link.stalled(Instant::now() + SEND_STALL));
        let mut frame = [0; 5];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame, [0, 3, b'a', b'b', b'c']);
    }
}
