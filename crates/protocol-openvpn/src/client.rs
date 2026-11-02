//! 命名出站与其后台会话：连接载体、驱动状态机、把解密后的 IP 包交给用户态 IP 数据面。

use crate::{
    config::{ClientOptions, Prepared, Proto},
    push::PushedConfig,
    session::{Event, Session},
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    Address, BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, OpenedTcp, Outbound, Result, ServiceContext,
    ServiceFailure, ServiceStatus, TargetPolicy,
};
use kerlico_wireguard::ip::{ClientTunnel, StackLimits, StackOptions};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
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
    loop {
        let result = run_session(&prepared, &host, &cancel, &publish).await;
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
    host: &ServiceContext,
    cancel: &CancellationToken,
    publish: &watch::Sender<TunnelState>,
) -> Result<()> {
    let handshake = prepared.settings.handshake;
    let mut link = tokio::select! { biased;
        _ = cancel.cancelled() => return Ok(()),
        link = tokio::time::timeout(handshake, Link::connect(prepared, host.clone())) => {
            link.map_err(|_| Error::Timeout)??
        }
    };
    let mut session = Session::new(prepared.settings.clone(), Instant::now())?;
    let mut tunnel: Option<ClientTunnel> = None;
    let mut timer = tokio::time::interval(TICK);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        for wire in session.take_outbox() {
            tokio::select! { biased;
                _ = cancel.cancelled() => return Ok(()),
                sent = link.send(&wire) => sent?,
            }
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
                Event::Packet(packet) => {
                    if let Some(tunnel) = &tunnel {
                        let _ = tunnel.receive(&packet);
                    }
                }
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            wire = link.recv() => session.receive(Instant::now(), &wire?)?,
            packet = next_packet(tunnel.as_ref()) => session.send_packet(Instant::now(), &packet?)?,
            _ = timer.tick() => session.tick(Instant::now())?,
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

enum Link {
    Udp {
        socket: UdpSocket,
        buffer: Vec<u8>,
        host: ServiceContext,
    },
    Tcp {
        stream: TcpStream,
        buffer: Vec<u8>,
        host: ServiceContext,
    },
}
impl Link {
    async fn connect(prepared: &Prepared, host: ServiceContext) -> Result<Self> {
        let endpoint = resolve(&prepared.remote, prepared.bind).await?;
        let bind = prepared.bind.unwrap_or_else(|| {
            let any = if endpoint.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            SocketAddr::new(any, 0)
        });
        match prepared.proto {
            Proto::Udp => {
                let socket = UdpSocket::bind(bind).await?;
                socket.connect(endpoint).await?;
                Ok(Self::Udp {
                    socket,
                    buffer: vec![0; 65536],
                    host,
                })
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
                Ok(Self::Tcp {
                    stream,
                    buffer: Vec::with_capacity(65538),
                    host,
                })
            }
        }
    }
    /// 可被 `select!` 取消：TCP 已读字节留在 `buffer`，下一次调用继续拼帧。
    async fn recv(&mut self) -> Result<Vec<u8>> {
        match self {
            Self::Udp {
                socket,
                buffer,
                host,
            } => {
                let count = socket.recv(buffer).await?;
                host.record_carrier(0, count as u64);
                Ok(buffer[..count].to_vec())
            }
            Self::Tcp {
                stream,
                buffer,
                host,
            } => loop {
                if let Some((length, rest)) = buffer.split_first_chunk::<2>() {
                    let length = usize::from(u16::from_be_bytes(*length));
                    if rest.len() >= length {
                        let packet = rest[..length].to_vec();
                        buffer.drain(..2 + length);
                        return Ok(packet);
                    }
                }
                let count = stream.read_buf(buffer).await?;
                if count == 0 {
                    return Err(Error::Protocol("OpenVPN 服务端关闭了 TCP 连接"));
                }
                host.record_carrier(0, count as u64);
            },
        }
    }
    async fn send(&mut self, packet: &[u8]) -> Result<()> {
        match self {
            Self::Udp { socket, host, .. } => {
                let count = socket.send(packet).await?;
                host.record_carrier(count as u64, 0);
            }
            Self::Tcp { stream, host, .. } => {
                let length =
                    u16::try_from(packet.len()).map_err(|_| Error::Protocol("OpenVPN 包过大"))?;
                let mut frame = Vec::with_capacity(2 + packet.len());
                frame.extend_from_slice(&length.to_be_bytes());
                frame.extend_from_slice(packet);
                stream.write_all(&frame).await?;
                host.record_carrier(frame.len() as u64, 0);
            }
        }
        Ok(())
    }
}
async fn resolve(remote: &Destination, bind: Option<SocketAddr>) -> Result<SocketAddr> {
    let mut addresses: Vec<SocketAddr> = match remote.address() {
        Address::Ip(ip) => vec![SocketAddr::new(*ip, remote.port())],
        Address::Domain(domain) => tokio::net::lookup_host((domain.as_str(), remote.port()))
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
