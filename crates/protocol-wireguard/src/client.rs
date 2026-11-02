use crate::carrier::Carrier;
use crate::{
    config::{ClientOptions, PeerConfig, Prepared, target},
    crypto::{CryptoPeer, Identified, PeerIndex},
    packet::{FragmentBudget, IpPacket, Reassembler, control_reply},
    queue::PacketBudget,
    stack::SharedStack,
    tcp::TcpStream,
    udp,
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    Address, BoxFuture, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Error, OpenedTcp, Outbound, Result, ServiceContext, ServiceFailure, ServiceStatus,
    TargetPolicy, TcpConnectInfo, is_peer_path_error,
};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Notify, time::MissedTickBehavior};

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: true,
    udp: true,
};

/// 只接收共享调度器已解析IP的原生WireGuard命名出站工厂。
pub struct WireGuardFactory;
struct WireGuardOutbound {
    stack: Arc<SharedStack>,
    status: ServiceStatus,
}
impl Drop for WireGuardOutbound {
    fn drop(&mut self) {
        self.stack.cancel.cancel();
    }
}
impl WireGuardOutbound {
    fn check(&self) -> Result<()> {
        if let Some(failure) = self.status.failure() {
            return Err(failure.error());
        }
        if self.stack.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
}
impl Outbound for WireGuardOutbound {
    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.stack.cancel.cancel();
            self.stack.close();
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
            self.check()?;
            let remote = target(remote)?;
            if !self.stack.allows(remote.ip()) {
                return Err(Error::Rejected);
            }
            let stream = TcpStream::connect(self.stack.clone(), remote, context).await?;
            let info = TcpConnectInfo::local_bound(stream.local_addr());
            Ok(OpenedTcp {
                stream: Box::new(stream),
                info,
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        remote: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            self.check()?;
            context
                .run(async { udp::fixed(self.stack.clone(), remote, context) })
                .await
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            self.check()?;
            context
                .run(async { udp::association(self.stack.clone(), context) })
                .await
        })
    }
}

impl OutboundFactory for WireGuardFactory {
    fn kind(&self) -> &'static str {
        "wireguard"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: ClientOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("WireGuard出站字段不合法".into()))?;
        let prepared = options.tunnel.prepare()?;
        let peer = options.peer.prepare()?;
        prepared.validate_peer(&peer)?;
        let endpoint = Destination::new(&options.endpoint.host, options.endpoint.port)?;
        if matches!(endpoint.address(), Address::Ip(ip) if !crate::config::unicast(*ip)) {
            return Err(Error::Config("WireGuard载体端点必须为单播地址".into()));
        }
        if let Some(bind) = options.bind
            && (bind.ip().is_multicast()
                || bind.ip().to_canonical() != bind.ip()
                || matches!(bind.ip(), IpAddr::V4(ip) if ip.is_broadcast()))
        {
            return Err(Error::Config("WireGuard载体绑定地址不合法".into()));
        }
        Ok(OutboundPlan::new(
            CAPABILITIES,
            true,
            TargetPolicy::Local,
            move |host| Box::pin(start(prepared, peer, endpoint, options.bind, host)),
        ))
    }
}

async fn start(
    prepared: Prepared,
    peer: PeerConfig,
    endpoint: Destination,
    bind: Option<SocketAddr>,
    host: ServiceContext,
) -> Result<Arc<dyn Outbound>> {
    let cancel = host.cancel();
    let selected = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(Error::Cancelled),
        result = resolve_endpoint(&endpoint, bind) => result?,
    };
    let bind = bind.unwrap_or_else(|| {
        SocketAddr::new(
            if selected.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        )
    });
    if bind.is_ipv4() != selected.is_ipv4() {
        return Err(Error::Config("WireGuard载体绑定与对端地址族不一致".into()));
    }
    let socket = UdpSocket::bind(bind).await?;
    let stack = SharedStack::new(
        &prepared,
        cancel.clone(),
        Arc::new(Notify::new()),
        peer.allowed.clone(),
        PacketBudget::new(prepared.limits.queue_packets, prepared.limits.queue_bytes),
    )?;
    let status = host.status();
    let runtime_stack = stack.clone();
    let runtime_host = host.clone();
    let index = PeerIndex::new(&prepared, std::slice::from_ref(&peer));
    let crypto = CryptoPeer::new(&prepared, &peer, 1, Some(selected), index.limiter.clone());
    let carrier = Carrier::Outbound(host.clone());
    host.spawn(async move {
        let guard = StackGuard(runtime_stack.clone());
        if let Err(error) = run(
            socket,
            prepared,
            peer,
            index,
            crypto,
            runtime_stack.clone(),
            carrier,
        )
        .await
            && !matches!(error, Error::Cancelled)
        {
            runtime_host.fail(runtime_failure(error));
            runtime_stack.cancel.cancel();
        }
        drop(guard);
    })?;
    Ok(Arc::new(WireGuardOutbound { stack, status }))
}
fn runtime_failure(error: Error) -> ServiceFailure {
    match error {
        Error::Timeout => ServiceFailure::Timeout,
        Error::Rejected => ServiceFailure::Rejected,
        Error::InvalidAddress => ServiceFailure::InvalidAddress,
        Error::ResourceLimit => ServiceFailure::ResourceLimit,
        Error::Protocol(message) | Error::Unsupported(message) => ServiceFailure::Protocol(message),
        Error::Io(error) => ServiceFailure::Io(error.kind(), "WireGuard载体运行失败"),
        _ => ServiceFailure::Protocol("WireGuard出站运行失败"),
    }
}
struct StackGuard(Arc<SharedStack>);
impl Drop for StackGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

async fn resolve_endpoint(endpoint: &Destination, bind: Option<SocketAddr>) -> Result<SocketAddr> {
    let mut addresses = match endpoint.address() {
        Address::Ip(ip) => vec![SocketAddr::new(*ip, endpoint.port())],
        Address::Domain(domain) => tokio::net::lookup_host((domain.as_str(), endpoint.port()))
            .await?
            .collect(),
    };
    addresses.retain(|address| {
        crate::config::unicast(address.ip())
            && bind.is_none_or(|bind| bind.is_ipv4() == address.is_ipv4())
    });
    addresses.sort_by_key(|address| address.is_ipv6());
    addresses.into_iter().next().ok_or(Error::InvalidAddress)
}

pub(crate) async fn send(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    packet: &[u8],
    cancel: &kerlico_core::CancellationToken,
    carrier: &Carrier,
) -> Result<()> {
    let count = tokio::select! { biased; _ = cancel.cancelled() => return Err(Error::Cancelled),
    result = socket.send_to(packet, endpoint) => result?, };
    carrier.record(count, 0);
    if count != packet.len() {
        return Err(Error::Protocol("WireGuard载体未发送完整数据报"));
    }
    Ok(())
}

pub(crate) async fn run(
    socket: UdpSocket,
    prepared: Prepared,
    peer: PeerConfig,
    index: PeerIndex,
    mut crypto: CryptoPeer,
    stack: Arc<SharedStack>,
    carrier: Carrier,
) -> Result<()> {
    let mut fragments = Reassembler::new(FragmentBudget::new(
        prepared.limits.fragment_packets,
        prepared.limits.fragment_bytes,
    ));
    let mut receive = vec![0; 65536];
    let mut timer = tokio::time::interval(Duration::from_millis(20));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! { biased;
            _ = stack.cancel.cancelled() => return Ok(()),
            _ = timer.tick() => {
                index.limiter.reset_count();
                fragments.expire(Instant::now());
                if let Some(packet) = crypto.tick()
                    && let Some(endpoint) = crypto.endpoint
                { send(&socket, endpoint, &packet, &stack.cancel, &carrier).await?; }
            }
            result = socket.recv_from(&mut receive) => {
                let (count, source) = match result {
                    Ok(value) => value,
                    Err(error) if is_peer_path_error(&error) => continue,
                    Err(error) => return Err(error.into()),
                };
                carrier.record(0, count);
                // 来源地址未经认证；回复发不出去只损失这一个数据报。
                match index.identify(source, &receive[..count]) {
                    Ok(Identified::Cookie(packet)) => { let _ = send(&socket, source, &packet, &stack.cancel, &carrier).await; }
                    Ok(Identified::Peer(_)) => {
                        if let Ok(received) = crypto.receive(source, &receive[..count]) {
                            for packet in received.network { let _ = send(&socket, source, &packet, &stack.cancel, &carrier).await; }
                            if let Some(packet) = received.plain { let _ = input(&stack, &peer, &mut fragments, &packet); }
                        }
                    }
                    Err(_) => {}
                }
            }
            _ = stack.notify.notified() => {}
        }
        stack.poll()?;
        if stack.has_output()
            && !crypto.ready()
            && let Some(packet) = crypto.initiate()
            && let Some(endpoint) = crypto.endpoint
        {
            send(&socket, endpoint, &packet, &stack.cancel, &carrier).await?;
        }
        if crypto.ready() {
            for packet in stack.drain(64)? {
                let destination = IpPacket::parse(&packet)?.target;
                if !peer.allows(destination) {
                    continue;
                }
                if let Some(wire) = crypto.encrypt(&packet)?
                    && let Some(endpoint) = crypto.endpoint
                {
                    send(&socket, endpoint, &wire, &stack.cancel, &carrier).await?;
                }
            }
            if stack.has_output() {
                stack.notify.notify_one();
            }
        }
    }
}
fn input(
    stack: &SharedStack,
    peer: &PeerConfig,
    fragments: &mut Reassembler,
    bytes: &[u8],
) -> Result<()> {
    let packet = IpPacket::parse(bytes)?;
    if !peer.allows(packet.source) || !stack.addresses.contains(packet.target) {
        return Err(Error::Rejected);
    }
    let Some(bytes) = fragments.accept(bytes, Instant::now())? else {
        return Ok(());
    };
    let packet = IpPacket::parse(&bytes)?;
    match packet.protocol {
        6 => stack.input_tcp(bytes),
        17 => stack.receive_udp(&packet),
        1 | 58 => {
            if let Some(reply) = control_reply(&bytes, &stack.addresses)? {
                stack.queue_packet(reply)?;
            }
            Ok(())
        }
        _ => Err(Error::Unsupported("WireGuard出站不提供该IP协议")),
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    #[tokio::test]
    async fn carrier_failure_keeps_stable_first_cause_without_dynamic_io_text() {
        let host = ServiceContext::for_test();
        let failure = runtime_failure(Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "dynamic upstream text",
        )));
        host.fail(failure);
        host.fail(runtime_failure(Error::Protocol("受控稍后协议失败")));
        assert_eq!(
            host.failure(),
            Some(ServiceFailure::Io(
                std::io::ErrorKind::ConnectionReset,
                "WireGuard载体运行失败"
            ))
        );
        assert!(
            matches!(host.failure().unwrap().error(),Error::Io(error) if error.kind()==std::io::ErrorKind::ConnectionReset && error.to_string()=="WireGuard载体运行失败")
        );
        host.shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
    }
}
