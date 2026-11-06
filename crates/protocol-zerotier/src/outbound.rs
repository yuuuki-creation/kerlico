use crate::{
    config::{ClientOptions, Prepared, TcpFallbackMode, build_node_options},
    interface::{Interface, Plan},
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, DialerOptions, Error, OpenedTcp, Outbound, Result,
    ServiceContext, ServiceFailure, ServiceStatus, TargetPolicy, is_peer_path_error,
};
use kerlico_wireguard::ip::ClientTunnel;
use serde_json::Value;
use std::{
    future::pending,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    time::MissedTickBehavior,
};
use zerotier_node::{Address, Event, IdentityCheck, IdentityVerdict, JoinStatus, Node};

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: true,
    udp: true,
};
const TICK_INTERVAL: Duration = Duration::from_millis(250);
const RECEIVE_BUFFER: usize = 16 * 1024;

/// 加入私有 ZeroTier 网络的命名出站；目标必须是调度器已解析的 IP。
pub struct ZeroTierFactory;

#[derive(Clone)]
enum Link {
    Joining,
    Ready(ClientTunnel),
    Refused,
}

struct ZeroTierOutbound {
    link: watch::Receiver<Link>,
    cancel: CancellationToken,
    status: ServiceStatus,
}

impl ZeroTierOutbound {
    /// 控制器尚未下发配置时等待至连接期限，被拒绝时立即失败。
    async fn tunnel(&self, context: &ConnectContext) -> Result<ClientTunnel> {
        if let Some(failure) = self.status.failure() {
            return Err(failure.error());
        }
        let mut link = self.link.clone();
        context
            .run(async move {
                let state = link
                    .wait_for(|state| !matches!(state, Link::Joining))
                    .await
                    .map_err(|_| Error::Cancelled)?;
                match &*state {
                    Link::Ready(tunnel) => Ok(tunnel.clone()),
                    _ => Err(Error::Rejected),
                }
            })
            .await
    }
}

impl Drop for ZeroTierOutbound {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Outbound for ZeroTierOutbound {
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
            let tunnel = self.tunnel(context).await?;
            tunnel.connect_tcp(remote, context).await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        remote: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let tunnel = self.tunnel(context).await?;
            tunnel.connect_udp(remote, context)
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            let tunnel = self.tunnel(context).await?;
            tunnel.associate_udp(context)
        })
    }
}

impl OutboundFactory for ZeroTierFactory {
    fn kind(&self) -> &'static str {
        "zerotier"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: ClientOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("ZeroTier出站字段不合法".into()))?;
        let prepared = options.prepare()?;
        let dialer = kerlico_core::current_compile_dialer();
        Ok(OutboundPlan::new(
            CAPABILITIES,
            true,
            TargetPolicy::Local,
            move |host| Box::pin(start(prepared, dialer, host)),
        ))
    }
}

/// 身份生成可能耗时数秒，放进后台任务，启动不因此超时；期间连接等待加入完成。
async fn start(
    prepared: Prepared,
    dialer: DialerOptions,
    host: ServiceContext,
) -> Result<Arc<dyn Outbound>> {
    let cancel = host.cancel();
    let (link_sender, link) = watch::channel(Link::Joining);
    let status = host.status();
    let runtime_host = host.clone();
    let outbound_cancel = cancel.clone();
    host.spawn(async move {
        if let Err(error) =
            drive(prepared, dialer, link_sender, &runtime_host, cancel.clone()).await
            && !matches!(error, Error::Cancelled)
        {
            runtime_host.fail(runtime_failure(error));
            cancel.cancel();
        }
    })?;
    Ok(Arc::new(ZeroTierOutbound {
        link,
        cancel: outbound_cancel,
        status,
    }))
}

async fn drive(
    prepared: Prepared,
    dialer: DialerOptions,
    link: watch::Sender<Link>,
    host: &ServiceContext,
    cancel: CancellationToken,
) -> Result<()> {
    let tcp_fallback_mode = prepared.tcp_fallback_mode;
    let tcp_fallback_relay = prepared.tcp_fallback_relay;
    let task = host.spawn_blocking_tracked(move || build_node_options(prepared))?;
    let (node_options, bind) = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(Error::Cancelled),
        result = task => result??,
    };
    let node = Node::new(node_options).map_err(|_| Error::Protocol("ZeroTier身份缺少私钥"))?;
    let node_address = node.address();
    // Node 限制在途校验数，通道长度因此有界。
    let (verdict_sender, verdicts) = mpsc::unbounded_channel();
    let mut driver = Driver {
        clock: Clock::new(),
        node,
        sockets: Sockets::bind(&dialer, bind, stable_port(node_address))?,
        tcp_fallback_mode,
        tcp_fallback_relay,
        interface: None,
        link,
        cancel,
        host: host.clone(),
        verdict_sender,
        verdicts,
    };
    let result = driver.run().await;
    driver.close_interface();
    result
}

fn runtime_failure(error: Error) -> ServiceFailure {
    match error {
        Error::Timeout => ServiceFailure::Timeout,
        Error::Rejected => ServiceFailure::Rejected,
        Error::InvalidAddress => ServiceFailure::InvalidAddress,
        Error::ResourceLimit => ServiceFailure::ResourceLimit,
        Error::Protocol(message) | Error::Unsupported(message) => ServiceFailure::Protocol(message),
        Error::Io(error) => ServiceFailure::Io(error.kind(), "ZeroTier载体运行失败"),
        _ => ServiceFailure::Protocol("ZeroTier出站运行失败"),
    }
}

/// 墙上时钟起点加单调增量：时间戳可与对端对照，定时器不受时钟跳变影响。
struct Clock {
    started: Instant,
    base: i64,
}

impl Clock {
    fn new() -> Self {
        let base = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as i64);
        Self {
            started: Instant::now(),
            base,
        }
    }
    fn now(&self) -> i64 {
        self.base + self.started.elapsed().as_millis() as i64
    }
}

struct Sockets {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
}

/// 对端在旧路径存活期间（约 30 秒）不会学习同一 IP 的新端口。默认端口由身份固定，
/// 重启后沿用旧路径，不必等它过期。
fn stable_port(address: Address) -> u16 {
    20000 + (address.value() % 45000) as u16
}

fn bind_preferring(dialer: &DialerOptions, ip: IpAddr, port: u16) -> std::io::Result<UdpSocket> {
    let socket = match dialer.udp_socket(SocketAddr::new(ip, port)) {
        Ok(socket) => socket,
        Err(_) => dialer.udp_socket(SocketAddr::new(ip, 0))?,
    };
    UdpSocket::from_std(socket)
}

fn bind_exact(dialer: &DialerOptions, address: SocketAddr) -> Result<Option<UdpSocket>> {
    Ok(Some(UdpSocket::from_std(dialer.udp_socket(address)?)?))
}

impl Sockets {
    fn bind(dialer: &DialerOptions, bind: Option<SocketAddr>, default_port: u16) -> Result<Self> {
        match bind {
            Some(address) if address.is_ipv4() => Ok(Self {
                v4: bind_exact(dialer, address)?,
                v6: None,
            }),
            Some(address) => Ok(Self {
                v4: None,
                v6: bind_exact(dialer, address)?,
            }),
            None => {
                let v4 = bind_preferring(
                    dialer,
                    IpAddr::V4(dialer.bind_v4.unwrap_or(Ipv4Addr::UNSPECIFIED)),
                    default_port,
                );
                let v6 = bind_preferring(
                    dialer,
                    IpAddr::V6(dialer.bind_v6.unwrap_or(Ipv6Addr::UNSPECIFIED)),
                    default_port,
                );
                match (v4, v6) {
                    (Err(error), Err(_)) => Err(error.into()),
                    (v4, v6) => Ok(Self {
                        v4: v4.ok(),
                        v6: v6.ok(),
                    }),
                }
            }
        }
    }

    fn for_address(&self, address: SocketAddr) -> Option<&UdpSocket> {
        if address.is_ipv4() {
            self.v4.as_ref()
        } else {
            self.v6.as_ref()
        }
    }
}

async fn receive(
    socket: Option<&UdpSocket>,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => pending().await,
    }
}

async fn next_packet(interface: Option<&Interface>) -> Result<Vec<u8>> {
    match interface {
        Some(interface) => interface.tunnel.next_packet().await,
        None => pending().await,
    }
}

struct Driver {
    clock: Clock,
    node: Node,
    sockets: Sockets,
    tcp_fallback_mode: TcpFallbackMode,
    tcp_fallback_relay: Option<SocketAddr>,
    interface: Option<Interface>,
    link: watch::Sender<Link>,
    cancel: CancellationToken,
    host: ServiceContext,
    verdict_sender: mpsc::UnboundedSender<IdentityVerdict>,
    verdicts: mpsc::UnboundedReceiver<IdentityVerdict>,
}

impl Driver {
    async fn run(&mut self) -> Result<()> {
        let mut buffer_v4 = vec![0; RECEIVE_BUFFER];
        let mut buffer_v6 = vec![0; RECEIVE_BUFFER];
        let mut timer = tokio::time::interval(TICK_INTERVAL);
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            // 不用 biased：入站突发不能饿死 IP 栈的出站包。
            tokio::select! {
                _ = self.cancel.cancelled() => return Ok(()),
                _ = timer.tick() => {
                    let now = self.clock.now();
                    self.node.tick(now);
                    if let Some(interface) = &mut self.interface {
                        interface.tick(&mut self.node, now);
                    }
                }
                result = receive(self.sockets.v4.as_ref(), &mut buffer_v4) => {
                    self.on_receive(result, &buffer_v4)?;
                }
                result = receive(self.sockets.v6.as_ref(), &mut buffer_v6) => {
                    self.on_receive(result, &buffer_v6)?;
                }
                result = next_packet(self.interface.as_ref()) => {
                    if let (Ok(packet), Some(interface)) = (result, &mut self.interface) {
                        interface.send_ip(&mut self.node, self.clock.now(), packet);
                    }
                }
                Some(verdict) = self.verdicts.recv() => {
                    self.node.on_identity_verdict(self.clock.now(), verdict);
                }
            }
            self.drain().await;
        }
    }

    fn on_receive(
        &mut self,
        result: std::io::Result<(usize, SocketAddr)>,
        buffer: &[u8],
    ) -> Result<()> {
        match result {
            Ok((count, from)) => {
                self.host.record_carrier(0, count as u64);
                self.node
                    .on_datagram(self.clock.now(), from, &buffer[..count]);
                Ok(())
            }
            Err(error) if is_peer_path_error(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn drain(&mut self) {
        while let Some(event) = self.node.poll_event() {
            match event {
                Event::Datagram { to, data } => {
                    let target = if self.tcp_fallback_mode == TcpFallbackMode::Always {
                        self.tcp_fallback_relay.unwrap_or(to)
                    } else {
                        to
                    };
                    if let Some(socket) = self.sockets.for_address(target)
                        && let Ok(sent) = socket.send_to(&data, target).await
                    {
                        self.host.record_carrier(sent as u64, 0);
                    }
                }
                Event::Frame(frame) => {
                    if let Some(interface) = &mut self.interface {
                        interface.receive(&mut self.node, self.clock.now(), frame);
                    }
                }
                Event::Config(_) | Event::Status(_) => self.sync_link(),
                Event::IdentityCheck(check) => self.start_identity_check(check),
            }
        }
    }

    /// 工作量校验要一次内存密集哈希，不能占用数据面任务。任务未能启动时 Node 按超时释放名额。
    fn start_identity_check(&self, check: IdentityCheck) {
        let verdicts = self.verdict_sender.clone();
        let _ = self.host.spawn_blocking_tracked(move || {
            let _ = verdicts.send(check.run());
        });
    }

    /// 让数据面跟随加入状态：地址或路由变化时重建 IP 栈，被拒绝时关闭。
    fn sync_link(&mut self) {
        match self.node.status() {
            JoinStatus::Requesting => {}
            JoinStatus::Joined => {
                let Some(config) = self.node.config().cloned() else {
                    return;
                };
                let Some(plan) = Plan::from_config(&config) else {
                    self.close_interface();
                    self.link.send_replace(Link::Joining);
                    return;
                };
                if let Some(interface) = &mut self.interface
                    && interface.plan == plan
                {
                    interface.update_config(config);
                    self.link
                        .send_replace(Link::Ready(interface.tunnel.clone()));
                    return;
                }
                self.close_interface();
                match Interface::new(plan, config, self.node.mac(), &self.cancel) {
                    Ok(interface) => {
                        self.link
                            .send_replace(Link::Ready(interface.tunnel.clone()));
                        self.interface = Some(interface);
                    }
                    Err(_) => {
                        self.link.send_replace(Link::Refused);
                    }
                }
            }
            _ => {
                self.close_interface();
                self.link.send_replace(Link::Refused);
            }
        }
    }

    fn close_interface(&mut self) {
        if let Some(interface) = self.interface.take() {
            interface.tunnel.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_is_stable_and_outside_privileged_range() {
        for value in [1u64, 0x6c_386d_c869, 0xfe_ffff_ffff] {
            let port = stable_port(Address::new(value));
            assert_eq!(port, stable_port(Address::new(value)));
            assert!((20000..65000).contains(&port));
        }
    }

    #[test]
    fn runtime_failures_keep_static_diagnostics() {
        assert!(matches!(
            runtime_failure(Error::Protocol("ZeroTier身份文件读写失败")),
            ServiceFailure::Protocol("ZeroTier身份文件读写失败")
        ));
        assert!(matches!(
            runtime_failure(Error::Config("dynamic".into())),
            ServiceFailure::Protocol("ZeroTier出站运行失败")
        ));
    }
}
