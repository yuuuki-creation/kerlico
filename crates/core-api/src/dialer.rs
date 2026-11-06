//! 出站套接字工厂：所有出站 TCP 连接与 UDP 套接字经 [`DialerOptions`] 创建。
//!
//! 工厂统一施加链式拨号、路由标记、出口接口、源地址、TCP Fast Open、MPTCP 与 Keep-Alive，
//! 选项施加失败时返回错误，不静默降级。入站监听套接字不经过本模块。

use crate::{
    Address, BoxFuture, BoxStream, ConnectContext, Destination, Error, OutId, Outbound, Result,
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// RFC 8305 连接尝试间隔的默认值，与 sing-box `fallback_delay` 默认一致。
pub const DEFAULT_FALLBACK_DELAY: Duration = Duration::from_millis(300);
const DETOUR_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// 按名称解析上游出站实例，供链式拨号（`detour` / `dialer-proxy`）在连接阶段调用。
pub trait DetourResolver: Send + Sync {
    fn resolve_outbound(&self, id: &OutId) -> Option<Arc<dyn Outbound>>;
}

/// 线程安全的命名出站注册表，由引擎启动出站时填充，供链式拨号查询。
#[derive(Default)]
pub struct DetourTable {
    services: std::sync::RwLock<std::collections::BTreeMap<OutId, Arc<dyn Outbound>>>,
}

impl DetourTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn insert(&self, id: OutId, outbound: Arc<dyn Outbound>) {
        self.services
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, outbound);
    }
}

impl DetourResolver for DetourTable {
    fn resolve_outbound(&self, id: &OutId) -> Option<Arc<dyn Outbound>> {
        self.services
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }
}

/// 出站套接字绑定的出口网卡。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceBinding {
    /// 固定网卡名（Mihomo `interface-name`、sing-box `bind_interface`）。
    Named(String),
    /// 每次建套接字时取默认路由所在网卡，跳过 `exclude` 中的网卡（例如本机 TUN）。
    AutoDetect { exclude: Vec<String> },
}

/// 出站底层拨号与套接字选项。
#[derive(Clone, Default)]
pub struct DialerOptions {
    pub detour: Option<OutId>,
    pub routing_mark: Option<u32>,
    pub interface: Option<InterfaceBinding>,
    pub bind_v4: Option<Ipv4Addr>,
    pub bind_v6: Option<Ipv6Addr>,
    pub tcp_fast_open: bool,
    pub mptcp: bool,
    pub disable_tcp_keep_alive: bool,
    pub tcp_keep_alive_idle: Option<Duration>,
    pub tcp_keep_alive_interval: Option<Duration>,
    pub fallback_delay: Option<Duration>,
    pub detour_resolver: Option<Arc<dyn DetourResolver>>,
}

impl fmt::Debug for DialerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DialerOptions")
            .field("detour", &self.detour)
            .field("routing_mark", &self.routing_mark)
            .field("interface", &self.interface)
            .field("bind_v4", &self.bind_v4)
            .field("bind_v6", &self.bind_v6)
            .field("tcp_fast_open", &self.tcp_fast_open)
            .field("mptcp", &self.mptcp)
            .field("disable_tcp_keep_alive", &self.disable_tcp_keep_alive)
            .field("tcp_keep_alive_idle", &self.tcp_keep_alive_idle)
            .field("tcp_keep_alive_interval", &self.tcp_keep_alive_interval)
            .field("fallback_delay", &self.fallback_delay)
            .finish()
    }
}

/// 一个面向固定对端的 UDP 套接字。配置 `detour` 时 `peer` 是本机回环中继地址，
/// 中继把数据报经上游出站的 UDP 通道转发到真实服务端；`relay` 丢弃时中继停止。
pub struct UdpPeer {
    pub socket: std::net::UdpSocket,
    pub peer: SocketAddr,
    pub relay: Option<RelayGuard>,
}

/// 链式 UDP 中继的生命周期句柄。
pub struct RelayGuard(#[allow(dead_code)] tokio_util::sync::DropGuard);

impl DialerOptions {
    /// 是否所有选项都取默认值，即建出的套接字与操作系统默认套接字相同。
    pub fn is_default(&self) -> bool {
        self.detour.is_none()
            && self.routing_mark.is_none()
            && self.interface.is_none()
            && self.bind_v4.is_none()
            && self.bind_v6.is_none()
            && !self.tcp_fast_open
            && !self.mptcp
            && !self.disable_tcp_keep_alive
            && self.tcp_keep_alive_idle.is_none()
            && self.tcp_keep_alive_interval.is_none()
    }

    pub fn has_detour(&self) -> bool {
        self.detour.is_some()
    }

    pub fn fallback_delay(&self) -> Duration {
        self.fallback_delay.unwrap_or(DEFAULT_FALLBACK_DELAY)
    }

    /// 在配置加载阶段拒绝当前平台无法施加的选项，避免运行时逐连接失败。
    pub fn validate_platform(&self) -> Result<()> {
        let linux = cfg!(target_os = "linux");
        let apple = cfg!(any(target_os = "macos", target_os = "ios"));
        if self.routing_mark.is_some() && !linux {
            return Err(Error::Config("routing_mark 仅支持 Linux".into()));
        }
        if self.tcp_fast_open && !linux {
            return Err(Error::Config("tcp_fast_open 仅支持 Linux".into()));
        }
        if self.mptcp && !linux {
            return Err(Error::Config("mptcp 仅支持 Linux".into()));
        }
        match &self.interface {
            Some(InterfaceBinding::Named(name)) => {
                if name.is_empty() || name.len() > 15 {
                    return Err(Error::Config("绑定网卡名不合法".into()));
                }
                if !linux && !apple {
                    return Err(Error::Config("绑定网卡仅支持 Linux 与 macOS".into()));
                }
            }
            Some(InterfaceBinding::AutoDetect { .. }) if !linux => {
                return Err(Error::Config("auto_detect_interface 仅支持 Linux".into()));
            }
            _ => {}
        }
        Ok(())
    }

    /// 创建已施加全部选项、尚未连接的 TCP 套接字；不处理 `detour`。
    pub fn tcp_socket(&self, peer: SocketAddr) -> io::Result<TcpSocket> {
        let domain = socket2::Domain::for_address(peer);
        let socket = self.stream_socket(domain)?;
        let interface = self.resolve_interface()?;
        apply_common(&socket, self.routing_mark, interface.as_deref())?;
        self.bind_source(&socket, peer)?;
        #[cfg(target_os = "linux")]
        if self.tcp_fast_open {
            set_fastopen_connect(&socket)?;
        }
        if self.disable_tcp_keep_alive {
            socket.set_keepalive(false)?;
        } else if self.tcp_keep_alive_idle.is_some() || self.tcp_keep_alive_interval.is_some() {
            let mut keepalive = socket2::TcpKeepalive::new()
                .with_time(self.tcp_keep_alive_idle.unwrap_or(Duration::from_secs(15)));
            if let Some(interval) = self.tcp_keep_alive_interval {
                keepalive = keepalive.with_interval(interval);
            }
            socket.set_tcp_keepalive(&keepalive)?;
        }
        socket.set_nonblocking(true)?;
        probe::record(&socket, probe::SocketKind::Tcp, interface);
        Ok(TcpSocket::from_std_stream(socket.into()))
    }

    /// 经操作系统套接字连接字面地址，启用 `TCP_NODELAY`；不处理 `detour`。
    pub async fn connect_addr(&self, peer: SocketAddr) -> io::Result<TcpStream> {
        let stream = self.tcp_socket(peer)?.connect(peer).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// 建立到代理端点的 TCP 字节流：配置 `detour` 时经上游出站建立，否则解析域名后按
    /// RFC 8305 交错地址族、以 `fallback_delay` 为间隔并行尝试。
    pub async fn connect(&self, server: &Destination) -> Result<BoxStream> {
        if let Some(upstream) = self.detour_outbound()? {
            return connect_via(upstream, server).await;
        }
        let addresses = resolve(server).await?;
        let (stream, _) = happy_eyeballs(addresses, self.fallback_delay(), |peer| async move {
            Ok(self.connect_addr(peer).await?)
        })
        .await?;
        Ok(Box::new(stream))
    }

    /// 创建已施加标记、出口网卡与源地址并绑定到 `local` 的非阻塞 UDP 套接字；不处理 `detour`。
    pub fn udp_socket(&self, local: SocketAddr) -> io::Result<std::net::UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(local),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        self.finish_udp(socket, local)
    }

    /// 创建与 `peer` 同地址族、绑定通配地址的 UDP 套接字；源地址取 `bind_v4`/`bind_v6`。
    pub fn udp_socket_for(&self, peer: SocketAddr) -> io::Result<std::net::UdpSocket> {
        let local = match peer {
            SocketAddr::V4(_) => {
                SocketAddr::from((self.bind_v4.unwrap_or(Ipv4Addr::UNSPECIFIED), 0))
            }
            SocketAddr::V6(_) => {
                SocketAddr::from((self.bind_v6.unwrap_or(Ipv6Addr::UNSPECIFIED), 0))
            }
        };
        self.udp_socket(local)
    }

    /// 创建 IPv6 通配 UDP 套接字；`only_v6` 为假时同时收发 IPv4 映射地址。
    pub fn udp_socket_dual(&self, only_v6: bool) -> io::Result<std::net::UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_only_v6(only_v6)?;
        self.finish_udp(socket, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
    }

    /// 为固定对端准备 UDP 套接字。未配置 `detour` 时解析服务端并返回真实地址；配置后
    /// 经上游出站的固定目标 UDP 通道转发，服务端域名交给上游解析。
    pub async fn udp_peer(&self, server: &Destination) -> Result<UdpPeer> {
        if let Some(upstream) = self.detour_outbound()? {
            return relay_via(upstream, server).await;
        }
        let mut addresses = resolve(server).await?;
        addresses.sort_by_key(SocketAddr::is_ipv6);
        let peer = *addresses.first().ok_or(Error::InvalidAddress)?;
        Ok(UdpPeer {
            socket: self.udp_socket_for(peer)?,
            peer,
            relay: None,
        })
    }

    fn detour_outbound(&self) -> Result<Option<Arc<dyn Outbound>>> {
        let Some(id) = &self.detour else {
            return Ok(None);
        };
        let resolver = self
            .detour_resolver
            .as_ref()
            .ok_or_else(|| Error::Config("链式拨号缺少上游解析表".into()))?;
        resolver
            .resolve_outbound(id)
            .map(Some)
            .ok_or_else(|| Error::Config("链式拨号引用的上游出站不存在或未启动".into()))
    }

    fn finish_udp(
        &self,
        socket: socket2::Socket,
        local: SocketAddr,
    ) -> io::Result<std::net::UdpSocket> {
        let interface = self.resolve_interface()?;
        apply_common(&socket, self.routing_mark, interface.as_deref())?;
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;
        probe::record(&socket, probe::SocketKind::Udp, interface);
        Ok(socket.into())
    }

    fn stream_socket(&self, domain: socket2::Domain) -> io::Result<socket2::Socket> {
        #[cfg(target_os = "linux")]
        if self.mptcp {
            match socket2::Socket::new(
                domain,
                socket2::Type::STREAM,
                Some(socket2::Protocol::MPTCP),
            ) {
                Ok(socket) => return Ok(socket),
                // 与 Go `SetMultipathTCP` 相同：内核未启用 MPTCP 时改用普通 TCP。
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(errno) if errno == nix::errno::Errno::EPROTONOSUPPORT as i32
                            || errno == nix::errno::Errno::ENOPROTOOPT as i32
                            || errno == nix::errno::Errno::EINVAL as i32
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
    }

    fn bind_source(&self, socket: &socket2::Socket, peer: SocketAddr) -> io::Result<()> {
        let source: Option<IpAddr> = match peer {
            SocketAddr::V4(_) => self.bind_v4.map(IpAddr::V4),
            SocketAddr::V6(_) => self.bind_v6.map(IpAddr::V6),
        };
        if let Some(ip) = source {
            socket.bind(&SocketAddr::new(ip, 0).into())?;
        }
        Ok(())
    }

    fn resolve_interface(&self) -> io::Result<Option<String>> {
        match &self.interface {
            None => Ok(None),
            Some(InterfaceBinding::Named(name)) => Ok(Some(name.clone())),
            Some(InterfaceBinding::AutoDetect { exclude }) => default_route::interface(exclude),
        }
    }
}

fn apply_common(
    socket: &socket2::Socket,
    mark: Option<u32>,
    interface: Option<&str>,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if let Some(name) = interface {
            socket.bind_device(Some(name.as_bytes()))?;
        }
        if let Some(mark) = mark {
            socket.set_mark(mark)?;
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if let Some(name) = interface {
            let index = interface_index(name)?;
            if socket.domain()? == socket2::Domain::IPV6 {
                socket.bind_device_by_index_v6(Some(index))?;
            } else {
                socket.bind_device_by_index_v4(Some(index))?;
            }
        }
        if mark.is_some() {
            return Err(unsupported("routing_mark"));
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
    {
        if interface.is_some() {
            return Err(unsupported("interface"));
        }
        if mark.is_some() {
            return Err(unsupported("routing_mark"));
        }
        let _ = socket;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn unsupported(option: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{option} 在当前平台不可用"),
    )
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn interface_index(name: &str) -> io::Result<std::num::NonZeroU32> {
    let index = nix::net::if_::if_nametoindex(name).map_err(io::Error::from)?;
    std::num::NonZeroU32::new(index).ok_or_else(|| io::ErrorKind::NotFound.into())
}

#[cfg(target_os = "linux")]
fn set_fastopen_connect(socket: &socket2::Socket) -> io::Result<()> {
    nix::sys::socket::setsockopt(socket, nix::sys::socket::sockopt::TcpFastOpenConnect, &true)
        .map_err(io::Error::from)
}

/// 读取套接字的 `TCP_FASTOPEN_CONNECT` 状态，供测试与诊断。
#[cfg(target_os = "linux")]
pub fn fastopen_connect_enabled(socket: &impl std::os::fd::AsFd) -> io::Result<bool> {
    nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::TcpFastOpenConnect)
        .map_err(io::Error::from)
}

async fn resolve(server: &Destination) -> Result<Vec<SocketAddr>> {
    let addresses: Vec<SocketAddr> = match server.address() {
        Address::Ip(ip) => vec![SocketAddr::new(*ip, server.port())],
        Address::Domain(host) => crate::lookup_host((host.as_str(), server.port()))
            .await?
            .collect(),
    };
    if addresses.is_empty() {
        return Err(Error::InvalidAddress);
    }
    Ok(addresses)
}

async fn connect_via(upstream: Arc<dyn Outbound>, server: &Destination) -> Result<BoxStream> {
    let context = ConnectContext::new(DETOUR_SETUP_TIMEOUT);
    match upstream.connect_tcp(server, &context).await {
        Ok(opened) => Ok(opened.stream),
        // 上游只接受字面地址（例如直连后端）时，本机解析后再交给上游。
        Err(Error::Unsupported(_)) if matches!(server.address(), Address::Domain(_)) => {
            let peer = *resolve(server)
                .await?
                .first()
                .ok_or(Error::InvalidAddress)?;
            let literal = Destination::new(&peer.ip().to_string(), peer.port())?;
            Ok(upstream.connect_tcp(&literal, &context).await?.stream)
        }
        Err(error) => Err(error),
    }
}

async fn relay_via(upstream: Arc<dyn Outbound>, server: &Destination) -> Result<UdpPeer> {
    let context = ConnectContext::new(DETOUR_SETUP_TIMEOUT);
    let channel = match upstream.connect_udp(server, &context).await {
        Ok(channel) => channel,
        Err(Error::Unsupported(_)) if matches!(server.address(), Address::Domain(_)) => {
            let peer = *resolve(server)
                .await?
                .first()
                .ok_or(Error::InvalidAddress)?;
            let literal = Destination::new(&peer.ip().to_string(), peer.port())?;
            upstream.connect_udp(&literal, &context).await?
        }
        Err(error) => return Err(error),
    };
    // 中继套接字只在本机回环收发，不进入出站路由，故不施加标记与出口网卡。
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let relay = Arc::new(UdpSocket::bind(loopback).await?);
    let client = std::net::UdpSocket::bind(loopback)?;
    client.set_nonblocking(true)?;
    let client_addr = client.local_addr()?;
    let peer = relay.local_addr()?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let crate::DatagramChannel {
        mut sender,
        mut receiver,
    } = channel;
    let outbound_relay = relay.clone();
    let outbound_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let received = tokio::select! {
                _ = outbound_cancel.cancelled() => break,
                received = outbound_relay.recv_from(&mut buffer) => received,
            };
            match received {
                Ok((length, source)) if source == client_addr => {
                    if sender.send(&buffer[..length]).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        outbound_cancel.cancel();
    });
    let inbound_cancel = cancel.clone();
    tokio::spawn(async move {
        loop {
            let received = tokio::select! {
                _ = inbound_cancel.cancelled() => break,
                received = receiver.recv() => received,
            };
            match received {
                Ok(Some(packet)) => {
                    if relay.send_to(&packet, client_addr).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        inbound_cancel.cancel();
    });
    Ok(UdpPeer {
        socket: client,
        peer,
        relay: Some(RelayGuard(cancel.drop_guard())),
    })
}

/// 按 RFC 8305 交错地址族：从首个地址的地址族开始，两族轮流。
pub fn interleave_families<T>(items: Vec<T>, is_v6: impl Fn(&T) -> bool) -> Vec<T> {
    let Some(first_v6) = items.first().map(&is_v6) else {
        return items;
    };
    let (mut primary, mut secondary): (Vec<T>, Vec<T>) =
        items.into_iter().partition(|item| is_v6(item) == first_v6);
    let mut ordered = Vec::with_capacity(primary.len() + secondary.len());
    primary.reverse();
    secondary.reverse();
    loop {
        match (primary.pop(), secondary.pop()) {
            (None, None) => return ordered,
            (a, b) => ordered.extend(a.into_iter().chain(b)),
        }
    }
}

/// RFC 8305 连接竞速：依次启动尝试，前一个失败或等待 `delay` 后启动下一个，返回首个成功。
///
/// `Io` 与 `Timeout` 视为该地址不可达并继续；其他错误立即返回。
pub async fn happy_eyeballs<A, T, F, Fut>(
    candidates: Vec<A>,
    delay: Duration,
    attempt: F,
) -> Result<(T, A)>
where
    A: Clone,
    F: Fn(A) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut queue = candidates.into_iter();
    let start = |candidate: A| {
        let future = attempt(candidate.clone());
        async move { (future.await, candidate) }
    };
    let mut running = FuturesUnordered::new();
    let mut last = Error::InvalidAddress;
    match queue.next() {
        Some(candidate) => running.push(start(candidate)),
        None => return Err(last),
    }
    loop {
        let has_more = queue.len() > 0;
        tokio::select! {
            finished = running.next() => match finished {
                Some((Ok(value), candidate)) => return Ok((value, candidate)),
                Some((Err(error @ (Error::Io(_) | Error::Timeout)), _)) => {
                    last = error;
                    match queue.next() {
                        Some(candidate) => running.push(start(candidate)),
                        None if running.is_empty() => return Err(last),
                        None => {}
                    }
                }
                Some((Err(error), _)) => return Err(error),
                None => return Err(last),
            },
            _ = tokio::time::sleep(delay), if has_more => {
                if let Some(candidate) = queue.next() {
                    running.push(start(candidate));
                }
            }
        }
    }
}

/// 读取 Linux 默认路由所在网卡，结果缓存一秒，路由变化在一秒内生效。
mod default_route {
    use std::io;

    #[cfg(target_os = "linux")]
    pub fn interface(exclude: &[String]) -> io::Result<Option<String>> {
        use std::sync::Mutex;
        use std::time::{Duration, Instant};
        struct Detected {
            at: Instant,
            exclude: Vec<String>,
            name: Option<String>,
        }
        static CACHE: Mutex<Option<Detected>> = Mutex::new(None);
        let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = cache.as_ref().is_some_and(|hit| {
            hit.at.elapsed() < Duration::from_secs(1) && hit.exclude.as_slice() == exclude
        });
        if !fresh {
            *cache = Some(Detected {
                at: Instant::now(),
                exclude: exclude.to_vec(),
                name: detect(exclude)?,
            });
        }
        match cache.as_ref().and_then(|hit| hit.name.clone()) {
            Some(name) => Ok(Some(name)),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "auto_detect_interface 未找到默认路由网卡",
            )),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn interface(_exclude: &[String]) -> io::Result<Option<String>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "auto_detect_interface 仅支持 Linux",
        ))
    }

    #[cfg(target_os = "linux")]
    fn detect(exclude: &[String]) -> io::Result<Option<String>> {
        let v4 = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
        if let Some(name) = pick_v4(&v4, exclude) {
            return Ok(Some(name));
        }
        let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
        Ok(pick_v6(&v6, exclude))
    }

    /// `/proc/net/route`：目的与掩码都为 0 的行是默认路由，取度量最小者。
    pub fn pick_v4(table: &str, exclude: &[String]) -> Option<String> {
        table
            .lines()
            .skip(1)
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let (name, destination, flags, metric, mask) = (
                    fields.first()?,
                    fields.get(1)?,
                    fields.get(3)?,
                    fields.get(6)?,
                    fields.get(7)?,
                );
                let up = u32::from_str_radix(flags, 16).ok()? & 1 == 1;
                (up && *destination == "00000000" && *mask == "00000000")
                    .then(|| (metric.parse::<u32>().unwrap_or(u32::MAX), name.to_string()))
            })
            .filter(|(_, name)| !exclude.contains(name))
            .min()
            .map(|(_, name)| name)
    }

    /// `/proc/net/ipv6_route`：目的前缀长度为 0 的行是默认路由，跳过 `lo`。
    pub fn pick_v6(table: &str, exclude: &[String]) -> Option<String> {
        table
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let (destination, prefix, metric, name) = (
                    fields.first()?,
                    fields.get(1)?,
                    fields.get(5)?,
                    fields.get(9)?,
                );
                (destination.chars().all(|c| c == '0') && *prefix == "00" && *name != "lo").then(
                    || {
                        (
                            u32::from_str_radix(metric, 16).unwrap_or(u32::MAX),
                            name.to_string(),
                        )
                    },
                )
            })
            .filter(|(_, name)| !exclude.contains(name))
            .min()
            .map(|(_, name)| name)
    }
}

std::thread_local! {
    static COMPILE_DIALER: std::cell::RefCell<DialerOptions> = std::cell::RefCell::new(DialerOptions::default());
}

/// 在编译单个出站期间注入当前出站的拨号配置，出站在编译阶段用
/// [`current_compile_dialer`] 取得并保存，运行期据此创建套接字。
pub fn with_compile_dialer<T>(dialer: DialerOptions, f: impl FnOnce() -> T) -> T {
    struct Reset(DialerOptions);
    impl Drop for Reset {
        fn drop(&mut self) {
            COMPILE_DIALER.with(|cell| *cell.borrow_mut() = std::mem::take(&mut self.0));
        }
    }
    let prev = COMPILE_DIALER.with(|cell| std::mem::replace(&mut *cell.borrow_mut(), dialer));
    let _reset = Reset(prev);
    f()
}

/// 读取当前出站编译上下文中的拨号配置。
pub fn current_compile_dialer() -> DialerOptions {
    COMPILE_DIALER.with(|cell| cell.borrow().clone())
}

/// 工厂创建套接字的观测点。启用 `dialer-probe` 特性时记录每个套接字从内核读回的选项，
/// 测试按唯一的路由标记取回记录；未启用时为空操作。
pub mod probe {
    /// 套接字类型。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SocketKind {
        Tcp,
        Udp,
    }

    /// 一个工厂套接字在施加选项后从内核读回的状态。
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SocketRecord {
        pub kind: SocketKind,
        pub mark: Option<u32>,
        pub interface: Option<String>,
        pub tcp_fast_open: bool,
    }

    #[cfg(feature = "dialer-probe")]
    static RECORDS: std::sync::Mutex<Vec<SocketRecord>> = std::sync::Mutex::new(Vec::new());

    #[cfg(feature = "dialer-probe")]
    pub(super) fn record(socket: &socket2::Socket, kind: SocketKind, interface: Option<String>) {
        #[cfg(target_os = "linux")]
        let (mark, tcp_fast_open) = (
            socket.mark().ok().filter(|mark| *mark != 0),
            kind == SocketKind::Tcp && super::fastopen_connect_enabled(socket).unwrap_or(false),
        );
        #[cfg(not(target_os = "linux"))]
        let (mark, tcp_fast_open) = (None, false);
        RECORDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(SocketRecord {
                kind,
                mark,
                interface,
                tcp_fast_open,
            });
    }

    #[cfg(not(feature = "dialer-probe"))]
    pub(super) fn record(_socket: &socket2::Socket, _kind: SocketKind, _interface: Option<String>) {
    }

    /// 取出并移除带指定标记的记录。
    #[cfg(feature = "dialer-probe")]
    pub fn take(mark: u32) -> Vec<SocketRecord> {
        let mut records = RECORDS.lock().unwrap_or_else(|e| e.into_inner());
        let (taken, kept) = records.drain(..).partition(|r| r.mark == Some(mark));
        *records = kept;
        taken
    }
}

/// 经 [`DialerOptions`] 建立 TCP 载体的 [`crate::StreamConnector`]。
impl crate::StreamConnector for DialerOptions {
    fn connect_tcp<'a>(
        &'a self,
        endpoint: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(context.run(self.connect(endpoint)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleave_alternates_from_first_family() {
        let v6 = |n: u16| SocketAddr::from((Ipv6Addr::LOCALHOST, n));
        let v4 = |n: u16| SocketAddr::from((Ipv4Addr::LOCALHOST, n));
        let ordered = interleave_families(vec![v6(1), v6(2), v6(3), v4(4)], SocketAddr::is_ipv6);
        assert_eq!(ordered, vec![v6(1), v4(4), v6(2), v6(3)]);
    }

    #[tokio::test]
    async fn happy_eyeballs_starts_next_after_delay_when_first_hangs() {
        let started = std::time::Instant::now();
        let (value, picked) =
            happy_eyeballs(vec![6u8, 4], Duration::from_millis(50), |n| async move {
                if n == 6 {
                    std::future::pending::<()>().await;
                }
                Ok(n)
            })
            .await
            .unwrap();
        assert_eq!((value, picked), (4, 4));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "第二个尝试没有按间隔启动"
        );
    }

    #[tokio::test]
    async fn happy_eyeballs_moves_on_immediately_after_failure() {
        let started = std::time::Instant::now();
        let (value, _) = happy_eyeballs(vec![1u8, 2], Duration::from_secs(5), |n| async move {
            if n == 1 {
                return Err(Error::Io(io::ErrorKind::ConnectionRefused.into()));
            }
            Ok(n)
        })
        .await
        .unwrap();
        assert_eq!(value, 2);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "失败后没有立即尝试下一个"
        );
    }

    #[tokio::test]
    async fn happy_eyeballs_returns_last_error_when_all_fail() {
        let result = happy_eyeballs(vec![1u8, 2], Duration::from_millis(10), |_| async {
            Err::<u8, _>(Error::Timeout)
        })
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
    }

    #[test]
    fn default_route_picks_lowest_metric_and_skips_excluded() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n\
                     eth1\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n\
                     eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t0000FFFF\n";
        assert_eq!(
            default_route::pick_v4(table, &["tun0".into()]).as_deref(),
            Some("eth0")
        );
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlan0\n\
                  00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n";
        assert_eq!(default_route::pick_v6(v6, &[]).as_deref(), Some("wlan0"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_socket_applies_fast_open_and_keepalive() {
        let dialer = DialerOptions {
            tcp_fast_open: true,
            tcp_keep_alive_idle: Some(Duration::from_secs(20)),
            ..DialerOptions::default()
        };
        let socket = dialer
            .tcp_socket(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)))
            .unwrap();
        assert!(
            fastopen_connect_enabled(&socket).unwrap(),
            "TCP_FASTOPEN_CONNECT 未设置"
        );
        assert!(socket.keepalive().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invalid_interface_is_an_error_not_ignored() {
        let dialer = DialerOptions {
            interface: Some(InterfaceBinding::Named("kerlico-none0".into())),
            ..DialerOptions::default()
        };
        assert!(
            dialer
                .tcp_socket(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)))
                .is_err()
        );
        assert!(
            dialer
                .udp_socket(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                .is_err()
        );
    }

    /// 上游出站：固定目标 UDP 通道把收到的数据报原样返回，并记录目标。
    struct EchoUpstream(std::sync::Mutex<Vec<Destination>>);
    struct EchoSender(tokio::sync::mpsc::Sender<Vec<u8>>);
    struct EchoReceiver(tokio::sync::mpsc::Receiver<Vec<u8>>);
    impl crate::DatagramSender for EchoSender {
        fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.0
                    .send(packet.to_vec())
                    .await
                    .map_err(|_| Error::Cancelled)
            })
        }
    }
    impl crate::DatagramReceiver for EchoReceiver {
        fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
            Box::pin(async move { Ok(self.0.recv().await) })
        }
    }
    impl Outbound for EchoUpstream {
        fn capabilities(&self) -> crate::Capabilities {
            crate::Capabilities {
                tcp: false,
                tcp_eof: false,
                udp: true,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _target: &'a Destination,
            _context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<crate::OpenedTcp>> {
            Box::pin(async { Err(Error::Unsupported("测试上游不提供 TCP")) })
        }
        fn connect_udp<'a>(
            &'a self,
            target: &'a Destination,
            _context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<crate::DatagramChannel>> {
            self.0.lock().unwrap().push(target.clone());
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            Box::pin(async move {
                Ok(crate::DatagramChannel {
                    sender: Box::new(EchoSender(tx)),
                    receiver: Box::new(EchoReceiver(rx)),
                })
            })
        }
    }

    #[tokio::test]
    async fn udp_peer_with_detour_relays_through_upstream_channel() {
        let upstream = Arc::new(EchoUpstream(std::sync::Mutex::new(Vec::new())));
        let table = DetourTable::new();
        let id = OutId::parse("hop").unwrap();
        table.insert(id.clone(), upstream.clone());
        let dialer = DialerOptions {
            detour: Some(id),
            detour_resolver: Some(table),
            ..DialerOptions::default()
        };
        let server = Destination::new("quic.example.com", 443).unwrap();
        let UdpPeer {
            socket,
            peer,
            relay,
        } = dialer.udp_peer(&server).await.unwrap();
        assert!(relay.is_some());
        assert!(peer.ip().is_loopback(), "detour 时对端应是本机中继");
        assert_eq!(
            upstream.0.lock().unwrap().as_slice(),
            &[server],
            "域名交给上游解析"
        );
        let socket = UdpSocket::from_std(socket).unwrap();
        socket.send_to(b"initial", peer).await.unwrap();
        let mut buffer = [0u8; 32];
        let (length, from) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!((&buffer[..length], from), (&b"initial"[..], peer));
    }

    #[tokio::test]
    async fn connect_without_detour_reaches_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        DialerOptions::default().connect(&server).await.unwrap();
        accept.await.unwrap();
    }
}
