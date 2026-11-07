//! 系统 TUN 入站：把内核交来的 IP 包还原成业务流，经本地会话进入共享调度器。
//!
//! Linux 上 `auto_route` 由 [`automation`] 安装专用路由表与策略规则，`auto_redirect`
//! 额外用 nftables 把 TCP 重定向到本节点监听的端口。
pub mod automation;
pub use automation::{
    AddressSet, Family, MarkInput, Prefix, Redirect, RoutePlan, Selection, UidRange,
};

use automation::{Installed, SystemDns};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, ConnectContext, CredentialManifest, Destination, Error, InboundContext,
    InboundProtocol, IngressBinding, NodeEvent, OriginalTarget, PeerSession, Result,
};
use kerlico_routing::{CompiledRuleSet, RuleSetSlot};
use kerlico_wireguard::ip::{ServerTunnel, StackLimits, StackOptions};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};
use tun_rs::DeviceBuilder;

/// 规则集被资源刷新任务换入后，TUN 路由表在一个周期内跟上。
const RULE_SET_POLL: Duration = Duration::from_secs(5);

fn default_name() -> String {
    "kerlico0".into()
}
fn default_mtu() -> u16 {
    1500
}
fn default_max_flows() -> usize {
    1024
}
fn default_table_index() -> u32 {
    automation::DEFAULT_TABLE_INDEX
}
fn default_rule_index() -> u32 {
    automation::DEFAULT_RULE_INDEX
}
fn default_fallback_rule_index() -> u32 {
    automation::DEFAULT_FALLBACK_RULE_INDEX
}

/// sing-box 与 Mihomo 的 `udp_timeout`：秒数或 `30s`、`5m` 形式的时长。
#[derive(Deserialize)]
#[serde(untagged)]
enum Timeout {
    Seconds(u64),
    Text(String),
}

impl Timeout {
    fn millis(&self) -> Result<u64> {
        let seconds = match self {
            Self::Seconds(s) => Some(*s),
            Self::Text(t) => {
                let t = t.trim();
                let (number, unit) =
                    t.split_at(t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len()));
                let n: Option<u64> = number.parse().ok();
                match unit {
                    "" | "s" => n,
                    "m" => n.and_then(|n| n.checked_mul(60)),
                    "h" => n.and_then(|n| n.checked_mul(3600)),
                    _ => None,
                }
            }
        };
        seconds
            .and_then(|s| s.checked_mul(1000))
            .ok_or_else(invalid)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(
        default = "default_name",
        alias = "interface_name",
        alias = "interface-name",
        alias = "device"
    )]
    name: String,
    #[serde(default, alias = "address")]
    addresses: Vec<String>,
    #[serde(default, alias = "inet4-address")]
    inet4_address: Vec<String>,
    #[serde(default, alias = "inet6-address")]
    inet6_address: Vec<String>,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default = "default_max_flows", alias = "max-flows")]
    max_flows: usize,
    /// `system`、`gvisor`、`mixed` 都由同一个用户态栈承载。
    #[serde(default)]
    stack: Option<String>,
    #[serde(default, alias = "udp-timeout")]
    udp_timeout: Option<Timeout>,
    /// UDP 按来源端口建立多目标关联，本身就是端点无关映射。
    #[serde(default, alias = "endpoint-independent-nat")]
    #[allow(dead_code)]
    endpoint_independent_nat: bool,
    #[serde(default)]
    #[allow(dead_code)]
    gso: bool,
    #[serde(default, alias = "gso-max-size")]
    #[allow(dead_code)]
    gso_max_size: Option<u32>,
    /// 由配置层并入全局出站拨号选项。
    #[serde(default, alias = "auto-detect-interface")]
    #[allow(dead_code)]
    auto_detect_interface: Option<bool>,
    #[serde(default, alias = "auto-outbounds-interface")]
    #[allow(dead_code)]
    auto_outbounds_interface: Option<String>,
    #[serde(default, alias = "auto-route")]
    auto_route: bool,
    #[serde(default, alias = "auto-system-routing-table")]
    auto_system_routing_table: Vec<String>,
    #[serde(default, alias = "strict-route")]
    strict_route: bool,
    #[serde(default = "default_table_index", alias = "iproute2-table-index")]
    iproute2_table_index: u32,
    #[serde(default = "default_rule_index", alias = "iproute2-rule-index")]
    iproute2_rule_index: u32,
    #[serde(default, alias = "route-address")]
    route_address: Vec<String>,
    #[serde(default, alias = "inet4-route-address")]
    inet4_route_address: Vec<String>,
    #[serde(default, alias = "inet6-route-address")]
    inet6_route_address: Vec<String>,
    #[serde(default, alias = "route-exclude-address")]
    route_exclude_address: Vec<String>,
    #[serde(default, alias = "inet4-route-exclude-address")]
    inet4_route_exclude_address: Vec<String>,
    #[serde(default, alias = "inet6-route-exclude-address")]
    inet6_route_exclude_address: Vec<String>,
    #[serde(default, alias = "route-address-set")]
    route_address_set: Vec<String>,
    #[serde(default, alias = "route-exclude-address-set")]
    route_exclude_address_set: Vec<String>,
    #[serde(default, alias = "include-uid")]
    include_uid: Vec<u32>,
    #[serde(default, alias = "include-uid-range")]
    include_uid_range: Vec<String>,
    #[serde(default, alias = "exclude-uid")]
    exclude_uid: Vec<u32>,
    #[serde(default, alias = "exclude-uid-range")]
    exclude_uid_range: Vec<String>,
    #[serde(default, alias = "include-interface")]
    include_interface: Vec<String>,
    #[serde(default, alias = "exclude-interface")]
    exclude_interface: Vec<String>,
    /// Android 专用过滤；Linux 上记录日志后忽略。
    #[serde(default, alias = "include-package")]
    include_package: Vec<String>,
    #[serde(default, alias = "exclude-package")]
    exclude_package: Vec<String>,
    #[serde(default, alias = "include-android-user")]
    include_android_user: Vec<u32>,
    #[serde(default, alias = "auto-redirect")]
    auto_redirect: bool,
    #[serde(default, alias = "auto-redirect-input-mark")]
    auto_redirect_input_mark: Option<MarkInput>,
    /// 由配置层用作 kerlico 出站套接字的默认标记。
    #[serde(default, alias = "auto-redirect-output-mark")]
    #[allow(dead_code)]
    auto_redirect_output_mark: Option<MarkInput>,
    #[serde(
        default = "default_fallback_rule_index",
        alias = "auto-redirect-iproute2-fallback-rule-index"
    )]
    auto_redirect_iproute2_fallback_rule_index: u32,
    /// 由配置层编译为限定本节点的 `hijack-dns` 路由规则。
    #[serde(default, alias = "dns-hijack")]
    #[allow(dead_code)]
    dns_hijack: Vec<String>,
    #[serde(default, alias = "dns-mode")]
    #[allow(dead_code)]
    dns_mode: Option<String>,
    #[serde(default, alias = "dns-address")]
    dns_address: Vec<IpAddr>,
    #[serde(default)]
    dns: Vec<IpAddr>,
    #[serde(default, alias = "auto-system-dns-to-gateway")]
    auto_system_dns_to_gateway: bool,
}

/// 未写地址时沿用 Mihomo 的默认 TUN 地址；Fake-IP 池从 `.4` 起分配，不与它重叠。
const DEFAULT_ADDRESSES: [&str; 2] = ["198.18.0.1/30", "fdfe:dcba:9876::1/126"];

fn invalid() -> Error {
    Error::Config("TUN 选项不合法".into())
}

/// 内核在 TUN 接口拉起时自动发出的链路本地（如 `fe80::/10`、`169.254.0.0/16`）或组播/广播探针，不进入代理转发或计为损坏包。
fn is_ambient_link_packet(packet: &[u8]) -> bool {
    let Some(&first) = packet.first() else {
        return false;
    };
    match first >> 4 {
        4 if packet.len() >= 20 => {
            let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            src.is_link_local()
                || dst.is_link_local()
                || dst.is_multicast()
                || dst.is_broadcast()
                || packet[9] == 2
        }
        6 if packet.len() >= 40 => {
            let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
            let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
            src.is_unicast_link_local()
                || dst.is_unicast_link_local()
                || dst.is_multicast()
                || packet[6] == 0
        }
        _ => false,
    }
}

/// 接口已被销毁。tun 驱动对已摘除的 fd 返回 EBADFD。
fn device_gone(error: &std::io::Error) -> bool {
    const EBADFD: i32 = 77;
    error.raw_os_error() == Some(EBADFD)
}

async fn read_device(
    device: Arc<tun_rs::AsyncDevice>,
    tunnel: Arc<ServerTunnel>,
    events: Arc<dyn kerlico_core::NodeObserver>,
    mtu: usize,
) -> Result<()> {
    // 留出链路层余量；过长的包由内核按 MTU 截断前已被拒绝。
    let mut buffer = vec![0; mtu + 64];
    loop {
        let length = device.recv(&mut buffer).await?;
        if is_ambient_link_packet(&buffer[..length]) {
            continue;
        }
        match tunnel.receive(&buffer[..length]) {
            Ok(()) => {}
            Err(Error::Cancelled) => return Ok(()),
            // 单个包不合法或超出配额不影响接口上的其他流量。
            Err(_) => events.record(NodeEvent::Dropped),
        }
    }
}

/// 接口地址。用户态栈用它的下一个地址。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterfaceAddress {
    ip: IpAddr,
    prefix: u8,
}

impl InterfaceAddress {
    fn parse(text: &str) -> Result<Self> {
        let (ip, prefix) = text.split_once('/').ok_or_else(invalid)?;
        let ip: IpAddr = ip.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        let usable = match ip {
            IpAddr::V4(_) => prefix <= 30,
            IpAddr::V6(_) => prefix <= 126,
        };
        if !usable || ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            return Err(invalid());
        }
        let parsed = Self { ip, prefix };
        parsed.gateway()?;
        Ok(parsed)
    }

    fn gateway(&self) -> Result<IpAddr> {
        let next = match self.ip {
            IpAddr::V4(ip) => IpAddr::from(
                ip.to_bits()
                    .checked_add(1)
                    .ok_or_else(invalid)?
                    .to_be_bytes(),
            ),
            IpAddr::V6(ip) => IpAddr::from(
                ip.to_bits()
                    .checked_add(1)
                    .ok_or_else(invalid)?
                    .to_be_bytes(),
            ),
        };
        Ok(next)
    }
}

/// auto-route 的静态计划与随规则集刷新的网段来源。
struct Routing {
    plan: RoutePlan,
    include: BTreeSet<Prefix>,
    exclude: BTreeSet<Prefix>,
    include_sets: Vec<RuleSetSlot>,
    exclude_sets: Vec<RuleSetSlot>,
}

type SetVersions = Vec<Arc<CompiledRuleSet>>;

impl Routing {
    fn versions(&self) -> SetVersions {
        self.include_sets
            .iter()
            .chain(&self.exclude_sets)
            .map(RuleSetSlot::load)
            .collect()
    }

    fn address_set(&self, versions: &SetVersions) -> AddressSet {
        let (include_versions, exclude_versions) = versions.split_at(self.include_sets.len());
        let prefixes = |sets: &[Arc<CompiledRuleSet>]| -> Vec<Prefix> {
            sets.iter()
                .flat_map(|set| set.cidr_strings())
                .filter_map(|text| Prefix::parse(&text).ok())
                .collect()
        };
        let mut include = self.include.clone();
        include.extend(prefixes(include_versions));
        let mut exclude = self.exclude.clone();
        exclude.extend(prefixes(exclude_versions));
        AddressSet {
            include,
            exclude,
            restricted: !self.include.is_empty() || !self.include_sets.is_empty(),
        }
    }
}

fn changed(old: &SetVersions, new: &SetVersions) -> bool {
    old.iter().zip(new).any(|(a, b)| !Arc::ptr_eq(a, b))
}

/// `auto_redirect` 的 TCP 入口：nftables 把经 TUN 路由的连接重定向到这里。
struct RedirectListeners {
    port: u16,
    v4: TcpListener,
    v6: Option<TcpListener>,
}

impl RedirectListeners {
    /// nft `redirect` 在本机发出时改写到回环地址，转发时改写到入接口主地址，因此监听全部地址。
    /// 监听套接字带上旁路标记，接受的连接继承它，回包不会再被策略规则导入 TUN。
    fn bind(mark: Option<u32>) -> Result<Self> {
        let v4 = Self::listener(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), mark)?;
        let port = v4.local_addr()?.port();
        let v6 = Self::listener(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)), mark).ok();
        Ok(Self { port, v4, v6 })
    }

    fn listener(address: SocketAddr, mark: Option<u32>) -> Result<TcpListener> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        #[cfg(target_os = "linux")]
        if let Some(mark) = mark {
            socket.set_mark(mark)?;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = mark;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        socket.listen(1024)?;
        Ok(TcpListener::from_std(socket.into())?)
    }

    async fn accept(&self) -> std::io::Result<TcpStream> {
        let accepted = match &self.v6 {
            Some(v6) => tokio::select! {
                r = self.v4.accept() => r,
                r = v6.accept() => r,
            },
            None => self.v4.accept().await,
        };
        accepted.map(|(stream, _)| stream)
    }
}

/// 未经 NAT 的直连没有原始目标，拒绝，避免监听端口成为开放代理。
fn redirected_target(stream: &TcpStream) -> Option<SocketAddr> {
    let local = stream.local_addr().ok()?;
    let sock = socket2::SockRef::from(stream);
    #[cfg(target_os = "linux")]
    let original = if local.is_ipv6() {
        sock.original_dst_v6()
    } else {
        sock.original_dst_v4()
    }
    .ok()
    .and_then(|a| a.as_socket())?;
    #[cfg(not(target_os = "linux"))]
    let original = {
        let _ = sock;
        local
    };
    (original != local).then(|| SocketAddr::new(original.ip().to_canonical(), original.port()))
}

async fn relay_redirected(stream: TcpStream, access: PeerSession, context: InboundContext) {
    let Some(target) = redirected_target(&stream) else {
        return;
    };
    let access = match stream.peer_addr() {
        Ok(peer) => access.with_observed_source(peer),
        Err(_) => access,
    };
    let result = async {
        let target = Destination::new(&target.ip().to_string(), target.port())?;
        let budget =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let remote = budget
            .run(access.open_tcp(OriginalTarget::from_destination(target), &budget))
            .await?;
        stream.set_nodelay(true)?;
        kerlico_core::relay_tcp(
            Box::new(stream),
            remote,
            context.idle_timeout,
            context.cancel.clone(),
        )
        .await
    }
    .await;
    context.events.record(match result {
        Ok(()) => NodeEvent::Completed,
        Err(_) => NodeEvent::Failed,
    });
}

struct TunNode {
    name: String,
    mtu: u16,
    max_flows: usize,
    udp_idle_timeout_ms: Option<u64>,
    addresses: Vec<InterfaceAddress>,
    routing: Option<Routing>,
    system_dns: Vec<IpAddr>,
}

impl TunNode {
    fn create(&self) -> Result<tun_rs::AsyncDevice> {
        let mut builder = DeviceBuilder::new().name(&self.name).mtu(self.mtu);
        for address in &self.addresses {
            builder = match address.ip {
                IpAddr::V4(ip) => builder.ipv4(ip, address.prefix, None),
                IpAddr::V6(ip) => builder.ipv6(ip, address.prefix),
            };
        }
        Ok(builder.build_async()?)
    }

    fn stack(&self) -> Result<StackOptions> {
        let mut limits = StackLimits {
            max_flows: self.max_flows,
            ..StackLimits::default()
        };
        if let Some(ms) = self.udp_idle_timeout_ms {
            limits.udp_idle_timeout_ms = ms;
        }
        Ok(StackOptions {
            addresses: self
                .addresses
                .iter()
                .map(InterfaceAddress::gateway)
                .collect::<Result<_>>()?,
            // 作为网关时来源是被转发的主机，不限于接口地址。
            allowed_ips: self
                .addresses
                .iter()
                .map(|address| {
                    if address.ip.is_ipv4() {
                        "0.0.0.0/0".to_owned()
                    } else {
                        "::/0".to_owned()
                    }
                })
                .collect(),
            mtu: usize::from(self.mtu),
            limits,
        })
    }
}

impl InboundProtocol for TunNode {
    fn credential_manifest(&self) -> CredentialManifest {
        CredentialManifest::new()
    }
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn supports_tcp(&self) -> bool {
        false
    }
    fn supports_virtual(&self) -> bool {
        true
    }
    fn reserved_sessions(&self) -> usize {
        1
    }
    fn handle<'a>(
        &'a self,
        _stream: kerlico_core::BoxStream,
        _ingress: IngressBinding,
        _context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("TUN 节点没有物理 TCP 入口")) })
    }
    fn handle_virtual<'a>(
        &'a self,
        ingress: IngressBinding,
        mut context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Engine 的 max_streams 是单条多路复用连接的上限；TUN 的流由 max_flows 和会话配额约束。
            context.max_streams = self.max_flows;
            let device = Arc::new(self.create()?);
            let access = ingress.local(&context)?;
            let redirect = match &self.routing {
                Some(routing) if routing.plan.redirect.is_some() => Some(RedirectListeners::bind(
                    routing.plan.bypass_marks.first().copied(),
                )?),
                _ => None,
            };
            let mut versions = SetVersions::new();
            let mut installed = match &self.routing {
                Some(routing) => {
                    versions = routing.versions();
                    Some(Installed::install(
                        &routing.plan,
                        &routing.address_set(&versions),
                        redirect.as_ref().map(|r| r.port),
                    )?)
                }
                None => None,
            };
            let _system_dns = SystemDns::apply(&self.name, &self.system_dns);
            let mut poll = tokio::time::interval(RULE_SET_POLL);
            let cancel = context.cancel.clone();
            let events = context.events.clone();
            let tasks = context.tasks.clone();
            let redirect_context = context.clone();
            let tunnel = Arc::new(ServerTunnel::new(self.stack()?, access.clone(), context)?);
            // 读接口单独成任务：与写回同在一个循环时，下载突发的回写会饿住读取，
            // 内核的 TUN 队列（500 包）溢出后上行包被静默丢弃。
            let mut reader = tasks.spawn_tracked(read_device(
                device.clone(),
                tunnel.clone(),
                events.clone(),
                usize::from(self.mtu),
            ))?;
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Ok(()),
                    read = &mut reader => return read.and_then(|read| read),
                    packet = tunnel.next_packet() => match packet {
                        Ok(packet) => match device.send(&packet).await {
                            Ok(_) => {}
                            Err(error) if device_gone(&error) => return Err(error.into()),
                            // 链路 down 的 EIO、缓冲不足等只影响这一个包。
                            Err(_) => events.record(NodeEvent::Dropped),
                        },
                        Err(Error::Cancelled) => return Ok(()),
                        Err(error) => return Err(error),
                    },
                    accepted = async { redirect.as_ref().expect("guarded").accept().await }, if redirect.is_some() => {
                        if let Ok(stream) = accepted {
                            events.record(NodeEvent::Accepted);
                            let relay = relay_redirected(stream, access.clone(), redirect_context.clone());
                            if tasks.spawn(relay).is_err() {
                                events.record(NodeEvent::Dropped);
                            }
                        }
                    }
                    _ = poll.tick(), if installed.is_some() => {
                        let routing = self.routing.as_ref().expect("installed implies routing");
                        let next = routing.versions();
                        if changed(&versions, &next) {
                            if let Some(installed) = installed.as_mut()
                                && let Err(error) = installed.update(&routing.address_set(&next))
                            {
                                kerlico_core::log::warning(format!("TUN 路由规则集刷新失败：{error}"));
                            }
                            versions = next;
                        }
                    }
                }
            }
        })
    }
}

fn parse_prefixes(
    sources: &[(&[String], Option<Family>)],
    into: &mut BTreeSet<Prefix>,
) -> Result<()> {
    for (texts, family) in sources {
        for text in texts.iter() {
            let prefix = Prefix::parse(text)?;
            if family.is_some_and(|f| f != prefix.family()) {
                return Err(invalid());
            }
            into.insert(prefix);
        }
    }
    Ok(())
}

fn rule_sets(input: &NodeBuildContext, tags: &[String]) -> Result<Vec<RuleSetSlot>> {
    tags.iter()
        .map(|tag| {
            input
                .rule_set(tag.trim())
                .ok_or_else(|| Error::Config(format!("TUN 引用的规则集不存在：{}", tag.trim())))
        })
        .collect()
}

fn stack_note(stack: Option<&str>) -> Result<()> {
    let Some(stack) = stack else {
        return Ok(());
    };
    match stack.trim().to_ascii_lowercase().as_str() {
        "gvisor" => Ok(()),
        "system" | "mixed" | "lwip" => {
            kerlico_core::log::info(format!("TUN stack={stack} 由 kerlico 用户态 TCP/IP 栈承载"));
            Ok(())
        }
        _ => Err(Error::Config(format!("TUN stack 不支持：{stack}"))),
    }
}

pub struct TunNodeFactory;

impl NodeFactory for TunNodeFactory {
    fn kind(&self) -> &'static str {
        "tun"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let mut options: Options = serde_json::from_value(input.options().clone())
            .map_err(|e| Error::Config(format!("TUN 选项不合法：{e}")))?;
        for address in options.inet4_address.iter().chain(&options.inet6_address) {
            if !options.addresses.contains(address) {
                options.addresses.push(address.clone());
            }
        }
        if options.addresses.is_empty() {
            options.addresses = DEFAULT_ADDRESSES.iter().map(|a| (*a).to_owned()).collect();
        }
        if options.name.is_empty()
            || options.name.len() > 15
            || !options
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            || !(1280..=9000).contains(&options.mtu)
            || options.addresses.is_empty()
            || options.addresses.len() > 2
        {
            return Err(invalid());
        }
        stack_note(options.stack.as_deref())?;
        if !options.include_package.is_empty()
            || !options.exclude_package.is_empty()
            || !options.include_android_user.is_empty()
        {
            kerlico_core::log::warning(
                "TUN include/exclude-package 与 include-android-user 仅用于 Android，已忽略",
            );
        }
        let addresses = options
            .addresses
            .iter()
            .map(|text| InterfaceAddress::parse(text))
            .collect::<Result<Vec<_>>>()?;
        if addresses.len() == 2 && addresses[0].ip.is_ipv4() == addresses[1].ip.is_ipv4() {
            return Err(invalid());
        }
        let gateways = addresses
            .iter()
            .map(InterfaceAddress::gateway)
            .collect::<Result<Vec<_>>>()?;

        let auto_route = options.auto_route || !options.auto_system_routing_table.is_empty();
        if options.auto_redirect && !auto_route {
            return Err(Error::Config(
                "TUN auto_redirect 需要同时开启 auto_route".into(),
            ));
        }
        let routing = if auto_route {
            if options.iproute2_table_index == 0
                || options.iproute2_rule_index == 0
                || options.iproute2_rule_index > u32::MAX - 16
            {
                return Err(invalid());
            }
            let mut include = BTreeSet::new();
            parse_prefixes(
                &[
                    (&options.route_address, None),
                    (&options.auto_system_routing_table, None),
                    (&options.inet4_route_address, Some(Family::V4)),
                    (&options.inet6_route_address, Some(Family::V6)),
                ],
                &mut include,
            )?;
            let mut exclude = BTreeSet::new();
            parse_prefixes(
                &[
                    (&options.route_exclude_address, None),
                    (&options.inet4_route_exclude_address, Some(Family::V4)),
                    (&options.inet6_route_exclude_address, Some(Family::V6)),
                ],
                &mut exclude,
            )?;
            let uids = |single: &[u32], ranges: &[String]| -> Result<Vec<UidRange>> {
                let mut out: Vec<UidRange> = single.iter().copied().map(UidRange::single).collect();
                for text in ranges {
                    out.push(UidRange::parse(text)?);
                }
                Ok(out)
            };
            let redirect = if options.auto_redirect {
                let input_mark = options
                    .auto_redirect_input_mark
                    .as_ref()
                    .map(MarkInput::parse_u32)
                    .transpose()?
                    .unwrap_or(automation::DEFAULT_INPUT_MARK);
                if input.bypass_marks().contains(&input_mark)
                    || options.auto_redirect_iproute2_fallback_rule_index == 0
                {
                    return Err(invalid());
                }
                Some(Redirect {
                    input_mark,
                    fallback_rule_index: options.auto_redirect_iproute2_fallback_rule_index,
                })
            } else {
                None
            };
            Some(Routing {
                plan: RoutePlan {
                    interface: options.name.clone(),
                    families: addresses.iter().map(|a| Family::of(a.ip)).collect(),
                    table: options.iproute2_table_index,
                    rule_index: options.iproute2_rule_index,
                    strict: options.strict_route,
                    bypass_marks: input.bypass_marks().iter().copied().collect(),
                    selection: Selection {
                        include_uid: uids(&options.include_uid, &options.include_uid_range)?,
                        exclude_uid: uids(&options.exclude_uid, &options.exclude_uid_range)?,
                        include_interface: options.include_interface.clone(),
                        exclude_interface: options.exclude_interface.clone(),
                    },
                    redirect,
                },
                include,
                exclude,
                include_sets: rule_sets(input, &options.route_address_set)?,
                exclude_sets: rule_sets(input, &options.route_exclude_address_set)?,
            })
        } else {
            None
        };
        let system_dns = if options.auto_system_dns_to_gateway {
            let explicit: Vec<IpAddr> = options
                .dns_address
                .iter()
                .chain(&options.dns)
                .copied()
                .collect();
            if explicit.is_empty() {
                gateways
            } else {
                explicit
            }
        } else {
            Vec::new()
        };
        let node = TunNode {
            name: options.name,
            mtu: options.mtu,
            max_flows: options.max_flows,
            udp_idle_timeout_ms: options
                .udp_timeout
                .as_ref()
                .map(Timeout::millis)
                .transpose()?,
            addresses,
            routing,
            system_dns,
        };
        node.stack()?.validate().map_err(|_| invalid())?;
        Ok(Arc::new(node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gateway_is_the_next_address() {
        let address = InterfaceAddress::parse("198.18.0.1/16").unwrap();
        assert_eq!(
            address.gateway().unwrap(),
            "198.18.0.2".parse::<IpAddr>().unwrap()
        );
        let address = InterfaceAddress::parse("fd00::1/64").unwrap();
        assert_eq!(
            address.gateway().unwrap(),
            "fd00::2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_unusable_addresses() {
        for text in [
            "198.18.0.1",
            "198.18.0.1/31",
            "0.0.0.0/8",
            "127.0.0.1/8",
            "224.0.0.1/24",
            "fd00::1/127",
            "::1/64",
        ] {
            assert!(InterfaceAddress::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn accepts_mihomo_tun_section_keys() {
        let options = json!({
            "stack": "mixed",
            "device": "kerlico-t0",
            "inet4-address": ["172.19.0.1/30"],
            "inet6-address": ["fdfe:dcba:9876::1/126"],
            "auto-route": true,
            "auto-redirect": true,
            "strict-route": true,
            "auto-detect-interface": true,
            "endpoint-independent-nat": false,
            "gso": true,
            "gso-max-size": 65536,
            "udp-timeout": 300,
            "dns-hijack": ["any:53", "tcp://any:53"],
            "route-exclude-address": ["192.168.0.0/16"],
            "include-uid-range": ["1000:99999"],
            "exclude-interface": ["wg0"],
            "include-package": ["com.example"],
        });
        let node = TunNodeFactory
            .build(&NodeBuildContext::for_test(options, Vec::new()))
            .unwrap();
        assert!(node.supports_virtual());
        let bad = json!({"addresses": ["172.19.0.1/30"], "stack": "netstack"});
        assert!(
            TunNodeFactory
                .build(&NodeBuildContext::for_test(bad, Vec::new()))
                .is_err()
        );
        let redirect_without_route = json!({"addresses": ["172.19.0.1/30"], "auto_redirect": true});
        assert!(
            TunNodeFactory
                .build(&NodeBuildContext::for_test(
                    redirect_without_route,
                    Vec::new()
                ))
                .is_err()
        );
        assert_eq!(Timeout::Text("5m".into()).millis().unwrap(), 300_000);
    }

    #[test]
    fn mihomo_tun_without_addresses_uses_mihomo_defaults() {
        let options = json!({
            "stack": "mixed",
            "device": "katun",
            "auto-route": true,
            "auto-detect-interface": true,
            "strict-route": true,
            "dns-hijack": ["any:53"],
        });
        let node = TunNodeFactory
            .build(&NodeBuildContext::for_test(options, Vec::new()))
            .unwrap();
        assert!(node.supports_virtual());
    }
}
