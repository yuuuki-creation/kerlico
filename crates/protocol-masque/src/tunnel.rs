//! 一条 QUIC 连接上的一个 CONNECT-IP 请求，及其与用户态 IP 数据面之间的收发任务。
use crate::{
    capsule::{self, Address, Capsule, Route},
    config::Prepared,
    invalid, protocol,
};
use bytes::Bytes;
use h3::ConnectionState;
use kerlico_core::{
    Address as TargetAddress, BoxStream, CancellationToken, Destination, Error, Result,
    ServiceContext,
};
use kerlico_http_carrier::{BodyIo, Reader, Writer, runtime::ServiceRuntime};
use kerlico_wireguard::ip::{ClientTunnel, StackLimits, StackOptions};
use std::{
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::{Instant, interval, timeout};

const TUNNEL_MTU: usize = 1280;
/// Quarter Stream ID 与 Context ID 在本连接的首个请求流上各占一字节。
const MIN_DATAGRAM: usize = TUNNEL_MTU + 2;
const H3_NO_ERROR: u32 = 0x100;
const SETTINGS_POLL: Duration = Duration::from_millis(5);
const IDLE_POLL: Duration = Duration::from_secs(1);

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// 代理通告的可达范围；通告到达之前不限制目标，由代理决定是否转发。
#[derive(Clone, Default)]
pub(crate) struct Routes(Arc<RwLock<Option<Vec<Route>>>>);
impl Routes {
    fn set(&self, routes: Vec<Route>) -> Result<()> {
        *self.0.write().map_err(|_| protocol())? = Some(routes);
        Ok(())
    }
    pub fn check(&self, target: &Destination, ip_protocol: u8) -> Result<()> {
        let TargetAddress::Ip(ip) = target.address() else {
            return Ok(());
        };
        let routes = self.0.read().map_err(|_| protocol())?;
        match routes.as_ref() {
            Some(routes) if !routes.iter().any(|route| route.allows(*ip, ip_protocol)) => {
                Err(Error::Rejected)
            }
            _ => Ok(()),
        }
    }
}

pub(crate) struct Tunnel {
    ip: ClientTunnel,
    pub routes: Routes,
    cancel: CancellationToken,
    in_use: Arc<AtomicBool>,
}
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Tunnel {
    pub fn alive(&self) -> bool {
        !self.cancel.is_cancelled()
    }
    /// 取出供新流使用，并让空闲判定把这次取用算作活动。
    pub fn lease(&self) -> &ClientTunnel {
        self.in_use.store(true, Ordering::Relaxed);
        &self.ip
    }
}

async fn resolve(server: &Destination) -> Result<SocketAddr> {
    let mut peers: Vec<SocketAddr> =
        tokio::net::lookup_host((server.host().as_str(), server.port()))
            .await?
            .collect();
    peers.sort_by_key(SocketAddr::is_ipv6);
    peers.first().copied().ok_or(Error::InvalidAddress)
}

fn request(prepared: &Prepared) -> Result<http::Request<()>> {
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(prepared.uri.clone())
        .header("capsule-protocol", "?1");
    if let Some(authorization) = &prepared.authorization {
        builder = builder.header(http::header::AUTHORIZATION, authorization);
    }
    let mut request = builder.body(()).map_err(|_| invalid())?;
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::CONNECT_IP);
    Ok(request)
}

/// 处理控制 Capsule 直到下一条地址分配。
async fn next_assignment(io: &mut BoxStream, routes: &Routes) -> Result<Vec<Address>> {
    loop {
        match capsule::read(io).await?.ok_or_else(protocol)? {
            Capsule::AddressAssign(entries) => return Ok(entries),
            Capsule::AddressRequest(entries) => capsule::write_rejection(io, &entries).await?,
            Capsule::RouteAdvertisement(new) => routes.set(new)?,
            Capsule::Ignored => {}
        }
    }
}

struct Opened {
    io: BoxStream,
    quarter_stream_id: u64,
    addresses: Vec<IpAddr>,
}
async fn open(
    sender: &mut Sender,
    connection: &quinn::Connection,
    prepared: &Prepared,
    routes: &Routes,
) -> Result<Opened> {
    // RFC 9220：收到对端 SETTINGS 之前不能发送带 :protocol 的请求；h3 只提供查询接口。
    let mut settings = interval(SETTINGS_POLL);
    while !(sender.settings().enable_extended_connect() && sender.settings().enable_datagram()) {
        settings.tick().await;
    }
    let mut stream = sender
        .send_request(request(prepared)?)
        .await
        .map_err(|_| protocol())?;
    let quarter_stream_id = stream.id().index();
    let response = stream.recv_response().await.map_err(|_| protocol())?;
    // 4xx 是对这组凭据或路径的结论；其余状态可能是代理的暂时故障，走短退避。
    if response.status().is_client_error() {
        return Err(Error::Rejected);
    }
    if !response.status().is_success() {
        return Err(protocol());
    }
    if connection
        .max_datagram_size()
        .is_none_or(|size| size < MIN_DATAGRAM)
    {
        return Err(Error::Unsupported(
            "MASQUE对端或路径的QUIC Datagram不能承载1280字节IP包",
        ));
    }
    let (send, recv) = stream.split();
    let mut io = BodyIo::boxed(Writer::Client(send), Reader::Client(recv));
    capsule::write_address_request(&mut io).await?;
    let addresses = loop {
        let hosts = capsule::assigned_hosts(&next_assignment(&mut io, routes).await?);
        if !hosts.is_empty() {
            break hosts;
        }
    };
    Ok(Opened {
        io,
        quarter_stream_id,
        addresses,
    })
}

/// 建立期间不产生后台任务；调用方丢弃该 future 即回收全部资源。
pub(crate) async fn establish(prepared: &Prepared, host: &ServiceContext) -> Result<Arc<Tunnel>> {
    let peer = resolve(&prepared.server).await?;
    let bind = if peer.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;
    let (socket, socket_close) = kerlico_http_carrier::socket::wrap(socket)?;
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        ServiceRuntime::new(host.clone()),
    )?;
    let connection = endpoint
        .connect_with(prepared.quic.clone(), peer, &prepared.server_name)
        .map_err(|_| invalid())?
        .await
        .map_err(|_| protocol())?;
    let (mut driver, mut sender) = h3::client::builder()
        .max_field_section_size(16384)
        .enable_datagram(true)
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|_| protocol())?;
    let routes = Routes::default();
    let opened = tokio::select! {
        result = open(&mut sender, &connection, prepared, &routes) => result?,
        _ = poll_fn(|cx| driver.poll_close(cx)) => return Err(protocol()),
    };
    let cancel = host.cancel().child_token();
    let allowed_ips = opened
        .addresses
        .iter()
        .map(|ip| if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" }.to_owned())
        .collect();
    let ip = ClientTunnel::new(
        StackOptions {
            addresses: opened.addresses.clone(),
            allowed_ips,
            mtu: TUNNEL_MTU,
            limits: StackLimits::default(),
        },
        cancel.clone(),
    )?;
    let in_use = Arc::new(AtomicBool::new(true));
    host.spawn(until_cancelled(
        cancel.clone(),
        upload(ip.clone(), connection.clone(), opened.quarter_stream_id),
    ))?;
    host.spawn(until_cancelled(
        cancel.clone(),
        download(ip.clone(), connection.clone(), opened.quarter_stream_id),
    ))?;
    let tunnel = Arc::new(Tunnel {
        ip: ip.clone(),
        routes: routes.clone(),
        cancel: cancel.clone(),
        in_use: in_use.clone(),
    });
    let idle = prepared.idle;
    host.spawn(async move {
        tokio::select! {
            _ = cancel.cancelled() => {}
            _ = poll_fn(|cx| driver.poll_close(cx)) => {}
            _ = watch_assignments(opened.io, opened.addresses, routes) => {}
            _ = idle_expiry(&ip, &in_use, idle) => {}
        }
        cancel.cancel();
        ip.close();
        drop(sender);
        connection.close(H3_NO_ERROR.into(), b"");
        // 留出发送 CONNECTION_CLOSE 的时间，代理才能立刻回收这条隧道的地址。
        let _ = timeout(kerlico_core::QUIC_CLOSE_GRACE, endpoint.wait_idle()).await;
        socket_close.close();
    })?;
    Ok(tunnel)
}

/// 任一方向结束都结束整条隧道。
async fn until_cancelled(cancel: CancellationToken, work: impl Future<Output = Result<()>>) {
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = work => cancel.cancel(),
    }
}
async fn upload(ip: ClientTunnel, connection: quinn::Connection, quarter: u64) -> Result<()> {
    loop {
        let packet = ip.next_packet().await?;
        match connection
            .send_datagram_wait(capsule::encode_datagram(quarter, &packet))
            .await
        {
            // 路径 MTU 临时缩小时丢包，由隧道内的 TCP 重传或 UDP 语义承担。
            Ok(()) | Err(quinn::SendDatagramError::TooLarge) => {}
            Err(_) => return Err(protocol()),
        }
    }
}
async fn download(ip: ClientTunnel, connection: quinn::Connection, quarter: u64) -> Result<()> {
    loop {
        let datagram = connection.read_datagram().await.map_err(|_| protocol())?;
        // 单个无法处理的 IP 包不影响同隧道其他流。
        if let Some(packet) = capsule::decode_datagram(quarter, &datagram) {
            let _ = ip.receive(packet);
        }
    }
}
/// 代理撤回已使用地址时结束隧道；数据面地址固定，下一条连接重新协商。
async fn watch_assignments(
    mut io: BoxStream,
    addresses: Vec<IpAddr>,
    routes: Routes,
) -> Result<()> {
    loop {
        let entries = next_assignment(&mut io, &routes).await?;
        if !addresses
            .iter()
            .all(|ip| entries.iter().any(|entry| entry.grants(*ip)))
        {
            return Err(Error::Rejected);
        }
    }
}
async fn idle_expiry(ip: &ClientTunnel, in_use: &AtomicBool, limit: Duration) {
    let mut ticks = interval(IDLE_POLL);
    let mut last_active = Instant::now();
    loop {
        ticks.tick().await;
        if in_use.swap(false, Ordering::Relaxed) || ip.active_flows() > 0 {
            last_active = Instant::now();
        } else if last_active.elapsed() >= limit {
            return;
        }
    }
}
