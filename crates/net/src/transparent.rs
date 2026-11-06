//! 透明代理入站（`redirect` NAT 重定向与 `tproxy` 透明拦截）。

use kerlico_config::{NodeBuildContext, NodeFactory, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, ConnectContext, CredentialManifest, DatagramReceiver,
    DatagramSender, Destination, Error, FlowFailure, FlowOutcome, InboundContext, InboundProtocol,
    IngressBinding, NodeEvent, OriginalTarget, PeerSession, Result,
};
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::mpsc};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TransparentOptions {
    #[serde(alias = "fallback-target")]
    pub target: Option<TargetSpec>,
    #[serde(default)]
    pub network: Option<String>,
}

fn resolve_target(
    fallback: Option<&Destination>,
    original: Option<SocketAddr>,
    local: Option<SocketAddr>,
) -> Result<Destination> {
    if let Some(orig) = original
        && (Some(orig) != local || fallback.is_none())
    {
        return Destination::new(&orig.ip().to_string(), orig.port());
    }
    fallback.cloned().ok_or(Error::InvalidAddress)
}

struct RedirectNode {
    fallback: Option<Destination>,
}

impl InboundProtocol for RedirectNode {
    fn credential_manifest(&self) -> CredentialManifest {
        CredentialManifest::new()
    }

    fn requires_loopback(&self) -> bool {
        false
    }

    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let access = ingress.local(&context)?;
            let target = resolve_target(
                self.fallback.as_ref(),
                context.original_dst(),
                context.local_addr,
            )?;
            let budget =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let remote = budget.run(access.connect_tcp(&target, &budget)).await?;
            kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
        })
    }
}

pub struct RedirectNodeFactory;

impl NodeFactory for RedirectNodeFactory {
    fn kind(&self) -> &'static str {
        "redirect"
    }

    fn allows_local_inbound(&self) -> bool {
        true
    }

    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        if !input.native_credentials().is_empty() {
            return Err(Error::Config("redirect 入站不支持用户认证凭据".into()));
        }
        let options: TransparentOptions = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("redirect 节点配置不合法".into()))?;
        if let Some(net) = &options.network
            && !net.eq_ignore_ascii_case("tcp")
        {
            return Err(Error::Config("redirect 入站仅支持 TCP".into()));
        }
        let fallback = options
            .target
            .as_ref()
            .map(TargetSpec::destination)
            .transpose()?;
        Ok(Arc::new(RedirectNode { fallback }))
    }
}

struct TproxyNode {
    fallback: Option<Destination>,
    tcp: bool,
    udp: bool,
}

impl InboundProtocol for TproxyNode {
    fn credential_manifest(&self) -> CredentialManifest {
        CredentialManifest::new()
    }

    fn requires_loopback(&self) -> bool {
        false
    }

    fn supports_tcp(&self) -> bool {
        self.tcp
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    fn transparent(&self) -> bool {
        true
    }

    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let access = ingress.local(&context)?;
            let target = resolve_target(
                self.fallback.as_ref(),
                context.original_dst(),
                context.local_addr,
            )?;
            let budget =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let remote = budget.run(access.connect_tcp(&target, &budget)).await?;
            kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
        })
    }

    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(serve_udp(self.fallback.as_ref(), socket, ingress, context))
    }
}

/// UDP 会话键：客户端来源与原始目标。同一来源访问不同目标各占一个会话。
type SessionKey = (SocketAddr, SocketAddr);

const SESSION_QUEUE_PACKETS: usize = 128;

/// 一个入站数据报的去向。
#[derive(Debug, PartialEq, Eq)]
struct UdpRoute {
    target: Destination,
    /// 原始目标不是监听地址时，回包须以它为源地址发出；`None` 表示从监听 socket 回包。
    spoof: Option<SocketAddr>,
}

fn addressed_listener(original: SocketAddr, listener: SocketAddr) -> bool {
    original.port() == listener.port()
        && (original.ip() == listener.ip() || listener.ip().is_unspecified())
}

/// 有原始目标且不是直接发给监听地址时走原始目标，否则走 `target` 回退。
fn udp_route(
    fallback: Option<&Destination>,
    original: Option<SocketAddr>,
    listener: SocketAddr,
) -> Option<UdpRoute> {
    match original {
        Some(orig) if !addressed_listener(orig, listener) => {
            Destination::new(&orig.ip().to_string(), orig.port())
                .ok()
                .map(|target| UdpRoute {
                    target,
                    spoof: Some(orig),
                })
        }
        _ => fallback.cloned().map(|target| UdpRoute {
            target,
            spoof: None,
        }),
    }
}

async fn serve_udp(
    fallback: Option<&Destination>,
    socket: Arc<UdpSocket>,
    ingress: IngressBinding,
    context: InboundContext,
) -> Result<()> {
    let access = ingress.local(&context)?;
    let listener = socket.local_addr()?;
    let limit = context.max_datagram_size;
    let mut buffer = vec![0u8; limit + 1];
    let mut control = sys::control_buffer();
    let mut sessions: HashMap<SessionKey, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let (finished, mut finished_rx) = mpsc::unbounded_channel::<SessionKey>();
    loop {
        let (len, peer, original) = tokio::select! {
            biased;
            _ = context.cancel.cancelled() => return Ok(()),
            Some(key) = finished_rx.recv() => {
                if sessions.get(&key).is_some_and(mpsc::Sender::is_closed) {
                    sessions.remove(&key);
                }
                continue;
            }
            res = sys::recv_with_original_dst(&socket, &mut buffer, &mut control) => match res {
                Ok(v) => v,
                Err(e) if kerlico_core::is_peer_path_error(&e) => {
                    context.events.record(NodeEvent::Dropped);
                    continue;
                }
                Err(e) => return Err(Error::Io(e)),
            }
        };
        let route = match udp_route(fallback, original, listener) {
            Some(route) if len <= limit => route,
            _ => {
                context.events.record(NodeEvent::Dropped);
                continue;
            }
        };
        let key = (peer, route.spoof.unwrap_or(listener));
        let mut payload = buffer[..len].to_vec();
        if let Some(queue) = sessions.get(&key) {
            match queue.try_send(payload) {
                Ok(()) => continue,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    context.events.record(NodeEvent::Dropped);
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(returned)) => {
                    sessions.remove(&key);
                    payload = returned;
                }
            }
        }
        let (queue, rx) = mpsc::channel(SESSION_QUEUE_PACKETS);
        if queue.try_send(payload).is_err() {
            continue;
        }
        sessions.insert(key, queue);
        context.events.record(NodeEvent::Accepted);
        let session = UdpSession {
            access: access.with_observed_source(peer),
            route,
            peer,
            listener: socket.clone(),
            queue: rx,
            connect_timeout: context.connect_timeout,
            idle_timeout: context.idle_timeout,
            limit,
            cancel: context.cancel.child_token(),
        };
        let events = context.events.clone();
        let finished = finished.clone();
        context.tasks.spawn(async move {
            events.record(match session.run().await {
                Ok(()) => NodeEvent::Completed,
                Err(_) => NodeEvent::Failed,
            });
            let _ = finished.send(key);
        })?;
    }
}

struct UdpSession {
    access: PeerSession,
    route: UdpRoute,
    peer: SocketAddr,
    listener: Arc<UdpSocket>,
    queue: mpsc::Receiver<Vec<u8>>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    limit: usize,
    cancel: CancellationToken,
}

impl UdpSession {
    async fn run(mut self) -> Result<()> {
        // 回包 socket 绑定原始目标并 connect 到客户端；内核按四元组把该客户端的后续报文直接投递给它，
        // 所以它同时是本会话的第二个入口。
        let spoofed = self
            .route
            .spoof
            .map(|local| sys::reply_socket(local, self.peer))
            .transpose()?;
        let budget = ConnectContext::new(self.connect_timeout)
            .with_cancel(self.cancel.clone())
            .with_udp_source(self.peer);
        let target = OriginalTarget::from_destination(self.route.target.clone());
        let channel = budget.run(self.access.open_udp(target, &budget)).await?;
        let (mut sender, mut receiver, completion) = channel.into_parts();
        let mut captured = vec![0u8; self.limit + 1];
        let idle = tokio::time::sleep(self.idle_timeout);
        tokio::pin!(idle);
        let result = loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break Err(Error::Cancelled),
                _ = &mut idle => break Ok(()),
                packet = self.queue.recv() => match packet {
                    Some(packet) => {
                        if let Err(err) = sender.send(&packet).await {
                            break Err(err);
                        }
                    }
                    None => break Ok(()),
                },
                read = recv_captured(spoofed.as_ref(), &mut captured) => match read {
                    Ok(len) if len <= self.limit => {
                        if let Err(err) = sender.send(&captured[..len]).await {
                            break Err(err);
                        }
                    }
                    Ok(_) => {}
                    Err(err) if kerlico_core::is_peer_path_error(&err) => {}
                    Err(err) => break Err(Error::Io(err)),
                },
                reply = receiver.recv() => match reply {
                    Ok(Some(reply)) => {
                        let sent = match &spoofed {
                            Some(socket) => socket.send(&reply).await,
                            None => self.listener.send_to(&reply, self.peer).await,
                        };
                        if let Err(err) = sent
                            && !kerlico_core::is_peer_path_error(&err)
                        {
                            break Err(Error::Io(err));
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(err) => break Err(err),
                },
            }
            idle.as_mut()
                .reset(tokio::time::Instant::now() + self.idle_timeout);
        };
        completion.finish(match &result {
            Ok(()) => FlowOutcome::ProtocolEnd,
            Err(err) => FlowOutcome::Failed(FlowFailure::from_error(err)),
        });
        result
    }
}

async fn recv_captured(socket: Option<&UdpSocket>, buffer: &mut [u8]) -> std::io::Result<usize> {
    match socket {
        Some(socket) => socket.recv(buffer).await,
        None => std::future::pending().await,
    }
}

/// 透明代理 socket 的系统接口：Linux 用 `IP(V6)_RECVORIGDSTADDR` 取原始目标，
/// 其他平台只有 `target` 回退。
#[cfg(target_os = "linux")]
pub mod sys {
    use nix::sys::socket::{
        ControlMessageOwned, MsgFlags, SockaddrLike, SockaddrStorage, recvmsg, setsockopt, sockopt,
    };
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
        os::fd::{AsFd, AsRawFd},
    };
    use tokio::{io::Interest, net::UdpSocket};

    /// 让 UDP socket 在每个数据报上附带原始目标地址。
    pub fn enable_original_dst(socket: &impl AsFd, ipv6: bool) -> io::Result<()> {
        if ipv6 {
            setsockopt(socket, sockopt::Ipv6OrigDstAddr, &true)?;
        } else {
            setsockopt(socket, sockopt::Ipv4OrigDstAddr, &true)?;
        }
        Ok(())
    }

    pub(super) fn control_buffer() -> Vec<u8> {
        nix::cmsg_space!(nix::libc::sockaddr_in6)
    }

    pub(super) fn original_dst(message: &ControlMessageOwned) -> Option<SocketAddr> {
        match message {
            ControlMessageOwned::Ipv4OrigDstAddr(addr) => Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                u16::from_be(addr.sin_port),
            ))),
            ControlMessageOwned::Ipv6OrigDstAddr(addr) => Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                0,
                addr.sin6_scope_id,
            ))),
            _ => None,
        }
    }

    fn peer_addr(storage: &SockaddrStorage) -> Option<SocketAddr> {
        if let Some(v4) = storage.as_sockaddr_in() {
            return Some(SocketAddr::V4((*v4).into()));
        }
        storage
            .as_sockaddr_in6()
            .map(|v6| SocketAddr::V6((*v6).into()))
    }

    fn recv_once(
        socket: &UdpSocket,
        buffer: &mut [u8],
        control: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
        let mut iov = [io::IoSliceMut::new(buffer)];
        let message = recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(control),
            MsgFlags::MSG_DONTWAIT,
        )?;
        let peer = message
            .address
            .as_ref()
            .filter(|addr| addr.len() > 0)
            .and_then(peer_addr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "数据报缺少来源地址"))?;
        let original = message.cmsgs()?.find_map(|cmsg| original_dst(&cmsg));
        let len = if message.flags.contains(MsgFlags::MSG_TRUNC) {
            usize::MAX
        } else {
            message.bytes
        };
        Ok((len, peer, original))
    }

    pub(super) async fn recv_with_original_dst(
        socket: &UdpSocket,
        buffer: &mut [u8],
        control: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
        socket
            .async_io(Interest::READABLE, || recv_once(socket, buffer, control))
            .await
    }

    /// 以非本机地址 `local` 为源向 `peer` 回包的 socket，需要 `CAP_NET_ADMIN`。
    pub(super) fn reply_socket(local: SocketAddr, peer: SocketAddr) -> io::Result<UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(local),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if local.is_ipv6() {
            socket.set_only_v6(true)?;
            socket.set_ip_transparent_v6(true)?;
        } else {
            socket.set_ip_transparent_v4(true)?;
        }
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;
        socket.connect(&peer.into())?;
        UdpSocket::from_std(socket.into())
    }
}

#[cfg(not(target_os = "linux"))]
pub mod sys {
    use std::{io, net::SocketAddr};
    use tokio::net::UdpSocket;

    pub(super) fn control_buffer() -> Vec<u8> {
        Vec::new()
    }

    pub(super) async fn recv_with_original_dst(
        socket: &UdpSocket,
        buffer: &mut [u8],
        _control: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
        let (len, peer) = socket.recv_from(buffer).await?;
        Ok((len, peer, None))
    }

    pub(super) fn reply_socket(_local: SocketAddr, _peer: SocketAddr) -> io::Result<UdpSocket> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "透明代理回包仅支持 Linux",
        ))
    }
}

pub struct TproxyNodeFactory;

impl NodeFactory for TproxyNodeFactory {
    fn kind(&self) -> &'static str {
        "tproxy"
    }

    fn allows_local_inbound(&self) -> bool {
        true
    }

    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        if !input.native_credentials().is_empty() {
            return Err(Error::Config("tproxy 入站不支持用户认证凭据".into()));
        }
        let options: TransparentOptions = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("tproxy 节点配置不合法".into()))?;
        let (tcp, udp) = match options.network.as_deref() {
            None | Some("tcp,udp") | Some("both") => (true, true),
            Some("tcp") => (true, false),
            Some("udp") => (false, true),
            Some(_) => return Err(Error::Config("tproxy network 字段不合法".into())),
        };
        let fallback = options
            .target
            .as_ref()
            .map(TargetSpec::destination)
            .transpose()?;
        Ok(Arc::new(TproxyNode { fallback, tcp, udp }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redirect_and_tproxy_factories_validate_options() {
        let redirect = RedirectNodeFactory
            .build(&NodeBuildContext::local_for_test(json!({
                "target": { "host": "127.0.0.1", "port": 8080 }
            })))
            .unwrap();
        assert!(redirect.supports_tcp());
        assert!(!redirect.supports_udp());
        assert!(!redirect.transparent());

        assert!(
            RedirectNodeFactory
                .build(&NodeBuildContext::local_for_test(json!({
                    "network": "udp"
                })))
                .is_err()
        );

        let tproxy = TproxyNodeFactory
            .build(&NodeBuildContext::local_for_test(json!({
                "network": "tcp,udp"
            })))
            .unwrap();
        assert!(tproxy.supports_tcp());
        assert!(tproxy.supports_udp());
        assert!(tproxy.transparent());
    }

    #[test]
    fn udp_route_prefers_original_destination_and_spoofs_replies_from_it() {
        let listener: SocketAddr = "0.0.0.0:7893".parse().unwrap();
        let fallback = Destination::new("192.0.2.1", 53).unwrap();
        let original: SocketAddr = "198.51.100.10:9000".parse().unwrap();
        assert_eq!(
            udp_route(Some(&fallback), Some(original), listener),
            Some(UdpRoute {
                target: Destination::new("198.51.100.10", 9000).unwrap(),
                spoof: Some(original),
            })
        );
        let original_v6: SocketAddr = "[2001:db8::10]:9000".parse().unwrap();
        assert_eq!(
            udp_route(None, Some(original_v6), "[::]:7893".parse().unwrap())
                .map(|route| route.spoof),
            Some(Some(original_v6))
        );
    }

    #[test]
    fn udp_route_falls_back_when_datagram_addressed_the_listener() {
        let listener: SocketAddr = "0.0.0.0:7893".parse().unwrap();
        let fallback = Destination::new("192.0.2.1", 53).unwrap();
        let direct = Some("192.0.2.7:7893".parse().unwrap());
        let expected = Some(UdpRoute {
            target: fallback.clone(),
            spoof: None,
        });
        assert_eq!(udp_route(Some(&fallback), direct, listener), expected);
        assert_eq!(udp_route(Some(&fallback), None, listener), expected);
        assert_eq!(udp_route(None, direct, listener), None);
        assert_eq!(udp_route(None, None, listener), None);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn recvmsg_reports_original_destination_for_both_families() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let address: SocketAddr = bind.parse().unwrap();
            let receiver = UdpSocket::bind(address).await.unwrap();
            let local = receiver.local_addr().unwrap();
            sys::enable_original_dst(&receiver, local.is_ipv6()).unwrap();
            let client = UdpSocket::bind(address).await.unwrap();
            client.send_to(b"ping", local).await.unwrap();
            let mut buffer = [0u8; 16];
            let mut control = sys::control_buffer();
            let (len, peer, original) =
                sys::recv_with_original_dst(&receiver, &mut buffer, &mut control)
                    .await
                    .unwrap();
            assert_eq!(&buffer[..len], b"ping");
            assert_eq!(peer, client.local_addr().unwrap());
            assert_eq!(original, Some(local));
        }
    }
}
