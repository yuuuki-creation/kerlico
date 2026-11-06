//! OpenVPN 2.x 服务端入站节点：TLS 模式、UDP/TCP 载体、`tls-auth`/`tls-crypt`/`tls-crypt-v2` 控制面包装、
//! 客户端证书与口令认证、NCP、逐客户端地址池推送、保活与换钥。

mod options;
pub(crate) mod registry;
mod session;

pub use options::{
    ControlWrapConfig, DnsServerGroup, KeepaliveConfig, PushOptions, ServerOptions,
    ServerTlsConfig, ServerUserConfig, StringOrU64, StringOrVec, VerifyX509Name,
};

use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use kerlico_wireguard::ip::{ServerTunnel, StackLimits, StackOptions};
use options::{NodeWrap, Plan, SessionSettings, UserPlan};
use registry::{Assignment, Registry, Ticket};
use ring::digest;
use session::{AuthRequest, Gate, Grant, ServerSession, Step, is_initial_reset, wire_session};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::MissedTickBehavior,
};

pub struct OpenVpnNodeFactory;

const SERVER_TICK: Duration = Duration::from_millis(250);

pub struct OpenVpnNode {
    users: CredentialSet<ServerUserConfig>,
    user_plans: BTreeMap<String, UserPlan>,
    wrap: NodeWrap,
    supports_tcp: bool,
    supports_udp: bool,
    tls: Arc<rustls::ServerConfig>,
    udp_settings: Arc<SessionSettings>,
    tcp_settings: Arc<SessionSettings>,
    registry: Arc<Registry>,
    server_cert_fingerprint: [u8; 32],
}

impl NodeFactory for OpenVpnNodeFactory {
    fn kind(&self) -> &'static str {
        "openvpn"
    }

    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: ServerOptions = serde_json::from_value(input.options().clone())
            .map_err(|error| Error::Config(format!("OpenVPN 入站配置不合法：{error}")))?;
        let members = input
            .native_credentials()
            .iter()
            .map(|value| {
                serde_json::from_value(value.clone())
                    .map_err(|error| Error::Config(format!("OpenVPN 成员凭据不合法：{error}")))
            })
            .collect::<Result<Vec<ServerUserConfig>>>()?;
        let plan = Plan::build(options, members)?;
        let mut tcp_settings = plan.settings.clone();
        tcp_settings.tcp = true;
        Ok(Arc::new(OpenVpnNode {
            users: input.credentials(plan.users)?,
            user_plans: plan.user_plans,
            wrap: plan.wrap,
            supports_tcp: plan.tcp,
            supports_udp: plan.udp,
            tls: plan.tls,
            udp_settings: Arc::new(plan.settings),
            tcp_settings: Arc::new(tcp_settings),
            registry: plan.registry,
            server_cert_fingerprint: plan.server_fingerprint,
        }))
    }
}

/// 口令成员按用户名与口令匹配；无口令成员只接受 CN 与用户名相同、已通过 TLS 校验的客户端证书。
fn credential_matches(row: &ServerUserConfig, request: &AuthRequest<'_>) -> bool {
    if request.username.is_empty() {
        row.password.is_empty()
            && request
                .common_name
                .is_some_and(|cn| bool::from(cn.as_bytes().ct_eq(row.name.as_bytes())))
    } else {
        let name = row.name.as_bytes().ct_eq(request.username.as_bytes());
        let password = row.password.as_bytes().ct_eq(request.password.as_bytes());
        !row.password.is_empty() && bool::from(name & password)
    }
}

/// `duplicate-cn` 判重所用的身份：证书 CN，没有证书时用用户名。
fn identity(request: &AuthRequest<'_>, username_as_common_name: bool) -> String {
    match request.common_name {
        Some(cn) if !(username_as_common_name && !request.username.is_empty()) => cn.to_owned(),
        _ => request.username.to_owned(),
    }
}

pub(crate) fn stack_options(assignment: &Assignment, mtu: usize) -> StackOptions {
    let mut addresses = Vec::new();
    let mut allowed_ips = Vec::new();
    if let Some(v4) = assignment.v4 {
        addresses.push(IpAddr::V4(v4.peer));
        allowed_ips.push(format!("{}/32", v4.client));
    }
    if let Some(v6) = assignment.v6 {
        addresses.push(IpAddr::V6(v6.server));
        allowed_ips.push(format!("{}/128", v6.client));
    }
    StackOptions {
        addresses,
        allowed_ips,
        mtu,
        limits: StackLimits::default(),
    }
}

struct NodeGate<'a> {
    node: &'a OpenVpnNode,
    settings: &'a SessionSettings,
    access: &'a IngressBinding,
    context: &'a InboundContext,
}
impl NodeGate<'_> {
    fn verify(&self, request: &AuthRequest<'_>) -> Option<kerlico_core::Verified<String>> {
        self.node
            .users
            .verify(request, |row, request| {
                Ok(credential_matches(row, request).then(|| row.name.clone()))
            })
            .ok()
    }
}
impl Gate for NodeGate<'_> {
    fn admit(
        &mut self,
        ticket: &mut Ticket,
        request: &AuthRequest<'_>,
    ) -> std::result::Result<Grant, &'static str> {
        let verified = self.verify(request).ok_or("")?;
        let (peer, name) = self
            .access
            .authenticated(verified, self.context)
            .map_err(|_| "")?;
        let plan = self.node.user_plans.get(&name).ok_or("")?;
        let identity = identity(request, self.settings.username_as_common_name);
        let lease = ticket
            .assign(&identity, plan.fixed_slot)
            .map_err(|_| "no free address in the pool")?;
        let tunnel = ServerTunnel::new(
            stack_options(&lease.assignment, self.settings.mtu),
            peer,
            self.context.clone(),
        )
        .map_err(|_| "")?;
        Ok(Grant {
            push: plan.push.clone(),
            tunnel: Some(Arc::new(tunnel)),
        })
    }

    fn readmit(&mut self, request: &AuthRequest<'_>, expected: &str) -> bool {
        self.verify(request).is_some()
            && identity(request, self.settings.username_as_common_name) == expected
    }
}

impl InboundProtocol for OpenVpnNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"kerlico/openvpn/server-cert/");
        ctx.update(&self.server_cert_fingerprint);
        let mut fp = [0u8; 32];
        fp.copy_from_slice(ctx.finish().as_ref());
        manifest.protection("openvpn", fp);
        for (slot, (_, user)) in self.users.rows().enumerate() {
            let mut ctx = digest::Context::new(&digest::SHA256);
            ctx.update(b"kerlico/openvpn/node-user/");
            ctx.update(user.name.as_bytes());
            ctx.update(b":");
            ctx.update(user.password.as_bytes());
            let mut fp = [0u8; 32];
            fp.copy_from_slice(ctx.finish().as_ref());
            manifest.authentication("openvpn", slot, fp);
        }
        manifest
    }

    fn requires_udp_association(&self) -> bool {
        true
    }

    fn requires_loopback(&self) -> bool {
        false
    }

    fn supports_tcp(&self) -> bool {
        self.supports_tcp
    }

    fn supports_udp(&self) -> bool {
        self.supports_udp
    }

    fn handle<'a>(
        &'a self,
        mut stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.supports_tcp {
                return Err(Error::Unsupported("当前 OpenVPN 节点未启用 TCP 载体"));
            }
            let mut gate = NodeGate {
                node: self,
                settings: &self.tcp_settings,
                access: &access,
                context: &context,
            };
            let mut frames = FrameReader::default();
            let first =
                tokio::time::timeout(self.tcp_settings.handshake_window, frames.next(&mut stream))
                    .await
                    .map_err(|_| Error::Timeout)??;
            let now = Instant::now();
            let Some((mut session, unwrapped)) = ServerSession::start(
                self.tcp_settings.clone(),
                self.tls.clone(),
                &self.wrap,
                &self.registry,
                context.cancel.child_token(),
                now,
                &first,
            ) else {
                return Ok(());
            };
            let mut step = session.begin(now, unwrapped, &mut gate);
            let mut timer = tokio::time::interval(SERVER_TICK);
            timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                for reply in session.take_outbox() {
                    stream
                        .write_all(&(reply.len() as u16).to_be_bytes())
                        .await?;
                    stream.write_all(&reply).await?;
                }
                stream.flush().await?;
                match step {
                    Ok(Step::Idle | Step::Opened(_)) => {}
                    Ok(Step::Closed) => return Ok(()),
                    Err(error) => return Err(error),
                }
                let tunnel = session.tunnel_handle();
                step = tokio::select! {
                    biased;
                    _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                    frame = frames.next(&mut stream) => match frame {
                        Ok(frame) => session.receive(Instant::now(), &frame, &mut gate),
                        Err(_) => return Ok(()),
                    },
                    packet = next_tunnel_packet(tunnel.as_ref()) => {
                        session.send_packet(Instant::now(), &packet?).map(|()| Step::Idle)
                    }
                    _ = timer.tick() => session.tick(Instant::now()).map(|()| Step::Idle),
                };
            }
        })
    }

    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.supports_udp {
                return Err(Error::Unsupported("当前 OpenVPN 节点未启用 UDP 载体"));
            }
            let mut peers: HashMap<SocketAddr, ServerSession> = HashMap::new();
            let (tx, mut rx) =
                tokio::sync::mpsc::unbounded_channel::<(SocketAddr, [u8; 8], Vec<u8>)>();
            let mut buf = vec![0u8; 65535];
            let mut timer = tokio::time::interval(SERVER_TICK);
            timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                    res = socket.recv_from(&mut buf) => {
                        let Ok((n, peer)) = res else { continue };
                        let wire = &buf[..n];
                        let now = Instant::now();
                        let mut gate = NodeGate {
                            node: self,
                            settings: &self.udp_settings,
                            access: &access,
                            context: &context,
                        };
                        // 同一源地址上新的首个硬重置代表客户端已重启，旧会话作废。
                        if is_initial_reset(wire)
                            && peers.get(&peer).is_some_and(|session| Some(session.remote()) != wire_session(wire))
                        {
                            peers.remove(&peer);
                        }
                        let step = match peers.get_mut(&peer) {
                            Some(session) => session.receive(now, wire, &mut gate),
                            None => {
                                let Some((mut session, first)) = ServerSession::start(
                                    self.udp_settings.clone(),
                                    self.tls.clone(),
                                    &self.wrap,
                                    &self.registry,
                                    context.cancel.child_token(),
                                    now,
                                    wire,
                                ) else {
                                    continue;
                                };
                                let step = session.begin(now, first, &mut gate);
                                peers.insert(peer, session);
                                step
                            }
                        };
                        let Some(session) = peers.get_mut(&peer) else { continue };
                        for reply in session.take_outbox() {
                            let _ = socket.send_to(&reply, peer).await;
                        }
                        match step {
                            Ok(Step::Idle) => {}
                            Ok(Step::Opened(tunnel)) => {
                                let tx = tx.clone();
                                let cancel = session.cancel().clone();
                                let remote = session.remote();
                                let _ = context.tasks.spawn(async move {
                                    loop {
                                        tokio::select! {
                                            biased;
                                            _ = cancel.cancelled() => break,
                                            packet = tunnel.next_packet() => {
                                                let Ok(packet) = packet else { break };
                                                if tx.send((peer, remote, packet)).is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                            Ok(Step::Closed) | Err(_) => {
                                peers.remove(&peer);
                            }
                        }
                    }
                    Some((peer, remote, packet)) = rx.recv() => {
                        if let Some(session) = peers.get_mut(&peer)
                            && session.remote() == remote
                            && session.send_packet(Instant::now(), &packet).is_ok()
                        {
                            for reply in session.take_outbox() {
                                let _ = socket.send_to(&reply, peer).await;
                            }
                        }
                    }
                    _ = timer.tick() => {
                        let now = Instant::now();
                        let mut finished = Vec::new();
                        for (peer, session) in &mut peers {
                            let alive = session.tick(now).is_ok();
                            for reply in session.take_outbox() {
                                let _ = socket.send_to(&reply, *peer).await;
                            }
                            if !alive {
                                finished.push(*peer);
                            }
                        }
                        for peer in finished {
                            peers.remove(&peer);
                        }
                    }
                }
            }
        })
    }
}

/// TCP 载体的 2 字节长度前缀分帧。缓冲跨 `select!` 保留，被取消的读取不会丢失已到达的字节。
#[derive(Default)]
struct FrameReader {
    buffer: Vec<u8>,
}
impl FrameReader {
    async fn next(&mut self, stream: &mut BoxStream) -> Result<Vec<u8>> {
        loop {
            if self.buffer.len() >= 2 {
                let length = usize::from(u16::from_be_bytes([self.buffer[0], self.buffer[1]]));
                if length == 0 || length > 16384 {
                    return Err(Error::Protocol("OpenVPN TCP 帧长度不合法"));
                }
                if self.buffer.len() >= 2 + length {
                    let frame = self.buffer[2..2 + length].to_vec();
                    self.buffer.drain(..2 + length);
                    return Ok(frame);
                }
            }
            let mut chunk = [0u8; 16384];
            let count = stream.read(&mut chunk).await?;
            if count == 0 {
                return Err(Error::Protocol("OpenVPN TCP 连接已关闭"));
            }
            self.buffer.extend_from_slice(&chunk[..count]);
        }
    }
}

async fn next_tunnel_packet(tunnel: Option<&Arc<ServerTunnel>>) -> Result<Vec<u8>> {
    match tunnel {
        Some(tunnel) => tunnel.next_packet().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
