use crate::{
    MAX_PACKET, MAX_WIRE, address, config::fingerprint, destination, inbound::Ss2022Node,
    outbound::Ss2022Outbound, protocol_error, replay::ReplayWindow,
};
use bytes::BytesMut;
use kerlico_core::{
    AccessService, BoxFuture, CancellationToken, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, InboundContext, NodeEvent, NodeObserver, Result,
    StreamLease,
};
use shadowsocks::{
    ServerConfig,
    context::SharedContext,
    relay::{
        socks5::Address,
        udprelay::{crypto_io, options::UdpSocketControlData},
    },
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet, time::Instant};

struct ClientSender {
    socket: Arc<UdpSocket>,
    config: Arc<ServerConfig>,
    crypto: SharedContext,
    target: Address,
    session: u64,
    packet: u64,
    cancel: CancellationToken,
}
struct ClientReceiver {
    socket: Arc<UdpSocket>,
    config: Arc<ServerConfig>,
    crypto: SharedContext,
    target: Address,
    session: u64,
    servers: HashMap<u64, (ReplayWindow, Instant)>,
    cancel: CancellationToken,
}

pub(crate) async fn connect(
    outbound: &Ss2022Outbound,
    target: &Destination,
    cancel: CancellationToken,
) -> Result<DatagramChannel> {
    let peer = tokio::net::lookup_host((outbound.server.host().as_str(), outbound.server.port()))
        .await?
        .next()
        .ok_or(Error::InvalidAddress)?;
    let socket = Arc::new(
        UdpSocket::bind(if peer.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .await?,
    );
    socket.connect(peer).await?;
    let session = rand::random();
    Ok(DatagramChannel {
        sender: Box::new(ClientSender {
            socket: socket.clone(),
            config: outbound.config.clone(),
            crypto: outbound.crypto.clone(),
            target: address(target),
            session,
            packet: 0,
            cancel: cancel.clone(),
        }),
        receiver: Box::new(ClientReceiver {
            socket,
            config: outbound.config.clone(),
            crypto: outbound.crypto.clone(),
            target: address(target),
            session,
            servers: HashMap::new(),
            cancel,
        }),
    })
}

impl DatagramSender for ClientSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if packet.len() > MAX_PACKET {
                return Err(Error::ResourceLimit);
            }
            let packet_id = self.packet;
            self.packet = self.packet.checked_add(1).ok_or(Error::ResourceLimit)?;
            let mut control = UdpSocketControlData::default();
            control.client_session_id = self.session;
            control.packet_id = packet_id;
            let mut wire = BytesMut::new();
            crypto_io::encrypt_client_payload(
                &self.crypto,
                self.config.method(),
                self.config.key(),
                &self.target,
                &control,
                self.config.identity_keys(),
                packet,
                &mut wire,
            );
            if wire.len() > MAX_WIRE {
                return Err(Error::ResourceLimit);
            }
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => Err(Error::Cancelled),
                result = self.socket.send(&wire) => { if result? != wire.len() { return Err(protocol_error()); } Ok(()) },
            }
        })
    }
}
impl DatagramReceiver for ClientReceiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut wire = vec![0; 65_536];
            loop {
                let len = tokio::select! { biased; _ = self.cancel.cancelled() => return Err(Error::Cancelled), r = self.socket.recv(&mut wire) => r? };
                let Ok((count, source, Some(control))) = crypto_io::decrypt_server_payload(
                    &self.crypto,
                    self.config.method(),
                    self.config.key(),
                    &mut wire[..len],
                ) else {
                    continue;
                };
                if control.client_session_id != self.session || count > MAX_PACKET {
                    continue;
                }
                // 固定目标通道允许远端将请求域名解析成真实来源地址。
                if source.port() != self.target.port() {
                    continue;
                }
                if matches!((&self.target, &source), (Address::SocketAddress(a), Address::SocketAddress(b)) if a != b)
                {
                    continue;
                }
                let now = Instant::now();
                self.servers
                    .retain(|_, (_, seen)| now.duration_since(*seen) < Duration::from_secs(60));
                if !self.servers.contains_key(&control.server_session_id)
                    && self.servers.len() >= 64
                {
                    continue;
                }
                let entry = self
                    .servers
                    .entry(control.server_session_id)
                    .or_insert_with(|| (ReplayWindow::default(), now));
                if !entry.0.accept(control.packet_id) {
                    continue;
                }
                entry.1 = now;
                return Ok(Some(wire[..count].to_vec()));
            }
        })
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct SessionKey {
    user: [u8; 32],
    client: u64,
}
struct Session {
    replay: ReplayWindow,
    last_seen: Instant,
    response: Arc<Response>,
    targets: HashMap<Destination, mpsc::Sender<Vec<u8>>>,
    _lease: StreamLease,
    _events: SessionEvents,
}
struct SessionEvents(Arc<dyn NodeObserver>);
impl Drop for SessionEvents {
    fn drop(&mut self) {
        self.0.record(NodeEvent::Completed);
    }
}
struct Response {
    peer: Mutex<SocketAddr>,
    server: u64,
    client: u64,
    packet: AtomicU64,
    key: Vec<u8>,
}

impl Ss2022Node {
    /// engine 提供已按节点地址族绑定的 socket；此处不另行绑定监听端口。
    pub async fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let mut sessions: HashMap<SessionKey, Session> = HashMap::new();
        let mut tasks = JoinSet::new();
        let mut wire = vec![0; 65_536];
        let idle = context.idle_timeout.max(Duration::from_secs(60));
        let mut maintenance = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                biased;
                _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                _ = maintenance.tick() => {
                    let now = Instant::now();
                    sessions.retain(|_, session| now.duration_since(session.last_seen) < idle);
                },
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                received = socket.recv_from(&mut wire) => {
                    let (len, peer) = received?;
                    let Ok((count, target, Some(control))) = crypto_io::decrypt_client_payload(&self.crypto, self.config.method(), self.config.key(), &mut wire[..len], self.config.user_manager()) else { continue };
                    if count > context.max_datagram_size.min(MAX_PACKET) { continue; }
                    let Ok(target) = destination(&target) else { continue };
                    let user_key = control.user.as_ref().map_or(self.config.key(), |user| user.key());
                    let key = SessionKey { user: fingerprint(user_key), client: control.client_session_id };
                    let now = Instant::now();
                    if !sessions.contains_key(&key) {
                        if sessions.len() >= context.max_streams { continue; }
                        let Ok(lease) = context.stream_budget.try_acquire() else { context.events.record(NodeEvent::Dropped); continue };
                        context.events.record(NodeEvent::Accepted);
                        sessions.insert(key, Session {
                            replay: ReplayWindow::default(), last_seen: now,
                            response: Arc::new(Response { peer: Mutex::new(peer), server: rand::random(), client: control.client_session_id, packet: AtomicU64::new(0), key: user_key.to_vec() }),
                            targets: HashMap::new(), _lease: lease, _events: SessionEvents(context.events.clone()),
                        });
                    }
                    let session = sessions.get_mut(&key).expect("会话已插入");
                    if !session.replay.accept(control.packet_id) { continue; }
                    session.last_seen = now;
                    *session.response.peer.lock().map_err(|_| protocol_error())? = peer;
                    // 回放状态独立保留；新鲜数据报可重建已经关闭的目标关联。
                    session.targets.retain(|_, sender| !sender.is_closed());
                    if let Some(sender) = session.targets.get(&target) {
                        let _ = sender.try_send(wire[..count].to_vec());
                        continue;
                    }
                    if session.targets.len() >= context.max_streams { continue; }
                    let Ok(lease) = context.stream_budget.try_acquire() else { context.events.record(NodeEvent::Dropped); continue };
                    let (sender, receiver) = mpsc::channel(32);
                    let _ = sender.try_send(wire[..count].to_vec());
                    session.targets.insert(target.clone(), sender);
                    let response = session.response.clone();
                    let config = self.config.clone();
                    let crypto = self.crypto.clone();
                    let socket = socket.clone();
                    let access = access.clone();
                    let context = context.clone();
                    tasks.spawn(async move {
                        let _lease = lease;
                        let events = context.events.clone();
                        if target_session(socket, access, context, config, crypto, target, response, receiver).await.is_err() { events.record(NodeEvent::Failed); }
                    });
                },
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn target_session(
    socket: Arc<UdpSocket>,
    access: Arc<dyn AccessService>,
    context: InboundContext,
    config: Arc<ServerConfig>,
    crypto: SharedContext,
    target: Destination,
    response: Arc<Response>,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let budget = ConnectContext {
        cancel: context.cancel.clone(),
        timeout: context.connect_timeout,
    };
    let channel = budget.run(access.connect_udp(&target, &budget)).await?;
    let mut sender = channel.sender;
    let mut receiver = channel.receiver;
    let target = address(&target);
    let idle = context.idle_timeout.max(Duration::from_secs(60));
    let timer = tokio::time::sleep(idle);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _ = context.cancel.cancelled() => return Err(Error::Cancelled),
            _ = &mut timer => return Ok(()),
            packet = packets.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                tokio::select! { biased; _ = context.cancel.cancelled() => return Err(Error::Cancelled), r = tokio::time::timeout(context.idle_timeout, sender.send(&packet)) => r.map_err(|_| Error::Timeout)?? };
                timer.as_mut().reset(Instant::now() + idle);
            },
            packet = receiver.recv() => {
                let Some(packet) = packet? else { return Ok(()) };
                if packet.len() > context.max_datagram_size.min(MAX_PACKET) { return Err(Error::ResourceLimit); }
                let packet_id = next_packet_id(&response.packet)?;
                let mut control = UdpSocketControlData::default();
                control.client_session_id = response.client;
                control.server_session_id = response.server;
                control.packet_id = packet_id;
                let mut wire = BytesMut::new();
                crypto_io::encrypt_server_payload(&crypto, config.method(), &response.key, &target, &control, &packet, &mut wire);
                if wire.len() > MAX_WIRE { return Err(Error::ResourceLimit); }
                let peer = *response.peer.lock().map_err(|_| protocol_error())?;
                tokio::select! { biased; _ = context.cancel.cancelled() => return Err(Error::Cancelled), r = tokio::time::timeout(context.idle_timeout, socket.send_to(&wire, peer)) => { r.map_err(|_| Error::Timeout)??; } };
                timer.as_mut().reset(Instant::now() + idle);
            },
        }
    }
}

fn next_packet_id(counter: &AtomicU64) -> Result<u64> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).ok_or(Error::ResourceLimit)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(current),
            Err(observed) => current = observed,
        }
    }
}
