use crate::{
    MAX_PACKET, MAX_WIRE, address, destination, inbound::ShadowsocksNode,
    outbound::ShadowsocksOutbound, protocol_error, replay::ReplayCache,
};
use bytes::BytesMut;
use kerlico_core::{
    AccessService, BoxFuture, CancellationToken, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, InboundContext, NodeEvent, NodeObserver, Result,
};
use shadowsocks::{
    ServerConfig,
    context::SharedContext,
    crypto::CipherKind,
    relay::{
        socks5::Address,
        udprelay::{crypto_io, options::UdpSocketControlData},
    },
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet, time::Instant};

fn nonce_len(method: CipherKind) -> usize {
    if method.is_aead() {
        method.salt_len()
    } else {
        method.iv_len()
    }
}
struct ClientSender {
    socket: Arc<UdpSocket>,
    config: Arc<ServerConfig>,
    crypto: SharedContext,
    target: Address,
    cancel: CancellationToken,
}
struct ClientReceiver {
    socket: Arc<UdpSocket>,
    config: Arc<ServerConfig>,
    crypto: SharedContext,
    target: Address,
    cancel: CancellationToken,
    replay: ReplayCache,
}
pub(crate) async fn connect(
    outbound: &ShadowsocksOutbound,
    target: &Destination,
    cancel: CancellationToken,
) -> Result<DatagramChannel> {
    let mut peers: Vec<_> =
        tokio::net::lookup_host((outbound.server.host().as_str(), outbound.server.port()))
            .await?
            .collect();
    peers.sort_by_key(|peer| peer.is_ipv6());
    let peer = peers.first().ok_or(Error::InvalidAddress)?;
    let socket = Arc::new(
        UdpSocket::bind(if peer.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .await?,
    );
    socket.connect(peer).await?;
    Ok(DatagramChannel {
        sender: Box::new(ClientSender {
            socket: socket.clone(),
            config: outbound.config.clone(),
            crypto: outbound.crypto.clone(),
            target: address(target),
            cancel: cancel.clone(),
        }),
        receiver: Box::new(ClientReceiver {
            socket,
            config: outbound.config.clone(),
            crypto: outbound.crypto.clone(),
            target: address(target),
            cancel,
            replay: ReplayCache::new(),
        }),
    })
}
impl DatagramSender for ClientSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if packet.len() > MAX_PACKET {
                return Err(Error::ResourceLimit);
            }
            let mut wire = BytesMut::new();
            crypto_io::encrypt_client_payload(
                &self.crypto,
                self.config.method(),
                self.config.key(),
                &self.target,
                &UdpSocketControlData::default(),
                &[],
                packet,
                &mut wire,
            );
            if wire.len() > MAX_WIRE {
                return Err(Error::ResourceLimit);
            }
            tokio::select! { biased; _ = self.cancel.cancelled() => Err(Error::Cancelled), result = self.socket.send(&wire) => {
                if result? != wire.len() { return Err(protocol_error()); } Ok(())
            } }
        })
    }
}
impl DatagramReceiver for ClientReceiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut wire = vec![0; 65_536];
            loop {
                let len = tokio::select! { biased; _ = self.cancel.cancelled() => return Err(Error::Cancelled), received = self.socket.recv(&mut wire) => received? };
                let salt_len = nonce_len(self.config.method());
                if len < salt_len {
                    continue;
                }
                let nonce = wire[..salt_len].to_vec();
                let Ok((count, source, None)) = crypto_io::decrypt_server_payload(
                    &self.crypto,
                    self.config.method(),
                    self.config.key(),
                    &mut wire[..len],
                ) else {
                    continue;
                };
                if count > MAX_PACKET || source.port() != self.target.port() {
                    continue;
                }
                if matches!((&self.target, &source), (Address::SocketAddress(a), Address::SocketAddress(b)) if a != b)
                {
                    continue;
                }
                if !self.replay.accept(&nonce) {
                    continue;
                }
                return Ok(Some(wire[..count].to_vec()));
            }
        })
    }
}
#[derive(Hash, Eq, PartialEq)]
struct Association {
    peer: SocketAddr,
    target: Destination,
}
struct Events(Arc<dyn NodeObserver>);
impl Drop for Events {
    fn drop(&mut self) {
        self.0.record(NodeEvent::Completed);
    }
}

impl ShadowsocksNode {
    /// 每个来源与目标持有独立通道和预算，不共享带节点身份的连接资源。
    pub async fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let mut sessions: HashMap<Association, mpsc::Sender<Vec<u8>>> = HashMap::new();
        let mut tasks = JoinSet::new();
        let mut replay = ReplayCache::new();
        let mut wire = vec![0; 65_536];
        let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(1));
        let result = loop {
            tokio::select! {
                biased;
                _ = context.cancel.cancelled() => break Ok(()),
                _ = tasks.join_next(), if !tasks.is_empty() => { sessions.retain(|_, sender| !sender.is_closed()); },
                _ = maintenance.tick() => { sessions.retain(|_, sender| !sender.is_closed()); },
                received = socket.recv_from(&mut wire) => {
                    let (len, peer) = match received { Ok(value) => value, Err(error) => break Err(error.into()) };
                    let salt_len = nonce_len(self.config.method());
                    if len < salt_len { continue; }
                    let nonce = wire[..salt_len].to_vec();
                    let Ok((count, target, None)) = crypto_io::decrypt_client_payload(&self.crypto, self.config.method(), self.config.key(), &mut wire[..len], None) else { continue; };
                    if count > context.max_datagram_size.min(MAX_PACKET) { continue; }
                    let Ok(target) = destination(&target) else { continue; };
                    if !replay.accept(&nonce) { context.events.record(NodeEvent::Dropped); continue; }
                    let key = Association { peer, target: target.clone() };
                    if let Some(sender) = sessions.get(&key) {
                        if sender.try_send(wire[..count].to_vec()).is_err() { context.events.record(NodeEvent::Dropped); }
                        continue;
                    }
                    sessions.retain(|_, sender| !sender.is_closed());
                    if sessions.len() >= context.max_streams { context.events.record(NodeEvent::Dropped); continue; }
                    let Ok(lease) = context.stream_budget.try_acquire() else { context.events.record(NodeEvent::Dropped); continue; };
                    let (sender, receiver) = mpsc::channel(32);
                    if sender.try_send(wire[..count].to_vec()).is_err() { continue; }
                    sessions.insert(key, sender);
                    context.events.record(NodeEvent::Accepted);
                    let config = self.config.clone(); let crypto = self.crypto.clone();
                    let socket = socket.clone(); let access = access.clone(); let context = context.clone();
                    tasks.spawn(async move {
                        let _lease = lease; let _events = Events(context.events.clone());
                        let events = context.events.clone();
                        if target_session(socket, access, context, config, crypto, peer, target, receiver).await.is_err() { events.record(NodeEvent::Failed); }
                    });
                },
            }
        };
        drop(sessions);
        if tokio::time::timeout(context.drain_timeout, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        result
    }
}
#[allow(clippy::too_many_arguments)]
async fn target_session(
    socket: Arc<UdpSocket>,
    access: Arc<dyn AccessService>,
    context: InboundContext,
    config: Arc<ServerConfig>,
    crypto: SharedContext,
    peer: SocketAddr,
    target: Destination,
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
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _ = context.cancel.cancelled() => return Ok(()),
            _ = &mut timer => return Ok(()),
            packet = packets.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                tokio::select! { biased; _ = context.cancel.cancelled() => return Ok(()), result = tokio::time::timeout(context.idle_timeout, sender.send(&packet)) => result.map_err(|_| Error::Timeout)?? }
                timer.as_mut().reset(Instant::now() + context.idle_timeout);
            },
            packet = receiver.recv() => {
                let Some(packet) = packet? else { return Ok(()); };
                if packet.len() > context.max_datagram_size.min(MAX_PACKET) { return Err(Error::ResourceLimit); }
                let mut wire = BytesMut::new();
                crypto_io::encrypt_server_payload(&crypto, config.method(), config.key(), &target, &UdpSocketControlData::default(), &packet, &mut wire);
                if wire.len() > MAX_WIRE { return Err(Error::ResourceLimit); }
                tokio::select! { biased; _ = context.cancel.cancelled() => return Ok(()), sent = tokio::time::timeout(context.idle_timeout, socket.send_to(&wire, peer)) => {
                    if sent.map_err(|_| Error::Timeout)?? != wire.len() { return Err(protocol_error()); }
                } }
                timer.as_mut().reset(Instant::now() + context.idle_timeout);
            },
        }
    }
}
