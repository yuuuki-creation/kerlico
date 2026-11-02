use crate::{
    MAX_PACKET, MAX_WIRE, address, destination, inbound::ShadowsocksNode,
    outbound::ShadowsocksOutbound, protocol_error, replay::ReplayCache,
};
use bytes::BytesMut;
use kerlico_core::{
    BoxFuture, CancellationToken, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, InboundContext, IngressBinding, NodeEvent, NodeObserver,
    PeerSession, Result, is_peer_path_error,
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
    credential: Vec<u8>,
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
        ingress: IngressBinding,
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
                    let (len, peer) = match received {
                        Ok(value) => value,
                        Err(error) if is_peer_path_error(&error) => { context.events.record(NodeEvent::Dropped); continue; }
                        Err(error) => break Err(error.into()),
                    };
                    let configurations: Vec<_> = if self.credentials.is_empty() { vec![(None, self.config.clone())] } else { self.credentials.rows().map(|(slot, row)| (Some(slot), row.config.clone())).collect() };
                    let mut decoded = None;
                    for (slot, config) in configurations {
                        let salt_len = nonce_len(config.method()); if len < salt_len { continue; }
                        let nonce = wire[..salt_len].to_vec(); let mut bytes = wire[..len].to_vec();
                        if let Ok((count, target, None)) = crypto_io::decrypt_client_payload(&self.crypto, config.method(), config.key(), &mut bytes, None) {
                            if count > context.max_datagram_size.min(MAX_PACKET) { continue; }
                            let Ok(target) = destination(&target) else { continue; };
                            // 停用成员的密钥仍能解密；拒绝只丢这一个数据报，取消由循环顶部处理。
                            let mut peer_context = context.clone(); peer_context.peer_addr = Some(peer);
                            let access = match slot {
                                Some(slot) => self.credentials.verified(&slot, ()).and_then(|verified| ingress.authenticated(verified, &peer_context)).map(|(access, ())| access),
                                None => ingress.local(&peer_context),
                            };
                            let Ok(access) = access else { break; };
                            bytes.truncate(count); decoded = Some((config, nonce, target, bytes, access)); break;
                        }
                    }
                    let Some((config, nonce, target, packet, access)) = decoded else { context.events.record(NodeEvent::Dropped); continue; };
                    let scoped_nonce = if nonce.is_empty() { nonce } else { let mut scoped = config.key().to_vec(); scoped.extend_from_slice(&nonce); scoped };
                    if !replay.accept(&scoped_nonce) { context.events.record(NodeEvent::Dropped); continue; }
                    let key = Association { peer, target: target.clone(), credential: config.key().to_vec() };
                    if let Some(sender) = sessions.get(&key) {
                        if sender.try_send(packet.clone()).is_err() { context.events.record(NodeEvent::Dropped); }
                        continue;
                    }
                    sessions.retain(|_, sender| !sender.is_closed());
                    if sessions.len() >= context.max_streams { context.events.record(NodeEvent::Dropped); continue; }
                    let Ok(lease) = context.stream_budget.try_acquire() else { context.events.record(NodeEvent::Dropped); continue; };
                    let (sender, receiver) = mpsc::channel(32);
                    if sender.try_send(packet.clone()).is_err() { continue; }
                    sessions.insert(key, sender);
                    context.events.record(NodeEvent::Accepted);
                    let crypto = self.crypto.clone();
                    let socket = socket.clone(); let access = access.clone(); let context = context.clone();
                    let owner=context.tasks.clone();
                    let task=owner.spawn_tracked(async move {
                        let _lease = lease; let _events = Events(context.events.clone());
                        let events = context.events.clone();
                        if target_session(socket, access, context, config, crypto, peer, target, receiver).await.is_err() { events.record(NodeEvent::Failed); }
                    })?;
                    tasks.spawn(async move {let _=task.await;});
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
    access: PeerSession,
    context: InboundContext,
    config: Arc<ServerConfig>,
    crypto: SharedContext,
    peer: SocketAddr,
    target: Destination,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let budget = ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    let channel = budget.run(access.connect_udp(&target, &budget)).await?;
    let (mut sender, mut receiver, completion) = channel.into_parts();
    let target = address(&target);
    let mut accepting_packets = true;
    let result = async {
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        let received={let receiving=receiver.recv();tokio::pin!(receiving);loop {
        tokio::select! {
            biased;
            _ = context.cancel.cancelled() => return Err(Error::Cancelled),
            _ = &mut timer => return Err(Error::Timeout),
            packet = packets.recv(), if accepting_packets => {
                let Some(packet) = packet else { accepting_packets = false; continue; };
                tokio::select! { biased; _ = context.cancel.cancelled() => return Err(Error::Cancelled), result = tokio::time::timeout(context.idle_timeout, sender.send(&packet)) => result.map_err(|_| Error::Timeout)?? }
                timer.as_mut().reset(Instant::now() + context.idle_timeout);
            },
            packet = &mut receiving => break packet?,
        }
        }};
                let Some(packet) = received else { return Ok(()); };
                if packet.len() > context.max_datagram_size.min(MAX_PACKET) { return Err(Error::ResourceLimit); }
                let mut wire = BytesMut::new();
                crypto_io::encrypt_server_payload(&crypto, config.method(), config.key(), &target, &UdpSocketControlData::default(), &packet, &mut wire);
                if wire.len() > MAX_WIRE { return Err(Error::ResourceLimit); }
                tokio::select! { biased; _ = context.cancel.cancelled() => return Err(Error::Cancelled), sent = tokio::time::timeout(context.idle_timeout, socket.send_to(&wire, peer)) => {
                    if sent.map_err(|_| Error::Timeout)?? != wire.len() { return Err(protocol_error()); }
                } }
                timer.as_mut().reset(Instant::now() + context.idle_timeout);
    }
}.await;
    completion.finish(match &result {
        Ok(()) => kerlico_core::FlowOutcome::ProtocolEnd,
        Err(error) => {
            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::from_error(error))
        }
    });
    result
}

#[cfg(test)]
#[path = "udp_flow_tests.rs"]
mod flow_tests;
