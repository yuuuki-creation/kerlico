use crate::{
    MAX_PACKET, address, config::Shared, crypto, destination, inbound::ShadowsocksRNode, invalid,
    outbound::ShadowsocksROutbound, protocol::UdpCodec,
};
use bytes::BytesMut;
use kerlico_core::{
    AddressedDatagram, BoxFuture, CancellationToken, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, InboundContext, IngressBinding, NodeEvent, NodeObserver,
    PeerSession, Result, is_peer_path_error,
};
use shadowsocks::relay::socks5::Address;
use std::{collections::HashMap, io::Cursor, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
};

fn encode(cfg: &Shared, data: &[u8]) -> Result<Vec<u8>> {
    let iv = crypto::random(cfg.method.iv_len());
    let mut cipher = crypto::State::new(cfg.method, &cfg.key, &iv)?;
    let mut bytes = data.to_vec();
    cipher.apply(&mut bytes, true)?;
    let mut output = iv;
    output.extend(bytes);
    if output.len() > 65507 {
        return Err(Error::ResourceLimit);
    }
    Ok(output)
}
fn decode(cfg: &Shared, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let size = cfg.method.iv_len();
    if data.len() < size {
        return Err(invalid());
    }
    let iv = data[..size].to_vec();
    let mut bytes = data[size..].to_vec();
    let mut cipher = crypto::State::new(cfg.method, &cfg.key, &iv)?;
    cipher.apply(&mut bytes, false)?;
    Ok((iv, bytes))
}
fn unpack(data: &[u8]) -> Result<AddressedDatagram> {
    let mut cursor = Cursor::new(data);
    let source = Address::read_cursor(&mut cursor).map_err(|_| invalid())?;
    let count = cursor.position() as usize;
    Ok((destination(&source)?, data[count..].to_vec()))
}
fn pack(target: &Destination, payload: &[u8]) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    address(target).write_to_buf(&mut bytes);
    bytes.extend_from_slice(payload);
    bytes.to_vec()
}
struct Lease {
    _permit: OwnedSemaphorePermit,
    _relay: Option<kerlico_core::dialer::RelayGuard>,
}
struct PacketSender {
    socket: Arc<UdpSocket>,
    codec: Arc<UdpCodec>,
    target: Option<Destination>,
    cancel: CancellationToken,
    _lease: Arc<Lease>,
}
struct PacketReceiver {
    socket: Arc<UdpSocket>,
    codec: Arc<UdpCodec>,
    target: Option<Destination>,
    cancel: CancellationToken,
    _lease: Arc<Lease>,
}
async fn open(
    outbound: &ShadowsocksROutbound,
) -> Result<(Arc<UdpSocket>, Arc<UdpCodec>, Arc<Lease>)> {
    if !outbound.cfg.udp {
        return Err(Error::Unsupported("SSR 出站未启用 UDP"));
    }
    let permit = outbound
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::ResourceLimit)?;
    let kerlico_core::UdpPeer {
        socket,
        peer,
        relay,
    } = outbound.dialer.udp_peer(&outbound.server).await?;
    let socket = Arc::new(UdpSocket::from_std(socket)?);
    socket.connect(peer).await?;
    Ok((
        socket,
        Arc::new(UdpCodec::new(outbound.cfg.clone())),
        Arc::new(Lease {
            _permit: permit,
            _relay: relay,
        }),
    ))
}
pub(crate) async fn fixed(
    outbound: &ShadowsocksROutbound,
    target: &Destination,
    cancel: CancellationToken,
) -> Result<DatagramChannel> {
    let (socket, codec, lease) = open(outbound).await?;
    Ok(DatagramChannel {
        sender: Box::new(PacketSender {
            socket: socket.clone(),
            codec: codec.clone(),
            target: Some(target.clone()),
            cancel: cancel.clone(),
            _lease: lease.clone(),
        }),
        receiver: Box::new(PacketReceiver {
            socket,
            codec,
            target: Some(target.clone()),
            cancel,
            _lease: lease,
        }),
    })
}
pub(crate) async fn association(
    outbound: &ShadowsocksROutbound,
    cancel: CancellationToken,
) -> Result<DatagramAssociation> {
    let (socket, codec, lease) = open(outbound).await?;
    Ok(DatagramAssociation {
        sender: Box::new(PacketSender {
            socket: socket.clone(),
            codec: codec.clone(),
            target: None,
            cancel: cancel.clone(),
            _lease: lease.clone(),
        }),
        receiver: Box::new(PacketReceiver {
            socket,
            codec,
            target: None,
            cancel,
            _lease: lease,
        }),
    })
}
impl PacketSender {
    async fn packet(&mut self, payload: &[u8], target: &Destination) -> Result<()> {
        if payload.len() > MAX_PACKET {
            return Err(Error::ResourceLimit);
        }
        let bytes = self.codec.encode_client(&pack(target, payload))?;
        let wire = encode(&self.codec.cfg, &bytes)?;
        tokio::select! {biased;_ = self.cancel.cancelled()=>Err(Error::Cancelled),result=self.socket.send(&wire)=>{if result?!=wire.len(){return Err(invalid());}Ok(())}}
    }
}
impl DatagramSender for PacketSender {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let target = self.target.clone().ok_or_else(invalid)?;
            self.packet(payload, &target).await
        })
    }
}
impl DatagramAssociationSender for PacketSender {
    fn send_to<'a>(
        &'a mut self,
        payload: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.packet(payload, target))
    }
}
impl PacketReceiver {
    async fn packet(&mut self) -> Result<Option<AddressedDatagram>> {
        let mut buffer = vec![0; 65536];
        loop {
            let count = tokio::select! {biased;_ = self.cancel.cancelled()=>return Err(Error::Cancelled),received=self.socket.recv(&mut buffer)=>received?};
            let Ok((iv, plain)) = decode(&self.codec.cfg, &buffer[..count]) else {
                continue;
            };
            let Ok(decoded) = self.codec.decode_server(&plain) else {
                continue;
            };
            let Ok((source, payload)) = unpack(&decoded.data) else {
                continue;
            };
            if payload.len() > MAX_PACKET {
                continue;
            }
            if let Some(target) = &self.target
                && (source.port() != target.port()
                    || matches!(target.address(), kerlico_core::Address::Ip(_))
                        && source != *target)
            {
                continue;
            }
            if self.codec.cfg.replay.nonce(&iv).is_err() {
                continue;
            }
            if iv.is_empty()
                && decoded.replay
                && self
                    .codec
                    .cfg
                    .replay
                    .insert(b"udp-chain-reply", &plain, Duration::from_secs(120))
                    .is_err()
            {
                continue;
            }
            return Ok(Some((source, payload)));
        }
    }
}
impl DatagramReceiver for PacketReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        self.target.clone()
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move { Ok(self.packet().await?.map(|(_, payload)| payload)) })
    }
}
impl DatagramAssociationReceiver for PacketReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(self.packet())
    }
}
struct Queued {
    packet: AddressedDatagram,
    _bytes: OwnedSemaphorePermit,
}
struct Entry {
    sender: mpsc::Sender<Queued>,
    cancel: CancellationToken,
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct Events(Arc<dyn NodeObserver>);
impl Drop for Events {
    fn drop(&mut self) {
        self.0.record(NodeEvent::Completed);
    }
}
#[derive(Hash, PartialEq, Eq)]
struct Key {
    peer: SocketAddr,
    user: Option<u32>,
    group: usize,
}
impl ShadowsocksRNode {
    pub async fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        if !self.cfg.udp {
            return Err(Error::Unsupported("SSR 节点未启用 UDP"));
        }
        if !self.cfg.authenticated() && !socket.local_addr()?.ip().is_loopback() {
            return Err(Error::Unsupported("未鉴权 SSR UDP 只能用作回环本地接入"));
        }
        if !ingress.supports_udp_association() {
            return Err(Error::Unsupported("SSR UDP 需要同源口多目标访问服务"));
        }
        let codecs: Vec<_> = self
            .groups
            .iter()
            .map(|cfg| Arc::new(UdpCodec::new(cfg.clone())))
            .collect();
        let byte_budget = Arc::new(Semaphore::new(self.cfg.limits.udp_queue_bytes));
        let mut entries: HashMap<Key, Entry> = HashMap::new();
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; 65536];
        let mut maintenance = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                biased;
                _ = context.cancel.cancelled()=>break,
                _ = tasks.join_next(),if !tasks.is_empty()=>{entries.retain(|_,entry|!entry.sender.is_closed());},
                _ = maintenance.tick()=>{entries.retain(|_,entry|!entry.sender.is_closed());},
                received=socket.recv_from(&mut buffer)=>{
                    let (count,peer)=match received {
                        Ok(value)=>value,
                        Err(error) if is_peer_path_error(&error)=>{context.events.record(NodeEvent::Dropped);continue;}
                        Err(error)=>return Err(error.into()),
                    };
                    let mut selected = None;
                    for (group, codec) in codecs.iter().enumerate() {
                        let Ok((iv, plain)) = decode(&codec.cfg, &buffer[..count]) else { continue; };
                        let Ok(decoded) = codec.decode_client(&plain) else { continue; };
                        let Ok((target, payload)) = unpack(&decoded.data) else { continue; };
                        if payload.len() > context.max_datagram_size.min(MAX_PACKET) { continue; }
                        let mut peer_context = context.clone(); peer_context.peer_addr = Some(peer);
                        let access = if self.credentials.is_empty() { ingress.local(&peer_context) } else {
                            let Some((slot, _)) = self.credentials.rows().find(|(_, row)| row.group == group && row.user == decoded.user) else { continue; };
                            self.credentials.verified(&slot, ()).and_then(|verified| ingress.authenticated(verified, &peer_context)).map(|(access, ())| access)
                        };
                        // 停用成员的密钥仍能解密；拒绝只丢这一个数据报，取消由循环顶部处理。
                        let Ok(access) = access else { selected = None; break; };
                        if selected.is_some() { selected = None; break; }
                        selected = Some((group, codec.clone(), iv, plain, decoded, target, payload, access));
                    }
                    let Some((group, codec, iv, plain, decoded, target, payload, access)) = selected else { context.events.record(NodeEvent::Dropped); continue; };
                    if codec.cfg.replay.nonce(&iv).is_err(){context.events.record(NodeEvent::Dropped);continue;}
                    if iv.is_empty()&&decoded.replay&&codec.cfg.replay.insert(b"udp-chain-request",&plain,Duration::from_secs(120)).is_err(){context.events.record(NodeEvent::Dropped);continue;}
                    entries.retain(|_,entry|!entry.sender.is_closed());let key=Key{peer,user:decoded.user,group};
                    if !entries.contains_key(&key){
                        if entries.len()>=context.max_streams.min(self.cfg.limits.max_sessions)||context.stream_budget.is_closed(){context.events.record(NodeEvent::Dropped);continue;}
                        let Ok(global)=context.stream_budget.try_acquire() else{context.events.record(NodeEvent::Dropped);continue;};let Ok(local)=self.slots.clone().try_acquire_owned() else{context.events.record(NodeEvent::Dropped);continue;};
                        let (sender,receiver)=mpsc::channel(self.cfg.limits.udp_queue_packets);let token=context.cancel.child_token();let mut child=context.clone();child.cancel=token.clone();entries.insert(key,Entry{sender,cancel:token});
                        let socket=socket.clone();let codec=codec.clone();let access=access.clone();let uid=decoded.user;context.events.record(NodeEvent::Accepted);
                        let owner=child.tasks.clone();
                    let task=owner.spawn_tracked(async move {let _global=global;let _local=local;let _events=Events(child.events.clone());if session(socket,codec,access,child.clone(),peer,uid,receiver).await.is_err(){child.events.record(NodeEvent::Failed);}})?;
                    tasks.spawn(async move {let _=task.await;});
                    }
                    let Some(entry)=entries.get(&Key{peer,user:decoded.user,group}) else{continue};
                    let Ok(permit)=byte_budget.clone().try_acquire_many_owned(payload.len() as u32) else{context.events.record(NodeEvent::Dropped);continue;};if entry.sender.try_send(Queued{packet:(target,payload),_bytes:permit}).is_err(){context.events.record(NodeEvent::Dropped);}
                }
            }
        }
        drop(entries);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
async fn session(
    socket: Arc<UdpSocket>,
    codec: Arc<UdpCodec>,
    access: PeerSession,
    context: InboundContext,
    peer: SocketAddr,
    user: Option<u32>,
    mut packets: mpsc::Receiver<Queued>,
) -> Result<()> {
    let establish =
        ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    let channel = establish.run(access.associate_udp(&establish)).await?;
    let (mut sender, mut receiver, completion) = channel.into_parts();
    let mut accepting_packets = true;
    let result = async {
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        let received={let receiving=receiver.recv_from();tokio::pin!(receiving);loop {
        tokio::select! {
            biased;
            _ = context.cancel.cancelled()=>return Err(Error::Cancelled),_ = &mut timer=>return Err(Error::Timeout),
            packet=packets.recv(),if accepting_packets=>{let Some(Queued{packet:(target,payload),..})=packet else{accepting_packets=false;continue;};tokio::select!{_ = context.cancel.cancelled()=>return Err(Error::Cancelled),result=tokio::time::timeout(context.idle_timeout,sender.send_to(&payload,&target))=>result.map_err(|_|Error::Timeout)??}timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);},
            packet=&mut receiving=>break packet?,
        }}};
        let Some((source,payload))=received else{return Ok(())};if payload.len()>context.max_datagram_size.min(MAX_PACKET){return Err(Error::ResourceLimit);}let body=codec.encode_server(&pack(&source,&payload),user)?;let bytes=encode(&codec.cfg,&body)?;
                tokio::select!{_ = context.cancel.cancelled()=>return Err(Error::Cancelled),result=tokio::time::timeout(context.idle_timeout,socket.send_to(&bytes,peer))=>{if result.map_err(|_|Error::Timeout)??!=bytes.len(){return Err(invalid());}}}
                timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);
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
