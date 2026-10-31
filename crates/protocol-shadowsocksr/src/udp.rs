use crate::{
    MAX_PACKET, address, config::Shared, crypto, destination, inbound::ShadowsocksRNode, invalid,
    outbound::ShadowsocksROutbound, protocol::UdpCodec,
};
use bytes::BytesMut;
use kerlico_core::{
    AccessService, AddressedDatagram, BoxFuture, CancellationToken, ConnectContext,
    DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, Error, InboundContext, NodeEvent, NodeObserver,
    Result,
};
use shadowsocks::relay::socks5::Address;
use std::{
    collections::HashMap,
    io::Cursor,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
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
    let mut candidates: Vec<_> =
        tokio::net::lookup_host((outbound.server.host().as_str(), outbound.server.port()))
            .await?
            .collect();
    candidates.sort_by_key(|peer| peer.is_ipv6());
    let peer = candidates.first().ok_or(Error::InvalidAddress)?;
    let socket = Arc::new(
        UdpSocket::bind(if peer.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .await?,
    );
    socket.connect(peer).await?;
    Ok((
        socket,
        Arc::new(UdpCodec::new(outbound.cfg.clone())),
        Arc::new(Lease { _permit: permit }),
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
    seen: Arc<Mutex<Instant>>,
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
}
impl ShadowsocksRNode {
    pub async fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        if !self.cfg.udp {
            return Err(Error::Unsupported("SSR 节点未启用 UDP"));
        }
        if !self.cfg.authenticated() && !socket.local_addr()?.ip().is_loopback() {
            return Err(Error::Unsupported("未鉴权 SSR UDP 只能用作回环本地接入"));
        }
        if !access.supports_udp_association() {
            return Err(Error::Unsupported("SSR UDP 需要同源口多目标访问服务"));
        }
        let codec = Arc::new(UdpCodec::new(self.cfg.clone()));
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
                _ = maintenance.tick()=>{let moment=Instant::now();entries.retain(|_,entry|!entry.sender.is_closed()&&entry.seen.lock().is_ok_and(|seen|moment.duration_since(*seen)<context.idle_timeout));},
                received=socket.recv_from(&mut buffer)=>{
                    let (count,peer)=received?;let Ok((iv,plain))=decode(&self.cfg,&buffer[..count]) else{continue};let Ok(decoded)=codec.decode_client(&plain) else{continue};let Ok((target,payload))=unpack(&decoded.data) else{continue};if payload.len()>context.max_datagram_size.min(MAX_PACKET){continue;}
                    if self.cfg.replay.nonce(&iv).is_err(){context.events.record(NodeEvent::Dropped);continue;}
                    if iv.is_empty()&&decoded.replay&&self.cfg.replay.insert(b"udp-chain-request",&plain,Duration::from_secs(120)).is_err(){context.events.record(NodeEvent::Dropped);continue;}
                    entries.retain(|_,entry|!entry.sender.is_closed());let key=Key{peer,user:decoded.user};
                    if !entries.contains_key(&key){
                        if entries.len()>=context.max_streams.min(self.cfg.limits.max_sessions)||context.stream_budget.is_closed(){context.events.record(NodeEvent::Dropped);continue;}
                        let Ok(global)=context.stream_budget.try_acquire() else{context.events.record(NodeEvent::Dropped);continue;};let Ok(local)=self.slots.clone().try_acquire_owned() else{context.events.record(NodeEvent::Dropped);continue;};
                        let (sender,receiver)=mpsc::channel(self.cfg.limits.udp_queue_packets);let seen=Arc::new(Mutex::new(Instant::now()));let token=context.cancel.child_token();let mut child=context.clone();child.cancel=token.clone();entries.insert(key,Entry{sender,seen:seen.clone(),cancel:token});
                        let socket=socket.clone();let codec=codec.clone();let access=access.clone();let uid=decoded.user;context.events.record(NodeEvent::Accepted);
                        tasks.spawn(async move{let _global=global;let _local=local;let _events=Events(child.events.clone());if session(socket,codec,access,child.clone(),peer,uid,seen,receiver).await.is_err(){child.events.record(NodeEvent::Failed);}});
                    }
                    let Some(entry)=entries.get(&Key{peer,user:decoded.user}) else{continue};if let Ok(mut seen)=entry.seen.lock(){*seen=Instant::now();}
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
    access: Arc<dyn AccessService>,
    context: InboundContext,
    peer: SocketAddr,
    user: Option<u32>,
    seen: Arc<Mutex<Instant>>,
    mut packets: mpsc::Receiver<Queued>,
) -> Result<()> {
    let establish = ConnectContext {
        cancel: context.cancel.clone(),
        timeout: context.connect_timeout,
    };
    let mut channel = establish.run(access.associate_udp(&establish)).await?;
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _ = context.cancel.cancelled()=>return Ok(()),_ = &mut timer=>return Ok(()),
            packet=packets.recv()=>{let Some(Queued{packet:(target,payload),..})=packet else{return Ok(())};tokio::select!{_ = context.cancel.cancelled()=>return Ok(()),result=tokio::time::timeout(context.idle_timeout,channel.sender.send_to(&payload,&target))=>result.map_err(|_|Error::Timeout)??}if let Ok(mut seen)=seen.lock(){*seen=Instant::now();}timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);},
            packet=channel.receiver.recv_from()=>{let Some((source,payload))=packet? else{return Ok(())};if payload.len()>context.max_datagram_size.min(MAX_PACKET){return Err(Error::ResourceLimit);}let body=codec.encode_server(&pack(&source,&payload),user)?;let bytes=encode(&codec.cfg,&body)?;
                tokio::select!{_ = context.cancel.cancelled()=>return Ok(()),result=tokio::time::timeout(context.idle_timeout,socket.send_to(&bytes,peer))=>{if result.map_err(|_|Error::Timeout)??!=bytes.len(){return Err(invalid());}}}
                if let Ok(mut seen)=seen.lock(){*seen=Instant::now();}timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);
            }
        }
    }
}
