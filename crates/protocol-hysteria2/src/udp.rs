use crate::{
    config::Limits,
    invalid,
    wire::{MAX_PAYLOAD, Packet, Reassembly},
};
use bytes::Bytes;
use kerlico_core::{
    AddressedDatagram, BoxFuture, CancellationToken, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, InboundContext, NodeEvent, NodeObserver, PeerSession,
    Result, ServiceContext, ServiceTask,
};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
};

type PeerSlot = Arc<std::sync::Mutex<Option<([u8; 32], PeerSession)>>>;

struct Delivered {
    source: Destination,
    payload: Vec<u8>,
    _bytes: OwnedSemaphorePermit,
}
struct Sink {
    sender: mpsc::Sender<Delivered>,
    reassembly: Reassembly,
}
pub(crate) struct Registry {
    entries: Mutex<HashMap<u32, Sink>>,
    next: AtomicU64,
    bytes: Arc<Semaphore>,
    limits: Limits,
}
impl Registry {
    pub(crate) fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            bytes: Arc::new(Semaphore::new(limits.udp_queue_bytes)),
            limits,
        })
    }
    fn register(self: &Arc<Self>) -> Result<(Arc<Lease>, mpsc::Receiver<Delivered>)> {
        let mut entries = self.entries.lock().map_err(|_| invalid())?;
        if entries.len() >= self.limits.max_streams {
            return Err(Error::ResourceLimit);
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let id = u32::try_from(id).map_err(|_| Error::ResourceLimit)?;
        let (sender, receiver) = mpsc::channel(self.limits.udp_queue_packets);
        entries.insert(
            id,
            Sink {
                sender,
                reassembly: Reassembly::new(MAX_PAYLOAD),
            },
        );
        Ok((
            Arc::new(Lease {
                registry: self.clone(),
                id,
            }),
            receiver,
        ))
    }
    pub(crate) fn spawn(
        self: &Arc<Self>,
        connection: quinn::Connection,
        host: &ServiceContext,
    ) -> Result<ServiceTask<()>> {
        let registry = self.clone();
        host.spawn_tracked(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = timer.tick()=> {if let Ok(mut entries)=registry.entries.lock() {for entry in entries.values_mut(){entry.reassembly.expire(Instant::now());}}},
                    bytes=connection.read_datagram()=> {
                        let Ok(bytes)=bytes else{break};let Ok(packet)=Packet::decode(&bytes) else{continue};
                        let Ok(mut entries)=registry.entries.lock() else{break};let Some(entry)=entries.get_mut(&packet.session) else{continue};
                        let Ok(Some((source,payload)))=entry.reassembly.feed(packet) else{continue};let Ok(source)=crate::target(&source) else{continue};
                        let Ok(permit)=registry.bytes.clone().try_acquire_many_owned(payload.len() as u32) else{continue};
                        let _=entry.sender.try_send(Delivered{source,payload,_bytes:permit});
                    }
                }
            }
            if let Ok(mut entries) = registry.entries.lock() {
                entries.clear();
            }
        })
    }
}
struct Lease {
    registry: Arc<Registry>,
    id: u32,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.registry.entries.lock() {
            entries.remove(&self.id);
        }
    }
}
struct PacketSender {
    connection: quinn::Connection,
    lease: Arc<Lease>,
    cancel: CancellationToken,
    target: Option<Destination>,
    packet: u16,
    _owner: Arc<dyn Send + Sync>,
}
struct PacketReceiver {
    receiver: mpsc::Receiver<Delivered>,
    cancel: CancellationToken,
    target: Option<Destination>,
    _lease: Arc<Lease>,
    _owner: Arc<dyn Send + Sync>,
}
impl PacketSender {
    async fn packet(&mut self, packet: &[u8], target: &Destination) -> Result<()> {
        if packet.len() > MAX_PAYLOAD {
            return Err(Error::ResourceLimit);
        }
        let message = Packet {
            session: self.lease.id,
            id: self.packet,
            index: 0,
            count: 1,
            address: target.to_string(),
            payload: packet.to_vec(),
        };
        self.packet = self.packet.wrapping_add(1);
        send_packet(&self.connection, &message, &self.cancel).await
    }
}
impl DatagramSender for PacketSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let target = self.target.clone().ok_or_else(invalid)?;
            self.packet(packet, &target).await
        })
    }
}
impl DatagramAssociationSender for PacketSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.packet(packet, target))
    }
}
impl PacketReceiver {
    async fn packet(&mut self) -> Result<Option<AddressedDatagram>> {
        loop {
            let received = tokio::select! {biased;_ = self.cancel.cancelled()=>return Err(Error::Cancelled),packet=self.receiver.recv()=>packet};
            let Some(Delivered {
                source, payload, ..
            }) = received
            else {
                return Ok(None);
            };
            if let Some(target) = &self.target {
                if source.port() != target.port() {
                    continue;
                }
                if matches!(target.address(), kerlico_core::Address::Ip(_)) && &source != target {
                    continue;
                }
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
pub(crate) fn fixed(
    registry: &Arc<Registry>,
    connection: quinn::Connection,
    target: Destination,
    cancel: CancellationToken,
    owner: Arc<dyn Send + Sync>,
) -> Result<DatagramChannel> {
    let (lease, receiver) = registry.register()?;
    Ok(DatagramChannel {
        sender: Box::new(PacketSender {
            connection,
            lease: lease.clone(),
            cancel: cancel.clone(),
            target: Some(target.clone()),
            packet: 0,
            _owner: owner.clone(),
        }),
        receiver: Box::new(PacketReceiver {
            receiver,
            cancel,
            target: Some(target),
            _lease: lease,
            _owner: owner,
        }),
    })
}
pub(crate) fn association(
    registry: &Arc<Registry>,
    connection: quinn::Connection,
    cancel: CancellationToken,
    owner: Arc<dyn Send + Sync>,
) -> Result<DatagramAssociation> {
    let (lease, receiver) = registry.register()?;
    Ok(DatagramAssociation {
        sender: Box::new(PacketSender {
            connection,
            lease: lease.clone(),
            cancel: cancel.clone(),
            target: None,
            packet: 0,
            _owner: owner.clone(),
        }),
        receiver: Box::new(PacketReceiver {
            receiver,
            cancel,
            target: None,
            _lease: lease,
            _owner: owner,
        }),
    })
}
async fn send_packet(
    connection: &quinn::Connection,
    packet: &Packet,
    cancel: &CancellationToken,
) -> Result<()> {
    let limit = connection
        .max_datagram_size()
        .ok_or(Error::Unsupported("Hysteria2 对端未启用 QUIC 数据报"))?;
    for fragment in packet.fragments(limit)? {
        tokio::select! {biased;_ = cancel.cancelled()=>return Err(Error::Cancelled),result=connection.send_datagram_wait(Bytes::from(fragment))=>result.map_err(|_|invalid())?}
    }
    Ok(())
}
struct ServerPacket {
    packet: AddressedDatagram,
    _bytes: OwnedSemaphorePermit,
}
struct ServerSink {
    sender: mpsc::Sender<ServerPacket>,
    reassembly: Reassembly,
}
struct Events(Arc<dyn NodeObserver>);
impl Drop for Events {
    fn drop(&mut self) {
        self.0.record(NodeEvent::Completed);
    }
}
pub(crate) async fn server(
    connection: quinn::Connection,
    peer: PeerSlot,
    context: InboundContext,
    limits: Limits,
    ready: Arc<Notify>,
    flows: Arc<crate::flow::FlowSet>,
) -> Result<()> {
    tokio::select! {
        biased;
        _ = context.cancel.cancelled()=>return Err(Error::Cancelled),
        _ = connection.closed()=>return Err(invalid()),
        _ = flows.admission_stopped()=>return Ok(()),
        _ = ready.notified()=>{},
    }
    let access = peer
        .lock()
        .map_err(|_| invalid())?
        .as_ref()
        .map(|(_, peer)| peer.clone())
        .ok_or(Error::Rejected)?;
    let mut sessions: HashMap<u32, ServerSink> = HashMap::new();
    let mut tasks = JoinSet::new();
    let queue_bytes = Arc::new(Semaphore::new(limits.udp_queue_bytes));
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
    let result = async {
    loop {
        if !flows.is_accepting() && sessions.is_empty() && tasks.is_empty() {
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = context.cancel.cancelled()=>return Err(Error::Cancelled),
            _ = connection.closed()=>return Err(invalid()),
            _ = flows.admission_stopped(),if flows.is_accepting()=>{},
            _ = tasks.join_next(),if !tasks.is_empty()=>{sessions.retain(|_,entry|!entry.sender.is_closed());},
            _ = timer.tick()=>{let now=Instant::now();sessions.retain(|_,entry|!entry.sender.is_closed());for entry in sessions.values_mut(){entry.reassembly.expire(now);}},
            bytes=connection.read_datagram()=> {
                let bytes=bytes.map_err(|_|invalid())?;let Ok(packet)=Packet::decode(&bytes) else{continue};let id=packet.session;sessions.retain(|_,entry|!entry.sender.is_closed());
                if !sessions.contains_key(&id) {
                    if !flows.is_accepting()||sessions.len()>=limits.max_streams.min(context.max_streams)||context.stream_budget.is_closed(){context.events.record(NodeEvent::Dropped);continue;}
                    let Ok(lease)=context.stream_budget.try_acquire() else{context.events.record(NodeEvent::Dropped);continue;};
                    let (sender,receiver)=mpsc::channel(limits.udp_queue_packets);sessions.insert(id,ServerSink{sender,reassembly:Reassembly::new(context.max_datagram_size.min(MAX_PAYLOAD))});
                    let connection=connection.clone();let access=access.clone();let context=context.clone();let flows=flows.clone();context.events.record(NodeEvent::Accepted);
                    crate::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut tasks, async move{let _lease=lease;let _events=Events(context.events.clone());if server_session(connection,access,context.clone(),id,receiver,flows).await.is_err(){context.events.record(NodeEvent::Failed);}}, |_| ())?;
                }
                let Some(entry)=sessions.get_mut(&id) else{continue};
                let Ok(Some((address,payload)))=entry.reassembly.feed(packet) else{continue};let Ok(target)=crate::target(&address) else{continue};
                let Ok(permit)=queue_bytes.clone().try_acquire_many_owned(payload.len() as u32) else{context.events.record(NodeEvent::Dropped);continue;};
                if entry.sender.try_send(ServerPacket{packet:(target,payload),_bytes:permit}).is_err(){context.events.record(NodeEvent::Dropped);}
            }
        }
    }
    }.await;
    if result.is_err() {
        flows.close(crate::flow::outcome(&result));
    }
    drop(sessions);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
async fn server_session(
    connection: quinn::Connection,
    access: PeerSession,
    context: InboundContext,
    id: u32,
    mut packets: mpsc::Receiver<ServerPacket>,
    flows: Arc<crate::flow::FlowSet>,
) -> Result<()> {
    let establish =
        ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    let (mut sender, mut receiver, completion) = establish
        .run(access.associate_udp(&establish))
        .await?
        .into_parts();
    let completion = flows.register(completion)?;
    let mut sequence = 0u16;
    let result = async {
        let timer = tokio::time::sleep(context.idle_timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! {
                biased;
                _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                _ = connection.closed() => return Err(Error::Protocol("Hysteria2 UDP 载体已关闭")),
                _ = &mut timer => return Err(Error::Timeout),
                packet = packets.recv() => {
                    let Some(ServerPacket { packet: (target, payload), .. }) = packet else { return Err(Error::Timeout); };
                    tokio::select! { biased;
                        _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                        result = tokio::time::timeout(context.idle_timeout, sender.send_to(&payload, &target)) => result.map_err(|_| Error::Timeout)??,
                    }
                    timer.as_mut().reset(tokio::time::Instant::now() + context.idle_timeout);
                }
                packet = receiver.recv_from() => {
                    let Some((source, payload)) = packet? else { return Ok(()); };
                    if payload.len() > context.max_datagram_size.min(MAX_PAYLOAD) { return Err(Error::ResourceLimit); }
                    let packet = Packet { session: id, id: sequence, index: 0, count: 1, address: source.to_string(), payload };
                    sequence = sequence.wrapping_add(1);
                    tokio::time::timeout(context.idle_timeout, send_packet(&connection, &packet, &context.cancel)).await.map_err(|_| Error::Timeout)??;
                    timer.as_mut().reset(tokio::time::Instant::now() + context.idle_timeout);
                }
            }
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
