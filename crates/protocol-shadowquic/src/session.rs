//! 地址映射、UDP 控制流及双端业务适配；映射不跨关联覆盖或复用。
use crate::{
    codec::{self, Mode},
    runtime::ScopedRuntime,
};
use kerlico_core::{
    AccessService, AddressedDatagram, BoxFuture, BoxStream, CancellationToken, ConnectContext,
    DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender, Destination,
    Error, InboundContext, NodeEvent, Result, StreamLease,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
    time::Instant,
};
const MAX_IDS: usize = 4096;
const MAX_TARGETS: usize = 256;
const MAX_PENDING_BYTES: usize = 256 * 1024;
struct Mapping {
    association: Weak<Association>,
    target: Destination,
}
struct Pending {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    created: Instant,
}
struct Maps {
    receive: HashMap<u16, Mapping>,
    retired: [u64; 1024],
    send: HashSet<u16>,
    pending: HashMap<u16, Pending>,
}
impl Maps {
    fn new() -> Self {
        Self {
            receive: HashMap::new(),
            retired: [0; 1024],
            send: HashSet::new(),
            pending: HashMap::new(),
        }
    }
    fn retired(&self, id: u16) -> bool {
        self.retired[id as usize / 64] & (1u64 << (id % 64)) != 0
    }
    fn prune(&mut self) {
        self.pending
            .retain(|_, entry| entry.created.elapsed() < Duration::from_secs(5));
    }
}
pub(crate) struct EndpointOwner {
    pub endpoint: jls_quinn::Endpoint,
    pub runtime: Arc<ScopedRuntime>,
}
impl Drop for EndpointOwner {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
        self.runtime.stop();
    }
}
pub(crate) struct Connection {
    pub quic: jls_quinn::Connection,
    _owner: Option<EndpointOwner>,
    pub cancel: CancellationToken,
    tasks: Mutex<JoinSet<()>>,
    maps: Mutex<Maps>,
    changes: watch::Sender<u64>,
    next_id: AtomicU32,
    next_association: AtomicU64,
    active: AtomicUsize,
    activity: Mutex<Instant>,
    uni_slots: Arc<Semaphore>,
    send_slots: Arc<Semaphore>,
    context: Option<InboundContext>,
    access: Option<Arc<dyn AccessService>>,
}
impl Connection {
    pub fn new(
        quic: jls_quinn::Connection,
        owner: Option<EndpointOwner>,
        context: Option<InboundContext>,
        access: Option<Arc<dyn AccessService>>,
    ) -> Arc<Self> {
        let cancel = context
            .as_ref()
            .map(|context| context.cancel.child_token())
            .unwrap_or_default();
        let (changes, _) = watch::channel(0);
        let value = Arc::new(Self {
            quic,
            _owner: owner,
            cancel,
            tasks: Mutex::new(JoinSet::new()),
            maps: Mutex::new(Maps::new()),
            changes,
            next_id: AtomicU32::new(0),
            next_association: AtomicU64::new(1),
            active: AtomicUsize::new(0),
            activity: Mutex::new(Instant::now()),
            uni_slots: Arc::new(Semaphore::new(128)),
            send_slots: Arc::new(Semaphore::new(128)),
            context,
            access,
        });
        value.start();
        value
    }
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Ok(mut tasks) = self.tasks.lock() {
            while tasks.try_join_next().is_some() {}
            tasks.spawn(future);
        }
    }
    fn event(&self, event: NodeEvent) {
        if let Some(context) = &self.context {
            context.events.record(event);
        }
    }
    fn touch(&self) {
        if let Ok(mut time) = self.activity.lock() {
            *time = Instant::now();
        }
    }
    pub fn release_active(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.touch();
    }
    pub fn exhausted(&self) -> bool {
        self.next_id.load(Ordering::Acquire) > 65535
    }
    pub fn stop(&self) {
        self.cancel.cancel();
        self.quic.close(0u32.into(), b"");
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.abort_all();
        }
    }
    async fn shutdown(&self) {
        self.stop();
        let mut tasks = if let Ok(mut tasks) = self.tasks.lock() {
            std::mem::take(&mut *tasks)
        } else {
            return;
        };
        while tasks.join_next().await.is_some() {}
    }
    fn start(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let quic = self.quic.clone();
        let cancel = self.cancel.clone();
        self.spawn(async move{loop{let bytes=tokio::select!{_=cancel.cancelled()=>break,bytes=quic.read_datagram()=>match bytes{Ok(bytes)=>bytes,Err(_)=>break}};let Some(value)=weak.upgrade()else{break;};match codec::decode_datagram(&bytes){Ok((id,packet))=>{if value.deliver(id,packet).is_err(){value.event(NodeEvent::Dropped);}},Err(_)=>value.event(NodeEvent::Dropped)}}if let Some(value)=weak.upgrade(){value.cancel.cancel();}});
        let weak = Arc::downgrade(self);
        let quic = self.quic.clone();
        let cancel = self.cancel.clone();
        self.spawn(async move{loop{let recv=tokio::select!{_=cancel.cancelled()=>break,stream=quic.accept_uni()=>match stream{Ok(stream)=>stream,Err(_)=>break}};let Some(value)=weak.upgrade()else{break;};let Ok(slot)=value.uni_slots.clone().try_acquire_owned()else{continue;};let lease=if let Some(context)=&value.context{match context.stream_budget.try_acquire(){Ok(lease)=>Some(lease),Err(_)=>continue}}else{None};let weak=Arc::downgrade(&value);value.spawn(async move{let _slot=slot;let _lease=lease;if Self::read_packets(weak.clone(),recv).await.is_err()&&let Some(value)=weak.upgrade(){value.event(NodeEvent::Dropped);}});}});
        let weak = Arc::downgrade(self);
        let cancel = self.cancel.clone();
        self.spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
                let Some(value) = weak.upgrade() else {
                    break;
                };
                if let Ok(mut maps) = value.maps.lock() {
                    maps.prune();
                }
                if value.context.is_none()
                    && value.active.load(Ordering::Acquire) == 0
                    && value
                        .activity
                        .lock()
                        .map(|time| time.elapsed() > Duration::from_secs(30))
                        .unwrap_or(true)
                {
                    value.quic.close(0u32.into(), b"");
                    break;
                }
            }
        });
    }
    fn allocate_id(&self) -> Result<u16> {
        let mut maps = self.maps.lock().map_err(|_| codec::malformed())?;
        if maps.send.len() >= MAX_IDS {
            return Err(Error::ResourceLimit);
        }
        let value = self
            .next_id
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                if value > 65535 { None } else { Some(value + 1) }
            })
            .map_err(|_| Error::ResourceLimit)? as u16;
        maps.send.insert(value);
        Ok(value)
    }
    fn release_ids(&self, association: u64, send_ids: impl Iterator<Item = u16>) {
        if let Ok(mut maps) = self.maps.lock() {
            let ids = maps
                .receive
                .iter()
                .filter(|(_, entry)| {
                    entry
                        .association
                        .upgrade()
                        .is_none_or(|value| value.id == association)
                })
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            for id in ids {
                maps.receive.remove(&id);
                maps.pending.remove(&id);
                maps.retired[id as usize / 64] |= 1u64 << (id % 64);
            }
            for id in send_ids {
                maps.send.remove(&id);
            }
        }
        self.changes
            .send_modify(|value| *value = value.wrapping_add(1));
    }
    fn register(&self, association: &Arc<Association>, target: Destination, id: u16) -> Result<()> {
        let buffered = {
            let mut maps = self.maps.lock().map_err(|_| codec::malformed())?;
            maps.prune();
            if maps.retired(id) {
                return Err(codec::malformed());
            }
            if let Some(entry) = maps.receive.get(&id) {
                if entry.target != target
                    || entry
                        .association
                        .upgrade()
                        .is_none_or(|value| value.id != association.id)
                {
                    return Err(codec::malformed());
                }
                return Ok(());
            }
            if maps.receive.len() >= MAX_IDS {
                return Err(Error::ResourceLimit);
            }
            maps.receive.insert(
                id,
                Mapping {
                    association: Arc::downgrade(association),
                    target: target.clone(),
                },
            );
            maps.pending.remove(&id)
        };
        self.changes
            .send_modify(|value| *value = value.wrapping_add(1));
        if let Some(buffered) = buffered {
            for packet in buffered.packets {
                let _ = association.output.try_send((target.clone(), packet));
            }
        }
        Ok(())
    }
    fn deliver(&self, id: u16, packet: Vec<u8>) -> Result<()> {
        let destination = {
            let mut maps = self.maps.lock().map_err(|_| codec::malformed())?;
            maps.prune();
            if let Some(entry) = maps.receive.get(&id) {
                Some((entry.association.upgrade(), entry.target.clone()))
            } else {
                if maps.retired(id) {
                    return Ok(());
                }
                let buffered = maps
                    .pending
                    .values()
                    .map(|entry| entry.bytes)
                    .sum::<usize>();
                if buffered + packet.len() > MAX_PENDING_BYTES
                    || !maps.pending.contains_key(&id) && maps.pending.len() >= 128
                {
                    return Err(Error::ResourceLimit);
                }
                let entry = maps.pending.entry(id).or_insert_with(|| Pending {
                    packets: VecDeque::new(),
                    bytes: 0,
                    created: Instant::now(),
                });
                if entry.packets.len() >= 16 {
                    return Err(Error::ResourceLimit);
                }
                entry.bytes += packet.len();
                entry.packets.push_back(packet);
                return Ok(());
            }
        };
        if let Some((Some(association), target)) = destination {
            association
                .output
                .try_send((target, packet))
                .map_err(|_| Error::ResourceLimit)?;
        }
        self.touch();
        Ok(())
    }
    fn lookup_mapping(&self, id: u16) -> Result<Option<(Weak<Association>, Destination)>> {
        let maps = self.maps.lock().map_err(|_| codec::malformed())?;
        if maps.retired(id) {
            return Err(codec::malformed());
        }
        Ok(maps
            .receive
            .get(&id)
            .map(|entry| (entry.association.clone(), entry.target.clone())))
    }
    async fn read_packets(weak: Weak<Self>, mut input: jls_quinn::RecvStream) -> Result<()> {
        let (cancel, mut changed) = {
            let value = weak.upgrade().ok_or(Error::Cancelled)?;
            (value.cancel.clone(), value.changes.subscribe())
        };
        let id = tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),id=tokio::time::timeout(Duration::from_secs(5),tokio::io::AsyncReadExt::read_u16(&mut input))=>id.map_err(|_|Error::Timeout)??};
        let mapping = async {
            loop {
                let entry = weak.upgrade().ok_or(Error::Cancelled)?.lookup_mapping(id)?;
                if let Some((association, target)) = entry
                    && let Some(association) = association.upgrade()
                {
                    return Ok::<_, Error>((
                        association.output.clone(),
                        association.cancel.clone(),
                        target,
                    ));
                }
                changed.changed().await.map_err(|_| Error::Cancelled)?;
            }
        };
        let (output, association_cancel, target) = tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),result=tokio::time::timeout(Duration::from_secs(5),mapping)=>result.map_err(|_|Error::Timeout)??};
        loop {
            let reading = async {
                let mut first = [0; 1];
                if tokio::io::AsyncReadExt::read(&mut input, &mut first).await? == 0 {
                    return Ok(None);
                }
                let second = tokio::io::AsyncReadExt::read_u8(&mut input).await?;
                let size = u16::from_be_bytes([first[0], second]) as usize;
                if size > codec::MAX_PACKET {
                    return Err(Error::ResourceLimit);
                }
                let mut bytes = vec![0; size];
                tokio::io::AsyncReadExt::read_exact(&mut input, &mut bytes).await?;
                Ok::<_, Error>(Some(bytes))
            };
            let packet = tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),_=association_cancel.cancelled()=>return Ok(()),packet=reading=>packet?};
            let Some(packet) = packet else {
                return Ok(());
            };
            tokio::select! {biased;_=association_cancel.cancelled()=>return Ok(()),result=output.send((target.clone(),packet))=>result.map_err(|_|Error::Cancelled)?};
            if let Some(value) = weak.upgrade() {
                value.touch();
            }
        }
    }
    fn association(
        self: &Arc<Self>,
        send: jls_quinn::SendStream,
        recv: jls_quinn::RecvStream,
        mode: Mode,
        lease: Option<StreamLease>,
    ) -> Result<DatagramAssociation> {
        if self.active.load(Ordering::Acquire) >= 128 {
            return Err(Error::ResourceLimit);
        }
        let id = self.next_association.fetch_add(1, Ordering::AcqRel);
        let (output, receiver) = mpsc::channel(32);
        let association = Arc::new(Association {
            id,
            parent: self.clone(),
            mode,
            output,
            cancel: self.cancel.child_token(),
            send: tokio::sync::Mutex::new(SendState {
                control: send,
                targets: HashMap::new(),
                failed: false,
            }),
            _lease: lease,
        });
        self.active.fetch_add(1, Ordering::AcqRel);
        self.touch();
        let weak = Arc::downgrade(&association);
        let cancel = association.cancel.clone();
        self.spawn(async move {
            let mut recv = recv;
            loop {
                let mapping = async {
                    let target = codec::read_address(&mut recv, false)
                        .await?
                        .ok_or_else(codec::malformed)?;
                    let id = tokio::io::AsyncReadExt::read_u16(&mut recv).await?;
                    Ok::<_, Error>((target, id))
                };
                let value = tokio::select! {_=cancel.cancelled()=>break,result=mapping=>result};
                let Ok((target, id)) = value else {
                    break;
                };
                let Some(association) = weak.upgrade() else {
                    break;
                };
                if association
                    .parent
                    .register(&association, target, id)
                    .is_err()
                {
                    break;
                }
            }
            if let Some(association) = weak.upgrade() {
                association.cancel.cancel();
            }
        });
        Ok(DatagramAssociation {
            sender: Box::new(Sender {
                association: association.clone(),
            }),
            receiver: Box::new(Receiver {
                association,
                receiver,
            }),
        })
    }
    pub async fn open_association(self: &Arc<Self>, mode: Mode) -> Result<DatagramAssociation> {
        let (mut send, recv) = self.quic.open_bi().await.map_err(|_| codec::malformed())?;
        tokio::io::AsyncWriteExt::write_all(&mut send, &codec::association_request(mode)).await?;
        self.association(send, recv, mode, None)
    }
    pub async fn open_tcp(self: &Arc<Self>, target: &Destination) -> Result<BoxStream> {
        let (mut send, recv) = self.quic.open_bi().await.map_err(|_| codec::malformed())?;
        tokio::io::AsyncWriteExt::write_all(&mut send, &codec::request(target)).await?;
        self.active.fetch_add(1, Ordering::AcqRel);
        self.touch();
        Ok(Box::new(crate::io::QuicIo {
            send,
            recv,
            owner: Some(self.clone()),
        }))
    }
    async fn serve_udp(
        &self,
        mut local: DatagramAssociation,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let connect = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let mut remote = access.associate_udp(&connect).await?;
        let timer = tokio::time::sleep(context.idle_timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! {
                biased;
                _=context.cancel.cancelled()=>return Ok(()),_=&mut timer=>return Ok(()),
                packet=local.receiver.recv_from()=>{let Some((target,packet))=packet?else{return Ok(());};if packet.len()>context.max_datagram_size{return Err(Error::ResourceLimit);}tokio::select!{_=context.cancel.cancelled()=>return Ok(()),result=remote.sender.send_to(&packet,&target)=>result?};timer.as_mut().reset(Instant::now()+context.idle_timeout);},
                packet=remote.receiver.recv_from()=>{let Some((source,packet))=packet?else{return Ok(());};if packet.len()>context.max_datagram_size{return Err(Error::ResourceLimit);}let result=tokio::select!{_=context.cancel.cancelled()=>return Ok(()),result=local.sender.send_to(&packet,&source)=>result};match result{Ok(())=>{},Err(Error::Unsupported(_)|Error::ResourceLimit)=>self.event(NodeEvent::Dropped),Err(error)=>return Err(error)}timer.as_mut().reset(Instant::now()+context.idle_timeout);}
            }
        }
    }
    async fn request(
        self: Arc<Self>,
        mut send: jls_quinn::SendStream,
        mut recv: jls_quinn::RecvStream,
        lease: StreamLease,
    ) -> Result<()> {
        let context = self.context.as_ref().ok_or_else(codec::malformed)?.clone();
        let access = self.access.as_ref().ok_or_else(codec::malformed)?.clone();
        let connect = ConnectContext {
            cancel: self.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let command = connect
            .run(async { Ok(tokio::io::AsyncReadExt::read_u8(&mut recv).await?) })
            .await?;
        match command {
            1 => {
                let target = connect
                    .run(async {
                        codec::read_address(&mut recv, false)
                            .await?
                            .ok_or_else(codec::malformed)
                    })
                    .await?;
                let _lease = lease;
                let remote = access.connect_tcp(&target, &connect).await?;
                kerlico_core::relay_tcp(
                    Box::new(crate::io::QuicIo {
                        send,
                        recv,
                        owner: None,
                    }),
                    remote,
                    context.idle_timeout,
                    self.cancel.clone(),
                )
                .await
            }
            3 | 4 => {
                let _ = connect.run(codec::read_address(&mut recv, true)).await?;
                let mode = if command == 3 {
                    Mode::Datagram
                } else {
                    Mode::Stream
                };
                let association = self.association(send, recv, mode, Some(lease))?;
                self.serve_udp(association, access, context).await
            }
            255 => {
                let _lease = lease;
                let opcode = connect
                    .run(async { Ok(tokio::io::AsyncReadExt::read_u64(&mut recv).await?) })
                    .await?;
                let mut output = vec![1, 0];
                if opcode == 1
                    && connect
                        .run(async { Ok(tokio::io::AsyncReadExt::read_u8(&mut recv).await?) })
                        .await?
                        == 0
                {
                    let stats = self.quic.stats();
                    output = vec![0];
                    output.extend(26u32.to_be_bytes());
                    output.extend(stats.path.lost_packets.to_be_bytes());
                    output.extend(stats.path.sent_packets.to_be_bytes());
                    output.extend(
                        self.quic
                            .rtt()
                            .as_secs_f64()
                            .mul_add(1000.0, 0.0)
                            .to_be_bytes(),
                    );
                    output.extend(stats.path.current_mtu.to_be_bytes());
                }
                tokio::io::AsyncWriteExt::write_all(&mut send, &output).await?;
                send.finish().map_err(|_| codec::malformed())?;
                Ok(())
            }
            _ => Err(Error::Unsupported("ShadowQUIC 命令未提供")),
        }
    }
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let _guard = ConnectionGuard(self.clone());
        let context = self.context.as_ref().ok_or_else(codec::malformed)?.clone();
        let result=async{loop{tokio::select!{_=self.cancel.cancelled()=>return Ok(()),_=self.quic.closed()=>return Ok(()),stream=self.quic.accept_bi()=>{let(send,recv)=stream.map_err(|_|codec::malformed())?;let Ok(lease)=context.stream_budget.try_acquire()else{self.event(NodeEvent::Dropped);continue;};let value=self.clone();self.spawn(async move{value.event(NodeEvent::Accepted);let result=value.clone().request(send,recv,lease).await;value.event(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});});}}}}.await;
        self.shutdown().await;
        result
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.quic.close(0u32.into(), b"");
        if let Ok(tasks) = self.tasks.get_mut() {
            tasks.abort_all();
        }
    }
}
struct ConnectionGuard(Arc<Connection>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}
struct TargetState {
    id: u16,
    stream: Option<jls_quinn::SendStream>,
    _slot: Option<OwnedSemaphorePermit>,
    _lease: Option<StreamLease>,
}
struct SendState {
    control: jls_quinn::SendStream,
    targets: HashMap<Destination, TargetState>,
    failed: bool,
}
struct Association {
    id: u64,
    parent: Arc<Connection>,
    mode: Mode,
    output: mpsc::Sender<AddressedDatagram>,
    cancel: CancellationToken,
    send: tokio::sync::Mutex<SendState>,
    _lease: Option<StreamLease>,
}
impl Association {
    async fn send(&self, bytes: &[u8], target: &Destination) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if bytes.len() > codec::MAX_PACKET {
            return Err(Error::ResourceLimit);
        }
        if self.mode == Mode::Datagram
            && self
                .parent
                .quic
                .max_datagram_size()
                .is_none_or(|max| bytes.len() + 2 > max)
        {
            return Err(Error::Unsupported(
                "ShadowQUIC datagram 不支持超 MTU 的整包",
            ));
        }
        let mut state = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Cancelled),state=self.send.lock()=>state};
        if state.failed {
            return Err(codec::malformed());
        }
        if !state.targets.contains_key(target) {
            if state.targets.len() >= MAX_TARGETS {
                return Err(Error::ResourceLimit);
            }
            let slot = if self.mode == Mode::Stream {
                Some(
                    self.parent
                        .send_slots
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| Error::ResourceLimit)?,
                )
            } else {
                None
            };
            let lease = if self.mode == Mode::Stream {
                self.parent
                    .context
                    .as_ref()
                    .map(|context| context.stream_budget.try_acquire())
                    .transpose()?
            } else {
                None
            };
            let id = self.parent.allocate_id()?;
            state.targets.insert(
                target.clone(),
                TargetState {
                    id,
                    stream: None,
                    _slot: slot,
                    _lease: lease,
                },
            );
            state.failed = true;
            tokio::io::AsyncWriteExt::write_all(&mut state.control, &codec::mapping(target, id))
                .await?;
            if self.mode == Mode::Stream {
                let mut stream = self
                    .parent
                    .quic
                    .open_uni()
                    .await
                    .map_err(|_| codec::malformed())?;
                tokio::io::AsyncWriteExt::write_all(&mut stream, &id.to_be_bytes()).await?;
                state
                    .targets
                    .get_mut(target)
                    .ok_or_else(codec::malformed)?
                    .stream = Some(stream);
            }
            state.failed = false;
        }
        state.failed = true;
        let entry = state.targets.get_mut(target).ok_or_else(codec::malformed)?;
        let result = if let Some(stream) = entry.stream.as_mut() {
            let mut packet = (bytes.len() as u16).to_be_bytes().to_vec();
            packet.extend_from_slice(bytes);
            tokio::io::AsyncWriteExt::write_all(stream, &packet)
                .await
                .map_err(Error::Io)
        } else {
            self.parent
                .quic
                .send_datagram(bytes::Bytes::from(codec::datagram(entry.id, bytes)?))
                .map_err(|_| Error::ResourceLimit)
        };
        if result.is_ok() || self.mode == Mode::Datagram {
            state.failed = false;
        }
        result?;
        self.parent.touch();
        Ok(())
    }
}
impl Drop for Association {
    fn drop(&mut self) {
        self.cancel.cancel();
        let state = self.send.get_mut();
        let _ = state.control.finish();
        for target in state.targets.values_mut() {
            if let Some(stream) = &mut target.stream {
                let _ = stream.finish();
            }
        }
        self.parent
            .release_ids(self.id, state.targets.values().map(|target| target.id));
        self.parent.release_active();
    }
}
struct Sender {
    association: Arc<Association>,
}
struct Receiver {
    association: Arc<Association>,
    receiver: mpsc::Receiver<AddressedDatagram>,
}
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        bytes: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.association.send(bytes, target))
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            tokio::select! {biased;_=self.association.cancel.cancelled()=>Ok(None),packet=self.receiver.recv()=>Ok(packet)}
        })
    }
}
