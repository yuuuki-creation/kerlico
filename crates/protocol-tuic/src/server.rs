//! QUIC 连接认证后才创建目标访问资源；所有 UDP 关联由统一出口服务提供。
use crate::{
    codec::{self, Mode, Packet, Reassembler},
    config::{self, Credential, ServerOptions},
    wire,
};
use kerlico_config::NodeBuildContext;
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet,
    DatagramAssociationReceiver, DatagramAssociationSender, Error, InboundContext, InboundProtocol,
    IngressBinding, NodeEvent, PeerSession, Result, StreamLease,
};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::{
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::Instant,
};

pub(crate) struct Node {
    version: u8,
    users: CredentialSet<Credential>,
    tls: Arc<dyn quinn::crypto::ServerConfig>,
    congestion: String,
}
impl Node {
    pub fn build(input: &NodeBuildContext) -> Result<Self> {
        let options: ServerOptions =
            serde_json::from_value(input.options().clone()).map_err(|_| config::invalid())?;
        if !matches!(options.version, 4 | 5) {
            return Err(config::invalid());
        }
        let users = input
            .native_credentials()
            .iter()
            .map(|value| {
                let user: config::NativeCredential =
                    serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
                Credential::parse(options.version, user.token, user.uuid, user.password)
            })
            .collect::<Result<Vec<_>>>()?;
        if users.is_empty() || users.len() > 256 {
            return Err(config::invalid());
        }
        let mut seen = BTreeSet::new();
        for user in &users {
            if !seen.insert(user.fingerprint()) {
                return Err(config::invalid());
            }
        }
        let _ = config::transport(
            &options.congestion_control,
            std::time::Duration::from_secs(60),
            None,
            128,
        )?;
        Ok(Self {
            version: options.version,
            users: input.credentials(users)?,
            tls: config::server_tls(options.tls)?,
            congestion: options.congestion_control,
        })
    }
    async fn serve(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        if !access.supports_udp_association() {
            return Err(Error::Unsupported("TUIC 节点需要多目标 UDP 关联出口"));
        }
        let mut server = quinn::ServerConfig::with_crypto(self.tls.clone());
        server.transport_config(config::transport(
            &self.congestion,
            context.idle_timeout,
            None,
            context.max_streams,
        )?);
        let fd = socket2::SockRef::from(socket.as_ref()).try_clone()?;
        let standard: std::net::UdpSocket = fd.into();
        standard.set_nonblocking(true)?;
        let runtime = crate::runtime::NodeRuntime::new(&context.cancel, context.tasks.clone());
        let _runtime_guard = runtime.guard();
        let mut context = context;
        context.cancel = runtime.cancel();
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server),
            standard,
            runtime.clone(),
        )?;
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _=context.cancel.cancelled()=>break,
                result=connections.join_next(),if !connections.is_empty()=>{runtime.observe(&result);},
                incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break;};if context.stream_budget.is_closed(){incoming.refuse();continue;}let Ok(lease)=context.stream_budget.try_acquire()else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};
                    let context=context.clone();let access=access.clone();let version=self.version;let credentials=self.users.clone();
                    crate::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut connections, async move {let _lease=lease;context.events.record(NodeEvent::Accepted);let result=async {let connection=tokio::time::timeout(context.connect_timeout,incoming).await.map_err(|_|Error::Timeout)?.map_err(|_|codec::malformed())?;connection_loop(connection,version,credentials,access,context.clone()).await}.await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});}, |_| ())?;
                }
            }
        }
        if runtime
            .shutdown(endpoint, &mut connections, context.drain_timeout)
            .await?
            == crate::runtime::NodeDrain::Forced
        {
            context.events.record(NodeEvent::ForcedCleanup);
        }
        Ok(())
    }
}
impl InboundProtocol for Node {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (index, (_, user)) in self.users.rows().enumerate() {
            manifest.authentication("tuic", index, user.fingerprint());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn supports_tcp(&self) -> bool {
        false
    }
    fn supports_udp(&self) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        _: BoxStream,
        _: IngressBinding,
        _: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("TUIC 仅监听 QUIC UDP 载体")) })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve(socket, access, context))
    }
}
struct Association {
    generation: u64,
    sender: mpsc::Sender<Packet>,
    cancel: kerlico_core::CancellationToken,
}
struct State {
    flows: Arc<crate::flow::FlowSet>,
    connection: quinn::Connection,
    version: u8,
    users: CredentialSet<Credential>,
    access: IngressBinding,
    context: InboundContext,
    auth: watch::Sender<Option<PeerSession>>,
    auth_seen: AtomicBool,
    stopping: AtomicBool,
    fragments: Mutex<Reassembler>,
    associations: Mutex<HashMap<u32, Association>>,
    generation: AtomicU64,
    tasks: Mutex<JoinSet<()>>,
    input: Arc<Semaphore>,
    uni_input: Arc<Semaphore>,
}
impl State {
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) -> Result<()> {
        if let Ok(mut tasks) = self.tasks.lock() {
            if self.stopping.load(Ordering::Acquire) {
                return Err(Error::Cancelled);
            }
            while tasks.try_join_next().is_some() {}
            crate::runtime::spawn_owned(
                self.context.tasks.clone(),
                self.context.events.clone(),
                &mut tasks,
                future,
                |_| (),
            )?;
        }
        Ok(())
    }
    async fn authenticated(&self) -> Result<PeerSession> {
        let mut auth = self.auth.subscribe();
        let wait = async {
            loop {
                let current = auth.borrow_and_update().clone();
                if let Some(peer) = current {
                    return Ok(peer);
                }
                auth.changed().await.map_err(|_| Error::Rejected)?;
            }
        };
        tokio::select! {_=self.context.cancel.cancelled()=>Err(Error::Cancelled),_=self.connection.closed()=>Err(Error::Rejected),result=tokio::time::timeout(self.context.connect_timeout,wait)=>result.map_err(|_|Error::Timeout)?}
    }
    fn remove(&self, id: u32, generation: Option<u64>) {
        let mut removed = generation.is_none();
        if let Ok(mut map) = self.associations.lock()
            && map
                .get(&id)
                .is_some_and(|entry| generation.is_none_or(|value| entry.generation == value))
            && let Some(entry) = map.remove(&id)
        {
            entry.cancel.cancel();
            removed = true;
        }
        if removed && let Ok(mut fragments) = self.fragments.lock() {
            fragments.remove(id);
        }
    }
    async fn packet(self: &Arc<Self>, bytes: &[u8], mode: Mode) -> Result<()> {
        self.authenticated().await?;
        let parsed = codec::decode_packet(self.version, bytes)?;
        let complete = self
            .fragments
            .lock()
            .map_err(|_| codec::malformed())?
            .feed(parsed, mode)?;
        let Some(packet) = complete else {
            return Ok(());
        };
        if packet.data.len() > self.context.max_datagram_size {
            return Err(Error::ResourceLimit);
        }
        let id = packet.assoc;
        let (sender, new) = {
            let mut map = self.associations.lock().map_err(|_| codec::malformed())?;
            if let Some(entry) = map.get(&id) {
                (entry.sender.clone(), None)
            } else {
                if map.len() >= self.context.max_streams || self.context.stream_budget.is_closed() {
                    return Err(Error::ResourceLimit);
                }
                let lease = self.context.stream_budget.try_acquire()?;
                let generation = self
                    .generation
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        value.checked_add(1)
                    })
                    .map_err(|_| Error::ResourceLimit)?;
                let (sender, receiver) = mpsc::channel(32);
                let cancel = self.context.cancel.child_token();
                map.insert(
                    id,
                    Association {
                        generation,
                        sender: sender.clone(),
                        cancel: cancel.clone(),
                    },
                );
                (sender, Some((receiver, cancel, generation, lease)))
            }
        };
        if let Some((receiver, cancel, generation, lease)) = new {
            let state = self.clone();
            self.spawn(async move {
                let _lease = lease;
                let _guard = AssociationGuard {
                    state: Arc::downgrade(&state),
                    id,
                    generation,
                };
                state.context.events.record(NodeEvent::Accepted);
                let result = state.udp(id, mode, receiver, cancel).await;
                state.context.events.record(if result.is_ok() {
                    NodeEvent::Completed
                } else {
                    NodeEvent::Failed
                });
            })?;
        }
        sender.try_send(packet).map_err(|_| Error::ResourceLimit)
    }
    async fn udp(
        &self,
        id: u32,
        mode: Mode,
        mut incoming: mpsc::Receiver<Packet>,
        cancel: kerlico_core::CancellationToken,
    ) -> Result<()> {
        let context = ConnectContext::new(self.context.connect_timeout)
            .with_cancel(self.context.cancel.clone());
        let access = self.authenticated().await?;
        let (mut sender, mut receiver, completion) =
            access.associate_udp(&context).await?.into_parts();
        let completion = self.flows.register(completion)?;
        let result = async {
            let mut sequence = wire::PacketSequence::new();
            let timer = tokio::time::sleep(self.context.idle_timeout);
            tokio::pin!(timer);
            loop {
                tokio::select! { biased;
                    _ = self.context.cancel.cancelled() => return Err(Error::Cancelled),
                    _ = cancel.cancelled() => return Ok(()),
                    _ = &mut timer => return Err(Error::Timeout),
                    packet = incoming.recv() => {
                        let Some(packet) = packet else { return Ok(()); };
                        let target = packet.target.ok_or_else(codec::malformed)?;
                        tokio::select! { biased;
                            _ = self.context.cancel.cancelled() => return Err(Error::Cancelled),
                            _ = cancel.cancelled() => return Ok(()),
                            result = sender.send_to(&packet.data, &target) => result?,
                        }
                        timer.as_mut().reset(Instant::now() + self.context.idle_timeout);
                    }
                    packet = receiver.recv_from() => {
                        let Some((source, data)) = packet? else { return Ok(()); };
                        if data.len() > self.context.max_datagram_size { return Err(Error::ResourceLimit); }
                        tokio::select! { biased;
                            _ = self.context.cancel.cancelled() => return Err(Error::Cancelled),
                            _ = cancel.cancelled() => return Ok(()),
                            result = wire::send(&self.connection, self.version, mode, id, sequence.next().await, &source, &data) => result?,
                        }
                        timer.as_mut().reset(Instant::now() + self.context.idle_timeout);
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
    async fn uni(self: Arc<Self>, mut stream: quinn::RecvStream) -> Result<()> {
        let bytes = tokio::time::timeout(
            self.context.connect_timeout,
            stream.read_to_end(codec::MAX_PACKET + 512),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| codec::malformed())?;
        if bytes.get(..2) == Some(&[self.version, 0]) {
            if self.auth_seen.swap(true, Ordering::AcqRel) {
                return Err(codec::malformed());
            }
            let verified = self.users.verify(&bytes, |user, bytes| {
                Ok(user.matches(&self.connection, bytes).then_some(()))
            });
            let peer = match verified.and_then(|verified| {
                self.access
                    .authenticated(verified, &self.context)
                    .map(|(peer, ())| peer)
            }) {
                Ok(peer) => peer,
                Err(error) => {
                    self.connection.close(0xfffffff1u32.into(), b"");
                    return Err(error);
                }
            };
            self.auth.send_replace(Some(peer));
            return Ok(());
        }
        if bytes == [self.version, 4] {
            return Ok(());
        }
        if bytes.get(..2) == Some(&[self.version, 3]) {
            self.authenticated().await?;
            let id = codec::dissociation(self.version, &bytes)?;
            self.remove(id, None);
            return Ok(());
        }
        self.packet(&bytes, Mode::Quic).await
    }
    async fn tcp(
        self: Arc<Self>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        _lease: StreamLease,
    ) -> Result<()> {
        let connect = ConnectContext::new(self.context.connect_timeout)
            .with_cancel(self.context.cancel.clone());
        let target = connect
            .run(async {
                let mut header = [0; 2];
                tokio::io::AsyncReadExt::read_exact(&mut recv, &mut header).await?;
                if header != [self.version, 1] {
                    return Err(codec::malformed());
                }
                codec::read_address(&mut recv).await
            })
            .await?;
        let access = self.authenticated().await?;
        let remote = match access.connect_tcp(&target, &connect).await {
            Ok(value) => value,
            Err(error) => {
                if self.version == 4 {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut send, &[4, 255, 255]).await;
                    let _ = send.finish();
                }
                return Err(error);
            }
        };
        let remote = self.flows.tcp(remote)?;
        if self.version == 4 {
            if let Err(error) = connect
                .run(async {
                    tokio::io::AsyncWriteExt::write_all(&mut send, &[4, 255, 0]).await?;
                    Ok(())
                })
                .await
            {
                remote.finish(kerlico_core::FlowOutcome::Failed(
                    kerlico_core::FlowFailure::from_error(&error),
                ));
                return Err(error);
            }
        }
        remote
            .relay(
                Box::new(crate::io::QuicIo {
                    send,
                    recv,
                    owner: None,
                }),
                self.context.idle_timeout,
                self.context.cancel.clone(),
            )
            .await
    }
}
struct AssociationGuard {
    state: Weak<State>,
    id: u32,
    generation: u64,
}
impl Drop for AssociationGuard {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            state.remove(self.id, Some(self.generation));
        }
    }
}
struct Guard(Arc<State>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.flows.close(kerlico_core::FlowOutcome::Failed(
            if self.0.context.cancel.is_cancelled() {
                kerlico_core::FlowFailure::Cancelled
            } else {
                kerlico_core::FlowFailure::Failed
            },
        ));
        self.0.context.cancel.cancel();
        self.0.connection.close(0u32.into(), b"");
        if let Ok(mut tasks) = self.0.tasks.lock() {
            self.0.stopping.store(true, Ordering::Release);
            tasks.abort_all();
        }
    }
}
async fn connection_loop(
    connection: quinn::Connection,
    version: u8,
    users: CredentialSet<Credential>,
    access: IngressBinding,
    mut context: InboundContext,
) -> Result<()> {
    context.peer_addr = Some(connection.remote_address());
    context.cancel = context.cancel.child_token();
    let (auth, _) = watch::channel(None);
    let state = Arc::new(State {
        flows: crate::flow::FlowSet::new(context.max_streams, context.cancel.clone()),
        connection,
        version,
        users,
        access,
        context,
        auth,
        auth_seen: AtomicBool::new(false),
        stopping: AtomicBool::new(false),
        fragments: Mutex::new(Reassembler::new()),
        associations: Mutex::new(HashMap::new()),
        generation: AtomicU64::new(1),
        tasks: Mutex::new(JoinSet::new()),
        input: Arc::new(Semaphore::new(64)),
        uni_input: Arc::new(Semaphore::new(32)),
    });
    let _guard = Guard(state.clone());
    let _flows_guard = state.flows.guard();
    let auth_timeout = tokio::time::sleep(state.context.connect_timeout);
    tokio::pin!(auth_timeout);
    let result = async {
    loop {
        tokio::select! {
            _=state.context.cancel.cancelled()=>return Err(Error::Cancelled),_=state.connection.closed()=>return Err(Error::Protocol("TUIC载体已关闭")),
            _=&mut auth_timeout,if !state.auth_seen.load(Ordering::Acquire)=>return Err(Error::Timeout),
            stream=state.connection.accept_uni()=>{let stream=stream.map_err(|_|codec::malformed())?;let Ok(permit)=state.uni_input.clone().try_acquire_owned()else{continue;};let value=state.clone();state.spawn(async move{let _permit=permit;if value.clone().uni(stream).await.is_err(){value.context.events.record(NodeEvent::Dropped);}})?;},
            stream=state.connection.accept_bi()=>{let(send,recv)=stream.map_err(|_|codec::malformed())?;let Ok(lease)=state.context.stream_budget.try_acquire()else{continue;};let value=state.clone();state.spawn(async move{value.context.events.record(NodeEvent::Accepted);let result=value.clone().tcp(send,recv,lease).await;value.context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});})?;},
            bytes=state.connection.read_datagram()=>{let bytes=bytes.map_err(|_|codec::malformed())?;if bytes.as_ref()==[version,4]{continue;}let Ok(permit)=state.input.clone().try_acquire_owned()else{continue;};let value=state.clone();state.spawn(async move{let _permit=permit;if value.packet(&bytes,Mode::Native).await.is_err(){value.context.events.record(NodeEvent::Dropped);}})?;}
        }
    }
    }.await;
    state.flows.close(crate::flow::outcome(&result));
    state.context.cancel.cancel();
    state.connection.close(0u32.into(), b"");
    let mut tasks = {
        let mut tasks = state.tasks.lock().map_err(|_| codec::malformed())?;
        state.stopping.store(true, Ordering::Release);
        std::mem::take(&mut *tasks)
    };
    tasks.abort_all();
    let mut failed = false;
    while let Some(result) = tasks.join_next().await {
        failed |= result.is_err_and(|error| !error.is_cancelled());
    }
    if failed {
        Err(Error::Protocol("TUIC连接任务异常退出"))
    } else {
        result
    }
}
