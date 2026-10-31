//! QUIC 连接认证后才创建目标访问资源；所有 UDP 关联由统一出口服务提供。
use crate::{
    codec::{self, Mode, Packet, Reassembler},
    config::{self, Credential, ServerOptions},
    wire,
};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    NodeEvent, Result, StreamLease,
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
    users: Arc<Vec<Credential>>,
    tls: Arc<dyn quinn::crypto::ServerConfig>,
    congestion: String,
}
impl Node {
    pub fn build(mut options: ServerOptions) -> Result<Self> {
        if !matches!(options.version, 4 | 5) {
            return Err(config::invalid());
        }
        let mut users = Vec::new();
        if options.version == 4 {
            if options.uuid.is_some() || options.password.is_some() || !options.users.is_empty() {
                return Err(config::invalid());
            }
            if let Some(token) = options.token {
                if !options.tokens.is_empty() {
                    return Err(config::invalid());
                }
                options.tokens.push(token);
            }
            for token in options.tokens {
                users.push(Credential::parse(4, Some(token), None, None)?);
            }
        } else {
            if options.token.is_some() || !options.tokens.is_empty() {
                return Err(config::invalid());
            }
            if options.uuid.is_some() || options.password.is_some() {
                if !options.users.is_empty() {
                    return Err(config::invalid());
                }
                users.push(Credential::parse(5, None, options.uuid, options.password)?);
            }
            for user in options.users {
                users.push(Credential::parse(
                    5,
                    None,
                    Some(user.uuid),
                    Some(user.password),
                )?);
            }
        }
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
            users: Arc::new(users),
            tls: config::server_tls(options.tls)?,
            congestion: options.congestion_control,
        })
    }
    async fn serve(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
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
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server),
            standard,
            Arc::new(quinn::TokioRuntime),
        )?;
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _=context.cancel.cancelled()=>break,
                _=connections.join_next(),if !connections.is_empty()=>{},
                incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break;};if context.stream_budget.is_closed(){incoming.refuse();continue;}let Ok(lease)=context.stream_budget.try_acquire()else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};
                    let context=context.clone();let access=access.clone();let version=self.version;let credentials=self.users.clone();
                    connections.spawn(async move {let _lease=lease;context.events.record(NodeEvent::Accepted);let result=async {let connection=tokio::time::timeout(context.connect_timeout,incoming).await.map_err(|_|Error::Timeout)?.map_err(|_|codec::malformed())?;connection_loop(connection,version,credentials,access,context.clone()).await}.await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});});
                }
            }
        }
        endpoint.close(0u32.into(), b"");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        let _ = tokio::time::timeout(context.drain_timeout, endpoint.wait_idle()).await;
        Ok(())
    }
}
impl InboundProtocol for Node {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.users.iter().map(Credential::fingerprint).collect()
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
        _: Arc<dyn AccessService>,
        _: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("TUIC 仅监听 QUIC UDP 载体")) })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
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
    connection: quinn::Connection,
    version: u8,
    users: Arc<Vec<Credential>>,
    access: Arc<dyn AccessService>,
    context: InboundContext,
    auth: watch::Sender<Option<bool>>,
    auth_seen: AtomicBool,
    fragments: Mutex<Reassembler>,
    associations: Mutex<HashMap<u32, Association>>,
    generation: AtomicU64,
    tasks: Mutex<JoinSet<()>>,
    input: Arc<Semaphore>,
    uni_input: Arc<Semaphore>,
}
impl State {
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Ok(mut tasks) = self.tasks.lock() {
            while tasks.try_join_next().is_some() {}
            tasks.spawn(future);
        }
    }
    async fn authenticated(&self) -> Result<()> {
        let mut auth = self.auth.subscribe();
        let wait = async {
            loop {
                let current = *auth.borrow_and_update();
                if let Some(valid) = current {
                    return if valid { Ok(()) } else { Err(Error::Rejected) };
                }
                auth.changed().await.map_err(|_| Error::Rejected)?;
            }
        };
        tokio::select! {_=self.context.cancel.cancelled()=>Err(Error::Cancelled),result=tokio::time::timeout(self.context.connect_timeout,wait)=>result.map_err(|_|Error::Timeout)?}
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
                let generation = self.generation.fetch_add(1, Ordering::AcqRel);
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
            });
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
        let context = ConnectContext {
            cancel: cancel.clone(),
            timeout: self.context.connect_timeout,
        };
        let mut remote = self.access.associate_udp(&context).await?;
        let mut sequence = wire::PacketSequence::new();
        let timer = tokio::time::sleep(self.context.idle_timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! {
                _=cancel.cancelled()=>return Ok(()),_=self.context.cancel.cancelled()=>return Ok(()),_=&mut timer=>return Ok(()),
                packet=incoming.recv()=>{let Some(packet)=packet else{return Ok(());};let target=packet.target.ok_or_else(codec::malformed)?;tokio::select!{_=cancel.cancelled()=>return Ok(()),result=remote.sender.send_to(&packet.data,&target)=>result?};timer.as_mut().reset(Instant::now()+self.context.idle_timeout);},
                packet=remote.receiver.recv_from()=>{let Some((source,data))=packet? else{return Ok(());};if data.len()>self.context.max_datagram_size{return Err(Error::ResourceLimit);}tokio::select!{_=cancel.cancelled()=>return Ok(()),result=wire::send(&self.connection,self.version,mode,id,sequence.next().await,&source,&data)=>result?};timer.as_mut().reset(Instant::now()+self.context.idle_timeout);}
            }
        }
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
            let valid = self
                .users
                .iter()
                .any(|user| user.matches(&self.connection, &bytes));
            self.auth.send_replace(Some(valid));
            if !valid {
                self.connection.close(0xfffffff1u32.into(), b"");
                return Err(Error::Rejected);
            }
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
        let connect = ConnectContext {
            cancel: self.context.cancel.clone(),
            timeout: self.context.connect_timeout,
        };
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
        self.authenticated().await?;
        let remote = match self.access.connect_tcp(&target, &connect).await {
            Ok(value) => value,
            Err(error) => {
                if self.version == 4 {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut send, &[4, 255, 255]).await;
                    let _ = send.finish();
                }
                return Err(error);
            }
        };
        if self.version == 4 {
            tokio::io::AsyncWriteExt::write_all(&mut send, &[4, 255, 0]).await?;
        }
        kerlico_core::relay_tcp(
            Box::new(crate::io::QuicIo {
                send,
                recv,
                owner: None,
            }),
            remote,
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
        self.0.context.cancel.cancel();
        self.0.connection.close(0u32.into(), b"");
        if let Ok(mut tasks) = self.0.tasks.lock() {
            tasks.abort_all();
        }
    }
}
async fn connection_loop(
    connection: quinn::Connection,
    version: u8,
    users: Arc<Vec<Credential>>,
    access: Arc<dyn AccessService>,
    mut context: InboundContext,
) -> Result<()> {
    context.cancel = context.cancel.child_token();
    let (auth, _) = watch::channel(None);
    let state = Arc::new(State {
        connection,
        version,
        users,
        access,
        context,
        auth,
        auth_seen: AtomicBool::new(false),
        fragments: Mutex::new(Reassembler::new()),
        associations: Mutex::new(HashMap::new()),
        generation: AtomicU64::new(1),
        tasks: Mutex::new(JoinSet::new()),
        input: Arc::new(Semaphore::new(64)),
        uni_input: Arc::new(Semaphore::new(32)),
    });
    let _guard = Guard(state.clone());
    let auth_timeout = tokio::time::sleep(state.context.connect_timeout);
    tokio::pin!(auth_timeout);
    loop {
        tokio::select! {
            _=state.context.cancel.cancelled()=>return Ok(()),_=state.connection.closed()=>return Ok(()),
            _=&mut auth_timeout,if !state.auth_seen.load(Ordering::Acquire)=>return Err(Error::Timeout),
            stream=state.connection.accept_uni()=>{let stream=stream.map_err(|_|codec::malformed())?;let Ok(permit)=state.uni_input.clone().try_acquire_owned()else{continue;};let value=state.clone();state.spawn(async move{let _permit=permit;if value.clone().uni(stream).await.is_err(){value.context.events.record(NodeEvent::Dropped);}});},
            stream=state.connection.accept_bi()=>{let(send,recv)=stream.map_err(|_|codec::malformed())?;let Ok(lease)=state.context.stream_budget.try_acquire()else{continue;};let value=state.clone();state.spawn(async move{value.context.events.record(NodeEvent::Accepted);let result=value.clone().tcp(send,recv,lease).await;value.context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});});},
            bytes=state.connection.read_datagram()=>{let bytes=bytes.map_err(|_|codec::malformed())?;if bytes.as_ref()==[version,4]{continue;}let Ok(permit)=state.input.clone().try_acquire_owned()else{continue;};let value=state.clone();state.spawn(async move{let _permit=permit;if value.packet(&bytes,Mode::Native).await.is_err(){value.context.events.record(NodeEvent::Dropped);}});}
        }
    }
}
