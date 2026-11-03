//! QUIC 载体鉴权后才开放业务；UDP 每会话只创建一套统一出口关联。
use crate::{
    config::{self, Auth, Limits, NodeOptions},
    dispatch::{Hub, Sender},
    io::QuicIo,
    protocol, wire,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet,
    DatagramAssociationReceiver, DatagramAssociationSender, Error, InboundContext, InboundProtocol,
    IngressBinding, NodeEvent, PeerSession, Result, StreamLease,
};

use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncReadExt, sync::watch, task::JoinSet, time::Instant};
pub struct Hysteria1NodeFactory;
struct Node {
    tls: Arc<dyn quinn::crypto::ServerConfig>,
    users: CredentialSet<[u8; 32]>,
    up: u64,
    down: u64,
    socket: Arc<crate::socket::Settings>,
    udp: bool,
    limits: Limits,
}
impl NodeFactory for Hysteria1NodeFactory {
    fn kind(&self) -> &'static str {
        "hysteria1"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: NodeOptions =
            serde_json::from_value(input.options().clone()).map_err(|_| crate::invalid())?;
        options.limits.validate()?;
        config::rate(options.up_bps, true)?;
        config::rate(options.down_bps, true)?;
        let rows = input
            .native_credentials()
            .iter()
            .map(|value| {
                serde_json::from_value::<Auth>(value.clone()).map_err(|_| crate::invalid())
            })
            .collect::<Result<Vec<_>>>()?;
        if rows.is_empty() || rows.len() > 256 {
            return Err(crate::invalid());
        }
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for user in rows {
            let bytes = config::auth(user.auth_str, user.auth)?;
            let hash: [u8; 32] = Sha256::digest(bytes).into();
            if !seen.insert(hash) {
                return Err(crate::invalid());
            }
            users.push(hash);
        }
        Ok(Arc::new(Node {
            tls: config::server_tls(options.tls)?,
            users: input.credentials(users)?,
            up: options.up_bps,
            down: options.down_bps,
            socket: Arc::new(crate::socket::Settings {
                carrier: options.transport,
                key: config::obfs(options.obfs)?,
                hop: None,
            }),
            udp: options.udp,
            limits: options.limits,
        }))
    }
}
impl Node {
    async fn serve(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        access: IngressBinding,
        mut context: InboundContext,
    ) -> Result<()> {
        if self.udp && !access.supports_udp_association() {
            return Err(Error::Unsupported(
                "Hysteria v1 节点需要同 socket 多目标 UDP 出口",
            ));
        }
        context.idle_timeout = context.idle_timeout.min(self.limits.idle());
        let mut limits = self.limits.clone();
        limits.idle_timeout_ms = context.idle_timeout.as_millis() as u64;
        limits.max_streams = limits.max_streams.min(context.max_streams);
        let mut server = quinn::ServerConfig::with_crypto(self.tls.clone());
        server.transport_config(limits.transport(limits.max_streams + 1, self.udp)?);
        let fd = socket2::SockRef::from(socket.as_ref()).try_clone()?;
        let standard: std::net::UdpSocket = fd.into();
        standard.set_nonblocking(true)?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.supported_versions(vec![1]);
        let (socket, _socket_close) = crate::socket::wrap(standard, self.socket.clone())?;
        let runtime = crate::runtime::NodeRuntime::new(&context.cancel, context.tasks.clone());
        let _runtime_guard = runtime.guard();
        let mut context = context;
        context.cancel = runtime.cancel();
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server),
            socket,
            runtime.clone(),
        )?;
        let mut connections = JoinSet::new();
        let mut draining = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                _=context.cancel.cancelled()=>break,
                _=draining.tick()=>{if context.stream_budget.is_closed()&&connections.is_empty(){break;}},
                result=connections.join_next(),if !connections.is_empty()=>{runtime.observe(&result);},
                incoming=endpoint.accept()=>{
                    let Some(incoming)=incoming else{break;};if context.stream_budget.is_closed(){incoming.refuse();continue;}let Ok(lease)=context.stream_budget.try_acquire()else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};
                    let users=self.users.clone();let access=access.clone();let context=context.clone();let limits=limits.clone();let up=self.up;let down=self.down;let udp=self.udp;
                    crate::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut connections, async move{let _lease=lease;context.events.record(NodeEvent::Accepted);let result=accept(incoming,Accept {users,up,down,udp,limits,access,context:context.clone()}).await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});}, |_| ())?;
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
        for (index, (_, auth)) in self.users.rows().enumerate() {
            let mut hash = Sha256::new();
            hash.update(b"kerlico/hysteria1/auth/");
            hash.update(auth);
            manifest.authentication("hysteria1", index, hash.finalize().into());
        }
        if let Some(key) = &self.socket.key {
            manifest.protection("hysteria1-obfs", Sha256::digest(key.as_ref()).into());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn requires_udp_association(&self) -> bool {
        self.udp
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
        Box::pin(async { Err(Error::Unsupported("Hysteria v1 使用 QUIC UDP 监听")) })
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
async fn reject(mut stream: QuicIo) {
    let _ = wire::write_response(&mut stream, false, 0).await;
    let _ = stream.send.finish();
    let _ = tokio::time::timeout(Duration::from_millis(100), stream.send.stopped()).await;
}
struct Accept {
    users: CredentialSet<[u8; 32]>,
    up: u64,
    down: u64,
    udp: bool,
    limits: Limits,
    access: IngressBinding,
    context: InboundContext,
}
async fn accept(incoming: quinn::Incoming, options: Accept) -> Result<()> {
    let Accept {
        users,
        up,
        down,
        udp,
        limits,
        access,
        mut context,
    } = options;
    let budget = ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    let (connection, control, access) = budget
        .run(async {
            let connection = incoming.await.map_err(|_| protocol())?;
            context.peer_addr = Some(connection.remote_address());
            let (send, recv) = connection.accept_bi().await.map_err(|_| protocol())?;
            let mut control = QuicIo::new(send, recv);
            if control.recv.id().index() != 0 {
                connection.close(1u32.into(), b"");
                return Err(protocol());
            }
            let hello = match wire::read_hello(&mut control).await {
                Ok(hello) => hello,
                Err(error) => {
                    let _ = wire::write_server_hello(&mut control, false, 0, 0).await;
                    let _ = control.send.finish();
                    let _ =
                        tokio::time::timeout(Duration::from_millis(100), control.send.stopped())
                            .await;
                    connection.close(1u32.into(), b"");
                    return Err(error);
                }
            };
            let hash: [u8; 32] = Sha256::digest(&hello.auth).into();
            let verified = users.verify(&hash, |user, hash| {
                Ok(bool::from(user.ct_eq(hash)).then_some(()))
            });
            if verified.is_err() {
                let _ = wire::write_server_hello(&mut control, false, 0, 0).await;
                let _ = control.send.finish();
                let _ =
                    tokio::time::timeout(Duration::from_millis(100), control.send.stopped()).await;
                connection.close(2u32.into(), b"");
                return Err(Error::Rejected);
            }
            let (send, receive) = wire::rates(up, down, &hello);
            wire::write_server_hello(&mut control, true, send, receive).await?;
            crate::congestion::negotiated(&connection, send)?;
            let peer = access.authenticated(verified?, &context)?.0;
            Ok((connection, control, peer))
        })
        .await?;
    let state = Arc::new(State {
        flows: crate::flow::FlowSet::new(context.max_streams, context.cancel.clone()),
        udp: udp && connection.max_datagram_size().is_some(),
        connection,
        access,
        context: context.clone(),
        hub: Hub::new(
            limits.udp_queue_packets,
            limits.udp_queue_bytes,
            context.max_datagram_size.min(wire::MAX_PACKET),
        ),
        sender: Sender::new(),
        next: AtomicU32::new(0),
        active: AtomicUsize::new(0),
        cancel: context.cancel.child_token(),
    });
    let _control = control;
    let _scope = Scope(state.clone());
    let _flows_guard = state.flows.guard();
    let mut tasks = JoinSet::new();
    if state.udp {
        let weak = Arc::downgrade(&state);
        let connection = state.connection.clone();
        let token = state.cancel.clone();
        crate::runtime::spawn_owned(
            context.tasks.clone(),
            context.events.clone(),
            &mut tasks,
            async move {
                loop {
                    let bytes = tokio::select! {biased;_=token.cancelled()=>break,result=connection.read_datagram()=>match result{Ok(bytes)=>bytes,Err(_)=>break}};
                    let Some(state) = weak.upgrade() else {
                        break;
                    };
                    if !state.hub.input(&bytes) {
                        state.context.events.record(NodeEvent::Dropped);
                    }
                }
            },
            |_| (),
        )?;
    }
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            _=state.cancel.cancelled()=>break,
            _=state.connection.closed()=>break,
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            _=tick.tick()=>{state.hub.prune();if context.stream_budget.is_closed()&&state.active.load(Ordering::Relaxed)==0{break;}},
            incoming=state.connection.accept_bi()=>{
                let Ok((mut send,mut recv))=incoming else{break;};if context.stream_budget.is_closed(){let _=send.reset(0u32.into());let _=recv.stop(0u32.into());continue;}
                let Ok(lease)=context.stream_budget.try_acquire()else{let _=send.reset(0u32.into());let _=recv.stop(0u32.into());context.events.record(NodeEvent::Dropped);continue;};let guard=Active::new(state.clone(),lease);let stream=QuicIo::new(send,recv);let state=state.clone();
                crate::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut tasks, async move{let _guard=guard;state.context.events.record(NodeEvent::Accepted);let result=state.handle(stream).await;state.context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});}, |_| ())?;
            }
        }
    }
    state.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
struct State {
    flows: Arc<crate::flow::FlowSet>,
    connection: quinn::Connection,
    access: PeerSession,
    context: InboundContext,
    hub: Hub,
    sender: Sender,
    next: AtomicU32,
    active: AtomicUsize,
    cancel: kerlico_core::CancellationToken,
    udp: bool,
}
impl State {
    fn close(&self) {
        self.flows.close(kerlico_core::FlowOutcome::Failed(
            if self.cancel.is_cancelled() {
                kerlico_core::FlowFailure::Cancelled
            } else {
                kerlico_core::FlowFailure::Failed
            },
        ));
        self.cancel.cancel();
        self.hub.close();
        self.connection.close(0u32.into(), b"");
    }
    async fn handle(self: &Arc<Self>, mut stream: QuicIo) -> Result<()> {
        let budget =
            ConnectContext::new(self.context.connect_timeout).with_cancel(self.cancel.clone());
        let (udp, target) = budget.run(wire::read_request(&mut stream)).await?;
        if udp {
            return self.udp_session(stream).await;
        }
        let target = target.ok_or_else(protocol)?;
        let remote = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Cancelled),_=stream.send.stopped()=>return Err(Error::Cancelled),result=budget.run(self.access.connect_tcp(&target,&budget))=>result};
        let remote = match remote {
            Ok(remote) => remote,
            Err(error) => {
                reject(stream).await;
                return Err(error);
            }
        };
        let remote = self.flows.tcp(remote)?;
        if let Err(error) = budget.run(wire::write_response(&mut stream, true, 0)).await {
            remote.finish(kerlico_core::FlowOutcome::Failed(
                kerlico_core::FlowFailure::from_error(&error),
            ));
            return Err(error);
        }
        remote
            .relay(
                Box::new(stream),
                self.context.idle_timeout,
                self.cancel.clone(),
            )
            .await
    }
    async fn udp_session(self: &Arc<Self>, mut stream: QuicIo) -> Result<()> {
        if !self.udp {
            reject(stream).await;
            return Err(Error::Unsupported("Hysteria v1 节点已禁用或未协商 UDP"));
        }
        let token = self.cancel.child_token();
        let _cancel_on_exit = token.clone().drop_guard();
        let budget = ConnectContext::new(self.context.connect_timeout).with_cancel(token.clone());
        let id = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::ResourceLimit)?
            + 1;
        let (generation, mut incoming) = self.hub.register(id, token.clone())?;
        let _session = Session {
            state: self.clone(),
            id,
            generation,
            cancel: token.clone(),
        };
        let offered = tokio::select! {biased;_=token.cancelled()=>return Err(Error::Cancelled),_=stream.send.stopped()=>return Err(Error::Cancelled),result=budget.run(self.access.associate_udp(&budget))=>result};
        let association = match offered {
            Ok(association) => association,
            Err(error) => {
                reject(stream).await;
                return Err(error);
            }
        };
        let (mut sender, mut receiver, completion) = association.into_parts();
        let completion = self.flows.register(completion)?;
        if let Err(error) = budget
            .run(wire::write_response(&mut stream, true, id))
            .await
        {
            completion.finish(kerlico_core::FlowOutcome::Failed(
                kerlico_core::FlowFailure::from_error(&error),
            ));
            return Err(error);
        }
        let result = async {
        let (activity, mut changes) = watch::channel(Instant::now());
        let sending_activity = activity.clone();
        let upload = async {
            loop {
                let queued = tokio::select! {biased;_=token.cancelled()=>return Err(Error::Cancelled),packet=incoming.recv()=>packet};
                let Some(queued) = queued else {
                    return Ok(());
                };
                if queued.packet.data.len() > self.context.max_datagram_size {
                    self.context.events.record(NodeEvent::Dropped);
                    continue;
                }
                sender
                    .send_to(&queued.packet.data, &queued.packet.target)
                    .await?;
                sending_activity.send_replace(Instant::now());
            }
        };
        let download = async {
            while let Some((source, packet)) = receiver.recv_from().await? {
                if packet.len() > self.context.max_datagram_size.min(wire::MAX_PACKET) {
                    self.context.events.record(NodeEvent::Dropped);
                    continue;
                }
                self.sender
                    .send(&self.connection, id, &source, &packet, &token)
                    .await?;
                activity.send_replace(Instant::now());
            }
            Ok::<_, Error>(())
        };
        let hold = async {
            let mut bytes = [0; 1024];
            loop {
                if stream.read(&mut bytes).await? == 0 {
                    return Ok::<_, Error>(());
                }
            }
        };
        let timer = tokio::time::sleep(self.context.idle_timeout);
        tokio::pin!(timer);
        tokio::pin!(upload);
        tokio::pin!(download);
        tokio::pin!(hold);
        loop {
            tokio::select! {biased;_=token.cancelled()=>return Err(Error::Cancelled),result=&mut hold=>return result,result=&mut upload=>return result,result=&mut download=>return result,_=&mut timer=>return Err(Error::Timeout),changed=changes.changed()=>{if changed.is_ok(){timer.as_mut().reset(*changes.borrow_and_update()+self.context.idle_timeout);}}}
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
}
struct Scope(Arc<State>);
impl Drop for Scope {
    fn drop(&mut self) {
        self.0.close();
    }
}
struct Session {
    state: Arc<State>,
    id: u32,
    generation: u64,
    cancel: kerlico_core::CancellationToken,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.state.hub.remove(self.id, self.generation);
    }
}
struct Active {
    state: Arc<State>,
    _lease: StreamLease,
}
impl Active {
    fn new(state: Arc<State>, lease: StreamLease) -> Self {
        state.active.fetch_add(1, Ordering::Relaxed);
        Self {
            state,
            _lease: lease,
        }
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::Relaxed);
    }
}
