//! 公网 TCP 与本地旧 UDP 分别注册能力；目标访问全部由注入服务提供。
use crate::{
    codec,
    config::{self, ServerOptions, Transport, User, UserOptions},
    crypto::{Replay, StreamCipher, Users},
    packet,
    session::{self, Life, Scope, Server, ServerAccess, SessionIo, TcpSettings},
    udp,
};
use kerlico_config::NodeBuildContext;
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Destination, Error,
    FlowCompletion, FlowFailure, FlowOpen, FlowOutcome, InboundContext, InboundProtocol,
    IngressBinding, PeerSession, Result,
};
use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{io::AsyncWriteExt, net::UdpSocket};
pub(crate) struct Node {
    users: Arc<Users>,
    credentials: CredentialSet<Arc<User>>,
    transport: Transport,
    traffic: config::Traffic,
    mtu: usize,
    replay: Arc<Replay>,
}

impl Node {
    pub fn build(input: &NodeBuildContext) -> Result<Self> {
        let mut options: ServerOptions =
            serde_json::from_value(input.options().clone()).map_err(|_| config::invalid())?;
        if !input.is_local() {
            if options.username.is_some() || options.password.is_some() || !options.users.is_empty()
            {
                return Err(config::invalid());
            }
            options.users = input
                .native_credentials()
                .iter()
                .map(|value| {
                    serde_json::from_value::<UserOptions>(value.clone())
                        .map_err(|_| config::invalid())
                })
                .collect::<Result<Vec<_>>>()?;
        }
        if options.username.is_some() || options.password.is_some() {
            if !options.users.is_empty() {
                return Err(config::invalid());
            }
            options.users.push(UserOptions {
                username: options.username.ok_or_else(config::invalid)?,
                password: options.password.ok_or_else(config::invalid)?,
            });
        }
        if options.users.is_empty() || options.users.len() > 256 {
            return Err(config::invalid());
        }
        let transport = Transport::parse(&options.transport, options.unsafe_udp_compatibility)?;
        config::validate_limits(128, 60, options.mtu)?;
        options.traffic.validate()?;
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for options in options.users {
            let user = User::new(options.username, options.password)?;
            if !seen.insert(user.identity_fingerprint()) {
                return Err(config::invalid());
            }
            users.push(user);
        }
        if (transport == Transport::LocalUnsafeUdp) != input.is_local() {
            return Err(config::invalid());
        }
        let credentials = input.credentials(if input.is_local() {
            Vec::new()
        } else {
            users.clone()
        })?;
        Ok(Self {
            users: Arc::new(Users::new(users, options.user_hint_required)),
            credentials,
            transport,
            traffic: options.traffic,
            mtu: options.mtu,
            replay: Arc::new(Replay::new()),
        })
    }
    async fn start_tcp(
        &self,
        mut stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<Arc<session::Link>> {
        Self::check_access(&access)?;
        let opening =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let (frame, receive, nonce) = opening
            .run(codec::read_server_first(&mut stream, &self.users))
            .await?;
        if frame.kind != 2 {
            return Err(codec::bad());
        }
        frame.direction(false)?;
        self.replay.accept(&receive.key, &nonce)?;
        let (slot, _) = self
            .credentials
            .rows()
            .find(|(_, user)| Arc::ptr_eq(user, &receive.key.user))
            .ok_or(Error::Rejected)?;
        let access = access
            .authenticated(self.credentials.verified(&slot, ())?, &context)?
            .0;
        let send = StreamCipher::new(receive.key.clone());
        let scope = Scope::node(&context.cancel, context.tasks.clone());
        let settings = TcpSettings {
            traffic: self.traffic.clone(),
            idle: context.idle_timeout,
            connect_timeout: context.connect_timeout,
            multiplexing: true,
            server: Some(Server {
                access: ServerAccess::Authenticated(access),
                context,
            }),
        };
        Ok(session::tcp_link(
            stream,
            receive,
            send,
            scope,
            settings,
            Some(frame),
        ))
    }
    fn check_access(access: &IngressBinding) -> Result<()> {
        if access.supports_udp_association() {
            Ok(())
        } else {
            Err(Error::Unsupported("Mieru 节点需要 Full Cone UDP 关联出口"))
        }
    }
}
impl InboundProtocol for Node {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (index, user) in self.users.entries.iter().enumerate() {
            if self.transport == Transport::LocalUnsafeUdp {
                manifest.protection("mieru", user.fingerprint());
            } else {
                manifest.authentication("mieru", index, user.fingerprint());
            }
            manifest.protection("mieru-user", user.identity_fingerprint());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        self.transport == Transport::LocalUnsafeUdp
    }
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn supports_tcp(&self) -> bool {
        self.transport == Transport::Tcp
    }
    fn supports_udp(&self) -> bool {
        self.transport == Transport::LocalUnsafeUdp
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.transport != Transport::Tcp {
                return Err(Error::Unsupported("该 Mieru 条目没有 TCP 载体"));
            }
            let link = self.start_tcp(stream, access, context).await?;
            link.scope.cancel.cancelled().await;
            link.scope.shutdown().await;
            Ok(())
        })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.transport != Transport::LocalUnsafeUdp {
                return Err(Error::Unsupported("公网 Mieru UDP 载体未支持"));
            }
            let address = socket.local_addr()?;
            if !address.ip().is_loopback() || address.ip().to_canonical() != address.ip() {
                return Err(Error::Config("Mieru 不安全 UDP 必须回环监听".into()));
            }
            Self::check_access(&access)?;
            let scope = Scope::node(&context.cancel, context.tasks.clone());
            let common = TcpSettings {
                traffic: self.traffic.clone(),
                idle: context.idle_timeout,
                connect_timeout: context.connect_timeout,
                multiplexing: true,
                server: Some(Server {
                    access: ServerAccess::Local(access),
                    context,
                }),
            };
            let link = packet::start(
                socket,
                scope,
                packet::Settings {
                    common,
                    mtu: self.mtu,
                    key: None,
                    peer: None,
                    users: Some(self.users.clone()),
                    replay: Some(self.replay.clone()),
                },
            )?;
            link.scope.cancel.cancelled().await;
            link.scope.shutdown().await;
            Ok(())
        })
    }
}
enum Ready {
    Tcp(kerlico_core::TcpFlow),
    Udp(kerlico_core::UdpAssociation),
}
enum TargetIo {
    Tcp(kerlico_core::TcpFlowIo),
    Udp(
        kerlico_core::AssociationSender,
        kerlico_core::AssociationReceiver,
    ),
}
struct SessionTarget {
    completion: SessionCompletion,
    io: TargetIo,
}
struct SessionCompletion {
    inner: Option<FlowCompletion>,
    end: SessionEnd,
    cleanup: RequestCleanup,
}
#[derive(Clone)]
struct SessionEnd {
    life: Arc<Life>,
    peer_cancel: kerlico_core::CancellationToken,
    node_cancel: kerlico_core::CancellationToken,
}
struct PendingTarget<'a, T> {
    opening: Option<FlowOpen<'a, T>>,
    end: SessionEnd,
    cleanup: Option<RequestCleanup>,
    #[cfg(test)]
    poll_gate: Option<Arc<pending_tests::OpeningPollGate>>,
}
impl SessionEnd {
    fn interrupted(&self) -> FlowOutcome {
        if let Some(failure) = self.life.failure() {
            FlowOutcome::Failed(failure)
        } else if std::thread::panicking() {
            FlowOutcome::Failed(FlowFailure::Failed)
        } else if self.peer_cancel.is_cancelled() || self.node_cancel.is_cancelled() {
            FlowOutcome::Failed(FlowFailure::Cancelled)
        } else if self.life.peer_ended() {
            FlowOutcome::ProtocolEnd
        } else {
            FlowOutcome::ClosedByCaller
        }
    }
}
impl<T> Future for PendingTarget<'_, T> {
    type Output = (Result<T>, RequestCleanup);
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let pending = self.get_mut();
        #[cfg(test)]
        if let Some(gate) = &pending.poll_gate {
            ready!(gate.poll(cx));
        }
        let result =
            ready!(Pin::new(pending.opening.as_mut().expect("目标建立只完成一次")).poll(cx));
        drop(pending.opening.take());
        Poll::Ready((
            result,
            pending.cleanup.take().expect("请求清理权只移交一次"),
        ))
    }
}
impl<T> Drop for PendingTarget<'_, T> {
    fn drop(&mut self) {
        if let Some(opening) = self.opening.take() {
            opening.finish(self.end.interrupted());
        }
    }
}
struct RequestCleanup(kerlico_core::CancellationToken);
impl Drop for RequestCleanup {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl SessionTarget {
    fn new(ready: Ready, end: SessionEnd, cleanup: RequestCleanup) -> Self {
        let (io, completion) = match ready {
            Ready::Tcp(flow) => {
                let (io, completion) = flow.into_parts();
                (TargetIo::Tcp(io), completion)
            }
            Ready::Udp(flow) => {
                let (send, recv, completion) = flow.into_parts();
                (TargetIo::Udp(send, recv), completion)
            }
        };
        Self {
            completion: SessionCompletion {
                inner: Some(completion),
                end,
                cleanup,
            },
            io,
        }
    }
}
impl SessionCompletion {
    fn finish(&mut self, result: &Result<()>, success: FlowOutcome) {
        if let Some(completion) = self.inner.take() {
            completion.finish(match result {
                Ok(()) => success,
                Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
            });
            self.cleanup.0.cancel();
        }
    }
}
impl Drop for SessionCompletion {
    fn drop(&mut self) {
        if let Some(completion) = self.inner.take() {
            completion.finish(self.end.interrupted());
        }
    }
}
pub(crate) async fn run_session(
    mut stream: SessionIo,
    access: PeerSession,
    context: InboundContext,
) -> Result<()> {
    let life = stream.life.clone();
    let cancel = context.cancel.clone();
    let cleanup = RequestCleanup(cancel.child_token());
    let end = SessionEnd {
        life: life.clone(),
        peer_cancel: context.cancel.clone(),
        node_cancel: context.tasks.cancel(),
    };
    let connecting = ConnectContext::new(context.connect_timeout).with_cancel(cleanup.0.clone());
    let (command, host, port) = connecting.run(codec::read_request(&mut stream)).await?;
    let (target, cleanup) = if command == 1 {
        let destination = Destination::new(&host, port)?;
        let (target, cleanup) = PendingTarget {
            opening: Some(access.connect_tcp(&destination, &connecting)),
            end: end.clone(),
            cleanup: Some(cleanup),
            #[cfg(test)]
            poll_gate: pending_tests::opening_poll_gate(&life),
        }
        .await;
        (target.map(Ready::Tcp), cleanup)
    } else {
        let (target, cleanup) = PendingTarget {
            opening: Some(access.associate_udp(&connecting)),
            end: end.clone(),
            cleanup: Some(cleanup),
            #[cfg(test)]
            poll_gate: pending_tests::opening_poll_gate(&life),
        }
        .await;
        (target.map(Ready::Udp), cleanup)
    };
    let target = match target {
        Ok(target) => target,
        Err(error) => {
            let _ = connecting
                .run(async {
                    stream.write_all(&codec::response(1)).await?;
                    stream.flush().await?;
                    Ok(())
                })
                .await;
            return Err(error);
        }
    };
    let mut target = SessionTarget::new(target, end, cleanup);
    let response = tokio::select! {
        biased;
        _ = life.abort_cancel.cancelled() => Err(life.error()),
        result = connecting.run(async {
            stream.write_all(&codec::response(0)).await?;
            stream.flush().await?;
            Ok(())
        }) => result,
    };
    if response.is_err() {
        target
            .completion
            .finish(&response, FlowOutcome::ProtocolEnd);
        return response;
    }
    let success = match &target.io {
        TargetIo::Tcp(_) => FlowOutcome::DuplexEof,
        TargetIo::Udp(_, _) => FlowOutcome::ProtocolEnd,
    };
    let result = tokio::select! {
        biased;
        _ = life.abort_cancel.cancelled() => Err(life.error()),
        result = async {
            match &mut target.io {
                TargetIo::Tcp(io) => {
                    kerlico_core::relay_tcp_io(Box::new(stream), io, context.idle_timeout, cancel).await
                }
                TargetIo::Udp(send, recv) => {
                    udp::relay_io(
                        stream,
                        send,
                        recv,
                        context.max_datagram_size.min(codec::MAX_UDP),
                        context.idle_timeout,
                        cancel,
                    ).await
                }
            }
        } => result,
    };
    target.completion.finish(&result, success);
    result
}

#[cfg(test)]
pub(crate) mod pending_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{self, Key},
        session::Command,
    };
    use kerlico_config::OutboundFactory;
    use kerlico_core::{
        FamilyMode, NodeEvent, NodeId, NodeObserver, NodeTasks, PeerLease, ServiceContext,
        StreamBudget, TargetPolicy,
    };
    use kerlico_egress::{FlowEnd, Resolver};
    use serde_json::json;
    use std::{net::IpAddr, sync::Mutex, time::Duration};
    use tokio::{
        io::AsyncReadExt,
        net::{TcpListener, TcpStream},
        sync::Semaphore,
        time::{Instant, timeout},
    };

    struct Observer;
    impl NodeObserver for Observer {
        fn record(&self, _: NodeEvent) {}
    }
    struct NoDns;
    impl Resolver for NoDns {
        fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
            Box::pin(async { Err(Error::Protocol("字面地址回归不得查询DNS")) })
        }
    }
    struct TargetRequests {
        backend: Arc<dyn kerlico_core::Outbound>,
        request: Mutex<Option<kerlico_core::CancellationToken>>,
    }
    impl kerlico_core::Outbound for TargetRequests {
        fn capabilities(&self) -> kerlico_core::Capabilities {
            self.backend.capabilities()
        }
        fn supports_udp_association(&self) -> bool {
            self.backend.supports_udp_association()
        }
        fn connect_tcp<'a>(
            &'a self,
            target: &'a Destination,
            context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
            *self.request.lock().unwrap() = Some(context.cancel.clone());
            self.backend.connect_tcp(target, context)
        }
        fn connect_udp<'a>(
            &'a self,
            target: &'a Destination,
            context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::DatagramChannel>> {
            self.backend.connect_udp(target, context)
        }
        fn associate_udp<'a>(
            &'a self,
            context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::DatagramAssociation>> {
            *self.request.lock().unwrap() = Some(context.cancel.clone());
            self.backend.associate_udp(context)
        }
    }
    #[derive(Clone, Copy)]
    enum End {
        InternalAbort,
        PeerCancel,
        NodeCancel,
        Idle,
        ProtocolClose,
    }

    async fn read_payload(
        stream: &mut TcpStream,
        cipher: &mut StreamCipher,
        size: usize,
    ) -> Vec<u8> {
        timeout(Duration::from_secs(2), async {
            let mut bytes = Vec::new();
            while bytes.len() < size {
                let frame = codec::read_stream(stream, cipher).await.unwrap();
                assert_eq!(frame.id, 1);
                if frame.is_data() {
                    bytes.extend_from_slice(&frame.body);
                }
            }
            bytes
        })
        .await
        .unwrap()
    }

    async fn authenticated_case(end: End, udp: bool) {
        let native = json!({"username":"node-user", "password":"synthetic-password"});
        let input = NodeBuildContext::for_test(json!({"transport":"tcp"}), vec![native]);
        let node = Node::build(&input).unwrap();
        let backend = kerlico_net::DirectFactory
            .compile(&json!({}))
            .unwrap()
            .start(ServiceContext::for_test())
            .await
            .unwrap();
        let requests = Arc::new(TargetRequests {
            backend,
            request: Mutex::new(None),
        });
        let (binding, telemetry) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            requests.clone(),
            TargetPolicy::Local,
            FamilyMode::V4Only,
            Arc::new(NoDns),
        )
        .unwrap();
        let node_cancel = binding.node_cancel();
        let peer_cancel = node_cancel.child_token();
        let tasks = NodeTasks::new(NodeId::parse("test-node").unwrap(), node_cancel.clone());
        let global = Arc::new(Semaphore::new(8));
        let local = Arc::new(Semaphore::new(8));
        let budget = StreamBudget::new(global.clone(), local.clone());
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = if udp {
            udp_target.local_addr().unwrap().port()
        } else {
            target_listener.local_addr().unwrap().port()
        };
        let target = Destination::new("127.0.0.1", target_port).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connecting = TcpStream::connect(listener.local_addr().unwrap());
        let (client, server) = tokio::join!(connecting, listener.accept());
        let mut client = client.unwrap();
        let (server, peer) = server.unwrap();
        let context = InboundContext {
            peer_lease: Some(PeerLease::new(
                peer_cancel.clone(),
                budget.try_acquire().unwrap(),
            )),
            tasks: tasks.clone(),
            peer_addr: Some(peer),
            local_addr: Some(listener.local_addr().unwrap()),
            cancel: peer_cancel.clone(),
            connect_timeout: Duration::from_secs(2),
            idle_timeout: if matches!(end, End::Idle) {
                Duration::from_millis(200)
            } else {
                Duration::from_secs(2)
            },
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 8,
            stream_budget: budget,
            events: Arc::new(Observer),
        };
        let user = User::new("node-user".into(), "synthetic-password".into()).unwrap();
        let key = Key::new(user, crypto::epoch(crypto::now().unwrap()));
        let mut send = StreamCipher::new(key.clone());
        let mut receive = StreamCipher::new(key);
        let opening =
            codec::Frame::control(2, 1, 0, codec::request((!udp).then_some(&target)).into());
        client
            .write_all(
                &codec::seal_stream(&mut send, &opening, &config::Traffic::default()).unwrap(),
            )
            .await
            .unwrap();
        let link = node
            .start_tcp(Box::new(server), binding, context)
            .await
            .unwrap();
        let mut website = if udp {
            None
        } else {
            Some(
                timeout(Duration::from_secs(2), target_listener.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
            )
        };
        assert_eq!(
            read_payload(&mut client, &mut receive, codec::response(0).len()).await,
            codec::response(0)
        );
        let payload = if udp {
            codec::udp_packet(&target, b"up").unwrap()
        } else {
            b"up".to_vec()
        };
        let body = codec::Frame::data(1, 1, payload.into(), true, &config::Traffic::default());
        client
            .write_all(&codec::seal_stream(&mut send, &body, &config::Traffic::default()).unwrap())
            .await
            .unwrap();
        let mut uploaded = [0; 2];
        let udp_peer = if let Some(website) = &mut website {
            timeout(Duration::from_secs(2), website.read_exact(&mut uploaded))
                .await
                .unwrap()
                .unwrap();
            website.write_all(b"tail").await.unwrap();
            None
        } else {
            let (length, peer) =
                timeout(Duration::from_secs(2), udp_target.recv_from(&mut uploaded))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(length, 2);
            udp_target.send_to(b"tail", peer).await.unwrap();
            Some(peer)
        };
        assert_eq!(&uploaded, b"up");
        let returned = if udp {
            codec::udp_packet(&target, b"tail").unwrap()
        } else {
            b"tail".to_vec()
        };
        assert_eq!(
            read_payload(&mut client, &mut receive, returned.len()).await,
            returned
        );
        assert_eq!(telemetry.usage().unwrap().active_flows, 1);
        assert_eq!(global.available_permits(), 6);
        assert_eq!(local.available_permits(), 6);
        assert!(
            !requests
                .request
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .is_cancelled()
        );
        let expected = match end {
            End::InternalAbort => {
                link.command
                    .send(Command::Close {
                        id: 1,
                        abort: true,
                        done: None,
                    })
                    .await
                    .unwrap();
                FlowEnd::Failed
            }
            End::PeerCancel => {
                peer_cancel.cancel();
                FlowEnd::Cancelled
            }
            End::NodeCancel => {
                node_cancel.cancel();
                FlowEnd::Cancelled
            }
            End::Idle => FlowEnd::Timeout,
            End::ProtocolClose => {
                let close = codec::Frame::control(4, 1, 2, bytes::Bytes::new());
                client
                    .write_all(
                        &codec::seal_stream(&mut send, &close, &config::Traffic::default())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                FlowEnd::Completed
            }
        };
        if let Some(website) = &mut website {
            assert_eq!(
                timeout(Duration::from_secs(3), website.read(&mut [0; 1]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
        timeout(Duration::from_secs(2), async {
            while telemetry.usage().unwrap().active_flows != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let records = telemetry.records(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].source.user().is_some());
        if udp {
            assert!(records[0].original.is_none());
            assert_eq!(records[0].usage.upload_packets, 1);
            assert_eq!(records[0].usage.download_packets, 1);
        } else {
            assert_eq!(records[0].original.as_ref().unwrap().target(), &target);
        }
        assert_eq!(records[0].end, Some(expected));
        assert_eq!(records[0].usage.upload_bytes, 2);
        assert_eq!(records[0].usage.download_bytes, 4);
        assert!(
            requests
                .request
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .is_cancelled()
        );
        if !matches!(end, End::PeerCancel | End::NodeCancel) {
            assert!(!peer_cancel.is_cancelled());
        }
        link.scope.shutdown().await;
        drop(link);
        let report = tasks
            .shutdown_at(Instant::now() + Duration::from_secs(1))
            .await;
        assert!(report.is_clean());
        assert_eq!(global.available_permits(), 8);
        assert_eq!(local.available_permits(), 8);
        assert_eq!(telemetry.records(0, 10).unwrap()[0].end, Some(expected));
        if let Some(peer) = udp_peer {
            let _rebound = UdpSocket::bind(peer).await.unwrap();
        }
    }

    #[tokio::test]
    async fn authenticated_inbound_internal_abort_records_failure_and_releases_socket() {
        authenticated_case(End::InternalAbort, false).await;
    }
    #[tokio::test]
    async fn authenticated_inbound_true_peer_and_node_cancellation_remain_cancelled() {
        authenticated_case(End::PeerCancel, false).await;
        authenticated_case(End::NodeCancel, false).await;
    }
    #[tokio::test]
    async fn authenticated_inbound_idle_timeout_survives_cleanup() {
        authenticated_case(End::Idle, false).await;
    }
    #[tokio::test]
    async fn authenticated_inbound_protocol_close_keeps_delivered_tail_and_record() {
        authenticated_case(End::ProtocolClose, false).await;
    }
    #[tokio::test]
    async fn authenticated_udp_association_keeps_end_reason_usage_and_socket_ownership() {
        for end in [
            End::InternalAbort,
            End::PeerCancel,
            End::NodeCancel,
            End::Idle,
            End::ProtocolClose,
        ] {
            authenticated_case(end, true).await;
        }
    }
}
