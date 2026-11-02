use super::*;
use crate::{
    crypto::{self, Key},
    session::Command,
};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    Capabilities, DatagramAssociation, DatagramChannel, DeviceLease, DeviceNetwork, FamilyMode,
    NodeEvent, NodeId, NodeObserver, NodeTasks, OpenedTcp, OutId, Outbound, PeerLease,
    ServiceContext, StreamBudget, TargetPolicy, TcpConnectInfo,
};
use kerlico_egress::{FlowEnd, FlowStage, Resolver, Usage};
use serde_json::json;
use std::{
    future::poll_fn,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::Waker,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
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
struct Released(Arc<AtomicUsize>);
impl Drop for Released {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
pub(crate) struct OpeningPollGate {
    id: u32,
    polls: AtomicUsize,
    paused: Mutex<Option<PausedPoll>>,
}
struct PausedPoll {
    blocked: Option<oneshot::Sender<()>>,
    waker: Option<Waker>,
}
struct ResumeOpening(Arc<OpeningPollGate>);
impl Drop for ResumeOpening {
    fn drop(&mut self) {
        let paused = self
            .0
            .paused
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(waker) = paused.and_then(|paused| paused.waker) {
            waker.wake();
        }
    }
}
impl OpeningPollGate {
    fn new(id: u32) -> Self {
        Self {
            id,
            polls: AtomicUsize::new(0),
            paused: Mutex::new(None),
        }
    }
    pub(crate) fn poll(&self, cx: &Context<'_>) -> Poll<()> {
        if let Some(paused) = &mut *self.paused.lock().unwrap() {
            paused.waker = Some(cx.waker().clone());
            if let Some(blocked) = paused.blocked.take() {
                let _ = blocked.send(());
            }
            return Poll::Pending;
        }
        self.polls.fetch_add(1, Ordering::AcqRel);
        Poll::Ready(())
    }
    fn pause(self: &Arc<Self>) -> (ResumeOpening, oneshot::Receiver<()>) {
        let (blocked, receiver) = oneshot::channel();
        let previous = self.paused.lock().unwrap().replace(PausedPoll {
            blocked: Some(blocked),
            waker: None,
        });
        assert!(previous.is_none());
        (ResumeOpening(self.clone()), receiver)
    }
}
pub(crate) fn opening_poll_gate(life: &Life) -> Option<Arc<OpeningPollGate>> {
    life.link
        .opening_poll_gate
        .lock()
        .unwrap()
        .as_ref()
        .filter(|gate| gate.id == life.id)
        .cloned()
}
struct PendingDevice {
    entered: Mutex<Option<oneshot::Sender<SocketAddr>>>,
    release: Mutex<Option<oneshot::Receiver<Result<()>>>>,
    released: Arc<AtomicUsize>,
    polls: AtomicUsize,
}
impl PendingDevice {
    async fn hold<T>(&self, value: T, address: SocketAddr) -> Result<T> {
        let _released = Released(self.released.clone());
        let mut entered = self.entered.lock().unwrap().take();
        let mut release = self.release.lock().unwrap().take().unwrap();
        poll_fn(|cx| {
            self.polls.fetch_add(1, Ordering::AcqRel);
            let result = Pin::new(&mut release).poll(cx);
            if result.is_pending()
                && let Some(entered) = entered.take()
            {
                let _ = entered.send(address);
            }
            result
        })
        .await
        .map_err(|_| Error::Protocol("建立控制通道提前释放"))??;
        Ok(value)
    }
}
impl DeviceNetwork for PendingDevice {
    fn connect_tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<OpenedTcp>> {
        Box::pin(async move {
            let stream = TcpStream::connect(target).await?;
            let local = stream.local_addr()?;
            self.hold(
                OpenedTcp {
                    stream: Box::new(stream),
                    info: TcpConnectInfo::local_bound(local),
                },
                local,
            )
            .await
        })
    }
    fn connect_udp(&self, _: SocketAddr) -> BoxFuture<'_, Result<Arc<UdpSocket>>> {
        Box::pin(async { Err(Error::Unsupported("本回归只建立TCP和多目标UDP关联")) })
    }
    fn udp_association(&self, mode: FamilyMode) -> BoxFuture<'_, Result<Arc<UdpSocket>>> {
        Box::pin(async move {
            assert_eq!(mode, FamilyMode::V4Only);
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            let local = socket.local_addr()?;
            self.hold(socket, local).await
        })
    }
}
struct Requests {
    backend: Arc<dyn Outbound>,
    context: Mutex<Option<ConnectContext>>,
}
impl Outbound for Requests {
    fn capabilities(&self) -> Capabilities {
        self.backend.capabilities()
    }
    fn supports_udp_association(&self) -> bool {
        self.backend.supports_udp_association()
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        *self.context.lock().unwrap() = Some(context.clone());
        self.backend.connect_tcp(target, context)
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.backend.connect_udp(target, context)
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        *self.context.lock().unwrap() = Some(context.clone());
        self.backend.associate_udp(context)
    }
}
#[derive(Clone, Copy, Debug)]
enum End {
    InternalAbort,
    PeerCancel,
    NodeCancel,
    Idle,
    ConnectDeadline,
    ProtocolClose,
    ServiceCancelBeforeProtocolClose(u8),
    EntryDrop,
    BackendFailure,
    BackendTimeout,
    OsAborted,
    OsTimedOut,
}
impl End {
    fn expected(self) -> FlowEnd {
        match self {
            Self::PeerCancel | Self::NodeCancel | Self::ServiceCancelBeforeProtocolClose(_) => {
                FlowEnd::Cancelled
            }
            Self::Idle | Self::ConnectDeadline | Self::BackendTimeout => FlowEnd::Timeout,
            Self::ProtocolClose => FlowEnd::Completed,
            Self::EntryDrop => FlowEnd::ClosedByCaller,
            Self::InternalAbort | Self::BackendFailure | Self::OsAborted | Self::OsTimedOut => {
                FlowEnd::Failed
            }
        }
    }
}

async fn pending_case(end: End, udp: bool) {
    let native = json!({"username":"node-user", "password":"synthetic-password"});
    let input = NodeBuildContext::for_test(json!({"transport":"tcp"}), vec![native]);
    let node = Node::build(&input).unwrap();
    let (entered, pending) = oneshot::channel();
    let (release, gate) = oneshot::channel();
    let released = Arc::new(AtomicUsize::new(0));
    let device = Arc::new(PendingDevice {
        entered: Mutex::new(Some(entered)),
        release: Mutex::new(Some(gate)),
        released: released.clone(),
        polls: AtomicUsize::new(0),
    });
    let service = ServiceContext::with_device(
        OutId::parse("test-outbound").unwrap(),
        DeviceLease::borrow(device.clone()),
    );
    let backend = kerlico_net::DirectFactory
        .compile(&json!({}))
        .unwrap()
        .start(service.clone())
        .await
        .unwrap();
    let requests = Arc::new(Requests {
        backend,
        context: Mutex::new(None),
    });
    let (binding, telemetry) = kerlico_egress::testing::ingress_with_service(
        &input,
        requests.clone(),
        TargetPolicy::Local,
        FamilyMode::V4Only,
        Arc::new(NoDns),
        service.clone(),
    )
    .unwrap();
    let node_cancel = binding.node_cancel();
    let peer_cancel = node_cancel.child_token();
    let tasks = NodeTasks::new(NodeId::parse("test-node").unwrap(), node_cancel.clone());
    let global = Arc::new(Semaphore::new(8));
    let local = Arc::new(Semaphore::new(8));
    let budget = StreamBudget::new(global.clone(), local.clone());
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target =
        Destination::new("127.0.0.1", target_listener.local_addr().unwrap().port()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connecting = TcpStream::connect(listener.local_addr().unwrap());
    let (client, server) = tokio::join!(connecting, listener.accept());
    let mut client = client.unwrap();
    let (server, observed) = server.unwrap();
    let context = InboundContext {
        peer_lease: Some(PeerLease::new(
            peer_cancel.clone(),
            budget.try_acquire().unwrap(),
        )),
        tasks: tasks.clone(),
        peer_addr: Some(observed),
        local_addr: Some(listener.local_addr().unwrap()),
        cancel: peer_cancel.clone(),
        connect_timeout: if matches!(end, End::ConnectDeadline) {
            Duration::from_millis(200)
        } else {
            Duration::from_secs(2)
        },
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
    let mut send = StreamCipher::new(key);
    let opening = codec::Frame::control(2, 1, 0, codec::request((!udp).then_some(&target)).into());
    client
        .write_all(&codec::seal_stream(&mut send, &opening, &config::Traffic::default()).unwrap())
        .await
        .unwrap();
    let link = node
        .start_tcp(Box::new(server), binding, context)
        .await
        .unwrap();
    let expected_source = match &link.server.as_ref().unwrap().access {
        session::ServerAccess::Authenticated(peer) => peer.source().clone(),
        session::ServerAccess::Local(_) => panic!("TCP回归必须经过真实鉴权"),
    };
    let poll_gate = matches!(end, End::ServiceCancelBeforeProtocolClose(_))
        .then(|| Arc::new(OpeningPollGate::new(1)));
    if let Some(gate) = &poll_gate {
        *link.opening_poll_gate.lock().unwrap() = Some(gate.clone());
    }
    let held_address = timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    let mut website = if udp {
        assert!(std::net::UdpSocket::bind(held_address).is_err());
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
    let request = requests.context.lock().unwrap().as_ref().unwrap().clone();
    assert!(!request.cancel.is_cancelled());
    assert!(!peer_cancel.is_cancelled());
    assert!(!node_cancel.is_cancelled());
    assert!(!request.service_cancel().is_cancelled());
    assert_eq!(released.load(Ordering::Acquire), 0);
    assert_eq!(global.available_permits(), 6);
    assert_eq!(local.available_permits(), 6);
    let before = telemetry.records(0, 10).unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].source, expected_source);
    assert_eq!(before[0].stage, FlowStage::Opening);
    assert_eq!(before[0].end, None);
    assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    let mut paused = None;
    let mut opening_polls = None;
    let backend_polls = device.polls.load(Ordering::Acquire);
    if let Some(gate) = &poll_gate {
        let polls = gate.polls.load(Ordering::Acquire);
        assert!(polls > 0);
        opening_polls = Some(polls);
        let (resume, blocked) = gate.pause();
        paused = Some(resume);
        let task = service
            .spawn_tracked(async { panic!("受控命名出站后台任务失败") })
            .unwrap();
        assert!(
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .is_err()
        );
        assert!(service.cancel().is_cancelled());
        assert!(request.service_cancel().is_cancelled());
        timeout(Duration::from_secs(1), blocked)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gate.polls.load(Ordering::Acquire), polls);
        assert_eq!(device.polls.load(Ordering::Acquire), backend_polls);
        assert_eq!(released.load(Ordering::Acquire), 0);
        assert!(!request.cancel.is_cancelled());
        assert!(!peer_cancel.is_cancelled());
        assert!(!node_cancel.is_cancelled());
        assert_eq!(telemetry.records(0, 10).unwrap()[0].end, None);
        assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    }
    let mut release = Some(release);
    match end {
        End::InternalAbort => link
            .command
            .send(Command::Close {
                id: 1,
                abort: true,
                done: None,
            })
            .await
            .unwrap(),
        End::PeerCancel => peer_cancel.cancel(),
        End::NodeCancel => node_cancel.cancel(),
        End::Idle | End::ConnectDeadline => {}
        End::ProtocolClose | End::ServiceCancelBeforeProtocolClose(_) | End::EntryDrop => {
            let (kind, sequence) = match end {
                End::ProtocolClose => (4, 1),
                End::ServiceCancelBeforeProtocolClose(kind) => (kind, 1),
                End::EntryDrop => (3, 0),
                _ => unreachable!(),
            };
            let frame = codec::Frame::control(kind, 1, sequence, bytes::Bytes::new());
            client
                .write_all(
                    &codec::seal_stream(&mut send, &frame, &config::Traffic::default()).unwrap(),
                )
                .await
                .unwrap();
        }
        End::BackendFailure | End::BackendTimeout | End::OsAborted | End::OsTimedOut => {
            let error = match end {
                End::BackendFailure => Error::Protocol("受控后端独立失败"),
                End::BackendTimeout => Error::Timeout,
                End::OsAborted => Error::Io(io::ErrorKind::ConnectionAborted.into()),
                End::OsTimedOut => Error::Io(io::ErrorKind::TimedOut.into()),
                _ => unreachable!(),
            };
            release.take().unwrap().send(Err(error)).unwrap();
        }
    }
    timeout(Duration::from_secs(3), async {
        while telemetry.usage().unwrap().active_flows != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let records = telemetry.records(0, 10).unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.id, before[0].id);
    assert_eq!(record.source, before[0].source);
    assert!(record.source.user().is_some());
    assert_eq!(record.source.node(), &NodeId::parse("test-node").unwrap());
    assert_eq!(record.outbound, OutId::parse("test-outbound").unwrap());
    assert_eq!(record.observed_source, Some(observed));
    assert_eq!(record.stage, FlowStage::Opening);
    assert_eq!(record.end, Some(end.expected()), "{end:?}, udp={udp}");
    assert_eq!(record.usage, Usage::default());
    let usage = telemetry.usage().unwrap();
    assert_eq!(usage.retained_records, 1);
    assert_eq!(usage.engine, record.usage);
    assert_eq!(usage.users[&record.source.user().unwrap()], record.usage);
    assert_eq!(usage.nodes[record.source.node()], record.usage);
    assert_eq!(usage.outbounds[&record.outbound], record.usage);
    assert!(record.observed_target.is_none());
    assert!(record.datagram_targets.is_empty());
    if udp {
        assert!(record.original.is_none());
    } else {
        assert_eq!(record.original.as_ref().unwrap().target(), &target);
    }
    assert_eq!(released.load(Ordering::Acquire), 1);
    if let Some(gate) = &poll_gate {
        assert_eq!(Some(gate.polls.load(Ordering::Acquire)), opening_polls);
        assert_eq!(device.polls.load(Ordering::Acquire), backend_polls);
    }
    drop(paused);
    if let Some(website) = &mut website {
        assert_eq!(
            timeout(Duration::from_secs(2), website.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    } else {
        let _rebound = UdpSocket::bind(held_address).await.unwrap();
    }
    timeout(Duration::from_secs(1), request.cancel.cancelled())
        .await
        .unwrap();
    let service_failed = matches!(end, End::ServiceCancelBeforeProtocolClose(_));
    assert_eq!(request.service_cancel().is_cancelled(), service_failed);
    if !matches!(end, End::PeerCancel | End::NodeCancel) {
        assert!(!peer_cancel.is_cancelled());
        assert!(!node_cancel.is_cancelled());
    }
    peer_cancel.cancel();
    node_cancel.cancel();
    link.scope.shutdown().await;
    drop(link);
    let report = tasks
        .shutdown_at(Instant::now() + Duration::from_secs(1))
        .await;
    assert!(report.is_clean());
    assert_eq!(report.forced_tasks, 0);
    assert_eq!(global.available_permits(), 8);
    assert_eq!(local.available_permits(), 8);
    assert_eq!(
        telemetry.records(0, 10).unwrap()[0].end,
        Some(end.expected())
    );
    assert_eq!(request.service_cancel().is_cancelled(), service_failed);
    let service_report = service
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await;
    assert!(!service_report.timed_out);
    assert_eq!(service_report.failed_tasks, usize::from(service_failed));
    assert_eq!(service_report.forced_tasks, 0);
}

#[tokio::test]
async fn authenticated_pending_tcp_abort_keeps_failure_before_cleanup() {
    pending_case(End::InternalAbort, false).await;
}
#[tokio::test]
async fn authenticated_pending_udp_abort_keeps_failure_before_cleanup() {
    pending_case(End::InternalAbort, true).await;
}
#[tokio::test]
async fn authenticated_pending_tcp_and_udp_keep_real_peer_and_node_cancellation() {
    for udp in [false, true] {
        for end in [End::PeerCancel, End::NodeCancel] {
            pending_case(end, udp).await;
        }
    }
}
#[tokio::test]
async fn authenticated_pending_tcp_and_udp_keep_idle_and_connect_timeout() {
    for udp in [false, true] {
        for end in [End::Idle, End::ConnectDeadline] {
            pending_case(end, udp).await;
        }
    }
}
#[tokio::test]
async fn authenticated_pending_tcp_and_udp_distinguish_protocol_end_from_entry_drop() {
    for udp in [false, true] {
        for end in [End::ProtocolClose, End::EntryDrop] {
            pending_case(end, udp).await;
        }
    }
}
#[tokio::test]
async fn authenticated_pending_tcp_and_udp_keep_prior_backend_failure_and_timeout() {
    for udp in [false, true] {
        for end in [
            End::BackendFailure,
            End::BackendTimeout,
            End::OsAborted,
            End::OsTimedOut,
        ] {
            pending_case(end, udp).await;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_pending_tcp_and_udp_keep_service_failure_before_frame4_and_frame5() {
    for udp in [false, true] {
        for frame in [4, 5] {
            pending_case(End::ServiceCancelBeforeProtocolClose(frame), udp).await;
        }
    }
}
