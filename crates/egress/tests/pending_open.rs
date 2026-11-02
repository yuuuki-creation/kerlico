use kerlico_config::{NodeBuildContext, OutboundFactory};
use kerlico_core::*;
use kerlico_egress::{FlowEnd, FlowKind, FlowStage, Resolver, Telemetry, Usage, testing};
use serde_json::json;
use std::{
    future::{Future, poll_fn},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
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
        Box::pin(async { Err(Error::Protocol("字面目标不应查询DNS")) })
    }
}
struct Released(Arc<AtomicUsize>);
impl Drop for Released {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
#[derive(Default)]
struct WriteGate {
    held: AtomicBool,
    attempts: AtomicUsize,
}
struct GatedStream {
    stream: TcpStream,
    gate: Arc<WriteGate>,
}
impl AsyncRead for GatedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for GatedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.gate.held.load(Ordering::Acquire) {
            this.gate.attempts.fetch_add(1, Ordering::AcqRel);
            return Poll::Pending;
        }
        Pin::new(&mut this.stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
struct PendingDevice {
    entered: Mutex<Option<oneshot::Sender<SocketAddr>>>,
    release: Mutex<Option<oneshot::Receiver<Result<()>>>>,
    started: AtomicUsize,
    polls: AtomicUsize,
    released: Arc<AtomicUsize>,
    write_gate: Arc<WriteGate>,
}
impl PendingDevice {
    async fn hold<T>(&self, value: T, address: SocketAddr) -> Result<T> {
        self.started.fetch_add(1, Ordering::AcqRel);
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
                    stream: Box::new(GatedStream { stream, gate: self.write_gate.clone() }),
                    info: TcpConnectInfo::local_bound(local),
                },
                local,
            )
            .await
        })
    }
    fn connect_udp(&self, target: SocketAddr) -> BoxFuture<'_, Result<Arc<UdpSocket>>> {
        Box::pin(async move {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            socket.connect(target).await?;
            let local = socket.local_addr()?;
            self.hold(socket, local).await
        })
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
#[derive(Clone, Copy, Debug)]
enum Kind {
    Tcp,
    Fixed,
    Association,
}
impl Kind {
    fn record_kind(self) -> FlowKind {
        match self {
            Self::Tcp => FlowKind::Tcp,
            Self::Fixed => FlowKind::FixedUdp,
            Self::Association => FlowKind::UdpAssociation,
        }
    }
}
enum Opening<'a> {
    Tcp(FlowOpen<'a, TcpFlow>),
    Fixed(FlowOpen<'a, FixedUdpFlow>),
    Association(FlowOpen<'a, UdpAssociation>),
}
enum Ready {
    Tcp(TcpFlow),
    Fixed(FixedUdpFlow),
    Association(UdpAssociation),
}
impl Ready {
    fn finish(self, outcome: FlowOutcome) {
        match self {
            Self::Tcp(flow) => flow.finish(outcome),
            Self::Fixed(flow) => flow.finish(outcome),
            Self::Association(flow) => flow.finish(outcome),
        }
    }
    fn finish_retaining_io(self, outcome: FlowOutcome) -> Box<dyn Send> {
        match self {
            Self::Tcp(flow) => {
                let (io, completion) = flow.into_parts();
                completion.finish(outcome);
                Box::new(io)
            }
            Self::Fixed(flow) => {
                let (send, recv, completion) = flow.into_parts();
                completion.finish(outcome);
                Box::new((send, recv))
            }
            Self::Association(flow) => {
                let (send, recv, completion) = flow.into_parts();
                completion.finish(outcome);
                Box::new((send, recv))
            }
        }
    }
}
impl Opening<'_> {
    fn finish(self, outcome: FlowOutcome) {
        match self {
            Self::Tcp(opening) => opening.finish(outcome),
            Self::Fixed(opening) => opening.finish(outcome),
            Self::Association(opening) => opening.finish(outcome),
        }
    }
}
impl Future for Opening<'_> {
    type Output = Result<Ready>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Tcp(opening) => Pin::new(opening)
                .poll(cx)
                .map(|result| result.map(Ready::Tcp)),
            Self::Fixed(opening) => Pin::new(opening)
                .poll(cx)
                .map(|result| result.map(Ready::Fixed)),
            Self::Association(opening) => Pin::new(opening)
                .poll(cx)
                .map(|result| result.map(Ready::Association)),
        }
    }
}
struct Fixture {
    binding: IngressBinding,
    peer: PeerSession,
    request: ConnectContext,
    target: Destination,
    tcp: TcpListener,
    _udp: UdpSocket,
    telemetry: Telemetry,
    service: ServiceContext,
    device: Arc<PendingDevice>,
    entered: Option<oneshot::Receiver<SocketAddr>>,
    release: Option<oneshot::Sender<Result<()>>>,
}
impl Fixture {
    async fn new(kind: Kind) -> Self {
        let (entered, pending) = oneshot::channel();
        let (release, gate) = oneshot::channel();
        let device = Arc::new(PendingDevice {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(Some(gate)),
            started: AtomicUsize::new(0),
            polls: AtomicUsize::new(0),
            released: Arc::new(AtomicUsize::new(0)),
            write_gate: Arc::new(WriteGate::default()),
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
        let input = NodeBuildContext::local_for_test(json!({}));
        let (binding, telemetry) = testing::ingress_with_service(
            &input,
            backend,
            TargetPolicy::Local,
            FamilyMode::V4Only,
            Arc::new(NoDns),
            service.clone(),
        )
        .unwrap();
        let node_cancel = binding.node_cancel();
        let context = InboundContext {
            peer_lease: None,
            tasks: NodeTasks::new(NodeId::parse("test-node").unwrap(), node_cancel.clone()),
            peer_addr: Some("127.0.0.1:12345".parse().unwrap()),
            local_addr: None,
            cancel: node_cancel.child_token(),
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 8,
            stream_budget: StreamBudget::new(
                Arc::new(Semaphore::new(8)),
                Arc::new(Semaphore::new(8)),
            ),
            events: Arc::new(Observer),
        };
        let peer = binding.local(&context).unwrap();
        let request =
            ConnectContext::new(Duration::from_secs(2)).with_cancel(peer.cancel().child_token());
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = if matches!(kind, Kind::Tcp) {
            tcp.local_addr().unwrap().port()
        } else {
            udp.local_addr().unwrap().port()
        };
        Self {
            binding,
            peer,
            request,
            target: Destination::new("127.0.0.1", port).unwrap(),
            tcp,
            _udp: udp,
            telemetry,
            service,
            device,
            entered: Some(pending),
            release: Some(release),
        }
    }
    fn open(&self, kind: Kind) -> Opening<'_> {
        match kind {
            Kind::Tcp => Opening::Tcp(self.peer.connect_tcp(&self.target, &self.request)),
            Kind::Fixed => Opening::Fixed(self.peer.connect_udp(&self.target, &self.request)),
            Kind::Association => Opening::Association(self.peer.associate_udp(&self.request)),
        }
    }
}
async fn held(
    opening: &mut Opening<'_>,
    pending: oneshot::Receiver<SocketAddr>,
    fixture: &Fixture,
    kind: Kind,
) -> (SocketAddr, Option<TcpStream>) {
    let address = timeout(Duration::from_secs(2), async {
        tokio::select! {
            _ = &mut *opening => panic!("建立操作必须仍然Pending"),
            address = pending => address.unwrap(),
        }
    })
    .await
    .unwrap();
    let website = if matches!(kind, Kind::Tcp) {
        Some(
            timeout(Duration::from_secs(1), fixture.tcp.accept())
                .await
                .unwrap()
                .unwrap()
                .0,
        )
    } else {
        assert!(std::net::UdpSocket::bind(address).is_err());
        None
    };
    let records = fixture.telemetry.records(0, 2).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, kind.record_kind());
    assert_eq!(records[0].stage, FlowStage::Opening);
    assert_eq!(records[0].end, None);
    assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 1);
    assert_eq!(fixture.device.started.load(Ordering::Acquire), 1);
    assert_eq!(fixture.device.released.load(Ordering::Acquire), 0);
    (address, website)
}
async fn assert_finished(
    fixture: &Fixture,
    address: SocketAddr,
    mut website: Option<TcpStream>,
    expected: FlowEnd,
) {
    let records = fixture.telemetry.records(0, 2).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].end, Some(expected));
    assert_eq!(records[0].usage, Usage::default());
    assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 0);
    assert_eq!(fixture.device.released.load(Ordering::Acquire), 1);
    if let Some(website) = &mut website {
        assert_eq!(
            timeout(Duration::from_secs(1), website.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    } else {
        let _rebound = UdpSocket::bind(address).await.unwrap();
    }
    fixture.request.cancel.cancel();
    assert!(!fixture.peer.cancel().is_cancelled());
    assert!(!fixture.binding.node_cancel().is_cancelled());
    assert_eq!(
        fixture.telemetry.records(0, 2).unwrap()[0].end,
        Some(expected)
    );
}

#[tokio::test]
async fn unpolled_open_finish_is_lazy_and_poll_rechecks_admission() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        let fixture = Fixture::new(kind).await;
        fixture
            .open(kind)
            .finish(FlowOutcome::Failed(FlowFailure::Failed));
        assert!(fixture.telemetry.records(0, 2).unwrap().is_empty());
        assert_eq!(fixture.device.started.load(Ordering::Acquire), 0);
        drop(fixture.open(kind));
        assert!(fixture.telemetry.records(0, 2).unwrap().is_empty());
        assert_eq!(fixture.device.started.load(Ordering::Acquire), 0);
        let opening = fixture.open(kind);
        fixture.binding.stop_admission();
        assert!(matches!(opening.await, Err(Error::Cancelled)));
        assert!(fixture.telemetry.records(0, 2).unwrap().is_empty());
        assert_eq!(fixture.device.started.load(Ordering::Acquire), 0);
    }
}

#[tokio::test]
async fn pending_three_kinds_report_before_disposal_and_keep_explicit_failure() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        for failure in [FlowFailure::Failed, FlowFailure::Timeout] {
            let mut fixture = Fixture::new(kind).await;
            let pending = fixture.entered.take().unwrap();
            let mut opening = fixture.open(kind);
            let (address, website) = held(&mut opening, pending, &fixture, kind).await;
            opening.finish(FlowOutcome::Failed(failure));
            let expected = if failure == FlowFailure::Timeout {
                FlowEnd::Timeout
            } else {
                FlowEnd::Failed
            };
            assert_finished(&fixture, address, website, expected).await;
        }
    }
}

#[tokio::test]
async fn pending_three_kinds_drop_distinguishes_caller_from_real_cancellation() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        for cancel in [false, true] {
            let mut fixture = Fixture::new(kind).await;
            let pending = fixture.entered.take().unwrap();
            let mut opening = fixture.open(kind);
            let (address, website) = held(&mut opening, pending, &fixture, kind).await;
            if cancel {
                fixture.request.cancel.cancel();
            }
            drop(opening);
            let expected = if cancel {
                FlowEnd::Cancelled
            } else {
                FlowEnd::ClosedByCaller
            };
            assert_finished(&fixture, address, website, expected).await;
        }
    }
}

#[tokio::test]
async fn pending_three_kinds_panic_drop_keeps_failure_and_releases_socket() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        let mut fixture = Fixture::new(kind).await;
        let pending = fixture.entered.take().unwrap();
        let mut opening = fixture.open(kind);
        let (address, website) = held(&mut opening, pending, &fixture, kind).await;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _opening = opening;
            panic!("受控调用方panic");
        }));
        assert!(result.is_err());
        assert_finished(&fixture, address, website, FlowEnd::Failed).await;
    }
}

#[tokio::test]
async fn ready_three_kinds_transfer_the_same_completion_once() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        let mut fixture = Fixture::new(kind).await;
        let pending = fixture.entered.take().unwrap();
        let release = fixture.release.take().unwrap();
        let mut opening = fixture.open(kind);
        let (address, website) = held(&mut opening, pending, &fixture, kind).await;
        release.send(Ok(())).unwrap();
        let flow = timeout(Duration::from_secs(1), &mut opening)
            .await
            .unwrap()
            .unwrap();
        drop(opening);
        assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 1);
        assert_eq!(fixture.telemetry.records(0, 2).unwrap()[0].end, None);
        flow.finish(FlowOutcome::ProtocolEnd);
        assert_finished(&fixture, address, website, FlowEnd::Completed).await;
    }
}

#[tokio::test]
async fn opening_three_kinds_keep_backend_error_before_later_cleanup() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        for timed_out in [false, true] {
            let mut fixture = Fixture::new(kind).await;
            let pending = fixture.entered.take().unwrap();
            let release = fixture.release.take().unwrap();
            let mut opening = fixture.open(kind);
            let (address, website) = held(&mut opening, pending, &fixture, kind).await;
            release
                .send(Err(if timed_out {
                    Error::Timeout
                } else {
                    Error::Protocol("受控独立失败")
                }))
                .unwrap();
            let error = match timeout(Duration::from_secs(1), &mut opening).await.unwrap() {
                Ok(_) => panic!("后端失败不能返回业务流"),
                Err(error) => error,
            };
            assert_eq!(
                FlowFailure::from_error(&error),
                if timed_out {
                    FlowFailure::Timeout
                } else {
                    FlowFailure::Failed
                }
            );
            drop(opening);
            fail_service(&fixture.service).await;
            let expected = if timed_out {
                FlowEnd::Timeout
            } else {
                FlowEnd::Failed
            };
            assert_finished(&fixture, address, website, expected).await;
            join_failed_service(&fixture.service).await;
        }
    }
}

async fn fail_service(service: &ServiceContext) {
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
}

async fn join_failed_service(service: &ServiceContext) {
    let report = service
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await;
    assert!(!report.timed_out);
    assert_eq!(report.failed_tasks, 1);
    assert_eq!(report.forced_tasks, 0);
}

#[tokio::test]
async fn pending_three_kinds_keep_service_failure_before_protocol_end_without_repoll() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        let mut fixture = Fixture::new(kind).await;
        let pending = fixture.entered.take().unwrap();
        let mut opening = fixture.open(kind);
        let (address, website) = held(&mut opening, pending, &fixture, kind).await;
        let polls = fixture.device.polls.load(Ordering::Acquire);
        fail_service(&fixture.service).await;
        assert_eq!(fixture.device.polls.load(Ordering::Acquire), polls);
        assert_eq!(fixture.device.released.load(Ordering::Acquire), 0);
        assert!(!fixture.request.cancel.is_cancelled());
        assert!(!fixture.peer.cancel().is_cancelled());
        assert!(!fixture.binding.node_cancel().is_cancelled());
        let before = fixture.telemetry.records(0, 2).unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].stage, FlowStage::Opening);
        assert_eq!(before[0].end, None);
        opening.finish(FlowOutcome::ProtocolEnd);
        assert_finished(&fixture, address, website, FlowEnd::Failed).await;
        assert_eq!(fixture.device.polls.load(Ordering::Acquire), polls);
        assert_eq!(fixture.telemetry.records(0, 2).unwrap()[0].id, before[0].id);
        join_failed_service(&fixture.service).await;
    }
}

#[tokio::test]
async fn ready_three_kinds_keep_protocol_end_when_service_fails_before_or_after_report() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        for cancel_before_report in [false, true] {
            let mut fixture = Fixture::new(kind).await;
            let pending = fixture.entered.take().unwrap();
            let release = fixture.release.take().unwrap();
            let mut opening = fixture.open(kind);
            let (address, website) = held(&mut opening, pending, &fixture, kind).await;
            release.send(Ok(())).unwrap();
            let flow = timeout(Duration::from_secs(1), &mut opening)
                .await
                .unwrap()
                .unwrap();
            drop(opening);
            let stage = if matches!(kind, Kind::Tcp) {
                FlowStage::LocalConnected
            } else {
                FlowStage::LocalDatagramReady
            };
            let before = fixture.telemetry.records(0, 2).unwrap();
            assert_eq!(before[0].stage, stage);
            assert_eq!(before[0].end, None);
            if cancel_before_report {
                fail_service(&fixture.service).await;
            }
            let io = flow.finish_retaining_io(FlowOutcome::ProtocolEnd);
            if !cancel_before_report {
                fail_service(&fixture.service).await;
            }
            assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 1);
            assert_eq!(fixture.telemetry.records(0, 2).unwrap()[0].end, None);
            drop(io);
            assert_finished(&fixture, address, website, FlowEnd::Completed).await;
            assert_eq!(fixture.telemetry.records(0, 2).unwrap()[0].id, before[0].id);
            join_failed_service(&fixture.service).await;
        }
    }
}

fn assert_service_failure(error: &Error, failure: ServiceFailure) {
    match failure {
        ServiceFailure::Timeout => assert!(matches!(error, Error::Timeout)),
        ServiceFailure::Protocol(expected) => assert!(matches!(error, Error::Protocol(actual) if *actual == expected)),
        _ => panic!("本回归只使用超时和协议失败"),
    }
}

#[tokio::test]
async fn dispatcher_preserves_first_service_failure_for_pending_and_new_requests() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        for failure in [ServiceFailure::Timeout, ServiceFailure::Protocol("协议版本已不满足网络要求")] {
            let mut fixture = Fixture::new(kind).await;
            let pending = fixture.entered.take().unwrap();
            let mut opening = fixture.open(kind);
            let (address, website) = held(&mut opening, pending, &fixture, kind).await;
            fixture.service.fail(failure);
            fixture.service.fail(ServiceFailure::Rejected);
            let error = match timeout(Duration::from_secs(1), &mut opening).await.unwrap() {
                Err(error) => error,
                Ok(_) => panic!("失败服务不能交付业务流"),
            };
            assert_service_failure(&error, failure);
            assert_eq!(fixture.service.failure(), Some(failure));
            drop(opening);
            match fixture.open(kind).await {
                Err(error) => assert_service_failure(&error, failure),
                Ok(_) => panic!("后续请求不能绕过已失败服务"),
            }
            assert_eq!(fixture.device.started.load(Ordering::Acquire), 1);
            assert!(!fixture.request.cancel.is_cancelled());
            assert!(!fixture.peer.cancel().is_cancelled());
            assert!(!fixture.binding.node_cancel().is_cancelled());
            let expected = if failure == ServiceFailure::Timeout { FlowEnd::Timeout } else { FlowEnd::Failed };
            assert_finished(&fixture, address, website, expected).await;
        }
    }
}

#[tokio::test]
async fn unpolled_pending_completion_reads_service_timeout() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        let mut fixture = Fixture::new(kind).await;
        let pending = fixture.entered.take().unwrap();
        let mut opening = fixture.open(kind);
        let (address, website) = held(&mut opening, pending, &fixture, kind).await;
        let polls = fixture.device.polls.load(Ordering::Acquire);
        fixture.service.fail(ServiceFailure::Timeout);
        opening.finish(FlowOutcome::ProtocolEnd);
        assert_eq!(fixture.device.polls.load(Ordering::Acquire), polls);
        assert_finished(&fixture, address, website, FlowEnd::Timeout).await;
    }
}

#[tokio::test]
async fn dispatcher_normal_request_peer_and_node_cancel_precede_service_failure() {
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        for domain in 0..3 {
            let mut fixture = Fixture::new(kind).await;
            let pending = fixture.entered.take().unwrap();
            let mut opening = fixture.open(kind);
            let (address, mut website) = held(&mut opening, pending, &fixture, kind).await;
            fixture.service.fail(ServiceFailure::Timeout);
            match domain {
                0 => fixture.request.cancel.cancel(),
                1 => fixture.peer.cancel().cancel(),
                _ => fixture.binding.node_cancel().cancel(),
            }
            assert!(matches!(opening.await, Err(Error::Cancelled)));
            assert!(matches!(fixture.open(kind).await, Err(Error::Cancelled)));
            assert_eq!(fixture.service.failure(), Some(ServiceFailure::Timeout));
            let records = fixture.telemetry.records(0, 2).unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].end, Some(FlowEnd::Cancelled));
            assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 0);
            assert_eq!(fixture.device.released.load(Ordering::Acquire), 1);
            if let Some(website) = &mut website {
                assert_eq!(timeout(Duration::from_secs(1), website.read(&mut [0; 1])).await.unwrap().unwrap(), 0);
            } else {
                let _rebound = UdpSocket::bind(address).await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn ready_io_keeps_service_failure_and_already_accounted_bytes() {
    let healthy = ServiceContext::for_test();
    for kind in [Kind::Tcp, Kind::Fixed, Kind::Association] {
        for failure in [ServiceFailure::Timeout, ServiceFailure::Protocol("协议版本已不满足网络要求")] {
            let mut fixture = Fixture::new(kind).await;
            let pending = fixture.entered.take().unwrap();
            let release = fixture.release.take().unwrap();
            let mut opening = fixture.open(kind);
            let (address, mut website) = held(&mut opening, pending, &fixture, kind).await;
            release.send(Ok(())).unwrap();
            let flow = timeout(Duration::from_secs(1), &mut opening).await.unwrap().unwrap();
            drop(opening);
            let expected_failure = if failure == ServiceFailure::Timeout { FlowFailure::Timeout } else { FlowFailure::Failed };
            timeout(Duration::from_secs(2), async {
                match flow {
                    Ready::Tcp(mut flow) => {
                        let website = website.as_mut().unwrap();
                        flow.write_all(b"up!").await.unwrap();
                        let mut up = [0; 3];
                        website.read_exact(&mut up).await.unwrap();
                        assert_eq!(&up, b"up!");
                        website.write_all(b"down").await.unwrap();
                        let mut down = [0; 4];
                        flow.read_exact(&mut down).await.unwrap();
                        assert_eq!(&down, b"down");
                        let (io, completion) = flow.into_parts();
                        let (mut reader, mut writer) = tokio::io::split(io);
                        fixture.device.write_gate.held.store(true, Ordering::Release);
                        let mut byte = [0; 1];
                        let mut read = Box::pin(reader.read(&mut byte));
                        let mut write = Box::pin(writer.write_all(b"not-counted"));
                        assert!(poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx).is_pending())).await);
                        assert!(poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx).is_pending())).await);
                        let polls = fixture.device.write_gate.attempts.load(Ordering::Acquire);
                        fixture.service.fail(failure);
                        let (read, write) = tokio::join!(read, write);
                        assert_eq!(FlowFailure::from_io_error(&read.unwrap_err()), expected_failure);
                        assert_eq!(FlowFailure::from_io_error(&write.unwrap_err()), expected_failure);
                        assert_eq!(fixture.device.write_gate.attempts.load(Ordering::Acquire), polls);
                        completion.finish(FlowOutcome::ProtocolEnd);
                        drop((reader, writer));
                    }
                    Ready::Fixed(flow) => {
                        let (mut sender, mut receiver, completion) = flow.into_parts();
                        sender.send(b"up!").await.unwrap();
                        let mut up = [0; 3];
                        let (length, client) = fixture._udp.recv_from(&mut up).await.unwrap();
                        assert_eq!((&up[..length], client), (b"up!".as_slice(), address));
                        fixture._udp.send_to(b"down", client).await.unwrap();
                        assert_eq!(receiver.recv().await.unwrap().unwrap(), b"down");
                        let mut receive = receiver.recv();
                        assert!(poll_fn(|cx| Poll::Ready(receive.as_mut().poll(cx).is_pending())).await);
                        fixture.service.fail(failure);
                        assert_service_failure(&receive.await.unwrap_err(), failure);
                        assert_service_failure(&sender.send(b"not-counted").await.unwrap_err(), failure);
                        completion.finish(FlowOutcome::ProtocolEnd);
                        drop((sender, receiver));
                    }
                    Ready::Association(flow) => {
                        let (mut sender, mut receiver, completion) = flow.into_parts();
                        sender.send_to(b"up!", &fixture.target).await.unwrap();
                        let mut up = [0; 3];
                        let (length, client) = fixture._udp.recv_from(&mut up).await.unwrap();
                        assert_eq!((&up[..length], client), (b"up!".as_slice(), address));
                        fixture._udp.send_to(b"down", client).await.unwrap();
                        let (source, bytes) = receiver.recv_from().await.unwrap().unwrap();
                        assert_eq!(source, fixture.target);
                        assert_eq!(bytes, b"down");
                        let mut receive = receiver.recv_from();
                        assert!(poll_fn(|cx| Poll::Ready(receive.as_mut().poll(cx).is_pending())).await);
                        fixture.service.fail(failure);
                        assert_service_failure(&receive.await.unwrap_err(), failure);
                        assert_service_failure(&sender.send_to(b"not-counted", &fixture.target).await.unwrap_err(), failure);
                        completion.finish(FlowOutcome::ProtocolEnd);
                        drop((sender, receiver));
                    }
                }
            }).await.unwrap();
            let records = fixture.telemetry.records(0, 2).unwrap();
            assert_eq!(records.len(), 1);
            let expected = if failure == ServiceFailure::Timeout { FlowEnd::Timeout } else { FlowEnd::Failed };
            assert_eq!(records[0].end, Some(expected));
            let packets = usize::from(!matches!(kind, Kind::Tcp)) as u64;
            let usage = Usage { upload_bytes: 3, download_bytes: 4, upload_packets: packets, download_packets: packets };
            assert_eq!(records[0].usage, usage);
            assert_eq!(fixture.telemetry.usage().unwrap().engine, usage);
            assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 0);
            assert!(!fixture.peer.cancel().is_cancelled());
            assert!(!fixture.binding.node_cancel().is_cancelled());
            assert_eq!(healthy.spawn_tracked(async { 31 }).unwrap().await.unwrap(), 31);
            if let Some(mut website) = website {
                assert_eq!(timeout(Duration::from_secs(1), website.read(&mut [0; 1])).await.unwrap().unwrap(), 0);
            } else {
                let _rebound = UdpSocket::bind(address).await.unwrap();
            }
        }
    }
    assert!(healthy.shutdown(Instant::now() + Duration::from_secs(1)).await.is_clean());
}
