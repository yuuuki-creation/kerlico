use super::*;
use kerlico_core::{Capabilities, NodeTasks, OpenedTcp, Outbound, StreamBudget, TargetPolicy};
use kerlico_egress::FlowEnd;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

struct Observer;
impl kerlico_core::NodeObserver for Observer {
    fn record(&self, _: kerlico_core::NodeEvent) {}
}
struct Control {
    replies: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    uploads: Mutex<Vec<Vec<u8>>>,
    received: AtomicUsize,
    eof: AtomicUsize,
    alive: AtomicBool,
}
struct TargetSender(Arc<Control>);
struct TargetReceiver {
    control: Arc<Control>,
    input: mpsc::UnboundedReceiver<Vec<u8>>,
}
impl Drop for TargetReceiver {
    fn drop(&mut self) {
        self.control.alive.store(false, Ordering::Release);
    }
}
impl DatagramSender for TargetSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0.uploads.lock().unwrap().push(packet.to_vec());
            Ok(())
        })
    }
}
impl DatagramReceiver for TargetReceiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let packet = self.input.recv().await;
            if packet.is_some() {
                self.control.received.fetch_add(1, Ordering::AcqRel);
            } else {
                self.control.eof.fetch_add(1, Ordering::AcqRel);
            }
            Ok(packet)
        })
    }
}
#[derive(Default)]
struct Backend(Mutex<HashMap<Destination, Arc<Control>>>);
impl Backend {
    fn target(&self, target: &Destination) -> Arc<Control> {
        self.0.lock().unwrap()[target].clone()
    }
}
impl Outbound for Backend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: false,
            tcp_eof: false,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async { Err(Error::Unsupported("回包交付回归只使用UDP")) })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let (replies, input) = mpsc::unbounded_channel();
            let control = Arc::new(Control {
                replies: Mutex::new(Some(replies)),
                uploads: Mutex::new(Vec::new()),
                received: AtomicUsize::new(0),
                eof: AtomicUsize::new(0),
                alive: AtomicBool::new(true),
            });
            self.0
                .lock()
                .unwrap()
                .insert(target.clone(), control.clone());
            Ok(DatagramChannel {
                sender: Box::new(TargetSender(control.clone())),
                receiver: Box::new(TargetReceiver { control, input }),
            })
        })
    }
}
fn fixture(
    backend: Arc<Backend>,
) -> (
    PeerSession,
    kerlico_egress::Telemetry,
    InboundContext,
    Arc<tokio::sync::Semaphore>,
) {
    let input = kerlico_config::NodeBuildContext::local_for_test(serde_json::json!({}));
    struct NoDns;
    impl kerlico_egress::Resolver for NoDns {
        fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
            Box::pin(async { panic!("字面UDP目标不应解析") })
        }
    }
    let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
        &input,
        backend,
        TargetPolicy::Remote,
        kerlico_core::FamilyMode::DualV4Preferred,
        Arc::new(NoDns),
    )
    .unwrap();
    let cancel = kerlico_core::CancellationToken::new();
    let permits = Arc::new(tokio::sync::Semaphore::new(8));
    let context = InboundContext {
        peer_lease: None,
        tasks: NodeTasks::new(input.issuer().node().clone(), cancel.clone()),
        cancel,
        peer_addr: None,
        local_addr: None,
        connect_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 8,
        events: Arc::new(Observer),
        stream_budget: StreamBudget::new(permits.clone(), Arc::new(tokio::sync::Semaphore::new(8))),
    };
    (
        ingress.local(&context).unwrap(),
        telemetry,
        context,
        permits,
    )
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockAt {
    Write,
    Flush,
    Never,
}
#[derive(Default)]
struct GateState {
    released: bool,
    waker: Option<Waker>,
}
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    entered: Notify,
    dropped: AtomicBool,
}
impl Gate {
    fn blocked(&self, cx: &Context<'_>) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.released {
            return false;
        }
        state.waker = Some(cx.waker().clone());
        self.entered.notify_one();
        true
    }
    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.released = true;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}
struct Front {
    io: TcpStream,
    gate: Arc<Gate>,
    at: BlockAt,
}
impl Drop for Front {
    fn drop(&mut self) {
        self.gate.dropped.store(true, Ordering::Release);
    }
}
impl AsyncRead for Front {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, output)
    }
}
impl AsyncWrite for Front {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.at == BlockAt::Write {
            if this.gate.blocked(cx) {
                return Poll::Pending;
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "受控前端写失败",
            )));
        }
        Pin::new(&mut this.io).poll_write(cx, input)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.at == BlockAt::Flush {
            if this.gate.blocked(cx) {
                return Poll::Pending;
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "受控前端flush失败",
            )));
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
async fn sockets(gate: Arc<Gate>, at: BlockAt) -> (TcpStream, BoxStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (
        client,
        Box::new(Front {
            io: server,
            gate,
            at,
        }),
    )
}
async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
type Ending = tokio::sync::watch::Sender<Option<kerlico_core::FlowOutcome>>;
type Client = TcpStream;
async fn start(
    peer: PeerSession,
    context: InboundContext,
    gate: Arc<Gate>,
    at: BlockAt,
) -> (Client, tokio::task::JoinHandle<Result<()>>, Option<Ending>) {
    let (client, server) = sockets(gate, at).await;
    (client, tokio::spawn(serve(server, peer, context)), None)
}
async fn request(client: &mut Client, target: &Destination, payload: &[u8]) {
    codec::write_packet(client, target, payload, 65535)
        .await
        .unwrap();
}
async fn reply(client: &mut Client) -> (Destination, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(1), codec::packet(client, 65535))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
async fn stop(client: &mut Client) {
    client.shutdown().await.unwrap();
}
async fn closed(client: &mut Client) {
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut bytes))
        .await
        .unwrap();
}
async fn failed_delivery(at: BlockAt) {
    let backend = Arc::new(Backend::default());
    let (peer, telemetry, context, permits) = fixture(backend.clone());
    let owner = context.tasks.clone();
    let gate = Arc::new(Gate::default());
    let (mut client, running, _ending) = start(peer, context, gate.clone(), at).await;
    let targets = [
        Destination::new("127.0.0.1", 5301).unwrap(),
        Destination::new("127.0.0.1", 5302).unwrap(),
    ];
    for target in &targets {
        request(&mut client, target, b"upload").await;
    }
    until(|| telemetry.usage().unwrap().engine.upload_packets == 2).await;
    let first = backend.target(&targets[0]);
    let second = backend.target(&targets[1]);
    first
        .replies
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .send(b"first-reply".to_vec())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), gate.entered.notified())
        .await
        .unwrap();
    second
        .replies
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .send(b"second-reply".to_vec())
        .unwrap();
    until(|| second.received.load(Ordering::Acquire) == 1).await;
    assert_eq!(first.eof.load(Ordering::Acquire), 0);
    assert_eq!(second.eof.load(Ordering::Acquire), 0);
    assert!(
        telemetry
            .records(0, 8)
            .unwrap()
            .iter()
            .all(|record| record.end.is_none())
    );
    gate.release();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), running)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Io(_))
    ));
    assert!(
        owner
            .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .is_clean()
    );
    closed(&mut client).await;
    assert!(gate.dropped.load(Ordering::Acquire));
    assert!(!first.alive.load(Ordering::Acquire));
    assert!(!second.alive.load(Ordering::Acquire));
    assert_eq!(permits.available_permits(), 8);
    assert_eq!(first.eof.load(Ordering::Acquire), 0);
    assert_eq!(second.eof.load(Ordering::Acquire), 0);
    assert_eq!(*first.uploads.lock().unwrap(), vec![b"upload".to_vec()]);
    assert_eq!(*second.uploads.lock().unwrap(), vec![b"upload".to_vec()]);
    let records = telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.end == Some(FlowEnd::Failed)
                && record.usage.upload_packets == 1
                && record.usage.download_packets == 1)
    );
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
}
#[tokio::test]
async fn queued_replies_fail_together_after_frontend_write_error() {
    failed_delivery(BlockAt::Write).await;
}
#[tokio::test]
async fn queued_replies_fail_together_after_frontend_flush_error() {
    failed_delivery(BlockAt::Flush).await;
}
#[tokio::test]
async fn successful_downlink_is_confirmed_before_target_eof() {
    let backend = Arc::new(Backend::default());
    let (peer, telemetry, context, permits) = fixture(backend.clone());
    let owner = context.tasks.clone();
    let gate = Arc::new(Gate::default());
    let (mut client, running, _ending) = start(peer, context, gate.clone(), BlockAt::Never).await;
    let target = Destination::new("127.0.0.1", 5301).unwrap();
    request(&mut client, &target, b"upload").await;
    until(|| telemetry.usage().unwrap().engine.upload_packets == 1).await;
    let control = backend.target(&target);
    control
        .replies
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .send(b"delivered".to_vec())
        .unwrap();
    assert_eq!(reply(&mut client).await, (target, b"delivered".to_vec()));
    until(|| telemetry.records(0, 8).unwrap()[0].end == Some(FlowEnd::Completed)).await;
    assert_eq!(control.eof.load(Ordering::Acquire), 1);
    stop(&mut client).await;
    tokio::time::timeout(Duration::from_secs(1), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        owner
            .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .is_clean()
    );
    assert!(!control.alive.load(Ordering::Acquire));
    assert!(gate.dropped.load(Ordering::Acquire));
    assert_eq!(permits.available_permits(), 8);
    let record = telemetry.records(0, 8).unwrap().pop().unwrap();
    assert_eq!(record.end, Some(FlowEnd::Completed));
    assert_eq!(record.usage.upload_packets, 1);
    assert_eq!(record.usage.download_packets, 1);
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
}
