use super::*;
use crate::{
    padding::Padding,
    session::{Incoming, Owner, Session},
};
use kerlico_core::NodeTask;
use std::sync::RwLock;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Point {
    Write,
    Flush,
}
#[derive(Clone, Copy, Default)]
enum Mode {
    #[default]
    Open,
    Hold {
        at: Point,
        remaining: usize,
    },
    Fail(Point),
}
#[derive(Default)]
struct PhysicalState {
    mode: Mode,
    waker: Option<Waker>,
    written: Vec<u8>,
    flushed: usize,
}
#[derive(Default)]
struct PhysicalGate {
    state: Mutex<PhysicalState>,
    entered: Notify,
    dropped: AtomicBool,
}
impl PhysicalGate {
    fn arm(&self, at: Point, remaining: usize) {
        self.state.lock().unwrap().mode = Mode::Hold { at, remaining };
    }
    fn poll(&self, at: Point, cx: &Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.state.lock().unwrap();
        match state.mode {
            Mode::Hold {
                at: blocked,
                remaining: 0,
            } if blocked == at => {
                state.waker = Some(cx.waker().clone());
                self.entered.notify_one();
                Poll::Pending
            }
            Mode::Fail(blocked) if blocked == at => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "受控物理载体失败",
            ))),
            _ => Poll::Ready(Ok(())),
        }
    }
    fn accepted(&self, at: Point, bytes: &[u8]) {
        let mut state = self.state.lock().unwrap();
        if let Mode::Hold {
            at: blocked,
            remaining,
        } = &mut state.mode
            && *blocked == at
            && *remaining != 0
        {
            *remaining -= 1;
        }
        if at == Point::Write {
            state.written.extend_from_slice(bytes);
        } else {
            state.flushed = state.written.len();
        }
    }
    fn release(&self, fail: bool) {
        let waiter = {
            let mut state = self.state.lock().unwrap();
            let Mode::Hold { at, .. } = state.mode else {
                panic!("载体尚未受控阻塞")
            };
            state.mode = if fail { Mode::Fail(at) } else { Mode::Open };
            state.waker.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
    async fn blocked(&self) {
        tokio::time::timeout(Duration::from_secs(1), self.entered.notified())
            .await
            .unwrap();
    }
    fn flushed(&self) -> Vec<u8> {
        let state = self.state.lock().unwrap();
        state.written[..state.flushed].to_vec()
    }
}
struct PhysicalFront {
    io: TcpStream,
    gate: Arc<PhysicalGate>,
}
impl Drop for PhysicalFront {
    fn drop(&mut self) {
        self.gate.dropped.store(true, Ordering::Release);
    }
}
impl AsyncRead for PhysicalFront {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, output)
    }
}
impl AsyncWrite for PhysicalFront {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.gate.poll(Point::Write, cx))?;
        let input = &input[..input.len().min(1024)];
        let n = std::task::ready!(Pin::new(&mut this.io).poll_write(cx, input))?;
        this.gate.accepted(Point::Write, &input[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.gate.poll(Point::Flush, cx))?;
        std::task::ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        this.gate.accepted(Point::Flush, &[]);
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
struct Wire {
    io: TcpStream,
    buffered: HashMap<u32, Vec<u8>>,
}
impl Wire {
    async fn frame(&mut self, command: u8, id: u32, data: Vec<u8>) {
        self.io
            .write_all(&codec::Frame::new(command, id, data).encode().unwrap())
            .await
            .unwrap();
        self.io.flush().await.unwrap();
    }
    async fn data(&mut self, id: u32, data: Vec<u8>) {
        for part in data.chunks(16384) {
            self.frame(codec::PSH, id, part.to_vec()).await;
        }
    }
    async fn read_data(&mut self, id: u32, length: usize) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if self
                    .buffered
                    .get(&id)
                    .is_some_and(|data| data.len() >= length)
                {
                    return self
                        .buffered
                        .get_mut(&id)
                        .unwrap()
                        .drain(..length)
                        .collect();
                }
                let frame = codec::Frame::read(&mut self.io).await.unwrap();
                match frame.command {
                    codec::PSH => self
                        .buffered
                        .entry(frame.id)
                        .or_default()
                        .extend(frame.data),
                    codec::FIN => assert_ne!(frame.id, id, "所需业务字节尚未完整即收到FIN"),
                    command => panic!("非预期帧 {command}"),
                }
            }
        })
        .await
        .unwrap()
    }
}
struct SessionPeer {
    wire: Wire,
    session: Arc<Session>,
    incoming: mpsc::Receiver<Incoming>,
    gate: Arc<PhysicalGate>,
    carrier_permits: Arc<tokio::sync::Semaphore>,
}
impl SessionPeer {
    async fn new(owner: NodeTasks) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let gate = Arc::new(PhysicalGate::default());
        let padding = Padding::parse(crate::padding::DEFAULT).unwrap();
        let settings = format!("v=1\npadding-md5={}", padding.md5).into_bytes();
        let (send, incoming) = mpsc::channel(8);
        let session = Session::start(
            Box::new(PhysicalFront {
                io: server,
                gate: gate.clone(),
            }),
            false,
            Arc::new(RwLock::new(padding)),
            8,
            Duration::from_secs(10),
            Some(send),
            Owner::Node(owner),
        )
        .await
        .unwrap();
        let carrier_permits = Arc::new(tokio::sync::Semaphore::new(1));
        session.assign_permit(carrier_permits.clone().acquire_owned().await.unwrap());
        let mut wire = Wire {
            io: client,
            buffered: HashMap::new(),
        };
        wire.frame(codec::SETTINGS, 0, settings).await;
        Self {
            wire,
            session,
            incoming,
            gate,
            carrier_permits,
        }
    }
    async fn open(&mut self, id: u32) -> Incoming {
        self.wire.frame(codec::SYN, id, Vec::new()).await;
        let incoming = tokio::time::timeout(Duration::from_secs(1), self.incoming.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(incoming.id, id);
        incoming
    }
    async fn close(&mut self, owner: &NodeTasks) {
        until(|| self.session.active.load(Ordering::Acquire) == 0).await;
        self.session.shutdown().await;
        assert!(
            owner
                .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
                .await
                .is_clean()
        );
        let mut remaining = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            self.wire.io.read_to_end(&mut remaining),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(self.gate.dropped.load(Ordering::Acquire));
        assert_eq!(self.carrier_permits.available_permits(), 1);
    }
}
async fn start_session(
    peer: PeerSession,
    context: InboundContext,
) -> (SessionPeer, NodeTask<Result<()>>) {
    start_session_observed(peer, context, None).await
}
async fn start_session_observed(
    peer: PeerSession,
    context: InboundContext,
    observer: Option<FeedbackObserver>,
) -> (SessionPeer, NodeTask<Result<()>>) {
    let mut carrier = SessionPeer::new(context.tasks.clone()).await;
    let incoming = carrier.open(1).await;
    let owner = context.tasks.clone();
    let running = owner
        .spawn_tracked(serve_inner(
            incoming.stream,
            peer,
            context,
            incoming.ending,
            observer,
        ))
        .unwrap();
    let mut header = vec![0];
    header.extend(codec::address(
        &Destination::new("127.0.0.1", 53).unwrap(),
        false,
    ));
    carrier.wire.data(1, header).await;
    (carrier, running)
}
fn uot_bytes(target: &Destination, payload: &[u8]) -> Vec<u8> {
    let mut bytes = codec::address(target, true);
    bytes.extend((payload.len() as u16).to_be_bytes());
    bytes.extend(payload);
    bytes
}
async fn send_request(carrier: &mut SessionPeer, target: &Destination, payload: &[u8]) {
    carrier.wire.data(1, uot_bytes(target, payload)).await;
}
async fn read_reply(carrier: &mut SessionPeer, target: &Destination, payload: &[u8]) {
    let expected = uot_bytes(target, payload);
    assert_eq!(carrier.wire.read_data(1, expected.len()).await, expected);
}
fn send_reply(control: &Control, packet: Vec<u8>) {
    control
        .replies
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .send(packet)
        .unwrap();
}
async fn joined(running: NodeTask<Result<()>>) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(1), running)
        .await
        .unwrap()
        .unwrap()
}
async fn frames(mut bytes: &[u8]) -> Vec<codec::Frame> {
    let mut output = Vec::new();
    while !bytes.is_empty() {
        output.push(codec::Frame::read(&mut bytes).await.unwrap());
    }
    output
}
fn assert_records(telemetry: &kerlico_egress::Telemetry, expected: &[FlowEnd]) {
    let records = telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), expected.len());
    for (record, expected) in records.iter().zip(expected) {
        assert_eq!(record.end, Some(*expected));
        assert_eq!(record.usage.upload_packets, 1);
        assert_eq!(record.usage.download_packets, 1);
    }
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
}
async fn failed_physical_delivery(at: Point) {
    let backend = Arc::new(Backend::default());
    let (peer, telemetry, context, permits) = fixture(backend.clone());
    let owner = context.tasks.clone();
    let (mut carrier, running) = start_session(peer, context).await;
    let targets = [
        Destination::new("127.0.0.1", 5301).unwrap(),
        Destination::new("127.0.0.1", 5302).unwrap(),
    ];
    for target in &targets {
        send_request(&mut carrier, target, b"upload").await;
    }
    until(|| telemetry.usage().unwrap().engine.upload_packets == 2).await;
    let first = backend.target(&targets[0]);
    let second = backend.target(&targets[1]);
    carrier.gate.arm(at, 0);
    send_reply(&first, b"first-reply".to_vec());
    carrier.gate.blocked().await;
    send_reply(&second, b"second-reply".to_vec());
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
    assert!(carrier.gate.flushed().is_empty());
    carrier.gate.release(true);
    assert!(joined(running).await.is_err());
    carrier.close(&owner).await;
    assert!(!first.alive.load(Ordering::Acquire));
    assert!(!second.alive.load(Ordering::Acquire));
    assert_eq!(permits.available_permits(), 8);
    assert_eq!(first.eof.load(Ordering::Acquire), 0);
    assert_eq!(second.eof.load(Ordering::Acquire), 0);
    assert_eq!(*first.uploads.lock().unwrap(), vec![b"upload".to_vec()]);
    assert_eq!(*second.uploads.lock().unwrap(), vec![b"upload".to_vec()]);
    assert_records(&telemetry, &[FlowEnd::Failed, FlowEnd::Failed]);
}
#[tokio::test]
async fn queued_replies_fail_together_after_physical_write_error() {
    failed_physical_delivery(Point::Write).await;
}
#[tokio::test]
async fn write_after_session_cancellation_terminates_and_keeps_typed_cause() {
    let owner = NodeTasks::new(
        kerlico_core::NodeId::parse("session-test").unwrap(),
        kerlico_core::CancellationToken::new(),
    );
    let mut carrier = SessionPeer::new(owner.clone()).await;
    let mut incoming = carrier.open(1).await;
    carrier
        .session
        .close_with(kerlico_core::FlowOutcome::Failed(
            kerlico_core::FlowFailure::Cancelled,
        ));
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        incoming.stream.write_all(b"after-cancel"),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(
        kerlico_core::FlowFailure::from_io_error(&error),
        kerlico_core::FlowFailure::Cancelled
    );
    drop(incoming);
    carrier.close(&owner).await;
}
#[tokio::test]
async fn queued_replies_fail_together_after_physical_flush_error() {
    failed_physical_delivery(Point::Flush).await;
}
#[tokio::test]
async fn physical_flush_confirms_reply_before_target_eof() {
    let backend = Arc::new(Backend::default());
    let (peer, telemetry, context, permits) = fixture(backend.clone());
    let owner = context.tasks.clone();
    let (mut carrier, running) = start_session(peer, context).await;
    let target = Destination::new("127.0.0.1", 5301).unwrap();
    send_request(&mut carrier, &target, b"upload").await;
    until(|| telemetry.usage().unwrap().engine.upload_packets == 1).await;
    let control = backend.target(&target);
    carrier.gate.arm(Point::Flush, 0);
    let payload = vec![0x61; 40000];
    send_reply(&control, payload.clone());
    carrier.gate.blocked().await;
    assert_eq!(control.eof.load(Ordering::Acquire), 0);
    assert!(carrier.gate.flushed().is_empty());
    assert!(telemetry.records(0, 8).unwrap()[0].end.is_none());
    carrier.gate.release(false);
    read_reply(&mut carrier, &target, &payload).await;
    until(|| telemetry.records(0, 8).unwrap()[0].end == Some(FlowEnd::Completed)).await;
    let delivered = frames(&carrier.gate.flushed()).await;
    assert!(delivered.len() >= 3);
    assert!(
        delivered
            .iter()
            .all(|frame| frame.command == codec::PSH && frame.id == 1 && frame.data.len() <= 16384)
    );
    assert_eq!(
        delivered
            .into_iter()
            .flat_map(|frame| frame.data)
            .collect::<Vec<_>>(),
        uot_bytes(&target, &payload)
    );
    assert_eq!(control.eof.load(Ordering::Acquire), 1);
    carrier.wire.frame(codec::FIN, 1, Vec::new()).await;
    joined(running).await.unwrap();
    carrier.close(&owner).await;
    assert!(!control.alive.load(Ordering::Acquire));
    assert_eq!(permits.available_permits(), 8);
    assert_records(&telemetry, &[FlowEnd::Completed]);
}
#[tokio::test]
async fn logical_flush_covers_buffered_bytes_fragments_and_repeated_flushes() {
    let owner = NodeTasks::new(
        kerlico_core::NodeId::parse("session-test").unwrap(),
        kerlico_core::CancellationToken::new(),
    );
    let mut carrier = SessionPeer::new(owner.clone()).await;
    let incoming = carrier.open(1).await;
    carrier.gate.arm(Point::Flush, 1);
    let first = vec![0x31; 60000];
    let second = vec![0x32; 1000];
    let expected_first = first.clone();
    let expected_second = second.clone();
    let (first_done, mut first_flushed) = tokio::sync::oneshot::channel();
    let (continue_send, continue_read) = tokio::sync::oneshot::channel();
    let writing = tokio::spawn(async move {
        let mut stream = incoming.stream;
        stream.write_all(&first).await.unwrap();
        stream.flush().await.unwrap();
        first_done.send(()).unwrap();
        continue_read.await.unwrap();
        stream.write_all(&second).await.unwrap();
        stream.flush().await.unwrap();
        stream
    });
    carrier.gate.blocked().await;
    assert!(matches!(
        first_flushed.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(carrier.gate.flushed().len() < expected_first.len());
    carrier.gate.release(false);
    first_flushed.await.unwrap();
    assert_eq!(
        carrier.wire.read_data(1, expected_first.len()).await,
        expected_first
    );
    carrier.gate.arm(Point::Flush, 0);
    continue_send.send(()).unwrap();
    carrier.gate.blocked().await;
    assert!(!writing.is_finished());
    carrier.gate.release(false);
    let stream = tokio::time::timeout(Duration::from_secs(1), writing)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        carrier.wire.read_data(1, expected_second.len()).await,
        expected_second
    );
    let delivered = frames(&carrier.gate.flushed()).await;
    assert!(delivered.len() >= 5);
    let expected = [expected_first, expected_second].concat();
    assert_eq!(
        delivered
            .into_iter()
            .flat_map(|frame| frame.data)
            .collect::<Vec<_>>(),
        expected
    );
    drop(stream);
    carrier.close(&owner).await;
}
#[tokio::test]
async fn blocked_downlink_keeps_sibling_uplink_and_read_waker_alive() {
    let owner = NodeTasks::new(
        kerlico_core::NodeId::parse("session-test").unwrap(),
        kerlico_core::CancellationToken::new(),
    );
    let mut carrier = SessionPeer::new(owner.clone()).await;
    let first = carrier.open(1).await;
    let second = carrier.open(2).await;
    let (mut reading, mut writing) = tokio::io::split(first.stream);
    carrier.gate.arm(Point::Flush, 0);
    let sending = tokio::spawn(async move {
        writing.write_all(b"downlink").await.unwrap();
        writing.flush().await.unwrap();
        writing
    });
    carrier.gate.blocked().await;
    let receiving = tokio::spawn(async move {
        let mut payload = [0; 6];
        reading.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"uplink");
        reading
    });
    let sibling = tokio::spawn(async move {
        let mut stream = second.stream;
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"sibling");
        stream
    });
    carrier.wire.data(1, b"uplink".to_vec()).await;
    carrier.wire.data(2, b"sibling".to_vec()).await;
    let reading = tokio::time::timeout(Duration::from_secs(1), receiving)
        .await
        .unwrap()
        .unwrap();
    let mut sibling = tokio::time::timeout(Duration::from_secs(1), sibling)
        .await
        .unwrap()
        .unwrap();
    assert!(!sending.is_finished());
    carrier.gate.release(false);
    let writing = tokio::time::timeout(Duration::from_secs(1), sending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(carrier.wire.read_data(1, 8).await, b"downlink");
    sibling.write_all(b"second").await.unwrap();
    sibling.flush().await.unwrap();
    assert_eq!(carrier.wire.read_data(2, 6).await, b"second");
    drop((reading, writing, sibling));
    carrier.close(&owner).await;
}
#[tokio::test]
async fn server_shutdown_waits_for_physical_fin_flush() {
    let owner = NodeTasks::new(
        kerlico_core::NodeId::parse("session-test").unwrap(),
        kerlico_core::CancellationToken::new(),
    );
    let mut carrier = SessionPeer::new(owner.clone()).await;
    let mut stream = carrier.open(1).await.stream;
    stream.write_all(b"before-fin").await.unwrap();
    stream.flush().await.unwrap();
    carrier.gate.arm(Point::Flush, 0);
    let shutdown = tokio::spawn(async move {
        stream.shutdown().await.unwrap();
        stream
    });
    carrier.gate.blocked().await;
    assert!(!shutdown.is_finished());
    assert!(
        frames(&carrier.gate.flushed())
            .await
            .iter()
            .all(|frame| frame.command != codec::FIN)
    );
    carrier.gate.release(false);
    let stream = tokio::time::timeout(Duration::from_secs(1), shutdown)
        .await
        .unwrap()
        .unwrap();
    let delivered = frames(&carrier.gate.flushed()).await;
    assert_eq!(delivered.last().unwrap().command, codec::FIN);
    assert_eq!(delivered.last().unwrap().id, 1);
    assert_eq!(
        delivered
            .iter()
            .filter(|frame| frame.command == codec::FIN)
            .count(),
        1
    );
    assert_eq!(
        delivered
            .into_iter()
            .filter(|frame| frame.command == codec::PSH)
            .flat_map(|frame| frame.data)
            .collect::<Vec<_>>(),
        b"before-fin"
    );
    drop(stream);
    carrier.close(&owner).await;
}
#[tokio::test]
async fn peer_fin_before_local_fin_flush_fails_shutdown() {
    let owner = NodeTasks::new(
        kerlico_core::NodeId::parse("session-test").unwrap(),
        kerlico_core::CancellationToken::new(),
    );
    let mut carrier = SessionPeer::new(owner.clone()).await;
    let incoming = carrier.open(1).await;
    let mut ending = incoming.ending;
    let mut stream = incoming.stream;
    carrier.gate.arm(Point::Flush, 0);
    let shutdown = tokio::spawn(async move { stream.shutdown().await });
    carrier.gate.blocked().await;
    assert!(!shutdown.is_finished());
    carrier.wire.frame(codec::FIN, 1, Vec::new()).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(
        crate::flow::ended(&mut ending).await,
        kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed)
    );
    assert!(carrier.gate.flushed().is_empty());
    carrier.close(&owner).await;
}
#[derive(Clone, Copy)]
enum CloseAt {
    PeerFin,
    CarrierEof,
    ParentTimeout,
}
async fn close_during_delivery(close: CloseAt) {
    let backend = Arc::new(Backend::default());
    let (peer, telemetry, context, permits) = fixture(backend.clone());
    let owner = context.tasks.clone();
    let (mut carrier, running) = start_session(peer, context).await;
    let target = Destination::new("127.0.0.1", 5301).unwrap();
    send_request(&mut carrier, &target, b"upload").await;
    until(|| telemetry.usage().unwrap().engine.upload_packets == 1).await;
    let control = backend.target(&target);
    carrier.gate.arm(Point::Flush, 0);
    send_reply(&control, b"pending".to_vec());
    carrier.gate.blocked().await;
    assert_eq!(control.eof.load(Ordering::Acquire), 0);
    match close {
        CloseAt::PeerFin => carrier.wire.frame(codec::FIN, 1, Vec::new()).await,
        CloseAt::CarrierEof => carrier.wire.io.shutdown().await.unwrap(),
        CloseAt::ParentTimeout => carrier
            .session
            .close_with(kerlico_core::FlowOutcome::Failed(
                kerlico_core::FlowFailure::Timeout,
            )),
    }
    let result = joined(running).await;
    let expected = if matches!(close, CloseAt::ParentTimeout) {
        assert!(matches!(result, Err(Error::Timeout)));
        FlowEnd::Timeout
    } else {
        assert!(result.is_err());
        FlowEnd::Failed
    };
    carrier.close(&owner).await;
    assert!(!control.alive.load(Ordering::Acquire));
    assert_eq!(control.eof.load(Ordering::Acquire), 0);
    assert_eq!(permits.available_permits(), 8);
    assert_records(&telemetry, &[expected]);
}
#[tokio::test]
async fn peer_fin_with_unflushed_reply_records_failed() {
    close_during_delivery(CloseAt::PeerFin).await;
}
#[tokio::test]
async fn carrier_eof_with_unflushed_reply_records_failed() {
    close_during_delivery(CloseAt::CarrierEof).await;
}
#[tokio::test]
async fn parent_timeout_with_unflushed_reply_preserves_timeout() {
    close_during_delivery(CloseAt::ParentTimeout).await;
}
#[tokio::test]
async fn delivered_target_stays_completed_when_later_target_write_fails() {
    let backend = Arc::new(Backend::default());
    let (peer, telemetry, context, permits) = fixture(backend.clone());
    let owner = context.tasks.clone();
    let (mut carrier, running) = start_session(peer, context).await;
    let first = Destination::new("127.0.0.1", 5301).unwrap();
    let second = Destination::new("127.0.0.1", 5302).unwrap();
    send_request(&mut carrier, &first, b"upload").await;
    send_request(&mut carrier, &second, b"upload").await;
    until(|| telemetry.usage().unwrap().engine.upload_packets == 2).await;
    send_reply(&backend.target(&first), b"delivered".to_vec());
    read_reply(&mut carrier, &first, b"delivered").await;
    until(|| telemetry.records(0, 8).unwrap()[0].end == Some(FlowEnd::Completed)).await;
    carrier.gate.arm(Point::Write, 0);
    send_reply(&backend.target(&second), b"undelivered".to_vec());
    carrier.gate.blocked().await;
    carrier.gate.release(true);
    assert!(joined(running).await.is_err());
    carrier.close(&owner).await;
    assert_eq!(permits.available_permits(), 8);
    assert_records(&telemetry, &[FlowEnd::Completed, FlowEnd::Failed]);
}

#[tokio::test]
async fn independent_target_timeout_survives_later_physical_failure() {
    let backend = Arc::new(Backend::default());
    let (peer, telemetry, context, permits) = fixture(backend.clone());
    let owner = context.tasks.clone();
    let (mut carrier, running) = start_session(peer, context).await;
    let first = Destination::new("127.0.0.1", 5301).unwrap();
    let second = Destination::new("127.0.0.1", 5302).unwrap();
    send_request(&mut carrier, &first, b"upload").await;
    send_request(&mut carrier, &second, b"upload").await;
    until(|| telemetry.usage().unwrap().engine.upload_packets == 2).await;
    let first_control = backend.target(&first);
    let second_control = backend.target(&second);
    carrier.gate.arm(Point::Write, 0);
    send_reply(&second_control, b"pending".to_vec());
    carrier.gate.blocked().await;
    first_control.timeout.store(true, Ordering::Release);
    first_control.replies.lock().unwrap().take();
    until(|| !first_control.alive.load(Ordering::Acquire)).await;
    assert!(
        telemetry
            .records(0, 8)
            .unwrap()
            .iter()
            .all(|record| record.end.is_none())
    );
    carrier.gate.release(true);
    assert!(joined(running).await.is_err());
    carrier.close(&owner).await;
    assert_eq!(permits.available_permits(), 8);
    let records = telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].end, Some(FlowEnd::Timeout));
    assert_eq!(records[0].usage.upload_packets, 1);
    assert_eq!(records[0].usage.download_packets, 0);
    assert_eq!(records[1].end, Some(FlowEnd::Failed));
    assert_eq!(records[1].usage.upload_packets, 1);
    assert_eq!(records[1].usage.download_packets, 1);
    assert!(!second_control.alive.load(Ordering::Acquire));
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
}

struct FeedbackTrace {
    input: mpsc::UnboundedReceiver<FeedbackEvent>,
    events: Vec<FeedbackEvent>,
}
impl FeedbackTrace {
    fn new() -> (FeedbackObserver, Self) {
        let (observer, input) = mpsc::unbounded_channel();
        (
            observer,
            Self {
                input,
                events: Vec::new(),
            },
        )
    }
    async fn wait_until(
        &mut self,
        deadline: tokio::time::Instant,
        ready: impl Fn(&[FeedbackEvent]) -> bool,
    ) {
        while !ready(&self.events) {
            let event = tokio::time::timeout_at(deadline, self.input.recv())
                .await
                .expect("等待真实反馈事件超时")
                .expect("目标任务尚未报告所需反馈事件");
            self.events.push(event);
        }
    }
}

#[tokio::test]
async fn full_feedback_queue_keeps_independent_timeouts_before_physical_failure() {
    let backend = Arc::new(Backend::default());
    let idle = Duration::from_secs(4);
    let (peer, telemetry, context, permits) = fixture_with_limits(backend.clone(), 17, idle);
    let owner = context.tasks.clone();
    let (observer, mut trace) = FeedbackTrace::new();
    let (mut carrier, running) = start_session_observed(peer, context, Some(observer)).await;
    let targets: Vec<_> = (5301..5318)
        .map(|port| Destination::new("127.0.0.1", port).unwrap())
        .collect();
    for target in &targets {
        send_request(&mut carrier, target, b"upload").await;
    }
    until(|| telemetry.usage().unwrap().engine.upload_packets == 17).await;
    let controls: Vec<_> = targets
        .iter()
        .map(|target| backend.target(target))
        .collect();
    let upload_gate = Arc::new(Gate::default());
    *controls[0].upload_gate.lock().unwrap() = Some(upload_gate.clone());
    send_request(&mut carrier, &targets[0], b"held-upload").await;
    tokio::time::timeout(Duration::from_secs(1), upload_gate.entered.notified())
        .await
        .unwrap();
    let held_at = tokio::time::Instant::now();
    carrier.gate.arm(Point::Write, 0);
    for control in &controls {
        send_reply(control, b"pending".to_vec());
    }
    trace
        .wait_until(held_at + Duration::from_secs(1), |events| {
            events
                .iter()
                .filter(|event| matches!(event, FeedbackEvent::PacketQueued { .. }))
                .count()
                == 17
        })
        .await;
    for target in &targets {
        assert_eq!(
            trace
                .events
                .iter()
                .filter(|event| matches!(event, FeedbackEvent::PacketQueued { key, .. } if key == target))
                .count(),
            1
        );
    }
    assert!(matches!(
        trace.events.last(),
        Some(FeedbackEvent::PacketQueued { remaining: 15, .. })
    ));
    let queued_at = tokio::time::Instant::now();
    let release_at = queued_at + idle / 2;
    assert!(release_at < held_at + idle);
    tokio::time::sleep_until(release_at).await;
    assert!(!running.is_finished());
    upload_gate.release();
    carrier.gate.blocked().await;
    trace
        .wait_until(queued_at + idle + Duration::from_secs(1), |events| {
            let ended = events
                .iter()
                .filter(|event| matches!(event, FeedbackEvent::EndObserved { accepted: true, .. }))
                .count();
            let queued = events
                .iter()
                .filter(|event| matches!(event, FeedbackEvent::EndQueued { .. }))
                .count();
            let blocked = events
                .iter()
                .filter(|event| matches!(event, FeedbackEvent::EndBlocked { .. }))
                .count();
            ended == 17 && queued == 16 && blocked == 1
        })
        .await;
    for target in &targets {
        assert_eq!(
            trace
                .events
                .iter()
                .filter(|event| matches!(event, FeedbackEvent::EndObserved {
                    key,
                    reason: kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Timeout),
                    accepted: true,
                } if key == target))
                .count(),
            1
        );
        assert_eq!(
            trace
                .events
                .iter()
                .filter(|event| match event {
                    FeedbackEvent::EndQueued { key }
                    | FeedbackEvent::EndBlocked { key, remaining: 0 } => key == target,
                    _ => false,
                })
                .count(),
            1
        );
    }
    assert!(!running.is_finished());
    assert!(carrier.gate.flushed().is_empty());
    assert_eq!(
        controls
            .iter()
            .filter(|control| control.alive.load(Ordering::Acquire))
            .count(),
        1
    );
    let pending_records = telemetry.records(0, 32).unwrap();
    assert_eq!(pending_records.len(), 17);
    assert!(pending_records.iter().all(|record| record.end.is_none()));
    carrier.gate.release(true);
    let error = joined(running).await.unwrap_err();
    assert_eq!(
        kerlico_core::FlowFailure::from_error(&error),
        kerlico_core::FlowFailure::Failed
    );
    carrier.close(&owner).await;
    assert_eq!(permits.available_permits(), 17);
    let records = telemetry.records(0, 32).unwrap();
    assert_eq!(records.len(), 17);
    for (index, ((record, target), control)) in
        records.iter().zip(&targets).zip(&controls).enumerate()
    {
        assert_eq!(record.original.as_ref().unwrap().target(), target);
        assert_eq!(record.end, Some(FlowEnd::Timeout));
        assert_eq!(record.usage.download_packets, 1);
        assert_eq!(record.usage.download_bytes, 7);
        let expected = if index == 0 {
            vec![b"upload".to_vec(), b"held-upload".to_vec()]
        } else {
            vec![b"upload".to_vec()]
        };
        assert_eq!(record.usage.upload_packets, expected.len() as u64);
        assert_eq!(
            record.usage.upload_bytes,
            expected
                .iter()
                .map(|packet| packet.len() as u64)
                .sum::<u64>()
        );
        assert_eq!(*control.uploads.lock().unwrap(), expected);
        assert!(!control.alive.load(Ordering::Acquire));
        assert_eq!(control.eof.load(Ordering::Acquire), 0);
    }
    let usage = telemetry.usage().unwrap();
    assert_eq!(usage.engine.upload_packets, 18);
    assert_eq!(usage.engine.download_packets, 17);
    assert_eq!(usage.engine.upload_bytes, 113);
    assert_eq!(usage.engine.download_bytes, 119);
    assert_eq!(usage.active_flows, 0);
}

#[tokio::test]
async fn parent_physical_failure_precedes_target_cleanup_cancellation() {
    let backend = Arc::new(Backend::default());
    let (peer, telemetry, context, permits) = fixture(backend.clone());
    let owner = context.tasks.clone();
    let (observer, mut trace) = FeedbackTrace::new();
    let (mut carrier, running) = start_session_observed(peer, context, Some(observer)).await;
    let first = Destination::new("127.0.0.1", 5301).unwrap();
    let second = Destination::new("127.0.0.1", 5302).unwrap();
    send_request(&mut carrier, &first, b"upload").await;
    send_request(&mut carrier, &second, b"upload").await;
    until(|| telemetry.usage().unwrap().engine.upload_packets == 2).await;
    let first_control = backend.target(&first);
    let second_control = backend.target(&second);
    carrier.gate.arm(Point::Write, 0);
    send_reply(&first_control, b"pending".to_vec());
    carrier.gate.blocked().await;
    carrier.gate.release(true);
    let error = joined(running).await.unwrap_err();
    assert_eq!(
        kerlico_core::FlowFailure::from_error(&error),
        kerlico_core::FlowFailure::Failed
    );
    trace
        .wait_until(
            tokio::time::Instant::now() + Duration::from_secs(1),
            |events| {
                events.iter().any(|event| {
                    matches!(event, FeedbackEvent::EndObserved {
                key,
                reason: kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Cancelled),
                accepted: false,
            } if key == &second)
                })
            },
        )
        .await;
    carrier.close(&owner).await;
    assert_eq!(permits.available_permits(), 8);
    assert!(!first_control.alive.load(Ordering::Acquire));
    assert!(!second_control.alive.load(Ordering::Acquire));
    assert_eq!(first_control.eof.load(Ordering::Acquire), 0);
    assert_eq!(second_control.eof.load(Ordering::Acquire), 0);
    let records = telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].original.as_ref().unwrap().target(), &first);
    assert_eq!(records[1].original.as_ref().unwrap().target(), &second);
    assert!(
        records
            .iter()
            .all(|record| record.end == Some(FlowEnd::Failed))
    );
    assert!(
        records
            .iter()
            .all(|record| record.usage.upload_packets == 1)
    );
    assert_eq!(records[0].usage.download_packets, 1);
    assert_eq!(records[1].usage.download_packets, 0);
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
}
