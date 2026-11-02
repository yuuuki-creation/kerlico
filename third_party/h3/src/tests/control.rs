use std::{
    collections::VecDeque,
    future::{poll_fn, Future},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use assert_matches::assert_matches;
use bytes::{Buf, Bytes, BytesMut};
use http::{Request, Response};
use tokio::sync::oneshot;

use crate::{
    error::{Code, ConnectionError, LocalError},
    frame::FrameStream,
    proto::{
        coding::Encode,
        frame::{Frame, Settings},
        headers::Header,
        push::PushId,
        stream::StreamType,
        varint::VarInt,
    },
    qpack,
    quic::{self, ConnectionErrorIncoming, RecvStream, SendStream, StreamErrorIncoming, StreamId},
    server,
    stream::{AcceptRecvStream, AcceptedRecvStream, WriteBuf},
};

#[derive(Default)]
struct Wire {
    chunks: VecDeque<Bytes>,
    repeat: Option<Bytes>,
    transcript: Vec<u8>,
    finished: bool,
    reader: Option<Waker>,
    observed: Option<oneshot::Sender<()>>,
    waiting: Option<oneshot::Sender<()>>,
}

struct Receive {
    id: StreamId,
    wire: Arc<Mutex<Wire>>,
}

impl RecvStream for Receive {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let mut wire = self.wire.lock().unwrap();
        let data = wire.chunks.pop_front().or_else(|| wire.repeat.clone());
        if let Some(data) = data {
            if let Some(observed) = wire.observed.take() {
                observed.send(()).unwrap();
            }
            return Poll::Ready(Ok(Some(data)));
        }
        if wire.finished {
            return Poll::Ready(Ok(None));
        }
        wire.reader = Some(cx.waker().clone());
        if let Some(waiting) = wire.waiting.take() {
            waiting.send(()).unwrap();
        }
        Poll::Pending
    }

    fn stop_sending(&mut self, _error_code: u64) {}

    fn recv_id(&self) -> StreamId {
        self.id
    }
}

struct Window {
    paused: bool,
    remaining: usize,
    error: Option<u64>,
    writer: Option<Waker>,
    blocked: Option<oneshot::Sender<()>>,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            paused: false,
            remaining: usize::MAX,
            error: None,
            writer: None,
            blocked: None,
        }
    }
}

struct Send {
    id: StreamId,
    wire: Arc<Mutex<Wire>>,
    window: Arc<Mutex<Window>>,
    writing: Option<WriteBuf<Bytes>>,
}

impl SendStream<Bytes> for Send {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        let mut window = self.window.lock().unwrap();
        if let Some(error_code) = window.error {
            return Poll::Ready(Err(StreamErrorIncoming::StreamTerminated { error_code }));
        }
        if !window.paused {
            if let Some(data) = self.writing.as_mut() {
                let mut wire = self.wire.lock().unwrap();
                while data.has_remaining() && window.remaining > 0 {
                    let count = data.chunk().len().min(window.remaining);
                    let bytes = Bytes::copy_from_slice(&data.chunk()[..count]);
                    data.advance(count);
                    window.remaining -= count;
                    wire.transcript.extend_from_slice(&bytes);
                    wire.chunks.push_back(bytes);
                }
                if let Some(reader) = wire.reader.take() {
                    reader.wake();
                }
                if !data.has_remaining() {
                    self.writing = None;
                }
            }
            if self.writing.is_none() {
                return Poll::Ready(Ok(()));
            }
        }
        window.writer = Some(cx.waker().clone());
        if let Some(blocked) = window.blocked.take() {
            blocked.send(()).unwrap();
        }
        Poll::Pending
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        assert!(self.writing.is_none(), "已有半写帧不能被覆盖");
        assert!(!self.window.lock().unwrap().paused, "发送前须等待窗口就绪");
        self.writing = Some(data.into());
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        std::task::ready!(self.poll_ready(cx))?;
        let mut wire = self.wire.lock().unwrap();
        wire.finished = true;
        if let Some(reader) = wire.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(()))
    }

    fn reset(&mut self, _reset_code: u64) {}

    fn send_id(&self) -> StreamId {
        self.id
    }
}

struct Bidi {
    send: Send,
    recv: Receive,
}

impl SendStream<Bytes> for Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl RecvStream for Bidi {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

#[derive(Default)]
struct OpenGate {
    paused: bool,
    waiter: Option<Waker>,
    blocked: Option<oneshot::Sender<()>>,
    opened: Vec<u64>,
}

#[derive(Clone, Default)]
struct Grease {
    wire: Arc<Mutex<Wire>>,
    window: Arc<Mutex<Window>>,
    open: Arc<Mutex<OpenGate>>,
}

#[derive(Clone)]
struct Opener {
    next_send: Arc<AtomicU64>,
    control: Arc<Mutex<Wire>>,
    window: Arc<Mutex<Window>>,
    closed: Arc<Mutex<Option<Code>>>,
    grease: Grease,
}

impl quic::OpenStreams<Bytes> for Opener {
    type BidiStream = Bidi;
    type SendStream = Send;

    fn poll_open_bidi(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        Poll::Pending
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Send, StreamErrorIncoming>> {
        if self.next_send.load(Ordering::Relaxed) >= 15 {
            let mut gate = self.grease.open.lock().unwrap();
            if gate.paused {
                gate.waiter = Some(cx.waker().clone());
                if let Some(blocked) = gate.blocked.take() {
                    blocked.send(()).unwrap();
                }
                return Poll::Pending;
            }
        }
        let id = self.next_send.fetch_add(4, Ordering::Relaxed);
        let (wire, window) = if id == 3 {
            (self.control.clone(), self.window.clone())
        } else if id >= 15 {
            self.grease.open.lock().unwrap().opened.push(id);
            (self.grease.wire.clone(), self.grease.window.clone())
        } else {
            (Arc::default(), Arc::default())
        };
        Poll::Ready(Ok(Send {
            id: id.try_into().unwrap(),
            wire,
            window,
            writing: None,
        }))
    }

    fn close(&mut self, code: Code, _reason: &[u8]) {
        *self.closed.lock().unwrap() = Some(code);
    }
}

struct Transport {
    opener: Opener,
    control: Option<Receive>,
    requests: VecDeque<Bidi>,
}

impl quic::OpenStreams<Bytes> for Transport {
    type BidiStream = Bidi;
    type SendStream = Send;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        self.opener.poll_open_bidi(cx)
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Send, StreamErrorIncoming>> {
        self.opener.poll_open_send(cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.opener.close(code, reason);
    }
}

impl quic::Connection<Bytes> for Transport {
    type RecvStream = Receive;
    type OpenStreams = Opener;

    fn poll_accept_recv(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Receive, ConnectionErrorIncoming>> {
        self.control
            .take()
            .map_or(Poll::Pending, |s| Poll::Ready(Ok(s)))
    }

    fn poll_accept_bidi(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Bidi, ConnectionErrorIncoming>> {
        self.requests
            .pop_front()
            .map_or(Poll::Pending, |s| Poll::Ready(Ok(s)))
    }

    fn opener(&self) -> Opener {
        self.opener.clone()
    }
}

struct Peer {
    sent_control: Arc<Mutex<Wire>>,
    received_control: Arc<Mutex<Wire>>,
    window: Arc<Mutex<Window>>,
    closed: Arc<Mutex<Option<Code>>>,
    grease: Grease,
}

impl Peer {
    fn limit_send(&self, paused: bool, remaining: usize) -> oneshot::Receiver<()> {
        limit_window(&self.window, paused, remaining)
    }

    fn resume_send(&self) {
        resume_window(&self.window);
    }

    fn observe_read(&self) -> oneshot::Receiver<()> {
        let (observed, receiver) = oneshot::channel();
        self.sent_control.lock().unwrap().observed = Some(observed);
        receiver
    }

    fn append_control(&self, data: Bytes) {
        let mut wire = self.sent_control.lock().unwrap();
        wire.chunks.push_back(data);
        if let Some(reader) = wire.reader.take() {
            reader.wake();
        }
    }

    fn coalesce_control(&self) {
        let mut wire = self.sent_control.lock().unwrap();
        let mut data = BytesMut::new();
        for chunk in wire.chunks.drain(..) {
            data.extend_from_slice(&chunk);
        }
        wire.chunks.push_back(data.freeze());
    }

    fn observe_input_wait(&self) -> oneshot::Receiver<()> {
        let (waiting, receiver) = oneshot::channel();
        self.sent_control.lock().unwrap().waiting = Some(waiting);
        receiver
    }

    fn output(&self) -> Vec<u8> {
        self.received_control.lock().unwrap().transcript.clone()
    }

    async fn control_reader(&self) -> FrameStream<Receive, Bytes> {
        let mut stream = AcceptRecvStream::new(Receive {
            id: 3u64.try_into().unwrap(),
            wire: self.received_control.clone(),
        });
        assert!(poll_fn(|cx| stream.poll_type(cx)).await.is_ok());
        let AcceptedRecvStream::Control(mut control) = stream.into_stream() else {
            panic!("服务端必须先创建控制流");
        };
        assert_matches!(
            poll_fn(|cx| control.poll_next(cx)).await.unwrap(),
            Some(Frame::Settings(_))
        );
        control
    }
}

fn limit_window(window: &Mutex<Window>, paused: bool, remaining: usize) -> oneshot::Receiver<()> {
    let (blocked, receiver) = oneshot::channel();
    let mut window = window.lock().unwrap();
    window.paused = paused;
    window.remaining = remaining;
    window.blocked = Some(blocked);
    receiver
}

fn resume_window(window: &Mutex<Window>) {
    let mut window = window.lock().unwrap();
    window.paused = false;
    window.remaining = usize::MAX;
    if let Some(writer) = window.writer.take() {
        writer.wake();
    }
}

impl Grease {
    fn pause_open(&self) -> oneshot::Receiver<()> {
        let (blocked, receiver) = oneshot::channel();
        let mut gate = self.open.lock().unwrap();
        gate.paused = true;
        gate.blocked = Some(blocked);
        receiver
    }

    fn resume_open(&self) {
        let mut gate = self.open.lock().unwrap();
        gate.paused = false;
        if let Some(waiter) = gate.waiter.take() {
            waiter.wake();
        }
    }

    async fn receive(&self) -> Bytes {
        let mut stream = Receive {
            id: 15u64.try_into().unwrap(),
            wire: self.wire.clone(),
        };
        let mut data = BytesMut::new();
        while let Some(chunk) = poll_fn(|cx| stream.poll_data(cx)).await.unwrap() {
            data.extend_from_slice(&chunk);
        }
        data.freeze()
    }
}

fn encoded(mut frame: Frame<Bytes>) -> Bytes {
    let mut bytes = BytesMut::new();
    frame.encode_with_payload(&mut bytes);
    bytes.freeze()
}

fn request(id: u64) -> Bidi {
    let (parts, ()) = Request::post("https://localhost/progress")
        .body(())
        .unwrap()
        .into_parts();
    let headers =
        Header::request(parts.method, parts.uri, parts.headers, parts.extensions).unwrap();
    let mut block = BytesMut::new();
    qpack::encode_stateless(&mut block, headers).unwrap();
    let input = Wire {
        chunks: VecDeque::from([
            encoded(Frame::Headers(block.freeze())),
            encoded(Frame::Data(Bytes::from_static(b"still-active"))),
        ]),
        ..Wire::default()
    };
    Bidi {
        send: Send {
            id: id.try_into().unwrap(),
            wire: Arc::default(),
            window: Arc::default(),
            writing: None,
        },
        recv: Receive {
            id: id.try_into().unwrap(),
            wire: Arc::new(Mutex::new(input)),
        },
    }
}

async fn setup(
    frames: Vec<Bytes>,
    repeat: Option<Bytes>,
    requests: Vec<Bidi>,
) -> (server::Connection<Transport, Bytes>, Peer) {
    setup_with_grease(frames, repeat, requests, false).await
}

async fn setup_with_grease(
    frames: Vec<Bytes>,
    repeat: Option<Bytes>,
    requests: Vec<Bidi>,
    send_grease: bool,
) -> (server::Connection<Transport, Bytes>, Peer) {
    let mut initial = BytesMut::new();
    StreamType::CONTROL.encode(&mut initial);
    Frame::<Bytes>::Settings(Settings::default()).encode(&mut initial);
    let mut chunks = VecDeque::from([initial.freeze()]);
    chunks.extend(frames);
    let sent_control = Arc::new(Mutex::new(Wire {
        chunks,
        repeat,
        ..Wire::default()
    }));
    let received_control: Arc<Mutex<Wire>> = Arc::default();
    let window: Arc<Mutex<Window>> = Arc::default();
    let closed: Arc<Mutex<Option<Code>>> = Arc::default();
    let grease = Grease::default();
    let opener = Opener {
        next_send: Arc::new(AtomicU64::new(3)),
        control: received_control.clone(),
        window: window.clone(),
        closed: closed.clone(),
        grease: grease.clone(),
    };
    let transport = Transport {
        opener,
        control: Some(Receive {
            id: 2u64.try_into().unwrap(),
            wire: sent_control.clone(),
        }),
        requests: requests.into(),
    };
    let connection = server::builder()
        .send_grease(send_grease)
        .build(transport)
        .await
        .unwrap();
    (
        connection,
        Peer {
            sent_control,
            received_control,
            window,
            closed,
            grease,
        },
    )
}

async fn cancel_when_blocked<F: Future>(future: F, blocked: oneshot::Receiver<()>) {
    let completion = tokio::spawn(async move { blocked.await.unwrap() });
    tokio::pin!(future);
    tokio::select! { biased;
        _ = &mut future => panic!("受控发送窗口尚未恢复，操作不能完成"),
        result = completion => result.unwrap(),
    }
}

async fn expect_goaway(control: &mut FrameStream<Receive, Bytes>, id: u64) {
    assert_matches!(
        poll_fn(|cx| control.poll_next(cx)).await.unwrap(),
        Some(Frame::Goaway(actual)) if actual.into_inner() == id
    );
}

async fn assert_flood_progress(frames: Vec<Bytes>, repeat: Bytes, timed: bool) {
    let (mut server, peer) = setup(frames, Some(repeat), vec![request(0)]).await;
    let resolver = server.accept().await.unwrap().unwrap();
    let (request, mut active) = resolver.resolve_request().await.unwrap();
    assert_eq!(request.uri().path(), "/progress");
    active.send_response(Response::new(())).await.unwrap();
    let observed = peer.observe_read();
    let cancellation = tokio::spawn(async move {
        observed.await.unwrap();
        if timed {
            tokio::time::sleep_until(tokio::time::Instant::now() + Duration::from_millis(1)).await;
        } else {
            tokio::task::yield_now().await;
        }
    });
    {
        let accept = server.accept();
        tokio::pin!(accept);
        tokio::select! { biased;
            _ = &mut accept => panic!("既有请求仍存活，接纳驱动不能结束"),
            result = cancellation => result.unwrap(),
        }
    }
    let mut data = active.recv_data().await.unwrap().unwrap();
    assert_eq!(
        data.copy_to_bytes(data.remaining()),
        Bytes::from_static(b"still-active")
    );
    active.finish().await.unwrap();
    assert!(peer.closed.lock().unwrap().is_none());
}

#[tokio::test]
async fn continuously_ready_control_keeps_accept_cancellation_and_timer_live() {
    tokio::time::timeout(Duration::from_secs(2), async {
        for frame in [
            encoded(Frame::Goaway(VarInt::from_u32(0))),
            encoded(Frame::MaxPushId(PushId(0))),
            Bytes::from_static(&[0x21, 0]),
            Bytes::from([0x21, 0].repeat(256)),
        ] {
            for timed in [false, true] {
                assert_flood_progress(Vec::new(), frame.clone(), timed).await;
            }
        }
        assert_flood_progress(
            vec![encoded(Frame::Goaway(VarInt::from_u32(1)))],
            encoded(Frame::Goaway(VarInt::from_u32(0))),
            false,
        )
        .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn continuously_ready_partial_unknown_frame_yields_without_losing_progress() {
    let mut header = BytesMut::new();
    VarInt::from_u32(0x21).encode(&mut header);
    VarInt::from_u32(65536).encode(&mut header);
    tokio::time::timeout(Duration::from_secs(2), async {
        assert_flood_progress(vec![header.freeze()], Bytes::from_static(&[0]), false).await;
        let mut unknown = BytesMut::new();
        VarInt::from_u32(0x21).encode(&mut unknown);
        VarInt::from_u32(256).encode(&mut unknown);
        unknown.extend_from_slice(&[0; 256]);
        let mut frames: Vec<_> = unknown
            .iter()
            .map(|byte| Bytes::copy_from_slice(&[*byte]))
            .collect();
        frames.push(encoded(Frame::Goaway(VarInt::from_u32(0))));
        let (mut server, peer) = setup(frames, None, Vec::new()).await;
        let mut control = peer.control_reader().await;
        assert!(server.accept().await.unwrap().is_none());
        expect_goaway(&mut control, 0).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_accept_resumes_goaway_before_submission() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (mut server, peer) = setup(
            vec![encoded(Frame::Goaway(VarInt::from_u32(0)))],
            None,
            Vec::new(),
        )
        .await;
        let mut control = peer.control_reader().await;
        let initial = peer.output();
        let blocked = peer.limit_send(true, usize::MAX);
        cancel_when_blocked(server.accept(), blocked).await;
        assert_eq!(peer.output(), initial);
        peer.resume_send();
        assert!(server.accept().await.unwrap().is_none());
        expect_goaway(&mut control, 0).await;
        server.shutdown(0).await.unwrap();
        assert_eq!(
            &peer.output()[initial.len()..],
            encoded(Frame::Goaway(VarInt::from_u32(0))).as_ref()
        );
        assert!(!peer.received_control.lock().unwrap().finished);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_accept_resumes_partial_goaway_without_repeating_header() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (mut server, peer) = setup(
            vec![encoded(Frame::Goaway(VarInt::from_u32(0)))],
            None,
            Vec::new(),
        )
        .await;
        let mut control = peer.control_reader().await;
        let initial = peer.output();
        let blocked = peer.limit_send(false, 1);
        cancel_when_blocked(server.accept(), blocked).await;
        assert_eq!(&peer.output()[initial.len()..], &[0x7]);
        let blocked = peer.limit_send(false, 0);
        cancel_when_blocked(server.shutdown(0), blocked).await;
        peer.resume_send();
        assert!(server.accept().await.unwrap().is_none());
        expect_goaway(&mut control, 0).await;
        server.shutdown(0).await.unwrap();
        server.shutdown(10).await.unwrap();
        assert_eq!(
            &peer.output()[initial.len()..],
            encoded(Frame::Goaway(VarInt::from_u32(0))).as_ref()
        );
        assert!(!peer.received_control.lock().unwrap().finished);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn decreasing_shutdown_replaces_only_an_unsubmitted_goaway() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (mut server, peer) = setup(Vec::new(), None, vec![request(0)]).await;
        let active = server.accept().await.unwrap().unwrap();
        let mut control = peer.control_reader().await;
        let initial = peer.output();
        let blocked = peer.limit_send(true, usize::MAX);
        cancel_when_blocked(server.shutdown(8), blocked).await;
        let blocked = peer.limit_send(true, usize::MAX);
        cancel_when_blocked(server.shutdown(0), blocked).await;
        assert_eq!(peer.output(), initial);
        peer.resume_send();
        server.shutdown(8).await.unwrap();
        expect_goaway(&mut control, 0).await;
        assert_eq!(
            &peer.output()[initial.len()..],
            encoded(Frame::Goaway(VarInt::from_u32(0))).as_ref()
        );
        assert!(!peer.received_control.lock().unwrap().finished);
        drop(active);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn decreasing_shutdown_preserves_partial_goaway_and_sends_only_latest_limit() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (mut server, peer) = setup(Vec::new(), None, vec![request(0)]).await;
        let active = server.accept().await.unwrap().unwrap();
        let mut control = peer.control_reader().await;
        let initial = peer.output();
        let blocked = peer.limit_send(false, 1);
        cancel_when_blocked(server.shutdown(8), blocked).await;
        let blocked = peer.limit_send(false, 0);
        cancel_when_blocked(server.shutdown(4), blocked).await;
        let blocked = peer.limit_send(false, 0);
        cancel_when_blocked(server.shutdown(0), blocked).await;
        peer.resume_send();
        server.shutdown(0).await.unwrap();
        server.shutdown(8).await.unwrap();
        expect_goaway(&mut control, 32).await;
        expect_goaway(&mut control, 0).await;
        let expected = [
            encoded(Frame::Goaway(VarInt::from_u32(32))),
            encoded(Frame::Goaway(VarInt::from_u32(0))),
        ]
        .concat();
        assert_eq!(&peer.output()[initial.len()..], expected);
        assert!(!peer.received_control.lock().unwrap().finished);
        drop(active);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_shutdown_is_resumed_by_accept_with_active_request() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (mut server, peer) = setup(Vec::new(), None, vec![request(0)]).await;
        let active = server.accept().await.unwrap().unwrap();
        let mut control = peer.control_reader().await;
        let blocked = peer.limit_send(false, 1);
        cancel_when_blocked(server.shutdown(0), blocked).await;
        peer.resume_send();
        tokio::select! { biased;
            _ = server.accept() => panic!("未释放的请求必须继续排空"),
            _ = expect_goaway(&mut control, 0) => (),
        }
        assert!(!peer.received_control.lock().unwrap().finished);
        drop(active);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pending_goaway_write_error_stays_a_connection_error() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (mut server, peer) = setup(
            vec![encoded(Frame::Goaway(VarInt::from_u32(0)))],
            None,
            Vec::new(),
        )
        .await;
        let blocked = peer.limit_send(false, 1);
        cancel_when_blocked(server.accept(), blocked).await;
        peer.window.lock().unwrap().error = Some(Code::H3_REQUEST_CANCELLED.value());
        peer.resume_send();
        for result in [server.shutdown(0).await, server.shutdown(0).await] {
            assert_matches!(
                result,
                Err(ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_CLOSED_CRITICAL_STREAM,
                        ..
                    }
                })
            );
        }
        assert_eq!(
            *peer.closed.lock().unwrap(),
            Some(Code::H3_CLOSED_CRITICAL_STREAM)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn control_errors_after_a_full_batch_keep_settings_and_goaway_validation() {
    tokio::time::timeout(Duration::from_secs(1), async {
        for (invalid, code) in [
            (
                encoded(Frame::Settings(Settings::default())),
                Code::H3_FRAME_UNEXPECTED,
            ),
            (
                encoded(Frame::Goaway(VarInt::from_u32(1))),
                Code::H3_ID_ERROR,
            ),
            (
                encoded(Frame::Data(Bytes::new())),
                Code::H3_FRAME_UNEXPECTED,
            ),
        ] {
            let frames = vec![encoded(Frame::Goaway(VarInt::from_u32(0))); 256];
            let (mut server, peer) = setup(frames, None, vec![request(0)]).await;
            let active = server.accept().await.unwrap().unwrap();
            peer.append_control(invalid);
            assert_matches!(
                server.accept().await.err().unwrap(),
                ConnectionError::Local {
                    error: LocalError::Application { code: actual, .. }
                } if actual == code
            );
            assert_eq!(*peer.closed.lock().unwrap(), Some(code));
            drop(active);
        }
    })
    .await
    .unwrap();
}

async fn assert_idle_buffered_error(frames: Vec<Bytes>, code: Code) {
    let (mut server, peer) = setup(frames, None, Vec::new()).await;
    peer.coalesce_control();
    let initial = peer.output();
    assert_matches!(
        server.accept().await.err().expect("已缓冲的非法控制帧必须报错"),
        ConnectionError::Local {
            error: LocalError::Application { code: actual, .. }
        } if actual == code
    );
    assert_eq!(*peer.closed.lock().unwrap(), Some(code));
    assert_eq!(peer.output(), initial, "非法控制帧不能转成正常 GOAWAY 排空");
}

#[tokio::test]
async fn buffered_data_after_control_budget_is_not_a_clean_shutdown() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut frames = vec![encoded(Frame::Goaway(VarInt::from_u32(0))); 63];
        frames.push(encoded(Frame::Data(Bytes::new())));
        assert_idle_buffered_error(frames, Code::H3_FRAME_UNEXPECTED).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn buffered_data_after_unknown_frame_budget_is_not_a_clean_shutdown() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let frames = vec![
            encoded(Frame::Goaway(VarInt::from_u32(0))),
            Bytes::from([0x21, 0].repeat(64)),
            encoded(Frame::Data(Bytes::new())),
        ];
        assert_idle_buffered_error(frames, Code::H3_FRAME_UNEXPECTED).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn idle_control_validation_survives_both_budgets() {
    tokio::time::timeout(Duration::from_secs(1), async {
        for prefix in [
            vec![encoded(Frame::Goaway(VarInt::from_u32(0))); 63],
            vec![
                encoded(Frame::Goaway(VarInt::from_u32(0))),
                Bytes::from([0x21, 0].repeat(64)),
            ],
        ] {
            for (invalid, code) in [
                (
                    encoded(Frame::Settings(Settings::default())),
                    Code::H3_FRAME_UNEXPECTED,
                ),
                (
                    Bytes::from_static(&[0x04, 0x02, 0, 0]),
                    Code::H3_SETTINGS_ERROR,
                ),
                (
                    encoded(Frame::Goaway(VarInt::from_u32(1))),
                    Code::H3_ID_ERROR,
                ),
            ] {
                let mut frames = prefix.clone();
                frames.push(invalid);
                assert_idle_buffered_error(frames, code).await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn finite_control_batches_drain_only_after_input_pending() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut frames = vec![encoded(Frame::Goaway(VarInt::from_u32(0))); 192];
        frames.push(Bytes::from([0x21, 0].repeat(192)));
        frames.push(encoded(Frame::MaxPushId(PushId(0))));
        let (mut server, peer) = setup(frames, None, Vec::new()).await;
        peer.coalesce_control();
        let mut waiting = peer.observe_input_wait();
        let mut control = peer.control_reader().await;
        let initial = peer.output();
        assert!(server.accept().await.unwrap().is_none());
        assert_eq!(waiting.try_recv(), Ok(()), "自然排空前必须读到真实输入等待");
        expect_goaway(&mut control, 0).await;
        assert_eq!(
            &peer.output()[initial.len()..],
            encoded(Frame::Goaway(VarInt::from_u32(0))).as_ref()
        );
        assert!(!peer.received_control.lock().unwrap().finished);
        assert!(peer.closed.lock().unwrap().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_request_does_not_hide_buffered_control_error() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut frames = vec![encoded(Frame::Goaway(VarInt::from_u32(0))); 63];
        frames.push(encoded(Frame::Data(Bytes::new())));
        let (mut server, peer) = setup(frames, None, vec![request(4)]).await;
        peer.coalesce_control();
        server.shutdown(0).await.unwrap();
        assert_matches!(
            server
                .accept()
                .await
                .err()
                .expect("拒绝新请求后仍须检查已缓冲控制帧"),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_FRAME_UNEXPECTED,
                    ..
                }
            }
        );
        assert_eq!(
            *peer.closed.lock().unwrap(),
            Some(Code::H3_FRAME_UNEXPECTED)
        );
    })
    .await
    .unwrap();
}

async fn assert_pending_grease_keeps_control_live(pause_open: bool) {
    for (frames, error) in [
        (vec![encoded(Frame::Goaway(VarInt::from_u32(0)))], None),
        (
            vec![encoded(Frame::Settings(Settings::default()))],
            Some(Code::H3_FRAME_UNEXPECTED),
        ),
        (
            vec![
                encoded(Frame::Goaway(VarInt::from_u32(0))),
                encoded(Frame::Goaway(VarInt::from_u32(1))),
            ],
            Some(Code::H3_ID_ERROR),
        ),
        (
            vec![encoded(Frame::Data(Bytes::new()))],
            Some(Code::H3_FRAME_UNEXPECTED),
        ),
    ] {
        let (mut server, peer) = setup_with_grease(frames, None, Vec::new(), true).await;
        peer.coalesce_control();
        let blocked = if pause_open {
            peer.grease.pause_open()
        } else {
            limit_window(&peer.grease.window, false, 1)
        };
        let (result, blocked) = tokio::join!(server.accept(), blocked);
        blocked.unwrap();
        if let Some(code) = error {
            assert_matches!(
                result.err().expect("grease 阻塞不能隐藏控制帧错误"),
                ConnectionError::Local {
                    error: LocalError::Application { code: actual, .. }
                } if actual == code
            );
            assert_eq!(*peer.closed.lock().unwrap(), Some(code));
        } else {
            assert!(result.unwrap().is_none(), "grease 阻塞不能吞掉 GOAWAY");
            let mut control = peer.control_reader().await;
            expect_goaway(&mut control, 0).await;
            assert!(peer.closed.lock().unwrap().is_none());
        }
        let wire = peer.grease.wire.lock().unwrap();
        assert_eq!(wire.transcript.len(), if pause_open { 0 } else { 1 });
        assert!(!wire.finished);
    }
}

#[tokio::test]
async fn pending_grease_open_keeps_control_validation_and_shutdown_live() {
    tokio::time::timeout(
        Duration::from_secs(1),
        assert_pending_grease_keeps_control_live(true),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pending_grease_write_keeps_control_validation_and_shutdown_live() {
    tokio::time::timeout(
        Duration::from_secs(1),
        assert_pending_grease_keeps_control_live(false),
    )
    .await
    .unwrap();
}

fn assert_one_grease_frame(mut wire: Bytes) {
    let stream_type = VarInt::decode(&mut wire).unwrap().into_inner();
    assert!(stream_type >= 0x21 && (stream_type - 0x21) % 0x1f == 0);
    let frame_type = VarInt::decode(&mut wire).unwrap().into_inner();
    assert!(frame_type >= 0x21 && (frame_type - 0x21) % 0x1f == 0);
    assert_eq!(VarInt::decode(&mut wire).unwrap().into_inner(), 6);
    assert_eq!(wire, Bytes::from_static(b"grease"));
}

#[tokio::test]
async fn pending_grease_resumes_once_without_new_control_input() {
    tokio::time::timeout(Duration::from_secs(1), async {
        for pause_open in [true, false] {
            let (mut server, peer) =
                setup_with_grease(Vec::new(), None, vec![request(0)], true).await;
            let blocked = if pause_open {
                peer.grease.pause_open()
            } else {
                limit_window(&peer.grease.window, false, 1)
            };
            let active = server.accept().await.unwrap().unwrap();
            blocked.await.unwrap();
            let prefix = peer.grease.wire.lock().unwrap().transcript.clone();
            assert_eq!(prefix.len(), if pause_open { 0 } else { 1 });
            peer.grease.resume_open();
            resume_window(&peer.grease.window);
            let wire = tokio::select! { biased;
                _ = server.accept() => panic!("活动请求仍持有连接，接纳不能结束"),
                wire = peer.grease.receive() => wire,
            };
            assert_eq!(&wire[..prefix.len()], prefix);
            assert_one_grease_frame(wire.clone());
            assert_eq!(peer.grease.open.lock().unwrap().opened, vec![15]);
            assert_eq!(peer.grease.wire.lock().unwrap().transcript, wire.as_ref());
            assert!(peer.grease.wire.lock().unwrap().finished);
            assert!(!peer.received_control.lock().unwrap().finished);
            assert!(peer.closed.lock().unwrap().is_none());
            drop(active);
        }
    })
    .await
    .unwrap();
}
