//! 逻辑会话与作用域任务；独立泵保持慢流、取消和载体密码计数器的边界。
use crate::crypto::StreamCipher;
use crate::{
    codec::{self, Frame},
    config::Traffic,
};
use bytes::{Buf, Bytes};
use kerlico_core::{
    AccessService, BoxStream, CancellationToken, ConnectContext, Error, InboundContext, NodeEvent,
    Result, StreamLease,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker, ready},
    time::{Duration, Instant},
};
use tokio::{
    io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        DuplexStream, ReadBuf,
    },
    sync::{OwnedSemaphorePermit, mpsc, oneshot, watch},
    task::JoinSet,
};
const PIPE_BYTES: usize = 32768;
pub(crate) const RECEIVE_BYTES: usize = 256 * 1024;
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;
pub(crate) struct Scope {
    pub cancel: CancellationToken,
    tasks: Mutex<JoinSet<()>>,
}
impl Scope {
    pub fn new(parent: &CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            cancel: parent.child_token(),
            tasks: Mutex::new(JoinSet::new()),
        })
    }
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        if self.cancel.is_cancelled() {
            return;
        }
        let cancel = self.cancel.clone();
        if let Ok(mut tasks) = self.tasks.lock() {
            while tasks.try_join_next().is_some() {}
            tasks.spawn(async move {
                tokio::select! { biased; _ = cancel.cancelled() => {}, _ = future => {} }
            });
        }
    }
    pub fn stop(&self) {
        self.cancel.cancel();
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.abort_all();
        }
    }
    pub async fn shutdown(&self) {
        self.stop();
        let mut tasks = if let Ok(mut tasks) = self.tasks.lock() {
            std::mem::take(&mut *tasks)
        } else {
            return;
        };
        while tasks.join_next().await.is_some() {}
    }
}
#[derive(Clone)]
pub(crate) struct Server {
    pub access: Arc<dyn AccessService>,
    pub context: InboundContext,
}
pub(crate) struct Link {
    pub command: mpsc::Sender<Command>,
    pub scope: Arc<Scope>,
    pub client: bool,
    pub traffic: Traffic,
    pub idle: Duration,
    pub connect_timeout: Duration,
    pub multiplexing: bool,
    pub created: Instant,
    pub active: AtomicUsize,
    pub issued: AtomicUsize,
    next: AtomicU32,
    pub server: Option<Server>,
}
impl Link {
    pub fn new(
        scope: Arc<Scope>,
        client: bool,
        traffic: Traffic,
        idle: Duration,
        connect_timeout: Duration,
        multiplexing: bool,
        server: Option<Server>,
    ) -> (Arc<Self>, mpsc::Receiver<Command>) {
        let (command, receive) = mpsc::channel(256);
        (
            Arc::new(Self {
                command,
                scope,
                client,
                traffic,
                idle,
                connect_timeout,
                multiplexing,
                created: Instant::now(),
                active: AtomicUsize::new(0),
                issued: AtomicUsize::new(0),
                next: AtomicU32::new((rand::random::<u32>() & 0x7fff_ffff) + 1),
                server,
            }),
            receive,
        )
    }
    pub fn reusable(&self) -> bool {
        !self.scope.cancel.is_cancelled()
            && self.multiplexing
            && self.created.elapsed() < Duration::from_secs(120)
            && self.issued.load(Ordering::Acquire) < 8192
    }
    pub fn stop(&self) {
        self.scope.stop();
    }
    pub fn id(&self) -> Result<u32> {
        if self.issued.fetch_add(1, Ordering::AcqRel) >= 8192 {
            return Err(Error::ResourceLimit);
        }
        let id = self.next.fetch_add(1, Ordering::AcqRel);
        if id == 0 || id == u32::MAX {
            return Err(Error::ResourceLimit);
        }
        Ok(id)
    }
    pub async fn open(
        self: &Arc<Self>,
        request: Bytes,
        lazy: bool,
        slot: OwnedSemaphorePermit,
        context: &ConnectContext,
    ) -> Result<(SessionIo, oneshot::Receiver<Result<()>>)> {
        let id = self.id()?;
        let (entry, io, handshake) = Entry::new(
            self.clone(),
            id,
            id,
            Some(slot),
            None,
            true,
            context.timeout,
        );
        self.command
            .send(Command::Open {
                entry,
                request,
                lazy,
            })
            .await
            .map_err(|_| Error::Rejected)?;
        let life = io.life.clone();
        let request_cancel = context.cancel.clone();
        let finished = life.finished.clone();
        self.scope.spawn(async move { tokio::select! { biased; _ = finished.cancelled() => {}, _ = request_cancel.cancelled() => life.abort(2) } });
        Ok((io, handshake))
    }
}
pub(crate) struct Life {
    pub id: u32,
    pub wire_id: u32,
    pub link: Arc<Link>,
    pub tx_cancel: CancellationToken,
    pub abort_cancel: CancellationToken,
    pub finished: CancellationToken,
    pub closed: AtomicBool,
    pub reason: AtomicU8,
    pub graceful: AtomicBool,
    pub peer_low: AtomicBool,
    pub received_bytes: AtomicUsize,
    pub started: watch::Sender<bool>,
    pub rx_done: AtomicBool,
    handshake_done: AtomicBool,
    handshake_ok: AtomicBool,
    sent: AtomicU64,
    flush_waker: Mutex<Option<Waker>>,
    _slot: Option<OwnedSemaphorePermit>,
    _lease: Option<Arc<StreamLease>>,
}
impl Life {
    pub fn abort(&self, reason: u8) {
        self.reason
            .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire)
            .ok();
        self.abort_cancel.cancel();
        self.tx_cancel.cancel();
        self.wake();
        let _ = self.link.command.try_send(Command::Close {
            id: self.id,
            abort: true,
            done: None,
        });
    }
    pub fn wake(&self) {
        if let Ok(mut waker) = self.flush_waker.lock()
            && let Some(waker) = waker.take()
        {
            waker.wake();
        }
    }
    pub fn finish_peer(&self) {
        self.closed.store(true, Ordering::Release);
        self.started.send_replace(true);
        self.tx_cancel.cancel();
        self.finished.cancel();
        self.wake();
    }
    fn io_error(&self) -> io::Error {
        io::Error::new(
            if self.reason.load(Ordering::Acquire) == 2 {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::BrokenPipe
            },
            "Mieru 逻辑会话已终止",
        )
    }
}
pub(crate) struct SessionIo {
    inner: DuplexStream,
    pub life: Arc<Life>,
    written: u64,
    shutdown: oneshot::Receiver<Result<()>>,
    shutting_down: bool,
    shutdown_status: Option<bool>,
}
impl AsyncRead for SessionIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let remaining = buffer.remaining();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buffer))?;
        if remaining != 0
            && buffer.filled().len() == before
            && self.life.reason.load(Ordering::Acquire) != 0
        {
            return Poll::Ready(Err(self.life.io_error()));
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for SessionIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.life.tx_cancel.is_cancelled() {
            return Poll::Ready(Err(self.life.io_error()));
        }
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, bytes))?;
        self.written += n as u64;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let complete = || {
            this.life.sent.load(Ordering::Acquire) >= this.written
                && (!this.life.link.client
                    || !*this.life.started.borrow()
                    || this.life.handshake_done.load(Ordering::Acquire)
                        && this.life.handshake_ok.load(Ordering::Acquire))
        };
        if complete() {
            return Poll::Ready(Ok(()));
        }
        if this.life.reason.load(Ordering::Acquire) != 0 || this.life.tx_cancel.is_cancelled() {
            return Poll::Ready(Err(this.life.io_error()));
        }
        if let Ok(mut waker) = this.life.flush_waker.lock() {
            *waker = Some(cx.waker().clone());
        }
        if complete() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(success) = self.shutdown_status {
            return Poll::Ready(if success {
                Ok(())
            } else {
                Err(self.life.io_error())
            });
        }
        if !self.shutting_down {
            ready!(self.as_mut().poll_flush(cx))?;
            ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
            self.shutting_down = true;
        }
        let success = matches!(ready!(Pin::new(&mut self.shutdown).poll(cx)), Ok(Ok(())));
        self.shutdown_status = Some(success);
        Poll::Ready(if success {
            Ok(())
        } else {
            Err(self.life.io_error())
        })
    }
}
impl Drop for SessionIo {
    fn drop(&mut self) {
        if !self.shutting_down && !self.life.closed.load(Ordering::Acquire) {
            self.life.abort(2);
        }
    }
}
struct ChunkReader {
    receive: mpsc::Receiver<Bytes>,
    current: Bytes,
    life: Arc<Life>,
}
impl AsyncRead for ChunkReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.current.is_empty() {
            match ready!(self.receive.poll_recv(cx)) {
                Some(bytes) => self.current = bytes,
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = buffer.remaining().min(self.current.len());
        buffer.put_slice(&self.current[..n]);
        self.current.advance(n);
        self.life.received_bytes.fetch_sub(n, Ordering::AcqRel);
        let _ = self
            .life
            .link
            .command
            .try_send(Command::Consumed(self.life.id));
        Poll::Ready(Ok(()))
    }
}
pub(crate) struct Entry {
    pub life: Arc<Life>,
    delivery: Option<mpsc::Sender<Bytes>>,
    pending: VecDeque<Bytes>,
    pub send_next: u32,
    pub receive_next: u32,
    pub request: Bytes,
    pub started: bool,
    pub established: bool,
    pub last_data: Instant,
    pub peer_closed: bool,
}
impl Entry {
    pub fn new(
        link: Arc<Link>,
        id: u32,
        wire_id: u32,
        slot: Option<OwnedSemaphorePermit>,
        lease: Option<Arc<StreamLease>>,
        client: bool,
        timeout: Duration,
    ) -> (Self, SessionIo, oneshot::Receiver<Result<()>>) {
        let (app, transport) = tokio::io::duplex(PIPE_BYTES);
        let (mut outgoing, mut incoming) = tokio::io::split(transport);
        let (delivery, receive) = mpsc::channel(4);
        let (started, _) = watch::channel(!client);
        let life = Arc::new(Life {
            id,
            wire_id,
            link: link.clone(),
            tx_cancel: CancellationToken::new(),
            abort_cancel: CancellationToken::new(),
            finished: CancellationToken::new(),
            closed: AtomicBool::new(false),
            reason: AtomicU8::new(0),
            graceful: AtomicBool::new(false),
            peer_low: AtomicBool::new(false),
            received_bytes: AtomicUsize::new(0),
            started,
            rx_done: AtomicBool::new(false),
            handshake_done: AtomicBool::new(!client),
            handshake_ok: AtomicBool::new(!client),
            sent: AtomicU64::new(0),
            flush_waker: Mutex::new(None),
            _slot: slot,
            _lease: lease,
        });
        let (handshake_tx, handshake_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let read_life = life.clone();
        link.scope.spawn(async move {
            let mut reader = ChunkReader { receive, current: Bytes::new(), life: read_life.clone() };
            let handshake = async {
                if client {
                    let mut started = read_life.started.subscribe();
                    while !*started.borrow_and_update() { started.changed().await.map_err(|_| Error::Rejected)?; }
                    tokio::time::timeout(timeout, codec::read_response(&mut reader)).await.map_err(|_| Error::Timeout)??;
                }
                Ok(())
            };
            let result = tokio::select! { biased; _ = read_life.abort_cancel.cancelled() => Err(Error::Cancelled), result = handshake => result };
            read_life.handshake_ok.store(result.is_ok(), Ordering::Release); read_life.handshake_done.store(true, Ordering::Release); read_life.wake();
            let good = result.is_ok(); let _ = handshake_tx.send(result);
            if !good { read_life.abort(1); read_life.rx_done.store(true, Ordering::Release); return; }
            let copying = async { let mut buffer = [0; 8192]; loop { let n = reader.read(&mut buffer).await?; if n == 0 { break; } incoming.write_all(&buffer[..n]).await?; } incoming.shutdown().await };
            if tokio::select! { biased; _ = read_life.abort_cancel.cancelled() => Err(io::ErrorKind::Interrupted.into()), result = copying => result }.is_err() && !read_life.graceful.load(Ordering::Acquire) && !read_life.closed.load(Ordering::Acquire) { read_life.abort(2); }
            read_life.rx_done.store(true, Ordering::Release); let _ = read_life.link.command.try_send(Command::Consumed(read_life.id));
        });
        let write_life = life.clone();
        link.scope.spawn(async move {
            let result: Result<()> = async {
                let mut buffer = vec![0; 32768];
                loop {
                    let n = tokio::select! { biased; _ = write_life.tx_cancel.cancelled() => return if write_life.closed.load(Ordering::Acquire) { Ok(()) } else { Err(Error::Cancelled) }, n = outgoing.read(&mut buffer) => n? };
                    if n == 0 {
                        write_life.graceful.store(true, Ordering::Release);
                        let (done, answer) = oneshot::channel();
                        write_life.link.command.send(Command::Close { id: write_life.id, abort: false, done: Some(done) }).await.map_err(|_| Error::Rejected)?;
                        return answer.await.map_err(|_| Error::Rejected)?;
                    }
                    let (done, answer) = oneshot::channel();
                    write_life.link.command.send(Command::Write { id: write_life.id, body: Bytes::copy_from_slice(&buffer[..n]), done }).await.map_err(|_| Error::Rejected)?;
                    tokio::select! { biased; _ = write_life.tx_cancel.cancelled() => return Err(Error::Cancelled), answer = answer => answer.map_err(|_| Error::Rejected)?? }
                    write_life.sent.fetch_add(n as u64, Ordering::AcqRel); write_life.wake();
                }
            }.await;
            if result.is_err() && !write_life.closed.load(Ordering::Acquire) { write_life.abort(2); }
            let _ = shutdown_tx.send(result);
        });
        link.active.fetch_add(1, Ordering::AcqRel);
        (
            Self {
                life: life.clone(),
                delivery: Some(delivery),
                pending: VecDeque::new(),
                send_next: 0,
                receive_next: 0,
                request: Bytes::new(),
                started: false,
                established: false,
                last_data: Instant::now(),
                peer_closed: false,
            },
            SessionIo {
                inner: app,
                life,
                written: 0,
                shutdown: shutdown_rx,
                shutting_down: false,
                shutdown_status: None,
            },
            handshake_rx,
        )
    }
    pub fn next(&mut self) -> Result<u32> {
        let seq = self.send_next;
        self.send_next = self.send_next.checked_add(1).ok_or(Error::ResourceLimit)?;
        Ok(seq)
    }
    pub fn traffic(&self) -> Traffic {
        let mut traffic = self.life.link.traffic.clone();
        if !self.life.link.client && !self.life.peer_low.load(Ordering::Acquire) {
            traffic.low_entropy_mode = 0;
            traffic.mask_rotation = 0;
        }
        traffic
    }
    pub fn deliver(&mut self, body: Bytes) -> Result<()> {
        if body.is_empty() {
            return Ok(());
        }
        if self
            .life
            .received_bytes
            .fetch_add(body.len(), Ordering::AcqRel)
            + body.len()
            > RECEIVE_BYTES
        {
            self.life
                .received_bytes
                .fetch_sub(body.len(), Ordering::AcqRel);
            return Err(Error::ResourceLimit);
        }
        self.last_data = Instant::now();
        self.pending.push_back(body);
        self.flush();
        Ok(())
    }
    pub fn flush(&mut self) {
        let mut discarded = false;
        if let Some(delivery) = &self.delivery {
            while let Some(body) = self.pending.pop_front() {
                match delivery.try_send(body) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(body)) => {
                        self.pending.push_front(body);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(body)) => {
                        self.life
                            .received_bytes
                            .fetch_sub(body.len(), Ordering::AcqRel);
                        if !self.life.graceful.load(Ordering::Acquire)
                            && !self.life.closed.load(Ordering::Acquire)
                        {
                            self.life.abort(2);
                        }
                        discarded = true;
                        break;
                    }
                }
            }
        }
        if discarded {
            for body in self.pending.drain(..) {
                self.life
                    .received_bytes
                    .fetch_sub(body.len(), Ordering::AcqRel);
            }
            self.delivery.take();
        }
        if self.peer_closed && self.pending.is_empty() {
            self.delivery.take();
        }
    }
    pub fn drained(&self) -> bool {
        self.life.rx_done.load(Ordering::Acquire)
    }
    pub fn peer_close(&mut self) {
        self.peer_closed = true;
        self.life.finish_peer();
        self.flush();
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.life.finish_peer();
        self.life.link.active.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(crate) struct Receipt {
    remaining: AtomicUsize,
    done: Mutex<Option<oneshot::Sender<Result<()>>>>,
}
impl Receipt {
    pub fn new(count: usize, done: Option<oneshot::Sender<Result<()>>>) -> Arc<Self> {
        Arc::new(Self {
            remaining: AtomicUsize::new(count),
            done: Mutex::new(done),
        })
    }
    pub fn sent(&self) {
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1
            && let Ok(mut done) = self.done.lock()
            && let Some(done) = done.take()
        {
            let _ = done.send(Ok(()));
        }
    }
    pub fn fail(&self) {
        if let Ok(mut done) = self.done.lock()
            && let Some(done) = done.take()
        {
            let _ = done.send(Err(Error::Rejected));
        }
    }
}
pub(crate) struct WireWrite {
    pub frame: Frame,
    pub life: Arc<Life>,
    pub receipt: Arc<Receipt>,
}
pub(crate) enum Command {
    Open {
        entry: Entry,
        request: Bytes,
        lazy: bool,
    },
    Write {
        id: u32,
        body: Bytes,
        done: oneshot::Sender<Result<()>>,
    },
    Close {
        id: u32,
        abort: bool,
        done: Option<oneshot::Sender<Result<()>>>,
    },
    Consumed(u32),
    Incoming(Frame),
    Written,
}
pub(crate) fn server_entry(link: &Arc<Link>, id: u32, wire_id: u32) -> Result<Entry> {
    let server = link.server.as_ref().ok_or_else(codec::bad)?;
    let lease = Arc::new(server.context.stream_budget.try_acquire()?);
    let (entry, io, _) = Entry::new(
        link.clone(),
        id,
        wire_id,
        None,
        Some(lease),
        false,
        server.context.connect_timeout,
    );
    let server = server.clone();
    let life = io.life.clone();
    link.scope.spawn(async move {
        server.context.events.record(NodeEvent::Accepted);
        let result = tokio::select! { biased; _ = life.finished.cancelled() => if life.reason.load(Ordering::Acquire) == 0 { Ok(()) } else { Err(Error::Cancelled) }, result = crate::server::run_session(io, server.access, server.context.clone()) => result };
        server.context.events.record(if result.is_ok() { NodeEvent::Completed } else { NodeEvent::Failed });
        if result.is_err() { life.abort(1); }
    });
    Ok(entry)
}
pub(crate) struct TcpSettings {
    pub traffic: Traffic,
    pub idle: Duration,
    pub connect_timeout: Duration,
    pub multiplexing: bool,
    pub server: Option<Server>,
}
pub(crate) fn tcp_link(
    stream: BoxStream,
    receive_cipher: StreamCipher,
    send_cipher: StreamCipher,
    scope: Arc<Scope>,
    settings: TcpSettings,
    first: Option<Frame>,
) -> Arc<Link> {
    let client = settings.server.is_none();
    let (link, commands) = Link::new(
        scope,
        client,
        settings.traffic,
        settings.idle,
        settings.connect_timeout,
        settings.multiplexing,
        settings.server,
    );
    let (reader, mut writer) = tokio::io::split(stream);
    let (output, mut writes) = mpsc::channel::<WireWrite>(16);
    let writing = link.clone();
    link.scope.spawn(async move {
        let mut cipher = send_cipher;
        while let Some(operation) = writes.recv().await {
            if operation.life.abort_cancel.is_cancelled() && !matches!(operation.frame.kind, 4 | 5)
            {
                operation.receipt.fail();
                continue;
            }
            let result: Result<()> = async {
                let wire = codec::seal_stream(&mut cipher, &operation.frame, &writing.traffic)?;
                tokio::time::timeout(writing.connect_timeout, writer.write_all(&wire))
                    .await
                    .map_err(|_| Error::Timeout)??;
                Ok(())
            }
            .await;
            if result.is_err() {
                operation.receipt.fail();
                writing.scope.cancel.cancel();
                return;
            }
            if operation.frame.kind == 2 {
                operation.life.started.send_replace(true);
                operation.life.wake();
            }
            operation.receipt.sent();
            let _ = writing.command.send(Command::Written).await;
        }
        writing.scope.cancel.cancel();
    });
    let reading = link.clone();
    link.scope.spawn(async move {
        let mut cipher = receive_cipher;
        let mut reader = BufReader::new(reader);
        loop {
            let result: Result<Frame> = async {
                if reader.fill_buf().await?.is_empty() {
                    return Err(Error::Rejected);
                }
                tokio::time::timeout(
                    reading.connect_timeout,
                    codec::read_stream(&mut reader, &mut cipher),
                )
                .await
                .map_err(|_| Error::Timeout)?
            }
            .await;
            match result {
                Ok(frame) => {
                    if reading
                        .command
                        .send(Command::Incoming(frame))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        reading.scope.cancel.cancel();
    });
    let ever_used = first.is_some();
    let actor = TcpActor {
        stop_when_empty: false,
        ever_used,
        link: link.clone(),
        entries: HashMap::new(),
        retired: HashSet::new(),
        output,
        queued: VecDeque::new(),
        queued_bytes: 0,
        last_wire: Instant::now(),
    };
    link.scope.spawn(actor.run(commands, first));
    link
}
struct TcpActor {
    stop_when_empty: bool,
    ever_used: bool,
    link: Arc<Link>,
    entries: HashMap<u32, Entry>,
    retired: HashSet<u32>,
    output: mpsc::Sender<WireWrite>,
    queued: VecDeque<WireWrite>,
    queued_bytes: usize,
    last_wire: Instant,
}
impl TcpActor {
    fn push(&mut self, frame: Frame, life: Arc<Life>, receipt: Arc<Receipt>) -> Result<()> {
        if self.queued.len() >= 512 || self.queued_bytes + frame.body.len() > MAX_PENDING_BYTES {
            receipt.fail();
            return Err(Error::ResourceLimit);
        }
        self.queued_bytes += frame.body.len();
        self.queued.push_back(WireWrite {
            frame,
            life,
            receipt,
        });
        Ok(())
    }
    fn flush(&mut self) {
        while let Some(operation) = self.queued.pop_front() {
            let size = operation.frame.body.len();
            match self.output.try_send(operation) {
                Ok(()) => {
                    self.queued_bytes -= size;
                    self.last_wire = Instant::now();
                }
                Err(mpsc::error::TrySendError::Full(operation)) => {
                    self.queued.push_front(operation);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(operation)) => {
                    operation.receipt.fail();
                    self.link.scope.cancel.cancel();
                    break;
                }
            }
        }
    }
    fn data(
        &mut self,
        entry: &mut Entry,
        body: Bytes,
        done: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        if body.is_empty() {
            if let Some(done) = done {
                let _ = done.send(Ok(()));
            }
            return Ok(());
        }
        let traffic = entry.traffic();
        let maximum = crate::entropy::max_fragment(traffic.low_entropy_mode, None)?;
        let receipt = Receipt::new(body.len().div_ceil(maximum), done);
        for chunk in body.chunks(maximum) {
            let frame = Frame::data(
                entry.life.wire_id,
                entry.next()?,
                Bytes::copy_from_slice(chunk),
                self.link.client,
                &traffic,
            );
            self.push(frame, entry.life.clone(), receipt.clone())?;
        }
        entry.last_data = Instant::now();
        Ok(())
    }
    fn start(
        &mut self,
        entry: &mut Entry,
        body: Bytes,
        done: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        let mut combined = Vec::with_capacity(entry.request.len() + body.len());
        combined.extend_from_slice(&entry.request);
        combined.extend_from_slice(&body);
        entry.request = Bytes::new();
        let combined: Bytes = combined.into();
        let traffic = entry.traffic();
        let piggyback = traffic.low_entropy_mode == 0 && combined.len() <= 1024;
        let frame = Frame::control(
            2,
            entry.life.wire_id,
            entry.next()?,
            if piggyback {
                combined.clone()
            } else {
                Bytes::new()
            },
        );
        if piggyback {
            self.push(frame, entry.life.clone(), Receipt::new(1, done))?;
        } else {
            self.push(frame, entry.life.clone(), Receipt::new(1, None))?;
            self.data(entry, combined, done)?;
        }
        entry.started = true;
        Ok(())
    }
    fn close(&mut self, id: u32, abort: bool, done: Option<oneshot::Sender<Result<()>>>) {
        let Some(mut entry) = self.entries.remove(&id) else {
            if let Some(done) = done {
                let _ = done.send(Ok(()));
            }
            return;
        };
        if abort {
            self.stop_when_empty = true;
            entry.life.abort(2);
        }
        if !entry.started || self.link.client && !*entry.life.started.borrow() || entry.peer_closed
        {
            if let Some(done) = done {
                let _ = done.send(Ok(()));
            }
            entry.peer_close();
            if !abort {
                self.entries.insert(id, entry);
            } else {
                self.retired.insert(id);
            }
            return;
        }
        entry.life.tx_cancel.cancel();
        let result = entry.next().and_then(|seq| {
            self.push(
                Frame::control(4, entry.life.wire_id, seq, Bytes::new()),
                entry.life.clone(),
                Receipt::new(1, done),
            )
        });
        if result.is_err() {
            entry.life.abort(3);
        }
        if abort {
            entry.peer_close();
            self.retired.insert(id);
        } else {
            self.entries.insert(id, entry);
        }
    }
    fn incoming(&mut self, frame: Frame) -> Result<()> {
        frame.direction(self.link.client)?;
        self.ever_used = true;
        self.last_wire = Instant::now();
        let id = frame.id;
        if frame.kind == 2 && !self.entries.contains_key(&id) {
            if self.link.client
                || self.retired.contains(&id)
                || self.retired.len() + self.entries.len() >= 8192
                || self.entries.len() >= 128
            {
                return Ok(());
            }
            let Ok(mut entry) = server_entry(&self.link, id, id) else {
                return Ok(());
            };
            entry.started = true;
            entry.established = true;
            entry.receive_next = 1;
            let response = Frame::control(3, id, entry.next()?, Bytes::new());
            self.push(response, entry.life.clone(), Receipt::new(1, None))?;
            entry.deliver(frame.body)?;
            self.entries.insert(id, entry);
            return Ok(());
        }
        let Some(mut entry) = self.entries.remove(&id) else {
            return Ok(());
        };
        let result = match frame.kind {
            2 => self.push(
                Frame::control(3, id, 0, Bytes::new()),
                entry.life.clone(),
                Receipt::new(1, None),
            ),
            3 => {
                if frame.status != 0 {
                    entry.life.abort(1);
                    entry.peer_close();
                } else if !entry.established {
                    entry.established = true;
                    entry.receive_next = 1;
                    entry.deliver(frame.body)?;
                }
                Ok(())
            }
            4 | 5 => {
                if frame.kind == 4 {
                    let response = Frame::control(5, id, entry.next()?, Bytes::new());
                    self.push(response, entry.life.clone(), Receipt::new(1, None))?;
                }
                entry.peer_close();
                Ok(())
            }
            8 | 9 => Ok(()),
            _ if frame.is_data() && !entry.peer_closed => {
                if !entry.established || frame.seq != entry.receive_next {
                    entry.life.abort(1);
                    entry.peer_close();
                    Ok(())
                } else {
                    entry.receive_next = entry
                        .receive_next
                        .checked_add(1)
                        .ok_or(Error::ResourceLimit)?;
                    if frame.mode != 0 {
                        entry.life.peer_low.store(true, Ordering::Release);
                    }
                    entry.deliver(frame.body)
                }
            }
            _ => Ok(()),
        };
        if result.is_err() {
            entry.life.abort(3);
            entry.peer_close();
        }
        self.entries.insert(id, entry);
        Ok(())
    }
    fn command(&mut self, command: Command) -> Result<()> {
        match command {
            Command::Open {
                mut entry,
                request,
                lazy,
            } => {
                self.ever_used = true;
                let id = entry.life.id;
                if !self.link.client || self.entries.len() >= 128 || self.retired.contains(&id) {
                    entry.life.abort(3);
                    return Ok(());
                }
                entry.request = request;
                if !lazy && self.start(&mut entry, Bytes::new(), None).is_err() {
                    entry.life.abort(1);
                }
                self.entries.insert(id, entry);
            }
            Command::Write { id, body, done } => {
                let Some(mut entry) = self.entries.remove(&id) else {
                    let _ = done.send(Err(Error::Rejected));
                    return Ok(());
                };
                if entry.peer_closed || entry.life.abort_cancel.is_cancelled() {
                    let _ = done.send(Err(Error::Rejected));
                } else {
                    let result = if entry.started {
                        self.data(&mut entry, body, Some(done))
                    } else {
                        self.start(&mut entry, body, Some(done))
                    };
                    if result.is_err() {
                        entry.life.abort(3);
                    }
                }
                self.entries.insert(id, entry);
            }
            Command::Close { id, abort, done } => self.close(id, abort, done),
            Command::Consumed(id) => {
                if let Some(entry) = self.entries.get_mut(&id) {
                    entry.flush();
                }
            }
            Command::Incoming(frame) => self.incoming(frame)?,
            Command::Written => self.last_wire = Instant::now(),
        }
        self.flush();
        Ok(())
    }
    fn maintain(&mut self) -> bool {
        let mut expired = Vec::new();
        let mut finished = Vec::new();
        for (id, entry) in &mut self.entries {
            entry.flush();
            if entry.peer_closed && entry.drained() {
                finished.push(*id);
            } else if entry.life.abort_cancel.is_cancelled()
                || entry.last_data.elapsed() >= self.link.idle
            {
                expired.push(*id);
            }
        }
        for id in finished {
            self.entries.remove(&id);
            self.retired.insert(id);
        }
        for id in expired {
            self.close(id, true, None);
        }
        self.flush();
        self.entries.is_empty()
            && self.queued.is_empty()
            && (self.stop_when_empty
                || !self.link.multiplexing && self.ever_used
                || self.last_wire.elapsed() >= self.link.idle)
    }
    async fn run(mut self, mut receive: mpsc::Receiver<Command>, first: Option<Frame>) {
        if let Some(frame) = first
            && self.incoming(frame).is_err()
        {
            self.link.scope.cancel.cancel();
            return;
        }
        self.flush();
        let mut timer = tokio::time::interval(Duration::from_millis(5));
        let mut swept = Instant::now();
        loop {
            tokio::select! { biased;
                _ = self.link.scope.cancel.cancelled() => break,
                command = receive.recv() => match command { Some(command) => if self.command(command).is_err() { break; }, None => break },
                _ = timer.tick() => {},
            }
            // 热流量也执行期限与回收；不能让偏置队列饿死定时分支。
            if swept.elapsed() >= Duration::from_millis(5) {
                swept = Instant::now();
                if self.maintain() {
                    break;
                }
            }
        }
        self.link.scope.cancel.cancel();
    }
}
