//! Native UDP readiness and stream halves. Authentication, ordering, credit,
//! recovery and wire encoding stay in the shared session state machine.

use super::*;
use std::io::IoSlice;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::sync::{futures::OwnedNotified, Notify};

const QUEUE_LIMIT: usize = 2 * 1024 * 1024;
const MAX_WIRE: usize = 65535;

/// Keep a UDP socket and its native stream relays on the same reactor.
fn udp_executor() -> io::Result<&'static tokio::runtime::Handle> {
    type Reactor = OnceLock<io::Result<tokio::runtime::Handle>>;
    static REACTORS: OnceLock<Vec<Reactor>> = OnceLock::new();
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let reactors = REACTORS.get_or_init(|| {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        let count = std::env::var("TOKIO_WORKER_THREADS")
            .ok()
            .and_then(|value| value.parse::<std::num::NonZeroUsize>().ok())
            .map_or(cpus, |n| n.get().min(cpus));
        (0..count).map(|_| OnceLock::new()).collect()
    });
    let index = NEXT.fetch_add(1, Ordering::Relaxed) % reactors.len();
    reactors[index]
        .get_or_init(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let handle = runtime.handle().clone();
            std::thread::Builder::new()
                .name(format!("mieru-udp-{index}"))
                .spawn(move || runtime.block_on(std::future::pending::<()>()))?;
            Ok(handle)
        })
        .as_ref()
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

struct Packet {
    peer: SocketAddr,
    wire: Vec<u8>,
    ticket: u64,
}

#[derive(Default)]
struct Tx {
    packets: VecDeque<Packet>,
    bytes: usize,
    scratch: Vec<u8>,
    appended: u64,
    sent: u64,
}

struct Socket {
    socket: tokio::net::UdpSocket,
    raw: UdpSocket,
}

pub(super) struct Udp {
    transport: Mutex<Option<Arc<Socket>>>,
    executor: tokio::runtime::Handle,
    tx: Mutex<Tx>,
    pending: Notify,
    space: Arc<Notify>,
    stopped: AtomicBool,
    closed: Notify,
}

impl Udp {
    pub(super) fn new(raw: UdpSocket) -> io::Result<Arc<Self>> {
        raw.set_nonblocking(true)?;
        raw.set_read_timeout(None)?;
        raw.set_write_timeout(None)?;
        let runtime = udp_executor()?;
        let _entered = runtime.enter();
        Ok(Arc::new(Self {
            transport: Mutex::new(Some(Arc::new(Socket {
                socket: tokio::net::UdpSocket::from_std(raw.try_clone()?)?,
                raw,
            }))),
            executor: runtime.clone(),
            tx: Mutex::new(Tx::default()),
            pending: Notify::new(),
            space: Arc::new(Notify::new()),
            stopped: AtomicBool::new(false),
            closed: Notify::new(),
        }))
    }

    fn transport(&self) -> io::Result<Arc<Socket>> {
        self.transport
            .lock()
            .expect("UDP transport")
            .clone()
            .ok_or_else(closed)
    }

    /// Reserve bounded queue space before invoking the encoder. WouldBlock never
    /// consumes a sequence number or changes the session's retransmission state.
    pub(super) fn submit(
        &self,
        peer: SocketAddr,
        encode: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
    ) -> io::Result<u64> {
        let mut tx = self.tx.lock().expect("native UDP send");
        if self.stopped.load(Ordering::Acquire) {
            return Err(closed());
        }
        if tx.bytes + MAX_WIRE > QUEUE_LIMIT {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        tx.scratch.clear();
        encode(&mut tx.scratch)?;
        if tx.scratch.len() > MAX_WIRE {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if tx.packets.is_empty() {
            match self.transport()?.socket.try_send_to(&tx.scratch, peer) {
                Ok(n) if n == tx.scratch.len() => {
                    tx.scratch.clear();
                    tx.appended += 1;
                    tx.sent = tx.appended;
                    return Ok(tx.sent);
                }
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        let wire = std::mem::take(&mut tx.scratch);
        tx.bytes += wire.len();
        tx.appended += 1;
        let ticket = tx.appended;
        tx.packets.push_back(Packet { peer, wire, ticket });
        self.pending.notify_one();
        Ok(ticket)
    }

    fn flush(&self) -> io::Result<bool> {
        let transport = self.transport()?;
        let mut tx = self.tx.lock().expect("native UDP send");
        let mut sent = 0;
        for _ in 0..16 {
            let Some(packet) = tx.packets.front() else {
                break;
            };
            match transport.socket.try_send_to(&packet.wire, packet.peer) {
                Ok(n) if n == packet.wire.len() => {}
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
            let mut packet = tx.packets.pop_front().unwrap();
            tx.bytes -= packet.wire.len();
            tx.sent = packet.ticket;
            sent += 1;
            if packet.wire.capacity() > tx.scratch.capacity() {
                packet.wire.clear();
                tx.scratch = packet.wire;
            }
        }
        let done = tx.packets.is_empty();
        drop(tx);
        if sent != 0 {
            self.space.notify_waiters();
        }
        Ok(done)
    }

    pub(super) fn close(&self) {
        self.stopped.store(true, Ordering::Release);
        self.closed.notify_waiters();
        self.pending.notify_one();
        self.space.notify_waiters();
        self.transport.lock().expect("UDP transport").take();
        let mut tx = self.tx.lock().expect("native UDP send");
        tx.packets.clear();
        tx.bytes = 0;
    }
}

pub(super) fn start(link: Arc<Link>) {
    let executor = link.native.as_ref().unwrap().executor.clone();
    let reader = link.clone();
    executor.spawn(async move {
        let _ = receive(&reader).await;
        reader.close();
    });
    let writer = link.clone();
    executor.spawn(async move {
        let _ = send(&writer).await;
        writer.close();
    });
    executor.spawn(async move {
        while link
            .timer
            .wait_async(Instant::now() + Duration::from_millis(100))
            .await
        {
            if !link.alive.load(Ordering::Acquire) {
                break;
            }
            link.tick();
        }
    });
}

async fn receive(link: &Arc<Link>) -> io::Result<()> {
    let native = link.native.as_ref().unwrap();
    let transport = native.transport()?;
    let mut input = receive::Packets::new();
    let mut wakes = Vec::new();
    loop {
        let closed = native.closed.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        if !link.alive.load(Ordering::Acquire) {
            return Ok(());
        }
        tokio::select! { result = transport.socket.readable() => result?, _ = closed => return Ok(()) }
        let mut packets = 0;
        let mut bytes = 0;
        loop {
            if !link.alive.load(Ordering::Acquire) {
                return Ok(());
            }
            let result = transport.socket.try_io(Interest::READABLE, || {
                input.read_ready(&transport.raw, |peer, packet| {
                    bytes += packet.len();
                    if let Some(incoming) = parse_udp_packet(packet, peer, link) {
                        dispatch_with_wakes(link, incoming, Some(&mut wakes));
                    }
                })
            });
            for sess in wakes.drain(..) {
                sess.wake_readers();
            }
            match result {
                Ok(0) => break,
                Ok(count) => packets += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // A short batch can deliver bytes before its final EAGAIN.
                    if bytes >= 256 * 1024 {
                        tokio::task::yield_now().await;
                    }
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
                Err(error) => return Err(error),
            }
            // Readiness belongs to this whole drain. Notifications still occur
            // after each sixteen-packet batch; do not enter epoll between them.
            // Bound both packet work and bytes before yielding to other flows.
            if packets >= 128 || bytes >= 256 * 1024 {
                tokio::task::yield_now().await;
                break;
            }
        }
    }
}

async fn send(link: &Arc<Link>) -> io::Result<()> {
    let native = link.native.as_ref().unwrap();
    let transport = native.transport()?;
    loop {
        let changed = native.pending.notified();
        let closed = native.closed.notified();
        tokio::pin!(changed, closed);
        changed.as_mut().enable();
        closed.as_mut().enable();
        if !link.alive.load(Ordering::Acquire) {
            return Ok(());
        }
        if native.flush()? {
            tokio::select! { _ = changed => {}, _ = closed => return Ok(()) }
        } else {
            tokio::select! { result = transport.socket.writable() => result?, _ = closed => return Ok(()) }
            tokio::task::yield_now().await;
        }
    }
}

struct Flow {
    conn: Conn,
}

impl Flow {
    fn session(&self) -> &Arc<Sess> {
        let ConnKind::Stream(sess) = &self.conn.kind else {
            unreachable!("native TCP flow")
        };
        sess
    }
}

struct Reader {
    flow: Arc<Flow>,
    bytes: VecDeque<u8>,
}

impl Reader {
    fn fill(&mut self, cx: &Context<'_>) -> Poll<io::Result<()>> {
        if !self.bytes.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let sess = self.flow.session();
        let mut pipe = sess.pipe.lock().expect("pipe");
        if !pipe.bytes.is_empty() {
            pipe.task = None;
            std::mem::swap(&mut self.bytes, &mut pipe.bytes);
            if pipe.waiting != 0 {
                sess.cv.notify_all();
            }
            drop(pipe);
            sess.read_space(self.bytes.len(), 0);
            return Poll::Ready(Ok(()));
        }
        if pipe.closed {
            return Poll::Ready(Ok(()));
        }
        pipe.task = Some(cx.waker().clone());
        Poll::Pending
    }

    fn consume(&mut self, count: usize) {
        self.bytes.drain(..count.min(self.bytes.len()));
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(this.fill(cx))?;
        let (front, back) = this.bytes.as_slices();
        let n = out.remaining().min(front.len());
        out.put_slice(&front[..n]);
        let rest = out.remaining().min(back.len());
        out.put_slice(&back[..rest]);
        this.consume(n + rest);
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for Reader {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        std::task::ready!(this.fill(cx))?;
        Poll::Ready(Ok(this.bytes.as_slices().0))
    }
    fn consume(self: Pin<&mut Self>, n: usize) {
        self.get_mut().consume(n);
    }
}

impl kerlico_shared::AsyncBufReadVectored for Reader {
    fn poll_fill_buf_vectored<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
        parts: &mut [IoSlice<'a>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.fill(cx))?;
        let (front, back) = this.bytes.as_slices();
        let mut count = 0;
        for bytes in [front, back] {
            if !bytes.is_empty() && count < parts.len() {
                parts[count] = IoSlice::new(bytes);
                count += 1;
            }
        }
        Poll::Ready(Ok(count))
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.flow.session().pipe.lock().expect("pipe").task = None;
    }
}

struct Writer {
    flow: Arc<Flow>,
    space: Option<Pin<Box<OwnedNotified>>>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    ended: bool,
    ticket: u64,
}

impl Writer {
    fn stalled(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        use std::future::Future;
        let timer = self
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_secs(60))));
        if timer.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(timed_out()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::future::Future;
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let flow = this.flow.clone();
        let sess = flow.session();
        let native = sess.link.native.as_ref().unwrap();
        {
            let state = sess.send_window.lock().expect("UDP send window");
            *sess.send_task.lock().expect("send task") = Some(cx.waker().clone());
            if sess.closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(closed()));
            }
            let limit = state.cwnd.min(state.advertised);
            if limit == 0 || state.flights.len() >= limit as usize {
                return this.stalled(cx);
            }
        }
        let mode = sess.link.low_entropy.load(Ordering::Relaxed) as u8;
        // A partial AsyncWrite accepts one complete PDU. Never consume bytes or
        // leave an unfinished fragment group when returning Pending.
        let count = bytes.len().min(fragment_size(false, sess.link.mtu, mode));
        let kind = if mode == 0 { DATA_S2C } else { DATA_S2C_LOW };
        loop {
            let space = this
                .space
                .get_or_insert_with(|| Box::pin(native.space.clone().notified_owned()));
            space.as_mut().enable();
            let result = native.submit(sess.peer, |wire| {
                let seq = sess.next_send.fetch_add(1, Ordering::Relaxed);
                let payload = &bytes[..count];
                let envelope = sess.envelope(kind, seq, payload.len(), 0)?;
                sess.seal_udp(wire, &envelope, payload)?;
                sess.remember(kind, seq, payload, 0);
                Ok(())
            });
            match result {
                Ok(ticket) => {
                    sess.sent_now();
                    this.ticket = ticket;
                    sess.send_task.lock().expect("send task").take();
                    this.space = None;
                    this.deadline = None;
                    return Poll::Ready(Ok(count));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if space.as_mut().poll(cx).is_pending() {
                        return this.stalled(cx);
                    }
                    this.space = None;
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::future::Future;
        let this = self.get_mut();
        let flow = this.flow.clone();
        let native = flow.session().link.native.as_ref().unwrap();
        loop {
            let space = this
                .space
                .get_or_insert_with(|| Box::pin(native.space.clone().notified_owned()));
            space.as_mut().enable();
            if native.stopped.load(Ordering::Acquire) {
                return Poll::Ready(Err(closed()));
            }
            if native.tx.lock().expect("native UDP send").sent >= this.ticket {
                this.space = None;
                this.deadline = None;
                return Poll::Ready(Ok(()));
            }
            if space.as_mut().poll(cx).is_pending() {
                return this.stalled(cx).map(|result| result.map(|_| ()));
            }
            this.space = None;
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // mieru has no write-half close. Retain the reverse direction until its
        // peer, cancellation or the outbound idle deadline ends the owned flow.
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        let this = self.get_mut();
        this.ended = true;
        this.space = None;
        this.deadline = None;
        this.flow
            .session()
            .send_task
            .lock()
            .expect("send task")
            .take();
        Poll::Ready(Ok(()))
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.flow
            .session()
            .send_task
            .lock()
            .expect("send task")
            .take();
    }
}

pub(super) fn stream(conn: Conn) -> kerlico_shared::AsyncTcp {
    let flow = Arc::new(Flow { conn });
    let executor = flow
        .session()
        .link
        .native
        .as_ref()
        .expect("native UDP")
        .executor
        .clone();
    kerlico_shared::AsyncTcp {
        executor,
        read: kerlico_shared::AsyncReadHalf::Vectored(Box::new(Reader {
            flow: flow.clone(),
            bytes: VecDeque::new(),
        })),
        write: kerlico_shared::AsyncWriteHalf::plain(Writer {
            flow,
            space: None,
            deadline: None,
            ended: false,
            ticket: 0,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Wake, Waker};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn session() -> (Arc<Sess>, UdpSocket) {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let native = Udp::new(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
        udp_executor()
            .unwrap()
            .block_on(native.transport().unwrap().socket.writable())
            .unwrap();
        let link = Link::new(LinkSetup {
            role: Role::Server,
            mtu: 1280,
            accounts: Arc::new(Mutex::new(Vec::new())),
            socket: LinkSocket::Native(native),
            ready: None,
            bound_user: String::new(),
            remote: peer.local_addr().unwrap(),
        });
        let sess = Sess::new(
            link,
            17,
            peer.local_addr().unwrap(),
            "native-test".into(),
            [7; 32],
        );
        assert!(sess.link.insert(sess.clone()));
        (sess, peer)
    }

    #[test]
    fn window_pending_is_cancel_safe_and_ack_releases_the_same_stream() {
        let (sess, peer) = session();
        let runtime = udp_executor().unwrap();
        let _entered = runtime.enter();
        let mut halves = Conn {
            kind: ConnKind::Stream(sess.clone()),
        }
        .into_async();
        let wakes = Arc::new(Count::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        sess.send_window.lock().unwrap().advertised = 0;
        assert!(Pin::new(&mut halves.write)
            .poll_write(&mut cx, b"canceled")
            .is_pending());
        assert_eq!(sess.next_send.load(Ordering::Relaxed), 0);
        assert!(sess.send_window.lock().unwrap().flights.is_empty());
        sess.on_ack(0, 16);
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert!(matches!(
            Pin::new(&mut halves.write).poll_write(&mut cx, b"replacement"),
            Poll::Ready(Ok(11))
        ));
        let mut wire = [0; 2048];
        let len = peer.recv(&mut wire).unwrap();
        let nonce: [u8; 24] = wire[..24].try_into().unwrap();
        let mut cipher = Direction::from_key(sess.key);
        let header_len = cipher.open_at_slice(&nonce, &mut wire[24..72]).unwrap();
        let meta = meta::parse(&wire[24..24 + header_len]).unwrap();
        assert_eq!((meta.seq, meta.fragment), (0, 0));
        assert_eq!(
            udp_body(&meta, &nonce, &mut wire[72..len], &mut cipher)
                .unwrap()
                .as_ref(),
            b"replacement"
        );
        assert!(matches!(
            Pin::new(&mut halves.write).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(
            !sess.closed.load(Ordering::Acquire),
            "write EOF preserves reverse response"
        );
        sess.append(b"reply");
        let mut reply = [0; 5];
        let mut buf = ReadBuf::new(&mut reply);
        assert!(matches!(
            Pin::new(&mut halves.read).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"reply");
        sess.link.close();
    }

    #[test]
    fn due_ack_stays_pending_until_send_queue_has_capacity() {
        let (sess, peer) = session();
        let native = sess.link.native.as_ref().unwrap();
        native.tx.lock().unwrap().bytes = QUEUE_LIMIT;

        sess.ack_at.store(0, Ordering::Release);
        sess.tick();
        assert_ne!(sess.ack_at.load(Ordering::Acquire), u64::MAX);

        native.tx.lock().unwrap().bytes = 0;
        sess.ack_at.store(0, Ordering::Release);
        sess.tick();
        assert_eq!(sess.ack_at.load(Ordering::Acquire), u64::MAX);

        let mut wire = [0; 2048];
        assert!(peer.recv(&mut wire).unwrap() >= 72);
        let nonce = wire[..24].try_into().unwrap();
        let header_len = Direction::from_key(sess.key)
            .open_at_slice(&nonce, &mut wire[24..72])
            .unwrap();
        let header = meta::parse(&wire[24..24 + header_len]).unwrap();
        assert!(meta::is_ack(header.kind));
        sess.link.close();
    }

    #[test]
    fn bounded_send_queue_does_not_encode_while_full_and_close_wakes_both_halves() {
        let (sess, _peer) = session();
        let runtime = udp_executor().unwrap();
        let _entered = runtime.enter();
        let native = sess.link.native.as_ref().unwrap();
        let address = native.transport().unwrap().raw.local_addr().unwrap();
        {
            // Model a socket that has accepted none of its already sealed queue.
            let mut tx = native.tx.lock().unwrap();
            tx.packets.push_back(Packet {
                peer: sess.peer,
                wire: vec![0; QUEUE_LIMIT],
                ticket: 1,
            });
            tx.bytes = QUEUE_LIMIT;
            tx.appended = 1;
        }
        let mut halves = Conn {
            kind: ConnKind::Stream(sess.clone()),
        }
        .into_async();
        let wakes = Arc::new(Count::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut halves.write)
            .poll_write(&mut cx, b"pending")
            .is_pending());
        assert_eq!(sess.next_send.load(Ordering::Relaxed), 0);
        assert!(sess.send_window.lock().unwrap().flights.is_empty());
        let mut bytes = [0; 1];
        let mut read = ReadBuf::new(&mut bytes);
        assert!(Pin::new(&mut halves.read)
            .poll_read(&mut cx, &mut read)
            .is_pending());
        sess.link.close();
        assert!(wakes.0.load(Ordering::Relaxed) >= 2);
        assert!(native.tx.lock().unwrap().packets.is_empty());
        assert!(matches!(
            Pin::new(&mut halves.write).poll_write(&mut cx, b"pending"),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut halves.read).poll_read(&mut cx, &mut read),
            Poll::Ready(Ok(()))
        ));
        assert!(read.filled().is_empty());
        let rebound = UdpSocket::bind(address)
            .expect("closed listener releases its port even with live session handles");
        drop(rebound);
    }

    #[test]
    fn native_udp_stream_carries_backpressured_bidirectional_bytes() {
        let account = Account {
            username: "native-client".into(),
            password: "test-password".into(),
        };
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let (ready, incoming) = dispatch::channel(None);
        let server = serve_udp(
            socket,
            Arc::new(Mutex::new(vec![account.clone()])),
            1280,
            ready,
        )
        .unwrap();
        let client = Arc::new(
            connect_udp(
                address,
                &account,
                &Target {
                    host: "example.com".into(),
                    port: 443,
                },
            )
            .unwrap(),
        );
        let conn = incoming.recv_timeout(Duration::from_secs(3)).unwrap().conn;
        assert!(conn.supports_async());
        let mut halves = conn.into_async();
        let echo = halves.executor.clone().spawn(async move {
            tokio::time::timeout(Duration::from_secs(15), async {
                let mut bytes = vec![0; 32768];
                loop {
                    let n = halves.read.read(&mut bytes).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    halves.write.write_all(&bytes[..n]).await.unwrap();
                }
            })
            .await
            .unwrap();
        });
        let payload: Vec<_> = (0..4 * 1024 * 1024 + 39).map(|n| (n % 251) as u8).collect();
        let sent = payload.clone();
        let sender = client.clone();
        let writer = thread::spawn(move || sender.write_user(&sent).unwrap());
        let mut got = vec![0; payload.len()];
        let mut count = 0;
        while count < got.len() {
            count += client
                .read_for(&mut got[count..], Duration::from_secs(10))
                .unwrap();
        }
        assert_eq!(got, payload);
        writer.join().unwrap();
        client.close();
        udp_executor().unwrap().block_on(echo).unwrap();
        server.close();
        assert!(server.is_closed());
    }

    #[test]
    fn flush_waits_for_its_packets_without_waiting_for_later_sessions() {
        let (sess, _peer) = session();
        let runtime = udp_executor().unwrap();
        let _entered = runtime.enter();
        let native = sess.link.native.as_ref().unwrap();
        {
            let mut tx = native.tx.lock().unwrap();
            tx.packets.push_back(Packet {
                peer: sess.peer,
                wire: b"lead".to_vec(),
                ticket: 1,
            });
            tx.bytes = 4;
            tx.appended = 1;
        }
        let mut halves = Conn {
            kind: ConnKind::Stream(sess.clone()),
        }
        .into_async();
        let wakes = Arc::new(Count::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Pin::new(&mut halves.write).poll_write(&mut cx, b"own"),
            Poll::Ready(Ok(3))
        ));
        for _ in 0..32 {
            native
                .submit(sess.peer, |wire| {
                    wire.extend_from_slice(b"later");
                    Ok(())
                })
                .unwrap();
        }
        assert!(Pin::new(&mut halves.write).poll_flush(&mut cx).is_pending());
        assert!(
            !native.flush().unwrap(),
            "later sessions still have queued packets"
        );
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert!(matches!(
            Pin::new(&mut halves.write).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut halves.write).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut halves.write).poll_write(&mut cx, b"after EOF"),
            Poll::Ready(Err(_))
        ));
        sess.link.close();
    }
}
