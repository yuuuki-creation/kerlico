//! Readiness ownership for native plaintext and extracted-record TLS sessions.
//! Framing, authentication, cipher state and queues remain owned by session.rs.

use super::*;
use crate::tx::input::Input;
use crate::tx::{NativeBatch, TaskWaiter};
use kerlico_shared::{AsyncWriteInput, WriteInput};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

mod receive;
pub(super) use receive::read_target;
use receive::Reader;

pub(super) fn runtime() -> io::Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<io::Result<tokio::runtime::Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

pub(super) struct Native {
    pub(super) socket: tokio::net::TcpStream,
    pub(super) read_notify: Notify,
    owner_notify: Arc<Notify>,
    pub(super) space_notify: Arc<Notify>,
    write_notify: Notify,
    closed_notify: Notify,
    auth_deadline: Instant,
}

impl Native {
    pub(super) fn new(tcp: &TcpStream) -> io::Result<Self> {
        let auth_wait = tcp.read_timeout()?.unwrap_or(tls::HANDSHAKE_TIMEOUT);
        let socket = tcp.try_clone()?;
        socket.set_nonblocking(true)?;
        let _entered = runtime()?.enter();
        Ok(Self {
            socket: tokio::net::TcpStream::from_std(socket)?,
            read_notify: Notify::new(),
            owner_notify: Arc::new(Notify::new()),
            space_notify: Arc::new(Notify::new()),
            write_notify: Notify::new(),
            closed_notify: Notify::new(),
            auth_deadline: Instant::now() + auth_wait,
        })
    }
}

pub(super) fn start(inner: &Arc<Inner>) -> tokio::task::JoinHandle<io::Result<()>> {
    let writer = inner.clone();
    runtime()
        .expect("registered native runtime")
        .spawn(async move { writer_loop(writer).await });
    let reader = inner.clone();
    runtime()
        .expect("registered native runtime")
        .spawn(async move {
            let result = reader_loop(&reader).await;
            reader.close();
            result
        })
}

async fn reader_loop(inner: &Arc<Inner>) -> io::Result<()> {
    receive::background(inner).await
}

fn wake_tasks(tx: &mut Tx) {
    let first_room = tx
        .task_waiters
        .iter()
        .find(|w| w.end.is_none())
        .map(|w| w.ticket);
    let room = tx.pending() == 0 || tx.pending() < tx.rate.limit();
    for waiter in &mut tx.task_waiters {
        let ready = tx.dead.is_some()
            || waiter.end.is_some_and(|end| end <= tx.written)
            || (room && waiter.end.is_none() && Some(waiter.ticket) == first_room);
        if ready && !waiter.woken {
            waiter.woken = true;
            waiter.waker.wake_by_ref();
        }
    }
}

fn compact(tx: &mut Tx) {
    if !tx.out.is_empty() {
        let storage = std::mem::replace(&mut tx.out, std::mem::take(&mut tx.spare));
        let len = storage.len();
        tx.ready.push_back(NativeBatch {
            storage,
            len,
            owner: None,
            input: false,
        });
    }
}

fn flush_owned(inner: &Inner, tx: &mut Tx, owner: Option<u64>) -> io::Result<()> {
    compact(tx);
    let native = inner.native.as_ref().expect("native session");
    let mut turn = 0;
    if !tx.ready.is_empty() && tx.native_batch.is_none() {
        tx.native_batch = Some((Instant::now(), tx.written));
    }
    while let Some(front) = tx.ready.front() {
        if front.owner.is_some() && front.owner != owner {
            break;
        }
        if turn >= 256 * 1024 {
            break;
        }
        match native
            .socket
            .try_write(&front.storage[tx.native_head..front.len])
        {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                tx.native_head += n;
                tx.written += n as u64;
                turn += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
        if tx.native_head == front.len {
            let mut batch = tx.ready.pop_front().unwrap();
            tx.native_head = 0;
            if batch.input {
                if tx.input_pool.len() < 2 {
                    tx.input_pool.push(batch.storage);
                }
            } else {
                batch.storage.clear();
                if batch.storage.capacity() > tx.spare.capacity() {
                    tx.spare = batch.storage;
                }
            }
        }
    }
    tx.flushing = !tx.ready.is_empty();
    if !tx.flushing {
        if let Some((started, before)) = tx.native_batch.take() {
            tx.rate.record(tx.written - before, started.elapsed());
        }
    }
    wake_tasks(tx);
    Ok(())
}

fn flush(inner: &Inner, tx: &mut Tx) -> io::Result<()> {
    flush_owned(inner, tx, None)
}

fn wake_input_owner(tx: &mut Tx) -> bool {
    let Some(owner) = tx.ready.front().and_then(|batch| batch.owner) else {
        return false;
    };
    if let Some(waiter) = tx
        .task_waiters
        .iter_mut()
        .find(|waiter| waiter.ticket == owner)
    {
        waiter.woken = true;
        waiter.waker.wake_by_ref();
    }
    true
}

async fn writer_loop(inner: Arc<Inner>) {
    let native = inner.native.as_ref().expect("native session");
    loop {
        native.write_notify.notified().await;
        if inner.lock_tx().dead.is_some() {
            inner.close();
        }
        if inner.closed.load(Ordering::Acquire) {
            break;
        }
        loop {
            let result = {
                let mut tx = inner.lock_tx();
                flush(&inner, &mut tx).map(|_| tx.pending() == 0)
            };
            match result {
                Ok(true) => break,
                Err(_) => {
                    inner.close();
                    break;
                }
                Ok(false) => {}
            }
            let closed = native.closed_notify.notified();
            tokio::pin!(closed);
            closed.as_mut().enable();
            if inner.closed.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                result = native.socket.writable() => { if result.is_err() { inner.close(); break; } },
                _ = &mut closed => break,
            }
            // Never complete an application batch on this helper. Its task
            // must report the completion to outbound in the same poll.
            if wake_input_owner(&mut inner.lock_tx()) {
                break;
            }
            tokio::task::yield_now().await;
        }
        if inner.closed.load(Ordering::Acquire) {
            break;
        }
    }
    // Preserve the existing best-effort one-second close drain without ever
    // blocking the executor or a different session's control messages.
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let done = {
                let mut tx = inner.lock_tx();
                if tx.ready.front().is_some_and(|batch| batch.owner.is_some()) {
                    return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
                }
                flush(&inner, &mut tx).map(|_| tx.pending() == 0)
            }?;
            if done {
                return Ok::<_, io::Error>(());
            }
            native.socket.writable().await?;
        }
    })
    .await;
    let _ = inner.tcp.shutdown(Shutdown::Both);
    if let Some(hook) = inner.on_close.lock().expect("hook").take() {
        hook();
    }
}

pub(super) fn close(inner: &Arc<Inner>) {
    let native = inner.native.as_ref().expect("native session");
    {
        let mut tx = inner.lock_tx();
        if tx.dead.is_none() && !tx.flushing {
            compact(&mut tx);
            let _ = tx.put(Out::CloseNotify, &inner.padding, &inner.kernel);
        }
        tx.dead = Some(io::ErrorKind::NotConnected);
        wake_tasks(&mut tx);
    }
    let streams: Vec<_> = inner
        .streams
        .lock()
        .expect("streams")
        .drain()
        .map(|(_, core)| core)
        .collect();
    for core in streams {
        core.finish(None);
    }
    native.closed_notify.notify_waiters();
    native.read_notify.notify_one();
    native.write_notify.notify_one();
}

struct SendState {
    owner: Weak<Inner>,
    ticket: Option<u64>,
    end: Option<u64>,
}

impl SendState {
    fn new(inner: &Arc<Inner>) -> Self {
        Self {
            owner: Arc::downgrade(inner),
            ticket: None,
            end: None,
        }
    }
    fn remove(&mut self, tx: &mut Tx) {
        if let Some(ticket) = self.ticket.take() {
            tx.task_waiters.retain(|w| w.ticket != ticket);
        }
        self.end = None;
        wake_tasks(tx);
    }
    fn register(&mut self, tx: &mut Tx, cx: &Context<'_>) {
        let ticket = *self.ticket.get_or_insert_with(|| tx.ticket());
        if let Some(waiter) = tx.task_waiters.iter_mut().find(|w| w.ticket == ticket) {
            waiter.end = self.end;
            waiter.waker.clone_from(cx.waker());
            waiter.woken = false;
        } else {
            tx.task_waiters.push_back(TaskWaiter {
                ticket,
                end: self.end,
                waker: cx.waker().clone(),
                woken: false,
            });
        }
    }
}

impl Drop for SendState {
    fn drop(&mut self) {
        if self.ticket.is_some() {
            if let Some(inner) = self.owner.upgrade() {
                self.remove(&mut inner.lock_tx());
            }
        }
    }
}

fn poll_submit(
    inner: &Arc<Inner>,
    state: &mut SendState,
    cx: &mut Context<'_>,
    item: Out<'_>,
) -> Poll<io::Result<()>> {
    let mut tx = inner.lock_tx();
    if state.end.is_some_and(|end| tx.written >= end) {
        state.remove(&mut tx);
        return Poll::Ready(Ok(()));
    }
    if tx.dead.is_some() {
        state.remove(&mut tx);
        return Poll::Ready(Err(closed_error()));
    }
    if state.end.is_none() {
        let first = tx
            .task_waiters
            .iter()
            .find(|w| w.end.is_none())
            .map(|w| w.ticket);
        let room = tx.pending() == 0 || tx.pending() < tx.rate.limit();
        if !room || (first.is_some() && first != state.ticket) {
            state.register(&mut tx, cx);
            return Poll::Pending;
        }
        if let Some(ticket) = state.ticket {
            tx.task_waiters.retain(|w| w.ticket != ticket);
        }
        compact(&mut tx);
        let result = tx.put(item, &inner.padding, &inner.kernel);
        match result {
            Ok(0) => {
                state.remove(&mut tx);
                return Poll::Ready(Ok(()));
            }
            Ok(_) => state.end = Some(tx.appended),
            Err(error) => {
                tx.dead = Some(error.kind());
                state.remove(&mut tx);
                drop(tx);
                inner.close();
                return Poll::Ready(Err(error));
            }
        }
    }
    if let Err(error) = flush(inner, &mut tx) {
        tx.dead = Some(error.kind());
        state.remove(&mut tx);
        drop(tx);
        inner.close();
        return Poll::Ready(Err(error));
    }
    if state.end.is_some_and(|end| tx.written >= end) {
        state.remove(&mut tx);
        Poll::Ready(Ok(()))
    } else {
        state.register(&mut tx, cx);
        inner.native.as_ref().unwrap().write_notify.notify_one();
        Poll::Pending
    }
}

pub(super) fn submit(inner: &Arc<Inner>, item: Out<'_>, sync: bool) -> io::Result<()> {
    if sync {
        let mut state = SendState::new(inner);
        return runtime()?.block_on(std::future::poll_fn(|cx| {
            poll_submit(inner, &mut state, cx, item)
        }));
    }
    let mut tx = inner.lock_tx();
    if tx.dead.is_some() {
        return Err(closed_error());
    }
    compact(&mut tx);
    let result = tx.put(item, &inner.padding, &inner.kernel).and_then(|n| {
        if n == 0 {
            Ok(())
        } else {
            flush(inner, &mut tx)
        }
    });
    if let Err(error) = result {
        tx.dead = Some(error.kind());
        wake_tasks(&mut tx);
        drop(tx);
        // A parser can enqueue a control frame while holding a stream lock.
        // Let the I/O owner close after those locks have been released.
        inner.native.as_ref().unwrap().write_notify.notify_one();
        return Err(error);
    }
    if tx.flushing {
        inner.native.as_ref().unwrap().write_notify.notify_one();
    }
    Ok(())
}

struct Writer {
    stream: Arc<Stream>,
    state: SendState,
    accepted: usize,
    input: Option<Input>,
}

impl Writer {
    fn relinquish(&mut self) {
        if let Some(ticket) = self.state.ticket {
            let mut tx = self.stream.session.lock_tx();
            for batch in &mut tx.ready {
                if batch.owner == Some(ticket) {
                    batch.owner = None;
                }
            }
            self.state.remove(&mut tx);
            self.stream
                .session
                .native
                .as_ref()
                .unwrap()
                .write_notify
                .notify_one();
        }
        if let Some(input) = &mut self.input {
            input.filled = 0;
        }
        self.accepted = 0;
    }
}

fn poll_input_send(
    inner: &Arc<Inner>,
    sid: u32,
    state: &mut SendState,
    input: &mut Input,
    cx: &mut Context<'_>,
) -> Poll<io::Result<usize>> {
    let mut tx = inner.lock_tx();
    if state.end.is_some_and(|end| tx.written >= end) {
        let n = input.filled;
        input.recycle(tx.input_pool.pop().unwrap_or_default());
        state.remove(&mut tx);
        if tx.flushing {
            inner.native.as_ref().unwrap().write_notify.notify_one();
        }
        return Poll::Ready(Ok(n));
    }
    if tx.dead.is_some() {
        state.remove(&mut tx);
        return Poll::Ready(Err(closed_error()));
    }
    if state.end.is_none() {
        let first = tx
            .task_waiters
            .iter()
            .find(|w| w.end.is_none())
            .map(|w| w.ticket);
        let room = tx.pending() == 0 || tx.pending() < tx.rate.limit();
        if !room || (first.is_some() && first != state.ticket) {
            state.register(&mut tx, cx);
            return Poll::Pending;
        }
        let ticket = *state.ticket.get_or_insert_with(|| tx.ticket());
        compact(&mut tx);
        match tx.seal_input(sid, input, &inner.kernel) {
            Ok(encoded) => {
                // Any required KeyUpdate was sealed first by the same cipher.
                compact(&mut tx);
                tx.ready.push_back(NativeBatch {
                    storage: encoded.storage,
                    len: encoded.len,
                    owner: Some(ticket),
                    input: true,
                });
                state.end = Some(tx.appended);
            }
            Err(error) => {
                tx.dead = Some(error.kind());
                state.remove(&mut tx);
                drop(tx);
                inner.close();
                return Poll::Ready(Err(error));
            }
        }
    }
    if let Err(error) = flush_owned(inner, &mut tx, state.ticket) {
        tx.dead = Some(error.kind());
        state.remove(&mut tx);
        drop(tx);
        inner.close();
        return Poll::Ready(Err(error));
    }
    if state.end.is_some_and(|end| tx.written >= end) {
        let n = input.filled;
        input.recycle(tx.input_pool.pop().unwrap_or_default());
        state.remove(&mut tx);
        if tx.flushing {
            inner.native.as_ref().unwrap().write_notify.notify_one();
        }
        Poll::Ready(Ok(n))
    } else {
        state.register(&mut tx, cx);
        inner.native.as_ref().unwrap().write_notify.notify_one();
        Poll::Pending
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(input) = &mut this.input {
            if input.filled == 0 {
                if this.stream.core.local_closed.load(Ordering::Acquire)
                    || this.stream.core.remote_closed.load(Ordering::Acquire)
                {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                if bytes.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                this.accepted = input.copy_from(bytes);
            }
            if bytes.len() < this.accepted {
                return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
            }
            return poll_input_send(
                &this.stream.session,
                this.stream.core.sid,
                &mut this.state,
                input,
                cx,
            );
        }
        if this.stream.core.local_closed.load(Ordering::Acquire)
            || this.stream.core.remote_closed.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.state.end.is_none() {
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let tx = this.stream.session.lock_tx();
            let limit = if tx.send_padding {
                bytes.len()
            } else {
                (tx.rate.limit() as usize / MAX_DATA).max(1) * MAX_DATA
            };
            this.accepted = bytes.len().min(limit);
        }
        if bytes.len() < this.accepted {
            this.stream.close();
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let item = Out::Frames {
            cmd: CMD_PSH,
            sid: this.stream.core.sid,
            data: &bytes[..this.accepted],
        };
        std::task::ready!(poll_submit(&this.stream.session, &mut this.state, cx, item))?;
        Poll::Ready(Ok(this.accepted))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.relinquish();
        this.stream.close(); // AnyTLS FIN ends both directions.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWriteInput for Writer {
    fn poll_input(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<WriteInput<'_>>> {
        let this = self.get_mut();
        if this.stream.core.local_closed.load(Ordering::Acquire)
            || this.stream.core.remote_closed.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let input = this.input.as_mut().ok_or(io::ErrorKind::Unsupported)?;
        Poll::Ready(Ok(input.borrow()))
    }

    fn poll_send_input(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.state.end.is_none()
            && (this.stream.core.local_closed.load(Ordering::Acquire)
                || this.stream.core.remote_closed.load(Ordering::Acquire))
        {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let input = this.input.as_mut().ok_or(io::ErrorKind::Unsupported)?;
        poll_input_send(
            &this.stream.session,
            this.stream.core.sid,
            &mut this.state,
            input,
            cx,
        )
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // A caller abandoning a write cannot remove already sealed records:
        // the other streams still need the session's exact sequence. Hand the
        // finite queued batch back before appending this stream's FIN.
        self.relinquish();
        self.stream.close();
    }
}

pub(super) fn stream(stream: Stream) -> kerlico_shared::AsyncTcp {
    assert!(stream.supports_async());
    let state = SendState::new(&stream.session);
    let input = if stream.session.role == Role::Server {
        stream.session.lock_tx().input_format().map(Input::new)
    } else {
        None
    };
    let stream = Arc::new(stream);
    let writer = Writer {
        stream: stream.clone(),
        state,
        accepted: 0,
        input,
    };
    let write = if writer.input.is_some() {
        kerlico_shared::AsyncWriteHalf::Input(Box::new(writer))
    } else {
        kerlico_shared::AsyncWriteHalf::plain(writer)
    };
    kerlico_shared::AsyncTcp {
        executor: runtime()
            .expect("registered native runtime")
            .handle()
            .clone(),
        read: kerlico_shared::AsyncReadHalf::Vectored(Box::new(Reader::new(stream.clone()))),
        write,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Accept {
        opened: mpsc::Sender<Opened>,
        password: [u8; 32],
    }
    impl Inbound for Accept {
        fn authenticate(&self, hash: &[u8; 32]) -> bool {
            hash == &self.password
        }
        fn open(&self, opened: Opened) {
            self.opened.send(opened).unwrap();
        }
    }

    fn sessions() -> (Session, mpsc::Receiver<Opened>, mpsc::Receiver<()>) {
        let (client, server) = crate::tests::pair();
        let password = crate::password_hash("native-session-test");
        let (opened, accept) = mpsc::channel();
        let (closed, closing) = mpsc::channel();
        Session::serve_detached(
            server,
            SchemeCell::new(crate::Scheme::default_scheme()),
            Arc::new(Accept { opened, password }),
            Box::new(move || {
                let _ = closed.send(());
            }),
        )
        .unwrap();
        let client = Session::client(
            client,
            SchemeCell::new(crate::Scheme::default_scheme()),
            "native-test",
            &password,
        )
        .unwrap();
        (client, accept, closing)
    }

    #[test]
    fn authenticated_backpressure_resumes_the_same_record_and_detached_session_stays_registered() {
        let (client, accept, closing) = sessions();
        let outgoing = client.open_stream().unwrap();
        let mut target = Vec::new();
        Target::new("example.com", 443)
            .encode(Family::Socks, &mut target)
            .unwrap();
        outgoing.write(&target).unwrap();
        let Flow::Tcp(incoming) = accept.recv_timeout(Duration::from_secs(3)).unwrap().flow else {
            panic!("TCP");
        };
        assert!(incoming.supports_async());
        assert!(
            closing.try_recv().is_err(),
            "detaching must retain the physical session registration"
        );
        let core = incoming.core.clone();
        let session = incoming.session.clone();
        let mut transferred = incoming.into_async();
        let payload: Vec<_> = (0..3 * STREAM_RX_LIMIT + 177)
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = payload.clone();
        let producer = thread::spawn(move || {
            outgoing.write(&payload).unwrap();
            let mut response = [0; 3];
            let mut pos = 0;
            while pos < response.len() {
                pos += outgoing
                    .read_for(&mut response[pos..], Duration::from_secs(5))
                    .unwrap();
            }
            assert_eq!(&response, b"ack");
            outgoing.close();
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let rx = core.rx.lock().unwrap();
            assert!(rx.queue.len() <= STREAM_RX_LIMIT);
            if rx.reader_waiting {
                break;
            }
            drop(rx);
            assert!(
                Instant::now() < deadline,
                "receive queue never applied backpressure"
            );
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            session
                .rx
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|side| side.pending.is_some()),
            "the authenticated PSH remainder is retained"
        );
        runtime().unwrap().block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut read = transferred.read.into_buffered(64 * 1024);
                let mut got = vec![0; expected.len()];
                read.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expected);
                transferred.write.write_all(b"ack").await.unwrap();
                let mut tail = Vec::new();
                read.read_to_end(&mut tail).await.unwrap();
                assert!(tail.is_empty());
            })
            .await
            .unwrap();
        });
        producer.join().unwrap();
        assert!(
            closing.try_recv().is_err(),
            "closing one stream must retain a reusable session"
        );
        client.close();
        closing.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn unauthenticated_native_session_expires_without_a_blocked_accept_thread() {
        let (_client, server) = crate::tests::pair();
        server
            .tcp
            .set_read_timeout(Some(Duration::from_millis(40)))
            .unwrap();
        let (opened, _) = mpsc::channel();
        let (closed, closing) = mpsc::channel();
        Session::serve_detached(
            server,
            SchemeCell::new(crate::Scheme::default_scheme()),
            Arc::new(Accept {
                opened,
                password: [7; 32],
            }),
            Box::new(move || {
                let _ = closed.send(());
            }),
        )
        .unwrap();
        closing.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn asynchronous_writes_resume_after_backpressure_and_wake_when_the_peer_closes() {
        use socket2::SockRef;
        for cancel in [false, true] {
            let (client, accept, closing) = sessions();
            let outgoing = client.open_stream().unwrap();
            let mut target = Vec::new();
            Target::new("example.com", 443)
                .encode(Family::Socks, &mut target)
                .unwrap();
            outgoing.write(&target).unwrap();
            let Flow::Tcp(incoming) = accept.recv_timeout(Duration::from_secs(3)).unwrap().flow
            else {
                panic!("TCP");
            };
            let server = incoming.session();
            SockRef::from(&server.inner.tcp)
                .set_send_buffer_size(4096)
                .unwrap();
            SockRef::from(&client.inner.tcp)
                .set_recv_buffer_size(4096)
                .unwrap();
            let transferred = incoming.into_async();
            let mut read = transferred.read.into_buffered(64 * 1024);
            let mut write = transferred.write;
            let payload: Vec<_> = (0..4 * STREAM_RX_LIMIT + 333)
                .map(|i| (i % 251) as u8)
                .collect();
            runtime().unwrap().block_on(async {
                tokio::time::timeout(Duration::from_secs(12), async {
                    // Keep this very same operation alive after the timeout;
                    // starting write_all again could resend an accepted prefix.
                    let pending = write.write_all(&payload);
                    tokio::pin!(pending);
                    assert!(
                        tokio::time::timeout(Duration::from_millis(40), &mut pending)
                            .await
                            .is_err()
                    );
                    if cancel {
                        client.close();
                        assert!(pending.await.is_err());
                        return;
                    }
                    SockRef::from(&server.inner.tcp)
                        .set_send_buffer_size(256 * 1024)
                        .unwrap();
                    SockRef::from(&client.inner.tcp)
                        .set_recv_buffer_size(256 * 1024)
                        .unwrap();
                    let expected = payload.clone();
                    let consumer = thread::spawn(move || {
                        let mut got = vec![0; expected.len()];
                        let mut pos = 0;
                        while pos < got.len() {
                            let n = outgoing
                                .read_for(&mut got[pos..], Duration::from_secs(5))
                                .unwrap();
                            assert!(n > 0);
                            pos += n;
                        }
                        assert_eq!(got, expected);
                        outgoing.write(b"ack").unwrap();
                        let mut tail = [0];
                        assert_eq!(
                            outgoing
                                .read_for(&mut tail, Duration::from_secs(5))
                                .unwrap(),
                            0
                        );
                    });
                    pending.await.unwrap();
                    let mut ack = [0; 3];
                    read.read_exact(&mut ack).await.unwrap();
                    assert_eq!(&ack, b"ack");
                    write.shutdown().await.unwrap();
                    consumer.join().unwrap();
                    client.close();
                })
                .await
                .unwrap();
            });
            drop(write);
            drop(read);
            assert!(server.inner.lock_tx().task_waiters.is_empty());
            closing.recv_timeout(Duration::from_secs(2)).unwrap();
        }
    }

    #[test]
    fn cancel_then_shutdown_releases_the_batch_while_the_writer_handle_stays_alive() {
        use socket2::SockRef;
        let (client, accept, closing) = sessions();
        let open = || {
            let outgoing = client.open_stream().unwrap();
            let mut target = Vec::new();
            Target::new("example.com", 443)
                .encode(Family::Socks, &mut target)
                .unwrap();
            outgoing.write(&target).unwrap();
            let Flow::Tcp(incoming) = accept.recv_timeout(Duration::from_secs(3)).unwrap().flow
            else {
                panic!("TCP")
            };
            (outgoing, incoming)
        };
        let (first, incoming) = open();
        let server = incoming.session();
        let (_first_read, mut first_write) = {
            let halves = incoming.into_async();
            (halves.read, halves.write)
        };
        let (second, incoming) = open();
        let second_halves = incoming.into_async();
        let mut second_write = second_halves.write;
        SockRef::from(&server.inner.tcp)
            .set_send_buffer_size(4096)
            .unwrap();
        SockRef::from(&client.inner.tcp)
            .set_recv_buffer_size(4096)
            .unwrap();
        let payload: Vec<u8> = (0..4 * STREAM_RX_LIMIT).map(|i| (i % 251) as u8).collect();
        runtime().unwrap().block_on(async {
            tokio::time::timeout(Duration::from_secs(8), async {
                // This timeout drops the write future, not the writer. A later
                // shutdown must release its ticket even if the handle is kept.
                assert!(tokio::time::timeout(
                    Duration::from_millis(40),
                    first_write.write_all(&payload)
                )
                .await
                .is_err());
                first_write.shutdown().await.unwrap();
                SockRef::from(&server.inner.tcp)
                    .set_send_buffer_size(256 * 1024)
                    .unwrap();
                SockRef::from(&client.inner.tcp)
                    .set_recv_buffer_size(256 * 1024)
                    .unwrap();
                let expected = payload.clone();
                let first_reader = thread::spawn(move || {
                    let mut buf = vec![0; 64 * 1024];
                    let mut got = Vec::new();
                    loop {
                        let n = first.read_for(&mut buf, Duration::from_secs(3)).unwrap();
                        if n == 0 {
                            break;
                        }
                        got.extend_from_slice(&buf[..n]);
                    }
                    assert!(!got.is_empty());
                    assert_eq!(got, expected[..got.len()]);
                });
                let second_reader = thread::spawn(move || {
                    let mut got = [0; 5];
                    let mut at = 0;
                    while at < got.len() {
                        let n = second
                            .read_for(&mut got[at..], Duration::from_secs(3))
                            .unwrap();
                        assert!(n > 0);
                        at += n;
                    }
                    assert_eq!(&got, b"alive");
                });
                second_write.write_all(b"alive").await.unwrap();
                first_reader.join().unwrap();
                second_reader.join().unwrap();
            })
            .await
            .unwrap();
        });
        assert!(
            closing.try_recv().is_err(),
            "a canceled flow must not end other streams' session"
        );
        drop(first_write);
        drop(second_write);
        drop(second_halves.read);
        drop(_first_read);
        client.close();
        closing.recv_timeout(Duration::from_secs(2)).unwrap();
    }
}
