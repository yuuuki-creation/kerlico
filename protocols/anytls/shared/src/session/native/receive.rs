//! The consumer owns the receive state while plaintext is lent to outbound.
//! The idle task uses the same parser only when no consumer is reading.

use super::*;
use std::future::Future;
use tokio::io::AsyncBufRead;
use tokio::sync::futures::OwnedNotified;

type ReadyWait = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct State {
    inner: Arc<Inner>,
    core: Arc<Core>,
    ticket: u64,
    side: Option<RxSide>,
    direct: Direct,
    first: usize,
    head: usize,
    fallback: Vec<u8>,
    queued: std::ops::Range<usize>,
    io_wait: Option<ReadyWait>,
    owner_wait: Option<Pin<Box<OwnedNotified>>>,
    space_wait: Option<Pin<Box<OwnedNotified>>>,
    terminal: bool,
    limit: usize,
    active: bool,
}

impl State {
    fn new(stream: &Stream, limit: usize) -> Self {
        let mut rx = stream.core.rx.lock().expect("rx");
        rx.next_task_reader = rx.next_task_reader.wrapping_add(1);
        let ticket = rx.next_task_reader;
        drop(rx);
        Self {
            inner: stream.session.clone(),
            core: stream.core.clone(),
            ticket,
            side: None,
            direct: Direct::none(),
            first: 0,
            head: 0,
            fallback: Vec::new(),
            queued: 0..0,
            io_wait: None,
            owner_wait: None,
            space_wait: None,
            terminal: false,
            limit,
            active: false,
        }
    }

    fn release(&mut self) {
        if let Some(side) = self.side.take() {
            let mut slot = self.inner.rx.lock().expect("receive lease");
            assert!(slot.is_none());
            *slot = Some(side);
            drop(slot);
            self.inner
                .native
                .as_ref()
                .unwrap()
                .owner_notify
                .notify_one();
        }
    }

    fn queued(&mut self, stream: &Stream, cx: &Context<'_>) -> Option<io::Result<usize>> {
        let mut rx = self.core.rx.lock().expect("rx");
        let n = rx.queue.len().min(self.limit);
        if self.fallback.len() < n {
            self.fallback.resize(n, 0);
        }
        let result = stream.take(&mut rx, &mut self.fallback[..n]);
        if result.is_some() {
            rx.task_readers.retain(|(id, _)| *id != self.ticket);
        } else if let Some((_, waker)) = rx
            .task_readers
            .iter_mut()
            .find(|(id, _)| *id == self.ticket)
        {
            waker.clone_from(cx.waker());
        } else {
            rx.task_readers.push((self.ticket, cx.waker().clone()));
        }
        result
    }

    fn poll(&mut self, stream: &Stream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.active {
            self.core.start_reading(&self.inner);
            self.inner.present.fetch_add(1, Ordering::AcqRel);
            self.inner.mark_lead();
            self.active = true;
        }
        if self.first < self.direct.count || !self.queued.is_empty() {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..8 {
            if let Some(result) = self.queued(stream, cx) {
                self.queued = 0..result?;
                return Poll::Ready(Ok(()));
            }
            if self.inner.closed.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }
            let native = self.inner.native.as_ref().unwrap();
            self.space_wait
                .get_or_insert_with(|| Box::pin(native.space_notify.clone().notified_owned()))
                .as_mut()
                .enable();
            if self.side.is_none() {
                // Register first: returning a lease before this task sleeps
                // must not lose the notification.
                let wait = self
                    .owner_wait
                    .get_or_insert_with(|| Box::pin(native.owner_notify.clone().notified_owned()));
                wait.as_mut().enable();
                self.side = self.inner.rx.lock().expect("receive lease").take();
                if self.side.is_none() {
                    if wait.as_mut().poll(cx).is_ready() {
                        self.owner_wait = None;
                        continue;
                    }
                    return Poll::Pending;
                }
                self.owner_wait = None;
            }
            let side = self.side.as_mut().unwrap();
            if side.ended {
                self.release();
                self.inner.close();
                continue;
            }
            self.direct = Direct::reader(self.core.sid, self.limit);
            let result = pump(&self.inner, side, &mut self.direct).and_then(|alive| {
                if alive && self.direct.bytes != 0 && !self.direct.blocked {
                    append_ready(&self.inner, side, &mut self.direct)
                } else {
                    Ok(alive)
                }
            });
            self.terminal = !matches!(result, Ok(true));
            side.ended |= self.terminal;
            if self.direct.bytes != 0 {
                self.first = 0;
                self.head = 0;
                self.io_wait = None;
                return Poll::Ready(Ok(()));
            }
            let blocked = self.direct.blocked;
            let needs_read = self.direct.needs_read;
            self.release();
            // An address/early-data fragment can have queued a valid prefix.
            // Deliver it before terminating this session on a later error.
            if let Some(result) = self.queued(stream, cx) {
                self.queued = 0..result?;
                if !self.queued.is_empty() {
                    return Poll::Ready(Ok(()));
                }
            }
            if self.terminal {
                self.inner.close();
                return Poll::Ready(Ok(()));
            }
            if blocked {
                if self
                    .space_wait
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .poll(cx)
                    .is_ready()
                {
                    self.space_wait = None;
                    continue;
                }
                return Poll::Pending;
            }
            self.space_wait = None;
            if needs_read {
                let inner = self.inner.clone();
                let wait = self.io_wait.get_or_insert_with(|| {
                    Box::pin(async move { inner.native.as_ref().unwrap().socket.readable().await })
                });
                match wait.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        self.io_wait = None;
                        result?;
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn slices<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        if !self.queued.is_empty() {
            out[0] = IoSlice::new(&self.fallback[self.queued.clone()]);
            return 1;
        }
        let Some(side) = &self.side else {
            return 0;
        };
        let n = (self.direct.count - self.first).min(out.len());
        for (i, part) in out[..n].iter_mut().enumerate() {
            let mut range = self.direct.ranges[self.first + i].clone();
            if i == 0 {
                range.start += self.head;
            }
            *part = IoSlice::new(&side.reader.buf[range]);
        }
        n
    }

    fn consume(&mut self, mut n: usize) {
        if !self.queued.is_empty() {
            assert!(n <= self.queued.len());
            self.queued.start += n;
            if !self.queued.is_empty() {
                return;
            }
        } else {
            while n != 0 {
                let part = &self.direct.ranges[self.first];
                let used = n.min(part.len() - self.head);
                self.head += used;
                n -= used;
                if self.head == part.len() {
                    self.first += 1;
                    self.head = 0;
                }
            }
            if self.first < self.direct.count {
                return;
            }
            self.direct.count = 0;
            self.first = 0;
            self.release();
        }
        if self.terminal {
            self.inner.close();
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.release();
        self.core
            .rx
            .lock()
            .expect("rx")
            .task_readers
            .retain(|(id, _)| *id != self.ticket);
        if self.active {
            self.inner.mark_lead();
            self.inner.present.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Append only currently readable wire bytes before any slice is lent. Existing
/// authenticated ranges stay at the same offsets; never compact over them.
fn append_ready(inner: &Arc<Inner>, side: &mut RxSide, direct: &mut Direct) -> io::Result<bool> {
    while direct.count < DIRECT_PARTS && direct.bytes < direct.limit && !direct.blocked {
        let reader = &mut side.reader;
        if reader.end == reader.buf.len() {
            if reader.buf.len() >= RX_BUF_MAX {
                break;
            }
            reader.buf.resize((reader.buf.len() * 2).min(RX_BUF_MAX), 0);
        }
        let from = reader.end;
        let n = match inner.read_socket(&mut reader.buf[from..]) {
            Ok(0) => return Ok(false),
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        reader.end += n;
        let alive = if reader.cipher.is_some() {
            process(inner, side, direct)?
        } else {
            side.pending = Some(from..from + n);
            pending_plain(inner, side, direct)?
        };
        if !alive {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) struct Reader {
    stream: Arc<Stream>,
    state: State,
}

impl Reader {
    pub(super) fn new(stream: Arc<Stream>) -> Self {
        Self {
            state: State::new(&stream, RX_BUF_MAX),
            stream,
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        std::task::ready!(this.state.poll(&this.stream, cx))?;
        let mut parts = [IoSlice::new(&[]); DIRECT_PARTS];
        let count = this.state.slices(&mut parts);
        let mut used = 0;
        for part in &parts[..count] {
            let n = part.len().min(out.remaining());
            out.put_slice(&part[..n]);
            used += n;
            if out.remaining() == 0 {
                break;
            }
        }
        this.state.consume(used);
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for Reader {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        std::task::ready!(this.state.poll(&this.stream, cx))?;
        if !this.state.queued.is_empty() {
            return Poll::Ready(Ok(&this.state.fallback[this.state.queued.clone()]));
        }
        let state = &this.state;
        let Some(side) = &state.side else {
            return Poll::Ready(Ok(&[]));
        };
        if state.first == state.direct.count {
            return Poll::Ready(Ok(&[]));
        }
        let range = &state.direct.ranges[state.first];
        Poll::Ready(Ok(&side.reader.buf[range.start + state.head..range.end]))
    }
    fn consume(self: Pin<&mut Self>, n: usize) {
        self.get_mut().state.consume(n);
    }
}

impl kerlico_shared::AsyncBufReadVectored for Reader {
    fn poll_fill_buf_vectored<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
        out: &mut [IoSlice<'a>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.state.poll(&this.stream, cx))?;
        Poll::Ready(Ok(this.state.slices(out)))
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.stream.close();
    }
}

pub(in crate::session) fn read_target(
    stream: &Stream,
    target: &mut ReadTarget<'_>,
    wait: Duration,
) -> io::Result<usize> {
    let mut state = State::new(stream, target.buffer().len());
    runtime()?.block_on(async {
        tokio::time::timeout(wait, std::future::poll_fn(|cx| state.poll(stream, cx)))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    })?;
    let mut parts = [IoSlice::new(&[]); DIRECT_PARTS];
    let count = state.slices(&mut parts);
    let n = parts[..count].iter().map(|part| part.len()).sum();
    target.direct(&parts[..count]);
    state.consume(n);
    Ok(n)
}

pub(super) async fn background(inner: &Arc<Inner>) -> io::Result<()> {
    let native = inner.native.as_ref().unwrap();
    loop {
        let closed = native.closed_notify.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        if inner.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(wait) = inner.background_wait() {
            tokio::select! { _ = tokio::time::sleep(wait) => {}, _ = native.read_notify.notified() => {}, _ = closed => return Ok(()) }
            continue;
        }
        let owner = native.owner_notify.notified();
        tokio::pin!(owner);
        owner.as_mut().enable();
        let space = native.space_notify.notified();
        tokio::pin!(space);
        space.as_mut().enable();
        let side = inner.rx.lock().expect("idle receive owner").take();
        let Some(mut side) = side else {
            tokio::select! { _ = owner => {}, _ = closed => return Ok(()) }
            continue;
        };
        let mut direct = Direct::none();
        let result = if side.ended {
            Ok(false)
        } else {
            pump(inner, &mut side, &mut direct)
        };
        side.ended |= !matches!(result, Ok(true));
        let authenticating = side.parser.auth.is_some();
        *inner.rx.lock().expect("idle receive owner") = Some(side);
        native.owner_notify.notify_one();
        if !result? {
            return Ok(());
        }
        if authenticating && Instant::now() >= native.auth_deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if direct.blocked {
            tokio::select! { _ = space => {}, _ = closed => return Ok(()) }
        } else if direct.needs_read {
            tokio::select! {
                ready = native.socket.readable() => { ready?; },
                _ = native.read_notify.notified() => {},
                _ = closed => return Ok(()),
                _ = tokio::time::sleep_until(native.auth_deadline.into()), if authenticating => return Err(io::ErrorKind::TimedOut.into()),
            }
        } else {
            tokio::task::yield_now().await;
        }
    }
}
