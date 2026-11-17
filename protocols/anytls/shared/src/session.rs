//! One AnyTLS session: a TLS connection carrying many streams.
//!
//! Native record/plaintext sessions run on a shared readiness executor and
//! lend async stream halves to outbound. Library-wrapped transports retain
//! synchronous ownership. Both use the parser, cipher, padding and queues below.
//!
//! For the synchronous carrier, one thread at a time holds the receive side: it reads the socket, opens every record where it
//! was read and hands each frame's bytes to the stream it names, waking that stream's reader only
//! if it is waiting. A stream reader with nothing queued takes the receive side itself when it is
//! free, so a session with one busy stream reads without a thread switch; the session's own thread reads only while no stream reader has asked
//! for data in the last 100 ms. Writers frame their
//! bytes straight into TLS records in a shared buffer. Whoever finds the socket idle writes the
//! whole buffer in one call; the others wait their turn, and the one whose bytes are still queued
//! when the writer finishes takes over. The reading thread never writes to the socket: its few
//! frames (SYNACK, heartbeat replies, settings answers) go to a helper thread when nobody else is
//! writing.

use std::collections::HashMap;
use std::io::{self, IoSlice, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread;
use std::time::{Duration, Instant};
use std::task::Waker;

mod native;

use kerlico_shared::DatagramSession;

use crate::addr::{Family, Target, UOT_V1, UOT_V2};
use crate::frame::{
    self, CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS,
    CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, HEADER, MAX_DATA,
};
use crate::padding::{go_atoi, string_map, SchemeCell};
use crate::queue::ByteQueue;
use crate::tls::{self, Cipher, Control, Established, Kernel, TransportWrite, Wire, CONTENT_APPDATA, MAX_CIPHERTEXT, RX_BUF_MAX};
use crate::tx::{Out, Tx, Waiter};

/// Bytes one stream may hold unread before the reading thread waits for it, which stalls the
/// session as mihomo's synchronous pipe does, only later.
pub const STREAM_RX_LIMIT: usize = 1 << 20;
/// Datagrams one UDP destination may hold unread; later ones are dropped.
pub const LEG_RX_LIMIT: usize = 256 << 10;
/// mihomo closes a reused session when the server does not answer a SYN within this time.
pub const SYNACK_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

/// What a server session reports to its listener.
pub trait Inbound: Send + Sync {
    /// The SHA-256 of a password, from the first bytes of the connection.
    fn authenticate(&self, hash: &[u8; 32]) -> bool;
    /// A stream named its target, or a UDP-over-TCP stream reached a new destination.
    fn open(&self, opened: Opened);
}

pub struct Opened {
    pub user: [u8; 32],
    pub peer: SocketAddr,
    pub target: Target,
    pub flow: Flow,
}

pub enum Flow {
    Tcp(Stream),
    Udp(Leg),
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "anytls session closed")
}

struct Inner {
    role: Role,
    tcp: TcpStream,
    library_write: Option<Mutex<Box<dyn TransportWrite>>>,
    tx: Mutex<Tx>,
    helper_cv: Condvar,
    streams: Mutex<HashMap<u32, Arc<Core>>>,
    next_sid: AtomicU32,
    closed: AtomicBool,
    padding: SchemeCell,
    peer_version: AtomicU8,
    kernel: Mutex<Kernel>,
    synack_deadline: Mutex<Option<Instant>>,
    on_close: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    rx: Mutex<Option<RxSide>>,
    started: Instant,
    /// Microseconds after `started` when a stream reader last entered or left `read_for`.
    last_lead: AtomicU64,
    /// Live streams whose reader has asked for data at least once.
    readers: AtomicUsize,
    /// Stream readers inside `read_for` right now.
    present: AtomicUsize,
    /// Stream readers waiting for whoever holds the receive side.
    followers: AtomicUsize,
    background: Mutex<Option<thread::Thread>>,
    native: Option<native::Native>,
}

/// A handle to a session. Clones share it.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

impl Session {
    /// Starts a client session on a fresh connection: the password record leaves with the first
    /// stream, preceded by the held-back TLS Finished, as mihomo's `createOutboundTLSConnection`
    /// and `Session.Run` arrange.
    pub fn client(link: Established, padding: SchemeCell, metadata: &str, password: &[u8; 32]) -> io::Result<Self> {
        link.tcp.set_read_timeout(Some(READ_SLICE))?;
        let inner = Arc::new(Inner::new(Role::Client, link, padding, Parser::new(Role::Client, None))?);
        {
            let scheme = inner.padding.load();
            let mut sizes = Vec::new();
            scheme.record_sizes(0, &mut sizes);
            let mut tx = inner.tx.lock().expect("tx");
            tx.put_auth(password, sizes.first().copied().unwrap_or(0), &inner.kernel)?;
            tx.buffering = true;
            let settings = frame::string_map(&[("v", "2"), ("client", metadata), ("padding-md5", scheme.md5())]);
            tx.put(Out::Frames { cmd: CMD_SETTINGS, sid: 0, data: &settings }, &inner.padding, &inner.kernel)?;
        }
        if inner.native.is_some() {
            native::start(&inner);
            return Ok(Self { inner });
        }
        let worker = Arc::clone(&inner);
        let handle = thread::Builder::new()
            .name("anytls-read".into())
            .spawn(move || {
                let _ = background(&worker);
                worker.close();
            })
            .map_err(io::Error::other)?;
        *inner.background.lock().expect("background") = Some(handle.thread().clone());
        Ok(Self { inner })
    }

    /// Runs a server session on this thread until it ends. The socket's read deadline, set for the
    /// handshake, stays until the password and its padding have arrived.
    pub fn serve(link: Established, padding: SchemeCell, inbound: Arc<dyn Inbound>) -> io::Result<()> {
        Self::serve_inner(link, padding, inbound, false, None)
    }

    /// The accept thread owns the handshake; an eligible native connection
    /// transfers steady I/O to the shared executor. The hook owns registration
    /// cleanup until the physical session has actually ended.
    pub fn serve_detached(link: Established, padding: SchemeCell, inbound: Arc<dyn Inbound>, close: Box<dyn FnOnce() + Send>) -> io::Result<()> {
        Self::serve_inner(link, padding, inbound, true, Some(close))
    }

    fn serve_inner(link: Established, padding: SchemeCell, inbound: Arc<dyn Inbound>, detached: bool, close: Option<Box<dyn FnOnce() + Send>>) -> io::Result<()> {
        let peer = link.tcp.peer_addr()?;
        let parser = Parser::new(Role::Server, Some(Server { inbound, peer, user: [0; 32] }));
        let inner = Arc::new(Inner::new(Role::Server, link, padding, parser)?);
        *inner.on_close.lock().expect("close hook") = close;
        if inner.native.is_some() {
            let completed = native::start(&inner);
            return if detached { Ok(()) } else { native::runtime()?.block_on(completed).map_err(io::Error::other)? };
        }
        *inner.background.lock().expect("background") = Some(thread::current());
        let result = background(&inner);
        inner.close();
        result
    }

    /// Opens a stream (mihomo `OpenStream`). The SYN joins the settings frame when this is the
    /// first stream of the session.
    pub fn open_stream(&self) -> io::Result<Stream> {
        let inner = &self.inner;
        if inner.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        let sid = inner.next_sid.fetch_add(1, Ordering::AcqRel) + 1;
        let core = Arc::new(Core::new(sid, Parse::Data, Arc::downgrade(inner)));
        inner.streams.lock().expect("streams").insert(sid, Arc::clone(&core));
        if sid >= 2 && inner.peer_version.load(Ordering::Acquire) >= 2 {
            *inner.synack_deadline.lock().expect("synack") = Some(Instant::now() + SYNACK_TIMEOUT);
        }
        if let Err(error) = inner.submit(Out::Frames { cmd: CMD_SYN, sid, data: &[] }, true) {
            inner.streams.lock().expect("streams").remove(&sid);
            return Err(error);
        }
        inner.tx.lock().expect("tx").buffering = false;
        if inner.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        Ok(Stream { core, session: Arc::clone(inner) })
    }

    pub fn close(&self) {
        self.inner.close();
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub fn role(&self) -> Role {
        self.inner.role
    }

    /// The peer's protocol version from its settings, 0 until they arrive.
    pub fn peer_version(&self) -> u8 {
        self.inner.peer_version.load(Ordering::Acquire)
    }

    /// When a reused session must have answered its latest SYN.
    pub fn synack_deadline(&self) -> Option<Instant> {
        *self.inner.synack_deadline.lock().expect("synack")
    }

    /// Runs once when the session ends.
    pub fn set_on_close(&self, hook: Box<dyn FnOnce() + Send>) {
        let mut slot = self.inner.on_close.lock().expect("hook");
        if self.inner.closed.load(Ordering::Acquire) {
            drop(slot);
            hook();
        } else {
            *slot = Some(hook);
        }
    }

    pub fn stream_count(&self) -> usize {
        self.inner.streams.lock().expect("streams").len()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.tcp.local_addr()
    }
}

impl Inner {
    fn new(role: Role, link: Established, padding: SchemeCell, parser: Parser) -> io::Result<Self> {
        let (reader, early, tx, kernel, library_write) = match link.wire {
            Wire::Records(records) => (
                Reader::new(records.rx, records.rx_buf, records.rx_len),
                records.early,
                Tx::new(Some(records.tx), records.pending, role == Role::Client),
                records.kernel,
                None,
            ),
            Wire::Library(read, write) => (
                Reader::stream(Some(read)),
                Vec::new(),
                Tx::new(None, Vec::new(), role == Role::Client),
                Kernel::Library,
                Some(Mutex::new(write)),
            ),
            Wire::Plain => (
                Reader::stream(None),
                Vec::new(),
                Tx::plaintext(role == Role::Client),
                Kernel::Library,
                None,
            ),
        };
        let native = if library_write.is_none() { Some(native::Native::new(&link.tcp)?) } else { None };
        let side = RxSide { reader, parser, early, early_pos: 0, pending: None, ended: false };
        Ok(Self {
            native,
            rx: Mutex::new(Some(side)),
            started: Instant::now(),
            last_lead: AtomicU64::new(0),
            readers: AtomicUsize::new(0),
            present: AtomicUsize::new(0),
            followers: AtomicUsize::new(0),
            background: Mutex::new(None),
            role,
            tcp: link.tcp,
            library_write,
            tx: Mutex::new(tx),
            helper_cv: Condvar::new(),
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            padding,
            peer_version: AtomicU8::new(0),
            kernel: Mutex::new(kernel),
            synack_deadline: Mutex::new(None),
            on_close: Mutex::new(None),
        })
    }

    fn lock_tx(&self) -> MutexGuard<'_, Tx> {
        self.tx.lock().expect("tx")
    }

    fn read_socket(&self, bytes: &mut [u8]) -> io::Result<usize> {
        match &self.native {
            Some(native) => native.socket.try_read(bytes),
            None => (&self.tcp).read(bytes),
        }
    }

    fn now_micros(&self) -> u64 {
        self.started.elapsed().as_micros() as u64
    }

    fn mark_lead(&self) {
        self.last_lead.store(self.now_micros(), Ordering::Relaxed);
    }

    /// How long the session's own thread should stay out of the way, or `None` if it should read
    /// now. No stream reader at all: read now. A reader inside `read_for`: it reads whatever
    /// arrives, look again later. All readers away (busy with what they read): read once they have
    /// been away for `LEAD_AWAY`.
    fn background_wait(&self) -> Option<Duration> {
        if self.readers.load(Ordering::Acquire) == 0 {
            return None;
        }
        if self.present.load(Ordering::Acquire) > 0 {
            return Some(PRESENT_RECHECK);
        }
        let away = self.now_micros().saturating_sub(self.last_lead.load(Ordering::Relaxed));
        let limit = LEAD_AWAY.as_micros() as u64;
        (away < limit).then(|| Duration::from_micros(limit - away))
    }

    fn wake_background(&self) {
        if let Some(native) = &self.native { native.read_notify.notify_one(); }
        if let Some(thread) = self.background.lock().expect("background").as_ref() {
            thread.unpark();
        }
    }

    /// The receive side was let go: if a stream reader is waiting for it, wake one so it reads.
    fn wake_follower(&self) {
        if self.followers.load(Ordering::Acquire) == 0 {
            return;
        }
        let streams = self.streams.lock().expect("streams");
        for core in streams.values() {
            let mut rx = core.rx.lock().expect("rx");
            if rx.app_waiting {
                rx.app_waiting = false;
                core.data_cv.notify_one();
                return;
            }
        }
    }

    /// Queues one item. `sync` waits for a turn in the queue bound and returns once the socket
    /// took the bytes; otherwise the bytes are left for the current writer or the helper.
    fn submit(self: &Arc<Self>, item: Out<'_>, sync: bool) -> io::Result<()> {
        if self.native.is_some() { return native::submit(self, item, sync); }
        let mut tx = self.lock_tx();
        if tx.dead.is_some() {
            return Err(closed_error());
        }
        if sync {
            tx = self.wait_room(tx)?;
        }
        let grown = match tx.put(item, &self.padding, &self.kernel) {
            Ok(grown) => grown,
            Err(error) => {
                tx.dead = Some(error.kind());
                wake_all(&mut tx);
                drop(tx);
                self.close();
                return Err(error);
            }
        };
        wake_room(&mut tx);
        if grown == 0 {
            return Ok(());
        }
        if !sync {
            if !tx.flushing {
                tx.flushing = true;
                tx.helper_wanted = true;
                if tx.helper_started {
                    self.helper_cv.notify_one();
                } else {
                    tx.helper_started = true;
                    let inner = Arc::clone(self);
                    thread::Builder::new()
                        .name("anytls-write".into())
                        .stack_size(64 << 10)
                        .spawn(move || helper(inner))
                        .map_err(io::Error::other)?;
                }
            }
            return Ok(());
        }
        let end = tx.appended;
        if !tx.flushing {
            tx.flushing = true;
            return self.flush(tx, Some(end)).1;
        }
        let ticket = tx.ticket();
        let cv = Arc::new(Condvar::new());
        tx.waiters.push_back(Waiter { ticket, end: Some(end), cv: Arc::clone(&cv), woken: false });
        loop {
            tx = cv.wait(tx).expect("tx");
            if tx.written >= end {
                remove_waiter(&mut tx, ticket);
                return Ok(());
            }
            if tx.handoff == Some(ticket) {
                tx.handoff = None;
                remove_waiter(&mut tx, ticket);
                return self.flush(tx, Some(end)).1;
            }
            if tx.dead.is_some() {
                remove_waiter(&mut tx, ticket);
                return Err(closed_error());
            }
            set_woken(&mut tx, ticket, false);
        }
    }

    /// Waits, in arrival order, until the queued bytes are under the bound.
    fn wait_room<'a>(&'a self, mut tx: MutexGuard<'a, Tx>) -> io::Result<MutexGuard<'a, Tx>> {
        let has_room = |tx: &Tx| tx.pending() == 0 || tx.pending() < tx.rate.limit();
        let queued = tx.waiters.iter().any(|waiter| waiter.end.is_none());
        if !queued && has_room(&tx) {
            return Ok(tx);
        }
        let ticket = tx.ticket();
        let cv = Arc::new(Condvar::new());
        tx.waiters.push_back(Waiter { ticket, end: None, cv: Arc::clone(&cv), woken: false });
        loop {
            tx = cv.wait(tx).expect("tx");
            if tx.dead.is_some() {
                remove_waiter(&mut tx, ticket);
                return Err(closed_error());
            }
            let first = tx.waiters.iter().find(|waiter| waiter.end.is_none()).map(|waiter| waiter.ticket);
            if first == Some(ticket) && has_room(&tx) {
                remove_waiter(&mut tx, ticket);
                return Ok(tx);
            }
            set_woken(&mut tx, ticket, false);
        }
    }

    /// Writes `out` to the socket until it is empty, or until this caller's bytes are out and a
    /// waiting writer can take over.
    fn flush<'a>(&'a self, mut tx: MutexGuard<'a, Tx>, mine: Option<u64>) -> (MutexGuard<'a, Tx>, io::Result<()>) {
        loop {
            if tx.out.is_empty() {
                tx.flushing = false;
                return (tx, Ok(()));
            }
            let mut batch = std::mem::take(&mut tx.spare);
            std::mem::swap(&mut batch, &mut tx.out);
            drop(tx);
            let started = Instant::now();
            let result = self.write_batch(&batch);
            let spent = started.elapsed();
            tx = self.lock_tx();
            let sent = batch.len() as u64;
            batch.clear();
            if tx.spare.capacity() < batch.capacity() {
                tx.spare = batch;
            }
            if let Err(error) = result {
                tx.flushing = false;
                if tx.dead.is_none() {
                    tx.dead = Some(error.kind());
                }
                wake_all(&mut tx);
                self.helper_cv.notify_all();
                let _ = self.tcp.shutdown(Shutdown::Both);
                return (tx, Err(error));
            }
            tx.written += sent;
            tx.rate.record(sent, spent);
            let written = tx.written;
            for waiter in tx.waiters.iter_mut() {
                if !waiter.woken && waiter.end.is_some_and(|end| end <= written) {
                    waiter.woken = true;
                    waiter.cv.notify_one();
                }
            }
            wake_room(&mut tx);
            if tx.out.is_empty() {
                tx.flushing = false;
                return (tx, Ok(()));
            }
            if mine.is_none_or(|end| end <= written) {
                if let Some(next) = tx.waiters.iter_mut().find(|waiter| waiter.end.is_some_and(|end| end > written)) {
                    next.woken = true;
                    next.cv.notify_one();
                    let ticket = next.ticket;
                    tx.handoff = Some(ticket);
                    return (tx, Ok(()));
                }
            }
        }
    }

    fn write_batch(&self, mut batch: &[u8]) -> io::Result<()> {
        let Some(write) = &self.library_write else {
            return (&self.tcp).write_all(batch);
        };
        let mut write = write.lock().expect("anytls library TLS writer");
        while let Some((len, remaining)) = batch.split_first_chunk::<2>() {
            let size = usize::from(u16::from_be_bytes(*len));
            if size == 0 {
                return write.close();
            }
            let (plain, rest) = remaining.split_at(size);
            write.write_all(plain)?;
            batch = rest;
        }
        debug_assert!(batch.is_empty());
        Ok(())
    }

    /// Waits up to `limit` for what is queued now to reach the socket.
    fn drain(&self, limit: Duration) {
        if self.native.is_some() { return; } // native close drains asynchronously
        let deadline = Instant::now() + limit;
        let mut tx = self.lock_tx();
        let end = tx.appended;
        let ticket = tx.ticket();
        let cv = Arc::new(Condvar::new());
        tx.waiters.push_back(Waiter { ticket, end: Some(end), cv: Arc::clone(&cv), woken: false });
        while tx.written < end && tx.dead.is_none() && tx.flushing {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            tx = cv.wait_timeout(tx, deadline - now).expect("tx").0;
            set_woken(&mut tx, ticket, false);
        }
        remove_waiter(&mut tx, ticket);
    }

    fn close(self: &Arc<Self>) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.native.is_some() {
            native::close(self);
            return;
        }
        {
            let mut tx = self.lock_tx();
            if tx.dead.is_none() && !tx.flushing && tx.put(Out::CloseNotify, &self.padding, &self.kernel).is_ok() {
                let batch = std::mem::take(&mut tx.out);
                tx.flushing = true;
                drop(tx);
                let _ = self.tcp.set_write_timeout(Some(Duration::from_secs(1)));
                let _ = self.write_batch(&batch);
                tx = self.lock_tx();
            }
            if tx.dead.is_none() {
                tx.dead = Some(io::ErrorKind::NotConnected);
            }
            wake_all(&mut tx);
        }
        self.helper_cv.notify_all();
        let _ = self.tcp.shutdown(Shutdown::Both);
        if let Some(thread) = self.background.lock().expect("background").clone() {
            thread.unpark();
        }
        let streams: Vec<Arc<Core>> = self.streams.lock().expect("streams").drain().map(|(_, core)| core).collect();
        for core in streams {
            core.finish(None);
        }
        if let Some(hook) = self.on_close.lock().expect("hook").take() {
            hook();
        }
    }
}

fn helper(inner: Arc<Inner>) {
    let mut tx = inner.lock_tx();
    loop {
        while !tx.helper_wanted && tx.dead.is_none() {
            tx = inner.helper_cv.wait(tx).expect("tx");
        }
        if tx.dead.is_some() {
            return;
        }
        tx.helper_wanted = false;
        tx = inner.flush(tx, None).0;
    }
}

fn remove_waiter(tx: &mut Tx, ticket: u64) {
    if let Some(index) = tx.waiters.iter().position(|waiter| waiter.ticket == ticket) {
        tx.waiters.remove(index);
    }
}

fn set_woken(tx: &mut Tx, ticket: u64, woken: bool) {
    if let Some(waiter) = tx.waiters.iter_mut().find(|waiter| waiter.ticket == ticket) {
        waiter.woken = woken;
    }
}

/// Lets the first writer waiting for room go, if there is room.
fn wake_room(tx: &mut Tx) {
    if tx.pending() != 0 && tx.pending() >= tx.rate.limit() {
        return;
    }
    if let Some(waiter) = tx.waiters.iter_mut().find(|waiter| waiter.end.is_none()) {
        if !waiter.woken {
            waiter.woken = true;
            waiter.cv.notify_one();
        }
    }
}

fn wake_all(tx: &mut Tx) {
    for waiter in tx.waiters.iter_mut() {
        waiter.woken = true;
        waiter.cv.notify_one();
    }
}

// ---------------------------------------------------------------------------------------------
// Streams

enum Parse {
    /// Bytes for the application.
    Data,
    /// Server: the SOCKS address at the start of a stream.
    Addr(Vec<u8>),
    /// Server: the UoT v2 request (`isConnect`, address) after the magic address.
    UotRequest(Vec<u8>),
    /// Server: UoT packets.
    Uot(Box<Uot>),
}

struct Uot {
    connect: Option<Target>,
    datagrams: Option<Arc<DatagramSession>>,
    tail: Vec<u8>,
    legs: HashMap<Target, Arc<LegCore>>,
}

impl Uot {
    fn new(connect: Option<Target>) -> Self {
        let datagrams = connect.is_none().then(|| Arc::new(DatagramSession::new(true)));
        Self { connect, datagrams, tail: Vec::new(), legs: HashMap::new() }
    }
}

struct Rx {
    queue: ByteQueue,
    parse: Parse,
    eof: bool,
    error: Option<String>,
    app_waiting: bool,
    reader_waiting: bool,
    task_readers: Vec<(u64, Waker)>,
    next_task_reader: u64,
}

struct Core {
    sid: u32,
    rx: Mutex<Rx>,
    data_cv: Condvar,
    space_cv: Condvar,
    local_closed: AtomicBool,
    remote_closed: AtomicBool,
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// 0 before its reader first asks for data, 1 while that reader counts as one of the session's
    /// readers, 2 once the stream ended.
    reader: AtomicU8,
    session: Weak<Inner>,
}

impl Core {
    fn new(sid: u32, parse: Parse, session: Weak<Inner>) -> Self {
        Self {
            reader: AtomicU8::new(0),
            session,
            sid,
            rx: Mutex::new(Rx {
                queue: ByteQueue::new(),
                parse,
                eof: false,
                error: None,
                app_waiting: false,
                reader_waiting: false,
                task_readers: Vec::new(),
                next_task_reader: 0,
            }),
            data_cv: Condvar::new(),
            space_cv: Condvar::new(),
            local_closed: AtomicBool::new(false),
            remote_closed: AtomicBool::new(false),
            hook: Mutex::new(None),
        }
    }

    /// The far side closed the stream, or the session ended (mihomo `closeLocally`).
    fn finish(&self, error: Option<String>) {
        self.remote_closed.store(true, Ordering::Release);
        let legs = {
            let mut rx = self.rx.lock().expect("rx");
            rx.eof = true;
            if rx.error.is_none() {
                rx.error = error;
            }
            self.data_cv.notify_all();
            self.space_cv.notify_all();
            for (_, waker) in rx.task_readers.drain(..) { waker.wake(); }
            match std::mem::replace(&mut rx.parse, Parse::Data) {
                Parse::Uot(uot) => uot.legs.into_values().collect(),
                _ => Vec::new(),
            }
        };
        for leg in legs {
            leg.close();
        }
        self.release_reader();
        self.run_hook();
    }

    /// The stream's reader starts counting as one of the session's readers.
    fn start_reading(&self, inner: &Inner) {
        if self.reader.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            inner.readers.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// The stream ended from either side: its reader no longer reads the socket for the session.
    /// When it was the last one, the session's own thread starts reading at once, so the next
    /// stream on a reused session waits for nothing.
    fn release_reader(&self) {
        if self.reader.swap(2, Ordering::AcqRel) != 1 {
            return;
        }
        if let Some(inner) = self.session.upgrade() {
            if inner.readers.fetch_sub(1, Ordering::AcqRel) == 1 {
                inner.wake_background();
            }
        }
    }

    fn run_hook(&self) {
        if let Some(hook) = self.hook.lock().expect("hook").take() {
            hook();
        }
    }
}

/// One TCP stream of a session.
pub struct Stream {
    core: Arc<Core>,
    session: Arc<Inner>,
}

enum ReadTarget<'a> {
    Buffer(&'a mut [u8]),
    Borrowed { fallback: &'a mut [u8], sink: &'a mut dyn FnMut(&[IoSlice<'_>]) },
}

impl ReadTarget<'_> {
    fn buffer(&mut self) -> &mut [u8] {
        match self {
            Self::Buffer(buf) => buf,
            Self::Borrowed { fallback, .. } => fallback,
        }
    }

    fn buffered(&mut self, n: usize) {
        if let Self::Borrowed { fallback, sink } = self {
            sink(&[IoSlice::new(&fallback[..n])]);
        }
    }

    fn direct(&mut self, parts: &[IoSlice<'_>]) {
        match self {
            Self::Buffer(buf) => {
                let mut at = 0;
                for part in parts {
                    buf[at..at + part.len()].copy_from_slice(part);
                    at += part.len();
                }
            }
            Self::Borrowed { sink, .. } => sink(parts),
        }
    }
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.core.sid
    }

    pub fn session(&self) -> Session {
        Session { inner: Arc::clone(&self.session) }
    }

    /// Reads what arrived. `Ok(0)` after the peer's FIN, `TimedOut` when nothing came within `wait`.
    ///
    /// A reader whose stream has nothing queued reads the socket itself when nobody else does, and
    /// hands what belongs to other streams to them; so a session with one busy stream costs no
    /// thread switch per read. Otherwise it waits for the thread that holds the socket.
    pub fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        self.read_target(&mut ReadTarget::Buffer(buf), wait)
    }

    /// Lends the ready regions in the receive storage until `sink` returns.
    /// Queued bytes from another session reader use `fallback`; both modes
    /// share parsing, ordering, receive arbitration and the same deadline.
    pub fn read_vectored_for(
        &self,
        fallback: &mut [u8],
        wait: Duration,
        sink: &mut dyn FnMut(&[IoSlice<'_>]),
    ) -> io::Result<usize> {
        self.read_target(&mut ReadTarget::Borrowed { fallback, sink }, wait)
    }

    fn read_target(&self, target: &mut ReadTarget<'_>, wait: Duration) -> io::Result<usize> {
        if target.buffer().is_empty() {
            return Ok(0);
        }
        if self.session.native.is_some() { return native::read_target(self, target, wait); }
        let session = &self.session;
        self.core.start_reading(session);
        session.present.fetch_add(1, Ordering::AcqRel);
        session.mark_lead();
        let result = self.read_inner(target, wait);
        session.mark_lead();
        session.present.fetch_sub(1, Ordering::AcqRel);
        result
    }

    fn read_inner(&self, target: &mut ReadTarget<'_>, wait: Duration) -> io::Result<usize> {
        let deadline = Instant::now() + wait;
        let session = &self.session;
        loop {
            {
                let mut rx = self.core.rx.lock().expect("rx");
                if let Some(result) = self.take(&mut rx, target.buffer()) {
                    drop(rx);
                    if let Ok(n) = result { target.buffered(n); }
                    return result;
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if let Ok(mut side_slot) = session.rx.try_lock() {
                let side = side_slot.as_mut().expect("synchronous receive owner");
                if side.ended {
                    drop(side_slot);
                    let mut rx = self.core.rx.lock().expect("rx");
                    if let Some(result) = self.take(&mut rx, target.buffer()) {
                        drop(rx);
                        if let Ok(n) = result { target.buffered(n); }
                        return result;
                    }
                    return Err(closed_error());
                }
                let mut direct = Direct::reader(self.core.sid, target.buffer().len());
                let alive = pump(session, side, &mut direct);
                let ended = !matches!(alive, Ok(true));
                // Parsing and decryption have finished for this batch. Holding
                // only the receive-side guard prevents storage reuse while the
                // outbound consumes it; no stream queue or writer lock is held.
                if direct.count != 0 {
                    let mut parts = [IoSlice::new(&[]); DIRECT_PARTS];
                    for (part, range) in parts.iter_mut().zip(&direct.ranges[..direct.count]) {
                        *part = IoSlice::new(&side.reader.buf[range.clone()]);
                    }
                    target.direct(&parts[..direct.count]);
                }
                if ended {
                    side.ended = true;
                    drop(side_slot);
                    session.close();
                } else {
                    drop(side_slot);
                    session.wake_follower();
                }
                if direct.bytes != 0 {
                    return Ok(direct.bytes);
                }
                continue;
            }
            // Someone else holds the socket: wait for it to hand over data or the socket.
            let mut rx = self.core.rx.lock().expect("rx");
            if let Some(result) = self.take(&mut rx, target.buffer()) {
                drop(rx);
                if let Ok(n) = result { target.buffered(n); }
                return result;
            }
            session.followers.fetch_add(1, Ordering::AcqRel);
            rx.app_waiting = true;
            let slice = (deadline - now).min(Duration::from_millis(20));
            rx = self.core.data_cv.wait_timeout(rx, slice).expect("rx").0;
            rx.app_waiting = false;
            session.followers.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// What a read returns now, if anything: queued bytes, an error, or the end.
    fn take(&self, rx: &mut Rx, buf: &mut [u8]) -> Option<io::Result<usize>> {
        if !rx.queue.is_empty() {
            let n = rx.queue.pop(buf);
            if rx.reader_waiting {
                rx.reader_waiting = false;
                self.core.space_cv.notify_one();
                if let Some(native) = &self.session.native {
                    native.read_notify.notify_one();
                    native.space_notify.notify_waiters();
                }
            }
            return Some(Ok(n));
        }
        if let Some(error) = &rx.error {
            return Some(Err(io::Error::new(io::ErrorKind::ConnectionReset, error.clone())));
        }
        if rx.eof {
            return Some(Ok(0));
        }
        if self.core.local_closed.load(Ordering::Acquire) {
            return Some(Err(closed_error()));
        }
        None
    }

    /// Sends `data` as PSH frames and returns once the socket took them. A FIN from the peer ends
    /// writing too: AnyTLS has no half-close.
    pub fn write(&self, data: &[u8]) -> io::Result<()> {
        if self.core.local_closed.load(Ordering::Acquire) || self.core.remote_closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if data.is_empty() {
            return Ok(());
        }
        // While the client pads, a write is one packet of the scheme, as in Go. Afterwards long
        // writes go in pieces, cut at whole frames, so other streams get turns in between.
        let (padding, limit) = {
            let tx = self.session.lock_tx();
            (tx.send_padding, tx.rate.limit() as usize)
        };
        if padding {
            return self.session.submit(Out::Frames { cmd: CMD_PSH, sid: self.core.sid, data }, true);
        }
        let piece = (limit / MAX_DATA).max(1) * MAX_DATA;
        for chunk in data.chunks(piece) {
            self.session.submit(Out::Frames { cmd: CMD_PSH, sid: self.core.sid, data: chunk }, true)?;
        }
        Ok(())
    }

    /// Closes the stream and sends FIN unless the peer closed it first.
    pub fn close(&self) {
        if self.core.local_closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let legs = {
            let mut rx = self.core.rx.lock().expect("rx");
            rx.queue.clear();
            self.core.data_cv.notify_all();
            self.core.space_cv.notify_all();
            for (_, waker) in rx.task_readers.drain(..) { waker.wake(); }
            match std::mem::replace(&mut rx.parse, Parse::Data) {
                Parse::Uot(uot) => uot.legs.into_values().collect(),
                _ => Vec::new(),
            }
        };
        for leg in legs {
            leg.close();
        }
        let removed = self.session.streams.lock().expect("streams").remove(&self.core.sid).is_some();
        if removed && !self.core.remote_closed.load(Ordering::Acquire) {
            let _ = self.session.submit(Out::Frames { cmd: CMD_FIN, sid: self.core.sid, data: &[] }, false);
        }
        self.core.release_reader();
        if let Some(native) = &self.session.native { native.read_notify.notify_one(); }
        self.core.run_hook();
    }

    /// Runs once when the stream ends from either side (mihomo's `dieHook`).
    pub fn set_close_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        let mut slot = self.core.hook.lock().expect("hook");
        if self.core.local_closed.load(Ordering::Acquire) || self.core.remote_closed.load(Ordering::Acquire) {
            drop(slot);
            hook();
        } else {
            *slot = Some(hook);
        }
    }

    pub fn supports_async(&self) -> bool { self.session.native.is_some() }

    pub fn into_async(self) -> kerlico_shared::AsyncTcp { native::stream(self) }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------------------------
// UDP over TCP on the server

struct LegRx {
    queue: ByteQueue,
    closed: bool,
    waiting: bool,
}

struct LegCore {
    target: Target,
    connect: bool,
    rx: Mutex<LegRx>,
    cv: Condvar,
}

impl LegCore {
    fn push(&self, payload: &[u8]) {
        let mut rx = self.rx.lock().expect("leg");
        if rx.closed || rx.queue.len() + payload.len() + 2 > LEG_RX_LIMIT {
            return;
        }
        rx.queue.push(&(payload.len() as u16).to_be_bytes());
        rx.queue.push(payload);
        if rx.waiting {
            rx.waiting = false;
            self.cv.notify_one();
        }
    }

    fn close(&self) {
        let mut rx = self.rx.lock().expect("leg");
        rx.closed = true;
        self.cv.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.rx.lock().expect("leg").closed
    }
}

/// The datagrams of one UoT stream that go to one destination.
pub struct Leg {
    core: Arc<LegCore>,
    stream: Arc<Core>,
    session: Arc<Inner>,
    datagrams: Option<Arc<DatagramSession>>,
}

impl Leg {
    pub fn target(&self) -> &Target {
        &self.core.target
    }

    pub fn datagram_session(&self) -> Option<&Arc<DatagramSession>> {
        self.datagrams.as_ref()
    }

    /// One whole datagram. `UnexpectedEof` once the stream or the session ended; a datagram larger
    /// than `buf` is dropped with `InvalidInput`.
    pub fn recv_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        let deadline = Instant::now() + wait;
        let mut rx = self.core.rx.lock().expect("leg");
        loop {
            let mut len = [0u8; 2];
            if rx.queue.peek(&mut len) {
                let len = usize::from(u16::from_be_bytes(len));
                rx.queue.skip(2);
                if len > buf.len() {
                    rx.queue.skip(len);
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram larger than the buffer"));
                }
                rx.queue.pop(&mut buf[..len]);
                return Ok(len);
            }
            if rx.closed {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            rx.waiting = true;
            rx = self.core.cv.wait_timeout(rx, deadline - now).expect("leg").0;
            rx.waiting = false;
        }
    }

    /// Fall back to the requested destination when the outbound stream has no source metadata.
    pub fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.reply(&self.core.target, payload)
    }

    pub fn send_from(&self, source: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.reply(&Target::new(source.ip().to_string(), source.port()), payload)
    }

    fn reply(&self, source: &Target, payload: &[u8]) -> io::Result<()> {
        if self.core.is_closed() || self.stream.remote_closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let len = u16::try_from(payload.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?;
        let mut packet = Vec::with_capacity(source.encoded_len() + 2 + payload.len());
        if !self.core.connect {
            source.encode(Family::Uot, &mut packet)?;
        }
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(payload);
        // Tx emits all PSH frames of a datagram together, even if there are replies on other legs.
        self.session.submit(Out::Frames { cmd: CMD_PSH, sid: self.stream.sid, data: &packet }, true)
    }
}

impl Drop for Leg {
    fn drop(&mut self) {
        self.core.close();
    }
}

// ---------------------------------------------------------------------------------------------
// Reading

struct Reader {
    cipher: Option<Cipher>,
    library: Option<Box<dyn Read + Send>>,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    hs: Vec<u8>,
}

impl Reader {
    fn new(cipher: Cipher, buf: Vec<u8>, len: usize) -> Self {
        Self { cipher: Some(cipher), library: None, buf, start: 0, end: len, hs: Vec::new() }
    }

    fn stream(library: Option<Box<dyn Read + Send>>) -> Self {
        Self { cipher: None, library, buf: vec![0; tls::MAX_PLAIN], start: 0, end: 0, hs: Vec::new() }
    }
}

struct Server {
    inbound: Arc<dyn Inbound>,
    peer: SocketAddr,
    user: [u8; 32],
}

enum Next {
    Go,
    Stop,
    /// Stop after what is queued has been sent (an alert).
    StopAfterFlush,
}

/// The socket's receive side: whoever holds it reads the socket and hands out what it read.
struct RxSide {
    reader: Reader,
    parser: Parser,
    early: Vec<u8>,
    early_pos: usize,
    pending: Option<std::ops::Range<usize>>,
    ended: bool,
}

/// How long one socket read may block (`SO_RCVTIMEO`, set once per connection), so the thread
/// holding the receive side gets back to its own deadline and to the session's state.
const READ_SLICE: Duration = Duration::from_millis(200);
/// The longest a frame for nobody's reader (a new stream's SYN, a heartbeat, a UoT datagram)
/// waits while every stream reader is busy with what it read.
const LEAD_AWAY: Duration = Duration::from_millis(5);
/// How often the session's own thread looks again while a stream reader is inside `read_for`.
/// Each look is a wakeup; at 20 ms, 300 quiet sessions cost a quarter more CPU than at 100 ms.
const PRESENT_RECHECK: Duration = Duration::from_millis(100);

fn finish_next(inner: &Arc<Inner>, next: Next) -> bool {
    match next {
        Next::Go => true,
        Next::Stop => false,
        Next::StopAfterFlush => {
            inner.drain(Duration::from_secs(1));
            false
        }
    }
}

/// One step of the receive side: every whole record already buffered, then one socket read and
/// the records it completed. `Ok(false)` when the session is over.
fn pump(inner: &Arc<Inner>, side: &mut RxSide, direct: &mut Direct) -> io::Result<bool> {
    if side.reader.cipher.is_none() {
        if !pending_plain(inner, side, direct)? || direct.blocked { return Ok(!side.ended); }
        let got = match &mut side.reader.library {
            Some(read) => read.read(&mut side.reader.buf),
            None => inner.read_socket(&mut side.reader.buf),
        };
        let n = match got {
            Ok(0) => return Ok(false),
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && inner.native.is_some() => {
                direct.needs_read = true;
                return Ok(true);
            }
            Err(error) if side.parser.auth.is_none()
                && matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
                return Ok(true),
            Err(error) => return Err(error),
        };
        side.reader.start = 0;
        side.reader.end = n;
        side.pending = Some(0..n);
        return pending_plain(inner, side, direct);
    }
    if !side.early.is_empty() {
        if !finish_next(inner, side.parser.feed(inner, &side.early[side.early_pos..], direct, None)?) {
            return Ok(false);
        }
        side.early_pos += direct.consumed;
        if direct.blocked { return Ok(true); }
        side.early.clear();
        side.early_pos = 0;
    }
    if !process(inner, side, direct)? {
        return Ok(false);
    }
    if direct.delivered || direct.blocked {
        return Ok(true);
    }
    let reader = &mut side.reader;
    if reader.start == reader.end {
        reader.start = 0;
        reader.end = 0;
    } else if reader.buf.len() - reader.end < MAX_CIPHERTEXT + 5 {
        reader.buf.copy_within(reader.start..reader.end, 0);
        reader.end -= reader.start;
        reader.start = 0;
    }
    let free = reader.buf.len() - reader.end;
    let n = match inner.read_socket(&mut reader.buf[reader.end..]) {
        Ok(0) => return Ok(false),
        Ok(n) => n,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(true),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock && inner.native.is_some() => {
            direct.needs_read = true;
            return Ok(true);
        }
        Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
            // Before the password the socket deadline is the handshake's, and it is final.
            if side.parser.auth.is_some() {
                return Err(error);
            }
            return Ok(true);
        }
        Err(error) => return Err(error),
    };
    reader.end += n;
    // A read that filled the buffer means more was waiting: read more at once next time.
    if n == free && reader.buf.len() < RX_BUF_MAX {
        let mut bigger = vec![0u8; reader.buf.len() * 2];
        bigger[..reader.end - reader.start].copy_from_slice(&reader.buf[reader.start..reader.end]);
        reader.end -= reader.start;
        reader.start = 0;
        reader.buf = bigger;
    }
    process(inner, side, direct)
}

/// Which stream's own reader holds the receive side, if any. That stream never waits for room in
/// its own queue, since its reader is the one that would empty it; and its reader stops pumping as
/// soon as something for it arrived.
const DIRECT_PARTS: usize = 64;

#[cfg(test)]
mod receive_tests;

struct Direct {
    sid: Option<u32>,
    delivered: bool,
    ranges: [std::ops::Range<usize>; DIRECT_PARTS],
    count: usize,
    bytes: usize,
    limit: usize,
    queued: bool,
    blocked: bool,
    needs_read: bool,
    consumed: usize,
}

impl Direct {
    fn none() -> Self {
        Self {
            sid: None, delivered: false, ranges: std::array::from_fn(|_| 0..0),
            count: 0, bytes: 0, limit: 0, queued: false, blocked: false, needs_read: false, consumed: 0,
        }
    }

    fn reader(sid: u32, limit: usize) -> Self {
        Self { sid: Some(sid), limit, ..Self::none() }
    }

    fn capture(&mut self, offset: Option<usize>, len: usize) -> usize {
        let Some(offset) = offset else { return 0; };
        if self.queued || self.count == DIRECT_PARTS { return 0; }
        let n = len.min(self.limit - self.bytes);
        if n != 0 {
            self.ranges[self.count] = offset..offset + n;
            self.count += 1;
            self.bytes += n;
        }
        n
    }
}

/// The session's own reading thread. It reads while no stream reader owns the socket: before the
/// first stream, between streams, for UDP legs, and for streams nobody is reading.
fn background(inner: &Arc<Inner>) -> io::Result<()> {
    loop {
        if inner.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(wait) = inner.background_wait() {
            thread::park_timeout(wait);
            continue;
        }
        let Ok(mut side_slot) = inner.rx.try_lock() else {
            // A stream reader that just ended may still be finishing its last read.
            thread::park_timeout(Duration::from_millis(1));
            continue;
        };
        let side = side_slot.as_mut().expect("synchronous receive owner");
        if side.ended {
            return Ok(());
        }
        let alive = pump(inner, side, &mut Direct::none());
        if !matches!(alive, Ok(true)) {
            side.ended = true;
            drop(side_slot);
            inner.close();
            return alive.map(|_| ());
        }
        drop(side_slot);
        inner.wake_follower();
    }
}

/// Opens every whole record already in the buffer. `Ok(false)` when the session is over.
fn process(inner: &Arc<Inner>, side: &mut RxSide, direct: &mut Direct) -> io::Result<bool> {
    if !pending_plain(inner, side, direct)? { return Ok(false); }
    if direct.blocked { return Ok(true); }
    let RxSide { reader, parser, .. } = side;
    {
        // Open every whole record that is already here.
        while reader.end - reader.start >= 5 {
            let len = usize::from(u16::from_be_bytes([reader.buf[reader.start + 3], reader.buf[reader.start + 4]]));
            if len > MAX_CIPHERTEXT {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "TLS record too large"));
            }
            if reader.end - reader.start < 5 + len {
                break;
            }
            let record = reader.start..reader.start + 5 + len;
            reader.start = record.end;
            let (kind, plain) = reader.cipher.as_mut().expect("record TLS").open(&mut reader.buf[record.clone()])?;
            let body = record.start + 5..record.start + 5 + plain;
            let next = if kind == CONTENT_APPDATA {
                let next = parser.feed(inner, &reader.buf[body.clone()], direct, Some(body.start))?;
                if direct.blocked {
                    side.pending = Some(body.start + direct.consumed..body.end);
                    return Ok(true);
                }
                next
            } else {
                let mut next = Next::Go;
                for event in tls::control(kind, &reader.buf[body], &mut reader.hs)? {
                    match event {
                        Control::Closed => next = Next::Stop,
                        Control::KeyUpdate(requested) => {
                            reader.cipher = Some(inner.kernel.lock().expect("kernel").next_rx()?);
                            if requested {
                                inner.submit(Out::KeyUpdate, false)?;
                            }
                        }
                        Control::Ignored => {}
                    }
                }
                next
            };
            if !finish_next(inner, next) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// A paused PSH keeps its already authenticated bytes in the receive slab.
/// Resuming queue space must never decrypt that TLS record a second time.
fn pending_plain(inner: &Arc<Inner>, side: &mut RxSide, direct: &mut Direct) -> io::Result<bool> {
    if let Some(range) = side.pending.clone() {
        let next = side.parser.feed(inner, &side.reader.buf[range.clone()], direct, Some(range.start))?;
        if !finish_next(inner, next) { side.ended = true; return Ok(false); }
        side.pending = direct.blocked.then_some(range.start + direct.consumed..range.end);
    }
    Ok(true)
}

enum State {
    Header,
    Psh { sid: u32, left: usize },
    Ctrl { cmd: u8, sid: u32, left: usize },
    Skip { left: usize },
}

enum Auth {
    Hash { buf: [u8; 34], have: usize },
    Padding { left: usize },
}

struct Parser {
    role: Role,
    state: State,
    header: [u8; HEADER],
    have: usize,
    ctrl: Vec<u8>,
    auth: Option<Auth>,
    server: Option<Server>,
    settings_seen: bool,
    last: Option<(u32, Arc<Core>)>,
}

impl Parser {
    fn new(role: Role, server: Option<Server>) -> Self {
        let auth = (role == Role::Server).then_some(Auth::Hash { buf: [0; 34], have: 0 });
        Self {
            role,
            state: State::Header,
            header: [0; HEADER],
            have: 0,
            ctrl: Vec::new(),
            auth,
            server,
            settings_seen: false,
            last: None,
        }
    }

    fn feed(&mut self, inner: &Arc<Inner>, mut data: &[u8], direct: &mut Direct, base: Option<usize>) -> io::Result<Next> {
        let length = data.len();
        let initial = data.len();
        direct.consumed = 0;
        direct.blocked = false;
        while !data.is_empty() {
            if let Some(auth) = &mut self.auth {
                match auth {
                    Auth::Hash { buf, have } => {
                        let n = (34 - *have).min(data.len());
                        buf[*have..*have + n].copy_from_slice(&data[..n]);
                        *have += n;
                        data = &data[n..];
                        if *have == 34 {
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&buf[..32]);
                            let padding = usize::from(u16::from_be_bytes([buf[32], buf[33]]));
                            let server = self.server.as_mut().expect("server");
                            if !server.inbound.authenticate(&hash) {
                                return Ok(Next::Stop);
                            }
                            server.user = hash;
                            *auth = Auth::Padding { left: padding };
                        }
                    }
                    Auth::Padding { left } => {
                        let n = (*left).min(data.len());
                        *left -= n;
                        data = &data[n..];
                    }
                }
                if matches!(self.auth, Some(Auth::Padding { left: 0 })) {
                    self.auth = None;
                    inner.tcp.set_read_timeout(Some(READ_SLICE))?;
                }
                continue;
            }
            match &mut self.state {
                State::Header => {
                    let n = (HEADER - self.have).min(data.len());
                    self.header[self.have..self.have + n].copy_from_slice(&data[..n]);
                    self.have += n;
                    data = &data[n..];
                    if self.have == HEADER {
                        self.have = 0;
                        let cmd = self.header[0];
                        let sid = u32::from_be_bytes([self.header[1], self.header[2], self.header[3], self.header[4]]);
                        let len = usize::from(u16::from_be_bytes([self.header[5], self.header[6]]));
                        match self.begin(inner, cmd, sid, len)? {
                            Next::Go => {}
                            other => return Ok(other),
                        }
                    }
                }
                State::Psh { sid, left } => {
                    let n = (*left).min(data.len());
                    let sid = *sid;
                    let remaining = *left - n;
                    if !self.deliver(inner, sid, &data[..n], direct, base.map(|base| base + length - data.len())) {
                        direct.blocked = true;
                        direct.consumed = initial - data.len();
                        return Ok(Next::Go);
                    }
                    self.state = if remaining == 0 { State::Header } else { State::Psh { sid, left: remaining } };
                    data = &data[n..];
                }
                State::Ctrl { cmd, sid, left } => {
                    let n = (*left).min(data.len());
                    self.ctrl.extend_from_slice(&data[..n]);
                    *left -= n;
                    data = &data[n..];
                    if *left == 0 {
                        let (cmd, sid) = (*cmd, *sid);
                        self.state = State::Header;
                        let body = std::mem::take(&mut self.ctrl);
                        let next = self.control(inner, cmd, sid, &body, true)?;
                        self.ctrl = body;
                        self.ctrl.clear();
                        match next {
                            Next::Go => {}
                            other => return Ok(other),
                        }
                    }
                }
                State::Skip { left } => {
                    let n = (*left).min(data.len());
                    *left -= n;
                    data = &data[n..];
                    if *left == 0 {
                        self.state = State::Header;
                    }
                }
            }
        }
        direct.consumed = initial - data.len();
        Ok(Next::Go)
    }

    /// A header arrived. Commands without data in mihomo (SYN, FIN, heartbeats) act at once;
    /// mihomo would not read data after them, so any is skipped here.
    fn begin(&mut self, inner: &Arc<Inner>, cmd: u8, sid: u32, len: usize) -> io::Result<Next> {
        self.state = State::Header;
        let next = match cmd {
            CMD_PSH => {
                if len > 0 {
                    self.state = State::Psh { sid, left: len };
                }
                Next::Go
            }
            CMD_SETTINGS | CMD_ALERT | CMD_UPDATE_PADDING_SCHEME | CMD_SYNACK | CMD_SERVER_SETTINGS => {
                if len > 0 {
                    self.ctrl.clear();
                    self.state = State::Ctrl { cmd, sid, left: len };
                    Next::Go
                } else {
                    self.control(inner, cmd, sid, &[], false)?
                }
            }
            CMD_SYN => self.syn(inner, sid)?,
            CMD_FIN => {
                let core = inner.streams.lock().expect("streams").remove(&sid);
                if self.last.as_ref().is_some_and(|(last, _)| *last == sid) {
                    self.last = None;
                }
                if let Some(core) = core {
                    core.finish(None);
                }
                Next::Go
            }
            CMD_HEART_REQUEST => {
                inner.submit(Out::Frames { cmd: CMD_HEART_RESPONSE, sid, data: &[] }, false)?;
                Next::Go
            }
            _ => Next::Go,
        };
        // WASTE, the data mihomo would not read after SYN, FIN and heartbeats, and unknown commands.
        if len > 0 && !matches!(cmd, CMD_PSH | CMD_SETTINGS | CMD_ALERT | CMD_UPDATE_PADDING_SCHEME | CMD_SYNACK | CMD_SERVER_SETTINGS) {
            self.state = State::Skip { left: len };
        }
        Ok(next)
    }

    fn syn(&mut self, inner: &Arc<Inner>, sid: u32) -> io::Result<Next> {
        if self.role == Role::Client {
            // mihomo's client has no stream handler and closes what the server opens.
            inner.submit(Out::Frames { cmd: CMD_FIN, sid, data: &[] }, false)?;
            return Ok(Next::Go);
        }
        if !self.settings_seen {
            inner.submit(Out::Frames { cmd: CMD_ALERT, sid: 0, data: b"client did not send its settings" }, false)?;
            return Ok(Next::StopAfterFlush);
        }
        let mut streams = inner.streams.lock().expect("streams");
        streams.entry(sid).or_insert_with(|| Arc::new(Core::new(sid, Parse::Addr(Vec::new()), Arc::downgrade(inner))));
        Ok(Next::Go)
    }

    fn control(&mut self, inner: &Arc<Inner>, cmd: u8, sid: u32, body: &[u8], has_data: bool) -> io::Result<Next> {
        match cmd {
            CMD_SYNACK => {
                *inner.synack_deadline.lock().expect("synack") = None;
                if has_data {
                    let core = inner.streams.lock().expect("streams").get(&sid).cloned();
                    if let Some(core) = core {
                        core.finish(Some(format!("remote: {}", String::from_utf8_lossy(body))));
                    }
                }
            }
            CMD_SETTINGS if has_data && self.role == Role::Server => {
                self.settings_seen = true;
                let map = string_map(body);
                let scheme = inner.padding.load();
                if map.get("padding-md5").map(String::as_str) != Some(scheme.md5()) {
                    inner.submit(Out::Frames { cmd: CMD_UPDATE_PADDING_SCHEME, sid: 0, data: scheme.raw() }, false)?;
                }
                if let Some(version) = map.get("v").and_then(|v| go_atoi(v)).filter(|v| *v >= 2) {
                    inner.peer_version.store(version as u8, Ordering::Release);
                    let reply = frame::string_map(&[("v", "2")]);
                    inner.submit(Out::Frames { cmd: CMD_SERVER_SETTINGS, sid: 0, data: &reply }, false)?;
                }
            }
            CMD_ALERT if has_data => return Ok(Next::Stop),
            CMD_UPDATE_PADDING_SCHEME if has_data && self.role == Role::Client => {
                inner.padding.update(body);
            }
            CMD_SERVER_SETTINGS if has_data && self.role == Role::Client => {
                if let Some(version) = string_map(body).get("v").and_then(|v| go_atoi(v)) {
                    inner.peer_version.store(version as u8, Ordering::Release);
                }
            }
            _ => {}
        }
        Ok(Next::Go)
    }

    fn deliver(&mut self, inner: &Arc<Inner>, sid: u32, chunk: &[u8], direct: &mut Direct, offset: Option<usize>) -> bool {
        if !self.last.as_ref().is_some_and(|(last, _)| *last == sid) {
            let core = inner.streams.lock().expect("streams").get(&sid).cloned();
            match core {
                Some(core) => self.last = Some((sid, core)),
                None => return true,
            }
        }
        let core = &self.last.as_ref().expect("stream").1;
        if core.local_closed.load(Ordering::Acquire) {
            return true;
        }
        let own = direct.sid == Some(sid);
        let mut rx = core.rx.lock().expect("rx");
        if matches!(rx.parse, Parse::Data) {
            let borrowed = if own { direct.capture(offset, chunk.len()) } else { 0 };
            let accepted = borrowed == chunk.len() || push_data(inner, core, rx, &chunk[borrowed..], own);
            direct.delivered |= own && accepted;
            direct.queued |= own && borrowed < chunk.len();
            return accepted;
        }
        let server = self.server.as_ref().expect("server");
        let parse = std::mem::replace(&mut rx.parse, Parse::Data);
        let (parse, rest, close) = server_parse(inner, core, server, parse, chunk);
        rx.parse = parse;
        if close {
            drop(rx);
            let core = Arc::clone(core);
            self.last = None;
            // An address mihomo cannot read ends the stream with FIN.
            let removed = inner.streams.lock().expect("streams").remove(&sid);
            if removed.is_some() {
                let _ = inner.submit(Out::Frames { cmd: CMD_FIN, sid, data: &[] }, false);
            }
            core_finish_local(&core);
            return true;
        }
        if !rest.is_empty() {
            direct.queued |= own;
            direct.delivered |= own;
            assert!(push_data(inner, core, rx, &rest, own), "newly addressed stream has room");
        }
        true
    }
}

fn core_finish_local(core: &Arc<Core>) {
    core.local_closed.store(true, Ordering::Release);
    core.finish(None);
}

/// Appends application bytes, waiting while the stream holds more than its bound, unless the
/// thread delivering them is that stream's own reader (`own`).
fn push_data(inner: &Inner, core: &Core, mut rx: MutexGuard<'_, Rx>, chunk: &[u8], own: bool) -> bool {
    loop {
        if core.local_closed.load(Ordering::Acquire) || inner.closed.load(Ordering::Acquire) {
            return true;
        }
        if own || rx.queue.is_empty() || rx.queue.len() + chunk.len() <= STREAM_RX_LIMIT {
            break;
        }
        rx.reader_waiting = true;
        if inner.native.is_some() { return false; }
        rx = core.space_cv.wait(rx).expect("rx");
    }
    rx.queue.push(chunk);
    for (_, waker) in rx.task_readers.drain(..) { waker.wake(); }
    if rx.app_waiting {
        rx.app_waiting = false;
        core.data_cv.notify_one();
    }
    true
}

/// Server side of a stream before it carries plain data: the address, then for UoT the request
/// and the packets. Returns the next state, bytes for the application, and whether to close.
fn server_parse(inner: &Arc<Inner>, core: &Arc<Core>, server: &Server, parse: Parse, chunk: &[u8]) -> (Parse, Vec<u8>, bool) {
    match parse {
        Parse::Data => (Parse::Data, chunk.to_vec(), false),
        Parse::Addr(mut acc) => {
            acc.extend_from_slice(chunk);
            match Target::decode(&acc, Family::Socks) {
                Ok(None) => (Parse::Addr(acc), Vec::new(), false),
                Err(_) => (Parse::Data, Vec::new(), true),
                Ok(Some((target, used))) => {
                    let rest = acc[used..].to_vec();
                    // mihomo answers before the outbound is dialed.
                    if inner.peer_version.load(Ordering::Acquire) >= 2 {
                        let _ = inner.submit(Out::Frames { cmd: CMD_SYNACK, sid: core.sid, data: &[] }, false);
                    }
                    if target.host == UOT_V2 {
                        server_parse(inner, core, server, Parse::UotRequest(Vec::new()), &rest)
                    } else if target.host == UOT_V1 {
                        let uot = Uot::new(None);
                        server_parse(inner, core, server, Parse::Uot(Box::new(uot)), &rest)
                    } else {
                        server.inbound.open(Opened {
                            user: server.user,
                            peer: server.peer,
                            target,
                            flow: Flow::Tcp(Stream { core: Arc::clone(core), session: Arc::clone(inner) }),
                        });
                        (Parse::Data, rest, false)
                    }
                }
            }
        }
        Parse::UotRequest(mut acc) => {
            acc.extend_from_slice(chunk);
            if acc.is_empty() {
                return (Parse::UotRequest(acc), Vec::new(), false);
            }
            match Target::decode(&acc[1..], Family::Socks) {
                Ok(None) => (Parse::UotRequest(acc), Vec::new(), false),
                Err(_) => (Parse::Data, Vec::new(), true),
                Ok(Some((target, used))) => {
                    let connect = (acc[0] != 0).then_some(target);
                    let rest = acc[1 + used..].to_vec();
                    let uot = Uot::new(connect);
                    server_parse(inner, core, server, Parse::Uot(Box::new(uot)), &rest)
                }
            }
        }
        Parse::Uot(mut uot) => {
            let ok = if uot.tail.is_empty() {
                let used = uot_packets(inner, core, server, &mut uot, chunk);
                used.map(|used| uot.tail.extend_from_slice(&chunk[used..]))
            } else {
                let mut tail = std::mem::take(&mut uot.tail);
                tail.extend_from_slice(chunk);
                let used = uot_packets(inner, core, server, &mut uot, &tail);
                used.map(|used| {
                    tail.copy_within(used.., 0);
                    tail.truncate(tail.len() - used);
                    uot.tail = tail;
                })
            };
            match ok {
                Some(()) => (Parse::Uot(uot), Vec::new(), false),
                None => (Parse::Data, Vec::new(), true),
            }
        }
    }
}

/// Hands out every whole packet in `bytes`; returns how many bytes were used, `None` on a bad address.
fn uot_packets(inner: &Arc<Inner>, core: &Arc<Core>, server: &Server, uot: &mut Uot, bytes: &[u8]) -> Option<usize> {
    let mut used = 0;
    loop {
        let rest = &bytes[used..];
        let (target, addr_len) = match &uot.connect {
            Some(_) => (None, 0),
            None => match Target::decode(rest, Family::Uot) {
                Ok(None) => return Some(used),
                Err(_) => return None,
                Ok(Some((target, len))) => (Some(target), len),
            },
        };
        let Some(len) = rest.get(addr_len..addr_len + 2) else { return Some(used) };
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        let Some(payload) = rest.get(addr_len + 2..addr_len + 2 + len) else { return Some(used) };
        let target = match target {
            Some(target) => target,
            None => uot.connect.clone().expect("connect target"),
        };
        let key = Target { host: target.host.to_ascii_lowercase(), port: target.port };
        let leg = match uot.legs.get(&key) {
            Some(leg) if !leg.is_closed() => Arc::clone(leg),
            _ => {
                let leg = Arc::new(LegCore {
                    target: target.clone(),
                    connect: uot.connect.is_some(),
                    rx: Mutex::new(LegRx { queue: ByteQueue::new(), closed: false, waiting: false }),
                    cv: Condvar::new(),
                });
                uot.legs.insert(key, Arc::clone(&leg));
                server.inbound.open(Opened {
                    user: server.user,
                    peer: server.peer,
                    target,
                    flow: Flow::Udp(Leg {
                        core: Arc::clone(&leg), stream: Arc::clone(core), session: Arc::clone(inner),
                        datagrams: uot.datagrams.clone(),
                    }),
                });
                leg
            }
        };
        leg.push(payload);
        used += addr_len + 2 + len;
    }
}
