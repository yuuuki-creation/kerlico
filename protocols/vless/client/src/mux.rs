//! Mux as Xray's VLESS outbound uses it: the carrier each flow takes, the Mux.Cool
//! connections that `land` calls share, and the sessions on them.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use kerlico_shared::{Destination, InboundStream, OpenError, PlaneFault, Settings, Transport};
use kerlico_vless::{decode_mux, Addr, Command, HeaderError, MuxFrame, UdpFraming, DATA, END, KEEP, KEEPALIVE, NEW};

use super::{map_io, parse_addr, retry_io, shared, Flow, Link, MuxOutbox, Shared};

/// Xray's `MaxConnection`: a carrier takes no new session after this many.
const CARRIER_SESSIONS: u16 = 128;
/// Xray closes a carrier that stayed without sessions through a 16-second monitor tick.
const CARRIER_IDLE: Duration = Duration::from_secs(16);
/// Xray's client sends NEW without data when the first payload is not there this soon.
const FIRST_PAYLOAD: Duration = Duration::from_millis(100);
const POLL: Duration = Duration::from_millis(200);
const INBOX_BYTES: usize = 1024 * 1024;
const INBOX_DATAGRAMS: usize = 256;

/// A UDP address on the wire.
pub(crate) type Target = (Addr, u16);

pub(crate) fn target(destination: &Destination) -> Result<Target, OpenError> {
    Ok((parse_addr(destination.host())?, destination.port()))
}

/// Xray's outbound `mux` object. `true` is `{"enabled": true}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    /// Sessions per carrier; `None` for a negative `concurrency`, which keeps TCP off Mux.
    concurrency: Option<u16>,
    xudp: XudpPool,
    udp443: Udp443,
}

/// `xudpConcurrency`: zero shares the TCP carriers, positive gives UDP carriers of its own,
/// negative keeps UDP off the pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XudpPool {
    Shared,
    Own(u16),
    Bypass,
}

/// `xudpProxyUDP443`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Udp443 {
    Reject,
    Allow,
    Skip,
}

impl Policy {
    /// `None` when Mux is off. XDrive always uses Mux and refuses the values that bypass it,
    /// as Xray's config check does.
    pub(crate) fn parse(settings: &Settings, xdrive: bool) -> Result<Option<Self>, OpenError> {
        let text = settings.optional_text("mux")?.unwrap_or("false");
        let value: serde_json::Value = serde_json::from_str(text).map_err(|_| OpenError::Settings)?;
        let (enabled, concurrency, xudp, udp443) = match &value {
            serde_json::Value::Bool(enabled) => (*enabled, 0, 0, ""),
            serde_json::Value::Object(fields) => {
                let count = |key: &str| fields.get(key).map_or(Ok(0), |value| {
                    value.as_i64().and_then(|count| i16::try_from(count).ok()).ok_or(OpenError::Settings)
                });
                (
                    fields.get("enabled").map_or(Ok(false), |value| value.as_bool().ok_or(OpenError::Settings))?,
                    count("concurrency")?,
                    count("xudpConcurrency")?,
                    fields.get("xudpProxyUDP443").map_or(Ok(""), |value| value.as_str().ok_or(OpenError::Settings))?,
                )
            }
            _ => return Err(OpenError::Settings),
        };
        let policy = Self {
            concurrency: match concurrency {
                count if count < 0 => None,
                0 => Some(8),
                count => Some(count.unsigned_abs()),
            },
            xudp: match xudp {
                count if count < 0 => XudpPool::Bypass,
                0 => XudpPool::Shared,
                count => XudpPool::Own(count.unsigned_abs()),
            },
            udp443: match udp443 {
                "" | "reject" => Udp443::Reject,
                "allow" => Udp443::Allow,
                "skip" => Udp443::Skip,
                _ => return Err(OpenError::Settings),
            },
        };
        if xdrive {
            if policy.concurrency.is_none() || policy.xudp == XudpPool::Bypass || policy.udp443 == Udp443::Skip {
                return Err(OpenError::Settings);
            }
            return Ok(Some(policy));
        }
        Ok(enabled.then_some(policy))
    }
}

/// Xray's `mux` and `xudp` client managers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PoolKind {
    Mux,
    Xudp,
}

/// How one flow reaches the server. Xray's outbound handler first picks a Mux pool; failing
/// that its VLESS outbound picks the request command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// A carrier of its own with the TCP or UDP command.
    Direct(Command),
    /// A carrier of its own with the Mux command and one XUDP session, Xray's `v1.mux.cool:666`.
    Xudp,
    /// A session on a shared Mux carrier, Xray's `v1.mux.cool:9527`, at this concurrency.
    Pooled(PoolKind, u16),
}

pub(crate) fn route(flow: Flow, policy: Option<Policy>, destination: &Destination) -> Result<Route, OpenError> {
    let udp = destination.transport() == Transport::Udp;
    let port = destination.port();
    if let Some(policy) = policy {
        let pooled = match (udp, policy.udp443, policy.xudp) {
            (true, Udp443::Reject, _) if port == 443 => return Err(OpenError::Settings),
            (true, Udp443::Skip, _) if port == 443 => None,
            (true, _, XudpPool::Own(concurrency)) => Some(Route::Pooled(PoolKind::Xudp, concurrency)),
            (true, _, XudpPool::Bypass) => None,
            _ => policy.concurrency.map(|concurrency| Route::Pooled(PoolKind::Mux, concurrency)),
        };
        if let Some(route) = pooled {
            // Xray's server breaks a Vision Mux connection once it carries TCP.
            if flow.vision() && !udp {
                return Err(OpenError::Settings);
            }
            return Ok(route);
        }
    }
    Ok(match flow {
        _ if !udp => Route::Direct(Command::Tcp),
        Flow::Vision { udp443: false } if port == 443 => return Err(OpenError::Settings),
        Flow::Vision { .. } => Route::Xudp,
        // Xray's cone UDP is on unless the `xray.cone.disabled` environment flag is set;
        // Kerlico has no such switch.
        Flow::Plain if port == 53 || port == 443 => Route::Direct(Command::Udp),
        Flow::Plain => Route::Xudp,
    })
}

/// Carriers one landing shares across `land` calls.
#[derive(Default)]
pub(crate) struct Pool {
    mux: Picker,
    xudp: Picker,
}

pub(crate) fn pool(host: &str, port: u16, settings: &Settings) -> Result<Arc<Pool>, OpenError> {
    static POOLS: OnceLock<Mutex<VecDeque<Shared<Pool>>>> = OnceLock::new();
    shared(&POOLS, host, port, settings, || Ok(Pool::default()))
}

impl Pool {
    pub(crate) fn session(
        &self,
        kind: PoolKind,
        concurrency: u16,
        destination: &Destination,
        global_id: Option<NonZeroU64>,
        dial: impl FnOnce() -> Result<(Link, Link), OpenError>,
    ) -> Result<Session, OpenError> {
        let picker = match kind {
            PoolKind::Mux => &self.mux,
            PoolKind::Xudp => &self.xudp,
        };
        let udp = destination.transport() == Transport::Udp;
        let target = target(destination)?;
        let (carrier, id, inbox) = picker.session(concurrency, udp, dial)?;
        Ok(Session::new(carrier, id, inbox, udp, UdpFraming::Mux, target, global_id))
    }
}

#[derive(Default)]
struct Picker {
    carriers: Mutex<Vec<Arc<Carrier>>>,
    /// Concurrent opens wait for one dial instead of each dialing a carrier.
    dialing: Mutex<()>,
}

type Allocated = (Arc<Carrier>, u16, Arc<Inbox>);

impl Picker {
    fn session(&self, concurrency: u16, udp: bool, dial: impl FnOnce() -> Result<(Link, Link), OpenError>) -> Result<Allocated, OpenError> {
        if let Some(found) = self.pick(concurrency, udp) {
            return Ok(found);
        }
        let _dialing = self.dialing.lock().expect("mux pool");
        if let Some(found) = self.pick(concurrency, udp) {
            return Ok(found);
        }
        let (read, write) = dial()?;
        let carrier = Carrier::start(read, write, 1..CARRIER_SESSIONS + 1);
        let (id, inbox) = carrier.allocate(concurrency, udp).ok_or(OpenError::Transport)?;
        self.carriers.lock().expect("mux pool").push(Arc::clone(&carrier));
        Ok((carrier, id, inbox))
    }

    fn pick(&self, concurrency: u16, udp: bool) -> Option<Allocated> {
        let mut carriers = self.carriers.lock().expect("mux pool");
        carriers.retain(|carrier| !carrier.closed());
        carriers.iter().find_map(|carrier| {
            carrier.allocate(concurrency, udp).map(|(id, inbox)| (Arc::clone(carrier), id, inbox))
        })
    }
}

/// One VLESS connection with the Mux command and the sessions on it.
struct Carrier {
    outbox: Mutex<Option<MuxOutbox>>,
    state: Mutex<CarrierState>,
}

struct CarrierState {
    sessions: HashMap<u16, Arc<Inbox>>,
    /// Session ids not handed out yet. The carrier is retired once none are left.
    unused: Range<u16>,
    idle_since: Instant,
    closed: bool,
}

impl Carrier {
    fn start(mut read: Link, mut write: Link, ids: Range<u16>) -> Arc<Self> {
        read.set_timeout(POLL);
        write.set_timeout(POLL);
        let carrier = Arc::new(Self {
            outbox: Mutex::new(Some(MuxOutbox::new(write))),
            state: Mutex::new(CarrierState { sessions: HashMap::new(), unused: ids, idle_since: Instant::now(), closed: false }),
        });
        let reader = Arc::clone(&carrier);
        std::thread::spawn(move || reader.run(read));
        carrier
    }

    fn closed(&self) -> bool {
        self.state.lock().expect("mux carrier").closed
    }

    fn allocate(&self, concurrency: u16, udp: bool) -> Option<(u16, Arc<Inbox>)> {
        let mut state = self.state.lock().expect("mux carrier");
        if state.closed || state.sessions.len() >= usize::from(concurrency) {
            return None;
        }
        let id = state.unused.next()?;
        let inbox = Arc::new(Inbox::new(udp));
        state.sessions.insert(id, Arc::clone(&inbox));
        Some((id, inbox))
    }

    fn send(&self, frame: &MuxFrame) -> std::io::Result<()> {
        let result = match self.outbox.lock().expect("mux carrier").as_mut() {
            Some(outbox) => outbox.send(frame),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        };
        if result.as_ref().is_err_and(|error| !retry_io(error)) {
            self.close();
        }
        result
    }

    fn end(&self, id: u16) {
        let result = match self.outbox.lock().expect("mux carrier").as_mut() {
            Some(outbox) => outbox.end(id, false),
            None => return,
        };
        if result.is_err_and(|error| !retry_io(&error)) {
            self.close();
        }
    }

    fn flush(&self) {
        let result = match self.outbox.try_lock() {
            Ok(mut outbox) => outbox.as_mut().map(MuxOutbox::flush),
            Err(_) => None,
        };
        if result.is_some_and(|result| result.is_err_and(|error| !retry_io(&error))) {
            self.close();
        }
    }

    fn finish(&self, id: u16, opened: bool) {
        {
            let mut state = self.state.lock().expect("mux carrier");
            state.sessions.remove(&id);
            if state.sessions.is_empty() {
                state.idle_since = Instant::now();
            }
        }
        if opened {
            self.end(id);
        }
        self.close_if(|state| state.sessions.is_empty() && state.unused.is_empty());
    }

    fn close(&self) {
        self.close_if(|_| true);
    }

    /// Closes under the same lock `allocate` takes, so no session lands on a closing carrier.
    fn close_if(&self, done: impl FnOnce(&CarrierState) -> bool) {
        let inboxes: Vec<Arc<Inbox>> = {
            let mut state = self.state.lock().expect("mux carrier");
            if state.closed || !done(&state) {
                return;
            }
            state.closed = true;
            state.sessions.values().cloned().collect()
        };
        self.outbox.lock().expect("mux carrier").take();
        for inbox in inboxes {
            inbox.end();
        }
    }

    fn run(self: Arc<Self>, mut read: Link) {
        let mut pending = Vec::new();
        let mut buf = vec![0; 16 * 1024];
        while !self.closed() {
            let n = match read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) if retry_io(&error) => {
                    self.flush();
                    self.close_if(|state| {
                        state.sessions.is_empty() && (state.unused.is_empty() || state.idle_since.elapsed() >= CARRIER_IDLE)
                    });
                    continue;
                }
                Err(_) => break,
            };
            pending.extend_from_slice(&buf[..n]);
            if !self.deliver_all(&mut pending) {
                break;
            }
        }
        self.close();
    }

    fn deliver_all(&self, pending: &mut Vec<u8>) -> bool {
        loop {
            match decode_mux(pending) {
                Ok((frame, used)) => {
                    pending.drain(..used);
                    if !self.deliver(frame) {
                        return false;
                    }
                }
                Err(HeaderError::Short) => return true,
                Err(HeaderError::Bad) => return false,
            }
        }
    }

    /// Follows Xray's client worker: it ignores NEW and KEEPALIVE, and an unknown status
    /// breaks the carrier.
    fn deliver(&self, frame: MuxFrame) -> bool {
        let inbox = self.state.lock().expect("mux carrier").sessions.get(&frame.id).cloned();
        match (frame.status, inbox) {
            (NEW | KEEPALIVE, _) | (END, None) => {}
            (END, Some(inbox)) => inbox.end(),
            (KEEP, Some(inbox)) => {
                if !frame.payload.is_empty() {
                    let port = frame.port;
                    inbox.push(frame.address.map(|address| (address, port)), frame.payload);
                }
            }
            // Xray asks the server to end a session this side no longer has.
            (KEEP, None) => {
                if frame.option & DATA != 0 {
                    self.end(frame.id);
                }
            }
            _ => return false,
        }
        true
    }
}

/// Frames a carrier received for one session that the session has not read yet.
struct Inbox {
    queue: Mutex<Queue>,
    ready: Condvar,
}

struct Queue {
    received: Received,
    size: usize,
    ended: bool,
    detached: bool,
}

enum Received {
    Stream(VecDeque<u8>),
    Datagrams(VecDeque<(Option<Target>, Vec<u8>)>),
}

impl Inbox {
    fn new(udp: bool) -> Self {
        let received = if udp { Received::Datagrams(VecDeque::new()) } else { Received::Stream(VecDeque::new()) };
        Self { queue: Mutex::new(Queue { received, size: 0, ended: false, detached: false }), ready: Condvar::new() }
    }

    /// A full stream holds the carrier's reader, as Xray's bounded pipe does; a full
    /// datagram queue drops the datagram.
    fn push(&self, source: Option<Target>, payload: Vec<u8>) {
        let len = payload.len();
        let full = |queue: &Queue| queue.size > 0 && queue.size + len > INBOX_BYTES;
        let mut queue = self.queue.lock().expect("mux inbox");
        while matches!(queue.received, Received::Stream(_)) && full(&queue) && !queue.ended && !queue.detached {
            queue = self.ready.wait_timeout(queue, POLL).expect("mux inbox").0;
        }
        if queue.ended || queue.detached {
            return;
        }
        let room = !full(&queue);
        match &mut queue.received {
            Received::Stream(bytes) => bytes.extend(&payload),
            Received::Datagrams(packets) if room && packets.len() < INBOX_DATAGRAMS => packets.push_back((source, payload)),
            Received::Datagrams(_) => return,
        }
        queue.size += len;
        self.ready.notify_all();
    }

    fn read(&self, buf: &mut [u8]) -> Result<(usize, Option<Target>), PlaneFault> {
        let mut queue = self.queue.lock().expect("mux inbox");
        loop {
            let taken = match &mut queue.received {
                Received::Stream(bytes) if !bytes.is_empty() => {
                    let n = bytes.len().min(buf.len());
                    for (slot, byte) in buf.iter_mut().zip(bytes.drain(..n)) {
                        *slot = byte;
                    }
                    Some((n, None))
                }
                Received::Stream(_) => None,
                Received::Datagrams(packets) => match packets.front() {
                    Some((_, packet)) if packet.len() > buf.len() => return Err(PlaneFault::Transport),
                    Some(_) => {
                        let (source, packet) = packets.pop_front().expect("queued datagram");
                        buf[..packet.len()].copy_from_slice(&packet);
                        Some((packet.len(), source))
                    }
                    None => None,
                },
            };
            if let Some((n, source)) = taken {
                queue.size -= n;
                self.ready.notify_all();
                return Ok((n, source));
            }
            if queue.ended {
                return Err(PlaneFault::Closed);
            }
            let (next, wait) = self.ready.wait_timeout(queue, POLL).expect("mux inbox");
            queue = next;
            if wait.timed_out() {
                return Err(PlaneFault::Again);
            }
        }
    }

    fn end(&self) {
        self.queue.lock().expect("mux inbox").ended = true;
        self.ready.notify_all();
    }

    fn detach(&self) {
        self.queue.lock().expect("mux inbox").detached = true;
        self.ready.notify_all();
    }
}

/// One Mux session. A TCP session carries a byte stream. A UDP session carries datagrams,
/// each to the first destination or to one it names.
pub(crate) struct Session {
    carrier: Arc<Carrier>,
    id: u16,
    inbox: Arc<Inbox>,
    udp: bool,
    /// XUDP for the only session on a carrier of its own, Mux on a shared carrier.
    framing: UdpFraming,
    target: Target,
    /// Sent on the NEW frame of a UDP session, as Xray's mux and XUDP writers do.
    global_id: Option<NonZeroU64>,
    opened: Mutex<bool>,
    created: Instant,
}

impl Session {
    fn new(carrier: Arc<Carrier>, id: u16, inbox: Arc<Inbox>, udp: bool, framing: UdpFraming, target: Target, global_id: Option<NonZeroU64>) -> Self {
        Self { carrier, id, inbox, udp, framing, target, global_id, opened: Mutex::new(false), created: Instant::now() }
    }

    /// The only session on a carrier of its own, which closes with it.
    pub(crate) fn xudp((read, write): (Link, Link), destination: &Destination, global_id: Option<NonZeroU64>) -> Result<Self, OpenError> {
        let target = target(destination)?;
        let carrier = Carrier::start(read, write, 0..1);
        let (id, inbox) = carrier.allocate(1, true).ok_or(OpenError::Transport)?;
        Ok(Self::new(carrier, id, inbox, true, UdpFraming::Xudp, target, global_id))
    }

    fn frame(&self, first: bool, payload: Option<&[u8]>, to: Option<&Target>) -> MuxFrame {
        let address = if first { Some(to.unwrap_or(&self.target)) } else { to.filter(|_| self.udp) };
        MuxFrame {
            id: self.id,
            status: if first { NEW } else { KEEP },
            option: if payload.is_some() { DATA } else { 0 },
            network: if self.udp { 2 } else { 1 },
            port: address.map_or(0, |target| target.1),
            address: address.map(|target| target.0.clone()),
            payload: payload.unwrap_or_default().to_vec(),
            global_id: self.global_id.filter(|_| first && self.udp),
        }
    }

    fn send(&self, payload: &[u8], to: Option<&Target>) -> std::io::Result<()> {
        let mut opened = self.opened.lock().expect("mux session");
        self.carrier.send(&self.frame(!*opened, Some(payload), to))?;
        *opened = true;
        Ok(())
    }

    /// A server that speaks first still gets its connection, as Xray's NEW without data.
    fn open_quietly(&self) {
        if self.created.elapsed() < FIRST_PAYLOAD {
            return;
        }
        let Ok(mut opened) = self.opened.try_lock() else { return };
        if !*opened && self.carrier.send(&self.frame(true, None, None)).is_ok() {
            *opened = true;
        }
    }

    fn write_stream(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        let mut sent = 0;
        for chunk in buf.chunks(usize::from(u16::MAX)) {
            match self.send(chunk, None) {
                Ok(()) => sent += chunk.len(),
                Err(error) if retry_io(&error) && sent > 0 => break,
                Err(error) => return Err(map_io(error)),
            }
        }
        Ok(sent)
    }

    pub(crate) fn send_datagram(&self, datagram: &[u8], to: Option<&Target>) -> Result<usize, PlaneFault> {
        // Xray's writers skip an empty datagram and one too large for the framing.
        if datagram.is_empty() || !self.framing.carries(datagram) {
            return Ok(datagram.len());
        }
        match self.send(datagram, to) {
            Ok(()) => Ok(datagram.len()),
            // A congested carrier drops the datagram, as a full UDP socket would.
            Err(error) if retry_io(&error) => Ok(datagram.len()),
            Err(error) => Err(map_io(error)),
        }
    }

    pub(crate) fn recv_datagram(&self, buf: &mut [u8]) -> Result<(usize, Option<Target>), PlaneFault> {
        self.inbox.read(buf)
    }
}

impl InboundStream for Session {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.udp {
            self.open_quietly();
        }
        self.inbox.read(buf).map(|(n, _)| n)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        if self.udp {
            self.send_datagram(buf, None)
        } else {
            self.write_stream(buf)
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.inbox.detach();
        let opened = *self.opened.get_mut().expect("mux session");
        self.carrier.finish(self.id, opened);
    }
}
