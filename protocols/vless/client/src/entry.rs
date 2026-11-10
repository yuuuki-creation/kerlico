//! VLESS behind the client leaf's local SOCKS5 and HTTP entry, as Xray runs a socks or http
//! inbound in front of a vless outbound. TCP flows open as `land` does. A SOCKS UDP association
//! picks each datagram's carrier the way Xray's VLESS outbound picks the request command.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use kerlico_shared::{
    Association, Destination, InboundStream, OpenError, PeerAddr, PlaneFault, Settings, Stream,
    Transport, Upstream,
};
use kerlico_vless::{parse_id, xudp_global_id, Command};

use super::{land, mux, udp_session, Flow, UdpSession};

/// Plain UDP links one association keeps, one per destination. Xray's UDP dispatcher retires an
/// idle link after the same minute.
const PLAIN_LINKS: usize = 64;
const PLAIN_IDLE: Duration = Duration::from_secs(60);
const REPLY_QUEUE: usize = 256;

type Reply = (String, u16, Vec<u8>);

/// Settings that only fail when a carrier is dialed still fail on the first flow.
pub(crate) fn upstream(peer: &PeerAddr, settings: &Settings) -> Result<Arc<dyn Upstream>, OpenError> {
    let flow = Flow::parse(settings)?;
    let policy = mux::Policy::parse(settings, settings.text("network").ok() == Some("xdrive"))?;
    parse_id(settings.text("id")?).map_err(|_| OpenError::Settings)?;
    settings.text("encryption")?;
    Ok(Arc::new(Endpoint {
        host: peer.host().to_string(),
        port: peer.port(),
        settings: settings.clone(),
        flow,
        policy,
        closed: Arc::new(AtomicBool::new(false)),
    }))
}

struct Endpoint {
    host: String,
    port: u16,
    settings: Settings,
    flow: Flow,
    policy: Option<mux::Policy>,
    /// Set by `close`. Every stream and association this endpoint opened checks it.
    closed: Arc<AtomicBool>,
}

fn refused(error: OpenError) -> io::Error {
    match error {
        OpenError::Settings => io::Error::new(io::ErrorKind::InvalidInput, "VLESS 设置不允许这个目标"),
        OpenError::Transport | OpenError::Again => io::Error::new(io::ErrorKind::ConnectionRefused, "VLESS 连接失败"),
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "VLESS 上游已关闭")
}

impl Upstream for Endpoint {
    fn open_stream(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed());
        }
        let destination = Destination::new(host, port, Transport::Tcp)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "目标地址无效"))?;
        let stream = land(&self.host, self.port, &self.settings, &destination).map_err(refused)?;
        Ok(Box::new(TcpFlow { stream, upstream: self.closed.clone(), done: AtomicBool::new(false) }))
    }

    fn associate(&self) -> io::Result<Box<dyn Association>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed());
        }
        let (replies, inbox) = sync_channel(REPLY_QUEUE);
        Ok(Box::new(UdpAssociation {
            shared: Arc::new(Lanes {
                host: self.host.clone(),
                port: self.port,
                settings: self.settings.clone(),
                upstream: self.closed.clone(),
                done: AtomicBool::new(false),
                open: Mutex::new(HashMap::new()),
                replies,
            }),
            flow: self.flow,
            policy: self.policy,
            global_id: OnceLock::new(),
            inbox: Mutex::new(inbox),
        }))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// `InboundStream` returns `Again` after its own 200 ms wait, so `read_for` waits by calling it
/// again rather than by sleeping.
struct TcpFlow {
    stream: Box<dyn InboundStream>,
    upstream: Arc<AtomicBool>,
    done: AtomicBool,
}

impl TcpFlow {
    fn finished(&self) -> bool {
        self.done.load(Ordering::Acquire) || self.upstream.load(Ordering::Acquire)
    }
}

impl Stream for TcpFlow {
    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        let deadline = Instant::now() + wait;
        loop {
            if self.finished() {
                return Err(closed());
            }
            match self.stream.read_from_user(buf) {
                Ok(n) => return Ok(n),
                Err(PlaneFault::Again) if Instant::now() < deadline => continue,
                Err(PlaneFault::Again) => return Err(io::ErrorKind::TimedOut.into()),
                Err(PlaneFault::Closed) => return Ok(0),
                Err(PlaneFault::Transport) => return Err(io::Error::other("VLESS 读取失败")),
            }
        }
    }

    /// After `Again` the stream keeps the unsent tail and expects the same bytes again.
    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut rest = buf;
        while !rest.is_empty() {
            if self.finished() {
                return Err(closed());
            }
            match self.stream.write_to_user(rest) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => rest = &rest[n..],
                Err(PlaneFault::Again) => std::thread::sleep(Duration::from_millis(5)),
                Err(PlaneFault::Closed) => return Err(io::ErrorKind::BrokenPipe.into()),
                Err(PlaneFault::Transport) => return Err(io::Error::other("VLESS 写入失败")),
            }
        }
        Ok(())
    }

    fn close(&self) {
        self.done.store(true, Ordering::Release);
    }
}

/// The carrier one datagram takes. Xray keeps one link per association and picks its command
/// from the first destination. Here each datagram picks by its own destination, so a datagram
/// to port 53 or 443 never rides a plain link that was opened for another target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum LaneKey {
    /// The association's one XUDP or Mux UDP session; each datagram names its destination.
    Xudp,
    /// A plain UDP command link, which reaches only this destination.
    Plain(String, u16),
}

struct Lane {
    session: UdpSession,
    alive: AtomicBool,
    last: Mutex<Instant>,
}

impl Lane {
    fn touch(&self) {
        *self.last.lock().expect("udp lane") = Instant::now();
    }

    fn idle(&self) -> Duration {
        self.last.lock().expect("udp lane").elapsed()
    }
}

/// What the association shares with the reader thread of each lane.
struct Lanes {
    host: String,
    port: u16,
    settings: Settings,
    upstream: Arc<AtomicBool>,
    done: AtomicBool,
    open: Mutex<HashMap<LaneKey, Arc<Lane>>>,
    replies: SyncSender<Reply>,
}

impl Lanes {
    fn finished(&self) -> bool {
        self.done.load(Ordering::Acquire) || self.upstream.load(Ordering::Acquire)
    }

    /// Ends a lane. A newer lane that already took the key stays.
    fn retire(&self, key: &LaneKey, lane: &Arc<Lane>) {
        lane.alive.store(false, Ordering::Release);
        let mut open = self.open.lock().expect("udp lanes");
        if open.get(key).is_some_and(|current| Arc::ptr_eq(current, lane)) {
            open.remove(key);
        }
    }

    fn read(self: Arc<Self>, key: LaneKey, lane: Arc<Lane>) {
        let mut buf = vec![0; 65535];
        while !self.finished() && lane.alive.load(Ordering::Acquire) {
            match lane.session.recv_from(&mut buf) {
                Ok((n, source)) => {
                    lane.touch();
                    let _ = self.replies.try_send((source.host().to_string(), source.port(), buf[..n].to_vec()));
                }
                Err(PlaneFault::Again) if matches!(key, LaneKey::Plain(..)) && lane.idle() >= PLAIN_IDLE => break,
                Err(PlaneFault::Again) => {}
                Err(_) => break,
            }
        }
        self.retire(&key, &lane);
    }
}

struct UdpAssociation {
    shared: Arc<Lanes>,
    flow: Flow,
    policy: Option<mux::Policy>,
    /// Taken from the local application's UDP source on the first datagram. A carrier opened
    /// after a failure sends it again, so the server keeps the same outbound socket.
    global_id: OnceLock<Option<NonZeroU64>>,
    inbox: Mutex<Receiver<Reply>>,
}

impl UdpAssociation {
    fn lane(&self, key: &LaneKey, destination: &Destination, global_id: Option<NonZeroU64>) -> Option<Arc<Lane>> {
        let shared = &self.shared;
        {
            let mut open = shared.open.lock().expect("udp lanes");
            if let Some(lane) = open.get(key).filter(|lane| lane.alive.load(Ordering::Acquire)) {
                return Some(lane.clone());
            }
            if matches!(key, LaneKey::Plain(..)) {
                open.retain(|key, lane| matches!(key, LaneKey::Xudp) || lane.idle() < PLAIN_IDLE);
                if open.keys().filter(|key| matches!(key, LaneKey::Plain(..))).count() >= PLAIN_LINKS {
                    return None;
                }
            }
        }
        let session = udp_session(&shared.host, shared.port, &shared.settings, destination, global_id).ok()?;
        let lane = Arc::new(Lane { session, alive: AtomicBool::new(true), last: Mutex::new(Instant::now()) });
        shared.open.lock().expect("udp lanes").insert(key.clone(), lane.clone());
        let (reader, key, opened) = (shared.clone(), key.clone(), lane.clone());
        std::thread::spawn(move || reader.read(key, opened));
        Some(lane)
    }
}

impl Association for UdpAssociation {
    /// Xray's SOCKS inbound drops empty datagrams, and its dispatcher drops a datagram whose
    /// link fails to open; the next datagram opens again.
    fn send_to(&self, source: SocketAddr, host: &str, port: u16, payload: &[u8]) -> io::Result<()> {
        if self.shared.finished() {
            return Err(closed());
        }
        let global_id = *self.global_id.get_or_init(|| xudp_global_id(source));
        let Ok(destination) = Destination::new(host, port, Transport::Udp) else { return Ok(()) };
        if payload.is_empty() {
            return Ok(());
        }
        let key = match mux::route(self.flow, self.policy, &destination) {
            Ok(mux::Route::Direct(Command::Udp)) => LaneKey::Plain(host.to_string(), port),
            Ok(mux::Route::Xudp | mux::Route::Pooled(..)) => LaneKey::Xudp,
            _ => return Ok(()),
        };
        let Some(lane) = self.lane(&key, &destination, global_id) else { return Ok(()) };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match lane.session.send_to(&destination, payload) {
                Ok(_) => {
                    lane.touch();
                    return Ok(());
                }
                // A plain link keeps the unsent tail of this datagram and expects it again.
                Err(PlaneFault::Again) if Instant::now() < deadline && !self.shared.finished() => {}
                Err(_) => {
                    self.shared.retire(&key, &lane);
                    return Ok(());
                }
            }
        }
    }

    fn recv_for(&self, wait: Duration) -> io::Result<Reply> {
        if self.shared.finished() {
            return Err(closed());
        }
        match self.inbox.lock().expect("udp replies").recv_timeout(wait) {
            Ok(reply) => Ok(reply),
            Err(RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
            Err(RecvTimeoutError::Disconnected) => Err(closed()),
        }
    }

    fn close(&self) {
        self.shared.done.store(true, Ordering::Release);
        self.shared.open.lock().expect("udp lanes").clear();
    }
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.close();
    }
}
