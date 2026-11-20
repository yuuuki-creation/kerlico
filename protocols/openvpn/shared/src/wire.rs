use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{collections::HashMap, net::SocketAddr, time::Instant};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::invalid;

pub const MAX_FRAME: usize = 16 * 1024;
pub const FRAME_BATCH: usize = 32;
pub const POLL: Duration = Duration::from_millis(10);
#[cfg(target_os = "linux")]
const ACTIVE_RECEIVE_INTERVAL: Duration = Duration::from_millis(2);
#[cfg(target_os = "linux")]
const NATIVE_COALESCE_DELAY: Duration = Duration::from_micros(900);
#[cfg(target_os = "linux")]
const NATIVE_BATCH_LIMIT: usize = 8;
pub(crate) const CONTROL: u8 = 4;
pub(crate) const ACK: u8 = 5;
pub(crate) const CLIENT_RESET: u8 = 7;
pub(crate) const SERVER_RESET: u8 = 8;
pub(crate) const DATA: u8 = 9;
pub(crate) type SessionId = [u8; 8];

pub trait Carrier: Send {
    fn send(&mut self, frame: &[u8]) -> io::Result<()>;
    fn send_batch(&mut self, frames: &[Vec<u8>]) -> io::Result<()> {
        for frame in frames {
            self.send(frame)?;
        }
        Ok(())
    }
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>>;
    /// Take a queued frame without waiting for more input.
    fn receive_ready(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn datagrams(&self) -> bool;
    fn ipv6(&self) -> bool;
}

#[cfg(unix)]
pub struct SocketWake {
    signal: UnixStream,
    #[cfg(target_os = "linux")]
    epoll: Option<SocketRegistration>,
    #[cfg(target_os = "linux")]
    last_readable: Option<Instant>,
    #[cfg(target_os = "linux")]
    last_native_readable: Option<Instant>,
    #[cfg(target_os = "linux")]
    last_native_reply: Option<Instant>,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct SocketRegistration {
    epoll: Arc<OwnedFd>,
    datagrams: Arc<DatagramInterests>,
}

#[cfg(target_os = "linux")]
struct DatagramInterests {
    pending: AtomicBool,
    native_requests: AtomicUsize,
    native_replies: AtomicUsize,
    state: Mutex<DatagramState>,
}

#[cfg(target_os = "linux")]
struct DatagramState {
    next: u64,
    peers: HashMap<u64, (SocketAddr, Arc<AtomicBool>)>,
    ready: Vec<SocketAddr>,
}

#[cfg(target_os = "linux")]
pub struct DatagramInterest {
    datagrams: Arc<DatagramInterests>,
    token: u64,
    ready: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
impl DatagramInterest {
    pub fn take_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed) && self.ready.swap(false, Ordering::Relaxed)
    }

    pub fn note_datagram_requests(&self, count: usize) {
        self.datagrams.native_requests.fetch_max(count, Ordering::Relaxed);
    }

    pub fn note_datagram_replies(&self, count: usize) {
        self.datagrams.native_replies.fetch_max(count, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
impl Drop for DatagramInterest {
    fn drop(&mut self) {
        self.datagrams
            .state
            .lock()
            .expect("OpenVPN socket interests")
            .peers
            .remove(&self.token);
        // The caller owns the registered socket. Closing it removes the epoll interest.
    }
}

#[cfg(target_os = "linux")]
impl SocketRegistration {
    pub fn add_datagram(
        &self,
        socket: BorrowedFd<'_>,
        peer: SocketAddr,
    ) -> io::Result<DatagramInterest> {
        let mut state = self.datagrams.state.lock().expect("OpenVPN socket interests");
        let token = state.next;
        state.next = token
            .checked_add(1)
            .ok_or_else(|| io::Error::other("socket token exhausted"))?;
        epoll_add(&self.epoll, socket.as_raw_fd(), token)?;
        let ready = Arc::new(AtomicBool::new(false));
        state.peers.insert(token, (peer, ready.clone()));
        Ok(DatagramInterest {
            datagrams: self.datagrams.clone(),
            token,
            ready,
        })
    }

    pub fn take_datagram_peers(&self, peers: &mut Vec<SocketAddr>) {
        peers.clear();
        if self.datagrams.pending.load(Ordering::Relaxed) {
            let mut state = self.datagrams.state.lock().expect("OpenVPN socket interests");
            std::mem::swap(peers, &mut state.ready);
            self.datagrams.pending.store(false, Ordering::Relaxed);
        }
    }

    fn record_ready(&self, mut tokens: impl Iterator<Item = u64>) {
        let Some(first) = tokens.next() else {
            return;
        };
        let mut state = self.datagrams.state.lock().expect("OpenVPN socket interests");
        for token in std::iter::once(first).chain(tokens) {
            let Some(&(peer, ref ready)) = state.peers.get(&token) else {
                continue;
            };
            ready.store(true, Ordering::Relaxed);
            if !state.ready.contains(&peer) {
                state.ready.push(peer);
            }
        }
        self.datagrams.pending.store(!state.ready.is_empty(), Ordering::Relaxed);
    }
}

#[cfg(unix)]
impl SocketWake {
    pub fn new(socket: &impl AsRawFd) -> io::Result<(Self, impl Fn() + Send + Sync + 'static)> {
        let (signal, write) = UnixStream::pair()?;
        signal.set_nonblocking(true)?;
        write.set_nonblocking(true)?;
        #[cfg(not(target_os = "linux"))]
        let _ = socket;
        let wait = Self {
            #[cfg(target_os = "linux")]
            epoll: register(socket, &signal).ok(),
            #[cfg(target_os = "linux")]
            last_readable: None,
            #[cfg(target_os = "linux")]
            last_native_readable: None,
            #[cfg(target_os = "linux")]
            last_native_reply: None,
            signal,
        };
        Ok((wait, move || {
            // A full socket already has a readable notification.
            let _ = (&write).write(&[1]);
        }))
    }

    #[cfg(target_os = "linux")]
    pub fn registration(&self) -> Option<SocketRegistration> {
        self.epoll.clone()
    }

    pub fn wait(&mut self, socket: &impl AsRawFd, timeout: Duration) -> io::Result<bool> {
        let millis = timeout
            .as_nanos()
            .div_ceil(1_000_000)
            .min(libc::c_int::MAX as u128) as libc::c_int;
        #[cfg(target_os = "linux")]
        let ready = if let Some(registration) = &self.epoll {
            epoll_wait(registration, millis)
        } else {
            self.poll(socket, millis)
        };
        #[cfg(not(target_os = "linux"))]
        let ready = self.poll(socket, millis);
        match ready {
            Ok((network, wake)) => {
                if wake {
                    // Bound the drain even if another thread is producing wakeups.
                    let _ = self.signal.read(&mut [0; 256]);
                }
                #[cfg(target_os = "linux")]
                if network {
                    self.coalesce_receive(wake);
                } else if !wake {
                    self.coalesce_replies();
                }
                Ok(network)
            }
            Err(error) if retry(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[cfg(target_os = "linux")]
    fn coalesce_receive(&mut self, wake: bool) {
        let now = Instant::now();
        let count = self.take_native_requests();
        if count == 0 {
            if self
                .last_readable
                .replace(now)
                .is_some_and(|last| now - last < ACTIVE_RECEIVE_INTERVAL)
            {
                std::thread::sleep(Duration::from_micros(50));
            }
            return;
        }
        let last = self.last_native_readable.replace(now);
        let replies_ready = self.epoll.as_ref().is_some_and(|registry| {
            registry.datagrams.pending.load(Ordering::Relaxed)
        });
        // Let consecutive small UDP batches accumulate. Drain immediately when
        // a larger batch or egress work shows that the loop already has work.
        if count < NATIVE_BATCH_LIMIT
            && !wake
            && !replies_ready
            && last.is_some_and(|last| now - last < ACTIVE_RECEIVE_INTERVAL)
        {
            std::thread::sleep(NATIVE_COALESCE_DELAY);
        }
    }

    #[cfg(target_os = "linux")]
    fn coalesce_replies(&mut self) {
        let Some(registry) = &self.epoll else {
            return;
        };
        if !registry.datagrams.pending.load(Ordering::Relaxed) {
            return;
        }
        let count = registry.datagrams.native_replies.swap(0, Ordering::Relaxed);
        let now = Instant::now();
        let last = self.last_native_reply.replace(now);
        if (1..NATIVE_BATCH_LIMIT).contains(&count)
            && last.is_some_and(|last| now - last < ACTIVE_RECEIVE_INTERVAL)
        {
            std::thread::sleep(NATIVE_COALESCE_DELAY);
        }
    }

    #[cfg(target_os = "linux")]
    fn take_native_requests(&self) -> usize {
        let Some(registry) = &self.epoll else {
            return 0;
        };
        let requests = &registry.datagrams.native_requests;
        if requests.load(Ordering::Relaxed) == 0 {
            return 0;
        }
        requests.swap(0, Ordering::Relaxed)
    }

    fn poll(&self, socket: &impl AsRawFd, millis: libc::c_int) -> io::Result<(bool, bool)> {
        let mut fds = [
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.signal.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // The live socket descriptors and array are valid for the duration of poll.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, millis) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((fds[0].revents != 0, fds[1].revents & libc::POLLIN != 0))
    }
}

#[cfg(target_os = "linux")]
fn register(socket: &impl AsRawFd, signal: &impl AsRawFd) -> io::Result<SocketRegistration> {
    // A successful syscall returns a fresh owned descriptor.
    let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let epoll = unsafe { OwnedFd::from_raw_fd(raw) };
    for (fd, token) in [(socket.as_raw_fd(), 1), (signal.as_raw_fd(), 2)] {
        epoll_add(&epoll, fd, token)?;
    }
    Ok(SocketRegistration {
        epoll: Arc::new(epoll),
        datagrams: Arc::new(DatagramInterests {
            pending: AtomicBool::new(false),
            native_requests: AtomicUsize::new(0),
            native_replies: AtomicUsize::new(0),
            state: Mutex::new(DatagramState {
                next: 4,
                peers: HashMap::new(),
                ready: Vec::new(),
            }),
        }),
    })
}

#[cfg(target_os = "linux")]
fn epoll_add(epoll: &OwnedFd, fd: std::os::fd::RawFd, token: u64) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: token,
    };
    // epoll_ctl registers the live descriptor and copies this event.
    if unsafe { libc::epoll_ctl(epoll.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut event) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn epoll_wait(registration: &SocketRegistration, millis: libc::c_int) -> io::Result<(bool, bool)> {
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 16];
    // The kernel writes at most the capacity of this event array.
    let count = unsafe {
        libc::epoll_wait(registration.epoll.as_raw_fd(), events.as_mut_ptr(), events.len() as i32, millis)
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let tokens = events[..count as usize].iter().map(|event| event.u64);
    let flags = tokens.clone().filter(|token| *token < 4).fold(0, |flags, token| flags | token);
    registration.record_ready(tokens.filter(|token| *token >= 4));
    Ok((flags & 1 != 0, flags & 2 != 0))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn datagram_readiness_identifies_the_registered_socket_and_peer() -> io::Result<()> {
        let carrier = UdpSocket::bind("127.0.0.1:0")?;
        let first = UdpSocket::bind("127.0.0.1:0")?;
        let second = UdpSocket::bind("127.0.0.1:0")?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let (mut wait, _wake) = SocketWake::new(&carrier)?;
        let registration = wait.registration().expect("epoll");
        let first_peer = first.local_addr()?;
        let second_peer = second.local_addr()?;
        let first_interest = registration.add_datagram(first.as_fd(), first_peer)?;
        let second_interest = registration.add_datagram(second.as_fd(), second_peer)?;
        let mut ready = Vec::new();
        assert_eq!(wait.take_native_requests(), 0);
        first_interest.note_datagram_requests(1);
        first_interest.note_datagram_requests(9);
        first_interest.note_datagram_requests(2);
        assert_eq!(wait.take_native_requests(), 9);
        assert_eq!(wait.take_native_requests(), 0);

        sender.send_to(b"a", first_peer)?;
        assert!(!wait.wait(&carrier, Duration::from_secs(1))?);
        registration.take_datagram_peers(&mut ready);
        assert_eq!(ready, [first_peer]);
        assert!(first_interest.take_ready());
        assert!(!second_interest.take_ready());
        assert_eq!(first.recv(&mut [0; 1])?, 1);

        sender.send_to(b"b", second_peer)?;
        assert!(!wait.wait(&carrier, Duration::from_secs(1))?);
        registration.take_datagram_peers(&mut ready);
        assert_eq!(ready, [second_peer]);
        assert!(!first_interest.take_ready());
        assert!(second_interest.take_ready());
        Ok(())
    }
}

pub struct TcpCarrier {
    socket: TcpStream,
    pending: Vec<u8>,
    tx: Vec<u8>,
    offset: usize,
    #[cfg(unix)]
    wake: Option<SocketWake>,
}

impl TcpCarrier {
    pub fn new(socket: TcpStream) -> io::Result<Self> {
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(POLL))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self {
            socket,
            pending: Vec::new(),
            tx: Vec::new(),
            offset: 0,
            #[cfg(unix)]
            wake: None,
        })
    }

    /// Wake a pending receive when the packet plane has output to send.
    pub fn enable_wake(&mut self) -> io::Result<impl Fn() + Send + Sync + 'static> {
        #[cfg(unix)]
        {
            let (wait, wake) = SocketWake::new(&self.socket)?;
            self.wake = Some(wait);
            Ok(wake)
        }
        #[cfg(not(unix))]
        Ok(|| {})
    }

    #[cfg(target_os = "linux")]
    pub fn registration(&self) -> Option<SocketRegistration> {
        self.wake.as_ref()?.registration()
    }

    fn take_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let pending = &self.pending[self.offset..];
        let Some(header) = pending.first_chunk::<2>() else {
            return Ok(None);
        };
        let len = usize::from(u16::from_be_bytes(*header));
        if !(1..=MAX_FRAME).contains(&len) {
            return Err(invalid("invalid TCP frame length"));
        }
        let Some(frame) = pending.get(2..2 + len) else {
            return Ok(None);
        };
        let frame = frame.to_vec();
        self.offset += len + 2;
        Ok(Some(frame))
    }

    fn write_frames<'a>(&mut self, frames: impl IntoIterator<Item = &'a [u8]>) -> io::Result<()> {
        self.tx.clear();
        for frame in frames {
            if !(1..=MAX_FRAME).contains(&frame.len()) {
                return Err(invalid("invalid TCP frame length"));
            }
            self.tx
                .extend_from_slice(&(frame.len() as u16).to_be_bytes());
            self.tx.extend_from_slice(frame);
        }
        self.socket.write_all(&self.tx)
    }
}

impl Carrier for TcpCarrier {
    fn datagrams(&self) -> bool {
        false
    }

    fn ipv6(&self) -> bool {
        self.socket.peer_addr().is_ok_and(|addr| addr.is_ipv6())
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.write_frames([frame])
    }

    fn send_batch(&mut self, frames: &[Vec<u8>]) -> io::Result<()> {
        self.write_frames(frames.iter().map(Vec::as_slice))
    }

    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(frame) = self.take_frame()? {
            return Ok(Some(frame));
        }
        #[cfg(unix)]
        if let Some(wake) = &mut self.wake {
            if !wake.wait(&self.socket, POLL)? {
                return Ok(None);
            }
        }
        self.pending.drain(..self.offset);
        self.offset = 0;
        let mut bytes = [0; MAX_FRAME];
        match self.socket.read(&mut bytes) {
            Ok(0) => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                self.pending.extend_from_slice(&bytes[..n]);
                self.take_frame()
            }
            Err(error) if retry(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn receive_ready(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.take_frame()
    }
}

pub fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

pub struct UdpCarrier(UdpSocket);

impl UdpCarrier {
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        socket.set_read_timeout(Some(POLL))?;
        socket.set_write_timeout(Some(POLL))?;
        Ok(Self(socket))
    }
}

impl Carrier for UdpCarrier {
    fn datagrams(&self) -> bool {
        true
    }

    fn ipv6(&self) -> bool {
        self.0.peer_addr().is_ok_and(|addr| addr.is_ipv6())
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        match self.0.send(frame) {
            Ok(n) if n == frame.len() => Ok(()),
            Ok(_) => Err(io::ErrorKind::WriteZero.into()),
            Err(error) if retry(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut frame = [0; MAX_FRAME + 1];
        match self.0.recv(&mut frame) {
            Ok(n) if n <= MAX_FRAME => Ok(Some(frame[..n].to_vec())),
            Ok(_) => Ok(None),
            Err(error) if retry(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

pub fn is_initial_reset(frame: &[u8]) -> bool {
    Control::parse(frame).is_some_and(|record| {
        record.opcode == CLIENT_RESET && record.sequence == Some(0) && record.remote.is_none()
    })
}

pub(crate) struct Control<'a> {
    pub opcode: u8,
    pub session: SessionId,
    pub acknowledgements: &'a [u8],
    pub remote: Option<SessionId>,
    pub sequence: Option<u32>,
    pub payload: &'a [u8],
}

impl<'a> Control<'a> {
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        let (&first, bytes) = frame.split_first()?;
        let opcode = first >> 3;
        if first & 7 != 0 || !matches!(opcode, CONTROL | ACK | CLIENT_RESET | SERVER_RESET) {
            return None;
        }
        let (session, bytes) = bytes.split_first_chunk::<8>()?;
        let (&count, bytes) = bytes.split_first()?;
        if count > 8 {
            return None;
        }
        let (acknowledgements, bytes) = bytes.split_at_checked(usize::from(count) * 4)?;
        let (remote, bytes) = if count == 0 {
            (None, bytes)
        } else {
            let (remote, bytes) = bytes.split_first_chunk::<8>()?;
            (Some(*remote), bytes)
        };
        let (sequence, payload) = if opcode == ACK {
            (None, bytes)
        } else {
            let (id, bytes) = bytes.split_first_chunk::<4>()?;
            (Some(u32::from_be_bytes(*id)), bytes)
        };
        if opcode != CONTROL && !payload.is_empty() {
            return None;
        }
        Some(Self {
            opcode,
            session: *session,
            acknowledgements,
            remote,
            sequence,
            payload,
        })
    }
}

pub(crate) fn control(
    opcode: u8,
    local: SessionId,
    ack: Option<(u32, SessionId)>,
    sequence: Option<u32>,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(26 + payload.len());
    frame.push(opcode << 3);
    frame.extend_from_slice(&local);
    if let Some((id, remote)) = ack {
        frame.push(1);
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&remote);
    } else {
        frame.push(0);
    }
    if let Some(id) = sequence {
        frame.extend_from_slice(&id.to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}
