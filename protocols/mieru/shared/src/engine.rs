use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::crypto::{self, Direction};
use crate::meta::{
    self, Meta, ACK_C2S, ACK_S2C, CLOSE_REQUEST, CLOSE_RESPONSE, DATA_C2S, DATA_C2S_LOW, DATA_S2C,
    DATA_S2C_LOW, OPEN_REQUEST, OPEN_RESPONSE,
};
use crate::{ClientOptions, HandshakeMode, Multiplexing, Transport};

const PIPE_LIMIT: usize = 2 * 1024 * 1024;
const WINDOW: u16 = 4096;
const INITIAL_WINDOW: u32 = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const LINK_IDLE: Duration = Duration::from_secs(60);
const DATA_IDLE: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct Account {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

pub struct Ready {
    pub username: String,
    pub target: Target,
    pub udp: bool,
    pub peer: SocketAddr,
    pub conn: Conn,
}

pub struct Conn {
    kind: ConnKind,
}

enum ConnKind {
    Stream(Arc<Sess>),
    Leg(Arc<Leg>),
}

pub struct Assoc {
    sess: Arc<Sess>,
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    peers: Vec<SocketAddr>,
    account: Account,
    options: ClientOptions,
    links: Mutex<Vec<Arc<Link>>>,
    closed: AtomicBool,
}

/// 服务端底层连接的关闭句柄；丢弃句柄不会自动关闭连接。
pub struct ServerHandle(Weak<Link>);

enum ClientPhase {
    Established,
    Lazy(Vec<u8>),
    AwaitReply,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

enum LinkSocket {
    Tcp(TcpStream),
    Udp(UdpSocket),
    #[cfg(test)]
    Detached(Transport),
}

struct LinkSetup {
    role: Role,
    mtu: u16,
    accounts: Arc<Mutex<Vec<Account>>>,
    socket: LinkSocket,
    ready: Option<Sender<Ready>>,
    bound_user: String,
    remote: SocketAddr,
}

struct Link {
    role: Role,
    tcp: bool,
    mtu: u16,
    accounts: Arc<Mutex<Vec<Account>>>,
    send_dir: Mutex<Option<Direction>>,
    bound_user: Mutex<String>,
    remote: SocketAddr,
    sessions: Mutex<HashMap<(SocketAddr, u32), Weak<Sess>>>,
    write_tcp: Mutex<Option<Arc<TcpStream>>>,
    write_udp: Mutex<Option<UdpSocket>>,
    ready: Mutex<Option<Sender<Ready>>>,
    alive: AtomicBool,
    last_activity: Mutex<Instant>,
    wire_lock: Mutex<()>,
    low_entropy: AtomicU32,
    reusable: AtomicBool,
    retired: Mutex<HashMap<(SocketAddr, u32), Instant>>,
}

struct Sess {
    link: Arc<Link>,
    id: u32,
    peer: SocketAddr,
    username: String,
    key: [u8; 32],
    pipe: Mutex<Pipe>,
    cv: Condvar,
    send_cv: Condvar,
    reorder: Mutex<Reorder>,
    inflight: Mutex<BTreeMap<u32, Flight>>,
    next_send: AtomicU32,
    peer_window: AtomicU32,
    cwnd: AtomicU32,
    open_response: AtomicBool,
    closed: AtomicBool,
    last_tx: Mutex<Instant>,
    last_rx: Mutex<Instant>,
    write_lock: Mutex<()>,
    read_lock: Mutex<()>,
    phase: Mutex<ClientPhase>,
}

struct Pipe {
    bytes: VecDeque<u8>,
    closed: bool,
}

struct Reorder {
    next: u32,
    held: BTreeMap<u32, Vec<u8>>,
    held_bytes: usize,
}

struct Flight {
    kind: u8,
    payload: Vec<u8>,
    sent: Instant,
    timeout: Duration,
    tx: u8,
    fragment: u8,
}

struct Leg {
    sess: Arc<Sess>,
    host: String,
    port: u16,
    queue: Mutex<LegQueue>,
    cv: Condvar,
}

struct LegQueue {
    later: VecDeque<Vec<u8>>,
    closed: bool,
}

pub fn resolve_peer(host: &str, port: u16) -> io::Result<SocketAddr> {
    let text = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    text.to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer"))
}

pub fn connect(peer: SocketAddr, account: &Account, target: &Target) -> io::Result<Conn> {
    open_connect(&dial(peer, account, true)?, target, &[])
}

pub fn connect_udp(peer: SocketAddr, account: &Account, target: &Target) -> io::Result<Conn> {
    open_connect(&dial(peer, account, false)?, target, &[])
}

pub fn associate(peer: SocketAddr, account: &Account, udp_transport: bool) -> io::Result<Assoc> {
    let link = dial(peer, account, !udp_transport)?;
    open_association(&link)
}

fn open_association(link: &Arc<Link>) -> io::Result<Assoc> {
    let sess = open_raw(link)?;
    let request = socks_request(3, "0.0.0.0", 0)?;
    if let Err(error) = sess
        .write_initial(&request)
        .and_then(|_| read_socks_reply(&sess))
    {
        sess.shutdown(true);
        return Err(error);
    }
    Ok(Assoc { sess })
}

impl Client {
    pub fn new(
        peers: Vec<SocketAddr>,
        account: Account,
        options: ClientOptions,
    ) -> io::Result<Self> {
        if peers.is_empty()
            || peers.iter().any(|peer| peer.port() < 1025)
            || account.username.is_empty()
            || account.password.is_empty()
            || !(1280..=1400).contains(&options.mtu)
            || options.low_entropy > 4
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "客户端设置无效",
            ));
        }
        Ok(Self {
            inner: Arc::new(ClientInner {
                peers,
                account,
                options,
                links: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
            }),
        })
    }

    fn link(&self) -> io::Result<Arc<Link>> {
        {
            let mut links = self.inner.links.lock().expect("links");
            if self.inner.closed.load(Ordering::Acquire) {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "客户端已关闭"));
            }
            links.retain(|link| link.alive.load(Ordering::Acquire));
            let factor = self.inner.options.multiplexing.factor();
            let reuse = links.len().saturating_mul(factor);
            let pick = random_below(reuse + 1);
            if pick < reuse {
                return Ok(Arc::clone(&links[pick / factor]));
            }
        }
        let peer = self.inner.peers[random_below(self.inner.peers.len())];
        let link = dial_options(peer, &self.inner.account, &self.inner.options)?;
        let mut links = self.inner.links.lock().expect("links");
        if self.inner.closed.load(Ordering::Acquire) {
            drop(links);
            link.close();
            return Err(io::Error::new(io::ErrorKind::NotConnected, "客户端已关闭"));
        }
        links.push(Arc::clone(&link));
        Ok(link)
    }

    pub fn open(&self, target: &Target) -> io::Result<Conn> {
        let request = socks_request(1, &target.host, target.port)?;
        let link = self.link()?;
        if self.inner.options.handshake == HandshakeMode::NoWait {
            let sess = open_raw(&link)?;
            *sess.phase.lock().expect("phase") = ClientPhase::Lazy(request);
            Ok(Conn {
                kind: ConnKind::Stream(sess),
            })
        } else {
            open_connect(&link, target, &[])
        }
    }

    pub fn associate(&self) -> io::Result<Assoc> {
        open_association(&self.link()?)
    }

    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        let links = std::mem::take(&mut *self.inner.links.lock().expect("links"));
        for link in links {
            link.close();
        }
    }

    pub fn active_connections(&self) -> usize {
        self.inner
            .links
            .lock()
            .expect("links")
            .iter()
            .filter(|link| link.alive.load(Ordering::Acquire))
            .count()
    }

    pub fn active_sessions(&self) -> usize {
        self.inner
            .links
            .lock()
            .expect("links")
            .iter()
            .map(|link| link.session_count())
            .sum()
    }
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        for link in self.links.get_mut().expect("links").drain(..) {
            link.reusable.store(false, Ordering::Release);
            if link.session_count() == 0 {
                link.close();
            }
        }
    }
}

impl ServerHandle {
    pub fn close(&self) {
        if let Some(link) = self.0.upgrade() {
            link.close();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.0
            .upgrade()
            .map(|link| !link.alive.load(Ordering::Acquire))
            .unwrap_or(true)
    }
}

pub fn accept(tcp: TcpStream, accounts: &[Account]) -> io::Result<(Conn, Target, String)> {
    let peer = tcp
        .peer_addr()
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
    let (tx, rx) = std::sync::mpsc::channel();
    serve_tcp(tcp, peer, Arc::new(Mutex::new(accounts.to_vec())), 1400, tx)?;
    let ready = rx
        .recv_timeout(Duration::from_secs(20))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "accept"))?;
    Ok((ready.conn, ready.target, ready.username))
}

pub fn serve_tcp(
    tcp: TcpStream,
    peer: SocketAddr,
    accounts: Arc<Mutex<Vec<Account>>>,
    mtu: u16,
    ready: Sender<Ready>,
) -> io::Result<ServerHandle> {
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_millis(200))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(2)))?;
    let write = tcp.try_clone()?;
    let link = Link::new(LinkSetup {
        role: Role::Server,
        mtu,
        accounts,
        socket: LinkSocket::Tcp(write),
        ready: Some(ready),
        bound_user: String::new(),
        remote: peer,
    });
    let handle = ServerHandle(Arc::downgrade(&link));
    start_timer(&link);
    thread::spawn(move || reader_tcp(tcp, link, peer));
    Ok(handle)
}

pub fn serve_udp(
    socket: UdpSocket,
    accounts: Arc<Mutex<Vec<Account>>>,
    mtu: u16,
    ready: Sender<Ready>,
) -> io::Result<ServerHandle> {
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    socket.set_write_timeout(Some(Duration::from_millis(200)))?;
    let write = socket.try_clone()?;
    let link = Link::new(LinkSetup {
        role: Role::Server,
        mtu,
        accounts,
        socket: LinkSocket::Udp(write),
        ready: Some(ready),
        bound_user: String::new(),
        remote: SocketAddr::from(([0, 0, 0, 0], 0)),
    });
    let handle = ServerHandle(Arc::downgrade(&link));
    start_timer(&link);
    thread::spawn(move || reader_udp(socket, link));
    Ok(handle)
}

fn dial(peer: SocketAddr, account: &Account, tcp: bool) -> io::Result<Arc<Link>> {
    dial_options(
        peer,
        account,
        &ClientOptions {
            transport: if tcp { Transport::Tcp } else { Transport::Udp },
            multiplexing: Multiplexing::Off,
            ..ClientOptions::default()
        },
    )
}

fn dial_options(
    peer: SocketAddr,
    account: &Account,
    options: &ClientOptions,
) -> io::Result<Arc<Link>> {
    let accounts = Arc::new(Mutex::new(vec![account.clone()]));
    let now = meta::unix_now();
    let send = crypto::client_direction(&account.username, &account.password, now);
    if options.transport == Transport::Tcp {
        let tcp = TcpStream::connect_timeout(&peer, Duration::from_secs(10))?;
        tcp.set_nodelay(true).ok();
        tcp.set_read_timeout(Some(Duration::from_millis(200))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(2)))?;
        let write = tcp.try_clone()?;
        let link = Link::new(LinkSetup {
            role: Role::Client,
            mtu: options.mtu,
            accounts,
            socket: LinkSocket::Tcp(write),
            ready: None,
            bound_user: account.username.clone(),
            remote: peer,
        });
        link.low_entropy
            .store(u32::from(options.low_entropy), Ordering::Relaxed);
        link.reusable
            .store(options.multiplexing != Multiplexing::Off, Ordering::Relaxed);
        *link.send_dir.lock().expect("send") = Some(send);
        let reader = Arc::clone(&link);
        start_timer(&link);
        thread::spawn(move || reader_tcp(tcp, reader, peer));
        Ok(link)
    } else {
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(peer)?;
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        socket.set_write_timeout(Some(Duration::from_millis(200)))?;
        let write = socket.try_clone()?;
        let link = Link::new(LinkSetup {
            role: Role::Client,
            mtu: options.mtu,
            accounts,
            socket: LinkSocket::Udp(write),
            ready: None,
            bound_user: account.username.clone(),
            remote: peer,
        });
        link.low_entropy
            .store(u32::from(options.low_entropy), Ordering::Relaxed);
        link.reusable
            .store(options.multiplexing != Multiplexing::Off, Ordering::Relaxed);
        *link.send_dir.lock().expect("send") = Some(send);
        let reader = Arc::clone(&link);
        start_timer(&link);
        thread::spawn(move || reader_udp(socket, reader));
        Ok(link)
    }
}

impl Link {
    fn new(setup: LinkSetup) -> Arc<Self> {
        let LinkSetup {
            role,
            mtu,
            accounts,
            socket,
            ready,
            bound_user,
            remote,
        } = setup;
        let (tcp, write_tcp, write_udp) = match socket {
            LinkSocket::Tcp(socket) => (true, Some(socket), None),
            LinkSocket::Udp(socket) => (false, None, Some(socket)),
            #[cfg(test)]
            LinkSocket::Detached(transport) => (transport == Transport::Tcp, None, None),
        };
        Arc::new(Self {
            role,
            tcp,
            mtu,
            accounts,
            send_dir: Mutex::new(None),
            bound_user: Mutex::new(bound_user),
            remote,
            sessions: Mutex::new(HashMap::new()),
            write_tcp: Mutex::new(write_tcp.map(Arc::new)),
            write_udp: Mutex::new(write_udp),
            ready: Mutex::new(ready),
            alive: AtomicBool::new(true),
            last_activity: Mutex::new(Instant::now()),
            wire_lock: Mutex::new(()),
            low_entropy: AtomicU32::new(0),
            reusable: AtomicBool::new(true),
            retired: Mutex::new(HashMap::new()),
        })
    }

    fn key_bytes(&self) -> io::Result<[u8; 32]> {
        self.send_dir
            .lock()
            .expect("send")
            .as_ref()
            .map(Direction::key_bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "key"))
    }

    fn tick(&self) {
        self.retired
            .lock()
            .expect("retired")
            .retain(|_, at| at.elapsed() < DATA_IDLE);
        let sessions = self.live_sessions();
        for sess in sessions {
            sess.tick();
        }
        if (self.role == Role::Client || self.tcp)
            && self.session_count() == 0
            && self.last_activity.lock().expect("activity").elapsed() > LINK_IDLE
        {
            self.close();
        }
    }

    fn insert(&self, sess: Arc<Sess>) -> bool {
        let mut sessions = self.sessions.lock().expect("sessions");
        if !self.alive.load(Ordering::Acquire) {
            return false;
        }
        sessions.insert((sess.peer, sess.id), Arc::downgrade(&sess));
        *self.last_activity.lock().expect("activity") = Instant::now();
        true
    }

    fn get(&self, peer: SocketAddr, id: u32) -> Option<Arc<Sess>> {
        self.sessions
            .lock()
            .expect("sessions")
            .get(&(peer, id))
            .and_then(Weak::upgrade)
    }

    fn live_sessions(&self) -> Vec<Arc<Sess>> {
        let mut sessions = self.sessions.lock().expect("sessions");
        sessions.retain(|_, sess| sess.strong_count() != 0);
        sessions.values().filter_map(Weak::upgrade).collect()
    }

    fn session_count(&self) -> usize {
        self.live_sessions()
            .into_iter()
            .filter(|sess| !sess.closed.load(Ordering::Acquire))
            .count()
    }

    fn close(&self) {
        if !self.alive.swap(false, Ordering::AcqRel) {
            return;
        }
        if let Some(tcp) = self.write_tcp.lock().expect("tcp").take() {
            let _ = tcp.shutdown(Shutdown::Both);
        }
        self.write_udp.lock().expect("udp").take();
        for sess in self.live_sessions() {
            sess.shutdown(false);
        }
        self.ready.lock().expect("ready").take();
    }
}

fn start_timer(link: &Arc<Link>) {
    let weak = Arc::downgrade(link);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(100));
        let Some(link) = weak.upgrade() else {
            break;
        };
        if !link.alive.load(Ordering::Acquire) {
            break;
        }
        link.tick();
    });
}

fn copy_deque(buf: &mut [u8], bytes: &mut VecDeque<u8>) -> usize {
    let n = buf.len().min(bytes.len());
    let (front, back) = bytes.as_slices();
    if n <= front.len() {
        buf[..n].copy_from_slice(&front[..n]);
    } else {
        let mid = front.len();
        buf[..mid].copy_from_slice(front);
        buf[mid..n].copy_from_slice(&back[..n - mid]);
    }
    bytes.drain(..n);
    n
}

impl Sess {
    fn new(
        link: Arc<Link>,
        id: u32,
        peer: SocketAddr,
        username: String,
        key: [u8; 32],
    ) -> Arc<Self> {
        Arc::new(Self {
            link,
            id,
            peer,
            username,
            key,
            pipe: Mutex::new(Pipe {
                bytes: VecDeque::new(),
                closed: false,
            }),
            cv: Condvar::new(),
            send_cv: Condvar::new(),
            reorder: Mutex::new(Reorder {
                next: 0,
                held: BTreeMap::new(),
                held_bytes: 0,
            }),
            inflight: Mutex::new(BTreeMap::new()),
            next_send: AtomicU32::new(0),
            peer_window: AtomicU32::new(INITIAL_WINDOW),
            cwnd: AtomicU32::new(INITIAL_WINDOW),
            open_response: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            last_tx: Mutex::new(Instant::now()),
            last_rx: Mutex::new(Instant::now()),
            write_lock: Mutex::new(()),
            read_lock: Mutex::new(()),
            phase: Mutex::new(ClientPhase::Established),
        })
    }

    fn append(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut pipe = self.pipe.lock().expect("pipe");
        if pipe.bytes.len().saturating_add(bytes.len()) > PIPE_LIMIT {
            drop(pipe);
            self.shutdown(true);
            return;
        }
        if pipe.closed {
            return;
        }
        pipe.bytes.extend(bytes);
        self.cv.notify_all();
    }

    fn read_some(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut pipe = self.pipe.lock().expect("pipe");
        loop {
            if !pipe.bytes.is_empty() {
                let n = copy_deque(buf, &mut pipe.bytes);
                self.cv.notify_all();
                return Ok(n);
            }
            if pipe.closed {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"));
            }
            pipe = self.cv.wait(pipe).expect("cv");
        }
    }

    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut pipe = self.pipe.lock().expect("pipe");
        let start = Instant::now();
        loop {
            if !pipe.bytes.is_empty() {
                let n = copy_deque(buf, &mut pipe.bytes);
                self.cv.notify_all();
                return Ok(n);
            }
            if pipe.closed {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"));
            }
            let left = wait.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle"));
            }
            let (next, status) = self.cv.wait_timeout(pipe, left).expect("cv");
            pipe = next;
            if status.timed_out() && pipe.bytes.is_empty() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle"));
            }
        }
    }

    fn queued(&self) -> usize {
        self.pipe.lock().expect("pipe").bytes.len()
    }

    fn window(&self) -> u16 {
        let room = PIPE_LIMIT.saturating_sub(self.queued());
        (room / fragment_size(self.link.tcp, self.link.mtu, 0)).min(WINDOW as usize) as u16
    }

    fn unack(&self) -> u32 {
        self.reorder.lock().expect("reorder").next
    }

    fn push_in(&self, seq: u32, payload: Vec<u8>) -> Vec<u8> {
        let mut reorder = self.reorder.lock().expect("reorder");
        if seq.wrapping_sub(reorder.next) > WINDOW as u32 {
            return Vec::new();
        }
        if seq != reorder.next && reorder.held.len() >= WINDOW as usize {
            return Vec::new();
        }
        if reorder.held_bytes.saturating_add(payload.len()) > PIPE_LIMIT {
            return Vec::new();
        }
        if seq != reorder.next {
            if let std::collections::btree_map::Entry::Vacant(entry) = reorder.held.entry(seq) {
                let len = payload.len();
                entry.insert(payload);
                reorder.held_bytes += len;
            }
            return Vec::new();
        }
        let mut out = payload;
        reorder.next = reorder.next.wrapping_add(1);
        loop {
            let next = reorder.next;
            let Some(payload) = reorder.held.remove(&next) else {
                break;
            };
            reorder.held_bytes -= payload.len();
            out.extend(payload);
            reorder.next = next.wrapping_add(1);
        }
        out
    }

    fn on_ack(&self, unack: u32, window: u16) {
        let mut inflight = self.inflight.lock().expect("inflight");
        let before = inflight.len();
        inflight.retain(|seq, _| seq.wrapping_sub(unack) < (1u32 << 31));
        let removed = before.saturating_sub(inflight.len());
        drop(inflight);
        if removed > 0 {
            let cwnd = self
                .cwnd
                .load(Ordering::Relaxed)
                .saturating_add(removed as u32)
                .min(WINDOW as u32);
            self.cwnd.store(cwnd.max(INITIAL_WINDOW), Ordering::Relaxed);
        }
        self.peer_window.store(u32::from(window), Ordering::Relaxed);
        self.send_cv.notify_all();
    }

    fn wait_slot(&self) -> io::Result<()> {
        if self.link.tcp {
            return Ok(());
        }
        let start = Instant::now();
        let mut inflight = self.inflight.lock().expect("inflight");
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
            }
            let limit = self
                .cwnd
                .load(Ordering::Relaxed)
                .min(self.peer_window.load(Ordering::Relaxed));
            if limit > 0 && inflight.len() < limit as usize {
                return Ok(());
            }
            if start.elapsed() > Duration::from_secs(60) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "window"));
            }
            let (next, _) = self
                .send_cv
                .wait_timeout(inflight, Duration::from_millis(200))
                .expect("cv");
            inflight = next;
        }
    }

    fn write_open(&self, payload: &[u8]) -> io::Result<()> {
        self.wait_slot()?;
        let seq = self.next_send.fetch_add(1, Ordering::Relaxed);
        self.emit(open_kind(self.link.role), seq, payload, true)?;
        Ok(())
    }

    fn write_app(&self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.wait_open_response()?;
        let mode = self.link.low_entropy.load(Ordering::Relaxed) as u8;
        let max = fragment_size(self.link.tcp, self.link.mtu, mode);
        for pdu in buf.chunks(meta::MAX_PDU) {
            let count = pdu.len().div_ceil(max);
            for (index, chunk) in pdu.chunks(max).enumerate() {
                if self.closed.load(Ordering::SeqCst) {
                    return Err(closed());
                }
                self.wait_slot()?;
                let seq = self.next_send.fetch_add(1, Ordering::Relaxed);
                let kind = if mode == 0 {
                    data_kind(self.link.role)
                } else if self.link.role == Role::Client {
                    DATA_C2S_LOW
                } else {
                    DATA_S2C_LOW
                };
                self.emit_fragment(kind, seq, chunk, true, (count - index - 1) as u8)?;
            }
        }
        Ok(())
    }

    fn waiting_for_open_response(&self) -> bool {
        !self.link.tcp
            && self.link.role == Role::Client
            && !self.open_response.load(Ordering::Acquire)
    }

    fn wait_open_response(&self) -> io::Result<()> {
        if !self.waiting_for_open_response() {
            return Ok(());
        }
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let mut pipe = self.pipe.lock().expect("pipe");
        loop {
            if pipe.closed {
                return Err(closed());
            }
            if self.open_response.load(Ordering::Acquire) {
                return Ok(());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(timed_out());
            }
            pipe = self.cv.wait_timeout(pipe, left).expect("cv").0;
        }
    }

    fn emit(&self, kind: u8, seq: u32, payload: &[u8], remember: bool) -> io::Result<()> {
        self.emit_fragment(kind, seq, payload, remember, 0)
    }

    fn emit_fragment(
        &self,
        kind: u8,
        seq: u32,
        payload: &[u8],
        remember: bool,
        fragment: u8,
    ) -> io::Result<()> {
        let mode = if meta::is_low(kind) {
            self.link.low_entropy.load(Ordering::Relaxed) as u8
        } else {
            0
        };
        let encoded_len = if mode == 0 {
            payload.len() as u16
        } else {
            crate::entropy::encoded_len(payload.len(), mode)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "低熵载荷长度无效"))?
        };
        let mask = low_mask(mode);
        let (prefix, suffix) = choose_padding(
            self.link.tcp,
            self.link.mtu,
            usize::from(encoded_len),
            meta::is_session(kind),
        );
        let plain = if meta::is_session(kind) {
            meta::session(kind, self.id, seq, payload.len() as u16, suffix.len() as u8)
        } else {
            meta::data(&Meta {
                kind,
                session: self.id,
                seq,
                unack: self.unack(),
                window: self.window(),
                fragment,
                prefix: prefix.len() as u8,
                payload_len: encoded_len,
                suffix: suffix.len() as u8,
                low_mode: mode,
                low_mask: mask,
                extracted: if mode == 0 { 0 } else { payload.len() as u16 },
                rotation: 0,
            })
        };
        if remember && !self.link.tcp {
            self.inflight.lock().expect("inflight").insert(
                seq,
                Flight {
                    kind,
                    payload: payload.to_vec(),
                    sent: Instant::now(),
                    timeout: Duration::from_secs(3),
                    tx: 1,
                    fragment,
                },
            );
        }
        let result = self.write_wire(&plain, payload, &prefix, &suffix, mode, mask);
        if result.is_err() && remember {
            self.inflight.lock().expect("inflight").remove(&seq);
        }
        result
    }

    fn send_ack(&self) -> io::Result<()> {
        if self.link.tcp || self.closed.load(Ordering::SeqCst) || self.waiting_for_open_response() {
            return Ok(());
        }
        let seq = self.next_send.load(Ordering::Relaxed).saturating_sub(1);
        self.emit(ack_kind(self.link.role), seq, &[], false)
    }

    fn send_close(&self, response: bool) {
        if self.link.alive.load(Ordering::SeqCst) {
            let seq = self.next_send.fetch_add(1, Ordering::Relaxed);
            let kind = if response {
                CLOSE_RESPONSE
            } else {
                CLOSE_REQUEST
            };
            let _ = self.emit(kind, seq, &[], false);
        }
    }

    fn shutdown(&self, request: bool) {
        let first = !self.closed.swap(true, Ordering::SeqCst);
        self.pipe.lock().expect("pipe").closed = true;
        self.cv.notify_all();
        self.send_cv.notify_all();
        let was_started = {
            let mut phase = self.phase.lock().expect("phase");
            if matches!(*phase, ClientPhase::Lazy(_)) {
                *phase = ClientPhase::Failed;
                false
            } else {
                true
            }
        };
        if first && request && was_started {
            self.send_close(false);
        }
        if first {
            self.link
                .sessions
                .lock()
                .expect("sessions")
                .remove(&(self.peer, self.id));
            if !self.link.tcp && was_started {
                let mut retired = self.link.retired.lock().expect("retired");
                if retired.len() >= WINDOW as usize {
                    if let Some(key) = retired
                        .iter()
                        .min_by_key(|(_, at)| **at)
                        .map(|(key, _)| *key)
                    {
                        retired.remove(&key);
                    }
                }
                retired.insert((self.peer, self.id), Instant::now());
            }
            self.inflight.lock().expect("inflight").clear();
            if self.link.role == Role::Client
                && !self.link.reusable.load(Ordering::Acquire)
                && self.link.session_count() == 0
            {
                self.link.close();
            }
        }
    }

    fn write_initial(&self, payload: &[u8]) -> io::Result<()> {
        if payload.len() <= meta::MAX_SESSION_PAYLOAD
            && self.link.low_entropy.load(Ordering::Relaxed) == 0
        {
            self.write_open(payload)
        } else {
            self.write_open(&[])?;
            self.write_app(payload)
        }
    }

    fn write_client(&self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let _write = self.write_lock.lock().expect("write");
        if self.closed.load(Ordering::Acquire) {
            return Err(closed());
        }
        let lazy = {
            let mut phase = self.phase.lock().expect("phase");
            if matches!(*phase, ClientPhase::Lazy(_)) {
                match std::mem::replace(&mut *phase, ClientPhase::AwaitReply) {
                    ClientPhase::Lazy(request) => Some(request),
                    _ => unreachable!(),
                }
            } else {
                None
            }
        };
        let result = if let Some(mut request) = lazy {
            request.extend_from_slice(payload);
            let result = self.write_initial(&request);
            self.cv.notify_all();
            result
        } else {
            self.write_app(payload)
        };
        if result.is_err() {
            self.shutdown(true);
        }
        result
    }

    fn read_client(&self, buf: &mut [u8], wait: Option<Duration>) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let _read = self.read_lock.lock().expect("read");
        let deadline = wait.map(|duration| Instant::now() + duration);
        loop {
            let phase = self.phase.lock().expect("phase");
            match &*phase {
                ClientPhase::Established => break,
                ClientPhase::Failed => return Err(closed()),
                ClientPhase::AwaitReply => {
                    drop(phase);
                    let result = read_socks_reply_for(
                        self,
                        Some(remaining(deadline)?.unwrap_or(HANDSHAKE_TIMEOUT)),
                    );
                    match result {
                        Ok(()) => *self.phase.lock().expect("phase") = ClientPhase::Established,
                        Err(error) => {
                            if error.kind() != io::ErrorKind::TimedOut {
                                *self.phase.lock().expect("phase") = ClientPhase::Failed;
                                self.shutdown(true);
                            }
                            return Err(error);
                        }
                    }
                }
                ClientPhase::Lazy(_) => {
                    drop(phase);
                    let left = remaining(deadline)?.unwrap_or(Duration::from_millis(200));
                    let pipe = self.pipe.lock().expect("pipe");
                    if pipe.closed {
                        return Err(closed());
                    }
                    drop(
                        self.cv
                            .wait_timeout(pipe, left.min(Duration::from_millis(200)))
                            .expect("cv"),
                    );
                }
            }
        }
        match remaining(deadline)? {
            Some(wait) => self.read_for(buf, wait),
            None => self.read_some(buf),
        }
    }

    #[cfg(test)]
    fn write_low_entropy(&self, payload: &[u8]) -> io::Result<()> {
        self.link.low_entropy.store(1, Ordering::Relaxed);
        self.write_client(payload)
    }

    fn send_wire(&self, wire: &[u8]) -> io::Result<()> {
        if self.link.tcp {
            let tcp = self
                .link
                .write_tcp
                .lock()
                .expect("tcp")
                .clone()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "tcp"))?;
            write_all_timeout(tcp.as_ref(), wire)?;
        } else {
            let udp = self.link.write_udp.lock().expect("udp");
            let udp = udp
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "udp"))?;
            udp.send_to(wire, self.peer)?;
        }
        *self.last_tx.lock().expect("tx") = Instant::now();
        *self.link.last_activity.lock().expect("activity") = Instant::now();
        Ok(())
    }

    fn write_wire(
        &self,
        meta_plain: &[u8],
        payload: &[u8],
        prefix: &[u8],
        suffix: &[u8],
        mode: u8,
        mask: u32,
    ) -> io::Result<()> {
        let _order = self.link.wire_lock.lock().expect("wire order");
        if !self.link.alive.load(Ordering::Acquire) {
            return Err(closed());
        }
        let body = |mut sealed: Vec<u8>| -> io::Result<Vec<u8>> {
            if mode == 0 {
                return Ok(sealed);
            }
            let tag = sealed.split_off(sealed.len() - 16);
            let mut encoded = crate::entropy::encode(&sealed, mode, mask, 0, 0)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "低熵编码参数无效"))?;
            encoded.extend(tag);
            Ok(encoded)
        };
        let body_len = if mode == 0 {
            payload.len()
        } else {
            usize::from(
                crate::entropy::encoded_len(payload.len(), mode).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "低熵载荷长度无效")
                })?,
            )
        };
        let mut wire = Vec::with_capacity(
            24 + meta_plain.len() + 16 + prefix.len() + body_len + 16 + suffix.len(),
        );
        if self.link.tcp {
            let mut guard = self.link.send_dir.lock().expect("send");
            let dir = guard
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "发送密钥未就绪"))?;
            dir.seal_into(&self.username, meta_plain, &mut wire);
            wire.extend_from_slice(prefix);
            if !payload.is_empty() {
                if mode == 0 {
                    dir.seal_into(&self.username, payload, &mut wire);
                } else {
                    wire.extend(body(dir.seal(&self.username, payload))?);
                }
            }
        } else {
            let nonce = crypto::nonce_with_hint(&self.username);
            let mut dir = Direction::from_key(self.key);
            wire.extend_from_slice(&nonce);
            dir.seal_at_into(&nonce, meta_plain, &mut wire);
            wire.extend_from_slice(prefix);
            if !payload.is_empty() {
                if mode == 0 {
                    dir.seal_at_into(&nonce, payload, &mut wire);
                } else {
                    wire.extend(body(dir.seal_at(&nonce, payload))?);
                }
            }
        }
        wire.extend_from_slice(suffix);
        self.send_wire(&wire)
    }

    fn tick(&self) {
        if self.link.tcp || self.closed.load(Ordering::SeqCst) {
            return;
        }
        if self.last_rx.lock().expect("rx").elapsed() > DATA_IDLE {
            self.shutdown(true);
            return;
        }
        let due = {
            let mut inflight = self.inflight.lock().expect("inflight");
            let mut due = Vec::new();
            for (seq, flight) in inflight.iter_mut() {
                if flight.sent.elapsed() < flight.timeout {
                    continue;
                }
                if flight.tx >= 20 {
                    drop(inflight);
                    self.shutdown(false);
                    return;
                }
                flight.tx = flight.tx.saturating_add(1);
                flight.sent = Instant::now();
                flight.timeout = (flight.timeout.mul_f32(1.5)).min(Duration::from_secs(10));
                due.push((*seq, flight.kind, flight.payload.clone(), flight.fragment));
            }
            due
        };
        for (seq, kind, payload, fragment) in due {
            self.cwnd
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some((n / 2).max(1))
                })
                .ok();
            let _ = self.emit_fragment(kind, seq, &payload, false, fragment);
        }
        if self.last_tx.lock().expect("tx").elapsed() > Duration::from_secs(5) {
            let _ = self.send_ack();
        }
    }
}

impl Conn {
    #[cfg(test)]
    fn write_low_entropy(&self, payload: &[u8]) -> io::Result<()> {
        let ConnKind::Stream(sess) = &self.kind else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "leg"));
        };
        sess.write_low_entropy(payload)
    }

    pub fn read_user(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.kind {
            ConnKind::Stream(sess) => sess.read_client(buf, None),
            ConnKind::Leg(leg) => leg.read(buf),
        }
    }

    pub fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        match &self.kind {
            ConnKind::Stream(sess) => sess.read_client(buf, Some(wait)),
            ConnKind::Leg(leg) => leg.read_for(buf, wait),
        }
    }

    pub fn write_user(&self, buf: &[u8]) -> io::Result<()> {
        match &self.kind {
            ConnKind::Stream(sess) => sess.write_client(buf),
            ConnKind::Leg(leg) => leg.write(buf),
        }
    }
}

impl Conn {
    pub fn close(&self) {
        match &self.kind {
            ConnKind::Stream(sess) => sess.shutdown(true),
            ConnKind::Leg(leg) => leg.close(),
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.close();
    }
}

impl Assoc {
    pub fn send_to(&self, host: &str, port: u16, payload: &[u8]) -> io::Result<()> {
        let packet = udp_datagram(host, port, payload)?;
        write_frame(&self.sess, &packet)
    }

    pub fn recv_from(&self) -> io::Result<(String, u16, Vec<u8>)> {
        self.recv_for(DATA_IDLE)
    }

    pub fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)> {
        let _read = self.sess.read_lock.lock().expect("read");
        let packet = read_frame_for(&self.sess, wait)?;
        parse_datagram(&packet)
    }

    pub fn close(&self) {
        self.sess.shutdown(true);
    }
}

impl Drop for Assoc {
    fn drop(&mut self) {
        self.close();
    }
}

impl Leg {
    fn push(&self, payload: Vec<u8>) {
        let mut queue = self.queue.lock().expect("leg");
        if queue.closed || queue.later.len() >= 64 {
            return;
        }
        queue.later.push_back(payload);
        self.cv.notify_all();
    }

    fn close(&self) {
        let mut queue = self.queue.lock().expect("leg");
        queue.closed = true;
        self.cv.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.queue.lock().expect("leg").closed
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_for(buf, DATA_IDLE)
    }

    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        let deadline = Instant::now() + wait;
        let mut queue = self.queue.lock().expect("leg");
        loop {
            if let Some(packet) = queue.later.front() {
                if packet.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "缓冲区不足以容纳完整数据报",
                    ));
                }
                let packet = queue.later.pop_front().expect("packet");
                buf[..packet.len()].copy_from_slice(&packet);
                return Ok(packet.len());
            }
            if queue.closed {
                return Err(closed());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(timed_out());
            }
            let (next, _) = self.cv.wait_timeout(queue, left).expect("leg");
            queue = next;
        }
    }

    fn write(&self, payload: &[u8]) -> io::Result<()> {
        if self.is_closed() {
            return Err(closed());
        }
        let packet = udp_datagram(&self.host, self.port, payload)?;
        write_frame(&self.sess, &packet)
    }
}

fn reader_tcp(tcp: TcpStream, link: Arc<Link>, peer: SocketAddr) {
    let mut tcp = BufReader::with_capacity(64 * 1024, tcp);
    let mut recv: Option<Direction> = None;
    loop {
        if !link.alive.load(Ordering::SeqCst) {
            break;
        }
        match read_tcp_segment(&mut tcp, &mut recv, &link, peer) {
            Ok(Some(incoming)) => dispatch(&link, incoming),
            Ok(None) => link.tick(),
            Err(_) => {
                link.close();
                break;
            }
        }
    }
}

fn reader_udp(socket: UdpSocket, link: Arc<Link>) {
    let mut buf = vec![0u8; 65535];
    while link.alive.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if let Some(incoming) = parse_udp_packet(&buf[..n], peer, &link) {
                    dispatch(&link, incoming);
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                link.tick();
            }
            Err(_) => break,
        }
    }
    link.close();
}

struct Incoming {
    peer: SocketAddr,
    meta: Meta,
    payload: Vec<u8>,
    key: [u8; 32],
    username: String,
}

fn dispatch(link: &Arc<Link>, incoming: Incoming) {
    if !from_peer(link.role, incoming.meta.kind) {
        return;
    }
    *link.last_activity.lock().expect("activity") = Instant::now();
    if let Some(sess) = link.get(incoming.peer, incoming.meta.session) {
        *sess.last_rx.lock().expect("rx") = Instant::now();
    }
    if meta::is_ack(incoming.meta.kind) {
        if let Some(sess) = link.get(incoming.peer, incoming.meta.session) {
            sess.on_ack(incoming.meta.unack, incoming.meta.window);
        }
        return;
    }
    if incoming.meta.kind == CLOSE_REQUEST || incoming.meta.kind == CLOSE_RESPONSE {
        if let Some(sess) = link.get(incoming.peer, incoming.meta.session) {
            if incoming.meta.kind == CLOSE_REQUEST {
                sess.send_close(true);
            }
            sess.shutdown(false);
        }
        return;
    }
    if incoming.meta.kind == OPEN_REQUEST && link.role == Role::Server {
        if incoming.meta.session == 0 {
            return;
        }
        if link
            .retired
            .lock()
            .expect("retired")
            .contains_key(&(incoming.peer, incoming.meta.session))
        {
            return;
        }
        if link.get(incoming.peer, incoming.meta.session).is_some() {
            if let Some(sess) = link.get(incoming.peer, incoming.meta.session) {
                let _ = sess.send_ack();
            }
            return;
        }
        if link.session_count() >= WINDOW as usize {
            close_unknown(link, &incoming);
            return;
        }
        let sess = Sess::new(
            Arc::clone(link),
            incoming.meta.session,
            incoming.peer,
            incoming.username.clone(),
            incoming.key,
        );
        let delivered = sess.push_in(incoming.meta.seq, incoming.payload);
        sess.append(&delivered);
        if !link.insert(Arc::clone(&sess)) {
            sess.shutdown(false);
            return;
        }
        if !link.tcp {
            let _ = sess.send_ack();
        }
        if sess.write_open(&[]).is_err() {
            sess.shutdown(false);
            return;
        }
        let link = Arc::clone(link);
        thread::spawn(move || handshake(sess, link));
        return;
    }
    if incoming.meta.kind == OPEN_RESPONSE && link.role == Role::Client {
        if let Some(sess) = link.get(incoming.peer, incoming.meta.session) {
            let delivered = sess.push_in(incoming.meta.seq, incoming.payload);
            sess.append(&delivered);
            if incoming.meta.seq == 0 && sess.unack() != 0 {
                let _pipe = sess.pipe.lock().expect("pipe");
                sess.open_response.store(true, Ordering::Release);
                sess.cv.notify_all();
            }
            if !link.tcp {
                let _ = sess.send_ack();
            }
        }
        return;
    }
    if meta::is_data(incoming.meta.kind) {
        let Some(sess) = link.get(incoming.peer, incoming.meta.session) else {
            close_unknown(link, &incoming);
            return;
        };
        if !link.tcp {
            sess.on_ack(incoming.meta.unack, incoming.meta.window);
        }
        let delivered = sess.push_in(incoming.meta.seq, incoming.payload);
        sess.append(&delivered);
        if !link.tcp {
            let _ = sess.send_ack();
        }
    }
}

fn close_unknown(link: &Arc<Link>, incoming: &Incoming) {
    let sess = Sess::new(
        Arc::clone(link),
        incoming.meta.session,
        incoming.peer,
        incoming.username.clone(),
        incoming.key,
    );
    sess.send_close(false);
    sess.shutdown(false);
}

fn handshake(sess: Arc<Sess>, link: Arc<Link>) {
    let ready = link.ready.lock().expect("ready").clone();
    let Some(ready) = ready else {
        sess.shutdown(false);
        return;
    };
    let request = match read_socks(&sess) {
        Ok(request) => request,
        Err(_) => {
            sess.shutdown(true);
            return;
        }
    };
    if sess.write_app(&socks_reply()).is_err() {
        sess.shutdown(false);
        return;
    }
    if request.command == 1 {
        let _ = ready.send(Ready {
            username: sess.username.clone(),
            target: request.target,
            udp: false,
            peer: sess.peer,
            conn: Conn {
                kind: ConnKind::Stream(sess),
            },
        });
        return;
    }
    if request.command == 3 {
        fanout(sess, ready);
        return;
    }
    sess.shutdown(true);
}

fn fanout(sess: Arc<Sess>, ready: Sender<Ready>) {
    let mut legs: HashMap<(String, u16), Weak<Leg>> = HashMap::new();
    while let Ok(packet) = read_frame(&sess) {
        let (host, port, payload) = match parse_datagram(&packet) {
            Ok(parsed) => parsed,
            Err(_) => break,
        };
        let key = (host.to_ascii_lowercase(), port);
        if let Some(leg) = legs.get(&key).and_then(Weak::upgrade) {
            if !leg.is_closed() {
                leg.push(payload);
                continue;
            }
        }
        legs.retain(|_, leg| leg.strong_count() != 0);
        let leg = Arc::new(Leg {
            sess: Arc::clone(&sess),
            host: host.clone(),
            port,
            queue: Mutex::new(LegQueue {
                later: VecDeque::new(),
                closed: false,
            }),
            cv: Condvar::new(),
        });
        leg.push(payload);
        legs.insert(key, Arc::downgrade(&leg));
        if ready
            .send(Ready {
                username: sess.username.clone(),
                target: Target { host, port },
                udp: true,
                peer: sess.peer,
                conn: Conn {
                    kind: ConnKind::Leg(leg),
                },
            })
            .is_err()
        {
            break;
        }
    }
    for leg in legs.values().filter_map(Weak::upgrade) {
        leg.close();
    }
    sess.shutdown(true);
}

fn open_connect(link: &Arc<Link>, target: &Target, early: &[u8]) -> io::Result<Conn> {
    let mut payload = socks_request(1, &target.host, target.port)?;
    payload.extend_from_slice(early);
    let sess = open_raw(link)?;
    if let Err(error) = sess
        .write_initial(&payload)
        .and_then(|_| read_socks_reply(&sess))
    {
        sess.shutdown(true);
        return Err(error);
    }
    Ok(Conn {
        kind: ConnKind::Stream(sess),
    })
}

fn open_raw(link: &Arc<Link>) -> io::Result<Arc<Sess>> {
    if !link.alive.load(Ordering::Acquire) {
        return Err(closed());
    }
    let id = loop {
        let candidate = random_u32().max(1);
        if link.get(link.remote, candidate).is_none()
            && !link
                .retired
                .lock()
                .expect("retired")
                .contains_key(&(link.remote, candidate))
        {
            break candidate;
        }
    };
    let username = link.bound_user.lock().expect("user").clone();
    let key = link.key_bytes()?;
    let sess = Sess::new(Arc::clone(link), id, link.remote, username, key);
    if !link.insert(Arc::clone(&sess)) {
        return Err(closed());
    }
    Ok(sess)
}

fn read_tcp_segment(
    tcp: &mut BufReader<TcpStream>,
    recv: &mut Option<Direction>,
    link: &Arc<Link>,
    peer: SocketAddr,
) -> io::Result<Option<Incoming>> {
    let first = recv.is_none();
    let header_len = if first { 24 + 32 + 16 } else { 32 + 16 };
    let header = match take(tcp, header_len, true) {
        Ok(header) => header,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if first && crate::replay::reject(&header[..16], None) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "replay"));
    }
    let (plain, key, username) = if let Some(direction) = recv.as_mut() {
        let plain = direction
            .open_next(header)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "decrypt"))?;
        let key = direction.key_bytes();
        let username = link.bound_user.lock().expect("user").clone();
        (plain, key, username)
    } else {
        let accounts = link.accounts.lock().expect("accounts").clone();
        let mut opened = None;
        for account in &accounts {
            if let Some(found) = crypto::open_first(
                &account.username,
                &account.password,
                &header,
                meta::unix_now(),
            ) {
                opened = Some(found);
                break;
            }
        }
        let opened =
            opened.ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "user"))?;
        if link.role == Role::Server {
            *link.send_dir.lock().expect("send") = Some(opened.direction.fork_send());
        }
        let key = opened.direction.key_bytes();
        let username = opened.username;
        *link.bound_user.lock().expect("user") = username.clone();
        *recv = Some(opened.direction);
        (opened.plain, key, username)
    };
    let meta = meta::parse(&plain)?;
    let payload = read_tcp_payload(tcp, recv.as_mut().unwrap(), &meta)?;
    Ok(Some(Incoming {
        peer,
        meta,
        payload,
        key,
        username,
    }))
}

fn read_tcp_payload(
    tcp: &mut BufReader<TcpStream>,
    direction: &mut Direction,
    meta: &Meta,
) -> io::Result<Vec<u8>> {
    if meta.prefix > 0 {
        skip_padding(tcp, meta.prefix)?;
    }
    let payload = if meta.payload_len == 0 {
        Vec::new()
    } else {
        let mut wire = take(tcp, meta.payload_len as usize + 16, false)?;
        if meta::is_low(meta.kind) {
            let body = crate::entropy::decode(
                &wire[..meta.payload_len as usize],
                meta.extracted as usize,
                meta.low_mode,
                meta.low_mask,
                meta.rotation,
            )
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "low entropy"))?;
            let tag: [u8; 16] = wire[meta.payload_len as usize..].try_into().unwrap();
            wire = body;
            wire.extend(tag);
        }
        direction
            .open_next(wire)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload"))?
    };
    if meta.suffix > 0 {
        skip_padding(tcp, meta.suffix)?;
    }
    Ok(payload)
}

fn parse_udp_packet(packet: &[u8], peer: SocketAddr, link: &Arc<Link>) -> Option<Incoming> {
    if packet.len() < 24 + 32 + 16 {
        return None;
    }
    if crate::replay::reject(&packet[..16], Some(peer)) {
        return None;
    }
    let nonce = packet[..24].try_into().ok()?;
    if let Some(found) = decrypt_known(link, peer, packet, &nonce) {
        return Some(found);
    }
    if link.role != Role::Server {
        let accounts = link.accounts.lock().expect("accounts").clone();
        for account in &accounts {
            if let Some(opened) = crypto::open_first(
                &account.username,
                &account.password,
                &packet[..72],
                meta::unix_now(),
            ) {
                let meta = meta::parse(&opened.plain).ok()?;
                let payload = udp_body(&meta, &nonce, &packet[72..], opened.direction.key_bytes())?;
                return Some(Incoming {
                    peer,
                    meta,
                    payload,
                    key: opened.direction.key_bytes(),
                    username: opened.username,
                });
            }
        }
        return None;
    }
    let accounts = link.accounts.lock().expect("accounts").clone();
    for account in &accounts {
        if let Some(opened) = crypto::open_first(
            &account.username,
            &account.password,
            &packet[..72],
            meta::unix_now(),
        ) {
            let meta = meta::parse(&opened.plain).ok()?;
            if meta.kind != OPEN_REQUEST || meta.session == 0 {
                return None;
            }
            let payload = udp_body(&meta, &nonce, &packet[72..], opened.direction.key_bytes())?;
            return Some(Incoming {
                peer,
                meta,
                payload,
                key: opened.direction.key_bytes(),
                username: opened.username,
            });
        }
    }
    None
}

fn decrypt_known(
    link: &Link,
    peer: SocketAddr,
    packet: &[u8],
    nonce: &[u8; 24],
) -> Option<Incoming> {
    let sessions: Vec<Arc<Sess>> = link
        .live_sessions()
        .into_iter()
        .filter(|sess| sess.peer == peer)
        .collect();
    for sess in sessions {
        let Some(plain) = Direction::from_key(sess.key).open_at(nonce, &packet[24..72]) else {
            continue;
        };
        let Ok(meta) = meta::parse(&plain) else {
            continue;
        };
        if meta.session != sess.id {
            continue;
        }
        let Some(payload) = udp_body(&meta, nonce, &packet[72..], sess.key) else {
            continue;
        };
        return Some(Incoming {
            peer,
            meta,
            payload,
            key: sess.key,
            username: sess.username.clone(),
        });
    }
    None
}

fn udp_body(meta: &Meta, nonce: &[u8; 24], mut rest: &[u8], key: [u8; 32]) -> Option<Vec<u8>> {
    if meta.prefix as usize > rest.len() {
        return None;
    }
    rest = &rest[meta.prefix as usize..];
    if meta.payload_len == 0 {
        if rest.len() != meta.suffix as usize {
            return None;
        }
        return Some(Vec::new());
    }
    let wire = meta.payload_len as usize + 16;
    if rest.len() != wire + meta.suffix as usize {
        return None;
    }
    let mut sealed = rest[..wire].to_vec();
    if meta::is_low(meta.kind) {
        let body = crate::entropy::decode(
            &sealed[..meta.payload_len as usize],
            meta.extracted as usize,
            meta.low_mode,
            meta.low_mask,
            meta.rotation,
        )?;
        let tag: [u8; 16] = sealed[meta.payload_len as usize..].try_into().ok()?;
        sealed = body;
        sealed.extend(tag);
    }
    Direction::from_key(key).open_at_in_place(nonce, &mut sealed)?;
    Some(sealed)
}

fn take(tcp: &mut BufReader<TcpStream>, n: usize, allow_idle: bool) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; n];
    read_tcp_exact(tcp, &mut bytes, allow_idle)?;
    Ok(bytes)
}

fn skip_padding(tcp: &mut BufReader<TcpStream>, len: u8) -> io::Result<()> {
    let mut padding = [0; u8::MAX as usize];
    read_tcp_exact(tcp, &mut padding[..usize::from(len)], false)
}

fn read_tcp_exact(
    tcp: &mut BufReader<TcpStream>,
    bytes: &mut [u8],
    allow_idle: bool,
) -> io::Result<()> {
    let start = Instant::now();
    let mut offset = 0;
    while offset < bytes.len() {
        match tcp.read(&mut bytes[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tcp")),
            Ok(read) => offset += read,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if allow_idle && offset == 0 {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "idle"));
                }
                if start.elapsed() > Duration::from_secs(20) {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "接收完整段超时"));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_timeout(mut tcp: &TcpStream, bytes: &[u8]) -> io::Result<()> {
    let mut rest = bytes;
    let start = Instant::now();
    while !rest.is_empty() {
        match tcp.write(rest) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "tcp")),
            Ok(n) => rest = &rest[n..],
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if start.elapsed() > Duration::from_secs(20) {
                    return Err(error);
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct SocksRequest {
    command: u8,
    target: Target,
}

fn read_socks(sess: &Sess) -> io::Result<SocksRequest> {
    // 加密底层已完成认证，mieru 会话直接承载 SOCKS 请求。
    let mut request = read_record(sess, Some(HANDSHAKE_TIMEOUT), |bytes| {
        if bytes.len() < 4 {
            return Ok(None);
        }
        if bytes[0] != 5 || !matches!(bytes[1], 1 | 3) || bytes[2] != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS 请求无效"));
        }
        socks_record_len(bytes)
    })?;
    let command = request[1];
    request[..3].fill(0);
    let (host, port, _) = parse_datagram(&request)?;
    Ok(SocksRequest {
        command,
        target: Target { host, port },
    })
}

fn socks_record_len(bytes: &VecDeque<u8>) -> io::Result<Option<usize>> {
    let length = match bytes[3] {
        1 => 10,
        4 => 22,
        3 => {
            if bytes.len() < 5 {
                return Ok(None);
            }
            7 + usize::from(bytes[4])
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS 地址类型无效",
            ))
        }
    };
    Ok(Some(length))
}

fn read_socks_reply(sess: &Sess) -> io::Result<()> {
    read_socks_reply_for(sess, Some(HANDSHAKE_TIMEOUT))
}

fn read_socks_reply_for(sess: &Sess, wait: Option<Duration>) -> io::Result<()> {
    read_record(sess, wait, |bytes| {
        if bytes.len() < 4 {
            return Ok(None);
        }
        if bytes[0] != 5 || bytes[1] != 0 || bytes[2] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "SOCKS 应答失败",
            ));
        }
        socks_record_len(bytes)
    })
    .map(|_| ())
}

fn read_record(
    sess: &Sess,
    wait: Option<Duration>,
    length: impl Fn(&VecDeque<u8>) -> io::Result<Option<usize>>,
) -> io::Result<Vec<u8>> {
    let deadline = wait.map(|duration| Instant::now() + duration);
    let mut pipe = sess.pipe.lock().expect("pipe");
    loop {
        if let Some(n) = length(&pipe.bytes)? {
            if pipe.bytes.len() >= n {
                let out = pipe.bytes.drain(..n).collect();
                sess.cv.notify_all();
                return Ok(out);
            }
        }
        if pipe.closed {
            return Err(closed());
        }
        let left = remaining(deadline)?.unwrap_or(DATA_IDLE);
        let (next, _) = sess.cv.wait_timeout(pipe, left).expect("pipe");
        pipe = next;
    }
}

fn socks_request(command: u8, host: &str, port: u16) -> io::Result<Vec<u8>> {
    if command == 1 && (host.is_empty() || port == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "目标地址或端口无效",
        ));
    }
    let mut out = vec![5, command, 0];
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        out.push(1);
        out.extend(ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        out.push(4);
        out.extend(ip.octets());
    } else {
        if host.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "host"));
        }
        out.push(3);
        out.push(host.len() as u8);
        out.extend(host.as_bytes());
    }
    out.extend(port.to_be_bytes());
    Ok(out)
}

fn socks_reply() -> Vec<u8> {
    vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
}

fn write_frame(sess: &Sess, packet: &[u8]) -> io::Result<()> {
    if packet.len() > 65535 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame"));
    }
    let mut frame = Vec::with_capacity(4 + packet.len());
    frame.push(0);
    frame.extend((packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(packet);
    frame.push(0xff);
    sess.write_client(&frame)
}

fn read_frame(sess: &Sess) -> io::Result<Vec<u8>> {
    read_frame_for(sess, DATA_IDLE)
}

fn read_frame_for(sess: &Sess, wait: Duration) -> io::Result<Vec<u8>> {
    let record = read_record(sess, Some(wait), |bytes| {
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes[0] != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP 封装帧无效"));
        }
        if bytes.len() < 3 {
            return Ok(None);
        }
        let length = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        Ok(Some(4 + length))
    })?;
    if record.last() != Some(&0xff) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP 封装帧无效"));
    }
    Ok(record[3..record.len() - 1].to_vec())
}

fn udp_datagram(host: &str, port: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = vec![0, 0, 0];
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        out.push(1);
        out.extend(ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        out.push(4);
        out.extend(ip.octets());
    } else {
        if host.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "host"));
        }
        out.push(3);
        out.push(host.len() as u8);
        out.extend(host.as_bytes());
    }
    out.extend(port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn parse_datagram(packet: &[u8]) -> io::Result<(String, u16, Vec<u8>)> {
    if packet.len() < 6 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "udp"));
    }
    let atyp = packet[3];
    let (host, used) = match atyp {
        1 => {
            if packet.len() < 10 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "udp"));
            }
            (
                format!("{}.{}.{}.{}", packet[4], packet[5], packet[6], packet[7]),
                8,
            )
        }
        4 => {
            if packet.len() < 22 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "udp"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[4..20]);
            (std::net::Ipv6Addr::from(octets).to_string(), 20)
        }
        3 => {
            let len = packet.get(4).copied().unwrap_or(0) as usize;
            if packet.len() < 5 + len + 2 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "udp"));
            }
            let host = String::from_utf8(packet[5..5 + len].to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "host"))?;
            (host, 5 + len)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "atyp")),
    };
    let port = u16::from_be_bytes([packet[used], packet[used + 1]]);
    Ok((host, port, packet[used + 2..].to_vec()))
}

fn from_peer(role: Role, kind: u8) -> bool {
    match role {
        Role::Server => matches!(
            kind,
            OPEN_REQUEST | CLOSE_REQUEST | CLOSE_RESPONSE | DATA_C2S | DATA_C2S_LOW | ACK_C2S
        ),
        Role::Client => matches!(
            kind,
            OPEN_RESPONSE | CLOSE_REQUEST | CLOSE_RESPONSE | DATA_S2C | DATA_S2C_LOW | ACK_S2C
        ),
    }
}

fn open_kind(role: Role) -> u8 {
    match role {
        Role::Client => OPEN_REQUEST,
        Role::Server => OPEN_RESPONSE,
    }
}

fn data_kind(role: Role) -> u8 {
    match role {
        Role::Client => DATA_C2S,
        Role::Server => DATA_S2C,
    }
}

fn ack_kind(role: Role) -> u8 {
    match role {
        Role::Client => ACK_C2S,
        Role::Server => ACK_S2C,
    }
}

fn choose_padding(tcp: bool, mtu: u16, payload: usize, session: bool) -> (Vec<u8>, Vec<u8>) {
    let room = if tcp {
        32
    } else {
        let base = 24 + 32 + 16 + if payload == 0 { 0 } else { payload + 16 };
        (mtu as usize).saturating_sub(48 + base)
    };
    if session {
        return (Vec::new(), padding(room.min(32)));
    }
    let prefix = padding(room.min(16));
    let suffix = padding(room.saturating_sub(prefix.len()).min(16));
    (prefix, suffix)
}

fn padding(max: usize) -> Vec<u8> {
    if max == 0 {
        return Vec::new();
    }
    struct PaddingRandom {
        bytes: [u8; 1024],
        cursor: usize,
    }
    thread_local! {
        static RANDOM: RefCell<PaddingRandom> = const {
            RefCell::new(PaddingRandom { bytes: [0; 1024], cursor: 1024 })
        };
    }
    RANDOM.with(|random| {
        let mut random = random.borrow_mut();
        let max = max.min(32);
        if random.cursor + max + 1 > random.bytes.len() {
            getrandom::getrandom(&mut random.bytes).expect("random padding");
            random.cursor = 0;
        }
        let start = random.cursor;
        let len = 1 + usize::from(random.bytes[start]) % max;
        random.cursor += len + 1;
        random.bytes[start + 1..start + 1 + len].to_vec()
    })
}

fn udp_budget(mtu: u16) -> usize {
    // 预留 IPv6 和 UDP 头、nonce、元数据、两个认证标签及最多 32 字节填充。
    mtu as usize - (48 + 24 + 32 + 16 + 16 + 32)
}

fn fragment_size(tcp: bool, mtu: u16, mode: u8) -> usize {
    let budget = if tcp { meta::MAX_PDU } else { udp_budget(mtu) };
    if mode == 0 {
        return budget;
    }
    let width = usize::from(mode) + 3;
    if tcp {
        budget.min((u16::MAX as usize / 8) * width)
    } else {
        (budget / 8) * width
    }
}

fn low_mask(mode: u8) -> u32 {
    if mode == 0 {
        0
    } else {
        (1u32 << (12 + 4 * u32::from(mode))) - 1
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "会话已关闭")
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "等待数据超时")
}

fn remaining(deadline: Option<Instant>) -> io::Result<Option<Duration>> {
    match deadline {
        None => Ok(None),
        Some(deadline) => {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                Err(timed_out())
            } else {
                Ok(Some(left))
            }
        }
    }
}

fn random_below(upper: usize) -> usize {
    let upper = upper as u64;
    let ceiling = u64::MAX - u64::MAX % upper;
    loop {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).expect("random");
        let value = u64::from_ne_bytes(bytes);
        if value < ceiling {
            return (value % upper) as usize;
        }
    }
}

fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).expect("random");
    u32::from_ne_bytes(bytes)
}

#[cfg(test)]
#[path = "completion_tests.rs"]
mod completion_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn detached_session() -> Arc<Sess> {
        let link = Link::new(LinkSetup {
            role: Role::Server,
            mtu: 1400,
            accounts: Arc::new(Mutex::new(Vec::new())),
            socket: LinkSocket::Detached(Transport::Udp),
            ready: None,
            bound_user: String::new(),
            remote: "127.0.0.1:1".parse().unwrap(),
        });
        Sess::new(
            link,
            1,
            "127.0.0.1:2".parse().unwrap(),
            "alice".into(),
            [0; 32],
        )
    }

    #[test]
    fn ordered_delivery_waits_for_the_hole() {
        let sess = detached_session();
        assert!(sess.push_in(1, b"b".to_vec()).is_empty());
        assert!(sess.push_in(1, b"duplicate".to_vec()).is_empty());
        assert_eq!(sess.push_in(0, b"a".to_vec()), b"ab");
        assert!(sess.push_in(0, b"a".to_vec()).is_empty());
    }

    #[test]
    fn ordered_delivery_crosses_the_sequence_wrap() {
        let sess = detached_session();
        sess.reorder.lock().unwrap().next = u32::MAX - 1;
        assert!(sess.push_in(0, b"c".to_vec()).is_empty());
        assert!(sess.push_in(u32::MAX, b"b".to_vec()).is_empty());
        assert_eq!(sess.push_in(u32::MAX - 1, b"a".to_vec()), b"abc");
        assert!(sess.push_in(u32::MAX, b"old".to_vec()).is_empty());
        assert_eq!(sess.push_in(1, b"d".to_vec()), b"d");
    }

    #[test]
    fn filling_a_gap_releases_the_reorder_byte_budget() {
        let sess = detached_session();
        let count = (PIPE_LIMIT / meta::MAX_PDU) as u32;
        for seq in 1..=count {
            assert!(sess.push_in(seq, vec![7; meta::MAX_PDU]).is_empty());
        }
        assert_eq!(sess.push_in(0, Vec::new()), vec![7; PIPE_LIMIT]);
        assert!(sess.push_in(count + 2, vec![8; meta::MAX_PDU]).is_empty());
        assert_eq!(sess.push_in(count + 1, Vec::new()), vec![8; meta::MAX_PDU]);
    }

    #[test]
    fn localhost_carries_bytes_after_socks() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let account = Account {
                username: "alice".into(),
                password: "secret".into(),
            };
            let (conn, target, user) = accept(tcp, &[account]).unwrap();
            assert_eq!(user, "alice");
            assert_eq!(target.host, "example.com");
            assert_eq!(target.port, 443);
            let mut buf = [0u8; 4];
            let n = conn.read_user(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping");
            conn.write_user(b"pong").unwrap();
        });
        let conn = connect(
            format!("127.0.0.1:{port}").parse().unwrap(),
            &Account {
                username: "alice".into(),
                password: "secret".into(),
            },
            &Target {
                host: "example.com".into(),
                port: 443,
            },
        )
        .unwrap();
        conn.write_user(b"ping").unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(conn.read_user(&mut buf).unwrap(), 4);
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
    }

    fn account() -> Account {
        Account {
            username: "alice".into(),
            password: "secret".into(),
        }
    }

    fn read_exact_user(conn: &Conn, buf: &mut [u8]) {
        let mut filled = 0;
        while filled < buf.len() {
            let n = conn.read_user(&mut buf[filled..]).unwrap();
            assert!(n > 0);
            filled += n;
        }
    }

    #[test]
    fn one_tcp_underlay_carries_two_sessions_and_early_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (tcp, peer) = listener.accept().unwrap();
            serve_tcp(tcp, peer, Arc::new(Mutex::new(vec![account()])), 1400, tx).unwrap();
        });
        let link = dial(
            format!("127.0.0.1:{port}").parse().unwrap(),
            &account(),
            true,
        )
        .unwrap();
        let early = open_connect(
            &link,
            &Target {
                host: "one.example".into(),
                port: 1,
            },
            b"early",
        )
        .unwrap();
        let second = open_connect(
            &link,
            &Target {
                host: "two.example".into(),
                port: 2,
            },
            b"",
        )
        .unwrap();
        let mut ready = [
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        ];
        ready.sort_by(|left, right| left.target.host.cmp(&right.target.host));
        assert_eq!(ready[0].target.host, "one.example");
        assert!(!ready[0].udp);
        let mut early_buf = [0u8; 5];
        read_exact_user(&ready[0].conn, &mut early_buf);
        assert_eq!(&early_buf, b"early");
        let echo = thread::spawn(move || {
            let mut buf = [0u8; 4];
            read_exact_user(&ready[1].conn, &mut buf);
            assert_eq!(&buf, b"ping");
            ready[1].conn.write_user(b"pong").unwrap();
        });
        second.write_user(b"ping").unwrap();
        let mut buf = [0u8; 4];
        read_exact_user(&second, &mut buf);
        assert_eq!(&buf, b"pong");
        echo.join().unwrap();
        drop(early);
    }

    #[test]
    fn udp_underlay_carries_a_connect() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        serve_udp(socket, Arc::new(Mutex::new(vec![account()])), 1280, tx).unwrap();
        let server = thread::spawn(move || {
            let ready = rx.recv_timeout(Duration::from_secs(8)).unwrap();
            assert!(!ready.udp);
            assert_eq!(ready.target.host, "example.com");
            assert_eq!(ready.target.port, 9);
            let mut buf = [0u8; 4];
            read_exact_user(&ready.conn, &mut buf);
            assert_eq!(&buf, b"ping");
            ready.conn.write_user(b"pong").unwrap();
        });
        let conn = connect_udp(
            format!("127.0.0.1:{port}").parse().unwrap(),
            &account(),
            &Target {
                host: "example.com".into(),
                port: 9,
            },
        )
        .unwrap();
        conn.write_user(b"ping").unwrap();
        let mut buf = [0u8; 4];
        read_exact_user(&conn, &mut buf);
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn udp_window_releases_after_the_initial_sixteen() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        serve_udp(socket, Arc::new(Mutex::new(vec![account()])), 1400, tx).unwrap();
        let server = thread::spawn(move || {
            let ready = rx.recv_timeout(Duration::from_secs(8)).unwrap();
            let mut buf = [0u8; 20];
            read_exact_user(&ready.conn, &mut buf);
            assert_eq!(buf, *b"abcdefghijklmnopqrst");
            ready.conn.write_user(&buf).unwrap();
        });
        let conn = connect_udp(
            format!("127.0.0.1:{port}").parse().unwrap(),
            &account(),
            &Target {
                host: "example.com".into(),
                port: 9,
            },
        )
        .unwrap();
        for byte in b"abcdefghijklmnopqrst" {
            conn.write_user(&[*byte]).unwrap();
        }
        let mut buf = [0u8; 20];
        read_exact_user(&conn, &mut buf);
        assert_eq!(&buf, b"abcdefghijklmnopqrst");
        server.join().unwrap();
    }

    #[test]
    fn udp_associate_frames_each_destination() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (tcp, peer) = listener.accept().unwrap();
            serve_tcp(tcp, peer, Arc::new(Mutex::new(vec![account()])), 1400, tx).unwrap();
        });
        let client = thread::spawn(move || {
            let assoc = associate(
                format!("127.0.0.1:{port}").parse().unwrap(),
                &account(),
                false,
            )
            .unwrap();
            assoc.send_to("1.2.3.4", 53, b"dns").unwrap();
            assoc.send_to("example.com", 443, b"hi").unwrap();
            let (host, port, payload) = assoc.recv_from().unwrap();
            assert_eq!(
                (host.as_str(), port, payload.as_slice()),
                ("1.2.3.4", 53, b"ok".as_slice())
            );
        });
        let mut first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut second = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        if first.target.port != 53 {
            std::mem::swap(&mut first, &mut second);
        }
        assert!(first.udp && second.udp);
        assert_eq!(first.target.host, "1.2.3.4");
        assert_eq!(second.target.host, "example.com");
        assert_eq!(second.target.port, 443);
        let mut buf = [0u8; 4];
        assert_eq!(first.conn.read_user(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"dns");
        let mut buf = [0u8; 2];
        assert_eq!(second.conn.read_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"hi");
        first.conn.write_user(b"ok").unwrap();
        client.join().unwrap();
    }

    #[test]
    fn low_entropy_segment_reaches_the_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let (conn, target, user) = accept(tcp, &[account()]).unwrap();
            let mut buf = [0u8; 4];
            read_exact_user(&conn, &mut buf);
            assert_eq!(&buf, b"low!");
            (target, user)
        });
        let conn = connect(
            format!("127.0.0.1:{port}").parse().unwrap(),
            &account(),
            &Target {
                host: "example.com".into(),
                port: 443,
            },
        )
        .unwrap();
        conn.write_low_entropy(b"low!").unwrap();
        let (target, user) = server.join().unwrap();
        assert_eq!(user, "alice");
        assert_eq!(target.port, 443);
    }
}
