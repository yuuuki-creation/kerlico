use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::crypto::{self, Direction};
use crate::meta::{self, Meta, ACK_C2S, ACK_S2C, CLOSE_REQUEST, CLOSE_RESPONSE, DATA_C2S, DATA_C2S_LOW, DATA_S2C, DATA_S2C_LOW, OPEN_REQUEST, OPEN_RESPONSE};

const PIPE_LIMIT: usize = 2 * 1024 * 1024;
const WINDOW: u16 = 4096;
const INITIAL_WINDOW: u32 = 16;

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

struct Link {
    role: Role,
    tcp: bool,
    mtu: u16,
    accounts: Arc<Mutex<Vec<Account>>>,
    send_dir: Mutex<Option<Direction>>,
    bound_user: Mutex<String>,
    remote: SocketAddr,
    sessions: Mutex<HashMap<(SocketAddr, u32), Arc<Sess>>>,
    write_tcp: Mutex<Option<TcpStream>>,
    write_udp: Mutex<Option<UdpSocket>>,
    ready: Mutex<Option<Sender<Ready>>>,
    alive: AtomicBool,
}

struct Sess {
    link: Arc<Link>,
    id: u32,
    peer: SocketAddr,
    username: String,
    key: [u8; 32],
    pipe: Mutex<Pipe>,
    cv: Condvar,
    reorder: Mutex<Reorder>,
    inflight: Mutex<BTreeMap<u32, Flight>>,
    next_send: AtomicU32,
    peer_window: AtomicU32,
    cwnd: AtomicU32,
    closed: AtomicBool,
    last_tx: Mutex<Instant>,
}

struct Pipe {
    bytes: VecDeque<u8>,
    closed: bool,
}

struct Reorder {
    next: u32,
    held: BTreeMap<u32, Vec<u8>>,
}

struct Flight {
    kind: u8,
    payload: Vec<u8>,
    sent: Instant,
    timeout: Duration,
    tx: u8,
}

struct Leg {
    sess: Arc<Sess>,
    host: String,
    port: u16,
    queue: Mutex<LegQueue>,
    cv: Condvar,
}

struct LegQueue {
    current: VecDeque<u8>,
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
    let sess = open_raw(&link)?;
    let request = socks_request(3, "0.0.0.0", 0)?;
    sess.write_open(&request)?;
    read_socks_reply(&sess)?;
    Ok(Assoc { sess })
}

pub fn accept(tcp: TcpStream, accounts: &[Account]) -> io::Result<(Conn, Target, String)> {
    let peer = tcp.peer_addr().unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
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
) -> io::Result<()> {
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let write = tcp.try_clone()?;
    let link = Link::new(Role::Server, true, mtu, accounts, Some(write), None, Some(ready), String::new(), peer);
    thread::spawn(move || reader_tcp(tcp, link, peer));
    Ok(())
}

pub fn serve_udp(socket: UdpSocket, accounts: Arc<Mutex<Vec<Account>>>, mtu: u16, ready: Sender<Ready>) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let write = socket.try_clone()?;
    let link = Link::new(
        Role::Server,
        false,
        mtu,
        accounts,
        None,
        Some(write),
        Some(ready),
        String::new(),
        SocketAddr::from(([0, 0, 0, 0], 0)),
    );
    thread::spawn(move || reader_udp(socket, link));
    Ok(())
}

fn dial(peer: SocketAddr, account: &Account, tcp: bool) -> io::Result<Arc<Link>> {
    let accounts = Arc::new(Mutex::new(vec![account.clone()]));
    let now = meta::unix_now();
    let send = crypto::client_direction(&account.username, &account.password, now);
    if tcp {
        let tcp = TcpStream::connect_timeout(&peer, Duration::from_secs(10))?;
        tcp.set_nodelay(true).ok();
        tcp.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let write = tcp.try_clone()?;
        let link = Link::new(Role::Client, true, 1400, accounts, Some(write), None, None, account.username.clone(), peer);
        *link.send_dir.lock().expect("send") = Some(send);
        let reader = Arc::clone(&link);
        thread::spawn(move || reader_tcp(tcp, reader, peer));
        Ok(link)
    } else {
        let bind = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(peer)?;
        socket.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let write = socket.try_clone()?;
        let link = Link::new(Role::Client, false, 1400, accounts, None, Some(write), None, account.username.clone(), peer);
        *link.send_dir.lock().expect("send") = Some(send);
        let reader = Arc::clone(&link);
        thread::spawn(move || reader_udp(socket, reader));
        Ok(link)
    }
}

impl Link {
    fn new(
        role: Role,
        tcp: bool,
        mtu: u16,
        accounts: Arc<Mutex<Vec<Account>>>,
        write_tcp: Option<TcpStream>,
        write_udp: Option<UdpSocket>,
        ready: Option<Sender<Ready>>,
        bound_user: String,
        remote: SocketAddr,
    ) -> Arc<Self> {
        Arc::new(Self {
            role,
            tcp,
            mtu,
            accounts,
            send_dir: Mutex::new(None),
            bound_user: Mutex::new(bound_user),
            remote,
            sessions: Mutex::new(HashMap::new()),
            write_tcp: Mutex::new(write_tcp),
            write_udp: Mutex::new(write_udp),
            ready: Mutex::new(ready),
            alive: AtomicBool::new(true),
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
        let sessions: Vec<Arc<Sess>> = self.sessions.lock().expect("sessions").values().cloned().collect();
        for sess in sessions {
            sess.tick();
        }
    }

    fn insert(&self, sess: Arc<Sess>) {
        self.sessions.lock().expect("sessions").insert((sess.peer, sess.id), sess);
    }

    fn get(&self, peer: SocketAddr, id: u32) -> Option<Arc<Sess>> {
        self.sessions.lock().expect("sessions").get(&(peer, id)).cloned()
    }
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
    fn new(link: Arc<Link>, id: u32, peer: SocketAddr, username: String, key: [u8; 32]) -> Arc<Self> {
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
            reorder: Mutex::new(Reorder {
                next: 0,
                held: BTreeMap::new(),
            }),
            inflight: Mutex::new(BTreeMap::new()),
            next_send: AtomicU32::new(0),
            peer_window: AtomicU32::new(INITIAL_WINDOW),
            cwnd: AtomicU32::new(INITIAL_WINDOW),
            closed: AtomicBool::new(false),
            last_tx: Mutex::new(Instant::now()),
        })
    }

    fn append(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut pipe = self.pipe.lock().expect("pipe");
        while !pipe.closed && pipe.bytes.len() >= PIPE_LIMIT {
            let (next, _) = self
                .cv
                .wait_timeout(pipe, Duration::from_millis(200))
                .expect("cv");
            pipe = next;
        }
        if pipe.closed {
            return;
        }
        pipe.bytes.extend(bytes);
        self.cv.notify_all();
    }

    fn read_exact(&self, n: usize) -> io::Result<Vec<u8>> {
        let start = Instant::now();
        let mut pipe = self.pipe.lock().expect("pipe");
        loop {
            if pipe.bytes.len() >= n {
                let out: Vec<u8> = pipe.bytes.drain(..n).collect();
                self.cv.notify_all();
                return Ok(out);
            }
            if pipe.closed {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"));
            }
            if start.elapsed() > Duration::from_secs(20) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "read"));
            }
            let (next, wait) = self
                .cv
                .wait_timeout(pipe, Duration::from_millis(200))
                .expect("cv");
            pipe = next;
            let _ = wait;
        }
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
        if self.queued() > PIPE_LIMIT {
            0
        } else {
            WINDOW
        }
    }

    fn unack(&self) -> u32 {
        self.reorder.lock().expect("reorder").next
    }

    fn push_in(&self, seq: u32, payload: Vec<u8>) -> Vec<u8> {
        let mut reorder = self.reorder.lock().expect("reorder");
        if seq < reorder.next {
            return Vec::new();
        }
        if seq != reorder.next && reorder.held.len() >= WINDOW as usize {
            return Vec::new();
        }
        reorder.held.insert(seq, payload);
        let mut out = Vec::new();
        loop {
            let next = reorder.next;
            let Some(payload) = reorder.held.remove(&next) else {
                break;
            };
            out.extend(payload);
            reorder.next = next.wrapping_add(1);
        }
        out
    }

    fn on_ack(&self, unack: u32, window: u16) {
        let mut inflight = self.inflight.lock().expect("inflight");
        let before = inflight.len();
        inflight.retain(|seq, _| *seq >= unack);
        let removed = before.saturating_sub(inflight.len());
        drop(inflight);
        if removed > 0 {
            let cwnd = self.cwnd.load(Ordering::Relaxed).saturating_add(removed as u32).min(WINDOW as u32);
            self.cwnd.store(cwnd.max(INITIAL_WINDOW), Ordering::Relaxed);
        }
        self.peer_window.store(u32::from(window), Ordering::Relaxed);
        self.cv.notify_all();
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
            let limit = self.cwnd.load(Ordering::Relaxed).min(self.peer_window.load(Ordering::Relaxed));
            if limit > 0 && inflight.len() < limit as usize {
                return Ok(());
            }
            if start.elapsed() > Duration::from_secs(60) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "window"));
            }
            let (next, _) = self
                .cv
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
        let max = if self.link.tcp {
            meta::MAX_PDU
        } else {
            udp_budget(self.link.mtu).max(1)
        };
        for chunk in buf.chunks(max) {
            if self.closed.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
            }
            self.wait_slot()?;
            let seq = self.next_send.fetch_add(1, Ordering::Relaxed);
            self.emit(data_kind(self.link.role), seq, chunk, true)?;
        }
        Ok(())
    }

    fn emit(&self, kind: u8, seq: u32, payload: &[u8], remember: bool) -> io::Result<()> {
        let (prefix, suffix) = choose_padding(self.link.tcp, self.link.mtu, payload.len(), meta::is_session(kind));
        let plain = if meta::is_session(kind) {
            meta::session(kind, self.id, seq, payload.len() as u16, suffix.len() as u8)
        } else {
            meta::data(&Meta {
                kind,
                session: self.id,
                seq,
                unack: self.unack(),
                window: self.window(),
                fragment: 0,
                prefix: prefix.len() as u8,
                payload_len: payload.len() as u16,
                suffix: suffix.len() as u8,
                low_mode: 0,
                low_mask: 0,
                extracted: 0,
                rotation: 0,
            })
        };
        self.write_wire(&plain, payload, &prefix, &suffix)?;
        if remember && !self.link.tcp {
            self.inflight.lock().expect("inflight").insert(
                seq,
                Flight {
                    kind,
                    payload: payload.to_vec(),
                    sent: Instant::now(),
                    timeout: Duration::from_secs(3),
                    tx: 1,
                },
            );
        }
        Ok(())
    }

    fn send_ack(&self) -> io::Result<()> {
        if self.link.tcp || self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        let seq = self.next_send.load(Ordering::Relaxed).saturating_sub(1);
        self.emit(ack_kind(self.link.role), seq, &[], false)
    }

    fn send_close(&self, response: bool) {
        if self.link.alive.load(Ordering::SeqCst) {
            let seq = self.next_send.fetch_add(1, Ordering::Relaxed);
            let kind = if response { CLOSE_RESPONSE } else { CLOSE_REQUEST };
            let _ = self.emit(kind, seq, &[], false);
        }
    }

    fn shutdown(&self, request: bool) {
        let first = !self.closed.swap(true, Ordering::SeqCst);
        self.pipe.lock().expect("pipe").closed = true;
        self.cv.notify_all();
        if first && request {
            self.send_close(false);
        }
    }

    #[cfg(test)]
    fn write_low_entropy(&self, payload: &[u8]) -> io::Result<()> {
        let mode = 1u8;
        let mask = 0x0f0f_0f0fu32;
        let rotation = 0u8;
        let encoded_len = crate::entropy::encoded_len(payload.len(), mode)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "low entropy"))?;
        self.wait_slot()?;
        let seq = self.next_send.fetch_add(1, Ordering::Relaxed);
        let (prefix, suffix) = choose_padding(self.link.tcp, self.link.mtu, encoded_len as usize, false);
        let plain = meta::data(&Meta {
            kind: if self.link.role == Role::Client { DATA_C2S_LOW } else { DATA_S2C_LOW },
            session: self.id,
            seq,
            unack: self.unack(),
            window: self.window(),
            fragment: 0,
            prefix: prefix.len() as u8,
            payload_len: encoded_len,
            suffix: suffix.len() as u8,
            low_mode: mode,
            low_mask: mask,
            extracted: payload.len() as u16,
            rotation,
        });
        let wire = self.seal_low(&plain, payload, &prefix, &suffix, mode, mask, rotation)?;
        self.send_wire(&wire)
    }

    #[cfg(test)]
    fn seal_low(
        &self,
        meta_plain: &[u8],
        payload: &[u8],
        prefix: &[u8],
        suffix: &[u8],
        mode: u8,
        mask: u32,
        rotation: u8,
    ) -> io::Result<Vec<u8>> {
        let encode_body = |mut sealed: Vec<u8>| -> io::Result<Vec<u8>> {
            if sealed.len() < 16 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "low entropy"));
            }
            let tag = sealed.split_off(sealed.len() - 16);
            let mut body = crate::entropy::encode(&sealed, mode, mask, rotation, 0)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "low entropy"))?;
            body.extend(tag);
            Ok(body)
        };
        if self.link.tcp {
            let mut guard = self.link.send_dir.lock().expect("send");
            let dir = guard
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "send"))?;
            let mut out = dir.seal(&self.username, meta_plain);
            out.extend_from_slice(prefix);
            out.extend(encode_body(dir.seal(&self.username, payload))?);
            out.extend_from_slice(suffix);
            Ok(out)
        } else {
            let nonce = crypto::nonce_with_hint(&self.username);
            let dir = Direction::from_key(self.key);
            let mut out = nonce.to_vec();
            out.extend(dir.seal_at(&nonce, meta_plain));
            out.extend_from_slice(prefix);
            out.extend(encode_body(dir.seal_at(&nonce, payload))?);
            out.extend_from_slice(suffix);
            Ok(out)
        }
    }

    fn send_wire(&self, wire: &[u8]) -> io::Result<()> {
        if self.link.tcp {
            let mut tcp = self.link.write_tcp.lock().expect("tcp");
            let tcp = tcp.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "tcp"))?;
            write_all_timeout(tcp, wire)?;
        } else {
            let udp = self.link.write_udp.lock().expect("udp");
            let udp = udp.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "udp"))?;
            udp.send_to(wire, self.peer)?;
        }
        *self.last_tx.lock().expect("tx") = Instant::now();
        Ok(())
    }

    fn write_wire(&self, meta_plain: &[u8], payload: &[u8], prefix: &[u8], suffix: &[u8]) -> io::Result<()> {
        let wire = if self.link.tcp {
            let mut guard = self.link.send_dir.lock().expect("send");
            let dir = guard
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "send"))?;
            let mut out = Vec::with_capacity(meta_plain.len() + payload.len() + prefix.len() + suffix.len() + 96);
            dir.seal_into(&self.username, meta_plain, &mut out);
            out.extend_from_slice(prefix);
            if !payload.is_empty() {
                dir.seal_into(&self.username, payload, &mut out);
            }
            out.extend_from_slice(suffix);
            out
        } else {
            let nonce = crypto::nonce_with_hint(&self.username);
            let dir = Direction::from_key(self.key);
            let mut out = nonce.to_vec();
            out.extend(dir.seal_at(&nonce, meta_plain));
            out.extend_from_slice(prefix);
            if !payload.is_empty() {
                out.extend(dir.seal_at(&nonce, payload));
            }
            out.extend_from_slice(suffix);
            out
        };
        self.send_wire(&wire)
    }

    fn tick(&self) {
        if self.link.tcp || self.closed.load(Ordering::SeqCst) {
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
                due.push((*seq, flight.kind, flight.payload.clone()));
            }
            due
        };
        for (seq, kind, payload) in due {
            let _ = self.emit(kind, seq, &payload, false);
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
            ConnKind::Stream(sess) => sess.read_some(buf),
            ConnKind::Leg(leg) => leg.read(buf),
        }
    }

    pub fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        match &self.kind {
            ConnKind::Stream(sess) => sess.read_for(buf, wait),
            ConnKind::Leg(leg) => leg.read_for(buf, wait),
        }
    }

    pub fn write_user(&self, buf: &[u8]) -> io::Result<()> {
        match &self.kind {
            ConnKind::Stream(sess) => sess.write_app(buf),
            ConnKind::Leg(leg) => leg.write(buf),
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let ConnKind::Stream(sess) = &self.kind {
            sess.shutdown(true);
        }
    }
}

impl Assoc {
    pub fn send_to(&self, host: &str, port: u16, payload: &[u8]) -> io::Result<()> {
        let packet = udp_datagram(host, port, payload)?;
        write_frame(&self.sess, &packet)
    }

    pub fn recv_from(&self) -> io::Result<(String, u16, Vec<u8>)> {
        let packet = read_frame(&self.sess)?;
        parse_datagram(&packet)
    }
}

impl Leg {
    fn push(&self, payload: Vec<u8>) {
        if payload.is_empty() {
            return;
        }
        let mut queue = self.queue.lock().expect("leg");
        if queue.closed {
            return;
        }
        if queue.later.len() >= 64 {
            return;
        }
        queue.later.push_back(payload);
        self.cv.notify_all();
    }

    fn close(&self) {
        self.queue.lock().expect("leg").closed = true;
        self.cv.notify_all();
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut queue = self.queue.lock().expect("leg");
        loop {
            if queue.current.is_empty() {
                if let Some(next) = queue.later.pop_front() {
                    queue.current.extend(next);
                }
            }
            if !queue.current.is_empty() {
                return Ok(copy_deque(buf, &mut queue.current));
            }
            if queue.closed {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"));
            }
            queue = self.cv.wait(queue).expect("leg");
        }
    }

    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut queue = self.queue.lock().expect("leg");
        let start = Instant::now();
        loop {
            if queue.current.is_empty() {
                if let Some(next) = queue.later.pop_front() {
                    queue.current.extend(next);
                }
            }
            if !queue.current.is_empty() {
                return Ok(copy_deque(buf, &mut queue.current));
            }
            if queue.closed {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"));
            }
            let left = wait.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle"));
            }
            let (next, status) = self.cv.wait_timeout(queue, left).expect("leg");
            queue = next;
            if status.timed_out() && queue.current.is_empty() && queue.later.is_empty() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle"));
            }
        }
    }

    fn write(&self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let packet = udp_datagram(&self.host, self.port, payload)?;
        write_frame(&self.sess, &packet)
    }
}

fn reader_tcp(mut tcp: TcpStream, link: Arc<Link>, peer: SocketAddr) {
    let mut stash = Vec::new();
    let mut recv: Option<Direction> = None;
    loop {
        if !link.alive.load(Ordering::SeqCst) {
            break;
        }
        match read_tcp_segment(&mut tcp, &mut stash, &mut recv, &link, peer) {
            Ok(Some(incoming)) => dispatch(&link, incoming),
            Ok(None) => link.tick(),
            Err(_) => {
                link.alive.store(false, Ordering::SeqCst);
                let sessions: Vec<_> = link.sessions.lock().expect("sessions").values().cloned().collect();
                for sess in sessions {
                    sess.shutdown(false);
                }
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
            Err(error) if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut => {
                link.tick();
            }
            Err(_) => break,
        }
    }
    link.alive.store(false, Ordering::SeqCst);
    let sessions: Vec<_> = link.sessions.lock().expect("sessions").values().cloned().collect();
    for sess in sessions {
        sess.shutdown(false);
    }
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
        if link.get(incoming.peer, incoming.meta.session).is_some() {
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
        link.insert(Arc::clone(&sess));
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
    let mut legs: HashMap<(String, u16), Arc<Leg>> = HashMap::new();
    loop {
        let packet = match read_frame(&sess) {
            Ok(packet) => packet,
            Err(_) => break,
        };
        let (host, port, payload) = match parse_datagram(&packet) {
            Ok(parsed) => parsed,
            Err(_) => break,
        };
        let key = (host.to_ascii_lowercase(), port);
        if let Some(leg) = legs.get(&key) {
            leg.push(payload);
            continue;
        }
        let leg = Arc::new(Leg {
            sess: Arc::clone(&sess),
            host: host.clone(),
            port,
            queue: Mutex::new(LegQueue {
                current: VecDeque::new(),
                later: VecDeque::new(),
                closed: false,
            }),
            cv: Condvar::new(),
        });
        leg.push(payload);
        legs.insert(key, Arc::clone(&leg));
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
    for leg in legs.values() {
        leg.close();
    }
    sess.shutdown(true);
}

fn open_connect(link: &Arc<Link>, target: &Target, early: &[u8]) -> io::Result<Conn> {
    let sess = open_raw(link)?;
    let mut payload = socks_request(1, &target.host, target.port)?;
    payload.extend_from_slice(early);
    if payload.len() <= meta::MAX_SESSION_PAYLOAD {
        sess.write_open(&payload)?;
    } else {
        sess.write_open(&[])?;
        sess.write_app(&payload)?;
    }
    read_socks_reply(&sess)?;
    Ok(Conn {
        kind: ConnKind::Stream(sess),
    })
}

fn open_raw(link: &Arc<Link>) -> io::Result<Arc<Sess>> {
    let id = random_u32().max(1);
    let username = link.bound_user.lock().expect("user").clone();
    let key = link.key_bytes()?;
    let sess = Sess::new(Arc::clone(link), id, link.remote, username, key);
    link.insert(Arc::clone(&sess));
    Ok(sess)
}

fn read_tcp_segment(
    tcp: &mut TcpStream,
    stash: &mut Vec<u8>,
    recv: &mut Option<Direction>,
    link: &Arc<Link>,
    peer: SocketAddr,
) -> io::Result<Option<Incoming>> {
    let first = recv.is_none();
    let header_len = if first { 24 + 32 + 16 } else { 32 + 16 };
    let header = match take(tcp, stash, header_len) {
        Ok(header) => header,
        Err(error) if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if first && crate::replay::reject(&header[..16], None) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "replay"));
    }
    let (plain, key, username) = if let Some(direction) = recv.as_mut() {
        let plain = direction
            .open_next(&header)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "decrypt"))?;
        let key = direction.key_bytes();
        let username = link.bound_user.lock().expect("user").clone();
        (plain, key, username)
    } else {
        let accounts = link.accounts.lock().expect("accounts").clone();
        let mut opened = None;
        for account in &accounts {
            if let Some(found) = crypto::open_first(&account.username, &account.password, &header, meta::unix_now()) {
                opened = Some(found);
                break;
            }
        }
        let opened = opened.ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "user"))?;
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
    let payload = read_tcp_payload(tcp, stash, recv.as_mut().unwrap(), &meta)?;
    Ok(Some(Incoming {
        peer,
        meta,
        payload,
        key,
        username,
    }))
}

fn read_tcp_payload(tcp: &mut TcpStream, stash: &mut Vec<u8>, direction: &mut Direction, meta: &Meta) -> io::Result<Vec<u8>> {
    if meta.prefix > 0 {
        let _ = take(tcp, stash, meta.prefix as usize)?;
    }
    let payload = if meta.payload_len == 0 {
        Vec::new()
    } else {
        let mut wire = take(tcp, stash, meta.payload_len as usize + 16)?;
        if meta::is_low(meta.kind) {
            let body = crate::entropy::decode(
                &wire[..meta.payload_len as usize],
                meta.extracted as usize,
                meta.low_mode,
                meta.low_mask,
                meta.rotation,
            )
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "low entropy"))?;
            let tag = wire[meta.payload_len as usize..].to_vec();
            wire = body;
            wire.extend(tag);
        }
        direction
            .open_next(&wire)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload"))?
    };
    if meta.suffix > 0 {
        let _ = take(tcp, stash, meta.suffix as usize)?;
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
            if let Some(opened) = crypto::open_first(&account.username, &account.password, &packet[..72], meta::unix_now()) {
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
        if let Some(opened) = crypto::open_first(&account.username, &account.password, &packet[..72], meta::unix_now()) {
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

fn decrypt_known(link: &Link, peer: SocketAddr, packet: &[u8], nonce: &[u8; 24]) -> Option<Incoming> {
    let sessions: Vec<Arc<Sess>> = link
        .sessions
        .lock()
        .expect("sessions")
        .values()
        .filter(|sess| sess.peer == peer)
        .cloned()
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
        let tag = sealed[meta.payload_len as usize..].to_vec();
        sealed = body;
        sealed.extend(tag);
    }
    Direction::from_key(key).open_at(nonce, &sealed)
}

fn take(tcp: &mut TcpStream, stash: &mut Vec<u8>, n: usize) -> io::Result<Vec<u8>> {
    let start = Instant::now();
    while stash.len() < n {
        let mut buf = [0u8; 64 * 1024];
        ack_soon(tcp);
        match tcp.read(&mut buf) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tcp")),
            Ok(read) => stash.extend_from_slice(&buf[..read]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut => {
                if stash.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "idle"));
                }
                if start.elapsed() > Duration::from_secs(20) {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(stash.drain(..n).collect())
}

#[cfg(target_os = "linux")]
fn ack_soon(tcp: &TcpStream) {
    use std::os::fd::AsRawFd;
    let on: i32 = 1;
    unsafe {
        setsockopt(tcp.as_raw_fd(), 6, 12, &on, 4);
    }
}

#[cfg(not(target_os = "linux"))]
fn ack_soon(_tcp: &TcpStream) {}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn setsockopt(fd: i32, level: i32, name: i32, val: *const i32, len: u32) -> i32;
}

fn write_all_timeout(tcp: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    let mut rest = bytes;
    let start = Instant::now();
    while !rest.is_empty() {
        match tcp.write(rest) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "tcp")),
            Ok(n) => rest = &rest[n..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut => {
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
    let first = sess.read_exact(2)?;
    if first[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "socks"));
    }
    let more = sess.read_exact(2)?;
    if matches!(first[1], 1 | 3) && more[0] == 0 && matches!(more[1], 1 | 3 | 4) {
        let target = read_addr(sess, more[1])?;
        return Ok(SocksRequest {
            command: first[1],
            target,
        });
    }
    let nmethods = first[1] as usize;
    if nmethods == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "socks"));
    }
    let mut methods = more;
    if nmethods > 2 {
        methods.extend(sess.read_exact(nmethods - 2)?);
    }
    let mut leftover = methods.split_off(nmethods.min(methods.len()));
    if !methods[..nmethods.min(methods.len())].contains(&0) {
        let _ = sess.write_app(&[5, 0xff]);
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "socks"));
    }
    sess.write_app(&[5, 0])?;
    if leftover.len() < 4 {
        leftover.extend(sess.read_exact(4 - leftover.len())?);
    }
    if leftover[0] != 5 || !matches!(leftover[1], 1 | 3) || leftover[2] != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "socks"));
    }
    let pending = leftover[4..].to_vec();
    let target = read_addr_prefix(sess, leftover[3], &pending)?;
    Ok(SocksRequest {
        command: leftover[1],
        target,
    })
}

fn read_addr(sess: &Sess, atyp: u8) -> io::Result<Target> {
    read_addr_prefix(sess, atyp, &[])
}

fn read_addr_prefix(sess: &Sess, atyp: u8, prefix: &[u8]) -> io::Result<Target> {
    let mut cursor = prefix.to_vec();
    let need = match atyp {
        1 => 4,
        4 => 16,
        3 => 1,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "atyp")),
    };
    if cursor.len() < need {
        cursor.extend(sess.read_exact(need - cursor.len())?);
    }
    let host = match atyp {
        1 => format!("{}.{}.{}.{}", cursor[0], cursor[1], cursor[2], cursor[3]),
        4 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&cursor[..16]);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        3 => {
            let len = cursor[0] as usize;
            if cursor.len() < 1 + len {
                cursor.extend(sess.read_exact(1 + len - cursor.len())?);
            }
            String::from_utf8(cursor[1..1 + len].to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "host"))?
        }
        _ => unreachable!(),
    };
    let used = match atyp {
        1 => 4,
        4 => 16,
        3 => 1 + host.len(),
        _ => 0,
    };
    let mut port_bytes = cursor.get(used..).unwrap_or(&[]).to_vec();
    if port_bytes.len() < 2 {
        port_bytes.extend(sess.read_exact(2 - port_bytes.len())?);
    }
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Ok(Target { host, port })
}

fn read_socks_reply(sess: &Sess) -> io::Result<()> {
    let head = sess.read_exact(3)?;
    if head[0] != 5 || head[1] != 0 {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "socks"));
    }
    let atyp = sess.read_exact(1)?[0];
    let _ = read_addr(sess, atyp)?;
    Ok(())
}

fn socks_request(command: u8, host: &str, port: u16) -> io::Result<Vec<u8>> {
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
    sess.write_app(&frame)
}

fn read_frame(sess: &Sess) -> io::Result<Vec<u8>> {
    let marker = sess.read_exact(1)?;
    if marker[0] != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame"));
    }
    let len = u16::from_be_bytes(sess.read_exact(2)?.try_into().unwrap()) as usize;
    let data = sess.read_exact(len)?;
    let end = sess.read_exact(1)?;
    if end[0] != 0xff {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame"));
    }
    Ok(data)
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
            (format!("{}.{}.{}.{}", packet[4], packet[5], packet[6], packet[7]), 8)
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
        mtu as usize - base.min(mtu as usize)
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
    let mut byte = [0u8; 1];
    let _ = getrandom::getrandom(&mut byte);
    let len = 1 + (byte[0] as usize % max.min(32));
    let mut out = vec![0u8; len];
    let _ = getrandom::getrandom(&mut out);
    out
}

fn udp_budget(mtu: u16) -> usize {
    mtu as usize - (24 + 32 + 16 + 16 + 64)
}

fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).expect("random");
    u32::from_ne_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn ordered_delivery_waits_for_the_hole() {
        let link = Link::new(
            Role::Server,
            false,
            1400,
            Arc::new(Mutex::new(Vec::new())),
            None,
            None,
            None,
            String::new(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let sess = Sess::new(link, 1, "127.0.0.1:2".parse().unwrap(), "alice".into(), [0; 32]);
        assert!(sess.push_in(1, b"b".to_vec()).is_empty());
        assert_eq!(sess.push_in(0, b"a".to_vec()), b"ab");
        assert!(sess.push_in(0, b"a".to_vec()).is_empty());
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
        let link = dial(format!("127.0.0.1:{port}").parse().unwrap(), &account(), true).unwrap();
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
        let mut ready = vec![
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
            let assoc = associate(format!("127.0.0.1:{port}").parse().unwrap(), &account(), false).unwrap();
            assoc.send_to("1.2.3.4", 53, b"dns").unwrap();
            assoc.send_to("example.com", 443, b"hi").unwrap();
            let (host, port, payload) = assoc.recv_from().unwrap();
            assert_eq!((host.as_str(), port, payload.as_slice()), ("1.2.3.4", 53, b"ok".as_slice()));
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
