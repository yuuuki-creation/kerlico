use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use kerlico_shared::{
    Accept, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError, PlaneFault,
    Settings, Transport, UserEmail,
};
use kerlico_ss2022::{
    address, block, config, context, key, map_io, method, relay, runtime, target, udp_wire_limit,
    Address, CipherKind, Replay, TcpFlow, FLOW_WAIT, OPEN_WAIT, UDP_IDLE,
};
use rand_core::{OsRng, RngCore};
use relay::udprelay::{crypto_io, options::UdpSocketControlData};
use tokio::io::AsyncReadExt;

mod identity;
mod request;

const MAX_SESSIONS: usize = 4096;
const MAX_DESTINATIONS: usize = 64;
const MAX_UDP_FLOWS: usize = 2048;
const MAX_UDP_QUEUED: usize = 16 * 1024 * 1024;

struct Account {
    email: UserEmail,
    key: Arc<[u8]>,
    id: u64,
    live: AtomicBool,
    target: Option<Address>,
}

/// Snapshots let TCP handshakes and UDP authentication share the same user table.
#[derive(Default)]
struct Users {
    by_email: HashMap<UserEmail, Arc<Account>>,
    by_key: HashMap<Arc<[u8]>, Arc<Account>>,
    by_hash: HashMap<identity::Identity, Arc<Account>>,
    eih: Option<Arc<config::ServerUserManager>>,
    next: u64,
}

impl Users {
    fn refresh_eih(&mut self, enabled: bool) {
        if enabled {
            let mut users = config::ServerUserManager::new();
            for user in self.by_email.values() {
                users.add_user(config::ServerUser::new(
                    user.email.as_str().to_owned(),
                    user.key.to_vec(),
                ));
            }
            self.eih = Some(Arc::new(users));
        }
    }

    fn lookup(&self, user_key: Option<&[u8]>, use_eih: bool) -> Option<Arc<Account>> {
        let account = if use_eih {
            self.by_key.get(user_key?)
        } else {
            self.by_email.values().next()
        }?;
        account
            .live
            .load(Ordering::Acquire)
            .then(|| account.clone())
    }
}

struct Node {
    protocol: Arc<Protocol>,
    flows: mpsc::Receiver<Handoff>,
    _stop: tokio::sync::watch::Sender<bool>,
}

struct Protocol {
    tag: NodeTag,
    kind: CipherKind,
    context: context::SharedContext,
    identity: Option<Arc<[u8]>>,
    relay: bool,
    users: RwLock<Users>,
    ready: mpsc::SyncSender<Handoff>,
}

impl Accept for Node {
    fn add_user(&mut self, email: &UserEmail, settings: &Settings) -> Result<(), OpenError> {
        if settings.keys().any(|name| {
            name != "password" && !(self.protocol.relay && matches!(name, "address" | "port"))
        }) {
            return Err(OpenError::Settings);
        }
        let key: Arc<[u8]> = key(self.protocol.kind, settings.text("password")?)?.into();
        let target = if self.protocol.relay {
            let port = settings
                .text("port")?
                .parse()
                .map_err(|_| OpenError::Settings)?;
            Some(address(settings.text("address")?, port).map_err(|_| OpenError::Settings)?)
        } else {
            None
        };
        let hash = identity::hash(&key);
        let mut users = self.protocol.users.write().expect("Shadowsocks users");
        let eih = self.protocol.identity.is_some();
        if users.by_email.contains_key(email)
            || users.by_key.contains_key(&key)
            || users.by_hash.contains_key(&hash)
            || (!eih && !users.by_email.is_empty())
            || self
                .protocol
                .identity
                .as_ref()
                .is_some_and(|value| *value == key)
        {
            return Err(OpenError::Settings);
        }
        let id = users.next.checked_add(1).ok_or(OpenError::Settings)?;
        users.next = id;
        let account = Arc::new(Account {
            email: email.clone(),
            key: key.clone(),
            id,
            live: AtomicBool::new(true),
            target,
        });
        users.by_email.insert(email.clone(), account.clone());
        users.by_key.insert(key, account.clone());
        users.by_hash.insert(hash, account);
        users.refresh_eih(eih && !self.protocol.relay);
        Ok(())
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let mut users = self.protocol.users.write().expect("Shadowsocks users");
        let account = users.by_email.remove(email).ok_or(OpenError::Settings)?;
        account.live.store(false, Ordering::Release);
        users.by_key.remove(&account.key);
        users.by_hash.remove(&identity::hash(&account.key));
        users.refresh_eih(self.protocol.identity.is_some() && !self.protocol.relay);
        Ok(())
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        self.flows.recv().map_err(|_| OpenError::Transport)
    }
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    if settings
        .keys()
        .any(|name| !matches!(name, "method" | "identityKey" | "mode" | "relay"))
    {
        return Err(OpenError::Settings);
    }
    let kind = method(settings.text("method")?)?;
    let identity = settings
        .optional_text("identityKey")?
        .map(|value| key(kind, value).map(Arc::from))
        .transpose()?;
    if identity.is_some() && !config::method_support_eih(kind) {
        return Err(OpenError::Settings);
    }
    let relay = match settings.optional_text("relay")? {
        None | Some("false") => false,
        Some("true") if identity.is_some() => true,
        _ => return Err(OpenError::Settings),
    };
    let (tcp, udp) = match settings.optional_text("mode")? {
        None | Some("tcp_and_udp") => (true, true),
        Some("tcp_only") => (true, false),
        Some("udp_only") => (false, true),
        _ => return Err(OpenError::Settings),
    };
    let rt = runtime().map_err(|_| OpenError::Transport)?;
    let _entered = rt.enter();
    let bind = bind.socket_addr();
    let tcp = tcp
        .then(|| {
            open_socket(bind, socket2::Type::STREAM, socket2::Protocol::TCP).and_then(|socket| {
                socket.listen(1024)?;
                tokio::net::TcpListener::from_std(socket.into())
            })
        })
        .transpose()
        .map_err(|_| OpenError::Transport)?;
    let udp = udp
        .then(|| {
            open_socket(bind, socket2::Type::DGRAM, socket2::Protocol::UDP)
                .and_then(|socket| tokio::net::UdpSocket::from_std(socket.into()))
        })
        .transpose()
        .map_err(|_| OpenError::Transport)?;
    let (ready, flows) = mpsc::sync_channel(256);
    let protocol = Arc::new(Protocol {
        tag: tag.clone(),
        kind,
        identity,
        relay,
        context: context::Context::new_shared(config::ServerType::Server),
        users: RwLock::default(),
        ready,
    });
    let (stop, stopped) = tokio::sync::watch::channel(false);
    if let Some(tcp) = tcp {
        rt.spawn(serve_tcp(tcp, protocol.clone(), stopped.clone()));
    }
    if let Some(udp) = udp {
        rt.spawn(serve_udp(Arc::new(udp), protocol.clone(), stopped));
    }
    Ok(Box::new(Node {
        protocol,
        flows,
        _stop: stop,
    }))
}

fn open_socket(
    addr: SocketAddr,
    kind: socket2::Type,
    protocol: socket2::Protocol,
) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(addr), kind, Some(protocol))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

fn reject(socket: &TcpStream) {
    // Consistent RST regardless of how much of a failed SIP022 header was read.
    let _ = socket2::SockRef::from(socket).set_linger(Some(Duration::ZERO));
}

async fn serve_tcp(
    listener: tokio::net::TcpListener,
    config: Arc<Protocol>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let pending = Arc::new(tokio::sync::Semaphore::new(256));
    loop {
        let (stream, peer) = tokio::select! {
            _ = stop.changed() => return,
            result = listener.accept() => match result { Ok(pair) => pair, Err(_) => { tokio::time::sleep(FLOW_WAIT).await; continue; } },
        };
        let Ok(permit) = pending.clone().try_acquire_owned() else {
            continue;
        };
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handshake(stream, peer, config).await;
        });
    }
}

async fn handshake(stream: tokio::net::TcpStream, peer: SocketAddr, config: Arc<Protocol>) {
    let Ok(socket) = stream.into_std() else {
        return;
    };
    let Ok(stream) = socket.try_clone().and_then(tokio::net::TcpStream::from_std) else {
        return;
    };
    let _ = stream.set_nodelay(true);
    if config.relay {
        let Some(identity) = config.identity.as_deref() else {
            return;
        };
        let mut stream = stream;
        let mut prefix = vec![0; 4096];
        let Ok(Ok(count)) = tokio::time::timeout(OPEN_WAIT, stream.read(&mut prefix)).await else {
            reject(&socket);
            return;
        };
        prefix.truncate(count);
        let Some(hash) = identity::tcp_identity(identity, &prefix) else {
            reject(&socket);
            return;
        };
        let account = config
            .users
            .read()
            .expect("Shadowsocks users")
            .by_hash
            .get(&hash)
            .cloned();
        let Some(account) = account.filter(|a| a.live.load(Ordering::Acquire)) else {
            reject(&socket);
            return;
        };
        let Some(addr) = &account.target else {
            reject(&socket);
            return;
        };
        let (host, port) = target(addr);
        let Ok(dest) = Destination::new(host, port, Transport::Tcp) else {
            reject(&socket);
            return;
        };
        let start = identity.len();
        prefix.drain(start..start + identity::BLOCK);
        let mut handoff = Handoff::new(
            config.tag.clone(),
            account.email.clone(),
            dest,
            Box::new(Tcp(TcpFlow::with_prefix(socket, stream, prefix))),
        );
        handoff.set_peer(peer);
        let _ = config.ready.try_send(handoff);
        return;
    }
    let eih = config.identity.is_some();
    let (credential, manager, single) = {
        let users = config.users.read().expect("Shadowsocks users");
        let single = users.lookup(None, false).filter(|_| !eih);
        let credential = config
            .identity
            .clone()
            .or_else(|| single.as_ref().map(|a| a.key.clone()));
        (credential, users.eih.clone(), single)
    };
    let Some(credential) = credential else {
        reject(&socket);
        return;
    };
    if eih && manager.is_none() {
        reject(&socket);
        return;
    }
    let Ok(Ok((stream, addr, first))) = tokio::time::timeout(
        OPEN_WAIT,
        request::Stream::handshake(
            stream,
            config.context.clone(),
            config.kind,
            &credential,
            manager,
        ),
    )
    .await
    else {
        reject(&socket);
        return;
    };
    let account = if eih {
        config
            .users
            .read()
            .expect("Shadowsocks users")
            .lookup(stream.user_key(), true)
    } else {
        single.filter(|value| value.live.load(Ordering::Acquire))
    };
    let (host, port) = target(&addr);
    let dest = address(&host, port)
        .ok()
        .and_then(|_| Destination::new(host, port, Transport::Tcp).ok());
    let (Some(account), Some(dest)) = (account, dest) else {
        reject(&socket);
        return;
    };
    let mut handoff = Handoff::new(
        config.tag.clone(),
        account.email.clone(),
        dest,
        Box::new(Tcp(TcpFlow::with_prefix(socket, stream, first))),
    );
    handoff.set_peer(peer);
    let _ = config.ready.try_send(handoff);
}

struct Tcp(TcpFlow);

impl InboundStream for Tcp {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.0.read(buf, FLOW_WAIT).map_err(map_io)
    }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.0.write(buf).map(|_| buf.len()).map_err(map_io)
    }
    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        self.0.finish().map(|_| true).map_err(map_io)
    }
}

struct Session {
    socket_group: Arc<kerlico_shared::DatagramSession>,
    replay: Replay,
    reply: Arc<Reply>,
    flows: HashMap<Address, Queue>,
}

struct UdpActivity {
    start: Instant,
    last_ns: AtomicU64,
}

impl UdpActivity {
    fn new(start: Instant) -> Self {
        Self {
            start,
            last_ns: AtomicU64::new(0),
        }
    }

    fn elapsed_ns(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.start).as_nanos()).unwrap_or(u64::MAX)
    }

    fn record(&self, now: Instant) {
        // Outbound workers and the input task may publish activity out of order.
        self.last_ns
            .fetch_max(self.elapsed_ns(now), Ordering::Release);
    }

    fn is_recent(&self, now: Instant) -> bool {
        let idle = self
            .elapsed_ns(now)
            .saturating_sub(self.last_ns.load(Ordering::Acquire));
        Duration::from_nanos(idle) < UDP_IDLE
    }
}

struct Queue {
    sender: mpsc::SyncSender<Datagram>,
    live: Arc<AtomicBool>,
}

struct Datagram {
    data: Vec<u8>,
    budget: Arc<AtomicUsize>,
}

impl Datagram {
    fn store(buf: &[u8], budget: &Arc<AtomicUsize>) -> Option<Self> {
        budget
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |size| {
                let size = size + buf.len();
                (size <= MAX_UDP_QUEUED).then_some(size)
            })
            .ok()?;
        Some(Self {
            data: buf.to_vec(),
            budget: budget.clone(),
        })
    }
}

impl Drop for Datagram {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.data.len(), Ordering::Relaxed);
    }
}

struct Reply {
    account: Arc<Account>,
    client_id: u64,
    server_id: u64,
    next: AtomicU64,
    endpoint: Mutex<SocketAddr>,
    activity: UdpActivity,
    active: AtomicBool,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.reply.active.store(false, Ordering::Release);
    }
}

async fn serve_udp(
    socket: Arc<tokio::net::UdpSocket>,
    config: Arc<Protocol>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut buffer = vec![0; 65_536];
    let mut sessions: HashMap<(u64, u64), Session> = HashMap::new();
    let mut idle = tokio::time::interval(Duration::from_secs(1));
    let budget = Arc::new(AtomicUsize::new(0));
    let flow_count = Arc::new(AtomicUsize::new(0));
    loop {
        let (n, peer) = tokio::select! {
            _ = stop.changed() => return,
            _ = idle.tick() => {
                let now = Instant::now();
                sessions.retain(|_, session| session.reply.account.live.load(Ordering::Acquire) && session.reply.activity.is_recent(now));
                for session in sessions.values_mut() { session.flows.retain(|_, flow| flow.live.load(Ordering::Acquire)); }
                continue;
            }
            result = socket.recv_from(&mut buffer) => match result { Ok(pair) => pair, Err(_) => continue },
        };
        let (body, addr, client_id, packet_id, account) = if config.relay {
            let Some(identity) = config.identity.as_deref() else {
                continue;
            };
            let Some((hash, mut separate)) = identity::udp_identity(identity, &buffer[..n]) else {
                continue;
            };
            let client_id = u64::from_be_bytes(separate[..8].try_into().expect("session id"));
            let packet_id = u64::from_be_bytes(separate[8..].try_into().expect("packet id"));
            let account = config
                .users
                .read()
                .expect("Shadowsocks users")
                .by_hash
                .get(&hash)
                .cloned();
            let Some(account) = account.filter(|a| a.live.load(Ordering::Acquire)) else {
                continue;
            };
            let Some(addr) = account.target.clone() else {
                continue;
            };
            if identity::encrypt_header(&account.key, &mut separate).is_none() {
                continue;
            }
            buffer[identity::BLOCK..2 * identity::BLOCK].copy_from_slice(&separate);
            (
                &buffer[identity::BLOCK..n],
                addr,
                client_id,
                packet_id,
                account,
            )
        } else {
            let users = config.users.read().expect("Shadowsocks users");
            let eih = config.identity.is_some();
            let primary = if eih {
                config.identity.as_deref()
            } else {
                users.by_email.values().next().map(|a| a.key.as_ref())
            };
            let Some(primary) = primary else {
                continue;
            };
            if eih && users.eih.is_none() {
                continue;
            }
            let Ok((len, addr, Some(control))) = crypto_io::decrypt_client_payload(
                &config.context,
                config.kind,
                primary,
                &mut buffer[..n],
                users.eih.as_deref(),
            ) else {
                continue;
            };
            let Some(account) = users.lookup(control.user.as_ref().map(|user| user.key()), eih)
            else {
                continue;
            };
            (
                &buffer[..len],
                addr,
                control.client_session_id,
                control.packet_id,
                account,
            )
        };
        let (host, port) = target(&addr);
        if address(&host, port).is_err() {
            continue;
        }
        let session_key = (account.id, client_id);
        if sessions.len() >= MAX_SESSIONS && !sessions.contains_key(&session_key) {
            continue;
        }
        let now = Instant::now();
        let session = sessions.entry(session_key).or_insert_with(|| {
            let mut server_id = OsRng.next_u64();
            while server_id == client_id {
                server_id = OsRng.next_u64();
            }
            Session {
                socket_group: Arc::new(kerlico_shared::DatagramSession::new(!config.relay)),
                replay: Replay::default(),
                flows: HashMap::new(),
                reply: Arc::new(Reply {
                    account,
                    client_id,
                    server_id,
                    next: AtomicU64::new(0),
                    endpoint: Mutex::new(peer),
                    activity: UdpActivity::new(now),
                    active: AtomicBool::new(true),
                }),
            }
        });
        if !session.replay.accept(packet_id) {
            continue;
        }
        session.reply.activity.record(now);
        *session
            .reply
            .endpoint
            .lock()
            .expect("Shadowsocks UDP endpoint") = peer;
        let Some(data) = Datagram::store(body, &budget) else {
            continue;
        };
        let data = if let Some(flow) = session.flows.get(&addr) {
            match flow.sender.try_send(data) {
                Err(mpsc::TrySendError::Disconnected(data)) => {
                    session.flows.remove(&addr);
                    data
                }
                _ => continue,
            }
        } else {
            data
        };
        if session.flows.len() >= MAX_DESTINATIONS
            || flow_count.load(Ordering::Relaxed) >= MAX_UDP_FLOWS
        {
            continue;
        }
        let Ok(destination) = Destination::new(host, port, Transport::Udp) else {
            continue;
        };
        let (tx, rx) = mpsc::sync_channel(16);
        if tx.try_send(data).is_err() {
            continue;
        }
        let live = Arc::new(AtomicBool::new(true));
        flow_count.fetch_add(1, Ordering::Relaxed);
        let udp = Udp {
            socket: socket.clone(),
            context: config.context.clone(),
            kind: config.kind,
            relay: config.relay,
            address: addr.clone(),
            inbound: Mutex::new(rx),
            reply: session.reply.clone(),
            live: live.clone(),
            flow_count: flow_count.clone(),
        };
        let mut handoff = Handoff::new(
            config.tag.clone(),
            session.reply.account.email.clone(),
            destination,
            Box::new(udp),
        );
        handoff.set_peer(peer);
        handoff.set_datagram_session(session.socket_group.clone());
        if config.ready.try_send(handoff).is_ok() {
            session.flows.insert(addr, Queue { sender: tx, live });
        }
    }
}

struct Udp {
    socket: Arc<tokio::net::UdpSocket>,
    context: context::SharedContext,
    kind: CipherKind,
    relay: bool,
    address: Address,
    inbound: Mutex<mpsc::Receiver<Datagram>>,
    reply: Arc<Reply>,
    live: Arc<AtomicBool>,
    flow_count: Arc<AtomicUsize>,
}

impl Drop for Udp {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Release);
        self.flow_count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Udp {
    fn check(&self) -> Result<(), PlaneFault> {
        if self.reply.active.load(Ordering::Acquire)
            && self.reply.account.live.load(Ordering::Acquire)
        {
            Ok(())
        } else {
            Err(PlaneFault::Closed)
        }
    }
}

impl InboundStream for Udp {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.check()?;
        let data = self
            .inbound
            .lock()
            .expect("Shadowsocks UDP receive")
            .recv_timeout(FLOW_WAIT)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => PlaneFault::Again,
                mpsc::RecvTimeoutError::Disconnected => PlaneFault::Closed,
            })?;
        buf.get_mut(..data.data.len())
            .ok_or(PlaneFault::Transport)?
            .copy_from_slice(&data.data);
        Ok(data.data.len())
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.reply(buf, &self.address)
    }

    fn write_datagram_to_user(&self, buf: &[u8], source: SocketAddr) -> Result<usize, PlaneFault> {
        self.reply(buf, &Address::SocketAddress(source))
    }
}

impl Udp {
    fn reply(&self, buf: &[u8], address: &Address) -> Result<usize, PlaneFault> {
        self.check()?;
        let peer = *self
            .reply
            .endpoint
            .lock()
            .expect("Shadowsocks UDP endpoint");
        let limit = udp_wire_limit(peer);
        if buf.len() > limit {
            return Ok(buf.len());
        }
        if self.relay {
            return self.send_reply(buf, peer).map(|_| buf.len());
        }
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.reply.client_id;
        control.server_session_id = self.reply.server_id;
        control.packet_id = self
            .reply
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| PlaneFault::Closed)?;
        let mut sealed = BytesMut::new();
        crypto_io::encrypt_server_payload(
            &self.context,
            self.kind,
            &self.reply.account.key,
            address,
            &control,
            buf,
            &mut sealed,
        );
        if sealed.len() > limit {
            return Ok(buf.len());
        }
        self.send_reply(&sealed, peer).map(|_| buf.len())
    }

    fn send_reply(&self, wire: &[u8], peer: SocketAddr) -> Result<(), PlaneFault> {
        // A valid reply from the egress is activity even when the client sends no more packets.
        self.reply.activity.record(Instant::now());
        block(FLOW_WAIT, self.socket.send_to(wire, peer))
            .map(|_| ())
            .map_err(map_io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bidirectional_activity_controls_session_expiry() {
        let start = Instant::now();
        let activity = UdpActivity::new(start);
        let tick = Duration::from_millis(1);
        assert!(activity.is_recent(start + UDP_IDLE - tick));
        assert!(!activity.is_recent(start + UDP_IDLE));

        let reply = start + UDP_IDLE - tick;
        activity.record(reply);
        activity.record(start + tick); // A delayed update cannot shorten the session.
        assert!(activity.is_recent(start + UDP_IDLE));
        assert!(activity.is_recent(reply + UDP_IDLE - tick));
        assert!(!activity.is_recent(reply + UDP_IDLE));
    }
}
