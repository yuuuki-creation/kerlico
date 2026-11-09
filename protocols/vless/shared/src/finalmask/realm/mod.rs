mod http;
mod packets;
mod portmap;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, MissedTickBehavior};

use crate::TlsNetwork;

use super::http_tls::runtime;
use super::{invalid, retryable, settings, PacketIo, UDP_POLL, UDP_SIZE};
use http::{session_invalid, Control, Event};
use packets::{
    candidates, stun_request, stun_response, stun_servers, Message, Punch, Transaction, PUNCH_MAX,
};
use portmap::{Mapping, PortMap};

const STUN_TIMEOUT: Duration = Duration::from_secs(4);
const STUN_CACHE: Duration = Duration::from_secs(10);
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const EVENT_LIMIT: usize = 16;

#[derive(Clone)]
pub(super) struct Realm {
    control: Control,
    stun: Arc<[String]>,
    ipv4: Option<bool>,
    mapping: PortMap,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    url: String,
    stun_servers: Vec<String>,
    ip_mode: String,
    tls_config: Value,
    port_mapping: PortMap,
}

impl Realm {
    pub(super) fn set_network(&mut self, network: Arc<crate::runtime::CarrierNetwork>) { self.control.set_network(network); }
    pub(super) fn parse(
        value: Value,
        tls_network: Option<Arc<dyn TlsNetwork>>,
        tls_cache: Option<Arc<crate::AdvancedTlsClientCache>>,
    ) -> io::Result<Self> {
        let config: Config = settings(value)?;
        let ipv4 = match config.ip_mode.to_ascii_lowercase().as_str() {
            "" | "dual" => None,
            "v4" => Some(true),
            "v6" => Some(false),
            _ => return Err(invalid("invalid Realm ipMode")),
        };
        if config.stun_servers.is_empty() || config.stun_servers.len() > 64 {
            return Err(invalid("Realm needs one to 64 STUN servers"));
        }
        for server in &config.stun_servers {
            let addr: ::http::uri::Authority = server.parse().map_err(invalid)?;
            if addr.port_u16().is_none_or(|port| port == 0) {
                return Err(invalid("Realm STUN server requires a port"));
            }
        }
        let control = Control::parse(&config.url, config.tls_config, tls_network, tls_cache)?;
        Ok(Self {
            control,
            stun: config.stun_servers.into(),
            ipv4,
            mapping: config.port_mapping,
        })
    }

    pub(super) fn wrap(
        &self,
        inner: Arc<dyn PacketIo>,
        peer: Option<SocketAddr>,
    ) -> io::Result<Arc<dyn PacketIo>> {
        let local = inner.local_addr()?;
        if self.ipv4.is_some_and(|ipv4| ipv4 != local.is_ipv4()) {
            return Err(invalid("Realm ipMode disagrees with UDP socket family"));
        }
        let rt = runtime()?;
        let mapping = rt.block_on(self.mapping.open(local));
        if let Some(peer) = peer {
            return self.client(inner, local, peer, mapping);
        }
        let state = Arc::new(ServerState {
            inner,
            config: self.clone(),
            local,
            mapping,
            locals: tokio::sync::Mutex::new(Cached::default()),
            stun: Mutex::new(HashMap::new()),
            punches: Mutex::new(HashMap::new()),
        });
        let (live, closed) = watch::channel(());
        rt.spawn(state.clone().run(closed));
        Ok(Arc::new(Server { state, _live: live }))
    }

    fn client(
        &self,
        inner: Arc<dyn PacketIo>,
        local: SocketAddr,
        logical: SocketAddr,
        mapping: Option<Mapping>,
    ) -> io::Result<Arc<dyn PacketIo>> {
        let servers = stun_servers(&self.stun, local.is_ipv4(), self.control.network());
        let mut locals = discover_client(&*inner, &servers)?;
        add_mapping(&mut locals, mapping.as_ref());
        if locals.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Realm STUN discovered no addresses",
            ));
        }
        let punch = Punch::random()?;
        let meta = punch.metadata();
        let peers = runtime()?.block_on(self.control.connect(strings(&locals), &meta))?;
        let peers = candidates(&locals, &peers);
        if peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Realm peer has no compatible addresses",
            ));
        }
        let physical = punch_client(&*inner, punch, &peers)?;
        Ok(Arc::new(Client {
            inner,
            logical,
            physical,
            punch,
            _mapping: mapping,
        }))
    }
}

fn strings(addresses: &[SocketAddr]) -> Vec<String> {
    addresses.iter().map(SocketAddr::to_string).collect()
}

fn add_mapping(addresses: &mut Vec<SocketAddr>, mapping: Option<&Mapping>) {
    if let Some(mapping) = mapping {
        addresses.push(mapping.address());
    }
    addresses.sort_unstable_by_key(SocketAddr::to_string);
    addresses.dedup();
}

fn discover_client(inner: &dyn PacketIo, servers: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
    let mut waiting = HashSet::new();
    for &server in servers {
        let (tx, request) = stun_request()?;
        if inner.send_to(&request, server).is_ok() {
            waiting.insert(tx);
        }
    }
    let deadline = Instant::now() + STUN_TIMEOUT;
    let mut addresses = Vec::new();
    let mut wire = [0; UDP_SIZE];
    while !waiting.is_empty() && Instant::now() < deadline {
        match inner.recv_from(&mut wire) {
            Ok((len, _)) => {
                if let Some((tx, address)) = stun_response(&wire[..len]) {
                    if waiting.remove(&tx) {
                        addresses.push(address);
                    }
                }
            }
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(addresses)
}

fn send_punch(
    inner: &dyn PacketIo,
    punch: Punch,
    message: Message,
    peers: &[SocketAddr],
) -> io::Result<()> {
    for &peer in peers {
        let packet = punch.encode(message)?;
        let _ = inner.send_to(&packet, peer);
    }
    Ok(())
}

fn punch_client(
    inner: &dyn PacketIo,
    punch: Punch,
    peers: &[SocketAddr],
) -> io::Result<SocketAddr> {
    let mut next = Instant::now();
    let deadline = next + PUNCH_TIMEOUT;
    let mut wire = [0; PUNCH_MAX + 1];
    while Instant::now() < deadline {
        if Instant::now() >= next {
            send_punch(inner, punch, Message::Hello, peers)?;
            next = Instant::now() + PUNCH_INTERVAL;
        }
        let (len, peer) = match inner.recv_from(&mut wire) {
            Ok(packet) => packet,
            Err(error) if retryable(&error) => continue,
            Err(error) => return Err(error),
        };
        if let Some(message) = punch.decode(&wire[..len]) {
            if message == Message::Hello {
                send_punch(inner, punch, Message::Ack, &[peer])?;
            }
            return Ok(peer);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Realm UDP hole punch timed out",
    ))
}

struct Client {
    inner: Arc<dyn PacketIo>,
    logical: SocketAddr,
    physical: SocketAddr,
    punch: Punch,
    _mapping: Option<Mapping>,
}

impl PacketIo for Client {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let deadline = Instant::now() + UDP_POLL;
        while Instant::now() < deadline {
            let (len, source) = self.inner.recv_from(out)?;
            if source != self.physical {
                continue;
            }
            if let Some(message) = self.punch.decode(&out[..len]) {
                if message == Message::Hello {
                    send_punch(&*self.inner, self.punch, Message::Ack, &[source])?;
                }
                continue;
            }
            return Ok((len, self.logical));
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], _: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(packet, self.physical)
    }
}

#[derive(Default)]
struct Cached {
    addresses: Vec<SocketAddr>,
    resolved: Option<Instant>,
}

struct Server {
    state: Arc<ServerState>,
    _live: watch::Sender<()>,
}

struct ServerState {
    inner: Arc<dyn PacketIo>,
    config: Realm,
    local: SocketAddr,
    mapping: Option<Mapping>,
    locals: tokio::sync::Mutex<Cached>,
    stun: Mutex<HashMap<Transaction, mpsc::Sender<SocketAddr>>>,
    punches: Mutex<HashMap<Punch, mpsc::Sender<(SocketAddr, Message)>>>,
}

impl PacketIo for Server {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let deadline = Instant::now() + UDP_POLL;
        while Instant::now() < deadline {
            let (len, peer) = self.state.inner.recv_from(out)?;
            if !self.state.accept_control(&out[..len], peer) {
                return Ok((len, peer));
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.state.inner.send_to(packet, peer)
    }
}

impl ServerState {
    fn accept_control(&self, packet: &[u8], peer: SocketAddr) -> bool {
        if let Some((tx, addr)) = stun_response(packet) {
            if let Some(sender) = self
                .stun
                .lock()
                .expect("Realm STUN transactions")
                .remove(&tx)
            {
                let _ = sender.try_send(addr);
            }
            return true;
        }
        let punches = self.punches.lock().expect("Realm punch events");
        for (punch, sender) in punches.iter() {
            if let Some(message) = punch.decode(packet) {
                let _ = sender.try_send((peer, message));
                return true;
            }
        }
        false
    }

    async fn locals(self: &Arc<Self>) -> Vec<SocketAddr> {
        let mut cached = self.locals.lock().await;
        if cached
            .resolved
            .is_none_or(|resolved| resolved.elapsed() >= STUN_CACHE)
        {
            let discovered = self.discover().await;
            if !discovered.is_empty() {
                cached.addresses = discovered;
                cached.resolved = Some(Instant::now());
            }
        }
        cached.addresses.clone()
    }

    async fn discover(self: &Arc<Self>) -> Vec<SocketAddr> {
        let stun = self.config.stun.clone();
        let network = self.config.control.network().cloned();
        let v4 = self.local.is_ipv4();
        let servers = tokio::task::spawn_blocking(move || stun_servers(&stun, v4, network.as_ref()))
            .await
            .unwrap_or_default();
        let (tx, mut answers) = mpsc::channel(servers.len().max(1));
        let mut waiting = StunWait {
            state: self.clone(),
            ids: Vec::new(),
        };
        let inner = self.inner.clone();
        let mut probes = Vec::with_capacity(servers.len());
        for server in servers {
            if let Ok((id, request)) = stun_request() {
                self.stun
                    .lock()
                    .expect("Realm STUN transactions")
                    .insert(id, tx.clone());
                waiting.ids.push(id);
                probes.push((request, server));
            }
        }
        drop(tx);
        tokio::task::spawn_blocking(move || {
            for (packet, peer) in probes {
                let _ = inner.send_to(&packet, peer);
            }
        });
        let mut addresses = Vec::new();
        let _ = timeout(STUN_TIMEOUT, async {
            while let Some(address) = answers.recv().await {
                addresses.push(address);
            }
        })
        .await;
        add_mapping(&mut addresses, self.mapping.as_ref());
        addresses
    }

    async fn run(self: Arc<Self>, mut closed: watch::Receiver<()>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let session = tokio::select! {
                _ = closed.changed() => return,
                session = async {
                    let locals = self.locals().await;
                    if locals.is_empty() {
                        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Realm STUN discovered no local addresses"));
                    }
                    let registered = self.config.control.register(strings(&locals)).await?;
                    Ok((registered, locals))
                } => session,
            };
            match session {
                Ok((session, locals)) => {
                    backoff = Duration::from_secs(1);
                    let close = tokio::select! {
                        _ = closed.changed() => true,
                        _ = self.heartbeat(&session.session_id, session.ttl, locals) => false,
                        _ = self.events(&session.session_id, session.ttl) => false,
                    };
                    if close {
                        let _ = self.config.control.deregister(&session.session_id).await;
                        return;
                    }
                }
                Err(error) => eprintln!("Realm registration: {error}"),
            }
            tokio::select! {
                _ = closed.changed() => return,
                _ = sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    async fn heartbeat(self: &Arc<Self>, sid: &str, ttl: u64, mut announced: Vec<SocketAddr>) {
        let mut ttl = lease(ttl);
        let mut last = Instant::now();
        loop {
            sleep(ttl / 2).await;
            let locals = self.locals().await;
            let updated = if locals == announced {
                Vec::new()
            } else {
                strings(&locals)
            };
            match self.config.control.heartbeat(sid, updated).await {
                Ok(reply) => {
                    if reply.ttl != 0 {
                        ttl = lease(reply.ttl);
                    }
                    announced = locals;
                    last = Instant::now();
                }
                Err(error) if session_invalid(&error) || last.elapsed() >= ttl => return,
                Err(_) => {}
            }
        }
    }

    async fn events(self: &Arc<Self>, sid: &str, ttl: u64) {
        let mut backoff = Duration::from_secs(1);
        let mut last = Instant::now();
        let mut punches = JoinSet::new();
        loop {
            match self.config.control.events(sid).await {
                Ok(mut stream) => {
                    last = Instant::now();
                    backoff = Duration::from_secs(1);
                    while let Ok(event) = stream.next().await {
                        while punches.try_join_next().is_some() {}
                        if punches.len() < EVENT_LIMIT {
                            let state = self.clone();
                            let sid = sid.to_owned();
                            punches.spawn(async move { state.punch(&sid, event).await });
                        }
                    }
                }
                Err(error) if session_invalid(&error) || last.elapsed() >= lease(ttl) => return,
                Err(_) => {}
            }
            sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    async fn punch(self: Arc<Self>, sid: &str, event: Event) -> io::Result<()> {
        let locals = self.locals().await;
        let peers = candidates(&locals, &event.addresses);
        if peers.is_empty() {
            return Ok(());
        }
        let nonce = event.meta.nonce.clone();
        let punch = Punch::from_metadata(event.meta)?;
        let (tx, mut replies) = mpsc::channel(EVENT_LIMIT);
        {
            let mut events = self.punches.lock().expect("Realm punch events");
            if events.contains_key(&punch) {
                return Ok(());
            }
            events.insert(punch, tx);
        }
        let _pending = PunchWait {
            state: self.clone(),
            punch,
        };
        let _ = self
            .config
            .control
            .acknowledge(sid, &nonce, strings(&locals))
            .await;
        let inner = self.inner.clone();
        let peers: Arc<[SocketAddr]> = peers.into();
        let mut ticker = tokio::time::interval(PUNCH_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let _ = timeout(PUNCH_TIMEOUT, async {
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let inner = inner.clone();
                        let peers = peers.clone();
                        let _ = tokio::task::spawn_blocking(move || send_punch(&*inner, punch, Message::Hello, &peers)).await;
                    }
                    reply = replies.recv() => {
                        if let Some((peer, Message::Hello)) = reply {
                            let inner = inner.clone();
                            let _ = tokio::task::spawn_blocking(move || send_punch(&*inner, punch, Message::Ack, &[peer])).await;
                        }
                        break;
                    }
                }
            }
        }).await;
        Ok(())
    }
}

fn lease(ttl: u64) -> Duration {
    Duration::from_secs(if ttl == 0 {
        30
    } else {
        ttl.min(7 * 24 * 60 * 60)
    })
}

struct StunWait {
    state: Arc<ServerState>,
    ids: Vec<Transaction>,
}

impl Drop for StunWait {
    fn drop(&mut self) {
        let mut pending = self.state.stun.lock().expect("Realm STUN transactions");
        for id in &self.ids {
            pending.remove(id);
        }
    }
}

struct PunchWait {
    state: Arc<ServerState>,
    punch: Punch,
}

impl Drop for PunchWait {
    fn drop(&mut self) {
        self.state
            .punches
            .lock()
            .expect("Realm punch events")
            .remove(&self.punch);
    }
}
