//! 原 UDP 兼容线格式的有限选择重传；本模块只接收已强制回环的 socket/端点。
use crate::{
    codec::{self, Frame},
    crypto::{Key, Replay, Users},
    entropy,
    session::{Command, Entry, Life, Link, Receipt, Scope, TcpSettings},
};
use bytes::Bytes;
use kerlico_core::{Error, Result};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
const WINDOW: usize = 128;
// 通告值保留内核 skb 与共享载体的余量，不能把协议缓存槽全当作瞬时 socket 容量。
const ADVERTISED_WINDOW: usize = 32;
const SEND_LIMIT: usize = 512;
type Route = (SocketAddr, [u8; 32], u32);
pub(crate) struct Settings {
    pub common: TcpSettings,
    pub mtu: usize,
    pub key: Option<Arc<Key>>,
    pub peer: Option<SocketAddr>,
    pub users: Option<Arc<Users>>,
    pub replay: Option<Arc<Replay>>,
}
pub(crate) fn start(
    socket: Arc<UdpSocket>,
    scope: Arc<Scope>,
    settings: Settings,
) -> Result<Arc<Link>> {
    let local = socket.local_addr()?;
    if !local.ip().is_loopback()
        || local.ip().to_canonical() != local.ip()
        || settings
            .peer
            .is_some_and(|peer| !peer.ip().is_loopback() || peer.ip().to_canonical() != peer.ip())
    {
        return Err(Error::Config("Mieru 不安全 UDP 仅允许回环载体".into()));
    }
    // 仅设置本项目持有的 socket；系统上限可能截断请求，不修改全局 sysctl。
    socket2::SockRef::from(socket.as_ref()).set_recv_buffer_size(2 * 1024 * 1024)?;
    let client = settings.peer.is_some();
    let common = settings.common;
    let (link, commands) = Link::new(
        scope,
        client,
        common.traffic,
        common.idle,
        common.connect_timeout,
        common.multiplexing,
        common.server,
    );
    let (incoming, receive) = mpsc::channel(128);
    let reading = socket.clone();
    let source = link.clone();
    link.scope.spawn(async move {
        let mut buffer = vec![0; 65536];
        loop {
            match reading.recv_from(&mut buffer).await {
                Ok((n, peer)) if (72..=1500).contains(&n) => {
                    if incoming
                        .send((peer, Bytes::copy_from_slice(&buffer[..n])))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        source.scope.cancel.cancel();
    });
    let actor = Actor {
        link: link.clone(),
        socket,
        users: settings.users,
        replay: settings.replay,
        client_key: settings.key,
        server_peer: settings.peer,
        mtu: settings.mtu,
        entries: HashMap::new(),
        routes: HashMap::new(),
        retired: HashMap::new(),
        next_server: 1,
        output: VecDeque::new(),
        last_wire: Instant::now(),
        ever_used: false,
        stop_when_empty: false,
    };
    link.scope.spawn(actor.run(commands, receive));
    Ok(link)
}
struct Pending {
    frame: Frame,
    receipt: Arc<Receipt>,
    transmissions: u8,
    sent_at: Instant,
    rto: Duration,
    duplicate_acks: u8,
}
impl Pending {
    fn retry(&mut self, now: Instant, base_rto: Duration) -> Result<bool> {
        if self.transmissions >= 20 {
            self.receipt.fail();
            return Err(Error::Timeout);
        }
        let timeout = now.duration_since(self.sent_at) >= self.rto;
        self.transmissions += 1;
        self.sent_at = now;
        self.duplicate_acks = 0;
        self.rto = base_rto
            .mul_f64(1.5f64.powi(i32::from(self.transmissions) - 1))
            .min(Duration::from_secs(5));
        Ok(timeout)
    }
}
struct Arq {
    unsent: VecDeque<Pending>,
    sent: BTreeMap<u32, Pending>,
    received: BTreeMap<u32, Frame>,
    highest_sent: u32,
    remote_window: usize,
    cwnd: f64,
    threshold: f64,
    srtt: Option<f64>,
    variance: f64,
    ack_due: Option<Instant>,
    last_tx: Instant,
    last_ack: u32,
}
impl Arq {
    fn new() -> Self {
        Self {
            unsent: VecDeque::new(),
            sent: BTreeMap::new(),
            received: BTreeMap::new(),
            highest_sent: 0,
            remote_window: WINDOW,
            cwnd: 4.0,
            threshold: 32.0,
            srtt: None,
            variance: 0.0,
            ack_due: None,
            last_tx: Instant::now(),
            last_ack: 0,
        }
    }
    fn rto(&self) -> Duration {
        Duration::from_secs_f64(
            self.srtt
                .map(|srtt| srtt + 4.0 * self.variance + 0.001)
                .unwrap_or(0.2)
                .clamp(0.1, 3.0),
        )
    }
    fn queue(&mut self, frame: Frame, receipt: Arc<Receipt>) -> Result<()> {
        if self.unsent.len() + self.sent.len() >= SEND_LIMIT {
            receipt.fail();
            return Err(Error::ResourceLimit);
        }
        self.unsent.push_back(Pending {
            frame,
            receipt,
            transmissions: 0,
            sent_at: Instant::now(),
            rto: self.rto(),
            duplicate_acks: 0,
        });
        Ok(())
    }
    fn acknowledge(&mut self, next: u32, window: u16, now: Instant) -> Result<()> {
        if next > self.highest_sent {
            return Err(codec::bad());
        }
        if next < self.last_ack {
            return Ok(());
        }
        self.remote_window = usize::from(window).min(WINDOW);
        if next == self.last_ack
            && let Some(pending) = self.sent.get_mut(&next)
        {
            pending.duplicate_acks = pending.duplicate_acks.saturating_add(1);
        }
        self.last_ack = next;
        let acknowledged = self
            .sent
            .range(..next)
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>();
        for seq in acknowledged {
            if let Some(pending) = self.sent.remove(&seq) {
                if pending.transmissions == 1 {
                    let sample = now
                        .duration_since(pending.sent_at)
                        .as_secs_f64()
                        .max(0.000001);
                    if let Some(srtt) = self.srtt {
                        self.variance = 0.75 * self.variance + 0.25 * (srtt - sample).abs();
                        self.srtt = Some(0.875 * srtt + 0.125 * sample);
                    } else {
                        self.srtt = Some(sample);
                        self.variance = sample / 2.0;
                    }
                }
                self.cwnd = (self.cwnd
                    + if self.cwnd < self.threshold {
                        1.0
                    } else {
                        1.0 / self.cwnd
                    })
                .min(WINDOW as f64);
            }
        }
        Ok(())
    }
    fn loss(&mut self, timeout: bool) {
        self.threshold = (self.cwnd * if timeout { 0.5 } else { 0.7 }).max(2.0);
        self.cwnd = self.threshold;
    }
}
struct PacketEntry {
    io: Entry,
    key: Arc<Key>,
    peer: SocketAddr,
    arq: Arq,
    close_pending: Option<Option<oneshot::Sender<Result<()>>>>,
}
impl PacketEntry {
    fn route(&self) -> Route {
        (self.peer, self.key.user.fingerprint(), self.io.life.wire_id)
    }
    fn window(&self) -> u16 {
        let free = crate::session::RECEIVE_BYTES
            .saturating_sub(self.io.life.received_bytes.load(Ordering::Acquire));
        ADVERTISED_WINDOW
            .min(WINDOW.saturating_sub(self.arq.received.len()))
            .min(free / 1500) as u16
    }
}
struct Tombstone {
    since: Instant,
    key: Arc<Key>,
    reply_seq: u32,
}
struct Out {
    peer: SocketAddr,
    bytes: Vec<u8>,
    id: u32,
    seq: u32,
    kind: u8,
    life: Option<Arc<Life>>,
    receipt: Option<Arc<Receipt>>,
    first: bool,
}
struct Actor {
    link: Arc<Link>,
    socket: Arc<UdpSocket>,
    users: Option<Arc<Users>>,
    replay: Option<Arc<Replay>>,
    client_key: Option<Arc<Key>>,
    server_peer: Option<SocketAddr>,
    mtu: usize,
    entries: HashMap<u32, PacketEntry>,
    routes: HashMap<Route, u32>,
    retired: HashMap<Route, Tombstone>,
    next_server: u32,
    output: VecDeque<Out>,
    last_wire: Instant,
    ever_used: bool,
    stop_when_empty: bool,
}
impl Actor {
    fn emit(
        &mut self,
        entry: &mut PacketEntry,
        frame: &Frame,
        receipt: Option<Arc<Receipt>>,
        first: bool,
    ) -> Result<()> {
        if self.output.len() >= 512 {
            if let Some(receipt) = receipt {
                receipt.fail();
            }
            return Err(Error::ResourceLimit);
        }
        let mut frame = frame.clone();
        if !frame.session() {
            frame.ack = entry.io.receive_next;
            frame.window = entry.window();
        }
        let bytes =
            codec::seal_local_unsafe_packet(&entry.key, &frame, &self.link.traffic, self.mtu)?;
        self.output.push_back(Out {
            peer: entry.peer,
            bytes,
            id: entry.io.life.id,
            seq: frame.seq,
            kind: frame.kind,
            life: Some(entry.io.life.clone()),
            receipt,
            first,
        });
        entry.arq.last_tx = Instant::now();
        Ok(())
    }
    fn flush_output(&mut self) -> Result<()> {
        for _ in 0..32 {
            let Some(out) = self.output.pop_front() else {
                break;
            };
            if out.life.as_ref().is_some_and(|life| {
                life.abort_cancel.is_cancelled() || life.closed.load(Ordering::Acquire)
            }) && matches!(out.kind, 2 | 6 | 7 | 10 | 11)
            {
                if let Some(receipt) = out.receipt {
                    receipt.fail();
                }
                continue;
            }
            match self.socket.try_send_to(&out.bytes, out.peer) {
                Ok(n) if n == out.bytes.len() => {
                    if out.kind == 2
                        && let Some(life) = &out.life
                    {
                        life.started.send_replace(true);
                        life.wake();
                    }
                    if out.first
                        && let Some(entry) = self.entries.get_mut(&out.id)
                    {
                        entry.arq.highest_sent =
                            entry.arq.highest_sent.max(out.seq.saturating_add(1));
                    }
                    if let Some(receipt) = out.receipt {
                        receipt.sent();
                    }
                    self.last_wire = Instant::now();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.output.push_front(out);
                    break;
                }
                _ => {
                    if let Some(receipt) = out.receipt {
                        receipt.fail();
                    }
                    if let Some(life) = out.life {
                        life.abort(2);
                    }
                }
            }
        }
        Ok(())
    }
    fn queue_data(
        &mut self,
        entry: &mut PacketEntry,
        body: Bytes,
        done: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        if body.is_empty() {
            if let Some(done) = done {
                let _ = done.send(Ok(()));
            }
            return Ok(());
        }
        let traffic = entry.io.traffic();
        let maximum = entropy::max_fragment(traffic.low_entropy_mode, Some(self.mtu))?;
        let fragments = body.len().div_ceil(maximum);
        if fragments > 256 {
            return Err(codec::bad());
        }
        let receipt = Receipt::new(fragments, done);
        for (index, chunk) in body.chunks(maximum).enumerate() {
            let mut frame = Frame::data(
                entry.io.life.wire_id,
                entry.io.next()?,
                Bytes::copy_from_slice(chunk),
                self.link.client,
                &traffic,
            );
            frame.fragment = (fragments - 1 - index) as u8;
            entry.arq.queue(frame, receipt.clone())?;
        }
        entry.io.last_data = Instant::now();
        Ok(())
    }
    fn start_entry(
        &mut self,
        entry: &mut PacketEntry,
        body: Bytes,
        done: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        let mut combined = Vec::with_capacity(entry.io.request.len() + body.len());
        combined.extend(&entry.io.request);
        combined.extend(&body);
        entry.io.request = Bytes::new();
        let combined: Bytes = combined.into();
        let traffic = entry.io.traffic();
        let piggyback = traffic.low_entropy_mode == 0
            && combined.len() <= 1024.min(self.mtu.saturating_sub(88));
        let frame = Frame::control(
            2,
            entry.io.life.wire_id,
            entry.io.next()?,
            if piggyback {
                combined.clone()
            } else {
                Bytes::new()
            },
        );
        if piggyback {
            entry.arq.queue(frame, Receipt::new(1, done))?;
        } else {
            entry.arq.queue(frame, Receipt::new(1, None))?;
            self.queue_data(entry, combined, done)?;
        }
        entry.io.started = true;
        Ok(())
    }
    fn retire(&mut self, mut entry: PacketEntry, abort: bool) {
        let route = entry.route();
        self.routes.remove(&route);
        self.retired.insert(
            route,
            Tombstone {
                since: Instant::now(),
                key: entry.key.clone(),
                reply_seq: entry.io.send_next,
            },
        );
        if let Some(Some(done)) = entry.close_pending.take() {
            let _ = done.send(Err(Error::Rejected));
        }
        if abort {
            entry.io.life.abort(2);
        }
        for pending in entry.arq.unsent {
            pending.receipt.fail();
        }
        for (_, pending) in entry.arq.sent {
            pending.receipt.fail();
        }
    }
    fn ack_later(entry: &mut PacketEntry) {
        entry
            .arq
            .ack_due
            .get_or_insert_with(|| Instant::now() + Duration::from_millis(1));
    }
    fn receive_ready(entry: &mut PacketEntry) -> Result<()> {
        loop {
            let next = entry.io.receive_next;
            let Some(frame) = entry.arq.received.get(&next) else {
                break;
            };
            if entry.io.life.received_bytes.load(Ordering::Acquire) + frame.body.len()
                > crate::session::RECEIVE_BYTES
            {
                break;
            }
            let frame = entry.arq.received.remove(&next).expect("已找到有序帧");
            if frame.mode != 0 {
                entry.io.life.peer_low.store(true, Ordering::Release);
            }
            entry.io.deliver(frame.body)?;
            entry.io.receive_next = entry
                .io
                .receive_next
                .checked_add(1)
                .ok_or(Error::ResourceLimit)?;
        }
        Self::ack_later(entry);
        Ok(())
    }
    fn process_frame(&mut self, entry: &mut PacketEntry, frame: Frame) -> Result<()> {
        match frame.kind {
            2 if !self.link.client => {
                let response = Frame::control(3, entry.io.life.wire_id, 0, Bytes::new());
                self.emit(entry, &response, None, false)?;
            }
            3 if self.link.client => {
                if frame.status != 0 {
                    return Err(Error::Rejected);
                }
                if !entry.io.established {
                    entry.io.established = true;
                    entry.io.receive_next = 1;
                    entry.arq.sent.remove(&0);
                    entry.arq.last_ack = 1;
                    entry.io.deliver(frame.body)?;
                    Self::receive_ready(entry)?;
                }
                Self::ack_later(entry);
            }
            4 | 5 => {
                if frame.kind == 4 {
                    let response =
                        Frame::control(5, entry.io.life.wire_id, entry.io.next()?, Bytes::new());
                    self.emit(entry, &response, None, false)?;
                }
                for (_, pending) in std::mem::take(&mut entry.arq.sent) {
                    pending.receipt.fail();
                }
                for pending in entry.arq.unsent.drain(..) {
                    pending.receipt.fail();
                }
                if frame.status != 0 {
                    entry.io.life.reason.store(1, Ordering::Release);
                }
                entry.io.peer_close();
            }
            8 | 9 => entry
                .arq
                .acknowledge(frame.ack, frame.window, Instant::now())?,
            _ if frame.is_data() && !entry.io.peer_closed => {
                entry
                    .arq
                    .acknowledge(frame.ack, frame.window, Instant::now())?;
                let next = entry.io.receive_next;
                if frame.seq >= next
                    && frame.seq.saturating_sub(next) < WINDOW as u32
                    && entry.arq.received.len() < WINDOW
                {
                    entry.arq.received.entry(frame.seq).or_insert(frame);
                }
                Self::receive_ready(entry)?;
            }
            _ => {}
        }
        Ok(())
    }
    fn incoming(&mut self, peer: SocketAddr, bytes: Bytes) -> Result<()> {
        if !peer.ip().is_loopback()
            || peer.ip().to_canonical() != peer.ip()
            || self.server_peer.is_some_and(|server| server != peer)
        {
            return Ok(());
        }
        let mut known = Vec::<Arc<Key>>::new();
        if let Some(key) = &self.client_key {
            known.push(key.clone());
        }
        for entry in self.entries.values().filter(|entry| entry.peer == peer) {
            if !known.iter().any(|key| Arc::ptr_eq(key, &entry.key)) {
                known.push(entry.key.clone());
            }
        }
        for (route, retired) in &self.retired {
            if route.0 == peer && !known.iter().any(|key| Arc::ptr_eq(key, &retired.key)) {
                known.push(retired.key.clone());
            }
        }
        let Ok((frame, key, nonce)) =
            codec::open_local_unsafe_packet(&bytes, self.users.as_deref(), &known)
        else {
            return Ok(());
        };
        if frame.direction(self.link.client).is_err() {
            return Ok(());
        }
        let route = (peer, key.user.fingerprint(), frame.id);
        self.last_wire = Instant::now();
        if let Some(&id) = self.routes.get(&route) {
            if let Some(mut entry) = self.entries.remove(&id) {
                if self.process_frame(&mut entry, frame).is_err() {
                    self.abort_entry(entry);
                } else {
                    self.entries.insert(id, entry);
                }
            }
            return Ok(());
        }
        if let Some(tombstone) = self.retired.get(&route) {
            if frame.kind == 4 && self.output.len() < 512 {
                let response = Frame::control(5, frame.id, tombstone.reply_seq, Bytes::new());
                let bytes = codec::seal_local_unsafe_packet(
                    &tombstone.key,
                    &response,
                    &self.link.traffic,
                    self.mtu,
                )?;
                self.output.push_back(Out {
                    peer,
                    bytes,
                    id: 0,
                    seq: response.seq,
                    kind: 5,
                    life: None,
                    receipt: None,
                    first: false,
                });
            }
            return Ok(());
        }
        if self.link.client
            || frame.kind != 2
            || self.entries.len() >= WINDOW
            || self.retired.len() >= 8192
        {
            return Ok(());
        }
        let Some(replay) = &self.replay else {
            return Err(codec::bad());
        };
        if replay.accept(&key, &nonce).is_err() {
            return Ok(());
        }
        let id = self.next_server;
        self.next_server = self
            .next_server
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        let Ok(mut io) = crate::session::server_entry(&self.link, id, frame.id) else {
            return Ok(());
        };
        io.started = true;
        io.established = true;
        io.receive_next = 1;
        let response = Frame::control(3, frame.id, io.next()?, Bytes::new());
        io.deliver(frame.body)?;
        let mut entry = PacketEntry {
            io,
            key,
            peer,
            arq: Arq::new(),
            close_pending: None,
        };
        entry.arq.queue(response, Receipt::new(1, None))?;
        Self::ack_later(&mut entry);
        self.routes.insert(route, id);
        self.entries.insert(id, entry);
        self.ever_used = true;
        Ok(())
    }
    fn abort_entry(&mut self, mut entry: PacketEntry) {
        if self.link.client {
            self.stop_when_empty = true;
        }
        if entry.io.started
            && (!self.link.client || *entry.io.life.started.borrow())
            && !entry.io.peer_closed
            && let Ok(seq) = entry.io.next()
        {
            let close = Frame::control(4, entry.io.life.wire_id, seq, Bytes::new());
            let _ = self.emit(&mut entry, &close, None, false);
        }
        self.retire(entry, true);
    }
    fn command(&mut self, command: Command) -> Result<()> {
        match command {
            Command::Open {
                mut entry,
                request,
                lazy,
            } => {
                self.ever_used = true;
                let peer = self.server_peer.ok_or_else(codec::bad)?;
                let key = self.client_key.clone().ok_or_else(codec::bad)?;
                let id = entry.life.id;
                entry.request = request;
                let mut entry = PacketEntry {
                    io: entry,
                    key,
                    peer,
                    arq: Arq::new(),
                    close_pending: None,
                };
                if !self.link.client || self.entries.len() >= WINDOW {
                    entry.io.life.abort(3);
                    return Ok(());
                }
                if !lazy && self.start_entry(&mut entry, Bytes::new(), None).is_err() {
                    self.abort_entry(entry);
                    return Ok(());
                }
                self.routes.insert(entry.route(), id);
                self.entries.insert(id, entry);
            }
            Command::Write { id, body, done } => {
                let Some(mut entry) = self.entries.remove(&id) else {
                    let _ = done.send(Err(Error::Rejected));
                    return Ok(());
                };
                if entry.io.peer_closed
                    || entry.close_pending.is_some()
                    || entry.io.life.abort_cancel.is_cancelled()
                {
                    let _ = done.send(Err(Error::Rejected));
                    self.entries.insert(id, entry);
                } else {
                    let result = if entry.io.started {
                        self.queue_data(&mut entry, body, Some(done))
                    } else {
                        self.start_entry(&mut entry, body, Some(done))
                    };
                    if result.is_err() {
                        self.abort_entry(entry);
                    } else {
                        self.entries.insert(id, entry);
                    }
                }
            }
            Command::Close { id, abort, done } => {
                let Some(mut entry) = self.entries.remove(&id) else {
                    if let Some(done) = done {
                        let _ = done.send(Ok(()));
                    }
                    return Ok(());
                };
                if abort {
                    if let Some(done) = done {
                        let _ = done.send(Err(Error::Cancelled));
                    }
                    self.abort_entry(entry);
                } else if !entry.io.started || entry.io.peer_closed {
                    if let Some(done) = done {
                        let _ = done.send(Ok(()));
                    }
                    entry.io.peer_close();
                    self.entries.insert(id, entry);
                } else {
                    entry.close_pending = Some(done);
                    self.entries.insert(id, entry);
                }
            }
            Command::Consumed(id) => {
                if let Some(entry) = self.entries.get_mut(&id) {
                    entry.io.flush();
                    Self::receive_ready(entry)?;
                }
            }
            Command::Incoming(_) | Command::Written => {}
        }
        Ok(())
    }
    fn tick_entry(&mut self, entry: &mut PacketEntry, now: Instant) -> Result<()> {
        entry.io.flush();
        if entry.io.peer_closed {
            return Ok(());
        }
        if entry.io.life.abort_cancel.is_cancelled()
            || entry.io.last_data.elapsed() >= self.link.idle
        {
            return Err(Error::Cancelled);
        }
        Self::receive_ready_if_buffered(entry)?;
        let mut loss = false;
        let mut timeout_loss = false;
        let retransmit = entry
            .arq
            .sent
            .iter()
            .filter(|(_, pending)| {
                now.duration_since(pending.sent_at) >= pending.rto
                    || pending.duplicate_acks >= 3 && pending.transmissions <= 1
            })
            .map(|(seq, _)| *seq)
            .take(16)
            .collect::<Vec<_>>();
        for seq in retransmit {
            let mut pending = entry.arq.sent.remove(&seq).expect("已找到待重传帧");
            timeout_loss |= pending.retry(now, entry.arq.rto())?;
            loss = true;
            self.emit(entry, &pending.frame, None, false)?;
            entry.arq.sent.insert(seq, pending);
        }
        if loss {
            entry.arq.loss(timeout_loss);
        }
        let limit = entry
            .arq
            .remote_window
            .min(entry.arq.cwnd.floor() as usize)
            .min(WINDOW);
        for _ in 0..16 {
            let Some(front) = entry.arq.unsent.front() else {
                break;
            };
            if entry.arq.sent.len() >= limit && !front.frame.session() {
                break;
            }
            if self.link.client && !entry.io.established && front.frame.is_data() {
                break;
            }
            let mut pending = entry.arq.unsent.pop_front().expect("已检查待发队列");
            pending.transmissions = 1;
            pending.sent_at = now;
            pending.rto = entry.arq.rto();
            self.emit(entry, &pending.frame, Some(pending.receipt.clone()), true)?;
            entry.arq.sent.insert(pending.frame.seq, pending);
        }
        if entry.close_pending.is_some() && entry.arq.unsent.is_empty() && entry.arq.sent.is_empty()
        {
            let done = entry.close_pending.take().expect("已检查关闭请求");
            let close = Frame::control(4, entry.io.life.wire_id, entry.io.next()?, Bytes::new());
            entry.arq.queue(close, Receipt::new(1, done))?;
        }
        if entry.io.established
            && (entry.arq.ack_due.is_some_and(|due| due <= now)
                || now.duration_since(entry.arq.last_tx)
                    >= Duration::from_millis(5000 + u64::from(entry.io.life.wire_id % 1000)))
        {
            let mut ack = Frame::control(
                if self.link.client { 8 } else { 9 },
                entry.io.life.wire_id,
                entry.io.send_next.saturating_sub(1),
                Bytes::new(),
            );
            ack.ack = entry.io.receive_next;
            ack.window = entry.window();
            entry.arq.ack_due = None;
            self.emit(entry, &ack, None, false)?;
        }
        Ok(())
    }
    fn receive_ready_if_buffered(entry: &mut PacketEntry) -> Result<()> {
        if entry.arq.received.contains_key(&entry.io.receive_next) {
            Self::receive_ready(entry)?;
        }
        Ok(())
    }
    fn tick(&mut self) -> Result<()> {
        let now = Instant::now();
        let ids = self.entries.keys().copied().collect::<Vec<_>>();
        for id in ids {
            let Some(mut entry) = self.entries.remove(&id) else {
                continue;
            };
            if self.tick_entry(&mut entry, now).is_err() {
                self.abort_entry(entry);
            } else if entry.io.peer_closed && entry.io.drained() {
                self.retire(entry, false);
            } else {
                self.entries.insert(id, entry);
            }
        }
        self.retired
            .retain(|_, retired| now.duration_since(retired.since) < Duration::from_secs(360));
        self.flush_output()
    }
    fn delay(&self) -> Duration {
        let now = Instant::now();
        let mut delay = Duration::from_millis(100);
        for entry in self.entries.values() {
            if let Some(ack) = entry.arq.ack_due {
                delay = delay.min(ack.saturating_duration_since(now));
            }
            for pending in entry.arq.sent.values() {
                delay = delay.min((pending.sent_at + pending.rto).saturating_duration_since(now));
            }
            if !entry.arq.unsent.is_empty()
                && (entry
                    .arq
                    .unsent
                    .front()
                    .is_some_and(|pending| pending.frame.session())
                    || entry.arq.sent.len()
                        < entry.arq.remote_window.min(entry.arq.cwnd.floor() as usize))
                && !(self.link.client
                    && !entry.io.established
                    && entry
                        .arq
                        .unsent
                        .front()
                        .is_some_and(|pending| pending.frame.is_data()))
            {
                delay = delay.min(Duration::from_millis(1));
            }
        }
        delay.max(Duration::from_micros(100))
    }
    async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        mut incoming: mpsc::Receiver<(SocketAddr, Bytes)>,
    ) {
        loop {
            let delay = self.delay();
            tokio::select! { biased;
                _ = self.link.scope.cancel.cancelled() => break,
                command = commands.recv() => match command { Some(command) => if self.command(command).is_err() { break; }, None => break },
                packet = incoming.recv() => match packet { Some((peer, bytes)) => if self.incoming(peer, bytes).is_err() { break; }, None => break },
                writable = self.socket.writable(), if !self.output.is_empty() => if writable.is_err() { break; },
                _ = tokio::time::sleep(delay) => {},
            }
            if self.tick().is_err() {
                break;
            }
            if self.link.client
                && self.entries.is_empty()
                && self.output.is_empty()
                && (self.stop_when_empty
                    || !self.link.multiplexing && self.ever_used
                    || self.last_wire.elapsed() >= self.link.idle)
            {
                break;
            }
        }
        self.link.scope.cancel.cancel();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cumulative_ack_window_and_rto_are_bounded_without_sequence_rollback() {
        let mut arq = Arq::new();
        arq.highest_sent = 2;
        let frame = Frame::control(2, 1, 0, Bytes::new());
        arq.queue(frame.clone(), Receipt::new(1, None)).unwrap();
        let mut pending = arq.unsent.pop_front().unwrap();
        pending.transmissions = 1;
        pending.sent_at = Instant::now() - Duration::from_millis(100);
        arq.sent.insert(0, pending);
        arq.acknowledge(1, 0, Instant::now()).unwrap();
        assert!(arq.sent.is_empty());
        assert_eq!(arq.remote_window, 0);
        arq.acknowledge(0, 128, Instant::now()).unwrap();
        assert_eq!(arq.remote_window, 0);
        arq.acknowledge(1, 128, Instant::now()).unwrap();
        assert_eq!(arq.remote_window, 128);
        assert!(arq.acknowledge(3, 128, Instant::now()).is_err());
        assert!((Duration::from_millis(100)..=Duration::from_secs(3)).contains(&arq.rto()));
        arq.cwnd = 100.0;
        arq.loss(true);
        assert_eq!(arq.cwnd, 50.0);
        let mut retry = Pending {
            frame: frame.clone(),
            receipt: Receipt::new(1, None),
            transmissions: 19,
            sent_at: Instant::now() - Duration::from_secs(10),
            rto: Duration::from_millis(100),
            duplicate_acks: 3,
        };
        assert!(
            retry
                .retry(Instant::now(), Duration::from_millis(100))
                .unwrap()
        );
        assert_eq!(retry.transmissions, 20);
        assert!(retry.rto <= Duration::from_secs(5));
        assert!(
            retry
                .retry(Instant::now(), Duration::from_millis(100))
                .is_err()
        );
        for _ in 0..SEND_LIMIT {
            arq.queue(frame.clone(), Receipt::new(1, None)).unwrap();
        }
        assert!(arq.queue(frame, Receipt::new(1, None)).is_err());
    }
}
