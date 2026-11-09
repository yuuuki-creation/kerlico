use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::super::{check_udp_size, copy_packet, invalid, retryable, PacketIo, UDP_SIZE};
use super::wire::{read_query, ClientId, Domain, ParsedQuery, Response, Uplink};
use super::POLL;

const MAX_WAIT: Duration = Duration::from_secs(1);
const ENTRY_TTL: Duration = Duration::from_secs(4);
const ENTRY_LIMIT: usize = 4096;
const READ_QUEUE: usize = 128;
const SEND_QUEUE: usize = 128;
const SEND_TOTAL: usize = 4096;
const QUERY_QUEUE: usize = 255;

pub(super) fn open(
    domains: Arc<[Arc<Domain>]>,
    inner: Arc<dyn PacketIo>,
) -> io::Result<Arc<dyn PacketIo>> {
    let core = Arc::new(Core {
        inner,
        domains,
        state: Mutex::new(State::default()),
        changed: Condvar::new(),
        alive: AtomicBool::new(true),
    });
    let (packets, receiver) = mpsc::sync_channel(READ_QUEUE);
    let server = Arc::new(Server {
        core: core.clone(),
        receiver: Mutex::new(receiver),
    });
    let reader = core.clone();
    std::thread::Builder::new()
        .name("vless-xdns-read".into())
        .spawn(move || reader.read(packets))?;
    std::thread::Builder::new()
        .name("vless-xdns-reply".into())
        .spawn(move || core.respond())?;
    Ok(server)
}

struct Server {
    core: Arc<Core>,
    receiver: Mutex<mpsc::Receiver<(ClientId, Vec<u8>)>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.core.close();
    }
}

impl PacketIo for Server {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.core.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self
            .receiver
            .lock()
            .expect("XDNS server receiver")
            .recv_timeout(POLL)
        {
            Ok((client, data)) => Ok((copy_packet(out, &data), client.addr())),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::WouldBlock.into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        if packet.is_empty() {
            return Err(invalid("XDNS cannot send an empty transport datagram"));
        }
        check_udp_size(packet.len())?;
        let client =
            ClientId::from_addr(peer).ok_or_else(|| invalid("invalid XDNS client address"))?;
        if !self.core.alive.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut state = self.core.state.lock().expect("XDNS response queues");
        state.enqueue(client, packet)?;
        self.core.changed.notify_one();
        Ok(packet.len())
    }
}

struct Pending {
    response: Response,
    client: ClientId,
    peer: SocketAddr,
    deadline: Instant,
}

struct Queue {
    packets: VecDeque<Vec<u8>>,
    expires: Instant,
}

#[derive(Default)]
struct State {
    queries: VecDeque<Pending>,
    outgoing: HashMap<ClientId, Queue>,
    outgoing_count: usize,
}

impl State {
    fn enqueue(&mut self, client: ClientId, packet: &[u8]) -> io::Result<()> {
        let now = Instant::now();
        if self.outgoing_count >= SEND_TOTAL {
            self.outgoing.retain(|_, queue| {
                if queue.expires > now {
                    return true;
                }
                self.outgoing_count -= queue.packets.len();
                false
            });
            if self.outgoing_count >= SEND_TOTAL {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let queue = self.outgoing.entry(client).or_insert_with(|| Queue {
            packets: VecDeque::new(),
            expires: now + ENTRY_TTL,
        });
        if queue.expires <= now {
            self.outgoing_count -= queue.packets.len();
            queue.packets.clear();
        }
        if queue.packets.len() >= SEND_QUEUE {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        queue.packets.push_back(packet.to_vec());
        queue.expires = now + ENTRY_TTL;
        self.outgoing_count += 1;
        Ok(())
    }

    fn take_reply(&mut self, client: ClientId, mut room: usize) -> (Vec<Vec<u8>>, bool) {
        let Some(queue) = self.outgoing.get_mut(&client) else {
            return (Vec::new(), false);
        };
        if queue.expires <= Instant::now() {
            self.outgoing_count -= queue.packets.len();
            self.outgoing.remove(&client);
            return (Vec::new(), false);
        }
        let mut reply = Vec::new();
        let mut oversized = false;
        while let Some(packet) = queue.packets.front() {
            let used = packet.len() + 2;
            if used > room {
                if reply.is_empty() {
                    // A datagram that cannot fit in the reply cannot pin its queue.
                    queue.packets.pop_front();
                    self.outgoing_count -= 1;
                    oversized = true;
                }
                break;
            }
            room -= used;
            self.outgoing_count -= 1;
            reply.push(queue.packets.pop_front().expect("queued XDNS datagram"));
        }
        if queue.packets.is_empty() {
            self.outgoing.remove(&client);
        }
        (reply, oversized)
    }
}

struct Core {
    inner: Arc<dyn PacketIo>,
    domains: Arc<[Arc<Domain>]>,
    state: Mutex<State>,
    changed: Condvar,
    alive: AtomicBool,
}

impl Core {
    fn close(&self) {
        self.alive.store(false, Ordering::Release);
        self.changed.notify_all();
    }

    fn read(&self, packets: mpsc::SyncSender<(ClientId, Vec<u8>)>) {
        let mut wire = [0; UDP_SIZE];
        let mut fragments = Fragments::default();
        while self.alive.load(Ordering::Acquire) {
            let (len, peer) = match self.inner.recv_from(&mut wire) {
                Ok(packet) => packet,
                Err(error) if retryable(&error) => continue,
                Err(_) => break,
            };
            match read_query(&self.domains, &wire[..len]) {
                Some(ParsedQuery::Reject(reply)) => {
                    let _ = self.inner.send_to(&reply, peer);
                }
                Some(ParsedQuery::Tunnel {
                    response,
                    client,
                    packet,
                }) => {
                    self.query(Pending {
                        response,
                        client,
                        peer,
                        deadline: Instant::now() + MAX_WAIT,
                    });
                    let payload = match packet {
                        Uplink::Poll => None,
                        Uplink::Data(packet) => Some(packet),
                        Uplink::Fragment {
                            id,
                            index,
                            count,
                            data,
                        } => fragments.feed(client, id, index, count, data),
                    };
                    if let Some(payload) = payload {
                        let _ = packets.try_send((client, payload));
                    }
                }
                None => {}
            }
        }
        self.close();
    }

    fn query(&self, query: Pending) {
        let mut state = self.state.lock().expect("XDNS response queues");
        if state.queries.len() < QUERY_QUEUE {
            state.queries.push_back(query);
            self.changed.notify_one();
        } else {
            drop(state);
            if let Ok(reply) = query.response.encode(&[]) {
                let _ = self.inner.send_to(&reply, query.peer);
            }
        }
    }

    fn respond(&self) {
        while self.alive.load(Ordering::Acquire) {
            let mut state = self.state.lock().expect("XDNS response queues");
            let Some(query) = state.queries.pop_front() else {
                let _guard = self
                    .changed
                    .wait_timeout(state, POLL)
                    .expect("XDNS response queues");
                continue;
            };
            let output = loop {
                let (output, oversized) = state.take_reply(query.client, query.response.capacity());
                let remaining = query.deadline.saturating_duration_since(Instant::now());
                if !output.is_empty()
                    || oversized
                    || !state.queries.is_empty()
                    || remaining.is_zero()
                    || !self.alive.load(Ordering::Acquire)
                {
                    break output;
                }
                state = self
                    .changed
                    .wait_timeout(state, remaining)
                    .expect("XDNS response queues")
                    .0;
            };
            drop(state);
            if let Ok(reply) = query.response.encode(&output) {
                let _ = self.inner.send_to(&reply, query.peer);
            }
        }
    }
}

#[derive(Default)]
struct Fragments {
    entries: HashMap<(ClientId, u8), Entry>,
}

struct Entry {
    chunks: BTreeMap<u8, Vec<u8>>,
    count: u8,
    size: usize,
    expires: Instant,
}

impl Fragments {
    fn feed(
        &mut self,
        client: ClientId,
        id: u8,
        index: u8,
        count: u8,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        if count < 2 || index >= count || data.is_empty() {
            return None;
        }
        let key = (client, id);
        let now = Instant::now();
        if self
            .entries
            .get(&key)
            .is_some_and(|entry| entry.expires <= now)
        {
            self.entries.remove(&key);
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= ENTRY_LIMIT {
            self.entries.retain(|_, entry| entry.expires > now);
            if self.entries.len() >= ENTRY_LIMIT {
                let expired = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires)
                    .map(|(key, _)| *key)?;
                self.entries.remove(&expired);
            }
        }
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            chunks: BTreeMap::new(),
            count,
            size: 0,
            expires: now + ENTRY_TTL,
        });
        if entry.count != count
            || entry.chunks.contains_key(&index)
            || entry.size + data.len() > UDP_SIZE
        {
            return None;
        }
        entry.size += data.len();
        entry.expires = now + ENTRY_TTL;
        entry.chunks.insert(index, data);
        if entry.chunks.len() != usize::from(count) {
            return None;
        }
        let entry = self.entries.remove(&key)?;
        let mut packet = Vec::with_capacity(entry.size);
        packet.extend(entry.chunks.into_values().flatten());
        Some(packet)
    }
}
