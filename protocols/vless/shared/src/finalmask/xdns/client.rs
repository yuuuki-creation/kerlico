use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use super::super::{
    check_udp_size, copy_packet, invalid, random_below, retryable, PacketIo, UDP_SIZE,
};
use super::resolver::Resolver;
use super::wire::{read_response, ClientId, Domain};
use super::POLL;

const START_POLL: Duration = Duration::from_millis(500);
const MAX_POLL: Duration = Duration::from_secs(10);
const SUBMIT_LIMIT: Duration = Duration::from_secs(15);
const READ_QUEUE: usize = 128;
const SEND_QUEUE: usize = 64;

pub(super) fn open(
    domains: Arc<[Arc<Domain>]>,
    resolvers: Vec<Arc<dyn Resolver>>,
    extra_poll: u8,
    peer: SocketAddr,
) -> io::Result<Arc<dyn PacketIo>> {
    let id = ClientId::new()?;
    let counts = (0..resolvers.len()).map(|_| AtomicU32::new(0)).collect();
    let core = Arc::new(Core {
        domains,
        resolvers,
        extra_poll,
        id,
        counts,
        alive: AtomicBool::new(true),
    });
    let (packets, receiver) = mpsc::sync_channel(READ_QUEUE);
    let (work, events) = mpsc::sync_channel(SEND_QUEUE);
    // The public wrapper owns shutdown even if spawning a worker fails.
    let client = Arc::new(Client {
        core: core.clone(),
        peer,
        receiver: Mutex::new(receiver),
        work: work.clone(),
        fragment: AtomicU8::new(0),
    });
    for (index, resolver) in core.resolvers.iter().cloned().enumerate() {
        let core = core.clone();
        let work = work.clone();
        let packets = packets.clone();
        std::thread::Builder::new()
            .name("vless-xdns-resolver".into())
            .spawn(move || {
                core.read(index, resolver, packets, work);
            })?;
    }
    std::thread::Builder::new()
        .name("vless-xdns-poll".into())
        .spawn(move || core.poll(events))?;
    Ok(client)
}

enum Work {
    Datagram(Vec<Vec<u8>>),
    Reply,
}

struct Core {
    domains: Arc<[Arc<Domain>]>,
    resolvers: Vec<Arc<dyn Resolver>>,
    extra_poll: u8,
    id: ClientId,
    counts: Vec<AtomicU32>,
    alive: AtomicBool,
}

impl Core {
    fn domain(&self) -> &Domain {
        &self.domains[random_below(self.domains.len() as u32) as usize]
    }

    fn send(&self, resolver: &mut usize, queries: Vec<Vec<u8>>) -> io::Result<()> {
        let deadline = Instant::now() + SUBMIT_LIMIT;
        for query in queries {
            loop {
                if !self.alive.load(Ordering::Acquire) {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                match self.query(resolver, &query) {
                    Ok(()) => break,
                    Err(error) if retryable(&error) && Instant::now() < deadline => {
                        std::thread::sleep(POLL)
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn query(&self, resolver: &mut usize, query: &[u8]) -> io::Result<()> {
        let mut temporary = None;
        let mut error =
            io::Error::new(io::ErrorKind::NotConnected, "no XDNS resolver is available");
        for _ in 0..self.resolvers.len() {
            let index = *resolver;
            let count = self.counts[index]
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1);
            let next = (index + 1) % self.resolvers.len();
            *resolver = (1..self.resolvers.len())
                .map(|delta| (index + delta) % self.resolvers.len())
                .find(|&candidate| self.counts[candidate].load(Ordering::Relaxed) < count)
                .unwrap_or(next);
            match self.resolvers[index].send(query) {
                Ok(()) => return Ok(()),
                Err(failure) if retryable(&failure) => temporary = Some(failure),
                Err(failure) => error = failure,
            }
        }
        Err(temporary.unwrap_or(error))
    }

    fn cover(&self, resolver: &mut usize, count: u8) {
        for _ in 0..count {
            if let Ok(queries) = self.domain().queries(self.id, 0, &[]) {
                for query in queries {
                    let _ = self.query(resolver, &query);
                }
            }
        }
    }

    fn read(
        &self,
        index: usize,
        resolver: Arc<dyn Resolver>,
        packets: mpsc::SyncSender<Vec<u8>>,
        work: mpsc::SyncSender<Work>,
    ) {
        let mut wire = [0; UDP_SIZE];
        while self.alive.load(Ordering::Acquire) {
            match resolver.recv(&mut wire, &self.alive) {
                Ok(len) => {
                    let Some(data) = read_response(&self.domains, self.id, &wire[..len]) else {
                        continue;
                    };
                    self.counts[index].store(0, Ordering::Relaxed);
                    for packet in data {
                        let _ = packets.try_send(packet);
                    }
                    let _ = work.try_send(Work::Reply);
                }
                Err(error) if retryable(&error) => {}
                Err(_) => std::thread::sleep(POLL),
            }
        }
    }

    fn poll(&self, events: mpsc::Receiver<Work>) {
        let mut delay = START_POLL;
        let mut next = None;
        let mut resolver = 0;
        while self.alive.load(Ordering::Acquire) {
            match events.recv_timeout(POLL) {
                Ok(Work::Datagram(queries)) => {
                    if self.send(&mut resolver, queries).is_ok() {
                        self.cover(&mut resolver, self.extra_poll);
                    }
                }
                Ok(Work::Reply) => {
                    delay = START_POLL;
                    next = Some(Instant::now());
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if next.is_some_and(|deadline| Instant::now() >= deadline) {
                self.cover(&mut resolver, 1 + self.extra_poll);
                next = Some(Instant::now() + delay);
                delay = (delay * 2).min(MAX_POLL);
            }
        }
    }
}

struct Client {
    core: Arc<Core>,
    peer: SocketAddr,
    receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    work: mpsc::SyncSender<Work>,
    fragment: AtomicU8,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.core.alive.store(false, Ordering::Release);
        for resolver in &self.core.resolvers {
            resolver.close();
        }
    }
}

impl PacketIo for Client {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let ip = if self.peer.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        Ok(SocketAddr::new(ip, 0))
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self
            .receiver
            .lock()
            .expect("XDNS client receiver")
            .recv_timeout(POLL)
        {
            Ok(packet) => Ok((copy_packet(out, &packet), self.peer)),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::WouldBlock.into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn send_to(&self, packet: &[u8], _: SocketAddr) -> io::Result<usize> {
        if !self.core.alive.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if packet.is_empty() {
            return Err(invalid("XDNS cannot send an empty transport datagram"));
        }
        check_udp_size(packet.len())?;
        let fragment = self.fragment.fetch_add(1, Ordering::Relaxed);
        let queries = self.core.domain().queries(self.core.id, fragment, packet)?;
        self.work
            .try_send(Work::Datagram(queries))
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
                mpsc::TrySendError::Disconnected(_) => io::ErrorKind::BrokenPipe,
            })?;
        Ok(packet.len())
    }
}

#[cfg(test)]
mod tests {
    use super::super::wire::{read_query, DomainConfig, ParsedQuery, Uplink};
    use super::*;

    struct LimitedResolver {
        sent: mpsc::Sender<Vec<u8>>,
        blocked: AtomicBool,
    }

    impl Resolver for LimitedResolver {
        fn send(&self, query: &[u8]) -> io::Result<()> {
            if self.blocked.fetch_xor(true, Ordering::Relaxed) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.sent.send(query.to_vec()).map_err(io::Error::other)
        }

        fn recv(&self, _: &mut [u8], _: &AtomicBool) -> io::Result<usize> {
            std::thread::sleep(POLL);
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    #[test]
    fn submits_every_fragment_once_when_resolver_backpressures() {
        let config: DomainConfig =
            serde_json::from_str(r#"{"names":["test.example"],"lenLimit":70,"labelLimit":15}"#)
                .unwrap();
        let domains: Arc<[Arc<Domain>]> = config
            .domains()
            .unwrap()
            .into_iter()
            .map(Arc::new)
            .collect();
        let (sent, queries) = mpsc::channel();
        let resolver = Arc::new(LimitedResolver {
            sent,
            blocked: AtomicBool::new(true),
        });
        let peer = "127.0.0.1:1234".parse().unwrap();
        let client = open(domains.clone(), vec![resolver], 0, peer).unwrap();
        let payload: Vec<_> = (0..200u8).collect();
        assert_eq!(client.send_to(&payload, peer).unwrap(), payload.len());
        let mut assembled = Vec::new();
        for expected_index in 0.. {
            let wire = queries.recv_timeout(Duration::from_secs(1)).unwrap();
            let Some(ParsedQuery::Tunnel {
                packet:
                    Uplink::Fragment {
                        index, count, data, ..
                    },
                ..
            }) = read_query(&domains, &wire)
            else {
                panic!("expected an XDNS data fragment");
            };
            assert_eq!(index, expected_index);
            assembled.extend_from_slice(&data);
            if index + 1 == count {
                break;
            }
        }
        assert_eq!(assembled, payload);
        assert!(queries.try_recv().is_err());
    }
}
