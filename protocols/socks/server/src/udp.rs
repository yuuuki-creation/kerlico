use super::*;

use kerlico_shared::DatagramSession;
use kerlico_socks::{decode, ip_address, udp_parts};
use socket2::{SockAddr, SockRef};
use std::io::IoSlice;
use std::sync::Mutex;
use tokio::net::{TcpStream as Control, UdpSocket};

const MAX_WIRE: usize = 65_507;
const MAX_TARGETS: usize = 64;
const MAX_QUEUED: usize = 8 * 1024 * 1024;

pub(super) async fn associate(
    mut control: Control,
    peer: SocketAddr,
    user: UserEmail,
    source: Address,
    state: &State,
) -> io::Result<()> {
    if source
        .host
        .parse::<IpAddr>()
        .is_ok_and(|ip| !ip.is_unspecified() && ip != peer.ip())
    {
        return control.write_all(&reply(2, unspecified(peer))).await;
    }
    let local = control.local_addr()?;
    let socket = std::net::UdpSocket::bind(SocketAddr::new(local.ip(), 0))?;
    socket.set_nonblocking(true)?;
    let receiver = UdpSocket::from_std(socket.try_clone()?)?;
    let bind = socket.local_addr()?;
    let advertised = SocketAddr::new(state.advertised_ip.unwrap_or(bind.ip()), bind.port());
    control.write_all(&reply(0, advertised)).await?;

    let mut relay = Relay {
        socket: Arc::new(socket),
        session: Arc::new(DatagramSession::new(true)),
        active: Active::new(),
        targets: HashMap::new(),
    };
    let mut endpoint = (source.port != 0).then(|| SocketAddr::new(peer.ip(), source.port));
    let mut wire = vec![0; MAX_WIRE + 1];
    let mut control_byte = [0];
    loop {
        let (len, from) = tokio::select! {
            biased;
            _ = control.read(&mut control_byte) => return Ok(()),
            packet = receiver.recv_from(&mut wire) => packet?,
        };
        if len > MAX_WIRE || from.ip() != peer.ip() || endpoint.is_some_and(|addr| addr != from) {
            continue;
        }
        let Ok((address, payload)) = udp_parts(&wire[..len]) else {
            continue;
        };
        if address.ends_with(&[0, 0]) {
            continue;
        }
        if relay.deliver(state, &user, address, from, payload) {
            endpoint.get_or_insert(from);
        }
    }
}

struct Relay {
    socket: Arc<std::net::UdpSocket>,
    session: Arc<DatagramSession>,
    active: Active,
    targets: HashMap<Vec<u8>, (mpsc::SyncSender<Packet>, Arc<AtomicBool>)>,
}

impl Relay {
    fn deliver(
        &mut self,
        state: &State,
        user: &UserEmail,
        address: &[u8],
        peer: SocketAddr,
        payload: &[u8],
    ) -> bool {
        if let Some((sender, _)) = self.targets.get(address) {
            let Some(packet) = Packet::new(payload, &state.queued) else {
                return true;
            };
            if !matches!(
                sender.try_send(packet),
                Err(mpsc::TrySendError::Disconnected(_))
            ) {
                return true;
            }
            self.targets.remove(address);
        }
        if self.targets.len() >= MAX_TARGETS {
            self.targets
                .retain(|_, (_, alive)| alive.load(Ordering::Acquire));
            if self.targets.len() >= MAX_TARGETS {
                return false;
            }
        }
        let Ok((target, _)) = decode(address) else {
            return false;
        };
        let Ok(dest) = Destination::new(target.host, target.port, Transport::Udp) else {
            return false;
        };
        let Some(packet) = Packet::new(payload, &state.queued) else {
            return false;
        };
        let (send, receive) = mpsc::sync_channel(16);
        if send.try_send(packet).is_err() {
            return false;
        }
        let alive = Active::new();
        let target_alive = alive.0.clone();
        let flow = Flow {
            socket: self.socket.clone(),
            active: self.active.0.clone(),
            _alive: alive,
            receive: Mutex::new(receive),
            target: address.to_vec(),
            peer: peer.into(),
        };
        let mut handoff = Handoff::new(state.tag.clone(), user.clone(), dest, Box::new(flow));
        handoff.set_peer(peer);
        handoff.set_datagram_session(self.session.clone());
        if state.ready.try_send(handoff).is_ok() {
            self.targets.insert(address.to_vec(), (send, target_alive));
        }
        true
    }
}

struct Active(Arc<AtomicBool>);
impl Active {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Packet {
    buffer: Vec<u8>,
    queued: Arc<AtomicUsize>,
}

impl Packet {
    fn new(bytes: &[u8], queued: &Arc<AtomicUsize>) -> Option<Self> {
        let size = bytes.len().max(64);
        if queued.fetch_add(size, Ordering::Relaxed) + size > MAX_QUEUED {
            queued.fetch_sub(size, Ordering::Relaxed);
            return None;
        }
        Some(Self {
            buffer: bytes.to_vec(),
            queued: queued.clone(),
        })
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        self.queued
            .fetch_sub(self.buffer.len().max(64), Ordering::Relaxed);
    }
}

struct Flow {
    socket: Arc<std::net::UdpSocket>,
    active: Arc<AtomicBool>,
    _alive: Active,
    receive: Mutex<mpsc::Receiver<Packet>>,
    target: Vec<u8>,
    peer: SockAddr,
}

impl Flow {
    fn check(&self) -> Result<(), PlaneFault> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(PlaneFault::Closed)
        }
    }

    fn send(&self, address: &[u8], payload: &[u8]) -> Result<usize, PlaneFault> {
        self.check()?;
        let wire_len = 3 + address.len() + payload.len();
        if wire_len > MAX_WIRE {
            return Ok(payload.len());
        }
        let parts = [
            IoSlice::new(&[0, 0, 0]),
            IoSlice::new(address),
            IoSlice::new(payload),
        ];
        match SockRef::from(self.socket.as_ref()).send_to_vectored(&parts, &self.peer) {
            Ok(size) if size == wire_len => Ok(payload.len()),
            Ok(_) => Err(PlaneFault::Transport),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(payload.len()),
            Err(error) => Err(map_io(error)),
        }
    }

    fn receive(&self) -> Result<Packet, PlaneFault> {
        self.check()?;
        let packet = self
            .receive
            .lock()
            .expect("SOCKS5 UDP")
            .recv_timeout(FLOW_WAIT)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => PlaneFault::Again,
                mpsc::RecvTimeoutError::Disconnected => PlaneFault::Closed,
            })?;
        self.check()?;
        Ok(packet)
    }
}

impl InboundStream for Flow {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        let packet = self.receive()?;
        let n = packet.buffer.len();
        buf.get_mut(..n)
            .ok_or(PlaneFault::Transport)?
            .copy_from_slice(&packet.buffer);
        Ok(n)
    }

    fn read_from_user_to(
        &self,
        _: &mut [u8],
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<usize, PlaneFault> {
        let packet = self.receive()?;
        sink(&packet.buffer);
        Ok(packet.buffer.len())
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.send(&self.target, buf)
    }

    fn write_datagram_to_user(&self, buf: &[u8], source: SocketAddr) -> Result<usize, PlaneFault> {
        self.send(ip_address(&mut [0; 19], source), buf)
    }
}
