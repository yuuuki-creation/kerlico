use super::*;

use kerlico_shared::{DatagramSession, DatagramUplink, DirectDatagram};
use kerlico_socks::{decode, ip_address, udp_parts};
use socket2::{SockAddr, SockRef};
use std::io::IoSlice;
use std::sync::{Mutex, OnceLock};
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
    let _ = SockRef::from(&socket).set_recv_buffer_size(256 * 1024);
    socket.set_nonblocking(true)?;
    let receiver = UdpSocket::from_std(socket.try_clone()?)?;
    let bind = socket.local_addr()?;
    let advertised = SocketAddr::new(state.advertised_ip.unwrap_or(bind.ip()), bind.port());
    control.write_all(&reply(0, advertised)).await?;

    let mut relay = Relay {
        socket: Arc::new(socket),
        session: Arc::new(
            DatagramSession::new(true).with_executor(tokio::runtime::Handle::current()),
        ),
        active: Active::new(),
        targets: HashMap::new(),
    };
    let mut endpoint = (source.port != 0).then(|| SocketAddr::new(peer.ip(), source.port));
    let mut wire = vec![0; MAX_WIRE + 1];
    let mut control_byte = [0];
    'association: loop {
        tokio::select! {
            biased;
            _ = control.read(&mut control_byte) => return Ok(()),
            ready = receiver.readable() => ready?,
        }
        for _ in 0..32 {
            let (len, from) = match receiver.try_recv_from(&mut wire) {
                Ok(packet) => packet,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue 'association,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if len > MAX_WIRE || from.ip() != peer.ip() || endpoint.is_some_and(|addr| addr != from)
            {
                continue;
            }
            let Ok((address, payload)) = udp_parts(&wire[..len]) else {
                continue;
            };
            if !address.ends_with(&[0, 0]) && relay.deliver(state, &user, address, from, payload) {
                endpoint.get_or_insert(from);
            }
        }
        tokio::task::yield_now().await;
    }
}

struct Relay {
    socket: Arc<std::net::UdpSocket>,
    session: Arc<DatagramSession>,
    active: Active,
    targets: HashMap<Vec<u8>, Target>,
}

struct Target {
    queue: mpsc::SyncSender<Packet>,
    native: Arc<OnceLock<Box<dyn DatagramUplink>>>,
    fallback_live: Arc<AtomicBool>,
}

impl Target {
    fn send(&self, payload: &[u8], queued: &Arc<AtomicUsize>) -> bool {
        if let Some(native) = self.native.get() {
            return match native.send(payload) {
                Ok(()) | Err(PlaneFault::Again) => true,
                Err(_) => false,
            };
        }
        let Some(packet) = Packet::new(payload, queued) else {
            return true;
        };
        !matches!(
            self.queue.try_send(packet),
            Err(mpsc::TrySendError::Disconnected(_))
        )
    }

    fn is_live(&self) -> bool {
        match self.native.get() {
            Some(native) => native.is_live(),
            None => self.fallback_live.load(Ordering::Acquire),
        }
    }
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
        if let Some(target) = self.targets.get(address) {
            if target.send(payload, &state.queued) {
                return true;
            }
            self.targets.remove(address);
        }
        if self.targets.len() >= MAX_TARGETS {
            self.targets.retain(|_, target| target.is_live());
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
        let target = Target {
            queue: send,
            native: Arc::new(OnceLock::new()),
            fallback_live: alive.0.clone(),
        };
        let flow = Flow {
            reply: Arc::new(Reply {
                socket: self.socket.clone(),
                active: self.active.0.clone(),
                peer: peer.into(),
            }),
            _alive: alive,
            receive: Arc::new(Mutex::new(receive)),
            native: target.native.clone(),
            target: address.to_vec(),
        };
        let mut handoff = Handoff::new(state.tag.clone(), user.clone(), dest, Box::new(flow));
        handoff.set_peer(peer);
        handoff.set_datagram_session(self.session.clone());
        if state.ready.try_send(handoff).is_ok() {
            self.targets.insert(address.to_vec(), target);
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
    reply: Arc<Reply>,
    _alive: Active,
    receive: Arc<Mutex<mpsc::Receiver<Packet>>>,
    native: Arc<OnceLock<Box<dyn DatagramUplink>>>,
    target: Vec<u8>,
}

struct Reply {
    socket: Arc<std::net::UdpSocket>,
    active: Arc<AtomicBool>,
    peer: SockAddr,
}

impl Reply {
    fn check(&self) -> Result<(), PlaneFault> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(PlaneFault::Closed)
        }
    }

    fn send(&self, address: &[u8], payload: &[u8]) -> Result<(), PlaneFault> {
        self.check()?;
        let wire_len = 3 + address.len() + payload.len();
        if wire_len > MAX_WIRE {
            return Err(PlaneFault::Again);
        }
        let parts = [
            IoSlice::new(&[0, 0, 0]),
            IoSlice::new(address),
            IoSlice::new(payload),
        ];
        match SockRef::from(self.socket.as_ref()).send_to_vectored(&parts, &self.peer) {
            Ok(size) if size == wire_len => Ok(()),
            Ok(_) => Err(PlaneFault::Transport),
            Err(error) => Err(map_io(error)),
        }
    }
}

impl Flow {
    fn receive(&self) -> Result<Packet, PlaneFault> {
        self.reply.check()?;
        let packet = self
            .receive
            .lock()
            .expect("SOCKS5 UDP")
            .recv_timeout(FLOW_WAIT)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => PlaneFault::Again,
                mpsc::RecvTimeoutError::Disconnected => PlaneFault::Closed,
            })?;
        self.reply.check()?;
        Ok(packet)
    }

    fn write(&self, address: &[u8], payload: &[u8]) -> Result<usize, PlaneFault> {
        match self.reply.send(address, payload) {
            Ok(()) | Err(PlaneFault::Again) => Ok(payload.len()),
            Err(error) => Err(error),
        }
    }
}

impl InboundStream for Flow {
    fn direct_datagram(&self) -> Option<DirectDatagram> {
        let reply = self.reply.clone();
        let active = reply.active.clone();
        let route = self.native.clone();
        let queue = self.receive.clone();
        Some(DirectDatagram {
            install: Box::new(move |native| {
                if !active.load(Ordering::Acquire) {
                    return Err(PlaneFault::Closed);
                }
                let queue = queue.lock().expect("SOCKS5 UDP");
                while let Ok(packet) = queue.try_recv() {
                    if !active.load(Ordering::Acquire) {
                        return Err(PlaneFault::Closed);
                    }
                    match native.send(&packet.buffer) {
                        Ok(()) | Err(PlaneFault::Again) => {}
                        Err(error) => return Err(error),
                    }
                }
                route.set(native).map_err(|_| PlaneFault::Transport)
            }),
            reply: Box::new(move |source, payload| {
                reply.send(ip_address(&mut [0; 19], source), payload)
            }),
        })
    }

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
        self.write(&self.target, buf)
    }

    fn write_datagram_to_user(&self, buf: &[u8], source: SocketAddr) -> Result<usize, PlaneFault> {
        self.write(ip_address(&mut [0; 19], source), buf)
    }
}
