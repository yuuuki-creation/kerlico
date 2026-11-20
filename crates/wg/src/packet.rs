use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread;
use std::time::Duration;

use boringtun::noise::Tunn;
use ipnet::IpNet;

#[cfg(feature = "tun-device")]
use crate::wire::MAX_IP_PACKET;
use crate::wire::{PeerKeys, WIRE_BUFFER};
use crate::{Hub, HubEvent};

#[cfg(all(feature = "tun-device", target_os = "linux"))]
mod socket_buffer;
#[cfg(all(feature = "tun-device", target_os = "linux"))]
pub(crate) mod tun_linux;
#[cfg(all(feature = "tun-device", target_os = "linux"))]
mod udp_batch;

const POLL: Duration = Duration::from_millis(5);
const QUEUE: usize = 128;

/// An initiator's IP packet plane over a socket owned by its caller.
pub struct PacketLink {
    tx: PacketTx,
    rx: PacketRx,
}

pub struct PacketTx {
    tx: SyncSender<Vec<u8>>,
    allowed: Option<Vec<IpNet>>,
    mtu: usize,
    wake: thread::Thread,
}

pub struct PacketRx(Receiver<Vec<u8>>);

pub struct LinkPeer {
    pub endpoint: SocketAddr,
    pub keys: PeerKeys,
    pub allowed: Vec<IpNet>,
}

#[derive(Clone, Copy)]
pub enum Reserved {
    Standard,
    Warp([u8; 3]),
    Xray([u8; 3]),
}

impl Reserved {
    fn apply(self, packet: &mut [u8], receive: bool) {
        let bytes = match self {
            Self::Standard => return,
            Self::Warp(bytes) if packet.first() == Some(&4) => bytes,
            Self::Warp(_) => return,
            Self::Xray(bytes) => bytes,
        };
        if let Some(field) = packet.get_mut(1..4) {
            field.copy_from_slice(&if receive { [0; 3] } else { bytes });
        }
    }
}

#[cfg(feature = "tun-device")]
pub(crate) struct TunCarrier {
    pub bind: SocketAddr,
    pub dual: bool,
    pub reserved: Reserved,
    pub first: Option<UdpSocket>,
    pub reopen: Box<dyn FnMut(u16, u32) -> io::Result<UdpSocket> + Send>,
    #[cfg(target_os = "linux")]
    pub egress_class: Option<u32>,
}

#[cfg(feature = "tun-device")]
impl TunCarrier {
    pub(crate) fn listener(bind: SocketAddr, dual: bool) -> Self {
        Self {
            bind,
            dual,
            reserved: Reserved::Standard,
            first: None,
            #[cfg(target_os = "linux")]
            egress_class: None,
            reopen: Box::new(move |port, mark| {
                let mut address = bind;
                address.set_port(port);
                open_carrier(address, dual, mark)
            }),
        }
    }

    fn open(&mut self, port: u16, mark: u32) -> io::Result<UdpSocket> {
        let socket = match self.first.take() {
            Some(socket) => socket,
            None => (self.reopen)(port, mark)?,
        };
        socket.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        {
            if let Some(class) = self.egress_class {
                crate::tun_egress::set_class(&socket, class).map_err(|error| {
                    io::Error::other(format!("set WireGuard egress class: {error}"))
                })?;
            }
            socket_buffer::tune(&socket);
        }
        Ok(socket)
    }
}

#[cfg(all(feature = "tun-device", any(target_os = "linux", windows)))]
struct TunBinding {
    carrier: TunCarrier,
    socket: Option<UdpSocket>,
    port: u16,
    mark: u32,
    up: bool,
}

#[cfg(all(feature = "tun-device", any(target_os = "linux", windows)))]
impl TunBinding {
    fn new(mut carrier: TunCarrier, up: bool) -> io::Result<Self> {
        let port = carrier.bind.port();
        let socket = if up {
            Some(carrier.open(port, 0)?)
        } else {
            carrier.first = None;
            None
        };
        let port = socket
            .as_ref()
            .map(UdpSocket::local_addr)
            .transpose()?
            .map_or(port, |addr| addr.port());
        Ok(Self {
            carrier,
            socket,
            port,
            mark: 0,
            up,
        })
    }

    fn control(&mut self, hub: &mut Hub, (action, reply): crate::uapi::Request) {
        if reply.is_closed() {
            return;
        }
        let answer = match action {
            crate::uapi::Action::Get => Ok(hub.snapshot(self.port, self.mark)),
            crate::uapi::Action::Set(change) => (|| {
                let plan = hub.plan(&change, self.carrier.bind.ip(), self.carrier.dual)?;
                let mark = change.mark.unwrap_or(self.mark);
                let port = change.port.unwrap_or(self.port);
                if self.up && (self.socket.is_none() || port != self.port) {
                    let next = self.carrier.open(port, mark)?;
                    self.port = next.local_addr()?.port();
                    #[cfg(target_os = "linux")]
                    if self.socket.is_none() {
                        hub.reset_transport();
                    }
                    self.socket = Some(next);
                } else {
                    #[cfg(target_os = "linux")]
                    if let Some(active) = self.socket.as_ref().filter(|_| mark != self.mark) {
                        socket2::SockRef::from(active).set_mark(mark)?;
                    }
                    self.port = port;
                }
                self.mark = mark;
                hub.commit(plan);
                Ok(String::new())
            })(),
        };
        let _ = reply.send(answer);
    }
}

#[cfg(feature = "tun-device")]
fn check_tun_mtu(hub: &Hub, mtu: usize) -> io::Result<()> {
    if !(576..=MAX_IP_PACKET).contains(&mtu)
        || (mtu < 1280
            && hub
                .allowed_ips()
                .iter()
                .any(|net| matches!(net, IpNet::V6(_))))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid WireGuard MTU",
        ));
    }
    Ok(())
}

impl PacketLink {
    pub fn start(
        socket: UdpSocket,
        peer: SocketAddr,
        keys: PeerKeys,
        allowed: Vec<IpNet>,
        mtu: usize,
    ) -> io::Result<Self> {
        Self::start_with_reserved(socket, peer, keys, allowed, mtu, Reserved::Standard)
    }

    pub fn start_with_reserved(
        socket: UdpSocket,
        peer: SocketAddr,
        keys: PeerKeys,
        allowed: Vec<IpNet>,
        mtu: usize,
        reserved: Reserved,
    ) -> io::Result<Self> {
        Self::start_peers(
            socket,
            false,
            vec![LinkPeer {
                endpoint: peer,
                keys,
                allowed,
            }],
            mtu,
            reserved,
        )
    }

    pub fn start_peers(
        socket: UdpSocket,
        dual: bool,
        peers: Vec<LinkPeer>,
        mtu: usize,
        reserved: Reserved,
    ) -> io::Result<Self> {
        let warp = if matches!(reserved, Reserved::Warp(_)) {
            peers.first().map(|peer| peer.endpoint)
        } else {
            None
        };
        let (hub, initial) = peer_hub(socket.local_addr()?, dual, peers, mtu, warp.is_some())?;
        let allowed = hub.allowed_ips();
        socket.set_nonblocking(true)?;
        let (tx, outbound) = mpsc::sync_channel(QUEUE);
        let (inbound, rx) = mpsc::sync_channel(QUEUE);
        let worker = thread::Builder::new()
            .name("kerlico-wireguard-client".into())
            .spawn(move || {
                let emit = |event| deliver(&socket, dual, reserved, &inbound, event);
                if let Some(event) = initial {
                    emit(event);
                }
                run(&socket, dual, hub, outbound, reserved, warp, emit);
            })?;
        Ok(Self {
            tx: PacketTx {
                tx,
                allowed: Some(allowed),
                mtu,
                wake: worker.thread().clone(),
            },
            rx: PacketRx(rx),
        })
    }

    pub fn send(&self, packet: Vec<u8>) -> io::Result<()> {
        self.tx.send(packet)
    }

    pub fn recv_for(&self, wait: Duration) -> io::Result<Vec<u8>> {
        self.rx.recv_for(wait)
    }

    pub fn into_halves(self) -> (PacketTx, PacketRx) {
        (self.tx, self.rx)
    }

    pub(crate) fn prefixes(&self) -> &[IpNet] {
        self.tx.allowed.as_deref().unwrap_or(&[])
    }

    #[cfg(all(feature = "tun-device", not(target_os = "linux")))]
    pub(crate) fn from_hub(
        carrier: TunCarrier,
        mut hub: Hub,
        mtu: usize,
        #[cfg(windows)] control: Option<Receiver<crate::uapi::Request>>,
    ) -> io::Result<Self> {
        check_tun_mtu(&hub, mtu)?;
        let (dual, reserved) = (carrier.dual, carrier.reserved);
        #[cfg(windows)]
        let mut binding = TunBinding::new(carrier, true)?;
        #[cfg(not(windows))]
        let socket = {
            let mut carrier = carrier;
            carrier.open(carrier.bind.port(), 0)?
        };
        let (tx, outbound) = mpsc::sync_channel::<Vec<u8>>(QUEUE);
        let (inbound, rx) = mpsc::sync_channel(QUEUE);
        let worker = thread::Builder::new()
            .name("kerlico-wireguard-tun-udp".into())
            .spawn(move || {
                let mut packet = vec![0; WIRE_BUFFER];
                loop {
                    #[cfg(windows)]
                    if let Some(requests) = &control {
                        for request in requests.try_iter().take(4) {
                            binding.control(&mut hub, request);
                        }
                    }
                    #[cfg(windows)]
                    let socket = binding.socket.as_ref().expect("Windows TUN carrier");
                    let emit = |event| deliver(&socket, dual, reserved, &inbound, event);
                    let mut busy = false;
                    for _ in 0..QUEUE {
                        match outbound.try_recv() {
                            Ok(frame) => {
                                busy = true;
                                if let Some(event) = hub.send(&frame) {
                                    emit(event);
                                }
                            }
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => return,
                        }
                    }
                    for _ in 0..32 {
                        match socket.recv_from(&mut packet) {
                            Ok((len, source)) => {
                                busy = true;
                                let source = unmapped(source, dual);
                                reserved.apply(&mut packet[..len], true);
                                hub.receive(source, &packet[..len], emit);
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock
                                        | io::ErrorKind::TimedOut
                                        | io::ErrorKind::ConnectionRefused
                                        | io::ErrorKind::ConnectionReset
                                ) =>
                            {
                                break;
                            }
                            Err(_) => return,
                        }
                    }
                    hub.tick(emit);
                    if !busy {
                        thread::park_timeout(POLL);
                    }
                }
            })?;
        Ok(Self {
            tx: PacketTx {
                tx,
                allowed: None, // The live Hub owns routing for this interface.
                mtu,
                wake: worker.thread().clone(),
            },
            rx: PacketRx(rx),
        })
    }
}

pub(crate) fn peer_hub(
    local: SocketAddr,
    dual: bool,
    peers: Vec<LinkPeer>,
    mtu: usize,
    warp: bool,
) -> io::Result<(Hub, Option<HubEvent>)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid WireGuard MTU or peer");
    let private = peers.first().ok_or_else(invalid)?.keys.private;
    if peers.len() > 32 || (warp && peers.len() != 1) || (dual && local.is_ipv4()) {
        return Err(invalid());
    }
    let mut hub = Hub::with_mtu(private, mtu)?;
    let mut initial = None;
    for peer in peers {
        if peer.keys.private != private || (!dual && peer.endpoint.is_ipv4() != local.is_ipv4()) {
            return Err(invalid());
        }
        let id = hub.add(
            peer.keys.public,
            peer.keys.preshared,
            peer.keys.keepalive,
            peer.allowed,
            Some(peer.endpoint),
        )?;
        if warp {
            initial = hub.initiate(id);
        }
    }
    Ok((hub, initial))
}

impl PacketTx {
    pub fn send(&self, packet: Vec<u8>) -> io::Result<()> {
        let dst = Tunn::dst_address(&packet).filter(|dst| {
            self.allowed
                .as_ref()
                .is_none_or(|allowed| contains(allowed, dst))
        });
        if packet.len() > self.mtu || dst.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet outside WireGuard MTU or allowed IPs",
            ));
        }
        self.tx.try_send(packet).map_err(|error| -> io::Error {
            match error {
                TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                TrySendError::Disconnected(_) => io::ErrorKind::BrokenPipe.into(),
            }
        })?;
        self.wake.unpark();
        Ok(())
    }
}

#[cfg(feature = "tun-device")]
fn open_carrier(bind: SocketAddr, dual: bool, mark: u32) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if bind.is_ipv6() {
        socket.set_only_v6(!dual)?;
    }
    #[cfg(target_os = "linux")]
    if mark != 0 {
        socket.set_mark(mark)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = mark;
    socket.bind(&bind.into())?;
    Ok(socket.into())
}

impl PacketRx {
    pub fn recv_for(&self, wait: Duration) -> io::Result<Vec<u8>> {
        self.0.recv_timeout(wait).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut.into(),
            mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe.into(),
        })
    }
}

pub(crate) fn contains(allowed: &[IpNet], addr: &IpAddr) -> bool {
    allowed.iter().any(|net| net.contains(addr))
}

fn deliver(
    socket: &UdpSocket,
    dual: bool,
    reserved: Reserved,
    inbound: &SyncSender<Vec<u8>>,
    event: HubEvent,
) {
    deliver_via(
        dual,
        reserved,
        event,
        |endpoint, frame| {
            let _ = socket.send_to(&frame, endpoint);
        },
        |frame| {
            let _ = inbound.try_send(frame);
        },
    );
}

fn deliver_via(
    dual: bool,
    reserved: Reserved,
    event: HubEvent,
    send: impl FnOnce(SocketAddr, Vec<u8>),
    receive: impl FnOnce(Vec<u8>),
) {
    match event {
        HubEvent::Datagram(mut endpoint, mut frame) => {
            endpoint = carrier_endpoint(endpoint, dual);
            reserved.apply(&mut frame, false);
            send(endpoint, frame);
        }
        HubEvent::Packet(_, _, frame) => receive(frame),
    }
}

fn carrier_endpoint(endpoint: SocketAddr, dual: bool) -> SocketAddr {
    match (dual, endpoint) {
        (true, SocketAddr::V4(v4)) => (v4.ip().to_ipv6_mapped(), v4.port()).into(),
        _ => endpoint,
    }
}

fn unmapped(source: SocketAddr, dual: bool) -> SocketAddr {
    match (dual, source) {
        (true, SocketAddr::V6(addr)) => addr
            .ip()
            .to_ipv4_mapped()
            .map_or(source, |v4| (v4, addr.port()).into()),
        _ => source,
    }
}

fn run(
    socket: &UdpSocket,
    dual: bool,
    mut hub: Hub,
    outbound: Receiver<Vec<u8>>,
    reserved: Reserved,
    warp: Option<SocketAddr>,
    emit: impl Fn(HubEvent),
) {
    let mut packet = vec![0; WIRE_BUFFER];
    loop {
        let mut busy = false;
        for _ in 0..QUEUE {
            match outbound.try_recv() {
                Ok(data) => {
                    if let Some(event) = hub.send(&data) {
                        emit(event);
                    }
                    busy = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        hub.tick(&emit);
        for _ in 0..32 {
            match socket.recv_from(&mut packet) {
                Ok((n, from)) if n != 0 => {
                    let from = unmapped(from, dual);
                    if warp.is_some_and(|endpoint| endpoint != from) {
                        continue;
                    }
                    busy = true;
                    reserved.apply(&mut packet[..n], true);
                    hub.receive(from, &packet[..n], &emit);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        if !busy {
            thread::park_timeout(POLL);
        }
    }
}
