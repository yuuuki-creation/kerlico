use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use smoltcp::iface::{Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, State};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv6Address, UdpPacket,
};

use crate::fragments::Reassembly;
use crate::stack::{fragment_udp, header, ipv6_transport, parse_ip, udp_packet};
use crate::{IpNet, PacketLink, PeerId, PeerKeys, Reserved};
use rand_core::{OsRng, RngCore};

pub struct Profile {
    pub private_key: [u8; 32],
    pub peer_public: [u8; 32],
    pub endpoint: SocketAddr,
    pub addresses: Vec<IpAddr>,
    pub reserved: [u8; 3],
    pub mtu: usize,
}

enum Op {
    OpenTcp(SocketAddr, Sender<io::Result<Arc<Mutex<Flow>>>>),
    OpenUdp(SocketAddr, Sender<io::Result<Arc<Mutex<Flow>>>>),
    BindUdp(Option<bool>, Sender<io::Result<DatagramPort>>),
}

const FLOW_BYTES: usize = 64 * 1024;
const FLOW_PACKETS: usize = 32;

pub(crate) struct Flow {
    stream: bool,
    incoming: VecDeque<u8>,
    pub(crate) packets: VecDeque<Vec<u8>>,
    outgoing: VecDeque<u8>,
    pub(crate) datagrams: VecDeque<Vec<u8>>,
    pub(crate) established: bool,
    pub(crate) failed: bool,
    pub(crate) closed: bool,
    pub(crate) dropped: bool,
    read_done: bool,
    write_done: bool,
    remote: SocketAddr,
    opened: Instant,
}

impl Flow {
    pub(crate) fn new(stream: bool, remote: SocketAddr) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            stream,
            incoming: VecDeque::new(),
            packets: VecDeque::new(),
            outgoing: VecDeque::new(),
            datagrams: VecDeque::new(),
            established: !stream,
            failed: false,
            closed: false,
            dropped: false,
            read_done: false,
            write_done: false,
            remote,
            opened: Instant::now(),
        }))
    }

    pub(crate) fn receive_udp(&mut self, packet: &[u8]) {
        if self.packets.len() < FLOW_PACKETS && !self.closed {
            self.packets.push_back(packet.to_vec());
        }
    }
}

struct Live {
    flow: Arc<Mutex<Flow>>,
    handle: smoltcp::iface::SocketHandle,
    local_port: u16,
}

struct LiveUdp {
    local: Vec<SocketAddr>,
    kind: UdpKind,
}

type UdpPacketBody = (SocketAddr, Vec<u8>);

enum UdpKind {
    Connected(Arc<Mutex<Flow>>),
    Bound {
        requests: Receiver<UdpPacketBody>,
        replies: SyncSender<UdpPacketBody>,
    },
}

struct DatagramPort {
    tx: SyncSender<UdpPacketBody>,
    rx: Receiver<UdpPacketBody>,
}

/// An unconnected UDP port in the userspace tunnel. Replies retain the actual source.
pub struct Datagrams {
    tx: SyncSender<UdpPacketBody>,
    rx: Mutex<Receiver<UdpPacketBody>>,
    ipv4: bool,
    ipv6: bool,
    allowed: Vec<IpNet>,
}

impl Datagrams {
    pub fn send_to(&self, target: SocketAddr, data: &[u8]) -> io::Result<()> {
        if target.port() == 0
            || !(if target.is_ipv4() {
                self.ipv4
            } else {
                self.ipv6
            })
            || !crate::packet::contains(&self.allowed, &target.ip())
            || data.len() > if target.is_ipv4() { 65_507 } else { 65_527 }
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.tx
            .try_send((target, data.to_vec()))
            .map_err(|error| match error {
                TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                TrySendError::Disconnected(_) => io::ErrorKind::BrokenPipe.into(),
            })
    }

    pub fn recv_for(&self, timeout: Duration) -> io::Result<(SocketAddr, Vec<u8>)> {
        self.rx
            .lock()
            .expect("WireGuard UDP port")
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut.into(),
                mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe.into(),
            })
    }
}

pub struct Tunnel {
    cmd: Sender<Op>,
    has_v4: bool,
    has_v6: bool,
    allowed: Vec<IpNet>,
    running: Arc<AtomicBool>,
}

impl Tunnel {
    pub fn spawn(profile: Profile, socket: UdpSocket) -> io::Result<Self> {
        let mtu = profile.mtu.max(1280);
        let allowed = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
        let keys = PeerKeys {
            private: profile.private_key,
            public: profile.peer_public,
            preshared: None,
            keepalive: 25,
        };
        let link = PacketLink::start_with_reserved(
            socket,
            profile.endpoint,
            keys,
            allowed,
            mtu,
            Reserved::Warp(profile.reserved),
        )?;
        Self::from_link(profile.addresses, mtu, link)
    }

    pub fn from_link(addresses: Vec<IpAddr>, mtu: usize, link: PacketLink) -> io::Result<Self> {
        let has_v4 = addresses.iter().any(|addr| addr.is_ipv4());
        let has_v6 = addresses.iter().any(|addr| addr.is_ipv6());
        if addresses.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let allowed = link.prefixes().to_vec();
        let (cmd, rx) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let alive = running.clone();
        thread::Builder::new()
            .name("kerlico-wireguard-stack".into())
            .spawn(move || {
                struct Done(Arc<AtomicBool>);
                impl Drop for Done {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _done = Done(alive);
                run(addresses, mtu, link, rx);
            })?;
        Ok(Self {
            cmd,
            has_v4,
            has_v6,
            allowed,
            running,
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub fn connect_tcp(&self, addr: SocketAddr) -> io::Result<Pipe> {
        self.open(addr, true)
    }

    pub fn connect_udp(&self, addr: SocketAddr) -> io::Result<Pipe> {
        self.open(addr, false)
    }

    pub fn associate_udp(&self, ipv4: bool) -> io::Result<Datagrams> {
        self.bind_datagrams(Some(ipv4))
    }

    pub fn associate_all_udp(&self) -> io::Result<Datagrams> {
        self.bind_datagrams(None)
    }

    fn bind_datagrams(&self, family: Option<bool>) -> io::Result<Datagrams> {
        let ipv4 = self.has_v4 && family != Some(false);
        let ipv6 = self.has_v6 && family != Some(true);
        if !(ipv4 || ipv6) {
            return Err(io::ErrorKind::AddrNotAvailable.into());
        }
        let (reply, response) = mpsc::channel();
        self.cmd
            .send(Op::BindUdp(family, reply))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        let port = response
            .recv_timeout(Duration::from_secs(3))
            .map_err(|err| match err {
                mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
            })??;
        Ok(Datagrams {
            tx: port.tx,
            rx: Mutex::new(port.rx),
            ipv4,
            ipv6,
            allowed: self.allowed.clone(),
        })
    }

    fn open(&self, addr: SocketAddr, tcp: bool) -> io::Result<Pipe> {
        let missing = addr.is_ipv4() && !self.has_v4 || addr.is_ipv6() && !self.has_v6;
        if missing || !crate::packet::contains(&self.allowed, &addr.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "warp family",
            ));
        }
        let (tx, rx) = mpsc::channel();
        let op = if tcp {
            Op::OpenTcp(addr, tx)
        } else {
            Op::OpenUdp(addr, tx)
        };
        self.cmd
            .send(op)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "warp"))?;
        let flow = rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "warp"))??;
        let start = Instant::now();
        loop {
            let guard = flow.lock().expect("flow");
            if guard.established {
                break;
            }
            if guard.failed || guard.closed {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "warp"));
            }
            drop(guard);
            if start.elapsed() > Duration::from_secs(10) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "warp"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(Pipe { flow })
    }
}

pub struct Pipe {
    flow: Arc<Mutex<Flow>>,
}

impl Pipe {
    pub(crate) fn from_flow(flow: Arc<Mutex<Flow>>) -> Self {
        Self { flow }
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut flow = self.flow.lock().expect("flow");
        if flow.failed {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        if flow.stream {
            if flow.incoming.is_empty() {
                return if flow.closed || flow.read_done {
                    Ok(0)
                } else {
                    Err(io::Error::new(io::ErrorKind::WouldBlock, "warp"))
                };
            }
            let n = flow.incoming.len().min(buf.len());
            for (slot, byte) in buf.iter_mut().zip(flow.incoming.drain(..n)) {
                *slot = byte;
            }
            return Ok(n);
        }
        if let Some(packet) = flow.packets.pop_front() {
            let n = packet.len();
            if n > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WireGuard UDP receive buffer too short",
                ));
            }
            buf[..n].copy_from_slice(&packet[..n]);
            return Ok(n);
        }
        if flow.closed {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "warp"))
        }
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut flow = self.flow.lock().expect("flow");
        if flow.closed || flow.failed || flow.write_done {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "warp"));
        }
        if flow.stream {
            let n = buf
                .len()
                .min(FLOW_BYTES.saturating_sub(flow.outgoing.len()));
            if n == 0 && !buf.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            flow.outgoing.extend(buf[..n].iter().copied());
            return Ok(n);
        } else {
            if flow.datagrams.len() >= FLOW_PACKETS {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            flow.datagrams.push_back(buf.to_vec());
        }
        Ok(buf.len())
    }

    pub fn finish(&self) -> bool {
        let mut flow = self.flow.lock().expect("flow");
        if !flow.stream {
            return false;
        }
        flow.write_done = true;
        true
    }

    pub fn abort(&self) {
        self.flow.lock().expect("flow").failed = true;
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        self.flow.lock().expect("flow").dropped = true;
    }
}

fn run(addresses: Vec<IpAddr>, mtu: usize, link: PacketLink, cmd: Receiver<Op>) {
    let mut device = IpDev {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
        mtu,
    };
    let mut config = smoltcp::iface::Config::new(HardwareAddress::Ip);
    config.random_seed = OsRng.next_u64();
    let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::now());
    iface.update_ip_addrs(|addrs| {
        for addr in &addresses {
            let cidr = match addr {
                IpAddr::V4(ip) => {
                    let o = ip.octets();
                    IpCidr::new(
                        IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])),
                        32,
                    )
                }
                IpAddr::V6(ip) => {
                    let s = ip.segments();
                    IpCidr::new(
                        IpAddress::Ipv6(Ipv6Address::new(
                            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                        )),
                        128,
                    )
                }
            };
            addrs.push(cidr).ok();
        }
    });
    if let Some(IpAddr::V4(ip)) = addresses.iter().copied().find(|addr| addr.is_ipv4()) {
        let o = ip.octets();
        let gateway = Ipv4Address::new(o[0], o[1], o[2], if o[3] == 1 { 2 } else { 1 });
        iface.routes_mut().add_default_ipv4_route(gateway).ok();
    }
    if addresses.iter().any(|addr| addr.is_ipv6()) {
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
            .ok();
    }
    let mut sockets = SocketSet::new(vec![]);
    let mut live = Vec::new();
    let mut udp = HashMap::new();
    let mut next_port = 20_000 + (OsRng.next_u32() % 40_000) as u16;
    let mut ident = OsRng.next_u32();
    let mut fragments = Reassembly::default();
    'running: loop {
        for _ in 0..64 {
            match cmd.try_recv() {
                Ok(op) => open_one(
                    &mut sockets,
                    &mut live,
                    &mut udp,
                    &mut iface,
                    &addresses,
                    &mut next_port,
                    op,
                ),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break 'running,
            }
        }
        match link.recv_for(Duration::from_millis(2)) {
            Ok(packet) => receive(packet, &mut device, &udp, &mut fragments),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        for _ in 0..127 {
            match link.recv_for(Duration::ZERO) {
                Ok(packet) => receive(packet, &mut device, &udp, &mut fragments),
                Err(_) => break,
            }
        }
        iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
        for item in &live {
            service_tcp(
                sockets.get_mut::<tcp::Socket>(item.handle),
                &mut item.flow.lock().expect("flow"),
            );
        }
        udp.retain(|_, item| {
            let mut send = |remote: SocketAddr, data: &[u8]| {
                let Some(source) = item
                    .local
                    .iter()
                    .copied()
                    .find(|ip| ip.is_ipv4() == remote.is_ipv4())
                else {
                    return;
                };
                if let Some(packet) = udp_packet(data, source, remote) {
                    if packet.len() <= mtu {
                        let _ = link.send(packet);
                    } else {
                        ident = ident.wrapping_add(1);
                        fragment_udp(&packet, source.ip(), remote.ip(), mtu, ident, |fragment| {
                            let _ = link.send(fragment);
                        });
                    }
                }
            };
            match &item.kind {
                UdpKind::Connected(flow) => {
                    let mut flow = flow.lock().expect("WireGuard UDP flow");
                    if flow.dropped || flow.closed || flow.failed {
                        return false;
                    }
                    for _ in 0..8 {
                        let Some(data) = flow.datagrams.pop_front() else {
                            break;
                        };
                        send(flow.remote, &data);
                    }
                }
                UdpKind::Bound { requests, .. } => {
                    for _ in 0..8 {
                        match requests.try_recv() {
                            Ok((remote, data)) => send(remote, &data),
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => return false,
                        }
                    }
                }
            }
            true
        });
        iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
        while let Some(ip) = device.tx.pop_front() {
            let _ = link.send(ip);
        }
        live.retain(|item| {
            let flow = item.flow.lock().expect("flow");
            // Keep a socket with a pending abort for the next poll to emit RST.
            let remove = (flow.closed || flow.failed)
                && sockets.get::<tcp::Socket>(item.handle).state() == State::Closed;
            drop(flow);
            if remove {
                sockets.remove(item.handle);
            }
            !remove
        });
    }
    for item in live {
        item.flow.lock().expect("flow").closed = true;
    }
    for item in udp.into_values() {
        if let UdpKind::Connected(flow) = item.kind {
            flow.lock().expect("flow").closed = true;
        }
    }
}

fn receive(
    packet: Vec<u8>,
    device: &mut IpDev,
    udp: &HashMap<u16, LiveUdp>,
    fragments: &mut Reassembly,
) {
    let Some(mut ip) = parse_ip(&packet) else {
        return;
    };
    if ip.fragment.is_none() && ip.protocol != IpProtocol::Udp {
        device.rx.push_back(packet);
        return;
    }
    let body;
    if let Some(fragment) = ip.fragment {
        let Some(joined) =
            fragments.insert(PeerId(0), ip.src, ip.dst, ip.protocol, fragment, ip.payload)
        else {
            return;
        };
        body = joined;
        if ip.src.is_ipv6() {
            let Some((kind, payload)) = ipv6_transport(ip.protocol, &body, false) else {
                return;
            };
            ip.protocol = kind;
            ip.payload = payload;
        } else {
            ip.payload = &body;
        }
    }
    if ip.protocol != IpProtocol::Udp {
        if let Some((mut packet, offset)) = header(ip.src, ip.dst, ip.protocol, ip.payload.len()) {
            packet[offset..].copy_from_slice(ip.payload);
            device.rx.push_back(packet);
        }
        return;
    }
    let Ok(datagram) = UdpPacket::new_checked(ip.payload) else {
        return;
    };
    let Some(item) = udp.get(&datagram.dst_port()) else {
        return;
    };
    if !item.local.iter().any(|address| address.ip() == ip.dst)
        || (datagram.checksum() == 0 && ip.src.is_ipv6())
        || (datagram.checksum() != 0
            && !datagram.verify_checksum(&crate::stack::smol(ip.src), &crate::stack::smol(ip.dst)))
    {
        return;
    }
    let source = SocketAddr::new(ip.src, datagram.src_port());
    if source.port() == 0 {
        return;
    }
    match &item.kind {
        UdpKind::Connected(flow) => {
            let mut flow = flow.lock().expect("WireGuard UDP flow");
            if flow.remote == source {
                flow.receive_udp(datagram.payload());
            }
        }
        UdpKind::Bound { replies, .. } => {
            let _ = replies.try_send((source, datagram.payload().to_vec()));
        }
    }
}

fn open_one(
    sockets: &mut SocketSet<'static>,
    live: &mut Vec<Live>,
    udp: &mut HashMap<u16, LiveUdp>,
    iface: &mut Interface,
    addresses: &[IpAddr],
    next_port: &mut u16,
    op: Op,
) {
    let (addr, reply, tcp) = match op {
        Op::OpenTcp(addr, reply) => (addr, reply, true),
        Op::OpenUdp(addr, reply) => (addr, reply, false),
        Op::BindUdp(family, reply) => {
            let bind = (|| {
                if udp.len() >= 1024 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let port = allocate_port(next_port, |port| udp.contains_key(&port));
                let local: Vec<_> = [true, false]
                    .into_iter()
                    .filter(|ipv4| family.is_none_or(|f| *ipv4 == f))
                    .filter_map(|ipv4| addresses.iter().find(|ip| ip.is_ipv4() == ipv4).copied())
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect();
                if local.is_empty() {
                    return Err(io::ErrorKind::AddrNotAvailable.into());
                }
                let (tx, requests) = mpsc::sync_channel(FLOW_PACKETS);
                let (replies, rx) = mpsc::sync_channel(FLOW_PACKETS);
                udp.insert(
                    port,
                    LiveUdp {
                        local,
                        kind: UdpKind::Bound { requests, replies },
                    },
                );
                Ok(DatagramPort { tx, rx })
            })();
            let _ = reply.send(bind);
            return;
        }
    };
    if if tcp {
        live.len() >= 1024
    } else {
        udp.len() >= 1024
    } {
        let _ = reply.send(Err(io::ErrorKind::WouldBlock.into()));
        return;
    }
    let port = allocate_port(next_port, |port| {
        if tcp {
            live.iter().any(|item| item.local_port == port)
        } else {
            udp.contains_key(&port)
        }
    });
    let flow = Flow::new(tcp, addr);
    if !tcp {
        let Some(local) = addresses
            .iter()
            .copied()
            .find(|ip| ip.is_ipv4() == addr.is_ipv4())
        else {
            let _ = reply.send(Err(io::ErrorKind::AddrNotAvailable.into()));
            return;
        };
        udp.insert(
            port,
            LiveUdp {
                local: vec![SocketAddr::new(local, port)],
                kind: UdpKind::Connected(flow.clone()),
            },
        );
        let _ = reply.send(Ok(flow));
        return;
    }
    let remote = smol(addr);
    let handle = {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65_536]),
            tcp::SocketBuffer::new(vec![0; 65_536]),
        );
        if socket.connect(iface.context(), remote, port).is_err() {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "warp",
            )));
            return;
        }
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(300)));
        sockets.add(socket)
    };
    live.push(Live {
        flow: Arc::clone(&flow),
        handle,
        local_port: port,
    });
    let _ = reply.send(Ok(flow));
}

fn allocate_port(next_port: &mut u16, used: impl Fn(u16) -> bool) -> u16 {
    loop {
        let port = *next_port;
        *next_port = if port == 60_000 { 20_000 } else { port + 1 };
        if !used(port) {
            return port;
        }
    }
}

pub(crate) fn service_tcp(socket: &mut tcp::Socket<'_>, flow: &mut Flow) {
    if flow.failed
        || (flow.dropped && !flow.write_done)
        || (!flow.established && flow.opened.elapsed() > Duration::from_secs(8))
    {
        socket.abort();
        flow.failed = true;
        return;
    }
    if socket.state() == State::Established || socket.may_send() {
        flow.established = true;
    }
    while socket.can_recv() {
        let capacity = FLOW_BYTES.saturating_sub(flow.incoming.len());
        if capacity == 0 {
            break;
        }
        if socket
            .recv(|data| {
                let n = capacity.min(data.len());
                flow.incoming.extend(&data[..n]);
                (n, ())
            })
            .is_err()
        {
            break;
        }
    }
    if flow.established && !socket.may_recv() {
        flow.read_done = true;
    }
    if socket.can_send() && !flow.outgoing.is_empty() {
        let (front, _) = flow.outgoing.as_slices();
        if let Ok(n) = socket.send_slice(front) {
            flow.outgoing.drain(..n);
        }
    }
    if flow.write_done && flow.outgoing.is_empty() && socket.may_send() {
        socket.close();
    }
    if flow.established && matches!(socket.state(), State::Closed | State::TimeWait) {
        flow.closed = true;
    }
}

fn smol(addr: SocketAddr) -> (IpAddress, u16) {
    match addr {
        SocketAddr::V4(addr) => {
            let o = addr.ip().octets();
            (
                IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])),
                addr.port(),
            )
        }
        SocketAddr::V6(addr) => {
            let s = addr.ip().segments();
            (
                IpAddress::Ipv6(Ipv6Address::new(
                    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                )),
                addr.port(),
            )
        }
    }
}

pub(crate) struct IpDev {
    pub(crate) rx: VecDeque<Vec<u8>>,
    pub(crate) tx: VecDeque<Vec<u8>>,
    pub(crate) mtu: usize,
}

impl Device for IpDev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((RxTok(packet), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub(crate) struct RxTok(Vec<u8>);

impl RxToken for RxTok {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

pub(crate) struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for TxTok<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let out = f(&mut buf);
        self.0.push_back(buf);
        out
    }
}
