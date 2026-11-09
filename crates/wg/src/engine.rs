use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use smoltcp::iface::{Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, State};
use smoltcp::socket::udp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};

use crate::noise::Link;

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
}

struct Flow {
    stream: bool,
    incoming: VecDeque<u8>,
    packets: VecDeque<Vec<u8>>,
    outgoing: VecDeque<u8>,
    datagrams: VecDeque<Vec<u8>>,
    established: bool,
    failed: bool,
    closed: bool,
    remote: SocketAddr,
    opened: Instant,
}

struct Live {
    flow: Arc<Mutex<Flow>>,
    handle: smoltcp::iface::SocketHandle,
    tcp: bool,
}

pub struct Tunnel {
    cmd: Sender<Op>,
    has_v4: bool,
    has_v6: bool,
}

impl Tunnel {
    pub fn spawn(profile: Profile) -> io::Result<Self> {
        let has_v4 = profile.addresses.iter().any(|addr| addr.is_ipv4());
        let has_v6 = profile.addresses.iter().any(|addr| addr.is_ipv6());
        let (cmd, rx) = mpsc::channel();
        thread::Builder::new()
            .name("kerlico-warp".into())
            .spawn(move || run(profile, rx))?;
        Ok(Self { cmd, has_v4, has_v6 })
    }

    pub fn connect_tcp(&self, addr: SocketAddr) -> io::Result<Pipe> {
        self.open(addr, true)
    }

    pub fn connect_udp(&self, addr: SocketAddr) -> io::Result<Pipe> {
        self.open(addr, false)
    }

    fn open(&self, addr: SocketAddr, tcp: bool) -> io::Result<Pipe> {
        let missing = addr.is_ipv4() && !self.has_v4 || addr.is_ipv6() && !self.has_v6;
        if missing {
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "warp family"));
        }
        let (tx, rx) = mpsc::channel();
        let op = if tcp { Op::OpenTcp(addr, tx) } else { Op::OpenUdp(addr, tx) };
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
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut flow = self.flow.lock().expect("flow");
        if flow.stream {
            if flow.incoming.is_empty() {
                return if flow.closed {
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
            let n = packet.len().min(buf.len());
            buf[..n].copy_from_slice(&packet[..n]);
            return Ok(n);
        }
        if flow.closed {
            Ok(0)
        } else {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "warp"))
        }
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut flow = self.flow.lock().expect("flow");
        if flow.closed || flow.failed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "warp"));
        }
        if flow.stream {
            flow.outgoing.extend(buf.iter().copied());
        } else {
            flow.datagrams.push_back(buf.to_vec());
        }
        Ok(buf.len())
    }
}

fn run(profile: Profile, cmd: Receiver<Op>) {
    let Ok(udp) = bind_udp(profile.endpoint) else {
        return;
    };
    udp.set_read_timeout(Some(Duration::from_millis(10))).ok();
    let reserved = profile.reserved;
    let mut link = Link::new(profile.private_key, profile.peer_public);
    let mut device = IpDev {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
        mtu: profile.mtu.max(1280),
    };
    let mut config = smoltcp::iface::Config::new(HardwareAddress::Ip);
    config.random_seed = 0x6b65_726c;
    let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::now());
    iface.update_ip_addrs(|addrs| {
        for addr in &profile.addresses {
            let cidr = match addr {
                IpAddr::V4(ip) => {
                    let o = ip.octets();
                    IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])), 32)
                }
                IpAddr::V6(ip) => {
                    let s = ip.segments();
                    IpCidr::new(
                        IpAddress::Ipv6(Ipv6Address::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])),
                        128,
                    )
                }
            };
            addrs.push(cidr).ok();
        }
    });
    if let Some(IpAddr::V4(ip)) = profile.addresses.iter().copied().find(|addr| addr.is_ipv4()) {
        let o = ip.octets();
        let gateway = Ipv4Address::new(o[0], o[1], o[2], if o[3] == 1 { 2 } else { 1 });
        iface.routes_mut().add_default_ipv4_route(gateway).ok();
    }
    if profile.addresses.iter().any(|addr| addr.is_ipv6()) {
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
            .ok();
    }
    let mut sockets = SocketSet::new(vec![]);
    let mut live = Vec::new();
    let mut next_port = 20_000u16;
    let mut last_hello = Instant::now() - Duration::from_secs(10);
    let mut last_sent = Instant::now();
    loop {
        while let Ok(op) = cmd.try_recv() {
            open_one(&mut sockets, &mut live, &mut iface, &mut next_port, op);
        }
        let mut packet = [0u8; 2048];
        if let Ok(n) = udp.recv(&mut packet) {
            clear_reserved(&mut packet[..n]);
            if let Some(ip) = link.input(&packet[..n]) {
                if !ip.is_empty() {
                    device.rx.push_back(ip);
                }
            }
            for sealed in link.drain() {
                send_udp(&udp, sealed, reserved);
                last_sent = Instant::now();
            }
        }
        if !link.ready() && last_hello.elapsed() > Duration::from_secs(5) {
            send_udp(&udp, link.initiation(), reserved);
            last_hello = Instant::now();
        }
        iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
        while let Some(ip) = device.tx.pop_front() {
            if let Some(sealed) = link.seal(&ip) {
                send_udp(&udp, sealed, reserved);
                last_sent = Instant::now();
            } else {
                link.queue(ip);
                if last_hello.elapsed() > Duration::from_secs(1) {
                    send_udp(&udp, link.initiation(), reserved);
                    last_hello = Instant::now();
                }
            }
        }
        if link.ready() && last_sent.elapsed() > Duration::from_secs(25) {
            if let Some(sealed) = link.seal(&[]) {
                send_udp(&udp, sealed, reserved);
                last_sent = Instant::now();
            }
        }
        service(&mut sockets, &live);
        thread::sleep(Duration::from_millis(2));
    }
}

fn open_one(
    sockets: &mut SocketSet<'static>,
    live: &mut Vec<Live>,
    iface: &mut Interface,
    next_port: &mut u16,
    op: Op,
) {
    let (addr, reply, tcp) = match op {
        Op::OpenTcp(addr, reply) => (addr, reply, true),
        Op::OpenUdp(addr, reply) => (addr, reply, false),
    };
    let port = *next_port;
    *next_port = if *next_port > 60_000 { 20_000 } else { *next_port + 1 };
    let remote = smol(addr);
    let handle = if tcp {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65_536]),
            tcp::SocketBuffer::new(vec![0; 65_536]),
        );
        if socket.connect(iface.context(), remote, port).is_err() {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "warp")));
            return;
        }
        sockets.add(socket)
    } else {
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65_536]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65_536]),
        );
        if socket.bind(port).is_err() {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::AddrInUse, "warp")));
            return;
        }
        sockets.add(socket)
    };
    let flow = Arc::new(Mutex::new(Flow {
        stream: tcp,
        incoming: VecDeque::new(),
        packets: VecDeque::new(),
        outgoing: VecDeque::new(),
        datagrams: VecDeque::new(),
        established: !tcp,
        failed: false,
        closed: false,
        remote: addr,
        opened: Instant::now(),
    }));
    live.push(Live {
        flow: Arc::clone(&flow),
        handle,
        tcp,
    });
    let _ = reply.send(Ok(flow));
}

fn service(sockets: &mut SocketSet<'static>, live: &[Live]) {
    for item in live {
        let mut flow = item.flow.lock().expect("flow");
        if item.tcp {
            let socket = sockets.get_mut::<tcp::Socket>(item.handle);
            let state = socket.state();
            if state == State::Established || socket.may_send() {
                flow.established = true;
            }
            if matches!(state, State::Closed | State::TimeWait) {
                if flow.established {
                    flow.closed = true;
                } else if flow.opened.elapsed() > Duration::from_secs(8) {
                    flow.failed = true;
                }
            }
            let mut got = Vec::new();
            while socket.can_recv() {
                if socket
                    .recv(|data| {
                        got.extend_from_slice(data);
                        (data.len(), ())
                    })
                    .is_err()
                {
                    break;
                }
            }
            flow.incoming.extend(got);
            if socket.can_send() && !flow.outgoing.is_empty() {
                let chunk: Vec<u8> = flow.outgoing.iter().copied().take(2048).collect();
                if let Ok(n) = socket.send_slice(&chunk) {
                    flow.outgoing.drain(..n);
                }
            }
        } else {
            let socket = sockets.get_mut::<udp::Socket>(item.handle);
            flow.established = true;
            let mut got = Vec::new();
            while socket.can_recv() {
                match socket.recv() {
                    Ok((data, _)) => got.push(data.to_vec()),
                    Err(_) => break,
                }
            }
            flow.packets.extend(got);
            if let Some(packet) = flow.datagrams.pop_front() {
                let remote = smol(flow.remote);
                if socket.send_slice(&packet, remote).is_err() {
                    flow.datagrams.push_front(packet);
                }
            }
        }
    }
}

fn send_udp(udp: &UdpSocket, mut packet: Vec<u8>, reserved: [u8; 3]) {
    stamp(&mut packet, reserved);
    let _ = udp.send(&packet);
}

fn stamp(packet: &mut [u8], reserved: [u8; 3]) {
    if packet.first() == Some(&4) && packet.len() >= 4 {
        packet[1] = reserved[0];
        packet[2] = reserved[1];
        packet[3] = reserved[2];
    }
}

fn clear_reserved(packet: &mut [u8]) {
    if packet.first() == Some(&4) && packet.len() >= 4 {
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
    }
}

fn bind_udp(endpoint: SocketAddr) -> io::Result<UdpSocket> {
    let bind = if endpoint.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(endpoint)?;
    Ok(socket)
}

fn smol(addr: SocketAddr) -> (IpAddress, u16) {
    match addr {
        SocketAddr::V4(addr) => {
            let o = addr.ip().octets();
            (IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])), addr.port())
        }
        SocketAddr::V6(addr) => {
            let s = addr.ip().segments();
            (
                IpAddress::Ipv6(Ipv6Address::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])),
                addr.port(),
            )
        }
    }
}

struct IpDev {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Device for IpDev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _timestamp: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
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

struct RxTok(Vec<u8>);

impl RxToken for RxTok {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

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
