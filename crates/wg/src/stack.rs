//! Turns authenticated IP traffic into TCP and UDP flows without dialing it.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, ChecksumCapabilities};
use smoltcp::socket::tcp::{self, State};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    TcpPacket, UdpPacket,
};

use crate::engine::{service_tcp, Flow, IpDev, Pipe, StackWake, UdpDriver, FLOW_PACKETS};
use crate::fragments::{Fragment, Reassembly};
use crate::wire::MAX_IP_PACKET;
use crate::PeerId;

const MAX_TCP: usize = 1024;
const MAX_UDP: usize = 1024;
const IDLE: Duration = Duration::from_secs(300);
const V4_LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V4_PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const V6_LOCAL: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V6_PEER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

pub struct Incoming {
    pub peer: PeerId,
    pub endpoint: SocketAddr,
    pub target: SocketAddr,
    pub protocol: Protocol,
    pub pipe: Pipe,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Key {
    peer: PeerId,
    src: SocketAddr,
    dst: SocketAddr,
}

struct TcpSlot {
    key: Key,
    endpoint: SocketAddr,
    handle: SocketHandle,
    flow: Arc<Mutex<Flow>>,
    offered: bool,
}

struct UdpSlot {
    route: UdpRoute,
    seen: Instant,
}

enum UdpRoute {
    Pipe(Arc<Mutex<Flow>>),
    Connected { driver: UdpDriver, requests: VecDeque<Vec<u8>> },
}

impl UdpRoute {
    fn close(&self) {
        if let Self::Pipe(flow) = self {
            flow.lock().expect("UDP flow").close();
        }
    }
}

pub struct Stack {
    device: IpDev,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp_index: HashMap<Key, u16>,
    tcp: HashMap<u16, TcpSlot>,
    udp: HashMap<Key, UdpSlot>,
    udp_receive: Vec<u8>,
    next: u16,
    fragment_id: u32,
    fragments: Reassembly,
    tcp_limit: usize,
    tcp_nodelay: bool,
    tcp_congestion: tcp::CongestionControl,
    tcp_buffers: (usize, usize),
    udp_limit: usize,
    wake: Option<StackWake>,
}

impl Stack {
    pub fn new(mtu: usize) -> io::Result<Self> {
        Self::with_limits(mtu, MAX_TCP, MAX_UDP)
    }

    pub fn with_limits(mtu: usize, tcp_limit: usize, udp_limit: usize) -> io::Result<Self> {
        if !(576..=MAX_IP_PACKET).contains(&mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IP stack MTU",
            ));
        }
        let mut device = IpDev {
            rx: Default::default(),
            tx: Default::default(),
            mtu,
            // TCP checksums cover the external addresses and ports, so verify
            // ingress and fill egress at the translation boundary.
            tcp_checksum: Checksum::None,
        };
        let mut config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        config.random_seed = OsRng.next_u64();
        let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(V4_LOCAL.into(), 30))
                .expect("IPv4 stack address");
            addrs
                .push(IpCidr::new(V6_LOCAL.into(), 126))
                .expect("IPv6 stack address");
        });
        Ok(Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            tcp_index: HashMap::new(),
            tcp: HashMap::new(),
            udp: HashMap::new(),
            udp_receive: Vec::new(),
            next: 1024,
            fragment_id: OsRng.next_u32(),
            fragments: Reassembly::default(),
            tcp_limit,
            tcp_nodelay: false,
            tcp_congestion: tcp::CongestionControl::None,
            tcp_buffers: (32 * 1024, 32 * 1024),
            udp_limit,
            wake: None,
        })
    }

    pub fn set_wake(&mut self, wake: impl Fn() + Send + Sync + 'static) {
        self.wake = Some(Arc::new(wake));
    }

    pub fn enable_tcp_nodelay(&mut self) {
        self.tcp_nodelay = true;
    }

    /// Apply congestion control to subsequently accepted TCP flows.
    pub fn enable_tcp_cubic(&mut self) {
        self.tcp_congestion = tcp::CongestionControl::Cubic;
    }

    /// Set the receive and send capacities of subsequently accepted TCP flows.
    pub fn set_tcp_buffers(&mut self, receive: usize, send: usize) {
        assert!(receive > 0 && send > 0);
        self.tcp_buffers = (receive, send);
    }

    pub fn receive(
        &mut self,
        peer: PeerId,
        endpoint: SocketAddr,
        packet: &[u8],
    ) -> Option<Incoming> {
        self.receive_packet(peer, endpoint, Cow::Borrowed(packet))
    }

    pub fn receive_owned(
        &mut self,
        peer: PeerId,
        endpoint: SocketAddr,
        packet: Vec<u8>,
    ) -> Option<Incoming> {
        self.receive_packet(peer, endpoint, Cow::Owned(packet))
    }

    fn receive_packet(
        &mut self,
        peer: PeerId,
        endpoint: SocketAddr,
        packet: Cow<'_, [u8]>,
    ) -> Option<Incoming> {
        if packet.len() > self.device.mtu {
            return None;
        }
        let mut ip = parse_ip(&packet)?;
        let joined;
        if let Some(fragment) = ip.fragment {
            joined =
                self.fragments
                    .insert(peer, ip.src, ip.dst, ip.protocol, fragment, ip.payload)?;
            (ip.protocol, ip.payload) = if ip.src.is_ipv6() {
                ipv6_transport(ip.protocol, &joined, false)?
            } else {
                (ip.protocol, &joined[..])
            };
        }
        match ip.protocol {
            IpProtocol::Tcp => {
                let segment = TcpPacket::new_checked(ip.payload).ok()?;
                if !segment.verify_checksum(&smol(ip.src), &smol(ip.dst))
                    || segment.src_port() == 0
                    || segment.dst_port() == 0
                {
                    return None;
                }
                let key = Key {
                    peer,
                    src: SocketAddr::new(ip.src, segment.src_port()),
                    dst: SocketAddr::new(ip.dst, segment.dst_port()),
                };
                let port = if let Some(&port) = self.tcp_index.get(&key) {
                    port
                } else {
                    if !segment.syn() || segment.ack() || self.tcp.len() >= self.tcp_limit {
                        return None;
                    }
                    let port = self.port()?;
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0; self.tcp_buffers.0]),
                        tcp::SocketBuffer::new(vec![0; self.tcp_buffers.1]),
                    );
                    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(300)));
                    socket.set_nagle_enabled(!self.tcp_nodelay);
                    socket.set_congestion_control(self.tcp_congestion);
                    let (local, _) = aliases(ip.src);
                    socket.listen((smol(local), port)).ok()?;
                    let handle = self.sockets.add(socket);
                    self.tcp.insert(
                        port,
                        TcpSlot {
                            key,
                            endpoint,
                            handle,
                            flow: Flow::with_wake(true, key.src, self.wake.clone()),
                            offered: false,
                        },
                    );
                    self.tcp_index.insert(key, port);
                    port
                };
                if self.device.rx.len() < 128 {
                    let (local, remote) = aliases(ip.src);
                    let src = SocketAddr::new(remote, segment.src_port());
                    let dst = SocketAddr::new(local, port);
                    let offset = ip_header_len(remote);
                    let translated = match packet {
                        Cow::Owned(mut packet)
                            if ip.fragment.is_none()
                                && packet.len() == offset + ip.payload.len() =>
                        {
                            translate_tcp(&mut packet, src, dst, false);
                            packet
                        }
                        _ => {
                            let (mut packet, offset) =
                                header(src.ip(), dst.ip(), IpProtocol::Tcp, ip.payload.len())?;
                            packet[offset..].copy_from_slice(ip.payload);
                            set_tcp_endpoints(&mut packet[offset..], src, dst, false);
                            packet
                        }
                    };
                    self.device.rx.push_back(translated);
                }
                None
            }
            IpProtocol::Udp => {
                let body = UdpPacket::new_checked(ip.payload).ok()?;
                // IPv4 may omit its UDP checksum. IPv6 may not.
                if (body.checksum() == 0 && ip.src.is_ipv6())
                    || (body.checksum() != 0 && !body.verify_checksum(&smol(ip.src), &smol(ip.dst)))
                    || body.src_port() == 0
                    || body.dst_port() == 0
                {
                    return None;
                }
                let key = Key {
                    peer,
                    src: SocketAddr::new(ip.src, body.src_port()),
                    dst: SocketAddr::new(ip.dst, body.dst_port()),
                };
                let now = Instant::now();
                if let Some(entry) = self.udp.get_mut(&key) {
                    if now.duration_since(entry.seen) < IDLE {
                        match &mut entry.route {
                            UdpRoute::Connected { requests, .. } => {
                                entry.seen = now;
                                if requests.len() < FLOW_PACKETS {
                                    let payload = body.payload();
                                    let owned = if ip.fragment.is_some() {
                                        payload.to_vec()
                                    } else {
                                        let offset = payload.as_ptr().addr() - packet.as_ptr().addr();
                                        let len = payload.len();
                                        match packet {
                                            Cow::Owned(mut bytes) => {
                                                bytes.copy_within(offset..offset + len, 0);
                                                bytes.truncate(len);
                                                bytes
                                            }
                                            Cow::Borrowed(bytes) => bytes[offset..offset + len].to_vec(),
                                        }
                                    };
                                    requests.push_back(owned);
                                }
                                return None;
                            }
                            UdpRoute::Pipe(flow) => {
                                let mut flow = flow.lock().expect("UDP flow");
                                if !flow.dropped && !flow.closed {
                                    entry.seen = now;
                                    flow.receive_udp(body.payload());
                                    return None;
                                }
                            }
                        }
                    }
                    entry.route.close();
                }
                if self.udp.len() >= self.udp_limit && !self.udp.contains_key(&key) {
                    return None;
                }
                let flow = Flow::with_wake(false, key.src, self.wake.clone());
                flow.lock()
                    .expect("WireGuard UDP flow")
                    .receive_udp(body.payload());
                self.udp.insert(
                    key,
                    UdpSlot {
                        route: UdpRoute::Pipe(flow.clone()),
                        seen: now,
                    },
                );
                Some(Incoming {
                    peer,
                    endpoint,
                    target: key.dst,
                    protocol: Protocol::Udp,
                    pipe: Pipe::from_flow(flow),
                })
            }
            _ => None,
        }
    }

    pub fn poll(
        &mut self,
        accept: impl FnMut(Incoming),
        emit: impl FnMut(PeerId, Vec<u8>),
    ) {
        self.poll_with_udp(false, accept, emit);
    }

    pub fn poll_with_udp(
        &mut self,
        udp_ready: bool,
        mut accept: impl FnMut(Incoming),
        mut emit: impl FnMut(PeerId, Vec<u8>),
    ) {
        let now = smoltcp::time::Instant::now();
        let ingress = !self.device.rx.is_empty();
        if ingress {
            self.iface.poll(now, &mut self.device, &mut self.sockets);
        }
        let mut egress = !ingress;
        for entry in self.tcp.values_mut() {
            let mut flow = entry.flow.lock().expect("WireGuard TCP flow");
            let socket = self.sockets.get_mut::<tcp::Socket>(entry.handle);
            egress |= service_tcp(socket, &mut flow);
            if flow.established && !flow.failed && !entry.offered {
                entry.offered = true;
                drop(flow);
                accept(Incoming {
                    peer: entry.key.peer,
                    endpoint: entry.endpoint,
                    target: entry.key.dst,
                    protocol: Protocol::Tcp,
                    pipe: Pipe::from_flow(entry.flow.clone()),
                });
            }
        }
        if egress {
            self.iface.poll(now, &mut self.device, &mut self.sockets);
        }
        while let Some(mut data) = self.device.tx.pop_front() {
            let Some(ip) = parse_ip(&data) else {
                continue;
            };
            if ip.protocol != IpProtocol::Tcp {
                continue;
            }
            let Ok(segment) = TcpPacket::new_checked(ip.payload) else {
                continue;
            };
            let Some(entry) = self.tcp.get(&segment.src_port()) else {
                continue;
            };
            let key = entry.key;
            if data.len() == ip_header_len(key.dst.ip()) + ip.payload.len() {
                translate_tcp(&mut data, key.dst, key.src, true);
                emit(key.peer, data);
            }
        }
        self.tcp.retain(|_, entry| {
            if self.sockets.get::<tcp::Socket>(entry.handle).state() != State::Closed {
                return true;
            }
            let flow = entry.flow.lock().expect("WireGuard TCP flow");
            if flow.failed || flow.closed {
                self.sockets.remove(entry.handle);
                self.tcp_index.remove(&entry.key);
                false
            } else {
                true
            }
        });
        self.poll_udp(udp_ready, emit);
    }

    pub fn poll_udp(&mut self, udp_ready: bool, mut emit: impl FnMut(PeerId, Vec<u8>)) {
        let now = Instant::now();
        let mtu = self.device.mtu;
        let ident = &mut self.fragment_id;
        let receive = &mut self.udp_receive;
        self.udp.retain(|key, entry| {
            if now.duration_since(entry.seen) >= IDLE {
                entry.route.close();
                return false;
            }
            let seen = &mut entry.seen;
            let mut send = |data: &[u8]| {
                let Some(packet) = udp_packet(data, key.dst, key.src) else {
                    return false;
                };
                if packet.len() <= mtu {
                    emit(key.peer, packet);
                } else {
                    *ident = ident.wrapping_add(1);
                    fragment_udp(&packet, key.dst.ip(), key.src.ip(), mtu, *ident, |packet| {
                        emit(key.peer, packet)
                    });
                }
                *seen = now;
                true
            };
            if let UdpRoute::Pipe(flow) = &entry.route {
                let mut flow = flow.lock().expect("UDP flow");
                if flow.dropped || flow.closed {
                    flow.close();
                    return false;
                }
                if let Some(driver) = flow.udp_driver.take() {
                    let requests = std::mem::take(&mut flow.packets);
                    drop(flow);
                    entry.route = UdpRoute::Connected { requests, driver };
                } else {
                    let queued = flow.datagrams.len();
                    for _ in 0..16 {
                        let Some(data) = flow.datagrams.pop_front() else {
                            break;
                        };
                        send(&data);
                    }
                    if queued - flow.datagrams.len() == 16 {
                        flow.wake_stack();
                    }
                    if queued != flow.datagrams.len() {
                        flow.notify_writer();
                    }
                    return true;
                }
            }
            let UdpRoute::Connected { requests, driver } = &mut entry.route else {
                unreachable!("pipe already driven");
            };
            if !udp_ready && requests.is_empty() {
                return true;
            }
            let buffer = udp_ready.then(|| {
                receive.resize(4 * 65_536, 0);
                receive.as_mut_slice()
            });
            driver(requests, buffer, &mut send).is_ok()
        });
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        self.fragments.remove_peer(peer);
        self.udp.retain(|key, entry| {
            if key.peer != peer {
                return true;
            }
            entry.route.close();
            false
        });
        self.tcp.retain(|_, entry| {
            if entry.key.peer != peer {
                return true;
            }
            entry.flow.lock().expect("WireGuard TCP flow").fail();
            self.sockets.remove(entry.handle);
            self.tcp_index.remove(&entry.key);
            false
        });
    }

    fn port(&mut self) -> Option<u16> {
        (0..=self.tcp.len()).find_map(|_| {
            let port = self.next;
            self.next = self.next.checked_add(1).unwrap_or(1024);
            (!self.tcp.contains_key(&port)).then_some(port)
        })
    }
}

pub(crate) struct Ip<'a> {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) protocol: IpProtocol,
    pub(crate) payload: &'a [u8],
    pub(crate) fragment: Option<Fragment>,
}

pub(crate) fn parse_ip(packet: &[u8]) -> Option<Ip<'_>> {
    match packet.first()? >> 4 {
        4 => {
            let p = Ipv4Packet::new_checked(packet).ok()?;
            if !p.verify_checksum() {
                return None;
            }
            let fragment = (p.more_frags() || p.frag_offset() != 0).then(|| Fragment {
                id: u32::from(p.ident()),
                offset: usize::from(p.frag_offset()),
                more: p.more_frags(),
            });
            Some(Ip {
                src: Ipv4Addr::from(p.src_addr()).into(),
                dst: Ipv4Addr::from(p.dst_addr()).into(),
                protocol: p.next_header(),
                payload: p.payload(),
                fragment,
            })
        }
        6 => {
            let p = Ipv6Packet::new_checked(packet).ok()?;
            let (mut protocol, mut payload) = ipv6_transport(p.next_header(), p.payload(), true)?;
            let mut fragment = None;
            if u8::from(protocol) == 44 {
                let hdr = payload.get(..8)?;
                let flags = u16::from_be_bytes([hdr[2], hdr[3]]);
                protocol = IpProtocol::from(hdr[0]);
                payload = &payload[8..];
                if flags & 0xfff9 != 0 {
                    fragment = Some(Fragment {
                        id: u32::from_be_bytes(hdr[4..8].try_into().ok()?),
                        offset: usize::from(flags & 0xfff8),
                        more: flags & 1 != 0,
                    });
                } else {
                    (protocol, payload) = ipv6_transport(protocol, payload, false)?;
                }
            }
            Some(Ip {
                src: Ipv6Addr::from(p.src_addr()).into(),
                dst: Ipv6Addr::from(p.dst_addr()).into(),
                protocol,
                payload,
                fragment,
            })
        }
        _ => None,
    }
}

pub(crate) fn ipv6_transport(
    mut protocol: IpProtocol,
    mut payload: &[u8],
    allow_fragment: bool,
) -> Option<(IpProtocol, &[u8])> {
    for _ in 0..8 {
        match u8::from(protocol) {
            0 | 43 | 60 => {
                let hdr = payload.get(..4)?;
                if u8::from(protocol) == 43 && hdr[3] != 0 {
                    return None;
                }
                protocol = IpProtocol::from(hdr[0]);
                payload = payload.get((usize::from(hdr[1]) + 1) * 8..)?;
            }
            44 if !allow_fragment => return None,
            _ => return Some((protocol, payload)),
        }
    }
    None
}

fn aliases(ip: IpAddr) -> (IpAddr, IpAddr) {
    if ip.is_ipv4() {
        (V4_LOCAL.into(), V4_PEER.into())
    } else {
        (V6_LOCAL.into(), V6_PEER.into())
    }
}

pub(crate) fn smol(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(ip) => ip.into(),
        IpAddr::V6(ip) => ip.into(),
    }
}

pub(crate) fn header(
    src: IpAddr,
    dst: IpAddr,
    protocol: IpProtocol,
    length: usize,
) -> Option<(Vec<u8>, usize)> {
    let offset = ip_header_len(src);
    if src.is_ipv4() != dst.is_ipv4() || (src.is_ipv4() && length > 65_515) {
        return None;
    }
    let mut packet = vec![0; length + offset];
    emit_header(&mut packet, src, dst, protocol);
    Some((packet, offset))
}

fn ip_header_len(address: IpAddr) -> usize {
    if address.is_ipv4() {
        20
    } else {
        40
    }
}

fn emit_header(packet: &mut [u8], src: IpAddr, dst: IpAddr, protocol: IpProtocol) {
    let hop_limit = 64;
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            Ipv4Repr {
                src_addr: src.into(),
                dst_addr: dst.into(),
                next_header: protocol,
                payload_len: packet.len() - 20,
                hop_limit,
            }
            .emit(
                &mut Ipv4Packet::new_unchecked(packet),
                &ChecksumCapabilities::default(),
            );
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            Ipv6Repr {
                src_addr: src.into(),
                dst_addr: dst.into(),
                next_header: protocol,
                payload_len: packet.len() - 40,
                hop_limit,
            }
            .emit(&mut Ipv6Packet::new_unchecked(packet));
        }
        _ => unreachable!("matched IP address families"),
    }
}

fn translate_tcp(packet: &mut [u8], src: SocketAddr, dst: SocketAddr, checksum: bool) {
    emit_header(packet, src.ip(), dst.ip(), IpProtocol::Tcp);
    set_tcp_endpoints(&mut packet[ip_header_len(src.ip())..], src, dst, checksum);
}

fn set_tcp_endpoints(segment: &mut [u8], src: SocketAddr, dst: SocketAddr, checksum: bool) {
    // The caller already checked the segment before changing its endpoints.
    let mut tcp = TcpPacket::new_unchecked(segment);
    tcp.set_src_port(src.port());
    tcp.set_dst_port(dst.port());
    if checksum {
        tcp.fill_checksum(&smol(src.ip()), &smol(dst.ip()));
    }
}

pub(crate) fn udp_packet(data: &[u8], src: SocketAddr, dst: SocketAddr) -> Option<Vec<u8>> {
    let length = data.len().checked_add(8)?;
    let (mut packet, offset) = header(src.ip(), dst.ip(), IpProtocol::Udp, length)?;
    let mut udp = UdpPacket::new_unchecked(&mut packet[offset..]);
    udp.set_src_port(src.port());
    udp.set_dst_port(dst.port());
    udp.set_len(length.try_into().ok()?);
    udp.payload_mut().copy_from_slice(data);
    udp.fill_checksum(&smol(src.ip()), &smol(dst.ip()));
    Some(packet)
}

pub(crate) fn fragment_udp(
    packet: &[u8],
    src: IpAddr,
    dst: IpAddr,
    mtu: usize,
    id: u32,
    mut emit: impl FnMut(Vec<u8>),
) {
    let (offset, extra) = if src.is_ipv4() { (20, 0) } else { (40, 8) };
    let data = &packet[offset..];
    let step = (mtu - offset - extra) & !7;
    for (index, chunk) in data.chunks(step).enumerate() {
        let start = index * step;
        let more = start + chunk.len() < data.len();
        let protocol = if src.is_ipv4() {
            IpProtocol::Udp
        } else {
            IpProtocol::from(44)
        };
        let Some((mut fragment, _)) = header(src, dst, protocol, extra + chunk.len()) else {
            return;
        };
        if src.is_ipv4() {
            let mut ip = Ipv4Packet::new_unchecked(&mut fragment[..]);
            ip.set_ident(id as u16);
            ip.set_dont_frag(false);
            ip.set_more_frags(more);
            ip.set_frag_offset(start as u16);
            ip.fill_checksum();
        } else {
            fragment[40] = u8::from(IpProtocol::Udp);
            fragment[42..44].copy_from_slice(&((start as u16) | u16::from(more)).to_be_bytes());
            fragment[44..48].copy_from_slice(&id.to_be_bytes());
        }
        fragment[offset + extra..].copy_from_slice(chunk);
        emit(fragment);
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        for entry in self.tcp.values() {
            entry.flow.lock().expect("WireGuard TCP flow").fail();
        }
        for entry in self.udp.values() {
            entry.route.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_udp_keeps_the_flow_after_the_handoff_is_released() -> io::Result<()> {
        let client = "10.73.11.2:45000".parse::<SocketAddr>().unwrap();
        let target = "192.0.2.17:8080".parse::<SocketAddr>().unwrap();
        let carrier = "127.0.0.1:1194".parse::<SocketAddr>().unwrap();
        let mut stack = Stack::new(1400)?;
        let sent = Arc::new(Mutex::new(Vec::new()));
        let captured = sent.clone();
        let initial = udp_packet(b"first", client, target).unwrap();
        let handoff = stack.receive_owned(PeerId::SINGLE, carrier, initial).unwrap();
        handoff.pipe.install_udp_driver(Box::new(move |requests, receive, reply| {
            captured.lock().unwrap().extend(requests.drain(..));
            if receive.is_some() {
                assert!(reply(b"reply"));
            }
            Ok(())
        }))?;
        drop(handoff);
        stack.poll(|_| panic!("duplicate handoff"), |_, _| panic!("unexpected reply"));

        let next = udp_packet(b"second", client, target).unwrap();
        assert!(stack.receive_owned(PeerId::SINGLE, carrier, next).is_none());
        let large = vec![7; 2600];
        let packet = udp_packet(&large, client, target).unwrap();
        fragment_udp(&packet, client.ip(), target.ip(), 1400, 7, |fragment| {
            assert!(stack.receive_owned(PeerId::SINGLE, carrier, fragment).is_none());
        });
        let mut replies = Vec::new();
        stack.poll_udp(true, |_, packet| replies.push(packet));
        assert_eq!(
            *sent.lock().unwrap(),
            [b"first".to_vec(), b"second".to_vec(), large]
        );
        assert_eq!(replies, [udp_packet(b"reply", target, client).unwrap()]);
        stack.remove_peer(PeerId::SINGLE);
        let fresh = udp_packet(b"new", client, target).unwrap();
        assert!(stack.receive_owned(PeerId::SINGLE, carrier, fresh).is_some());
        Ok(())
    }

    #[test]
    fn translated_tcp_checksums_cover_the_original_endpoints() -> io::Result<()> {
        let client = "10.73.11.2:45000".parse::<SocketAddr>().unwrap();
        let target = "192.0.2.17:8080".parse::<SocketAddr>().unwrap();
        let carrier = "127.0.0.1:1194".parse::<SocketAddr>().unwrap();
        let (mut syn, offset) = header(client.ip(), target.ip(), IpProtocol::Tcp, 20).unwrap();
        let mut tcp = TcpPacket::new_unchecked(&mut syn[offset..]);
        tcp.set_header_len(20);
        tcp.set_syn(true);
        tcp.set_src_port(client.port());
        tcp.set_dst_port(target.port());
        tcp.set_window_len(4096);
        tcp.fill_checksum(&smol(client.ip()), &smol(target.ip()));

        let mut stack = Stack::new(1400)?;
        let mut bad = syn.clone();
        bad[offset + 16] ^= 1;
        stack.receive_owned(PeerId::SINGLE, carrier, bad);
        stack.poll(
            |_| panic!("invalid TCP accepted"),
            |_, _| panic!("invalid TCP answered"),
        );

        stack.receive_owned(PeerId::SINGLE, carrier, syn);
        let mut replies = Vec::new();
        stack.poll(
            |_| panic!("SYN alone opened a flow"),
            |_, reply| replies.push(reply),
        );
        let [reply] = replies.as_slice() else {
            panic!("expected one SYN-ACK")
        };
        let ip = parse_ip(reply).expect("valid IP checksum");
        let reply = TcpPacket::new_checked(ip.payload).expect("valid TCP header");
        assert_eq!((ip.src, ip.dst), (target.ip(), client.ip()));
        assert_eq!(
            (reply.src_port(), reply.dst_port()),
            (target.port(), client.port())
        );
        assert!(reply.syn() && reply.ack());
        assert!(reply.verify_checksum(&smol(ip.src), &smol(ip.dst)));
        Ok(())
    }
}
