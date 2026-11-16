//! Turns authenticated IP traffic into TCP and UDP flows without dialing it.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::tcp::{self, State};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    TcpPacket, UdpPacket,
};

use crate::engine::{service_tcp, Flow, IpDev, Pipe};
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
    flow: Arc<Mutex<Flow>>,
    seen: Instant,
}

pub struct Stack {
    device: IpDev,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp_index: HashMap<Key, u16>,
    tcp: HashMap<u16, TcpSlot>,
    udp: HashMap<Key, UdpSlot>,
    next: u16,
    fragment_id: u32,
    fragments: Reassembly,
}

impl Stack {
    pub fn new(mtu: usize) -> io::Result<Self> {
        if !(576..=MAX_IP_PACKET).contains(&mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WireGuard node MTU",
            ));
        }
        let mut device = IpDev {
            rx: Default::default(),
            tx: Default::default(),
            mtu,
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
            next: 1024,
            fragment_id: OsRng.next_u32(),
            fragments: Reassembly::default(),
        })
    }

    pub fn receive(
        &mut self,
        peer: PeerId,
        endpoint: SocketAddr,
        packet: &[u8],
    ) -> Option<Incoming> {
        if packet.len() > self.device.mtu {
            return None;
        }
        let mut ip = parse_ip(packet)?;
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
                    if !segment.syn() || segment.ack() || self.tcp.len() >= MAX_TCP {
                        return None;
                    }
                    let port = self.port()?;
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0; 32 * 1024]),
                        tcp::SocketBuffer::new(vec![0; 32 * 1024]),
                    );
                    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(300)));
                    let (local, _) = aliases(ip.src);
                    socket.listen((smol(local), port)).ok()?;
                    let handle = self.sockets.add(socket);
                    self.tcp.insert(
                        port,
                        TcpSlot {
                            key,
                            endpoint,
                            handle,
                            flow: Flow::new(true, key.src),
                            offered: false,
                        },
                    );
                    self.tcp_index.insert(key, port);
                    port
                };
                if self.device.rx.len() < 128 {
                    let (local, remote) = aliases(ip.src);
                    self.device.rx.push_back(tcp_packet(
                        ip.payload,
                        remote,
                        local,
                        segment.src_port(),
                        port,
                    )?);
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
                    let mut flow = entry.flow.lock().expect("WireGuard UDP flow");
                    if !flow.dropped && !flow.closed && now.duration_since(entry.seen) < IDLE {
                        entry.seen = now;
                        flow.receive_udp(body.payload());
                        return None;
                    }
                    flow.closed = true;
                }
                if self.udp.len() >= MAX_UDP && !self.udp.contains_key(&key) {
                    return None;
                }
                let flow = Flow::new(false, key.src);
                flow.lock()
                    .expect("WireGuard UDP flow")
                    .receive_udp(body.payload());
                self.udp.insert(
                    key,
                    UdpSlot {
                        flow: flow.clone(),
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
        mut accept: impl FnMut(Incoming),
        mut emit: impl FnMut(PeerId, Vec<u8>),
    ) {
        let now = smoltcp::time::Instant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        for entry in self.tcp.values_mut() {
            let mut flow = entry.flow.lock().expect("WireGuard TCP flow");
            let socket = self.sockets.get_mut::<tcp::Socket>(entry.handle);
            service_tcp(socket, &mut flow);
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
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(data) = self.device.tx.pop_front() {
            let Some(ip) = parse_ip(&data) else {
                continue;
            };
            let Ok(segment) = TcpPacket::new_checked(ip.payload) else {
                continue;
            };
            let Some(entry) = self.tcp.get(&segment.src_port()) else {
                continue;
            };
            let key = entry.key;
            if let Some(packet) = tcp_packet(
                ip.payload,
                key.dst.ip(),
                key.src.ip(),
                key.dst.port(),
                key.src.port(),
            ) {
                emit(key.peer, packet);
            }
        }
        self.tcp.retain(|_, entry| {
            let flow = entry.flow.lock().expect("WireGuard TCP flow");
            if (flow.failed || flow.closed)
                && self.sockets.get::<tcp::Socket>(entry.handle).state() == State::Closed
            {
                self.sockets.remove(entry.handle);
                self.tcp_index.remove(&entry.key);
                false
            } else {
                true
            }
        });
        let now = Instant::now();
        let mtu = self.device.mtu;
        let ident = &mut self.fragment_id;
        self.udp.retain(|key, entry| {
            let mut flow = entry.flow.lock().expect("WireGuard UDP flow");
            if flow.dropped || flow.closed || now.duration_since(entry.seen) >= IDLE {
                flow.closed = true;
                return false;
            }
            for _ in 0..16 {
                let Some(data) = flow.datagrams.pop_front() else {
                    break;
                };
                if let Some(packet) = udp_packet(&data, key.dst, key.src) {
                    if packet.len() <= mtu {
                        emit(key.peer, packet);
                    } else {
                        *ident = ident.wrapping_add(1);
                        fragment_udp(&packet, key.dst.ip(), key.src.ip(), mtu, *ident, |packet| {
                            emit(key.peer, packet)
                        });
                    }
                    entry.seen = now;
                }
            }
            true
        });
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        self.fragments.remove_peer(peer);
        self.udp.retain(|key, entry| {
            if key.peer != peer {
                return true;
            }
            entry.flow.lock().expect("WireGuard UDP flow").closed = true;
            false
        });
        self.tcp.retain(|_, entry| {
            if entry.key.peer != peer {
                return true;
            }
            entry.flow.lock().expect("WireGuard TCP flow").failed = true;
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
    let hop_limit = 64;
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            if length > 65_515 {
                return None;
            }
            let mut packet = vec![0; length + 20];
            Ipv4Repr {
                src_addr: src.into(),
                dst_addr: dst.into(),
                next_header: protocol,
                payload_len: length,
                hop_limit,
            }
            .emit(
                &mut Ipv4Packet::new_unchecked(&mut packet[..]),
                &ChecksumCapabilities::default(),
            );
            Some((packet, 20))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut packet = vec![0; length + 40];
            Ipv6Repr {
                src_addr: src.into(),
                dst_addr: dst.into(),
                next_header: protocol,
                payload_len: length,
                hop_limit,
            }
            .emit(&mut Ipv6Packet::new_unchecked(&mut packet[..]));
            Some((packet, 40))
        }
        _ => None,
    }
}

fn tcp_packet(
    tcp: &[u8],
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> Option<Vec<u8>> {
    let (mut packet, offset) = header(src, dst, IpProtocol::Tcp, tcp.len())?;
    packet[offset..].copy_from_slice(tcp);
    let mut tcp = TcpPacket::new_checked(&mut packet[offset..]).ok()?;
    tcp.set_src_port(src_port);
    tcp.set_dst_port(dst_port);
    tcp.fill_checksum(&smol(src), &smol(dst));
    Some(packet)
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
            entry.flow.lock().expect("WireGuard TCP flow").failed = true;
        }
        for entry in self.udp.values() {
            entry.flow.lock().expect("WireGuard UDP flow").closed = true;
        }
    }
}
