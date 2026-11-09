#[cfg(target_os = "linux")]
mod linux;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::Value;
use socket2::{Domain, Protocol, Socket, Type};

use super::{check_udp_size, copy_packet, random_below, retryable, settings, PacketIo, UDP_SIZE};

const READ_POLL: Duration = Duration::from_millis(25);
const WRITE_TIMEOUT: Duration = Duration::from_millis(200);
const PEER_TTL: Duration = Duration::from_secs(60);
const PEER_LIMIT: usize = 4096;
const ECHO_HEADER: usize = 8;
const CLIENT_ID: usize = 8;

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Icmp {
    dgram: bool,
    ips: Vec<IpAddr>,
}

impl Icmp {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        settings(value)
    }

    pub(super) fn client(&self, peer: SocketAddr) -> io::Result<Arc<dyn PacketIo>> {
        let ips = if self.ips.is_empty() { vec![peer.ip()] } else { self.ips.clone() };
        let ips: Vec<_> = ips.into_iter().map(|ip| ip.to_canonical()).collect();
        let socket = |ipv4| {
            ips.iter().any(|addr| addr.is_ipv4() == ipv4).then(|| EchoSocket::open(unspecified(ipv4), self.dgram)).transpose()
        };
        let v4 = socket(true)?;
        let v6 = socket(false)?;
        let mut client_id = [0; CLIENT_ID];
        OsRng.try_fill_bytes(&mut client_id).map_err(|err| io::Error::other(err.to_string()))?;
        Ok(Arc::new(Client {
            v4, v6, ips, peer, client_id, dgram: self.dgram,
            id: OsRng.next_u32() as u16, sequence: AtomicU16::new(1), read_v4: AtomicBool::new(false),
        }))
    }

    pub(super) fn server(&self, local: SocketAddr) -> io::Result<Arc<dyn PacketIo>> {
        let socket = EchoSocket::open(local.ip(), false)?;
        #[cfg(target_os = "linux")]
        linux::receive_packet_info(&socket)?;
        Ok(Arc::new(Server { socket, local, allowed: self.ips.clone(), peers: Mutex::new(HashMap::new()) }))
    }
}

fn unspecified(ipv4: bool) -> IpAddr {
    if ipv4 { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() }
}

struct EchoSocket {
    io: UdpSocket,
    ipv4: bool,
    raw: bool,
}

impl EchoSocket {
    fn open(ip: IpAddr, dgram: bool) -> io::Result<Self> {
        let ipv4 = ip.is_ipv4();
        let addr = SocketAddr::new(ip, 0);
        let ty = if dgram { Type::DGRAM } else { Type::RAW };
        let protocol = if ipv4 { Protocol::ICMPV4 } else { Protocol::ICMPV6 };
        let socket = Socket::new(Domain::for_address(addr), ty, Some(protocol))?;
        socket.bind(&addr.into())?;
        socket.set_read_timeout(Some(READ_POLL))?;
        socket.set_write_timeout(Some(WRITE_TIMEOUT))?;
        Ok(Self { io: socket.into(), ipv4, raw: !dgram })
    }

    fn decode<'a>(&self, wire: &'a [u8], request: bool) -> Option<Echo<'a>> {
        // IPv4 raw sockets generally return the IP header before the echo.
        let packet = match wire.first()? >> 4 {
            4 if self.raw && self.ipv4 => {
                let len = usize::from(wire[0] & 0x0f) * 4;
                if len < 20 || wire.get(9) != Some(&1) {
                    return None;
                }
                wire.get(len..)?
            }
            6 if self.raw && !self.ipv4 => wire.get(40..)?,
            _ => wire,
        };
        if packet.len() < ECHO_HEADER || packet.len() > UDP_SIZE
            || packet[0] != echo_type(self.ipv4, request) || packet[1] != 0
        {
            return None;
        }
        Some(Echo {
            id: u16::from_be_bytes([packet[4], packet[5]]),
            seq: u16::from_be_bytes([packet[6], packet[7]]),
            payload: &packet[ECHO_HEADER..],
        })
    }
}

struct Echo<'a> {
    id: u16,
    seq: u16,
    payload: &'a [u8],
}

fn echo_type(ipv4: bool, request: bool) -> u8 {
    match (ipv4, request) {
        (true, true) => 8,
        (true, false) => 0,
        (false, true) => 128,
        (false, false) => 129,
    }
}

fn echo(ipv4: bool, request: bool, id: u16, seq: u16, client_id: &[u8], packet: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(ECHO_HEADER + client_id.len() + packet.len());
    wire.extend_from_slice(&[echo_type(ipv4, request), 0, 0, 0]);
    wire.extend_from_slice(&id.to_be_bytes());
    wire.extend_from_slice(&seq.to_be_bytes());
    wire.extend_from_slice(client_id);
    wire.extend_from_slice(packet);
    if ipv4 {
        let mut sum = 0u32;
        for bytes in wire.chunks(2) {
            sum += u32::from(u16::from_be_bytes([bytes[0], *bytes.get(1).unwrap_or(&0)]));
        }
        while sum > u32::from(u16::MAX) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        wire[2..4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }
    wire
}

struct Client {
    v4: Option<EchoSocket>,
    v6: Option<EchoSocket>,
    ips: Vec<IpAddr>,
    peer: SocketAddr,
    client_id: [u8; CLIENT_ID],
    dgram: bool,
    id: u16,
    sequence: AtomicU16,
    read_v4: AtomicBool,
}

impl PacketIo for Client {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(unspecified(self.peer.is_ipv4()), 0))
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = [0; UDP_SIZE + 64];
        let deadline = Instant::now() + READ_POLL * 2;
        while Instant::now() < deadline {
            let read_v4 = self.read_v4.fetch_xor(true, Ordering::Relaxed);
            let socket = if read_v4 { self.v4.as_ref().or(self.v6.as_ref()) } else { self.v6.as_ref().or(self.v4.as_ref()) };
            let socket = socket.expect("at least one ICMP socket");
            let (len, source) = match socket.io.recv_from(&mut wire) {
                Ok(packet) => packet,
                Err(err) if retryable(&err) => continue,
                Err(err) => return Err(err),
            };
            let Some(reply) = socket.decode(&wire[..len], false) else { continue; };
            if (!self.dgram && reply.id != self.id) || reply.payload.starts_with(&self.client_id)
                || !self.ips.contains(&source.ip().to_canonical())
            {
                continue;
            }
            return Ok((copy_packet(out, reply.payload), self.peer));
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], _: SocketAddr) -> io::Result<usize> {
        check_udp_size(ECHO_HEADER + CLIENT_ID + packet.len())?;
        let ip = self.ips[random_below(self.ips.len() as u32) as usize];
        let socket = if ip.is_ipv4() { self.v4.as_ref() } else { self.v6.as_ref() }.expect("ICMP address family");
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let wire = echo(ip.is_ipv4(), true, self.id, seq, &self.client_id, packet);
        let remote = match self.peer {
            SocketAddr::V6(mut peer) if IpAddr::V6(*peer.ip()) == ip => {
                peer.set_port(0);
                peer.into()
            }
            _ => SocketAddr::new(ip, 0),
        };
        send_result(socket.io.send_to(&wire, remote)?, wire.len(), packet.len())
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct Source {
    ip: IpAddr,
    interface: u32,
}

struct Reply {
    remote: SocketAddr,
    #[cfg(target_os = "linux")]
    source: Option<Source>,
    id: u16,
    seq: u16,
    last: Instant,
}

struct Server {
    socket: EchoSocket,
    local: SocketAddr,
    allowed: Vec<IpAddr>,
    peers: Mutex<HashMap<SocketAddr, Reply>>,
}

fn synthetic_peer(id: &[u8]) -> SocketAddr {
    let mut bytes = [0; 16];
    bytes[0] = 0xfd;
    bytes[8..].copy_from_slice(id);
    SocketAddr::new(Ipv6Addr::from(bytes).into(), 0)
}

impl PacketIo for Server {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = [0; UDP_SIZE + 64];
        let deadline = Instant::now() + READ_POLL * 2;
        while Instant::now() < deadline {
            #[cfg(target_os = "linux")]
            let (len, remote, source) = linux::recv(&self.socket, &mut wire)?;
            #[cfg(not(target_os = "linux"))]
            let (len, remote) = self.socket.io.recv_from(&mut wire)?;
            let Some(echo) = self.socket.decode(&wire[..len], true) else { continue; };
            if echo.payload.len() <= CLIENT_ID
                || (!self.allowed.is_empty() && !self.allowed.contains(&remote.ip().to_canonical()))
            {
                continue;
            }
            let peer = synthetic_peer(&echo.payload[..CLIENT_ID]);
            let mut peers = self.peers.lock().expect("ICMP peers");
            if peers.len() >= PEER_LIMIT && !peers.contains_key(&peer) {
                if let Some(oldest) = peers.iter().min_by_key(|(_, reply)| reply.last).map(|(addr, _)| *addr) {
                    peers.remove(&oldest);
                }
            }
            peers.insert(peer, Reply {
                remote,
                #[cfg(target_os = "linux")]
                source,
                id: echo.id,
                seq: echo.seq,
                last: Instant::now(),
            });
            return Ok((copy_packet(out, &echo.payload[CLIENT_ID..]), peer));
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        check_udp_size(ECHO_HEADER + packet.len())?;
        let mut peers = self.peers.lock().expect("ICMP peers");
        let reply = peers.get_mut(&peer).ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "unknown ICMP client"))?;
        if reply.last.elapsed() >= PEER_TTL {
            peers.remove(&peer);
            return Err(io::Error::new(io::ErrorKind::NotConnected, "ICMP client expired"));
        }
        reply.last = Instant::now();
        let wire = echo(self.socket.ipv4, false, reply.id, reply.seq, &[], packet);
        #[cfg(target_os = "linux")]
        let sent = linux::send(&self.socket, &wire, reply.remote, reply.source)?;
        #[cfg(not(target_os = "linux"))]
        let sent = self.socket.io.send_to(&wire, reply.remote)?;
        send_result(sent, wire.len(), packet.len())
    }
}

fn send_result(sent: usize, wire: usize, payload: usize) -> io::Result<usize> {
    if sent != wire {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "partial ICMP echo"));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_echo_type_id_sequence_fixture() {
        assert_eq!(echo(true, true, 65535, 1, &[], &[]), [8, 0, 247, 254, 255, 255, 0, 1]);
        assert_eq!(echo(true, false, 65535, 1, &[], &[]), [0, 0, 255, 254, 255, 255, 0, 1]);
        assert_eq!(echo(false, true, 65535, 1, &[], &[]), [128, 0, 0, 0, 255, 255, 0, 1]);
        assert_eq!(echo(false, false, 65535, 1, &[], &[]), [129, 0, 0, 0, 255, 255, 0, 1]);
    }
}
