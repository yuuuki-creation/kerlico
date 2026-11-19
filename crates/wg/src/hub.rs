use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use boringtun::noise::{
    handshake::parse_handshake_anon, rate_limiter::RateLimiter, Packet, Tunn, TunnResult,
};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;

use crate::wire::{PeerKeys, Received, Wire};

#[cfg(all(feature = "tun-device", any(target_os = "linux", windows)))]
#[path = "hub_control.rs"]
pub(crate) mod control;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(pub(crate) u32);

pub enum HubEvent {
    Datagram(SocketAddr, Vec<u8>),
    Packet(PeerId, SocketAddr, Vec<u8>),
}

pub(crate) enum HubEventRef<'a> {
    Datagram(SocketAddr, &'a mut [u8]),
    Packet(PeerId, SocketAddr, &'a [u8]),
}

struct Peer {
    key: [u8; 32],
    allowed: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
    wire: Option<Wire>,
    #[cfg_attr(
        not(all(feature = "tun-device", any(target_os = "linux", windows))),
        allow(dead_code)
    )]
    preshared: Option<[u8; 32]>,
    keepalive: u16,
    last_traffic: Option<Instant>,
    last_handshake: Option<SystemTime>,
    received: u64,
    sent: u64,
}

/// WireGuard's authenticated peer selection and cryptokey routing. The caller
/// owns the UDP socket and decides what to do with authenticated IP packets.
pub struct Hub {
    secret: StaticSecret,
    public: PublicKey,
    limiter: Arc<RateLimiter>,
    peers: HashMap<PeerId, Peer>,
    by_key: HashMap<[u8; 32], PeerId>,
    receive_buffer: Vec<u8>,
    next: u32,
    mtu: usize,
}

impl Hub {
    pub fn new(private: [u8; 32]) -> io::Result<Self> {
        Self::with_mtu(private, 1420)
    }

    pub fn with_mtu(private: [u8; 32], mtu: usize) -> io::Result<Self> {
        if !(576..=crate::wire::MAX_IP_PACKET).contains(&mtu) {
            return Err(invalid("invalid WireGuard MTU"));
        }
        if private == [0; 32] {
            return Err(invalid("invalid WireGuard private key"));
        }
        let secret = StaticSecret::from(canonical_private_key(private));
        let public = PublicKey::from(&secret);
        let limiter = Arc::new(RateLimiter::new(&public, 100));
        Ok(Self {
            limiter,
            secret,
            public,
            peers: HashMap::new(),
            by_key: HashMap::new(),
            receive_buffer: Vec::new(),
            next: 1,
            mtu,
        })
    }

    pub fn add(
        &mut self,
        key: [u8; 32],
        preshared: Option<[u8; 32]>,
        keepalive: u16,
        allowed: Vec<IpNet>,
        endpoint: Option<SocketAddr>,
    ) -> io::Result<PeerId> {
        let allowed: Vec<_> = allowed.into_iter().map(|net| net.trunc()).collect();
        if self.peers.len() >= 1024
            || self.by_key.contains_key(&key)
            || (self.mtu < 1280 && allowed.iter().any(|net| matches!(net, IpNet::V6(_))))
            || self
                .peers
                .values()
                .any(|peer| peer.allowed.iter().any(|net| allowed.contains(net)))
        {
            return Err(invalid("duplicate, excess, or incomplete WireGuard peer"));
        }
        let id = (0..=self.peers.len())
            .find_map(|_| {
                let id = PeerId(self.next);
                self.next = if self.next == 0xff_ffff {
                    1
                } else {
                    self.next + 1
                };
                (!self.peers.contains_key(&id)).then_some(id)
            })
            .ok_or_else(|| invalid("no WireGuard peer indexes available"))?;
        let wire = make_wire(&self.secret, &self.limiter, id, key, preshared)?;
        self.peers.insert(
            id,
            Peer {
                key,
                allowed,
                endpoint,
                wire,
                preshared,
                keepalive,
                last_traffic: None,
                last_handshake: None,
                received: 0,
                sent: 0,
            },
        );
        self.by_key.insert(key, id);
        Ok(id)
    }

    pub fn remove(&mut self, id: PeerId) -> bool {
        self.peers
            .remove(&id)
            .is_some_and(|peer| self.by_key.remove(&peer.key).is_some())
    }

    pub fn route(&self, address: &IpAddr) -> Option<PeerId> {
        find_route(&self.peers, address)
    }

    pub(crate) fn allowed_ips(&self) -> Vec<IpNet> {
        self.peers
            .values()
            .flat_map(|peer| peer.allowed.iter().copied())
            .collect()
    }

    pub fn receive(&mut self, from: SocketAddr, packet: &[u8], mut emit: impl FnMut(HubEvent)) {
        self.receive_with(from, packet, |event| match event {
            HubEventRef::Datagram(addr, data) => emit(HubEvent::Datagram(addr, data.to_vec())),
            HubEventRef::Packet(id, addr, ip) => emit(HubEvent::Packet(id, addr, ip.to_vec())),
        });
    }

    pub(crate) fn receive_with(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
        mut emit: impl FnMut(HubEventRef<'_>),
    ) {
        if self.secret.to_bytes() == [0; 32] {
            return;
        }
        let mut cookie = [0; 64];
        let parsed = match self.limiter.verify_packet(Some(from), packet, &mut cookie) {
            Ok(parsed) => parsed,
            Err(TunnResult::WriteToNetwork(data)) => {
                emit(HubEventRef::Datagram(from, data));
                return;
            }
            Err(_) => return,
        };
        let id = match parsed.packet() {
            // Validate MAC1/cookie before the anonymous DH used to identify a peer.
            Packet::HandshakeInit(init) => parse_handshake_anon(&self.secret, &self.public, init)
                .ok()
                .and_then(|half| self.by_key.get(&half.peer_static_public).copied()),
            Packet::HandshakeResponse(frame) => Some(PeerId(frame.receiver_idx >> 8)),
            Packet::PacketCookieReply(frame) => Some(PeerId(frame.receiver_idx >> 8)),
            Packet::PacketData(frame) => Some(PeerId(frame.receiver_idx >> 8)),
        };
        let Some(id) = id else {
            return;
        };
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        let Some(wire) = &mut peer.wire else {
            return;
        };
        let reception = wire.receive_verified(parsed, packet.len(), &mut self.receive_buffer);
        if reception.authenticated {
            peer.endpoint = Some(from);
            peer.last_traffic = Some(Instant::now());
            peer.received = peer.received.saturating_add(packet.len() as u64);
        }
        if reception.handshake_completed {
            peer.last_handshake = Some(SystemTime::now());
        }
        match reception.output {
            Some(Received::Datagram(data)) => {
                let mut send = |data: &mut [u8]| {
                    peer.sent = peer.sent.saturating_add(data.len() as u64);
                    emit(HubEventRef::Datagram(from, data));
                };
                send(data);
                wire.drain(&mut self.receive_buffer, send);
            }
            Some(Received::Packet(data, src)) => {
                if find_route(&self.peers, &src) == Some(id) {
                    emit(HubEventRef::Packet(id, from, data));
                }
            }
            None => {}
        }
    }

    pub fn send(&mut self, packet: &[u8]) -> Option<HubEvent> {
        self.send_with(packet, None, |peer, bytes| {
            HubEvent::Datagram(peer, bytes.to_vec())
        })
    }

    pub(crate) fn send_with<T>(
        &mut self,
        packet: &[u8],
        buffer: Option<(&mut Vec<u8>, usize)>,
        emit: impl FnOnce(SocketAddr, &mut [u8]) -> T,
    ) -> Option<T> {
        let id = self.route(&Tunn::dst_address(packet)?)?;
        self.send_routed(id, packet, buffer, emit)
    }

    #[cfg(all(feature = "tun-device", target_os = "linux"))]
    pub(crate) fn send_prepared<T>(
        &mut self,
        frame: &mut [u8],
        n: usize,
        emit: impl FnOnce(SocketAddr, &mut [u8]) -> T,
    ) -> Option<T> {
        let id = self.route(&Tunn::dst_address(frame.get(16..16 + n)?)?)?;
        let peer = self.peers.get_mut(&id)?;
        let endpoint = peer.endpoint?;
        let wire = peer.wire.as_mut()?.seal_prepared(frame, n, self.mtu)?;
        let len = wire.len();
        let out = emit(endpoint, wire);
        peer.record_send(len);
        Some(out)
    }

    pub(crate) fn initiate(&mut self, id: PeerId) -> Option<HubEvent> {
        let peer = self.peers.get_mut(&id)?;
        let endpoint = peer.endpoint?;
        let data = peer.wire.as_mut()?.initiate()?;
        peer.record_send(data.len());
        Some(HubEvent::Datagram(endpoint, data))
    }

    pub fn send_to(&mut self, id: PeerId, packet: &[u8]) -> Option<HubEvent> {
        let dst = Tunn::dst_address(packet)?;
        if self.route(&dst) != Some(id) {
            return None;
        }
        self.send_routed(id, packet, None, |peer, bytes| {
            HubEvent::Datagram(peer, bytes.to_vec())
        })
    }

    fn send_routed<T>(
        &mut self,
        id: PeerId,
        packet: &[u8],
        buffer: Option<(&mut Vec<u8>, usize)>,
        emit: impl FnOnce(SocketAddr, &mut [u8]) -> T,
    ) -> Option<T> {
        let peer = self.peers.get_mut(&id)?;
        let endpoint = peer.endpoint?;
        let frame = peer.wire.as_mut()?.send(packet, self.mtu, buffer)?;
        let len = frame.len();
        let result = emit(endpoint, frame);
        peer.record_send(len);
        Some(result)
    }

    #[cfg(all(feature = "tun-device", target_os = "linux"))]
    pub(crate) fn reset_transport(&mut self) {
        for peer in self.peers.values_mut() {
            if let Some(wire) = &mut peer.wire {
                wire.reset_transport();
            }
            peer.last_traffic = None;
        }
    }

    #[cfg(all(feature = "tun-device", target_os = "linux"))]
    pub(crate) fn mtu(&self) -> usize {
        self.mtu
    }

    #[cfg(all(feature = "tun-device", target_os = "linux"))]
    pub(crate) fn update_mtu(&mut self, mtu: usize) {
        self.mtu = mtu.min(crate::wire::MAX_IP_PACKET);
    }

    pub fn tick(&mut self, mut emit: impl FnMut(HubEvent)) {
        self.limiter.reset_count();
        for peer in self.peers.values_mut() {
            let (Some(endpoint), Some(wire)) = (peer.endpoint, &mut peer.wire) else {
                continue;
            };
            let tick = wire.tick();
            let due = peer.keepalive != 0
                && peer.last_traffic.is_none_or(|at| {
                    at.elapsed() >= Duration::from_secs(u64::from(peer.keepalive))
                });
            let event = if tick.is_none() && due {
                peer.last_traffic = Some(Instant::now());
                wire.send(&[], self.mtu, None).map(|bytes| bytes.to_vec())
            } else {
                tick
            };
            if let Some(data) = event {
                peer.record_send(data.len());
                emit(HubEvent::Datagram(endpoint, data));
            }
        }
    }
}

fn find_route(peers: &HashMap<PeerId, Peer>, address: &IpAddr) -> Option<PeerId> {
    peers
        .iter()
        .flat_map(|(id, peer)| peer.allowed.iter().map(move |net| (*id, net)))
        .filter(|(_, net)| net.contains(address))
        .max_by_key(|(_, net)| net.prefix_len())
        .map(|(id, _)| id)
}

fn canonical_private_key(mut key: [u8; 32]) -> [u8; 32] {
    // An all-zero private key clears the identity. Clamp only nonzero keys so the
    // bytes reported through UAPI and used to detect changes match WireGuard.
    if key != [0; 32] {
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
    }
    key
}

impl Peer {
    fn record_send(&mut self, len: usize) {
        self.sent = self.sent.saturating_add(len as u64);
        self.last_traffic = Some(Instant::now());
    }
}

fn make_wire(
    secret: &StaticSecret,
    mac: &Arc<RateLimiter>,
    id: PeerId,
    key: [u8; 32],
    preshared: Option<[u8; 32]>,
) -> io::Result<Option<Wire>> {
    let private = secret.to_bytes();
    if private == [0; 32] {
        return Ok(None);
    }
    // The listener owns cookie and keepalive policy for its mutable peer table.
    let keys = PeerKeys {
        private,
        public: key,
        preshared,
        keepalive: 0,
    };
    Wire::with_limiter(&keys, id.0, Some(mac.clone())).map(Some)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(result: TunnResult<'_>) -> Vec<u8> {
        match result {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            _ => panic!("expected a WireGuard datagram"),
        }
    }

    fn receive_datagram(hub: &mut Hub, from: SocketAddr, data: &[u8]) -> Vec<u8> {
        let mut reply = None;
        hub.receive(from, data, |event| match event {
            HubEvent::Datagram(destination, bytes) => {
                assert_eq!(destination, from);
                assert!(reply.replace(bytes).is_none());
            }
            HubEvent::Packet(..) => panic!("unexpected IP packet during handshake"),
        });
        reply.expect("expected a WireGuard handshake response or cookie")
    }

    #[test]
    fn jumbo_packet_queued_during_handshake_survives_batch_reuse() {
        queued_jumbo(false);
    }

    #[cfg(all(feature = "tun-device", target_os = "linux"))]
    #[test]
    fn prepared_jumbo_survives_reuse_before_the_handshake_completes() {
        queued_jumbo(true);
    }

    fn queued_jumbo(prepared: bool) {
        let mut hub = Hub::with_mtu([42; 32], 9000).unwrap();
        let endpoint: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let secret = StaticSecret::from([99; 32]);
        let allowed = "192.0.2.9/32".parse().unwrap();
        hub.add(
            *PublicKey::from(&secret).as_bytes(),
            None,
            0,
            vec![allowed],
            Some(endpoint),
        )
        .unwrap();
        let mut remote = Tunn::new(secret, hub.public, None, None, 43, None);
        let mut ip = vec![7; 9000];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&9000u16.to_be_bytes());
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[192, 0, 2, 9]);
        let mut batch = vec![0; 16];
        let initiation = if prepared {
            #[cfg(all(feature = "tun-device", target_os = "linux"))]
            {
                batch.resize(32 + ip.len(), 0);
                batch[16..16 + ip.len()].copy_from_slice(&ip);
                hub.send_prepared(&mut batch, ip.len(), |_, bytes| bytes.to_vec())
                    .unwrap()
            }
            #[cfg(not(all(feature = "tun-device", target_os = "linux")))]
            unreachable!()
        } else {
            hub.send_with(&ip, Some((&mut batch, 16)), |_, bytes| bytes.to_vec())
                .unwrap()
        };
        batch.fill(0);

        let mut scratch = vec![0; 9100];
        let response = datagram(remote.decapsulate(Some(endpoint), &initiation, &mut scratch));
        let mut delivered = 0;
        hub.receive(endpoint, &response, |event| {
            let HubEvent::Datagram(_, frame) = event else {
                panic!("expected a datagram")
            };
            match remote.decapsulate(Some(endpoint), &frame, &mut scratch) {
                TunnResult::Done => {}
                TunnResult::WriteToTunnelV4(packet, _) => {
                    assert_eq!(packet, &ip[..]);
                    delivered += 1;
                }
                _ => panic!("unexpected handshake or payload result"),
            }
        });
        assert_eq!(delivered, 1);
    }

    #[cfg(all(feature = "tun-device", target_os = "linux"))]
    #[test]
    fn link_down_clears_sessions_without_forgetting_handshake_replays() {
        let mut hub = Hub::new([42; 32]).unwrap();
        let from = "127.0.0.1:3000".parse().unwrap();
        let secret = StaticSecret::from([99; 32]);
        let public = PublicKey::from(&secret);
        let id = hub.add(*public.as_bytes(), None, 0, vec![], None).unwrap();
        let mut peer = Tunn::new(secret, hub.public, None, None, 43, None);
        let mut buffer = [0; 256];
        let initiation = datagram(peer.format_handshake_initiation(&mut buffer, false));
        let response = receive_datagram(&mut hub, from, &initiation);
        let confirmation = datagram(peer.decapsulate(Some(from), &response, &mut buffer));
        hub.receive(from, &confirmation, |_| panic!("unexpected output"));
        let stamp = hub.peers[&id].last_handshake.unwrap();
        let received = hub.peers[&id].received;
        hub.reset_transport();
        hub.receive(from, &initiation, |_| panic!("old handshake replayed"));
        let stale = datagram(peer.encapsulate(&[], &mut buffer));
        hub.receive(from, &stale, |_| panic!("stale transport key accepted"));
        assert_eq!(hub.peers[&id].last_handshake, Some(stamp));
        assert_eq!(hub.peers[&id].received, received);
    }

    #[test]
    fn cookie_follows_udp_source_for_both_handshake_types() {
        for source in ["127.0.0.1:3000", "[::1]:3000"] {
            let from: SocketAddr = source.parse().unwrap();
            let rebound = SocketAddr::new(from.ip(), from.port() + 1);
            let mut hub = Hub::new([42; 32]).unwrap();
            hub.limiter = Arc::new(RateLimiter::new(&hub.public, 0));

            let secret = StaticSecret::from([99; 32]);
            let public = PublicKey::from(&secret);
            let id = hub.add(*public.as_bytes(), None, 0, vec![], None).unwrap();
            let mut peer = Tunn::new(secret.clone(), hub.public, None, None, 43, None);
            let mut buf = [0; 256];

            let init = datagram(peer.format_handshake_initiation(&mut buf, false));
            let cookie = receive_datagram(&mut hub, from, &init);
            assert_eq!(cookie[0], 3);
            assert!(matches!(
                peer.decapsulate(Some(from), &cookie, &mut buf),
                TunnResult::Done
            ));
            let retry = datagram(peer.format_handshake_initiation(&mut buf, true));
            assert_eq!(receive_datagram(&mut hub, rebound, &retry)[0], 3);
            assert_eq!(hub.peers[&id].endpoint, None);
            let response = receive_datagram(&mut hub, from, &retry);
            assert_eq!(response[0], 2);
            let confirmation = datagram(peer.decapsulate(Some(from), &response, &mut buf));
            hub.receive(from, &confirmation, |_| {
                panic!("unexpected confirmation output")
            });
            assert!(hub.peers[&id].last_handshake.is_some());

            // When this listener initiates, the response also has to prove its source.
            let mut hub = Hub::new([42; 32]).unwrap();
            hub.limiter = Arc::new(RateLimiter::new(&hub.public, 0));
            let id = hub
                .add(*public.as_bytes(), None, 0, vec![], Some(from))
                .unwrap();
            let HubEvent::Datagram(_, init) = hub.initiate(id).unwrap() else {
                panic!("expected WireGuard initiation")
            };
            let mut peer = Tunn::new(secret, hub.public, None, None, 43, None);
            let response = datagram(peer.decapsulate(Some(from), &init, &mut buf));
            let cookie = receive_datagram(&mut hub, rebound, &response);
            assert_eq!(cookie[0], 3);
            assert_eq!(hub.peers[&id].endpoint, Some(from));
            assert!(matches!(
                peer.decapsulate(Some(from), &cookie, &mut buf),
                TunnResult::Done
            ));
        }
    }

    #[test]
    fn receive_transport_with_original_wireguard_reorder_window() {
        let from = "127.0.0.1:3000".parse().unwrap();
        let mut hub = Hub::new([42; 32]).unwrap();
        let secret = StaticSecret::from([99; 32]);
        let public = PublicKey::from(&secret);
        hub.add(
            *public.as_bytes(),
            None,
            0,
            vec!["192.0.2.2/32".parse().unwrap()],
            None,
        )
        .unwrap();
        let mut peer = Tunn::new(secret, hub.public, None, None, 43, None);
        let mut buf = [0; 256];
        let init = datagram(peer.format_handshake_initiation(&mut buf, false));
        let response = receive_datagram(&mut hub, from, &init);
        let keepalive = datagram(peer.decapsulate(Some(from), &response, &mut buf));
        hub.receive(from, &keepalive, |_| panic!("unexpected keepalive output"));

        let mut ip = [0; 20];
        ip[0] = 0x45;
        ip[3] = 20;
        ip[12..16].copy_from_slice(&[192, 0, 2, 2]);
        ip[16..20].copy_from_slice(&[192, 0, 2, 3]);
        let mut captured = HashMap::new();
        for counter in 1..=8194u64 {
            let encrypted = peer.encapsulate(&ip, &mut buf);
            if [64, 65, 8193, 8194].contains(&counter) {
                let wire = datagram(encrypted);
                assert_eq!(&wire[8..16], &counter.to_le_bytes());
                captured.insert(counter, wire);
            }
        }
        for (counter, accepted) in [
            (8193, true),
            (65, true),
            (64, false),
            (65, false),
            (8194, true),
        ] {
            let mut delivered = 0;
            hub.receive(from, &captured[&counter], |event| {
                let HubEvent::Packet(_, _, payload) = event else {
                    panic!("unexpected traffic response");
                };
                assert_eq!(payload, ip);
                delivered += 1;
            });
            assert_eq!(delivered, usize::from(accepted), "counter {counter}");
        }
    }
}
