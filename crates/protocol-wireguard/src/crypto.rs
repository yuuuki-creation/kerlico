use crate::config::{PeerConfig, Prepared};
use boringtun::{
    noise::{Packet, Tunn, TunnResult, handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    x25519::{PublicKey, StaticSecret},
};
use kerlico_core::{Error, Result};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

pub(crate) struct Received {
    pub authenticated: bool,
    pub plain: Option<Vec<u8>>,
    pub network: Vec<Vec<u8>>,
}
pub(crate) struct CryptoPeer {
    tunnel: Tunn,
    pub endpoint: Option<SocketAddr>,
    ready: bool,
}
impl CryptoPeer {
    pub fn new(
        config: &Prepared,
        peer: &PeerConfig,
        index: u32,
        endpoint: Option<SocketAddr>,
        limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            tunnel: Tunn::new(
                config.private_key.clone(),
                PublicKey::from(peer.public_key),
                peer.preshared_key.as_ref().map(|key| **key),
                peer.keepalive,
                index,
                Some(limiter),
            ),
            endpoint,
            ready: false,
        }
    }
    /// 不共享限速器的独立会话；对端路径由调用方维护。
    pub fn standalone(private: StaticSecret, public: PublicKey, index: u32) -> Self {
        Self {
            tunnel: Tunn::new(private, public, None, None, index, None),
            endpoint: None,
            ready: false,
        }
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
    pub fn receive(&mut self, source: SocketAddr, packet: &[u8]) -> Result<Received> {
        let kind = packet.first().copied().unwrap_or(0);
        let mut output = vec![0; 65536];
        let result = self
            .tunnel
            .decapsulate(Some(source.ip()), packet, &mut output);
        let mut received = Received {
            authenticated: false,
            plain: None,
            network: Vec::new(),
        };
        match result {
            TunnResult::Err(_) => return Err(Error::Rejected),
            TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                received.authenticated = true;
                received.plain = Some(bytes.to_vec());
                self.ready = true;
            }
            TunnResult::Done => {
                received.authenticated = kind == 4;
                if kind == 4 {
                    self.ready = true;
                }
            }
            TunnResult::WriteToNetwork(bytes) => {
                received.authenticated = kind == 2 && bytes.first() == Some(&4);
                if kind == 2 && received.authenticated {
                    self.ready = true;
                }
                received.network.push(bytes.to_vec());
            }
        }
        if received.authenticated {
            self.endpoint = Some(source);
        }
        for _ in 0..257 {
            match self.tunnel.decapsulate(None, &[], &mut output) {
                TunnResult::WriteToNetwork(bytes) => received.network.push(bytes.to_vec()),
                TunnResult::Done => return Ok(received),
                TunnResult::Err(_) => return Err(Error::Rejected),
                _ => return Err(Error::Protocol("WireGuard排空产生了意外内部包")),
            }
        }
        Err(Error::ResourceLimit)
    }
    pub fn encrypt(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        if !self.ready {
            return Err(Error::Protocol("WireGuard会话尚未确认"));
        }
        self.encapsulate(packet)
    }
    /// 无有效会话时 boringtun 缓存明文并返回握手发起。
    pub fn encapsulate(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut output = vec![0; packet.len().saturating_add(32).max(148)];
        match self.tunnel.encapsulate(packet, &mut output) {
            TunnResult::WriteToNetwork(bytes) => Ok(Some(bytes.to_vec())),
            TunnResult::Done => Ok(None),
            TunnResult::Err(_) => Err(Error::Protocol("WireGuard加密失败")),
            _ => Err(Error::Protocol("WireGuard加密产生了意外内部包")),
        }
    }
    pub fn initiate(&mut self) -> Option<Vec<u8>> {
        let mut output = [0; 148];
        match self.tunnel.format_handshake_initiation(&mut output, false) {
            TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }
    pub fn tick(&mut self) -> Option<Vec<u8>> {
        let mut output = [0; 148];
        match self.tunnel.update_timers(&mut output) {
            TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
            TunnResult::Err(_) => {
                self.ready = false;
                None
            }
            _ => None,
        }
    }
}

pub(crate) enum Identified {
    Peer(usize),
    Cookie(Vec<u8>),
}
pub(crate) struct PeerIndex {
    prepared: Prepared,
    public: HashMap<[u8; 32], usize>,
    pub limiter: Arc<RateLimiter>,
    count: usize,
}
impl PeerIndex {
    pub fn new(prepared: &Prepared, peers: &[PeerConfig]) -> Self {
        Self {
            prepared: prepared.clone(),
            public: peers
                .iter()
                .enumerate()
                .map(|(index, peer)| (peer.public_key, index))
                .collect(),
            limiter: Arc::new(RateLimiter::new(&prepared.public_key, 100)),
            count: peers.len(),
        }
    }
    pub fn identify(&self, source: SocketAddr, bytes: &[u8]) -> Result<Identified> {
        let mut cookie = [0; 64];
        let packet = match self
            .limiter
            .verify_packet(Some(source.ip()), bytes, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(bytes)) => {
                return Ok(Identified::Cookie(bytes.to_vec()));
            }
            _ => return Err(Error::Rejected),
        };
        let index = match packet {
            Packet::HandshakeInit(packet) => {
                let half = parse_handshake_anon(
                    &self.prepared.private_key,
                    &self.prepared.public_key,
                    &packet,
                )
                .map_err(|_| Error::Rejected)?;
                *self
                    .public
                    .get(&half.peer_static_public)
                    .ok_or(Error::Rejected)?
            }
            Packet::HandshakeResponse(packet) => receiver_index(packet.receiver_idx)?,
            Packet::PacketCookieReply(packet) => receiver_index(packet.receiver_idx)?,
            Packet::PacketData(packet) => receiver_index(packet.receiver_idx)?,
        };
        if index >= self.count {
            return Err(Error::Rejected);
        }
        Ok(Identified::Peer(index))
    }
}
fn receiver_index(index: u32) -> Result<usize> {
    (index >> 8)
        .checked_sub(1)
        .map(|value| value as usize)
        .ok_or(Error::Rejected)
}
