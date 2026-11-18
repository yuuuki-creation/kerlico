use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use boringtun::noise::{
    rate_limiter::{RateLimiter, VerifiedPacket},
    Packet, Tunn, TunnResult,
};
use boringtun::x25519::{PublicKey, StaticSecret};

pub const MAX_IP_PACKET: usize = 65_472;
pub(crate) const WIRE_BUFFER: usize = 65_535;

pub fn parse_key(text: &str) -> io::Result<[u8; 32]> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a 32-byte WireGuard key",
        )
    };
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut key = [0; 32];
        for (offset, byte) in key.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(&text[offset * 2..offset * 2 + 2], 16).map_err(|_| invalid())?;
        }
        return Ok(key);
    }
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .into_iter()
        .find_map(|encoding| encoding.decode(text).ok()?.try_into().ok())
        .ok_or_else(invalid)
}

#[derive(Clone)]
pub struct PeerKeys {
    pub private: [u8; 32],
    pub public: [u8; 32],
    pub preshared: Option<[u8; 32]>,
    pub keepalive: u16,
}

pub(crate) enum Event {
    Datagram(Vec<u8>),
    Packet(Vec<u8>, IpAddr),
}

pub(crate) struct Reception {
    pub authenticated: bool,
    pub handshake_completed: bool,
}

pub(crate) struct Wire {
    inner: Tunn,
    buffer: Vec<u8>,
    padding: Vec<u8>,
}

impl Wire {
    pub fn with_limiter(
        keys: &PeerKeys,
        index: u32,
        limiter: Option<Arc<RateLimiter>>,
    ) -> io::Result<Self> {
        let secret = StaticSecret::from(keys.private);
        let peer = PublicKey::from(keys.public);
        if keys.private == [0; 32]
            || peer == PublicKey::from(&secret)
            || !secret.diffie_hellman(&peer).was_contributory()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WireGuard key pair",
            ));
        }
        Ok(Self {
            inner: Tunn::new(
                secret,
                peer,
                keys.preshared,
                (keys.keepalive != 0).then_some(keys.keepalive),
                index,
                limiter,
            ),
            buffer: vec![0; 2048],
            padding: Vec::new(),
        })
    }

    pub fn initiate(&mut self) -> Option<Event> {
        collect(
            self.inner
                .format_handshake_initiation(&mut self.buffer, false),
        )
    }

    #[cfg(all(feature = "tun-device", any(target_os = "linux", windows)))]
    pub(crate) fn set_preshared_key(&mut self, key: Option<[u8; 32]>) {
        self.inner.set_preshared_key(key);
    }

    pub fn send<'a>(
        &'a mut self,
        packet: &[u8],
        mtu: usize,
        output: Option<(&'a mut Vec<u8>, usize)>,
    ) -> Option<&'a mut [u8]> {
        if packet.len() > mtu || packet.len() > MAX_IP_PACKET {
            return None;
        }
        // The transport pads plaintext before AEAD, capped at the interface MTU.
        let length = packet.len().next_multiple_of(16).min(mtu);
        let packet = if length != packet.len() {
            self.padding.clear();
            self.padding.extend_from_slice(packet);
            self.padding.resize(length, 0);
            &self.padding[..]
        } else {
            packet
        };
        let required = (length + 32).max(148);
        // Before a session exists, BoringTun queues the IP packet and returns
        // a handshake instead. Its later drain uses the peer's own buffer.
        if self.buffer.len() < required {
            self.buffer.resize(required, 0);
        }
        let (output, offset) = output.unwrap_or((&mut self.buffer, 0));
        if offset + required > output.len() {
            output.resize(offset + required, 0);
        }
        match self
            .inner
            .encapsulate(packet, &mut output[offset..offset + required])
        {
            TunnResult::WriteToNetwork(frame) => Some(frame),
            _ => None,
        }
    }

    pub fn tick(&mut self) -> Option<Event> {
        collect(self.inner.update_timers(&mut self.buffer))
    }

    #[cfg(all(feature = "tun-device", target_os = "linux"))]
    pub(crate) fn reset_transport(&mut self) {
        self.inner.reset_transport();
    }

    pub fn receive_verified(
        &mut self,
        packet: VerifiedPacket<'_>,
        wire_len: usize,
        mut emit: impl FnMut(Event),
    ) -> Reception {
        if wire_len > self.buffer.len() {
            self.buffer.resize(wire_len, 0);
        }
        let is_cookie = matches!(packet.packet(), Packet::PacketCookieReply(_));
        let result = self.inner.handle_verified_packet(packet, &mut self.buffer);
        let (authenticated, drain) = match &result {
            TunnResult::Err(_) => (false, false),
            TunnResult::WriteToNetwork(_) => (true, true),
            _ => (true, false),
        };
        let handshake_completed = self.inner.take_handshake_completed();
        if let Some(event) = collect(result) {
            emit(event);
        }
        if drain {
            while let Some(event) = collect(self.inner.decapsulate(None, &[], &mut self.buffer)) {
                emit(event);
            }
        }
        Reception {
            authenticated: authenticated && !is_cookie,
            handshake_completed,
        }
    }
}

fn collect(result: TunnResult<'_>) -> Option<Event> {
    match result {
        TunnResult::WriteToNetwork(data) => Some(Event::Datagram(data.to_vec())),
        TunnResult::WriteToTunnelV4(data, addr) => Some(Event::Packet(data.to_vec(), addr.into())),
        TunnResult::WriteToTunnelV6(data, addr) => Some(Event::Packet(data.to_vec(), addr.into())),
        TunnResult::Done | TunnResult::Err(_) => None,
    }
}
