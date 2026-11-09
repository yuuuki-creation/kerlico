use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake2::{digest::consts::U32, Blake2b, Digest};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::Value;

use super::{check_udp_size, copy_packet, invalid, random_below, send_packet, settings, PacketIo, Range, UDP_POLL, UDP_SIZE};

const SALT: usize = 8;
const GECKO_HEADER: usize = 5;
const FRAGMENT_TTL: Duration = Duration::from_secs(8);
const MAX_REASSEMBLIES: usize = 4096;
const MAX_PER_SOURCE: usize = 8;

#[derive(Clone)]
pub(super) struct Salamander {
    password: Arc<[u8]>,
    packet_size: Range,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    password: String,
    packet_size: Range,
}

impl Salamander {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        let config: Config = settings(value)?;
        if config.password.len() < 4 {
            return Err(invalid("salamander password must have at least four bytes"));
        }
        if config.packet_size.max > 0 && (config.packet_size.min == 0 || config.packet_size.max > 2048) {
            return Err(invalid("invalid salamander Gecko packetSize"));
        }
        Ok(Self { password: config.password.into_bytes().into(), packet_size: config.packet_size })
    }

    pub(super) fn wrap(&self, inner: Arc<dyn PacketIo>) -> Arc<dyn PacketIo> {
        Arc::new(Packets {
            inner,
            config: self.clone(),
            message: AtomicU8::new(0),
            reassembly: Mutex::new(Reassembly::default()),
        })
    }

    fn xor(&self, salt: &[u8], body: &mut [u8]) {
        let mut hash = Blake2b::<U32>::new();
        hash.update(&self.password);
        hash.update(salt);
        let key = hash.finalize();
        for (byte, mask) in body.iter_mut().zip(key.iter().cycle()) {
            *byte ^= mask;
        }
    }

    fn encode(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        check_udp_size(SALT + payload.len())?;
        let mut wire = vec![0; SALT];
        OsRng.try_fill_bytes(&mut wire).map_err(|err| io::Error::other(err.to_string()))?;
        wire.extend_from_slice(payload);
        let (salt, data) = wire.split_at_mut(SALT);
        self.xor(salt, data);
        Ok(wire)
    }

    fn decode<'a>(&self, wire: &'a mut [u8]) -> Option<&'a [u8]> {
        let (salt, payload) = wire.split_at_mut_checked(SALT)?;
        self.xor(salt, payload);
        Some(payload)
    }
}

struct Packets {
    inner: Arc<dyn PacketIo>,
    config: Salamander,
    message: AtomicU8,
    reassembly: Mutex<Reassembly>,
}

impl Packets {
    fn send_fragments(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        let count = 2 + random_below(7) as usize;
        let chunk_size = packet.len() / count;
        let message = self.message.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        for index in 0..count {
            let start = index * chunk_size;
            let end = if index + 1 == count { packet.len() } else { start + chunk_size };
            let chunk = &packet[start..end];
            let base = SALT + GECKO_HEADER + chunk.len();
            let low = (self.config.packet_size.min as usize).max(base);
            let high = self.config.packet_size.max as usize;
            let padding = if low > high { 0 } else { low - base + random_below((high - low + 1) as u32) as usize };
            let mut frame = Vec::with_capacity(GECKO_HEADER + padding + chunk.len());
            frame.extend_from_slice(&[0x80, message, ((index << 4) | count) as u8]);
            frame.extend_from_slice(&(padding as u16).to_be_bytes());
            frame.resize(GECKO_HEADER + padding, 0);
            OsRng.try_fill_bytes(&mut frame[GECKO_HEADER..]).map_err(|err| io::Error::other(err.to_string()))?;
            frame.extend_from_slice(chunk);
            let wire = self.config.encode(&frame)?;
            send_packet(&*self.inner, frame.len(), &wire, peer)?;
        }
        Ok(packet.len())
    }
}

impl PacketIo for Packets {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = [0; UDP_SIZE];
        let deadline = Instant::now() + UDP_POLL;
        while Instant::now() < deadline {
            let (len, peer) = self.inner.recv_from(&mut wire)?;
            let Some(payload) = self.config.decode(&mut wire[..len]) else { continue; };
            if self.config.packet_size.max == 0 || payload.first().is_some_and(|first| first & 0x80 == 0) {
                return Ok((copy_packet(out, payload), peer));
            }
            if let Some(packet) = self.reassembly.lock().expect("Gecko fragments").accept(peer, payload) {
                return Ok((copy_packet(out, &packet), peer));
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        if self.config.packet_size.max > 0 {
            let Some(first) = packet.first() else { return Ok(0); };
            if first & 0x80 != 0 {
                check_udp_size(packet.len())?;
                return self.send_fragments(packet, peer);
            }
        }
        let wire = self.config.encode(packet)?;
        send_packet(&*self.inner, packet.len(), &wire, peer)
    }
}

struct Partial {
    expires: Instant,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
    missing: usize,
}

#[derive(Default)]
struct Reassembly {
    pending: HashMap<(SocketAddr, u8), Partial>,
    next_gc: Option<Instant>,
}

impl Reassembly {
    fn accept(&mut self, peer: SocketAddr, frame: &[u8]) -> Option<Vec<u8>> {
        let header = frame.get(..GECKO_HEADER)?;
        let count = usize::from(header[2] & 15);
        let index = usize::from(header[2] >> 4);
        if !(2..=8).contains(&count) || index >= count {
            return None;
        }
        let padding = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let part = frame.get(GECKO_HEADER + padding..)?;
        let now = Instant::now();
        if self.next_gc.is_none_or(|next| now >= next) {
            self.pending.retain(|_, packet| packet.expires > now);
            self.next_gc = Some(now + FRAGMENT_TTL / 2);
        }
        let key = (peer, header[1]);
        if self.pending.get(&key).is_some_and(|packet| now >= packet.expires) {
            self.pending.remove(&key);
        }
        if !self.pending.contains_key(&key) {
            if self.pending.keys().filter(|(source, _)| source == &peer).take(MAX_PER_SOURCE).count() == MAX_PER_SOURCE {
                return None;
            }
            if self.pending.len() == MAX_REASSEMBLIES {
                let oldest = self.pending.iter().min_by_key(|(_, packet)| packet.expires).map(|(key, _)| *key)?;
                self.pending.remove(&oldest);
            }
        }
        let packet = self.pending.entry(key).or_insert_with(|| Partial {
            expires: now + FRAGMENT_TTL,
            parts: vec![None; count],
            bytes: 0,
            missing: count,
        });
        if packet.parts.len() != count || packet.parts[index].is_some() {
            return None;
        }
        if packet.bytes + part.len() > UDP_SIZE {
            self.pending.remove(&key);
            return None;
        }
        packet.parts[index] = Some(part.to_vec());
        packet.bytes += part.len();
        packet.missing -= 1;
        if packet.missing != 0 {
            return None;
        }
        let packet = self.pending.remove(&key)?;
        let mut out = Vec::with_capacity(packet.bytes);
        out.extend(packet.parts.into_iter().flatten().flatten());
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_hysteria_salamander_fixture() {
        let config = Salamander { password: Arc::from(b"salamander-password".as_slice()), packet_size: Range::default() };
        let mut wire = [0, 1, 2, 3, 4, 5, 6, 7, 0x2f, 0xa6, 0xdf, 0x67, 0x83];
        // BLAKE2b with a 32-byte digest over password || 0001020304050607.
        assert_eq!(config.decode(&mut wire), Some(&b"hello"[..]));
    }
}
