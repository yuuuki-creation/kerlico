use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use crate::{invalid, put_varint, read_len, split_address, varint_len, MAX_ADDRESS};

const FIXED: usize = 8;
const MAX_PAYLOAD: usize = 65_527;
const PARTIAL_TTL: Duration = Duration::from_secs(5);
const MAX_PARTIAL_PACKETS: usize = 128;
const MAX_PARTIAL_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub session: u32,
    pub id: u16,
    pub index: u8,
    pub count: u8,
    pub address: &'a str,
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn read(wire: &'a [u8]) -> io::Result<Self> {
        let (fixed, mut tail) = wire
            .split_first_chunk::<FIXED>()
            .ok_or_else(|| invalid("short Hysteria UDP header"))?;
        let count = fixed[7];
        let index = fixed[6];
        // Unfragmented packets intentionally ignore their packet and fragment IDs.
        if count == 0 || (count > 1 && index >= count) {
            return Err(invalid("invalid Hysteria UDP fragment index"));
        }
        let len = read_len(&mut tail, MAX_ADDRESS)?;
        let (address, payload) = tail
            .split_at_checked(len)
            .ok_or_else(|| invalid("short Hysteria UDP address"))?;
        let address =
            std::str::from_utf8(address).map_err(|_| invalid("invalid Hysteria UDP address"))?;
        split_address(address)?;
        if payload.len() > MAX_PAYLOAD {
            return Err(invalid("Hysteria UDP payload too long"));
        }
        Ok(Self {
            session: u32::from_be_bytes(fixed[..4].try_into().expect("UDP session")),
            id: u16::from_be_bytes([fixed[4], fixed[5]]),
            index,
            count,
            address,
            payload,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(header_len(self.address) + self.payload.len());
        out.extend(self.session.to_be_bytes());
        out.extend(self.id.to_be_bytes());
        out.extend([self.index, self.count]);
        put_varint(&mut out, self.address.len());
        out.extend_from_slice(self.address.as_bytes());
        out.extend_from_slice(self.payload);
        out
    }
}

fn header_len(address: &str) -> usize {
    FIXED + varint_len(address.len()) + address.len()
}

/// Slices a UDP payload to fit the QUIC limit. Only fragmented packets reserve
/// an ID, which must be distinct among fragmented packets in flight.
pub fn fragments<'a>(
    session: u32,
    next_id: impl FnOnce() -> u16,
    address: &'a str,
    payload: &'a [u8],
    limit: usize,
) -> io::Result<impl Iterator<Item = Vec<u8>> + 'a> {
    split_address(address)?;
    let chunk = limit
        .checked_sub(header_len(address))
        .ok_or_else(|| invalid("Hysteria UDP header exceeds the datagram limit"))?;
    if payload.len() > MAX_PAYLOAD || (chunk == 0 && !payload.is_empty()) {
        return Err(invalid("Hysteria UDP payload exceeds the datagram limit"));
    }
    let chunk = chunk.max(1);
    let count = u8::try_from(payload.len().div_ceil(chunk).max(1))
        .map_err(|_| invalid("too many Hysteria UDP fragments"))?;
    let id = if count == 1 { 0 } else { next_id() };
    Ok((0..count).map(move |index| {
        let start = usize::from(index) * chunk;
        let end = start.saturating_add(chunk).min(payload.len());
        Packet {
            session,
            id,
            index,
            count,
            address,
            payload: &payload[start..end],
        }
        .encode()
    }))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Datagram {
    pub session: u32,
    pub address: String,
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct Reassembler {
    partial: HashMap<(u32, u16), Partial>,
    bytes: usize,
}

struct Partial {
    start: Instant,
    address: String,
    parts: Vec<Option<Vec<u8>>>,
    pending: usize,
    bytes: usize,
}

impl Reassembler {
    pub fn push(&mut self, packet: Packet<'_>, now: Instant) -> Option<Datagram> {
        let Packet {
            session,
            id,
            index,
            count,
            address,
            payload,
        } = packet;
        if count == 1 {
            return Some(Datagram {
                session,
                address: address.to_owned(),
                payload: payload.to_vec(),
            });
        }
        if count < 2 || index >= count || payload.len() > MAX_PAYLOAD {
            return None;
        }
        self.partial.retain(|_, value| {
            let retain = now.saturating_duration_since(value.start) < PARTIAL_TTL;
            if !retain {
                self.bytes -= value.bytes;
            }
            retain
        });
        let key = (session, id);
        if !self.partial.contains_key(&key) && self.partial.len() == MAX_PARTIAL_PACKETS {
            return None;
        }
        let entry = self.partial.entry(key).or_insert_with(|| Partial {
            start: now,
            address: address.to_owned(),
            parts: vec![None; usize::from(count)],
            pending: usize::from(count),
            bytes: 0,
        });
        if entry.address != address || entry.parts.len() != usize::from(count) {
            return None;
        }
        let part = &mut entry.parts[usize::from(index)];
        if part.is_some() {
            return None;
        }
        if entry.bytes + payload.len() > MAX_PAYLOAD
            || self.bytes + payload.len() > MAX_PARTIAL_BYTES
        {
            self.bytes -= self.partial.remove(&key).expect("partial datagram").bytes;
            return None;
        }
        self.bytes += payload.len();
        entry.bytes += payload.len();
        *part = Some(payload.to_vec());
        entry.pending -= 1;
        if entry.pending != 0 {
            return None;
        }
        let entry = self.partial.remove(&key).expect("complete datagram");
        self.bytes -= entry.bytes;
        let mut payload = Vec::with_capacity(entry.bytes);
        for part in entry.parts.into_iter().flatten() {
            payload.extend(part);
        }
        Some(Datagram {
            session,
            address: entry.address,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_vectors_keep_sessions_and_addresses_separate() {
        let payload = b"ABCDEF";
        let wires: Vec<_> = fragments(0x01020304, || 0x0506, "x:8", payload, 14)
            .unwrap()
            .collect();
        assert_eq!(
            wires,
            [
                b"\x01\x02\x03\x04\x05\x06\x00\x03\x03x:8AB".to_vec(),
                b"\x01\x02\x03\x04\x05\x06\x01\x03\x03x:8CD".to_vec(),
                b"\x01\x02\x03\x04\x05\x06\x02\x03\x03x:8EF".to_vec()
            ]
        );
        let now = Instant::now();
        let mut decoder = Reassembler::default();
        let pieces: Vec<_> = wires
            .iter()
            .map(|wire| Packet::read(wire).unwrap())
            .collect();
        for packet in [&pieces[2], &pieces[2], &pieces[0]] {
            assert!(decoder.push(Packet { ..*packet }, now).is_none());
        }
        assert!(decoder
            .push(
                Packet {
                    session: 7,
                    ..pieces[1]
                },
                now
            )
            .is_none());
        assert!(decoder
            .push(
                Packet {
                    address: "y:8",
                    ..pieces[1]
                },
                now
            )
            .is_none());
        assert_eq!(
            decoder.push(Packet { ..pieces[1] }, now).unwrap().payload,
            payload
        );
    }

    #[test]
    fn stale_fragments_do_not_complete_and_empty_datagrams_are_preserved() {
        let mut decoder = Reassembler::default();
        let now = Instant::now();
        let mut wires = fragments(1, || 2, "a:8", b"abcd", 14).unwrap();
        assert!(decoder
            .push(Packet::read(&wires.next().unwrap()).unwrap(), now)
            .is_none());
        assert!(decoder
            .push(
                Packet::read(&wires.next().unwrap()).unwrap(),
                now + PARTIAL_TTL
            )
            .is_none());
        let mut empty = fragments(
            8,
            || panic!("one fragment does not need an ID"),
            "a:8",
            b"",
            12,
        )
        .unwrap()
        .next()
        .unwrap();
        empty[6] = 200;
        assert!(decoder
            .push(Packet::read(&empty).unwrap(), now)
            .unwrap()
            .payload
            .is_empty());
    }
}
