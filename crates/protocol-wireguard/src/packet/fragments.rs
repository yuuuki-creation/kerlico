use super::{IpPacket, ip_packet, malformed};
use kerlico_core::{Error, Result};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub(crate) struct FragmentBudget {
    packets: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}
impl FragmentBudget {
    pub fn new(packets: usize, bytes: usize) -> Self {
        Self {
            packets: Arc::new(Semaphore::new(packets)),
            bytes: Arc::new(Semaphore::new(bytes)),
        }
    }
}
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Key {
    source: IpAddr,
    target: IpAddr,
    protocol: u8,
    id: u32,
}
struct Piece {
    data: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}
struct Assembly {
    pieces: BTreeMap<usize, Piece>,
    total: Option<usize>,
    expires: Instant,
    hop_limit: u8,
    _budget: OwnedSemaphorePermit,
}
pub(crate) struct Reassembler {
    budget: FragmentBudget,
    entries: HashMap<Key, Assembly>,
    rejected: HashMap<Key, Instant>,
}
impl Reassembler {
    pub fn new(budget: FragmentBudget) -> Self {
        Self {
            budget,
            entries: HashMap::new(),
            rejected: HashMap::new(),
        }
    }
    pub fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.expires > now);
        self.rejected.retain(|_, expiry| *expiry > now);
    }
    pub fn accept(&mut self, bytes: &[u8], now: Instant) -> Result<Option<Vec<u8>>> {
        self.expire(now);
        let packet = IpPacket::parse(bytes)?;
        let Some(fragment) = &packet.fragment else {
            return ip_packet(
                packet.source,
                packet.target,
                packet.protocol,
                packet.payload,
                packet.hop_limit,
            )
            .map(Some);
        };
        let key = Key {
            source: packet.source,
            target: packet.target,
            protocol: packet.protocol,
            id: fragment.id,
        };
        if self.rejected.contains_key(&key) {
            return Err(malformed());
        }
        let end = fragment
            .offset
            .checked_add(packet.payload.len())
            .ok_or_else(malformed)?;
        let maximum = if packet.source.is_ipv4() {
            65515
        } else {
            65535
        };
        if packet.payload.is_empty()
            || end > maximum
            || fragment.more && !packet.payload.len().is_multiple_of(8)
        {
            self.reject(key, now);
            return Err(malformed());
        }
        if !self.entries.contains_key(&key) {
            let lease = self
                .budget
                .packets
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?;
            self.entries.insert(
                key,
                Assembly {
                    pieces: BTreeMap::new(),
                    total: None,
                    expires: now + Duration::from_secs(30),
                    hop_limit: packet.hop_limit,
                    _budget: lease,
                },
            );
        }
        let entry = self.entries.get_mut(&key).ok_or_else(malformed)?;
        let overlap = entry
            .pieces
            .iter()
            .any(|(offset, piece)| fragment.offset < *offset + piece.data.len() && end > *offset);
        let invalid_end = entry
            .total
            .is_some_and(|total| end > total || !fragment.more && end != total)
            || !fragment.more
                && entry
                    .pieces
                    .iter()
                    .any(|(offset, piece)| offset + piece.data.len() > end);
        if overlap || invalid_end || entry.pieces.len() >= 128 {
            self.reject(key, now);
            return Err(malformed());
        }
        let lease = self
            .budget
            .bytes
            .clone()
            .try_acquire_many_owned(packet.payload.len() as u32)
            .map_err(|_| Error::ResourceLimit)?;
        entry.pieces.insert(
            fragment.offset,
            Piece {
                data: packet.payload.to_vec(),
                _budget: lease,
            },
        );
        if !fragment.more {
            entry.total = Some(end);
        }
        let Some(total) = entry.total else {
            return Ok(None);
        };
        let mut position = 0;
        for (offset, piece) in &entry.pieces {
            if *offset != position {
                return Ok(None);
            }
            position += piece.data.len();
        }
        if position != total {
            return Ok(None);
        }
        let entry = self.entries.remove(&key).ok_or_else(malformed)?;
        let mut payload = Vec::with_capacity(total);
        for piece in entry.pieces.values() {
            payload.extend_from_slice(&piece.data);
        }
        let packet = ip_packet(
            key.source,
            key.target,
            key.protocol,
            &payload,
            entry.hop_limit,
        )?;
        let parsed = IpPacket::parse(&packet)?;
        if parsed.fragment.is_some() {
            return Err(malformed());
        }
        ip_packet(
            parsed.source,
            parsed.target,
            parsed.protocol,
            parsed.payload,
            parsed.hop_limit,
        )
        .map(Some)
    }
    fn reject(&mut self, key: Key, now: Instant) {
        self.entries.remove(&key);
        if self.rejected.len() < 128 {
            self.rejected.insert(key, now + Duration::from_secs(30));
        }
    }
}

pub(crate) fn fragment(bytes: Vec<u8>, mtu: usize, id: u32) -> Result<Vec<Vec<u8>>> {
    if bytes.len() <= mtu {
        return Ok(vec![bytes]);
    }
    let packet = IpPacket::parse(&bytes)?;
    if packet.fragment.is_some() || mtu < 1280 {
        return Err(malformed());
    }
    let header = if packet.source.is_ipv4() { 20 } else { 48 };
    let part = (mtu - header) & !7;
    let mut output = Vec::new();
    let mut offset = 0;
    while offset < packet.payload.len() {
        let end = (offset + part).min(packet.payload.len());
        let more = end != packet.payload.len();
        let payload = &packet.payload[offset..end];
        let mut fragment = if packet.source.is_ipv4() {
            let mut fragment = ip_packet(
                packet.source,
                packet.target,
                packet.protocol,
                payload,
                packet.hop_limit,
            )?;
            fragment[4..6].copy_from_slice(&(id as u16).to_be_bytes());
            let field = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
            fragment[6..8].copy_from_slice(&field.to_be_bytes());
            fragment[10..12].fill(0);
            let check = super::checksum(&fragment[..20]);
            fragment[10..12].copy_from_slice(&check.to_be_bytes());
            fragment
        } else {
            let mut extended = vec![0; 8 + payload.len()];
            extended[0] = packet.protocol;
            let field = offset as u16 | u16::from(more);
            extended[2..4].copy_from_slice(&field.to_be_bytes());
            extended[4..8].copy_from_slice(&id.to_be_bytes());
            extended[8..].copy_from_slice(payload);
            ip_packet(
                packet.source,
                packet.target,
                44,
                &extended,
                packet.hop_limit,
            )?
        };
        fragment.shrink_to_fit();
        output.push(fragment);
        offset = end;
    }
    Ok(output)
}
