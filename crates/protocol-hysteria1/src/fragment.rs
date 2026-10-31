//! 分片按会话与消息隔离，冲突、缺片与超限均不得交付部分负载。
use crate::wire::{MAX_PACKET, Packet};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};
const TTL: Duration = Duration::from_secs(10);
const MAX_GROUPS: usize = 128;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECENT: usize = 65536;
type Key = (u64, u32, u16);
struct Group {
    target: kerlico_core::Destination,
    count: u8,
    parts: Vec<Option<Vec<u8>>>,
    seen: usize,
    bytes: usize,
    deadline: Instant,
}
pub(crate) struct Reassembler {
    groups: HashMap<Key, Group>,
    expiry: VecDeque<(Instant, Key)>,
    recent: HashMap<Key, Instant>,
    recent_expiry: VecDeque<(Instant, Key)>,
    bytes: usize,
    maximum: usize,
}
impl Reassembler {
    pub fn new(maximum: usize) -> Self {
        Self {
            groups: HashMap::new(),
            expiry: VecDeque::new(),
            recent: HashMap::new(),
            recent_expiry: VecDeque::new(),
            bytes: 0,
            maximum: maximum.min(MAX_PACKET),
        }
    }
    pub fn prune(&mut self, now: Instant) {
        while self.expiry.front().is_some_and(|(time, _)| *time <= now) {
            let Some((time, key)) = self.expiry.pop_front() else {
                break;
            };
            if self
                .groups
                .get(&key)
                .is_some_and(|group| group.deadline == time)
            {
                self.discard(key);
            }
        }
        while self
            .recent_expiry
            .front()
            .is_some_and(|(time, _)| *time <= now)
        {
            let Some((time, key)) = self.recent_expiry.pop_front() else {
                break;
            };
            if self.recent.get(&key) == Some(&time) {
                self.recent.remove(&key);
            }
        }
        if self.expiry.len() > MAX_GROUPS * 2 {
            self.expiry.retain(|(time, key)| {
                self.groups
                    .get(key)
                    .is_some_and(|group| group.deadline == *time)
            });
        }
        if self.recent_expiry.len() > MAX_RECENT * 2 {
            self.recent_expiry
                .retain(|(time, key)| self.recent.get(key) == Some(time));
        }
    }
    fn discard(&mut self, key: Key) {
        if let Some(group) = self.groups.remove(&key) {
            self.bytes -= group.bytes;
        }
    }
    fn remember(&mut self, key: Key, now: Instant) {
        if self.recent.len() < MAX_RECENT {
            let deadline = now + TTL;
            self.recent.insert(key, deadline);
            self.recent_expiry.push_back((deadline, key));
        }
    }
    pub fn remove_session(&mut self, session: u32, generation: u64) {
        let keys: Vec<_> = self
            .groups
            .keys()
            .copied()
            .filter(|(epoch, id, _)| *epoch == generation && *id == session)
            .collect();
        for key in keys {
            self.discard(key);
        }
        self.recent
            .retain(|(epoch, id, _), _| *epoch != generation || *id != session);
    }
    pub fn feed(&mut self, packet: Packet, generation: u64, now: Instant) -> Option<Packet> {
        self.prune(now);
        if packet.data.len() > self.maximum {
            return None;
        }
        if packet.count == 1 {
            return Some(packet);
        }
        if packet.count == 0 || packet.index >= packet.count || packet.message == 0 {
            return None;
        }
        let key = (generation, packet.session, packet.message);
        if self.recent.contains_key(&key) {
            return None;
        }
        if !self.groups.contains_key(&key) {
            if self.groups.len() >= MAX_GROUPS || self.recent.len() >= MAX_RECENT {
                return None;
            }
            let deadline = now + TTL;
            self.groups.insert(
                key,
                Group {
                    target: packet.target.clone(),
                    count: packet.count,
                    parts: (0..packet.count).map(|_| None).collect(),
                    seen: 0,
                    bytes: 0,
                    deadline,
                },
            );
            self.expiry.push_back((deadline, key));
        }
        let group = self.groups.get(&key)?;
        let mismatch = group.target != packet.target
            || group.count != packet.count
            || group.parts[packet.index as usize]
                .as_ref()
                .is_some_and(|bytes| bytes != &packet.data);
        if mismatch {
            self.discard(key);
            self.remember(key, now);
            return None;
        }
        if group.parts[packet.index as usize].is_some() {
            return None;
        }
        if group.bytes + packet.data.len() > self.maximum
            || self.bytes + packet.data.len() > MAX_BYTES
        {
            self.discard(key);
            self.remember(key, now);
            return None;
        }
        let group = self.groups.get_mut(&key)?;
        group.bytes += packet.data.len();
        self.bytes += packet.data.len();
        group.parts[packet.index as usize] = Some(packet.data);
        group.seen += 1;
        if group.seen != group.count as usize {
            return None;
        }
        let group = self.groups.remove(&key)?;
        self.bytes -= group.bytes;
        self.remember(key, now);
        let mut data = Vec::with_capacity(group.bytes);
        for part in group.parts {
            data.extend_from_slice(&part?);
        }
        Some(Packet {
            session: key.1,
            target: group.target,
            message: key.2,
            index: 0,
            count: 1,
            data,
        })
    }
}
pub(crate) struct Sequence {
    next: u32,
    blocked_until: Option<Instant>,
}
impl Sequence {
    pub fn new() -> Self {
        Self {
            next: 1,
            blocked_until: None,
        }
    }
    pub fn next(&mut self, now: Instant) -> kerlico_core::Result<u16> {
        if self.next > u16::MAX as u32 {
            let until = *self.blocked_until.get_or_insert(now + TTL);
            if now < until {
                return Err(kerlico_core::Error::ResourceLimit);
            }
            self.next = 1;
            self.blocked_until = None;
        }
        let value = self.next as u16;
        self.next += 1;
        if self.next > u16::MAX as u32 {
            self.blocked_until = Some(now + TTL);
        }
        Ok(value)
    }
}
pub(crate) fn split(
    mut packet: Packet,
    maximum: usize,
    sequence: &mut Sequence,
    now: Instant,
) -> kerlico_core::Result<Vec<Packet>> {
    if packet.data.len() > MAX_PACKET || maximum <= packet.header_len() {
        return Err(kerlico_core::Error::ResourceLimit);
    }
    let size = maximum - packet.header_len();
    if packet.data.len() <= size {
        packet.count = 1;
        packet.index = 0;
        packet.message = 0;
        return Ok(vec![packet]);
    }
    let count = packet.data.len().div_ceil(size);
    if count > u8::MAX as usize {
        return Err(kerlico_core::Error::ResourceLimit);
    }
    let id = sequence.next(now)?;
    let mut output = Vec::with_capacity(count);
    for (index, data) in packet.data.chunks(size).enumerate() {
        output.push(Packet {
            session: packet.session,
            target: packet.target.clone(),
            message: id,
            index: index as u8,
            count: count as u8,
            data: data.to_vec(),
        });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(id: u32, bytes: usize) -> Packet {
        Packet {
            session: id,
            target: kerlico_core::Destination::new("127.0.0.1", 53).unwrap(),
            message: 0,
            index: 0,
            count: 1,
            data: vec![id as u8; bytes],
        }
    }
    #[test]
    fn out_of_order_interleaved_sessions_and_duplicates_do_not_mix() {
        let now = Instant::now();
        let mut sequence = Sequence::new();
        let first = split(packet(1, 12000), 1200, &mut sequence, now).unwrap();
        let second = split(packet(2, 4096), 1200, &mut sequence, now).unwrap();
        let mut receiver = Reassembler::new(MAX_PACKET);
        let mut result = Vec::new();
        for index in (0..first.len().max(second.len())).rev() {
            for parts in [&first, &second] {
                if let Some(part) = parts.get(index) {
                    if let Some(done) = receiver.feed(part.clone(), 11, now) {
                        result.push(done);
                    }
                    assert!(receiver.feed(part.clone(), 11, now).is_none());
                }
            }
        }
        result.sort_by_key(|packet| packet.session);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].data, vec![1; 12000]);
        assert_eq!(result[1].data, vec![2; 4096]);
        assert_eq!(receiver.bytes, 0);
    }
    #[test]
    fn missing_conflicting_expired_and_oversized_groups_are_not_forwarded() {
        let now = Instant::now();
        let mut sequence = Sequence::new();
        let parts = split(packet(1, 4096), 1200, &mut sequence, now).unwrap();
        let mut receiver = Reassembler::new(65507);
        assert!(receiver.feed(parts[0].clone(), 1, now).is_none());
        let mut bad = parts[0].clone();
        bad.data[0] ^= 1;
        assert!(receiver.feed(bad, 1, now).is_none());
        for part in &parts {
            assert!(receiver.feed(part.clone(), 1, now).is_none());
        }
        receiver.prune(now + TTL + Duration::from_millis(1));
        for part in &parts {
            let _ = receiver.feed(part.clone(), 2, now + TTL + Duration::from_millis(1));
        }
        assert_eq!(receiver.groups.len(), 0);
        let mut receiver = Reassembler::new(100);
        for part in parts {
            assert!(receiver.feed(part, 1, now).is_none());
        }
        assert_eq!(receiver.bytes, 0);
    }
    #[test]
    fn fragment_id_exhaustion_waits_for_old_messages_to_expire() {
        let now = Instant::now();
        let mut sequence = Sequence {
            next: u16::MAX as u32,
            blocked_until: None,
        };
        assert_eq!(sequence.next(now).unwrap(), u16::MAX);
        assert!(sequence.next(now).is_err());
        assert_eq!(
            sequence.next(now + TTL + Duration::from_millis(1)).unwrap(),
            1
        );
        assert!(split(packet(1, 65507), 40, &mut sequence, now).is_err());
    }
}
