use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use smoltcp::wire::IpProtocol;

use crate::PeerId;

const MAX_PENDING: usize = 128;
const MAX_PARTS: usize = 128;
const MAX_BYTES: usize = 65_535 - 20;
const EXPIRES: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub(crate) struct Fragment {
    pub(crate) id: u32,
    pub(crate) offset: usize,
    pub(crate) more: bool,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Key {
    peer: PeerId,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u32,
}

struct Pending {
    until: Instant,
    last: Option<usize>,
    data: BTreeMap<usize, Vec<u8>>,
}

#[derive(Default)]
pub(crate) struct Reassembly(HashMap<Key, Pending>);

impl Reassembly {
    pub(crate) fn insert(
        &mut self,
        peer: PeerId,
        src: IpAddr,
        dst: IpAddr,
        proto: IpProtocol,
        frame: Fragment,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let key = Key {
            peer,
            src,
            dst,
            protocol: proto.into(),
            id: frame.id,
        };
        let end = frame.offset.checked_add(data.len())?;
        if data.is_empty() || end > MAX_BYTES || (frame.more && data.len() % 8 != 0) {
            self.0.remove(&key);
            return None;
        }
        let now = Instant::now();
        if self.0.get(&key).is_some_and(|entry| now >= entry.until) {
            self.0.remove(&key);
        }
        if self.0.len() >= MAX_PENDING && !self.0.contains_key(&key) {
            self.0.retain(|_, entry| now < entry.until);
            if self.0.len() >= MAX_PENDING {
                return None;
            }
        }
        let entry = self.0.entry(key).or_insert_with(|| Pending {
            until: now + EXPIRES,
            last: None,
            data: BTreeMap::new(),
        });
        // Discard the full datagram on overlaps, inconsistent lengths or excessive fragments.
        if entry.data.len() >= MAX_PARTS
            || entry
                .last
                .is_some_and(|length| end > length || (!frame.more && end != length))
            || entry
                .data
                .range(..end)
                .next_back()
                .is_some_and(|(start, bytes)| start + bytes.len() > frame.offset)
            || (!frame.more && entry.data.keys().any(|start| *start >= end))
        {
            self.0.remove(&key);
            return None;
        }
        entry.data.insert(frame.offset, data.to_vec());
        if !frame.more {
            entry.last = Some(end);
        }
        let length = entry.last?;
        let mut next = 0;
        for (offset, data) in &entry.data {
            if *offset != next {
                return None;
            }
            next += data.len();
        }
        if next != length {
            return None;
        }
        let entry = self.0.remove(&key).expect("reassembled datagram");
        let mut joined = Vec::with_capacity(next);
        for bytes in entry.data.into_values() {
            joined.extend(bytes);
        }
        Some(joined)
    }

    pub(crate) fn remove_peer(&mut self, peer: PeerId) {
        self.0.retain(|key, _| key.peer != peer);
    }
}
