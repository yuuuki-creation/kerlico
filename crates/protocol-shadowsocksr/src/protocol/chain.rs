use super::{Codec, Role};
use crate::{
    config::Protocol,
    crypto::{self, Hash},
    invalid,
};
use kerlico_core::Result;
#[derive(Clone, Copy)]
struct Random(u64, u64);
impl Random {
    fn seed(bytes: &[u8]) -> Self {
        let mut key = [0; 16];
        let count = bytes.len().min(16);
        key[..count].copy_from_slice(&bytes[..count]);
        Self(
            u64::from_le_bytes(key[..8].try_into().expect("固定长度")),
            u64::from_le_bytes(key[8..].try_into().expect("固定长度")),
        )
    }
    fn length(bytes: &[u8], length: usize) -> Self {
        let mut key = [0; 16];
        key.copy_from_slice(&bytes[..16]);
        key[..2].copy_from_slice(&(length as u16).to_le_bytes());
        let mut random = Self::seed(&key);
        for _ in 0..4 {
            random.next();
        }
        random
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        let y = self.1;
        self.0 = y;
        x ^= x.wrapping_shl(23);
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.1 = x;
        x.wrapping_add(y)
    }
}
fn lists(key: &[u8]) -> (Vec<usize>, Vec<usize>) {
    let mut random = Random::seed(key);
    let first = random.next() % 8 + 4;
    let mut a = Vec::new();
    for _ in 0..first {
        a.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    a.sort_unstable();
    let second = random.next() % 16 + 8;
    let mut b = Vec::new();
    for _ in 0..second {
        b.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    b.sort_unstable();
    (a, b)
}
fn layout(
    protocol: Protocol,
    key: &[u8],
    overhead: usize,
    hash: &[u8],
    length: usize,
) -> (usize, usize) {
    let mut random = Random::length(hash, length);
    let fallback = |random: &mut Random| {
        let modulo = if length > 1300 {
            31
        } else if length > 900 {
            127
        } else if length > 400 {
            521
        } else {
            1021
        };
        (random.next() % modulo) as usize
    };
    let count = if protocol == Protocol::ChainB {
        if length >= 1440 {
            return (0, 0);
        }
        let (first, second) = lists(key);
        let position = first.partition_point(|value| *value < length + overhead);
        let chosen = position + (random.next() % first.len() as u64) as usize;
        if chosen < first.len() {
            first[chosen] - length - overhead
        } else {
            let position = second.partition_point(|value| *value < length + overhead);
            let chosen = position + (random.next() % second.len() as u64) as usize;
            if chosen < second.len() {
                second[chosen] - length - overhead
            } else if chosen < position + second.len() - 1 {
                0
            } else {
                fallback(&mut random)
            }
        }
    } else {
        if length > 1440 {
            return (0, 0);
        }
        fallback(&mut random)
    };
    let position = if count > 0 && length > 0 {
        (random.next() % 8589934609 % count as u64) as usize
    } else {
        0
    };
    (count, position)
}
impl Codec {
    pub(super) fn chain_auth(&mut self, metadata: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut head = crypto::random(4);
        self.last_client = crypto::mac(Hash::Md5, &self.base_mac_key(&self.send_iv), &head);
        head.extend_from_slice(&self.last_client[..8]);
        let mask = u32::from_le_bytes(self.last_client[8..12].try_into().map_err(|_| invalid())?);
        let mut middle = (self.uid ^ mask).to_le_bytes().to_vec();
        let mut plain = metadata.to_vec();
        plain.extend_from_slice(&(self.cfg.overhead() as u16).to_le_bytes());
        plain.extend_from_slice(&[0, 0]);
        middle.extend(crypto::aes_block(&self.block_password(), &plain, true)?);
        self.last_server = crypto::mac(Hash::Md5, &self.user_key, &middle);
        head.extend(middle);
        head.extend_from_slice(&self.last_server[..4]);
        self.init_rc4()?;
        head.extend(self.chain_data(data)?);
        Ok(head)
    }
    pub(super) fn chain_header(&mut self, time: u32) -> Result<bool> {
        if self.buffer.len() < 12 {
            return Ok(false);
        }
        let hash = crypto::mac(
            Hash::Md5,
            &self.base_mac_key(&self.recv_iv),
            &self.buffer[..4],
        );
        if !crypto::equal(&hash[..8], &self.buffer[4..12]) {
            return Err(invalid());
        }
        if self.buffer.len() < 36 {
            return Ok(false);
        }
        self.last_client = hash;
        let uid = u32::from_le_bytes(self.buffer[12..16].try_into().map_err(|_| invalid())?)
            ^ u32::from_le_bytes(self.last_client[8..12].try_into().map_err(|_| invalid())?);
        let (uid, key) = self.user(uid)?;
        self.uid = uid;
        self.user_key = key;
        self.last_server = crypto::mac(Hash::Md5, &self.user_key, &self.buffer[12..32]);
        if !crypto::equal(&self.last_server[..4], &self.buffer[32..36]) {
            return Err(invalid());
        }
        let plain = crypto::aes_block(&self.block_password(), &self.buffer[16..32], false)?;
        self.peer_overhead = usize::from(u16::from_le_bytes(
            plain[12..14].try_into().map_err(|_| invalid())?,
        ));
        if self.peer_overhead >= usize::from(self.mss) || self.peer_overhead > 1024 {
            return Err(invalid());
        }
        self.cfg.replay.auth(
            self.cfg.protocol.salt(),
            uid,
            &plain[..12],
            self.cfg.limits.auth_window_secs,
            time,
        )?;
        self.init_rc4()?;
        self.buffer.drain(..36);
        Ok(true)
    }
    pub(super) fn chain_data(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let client = self.role == Role::Client;
        let previous = if client {
            &self.last_client
        } else {
            &self.last_server
        };
        let (padding, position) = layout(
            self.cfg.protocol,
            &self.cfg.key,
            self.cfg.overhead(),
            previous,
            data.len(),
        );
        let mut encoded = data.to_vec();
        self.cipher_send
            .as_mut()
            .ok_or_else(invalid)?
            .apply(&mut encoded, true)?;
        let random = crypto::random(padding);
        let length = data.len() as u16
            ^ u16::from_le_bytes(previous[14..16].try_into().map_err(|_| invalid())?);
        let mut bytes = length.to_le_bytes().to_vec();
        bytes.extend_from_slice(&random[..position]);
        bytes.extend(encoded);
        bytes.extend_from_slice(&random[position..]);
        let hash = crypto::mac(Hash::Md5, &self.packet_key(self.send_id), &bytes);
        bytes.extend_from_slice(&hash[..2]);
        if client {
            self.last_client = hash;
        } else {
            self.last_server = hash;
        }
        self.next_send()?;
        Ok(bytes)
    }
    pub(super) fn chain_decode(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buffer.len() < 2 {
            return Ok(None);
        }
        let client = self.role == Role::Client;
        let previous = if client {
            &self.last_server
        } else {
            &self.last_client
        };
        let length = usize::from(
            u16::from_le_bytes(self.buffer[..2].try_into().map_err(|_| invalid())?)
                ^ u16::from_le_bytes(previous[14..16].try_into().map_err(|_| invalid())?),
        );
        let (padding, position) = layout(
            self.cfg.protocol,
            &self.cfg.key,
            self.cfg.overhead(),
            previous,
            length,
        );
        if length + padding >= 4096 {
            return Err(invalid());
        }
        let total = length + padding + 4;
        if self.buffer.len() < total {
            return Ok(None);
        }
        let frame = self.buffer[..total].to_vec();
        let hash = crypto::mac(
            Hash::Md5,
            &self.packet_key(self.receive_id),
            &frame[..total - 2],
        );
        if !crypto::equal(&hash[..2], &frame[total - 2..]) {
            return Err(invalid());
        }
        let mut data = frame[2 + position..2 + position + length].to_vec();
        self.cipher_receive
            .as_mut()
            .ok_or_else(invalid)?
            .apply(&mut data, false)?;
        if client && self.receive_id == 1 {
            if data.len() < 2 {
                return Err(invalid());
            }
            self.mss = u16::from_le_bytes(data[..2].try_into().map_err(|_| invalid())?);
            if self.mss < 256 {
                return Err(invalid());
            }
            data.drain(..2);
        }
        if client {
            self.last_server = hash;
        } else {
            self.last_client = hash;
        }
        self.next_receive()?;
        self.buffer.drain(..total);
        Ok(Some(data))
    }
}
pub(super) fn udp_layout(hash: &[u8]) -> usize {
    (Random::seed(hash).next() % 127) as usize
}
