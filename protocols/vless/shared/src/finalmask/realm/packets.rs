use std::collections::{BTreeMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::{decode_bytes, invalid, random_below};

const PUNCH_SALT: usize = 8;
const PUNCH_MAGIC: &[u8; 8] = b"HYRLMv1\0";
const PUNCH_MIN: usize = 33;
const PUNCH_PADDING: usize = 1024;
pub(super) const PUNCH_MAX: usize = PUNCH_MIN + PUNCH_PADDING;
const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct Punch {
    nonce: [u8; 16],
    key: [u8; 32],
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct PunchMetadata {
    pub(super) nonce: String,
    obfs: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Message {
    Hello = 1,
    Ack = 2,
}

impl Punch {
    pub(super) fn random() -> io::Result<Self> {
        let mut nonce = [0; 16];
        let mut key = [0; 32];
        random(&mut nonce)?;
        random(&mut key)?;
        Ok(Self { nonce, key })
    }

    pub(super) fn from_metadata(meta: PunchMetadata) -> io::Result<Self> {
        let hex = |value| decode_bytes(Value::String(value), "hex");
        let nonce = hex(meta.nonce)?
            .try_into()
            .map_err(|_| invalid("invalid Realm punch nonce"))?;
        let key = hex(meta.obfs)?
            .try_into()
            .map_err(|_| invalid("invalid Realm punch key"))?;
        Ok(Self { nonce, key })
    }

    pub(super) fn metadata(self) -> PunchMetadata {
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect();
        PunchMetadata {
            nonce: hex(&self.nonce),
            obfs: hex(&self.key),
        }
    }

    pub(super) fn encode(self, message: Message) -> io::Result<Vec<u8>> {
        let padding = random_below((PUNCH_PADDING + 1) as u32) as usize;
        let mut wire = vec![0; PUNCH_MIN + padding];
        random(&mut wire[..PUNCH_SALT])?;
        random(&mut wire[PUNCH_MIN..])?;
        wire[PUNCH_SALT..16].copy_from_slice(PUNCH_MAGIC);
        wire[16] = message as u8;
        wire[17..PUNCH_MIN].copy_from_slice(&self.nonce);
        let (salt, body) = wire.split_at_mut(PUNCH_SALT);
        for (byte, mask) in body.iter_mut().zip(self.mask(salt).iter().cycle()) {
            *byte ^= mask;
        }
        Ok(wire)
    }

    pub(super) fn decode(self, wire: &[u8]) -> Option<Message> {
        if !(PUNCH_MIN..=PUNCH_MAX).contains(&wire.len()) {
            return None;
        }
        let (salt, body) = wire.split_at(PUNCH_SALT);
        let mask = self.mask(salt);
        let plain: [u8; PUNCH_MIN - PUNCH_SALT] =
            std::array::from_fn(|index| body[index] ^ mask[index]);
        if &plain[..8] != PUNCH_MAGIC || plain[9..] != self.nonce {
            return None;
        }
        match plain[8] {
            1 => Some(Message::Hello),
            2 => Some(Message::Ack),
            _ => None,
        }
    }

    fn mask(self, salt: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.key);
        hash.update(salt);
        hash.finalize().into()
    }
}

fn random(bytes: &mut [u8]) -> io::Result<()> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|err| io::Error::other(err.to_string()))
}

pub(super) type Transaction = [u8; 12];

pub(super) fn stun_request() -> io::Result<(Transaction, [u8; 20])> {
    let mut tx = [0; 12];
    random(&mut tx)?;
    let mut request = [0; 20];
    request[1] = 1;
    request[4..8].copy_from_slice(&STUN_COOKIE);
    request[8..].copy_from_slice(&tx);
    Ok((tx, request))
}

pub(super) fn stun_response(packet: &[u8]) -> Option<(Transaction, SocketAddr)> {
    let header = packet.get(..20)?;
    if header[..2] != [1, 1] || header[4..8] != STUN_COOKIE {
        return None;
    }
    let mut attributes =
        packet.get(20..20 + usize::from(u16::from_be_bytes([header[2], header[3]])))?;
    let tx = header[8..20].try_into().ok()?;
    let mut mapped = None;
    while let Some(attribute) = attributes.get(..4) {
        let kind = u16::from_be_bytes([attribute[0], attribute[1]]);
        let len = usize::from(u16::from_be_bytes([attribute[2], attribute[3]]));
        if kind == 0x0020 || kind == 0x0001 {
            if let Some(addr) =
                mapped_address(attributes.get(4..4 + len)?, kind == 0x0020, &header[4..20])
            {
                if kind == 0x0020 {
                    return Some((tx, addr));
                }
                mapped = Some(addr);
            }
        }
        attributes = attributes.get(4 + len.next_multiple_of(4)..)?;
    }
    mapped.map(|addr| (tx, addr))
}

fn mapped_address(attr: &[u8], xor: bool, mask: &[u8]) -> Option<SocketAddr> {
    let header = attr.get(..4)?;
    let mut port = u16::from_be_bytes([header[2], header[3]]);
    if xor {
        port ^= u16::from_be_bytes([mask[0], mask[1]]);
    }
    if port == 0 {
        return None;
    }
    let ip = match (header[1], attr.len()) {
        (1, 8) => {
            let octets: [u8; 4] = std::array::from_fn(|i| {
                if xor {
                    attr[4 + i] ^ mask[i]
                } else {
                    attr[4 + i]
                }
            });
            IpAddr::from(octets)
        }
        (2, 20) => {
            let octets: [u8; 16] = std::array::from_fn(|i| {
                if xor {
                    attr[4 + i] ^ mask[i]
                } else {
                    attr[4 + i]
                }
            });
            IpAddr::from(octets)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip.to_canonical(), port))
}

pub(super) fn stun_servers(names: &[String], ipv4: bool, network: Option<&crate::runtime::CarrierNetwork>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    names
        .iter()
        .filter_map(|name| {
            let addresses = if let Some(network) = network {
                let authority: http::uri::Authority = name.parse().ok()?;
                let family = if ipv4 { crate::socket::AddressFamily::V4 } else { crate::socket::AddressFamily::V6 };
                network.resolve(authority.host().trim_matches(['[', ']']), authority.port_u16()?, Some(family)).ok()?
            } else { name.to_socket_addrs().ok()?.collect() };
            addresses.into_iter()
                .find(|addr| addr.is_ipv4() == ipv4 && seen.insert(*addr))
        })
        .collect()
}

pub(super) fn candidates(locals: &[SocketAddr], peers: &[String]) -> Vec<SocketAddr> {
    let allow4 = locals.iter().any(SocketAddr::is_ipv4);
    let allow6 = locals.iter().any(SocketAddr::is_ipv6);
    let mut seen = HashSet::new();
    let mut candidates: Vec<_> = peers
        .iter()
        .filter_map(|peer| peer.parse::<SocketAddr>().ok())
        .filter(|peer| (if peer.is_ipv4() { allow4 } else { allow6 }) && seen.insert(*peer))
        .collect();
    let mut v4 = BTreeMap::new();
    for peer in candidates.iter().filter(|peer| peer.is_ipv4()) {
        v4.entry(peer.ip())
            .or_insert_with(Vec::new)
            .push(peer.port());
    }
    for (ip, mut ports) in v4 {
        ports.sort_unstable();
        ports.dedup();
        if ports.len() < 2 || ports.windows(2).any(|pair| pair[1] - pair[0] > 4) {
            continue;
        }
        let last = ports.last().expect("ports").saturating_add(4);
        candidates.extend(
            (ports[0]..=last)
                .map(|port| SocketAddr::new(ip, port))
                .filter(|peer| seen.insert(*peer))
                .take(32),
        );
    }
    candidates.sort_unstable_by_key(SocketAddr::to_string);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_rfc5769_ipv4_xor_address() {
        let packet = decode_bytes(
            Value::String(
                "0101000c2112a442b7e7a701bc34d686fa87dfae002000080001a147e112a643".into(),
            ),
            "hex",
        )
        .unwrap();
        assert_eq!(
            stun_response(&packet).unwrap().1,
            "192.0.2.1:32853".parse().unwrap()
        );
    }
}
