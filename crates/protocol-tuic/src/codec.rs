//! TUIC v4/v5 格式，地址与整包语义独立于 QUIC 数据路径。
use kerlico_core::{Address, Destination, Error, Result};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt};
pub(crate) const MAX_PACKET: usize = 65507;
pub(crate) fn malformed() -> Error {
    Error::Protocol("TUIC 命令或分片格式不合法")
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Native,
    Quic,
}
impl Mode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "native" => Ok(Self::Native),
            "quic" => Ok(Self::Quic),
            _ => Err(Error::Config("TUIC udp_relay_mode 不合法".into())),
        }
    }
}
pub(crate) fn address(out: &mut Vec<u8>, value: Option<&Destination>) {
    let Some(value) = value else {
        out.push(255);
        return;
    };
    match value.address() {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend(ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(2);
            out.extend(ip.octets());
        }
        Address::Domain(name) => {
            out.extend([0, name.len() as u8]);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend(value.port().to_be_bytes());
}
pub(crate) async fn read_address<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Destination> {
    let kind = reader.read_u8().await?;
    let length = match kind {
        0 => usize::from(reader.read_u8().await?),
        1 => 4,
        2 => 16,
        _ => return Err(malformed()),
    };
    if length == 0 {
        return Err(malformed());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    let host = match kind {
        0 => String::from_utf8(bytes).map_err(|_| malformed())?,
        1 => std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes.as_slice()).map_err(|_| malformed())?,
        )
        .to_string(),
        2 => std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| malformed())?,
        )
        .to_string(),
        _ => return Err(malformed()),
    };
    let port = reader.read_u16().await?;
    Destination::new(&host, port)
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if input.len() < n {
        return Err(malformed());
    }
    let (out, rest) = input.split_at(n);
    *input = rest;
    Ok(out)
}
fn parse_address(input: &mut &[u8]) -> Result<Option<Destination>> {
    let kind = take(input, 1)?[0];
    if kind == 255 {
        return Ok(None);
    }
    let n = match kind {
        0 => usize::from(take(input, 1)?[0]),
        1 => 4,
        2 => 16,
        _ => return Err(malformed()),
    };
    if n == 0 {
        return Err(malformed());
    }
    let bytes = take(input, n)?;
    let host = match kind {
        0 => std::str::from_utf8(bytes)
            .map_err(|_| malformed())?
            .to_owned(),
        1 => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes).map_err(|_| malformed())?)
            .to_string(),
        2 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).map_err(|_| malformed())?)
            .to_string(),
        _ => return Err(malformed()),
    };
    let port = u16::from_be_bytes(take(input, 2)?.try_into().map_err(|_| malformed())?);
    Ok(Some(Destination::new(&host, port)?))
}
#[derive(Clone)]
pub(crate) struct Packet {
    pub assoc: u32,
    pub id: u16,
    pub total: u8,
    pub fragment: u8,
    pub target: Option<Destination>,
    pub data: Vec<u8>,
}
pub(crate) fn packet(version: u8, value: &Packet) -> Result<Vec<u8>> {
    if value.data.len() > MAX_PACKET
        || !matches!(version, 4 | 5)
        || version == 5 && value.assoc > 65535
    {
        return Err(malformed());
    }
    let mut out = vec![version, 2];
    if version == 4 {
        if value.target.is_none() || value.total != 1 || value.fragment != 0 {
            return Err(malformed());
        }
        out.extend(value.assoc.to_be_bytes());
        out.extend((value.data.len() as u16).to_be_bytes());
    } else {
        out.extend((value.assoc as u16).to_be_bytes());
        out.extend(value.id.to_be_bytes());
        out.extend([value.total, value.fragment]);
        out.extend((value.data.len() as u16).to_be_bytes());
    }
    address(&mut out, value.target.as_ref());
    out.extend_from_slice(&value.data);
    Ok(out)
}
pub(crate) fn decode_packet(version: u8, mut input: &[u8]) -> Result<Packet> {
    if take(&mut input, 2)? != [version, 2] {
        return Err(malformed());
    }
    let (assoc, id, total, fragment) = if version == 4 {
        (
            u32::from_be_bytes(take(&mut input, 4)?.try_into().map_err(|_| malformed())?),
            0,
            1,
            0,
        )
    } else if version == 5 {
        let assoc =
            u16::from_be_bytes(take(&mut input, 2)?.try_into().map_err(|_| malformed())?) as u32;
        let id = u16::from_be_bytes(take(&mut input, 2)?.try_into().map_err(|_| malformed())?);
        let count = take(&mut input, 2)?;
        (assoc, id, count[0], count[1])
    } else {
        return Err(malformed());
    };
    let size =
        u16::from_be_bytes(take(&mut input, 2)?.try_into().map_err(|_| malformed())?) as usize;
    let target = parse_address(&mut input)?;
    if input.len() != size
        || size > MAX_PACKET
        || total == 0
        || fragment >= total
        || fragment == 0 && target.is_none()
        || fragment != 0 && target.is_some()
    {
        return Err(malformed());
    }
    Ok(Packet {
        assoc,
        id,
        total,
        fragment,
        target,
        data: input.to_vec(),
    })
}
pub(crate) fn dissociate(version: u8, assoc: u32) -> Vec<u8> {
    let mut out = vec![version, 3];
    if version == 4 {
        out.extend(assoc.to_be_bytes());
    } else {
        out.extend((assoc as u16).to_be_bytes());
    }
    out
}
pub(crate) fn dissociation(version: u8, input: &[u8]) -> Result<u32> {
    if input.get(..2) != Some(&[version, 3]) {
        return Err(malformed());
    }
    match (version, input.len()) {
        (4, 6) => Ok(u32::from_be_bytes(
            input[2..].try_into().map_err(|_| malformed())?,
        )),
        (5, 4) => Ok(u16::from_be_bytes(input[2..].try_into().map_err(|_| malformed())?) as u32),
        _ => Err(malformed()),
    }
}
struct Bag {
    total: u8,
    target: Option<Destination>,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
    created: Instant,
    mode: Mode,
}
pub(crate) struct Reassembler {
    bags: HashMap<(u32, u16), Bag>,
}
impl Reassembler {
    pub fn new() -> Self {
        Self {
            bags: HashMap::new(),
        }
    }
    pub fn remove(&mut self, assoc: u32) {
        self.bags.retain(|(id, _), _| *id != assoc);
    }
    pub fn feed(&mut self, packet: Packet, mode: Mode) -> Result<Option<Packet>> {
        let now = Instant::now();
        self.bags
            .retain(|_, bag| now.duration_since(bag.created) < Duration::from_secs(5));
        if packet.total == 1 {
            return Ok(Some(packet));
        }
        let key = (packet.assoc, packet.id);
        if !self.bags.contains_key(&key) {
            if self.bags.len() >= 64
                || self.bags.values().map(|v| v.bytes).sum::<usize>() + packet.data.len()
                    > 2 * 1024 * 1024
            {
                return Err(Error::ResourceLimit);
            }
            self.bags.insert(
                key,
                Bag {
                    total: packet.total,
                    target: None,
                    parts: vec![None; packet.total as usize],
                    bytes: 0,
                    created: now,
                    mode,
                },
            );
        }
        if self.bags.values().map(|bag| bag.bytes).sum::<usize>() + packet.data.len()
            > 2 * 1024 * 1024
        {
            return Err(Error::ResourceLimit);
        }
        let bag = self.bags.get_mut(&key).ok_or_else(malformed)?;
        if bag.total != packet.total || bag.mode != mode {
            return Err(malformed());
        }
        let slot = &mut bag.parts[packet.fragment as usize];
        if let Some(previous) = slot {
            if previous != &packet.data {
                return Err(malformed());
            }
            return Ok(None);
        }
        bag.bytes = bag
            .bytes
            .checked_add(packet.data.len())
            .ok_or(Error::ResourceLimit)?;
        if bag.bytes > MAX_PACKET {
            return Err(Error::ResourceLimit);
        }
        if packet.fragment == 0 {
            bag.target = packet.target;
        }
        *slot = Some(packet.data);
        if bag.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let bag = self.bags.remove(&key).ok_or_else(malformed)?;
        let mut data = Vec::with_capacity(bag.bytes);
        for fragment in bag.parts {
            data.extend(fragment.ok_or_else(malformed)?);
        }
        Ok(Some(Packet {
            assoc: key.0,
            id: key.1,
            total: 1,
            fragment: 0,
            target: bag.target,
            data,
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_versions_addresses_and_empty_packets() {
        for version in [4, 5] {
            for host in ["192.0.2.1", "2001:db8::1", "example.invalid"] {
                let target = Destination::new(host, 443).unwrap();
                let value = Packet {
                    assoc: 42,
                    id: 7,
                    total: 1,
                    fragment: 0,
                    target: Some(target.clone()),
                    data: Vec::new(),
                };
                let wire = packet(version, &value).unwrap();
                let parsed = decode_packet(version, &wire).unwrap();
                assert_eq!(parsed.target, Some(target));
                assert!(parsed.data.is_empty());
                for cut in 0..wire.len() {
                    assert!(decode_packet(version, &wire[..cut]).is_err());
                }
            }
        }
    }
    #[test]
    fn fragmented_packets_reassemble_out_of_order_and_reject_conflicts() {
        let target = Destination::new("192.0.2.1", 53).unwrap();
        let mut state = Reassembler::new();
        let mut packet = Packet {
            assoc: 1,
            id: 2,
            total: 2,
            fragment: 1,
            target: None,
            data: vec![2; 5],
        };
        assert!(state.feed(packet.clone(), Mode::Native).unwrap().is_none());
        assert!(state.feed(packet.clone(), Mode::Native).unwrap().is_none());
        packet.data = vec![3; 5];
        assert!(state.feed(packet.clone(), Mode::Native).is_err());
        packet.fragment = 0;
        packet.target = Some(target.clone());
        packet.data = vec![1; 5];
        let complete = state.feed(packet, Mode::Native).unwrap().unwrap();
        assert_eq!(complete.target, Some(target));
        assert_eq!(complete.data, [vec![1; 5], vec![2; 5]].concat());
    }
}
