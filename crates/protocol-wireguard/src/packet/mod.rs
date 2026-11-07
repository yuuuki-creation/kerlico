mod fragments;
pub(crate) use fragments::{FragmentBudget, Reassembler, fragment};

use crate::config::{Addresses, unicast};
use kerlico_core::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FlowTuple {
    pub source: SocketAddr,
    pub target: SocketAddr,
}
pub(crate) struct IpPacket<'a> {
    pub source: IpAddr,
    pub target: IpAddr,
    pub protocol: u8,
    pub payload: &'a [u8],
    pub hop_limit: u8,
    pub fragment: Option<Fragment>,
}
pub(crate) struct Fragment {
    pub id: u32,
    pub offset: usize,
    pub more: bool,
}
impl<'a> IpPacket<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        match bytes.first().map(|byte| byte >> 4) {
            Some(4) => Self::ipv4(bytes),
            Some(6) => Self::ipv6(bytes),
            _ => Err(malformed()),
        }
    }
    fn ipv4(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 20 {
            return Err(malformed());
        }
        let header_len = usize::from(bytes[0] & 15) * 4;
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if header_len < 20
            || header_len > length
            || length != bytes.len()
            || checksum(bytes.get(..header_len).ok_or_else(malformed)?) != 0
        {
            return Err(malformed());
        }
        let mut option = 20;
        while option < header_len {
            match bytes[option] {
                0 if bytes[option..header_len].iter().all(|byte| *byte == 0) => break,
                1 => option += 1,
                _ => return Err(Error::Unsupported("WireGuard不处理IPv4选项")),
            }
        }
        let source = IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
        let target = IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]));
        if !unicast(source) || !unicast(target) || bytes[8] == 0 {
            return Err(malformed());
        }
        let field = u16::from_be_bytes([bytes[6], bytes[7]]);
        if field & 0x8000 != 0 {
            return Err(malformed());
        }
        let offset = usize::from(field & 0x1fff) * 8;
        let more = field & 0x2000 != 0;
        if (more || offset != 0) && field & 0x4000 != 0 {
            return Err(malformed());
        }
        Ok(Self {
            source,
            target,
            protocol: bytes[9],
            payload: &bytes[header_len..],
            hop_limit: bytes[8],
            fragment: (more || offset != 0).then_some(Fragment {
                id: u32::from(u16::from_be_bytes([bytes[4], bytes[5]])),
                offset,
                more,
            }),
        })
    }
    fn ipv6(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 40
            || usize::from(u16::from_be_bytes([bytes[4], bytes[5]])) + 40 != bytes.len()
        {
            return Err(malformed());
        }
        let source = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[8..24]).map_err(|_| malformed())?,
        ));
        let target = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[24..40]).map_err(|_| malformed())?,
        ));
        if !unicast(source) || !unicast(target) || bytes[7] == 0 {
            return Err(malformed());
        }
        let mut protocol = bytes[6];
        let mut offset = 40;
        let mut extensions = 0;
        while matches!(protocol, 0 | 60) {
            extensions += 1;
            if extensions > 8 || offset + 2 > bytes.len() {
                return Err(malformed());
            }
            let size = (usize::from(bytes[offset + 1]) + 1) * 8;
            let header = bytes.get(offset..offset + size).ok_or_else(malformed)?;
            let mut option = 2;
            while option < header.len() {
                let kind = header[option];
                if kind == 0 {
                    option += 1;
                    continue;
                }
                let length = usize::from(*header.get(option + 1).ok_or_else(malformed)?);
                if kind & 0xc0 != 0 || option + length + 2 > header.len() {
                    return Err(malformed());
                }
                option += length + 2;
            }
            protocol = header[0];
            offset += size;
        }
        if protocol == 43 {
            return Err(Error::Unsupported("WireGuard不处理IPv6路由扩展头"));
        }
        let fragment = if protocol == 44 {
            let header = bytes.get(offset..offset + 8).ok_or_else(malformed)?;
            let field = u16::from_be_bytes([header[2], header[3]]);
            if header[1] != 0 || field & 6 != 0 {
                return Err(malformed());
            }
            protocol = header[0];
            offset += 8;
            Some(Fragment {
                id: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                offset: usize::from(field & 0xfff8),
                more: field & 1 != 0,
            })
        } else {
            None
        };
        Ok(Self {
            source,
            target,
            protocol,
            payload: &bytes[offset..],
            hop_limit: bytes[7],
            fragment,
        })
    }
    pub fn tcp_syn(&self) -> Result<Option<FlowTuple>> {
        if self.protocol != 6 || self.fragment.is_some() {
            return Ok(None);
        }
        let tuple = self.tcp_tuple()?;
        let flags = self.payload[13];
        if flags & 0x17 != 2 {
            return Ok(None);
        }
        Ok(Some(tuple))
    }
    pub fn tcp_tuple(&self) -> Result<FlowTuple> {
        if self.protocol != 6 || self.fragment.is_some() {
            return Err(malformed());
        }
        if self.payload.len() < 20
            || usize::from(self.payload[12] >> 4) * 4 < 20
            || usize::from(self.payload[12] >> 4) * 4 > self.payload.len()
            || transport_checksum(self.source, self.target, 6, self.payload) != 0
        {
            return Err(malformed());
        }
        self.tuple()
    }
    pub(crate) fn tuple(&self) -> Result<FlowTuple> {
        let bytes = self.payload.get(..4).ok_or_else(malformed)?;
        let source_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let target_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        if source_port == 0 || target_port == 0 {
            return Err(malformed());
        }
        Ok(FlowTuple {
            source: SocketAddr::new(self.source, source_port),
            target: SocketAddr::new(self.target, target_port),
        })
    }
    pub fn udp(&self) -> Result<(FlowTuple, &'a [u8])> {
        if self.protocol != 17
            || self.fragment.is_some()
            || self.payload.len() < 8
            || usize::from(u16::from_be_bytes([self.payload[4], self.payload[5]]))
                != self.payload.len()
        {
            return Err(malformed());
        }
        let zero = self.payload[6] == 0 && self.payload[7] == 0;
        if zero && self.source.is_ipv6()
            || !zero && transport_checksum(self.source, self.target, 17, self.payload) != 0
        {
            return Err(malformed());
        }
        Ok((self.tuple()?, &self.payload[8..]))
    }
}

pub(crate) fn malformed() -> Error {
    Error::Protocol("WireGuard内部IP包不合法")
}
fn sum(bytes: &[u8]) -> u32 {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    let value: u32 = chunks
        .iter()
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    value + remainder.first().map_or(0, |byte| u32::from(*byte) << 8)
}
fn finish(mut value: u32) -> u16 {
    while value >> 16 != 0 {
        value = (value & 0xffff) + (value >> 16);
    }
    !(value as u16)
}
pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    finish(sum(bytes))
}
pub(crate) fn transport_checksum(
    source: IpAddr,
    target: IpAddr,
    protocol: u8,
    bytes: &[u8],
) -> u16 {
    let pseudo = match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => sum(&source.octets()) + sum(&target.octets()),
        (IpAddr::V6(source), IpAddr::V6(target)) => sum(&source.octets()) + sum(&target.octets()),
        _ => return 1,
    };
    finish(pseudo + u32::from(protocol) + bytes.len() as u32 + sum(bytes))
}
pub(crate) fn ip_packet(
    source: IpAddr,
    target: IpAddr,
    protocol: u8,
    payload: &[u8],
    hop_limit: u8,
) -> Result<Vec<u8>> {
    if source.is_ipv4() != target.is_ipv4() || !unicast(source) || !unicast(target) {
        return Err(malformed());
    }
    let header = if source.is_ipv4() { 20 } else { 40 };
    if payload.len() + if source.is_ipv4() { 20 } else { 0 } > 65535 {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = vec![0; header + payload.len()];
    match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            bytes[0] = 0x45;
            let len = bytes.len() as u16;
            bytes[2..4].copy_from_slice(&len.to_be_bytes());
            bytes[8] = hop_limit;
            bytes[9] = protocol;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&target.octets());
            let check = checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&check.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            bytes[6] = protocol;
            bytes[7] = hop_limit;
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&target.octets());
        }
        _ => return Err(malformed()),
    }
    bytes[header..].copy_from_slice(payload);
    Ok(bytes)
}
pub(crate) fn udp_packet(
    source: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let maximum = if source.is_ipv4() { 65507 } else { 65527 };
    if payload.len() > maximum || source.port() == 0 || target.port() == 0 {
        return Err(Error::ResourceLimit);
    }
    let mut udp = vec![0; payload.len() + 8];
    udp[..2].copy_from_slice(&source.port().to_be_bytes());
    udp[2..4].copy_from_slice(&target.port().to_be_bytes());
    let len = udp.len() as u16;
    udp[4..6].copy_from_slice(&len.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let check = transport_checksum(source.ip(), target.ip(), 17, &udp);
    udp[6..8].copy_from_slice(&(if check == 0 { u16::MAX } else { check }).to_be_bytes());
    ip_packet(source.ip(), target.ip(), 17, &udp, 64)
}

pub(crate) fn rewrite_tcp(bytes: &[u8], source: SocketAddr, target: SocketAddr) -> Result<Vec<u8>> {
    let mut owned = bytes.to_vec();
    rewrite_tcp_in_place(&mut owned, source, target, true)?;
    Ok(owned)
}

pub(crate) fn rewrite_tcp_in_place(
    bytes: &mut [u8],
    source: SocketAddr,
    target: SocketAddr,
    verify_checksum: bool,
) -> Result<()> {
    let packet = IpPacket::parse(bytes)?;
    if verify_checksum {
        packet.tcp_tuple()?;
    } else if packet.protocol != 6 || packet.fragment.is_some() || packet.payload.len() < 20 {
        return Err(malformed());
    } else {
        let _ = packet.tuple()?;
    }
    if source.is_ipv4() != packet.source.is_ipv4() || target.is_ipv4() != source.is_ipv4() {
        return Err(malformed());
    }
    if !unicast(source.ip()) || !unicast(target.ip()) {
        return Err(malformed());
    }
    let header_len = bytes.len() - packet.payload.len();
    let old_src_port = u16::from_be_bytes([bytes[header_len], bytes[header_len + 1]]);
    let old_dst_port = u16::from_be_bytes([bytes[header_len + 2], bytes[header_len + 3]]);
    let old_tcp_check = u16::from_be_bytes([bytes[header_len + 16], bytes[header_len + 17]]);
    let mut tcp_acc = u32::from(!old_tcp_check);
    tcp_acc = tcp_acc
        .wrapping_add(u32::from(!old_src_port))
        .wrapping_add(u32::from(source.port()))
        .wrapping_add(u32::from(!old_dst_port))
        .wrapping_add(u32::from(target.port()));
    match (source.ip(), target.ip()) {
        (IpAddr::V4(src4), IpAddr::V4(dst4)) => {
            if header_len != 20 {
                return Err(malformed());
            }
            let old_ip_check = u16::from_be_bytes([bytes[10], bytes[11]]);
            let mut ip_acc = u32::from(!old_ip_check);
            let old_addrs = [
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
                u16::from_be_bytes([bytes[16], bytes[17]]),
                u16::from_be_bytes([bytes[18], bytes[19]]),
            ];
            let s_oct = src4.octets();
            let d_oct = dst4.octets();
            let new_addrs = [
                u16::from_be_bytes([s_oct[0], s_oct[1]]),
                u16::from_be_bytes([s_oct[2], s_oct[3]]),
                u16::from_be_bytes([d_oct[0], d_oct[1]]),
                u16::from_be_bytes([d_oct[2], d_oct[3]]),
            ];
            for (old_w, new_w) in old_addrs.into_iter().zip(new_addrs) {
                ip_acc = ip_acc
                    .wrapping_add(u32::from(!old_w))
                    .wrapping_add(u32::from(new_w));
                tcp_acc = tcp_acc
                    .wrapping_add(u32::from(!old_w))
                    .wrapping_add(u32::from(new_w));
            }
            bytes[12..16].copy_from_slice(&s_oct);
            bytes[16..20].copy_from_slice(&d_oct);
            let new_ip_check = finish(ip_acc);
            bytes[10..12].copy_from_slice(&new_ip_check.to_be_bytes());
        }
        (IpAddr::V6(src6), IpAddr::V6(dst6)) => {
            if header_len < 40 {
                return Err(malformed());
            }
            let s_oct = src6.octets();
            let d_oct = dst6.octets();
            for i in (0..16).step_by(2) {
                let old_s = u16::from_be_bytes([bytes[8 + i], bytes[8 + i + 1]]);
                let new_s = u16::from_be_bytes([s_oct[i], s_oct[i + 1]]);
                let old_d = u16::from_be_bytes([bytes[24 + i], bytes[24 + i + 1]]);
                let new_d = u16::from_be_bytes([d_oct[i], d_oct[i + 1]]);
                tcp_acc = tcp_acc
                    .wrapping_add(u32::from(!old_s))
                    .wrapping_add(u32::from(new_s))
                    .wrapping_add(u32::from(!old_d))
                    .wrapping_add(u32::from(new_d));
            }
            bytes[8..24].copy_from_slice(&s_oct);
            bytes[24..40].copy_from_slice(&d_oct);
        }
        _ => return Err(malformed()),
    }
    bytes[header_len..header_len + 2].copy_from_slice(&source.port().to_be_bytes());
    bytes[header_len + 2..header_len + 4].copy_from_slice(&target.port().to_be_bytes());
    let new_tcp_check = finish(tcp_acc);
    bytes[header_len + 16..header_len + 18].copy_from_slice(&new_tcp_check.to_be_bytes());
    Ok(())
}

pub(crate) fn tcp_reset(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let packet = IpPacket::parse(bytes)?;
    let tuple = packet.tcp_tuple()?;
    let incoming = packet.payload;
    if incoming[13] & 4 != 0 {
        return Ok(None);
    }
    let mut payload = vec![0; 20];
    payload[..2].copy_from_slice(&tuple.target.port().to_be_bytes());
    payload[2..4].copy_from_slice(&tuple.source.port().to_be_bytes());
    payload[12] = 0x50;
    payload[13] = 4;
    if incoming[13] & 16 != 0 {
        payload[4..8].copy_from_slice(&incoming[8..12]);
    } else {
        let sequence = u32::from_be_bytes(incoming[4..8].try_into().map_err(|_| malformed())?);
        let data = incoming.len() - usize::from(incoming[12] >> 4) * 4;
        let acknowledge = sequence
            .wrapping_add(data as u32)
            .wrapping_add(u32::from(incoming[13] & 2 != 0))
            .wrapping_add(u32::from(incoming[13] & 1 != 0));
        payload[8..12].copy_from_slice(&acknowledge.to_be_bytes());
        payload[13] |= 16;
    }
    let check = transport_checksum(packet.target, packet.source, 6, &payload);
    payload[16..18].copy_from_slice(&check.to_be_bytes());
    ip_packet(packet.target, packet.source, 6, &payload, 64).map(Some)
}

pub(crate) fn control_reply(bytes: &[u8], local: &Addresses) -> Result<Option<Vec<u8>>> {
    let packet = IpPacket::parse(bytes)?;
    let icmp = if packet.source.is_ipv4() { 1 } else { 58 };
    if packet.protocol != icmp || packet.payload.len() < 8 {
        return Ok(None);
    }
    let valid = if icmp == 1 {
        checksum(packet.payload) == 0
    } else {
        transport_checksum(packet.source, packet.target, 58, packet.payload) == 0
    };
    if !valid {
        return Err(malformed());
    }
    let echo = if icmp == 1 { 8 } else { 128 };
    if packet.payload[0] != echo || packet.payload[1] != 0 {
        return Ok(None);
    }
    if !local.contains(packet.target) {
        return unreachable(bytes, local);
    }
    let mut payload = packet.payload.to_vec();
    payload[0] = if icmp == 1 { 0 } else { 129 };
    payload[2..4].fill(0);
    let check = if icmp == 1 {
        checksum(&payload)
    } else {
        transport_checksum(packet.target, packet.source, 58, &payload)
    };
    payload[2..4].copy_from_slice(&check.to_be_bytes());
    ip_packet(packet.target, packet.source, icmp, &payload, 64).map(Some)
}

pub(crate) fn unreachable(bytes: &[u8], local: &Addresses) -> Result<Option<Vec<u8>>> {
    let packet = IpPacket::parse(bytes)?;
    let source = local.for_target(packet.source)?;
    let maximum = if source.is_ipv4() { 548 } else { 1232 };
    let mut payload = vec![0; 8 + bytes.len().min(maximum)];
    payload[0] = if source.is_ipv4() { 3 } else { 1 };
    payload[1] = if source.is_ipv4() { 13 } else { 1 };
    payload[8..].copy_from_slice(&bytes[..bytes.len().min(maximum)]);
    let protocol = if source.is_ipv4() { 1 } else { 58 };
    let check = if protocol == 1 {
        checksum(&payload)
    } else {
        transport_checksum(source, packet.source, 58, &payload)
    };
    payload[2..4].copy_from_slice(&check.to_be_bytes());
    ip_packet(source, packet.source, protocol, &payload, 64).map(Some)
}
