//! RFC 9297 Capsule、HTTP Datagram 与 RFC 9484 地址/路由负载的线格式。
use crate::protocol;
use bytes::Bytes;
use kerlico_core::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const ADDRESS_ASSIGN: u64 = 1;
const ADDRESS_REQUEST: u64 = 2;
const ROUTE_ADVERTISEMENT: u64 = 3;
const MAX_CONTROL_CAPSULE: u64 = 64 * 1024;
const CONTEXT_IP_PACKET: u64 = 0;

fn put_varint(value: u64, out: &mut Vec<u8>) {
    let (length, flag) = match value {
        0..64 => (1, 0x00),
        64..16384 => (2, 0x40),
        16384..0x4000_0000 => (4, 0x80),
        _ => (8, 0xc0),
    };
    let start = out.len();
    out.extend_from_slice(&value.to_be_bytes()[8 - length..]);
    out[start] |= flag;
}
fn take_varint(input: &mut &[u8]) -> Result<u64> {
    let first = *input.first().ok_or_else(protocol)?;
    let length = 1usize << (first >> 6);
    let (encoded, rest) = input.split_at_checked(length).ok_or_else(protocol)?;
    *input = rest;
    Ok(encoded[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |value, byte| {
            value << 8 | u64::from(*byte)
        }))
}
async fn read_varint<R: AsyncRead + Unpin>(io: &mut R) -> Result<Option<u64>> {
    let mut bytes = [0; 8];
    if io.read(&mut bytes[..1]).await? == 0 {
        return Ok(None);
    }
    let length = 1usize << (bytes[0] >> 6);
    io.read_exact(&mut bytes[1..length]).await?;
    take_varint(&mut &bytes[..length]).map(Some)
}

fn raw(ip: IpAddr) -> (u128, u8) {
    match ip {
        IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32),
        IpAddr::V6(ip) => (u128::from(ip), 128),
    }
}
fn take_ip(family: u8, input: &mut &[u8]) -> Result<IpAddr> {
    let length = match family {
        4 => 4,
        6 => 16,
        _ => return Err(protocol()),
    };
    let (bytes, rest) = input.split_at_checked(length).ok_or_else(protocol)?;
    *input = rest;
    Ok(match <[u8; 4]>::try_from(bytes) {
        Ok(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
        Err(_) => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| protocol())?,
        )),
    })
}
fn take_byte(input: &mut &[u8]) -> Result<u8> {
    let (&byte, rest) = input.split_first().ok_or_else(protocol)?;
    *input = rest;
    Ok(byte)
}
fn put_ip(ip: IpAddr, out: &mut Vec<u8>) {
    match ip {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend(ip.octets());
        }
    }
}

/// ADDRESS_ASSIGN 与 ADDRESS_REQUEST 共用的一条记录。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Address {
    pub request_id: u64,
    pub ip: IpAddr,
    pub prefix_len: u8,
}
impl Address {
    pub(crate) fn unspecified(request_id: u64, ipv4: bool) -> Self {
        let ip = if ipv4 {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        Self {
            request_id,
            ip,
            prefix_len: raw(ip).1,
        }
    }
    /// RFC 9484 用全零地址表示对端拒绝该请求。
    fn rejected(&self) -> bool {
        self.ip.is_unspecified()
    }
    pub fn grants(&self, ip: IpAddr) -> bool {
        let (value, width) = raw(self.ip);
        let (other, other_width) = raw(ip);
        !self.rejected()
            && width == other_width
            && (value ^ other)
                .checked_shr(u32::from(width - self.prefix_len))
                .unwrap_or(0)
                == 0
    }
    /// 短于地址宽度的前缀取其第一个主机地址。
    fn host(&self) -> IpAddr {
        let (value, width) = raw(self.ip);
        if self.prefix_len == width {
            return self.ip;
        }
        match self.ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from((value | 1) as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(value | 1)),
        }
    }
}
/// 每个地址族取第一条未被拒绝的分配，地址数量与用户态数据面的单族单地址一致。
pub(crate) fn assigned_hosts(entries: &[Address]) -> Vec<IpAddr> {
    let mut hosts: Vec<IpAddr> = Vec::with_capacity(2);
    for entry in entries.iter().filter(|entry| !entry.rejected()) {
        if !hosts.iter().any(|ip| ip.is_ipv4() == entry.ip.is_ipv4()) {
            hosts.push(entry.host());
        }
    }
    hosts
}
fn parse_addresses(mut input: &[u8], request: bool) -> Result<Vec<Address>> {
    let mut entries = Vec::new();
    while !input.is_empty() {
        let request_id = take_varint(&mut input)?;
        let family = take_byte(&mut input)?;
        let ip = take_ip(family, &mut input)?;
        let prefix_len = take_byte(&mut input)?;
        let (value, width) = raw(ip);
        let host_bits = u32::from(width.checked_sub(prefix_len).ok_or_else(protocol)?);
        let host_mask = 1u128
            .checked_shl(host_bits)
            .map_or(u128::MAX, |bit| bit - 1);
        if request && request_id == 0 || value & host_mask != 0 {
            return Err(protocol());
        }
        entries.push(Address {
            request_id,
            ip,
            prefix_len,
        });
    }
    Ok(entries)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Route {
    pub start: IpAddr,
    pub end: IpAddr,
    pub protocol: u8,
}
impl Route {
    pub fn allows(&self, ip: IpAddr, protocol: u8) -> bool {
        ip.is_ipv4() == self.start.is_ipv4()
            && self.start <= ip
            && ip <= self.end
            && (self.protocol == 0 || self.protocol == protocol)
    }
}
/// RFC 9484 §4.7.3：按地址族、协议、起始地址升序，同族同协议范围不得重叠。
fn parse_routes(mut input: &[u8]) -> Result<Vec<Route>> {
    let mut routes: Vec<Route> = Vec::new();
    while !input.is_empty() {
        let family = take_byte(&mut input)?;
        let start = take_ip(family, &mut input)?;
        let end = take_ip(family, &mut input)?;
        let protocol_number = take_byte(&mut input)?;
        if start > end {
            return Err(protocol());
        }
        if let Some(last) = routes.last() {
            let previous = (last.start.is_ipv6(), last.protocol);
            let current = (start.is_ipv6(), protocol_number);
            if previous > current || previous == current && last.end >= start {
                return Err(protocol());
            }
        }
        routes.push(Route {
            start,
            end,
            protocol: protocol_number,
        });
    }
    Ok(routes)
}

pub(crate) enum Capsule {
    AddressAssign(Vec<Address>),
    AddressRequest(Vec<Address>),
    RouteAdvertisement(Vec<Route>),
    Ignored,
}
/// RFC 9297 要求跳过未知类型；HTTP/3 上的 DATAGRAM Capsule 同样不进入数据面。
pub(crate) async fn read<R: AsyncRead + Unpin>(io: &mut R) -> Result<Option<Capsule>> {
    let Some(kind) = read_varint(io).await? else {
        return Ok(None);
    };
    let length = read_varint(io).await?.ok_or_else(protocol)?;
    if !matches!(kind, ADDRESS_ASSIGN | ADDRESS_REQUEST | ROUTE_ADVERTISEMENT) {
        let mut body = (&mut *io).take(length);
        if tokio::io::copy(&mut body, &mut tokio::io::sink()).await? != length {
            return Err(protocol());
        }
        return Ok(Some(Capsule::Ignored));
    }
    if length > MAX_CONTROL_CAPSULE {
        return Err(protocol());
    }
    let mut payload = vec![0; length as usize];
    io.read_exact(&mut payload).await?;
    Ok(Some(match kind {
        ADDRESS_ASSIGN => Capsule::AddressAssign(parse_addresses(&payload, false)?),
        ADDRESS_REQUEST => Capsule::AddressRequest(parse_addresses(&payload, true)?),
        _ => Capsule::RouteAdvertisement(parse_routes(&payload)?),
    }))
}
fn encode(kind: u64, entries: &[Address]) -> Vec<u8> {
    let mut payload = Vec::new();
    for entry in entries {
        put_varint(entry.request_id, &mut payload);
        put_ip(entry.ip, &mut payload);
        payload.push(entry.prefix_len);
    }
    let mut capsule = Vec::with_capacity(payload.len() + 4);
    put_varint(kind, &mut capsule);
    put_varint(payload.len() as u64, &mut capsule);
    capsule.extend(payload);
    capsule
}
fn encode_routes(routes: &[Route]) -> Vec<u8> {
    let mut payload = Vec::new();
    for route in routes {
        put_ip(route.start, &mut payload);
        match route.end {
            IpAddr::V4(ip) => payload.extend(ip.octets()),
            IpAddr::V6(ip) => payload.extend(ip.octets()),
        }
        payload.push(route.protocol);
    }
    let mut capsule = Vec::with_capacity(payload.len() + 4);
    put_varint(ROUTE_ADVERTISEMENT, &mut capsule);
    put_varint(payload.len() as u64, &mut capsule);
    capsule.extend(payload);
    capsule
}
async fn write<W: AsyncWrite + Unpin>(io: &mut W, bytes: &[u8]) -> Result<()> {
    io.write_all(bytes).await?;
    io.flush().await?;
    Ok(())
}
/// 向代理请求 IPv4 与 IPv6 各一个地址，由代理决定具体值。
pub(crate) async fn write_address_request<W: AsyncWrite + Unpin>(io: &mut W) -> Result<()> {
    let entries = [
        Address::unspecified(1, true),
        Address::unspecified(2, false),
    ];
    write(io, &encode(ADDRESS_REQUEST, &entries)).await
}
pub(crate) async fn write_address_assign<W: AsyncWrite + Unpin>(
    io: &mut W,
    entries: &[Address],
) -> Result<()> {
    write(io, &encode(ADDRESS_ASSIGN, entries)).await
}
pub(crate) async fn write_route_advertisement<W: AsyncWrite + Unpin>(
    io: &mut W,
    routes: &[Route],
) -> Result<()> {
    write(io, &encode_routes(routes)).await
}
/// 客户端不向代理提供地址，逐条按原请求 ID 拒绝。
pub(crate) async fn write_rejection<W: AsyncWrite + Unpin>(
    io: &mut W,
    requested: &[Address],
) -> Result<()> {
    let entries: Vec<Address> = requested
        .iter()
        .map(|entry| Address::unspecified(entry.request_id, entry.ip.is_ipv4()))
        .collect();
    write(io, &encode(ADDRESS_ASSIGN, &entries)).await
}

/// QUIC DATAGRAM 负载：Quarter Stream ID、Context ID 0、完整 IP 包。
pub(crate) fn encode_datagram(quarter_stream_id: u64, packet: &[u8]) -> Bytes {
    let mut datagram = Vec::with_capacity(packet.len() + 9);
    put_varint(quarter_stream_id, &mut datagram);
    put_varint(CONTEXT_IP_PACKET, &mut datagram);
    datagram.extend_from_slice(packet);
    datagram.into()
}
pub(crate) fn decode_datagram(quarter_stream_id: u64, mut datagram: &[u8]) -> Option<&[u8]> {
    let stream = take_varint(&mut datagram).ok()?;
    let context = take_varint(&mut datagram).ok()?;
    (stream == quarter_stream_id && context == CONTEXT_IP_PACKET).then_some(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }
    async fn parsed(mut wire: &[u8]) -> Result<Capsule> {
        Ok(read(&mut wire).await?.unwrap())
    }

    #[test]
    fn varints_match_rfc9000_appendix_a() {
        let vectors: [(&[u8], u64); 4] = [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (wire, value) in vectors {
            let mut input = wire;
            assert_eq!(take_varint(&mut input).unwrap(), value);
            assert!(input.is_empty());
            let mut output = Vec::new();
            put_varint(value, &mut output);
            assert_eq!(output, wire);
        }
        assert!(take_varint(&mut &[0x40][..]).is_err());
    }

    /// 字节取自固定 Xray connectip/capsule_test.go 的 TestParseAddressAssignCapsule 输入。
    #[tokio::test]
    async fn address_assign_vector_from_xray() {
        let mut wire = vec![0x01, 0x1f];
        wire.extend([0x45, 0x39, 4, 1, 2, 3, 0, 24]);
        wire.extend([0x45, 0x3a, 6]);
        wire.extend(ip6_octets("2001:db8::1"));
        wire.push(128);
        wire[1] = (wire.len() - 2) as u8;
        let Capsule::AddressAssign(entries) = parsed(&wire).await.unwrap() else {
            panic!("capsule type");
        };
        assert_eq!(
            entries,
            [
                Address {
                    request_id: 1337,
                    ip: ip("1.2.3.0"),
                    prefix_len: 24
                },
                Address {
                    request_id: 1338,
                    ip: ip("2001:db8::1"),
                    prefix_len: 128
                },
            ]
        );
        assert_eq!(assigned_hosts(&entries), [ip("1.2.3.1"), ip("2001:db8::1")]);
        assert!(entries[0].grants(ip("1.2.3.200")));
        assert!(!entries[0].grants(ip("1.2.4.1")));
        assert!(!entries[0].grants(ip("2001:db8::1")));
    }
    fn ip6_octets(text: &str) -> [u8; 16] {
        text.parse::<Ipv6Addr>().unwrap().octets()
    }

    #[tokio::test]
    async fn address_rules_reject_host_bits_and_zero_request_id() {
        let host_bits = [0x01, 0x07, 1, 4, 192, 0, 2, 1, 24];
        assert!(parsed(&host_bits).await.is_err());
        let wide_prefix = [0x01, 0x07, 1, 4, 192, 0, 2, 1, 33];
        assert!(parsed(&wide_prefix).await.is_err());
        let zero_request = [0x02, 0x07, 0, 4, 192, 0, 2, 1, 32];
        assert!(parsed(&zero_request).await.is_err());
        let unsolicited = [0x01, 0x07, 0, 4, 192, 0, 2, 1, 32];
        assert!(matches!(
            parsed(&unsolicited).await,
            Ok(Capsule::AddressAssign(_))
        ));
    }

    #[test]
    fn rejected_family_is_skipped_and_first_per_family_wins() {
        let entries = [
            Address::unspecified(1, true),
            Address {
                request_id: 2,
                ip: ip("fd89::2"),
                prefix_len: 128,
            },
            Address {
                request_id: 0,
                ip: ip("fd89::3"),
                prefix_len: 128,
            },
        ];
        assert_eq!(assigned_hosts(&entries), [ip("fd89::2")]);
        assert!(!entries[0].grants(ip("10.0.0.1")));
    }

    #[test]
    fn address_request_wire_format() {
        let mut expected = vec![0x02, 0x1a, 1, 4, 0, 0, 0, 0, 32, 2, 6];
        expected.extend([0; 16]);
        expected.push(128);
        assert_eq!(
            encode(
                ADDRESS_REQUEST,
                &[
                    Address::unspecified(1, true),
                    Address::unspecified(2, false)
                ]
            ),
            expected
        );
    }

    #[tokio::test]
    async fn route_order_and_filter() {
        let mut full = vec![0x03, 0x00, 4, 0, 0, 0, 0, 255, 255, 255, 255, 0];
        full.extend([6]);
        full.extend([0; 16]);
        full.extend([0xff; 16]);
        full.push(17);
        full[1] = (full.len() - 2) as u8;
        let Capsule::RouteAdvertisement(routes) = parsed(&full).await.unwrap() else {
            panic!("capsule type");
        };
        assert!(routes[0].allows(ip("192.0.2.1"), 6));
        assert!(routes[1].allows(ip("2001:db8::1"), 17));
        assert!(!routes[1].allows(ip("2001:db8::1"), 6));
        assert!(!routes[1].allows(ip("192.0.2.1"), 17));

        let overlap = [
            0x03, 20, 4, 10, 0, 0, 0, 10, 0, 0, 9, 0, 4, 10, 0, 0, 9, 10, 0, 0, 10, 0,
        ];
        assert!(parsed(&overlap).await.is_err());
        let descending = [0x03, 10, 4, 10, 0, 0, 9, 10, 0, 0, 1, 0];
        assert!(parsed(&descending).await.is_err());
        assert!(parsed(&[0x03, 5, 5, 0, 0, 0, 0]).await.is_err());
    }

    #[tokio::test]
    async fn unknown_capsules_are_skipped_and_truncation_fails() {
        let mut oversized = vec![0x80, 0x01, 0x00, 0x00];
        put_varint(MAX_CONTROL_CAPSULE + 1, &mut oversized);
        oversized.resize(oversized.len() + MAX_CONTROL_CAPSULE as usize + 1, 0);
        oversized.extend([0x02, 0x07, 1, 4, 0, 0, 0, 0, 32]);
        let mut input = oversized.as_slice();
        assert!(matches!(read(&mut input).await, Ok(Some(Capsule::Ignored))));
        assert!(matches!(
            read(&mut input).await,
            Ok(Some(Capsule::AddressRequest(_)))
        ));
        assert!(read(&mut input).await.unwrap().is_none());
        assert!(read(&mut &[0x40, 0x10, 1][..]).await.is_err());
        assert!(read(&mut &[0x01, 0x05, 1][..]).await.is_err());
    }

    #[test]
    fn datagram_carries_quarter_stream_id_and_context_zero() {
        // 请求流 ID 4 对应 Quarter Stream ID 1（RFC 9297 §2.1）。
        let datagram = encode_datagram(1, &[0x45, 0x00]);
        assert_eq!(&datagram[..], [0x01, 0x00, 0x45, 0x00]);
        assert_eq!(decode_datagram(1, &datagram), Some(&[0x45, 0x00][..]));
        assert_eq!(decode_datagram(2, &datagram), None);
        assert_eq!(decode_datagram(1, &[0x01, 0x02, 0x45]), None);
        assert_eq!(decode_datagram(1, &[0x40]), None);
    }
}
