//! packetaddr 的 IP 地址类型独立于 VLESS 请求头：IPv4=1、IPv6=2。
use kerlico_core::{Address, Destination, Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
pub(crate) fn encode(target: &Destination, payload: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(payload.len() + 19);
    match target.address() {
        Address::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            bytes.push(2);
            bytes.extend_from_slice(&ip.octets());
        }
        Address::Domain(_) => return Err(Error::Unsupported("packetaddr 域名目标")),
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
pub(crate) fn decode(bytes: &[u8]) -> Result<(Destination, &[u8])> {
    let (ip, length) = match bytes.first() {
        Some(1) if bytes.len() >= 7 => (
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&bytes[1..5]).map_err(|_| Error::InvalidAddress)?,
            )),
            7,
        ),
        Some(2) if bytes.len() >= 19 => (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[1..17]).map_err(|_| Error::InvalidAddress)?,
            )),
            19,
        ),
        _ => return Err(Error::Protocol("packetaddr 地址格式不合法或被截断")),
    };
    let port = u16::from_be_bytes([bytes[length - 2], bytes[length - 1]]);
    Ok((Destination::new(&ip.to_string(), port)?, &bytes[length..]))
}
