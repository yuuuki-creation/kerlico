//! ShadowQUIC 应用格式；JLS 已在传输层完成，认证字段不混入业务头。
use kerlico_core::{Address, Destination, Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt};
pub(crate) const MAX_PACKET: usize = 65507;
pub(crate) fn malformed() -> Error {
    Error::Protocol("ShadowQUIC 报文或映射不合法")
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Datagram,
    Stream,
}
impl Mode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "datagram" => Ok(Self::Datagram),
            "stream" => Ok(Self::Stream),
            _ => Err(Error::Config("ShadowQUIC udp_mode 不合法".into())),
        }
    }
    pub fn command(self) -> u8 {
        match self {
            Self::Datagram => 3,
            Self::Stream => 4,
        }
    }
}
pub(crate) fn address(out: &mut Vec<u8>, value: &Destination) {
    match value.address() {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend(ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend(ip.octets());
        }
        Address::Domain(name) => {
            out.extend([3, name.len() as u8]);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend(value.port().to_be_bytes());
}
pub(crate) async fn read_address<R: AsyncRead + Unpin>(
    input: &mut R,
    allow_unspecified: bool,
) -> Result<Option<Destination>> {
    let kind = input.read_u8().await?;
    let length = match kind {
        1 => 4,
        4 => 16,
        3 => input.read_u8().await? as usize,
        _ => return Err(malformed()),
    };
    if length == 0 {
        return Err(malformed());
    }
    let mut value = vec![0; length];
    input.read_exact(&mut value).await?;
    let host = match kind {
        1 => std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(value.as_slice()).map_err(|_| malformed())?,
        )
        .to_string(),
        4 => std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(value.as_slice()).map_err(|_| malformed())?,
        )
        .to_string(),
        3 => String::from_utf8(value).map_err(|_| malformed())?,
        _ => return Err(malformed()),
    };
    let port = input.read_u16().await?;
    if port == 0
        && allow_unspecified
        && host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_unspecified())
    {
        return Ok(None);
    }
    Ok(Some(Destination::new(&host, port)?))
}
pub(crate) fn request(target: &Destination) -> Vec<u8> {
    let mut out = vec![1];
    address(&mut out, target);
    out
}
pub(crate) fn association_request(mode: Mode) -> Vec<u8> {
    vec![mode.command(), 1, 0, 0, 0, 0, 0, 0]
}
pub(crate) fn mapping(target: &Destination, id: u16) -> Vec<u8> {
    let mut out = Vec::new();
    address(&mut out, target);
    out.extend(id.to_be_bytes());
    out
}
pub(crate) fn datagram(id: u16, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_PACKET {
        return Err(Error::ResourceLimit);
    }
    let mut out = id.to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    Ok(out)
}
pub(crate) fn decode_datagram(bytes: &[u8]) -> Result<(u16, Vec<u8>)> {
    if bytes.len() < 2 || bytes.len() > MAX_PACKET + 2 {
        return Err(malformed());
    }
    Ok((
        u16::from_be_bytes(bytes[..2].try_into().map_err(|_| malformed())?),
        bytes[2..].to_vec(),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn address_requests_and_empty_datagrams_preserve_wire_format() {
        for host in ["192.0.2.1", "2001:db8::1", "example.invalid"] {
            let target = Destination::new(host, 443).unwrap();
            let wire = request(&target);
            let mut bytes = &wire[1..];
            assert_eq!(read_address(&mut bytes, false).await.unwrap(), Some(target));
            assert!(bytes.is_empty());
        }
        assert_eq!(
            decode_datagram(&datagram(42, b"").unwrap()).unwrap(),
            (42, Vec::new())
        );
        assert!(decode_datagram(&[1]).is_err());
        assert_eq!(association_request(Mode::Stream), [4, 1, 0, 0, 0, 0, 0, 0]);
    }
}
