//! SOCKS5 request addresses and UDP envelopes from RFC 1928.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Address {
    pub host: String,
    pub port: u16,
}

pub fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 message")
}

pub async fn read_address<R: AsyncRead + Unpin>(read: &mut R, kind: u8) -> io::Result<Address> {
    let mut wire = [0; 259];
    wire[0] = kind;
    let len = match kind {
        1 => 7,
        4 => 19,
        3 => {
            wire[1] = read.read_u8().await?;
            if wire[1] == 0 {
                return Err(invalid());
            }
            let end = usize::from(wire[1]) + 4;
            read.read_exact(&mut wire[2..end]).await?;
            return decode(&wire[..end]).map(|(address, _)| address);
        }
        _ => return Err(invalid()),
    };
    read.read_exact(&mut wire[1..len]).await?;
    decode(&wire[..len]).map(|(address, _)| address)
}

pub fn decode(wire: &[u8]) -> io::Result<(Address, &[u8])> {
    let (kind, data) = wire.split_first().ok_or_else(invalid)?;
    let (host, rest) = match *kind {
        1 => {
            let (bytes, rest) = data.split_first_chunk::<4>().ok_or_else(invalid)?;
            (Ipv4Addr::from(*bytes).to_string(), rest)
        }
        4 => {
            let (bytes, rest) = data.split_first_chunk::<16>().ok_or_else(invalid)?;
            (Ipv6Addr::from(*bytes).to_string(), rest)
        }
        3 => {
            let (&len, data) = data.split_first().ok_or_else(invalid)?;
            if len == 0 {
                return Err(invalid());
            }
            let (host, rest) = data
                .split_at_checked(usize::from(len))
                .ok_or_else(invalid)?;
            let host = std::str::from_utf8(host).map_err(|_| invalid())?;
            (host.to_owned(), rest)
        }
        _ => return Err(invalid()),
    };
    let (port, remaining) = rest.split_first_chunk::<2>().ok_or_else(invalid)?;
    Ok((
        Address {
            host,
            port: u16::from_be_bytes(*port),
        },
        remaining,
    ))
}

pub fn encode_ip(wire: &mut Vec<u8>, address: SocketAddr) {
    let mut buf = [0; 19];
    wire.extend_from_slice(ip_address(&mut buf, address));
}

pub fn ip_address(buf: &mut [u8; 19], address: SocketAddr) -> &[u8] {
    let end = match address.ip() {
        IpAddr::V4(ip) => {
            buf[0] = 1;
            buf[1..5].copy_from_slice(&ip.octets());
            5
        }
        IpAddr::V6(ip) => {
            buf[0] = 4;
            buf[1..17].copy_from_slice(&ip.octets());
            17
        }
    };
    buf[end..end + 2].copy_from_slice(&address.port().to_be_bytes());
    &buf[..end + 2]
}

pub fn encode(wire: &mut Vec<u8>, address: &Address) -> io::Result<()> {
    if let Ok(ip) = address.host.parse() {
        encode_ip(wire, SocketAddr::new(ip, address.port));
    } else {
        let len = u8::try_from(address.host.len()).map_err(|_| invalid())?;
        if len == 0 {
            return Err(invalid());
        }
        wire.extend([3, len]);
        wire.extend(address.host.as_bytes());
        wire.extend(address.port.to_be_bytes());
    }
    Ok(())
}

pub fn decode_udp(wire: &[u8]) -> io::Result<(Address, &[u8])> {
    decode(wire.strip_prefix(&[0, 0, 0]).ok_or_else(invalid)?)
}

pub fn udp_parts(wire: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let body = wire.strip_prefix(&[0, 0, 0]).ok_or_else(invalid)?;
    let header = match body.first() {
        Some(1) => 7,
        Some(4) => 19,
        Some(3) => match body.get(1) {
            None | Some(0) => return Err(invalid()),
            Some(&len) => 4 + usize::from(len),
        },
        _ => return Err(invalid()),
    };
    body.split_at_checked(header).ok_or_else(invalid)
}
