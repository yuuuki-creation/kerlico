//! Addresses on the wire. The stream header and the UoT request use sing's `SocksaddrSerializer`
//! (1 = IPv4, 4 = IPv6, 3 = domain); UoT packets use `uot.AddrParser` (0, 1, 2). Both put the
//! address first and then a big-endian port.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The magic host of sing's UDP-over-TCP version 2 (`uot.MagicAddress`).
pub const UOT_V2: &str = "sp.v2.udp-over-tcp.arpa";
/// The magic host of version 1 (`uot.LegacyMagicAddress`).
pub const UOT_V1: &str = "sp.udp-over-tcp.arpa";

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Socks,
    Uot,
}

impl Family {
    const fn bytes(self) -> [u8; 3] {
        match self {
            Self::Socks => [1, 4, 3],
            Self::Uot => [0, 1, 2],
        }
    }
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port }
    }

    pub fn encoded_len(&self) -> usize {
        match parse_ip(&self.host) {
            Some(IpAddr::V4(_)) => 1 + 4 + 2,
            Some(IpAddr::V6(_)) => 1 + 16 + 2,
            None => 1 + 1 + self.host.len() + 2,
        }
    }

    /// Appends the address. A domain longer than 255 bytes, or an empty one, is refused.
    pub fn encode(&self, family: Family, out: &mut Vec<u8>) -> io::Result<()> {
        let [v4, v6, name] = family.bytes();
        match parse_ip(&self.host) {
            Some(IpAddr::V4(ip)) => {
                out.push(v4);
                out.extend_from_slice(&ip.octets());
            }
            Some(IpAddr::V6(ip)) => {
                out.push(v6);
                out.extend_from_slice(&ip.octets());
            }
            None => {
                let len = u8::try_from(self.host.len())
                    .ok()
                    .filter(|len| *len > 0)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "domain length"))?;
                out.push(name);
                out.push(len);
                out.extend_from_slice(self.host.as_bytes());
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }

    /// Reads one address from the front of `buf`. `Ok(None)` asks for more bytes.
    pub fn decode(buf: &[u8], family: Family) -> io::Result<Option<(Self, usize)>> {
        let [v4, v6, name] = family.bytes();
        let Some(&kind) = buf.first() else { return Ok(None) };
        let (host, used) = if kind == v4 {
            let Some(octets) = buf.get(1..5) else { return Ok(None) };
            (Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string(), 5)
        } else if kind == v6 {
            let Some(octets) = buf.get(1..17) else { return Ok(None) };
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(octets);
            (Ipv6Addr::from(bytes).to_string(), 17)
        } else if kind == name {
            let Some(&len) = buf.get(1) else { return Ok(None) };
            let Some(text) = buf.get(2..2 + usize::from(len)) else { return Ok(None) };
            let text = std::str::from_utf8(text)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "domain is not UTF-8"))?;
            (text.to_string(), 2 + usize::from(len))
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "address type"));
        };
        let Some(port) = buf.get(used..used + 2) else { return Ok(None) };
        Ok(Some((Self { host, port: u16::from_be_bytes([port[0], port[1]]) }, used + 2)))
    }
}

/// An IP literal, with or without the brackets an IPv6 host may carry.
pub fn parse_ip(host: &str) -> Option<IpAddr> {
    let bare = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(host);
    bare.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors::{unhex, ADDRS};

    #[test]
    fn both_forms_match_sing() {
        for (host, port, socks, uot) in ADDRS {
            let target = Target::new(*host, *port);
            for (family, hex) in [(Family::Socks, socks), (Family::Uot, uot)] {
                let mut out = Vec::new();
                target.encode(family, &mut out).unwrap();
                assert_eq!(out, unhex(hex), "{host} {family:?}");
                assert_eq!(out.len(), target.encoded_len());
                let (back, used) = Target::decode(&out, family).unwrap().unwrap();
                assert_eq!((back, used), (target.clone(), out.len()));
                for cut in 0..out.len() {
                    assert!(Target::decode(&out[..cut], family).unwrap().is_none(), "{host} cut {cut}");
                }
            }
        }
    }

    #[test]
    fn unknown_types_and_long_names_are_refused() {
        assert!(Target::decode(&[9, 0, 0], Family::Socks).is_err());
        assert!(Target::decode(&[3, 0, 0], Family::Uot).is_err());
        let long = Target::new("a".repeat(256), 1);
        assert!(long.encode(Family::Socks, &mut Vec::new()).is_err());
    }
}
