use kerlico_core::{Address, Destination, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn encode(target: &Destination) -> Vec<u8> {
    let mut bytes = Vec::new();
    match target.address() {
        Address::Ip(ip) => match ip.to_canonical() {
            IpAddr::V4(ip) => {
                bytes.push(1);
                bytes.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                bytes.push(4);
                bytes.extend_from_slice(&ip.octets());
            }
        },
        Address::Domain(name) => {
            bytes.extend_from_slice(&[3, name.len() as u8]);
            bytes.extend_from_slice(name.as_bytes());
        }
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes
}

pub(crate) fn decode(bytes: &[u8]) -> Result<(Destination, usize)> {
    let (host, end) = match bytes.first() {
        Some(1) if bytes.len() >= 7 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[1..5]).unwrap()).to_string(),
            5,
        ),
        Some(4) if bytes.len() >= 19 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[1..17]).unwrap())
                .to_canonical()
                .to_string(),
            17,
        ),
        Some(3) if bytes.len() >= 4 => {
            let size = usize::from(bytes[1]);
            if size == 0 || bytes.len() < size + 4 {
                return Err(crate::invalid());
            }
            (
                std::str::from_utf8(&bytes[2..2 + size])
                    .map_err(|_| crate::invalid())?
                    .to_owned(),
                size + 2,
            )
        }
        _ => return Err(crate::invalid()),
    };
    let port = u16::from_be_bytes(bytes[end..end + 2].try_into().unwrap());
    Ok((Destination::new(&host, port)?, end + 2))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_address_types_canonical_mapping_padding_and_invalid_values() {
        for host in ["192.0.2.1", "2001:db8::1", "target.invalid"] {
            let target = Destination::new(host, 443).unwrap();
            let mut bytes = encode(&target);
            let len = bytes.len();
            bytes.extend_from_slice(b"padding");
            let (result, used) = decode(&bytes).unwrap();
            assert_eq!(result, target);
            assert_eq!(used, len);
        }
        assert_eq!(
            encode(&Destination::new("::ffff:192.0.2.1", 53).unwrap()),
            vec![1, 192, 0, 2, 1, 0, 53]
        );
        for bytes in [
            &[1, 0, 0, 0, 0, 0, 0][..],
            &[2, 1, 2, 3][..],
            &[3, 0, 0, 1][..],
            &[3, 1, 0xff, 0, 1][..],
            &[4, 0, 0][..],
        ] {
            assert!(decode(bytes).is_err());
        }
    }
}
