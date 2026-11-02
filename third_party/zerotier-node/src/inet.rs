// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/InetAddress.hpp (binary form only).

use crate::reader::Reader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// In network configs the port field carries the netmask bits instead of a port.
pub(crate) fn deserialize(reader: &mut Reader<'_>) -> Option<Option<SocketAddr>> {
    match reader.u8()? {
        0 => Some(None),
        0x01 | 0x02 => {
            reader.skip(6)?;
            Some(None)
        }
        0x03 => {
            let length = usize::from(reader.u16()?);
            reader.skip(length)?;
            Some(None)
        }
        0x04 => {
            let ip: [u8; 4] = reader.array()?;
            let port = reader.u16()?;
            Some(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)))
        }
        0x06 => {
            let ip: [u8; 16] = reader.array()?;
            let port = reader.u16()?;
            Some(Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)))
        }
        _ => None,
    }
}

pub(crate) fn serialize(address: SocketAddr, output: &mut Vec<u8>) {
    match address.ip().to_canonical() {
        IpAddr::V4(ip) => {
            output.push(0x04);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(0x06);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&address.port().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_forms_match_upstream_layout() {
        let mut output = Vec::new();
        serialize("10.1.2.3:9993".parse().unwrap(), &mut output);
        assert_eq!(output, [0x04, 10, 1, 2, 3, 0x27, 0x09]);
        let mut reader = Reader::new(&output);
        assert_eq!(
            deserialize(&mut reader).unwrap(),
            Some("10.1.2.3:9993".parse().unwrap())
        );
        assert_eq!(reader.remaining(), 0);

        let mut output = Vec::new();
        serialize("[fd00::1]:88".parse().unwrap(), &mut output);
        assert_eq!(output.len(), 19);
        assert_eq!(output[0], 0x06);
        assert_eq!(
            deserialize(&mut Reader::new(&output)).unwrap(),
            Some("[fd00::1]:88".parse().unwrap())
        );
    }

    #[test]
    fn nil_and_foreign_address_types_are_skipped_by_their_declared_length() {
        let mut reader = Reader::new(&[0, 0x01, 1, 2, 3, 4, 5, 6, 0x03, 0, 2, 9, 9, 0x07]);
        assert_eq!(deserialize(&mut reader), Some(None));
        assert_eq!(deserialize(&mut reader), Some(None));
        assert_eq!(deserialize(&mut reader), Some(None));
        assert_eq!(deserialize(&mut reader), None);
    }
}
