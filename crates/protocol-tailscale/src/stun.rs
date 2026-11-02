//! 上游 DERP 接受的 STUN Binding 请求与 XOR-MAPPED-ADDRESS 解析。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const HEADER: usize = 20;
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const SOFTWARE: &[u8; 8] = b"tailnode";
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const ATTR_XOR_MAPPED_ALT: u16 = 0x8020;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

pub fn is_stun(packet: &[u8]) -> bool {
    packet.len() >= HEADER && packet[0] & 0xc0 == 0 && packet[4..8] == COOKIE
}
pub fn request(tx: &[u8; 12]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HEADER + 20);
    packet.extend_from_slice(&[0, 1]);
    packet.extend_from_slice(&20u16.to_be_bytes());
    packet.extend_from_slice(&COOKIE);
    packet.extend_from_slice(tx);
    packet.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    packet.extend_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    packet.extend_from_slice(SOFTWARE);
    let fingerprint = crc32fast::hash(&packet) ^ FINGERPRINT_XOR;
    packet.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes());
    packet.extend_from_slice(&fingerprint.to_be_bytes());
    packet
}
pub fn parse_response(packet: &[u8]) -> Option<([u8; 12], SocketAddr)> {
    if !is_stun(packet) || packet[..2] != [1, 1] {
        return None;
    }
    let tx: [u8; 12] = packet[8..HEADER].try_into().ok()?;
    let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let mut attributes = packet.get(HEADER..HEADER + length)?;
    while attributes.len() >= 4 {
        let kind = u16::from_be_bytes([attributes[0], attributes[1]]);
        let size = usize::from(u16::from_be_bytes([attributes[2], attributes[3]]));
        let value = attributes.get(4..4 + size)?;
        if matches!(kind, ATTR_XOR_MAPPED | ATTR_XOR_MAPPED_ALT) {
            return Some((tx, xor_address(value, &tx)?));
        }
        attributes = attributes.get((4 + size + 3) & !3..)?;
    }
    None
}
fn xor_address(value: &[u8], tx: &[u8; 12]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]) ^ 0x2112;
    let ip = match *value.get(1)? {
        1 => {
            let mut octets: [u8; 4] = value.get(4..8)?.try_into().ok()?;
            octets.iter_mut().zip(COOKIE).for_each(|(a, b)| *a ^= b);
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        2 => {
            let mut octets: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            let mask = COOKIE.iter().chain(tx.iter());
            octets.iter_mut().zip(mask).for_each(|(a, b)| *a ^= b);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_upstream_layout_and_fingerprint() {
        let packet = request(&[1; 12]);
        assert_eq!(packet.len(), 40);
        assert!(is_stun(&packet));
        assert_eq!(&packet[..4], &[0, 1, 0, 20]);
        assert_eq!(&packet[24..32], SOFTWARE);
        let expected = crc32fast::hash(&packet[..32]) ^ FINGERPRINT_XOR;
        assert_eq!(packet[36..], expected.to_be_bytes());
    }

    // 响应字节来自上游 net/stun/stun_test.go 的 "google-1" 与 "stuntman-server ipv6"。
    #[test]
    fn upstream_responses_parse() {
        let google = hex::decode(concat!(
            "0101000c2112a4422360b11e3ec68ffa",
            "93e0800700200008",
            "0001c7866957856f"
        ))
        .unwrap();
        let (tx, address) = parse_response(&google).unwrap();
        assert_eq!(hex::encode(tx), "2360b11e3ec68ffa93e08007");
        assert_eq!(address, "72.69.33.45:59028".parse().unwrap());
        let stuntman = hex::decode(concat!(
            "010100482112a44206f56685d28af3e6",
            "9ce341e2000100140002",
            "90ce260200d1b4cfc10038b231fffeef96f6",
            "802b001400020d962604a880000200d1",
            "0000000000c57001002000140002b1dc",
            "0710a493b23aa785ea38c219620cd714"
        ))
        .unwrap();
        let (_, address) = parse_response(&stuntman).unwrap();
        assert_eq!(
            address,
            "[2602:d1:b4cf:c100:38b2:31ff:feef:96f6]:37070"
                .parse()
                .unwrap()
        );
    }
}
