//! 对端发现消息（上游 `disco` 包）：外层封装与明文消息。

use crate::keys::{DiscoKey, NodeKey, Secret};
use kerlico_core::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const HEADER: usize = MAGIC.len() + 32;
const TYPE_PING: u8 = 1;
const TYPE_PONG: u8 = 2;
const TYPE_CALL_ME_MAYBE: u8 = 3;
const ADDRESS: usize = 18;

/// DERP 路径在 Pong 中使用的魔术地址，端口为区域号。
pub const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Ping { tx: [u8; 12], node: NodeKey },
    Pong { tx: [u8; 12], source: SocketAddr },
    CallMeMaybe { endpoints: Vec<SocketAddr> },
}
impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        match self {
            Self::Ping { tx, node } => {
                output.extend_from_slice(&[TYPE_PING, 0]);
                output.extend_from_slice(tx);
                output.extend_from_slice(&node.0);
            }
            Self::Pong { tx, source } => {
                output.extend_from_slice(&[TYPE_PONG, 0]);
                output.extend_from_slice(tx);
                put_address(&mut output, *source);
            }
            Self::CallMeMaybe { endpoints } => {
                output.extend_from_slice(&[TYPE_CALL_ME_MAYBE, 0]);
                for endpoint in endpoints {
                    put_address(&mut output, *endpoint);
                }
            }
        }
        output
    }
    /// 未知类型与更高版本的字段按上游规则忽略。
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let (&kind, rest) = bytes.split_first()?;
        let (_version, body) = rest.split_first()?;
        match kind {
            TYPE_PING => Some(Self::Ping {
                tx: body.get(..12)?.try_into().ok()?,
                node: NodeKey(body.get(12..44)?.try_into().ok()?),
            }),
            TYPE_PONG => Some(Self::Pong {
                tx: body.get(..12)?.try_into().ok()?,
                source: get_address(body.get(12..12 + ADDRESS)?.try_into().ok()?),
            }),
            TYPE_CALL_ME_MAYBE => Some(Self::CallMeMaybe {
                endpoints: body
                    .as_chunks::<ADDRESS>()
                    .0
                    .iter()
                    .map(get_address)
                    .collect(),
            }),
            _ => None,
        }
    }
}
fn put_address(output: &mut Vec<u8>, address: SocketAddr) {
    let ip = match address.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    output.extend_from_slice(&ip.octets());
    output.extend_from_slice(&address.port().to_be_bytes());
}
fn get_address(bytes: &[u8; ADDRESS]) -> SocketAddr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&bytes[..16]);
    let ip = Ipv6Addr::from(octets).to_canonical();
    SocketAddr::new(ip, u16::from_be_bytes([bytes[16], bytes[17]]))
}

pub fn is_disco(packet: &[u8]) -> bool {
    packet.starts_with(MAGIC) && packet.len() >= HEADER + 24
}
pub fn seal(secret: &Secret, peer: &DiscoKey, message: &Message) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(HEADER + 64);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&secret.public());
    output.extend_from_slice(&secret.seal(&peer.0, &message.encode())?);
    Ok(output)
}
pub fn sender(packet: &[u8]) -> Option<DiscoKey> {
    if !is_disco(packet) {
        return None;
    }
    Some(DiscoKey(packet[MAGIC.len()..HEADER].try_into().ok()?))
}
pub fn open(secret: &Secret, packet: &[u8]) -> Option<(DiscoKey, Message)> {
    let from = sender(packet)?;
    let plain = secret.open(&from.0, &packet[HEADER..])?;
    Some((from, Message::parse(&plain)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 期望字节来自上游 disco/disco_test.go 的 TestMarshalAndParse。
    #[test]
    fn upstream_marshal_vectors() {
        let tx: [u8; 12] = std::array::from_fn(|index| index as u8 + 1);
        let mut node = [0; 32];
        node[1] = 1;
        node[2] = 2;
        node[30] = 30;
        node[31] = 31;
        let ping = Message::Ping {
            tx,
            node: NodeKey(node),
        };
        assert_eq!(
            hex::encode(ping.encode()),
            concat!(
                "01000102030405060708090a0b0c",
                "0001020000000000000000000000000000000000000000000000000000001e1f"
            )
        );
        assert_eq!(Message::parse(&ping.encode()), Some(ping));
        let pong = Message::Pong {
            tx,
            source: "2.3.4.5:1234".parse().unwrap(),
        };
        assert_eq!(
            hex::encode(pong.encode()),
            "02000102030405060708090a0b0c00000000000000000000ffff0203040504d2"
        );
        assert_eq!(Message::parse(&pong.encode()), Some(pong));
        let call = Message::CallMeMaybe {
            endpoints: vec![
                "1.2.3.4:567".parse().unwrap(),
                "[2001::3456]:789".parse().unwrap(),
            ],
        };
        assert_eq!(
            hex::encode(call.encode()),
            "030000000000000000000000ffff010203040237200100000000000000000000000034560315"
        );
        assert_eq!(Message::parse(&call.encode()), Some(call));
    }

    #[test]
    fn sealed_message_opens_for_the_peer_only() {
        let (alice, bob, eve) = (Secret::generate(), Secret::generate(), Secret::generate());
        let message = Message::Ping {
            tx: [7; 12],
            node: NodeKey([9; 32]),
        };
        let packet = seal(&alice, &DiscoKey(bob.public()), &message).unwrap();
        assert_eq!(
            open(&bob, &packet),
            Some((DiscoKey(alice.public()), message))
        );
        assert_eq!(open(&eve, &packet), None);
        assert!(!is_disco(&packet[..20]));
    }

    #[test]
    fn unknown_type_is_ignored() {
        assert_eq!(Message::parse(&[9, 0, 1, 2]), None);
    }
}
