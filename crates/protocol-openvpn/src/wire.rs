//! 控制包在外层包装内部的明文结构。

use kerlico_core::{Error, Result};

pub(crate) type SessionId = [u8; 8];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Opcode {
    SoftReset,
    Control,
    Ack,
    HardResetClient,
    HardResetServer,
    DataV2,
    HardResetClientV3,
}
impl Opcode {
    pub fn parse(byte: u8) -> Option<(Self, u8)> {
        let opcode = match byte >> 3 {
            3 => Self::SoftReset,
            4 => Self::Control,
            5 => Self::Ack,
            7 => Self::HardResetClient,
            8 => Self::HardResetServer,
            9 => Self::DataV2,
            10 => Self::HardResetClientV3,
            _ => return None,
        };
        Some((opcode, byte & 7))
    }
    pub fn byte(self, key_id: u8) -> u8 {
        let code = match self {
            Self::SoftReset => 3,
            Self::Control => 4,
            Self::Ack => 5,
            Self::HardResetClient => 7,
            Self::HardResetServer => 8,
            Self::DataV2 => 9,
            Self::HardResetClientV3 => 10,
        };
        code << 3 | key_id & 7
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ControlBody<'a> {
    pub acks: Vec<u32>,
    pub ack_session: Option<SessionId>,
    pub packet_id: Option<u32>,
    pub payload: &'a [u8],
}

/// 上游 `RELIABLE_ACK_SIZE`。
const MAX_ACKS: usize = 8;

pub(crate) fn encode_body(
    acks: &[u32],
    remote: Option<&SessionId>,
    packet_id: Option<u32>,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + acks.len() * 4 + 12 + payload.len());
    body.push(acks.len() as u8);
    for ack in acks {
        body.extend_from_slice(&ack.to_be_bytes());
    }
    if let (false, Some(remote)) = (acks.is_empty(), remote) {
        body.extend_from_slice(remote);
    }
    if let Some(packet_id) = packet_id {
        body.extend_from_slice(&packet_id.to_be_bytes());
    }
    body.extend_from_slice(payload);
    body
}

pub(crate) fn decode_body(opcode: Opcode, bytes: &[u8]) -> Result<ControlBody<'_>> {
    let malformed = || Error::Protocol("OpenVPN 控制包格式不合法");
    let (&count, mut rest) = bytes.split_first().ok_or_else(malformed)?;
    let count = usize::from(count);
    if count > MAX_ACKS || rest.len() < count * 4 {
        return Err(malformed());
    }
    let (ids, tail) = rest.split_at(count * 4);
    rest = tail;
    let acks = ids
        .as_chunks::<4>()
        .0
        .iter()
        .map(|id| u32::from_be_bytes(*id))
        .collect();
    let mut ack_session = None;
    if count > 0 {
        let (session, tail) = rest.split_first_chunk::<8>().ok_or_else(malformed)?;
        ack_session = Some(*session);
        rest = tail;
    }
    let mut packet_id = None;
    if opcode != Opcode::Ack {
        let (id, tail) = rest.split_first_chunk::<4>().ok_or_else(malformed)?;
        packet_id = Some(u32::from_be_bytes(*id));
        rest = tail;
    }
    Ok(ControlBody {
        acks,
        ack_session,
        packet_id,
        payload: rest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_byte_splits_high_five_opcode_bits_from_low_three_key_bits() {
        assert_eq!(Opcode::HardResetClient.byte(0), 0x38);
        assert_eq!(Opcode::HardResetServer.byte(0), 0x40);
        assert_eq!(Opcode::DataV2.byte(0), 0x48);
        assert_eq!(Opcode::parse(0x23), Some((Opcode::Control, 3)));
        assert_eq!(Opcode::parse(0x30), None);
    }

    #[test]
    fn control_body_layout_is_acks_then_remote_session_then_packet_id_then_payload() {
        let remote = [1, 2, 3, 4, 5, 6, 7, 8];
        let body = encode_body(&[9], Some(&remote), Some(2), b"tls");
        assert_eq!(
            body,
            [
                1, 0, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 2, b't', b'l', b's'
            ]
        );
        let parsed = decode_body(Opcode::Control, &body).unwrap();
        assert_eq!(
            parsed,
            ControlBody {
                acks: vec![9],
                ack_session: Some(remote),
                packet_id: Some(2),
                payload: b"tls",
            }
        );
    }

    #[test]
    fn ack_packet_has_no_packet_id_and_reset_without_acks_has_no_session() {
        let body = encode_body(&[7], Some(&[1; 8]), None, &[]);
        let parsed = decode_body(Opcode::Ack, &body).unwrap();
        assert_eq!(parsed.packet_id, None);
        assert_eq!(parsed.acks, [7]);
        assert_eq!(encode_body(&[], None, Some(0), &[]), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn truncated_or_oversized_ack_lists_are_rejected() {
        assert!(decode_body(Opcode::Control, &[]).is_err());
        assert!(decode_body(Opcode::Control, &[1, 0, 0]).is_err());
        assert!(decode_body(Opcode::Control, &[9; 80]).is_err());
        assert!(decode_body(Opcode::Control, &[0, 0, 0]).is_err());
    }
}
