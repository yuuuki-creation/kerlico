//! CSTP 帧：`"STF" 0x01`、两字节大端负载长度、一字节类型、一字节保留。

use bytes::{Buf, BytesMut};
use kerlico_core::{Error, Result};

const MAGIC: [u8; 4] = [b'S', b'T', b'F', 1];
const HEADER: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameKind {
    Data,
    DpdRequest,
    DpdResponse,
    Disconnect,
    Keepalive,
    Compressed,
    Terminate,
    Other(u8),
}
impl FrameKind {
    fn code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::DpdRequest => 3,
            Self::DpdResponse => 4,
            Self::Disconnect => 5,
            Self::Keepalive => 7,
            Self::Compressed => 8,
            Self::Terminate => 9,
            Self::Other(code) => code,
        }
    }
    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Data,
            3 => Self::DpdRequest,
            4 => Self::DpdResponse,
            5 => Self::Disconnect,
            7 => Self::Keepalive,
            8 => Self::Compressed,
            9 => Self::Terminate,
            other => Self::Other(other),
        }
    }
}

pub(crate) struct Frame {
    pub kind: FrameKind,
    pub payload: BytesMut,
}

pub(crate) fn encode(kind: FrameKind, payload: &[u8], out: &mut BytesMut) -> Result<()> {
    let length =
        u16::try_from(payload.len()).map_err(|_| Error::Protocol("OpenConnect 帧负载过长"))?;
    out.reserve(HEADER + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&[kind.code(), 0]);
    out.extend_from_slice(payload);
    Ok(())
}

/// 从缓冲取出一个完整帧；数据不足时返回 `None` 且不消费。
pub(crate) fn take_frame(buffer: &mut BytesMut) -> Result<Option<Frame>> {
    if buffer.len() < HEADER {
        return Ok(None);
    }
    if buffer[..MAGIC.len()] != MAGIC {
        return Err(Error::Protocol("OpenConnect 帧头不合法"));
    }
    let length = usize::from(u16::from_be_bytes([buffer[4], buffer[5]]));
    if buffer.len() < HEADER + length {
        return Ok(None);
    }
    let kind = FrameKind::from_code(buffer[6]);
    buffer.advance(HEADER);
    Ok(Some(Frame {
        kind,
        payload: buffer.split_to(length),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_frames_match_the_openconnect_fixed_packets() {
        for (kind, expected) in [
            (FrameKind::DpdRequest, *b"STF\x01\0\0\x03\0"),
            (FrameKind::DpdResponse, *b"STF\x01\0\0\x04\0"),
            (FrameKind::Keepalive, *b"STF\x01\0\0\x07\0"),
        ] {
            let mut out = BytesMut::new();
            encode(kind, &[], &mut out).unwrap();
            assert_eq!(out.as_ref(), expected);
        }
    }

    #[test]
    fn data_frame_round_trips_and_partial_input_is_not_consumed() {
        let mut wire = BytesMut::new();
        encode(FrameKind::Data, &[0x45, 0, 0, 20], &mut wire).unwrap();
        assert_eq!(wire.as_ref(), b"STF\x01\0\x04\0\0\x45\0\0\x14");
        let mut partial = BytesMut::from(&wire[..wire.len() - 1]);
        assert!(take_frame(&mut partial).unwrap().is_none());
        assert_eq!(partial.len(), wire.len() - 1);
        let frame = take_frame(&mut wire).unwrap().unwrap();
        assert_eq!(frame.kind, FrameKind::Data);
        assert_eq!(frame.payload.as_ref(), &[0x45, 0, 0, 20]);
        assert!(wire.is_empty());
    }

    #[test]
    fn bad_magic_is_a_protocol_error_and_unknown_types_are_kept() {
        let mut bad = BytesMut::from(&b"HTTP/1.1"[..]);
        assert!(take_frame(&mut bad).is_err());
        let mut unknown = BytesMut::from(&b"STF\x01\0\0\x63\0"[..]);
        assert_eq!(
            take_frame(&mut unknown).unwrap().unwrap().kind,
            FrameKind::Other(0x63)
        );
    }

    #[test]
    fn oversized_payload_is_refused() {
        let mut out = BytesMut::new();
        assert!(encode(FrameKind::Data, &vec![0; 65536], &mut out).is_err());
        assert!(out.is_empty());
    }
}
