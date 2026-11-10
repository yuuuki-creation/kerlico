//! 32-byte segment metadata. Multi-byte fields are big endian.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub const OPEN_REQUEST: u8 = 2;
pub const OPEN_RESPONSE: u8 = 3;
pub const CLOSE_REQUEST: u8 = 4;
pub const CLOSE_RESPONSE: u8 = 5;
pub const DATA_C2S: u8 = 6;
pub const DATA_S2C: u8 = 7;
pub const ACK_C2S: u8 = 8;
pub const ACK_S2C: u8 = 9;
pub const DATA_C2S_LOW: u8 = 10;
pub const DATA_S2C_LOW: u8 = 11;
pub const MAX_SESSION_PAYLOAD: usize = 1024;
pub const MAX_PDU: usize = 32 * 1024;
pub const LOW_ENTROPY_PDU: usize = 32764;

#[derive(Clone, Debug)]
pub struct Meta {
    pub kind: u8,
    pub session: u32,
    pub seq: u32,
    pub unack: u32,
    pub window: u16,
    pub fragment: u8,
    pub prefix: u8,
    pub payload_len: u16,
    pub suffix: u8,
    pub low_mode: u8,
    pub low_mask: u32,
    pub extracted: u16,
    pub rotation: u8,
}

pub fn session(kind: u8, session: u32, seq: u32, payload_len: u16, suffix: u8) -> [u8; 32] {
    let mut meta = [0u8; 32];
    meta[0] = kind;
    meta[2..6].copy_from_slice(&minutes().to_be_bytes());
    meta[6..10].copy_from_slice(&session.to_be_bytes());
    meta[10..14].copy_from_slice(&seq.to_be_bytes());
    meta[15..17].copy_from_slice(&payload_len.to_be_bytes());
    meta[17] = suffix;
    meta
}

pub fn data(meta: &Meta) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = meta.kind;
    if is_low(meta.kind) {
        out[1] = meta.low_mode;
    }
    out[2..6].copy_from_slice(&minutes().to_be_bytes());
    out[6..10].copy_from_slice(&meta.session.to_be_bytes());
    out[10..14].copy_from_slice(&meta.seq.to_be_bytes());
    out[14..18].copy_from_slice(&meta.unack.to_be_bytes());
    out[18..20].copy_from_slice(&meta.window.to_be_bytes());
    out[20] = meta.fragment;
    out[21] = meta.prefix;
    out[22..24].copy_from_slice(&meta.payload_len.to_be_bytes());
    out[24] = meta.suffix;
    if is_low(meta.kind) {
        out[25..29].copy_from_slice(&meta.low_mask.to_be_bytes());
        out[29..31].copy_from_slice(&meta.extracted.to_be_bytes());
        out[31] = meta.rotation;
    }
    out
}

pub fn parse(plain: &[u8]) -> io::Result<Meta> {
    if plain.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "meta"));
    }
    let stamp = u32::from_be_bytes(plain[2..6].try_into().unwrap());
    if stamp.abs_diff(minutes()) > 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "time"));
    }
    let kind = plain[0];
    let session = u32::from_be_bytes(plain[6..10].try_into().unwrap());
    let seq = u32::from_be_bytes(plain[10..14].try_into().unwrap());
    if is_session(kind) {
        let payload_len = u16::from_be_bytes(plain[15..17].try_into().unwrap());
        if payload_len as usize > MAX_SESSION_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session payload",
            ));
        }
        return Ok(Meta {
            kind,
            session,
            seq,
            unack: 0,
            window: 0,
            fragment: 0,
            prefix: 0,
            payload_len,
            suffix: plain[17],
            low_mode: 0,
            low_mask: 0,
            extracted: 0,
            rotation: 0,
        });
    }
    if !is_data_ack(kind) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "protocol"));
    }
    let payload_len = u16::from_be_bytes(plain[22..24].try_into().unwrap());
    if !is_low(kind) && payload_len as usize > MAX_PDU {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "数据段载荷超过上限",
        ));
    }
    let low_mode = if is_low(kind) { plain[1] } else { 0 };
    let low_mask = if is_low(kind) {
        u32::from_be_bytes(plain[25..29].try_into().unwrap())
    } else {
        0
    };
    let extracted = if is_low(kind) {
        u16::from_be_bytes(plain[29..31].try_into().unwrap())
    } else {
        0
    };
    let rotation = if is_low(kind) { plain[31] } else { 0 };
    if is_low(kind) {
        let expect = crate::entropy::encoded_len(extracted as usize, low_mode)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "low entropy"))?;
        if payload_len != expect || !crate::entropy::valid_params(low_mode, low_mask, rotation) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "low entropy"));
        }
        let limit = if low_mode == 1 {
            LOW_ENTROPY_PDU
        } else {
            MAX_PDU
        };
        if extracted as usize > limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "low entropy"));
        }
    }
    Ok(Meta {
        kind,
        session,
        seq,
        unack: u32::from_be_bytes(plain[14..18].try_into().unwrap()),
        window: u16::from_be_bytes(plain[18..20].try_into().unwrap()),
        fragment: plain[20],
        prefix: plain[21],
        payload_len,
        suffix: plain[24],
        low_mode,
        low_mask,
        extracted,
        rotation,
    })
}

pub fn is_session(kind: u8) -> bool {
    matches!(
        kind,
        OPEN_REQUEST | OPEN_RESPONSE | CLOSE_REQUEST | CLOSE_RESPONSE
    )
}

pub fn is_data(kind: u8) -> bool {
    matches!(kind, DATA_C2S | DATA_S2C | DATA_C2S_LOW | DATA_S2C_LOW)
}

pub fn is_ack(kind: u8) -> bool {
    matches!(kind, ACK_C2S | ACK_S2C)
}

pub fn is_low(kind: u8) -> bool {
    matches!(kind, DATA_C2S_LOW | DATA_S2C_LOW)
}

fn is_data_ack(kind: u8) -> bool {
    is_data(kind) || is_ack(kind)
}

pub fn minutes() -> u32 {
    (unix_now() / 60) as u32
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
