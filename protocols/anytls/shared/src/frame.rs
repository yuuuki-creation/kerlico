//! Session frames: 1 byte command, 4 byte stream id, 2 byte length, then the data
//! (mihomo `transport/anytls/session/frame.go`).

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

pub const HEADER: usize = 7;
/// The length field is 16 bits, so one PSH frame carries at most this much.
pub const MAX_DATA: usize = 0xFFFF;

pub fn header(cmd: u8, sid: u32, len: usize) -> [u8; HEADER] {
    let sid = sid.to_be_bytes();
    let len = (len as u16).to_be_bytes();
    [cmd, sid[0], sid[1], sid[2], sid[3], len[0], len[1]]
}

/// `util.StringMap.ToBytes` with a fixed key order; Go iterates its map in random order, and the
/// reader does not care.
pub fn string_map(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Appends whole PSH frames for `data`, split at `MAX_DATA` as `writeDataFrame` does.
pub fn push_data(out: &mut Vec<u8>, sid: u32, data: &[u8]) {
    for chunk in data.chunks(MAX_DATA) {
        out.extend_from_slice(&header(CMD_PSH, sid, chunk.len()));
        out.extend_from_slice(chunk);
    }
}

pub fn push_frame(out: &mut Vec<u8>, cmd: u8, sid: u32, data: &[u8]) {
    out.extend_from_slice(&header(cmd, sid, data.len()));
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors::{unhex, CLIENT_FIN, SERVER};

    #[test]
    fn frames_match_mihomo() {
        let mut out = Vec::new();
        push_frame(&mut out, CMD_SYNACK, 7, &[]);
        assert_eq!(out, unhex(SERVER[0]));
        out.clear();
        push_data(&mut out, 7, &crate::vectors::pattern(3, 5));
        assert_eq!(out, unhex(SERVER[1]));
        out.clear();
        push_frame(&mut out, CMD_SERVER_SETTINGS, 0, &string_map(&[("v", "2")]));
        assert_eq!(out, unhex(SERVER[2]));
        assert_eq!(header(CMD_FIN, 1, 0).to_vec(), unhex(CLIENT_FIN));
        out.clear();
        push_data(&mut out, 9, &vec![1u8; 70000]);
        assert_eq!(out.len(), 70000 + 14);
        assert_eq!(&out[..7], &header(CMD_PSH, 9, 65535));
        assert_eq!(&out[7 + 65535..7 + 65535 + 7], &header(CMD_PSH, 9, 70000 - 65535));
    }
}
