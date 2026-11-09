use sha1::{Digest, Sha1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UuidError;

/// Xray accepts a UUID or a custom string of 1 to 30 bytes.
pub fn parse_id(text: &str) -> Result<[u8; 16], UuidError> {
    let bytes = text.as_bytes();
    if (32..=36).contains(&bytes.len()) {
        return parse_uuid(bytes);
    }
    if bytes.is_empty() || bytes.len() > 30 {
        return Err(UuidError);
    }
    let mut hasher = Sha1::new();
    hasher.update([0u8; 16]);
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 0x0f) | 0x50;
    id[8] = (id[8] & 0x3f) | 0x80;
    Ok(id)
}

fn parse_uuid(text: &[u8]) -> Result<[u8; 16], UuidError> {
    let groups = [8usize, 4, 4, 4, 12];
    let mut id = [0u8; 16];
    let mut cursor = 0;
    let mut out = 0;
    for group in groups {
        if cursor < text.len() && text[cursor] == b'-' {
            cursor += 1;
        }
        if cursor + group > text.len() {
            return Err(UuidError);
        }
        let mut nibble = [0u8; 2];
        for index in (0..group).step_by(2) {
            nibble[0] = text[cursor + index];
            nibble[1] = text[cursor + index + 1];
            id[out] = decode_hex(&nibble)?;
            out += 1;
        }
        cursor += group;
    }
    if cursor != text.len() {
        return Err(UuidError);
    }
    Ok(id)
}

fn decode_hex(pair: &[u8; 2]) -> Result<u8, UuidError> {
    Ok((hex(pair[0])? << 4) | hex(pair[1])?)
}

fn hex(byte: u8) -> Result<u8, UuidError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(UuidError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_string_matches_xray() {
        let id = parse_id("我爱🍉老师1314").unwrap();
        assert_eq!(
            id,
            [
                0x57, 0x83, 0xa3, 0xe7, 0xe3, 0x73, 0x51, 0xcd, 0x86, 0x42, 0xc8, 0x37, 0x82, 0xb8, 0x07, 0xc5
            ]
        );
        assert_eq!(parse_id("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap(), id);
    }

    #[test]
    fn rejects_empty_and_31_bytes() {
        assert!(parse_id("").is_err());
        assert!(parse_id(&"a".repeat(31)).is_err());
    }
}
