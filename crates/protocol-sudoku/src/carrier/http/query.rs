use kerlico_core::{Error, Result};
use std::collections::BTreeMap;

fn decode(input: &str) -> Result<String> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            b'+' => {
                out.push(b' ');
                offset += 1;
            }
            b'%' => {
                if bytes.len() - offset < 3 {
                    return Err(crate::invalid());
                }
                let high = nibble(bytes[offset + 1]).ok_or_else(crate::invalid)?;
                let low = nibble(bytes[offset + 2]).ok_or_else(crate::invalid)?;
                out.push((high << 4) | low);
                offset += 3;
            }
            byte => {
                out.push(byte);
                offset += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| crate::invalid())
}
pub(crate) fn parse(input: Option<&str>) -> Result<BTreeMap<String, String>> {
    let input = input.unwrap_or("");
    if input.len() > 16 * 1024 {
        return Err(Error::ResourceLimit);
    }
    let mut fields = BTreeMap::new();
    for (count, field) in input.split('&').filter(|s| !s.is_empty()).enumerate() {
        if count >= 32 {
            return Err(Error::ResourceLimit);
        }
        let (name, value) = field.split_once('=').unwrap_or((field, ""));
        let name = decode(name)?;
        let value = decode(value)?;
        if fields.insert(name, value).is_some() {
            return Err(crate::invalid());
        }
    }
    Ok(fields)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_decodes_once_and_rejects_duplicate_control_fields() {
        let q = parse(Some("token=abc%5F123&ed=AQID&seq=1")).unwrap();
        assert_eq!(q["token"], "abc_123");
        assert!(parse(Some("token=a&token=b")).is_err());
        assert!(parse(Some("ed=%x0")).is_err());
        assert!(parse(Some("ed=%ff")).is_err());
    }
}
