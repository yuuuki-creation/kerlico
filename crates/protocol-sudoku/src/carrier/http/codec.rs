use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use kerlico_core::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Stream,
    Poll,
}
impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Poll => "poll",
        }
    }
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Stream => "application/octet-stream",
            Self::Poll => "text/plain",
        }
    }
    pub fn encode(self, bytes: &[u8]) -> Vec<u8> {
        if self == Self::Stream {
            return bytes.to_vec();
        }
        let mut out = Vec::new();
        for line in bytes.chunks(16 * 1024) {
            out.extend_from_slice(STANDARD.encode(line).as_bytes());
            out.push(b'\n');
        }
        out
    }
    pub fn decode_upload(self, bytes: &[u8]) -> Result<Vec<u8>> {
        if bytes.len() > 1024 * 1024 {
            return Err(Error::ResourceLimit);
        }
        if self == Self::Stream {
            return Ok(bytes.to_vec());
        }
        let mut out = Vec::new();
        for line in bytes.split(|&b| b == b'\n') {
            let line = trim(line);
            if line.is_empty() {
                continue;
            }
            let decoded = STANDARD.decode(line).map_err(|_| crate::invalid())?;
            if out.len().saturating_add(decoded.len()) > 1024 * 1024 {
                return Err(Error::ResourceLimit);
            }
            out.extend(decoded);
        }
        Ok(out)
    }
}
fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub(crate) struct Authorization {
    pub token: String,
    pub early: Option<Vec<u8>>,
    pub sequences: bool,
}
pub(crate) fn authorization(bytes: &[u8]) -> Result<Authorization> {
    if bytes.len() > 4096 {
        return Err(Error::ResourceLimit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| crate::invalid())?;
    let mut token = None;
    let mut early = None;
    let mut sequences = false;
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("token=") {
            if token.is_some()
                || value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(crate::invalid());
            }
            token = Some(value.to_owned());
        } else if let Some(value) = line.trim().strip_prefix("ed=") {
            if early.is_some() {
                return Err(crate::invalid());
            }
            early = Some(
                URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|_| crate::invalid())?,
            );
        } else if let Some(value) = line.trim().strip_prefix("cap=") {
            sequences = value.split(',').any(|cap| cap.trim() == "upload-seq");
        }
    }
    Ok(Authorization {
        token: token.ok_or_else(crate::invalid)?,
        early,
        sequences,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_upload_lines_zero_and_authorization_fields() {
        let data = vec![0x5a; 65537];
        for mode in [Mode::Stream, Mode::Poll] {
            assert_eq!(mode.decode_upload(&mode.encode(&data)).unwrap(), data);
            assert!(mode.decode_upload(&[]).unwrap().is_empty());
        }
        let auth = authorization(b"token=abc_-123\ned=AQID\ncap=upload-seq\n").unwrap();
        assert_eq!(auth.token, "abc_-123");
        assert_eq!(auth.early, Some(vec![1, 2, 3]));
        assert!(auth.sequences);
        assert!(authorization(b"token=abc\ntoken=other").is_err());
        assert!(authorization(b"token=bad&query").is_err());
    }
}
