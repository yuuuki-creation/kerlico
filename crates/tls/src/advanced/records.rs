//! TLS 1.3 receive records after the native handshake has authenticated its peer.
//! Writes, handshake policy, ticket validation and KeyUpdate replies stay native.

use boring2::{
    ex_data::Index,
    ssl::{Ssl, SslRef, SslVersion},
};
use foreign_types::ForeignTypeRef;
use ring::{aead, hkdf};
use std::{
    io,
    sync::{Arc, LazyLock, Mutex},
};

type Capture = Arc<Mutex<Vec<u8>>>;
static CAPTURE: LazyLock<Index<Ssl, Capture>> =
    LazyLock::new(|| Ssl::new_ex_index().expect("TLS receive secret index"));

pub(super) fn capture(ssl: &mut Ssl) -> Capture {
    let value = Arc::new(Mutex::new(Vec::new()));
    ssl.set_ex_data(*CAPTURE, value.clone());
    value
}

/// The native callback only copies this direction's application traffic secret
/// into this connection. It never logs it or retains handshake traffic keys.
pub(super) fn keylog(ssl: &SslRef, line: &str) {
    let Some(capture) = ssl.ex_data(*CAPTURE) else {
        return;
    };
    let mut parts = line.split_ascii_whitespace();
    let wanted = if ssl.is_server() {
        "CLIENT_TRAFFIC_SECRET_0"
    } else {
        "SERVER_TRAFFIC_SECRET_0"
    };
    if parts.next() != Some(wanted) {
        return;
    }
    let _random = parts.next();
    let Some(hex) = parts.next().filter(|s| matches!(s.len(), 64 | 96)) else {
        return;
    };
    let mut secret = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let nibble = |v: u8| match v {
            b'0'..=b'9' => Some(v - b'0'),
            b'a'..=b'f' => Some(v - b'a' + 10),
            b'A'..=b'F' => Some(v - b'A' + 10),
            _ => None,
        };
        let (Some(a), Some(b)) = (nibble(pair[0]), nibble(pair[1])) else {
            return;
        };
        secret.push(a * 16 + b);
    }
    *capture.lock().expect("TLS receive secret") = secret;
}

pub(super) enum Message {
    Closed,
    KeyUpdate(bool),
    Ticket(Vec<u8>),
}

pub(super) struct Receiver {
    secret: hkdf::Prk,
    hash: hkdf::Algorithm,
    algorithm: &'static aead::Algorithm,
    key: aead::LessSafeKey,
    iv: [u8; 12],
    seq: u64,
    server: bool,
    handshake: Vec<u8>,
    empty_records: u8,
    warnings: u8,
    key_updates: u8,
}

#[derive(Debug)]
pub(super) struct RecordError {
    pub alert: u8,
    message: &'static str,
}
impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for RecordError {}
fn invalid(message: &'static str) -> io::Error {
    alert(50, message)
}
fn alert(alert: u8, message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, RecordError { alert, message })
}

struct Length(usize);
impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(secret: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> io::Result<()> {
    let mut info = Vec::with_capacity(label.len() + 10);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    secret
        .expand(&[&info], Length(out.len()))
        .map_err(|_| invalid("TLS key expansion"))?
        .fill(out)
        .map_err(|_| invalid("TLS key expansion"))
}

impl Receiver {
    pub(super) fn from_handshake(ssl: &SslRef, capture: Capture) -> io::Result<Option<Self>> {
        if ssl.version() != Some(SslVersion::TLS1_3) {
            return Ok(None);
        }
        let cipher = ssl
            .current_cipher()
            .ok_or_else(|| invalid("TLS cipher"))?
            .protocol_id();
        let (algorithm, hash) = match cipher {
            0x1301 => (&aead::AES_128_GCM, hkdf::HKDF_SHA256),
            0x1302 => (&aead::AES_256_GCM, hkdf::HKDF_SHA384),
            0x1303 => (&aead::CHACHA20_POLY1305, hkdf::HKDF_SHA256),
            _ => return Err(invalid("TLS 1.3 receive cipher")),
        };
        let mut captured = std::mem::take(&mut *capture.lock().expect("TLS receive secret"));
        if captured.len() != hash.hmac_algorithm().digest_algorithm().output_len() {
            return Err(invalid("missing TLS 1.3 receive secret"));
        }
        let secret = hkdf::Prk::new_less_safe(hash, &captured);
        captured.fill(0);
        let (key, iv) = Self::key(&secret, algorithm)?;
        // SAFETY: ssl is the live, completed native connection. This public
        // accessor reports its actual next record number, including any
        // application-epoch messages processed during the handshake.
        let seq = unsafe { boring_sys::SSL_get_read_sequence(ssl.as_ptr()) };
        Ok(Some(Self {
            secret,
            hash,
            algorithm,
            key,
            iv,
            seq,
            server: ssl.is_server(),
            handshake: Vec::new(),
            empty_records: 0,
            warnings: 0,
            key_updates: 0,
        }))
    }

    fn key(
        secret: &hkdf::Prk,
        algorithm: &'static aead::Algorithm,
    ) -> io::Result<(aead::LessSafeKey, [u8; 12])> {
        let mut bytes = [0; 32];
        expand(secret, b"key", &mut bytes[..algorithm.key_len()])?;
        let key = aead::UnboundKey::new(algorithm, &bytes[..algorithm.key_len()])
            .map_err(|_| invalid("TLS key"))?;
        bytes.fill(0);
        let mut iv = [0; 12];
        expand(secret, b"iv", &mut iv)?;
        Ok((aead::LessSafeKey::new(key), iv))
    }

    pub(super) fn open(&mut self, record: &mut [u8]) -> io::Result<(u8, usize)> {
        if record.len() < 22
            || record.len() > 5 + 16384 + 256
            || record[..3] != [23, 3, 3]
            || usize::from(u16::from_be_bytes([record[3], record[4]])) != record.len() - 5
        {
            return Err(invalid("TLS 1.3 record header"));
        }
        if self.seq == u64::MAX {
            return Err(invalid("TLS receive sequence exhausted"));
        }
        let header: [u8; 5] = record[..5].try_into().expect("record header");
        let mut iv = self.iv;
        for (byte, seq) in iv[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *byte ^= seq;
        }
        let plain = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::from(header),
                &mut record[5..],
            )
            .map_err(|_| alert(20, "TLS record authentication"))?;
        self.seq += 1;
        let end = plain
            .iter()
            .rposition(|&b| b != 0)
            .ok_or_else(|| invalid("TLS record without content type"))?;
        if end > 16384 {
            return Err(invalid("TLS plaintext too large"));
        }
        let kind = plain[end];
        if kind != 22 && !self.handshake.is_empty() {
            return Err(invalid("interleaved TLS handshake message"));
        }
        if !matches!(kind, 21..=23) {
            return Err(invalid("TLS inner content type"));
        }
        if end == 0 {
            self.empty_records += 1;
            if self.empty_records > 32 {
                return Err(alert(10, "too many empty TLS records"));
            }
        } else if kind != 21 {
            self.empty_records = 0;
            self.warnings = 0;
        }
        if kind == 23 && end != 0 {
            self.key_updates = 0;
        }
        Ok((kind, end))
    }

    pub(super) fn control(&mut self, kind: u8, plain: &[u8]) -> io::Result<Vec<Message>> {
        if kind == 21 {
            if plain.len() != 2 {
                return Err(invalid("TLS alert length"));
            }
            return match (plain[0], plain[1]) {
                (1, 0) => Ok(vec![Message::Closed]),
                (1, 90) => {
                    self.warnings += 1;
                    if self.warnings > 4 {
                        return Err(alert(10, "too many TLS warning alerts"));
                    }
                    Ok(Vec::new())
                }
                (2, _) => Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "TLS peer alert",
                )),
                _ => Err(alert(47, "TLS alert level or description")),
            };
        }
        if kind != 22 {
            return Err(invalid("TLS control content type"));
        }
        self.handshake.extend_from_slice(plain);
        let mut messages = Vec::new();
        let mut used = 0;
        while self.handshake.len() - used >= 4 {
            let head = &self.handshake[used..used + 4];
            let len = u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize;
            if len > 65536 {
                return Err(invalid("TLS post-handshake message too large"));
            }
            let end = used + 4 + len;
            if end > self.handshake.len() {
                break;
            }
            match head[0] {
                24 if len == 1 && self.handshake[used + 4] <= 1 && end == self.handshake.len() => {
                    self.key_updates += 1;
                    if self.key_updates > 32 {
                        return Err(alert(10, "too many TLS key updates"));
                    }
                    messages.push(Message::KeyUpdate(self.handshake[used + 4] == 1));
                    let mut next = [0; 48];
                    let len = self.hash.hmac_algorithm().digest_algorithm().output_len();
                    expand(&self.secret, b"traffic upd", &mut next[..len])?;
                    self.secret = hkdf::Prk::new_less_safe(self.hash, &next[..len]);
                    next.fill(0);
                    (self.key, self.iv) = Self::key(&self.secret, self.algorithm)?;
                    self.seq = 0;
                }
                4 if !self.server => {
                    messages.push(Message::Ticket(self.handshake[used..end].to_vec()))
                }
                _ => return Err(invalid("unexpected TLS post-handshake message")),
            }
            used = end;
        }
        self.handshake.drain(..used);
        Ok(messages)
    }
}
