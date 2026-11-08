use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

pub struct Direction {
    key: [u8; 32],
    nonce: Option<[u8; 24]>,
}

pub struct Opened {
    pub direction: Direction,
    pub plain: Vec<u8>,
    pub username: String,
}

pub fn keys_for(username: &str, password: &str, now_secs: i64) -> [[u8; 32]; 3] {
    let hashed = hash_password(password, username);
    let rounded = round_two_minutes(now_secs);
    [rounded - 120, rounded, rounded + 120].map(|stamp| derive(&hashed, &time_salt(stamp)))
}

pub fn open_first(username: &str, password: &str, packet: &[u8], now_secs: i64) -> Option<Opened> {
    if packet.len() < 24 + 16 {
        return None;
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&packet[..24]);
    if !hint_matches(username, &nonce) {
        return None;
    }
    let sealed = &packet[24..];
    for key in keys_for(username, password, now_secs) {
        if let Some(plain) = open_with(&key, &nonce, sealed) {
            return Some(Opened {
                direction: Direction {
                    key,
                    nonce: Some(nonce),
                },
                plain,
                username: username.to_string(),
            });
        }
    }
    None
}

pub fn client_direction(username: &str, password: &str, now_secs: i64) -> Direction {
    let key = keys_for(username, password, now_secs)[1];
    Direction { key, nonce: None }
}

impl Direction {
    pub(crate) fn fork_send(&self) -> Self {
        Self {
            key: self.key,
            nonce: None,
        }
    }

    pub(crate) fn key_bytes(&self) -> [u8; 32] {
        self.key
    }

    pub(crate) fn from_key(key: [u8; 32]) -> Self {
        Self { key, nonce: None }
    }

    pub(crate) fn seal_at(&self, nonce: &[u8; 24], plain: &[u8]) -> Vec<u8> {
        XChaCha20Poly1305::new((&self.key).into())
            .encrypt(nonce.into(), plain)
            .expect("seal")
    }

    pub(crate) fn open_at(&self, nonce: &[u8; 24], sealed: &[u8]) -> Option<Vec<u8>> {
        open_with(&self.key, nonce, sealed)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn seal(&mut self, username: &str, plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len() + 24 + 16);
        self.seal_into(username, plain, &mut out);
        out
    }

    pub(crate) fn seal_into(&mut self, username: &str, plain: &[u8], out: &mut Vec<u8>) {
        let first = self.nonce.is_none();
        let nonce = if let Some(current) = &mut self.nonce {
            bump(current);
            *current
        } else {
            let mut fresh = [0u8; 24];
            getrandom::getrandom(&mut fresh).expect("nonce");
            apply_hint(username, &mut fresh);
            self.nonce = Some(fresh);
            fresh
        };
        if first {
            out.extend_from_slice(&nonce);
        }
        let start = out.len();
        out.extend_from_slice(plain);
        let tag = XChaCha20Poly1305::new((&self.key).into())
            .encrypt_in_place_detached((&nonce).into(), b"", &mut out[start..])
            .expect("seal");
        out.extend_from_slice(&tag);
    }

    pub fn open_next(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.nonce.as_mut()?;
        bump(nonce);
        open_with(&self.key, nonce, packet)
    }
}

fn open_with(key: &[u8; 32], nonce: &[u8; 24], sealed: &[u8]) -> Option<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(nonce.into(), sealed)
        .ok()
}

fn hash_password(password: &str, username: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update([0u8]);
    hasher.update(username.as_bytes());
    hasher.finalize().into()
}

fn derive(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, 64, &mut key);
    key
}

fn time_salt(unix: i64) -> [u8; 32] {
    Sha256::digest(unix.to_be_bytes()).into()
}

pub fn round_two_minutes(secs: i64) -> i64 {
    let interval = 120i64;
    let rem = secs.rem_euclid(interval);
    let base = secs - rem;
    if rem * 2 < interval {
        base
    } else {
        base + interval
    }
}

fn hint_matches(username: &str, nonce: &[u8; 24]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(&nonce[..16]);
    hasher.finalize()[..4] == nonce[20..]
}

pub(crate) fn nonce_with_hint(username: &str) -> [u8; 24] {
    let mut fresh = [0u8; 24];
    getrandom::getrandom(&mut fresh).expect("nonce");
    apply_hint(username, &mut fresh);
    fresh
}

fn apply_hint(username: &str, nonce: &mut [u8; 24]) {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(&nonce[..16]);
    let digest = hasher.finalize();
    nonce[20..24].copy_from_slice(&digest[..4]);
}

fn bump(nonce: &mut [u8; 24]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_minute_rounding_matches_halfway_away_from_zero() {
        assert_eq!(round_two_minutes(50), 0);
        assert_eq!(round_two_minutes(60), 120);
        assert_eq!(round_two_minutes(100), 120);
        assert_eq!(round_two_minutes(180), 240);
    }

    #[test]
    fn first_seal_opens_with_the_same_password() {
        let now = 1_700_000_000i64;
        let mut client = client_direction("alice", "secret", now);
        let packet = client.seal("alice", b"hello");
        let opened = open_first("alice", "secret", &packet, now).expect("open");
        assert_eq!(opened.plain, b"hello");
        let second = client.seal("alice", b"next");
        let mut server = opened.direction;
        assert_eq!(server.open_next(&second).unwrap(), b"next");
    }
}
