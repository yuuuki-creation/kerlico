use chacha20::cipher::consts::U10;
use pbkdf2::pbkdf2_hmac;
use ring::aead;
use sha2::{Digest, Sha256};

pub struct Direction {
    key: [u8; 32],
    nonce: Option<[u8; 24]>,
    cipher: Option<CachedCipher>,
}

struct CachedCipher {
    prefix: [u8; 16],
    key: aead::LessSafeKey,
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
        let mut direction = Direction::from_key(key);
        if let Some(plain) = direction.open_at(&nonce, sealed) {
            direction.nonce = Some(nonce);
            return Some(Opened {
                direction,
                plain,
                username: username.to_string(),
            });
        }
    }
    None
}

pub fn client_direction(username: &str, password: &str, now_secs: i64) -> Direction {
    let key = keys_for(username, password, now_secs)[1];
    Direction {
        key,
        nonce: None,
        cipher: None,
    }
}

impl Direction {
    pub(crate) fn fork_send(&self) -> Self {
        Self {
            key: self.key,
            nonce: None,
            cipher: None,
        }
    }

    pub(crate) fn key_bytes(&self) -> [u8; 32] {
        self.key
    }

    pub(crate) fn from_key(key: [u8; 32]) -> Self {
        Self {
            key,
            nonce: None,
            cipher: None,
        }
    }

    pub(crate) fn seal_at(&mut self, nonce: &[u8; 24], plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len() + 16);
        self.seal_at_into(nonce, plain, &mut out);
        out
    }

    pub(crate) fn seal_at_into(&mut self, nonce: &[u8; 24], plain: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(plain);
        let (key, nonce) = self.cipher_at(nonce);
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut out[start..])
            .expect("seal");
        out.extend_from_slice(tag.as_ref());
    }

    pub(crate) fn open_at(&mut self, nonce: &[u8; 24], sealed: &[u8]) -> Option<Vec<u8>> {
        let mut plain = sealed.to_vec();
        self.open_at_in_place(nonce, &mut plain)?;
        Some(plain)
    }

    pub(crate) fn open_at_in_place(
        &mut self,
        nonce: &[u8; 24],
        sealed: &mut Vec<u8>,
    ) -> Option<()> {
        let (key, nonce) = self.cipher_at(nonce);
        let len = key
            .open_in_place(nonce, aead::Aad::empty(), sealed)
            .ok()?
            .len();
        sealed.truncate(len);
        Some(())
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
        self.seal_at_into(&nonce, plain, out);
    }

    pub fn open_next(&mut self, mut packet: Vec<u8>) -> Option<Vec<u8>> {
        let nonce = self.nonce.as_mut()?;
        bump(nonce);
        let nonce = *nonce;
        self.open_at_in_place(&nonce, &mut packet)?;
        Some(packet)
    }

    fn cipher_at(&mut self, nonce: &[u8; 24]) -> (&aead::LessSafeKey, aead::Nonce) {
        let prefix: [u8; 16] = nonce[..16].try_into().unwrap();
        if !matches!(&self.cipher, Some(cipher) if cipher.prefix == prefix) {
            let subkey = chacha20::hchacha::<U10>((&self.key).into(), (&prefix).into());
            let key =
                aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &subkey).expect("32-byte key");
            self.cipher = Some(CachedCipher {
                prefix,
                key: aead::LessSafeKey::new(key),
            });
        }
        let mut short_nonce = [0; 12];
        short_nonce[4..].copy_from_slice(&nonce[16..]);
        (
            &self.cipher.as_ref().unwrap().key,
            aead::Nonce::assume_unique_for_key(short_nonce),
        )
    }
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
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305,
    };

    #[test]
    fn wire_cipher_matches_rustcrypto_across_block_and_nonce_boundaries() {
        for seed in [0u8, 1, 127, 255] {
            let key = std::array::from_fn(|i| (i as u8).wrapping_add(seed));
            let reference = XChaCha20Poly1305::new((&key).into());
            let mut direction = Direction::from_key(key);
            for nonce in [
                [0; 24],
                [255; 24],
                std::array::from_fn(|i| (i as u8) ^ seed),
            ] {
                for len in [0, 1, 15, 16, 31, 32, 63, 64, 65, 255, 1024, 32768, 65535] {
                    let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
                    let expected = reference
                        .encrypt((&nonce).into(), plain.as_slice())
                        .unwrap();
                    let actual = direction.seal_at(&nonce, &plain);
                    assert_eq!(actual, expected, "seed={seed}, len={len}");
                    assert_eq!(direction.open_at(&nonce, &expected).unwrap(), plain);
                }
            }
        }
    }

    #[test]
    fn tcp_nonce_carry_changes_the_xchacha_subkey() {
        let key = [7; 32];
        let mut nonce = [0x37; 24];
        nonce[16..].fill(255);
        let mut direction = Direction {
            key,
            nonce: Some(nonce),
            cipher: None,
        };
        direction.seal_at(&nonce, b"before");
        let wire = direction.seal("alice", b"carry");
        let mut expected_nonce = [0x37; 24];
        expected_nonce[15] = 0x38;
        expected_nonce[16..].fill(0);
        let reference = XChaCha20Poly1305::new((&key).into());
        assert_eq!(
            wire,
            reference
                .encrypt((&expected_nonce).into(), b"carry".as_slice())
                .unwrap()
        );
    }

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
        assert_eq!(server.open_next(second).unwrap(), b"next");
    }

    #[test]
    fn appended_frames_keep_padding_outside_the_cipher_and_reject_tampering() {
        let now = 1_700_000_000;
        let mut client = client_direction("alice", "secret", now);
        let mut wire = Vec::new();
        client.seal_into("alice", &[7; 32], &mut wire);
        let header_end = wire.len();
        wire.extend_from_slice(b"pad");
        client.seal_into("alice", b"payload", &mut wire);
        let opened = open_first("alice", "secret", &wire[..header_end], now).unwrap();
        assert_eq!(opened.plain, [7; 32]);
        let mut server = opened.direction;
        assert_eq!(
            server.open_next(wire[header_end + 3..].to_vec()).unwrap(),
            b"payload"
        );
        for index in [header_end + 3, wire.len() - 1] {
            let mut damaged = wire[header_end + 3..].to_vec();
            damaged[index - header_end - 3] ^= 1;
            let mut server = open_first("alice", "secret", &wire[..header_end], now)
                .unwrap()
                .direction;
            assert!(server.open_next(damaged).is_none());
        }
    }
}
