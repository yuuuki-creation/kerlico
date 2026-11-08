//! 固定 Snell KDF 参数，头部与载荷分别使用不重复的 nonce。
use crate::io_protocol;
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::aead::{AES_128_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use std::io;
pub(crate) struct Cipher {
    key: LessSafeKey,
    counter: u64,
}
impl Cipher {
    pub fn new(psk: &[u8], salt: &[u8; 16]) -> io::Result<Self> {
        Self::new_v3(psk, salt, false)
    }
    pub fn derive_key(psk: &[u8], salt: &[u8; 16]) -> io::Result<[u8; 32]> {
        let params = Params::new(8, 3, 1, Some(32)).map_err(|_| io_protocol())?;
        let mut bytes = [0; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(psk, salt, &mut bytes)
            .map_err(|_| io_protocol())?;
        Ok(bytes)
    }
    pub fn from_derived_key(bytes: &[u8; 32], chacha: bool) -> io::Result<Self> {
        let key = if chacha {
            UnboundKey::new(&CHACHA20_POLY1305, &bytes[..32]).map_err(|_| io_protocol())?
        } else {
            UnboundKey::new(&AES_128_GCM, &bytes[..16]).map_err(|_| io_protocol())?
        };
        Ok(Self {
            key: LessSafeKey::new(key),
            counter: 0,
        })
    }
    pub fn new_v3(psk: &[u8], salt: &[u8; 16], chacha: bool) -> io::Result<Self> {
        let mut bytes = Self::derive_key(psk, salt)?;
        let cipher = Self::from_derived_key(&bytes, chacha);
        bytes.fill(0);
        cipher
    }
    fn nonce(&mut self) -> io::Result<Nonce> {
        let mut bytes = [0; 12];
        bytes[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.checked_add(1).ok_or_else(io_protocol)?;
        Ok(Nonce::assume_unique_for_key(bytes))
    }
    pub fn seal_into(&mut self, data: &[u8], aad: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.nonce()?;
        let start = out.len();
        out.extend_from_slice(data);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut out[start..])
            .map_err(|_| io_protocol())?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }
    #[cfg(test)]
    pub fn seal(&mut self, data: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(data.len() + 16);
        self.seal_into(data, aad, &mut bytes)?;
        Ok(bytes)
    }
    pub fn open_in_place(&mut self, bytes: &mut Vec<u8>, aad: &[u8]) -> io::Result<()> {
        let nonce = self.nonce()?;
        let n = self
            .key
            .open_in_place(nonce, Aad::from(aad), bytes)
            .map_err(|_| io_protocol())?
            .len();
        bytes.truncate(n);
        Ok(())
    }
    #[cfg(test)]
    pub fn open(&mut self, mut bytes: Vec<u8>, aad: &[u8]) -> io::Result<Vec<u8>> {
        self.open_in_place(&mut bytes, aad)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonce_exhaustion_and_aad_authentication() {
        let salt = [17; 16];
        let mut sender = Cipher::new(b"snell-test-psk", &salt).unwrap();
        let sealed = sender.seal(b"payload", b"header").unwrap();
        let mut receiver = Cipher::new(b"snell-test-psk", &salt).unwrap();
        assert_eq!(
            receiver.open(sealed.clone(), b"header").unwrap(),
            b"payload"
        );
        let mut wrong = Cipher::new(b"snell-test-psk", &salt).unwrap();
        assert!(wrong.open(sealed, b"wrong").is_err());
        sender.counter = u64::MAX - 1;
        assert!(sender.seal(b"last", b"").is_ok());
        assert!(sender.seal(b"no-reuse", b"").is_err());
    }
}
