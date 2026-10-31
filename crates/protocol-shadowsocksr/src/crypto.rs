use crate::invalid;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as _};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use kerlico_core::{Error, Result};
use md5::{Digest, Md5};
use sha1::Sha1;
use shadowsocks::crypto::{CipherKind, v1::Cipher};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    Md5,
    Sha1,
}
pub(crate) fn digest(kind: Hash, data: &[u8]) -> Vec<u8> {
    match kind {
        Hash::Md5 => Md5::digest(data).to_vec(),
        Hash::Sha1 => Sha1::digest(data).to_vec(),
    }
}
pub(crate) fn mac(kind: Hash, key: &[u8], data: &[u8]) -> Vec<u8> {
    match kind {
        Hash::Md5 => {
            let mut value = <hmac::Hmac<Md5> as hmac::KeyInit>::new_from_slice(key)
                .expect("HMAC 接受任意长度 key");
            value.update(data);
            value.finalize().into_bytes().to_vec()
        }
        Hash::Sha1 => {
            let mut value = <hmac::Hmac<Sha1> as hmac::KeyInit>::new_from_slice(key)
                .expect("HMAC 接受任意长度 key");
            value.update(data);
            value.finalize().into_bytes().to_vec()
        }
    }
}
pub(crate) fn equal(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}
pub(crate) fn key(password: &[u8], length: usize) -> Vec<u8> {
    let mut output = vec![0; length];
    shadowsocks::crypto::v1::openssl_bytes_to_key(password, &mut output);
    output
}
pub(crate) fn aes_block(password: &[u8], block: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    if block.len() != 16 {
        return Err(invalid());
    }
    let key = key(password, 16);
    let cipher = aes::Aes128::new_from_slice(&key).map_err(|_| invalid())?;
    let mut data = aes::Block::default();
    data.copy_from_slice(block);
    if encrypt {
        cipher.encrypt_block(&mut data);
    } else {
        cipher.decrypt_block(&mut data);
    }
    Ok(data.to_vec())
}
pub(crate) fn random(length: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut data = vec![0; length];
    rand::thread_rng().fill_bytes(&mut data);
    data
}
pub(crate) fn adler(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Base(CipherKind),
    Rc4Md5Six,
    ChaChaLegacy,
    XChaCha,
    Salsa,
}
impl Method {
    pub(crate) fn parse(name: &str) -> Result<Self> {
        match name {
            "rc4-md5-6" => Ok(Self::Rc4Md5Six),
            "chacha20" => Ok(Self::ChaChaLegacy),
            "xchacha20" => Ok(Self::XChaCha),
            "salsa20" => Ok(Self::Salsa),
            _ => name
                .parse()
                .map(Self::Base)
                .map_err(|_| Error::Config("SSR cipher 不在本轮范围".into())),
        }
    }
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Base(CipherKind::NONE | CipherKind::SS_TABLE) => 16,
            Self::Base(kind) => kind.key_len(),
            Self::Rc4Md5Six => 16,
            _ => 32,
        }
    }
    pub(crate) fn iv_len(self) -> usize {
        match self {
            Self::Base(kind) => kind.iv_len(),
            Self::Rc4Md5Six => 6,
            Self::ChaChaLegacy | Self::Salsa => 8,
            Self::XChaCha => 24,
        }
    }
}
pub(crate) enum State {
    Base(Box<Cipher>),
    ChaCha(Box<chacha20::ChaCha20Legacy>),
    XChaCha(Box<chacha20::XChaCha20>),
    Salsa(Box<salsa20::Salsa20>),
}
impl State {
    pub(crate) fn new(method: Method, key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != method.key_len() || iv.len() != method.iv_len() {
            return Err(invalid());
        }
        Ok(match method {
            Method::Base(kind) => Self::Base(Box::new(Cipher::new(kind, key, iv))),
            Method::Rc4Md5Six => {
                let mut seed = key.to_vec();
                seed.extend_from_slice(iv);
                Self::Base(Box::new(Cipher::new(
                    CipherKind::RC4,
                    &Md5::digest(&seed),
                    &[],
                )))
            }
            Method::ChaChaLegacy => Self::ChaCha(Box::new(
                chacha20::ChaCha20Legacy::new_from_slices(key, iv).map_err(|_| invalid())?,
            )),
            Method::XChaCha => Self::XChaCha(Box::new(
                chacha20::XChaCha20::new_from_slices(key, iv).map_err(|_| invalid())?,
            )),
            Method::Salsa => Self::Salsa(Box::new(
                salsa20::Salsa20::new_from_slices(key, iv).map_err(|_| invalid())?,
            )),
        })
    }
    pub(crate) fn apply(&mut self, data: &mut [u8], encrypt: bool) -> Result<()> {
        match self {
            Self::Base(cipher) => {
                if encrypt {
                    cipher.encrypt_packet(data);
                } else if !cipher.decrypt_packet(data) {
                    return Err(invalid());
                }
            }
            Self::ChaCha(cipher) => cipher
                .try_apply_keystream(data)
                .map_err(|_| Error::ResourceLimit)?,
            Self::XChaCha(cipher) => cipher
                .try_apply_keystream(data)
                .map_err(|_| Error::ResourceLimit)?,
            Self::Salsa(cipher) => cipher
                .try_apply_keystream(data)
                .map_err(|_| Error::ResourceLimit)?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Deserialize)]
    struct Vectors {
        plain: Vec<u8>,
        records: Vec<Record>,
    }
    #[derive(serde::Deserialize)]
    struct Record {
        method: String,
        key: Vec<u8>,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
    }
    #[test]
    fn all_cipher_bytes_match_independent_native_vectors() {
        let vectors: Vectors =
            serde_json::from_str(include_str!("../tests/fixtures/cipher-vectors.json")).unwrap();
        assert_eq!(vectors.records.len(), crate::config::CIPHERS.len());
        for vector in vectors.records {
            let method = Method::parse(&vector.method).unwrap();
            let mut state = State::new(method, &vector.key, &vector.iv).unwrap();
            let mut encoded = vectors.plain.clone();
            for chunk in encoded.chunks_mut(17) {
                state.apply(chunk, true).unwrap();
            }
            assert_eq!(encoded, vector.ciphertext, "{} encode", vector.method);
            let mut state = State::new(method, &vector.key, &vector.iv).unwrap();
            for chunk in encoded.chunks_mut(19) {
                state.apply(chunk, false).unwrap();
            }
            assert_eq!(encoded, vectors.plain, "{} decode", vector.method);
        }
    }
}
