//! VMess AEAD 密钥派生、认证标识和带独立计数器的记录。
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::{Aes128Gcm, aead::AeadInPlace};
use chacha20poly1305::ChaCha20Poly1305;
use md5::Md5;
use sha2::{Digest, Sha256};
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::io;
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "VMess 报文认证或格式不合法")
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    Aes,
    ChaCha,
}
impl Cipher {
    pub fn parse(name: &str) -> io::Result<Self> {
        match name {
            "aes-128-gcm" => Ok(Self::Aes),
            "chacha20-poly1305" => Ok(Self::ChaCha),
            "auto" => Ok(Self::Aes),
            _ => Err(invalid()),
        }
    }
    pub fn from_wire(value: u8) -> io::Result<Self> {
        match value {
            3 => Ok(Self::Aes),
            4 => Ok(Self::ChaCha),
            _ => Err(invalid()),
        }
    }
    pub fn wire(self) -> u8 {
        if self == Self::Aes { 3 } else { 4 }
    }
}
pub(crate) fn md5(bytes: &[u8]) -> [u8; 16] {
    Md5::digest(bytes).into()
}
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn command_key(uuid: &[u8; 16]) -> Zeroizing<[u8; 16]> {
    let mut material = Zeroizing::new(uuid.to_vec());
    material.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    Zeroizing::new(md5(&material))
}
fn nested(path: &[&[u8]], bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let Some((key, prefix)) = path.split_last() else {
        return Zeroizing::new(sha256(bytes));
    };
    let mut block = Zeroizing::new([0u8; 64]);
    if key.len() > 64 {
        block[..32].copy_from_slice(&*nested(prefix, key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Zeroizing::new(Vec::with_capacity(64 + bytes.len()));
    inner.extend(block.iter().map(|v| v ^ 0x36));
    inner.extend_from_slice(bytes);
    let hash = nested(prefix, &inner);
    let mut outer = Zeroizing::new(Vec::with_capacity(96));
    outer.extend(block.iter().map(|v| v ^ 0x5c));
    outer.extend_from_slice(&*hash);
    nested(prefix, &outer)
}
pub(crate) fn kdf(key: &[u8], path: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut all = vec![b"VMess AEAD KDF".as_slice()];
    all.extend_from_slice(path);
    nested(&all, key)
}
pub(crate) fn auth_id(key: &[u8; 16], timestamp: u64, random: [u8; 4]) -> [u8; 16] {
    let derived = kdf(key, &[b"AES Auth ID Encryption"]);
    let mut out = [0; 16];
    out[..8].copy_from_slice(&timestamp.to_be_bytes());
    out[8..12].copy_from_slice(&random);
    let crc = crc32fast::hash(&out[..12]);
    out[12..].copy_from_slice(&crc.to_be_bytes());
    aes::Aes128::new_from_slice(&derived[..16])
        .unwrap()
        .encrypt_block((&mut out).into());
    out
}
pub(crate) fn decode_auth(key: &[u8; 16], auth: &[u8; 16]) -> io::Result<u64> {
    let derived = kdf(key, &[b"AES Auth ID Encryption"]);
    let mut bytes = Zeroizing::new(*auth);
    aes::Aes128::new_from_slice(&derived[..16])
        .unwrap()
        .decrypt_block((&mut *bytes).into());
    if crc32fast::hash(&bytes[..12]).to_be_bytes() != bytes[12..] {
        return Err(invalid());
    }
    Ok(u64::from_be_bytes(bytes[..8].try_into().unwrap()))
}
enum Aead {
    Aes(Box<Aes128Gcm>),
    ChaCha(ChaCha20Poly1305),
}
impl Aead {
    fn new(cipher: Cipher, key: &[u8; 16]) -> Self {
        match cipher {
            Cipher::Aes => Self::Aes(Box::new(Aes128Gcm::new_from_slice(key).unwrap())),
            Cipher::ChaCha => {
                let first = Zeroizing::new(md5(key));
                let second = Zeroizing::new(md5(&*first));
                let mut full = Zeroizing::new([0; 32]);
                full[..16].copy_from_slice(&*first);
                full[16..].copy_from_slice(&*second);
                Self::ChaCha(ChaCha20Poly1305::new_from_slice(&*full).unwrap())
            }
        }
    }
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], bytes: &mut Vec<u8>) -> io::Result<()> {
        let result = match self {
            Self::Aes(c) => c.encrypt_in_place(nonce.into(), aad, bytes),
            Self::ChaCha(c) => c.encrypt_in_place(nonce.into(), aad, bytes),
        };
        result.map_err(|_| {
            bytes.zeroize();
            invalid()
        })
    }
    fn open(&self, nonce: &[u8; 12], aad: &[u8], bytes: &mut Vec<u8>) -> io::Result<()> {
        let result = match self {
            Self::Aes(c) => c.decrypt_in_place(nonce.into(), aad, bytes),
            Self::ChaCha(c) => c.decrypt_in_place(nonce.into(), aad, bytes),
        };
        result.map_err(|_| {
            bytes.zeroize();
            invalid()
        })
    }
}
pub(crate) fn header_seal(
    key: &[u8],
    iv: &[u8],
    kp: &[&[u8]],
    np: &[&[u8]],
    aad: &[u8],
    bytes: &mut Vec<u8>,
) -> io::Result<()> {
    let derived = kdf(key, kp);
    let nonce = kdf(iv, np);
    Aead::new(Cipher::Aes, derived[..16].try_into().unwrap()).seal(
        nonce[..12].try_into().unwrap(),
        aad,
        bytes,
    )
}
pub(crate) fn header_open(
    key: &[u8],
    iv: &[u8],
    kp: &[&[u8]],
    np: &[&[u8]],
    aad: &[u8],
    bytes: &mut Vec<u8>,
) -> io::Result<()> {
    let derived = kdf(key, kp);
    let nonce = kdf(iv, np);
    Aead::new(Cipher::Aes, derived[..16].try_into().unwrap()).open(
        nonce[..12].try_into().unwrap(),
        aad,
        bytes,
    )
}
struct Counter {
    aead: Aead,
    iv: Zeroizing<[u8; 12]>,
    next: Option<u16>,
}
impl Counter {
    fn new(cipher: Cipher, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            aead: Aead::new(cipher, key),
            iv: Zeroizing::new(iv[..12].try_into().unwrap()),
            next: Some(0),
        }
    }
    fn nonce(&mut self) -> io::Result<[u8; 12]> {
        let n = self.next.ok_or_else(invalid)?;
        self.next = n.checked_add(1);
        self.iv[..2].copy_from_slice(&n.to_be_bytes());
        Ok(*self.iv)
    }
    fn seal(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.nonce()?;
        self.aead.seal(&nonce, &[], bytes)
    }
    fn open(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.nonce()?;
        self.aead.open(&nonce, &[], bytes)
    }
}
pub(crate) const MAX_DATAGRAM: usize = 65_456;
pub(crate) struct Records {
    body: Counter,
    length: Option<Counter>,
    shake: Shake128Reader,
    mask: bool,
    padding: bool,
}
impl Records {
    pub fn new(
        cipher: Cipher,
        key: &[u8; 16],
        iv: &[u8; 16],
        auth_keys: Option<(&[u8; 16], &[u8; 16])>,
        flags: u8,
    ) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv);
        let length = auth_keys.map(|(key, iv)| {
            let key = kdf(key, &[b"auth_len"]);
            Counter::new(cipher, key[..16].try_into().unwrap(), iv)
        });
        Self {
            body: Counter::new(cipher, key, iv),
            length,
            shake: shake.finalize_xof(),
            mask: flags & 4 != 0,
            padding: flags & 8 != 0,
        }
    }
    pub fn size_bytes(&self) -> usize {
        if self.length.is_some() { 18 } else { 2 }
    }
    fn next(&mut self) -> u16 {
        let mut b = [0; 2];
        self.shake.read(&mut b);
        u16::from_be_bytes(b)
    }
    fn padding(&mut self) -> usize {
        if self.padding {
            (self.next() % 64) as usize
        } else {
            0
        }
    }
    pub fn seal(&mut self, plain: &[u8]) -> io::Result<Vec<u8>> {
        if plain.len() > MAX_DATAGRAM {
            return Err(invalid());
        }
        let padding = self.padding();
        let size = plain.len() + 16 + padding;
        let mut prefix = if let Some(length) = &mut self.length {
            let mut b = ((size - 16) as u16).to_be_bytes().to_vec();
            length.seal(&mut b)?;
            b
        } else {
            let mask = if self.mask { self.next() } else { 0 };
            ((size as u16) ^ mask).to_be_bytes().to_vec()
        };
        let mut body = Zeroizing::new(plain.to_vec());
        self.body.seal(&mut body)?;
        prefix.extend_from_slice(&body);
        let start = prefix.len();
        prefix.resize(start + padding, 0);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut prefix[start..]);
        Ok(prefix)
    }
    pub fn length(&mut self, mut bytes: Vec<u8>) -> io::Result<(usize, usize)> {
        let padding = self.padding();
        let n = if let Some(length) = &mut self.length {
            length.open(&mut bytes)?;
            u16::from_be_bytes(bytes.as_slice().try_into().map_err(|_| invalid())?) as usize + 16
        } else {
            let mask = if self.mask { self.next() } else { 0 };
            (u16::from_be_bytes(bytes.as_slice().try_into().map_err(|_| invalid())?) ^ mask)
                as usize
        };
        if !(16 + padding..=65535).contains(&n) {
            return Err(invalid());
        }
        Ok((n, padding))
    }
    pub fn open(&mut self, mut bytes: Vec<u8>, padding: usize) -> io::Result<Vec<u8>> {
        if padding > bytes.len() {
            return Err(invalid());
        }
        bytes.truncate(bytes.len() - padding);
        self.body.open(&mut bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn records_variants_authentication_and_counter_exhaustion() {
        for cipher in [Cipher::Aes, Cipher::ChaCha] {
            for flags in [1, 5, 13, 17, 21, 29] {
                let key = [1; 16];
                let iv = [2; 16];
                let auth = (flags & 16 != 0).then_some((&key, &iv));
                let mut w = Records::new(cipher, &key, &iv, auth, flags);
                let mut r = Records::new(cipher, &key, &iv, auth, flags);
                for size in [0, 1, 1200, 12000, MAX_DATAGRAM] {
                    let data = vec![7; size];
                    let wire = w.seal(&data).unwrap();
                    let n = r.size_bytes();
                    let (size, padding) = r.length(wire[..n].to_vec()).unwrap();
                    assert_eq!(wire.len(), n + size);
                    assert_eq!(r.open(wire[n..].to_vec(), padding).unwrap(), data);
                }
                let mut bad = w.seal(b"payload").unwrap();
                let n = r.size_bytes();
                let (_, padding) = r.length(bad[..n].to_vec()).unwrap();
                bad[n] ^= 1;
                assert!(r.open(bad[n..].to_vec(), padding).is_err());
            }
        }
        let mut counter = Counter::new(Cipher::Aes, &[3; 16], &[4; 16]);
        counter.next = Some(u16::MAX);
        assert!(counter.seal(&mut vec![1]).is_ok());
        assert!(counter.seal(&mut vec![1]).is_err());
    }
    #[test]
    fn auth_id_time_binding_and_header_tag() {
        let key = command_key(&[5; 16]);
        let auth = auth_id(&key, 12345, [1, 2, 3, 4]);
        assert_eq!(decode_auth(&key, &auth).unwrap(), 12345);
        let mut bad = auth;
        bad[2] ^= 1;
        assert!(decode_auth(&key, &bad).is_err());
        let mut b = b"header".to_vec();
        header_seal(&*key, &*key, &[b"key"], &[b"nonce"], &auth, &mut b).unwrap();
        header_open(&*key, &*key, &[b"key"], &[b"nonce"], &auth, &mut b).unwrap();
        assert_eq!(b, b"header");
    }
}

#[cfg(test)]
mod vectors {
    use super::*;
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn fixed_go_vectors_bind_kdf_auth_id_and_both_record_ciphers() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/vmess-vectors.json")).unwrap();
        let id = uuid::Uuid::parse_str(vectors["id"].as_str().unwrap()).unwrap();
        let key = command_key(id.as_bytes());
        assert_eq!(
            key.as_slice(),
            unhex(vectors["commandKey"].as_str().unwrap())
        );
        assert_eq!(
            auth_id(&key, 1700000000, [0x33; 4]).as_slice(),
            unhex(vectors["authId"].as_str().unwrap())
        );
        for case in vectors["kdf"].as_array().unwrap() {
            let path: Vec<Vec<u8>> = case["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| unhex(v.as_str().unwrap()))
                .collect();
            let refs: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
            assert_eq!(
                kdf(&*key, &refs).as_slice(),
                unhex(case["output"].as_str().unwrap())
            );
        }
        for case in vectors["records"].as_array().unwrap() {
            let key: [u8; 16] = unhex(case["key"].as_str().unwrap()).try_into().unwrap();
            let iv: [u8; 16] = unhex(case["iv"].as_str().unwrap()).try_into().unwrap();
            let cipher = Cipher::parse(case["method"].as_str().unwrap()).unwrap();
            let auth = case["authenticatedLength"]
                .as_bool()
                .unwrap()
                .then_some((&key, &iv));
            let flags = 13 | if auth.is_some() { 16 } else { 0 };
            let mut writer = Records::new(cipher, &key, &iv, auth, flags);
            let mut reader = Records::new(cipher, &key, &iv, auth, flags);
            for chunk in case["chunks"].as_array().unwrap() {
                let payload = unhex(chunk["payload"].as_str().unwrap());
                let padding = chunk["padding"].as_u64().unwrap() as usize;
                let mut actual = writer.seal(&payload).unwrap();
                let end = actual.len();
                actual[end - padding..].fill(0);
                assert_eq!(actual, unhex(chunk["wire"].as_str().unwrap()));
                let size = reader.size_bytes();
                let (_, pad) = reader.length(actual[..size].to_vec()).unwrap();
                assert_eq!(reader.open(actual[size..].to_vec(), pad).unwrap(), payload);
            }
        }
    }
}
