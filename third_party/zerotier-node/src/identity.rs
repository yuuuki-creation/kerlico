// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/Identity.hpp, node/Identity.cpp,
// node/ECC.hpp, node/ECC.cpp (key agreement and signature composition only; the curve
// arithmetic comes from the x25519-dalek and ed25519-dalek crates).

use crate::address::Address;
use crate::reader::Reader;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use salsa20::Salsa20;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha384, Sha512};
use std::fmt;
use zeroize::Zeroizing;

const POW_FIRST_BYTE_LESS_THAN: u8 = 17;
const POW_MEMORY: usize = 2_097_152;
pub(crate) const PUBLIC_LEN: usize = 64;
pub(crate) const SECRET_LEN: usize = 64;
pub(crate) const SIGNATURE_LEN: usize = 96;
const SHA512_LEN: usize = 64;

#[derive(Debug, Eq, PartialEq)]
pub enum IdentityError {
    Format,
    SecretRequired,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Format => "invalid ZeroTier identity format",
            Self::SecretRequired => "ZeroTier identity has no secret key",
        })
    }
}

impl std::error::Error for IdentityError {}

/// A node identity: a 40-bit address bound to a Curve25519 key and an Ed25519 key by a
/// memory-hard proof of work.
#[derive(Clone)]
pub struct Identity {
    address: Address,
    public: [u8; PUBLIC_LEN],
    secret: Option<Zeroizing<[u8; SECRET_LEN]>>,
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.public == other.public
    }
}

impl Eq for Identity {}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

fn memory_hard_hash(public: &[u8; PUBLIC_LEN]) -> [u8; SHA512_LEN] {
    let mut digest: [u8; SHA512_LEN] = Sha512::digest(public).into();
    let mut memory = vec![0u8; POW_MEMORY];
    let key: [u8; 32] = digest[..32].try_into().expect("digest prefix is 32 bytes");
    let iv: [u8; 8] = digest[32..40].try_into().expect("digest range is 8 bytes");
    let mut cipher = Salsa20::new(&key.into(), &iv.into());

    // CBC-like chaining defeats Salsa20's random seekability, which makes the fill sequential.
    cipher.apply_keystream(&mut memory[..64]);
    for start in (64..POW_MEMORY).step_by(64) {
        memory.copy_within(start - 64..start, start);
        cipher.apply_keystream(&mut memory[start..start + 64]);
    }

    let words = POW_MEMORY / 8;
    let mut position = 0;
    while position < words {
        let first = read_word(&memory, position) % 8;
        let second = read_word(&memory, position + 1) % words as u64;
        position += 2;
        let digest_at = first as usize * 8;
        let memory_at = second as usize * 8;
        let held: [u8; 8] = memory[memory_at..memory_at + 8]
            .try_into()
            .expect("word range is 8 bytes");
        memory[memory_at..memory_at + 8].copy_from_slice(&digest[digest_at..digest_at + 8]);
        digest[digest_at..digest_at + 8].copy_from_slice(&held);
        cipher.apply_keystream(&mut digest);
    }
    digest
}

fn read_word(memory: &[u8], index: usize) -> u64 {
    let start = index * 8;
    u64::from_be_bytes(
        memory[start..start + 8]
            .try_into()
            .expect("word range is 8 bytes"),
    )
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return None;
    }
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

impl Identity {
    /// Searches for a key pair that satisfies the proof of work. Takes seconds and blocks.
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        rand::rngs::OsRng.fill_bytes(&mut secret[..]);
        let seed: [u8; 32] = secret[32..].try_into().expect("seed range is 32 bytes");
        let verifying = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let mut public = [0u8; PUBLIC_LEN];
        public[32..].copy_from_slice(&verifying);
        loop {
            rand::rngs::OsRng.fill_bytes(&mut secret[..32]);
            let exchange: [u8; 32] = secret[..32].try_into().expect("key range is 32 bytes");
            public[..32].copy_from_slice(&x25519_dalek::x25519(
                exchange,
                x25519_dalek::X25519_BASEPOINT_BYTES,
            ));
            let digest = memory_hard_hash(&public);
            let address = address_from_digest(&digest);
            if digest[0] < POW_FIRST_BYTE_LESS_THAN && !address.is_reserved() {
                return Self {
                    address,
                    public,
                    secret: Some(secret),
                };
            }
        }
    }

    /// A key holder without a node address, for world update signatures.
    pub(crate) fn with_public_key(public: [u8; PUBLIC_LEN]) -> Self {
        Self {
            address: Address::new(0),
            public,
            secret: None,
        }
    }

    /// Checks that the address really derives from the public key. Blocks for one hash.
    pub fn locally_validate(&self) -> bool {
        if self.address.is_reserved() {
            return false;
        }
        let digest = memory_hard_hash(&self.public);
        digest[0] < POW_FIRST_BYTE_LESS_THAN && address_from_digest(&digest) == self.address
    }

    pub fn address(&self) -> Address {
        self.address
    }
    pub fn has_secret(&self) -> bool {
        self.secret.is_some()
    }

    /// Parses `address:0:public[:secret]`, the format of `identity.public` and `identity.secret`.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        let mut fields = value.trim().split(':');
        let address = fields.next().ok_or(IdentityError::Format)?;
        let kind = fields.next().ok_or(IdentityError::Format)?;
        let public = fields.next().ok_or(IdentityError::Format)?;
        let secret = fields.next();
        if kind != "0" || fields.next().is_some() || address.len() != 10 {
            return Err(IdentityError::Format);
        }
        let address = u64::from_str_radix(address, 16).map_err(|_| IdentityError::Format)?;
        let address = Address::new(address);
        if address.is_reserved() {
            return Err(IdentityError::Format);
        }
        let public = decode_hex::<PUBLIC_LEN>(public).ok_or(IdentityError::Format)?;
        let secret = match secret {
            Some(secret) => Some(Zeroizing::new(
                decode_hex::<SECRET_LEN>(secret).ok_or(IdentityError::Format)?,
            )),
            None => None,
        };
        Ok(Self {
            address,
            public,
            secret,
        })
    }

    pub fn to_public_string(&self) -> String {
        format!("{}:0:{}", self.address, encode_hex(&self.public))
    }

    pub fn to_secret_string(&self) -> Result<Zeroizing<String>, IdentityError> {
        let secret = self.secret.as_ref().ok_or(IdentityError::SecretRequired)?;
        Ok(Zeroizing::new(format!(
            "{}:{}",
            self.to_public_string(),
            encode_hex(&secret[..])
        )))
    }

    pub(crate) fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.address.to_bytes());
        output.push(0);
        output.extend_from_slice(&self.public);
        output.push(0);
    }

    pub(crate) fn deserialize(reader: &mut Reader<'_>) -> Option<Self> {
        let address = Address::from_bytes(&reader.array()?);
        if reader.u8()? != 0 {
            return None;
        }
        let public = reader.array()?;
        let secret_length = usize::from(reader.u8()?);
        if secret_length != 0 && secret_length != SECRET_LEN {
            return None;
        }
        let secret = if secret_length == 0 {
            None
        } else {
            Some(Zeroizing::new(reader.array()?))
        };
        Some(Self {
            address,
            public,
            secret,
        })
    }

    /// SHA-384 over address and public keys, embedded in certificates of membership.
    pub(crate) fn public_key_hash(&self) -> [u8; 48] {
        let mut hash = Sha384::new();
        hash.update(self.address.to_bytes());
        hash.update(self.public);
        hash.finalize().into()
    }

    /// Curve25519 agreement hashed with SHA-512. Packets use the first 32 bytes.
    pub(crate) fn agree(&self, other: &Self) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        let secret = self.secret.as_ref().ok_or(IdentityError::SecretRequired)?;
        let exchange: [u8; 32] = secret[..32].try_into().expect("key range is 32 bytes");
        let theirs: [u8; 32] = other.public[..32]
            .try_into()
            .expect("key range is 32 bytes");
        let shared = Zeroizing::new(x25519_dalek::x25519(exchange, theirs));
        let digest = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(&shared[..])));
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&digest[..32]);
        Ok(key)
    }

    /// Ed25519 over the first 32 bytes of SHA-512(message), followed by those 32 bytes.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], IdentityError> {
        let secret = self.secret.as_ref().ok_or(IdentityError::SecretRequired)?;
        let seed: [u8; 32] = secret[32..].try_into().expect("seed range is 32 bytes");
        let digest: [u8; 64] = Sha512::digest(message).into();
        let signature = SigningKey::from_bytes(&seed).sign(&digest[..32]);
        let mut output = [0u8; SIGNATURE_LEN];
        output[..64].copy_from_slice(&signature.to_bytes());
        output[64..].copy_from_slice(&digest[..32]);
        Ok(output)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = <&[u8; SIGNATURE_LEN]>::try_from(signature) else {
            return false;
        };
        let digest: [u8; 64] = Sha512::digest(message).into();
        if signature[64..] != digest[..32] {
            return false;
        }
        let verifying: [u8; 32] = self.public[32..].try_into().expect("key range is 32 bytes");
        let Ok(verifying) = VerifyingKey::from_bytes(&verifying) else {
            return false;
        };
        let ed25519: [u8; 64] = signature[..64].try_into().expect("signature prefix");
        verifying
            .verify(&digest[..32], &Signature::from_bytes(&ed25519))
            .is_ok()
    }
}

fn address_from_digest(digest: &[u8; SHA512_LEN]) -> Address {
    let bytes: [u8; 5] = digest[59..].try_into().expect("address range is 5 bytes");
    Address::from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced by `zerotier-idtool generate` and `zerotier-idtool sign` from ZeroTierOne 1.14.2.
    const SECRET: &str = "6c386dc869:0:6b92e4ccfd2426e77d67f1e4d88ec6947f207054f6f8e71db4cd423be2031a4a30b73c8cf406e630ee51ac777f2af39c8f85a87a0d29c760ab7c3abc45db7a8e:0f48db623afef19c59353992b69aa426cfbe4146a362f19334f4461ac7dc042f3f98bca50ba4dca9c49a21a49fb664ca5d671af47a49fdaed668f746c2e94ff7";
    const MESSAGE: &[u8] = b"hello-kerlico";
    const SIGNATURE: &str = "892058559b096a4a405c24587668087857df21e6a3db72e019c9211b3db17b02800c06911be0001ca95277f302377bbf54ba03307b5b54c1d7ed39a756fbf107ad796e63ad5d5916d7d79f89aae27e4fed196c14667c994e079f694412bb2be8";

    #[test]
    fn upstream_identity_passes_proof_of_work_and_tampering_fails() {
        let identity = Identity::parse(SECRET).unwrap();
        assert!(identity.locally_validate());
        assert_eq!(identity.to_secret_string().unwrap().as_str(), SECRET);
        assert_eq!(identity.address().to_string(), "6c386dc869");

        let mut forged = identity.clone();
        forged.address = Address::new(identity.address().value() ^ 1);
        assert!(!forged.locally_validate());
    }

    #[test]
    fn signature_matches_upstream_tool_byte_for_byte() {
        let identity = Identity::parse(SECRET).unwrap();
        let signature = identity.sign(MESSAGE).unwrap();
        assert_eq!(encode_hex(&signature), SIGNATURE);
        assert!(identity.verify(MESSAGE, &signature));
        assert!(!identity.verify(b"other", &signature));
        let mut tampered = signature;
        tampered[0] ^= 1;
        assert!(!identity.verify(MESSAGE, &tampered));
    }

    #[test]
    fn identity_derives_public_keys_from_secret() {
        let identity = Identity::parse(SECRET).unwrap();
        let secret = identity.secret.as_ref().unwrap();
        let exchange: [u8; 32] = secret[..32].try_into().unwrap();
        assert_eq!(
            x25519_dalek::x25519(exchange, x25519_dalek::X25519_BASEPOINT_BYTES),
            identity.public[..32]
        );
        let seed: [u8; 32] = secret[32..].try_into().unwrap();
        assert_eq!(
            SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            identity.public[32..]
        );
    }

    #[test]
    fn binary_form_round_trips_and_rejects_unknown_type() {
        let identity = Identity::parse(SECRET).unwrap();
        let mut bytes = Vec::new();
        identity.serialize(&mut bytes);
        assert_eq!(bytes.len(), 5 + 1 + 64 + 1);
        let mut reader = Reader::new(&bytes);
        let parsed = Identity::deserialize(&mut reader).unwrap();
        assert_eq!(parsed, identity);
        assert!(!parsed.has_secret());
        assert_eq!(reader.remaining(), 0);

        bytes[5] = 1;
        assert!(Identity::deserialize(&mut Reader::new(&bytes)).is_none());
    }

    #[test]
    fn parse_rejects_malformed_identities() {
        for value in [
            "",
            "6c386dc869:1:00",
            "ff00000001:0:6b92",
            "6c386dc869:0:zz",
            &format!("{SECRET}:extra"),
        ] {
            assert_eq!(Identity::parse(value).unwrap_err(), IdentityError::Format);
        }
    }

    #[test]
    fn agreement_is_symmetric_between_generated_and_upstream_identity() {
        let ours = Identity::generate();
        assert!(ours.locally_validate());
        let theirs = Identity::parse(SECRET).unwrap();
        assert_eq!(*ours.agree(&theirs).unwrap(), *theirs.agree(&ours).unwrap());
    }
}
