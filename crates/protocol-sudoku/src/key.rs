use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use hkdf::Hkdf;
use kerlico_core::{Error, Result};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

pub(crate) struct Material {
    pub seed: Zeroizing<String>,
    pub user_hash: [u8; 8],
    pub fingerprint: [u8; 32],
}
impl Material {
    pub fn parse(key: &str) -> Result<Self> {
        let key = key.trim();
        if key.is_empty() || key.len() > 4096 {
            return Err(Error::Config(
                "Sudoku seed凭据不能为空或超过4096字节".into(),
            ));
        }
        let decoded = unhex(key).map(Zeroizing::new);
        let user_digest = Sha256::digest(match decoded.as_ref() {
            Some(bytes) if !bytes.is_empty() => bytes.as_slice(),
            _ => key.as_bytes(),
        });
        let mut seed = None;
        if let Some(bytes) = decoded.as_ref() {
            if bytes.len() == 32 {
                let raw: [u8; 32] = bytes.as_slice().try_into().unwrap();
                // 固定参考实现优先把32字节hex解释为点，不能擅自改成必定是主标量。
                if let Some(point) = CompressedEdwardsY(raw).decompress() {
                    seed = Some(hex(point.compress().as_bytes()));
                } else if let Some(scalar) =
                    Option::<Scalar>::from(Scalar::from_canonical_bytes(raw))
                {
                    seed = Some(hex(curve25519_dalek::edwards::EdwardsPoint::mul_base(
                        &scalar,
                    )
                    .compress()
                    .as_bytes()));
                }
            } else if bytes.len() == 64 {
                let r = Option::<Scalar>::from(Scalar::from_canonical_bytes(
                    bytes[..32].try_into().unwrap(),
                ));
                let k = Option::<Scalar>::from(Scalar::from_canonical_bytes(
                    bytes[32..].try_into().unwrap(),
                ));
                if let (Some(r), Some(k)) = (r, k) {
                    seed = Some(hex(curve25519_dalek::edwards::EdwardsPoint::mul_base(
                        &(r + k),
                    )
                    .compress()
                    .as_bytes()));
                }
            }
        }
        let seed = Zeroizing::new(seed.unwrap_or_else(|| key.to_owned()));
        let mut domain = Sha256::new();
        domain.update(b"kerlico/sudoku/seed\0");
        domain.update(seed.as_bytes());
        Ok(Self {
            seed,
            user_hash: user_digest[..8].try_into().unwrap(),
            fingerprint: domain.finalize().into(),
        })
    }
}

pub(crate) struct Keys {
    pub c2s: Zeroizing<[u8; 32]>,
    pub s2c: Zeroizing<[u8; 32]>,
}
fn expand(hkdf: Hkdf<Sha256>, client_label: &[u8], server_label: &[u8]) -> Result<Keys> {
    let mut c2s = Zeroizing::new([0; 32]);
    let mut s2c = Zeroizing::new([0; 32]);
    hkdf.expand(client_label, &mut c2s[..])
        .map_err(|_| crate::invalid())?;
    hkdf.expand(server_label, &mut s2c[..])
        .map_err(|_| crate::invalid())?;
    Ok(Keys { c2s, s2c })
}
pub(crate) fn initial_keys(seed: &str) -> Result<Keys> {
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(seed.as_bytes())));
    expand(
        Hkdf::<Sha256>::from_prk(digest.as_ref()).map_err(|_| crate::invalid())?,
        b"sudoku-psk-c2s",
        b"sudoku-psk-s2c",
    )
}
pub(crate) fn session_keys(
    seed: &str,
    secret: &StaticSecret,
    peer: [u8; 32],
    nonce: [u8; 16],
) -> Result<Keys> {
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    if !shared.was_contributory() {
        return Err(crate::invalid());
    }
    let salt = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(seed.as_bytes())));
    let mut material = Zeroizing::new([0; 48]);
    material[..32].copy_from_slice(shared.as_bytes());
    material[32..].copy_from_slice(&nonce);
    expand(
        Hkdf::<Sha256>::new(Some(salt.as_ref()), material.as_ref()),
        b"sudoku-session-c2s",
        b"sudoku-session-s2c",
    )
}
pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::Protocol("Sudoku随机源不可用"))?;
    Ok(bytes)
}
pub(crate) fn exchange() -> Result<(StaticSecret, [u8; 32])> {
    let bytes = Zeroizing::new(random::<32>()?);
    let secret = StaticSecret::from(*bytes);
    let public = PublicKey::from(&secret).to_bytes();
    Ok((secret, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_public_aliases_share_real_authentication_fingerprint() {
        let scalar = (1u64..64)
            .map(Scalar::from)
            .find(|s| CompressedEdwardsY(s.to_bytes()).decompress().is_none())
            .unwrap();
        let point = curve25519_dalek::edwards::EdwardsPoint::mul_base(&scalar)
            .compress()
            .to_bytes();
        let master = Material::parse(&hex(&scalar.to_bytes())).unwrap();
        let public = Material::parse(&hex(&point)).unwrap();
        assert_eq!(master.fingerprint, public.fingerprint);
        for r in [Scalar::from(2u64), Scalar::from(5u64)] {
            let k = scalar - r;
            let mut split = [0; 64];
            split[..32].copy_from_slice(&r.to_bytes());
            split[32..].copy_from_slice(&k.to_bytes());
            let private = Material::parse(&hex(&split)).unwrap();
            assert_eq!(private.seed.as_str(), public.seed.as_str());
            assert_eq!(private.fingerprint, public.fingerprint);
            assert_ne!(private.user_hash, public.user_hash);
        }
        let identity_point = Material::parse(&format!("01{}", "00".repeat(31))).unwrap();
        assert_eq!(
            identity_point.seed.as_str(),
            format!("01{}", "00".repeat(31))
        );
    }
    #[test]
    fn directional_keys_and_low_order_rejection() {
        let material = Material::parse("synthetic-independent-sudoku-seed").unwrap();
        let initial = initial_keys(&material.seed).unwrap();
        assert_ne!(*initial.c2s, *initial.s2c);
        let (a, a_public) = exchange().unwrap();
        let (b, b_public) = exchange().unwrap();
        let nonce = random().unwrap();
        let left = session_keys(&material.seed, &a, b_public, nonce).unwrap();
        let right = session_keys(&material.seed, &b, a_public, nonce).unwrap();
        assert_eq!(*left.c2s, *right.c2s);
        assert_eq!(*left.s2c, *right.s2c);
        assert_ne!(*left.c2s, *left.s2c);
        assert!(session_keys(&material.seed, &a, [0; 32], nonce).is_err());
        let other = session_keys(&material.seed, &a, b_public, [7; 16]).unwrap();
        assert_ne!(*left.c2s, *other.c2s);
    }
}
