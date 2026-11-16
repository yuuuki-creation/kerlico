//! SIP023: peel one identity header without decrypting the payload.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

pub const BLOCK: usize = 16;
pub type Identity = [u8; BLOCK];

pub fn hash(key: &[u8]) -> Identity {
    blake3::hash(key).as_bytes()[..BLOCK]
        .try_into()
        .expect("BLAKE3 output length")
}

pub fn tcp_identity(key: &[u8], head: &[u8]) -> Option<Identity> {
    let len = key.len();
    let salt = head.get(..len)?;
    let mut input = [0; 64];
    input.get_mut(..len)?.copy_from_slice(key);
    input.get_mut(len..2 * len)?.copy_from_slice(salt);
    let subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &input[..2 * len]);
    let mut identity = head.get(len..len + BLOCK)?.try_into().ok()?;
    transform(&subkey[..len], &mut identity, false)?;
    Some(identity)
}

pub fn udp_identity(key: &[u8], head: &[u8]) -> Option<(Identity, Identity)> {
    let mut separate: Identity = head.get(..BLOCK)?.try_into().ok()?;
    let mut identity: Identity = head.get(BLOCK..2 * BLOCK)?.try_into().ok()?;
    transform(key, &mut separate, false)?;
    transform(key, &mut identity, false)?;
    for (byte, value) in identity.iter_mut().zip(separate) {
        *byte ^= value;
    }
    Some((identity, separate))
}

pub fn encrypt_header(key: &[u8], head: &mut Identity) -> Option<()> {
    transform(key, head, true)
}

fn transform(key: &[u8], block: &mut Identity, encrypt: bool) -> Option<()> {
    let block = aes::Block::from_mut_slice(block);
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).ok()?;
            if encrypt {
                cipher.encrypt_block(block);
            } else {
                cipher.decrypt_block(block);
            }
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).ok()?;
            if encrypt {
                cipher.encrypt_block(block);
            } else {
                cipher.decrypt_block(block);
            }
        }
        _ => return None,
    }
    Some(())
}
