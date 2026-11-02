//! AEAD 数据通道。线格式：`opcode|key_id, peer_id[3], packet_id[4], tag[16], ciphertext`。

use crate::{wire::Opcode, wrap::ReplayWindow};
use kerlico_core::{Error, Result};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

/// 上游 `ping_string`：数据通道保活负载。
pub(crate) const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
const HEADER: usize = 8;
const TAG: usize = 16;
/// 接近 32 位序号上限时发起换钥，留足余量。
const REKEY_AT: u32 = 0xff00_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}
impl DataCipher {
    pub const ALL: [Self; 3] = [Self::Aes256Gcm, Self::Aes128Gcm, Self::Chacha20Poly1305];
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Some(Self::Aes128Gcm),
            "AES-256-GCM" => Some(Self::Aes256Gcm),
            "CHACHA20-POLY1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Chacha20Poly1305 => "CHACHA20-POLY1305",
        }
    }
    pub fn key_bits(self) -> usize {
        self.algorithm().key_len() * 8
    }
    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::Chacha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
    fn key(self, material: &[u8]) -> Result<LessSafeKey> {
        let unbound = UnboundKey::new(self.algorithm(), &material[..self.algorithm().key_len()])
            .map_err(|_| Error::Protocol("OpenVPN 数据通道密钥不合法"))?;
        Ok(LessSafeKey::new(unbound))
    }
}

pub(crate) struct SealKey {
    key: LessSafeKey,
    implicit_iv: [u8; 8],
    header: [u8; 4],
    next: u32,
}
impl SealKey {
    pub fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        if self.next == u32::MAX {
            return Err(Error::Protocol("OpenVPN 数据通道序号耗尽"));
        }
        let id = self.next.to_be_bytes();
        self.next += 1;
        let mut wire = Vec::with_capacity(HEADER + TAG + plain.len());
        wire.extend_from_slice(&self.header);
        wire.extend_from_slice(&id);
        let mut aad = [0; HEADER];
        aad.copy_from_slice(&wire);
        wire.extend_from_slice(&[0; TAG]);
        wire.extend_from_slice(plain);
        let tag = self
            .key
            .seal_in_place_separate_tag(
                nonce(id, &self.implicit_iv),
                Aad::from(aad),
                &mut wire[HEADER + TAG..],
            )
            .map_err(|_| Error::Protocol("OpenVPN 数据包加密失败"))?;
        wire[HEADER..HEADER + TAG].copy_from_slice(tag.as_ref());
        Ok(wire)
    }
    pub fn needs_rekey(&self) -> bool {
        self.next >= REKEY_AT
    }
}

pub(crate) struct OpenKey {
    key: LessSafeKey,
    implicit_iv: [u8; 8],
    key_id: u8,
    replay: ReplayWindow,
}
impl OpenKey {
    pub fn key_id(&self) -> u8 {
        self.key_id
    }
    /// 认证失败或重放时返回 `None`；伪造包不影响会话。
    pub fn open(&mut self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() < HEADER + TAG {
            return None;
        }
        let (aad, rest) = wire.split_at(HEADER);
        let (tag, cipher) = rest.split_at(TAG);
        let id = [aad[4], aad[5], aad[6], aad[7]];
        let mut plain = Vec::with_capacity(cipher.len() + TAG);
        plain.extend_from_slice(cipher);
        plain.extend_from_slice(tag);
        self.key
            .open_in_place(nonce(id, &self.implicit_iv), Aad::from(aad), &mut plain)
            .ok()?;
        if !self.replay.accept(u32::from_be_bytes(id)) {
            return None;
        }
        plain.truncate(cipher.len());
        Some(plain)
    }
}
fn nonce(id: [u8; 4], implicit_iv: &[u8; 8]) -> Nonce {
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&id);
    bytes[4..].copy_from_slice(implicit_iv);
    Nonce::assume_unique_for_key(bytes)
}

/// `key2` 为两组 `cipher[64] + hmac[64]`；客户端以第一组发送、第二组接收，
/// AEAD 模式下 hmac 段的前 8 字节是隐式 IV。
pub(crate) fn data_keys(
    cipher: DataCipher,
    key2: &[u8; 256],
    key_id: u8,
    peer_id: u32,
) -> Result<(SealKey, OpenKey)> {
    let part = |index: usize| {
        let group = &key2[index * 128..index * 128 + 128];
        let mut implicit_iv = [0; 8];
        implicit_iv.copy_from_slice(&group[64..72]);
        (&group[..64], implicit_iv)
    };
    let (seal_material, seal_iv) = part(0);
    let (open_material, open_iv) = part(1);
    let id = peer_id.to_be_bytes();
    Ok((
        SealKey {
            key: cipher.key(seal_material)?,
            implicit_iv: seal_iv,
            header: [Opcode::DataV2.byte(key_id), id[1], id[2], id[3]],
            next: 1,
        },
        OpenKey {
            key: cipher.key(open_material)?,
            implicit_iv: open_iv,
            key_id,
            replay: ReplayWindow::default(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key2() -> [u8; 256] {
        std::array::from_fn(|index| index as u8)
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// 向量按上游 `openvpn_encrypt_aead` 的 IV 与 AD 构造，用 Python `cryptography` 独立计算。
    #[test]
    fn data_v2_packets_match_independent_vectors() {
        for (cipher, expected) in [
            (DataCipher::Aes128Gcm, DATA_AES128),
            (DataCipher::Aes256Gcm, DATA_AES256),
            (DataCipher::Chacha20Poly1305, DATA_CHACHA),
        ] {
            let (mut seal, _) = data_keys(cipher, &key2(), 2, 0x0a0b0c).unwrap();
            assert_eq!(hex(&seal.seal(b"ip packet").unwrap()), expected);
        }
    }

    #[test]
    fn sealed_packet_opens_only_with_the_peer_direction_and_only_once() {
        let mut swapped = key2();
        let (first, second) = swapped.split_at_mut(128);
        first.swap_with_slice(second);
        let (mut seal, mut own) = data_keys(DataCipher::Aes256Gcm, &key2(), 1, 7).unwrap();
        let (_, mut peer) = data_keys(DataCipher::Aes256Gcm, &swapped, 1, 7).unwrap();
        let wire = seal.seal(&PING).unwrap();
        assert_eq!(wire[0], Opcode::DataV2.byte(1));
        assert_eq!(&wire[1..8], &[0, 0, 7, 0, 0, 0, 1]);
        assert!(own.open(&wire).is_none());
        assert_eq!(peer.open(&wire).unwrap(), PING);
        assert!(peer.open(&wire).is_none());
        let mut tampered = seal.seal(b"x").unwrap();
        tampered[1] ^= 1;
        assert!(peer.open(&tampered).is_none());
        assert!(peer.open(&[0; 10]).is_none());
    }

    const DATA_AES128: &str = "4a0a0b0c00000001c40c840a1e7b65332007d17985899f13bb73dc97bdb051f5f6";
    const DATA_AES256: &str = "4a0a0b0c00000001fcdd42a89384d32367bd10c9b972a26ca2bb5bcd0ad5cdac61";
    const DATA_CHACHA: &str = "4a0a0b0c00000001262193134e752898e67d3b25938e587967f412b492cf085be7";
}
