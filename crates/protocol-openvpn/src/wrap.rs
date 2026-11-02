//! 控制通道外层包装：无包装、`tls-auth`、`tls-crypt`，及共用的防重放窗口。

use crate::wire::SessionId;
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use kerlico_core::{Error, Result};
use ring::hmac;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const STATIC_KEY_BEGIN: &str = "-----BEGIN OpenVPN Static key V1-----";
const STATIC_KEY_END: &str = "-----END OpenVPN Static key V1-----";
const CRYPT_TAG: usize = 32;

/// 静态密钥文件中的两组 `cipher[64] + hmac[64]`。
pub(crate) struct StaticKey(Zeroizing<[u8; 256]>);
impl StaticKey {
    pub fn parse(text: &str) -> Result<Self> {
        let invalid = || Error::Config("OpenVPN 静态密钥不合法".into());
        let (_, body) = text.split_once(STATIC_KEY_BEGIN).ok_or_else(invalid)?;
        let (body, _) = body.split_once(STATIC_KEY_END).ok_or_else(invalid)?;
        let mut key = Zeroizing::new([0; 256]);
        let mut nibbles = body.bytes().filter(|byte| !byte.is_ascii_whitespace());
        for slot in key.iter_mut() {
            let high = nibbles.next().and_then(hex).ok_or_else(invalid)?;
            let low = nibbles.next().and_then(hex).ok_or_else(invalid)?;
            *slot = high << 4 | low;
        }
        if nibbles.next().is_some() {
            return Err(invalid());
        }
        Ok(Self(key))
    }
    fn cipher(&self, index: usize) -> &[u8] {
        &self.0[index * 128..index * 128 + 64]
    }
    fn hmac(&self, index: usize) -> &[u8] {
        &self.0[index * 128 + 64..index * 128 + 128]
    }
}
fn hex(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthDigest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}
impl AuthDigest {
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Some(Self::Sha1),
            "SHA256" | "SHA-256" => Some(Self::Sha256),
            "SHA384" | "SHA-384" => Some(Self::Sha384),
            "SHA512" | "SHA-512" => Some(Self::Sha512),
            _ => None,
        }
    }
    fn algorithm(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
    fn size(self) -> usize {
        self.algorithm().digest_algorithm().output_len()
    }
}

/// 不可变的包装密钥；每个 OpenVPN 会话由此派生独立的发送序号与防重放状态。
#[derive(Clone)]
pub(crate) enum WrapKeys {
    Plain,
    Auth {
        size: usize,
        send: hmac::Key,
        receive: hmac::Key,
    },
    Crypt {
        send_hmac: hmac::Key,
        receive_hmac: hmac::Key,
        send_cipher: Zeroizing<[u8; 32]>,
        receive_cipher: Zeroizing<[u8; 32]>,
    },
}
impl WrapKeys {
    /// `direction` 对应 `key-direction`；缺省时两方向共用第一组密钥。
    pub fn auth(key: &StaticKey, digest: AuthDigest, direction: Option<u8>) -> Self {
        let (send, receive) = match direction {
            None => (0, 0),
            Some(0) => (0, 1),
            Some(_) => (1, 0),
        };
        let algorithm = digest.algorithm();
        Self::Auth {
            size: digest.size(),
            send: hmac::Key::new(algorithm, &key.hmac(send)[..digest.size()]),
            receive: hmac::Key::new(algorithm, &key.hmac(receive)[..digest.size()]),
        }
    }
    /// `tls-crypt` 的客户端方向固定为上游 `KEY_DIRECTION_INVERSE`。
    pub fn crypt(key: &StaticKey) -> Self {
        Self::crypt_directed(key, 1, 0)
    }
    fn crypt_directed(key: &StaticKey, send: usize, receive: usize) -> Self {
        let cipher = |index| {
            let mut bytes = Zeroizing::new([0; 32]);
            bytes.copy_from_slice(&key.cipher(index)[..32]);
            bytes
        };
        let mac = |index| hmac::Key::new(hmac::HMAC_SHA256, &key.hmac(index)[..32]);
        Self::Crypt {
            send_hmac: mac(send),
            receive_hmac: mac(receive),
            send_cipher: cipher(send),
            receive_cipher: cipher(receive),
        }
    }
}

pub(crate) struct Unwrapped {
    pub header: u8,
    pub session: SessionId,
    pub body: Vec<u8>,
    /// 无包装时为空。
    pub replay: Option<ReplayStamp>,
}

pub(crate) struct ControlWrap {
    keys: WrapKeys,
    next_id: u32,
    replay: ControlReplay,
}
impl ControlWrap {
    pub fn new(keys: WrapKeys) -> Self {
        Self {
            keys,
            next_id: 1,
            replay: ControlReplay::default(),
        }
    }
    pub fn wrap(&mut self, header: u8, session: &SessionId, body: &[u8], time: u32) -> Vec<u8> {
        let mut wire = Vec::with_capacity(9 + 72 + body.len());
        wire.push(header);
        wire.extend_from_slice(session);
        let mut replay = [0; 8];
        replay[..4].copy_from_slice(&self.next_id.to_be_bytes());
        replay[4..].copy_from_slice(&time.to_be_bytes());
        match &self.keys {
            WrapKeys::Plain => {
                wire.extend_from_slice(body);
                return wire;
            }
            WrapKeys::Auth { send, .. } => {
                let tag = auth_tag(send, &replay, header, session, body);
                wire.extend_from_slice(tag.as_ref());
                wire.extend_from_slice(&replay);
                wire.extend_from_slice(body);
            }
            WrapKeys::Crypt {
                send_hmac,
                send_cipher,
                ..
            } => {
                let tag = crypt_tag(send_hmac, header, session, &replay, body);
                wire.extend_from_slice(&replay);
                wire.extend_from_slice(tag.as_ref());
                let start = wire.len();
                wire.extend_from_slice(body);
                apply_ctr(send_cipher, tag.as_ref(), &mut wire[start..]);
            }
        }
        self.next_id = self.next_id.wrapping_add(1);
        wire
    }
    /// 只校验认证。静态密钥下旧会话的包同样能通过，调用方确认包属于本会话后才用 [`Self::commit`] 推进窗口。
    pub fn unwrap(&self, wire: &[u8]) -> Result<Unwrapped> {
        let forged = || Error::Protocol("OpenVPN 控制包认证失败");
        let (&header, rest) = wire.split_first().ok_or_else(forged)?;
        let (session, rest) = rest.split_first_chunk::<8>().ok_or_else(forged)?;
        let (replay, body) = match &self.keys {
            WrapKeys::Plain => (None, rest.to_vec()),
            WrapKeys::Auth { size, receive, .. } => {
                if rest.len() < size + 8 {
                    return Err(forged());
                }
                let (tag, rest) = rest.split_at(*size);
                let (replay, body) = rest.split_at(8);
                let expected = auth_tag(receive, replay, header, session, body);
                if !bool::from(expected.as_ref().ct_eq(tag)) {
                    return Err(forged());
                }
                (Some(ReplayStamp::parse(replay)), body.to_vec())
            }
            WrapKeys::Crypt {
                receive_hmac,
                receive_cipher,
                ..
            } => {
                if rest.len() < 8 + CRYPT_TAG {
                    return Err(forged());
                }
                let (replay, rest) = rest.split_at(8);
                let (tag, cipher) = rest.split_at(CRYPT_TAG);
                let mut body = cipher.to_vec();
                apply_ctr(receive_cipher, tag, &mut body);
                let expected = crypt_tag(receive_hmac, header, session, replay, &body);
                if !bool::from(expected.as_ref().ct_eq(tag)) {
                    return Err(forged());
                }
                (Some(ReplayStamp::parse(replay)), body)
            }
        };
        Ok(Unwrapped {
            header,
            session: *session,
            body,
            replay,
        })
    }
    /// 返回 `false` 表示重放或早于会话起始，应丢弃该包。
    pub fn commit(&mut self, replay: Option<ReplayStamp>) -> bool {
        replay.is_none_or(|stamp| self.replay.accept(stamp))
    }
}
fn auth_tag(
    key: &hmac::Key,
    replay: &[u8],
    header: u8,
    session: &SessionId,
    body: &[u8],
) -> hmac::Tag {
    let mut context = hmac::Context::with_key(key);
    context.update(replay);
    context.update(&[header]);
    context.update(session);
    context.update(body);
    context.sign()
}
fn crypt_tag(
    key: &hmac::Key,
    header: u8,
    session: &SessionId,
    replay: &[u8],
    body: &[u8],
) -> hmac::Tag {
    let mut context = hmac::Context::with_key(key);
    context.update(&[header]);
    context.update(session);
    context.update(replay);
    context.update(body);
    context.sign()
}
fn apply_ctr(key: &[u8; 32], tag: &[u8], data: &mut [u8]) {
    let mut cipher = ctr::Ctr128BE::<Aes256>::new(key.into(), tag[..16].into());
    cipher.apply_keystream(data);
}

#[derive(Clone, Copy)]
pub(crate) struct ReplayStamp {
    id: u32,
    time: u32,
}
impl ReplayStamp {
    fn parse(replay: &[u8]) -> Self {
        Self {
            id: u32::from_be_bytes([replay[0], replay[1], replay[2], replay[3]]),
            time: u32::from_be_bytes([replay[4], replay[5], replay[6], replay[7]]),
        }
    }
}

/// 时间戳来自对端时钟，与上游 `packet_id_test` 一样只比较先后，不与本机时钟比较：更早的被拒绝，更新的开始新窗口。
#[derive(Default)]
struct ControlReplay {
    time: u32,
    window: ReplayWindow,
}
impl ControlReplay {
    fn accept(&mut self, stamp: ReplayStamp) -> bool {
        if stamp.time < self.time {
            return false;
        }
        if stamp.time > self.time {
            *self = Self {
                time: stamp.time,
                window: ReplayWindow::default(),
            };
        }
        self.window.accept(stamp.id)
    }
}

/// 收到的最高序号及其之前 128 个序号的位图；序号 0 在 OpenVPN 中保留不用。
#[derive(Default)]
pub(crate) struct ReplayWindow {
    highest: u32,
    seen: u128,
}
impl ReplayWindow {
    pub fn accept(&mut self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        if id > self.highest {
            let shift = id - self.highest;
            self.seen = if shift >= 128 { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.highest = id;
            return true;
        }
        let distance = self.highest - id;
        if distance >= 128 || self.seen & 1 << distance != 0 {
            return false;
        }
        self.seen |= 1 << distance;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Opcode;

    fn key_text() -> String {
        let bytes: Vec<u8> = (0..=255).collect();
        let lines: Vec<String> = bytes
            .chunks(16)
            .map(|line| line.iter().map(|byte| format!("{byte:02x}")).collect())
            .collect();
        format!(
            "#\n# 2048 bit OpenVPN static key\n#\n{STATIC_KEY_BEGIN}\n{}\n{STATIC_KEY_END}\n",
            lines.join("\n")
        )
    }
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn static_key_parses_the_upstream_file_layout_and_rejects_short_bodies() {
        let key = StaticKey::parse(&key_text()).unwrap();
        assert_eq!(key.cipher(0)[0], 0);
        assert_eq!(key.hmac(0)[0], 64);
        assert_eq!(key.cipher(1)[0], 128);
        assert_eq!(key.hmac(1)[0], 192);
        let short = format!("{STATIC_KEY_BEGIN}\n00ff\n{STATIC_KEY_END}\n");
        assert!(StaticKey::parse(&short).is_err());
    }

    /// 向量按上游 `swap_hmac` 与 `tls_crypt_wrap` 的格式，用 Python hmac 与 `cryptography` 独立计算。
    #[test]
    fn tls_auth_packet_matches_independent_vector() {
        let key = StaticKey::parse(&key_text()).unwrap();
        let mut wrap = ControlWrap::new(WrapKeys::auth(&key, AuthDigest::Sha1, Some(1)));
        let header = Opcode::HardResetClient.byte(0);
        let wire = wrap.wrap(header, &[0x11; 8], &[0, 0, 0, 0, 0], 0x6000_0000);
        assert_eq!(to_hex(&wire), TLS_AUTH_CLIENT);
    }
    #[test]
    fn tls_crypt_packet_matches_independent_vector() {
        let key = StaticKey::parse(&key_text()).unwrap();
        let mut wrap = ControlWrap::new(WrapKeys::crypt(&key));
        let header = Opcode::HardResetClient.byte(0);
        let wire = wrap.wrap(header, &[0x11; 8], &[0, 0, 0, 0, 0], 0x6000_0000);
        assert_eq!(to_hex(&wire), TLS_CRYPT_CLIENT);
    }
    #[test]
    fn wrappers_accept_the_server_direction_and_reject_tamper_and_replay() {
        let key = StaticKey::parse(&key_text()).unwrap();
        for (client, server) in [
            (WrapKeys::crypt(&key), WrapKeys::crypt_directed(&key, 0, 1)),
            (
                WrapKeys::auth(&key, AuthDigest::Sha256, Some(1)),
                WrapKeys::auth(&key, AuthDigest::Sha256, Some(0)),
            ),
        ] {
            let mut sender = ControlWrap::new(server);
            let mut receiver = ControlWrap::new(client);
            let wire = sender.wrap(0x40, &[7; 8], b"body", 1);
            let opened = receiver.unwrap(&wire).unwrap();
            assert_eq!(
                (opened.header, opened.session, opened.body.as_slice()),
                (0x40, [7; 8], b"body".as_slice())
            );
            assert!(receiver.commit(opened.replay));
            assert!(!receiver.commit(receiver.unwrap(&wire).unwrap().replay));
            let mut tampered = sender.wrap(0x40, &[7; 8], b"body", 1);
            *tampered.last_mut().unwrap() ^= 1;
            assert!(receiver.unwrap(&tampered).is_err());
        }
    }
    #[test]
    fn replay_window_accepts_reordering_and_rejects_duplicates_and_stale_ids() {
        let mut window = ReplayWindow::default();
        assert!(!window.accept(0));
        assert!(window.accept(5));
        assert!(!window.accept(5));
        assert!(window.accept(3));
        assert!(!window.accept(3));
        assert!(window.accept(1000));
        assert!(!window.accept(872));
        assert!(window.accept(873));
    }
    #[test]
    fn control_replay_orders_by_timestamp_before_id() {
        let mut window = ControlReplay::default();
        assert!(window.accept(ReplayStamp { id: 500, time: 7 }));
        assert!(!window.accept(ReplayStamp { id: 501, time: 6 }));
        assert!(window.accept(ReplayStamp { id: 1, time: 8 }));
        assert!(!window.accept(ReplayStamp { id: 1, time: 8 }));
        assert!(!window.accept(ReplayStamp { id: 502, time: 7 }));
    }

    const TLS_AUTH_CLIENT: &str =
        "3811111111111111112a8cb63b43b3e8f94a09d6fabea15c352d756e0a00000001600000000000000000";
    const TLS_CRYPT_CLIENT: &str = "3811111111111111110000000160000000e33ce4cd8f4bb3b39a8c6557c4310ec2ee745f0d5ed255431ed274a59dd2c8de09b9620ad4";
}
