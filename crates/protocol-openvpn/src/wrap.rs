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
const CRYPT_V2_KEY_BEGIN: &str = "-----BEGIN OpenVPN tls-crypt-v2 client key-----";
const CRYPT_V2_KEY_END: &str = "-----END OpenVPN tls-crypt-v2 client key-----";
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
        wk: Option<Vec<u8>>,
    },
}
impl WrapKeys {
    pub fn is_crypt_v2(&self) -> bool {
        matches!(self, Self::Crypt { wk: Some(_), .. })
    }
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
        Self::crypt_directed(key, 1, 0, None)
    }
    /// `tls-crypt` 的服务端方向固定为上游 `KEY_DIRECTION_NORMAL`（0 发 1 收）。
    pub fn crypt_server(key: &StaticKey) -> Self {
        Self::crypt_directed(key, 0, 1, None)
    }
    pub fn parse_crypt_v2(text: &str) -> Result<Self> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let invalid = || Error::Config("OpenVPN tls-crypt-v2 客户端密钥不合法".into());
        let (_, body) = text.split_once(CRYPT_V2_KEY_BEGIN).ok_or_else(invalid)?;
        let (body, _) = body.split_once(CRYPT_V2_KEY_END).ok_or_else(invalid)?;
        let cleaned: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let raw = Zeroizing::new(STANDARD.decode(cleaned).map_err(|_| invalid())?);
        if raw.len() < 256 + 2 || raw.len() > 256 + 1024 {
            return Err(invalid());
        }
        let mut key_bytes = Zeroizing::new([0u8; 256]);
        key_bytes.copy_from_slice(&raw[..256]);
        let wk = raw[256..].to_vec();
        if wkc_length(&wk) != Some(wk.len()) {
            return Err(invalid());
        }
        Ok(Self::crypt_directed(&StaticKey(key_bytes), 1, 0, Some(wk)))
    }
    fn crypt_directed(key: &StaticKey, send: usize, receive: usize, wk: Option<Vec<u8>>) -> Self {
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
            wk,
        }
    }
}

/// `WKc = T || AES-256-CTR(Ke, T[..16], Kc || metadata) || len`，`len` 为整个 WKc 的字节数，位于末尾。
fn wkc_length(wkc: &[u8]) -> Option<usize> {
    let tail = wkc.len().checked_sub(2)?;
    Some(usize::from(u16::from_be_bytes([wkc[tail], wkc[tail + 1]])))
}
const WKC_MIN: usize = CRYPT_TAG + 256 + 2;
/// 上游 `TLS_CRYPT_V2_MAX_WKC_LEN`。
const WKC_MAX: usize = 1024;
const CRYPT_V2_SERVER_BEGIN: &str = "-----BEGIN OpenVPN tls-crypt-v2 server key-----";
const CRYPT_V2_SERVER_END: &str = "-----END OpenVPN tls-crypt-v2 server key-----";

/// tls-crypt-v2 客户端密钥携带的元数据，首字节为类型。
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CryptV2Metadata {
    User(Vec<u8>),
    /// 生成密钥时的 Unix 时间。
    Timestamp(u64),
}

/// 服务端密钥：两组 512 位密钥，取第一组前 256 位作 AES-256-CTR 的 Ke、第二组前 256 位作 HMAC-SHA256 的 Ka。
pub(crate) struct CryptV2ServerKey {
    encrypt: Zeroizing<[u8; 32]>,
    authenticate: hmac::Key,
}
impl CryptV2ServerKey {
    pub fn parse(text: &str) -> Result<Self> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let invalid = || Error::Config("OpenVPN tls-crypt-v2 服务端密钥不合法".into());
        let (_, body) = text.split_once(CRYPT_V2_SERVER_BEGIN).ok_or_else(invalid)?;
        let (body, _) = body.split_once(CRYPT_V2_SERVER_END).ok_or_else(invalid)?;
        let cleaned: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let raw = Zeroizing::new(STANDARD.decode(cleaned).map_err(|_| invalid())?);
        if raw.len() != 128 {
            return Err(invalid());
        }
        let mut encrypt = Zeroizing::new([0; 32]);
        encrypt.copy_from_slice(&raw[..32]);
        Ok(Self {
            encrypt,
            authenticate: hmac::Key::new(hmac::HMAC_SHA256, &raw[64..96]),
        })
    }

    /// 从 `P_CONTROL_HARD_RESET_CLIENT_V3` 末尾取出 WKc，返回去掉 WKc 的包、客户端密钥 Kc 与元数据。
    /// 任何一步失败都返回 `None`，调用方静默丢包。
    pub fn open_reset<'a>(&self, wire: &'a [u8]) -> Option<(&'a [u8], WrapKeys, CryptV2Metadata)> {
        let length = wkc_length(wire)?;
        if !(WKC_MIN..=WKC_MAX).contains(&length) || length > wire.len() {
            return None;
        }
        let (packet, wkc) = wire.split_at(wire.len() - length);
        let (tag, rest) = wkc.split_at(CRYPT_TAG);
        let (sealed, len) = rest.split_at(rest.len() - 2);
        let mut plain = Zeroizing::new(sealed.to_vec());
        apply_ctr(&self.encrypt, tag, &mut plain);
        let mut context = hmac::Context::with_key(&self.authenticate);
        context.update(len);
        context.update(&plain);
        if !bool::from(context.sign().as_ref().ct_eq(tag)) {
            return None;
        }
        let (key, metadata) = plain.split_at(256);
        let metadata = match metadata.split_first() {
            Some((0, user)) => CryptV2Metadata::User(user.to_vec()),
            Some((1, stamp)) => {
                CryptV2Metadata::Timestamp(u64::from_be_bytes(stamp.try_into().ok()?))
            }
            _ => return None,
        };
        let mut client = Zeroizing::new([0; 256]);
        client.copy_from_slice(key);
        Some((packet, WrapKeys::crypt_server(&StaticKey(client)), metadata))
    }

    #[cfg(test)]
    pub fn seal_client_key(&self, client: &[u8; 256], metadata: &[u8]) -> Vec<u8> {
        let length = (CRYPT_TAG + client.len() + metadata.len() + 2) as u16;
        let mut context = hmac::Context::with_key(&self.authenticate);
        context.update(&length.to_be_bytes());
        context.update(client);
        context.update(metadata);
        let tag = context.sign();
        let mut sealed = [client.as_slice(), metadata].concat();
        apply_ctr(&self.encrypt, tag.as_ref(), &mut sealed);
        [tag.as_ref(), &sealed, &length.to_be_bytes()].concat()
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
                wk,
                ..
            } => {
                let tag = crypt_tag(send_hmac, header, session, &replay, body);
                wire.extend_from_slice(&replay);
                wire.extend_from_slice(tag.as_ref());
                let start = wire.len();
                wire.extend_from_slice(body);
                apply_ctr(send_cipher, tag.as_ref(), &mut wire[start..]);
                if header >> 3 == 10
                    && let Some(wk) = wk
                {
                    wire.extend_from_slice(wk);
                }
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

/// 数据通道防重放参数，对应上游 `replay-window n [t]`。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplayConfig {
    pub size: u32,
    /// 最高序号到达后，更早序号的包最多晚到这么久。
    pub max_delay: Option<std::time::Duration>,
}
impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            size: 128,
            max_delay: None,
        }
    }
}

/// 收到的最高序号及其之前 `size` 个序号的环形位图；序号 0 在 OpenVPN 中保留不用。
pub(crate) struct ReplayWindow {
    highest: u32,
    highest_at: Option<std::time::Instant>,
    bits: Vec<u64>,
    config: ReplayConfig,
}
impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new(ReplayConfig::default())
    }
}
impl ReplayWindow {
    pub fn new(config: ReplayConfig) -> Self {
        Self {
            highest: 0,
            highest_at: None,
            bits: vec![0; (config.size as usize).div_ceil(64).max(1)],
            config,
        }
    }
    fn capacity(&self) -> u32 {
        self.bits.len() as u32 * 64
    }
    fn bit(&self, id: u32) -> (usize, u64) {
        let index = id % self.capacity();
        ((index / 64) as usize, 1 << (index % 64))
    }
    pub fn accept(&mut self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        if id > self.highest {
            let shift = id - self.highest;
            if shift >= self.capacity() {
                self.bits.fill(0);
            } else {
                for cleared in self.highest + 1..=id {
                    let (word, mask) = self.bit(cleared);
                    self.bits[word] &= !mask;
                }
            }
            let (word, mask) = self.bit(id);
            self.bits[word] |= mask;
            self.highest = id;
            if self.config.max_delay.is_some() {
                self.highest_at = Some(std::time::Instant::now());
            }
            return true;
        }
        if self.highest - id >= self.config.size {
            return false;
        }
        if let (Some(limit), Some(at)) = (self.config.max_delay, self.highest_at)
            && at.elapsed() > limit
        {
            return false;
        }
        let (word, mask) = self.bit(id);
        if self.bits[word] & mask != 0 {
            return false;
        }
        self.bits[word] |= mask;
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
            (
                WrapKeys::crypt(&key),
                WrapKeys::crypt_directed(&key, 0, 1, None),
            ),
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
    fn configured_replay_window_size_bounds_how_far_back_ids_are_accepted() {
        let mut window = ReplayWindow::new(ReplayConfig {
            size: 64,
            max_delay: None,
        });
        assert!(window.accept(100));
        assert!(window.accept(37));
        assert!(!window.accept(36), "outside a 64-packet window");
        assert!(!window.accept(37));
        let mut wide = ReplayWindow::new(ReplayConfig {
            size: 1024,
            max_delay: None,
        });
        assert!(wide.accept(2000));
        assert!(wide.accept(1000));
        assert!(!wide.accept(976));
        assert!(wide.accept(2001));
        assert!(!wide.accept(1000));
    }
    #[test]
    fn replay_window_time_rejects_old_ids_that_arrive_too_late() {
        let mut window = ReplayWindow::new(ReplayConfig {
            size: 64,
            max_delay: Some(std::time::Duration::ZERO),
        });
        assert!(window.accept(10));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(!window.accept(9));
        assert!(window.accept(11), "newer ids are never too late");
    }
    #[test]
    fn tls_crypt_v2_client_key_file_carries_its_length_at_the_end() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let server = CryptV2ServerKey::parse(CRYPT_V2_SERVER).unwrap();
        let client: [u8; 256] = std::array::from_fn(|index| index as u8);
        let mut metadata = vec![1];
        metadata.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        let wkc = server.seal_client_key(&client, &metadata);
        assert_eq!(wkc_length(&wkc), Some(wkc.len()));
        let file = format!(
            "{CRYPT_V2_KEY_BEGIN}\n{}\n{CRYPT_V2_KEY_END}\n",
            STANDARD.encode([client.as_slice(), &wkc].concat())
        );
        let keys = WrapKeys::parse_crypt_v2(&file).unwrap();
        assert!(keys.is_crypt_v2());
        let mut client_wrap = ControlWrap::new(keys);
        let reset = client_wrap.wrap(
            Opcode::HardResetClientV3.byte(0),
            &[3; 8],
            &[0, 0, 0, 0, 0],
            9,
        );
        let (packet, server_keys, opened) = server.open_reset(&reset).unwrap();
        assert_eq!(opened, CryptV2Metadata::Timestamp(1_700_000_000));
        let unwrapped = ControlWrap::new(server_keys).unwrap(packet).unwrap();
        assert_eq!((unwrapped.header, unwrapped.session), (0x50, [3; 8]));
        let mut forged = reset.clone();
        forged[reset.len() - 40] ^= 1;
        assert!(server.open_reset(&forged).is_none());
        let other = CryptV2ServerKey::parse(&CRYPT_V2_SERVER.replacen('q', "r", 1)).unwrap();
        assert!(
            other.open_reset(&reset).is_none(),
            "WKc from another server key"
        );
    }
    /// 两份密钥由 OpenVPN 2.6.20 `--genkey tls-crypt-v2-server` 与 `--genkey tls-crypt-v2-client` 生成。
    #[test]
    fn server_key_opens_a_client_key_generated_by_upstream_openvpn() {
        let server = CryptV2ServerKey::parse(CRYPT_V2_SERVER).unwrap();
        let mut client = ControlWrap::new(WrapKeys::parse_crypt_v2(CRYPT_V2_CLIENT).unwrap());
        let reset = client.wrap(
            Opcode::HardResetClientV3.byte(0),
            &[5; 8],
            &[0, 0, 0, 0, 0],
            9,
        );
        let (packet, keys, metadata) = server.open_reset(&reset).unwrap();
        assert!(matches!(metadata, CryptV2Metadata::Timestamp(stamp) if stamp > 1_700_000_000));
        let mut server_wrap = ControlWrap::new(keys);
        let opened = server_wrap.unwrap(packet).unwrap();
        assert_eq!(opened.body, [0, 0, 0, 0, 0]);
        let reply = server_wrap.wrap(Opcode::HardResetServer.byte(0), &[6; 8], b"ok", 9);
        assert_eq!(client.unwrap(&reply).unwrap().body, b"ok");
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

    const CRYPT_V2_SERVER: &str = "-----BEGIN OpenVPN tls-crypt-v2 server key-----
qfE7ZBoHgaF3gxUP9uA0PME1MokkjfkbVpnnkxkibaZWWYeaXXpz2sENldRbhB7z
oCevNa7VHjQlHgGk4pAG5RHcQK7QRXXIOHDQww0GpJ5LY8ZKph8XcQprVntThHL4
Ru6kPG7thUoy4SapIGu1wOYfSD6UBOaI1iqyAbD0URE=
-----END OpenVPN tls-crypt-v2 server key-----
";
    const CRYPT_V2_CLIENT: &str = "-----BEGIN OpenVPN tls-crypt-v2 client key-----
9yARAo3DgvWyrby3e7cfehzYAybldfVVgt5EqmWWARmjhQxTp+SCJKiImNRyOP/W
r4p9NIv2AOWWBjlF71RZlL/4OYxovXOP0xakuUipXh7mjiTRwZGwY5pCiYUdRE/F
JxG1yUIAncVYuAqukLCPHv/dvkLB0gGgz98tl93NbzQSaqfI6aJBkM6oeZZzzbqJ
NjO8MtNeP3Mu6LNN0Mt2CxsZDKudwo1e1671SIL5H0ZcRPJR2oZQaQXQTbTE2a+m
ueOTgllMsUxMH5MTODFuH5Yqirxejatzqudw7kDTpW3tw9xdtLkSuitsSoVi9wIu
JSX00Qgoq/d45JHtZ6vHINDlxxqj3ClPILJnLG0dSwwE9xf7IW1KrECotptoyRiA
npmZpRwR8qkmXD0kwi2AmBxUZ8LVKdvP0xVcwG0BermKNfd+2UjuXnie4MpV9Ku2
4YSQ5sS9jYj2HtcuQw6EJoeQl2R5ywAdycxuK1DCH1WbtKMxYLZCgarKyrfnOQIr
dhSMckStuYIc6vF3c4niLIM82u374LD2+7oIhTPGgPVxSGunOnqc1RsCtCo00qtE
h8bjXFSQ8OUZ/dfA1STSWIVabqcsc77d8c89GOPzck/ziX1q7zA28fjl8KAHKSqF
AVS9m5sLVwxSegJyw1fyw6zmrNjainsvSD2VZfhNCp4EHRF4ZCkTdOdxQeoDyLSF
JQ7GTf7otyf8iZ/K85ZzKnDpH3P3P4+4FgEr
-----END OpenVPN tls-crypt-v2 client key-----
";
    const TLS_AUTH_CLIENT: &str =
        "3811111111111111112a8cb63b43b3e8f94a09d6fabea15c352d756e0a00000001600000000000000000";
    const TLS_CRYPT_CLIENT: &str = "3811111111111111110000000160000000e33ce4cd8f4bb3b39a8c6557c4310ec2ee745f0d5ed255431ed274a59dd2c8de09b9620ad4";
}
