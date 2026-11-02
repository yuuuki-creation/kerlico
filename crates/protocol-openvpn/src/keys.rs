//! key-method 2 消息与旧式 TLS 1.0 PRF 数据通道密钥派生。

use crate::wire::SessionId;
use hmac::{Hmac, Mac, digest::KeyInit};
use kerlico_core::{Error, Result};
use md5::Md5;
use rand::{RngCore, rngs::OsRng};
use sha1::Sha1;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const EKM_LABEL: &[u8] = b"EXPORTER-OpenVPN-datakeys";
const KEY_METHOD_2: u8 = 2;

pub(crate) struct ClientKeySource {
    pre_master: [u8; 48],
    random1: [u8; 32],
    random2: [u8; 32],
}
impl ClientKeySource {
    pub fn generate() -> Self {
        let mut source = Self {
            pre_master: [0; 48],
            random1: [0; 32],
            random2: [0; 32],
        };
        OsRng.fill_bytes(&mut source.pre_master);
        OsRng.fill_bytes(&mut source.random1);
        OsRng.fill_bytes(&mut source.random2);
        source
    }
}
impl Drop for ClientKeySource {
    fn drop(&mut self) {
        self.pre_master.zeroize();
    }
}

pub(crate) struct ServerKeySource {
    random1: [u8; 32],
    random2: [u8; 32],
}

pub(crate) struct KeyMessage<'a> {
    pub options: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub peer_info: &'a str,
}

pub(crate) fn write_key_method(source: &ClientKeySource, message: &KeyMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + message.options.len() + message.peer_info.len());
    out.extend_from_slice(&[0; 4]);
    out.push(KEY_METHOD_2);
    out.extend_from_slice(&source.pre_master);
    out.extend_from_slice(&source.random1);
    out.extend_from_slice(&source.random2);
    write_string(&mut out, Some(message.options));
    write_string(&mut out, message.username);
    write_string(&mut out, message.password);
    write_string(&mut out, Some(message.peer_info));
    out
}
/// 上游 `write_string` 把结尾 NUL 计入长度；缺省字段写零长度。
fn write_string(out: &mut Vec<u8>, value: Option<&str>) {
    let Some(value) = value else {
        out.extend_from_slice(&[0, 0]);
        return;
    };
    out.extend_from_slice(&(value.len() as u16 + 1).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}

/// 消息不完整时返回 `None`。选项串之后的字段对客户端没有用途，不解析。
pub(crate) fn read_key_method(bytes: &[u8]) -> Result<Option<ServerKeySource>> {
    const FIXED: usize = 4 + 1 + 32 + 32;
    if bytes.len() < FIXED + 2 {
        return Ok(None);
    }
    if bytes[..4] != [0; 4] || bytes[4] & 0x0f != KEY_METHOD_2 {
        return Err(Error::Protocol("OpenVPN 密钥交换消息不合法"));
    }
    let options = usize::from(u16::from_be_bytes([bytes[FIXED], bytes[FIXED + 1]]));
    if bytes.len() < FIXED + 2 + options {
        return Ok(None);
    }
    let mut source = ServerKeySource {
        random1: [0; 32],
        random2: [0; 32],
    };
    source.random1.copy_from_slice(&bytes[5..37]);
    source.random2.copy_from_slice(&bytes[37..69]);
    Ok(Some(source))
}

fn p_hash<M: Mac + KeyInit + Clone>(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let keyed = <M as KeyInit>::new_from_slice(secret).expect("HMAC 接受任意长度密钥");
    let mut a = {
        let mut mac = keyed.clone();
        mac.update(seed);
        mac.finalize().into_bytes()
    };
    for chunk in output.chunks_mut(a.len()) {
        let mut mac = keyed.clone();
        mac.update(&a);
        mac.update(seed);
        let block = mac.finalize().into_bytes();
        for (out, byte) in chunk.iter_mut().zip(block.iter()) {
            *out ^= byte;
        }
        let mut mac = keyed.clone();
        mac.update(&a);
        a = mac.finalize().into_bytes();
    }
}
/// RFC 2246 PRF：两半密钥分别做 P_MD5 与 P_SHA1 后异或。
fn tls1_prf(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    output.fill(0);
    let half = secret.len() / 2;
    let odd = secret.len() % 2;
    p_hash::<Hmac<Md5>>(&secret[..half + odd], seed, output);
    p_hash::<Hmac<Sha1>>(&secret[half..], seed, output);
}

pub(crate) fn expand_with_prf(
    client: &ClientKeySource,
    server: &ServerKeySource,
    client_sid: &SessionId,
    server_sid: &SessionId,
) -> Zeroizing<[u8; 256]> {
    let mut master = Zeroizing::new([0; 48]);
    let mut seed = Vec::with_capacity(100);
    seed.extend_from_slice(b"OpenVPN master secret");
    seed.extend_from_slice(&client.random1);
    seed.extend_from_slice(&server.random1);
    tls1_prf(&client.pre_master, &seed, &mut master[..]);
    seed.clear();
    seed.extend_from_slice(b"OpenVPN key expansion");
    seed.extend_from_slice(&client.random2);
    seed.extend_from_slice(&server.random2);
    seed.extend_from_slice(client_sid);
    seed.extend_from_slice(server_sid);
    let mut key2 = Zeroizing::new([0; 256]);
    tls1_prf(&master[..], &seed, &mut key2[..]);
    key2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// 上游 `tests/unit_tests/openvpn/test_crypto.c` 的 `crypto_test_tls_prf`。
    #[test]
    fn tls1_prf_matches_upstream_unit_test_vector() {
        let secret = b"Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua.";
        let seed = b"Quis aute iure reprehenderit in voluptate velit esse cillum dolore";
        let mut out = [0; 32];
        tls1_prf(secret, seed, &mut out);
        assert_eq!(
            out,
            [
                0xd9, 0x8c, 0x85, 0x18, 0xc8, 0x5e, 0x94, 0x69, 0x27, 0x91, 0x6a, 0xcf, 0xc2, 0xd5,
                0x92, 0xfb, 0xb1, 0x56, 0x7e, 0x4b, 0x4b, 0x14, 0x59, 0xe6, 0xa9, 0x04, 0xac, 0x2d,
                0xda, 0xb7, 0x2d, 0x67
            ]
        );
    }

    /// 向量按上游 `generate_key_expansion_openvpn_prf` 用 Python hashlib 独立计算。
    #[test]
    fn key_expansion_matches_independent_vector() {
        let client = ClientKeySource {
            pre_master: [0x11; 48],
            random1: [0x22; 32],
            random2: [0x33; 32],
        };
        let server = ServerKeySource {
            random1: [0x44; 32],
            random2: [0x55; 32],
        };
        let key2 = expand_with_prf(&client, &server, &[0x66; 8], &[0x77; 8]);
        assert_eq!(hex(&key2[..]), KEY_EXPANSION);
    }

    #[test]
    fn key_method_message_uses_upstream_field_order_and_nul_counted_strings() {
        let source = ClientKeySource {
            pre_master: [1; 48],
            random1: [2; 32],
            random2: [3; 32],
        };
        let wire = write_key_method(
            &source,
            &KeyMessage {
                options: "V4",
                username: Some("u"),
                password: None,
                peer_info: "IV_PROTO=10\n",
            },
        );
        assert_eq!(wire[..5], [0, 0, 0, 0, 2]);
        assert_eq!(wire[5..53], [1; 48]);
        assert_eq!(wire[53..85], [2; 32]);
        assert_eq!(wire[85..117], [3; 32]);
        assert_eq!(
            wire[117..],
            *b"\0\x03V4\0\0\x02u\0\0\0\0\x0dIV_PROTO=10\n\0"
        );
    }

    #[test]
    fn server_key_reply_waits_for_all_of_the_options_string() {
        let mut reply = vec![0, 0, 0, 0, 2];
        reply.extend_from_slice(&[0xaa; 32]);
        reply.extend_from_slice(&[0xbb; 32]);
        assert!(read_key_method(&reply).unwrap().is_none());
        reply.extend_from_slice(&[0, 3, b'V', b'4']);
        assert!(read_key_method(&reply).unwrap().is_none());
        reply.push(0);
        let parsed = read_key_method(&reply).unwrap().unwrap();
        assert_eq!(parsed.random1, [0xaa; 32]);
        assert_eq!(parsed.random2, [0xbb; 32]);
        reply[4] = 1;
        assert!(read_key_method(&reply).is_err());
    }

    const KEY_EXPANSION: &str = "71113df37704e56e4a8b36b8c0e5e93f556c2d0a6052bca1dd65e490dd44b6b93183e0ba18616c91dde15fa92c455270793e0680f9a4e2c2e97ee5ec8a544927e859fb6ba23d8d77029fa911d7912e262658224f1728b1cfd09b9b6e587d7459ee4ccfecb96c9dc94c7bb16dcd73fd5be903757967eeb2a7ab106bc6f2391292b68b2ded19cb5f74e702f95db86eb1524bad46c2c7491266731221a87c4da6c177d88f94b05fc82c6b6d07cc5e274ac86bdf59627fa4a418d18ab1b8ed774ce89a601a6127ae6d84709ab60d7f9fe2dbb2ce844aa9aef8bbc9afd34abadbf15674bd5eb09a4da63220d42b2561c2b4feb1757dd95179f0bde28406dde0769d61";
}
