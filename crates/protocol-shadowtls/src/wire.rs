//! 固定 ShadowTLS 记录与截短 HMAC；不提供内容加密。
use hmac::{Hmac, Mac};
use kerlico_core::{Error, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const HANDSHAKE: u8 = 22;
pub(crate) const APP: u8 = 23;
pub(crate) const ALERT: u8 = 21;
pub(crate) const CCS: u8 = 20;
pub(crate) const MAX_RECORD: usize = u16::MAX as usize;
pub(crate) const MAX_PLAIN: usize = 16384;
/// RFC 8446 的 HRR 标识是常量，不能用作跨连接认证的新鲜种子。
pub(crate) const HRR_RANDOM:[u8;32]=[0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c];

pub(crate) type Hash = Hmac<Sha1>;

pub(crate) fn hash(key: &[u8], seed: &[u8]) -> Hash {
    let mut value = <Hash as Mac>::new_from_slice(key).expect("HMAC 接受任意长度 key");
    value.update(seed);
    value
}
pub(crate) fn sum<const N: usize>(value: &Hash) -> [u8; N] {
    let digest = value.clone().finalize().into_bytes();
    let mut bytes = [0; N];
    bytes.copy_from_slice(&digest[..N]);
    bytes
}
pub(crate) fn equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}
pub(crate) fn directional(key: &[u8], random: &[u8; 32], side: u8) -> Hash {
    let mut value = hash(key, random);
    value.update(&[side]);
    value
}
pub(crate) fn tag(value: &mut Hash, payload: &[u8], feedback: bool) -> [u8; 4] {
    value.update(payload);
    let digest = sum::<4>(value);
    if feedback {
        value.update(&digest);
    }
    digest
}
pub(crate) fn verify(value: &mut Hash, payload: &[u8], feedback: bool) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let mut candidate = value.clone();
    let expected = tag(&mut candidate, &payload[4..], feedback);
    if !equal(&payload[..4], &expected) {
        return false;
    }
    *value = candidate;
    true
}
pub(crate) fn xor(key: &[u8], random: &[u8; 32], payload: &mut [u8]) {
    let mut digest = Sha256::new();
    digest.update(key);
    digest.update(random);
    let mask = digest.finalize();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 32];
    }
}
pub(crate) fn error() -> Error {
    Error::Protocol("ShadowTLS 记录或认证不合法")
}

pub(crate) fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, 3, 3];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
pub(crate) async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut header = [0; 5];
    let first = reader.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[1] != 3 || !(1..=3).contains(&header[2]) || length > MAX_RECORD {
        return Err(error());
    }
    let mut bytes = header.to_vec();
    bytes.resize(5 + length, 0);
    reader.read_exact(&mut bytes[5..]).await?;
    Ok(Some(bytes))
}
pub(crate) async fn alert<W: AsyncWrite + Unpin>(writer: &mut W) {
    use rand::RngCore;
    let mut payload = [0; 26];
    rand::thread_rng().fill_bytes(&mut payload);
    let _ = writer.write_all(&frame(ALERT, &payload)).await;
}
pub(crate) fn hello(bytes: &[u8], expected: u8) -> Result<(&[u8], &[u8], &[u8])> {
    if bytes.len() < 44 || bytes[0] != HANDSHAKE || bytes[5] != expected {
        return Err(error());
    }
    let length = ((bytes[6] as usize) << 16) | ((bytes[7] as usize) << 8) | bytes[8] as usize;
    if length + 9 > bytes.len() || expected == 1 && length + 9 != bytes.len() || length < 35 {
        return Err(error());
    }
    let message = &bytes[5..9 + length];
    let sid_length = message[38] as usize;
    if 39 + sid_length > message.len() {
        return Err(error());
    }
    Ok((message, &message[6..38], &message[39..39 + sid_length]))
}
fn extensions(message: &[u8], server: bool) -> Result<&[u8]> {
    let mut offset = 39usize
        .checked_add(message[38] as usize)
        .ok_or_else(error)?;
    if server {
        offset = offset.checked_add(3).ok_or_else(error)?;
    } else {
        let length = u16_at(message, offset)? as usize;
        offset += 2 + length;
        let length = *message.get(offset).ok_or_else(error)? as usize;
        offset += 1 + length;
    }
    if offset == message.len() {
        return Ok(&[]);
    }
    let length = u16_at(message, offset)? as usize;
    offset += 2;
    if offset + length != message.len() {
        return Err(error());
    }
    Ok(&message[offset..])
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes.get(offset..offset + 2).ok_or_else(error)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}
fn extension(mut bytes: &[u8], kind: u16) -> Result<Option<&[u8]>> {
    let mut found = None;
    while !bytes.is_empty() {
        let current = u16_at(bytes, 0)?;
        let length = u16_at(bytes, 2)? as usize;
        let payload = bytes.get(4..4 + length).ok_or_else(error)?;
        if current == kind {
            if found.is_some() {
                return Err(error());
            }
            found = Some(payload);
        }
        bytes = &bytes[4 + length..];
    }
    Ok(found)
}
pub(crate) fn server_hello(bytes: &[u8]) -> Result<([u8; 32], bool)> {
    let (message, random, _) = hello(bytes, 2)?;
    let tls13 = extension(extensions(message, true)?, 43)? == Some(&[3, 4][..]);
    let mut result = [0; 32];
    result.copy_from_slice(random);
    Ok((result, tls13))
}
pub(crate) fn server_name(bytes: &[u8]) -> Result<Option<String>> {
    let (message, _, _) = hello(bytes, 1)?;
    let Some(names) = extension(extensions(message, false)?, 0)? else {
        return Ok(None);
    };
    let length = u16_at(names, 0)? as usize;
    if length + 2 != names.len() {
        return Err(error());
    }
    let mut list = &names[2..];
    let mut found = None;
    while !list.is_empty() {
        let kind = *list.first().ok_or_else(error)?;
        let length = u16_at(list, 1)? as usize;
        let value = list.get(3..3 + length).ok_or_else(error)?;
        if kind == 0 {
            if found.is_some() || value.is_empty() {
                return Err(error());
            }
            found = Some(
                std::str::from_utf8(value)
                    .map_err(|_| error())?
                    .to_ascii_lowercase(),
            );
        }
        list = &list[3 + length..];
    }
    Ok(found)
}
pub(crate) fn client_auth(bytes: &[u8], key: &[u8]) -> bool {
    let Ok((message, _, sid)) = hello(bytes, 1) else {
        return false;
    };
    if sid.len() != 32 {
        return false;
    }
    let mut state = hash(key, &message[..67]);
    state.update(&[0; 4]);
    state.update(&message[71..]);
    equal(&sid[28..], &sum::<4>(&state))
}

/// 部分记录保存在结构体中，select 取消一次读取不会丢失字节。
pub(crate) struct Reader {
    bytes: Vec<u8>,
    offset: usize,
    total: usize,
}
impl Reader {
    pub fn new() -> Self {
        Self {
            bytes: vec![0; 5],
            offset: 0,
            total: 5,
        }
    }
    pub async fn next<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>> {
        loop {
            if self.offset == self.total {
                if self.total == 5 {
                    let length = u16::from_be_bytes([self.bytes[3], self.bytes[4]]) as usize;
                    if self.bytes[1] != 3
                        || !(1..=3).contains(&self.bytes[2])
                        || length > MAX_RECORD
                    {
                        return Err(error());
                    }
                    self.total = 5 + length;
                    self.bytes.resize(self.total, 0);
                    if length != 0 {
                        continue;
                    }
                }
                let frame = std::mem::replace(&mut self.bytes, vec![0; 5]);
                self.offset = 0;
                self.total = 5;
                return Ok(Some(frame));
            }
            let n = reader
                .read(&mut self.bytes[self.offset..self.total])
                .await?;
            if n == 0 {
                if self.offset == 0 {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "ShadowTLS 半条记录被截断",
                )
                .into());
            }
            self.offset += n;
        }
    }
    pub fn pending(&self) -> Vec<u8> {
        self.bytes[..self.offset].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directional_chains_reject_tamper_reorder_reflection_and_splice() {
        let seed = [7; 32];
        let mut sender = directional(b"test-key", &seed, b'C');
        let mut receiver = sender.clone();
        let encode = |state: &mut Hash, data: &[u8]| {
            let mut bytes = tag(state, data, true).to_vec();
            bytes.extend_from_slice(data);
            bytes
        };
        let first = encode(&mut sender, b"first");
        let second = encode(&mut sender, b"second");
        assert!(!verify(&mut receiver, &second, true));
        let mut tampered = first.clone();
        tampered[4] ^= 1;
        assert!(!verify(&mut receiver, &tampered, true));
        assert!(!verify(
            &mut directional(b"test-key", &seed, b'S'),
            &first,
            true
        ));
        let mut spliced = first.clone();
        spliced.extend_from_slice(&second);
        assert!(!verify(&mut receiver, &spliced, true));
        assert!(verify(&mut receiver, &first, true));
        assert!(!verify(&mut receiver, &first, true));
        assert!(verify(&mut receiver, &second, true));
        assert!(!verify(
            &mut directional(b"wrong-key", &seed, b'C'),
            &first,
            true
        ));
    }
    #[test]
    fn server_hello_can_share_a_tls12_record_with_later_handshake_messages() {
        let mut message = vec![2, 0, 0, 38, 3, 3];
        message.extend_from_slice(&[19; 32]);
        message.extend_from_slice(&[0, 0xc0, 0x2f, 0]);
        let mut payload = message.clone();
        payload.extend_from_slice(&[14, 0, 0, 0]);
        let (random, tls13) = server_hello(&frame(HANDSHAKE, &payload)).unwrap();
        assert_eq!(random, [19; 32]);
        assert!(!tls13);
        message[0] = 1;
        assert!(hello(&frame(HANDSHAKE, &message), 1).is_ok());
        message.extend_from_slice(&[14, 0, 0, 0]);
        assert!(hello(&frame(HANDSHAKE, &message), 1).is_err());
    }
    #[tokio::test]
    async fn reader_retains_split_header_and_rejects_truncated_records() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let bytes = frame(APP, b"record");
        writer.write_all(&bytes[..2]).await.unwrap();
        let mut state = Reader::new();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                state.next(&mut reader)
            )
            .await
            .is_err()
        );
        assert_eq!(state.pending(), bytes[..2]);
        writer.write_all(&bytes[2..]).await.unwrap();
        assert_eq!(state.next(&mut reader).await.unwrap().unwrap(), bytes);
        writer.write_all(&[23, 3, 3, 0, 9, 1]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(state.next(&mut reader).await.is_err());
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&[23, 3, 3, 255, 255]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(read(&mut reader).await.is_err());
    }
    #[tokio::test]
    async fn empty_payload_is_a_record_and_physical_boundary_eof_is_distinct() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(&frame(APP, &[])).await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(read(&mut reader).await.unwrap().unwrap(), [APP, 3, 3, 0, 0]);
        assert!(read(&mut reader).await.unwrap().is_none());
    }
}

pub(crate) fn client_early_data(record: &[u8]) -> bool {
    hello(record, 1)
        .and_then(|(message, _, _)| extensions(message, false))
        .and_then(|values| extension(values, 42))
        .ok()
        .flatten()
        .is_some()
}

#[cfg(test)]
mod early_tests {
    use super::*;
    #[test]
    fn early_data_clients_are_classified_for_fixed_origin_fallback() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[1; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 4, 0, 42, 0, 0]);
        let mut message = vec![1, 0, 0, body.len() as u8];
        message.extend_from_slice(&body);
        assert!(client_early_data(&frame(HANDSHAKE, &message)));
        let last = message.len() - 4;
        message[last + 1] = 41;
        assert!(!client_early_data(&frame(HANDSHAKE, &message)));
    }
}
