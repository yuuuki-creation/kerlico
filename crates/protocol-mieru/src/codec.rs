//! 固定 32 字节元数据、载体段与 SOCKS/UDP 包隧道；不从载体认证推定目标已接纳。
use crate::{
    config::Traffic,
    crypto::{self, Key, StreamCipher, Users},
    entropy,
};
use bytes::Bytes;
use kerlico_core::{Address, Destination, Error, Result};
use rand::Rng;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt};
pub(crate) const MAX_UDP: usize = 65507;
pub(crate) fn bad() -> Error {
    Error::Protocol("Mieru 报文不合法")
}
#[derive(Clone)]
pub(crate) struct Frame {
    pub kind: u8,
    pub id: u32,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub fragment: u8,
    pub status: u8,
    pub mode: u8,
    pub rotation: u8,
    pub body: Bytes,
}
impl Frame {
    pub fn control(kind: u8, id: u32, seq: u32, body: Bytes) -> Self {
        Self {
            kind,
            id,
            seq,
            ack: 0,
            window: 128,
            fragment: 0,
            status: 0,
            mode: 0,
            rotation: 0,
            body,
        }
    }
    pub fn data(id: u32, seq: u32, body: Bytes, client: bool, traffic: &Traffic) -> Self {
        let mode = traffic.low_entropy_mode;
        Self {
            kind: if client {
                if mode == 0 { 6 } else { 10 }
            } else if mode == 0 {
                7
            } else {
                11
            },
            id,
            seq,
            ack: 0,
            window: 128,
            fragment: 0,
            status: 0,
            mode,
            rotation: traffic.mask_rotation,
            body,
        }
    }
    pub fn is_data(&self) -> bool {
        matches!(self.kind, 6 | 7 | 10 | 11)
    }
    pub fn is_ack(&self) -> bool {
        matches!(self.kind, 8 | 9)
    }
    pub fn session(&self) -> bool {
        (2..=5).contains(&self.kind)
    }
    pub fn direction(&self, receiving_client: bool) -> Result<()> {
        let valid = if receiving_client {
            matches!(self.kind, 3 | 4 | 5 | 7 | 9 | 11)
        } else {
            matches!(self.kind, 2 | 4 | 5 | 6 | 8 | 10)
        };
        if valid { Ok(()) } else { Err(bad()) }
    }
}
struct Description {
    frame: Frame,
    length: usize,
    raw_length: usize,
    prefix: usize,
    suffix: usize,
    half: u32,
}
impl Description {
    fn parse(bytes: [u8; 32], seconds: u64) -> Result<Self> {
        let kind = bytes[0];
        let minute = u32::from_be_bytes(bytes[2..6].try_into().expect("固定时间字段"));
        let current = u32::try_from(seconds / 60).map_err(|_| bad())?;
        if current.abs_diff(minute) > 1 {
            return Err(Error::Rejected);
        }
        let id = u32::from_be_bytes(bytes[6..10].try_into().expect("固定 ID 字段"));
        let seq = u32::from_be_bytes(bytes[10..14].try_into().expect("固定序号字段"));
        if id == 0 {
            return Err(bad());
        }
        let mut frame = Frame::control(kind, id, seq, Bytes::new());
        if (2..=5).contains(&kind) {
            let length = usize::from(u16::from_be_bytes([bytes[15], bytes[16]]));
            if length > 1024 || matches!(kind, 2 | 3) && seq != 0 {
                return Err(bad());
            }
            frame.status = bytes[14];
            return Ok(Self {
                frame,
                length,
                raw_length: length,
                prefix: 0,
                suffix: usize::from(bytes[17]),
                half: 0,
            });
        }
        if !(6..=11).contains(&kind) {
            return Err(bad());
        }
        frame.ack = u32::from_be_bytes(bytes[14..18].try_into().expect("固定 ACK 字段"));
        frame.window = u16::from_be_bytes([bytes[18], bytes[19]]);
        frame.fragment = bytes[20];
        let length = usize::from(u16::from_be_bytes([bytes[22], bytes[23]]));
        let mut raw_length = length;
        let mut half = 0;
        if matches!(kind, 10 | 11) {
            frame.mode = bytes[1];
            frame.rotation = bytes[31];
            half = u32::from_be_bytes(bytes[25..29].try_into().expect("固定掩码字段"));
            raw_length = usize::from(u16::from_be_bytes([bytes[29], bytes[30]]));
            if raw_length > 32768 || entropy::encoded_len(raw_length, frame.mode)? != length {
                return Err(bad());
            }
            // 空体也必须有合法掩码与旋转。
            entropy::decode(&[], 0, frame.mode, half, frame.rotation)?;
        } else if length > 32768 {
            return Err(bad());
        }
        if frame.is_ack() && length != 0 {
            return Err(bad());
        }
        Ok(Self {
            frame,
            length,
            raw_length,
            prefix: usize::from(bytes[21]),
            suffix: usize::from(bytes[24]),
            half,
        })
    }
    fn remaining(&self) -> usize {
        self.prefix + self.length + usize::from(self.length != 0) * 16 + self.suffix
    }
    fn encrypted(&self, tail: &[u8]) -> Result<Vec<u8>> {
        if tail.len() != self.remaining() {
            return Err(bad());
        }
        if self.length == 0 {
            return Ok(Vec::new());
        }
        let body = &tail[self.prefix..self.prefix + self.length + 16];
        if self.frame.mode == 0 {
            return Ok(body.to_vec());
        }
        let mut decoded = entropy::decode(
            &body[..self.length],
            self.raw_length,
            self.frame.mode,
            self.half,
            self.frame.rotation,
        )?;
        decoded.extend(&body[self.length..]);
        Ok(decoded)
    }
    fn finish(mut self, plain: Vec<u8>) -> Result<Frame> {
        if plain.len() != self.raw_length {
            return Err(bad());
        }
        self.frame.body = plain.into();
        Ok(self.frame)
    }
}
struct Prepared {
    meta: [u8; 32],
    half: u32,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}
fn padding(length: usize) -> Vec<u8> {
    (0..length)
        .map(|_| rand::thread_rng().gen_range(32..=126))
        .collect()
}
fn prepare(frame: &Frame, traffic: &Traffic, mtu: Option<usize>) -> Result<Prepared> {
    if frame.id == 0 || frame.body.len() > if frame.session() { 1024 } else { 32768 } {
        return Err(bad());
    }
    let length = if frame.mode == 0 {
        frame.body.len()
    } else {
        entropy::encoded_len(frame.body.len(), frame.mode)?
    };
    let half = if frame.mode == 0 {
        0
    } else {
        entropy::random_mask(frame.mode)?
    };
    let allowance = mtu
        .map(|mtu| mtu.saturating_sub(88 + length))
        .unwrap_or(510);
    let max_prefix = if frame.session() {
        0
    } else {
        usize::from(traffic.max_padding).min(allowance)
    };
    let prefix = rand::thread_rng().gen_range(0..=max_prefix);
    let suffix =
        rand::thread_rng().gen_range(0..=usize::from(traffic.max_padding).min(allowance - prefix));
    let meta = metadata(frame, half, prefix, suffix, crypto::now()?)?;
    Ok(Prepared {
        meta,
        half,
        prefix: padding(prefix),
        suffix: padding(suffix),
    })
}
fn metadata(
    frame: &Frame,
    half: u32,
    prefix: usize,
    suffix: usize,
    seconds: u64,
) -> Result<[u8; 32]> {
    if prefix > 255
        || suffix > 255
        || frame.session() && frame.mode != 0
        || frame.body.len() > if frame.session() { 1024 } else { 32768 }
    {
        return Err(bad());
    }
    let length = if frame.mode == 0 {
        frame.body.len()
    } else {
        entropy::encoded_len(frame.body.len(), frame.mode)?
    };
    let mut meta = [0; 32];
    meta[0] = frame.kind;
    meta[2..6].copy_from_slice(
        &u32::try_from(seconds / 60)
            .map_err(|_| bad())?
            .to_be_bytes(),
    );
    meta[6..10].copy_from_slice(&frame.id.to_be_bytes());
    meta[10..14].copy_from_slice(&frame.seq.to_be_bytes());
    if frame.session() {
        meta[14] = frame.status;
        meta[15..17].copy_from_slice(&(length as u16).to_be_bytes());
        meta[17] = suffix as u8;
    } else {
        meta[14..18].copy_from_slice(&frame.ack.to_be_bytes());
        meta[18..20].copy_from_slice(&frame.window.to_be_bytes());
        meta[20] = frame.fragment;
        meta[21] = prefix as u8;
        meta[22..24].copy_from_slice(&(length as u16).to_be_bytes());
        meta[24] = suffix as u8;
        if frame.mode != 0 {
            meta[1] = frame.mode;
            meta[25..29].copy_from_slice(&half.to_be_bytes());
            meta[29..31].copy_from_slice(&(frame.body.len() as u16).to_be_bytes());
            meta[31] = frame.rotation;
        }
    }
    Description::parse(meta, seconds)?;
    Ok(meta)
}
fn transform_body(mut encrypted: Vec<u8>, frame: &Frame, half: u32) -> Result<Vec<u8>> {
    if frame.mode == 0 || frame.body.is_empty() {
        return Ok(encrypted);
    }
    if encrypted.len() != frame.body.len() + 16 {
        return Err(bad());
    }
    let tag = encrypted.split_off(encrypted.len() - 16);
    let mut encoded = entropy::encode(
        &encrypted,
        frame.mode,
        half,
        frame.rotation,
        entropy::padding_bit(),
    )?;
    encoded.extend(tag);
    Ok(encoded)
}
pub(crate) fn seal_stream(
    cipher: &mut StreamCipher,
    frame: &Frame,
    traffic: &Traffic,
) -> Result<Vec<u8>> {
    let prepared = prepare(frame, traffic, None)?;
    let mut out = cipher.seal(&prepared.meta)?;
    out.extend(prepared.prefix);
    if !frame.body.is_empty() {
        out.extend(transform_body(
            cipher.seal(&frame.body)?,
            frame,
            prepared.half,
        )?);
    }
    out.extend(prepared.suffix);
    Ok(out)
}
pub(crate) async fn read_stream<R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &mut StreamCipher,
) -> Result<Frame> {
    let mut encrypted = vec![0; cipher.first_len()];
    reader.read_exact(&mut encrypted).await?;
    let meta: [u8; 32] = cipher.open(&encrypted)?.try_into().map_err(|_| bad())?;
    let description = Description::parse(meta, crypto::now()?)?;
    let mut tail = vec![0; description.remaining()];
    reader.read_exact(&mut tail).await?;
    let body = description.encrypted(&tail)?;
    let plain = if body.is_empty() {
        Vec::new()
    } else {
        cipher.open(&body)?
    };
    description.finish(plain)
}
pub(crate) async fn read_server_first<R: AsyncRead + Unpin>(
    reader: &mut R,
    users: &Users,
) -> Result<(Frame, StreamCipher, [u8; 24])> {
    let mut bytes = [0; 72];
    reader.read_exact(&mut bytes).await?;
    let nonce: [u8; 24] = bytes[..24].try_into().expect("固定 nonce 字段");
    let (key, meta) = users.select(&nonce, &bytes[24..], &[])?;
    let description = Description::parse(meta, crypto::now()?)?;
    let mut cipher = StreamCipher::from_metadata(key, nonce);
    let mut tail = vec![0; description.remaining()];
    reader.read_exact(&mut tail).await?;
    let body = description.encrypted(&tail)?;
    let plain = if body.is_empty() {
        Vec::new()
    } else {
        cipher.open(&body)?
    };
    Ok((description.finish(plain)?, cipher, nonce))
}
/// 保留官方有缺陷的同段 nonce 规则；调用者必须已经强制本地不安全兼容边界。
pub(crate) fn seal_local_unsafe_packet(
    key: &Key,
    frame: &Frame,
    traffic: &Traffic,
    mtu: usize,
) -> Result<Vec<u8>> {
    let prepared = prepare(frame, traffic, Some(mtu))?;
    let nonce = key.nonce()?;
    let mut out = nonce.to_vec();
    out.extend(key.seal(&nonce, &prepared.meta)?);
    out.extend(prepared.prefix);
    if !frame.body.is_empty() {
        out.extend(transform_body(
            key.seal(&nonce, &frame.body)?,
            frame,
            prepared.half,
        )?);
    }
    out.extend(prepared.suffix);
    if out.len() > mtu {
        return Err(bad());
    }
    Ok(out)
}
pub(crate) fn open_local_unsafe_packet(
    bytes: &[u8],
    users: Option<&Users>,
    known: &[Arc<Key>],
) -> Result<(Frame, Arc<Key>, [u8; 24])> {
    if !(72..=1500).contains(&bytes.len()) {
        return Err(bad());
    }
    let nonce: [u8; 24] = bytes[..24].try_into().expect("已检查 nonce 字段");
    let (key, meta) = if let Some(users) = users {
        users.select(&nonce, &bytes[24..72], known)?
    } else {
        let mut found = None;
        for key in known {
            if let Ok(plain) = key.open(&nonce, &bytes[24..72])
                && let Ok(meta) = <[u8; 32]>::try_from(plain)
            {
                found = Some((key.clone(), meta));
                break;
            }
        }
        found.ok_or(Error::Rejected)?
    };
    let description = Description::parse(meta, crypto::now()?)?;
    let body = description.encrypted(&bytes[72..])?;
    let plain = if body.is_empty() {
        Vec::new()
    } else {
        key.open(&nonce, &body)?
    };
    Ok((description.finish(plain)?, key, nonce))
}
pub(crate) fn address(out: &mut Vec<u8>, target: &Destination) {
    match target.address() {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend(ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend(ip.octets());
        }
        Address::Domain(host) => {
            out.push(3);
            out.push(host.len() as u8);
            out.extend(host.as_bytes());
        }
    }
    out.extend(target.port().to_be_bytes());
}
pub(crate) fn request(target: Option<&Destination>) -> Vec<u8> {
    let mut out = vec![5, if target.is_some() { 1 } else { 3 }, 0];
    if let Some(target) = target {
        address(&mut out, target);
    } else {
        out.extend([1, 0, 0, 0, 0, 0, 0]);
    }
    out
}
pub(crate) async fn read_address<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(String, u16)> {
    let host = match reader.read_u8().await? {
        1 => {
            let mut ip = [0; 4];
            reader.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            reader.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let length = reader.read_u8().await?;
            if length == 0 {
                return Err(bad());
            }
            let mut bytes = vec![0; usize::from(length)];
            reader.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| bad())?
        }
        _ => return Err(bad()),
    };
    Ok((host, reader.read_u16().await?))
}
pub(crate) async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(u8, String, u16)> {
    let mut head = [0; 3];
    reader.read_exact(&mut head).await?;
    if head[0] != 5 || head[2] != 0 || !matches!(head[1], 1 | 3) {
        return Err(bad());
    }
    let (host, port) = read_address(reader).await?;
    Ok((head[1], host, port))
}
pub(crate) async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut head = [0; 3];
    reader.read_exact(&mut head).await?;
    if head[0] != 5 || head[2] != 0 {
        return Err(bad());
    }
    read_address(reader).await?;
    if head[1] == 0 {
        Ok(())
    } else {
        Err(Error::Rejected)
    }
}
pub(crate) fn response(status: u8) -> [u8; 10] {
    [5, status, 0, 1, 0, 0, 0, 0, 0, 0]
}
pub(crate) fn udp_packet(target: &Destination, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_UDP {
        return Err(Error::Protocol("Mieru UDP 负载超过上限"));
    }
    let mut inner = vec![0; 3];
    address(&mut inner, target);
    inner.extend(payload);
    if inner.len() > u16::MAX as usize {
        return Err(Error::Protocol("Mieru UDP 地址与负载超过包封装上限"));
    }
    let mut out = vec![0];
    out.extend((inner.len() as u16).to_be_bytes());
    out.extend(inner);
    out.push(255);
    Ok(out)
}
pub(crate) async fn read_udp_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(Destination, Vec<u8>)>> {
    let mut marker = [0];
    let n = reader.read(&mut marker).await?;
    if n == 0 {
        return Ok(None);
    }
    if marker[0] != 0 {
        return Err(bad());
    }
    let len = usize::from(reader.read_u16().await?);
    if len < 7 {
        return Err(bad());
    }
    let mut frame = vec![0; len];
    reader.read_exact(&mut frame).await?;
    if reader.read_u8().await? != 255 || frame[..3] != [0, 0, 0] {
        return Err(bad());
    }
    let mut source = &frame[3..];
    let (host, port) = read_address(&mut source).await?;
    let target = Destination::new(&host, port)?;
    if source.len() > MAX_UDP {
        return Err(bad());
    }
    Ok(Some((target, source.to_vec())))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::User, crypto::key_bytes};
    use serde_json::Value;
    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
    fn bytes(value: &Value, name: &str) -> Vec<u8> {
        unhex(value[name].as_str().unwrap())
    }
    fn fixtures() -> Value {
        let path = std::env::var_os("KERLICO_MIERU_VECTORS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/go-vectors.json")
            });
        serde_json::from_slice(
            &std::fs::read(path).expect("先在 worker 运行独立 Go 固定向量生成工具"),
        )
        .unwrap()
    }
    #[test]
    fn official_go_metadata_kdf_cipher_and_low_entropy_vectors_match_both_directions() {
        let all = fixtures();
        let frames = all["frames"].as_array().unwrap();
        assert_eq!(frames.len(), 64);
        for vector in frames {
            let user = User::new(
                vector["username"].as_str().unwrap().into(),
                vector["password"].as_str().unwrap().into(),
            )
            .unwrap();
            let epoch = vector["epoch"].as_u64().unwrap();
            assert_eq!(&key_bytes(&user, epoch)[..], bytes(vector, "key_hex"));
            let key = Key::new(user, epoch);
            let nonce: [u8; 24] = bytes(vector, "nonce_hex").try_into().unwrap();
            let wire = bytes(vector, "wire_hex");
            let plain_meta: [u8; 32] = bytes(vector, "metadata_hex").try_into().unwrap();
            assert_eq!(key.open(&nonce, &wire[24..72]).unwrap(), plain_meta);
            assert_eq!(key.seal(&nonce, &plain_meta).unwrap(), &wire[24..72]);
            let seconds = vector["unix_seconds"].as_u64().unwrap();
            let description = Description::parse(plain_meta, seconds).unwrap();
            let encrypted = description.encrypted(&wire[72..]).unwrap();
            let body = if encrypted.is_empty() {
                Vec::new()
            } else if vector["transport"] == "tcp" {
                StreamCipher::from_metadata(key, nonce)
                    .open(&encrypted)
                    .unwrap()
            } else {
                key.open(&nonce, &encrypted).unwrap()
            };
            assert_eq!(body, bytes(vector, "payload_hex"));
            let decoded = description.finish(body).unwrap();
            assert_eq!(
                metadata(
                    &decoded,
                    vector["half_mask"].as_u64().unwrap() as u32,
                    vector["prefix"].as_u64().unwrap() as usize,
                    vector["suffix"].as_u64().unwrap() as usize,
                    seconds
                )
                .unwrap(),
                plain_meta
            );
        }
        let entropy_vectors = all["entropy"].as_array().unwrap();
        assert_eq!(entropy_vectors.len(), 96);
        for vector in entropy_vectors {
            let mode = vector["mode"].as_u64().unwrap() as u8;
            let half = vector["half_mask"].as_u64().unwrap() as u32;
            let rotation = vector["rotation"].as_u64().unwrap() as u8;
            let polarity = vector["polarity"].as_u64().unwrap() as u8;
            let source = bytes(vector, "source_hex");
            let encoded = bytes(vector, "encoded_hex");
            assert_eq!(
                entropy::encode(&source, mode, half, rotation, polarity).unwrap(),
                encoded
            );
            assert_eq!(
                entropy::decode(&encoded, source.len(), mode, half, rotation).unwrap(),
                source
            );
        }
        for vector in all["lengths"].as_array().unwrap() {
            let value = entropy::encoded_len(
                vector["raw"].as_u64().unwrap() as usize,
                vector["mode"].as_u64().unwrap() as u8,
            );
            assert_eq!(value.is_ok(), vector["valid"].as_bool().unwrap());
            if let Ok(length) = value {
                assert_eq!(length as u64, vector["encoded"].as_u64().unwrap());
            }
        }
    }
    #[tokio::test]
    async fn udp_packet_zero_payload_limits_and_truncated_markers_preserve_boundaries() {
        let target = Destination::new("::1", 12345).unwrap();
        for size in [0, 17, 65507] {
            let data = vec![7; size];
            let frame = udp_packet(&target, &data).unwrap();
            let decoded = read_udp_packet(&mut frame.as_slice())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(decoded, (target.clone(), data));
            for cut in [1, 2, 3, frame.len() - 1] {
                assert!(read_udp_packet(&mut &frame[..cut]).await.is_err());
            }
        }
        assert!(udp_packet(&target, &[0; 65508]).is_err());
        let host = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let domain = Destination::new(&host, 53).unwrap();
        assert!(udp_packet(&domain, &[0; 65507]).is_err());
        assert!(read_udp_packet(&mut &[255][..]).await.is_err());
        assert!(read_udp_packet(&mut &[0][..]).await.is_err());
    }
}
