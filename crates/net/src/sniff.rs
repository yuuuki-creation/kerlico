//! 流量协议嗅探器（HTTP Host、TLS ClientHello SNI、QUIC Initial SNI）。

use crate::fallback::PrefixedStream;
use kerlico_core::{Address, BoxStream, Destination, SniffPolicy};
use rustls::{Side, quic::Version};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SniffProtocol {
    Http,
    Tls,
    Quic,
}

impl SniffProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Quic => "quic",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SniffResult {
    pub protocol: SniffProtocol,
    pub domain: Option<String>,
    pub alpn: Option<String>,
}

fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let host = if let Some((h, port_str)) = trimmed.rsplit_once(':') {
        if !h.contains(':') && port_str.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            trimmed
        }
    } else {
        trimmed
    };
    let dest = Destination::new(host, 443).ok()?;
    match dest.address() {
        Address::Domain(domain) => Some(domain.strip_suffix('.').unwrap_or(domain).to_owned()),
        Address::Ip(_) => None,
    }
}

/// 解析 TLS 1.0–1.3 Record 中的 `ClientHello`（或裸 `ClientHello` 握手消息），提取 SNI 与 ALPN。
pub fn sniff_tls_client_hello(buf: &[u8]) -> Option<SniffResult> {
    if buf.len() < 5 {
        return None;
    }
    // 标准 TLS Handshake Record: ContentType = 0x16, Version = 0x03 0x00..0x04
    if buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x04 {
        let mut reassembled = Vec::new();
        let mut cursor = 0usize;
        while cursor + 5 <= buf.len() {
            if buf[cursor] != 0x16 || buf[cursor + 1] != 0x03 || buf[cursor + 2] > 0x04 {
                break;
            }
            let rec_len = u16::from_be_bytes([buf[cursor + 3], buf[cursor + 4]]) as usize;
            let end = (cursor + 5 + rec_len).min(buf.len());
            reassembled.extend_from_slice(&buf[cursor + 5..end]);
            if cursor + 5 + rec_len > buf.len() {
                break;
            }
            cursor += 5 + rec_len;
        }
        parse_client_hello_handshake(&reassembled, SniffProtocol::Tls)
    } else {
        None
    }
}

fn parse_client_hello_handshake(hs: &[u8], protocol: SniffProtocol) -> Option<SniffResult> {
    // Handshake Type: ClientHello = 0x01, 24-bit length
    if hs.len() < 42 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    let body = hs.get(4..4usize.saturating_add(hs_len).min(hs.len()))?;
    if body.len() < 35 {
        return None;
    }
    // legacy_version (2) + random (32)
    let mut pos = 34usize;
    let session_id_len = *body.get(pos)? as usize;
    pos += 1 + session_id_len;
    if pos + 2 > body.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos >= body.len() {
        return None;
    }
    let compression_methods_len = body[pos] as usize;
    pos += 1 + compression_methods_len;
    if pos + 2 > body.len() {
        return Some(SniffResult {
            protocol,
            domain: None,
            alpn: None,
        });
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos.saturating_add(ext_total_len).min(body.len());
    let mut domain = None;
    let mut alpn = None;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let Some(ext_data) = body.get(pos..pos + ext_len) else {
            break;
        };
        pos += ext_len;
        if ext_type == 0x0000 && ext_data.len() >= 2 {
            // server_name extension
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            let mut sni_pos = 2usize;
            let sni_end = (2 + list_len).min(ext_data.len());
            while sni_pos + 3 <= sni_end {
                let name_type = ext_data[sni_pos];
                let name_len =
                    u16::from_be_bytes([ext_data[sni_pos + 1], ext_data[sni_pos + 2]]) as usize;
                sni_pos += 3;
                let Some(name_bytes) = ext_data.get(sni_pos..sni_pos + name_len) else {
                    break;
                };
                sni_pos += name_len;
                if name_type == 0
                    && let Ok(name_str) = std::str::from_utf8(name_bytes)
                    && let Some(valid) = normalize_domain(name_str)
                {
                    domain = Some(valid);
                    break;
                }
            }
        } else if ext_type == 0x0010 && ext_data.len() >= 3 {
            // ALPN extension
            let proto_len = ext_data[2] as usize;
            if let Some(proto_bytes) = ext_data.get(3..3 + proto_len)
                && let Ok(proto_str) = std::str::from_utf8(proto_bytes)
            {
                alpn = Some(proto_str.to_owned());
            }
        }
    }
    Some(SniffResult {
        protocol,
        domain,
        alpn,
    })
}

/// 解析 HTTP/1.x 请求首包，从 `Host` 头或请求行绝对 URI 提取域名。
pub fn sniff_http_request(buf: &[u8]) -> Option<SniffResult> {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    if !METHODS.iter().any(|m| buf.starts_with(m)) {
        return None;
    }
    let text = std::str::from_utf8(&buf[..buf.len().min(4096)]).ok()?;
    let mut lines = text.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target_uri = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("host")
            && let Some(domain) = normalize_domain(value)
        {
            return Some(SniffResult {
                protocol: SniffProtocol::Http,
                domain: Some(domain),
                alpn: Some("http/1.1".into()),
            });
        }
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        if let Some(domain) = normalize_domain(target_uri) {
            return Some(SniffResult {
                protocol: SniffProtocol::Http,
                domain: Some(domain),
                alpn: Some("http/1.1".into()),
            });
        }
    } else if let Some(rest) = target_uri
        .strip_prefix("http://")
        .or_else(|| target_uri.strip_prefix("https://"))
    {
        let authority = rest.split('/').next().unwrap_or(rest);
        if let Some(domain) = normalize_domain(authority) {
            return Some(SniffResult {
                protocol: SniffProtocol::Http,
                domain: Some(domain),
                alpn: Some("http/1.1".into()),
            });
        }
    }
    None
}

fn read_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let tag = first >> 6;
    let len = 1usize << tag;
    if buf.len() < len {
        return None;
    }
    let mut val = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        val = (val << 8) | u64::from(b);
    }
    Some((val, len))
}

/// 解析并解密 QUIC v1 / v2 Initial UDP 数据报，提取内嵌 TLS 1.3 `ClientHello` SNI。
pub fn sniff_quic_initial(packet: &[u8]) -> Option<SniffResult> {
    if packet.len() < 32 {
        return None;
    }
    let first = packet[0];
    // Long Header (bit 7 = 1) + Fixed Bit (bit 6 = 1)
    if (first & 0xc0) != 0xc0 {
        return None;
    }
    let raw_version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    let version = match raw_version {
        0x0000_0001 => {
            // QUIC v1 Initial packet type: bits 5..4 == 0b00
            if ((first >> 4) & 0x03) != 0b00 {
                return None;
            }
            Version::V1
        }
        0x6b33_43cf => {
            // QUIC v2 Initial packet type: bits 5..4 == 0b01
            if ((first >> 4) & 0x03) != 0b01 {
                return None;
            }
            Version::V2
        }
        0xff00_001d..=0xff00_0020 => {
            if ((first >> 4) & 0x03) != 0b00 {
                return None;
            }
            Version::V1Draft
        }
        _ => return None,
    };
    let mut pos = 5usize;
    let dcid_len = *packet.get(pos)? as usize;
    pos += 1;
    let dcid = packet.get(pos..pos + dcid_len)?;
    pos += dcid_len;
    let scid_len = *packet.get(pos)? as usize;
    pos += 1;
    if pos + scid_len > packet.len() {
        return None;
    }
    pos += scid_len;
    let (token_len, token_vlen) = read_quic_varint(&packet[pos..])?;
    pos += token_vlen + usize::try_from(token_len).ok()?;
    let (payload_len, len_vlen) = read_quic_varint(&packet[pos..])?;
    pos += len_vlen;
    let pn_offset = pos;
    let total_len = pn_offset.checked_add(usize::try_from(payload_len).ok()?)?;
    if total_len > packet.len() || pn_offset + 20 > total_len {
        return None;
    }

    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()?
        .quic_suite()?;
    let keys = suite.keys(dcid, Side::Server, version);
    let sample_len = keys.remote.header.sample_len();
    let sample_offset = pn_offset + 4;
    if sample_offset + sample_len > total_len {
        return None;
    }
    let mut buf = packet[..total_len].to_vec();
    let sample = buf[sample_offset..sample_offset + sample_len].to_vec();
    let (head, rest) = buf.split_at_mut(pn_offset);
    keys.remote
        .header
        .decrypt_in_place(&sample, &mut head[0], &mut rest[..4])
        .ok()?;
    let pn_len = usize::from((head[0] & 0x03) + 1);
    if pn_offset + pn_len > total_len {
        return None;
    }
    let mut pn = 0u64;
    for &b in &buf[pn_offset..pn_offset + pn_len] {
        pn = (pn << 8) | u64::from(b);
    }
    let (header, ciphertext) = buf.split_at_mut(pn_offset + pn_len);
    let plaintext = keys
        .remote
        .packet
        .decrypt_in_place(pn, header, ciphertext)
        .ok()?;

    // 从解密后的 QUIC 帧中收集 CRYPTO (0x06) 帧数据
    let mut crypto_segments: Vec<(usize, &[u8])> = Vec::new();
    let mut fpos = 0usize;
    while fpos < plaintext.len() {
        match plaintext[fpos] {
            0x00 | 0x01 => {
                // PADDING or PING
                fpos += 1;
            }
            0x06 => {
                // CRYPTO frame: type(0x06) + offset(varint) + length(varint) + data
                fpos += 1;
                let (offset, olen) = read_quic_varint(&plaintext[fpos..])?;
                fpos += olen;
                let (length, llen) = read_quic_varint(&plaintext[fpos..])?;
                fpos += llen;
                let length = usize::try_from(length).ok()?;
                let data = plaintext.get(fpos..fpos + length)?;
                fpos += length;
                crypto_segments.push((usize::try_from(offset).ok()?, data));
            }
            _ => break,
        }
    }
    if crypto_segments.is_empty() {
        return None;
    }
    crypto_segments.sort_by_key(|(offset, _)| *offset);
    let max_end = crypto_segments
        .iter()
        .map(|(off, data)| off.saturating_add(data.len()))
        .max()
        .unwrap_or(0)
        .min(16384);
    let mut crypto_buf = vec![0u8; max_end];
    for (off, data) in crypto_segments {
        if off < max_end {
            let copy_len = data.len().min(max_end - off);
            crypto_buf[off..off + copy_len].copy_from_slice(&data[..copy_len]);
        }
    }
    parse_client_hello_handshake(&crypto_buf, SniffProtocol::Quic)
}

/// 按给定协议集合对单块数据进行探测。
pub fn sniff_bytes(buf: &[u8], udp: bool, policy: &SniffPolicy, port: u16) -> Option<SniffResult> {
    if udp {
        if policy.allows_protocol("quic", port) {
            return sniff_quic_initial(buf);
        }
        return None;
    }
    if policy.allows_protocol("tls", port)
        && let Some(res) = sniff_tls_client_hello(buf)
    {
        return Some(res);
    }
    if policy.allows_protocol("http", port)
        && let Some(res) = sniff_http_request(buf)
    {
        return Some(res);
    }
    None
}

/// 在给定超时内预读 TCP 流首包进行协议嗅探，随后将已读字节无损回放至返回流头部。
pub async fn sniff_stream(
    mut stream: BoxStream,
    policy: &SniffPolicy,
    port: u16,
) -> (BoxStream, Option<SniffResult>) {
    let mut buf = Vec::with_capacity(1024);
    let mut scratch = [0u8; 1024];
    let timeout = policy.effective_timeout();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut result = None;

    while buf.len() < 4096 {
        let read_fut = stream.read(&mut scratch);
        match tokio::time::timeout_at(deadline, read_fut).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&scratch[..n]);
                if let Some(sniffed) = sniff_bytes(&buf, false, policy, port) {
                    result = Some(sniffed);
                    break;
                }
                // 若首字节既不是 TLS Handshake (0x16) 也不是常见 HTTP 方法首字母，提前停止等待
                if let Some(&first) = buf.first()
                    && first != 0x16
                    && !matches!(first, b'G' | b'P' | b'H' | b'D' | b'O' | b'C' | b'T')
                {
                    break;
                }
            }
        }
    }

    let restored: BoxStream = if buf.is_empty() {
        stream
    } else {
        Box::new(PrefixedStream::new(buf, stream))
    };
    (restored, result)
}

/// 根据节点嗅探策略决定是否对 TCP 流首包执行协议嗅探，并构造含嗅探元数据的 `OriginalTarget`。
pub async fn sniff_and_prepare_tcp(
    stream: BoxStream,
    target: &kerlico_core::Destination,
    policy: &SniffPolicy,
) -> (BoxStream, kerlico_core::OriginalTarget) {
    let mut orig = kerlico_core::OriginalTarget::from_destination(target.clone());
    if !policy.should_sniff_target(target) {
        return (stream, orig);
    }
    let (restored, sniffed) = sniff_stream(stream, policy, target.port()).await;
    if let Some(res) = sniffed {
        if let Some(domain) = &res.domain
            && policy.should_override(domain)
            && let Ok(new_dst) = kerlico_core::Destination::new(domain, target.port())
        {
            orig = orig.with_target(new_dst);
        }
        orig = orig.with_sniffed(res.domain, Some(res.protocol.as_str().to_owned()));
    }
    (restored, orig)
}

/// 根据节点嗅探策略对首包 UDP 数据报（QUIC Initial）执行探测，并构造 `OriginalTarget`。
pub fn sniff_and_prepare_udp(
    packet: &[u8],
    target: &kerlico_core::Destination,
    policy: &SniffPolicy,
) -> kerlico_core::OriginalTarget {
    let mut orig = kerlico_core::OriginalTarget::from_destination(target.clone());
    if !policy.should_sniff_target(target) {
        return orig;
    }
    if let Some(res) = sniff_bytes(packet, true, policy, target.port()) {
        if let Some(domain) = &res.domain
            && policy.should_override(domain)
            && let Ok(new_dst) = kerlico_core::Destination::new(domain, target.port())
        {
            orig = orig.with_target(new_dst);
        }
        orig = orig.with_sniffed(res.domain, Some(res.protocol.as_str().to_owned()));
    }
    orig
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tls_client_hello_record(sni: &str) -> Vec<u8> {
        let host = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let list_len = (3 + host.len()) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0x00); // host_name
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0x00); // session_id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x01); // compression methods len
        body.push(0x00); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = body.len() as u32;
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn sniffs_tls_client_hello_and_http_host() {
        let tls_pkt = build_tls_client_hello_record("Sniff.Example.COM");
        let tls_res = sniff_tls_client_hello(&tls_pkt).unwrap();
        assert_eq!(tls_res.protocol, SniffProtocol::Tls);
        assert_eq!(tls_res.domain.as_deref(), Some("sniff.example.com"));

        let http_pkt =
            b"GET /index.html HTTP/1.1\r\nUser-Agent: test\r\nHost: Web.Example.ORG:8080\r\n\r\n";
        let http_res = sniff_http_request(http_pkt).unwrap();
        assert_eq!(http_res.protocol, SniffProtocol::Http);
        assert_eq!(http_res.domain.as_deref(), Some("web.example.org"));
    }

    fn push_quic_varint(buf: &mut Vec<u8>, val: usize) {
        if val < 64 {
            buf.push(val as u8);
        } else {
            let v = 0x4000u16 | (val as u16);
            buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    #[test]
    fn sniffs_quic_v1_initial_sni() {
        let record = build_tls_client_hello_record("quic.example.net");
        let hs = &record[5..]; // strip 5-byte TLS record header

        // Build CRYPTO frame (0x06, offset=0, len=hs.len(), data=hs)
        let mut plaintext = Vec::new();
        plaintext.push(0x06);
        plaintext.push(0x00); // offset = 0
        push_quic_varint(&mut plaintext, hs.len());
        plaintext.extend_from_slice(hs);
        while plaintext.len() < 32 {
            plaintext.push(0x00); // PADDING so sample has enough bytes
        }

        let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut packet = Vec::new();
        packet.push(0xc0); // Long Header, Initial, 1-byte PN (0x00)
        packet.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(&dcid);
        packet.push(0); // scid len = 0
        packet.push(0); // token len = 0
        let payload_len = 1 + plaintext.len() + 16; // 1-byte PN + plaintext + 16-byte AEAD tag
        push_quic_varint(&mut packet, payload_len);
        let pn_offset = packet.len();
        packet.push(0x01); // PN = 1

        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        let keys = suite.keys(&dcid, Side::Client, Version::V1);
        let mut body = plaintext;
        let tag = keys
            .local
            .packet
            .encrypt_in_place(1, &packet, &mut body)
            .unwrap();
        packet.extend_from_slice(&body);
        packet.extend_from_slice(tag.as_ref());

        let sample_offset = pn_offset + 4;
        let sample_len = keys.local.header.sample_len();
        let sample = packet[sample_offset..sample_offset + sample_len].to_vec();
        let (head, rest) = packet.split_at_mut(pn_offset);
        keys.local
            .header
            .encrypt_in_place(&sample, &mut head[0], &mut rest[..1])
            .unwrap();

        let res = sniff_quic_initial(&packet).unwrap();
        assert_eq!(res.protocol, SniffProtocol::Quic);
        assert_eq!(res.domain.as_deref(), Some("quic.example.net"));
    }
}
