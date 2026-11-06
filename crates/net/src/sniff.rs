//! 流量协议嗅探器：TCP 首段（HTTP、TLS、BitTorrent、SSH、RDP）与 UDP 流（QUIC、DTLS、STUN、BitTorrent）。
//!
//! 语义对齐 sing-box `common/sniff` 与 Mihomo `component/sniffer`；只有 HTTP Host 与 TLS/QUIC SNI 产出域名。

use kerlico_core::{Address, Destination};
use rustls::{
    Side,
    quic::{DirectionalKeys, Version},
};
use serde::{Deserialize, Serialize};

/// 嗅探缓冲与 CRYPTO 流的统一上限，与 Mihomo `maxCryptoStreamOffset` 一致。
const MAX_SNIFF_LEN: usize = 64 * 1024;
/// TLSPlaintext 与 TLSCiphertext 记录长度上限（RFC 8446 §5.1、§5.2）。
const TLS_MAX_RECORD: usize = 16384 + 2048;
/// RFC 4253 §4.2：版本行含 CRLF 最长 255 字节。
const SSH_MAX_BANNER: usize = 255;
/// 单条 UDP 流最多观察的数据报数，超出仍未判定则放弃。
const MAX_UDP_DATAGRAMS: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SniffProtocol {
    Http,
    Tls,
    Quic,
    Bittorrent,
    Dtls,
    Stun,
    Ssh,
    Rdp,
}

impl SniffProtocol {
    pub const ALL: [SniffProtocol; 8] = [
        Self::Tls,
        Self::Http,
        Self::Quic,
        Self::Bittorrent,
        Self::Dtls,
        Self::Stun,
        Self::Ssh,
        Self::Rdp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Quic => "quic",
            Self::Bittorrent => "bittorrent",
            Self::Dtls => "dtls",
            Self::Stun => "stun",
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        Some(match name.as_str() {
            "http" => Self::Http,
            "tls" | "https" | "ssl" => Self::Tls,
            "quic" => Self::Quic,
            "bittorrent" | "bt" => Self::Bittorrent,
            "dtls" => Self::Dtls,
            "stun" => Self::Stun,
            "ssh" => Self::Ssh,
            "rdp" => Self::Rdp,
            _ => return None,
        })
    }

    pub fn tcp(self) -> bool {
        matches!(
            self,
            Self::Http | Self::Tls | Self::Ssh | Self::Rdp | Self::Bittorrent
        )
    }

    pub fn udp(self) -> bool {
        matches!(
            self,
            Self::Quic | Self::Dtls | Self::Stun | Self::Bittorrent
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SniffResult {
    pub protocol: SniffProtocol,
    pub domain: Option<String>,
    pub alpn: Option<String>,
    /// SSH 版本行中的软件标识（同 sing-box `metadata.Client`）；QUIC 客户端指纹未实现，恒为 `None`。
    pub client: Option<String>,
}

impl SniffResult {
    fn bare(protocol: SniffProtocol) -> Self {
        Self {
            protocol,
            domain: None,
            alpn: None,
            client: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Sniffed {
    Found(SniffResult),
    NeedMore,
    Miss,
}

/// TCP：`buf` 为已累积的客户端首段，按 `protocols` 顺序尝试（跳过非 TCP 协议）。
pub fn sniff_tcp(buf: &[u8], protocols: &[SniffProtocol]) -> Sniffed {
    let mut pending = false;
    for &protocol in protocols.iter().filter(|p| p.tcp()) {
        let verdict = match protocol {
            SniffProtocol::Tls => sniff_tls(buf),
            SniffProtocol::Http => sniff_http(buf),
            SniffProtocol::Bittorrent => sniff_bittorrent_tcp(buf),
            SniffProtocol::Ssh => sniff_ssh(buf),
            SniffProtocol::Rdp => sniff_rdp(buf),
            SniffProtocol::Quic | SniffProtocol::Dtls | SniffProtocol::Stun => Sniffed::Miss,
        };
        match verdict {
            Sniffed::Found(res) => return Sniffed::Found(res),
            Sniffed::NeedMore => pending = true,
            Sniffed::Miss => {}
        }
    }
    if pending {
        Sniffed::NeedMore
    } else {
        Sniffed::Miss
    }
}

/// UDP 单流嗅探器：按序推入数据报；判定为 `Found`/`Miss` 后再推入直接返回缓存结论。
pub struct UdpSniffer {
    protocols: Vec<SniffProtocol>,
    datagrams: u32,
    quic: Option<QuicFlow>,
    verdict: Option<Sniffed>,
}

impl UdpSniffer {
    pub fn new(protocols: &[SniffProtocol]) -> Self {
        let mut list: Vec<SniffProtocol> = Vec::new();
        for &p in protocols.iter().filter(|p| p.udp()) {
            if !list.contains(&p) {
                list.push(p);
            }
        }
        let quic = list.contains(&SniffProtocol::Quic).then(QuicFlow::default);
        let verdict = list.is_empty().then_some(Sniffed::Miss);
        Self {
            protocols: list,
            datagrams: 0,
            quic,
            verdict,
        }
    }

    pub fn push(&mut self, packet: &[u8]) -> Sniffed {
        if let Some(verdict) = &self.verdict {
            return verdict.clone();
        }
        self.datagrams += 1;
        let first = self.datagrams == 1;
        let mut pending = false;
        for protocol in self.protocols.iter().copied() {
            let verdict = match protocol {
                SniffProtocol::Quic => match self.quic.as_mut() {
                    Some(flow) => {
                        let v = flow.push(packet);
                        if v == Sniffed::Miss {
                            self.quic = None;
                        }
                        v
                    }
                    None => Sniffed::Miss,
                },
                // 无状态协议只看流的首个数据报，避免把后续业务负载误判。
                _ if !first => Sniffed::Miss,
                SniffProtocol::Dtls => found_if(is_dtls(packet), SniffProtocol::Dtls),
                SniffProtocol::Stun => found_if(is_stun(packet), SniffProtocol::Stun),
                SniffProtocol::Bittorrent => {
                    found_if(is_bittorrent_udp(packet), SniffProtocol::Bittorrent)
                }
                SniffProtocol::Http
                | SniffProtocol::Tls
                | SniffProtocol::Ssh
                | SniffProtocol::Rdp => Sniffed::Miss,
            };
            match verdict {
                Sniffed::Found(res) => {
                    let found = Sniffed::Found(res);
                    self.verdict = Some(found.clone());
                    return found;
                }
                Sniffed::NeedMore => pending = true,
                Sniffed::Miss => {}
            }
        }
        if pending && self.datagrams < MAX_UDP_DATAGRAMS {
            Sniffed::NeedMore
        } else {
            self.verdict = Some(Sniffed::Miss);
            Sniffed::Miss
        }
    }
}

fn found_if(hit: bool, protocol: SniffProtocol) -> Sniffed {
    if hit {
        Sniffed::Found(SniffResult::bare(protocol))
    } else {
        Sniffed::Miss
    }
}

enum Prefix {
    Full,
    Partial,
    Mismatch,
}

fn match_prefix(buf: &[u8], magic: &[u8]) -> Prefix {
    let n = buf.len().min(magic.len());
    if buf[..n] != magic[..n] {
        Prefix::Mismatch
    } else if n == magic.len() {
        Prefix::Full
    } else {
        Prefix::Partial
    }
}

fn need_more_within_limit(buf: &[u8]) -> Sniffed {
    if buf.len() >= MAX_SNIFF_LEN {
        Sniffed::Miss
    } else {
        Sniffed::NeedMore
    }
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

fn tls_record_prefix_ok(header: &[u8]) -> bool {
    header.first().is_none_or(|&b| b == 0x16)
        && header.get(1).is_none_or(|&b| b == 0x03)
        && header.get(2).is_none_or(|&b| b <= 0x04)
}

fn sniff_tls(buf: &[u8]) -> Sniffed {
    let mut hs: Vec<u8> = Vec::new();
    let mut rest = buf;
    loop {
        if let Some(verdict) = client_hello_verdict(&hs, SniffProtocol::Tls) {
            return verdict;
        }
        if !tls_record_prefix_ok(&rest[..rest.len().min(3)]) {
            return Sniffed::Miss;
        }
        if rest.len() < 5 {
            return Sniffed::NeedMore;
        }
        let rec_len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        if rec_len == 0 || rec_len > TLS_MAX_RECORD {
            return Sniffed::Miss;
        }
        let body = &rest[5..];
        let take = body.len().min(rec_len);
        hs.extend_from_slice(&body[..take]);
        if take < rec_len {
            return client_hello_verdict(&hs, SniffProtocol::Tls).unwrap_or(Sniffed::NeedMore);
        }
        rest = &body[rec_len..];
    }
}

/// 握手字节足以判定时返回结论；`None` 表示还需更多握手字节。
fn client_hello_verdict(hs: &[u8], protocol: SniffProtocol) -> Option<Sniffed> {
    let &kind = hs.first()?;
    if kind != 0x01 {
        return Some(Sniffed::Miss);
    }
    if hs.len() < 4 {
        return None;
    }
    let size = 4 + ((usize::from(hs[1]) << 16) | (usize::from(hs[2]) << 8) | usize::from(hs[3]));
    if size > MAX_SNIFF_LEN {
        return Some(Sniffed::Miss);
    }
    if hs.len() < size {
        return None;
    }
    Some(match parse_client_hello(&hs[..size], protocol) {
        Some(res) => Sniffed::Found(res),
        None => Sniffed::Miss,
    })
}

/// 解析完整的 `ClientHello` 握手消息（含 4 字节握手头），提取 SNI 与首个 ALPN。
fn parse_client_hello(hs: &[u8], protocol: SniffProtocol) -> Option<SniffResult> {
    if hs.len() < 42 || hs[0] != 0x01 {
        return None;
    }
    let body = &hs[4..];
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
    let mut res = SniffResult::bare(protocol);
    if pos + 2 > body.len() {
        return Some(res);
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos.saturating_add(ext_total_len).min(body.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let Some(ext_data) = body.get(pos..pos + ext_len) else {
            break;
        };
        pos += ext_len;
        if ext_type == 0x0000 && ext_data.len() >= 2 {
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
                    res.domain = Some(valid);
                    break;
                }
            }
        } else if ext_type == 0x0010 && ext_data.len() >= 3 {
            let proto_len = ext_data[2] as usize;
            if let Some(proto_bytes) = ext_data.get(3..3 + proto_len)
                && let Ok(proto_str) = std::str::from_utf8(proto_bytes)
            {
                res.alpn = Some(proto_str.to_owned());
            }
        }
    }
    Some(res)
}

const HTTP_METHODS: [&[u8]; 9] = [
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

fn sniff_http(buf: &[u8]) -> Sniffed {
    let mut partial = false;
    let mut matched = false;
    for method in HTTP_METHODS {
        match match_prefix(buf, method) {
            Prefix::Full => matched = true,
            Prefix::Partial => partial = true,
            Prefix::Mismatch => {}
        }
    }
    if !matched {
        return if partial {
            Sniffed::NeedMore
        } else {
            Sniffed::Miss
        };
    }
    let window = &buf[..buf.len().min(MAX_SNIFF_LEN)];
    let mut lines = window
        .split_inclusive(|&b| b == b'\n')
        .take_while(|line| line.ends_with(b"\n"))
        .map(|line| line.strip_suffix(b"\n").unwrap_or(line))
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let Some(request_line) = lines.next() else {
        return need_more_within_limit(buf);
    };
    let Ok(request_line) = std::str::from_utf8(request_line) else {
        return Sniffed::Miss;
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Sniffed::Miss;
    };
    if !version.starts_with("HTTP/1.") {
        return Sniffed::Miss;
    }
    let found = |domain: Option<String>| {
        Sniffed::Found(SniffResult {
            protocol: SniffProtocol::Http,
            domain,
            alpn: Some("http/1.1".into()),
            client: None,
        })
    };
    for line in lines {
        if line.is_empty() {
            return found(request_target_domain(method, target));
        }
        if let Ok(line) = std::str::from_utf8(line)
            && let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("host")
        {
            return found(normalize_domain(value));
        }
    }
    need_more_within_limit(buf)
}

fn request_target_domain(method: &str, target: &str) -> Option<String> {
    if method.eq_ignore_ascii_case("CONNECT") {
        return normalize_domain(target);
    }
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))?;
    normalize_domain(rest.split('/').next().unwrap_or(rest))
}

fn sniff_bittorrent_tcp(buf: &[u8]) -> Sniffed {
    match match_prefix(buf, b"\x13BitTorrent protocol") {
        Prefix::Full => Sniffed::Found(SniffResult::bare(SniffProtocol::Bittorrent)),
        Prefix::Partial => Sniffed::NeedMore,
        Prefix::Mismatch => Sniffed::Miss,
    }
}

fn sniff_ssh(buf: &[u8]) -> Sniffed {
    const PREFIX: &[u8] = b"SSH-2.0-";
    match match_prefix(buf, PREFIX) {
        Prefix::Mismatch => return Sniffed::Miss,
        Prefix::Partial => return Sniffed::NeedMore,
        Prefix::Full => {}
    }
    let window = &buf[..buf.len().min(SSH_MAX_BANNER)];
    let client = match window.iter().position(|&b| b == b'\n') {
        Some(end) => {
            let line = &window[PREFIX.len()..end];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            Some(String::from_utf8_lossy(line).into_owned())
        }
        None if buf.len() < SSH_MAX_BANNER => return Sniffed::NeedMore,
        None => None,
    };
    Sniffed::Found(SniffResult {
        client,
        ..SniffResult::bare(SniffProtocol::Ssh)
    })
}

/// TPKT + X.224 Connection Request。sing-box 只认 19 字节的纯 RDP Negotiation Request；
/// mstsc 首包带 `Cookie: mstshash=`，长度不定，故额外按 Cookie 前缀识别。
fn sniff_rdp(buf: &[u8]) -> Sniffed {
    const COOKIE: &[u8] = b"Cookie: msts";
    if !prefix_consistent(buf, &[0x03, 0x00]) {
        return Sniffed::Miss;
    }
    if buf.len() < 7 {
        return Sniffed::NeedMore;
    }
    let tpkt_len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if tpkt_len < 11 || usize::from(buf[4]) + 5 != tpkt_len || buf[5] != 0xe0 {
        return Sniffed::Miss;
    }
    if buf.len() < 11 {
        return Sniffed::NeedMore;
    }
    if buf[6..8] != [0, 0] {
        return Sniffed::Miss;
    }
    let payload = &buf[11..buf.len().min(tpkt_len)];
    if tpkt_len == 19 {
        if payload.len() < 3 {
            return Sniffed::NeedMore;
        }
        if payload[0] == 0x01 && payload[2] == 0x08 {
            return Sniffed::Found(SniffResult::bare(SniffProtocol::Rdp));
        }
    }
    match match_prefix(payload, COOKIE) {
        Prefix::Full => Sniffed::Found(SniffResult::bare(SniffProtocol::Rdp)),
        Prefix::Partial if payload.len() < tpkt_len - 11 => Sniffed::NeedMore,
        _ => Sniffed::Miss,
    }
}

fn prefix_consistent(buf: &[u8], magic: &[u8]) -> bool {
    !matches!(match_prefix(buf, magic), Prefix::Mismatch)
}

/// sing-box `dtls.go`：记录类型 20–23/25，版本 DTLS 1.0（0xfeff）或 1.2（0xfefd）。
fn is_dtls(packet: &[u8]) -> bool {
    packet.len() >= 13
        && matches!(packet[0], 20..=23 | 25)
        && packet[1] == 0xfe
        && matches!(packet[2], 0xff | 0xfd)
}

/// sing-box `stun.go`：RFC 5389 magic cookie 且声明长度不超过数据报。
fn is_stun(packet: &[u8]) -> bool {
    packet.len() >= 20
        && packet[4..8] == [0x21, 0x12, 0xa4, 0x42]
        && packet.len() >= 20 + usize::from(u16::from_be_bytes([packet[2], packet[3]]))
}

fn is_bittorrent_udp(packet: &[u8]) -> bool {
    is_utp(packet) || is_udp_tracker_connect(packet) || is_dht(packet)
}

/// sing-box `bittorrent.go` `UTP`（BEP 29）。
fn is_utp(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] & 0x0f != 1 || packet[0] >> 4 > 4 {
        return false;
    }
    let mut extension = packet[1];
    let mut pos = 20usize;
    while extension != 0 {
        let (Some(&next), Some(&len)) = (packet.get(pos), packet.get(pos + 1)) else {
            return false;
        };
        if next > 0x04 {
            return false;
        }
        extension = next;
        pos += 2 + usize::from(len);
    }
    true
}

/// sing-box `bittorrent.go` `UDPTracker`（BEP 15 connect 请求）。
fn is_udp_tracker_connect(packet: &[u8]) -> bool {
    packet.len() >= 16
        && packet[..8] == 0x0417_2710_1980u64.to_be_bytes()
        && packet[8..12] == [0, 0, 0, 0]
}

/// BEP 5 DHT KRPC：bencode 字典，首键按字典序为 `a`/`e`/`ip`/`r`，且带消息类型键 `y`。
/// sing-box 无此项，补上是为了让只走 DHT 的流量也命中 `bittorrent`。
fn is_dht(packet: &[u8]) -> bool {
    const FIRST_KEYS: [&[u8]; 4] = [b"d1:a", b"d1:e", b"d2:ip", b"d1:r"];
    packet.last() == Some(&b'e')
        && FIRST_KEYS.iter().any(|k| packet.starts_with(k))
        && packet.windows(5).any(|w| w == b"1:y1:")
}

#[derive(Default)]
struct QuicFlow {
    version: Option<u32>,
    keys: Vec<InitialKey>,
    authenticated: bool,
    crypto: Vec<u8>,
    /// 已收到的 CRYPTO 区间，按起点排序且互不重叠。
    ranges: Vec<(usize, usize)>,
}

struct InitialKey {
    dcid: Vec<u8>,
    keys: DirectionalKeys,
    largest_pn: Option<u64>,
}

impl InitialKey {
    fn derive(dcid: &[u8], version: Version) -> Option<Self> {
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()?
            .quic_suite()?;
        Some(Self {
            dcid: dcid.to_vec(),
            keys: suite.keys(dcid, Side::Server, version).remote,
            largest_pn: None,
        })
    }

    fn open(&mut self, packet: &[u8], pn_offset: usize) -> Option<Vec<u8>> {
        let (plain, pn) = open_initial(&self.keys, packet, pn_offset, self.largest_pn)?;
        self.largest_pn = Some(self.largest_pn.map_or(pn, |l| l.max(pn)));
        Some(plain)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LongKind {
    Initial,
    Retry,
    Other,
}

struct LongHeader<'a> {
    raw_version: u32,
    version: Version,
    kind: LongKind,
    dcid: &'a [u8],
    pn_offset: usize,
    end: usize,
}

fn parse_long_header(b: &[u8]) -> Option<LongHeader<'_>> {
    let first = *b.first()?;
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let raw_version = u32::from_be_bytes(b.get(1..5)?.try_into().ok()?);
    // RFC 9369 §3.2：QUIC v2 重排了长包头类型编号。
    let (version, initial, retry) = match raw_version {
        0x0000_0001 => (Version::V1, 0b00, 0b11),
        0x6b33_43cf => (Version::V2, 0b01, 0b00),
        0xff00_001d..=0xff00_0020 => (Version::V1Draft, 0b00, 0b11),
        _ => return None,
    };
    let ty = (first >> 4) & 0x03;
    let kind = if ty == initial {
        LongKind::Initial
    } else if ty == retry {
        LongKind::Retry
    } else {
        LongKind::Other
    };
    let mut cur = Cursor(&b[5..]);
    let dcid_len = usize::from(*cur.take(1)?.first()?);
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let dcid = cur.take(dcid_len)?;
    let scid_len = usize::from(*cur.take(1)?.first()?);
    if scid_len > 20 {
        return None;
    }
    cur.take(scid_len)?;
    if kind == LongKind::Retry {
        return Some(LongHeader {
            raw_version,
            version,
            kind,
            dcid,
            pn_offset: b.len(),
            end: b.len(),
        });
    }
    if kind == LongKind::Initial {
        let token_len = usize::try_from(cur.varint()?).ok()?;
        cur.take(token_len)?;
    }
    let length = usize::try_from(cur.varint()?).ok()?;
    let pn_offset = b.len() - cur.0.len();
    let end = pn_offset.checked_add(length)?;
    if end > b.len() {
        return None;
    }
    Some(LongHeader {
        raw_version,
        version,
        kind,
        dcid,
        pn_offset,
        end,
    })
}

/// 去除头部保护并解密一个 Initial 包，返回明文与完整包号。
fn open_initial(
    keys: &DirectionalKeys,
    packet: &[u8],
    pn_offset: usize,
    largest_pn: Option<u64>,
) -> Option<(Vec<u8>, u64)> {
    let sample_len = keys.header.sample_len();
    let sample_offset = pn_offset + 4;
    if sample_offset + sample_len > packet.len() {
        return None;
    }
    let mut buf = packet.to_vec();
    let sample = buf[sample_offset..sample_offset + sample_len].to_vec();
    let (head, rest) = buf.split_at_mut(pn_offset);
    keys.header
        .decrypt_in_place(&sample, &mut head[0], &mut rest[..4])
        .ok()?;
    let pn_len = usize::from(buf[0] & 0x03) + 1;
    let truncated = buf[pn_offset..pn_offset + pn_len]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let pn = decode_packet_number(largest_pn, truncated, pn_len);
    let (header, payload) = buf.split_at_mut(pn_offset + pn_len);
    let plain = keys.packet.decrypt_in_place(pn, header, payload).ok()?;
    Some((plain.to_vec(), pn))
}

/// RFC 9000 附录 A.3。
fn decode_packet_number(largest: Option<u64>, truncated: u64, pn_len: usize) -> u64 {
    let expected = largest.map_or(0, |l| l + 1);
    let window = 1u64 << (pn_len * 8);
    let half = window / 2;
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected && candidate < (1u64 << 62) - window {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    fn varint(&mut self) -> Option<u64> {
        let first = *self.0.first()?;
        let bytes = self.take(1usize << (first >> 6))?;
        Some(
            bytes[1..]
                .iter()
                .fold(u64::from(first & 0x3f), |acc, &b| (acc << 8) | u64::from(b)),
        )
    }
}

impl QuicFlow {
    fn push(&mut self, datagram: &[u8]) -> Sniffed {
        // 一个数据报可合并多个长包头包；短包头包没有长度字段，出现即占满剩余部分。
        let mut rest = datagram;
        let mut first = true;
        let mut rejected_initial = false;
        while let Some(&type_byte) = rest.first() {
            if type_byte & 0x80 == 0 {
                if first {
                    return Sniffed::Miss;
                }
                break;
            }
            let Some(header) = parse_long_header(rest) else {
                return Sniffed::Miss;
            };
            if self.version.is_some_and(|v| v != header.raw_version) {
                return Sniffed::Miss;
            }
            self.version = Some(header.raw_version);
            match header.kind {
                LongKind::Retry => break,
                LongKind::Other => {}
                LongKind::Initial => match self.open(&rest[..header.end], &header) {
                    Some(plain) => {
                        if self.read_frames(&plain).is_none() {
                            return Sniffed::Miss;
                        }
                    }
                    None => rejected_initial = true,
                },
            }
            rest = &rest[header.end..];
            first = false;
        }
        // 客户端首个 Initial 的密钥必由其自身 DCID 导出；从未认证成功却解密失败，说明并非 QUIC。
        if rejected_initial && !self.authenticated {
            return Sniffed::Miss;
        }
        let contiguous = self.ranges.first().filter(|r| r.0 == 0).map_or(0, |r| r.1);
        client_hello_verdict(&self.crypto[..contiguous], SniffProtocol::Quic)
            .unwrap_or(Sniffed::NeedMore)
    }

    /// Retry 会换 DCID 而不重置包号空间，最多保留两代 Initial 密钥（同 Mihomo）。
    fn open(&mut self, packet: &[u8], header: &LongHeader<'_>) -> Option<Vec<u8>> {
        if self.keys.is_empty() {
            self.keys
                .push(InitialKey::derive(header.dcid, header.version)?);
        }
        let mut has_current = false;
        let mut largest = None;
        for key in &mut self.keys {
            has_current |= key.dcid == header.dcid;
            largest = largest.max(key.largest_pn);
            if let Some(plain) = key.open(packet, header.pn_offset) {
                self.authenticated = true;
                return Some(plain);
            }
        }
        if has_current {
            return None;
        }
        let mut candidate = InitialKey::derive(header.dcid, header.version)?;
        candidate.largest_pn = largest;
        let plain = candidate.open(packet, header.pn_offset)?;
        self.authenticated = true;
        if self.keys.len() == 1 {
            self.keys.push(candidate);
        } else {
            self.keys[1] = candidate;
        }
        Some(plain)
    }

    /// RFC 9000 §17.2.2：Initial 包只允许 PADDING、PING、ACK、CRYPTO、CONNECTION_CLOSE。
    fn read_frames(&mut self, plain: &[u8]) -> Option<()> {
        let mut cur = Cursor(plain);
        while let Some(frame) = cur.take(1) {
            match frame[0] {
                0x00 | 0x01 => {}
                ty @ (0x02 | 0x03) => {
                    cur.varint()?;
                    cur.varint()?;
                    let ranges = cur.varint()?;
                    cur.varint()?;
                    for _ in 0..ranges {
                        cur.varint()?;
                        cur.varint()?;
                    }
                    if ty == 0x03 {
                        cur.varint()?;
                        cur.varint()?;
                        cur.varint()?;
                    }
                }
                0x06 => {
                    let offset = cur.varint()?;
                    let len = usize::try_from(cur.varint()?).ok()?;
                    let data = cur.take(len)?;
                    self.add_crypto(offset, data)?;
                }
                0x1c => {
                    cur.varint()?;
                    cur.varint()?;
                    let len = usize::try_from(cur.varint()?).ok()?;
                    cur.take(len)?;
                }
                _ => return None,
            }
        }
        Some(())
    }

    fn add_crypto(&mut self, offset: u64, data: &[u8]) -> Option<()> {
        if data.is_empty() {
            return Some(());
        }
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(data.len())?;
        if end > MAX_SNIFF_LEN {
            return None;
        }
        if self.crypto.len() < end {
            self.crypto.resize(end, 0);
        }
        self.crypto[start..end].copy_from_slice(data);
        self.ranges.push((start, end));
        self.ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.ranges.len());
        for &(s, e) in &self.ranges {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.ranges = merged;
        Some(())
    }
}

/// 解析 TLS 1.0–1.3 Record 中的完整 `ClientHello`，提取 SNI 与 ALPN。
pub fn sniff_tls_client_hello(buf: &[u8]) -> Option<SniffResult> {
    match sniff_tls(buf) {
        Sniffed::Found(res) => Some(res),
        Sniffed::NeedMore | Sniffed::Miss => None,
    }
}

/// 解析 HTTP/1.x 请求首包，从 `Host` 头或请求行绝对 URI 提取域名。
pub fn sniff_http_request(buf: &[u8]) -> Option<SniffResult> {
    match sniff_http(buf) {
        Sniffed::Found(res) => Some(res),
        Sniffed::NeedMore | Sniffed::Miss => None,
    }
}

/// 解析并解密单个 QUIC v1 / v2 Initial 数据报，提取内嵌 `ClientHello` 的 SNI。
pub fn sniff_quic_initial(packet: &[u8]) -> Option<SniffResult> {
    match UdpSniffer::new(&[SniffProtocol::Quic]).push(packet) {
        Sniffed::Found(res) => Some(res),
        Sniffed::NeedMore | Sniffed::Miss => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tls_client_hello_record(sni: &str) -> Vec<u8> {
        let host = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let list_len = (3 + host.len()) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        let hs_len = body.len() as u32;
        hs.extend_from_slice(&hs_len.to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
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

    #[test]
    fn tls_split_across_records_and_truncated() {
        let record = build_tls_client_hello_record("split.example.com");
        let hs = &record[5..];
        let mut split = Vec::new();
        for chunk in hs.chunks(7) {
            split.extend_from_slice(&[0x16, 0x03, 0x01]);
            split.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            split.extend_from_slice(chunk);
        }
        let Sniffed::Found(res) = sniff_tcp(&split, &[SniffProtocol::Tls]) else {
            panic!("split hello not found");
        };
        assert_eq!(res.domain.as_deref(), Some("split.example.com"));
        for cut in [0, 1, 4, 5, 9, record.len() - 1] {
            assert_eq!(
                sniff_tcp(&record[..cut], &[SniffProtocol::Tls]),
                Sniffed::NeedMore,
                "cut at {cut}"
            );
        }
    }

    fn push_quic_varint(buf: &mut Vec<u8>, val: usize) {
        if val < 64 {
            buf.push(val as u8);
        } else {
            buf.extend_from_slice(&(0x4000u16 | val as u16).to_be_bytes());
        }
    }

    fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        push_quic_varint(&mut frame, offset);
        push_quic_varint(&mut frame, data.len());
        frame.extend_from_slice(data);
        frame
    }

    fn build_initial(dcid: &[u8], pn: u8, mut plaintext: Vec<u8>) -> Vec<u8> {
        while plaintext.len() < 32 {
            plaintext.push(0x00);
        }
        let mut packet = vec![0xc0];
        packet.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(dcid);
        packet.push(0);
        packet.push(0);
        push_quic_varint(&mut packet, 1 + plaintext.len() + 16);
        let pn_offset = packet.len();
        packet.push(pn);

        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        let keys = suite.keys(dcid, Side::Client, Version::V1);
        let tag = keys
            .local
            .packet
            .encrypt_in_place(u64::from(pn), &packet, &mut plaintext)
            .unwrap();
        packet.extend_from_slice(&plaintext);
        packet.extend_from_slice(tag.as_ref());

        let sample_offset = pn_offset + 4;
        let sample = packet[sample_offset..sample_offset + keys.local.header.sample_len()].to_vec();
        let (head, rest) = packet.split_at_mut(pn_offset);
        keys.local
            .header
            .encrypt_in_place(&sample, &mut head[0], &mut rest[..1])
            .unwrap();
        packet
    }

    #[test]
    fn sniffs_quic_v1_initial_sni() {
        let record = build_tls_client_hello_record("quic.example.net");
        let packet = build_initial(&[1, 2, 3, 4, 5, 6, 7, 8], 1, crypto_frame(0, &record[5..]));
        let res = sniff_quic_initial(&packet).unwrap();
        assert_eq!(res.protocol, SniffProtocol::Quic);
        assert_eq!(res.domain.as_deref(), Some("quic.example.net"));
    }

    #[test]
    fn quic_reassembles_out_of_order_crypto_across_packets() {
        let record = build_tls_client_hello_record("reorder.example.net");
        let hs = &record[5..];
        let (a, rest) = hs.split_at(20);
        let (b, c) = rest.split_at(15);
        let dcid = [9u8; 8];
        let mut later = crypto_frame(35, c);
        later.extend_from_slice(&crypto_frame(20, b));
        let first = build_initial(&dcid, 0, later);
        let second = build_initial(&dcid, 1, crypto_frame(0, a));

        let mut sniffer = UdpSniffer::new(&SniffProtocol::ALL);
        assert_eq!(sniffer.push(&first), Sniffed::NeedMore);
        let Sniffed::Found(res) = sniffer.push(&second) else {
            panic!("reassembly failed");
        };
        assert_eq!(res.domain.as_deref(), Some("reorder.example.net"));
        assert_eq!(sniffer.push(b"anything"), Sniffed::Found(res));
    }

    #[test]
    fn decodes_packet_numbers_per_rfc9000_a3() {
        assert_eq!(
            decode_packet_number(Some(0xa82f30ea), 0x9b32, 2),
            0xa82f9b32
        );
        assert_eq!(decode_packet_number(None, 1, 1), 1);
        assert_eq!(decode_packet_number(Some(254), 0, 1), 256);
    }
}
