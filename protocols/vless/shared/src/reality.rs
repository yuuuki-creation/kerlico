//! REALITY session id inside a TLS ClientHello.
//!
//! Authentication binds the session ID to the complete ClientHello handshake message.

use crate::encrypt::checked_x25519;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn auth_key(shared: &[u8], random: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&random[..20]), shared)
        .expand(b"REALITY", &mut key)
        .expect("hkdf");
    key
}

pub fn seal_session(
    key: &[u8; 32],
    hello: &[u8],
    random: &[u8; 32],
    plain: &[u8; 16],
) -> Option<[u8; 32]> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&random[20..]),
            Payload {
                msg: plain,
                aad: hello,
            },
        )
        .ok()?;
    sealed.try_into().ok()
}

pub fn open_session(
    key: &[u8; 32],
    hello: &[u8],
    random: &[u8; 32],
    sealed: &[u8; 32],
) -> Option<[u8; 16]> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&random[20..]),
            Payload {
                msg: sealed,
                aad: hello,
            },
        )
        .ok()?;
    plain.try_into().ok()
}

pub fn reality_pair() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).expect("random");
    let secret = x25519_dalek::StaticSecret::from(secret);
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    (secret.to_bytes(), public)
}

pub fn reality_offer(
    server_public: &[u8; 32],
    short_id: &[u8; 8],
    server_name: &str,
) -> std::io::Result<(Vec<u8>, [u8; 32])> {
    let (secret, public) = ephemeral();
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|error| std::io::Error::other(error.to_string()))?;
    let alpn = encode_alpn(&["h2", "http/1.1"])?;
    let handshake = handshake_message(
        &random,
        &classical_share(&public),
        false,
        server_name,
        &alpn,
    );
    let record = seal_hello(handshake, server_public, &secret, short_id, &random)?;
    Ok((record, secret.to_bytes()))
}

pub fn reality_offer_hybrid(
    server_public: &[u8; 32],
    short_id: &[u8; 8],
    server_name: &str,
) -> std::io::Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
    reality_offer_hybrid_with_alpn(server_public, short_id, server_name, &["h2", "http/1.1"])
}

pub fn reality_offer_hybrid_with_alpn<P: AsRef<str>>(
    server_public: &[u8; 32],
    short_id: &[u8; 8],
    server_name: &str,
    protocols: &[P],
) -> io::Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
    let (kem_secret, kem_public) = kem_keypair()?;
    let (secret, public) = ephemeral();
    let mut share = kem_public;
    share.extend_from_slice(&public);
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|error| std::io::Error::other(error.to_string()))?;
    let alpn = encode_alpn(protocols)?;
    let handshake = handshake_message(
        &random,
        &hybrid_share(&share, &public),
        true,
        server_name,
        &alpn,
    );
    let record = seal_hello(handshake, server_public, &secret, short_id, &random)?;
    Ok((record, secret.to_bytes(), kem_secret))
}

pub struct RealityOffer {
    pub record: Vec<u8>,
    pub(crate) x25519: [u8; 32],
    kem: Vec<u8>,
    curves: std::collections::HashMap<u16, boring2::pkey::PKey<boring2::pkey::Private>>,
}

pub fn reality_offer_fingerprint(
    server_public: &[u8; 32],
    short_id: &[u8; 8],
    name: &str,
    protocols: &[String],
    fingerprint: &str,
) -> io::Result<RealityOffer> {
    use boring2::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
        pkey::PKey,
    };
    let profile = crate::advanced_tls::fingerprint::resolve(fingerprint)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY requires a ClientHello fingerprint",
        )
    })?;
    let offered = profile
        .extensions
        .iter()
        .find(|extension| extension.id == 51)
        .ok_or_else(invalid_hello)?;
    if !offered
        .shares
        .iter()
        .any(|&(group, _)| matches!(group, 0x001d | 0x11ec))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY fingerprint requires X25519 or X25519MLKEM768",
        ));
    }
    let (secret, public) = ephemeral();
    let (kem, kem_public) = kem_keypair()?;
    let mut curves = std::collections::HashMap::new();
    let mut random = [0; 32];
    getrandom::getrandom(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
    let hello = crate::advanced_tls::fingerprint::reality_hello(
        &profile,
        &random,
        name,
        protocols,
        |group| match group {
            0x001d => Ok(public.to_vec()),
            0x11ec => {
                let mut share = kem_public.clone();
                share.extend_from_slice(&public);
                Ok(share)
            }
            23 | 24 | 25 => {
                let nid = match group {
                    23 => Nid::X9_62_PRIME256V1,
                    24 => Nid::SECP384R1,
                    _ => Nid::SECP521R1,
                };
                let curve = EcGroup::from_curve_name(nid).map_err(io::Error::other)?;
                let key = EcKey::generate(&curve).map_err(io::Error::other)?;
                let mut context = BigNumContext::new().map_err(io::Error::other)?;
                let public = key
                    .public_key()
                    .to_bytes(&curve, PointConversionForm::UNCOMPRESSED, &mut context)
                    .map_err(io::Error::other)?;
                curves.insert(group, PKey::from_ec_key(key).map_err(io::Error::other)?);
                Ok(public)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported REALITY key share",
            )),
        },
    )?;
    Ok(RealityOffer {
        record: seal_hello(hello, server_public, &secret, short_id, &random)?,
        x25519: secret.to_bytes(),
        kem,
        curves,
    })
}

impl RealityOffer {
    pub(crate) fn shared(&self, group: u16, share: &[u8]) -> io::Result<Vec<u8>> {
        use boring2::{
            bn::BigNumContext,
            derive::Deriver,
            ec::{EcKey, EcPoint},
            pkey::PKey,
        };
        if let Some(private) = self.curves.get(&group) {
            let key = private.ec_key().map_err(io::Error::other)?;
            let mut context = BigNumContext::new().map_err(io::Error::other)?;
            let point =
                EcPoint::from_bytes(key.group(), share, &mut context).map_err(io::Error::other)?;
            let public = PKey::from_ec_key(
                EcKey::from_public_key(key.group(), &point).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
            let mut derive = Deriver::new(private).map_err(io::Error::other)?;
            derive.set_peer(&public).map_err(io::Error::other)?;
            derive.derive_to_vec().map_err(io::Error::other)
        } else {
            crate::reality_tls::traffic_shared(&self.x25519, Some(&self.kem), group, share)
        }
    }
}

fn ephemeral() -> (x25519_dalek::StaticSecret, [u8; 32]) {
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes).expect("random");
    let secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    (secret, public)
}

fn seal_hello(
    mut handshake: Vec<u8>,
    server_public: &[u8; 32],
    secret: &x25519_dalek::StaticSecret,
    short_id: &[u8; 8],
    random: &[u8; 32],
) -> std::io::Result<Vec<u8>> {
    let shared = checked_x25519(secret, &x25519_dalek::PublicKey::from(*server_public))
        .ok_or_else(invalid_hello)?;
    let mut plain = [0u8; 16];
    plain[..3].copy_from_slice(&[26, 10, 31]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| std::io::Error::other(error.to_string()))?
        .as_secs() as u32;
    plain[4..8].copy_from_slice(&now.to_be_bytes());
    plain[8..].copy_from_slice(short_id);
    let key = auth_key(&shared, random);
    let sealed = seal_session(&key, &handshake, random, &plain)
        .ok_or_else(|| std::io::Error::other("reality"))?;
    handshake[39..71].copy_from_slice(&sealed);
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.extend_from_slice(&[22, 3, 1]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(record)
}

fn classical_share(share: &[u8; 32]) -> Vec<u8> {
    key_share_body(&[(0x001d, share)])
}

fn hybrid_share(share: &[u8], classical: &[u8; 32]) -> Vec<u8> {
    key_share_body(&[(0x11ec, share), (0x001d, classical)])
}

fn key_share_body(shares: &[(u16, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    list.extend_from_slice(&0x0a0au16.to_be_bytes());
    list.extend_from_slice(&32u16.to_be_bytes());
    list.extend_from_slice(&[0u8; 32]);
    for (group, share) in shares {
        list.extend_from_slice(&group.to_be_bytes());
        list.extend_from_slice(&(share.len() as u16).to_be_bytes());
        list.extend_from_slice(share);
    }
    let mut body = Vec::new();
    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
    body.extend(list);
    body
}

fn kem_keypair() -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    use ml_kem::{EncodedSizeUser, KemCore};
    let mut rng = rand_core::OsRng;
    let (secret, public) = ml_kem::MlKem768::generate(&mut rng);
    Ok((secret.as_bytes().to_vec(), public.as_bytes().to_vec()))
}

pub fn reality_hello(
    server_public: &[u8; 32],
    short_id: &[u8; 8],
    server_name: &str,
) -> std::io::Result<Vec<u8>> {
    Ok(reality_offer(server_public, short_id, server_name)?.0)
}

pub fn reality_accept(record: &[u8], private: &[u8; 32], short_id: &[u8; 8]) -> bool {
    reality_accept_with_policy(record, private, &RealityPolicy::single_id(*short_id))
}

#[derive(Clone, Debug, Default)]
pub struct RealityPolicy {
    pub server_names: Vec<String>,
    pub short_ids: Vec<[u8; 8]>,
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    pub max_time_diff: Option<Duration>,
}

impl RealityPolicy {
    pub fn single_id(short_id: [u8; 8]) -> Self {
        Self {
            short_ids: vec![short_id],
            max_time_diff: Some(Duration::from_secs(60)),
            ..Self::default()
        }
    }
}

pub fn decode_reality_version(text: &str) -> Option<[u8; 3]> {
    let mut version = [0; 3];
    for (index, segment) in text.split('.').enumerate() {
        *version.get_mut(index)? = segment.parse::<u8>().ok()?;
    }
    Some(version)
}

pub fn reality_accept_with_policy(
    record: &[u8],
    private: &[u8; 32],
    policy: &RealityPolicy,
) -> bool {
    authenticate_hello(record, private, policy).is_some()
}

pub(crate) fn authenticate_hello<'a>(
    record: &'a [u8],
    private: &[u8; 32],
    policy: &RealityPolicy,
) -> Option<(&'a [u8], [u8; 32])> {
    if record.len() < 5 + 71 || record[0] != 22 {
        return None;
    }
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() != 5 + len {
        return None;
    }
    let handshake = &record[5..];
    if !policy.server_names.is_empty() {
        let sni = client_server_name(handshake)?.unwrap_or("");
        if !policy.server_names.iter().any(|name| name == sni) {
            return None;
        }
    }
    let share = client_share(handshake)?;
    let mut aad = handshake.to_vec();
    let sealed = handshake[39..71].try_into().ok()?;
    aad[39..71].fill(0);
    let random = handshake[6..38].try_into().ok()?;
    let secret = x25519_dalek::StaticSecret::from(*private);
    let shared = checked_x25519(&secret, &x25519_dalek::PublicKey::from(share))?;
    let key = auth_key(&shared, &random);
    let plain = open_session(&key, &aad, &random, &sealed)?;
    let short_id: [u8; 8] = plain[8..].try_into().ok()?;
    let version: [u8; 3] = plain[..3].try_into().ok()?;
    if !policy.short_ids.contains(&short_id)
        || policy.min_client_ver.is_some_and(|min| version < min)
        || policy.max_client_ver.is_some_and(|max| version > max)
    {
        return None;
    }
    if let Some(max) = policy.max_time_diff.filter(|max| !max.is_zero()) {
        let stamp = u32::from_be_bytes(plain[4..8].try_into().ok()?) as u128 * 1000;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis();
        if stamp.abs_diff(now) > max.as_millis() {
            return None;
        }
    }
    Some((handshake, key))
}

pub fn read_tls_record<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    read_client_hello(reader).map(|(record, _)| record)
}

/// Returns the canonical ClientHello record and the original wire records for fallback.
pub fn read_client_hello<R: Read>(reader: &mut R) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let (handshake, wire) = read_plain_handshake(reader, 1)?;
    let mut record = wire[..3].to_vec();
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok((record, wire))
}

pub(crate) fn read_plain_handshake<R: Read>(
    reader: &mut R,
    kind: u8,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut wire = Vec::new();
    let mut handshake = Vec::new();
    loop {
        let mut header = [0u8; 5];
        reader.read_exact(&mut header)?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 22
            || header[1] != 3
            || !(1..=3).contains(&header[2])
            || !(1..=16384).contains(&len)
        {
            return Err(invalid_hello());
        }
        let offset = handshake.len();
        if offset + len > u16::MAX as usize {
            return Err(invalid_hello());
        }
        handshake.resize(offset + len, 0);
        reader.read_exact(&mut handshake[offset..])?;
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&handshake[offset..]);
        if handshake[0] != kind {
            return Err(invalid_hello());
        }
        if handshake.len() >= 4 {
            let end = 4 + u24(&handshake[1..4]);
            if end > u16::MAX as usize || handshake.len() > end {
                return Err(invalid_hello());
            }
            if handshake.len() == end {
                return Ok((handshake, wire));
            }
        }
    }
}

pub(crate) fn u24(bytes: &[u8]) -> usize {
    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize
}

fn invalid_hello() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "reality hello")
}

pub fn decode_reality_key(text: &str) -> Option<[u8; 32]> {
    let bytes = b64(text)?;
    bytes.try_into().ok()
}

pub fn decode_short_id(text: &str) -> Option<[u8; 8]> {
    if text.is_empty() {
        return Some([0; 8]);
    }
    if text.len() > 16 || text.len() % 2 != 0 {
        return None;
    }
    let mut out = [0u8; 8];
    let bytes = text.len() / 2;
    for index in 0..bytes {
        out[index] = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn encode_reality_key(key: &[u8; 32]) -> String {
    encode_base64(key)
}

pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in bytes {
        acc = (acc << 8) | *byte as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ALPH[(acc >> bits) as usize & 63] as char);
        }
    }
    if bits > 0 {
        out.push(ALPH[(acc << (6 - bits)) as usize & 63] as char);
    }
    out
}

fn encode_alpn<P: AsRef<str>>(protocols: &[P]) -> io::Result<Vec<u8>> {
    let mut list = vec![0, 0];
    for protocol in protocols {
        let bytes = protocol.as_ref().as_bytes();
        if bytes.is_empty() || bytes.len() > 255 || list.len() + 1 + bytes.len() > 4096 {
            return Err(invalid_hello());
        }
        list.push(bytes.len() as u8);
        list.extend_from_slice(bytes);
    }
    let len = (list.len() - 2) as u16;
    list[..2].copy_from_slice(&len.to_be_bytes());
    Ok(list)
}

fn handshake_message(
    random: &[u8; 32],
    key_share: &[u8],
    hybrid: bool,
    server_name: &str,
    alpn: &[u8],
) -> Vec<u8> {
    let mut hs = vec![1, 0, 0, 0, 3, 3];
    hs.extend_from_slice(random);
    hs.push(32);
    hs.extend_from_slice(&[0u8; 32]);
    let suites: [u16; 16] = [
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ];
    hs.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for suite in suites {
        hs.extend_from_slice(&suite.to_be_bytes());
    }
    hs.push(1);
    hs.push(0);
    let ext_at = hs.len();
    hs.extend_from_slice(&[0, 0]);
    let ext_start = hs.len();
    push_ext(&mut hs, 0x0a0a, &[0]);
    if !server_name.is_empty() {
        let name = server_name.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&((1 + 2 + name.len()) as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        body.extend_from_slice(name);
        push_ext(&mut hs, 0, &body);
    }
    push_ext(&mut hs, 0x0017, &[]);
    push_ext(&mut hs, 0xff01, &[0]);
    let groups: &[u8] = if hybrid {
        &[
            0, 10, 0x0a, 0x0a, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
        ]
    } else {
        &[0, 8, 0x0a, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]
    };
    push_ext(&mut hs, 0x000a, groups);
    push_ext(&mut hs, 0x000b, &[1, 0]);
    push_ext(&mut hs, 0x0023, &[]);
    if alpn.len() > 2 {
        push_ext(&mut hs, 0x0010, alpn);
    }
    push_ext(&mut hs, 0x0005, &[1, 0, 0, 0, 0]);
    push_ext(
        &mut hs,
        0x000d,
        &[
            0, 18, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08,
            0x06, 0x06, 0x01, 0x08, 0x07,
        ],
    );
    push_ext(&mut hs, 0x0012, &[]);
    push_ext(&mut hs, 0x0033, key_share);
    push_ext(&mut hs, 0x002d, &[1, 1]);
    push_ext(&mut hs, 0x002b, &[6, 0x0a, 0x0a, 3, 4, 3, 3]);
    push_ext(&mut hs, 0x4469, &[0, 5, 2, b'h', b'2', 0, 0]);
    push_ext(&mut hs, 0x1a1a, &[0]);
    finish_hello(&mut hs, ext_at, ext_start);
    let record_len = 5 + hs.len();
    if record_len < 512 {
        let need = 512 - record_len;
        let body = if need > 4 { need - 4 } else { 0 };
        push_ext(&mut hs, 0x0015, &vec![0u8; body]);
        finish_hello(&mut hs, ext_at, ext_start);
    }
    hs
}

fn finish_hello(hs: &mut [u8], ext_at: usize, ext_start: usize) {
    let ext_len = (hs.len() - ext_start) as u16;
    hs[ext_at..ext_at + 2].copy_from_slice(&ext_len.to_be_bytes());
    let msg_len = (hs.len() - 4) as u32;
    hs[1] = (msg_len >> 16) as u8;
    hs[2] = (msg_len >> 8) as u8;
    hs[3] = msg_len as u8;
}

fn push_ext(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

pub(crate) enum ClientKem {
    X25519([u8; 32]),
    Hybrid { kem: Vec<u8>, x25519: [u8; 32] },
}

pub(crate) fn client_share(handshake: &[u8]) -> Option<[u8; 32]> {
    let shares = key_shares(handshake)?;
    if let Some((_, key)) = shares
        .iter()
        .find(|(group, key)| *group == 0x001d && key.len() == 32)
    {
        return key.as_slice().try_into().ok();
    }
    if let Some((_, key)) = shares
        .iter()
        .find(|(group, key)| *group == 0x11ec && key.len() == 1216)
    {
        return key[1184..].try_into().ok();
    }
    None
}

pub(crate) fn client_kem(handshake: &[u8]) -> Option<ClientKem> {
    client_kem_for_group(handshake, 0x11ec).or_else(|| client_kem_for_group(handshake, 0x001d))
}

pub(crate) fn client_kem_for_group(handshake: &[u8], selected: u16) -> Option<ClientKem> {
    let shares = key_shares(handshake)?;
    if let Some((_, key)) = shares
        .iter()
        .find(|(group, key)| selected == 0x11ec && *group == selected && key.len() == 1216)
    {
        let mut x25519 = [0u8; 32];
        x25519.copy_from_slice(&key[1184..]);
        return Some(ClientKem::Hybrid {
            kem: key[..1184].to_vec(),
            x25519,
        });
    }
    if let Some((_, key)) = shares
        .iter()
        .find(|(group, key)| selected == 0x001d && *group == selected && key.len() == 32)
    {
        return Some(ClientKem::X25519(key.as_slice().try_into().ok()?));
    }
    None
}

pub(crate) fn client_suites(handshake: &[u8]) -> Option<&[u8]> {
    if handshake.len() < 73
        || handshake[0] != 1
        || handshake[38] != 32
        || u24(&handshake[1..4]) + 4 != handshake.len()
    {
        return None;
    }
    let suites = u16::from_be_bytes([handshake[71], handshake[72]]) as usize;
    if suites == 0 || suites % 2 != 0 {
        return None;
    }
    handshake.get(73..73 + suites)
}

pub(crate) fn client_extensions(handshake: &[u8]) -> Option<&[u8]> {
    let mut index = 73 + client_suites(handshake)?.len();
    let methods = *handshake.get(index)? as usize;
    index += 1 + methods;
    let ext_len = u16::from_be_bytes([*handshake.get(index)?, *handshake.get(index + 1)?]) as usize;
    index += 2;
    let extensions = handshake.get(index..)?;
    (extensions.len() == ext_len).then_some(extensions)
}

pub(crate) fn client_alpn(handshake: &[u8]) -> Option<Vec<&[u8]>> {
    let mut extensions = client_extensions(handshake)?;
    let mut alpn = None;
    while !extensions.is_empty() {
        let header = extensions.get(..4)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let (body, rest) = extensions[4..].split_at_checked(len)?;
        if kind == 0x0010 {
            if alpn.is_some() {
                return None;
            }
            alpn = Some(alpn_protocols(body)?);
        }
        extensions = rest;
    }
    Some(alpn.unwrap_or_default())
}

fn client_server_name(handshake: &[u8]) -> Option<Option<&str>> {
    let mut extensions = client_extensions(handshake)?;
    let mut name = None;
    let mut seen = false;
    while !extensions.is_empty() {
        let header = extensions.get(..4)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let (body, rest) = extensions[4..].split_at_checked(len)?;
        if kind == 0 {
            if seen
                || body.len() < 2
                || u16::from_be_bytes([body[0], body[1]]) as usize != body.len() - 2
            {
                return None;
            }
            seen = true;
            let mut names = &body[2..];
            while !names.is_empty() {
                let head = names.get(..3)?;
                let len = u16::from_be_bytes([head[1], head[2]]) as usize;
                let (value, remaining) = names[3..].split_at_checked(len)?;
                if head[0] == 0 {
                    if name.is_some() || value.is_empty() {
                        return None;
                    }
                    name = Some(std::str::from_utf8(value).ok()?);
                }
                names = remaining;
            }
        }
        extensions = rest;
    }
    Some(name)
}

pub(crate) fn alpn_protocols(body: &[u8]) -> Option<Vec<&[u8]>> {
    let len = u16::from_be_bytes(body.get(..2)?.try_into().ok()?) as usize;
    let mut bytes = body.get(2..)?;
    if bytes.len() != len || len == 0 {
        return None;
    }
    let mut list = Vec::new();
    while let Some((&len, rest)) = bytes.split_first() {
        if len == 0 {
            return None;
        }
        let (protocol, remaining) = rest.split_at_checked(len as usize)?;
        list.push(protocol);
        bytes = remaining;
    }
    Some(list)
}

fn key_shares(handshake: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    let handshake = client_extensions(handshake)?;
    let mut index = 0;
    let end = handshake.len();
    let mut found = Vec::new();
    while index + 4 <= end {
        let kind = u16::from_be_bytes([handshake[index], handshake[index + 1]]);
        let len = u16::from_be_bytes([handshake[index + 2], handshake[index + 3]]) as usize;
        index += 4;
        if index + len > end {
            return None;
        }
        if kind == 0x0033 && len >= 2 {
            let shares = u16::from_be_bytes([handshake[index], handshake[index + 1]]) as usize;
            let mut cursor = index + 2;
            let limit = index + 2 + shares;
            if limit != index + len {
                return None;
            }
            while cursor + 4 <= limit {
                let group = u16::from_be_bytes([handshake[cursor], handshake[cursor + 1]]);
                let key_len =
                    u16::from_be_bytes([handshake[cursor + 2], handshake[cursor + 3]]) as usize;
                cursor += 4;
                if cursor + key_len > limit {
                    return None;
                }
                found.push((group, handshake[cursor..cursor + key_len].to_vec()));
                cursor += key_len;
            }
            if cursor != limit {
                return None;
            }
        }
        index += len;
    }
    (index == end).then_some(found)
}

pub(crate) fn b64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_policy_checks_sni_short_id_version_and_skew() {
        let (private, public) = reality_pair();
        let short_id = [9; 8];
        let (mut hello, secret) = reality_offer(&public, &short_id, "example.com").unwrap();
        let mut policy = RealityPolicy {
            server_names: vec!["other.example".into(), "example.com".into()],
            short_ids: vec![[0; 8], short_id],
            min_client_ver: decode_reality_version("26.10.31"),
            max_client_ver: decode_reality_version("26.10.31"),
            max_time_diff: Some(Duration::from_secs(300)),
        };
        assert!(reality_accept_with_policy(&hello, &private, &policy));
        policy.server_names[1] = "Example.com".into();
        assert!(!reality_accept_with_policy(&hello, &private, &policy));
        policy.server_names[1] = "example.com".into();
        policy.short_ids.pop();
        assert!(!reality_accept_with_policy(&hello, &private, &policy));
        policy.short_ids.push(short_id);
        policy.max_client_ver = decode_reality_version("26.10.30");
        assert!(!reality_accept_with_policy(&hello, &private, &policy));
        policy.max_client_ver = None;
        policy.min_client_ver = decode_reality_version("26.10.32");
        assert!(!reality_accept_with_policy(&hello, &private, &policy));
        policy.min_client_ver = None;

        let random: [u8; 32] = hello[11..43].try_into().unwrap();
        let secret = x25519_dalek::StaticSecret::from(secret);
        let shared = checked_x25519(&secret, &x25519_dalek::PublicKey::from(public)).unwrap();
        let auth = auth_key(&shared, &random);
        let sealed: [u8; 32] = hello[44..76].try_into().unwrap();
        hello[44..76].fill(0);
        let mut plain = open_session(&auth, &hello[5..], &random, &sealed).unwrap();
        let stamp = u32::from_be_bytes(plain[4..8].try_into().unwrap()) - 600;
        plain[4..8].copy_from_slice(&stamp.to_be_bytes());
        let sealed = seal_session(&auth, &hello[5..], &random, &plain).unwrap();
        hello[44..76].copy_from_slice(&sealed);
        assert!(!reality_accept_with_policy(&hello, &private, &policy));
        policy.max_time_diff = Some(Duration::ZERO);
        assert!(reality_accept_with_policy(&hello, &private, &policy));
        assert_eq!(decode_reality_version("26.10"), Some([26, 10, 0]));
        assert!(decode_reality_version("26.10.256").is_none());
        assert!(decode_reality_version("26.10.1.0").is_none());
    }

    #[test]
    fn malformed_and_low_order_hellos_are_rejected() {
        for len in [71, 72] {
            let mut record = vec![22, 3, 1, 0, len as u8];
            record.resize(5 + len, 0);
            record[5] = 1;
            record[8] = (len - 4) as u8;
            record[43] = 32;
            assert!(!reality_accept(&record, &[7; 32], &[0; 8]));
        }

        let random = [3; 32];
        let mut hello = handshake_message(
            &random,
            &classical_share(&[0; 32]),
            false,
            "example.com",
            &[0, 0],
        );
        let mut plain = [0; 16];
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        plain[4..8].copy_from_slice(&seconds.to_be_bytes());
        let sealed = seal_session(&auth_key(&[0; 32], &random), &hello, &random, &plain).unwrap();
        hello[39..71].copy_from_slice(&sealed);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        assert!(!reality_accept(&record, &[7; 32], &[0; 8]));
    }

    #[test]
    fn client_hello_spans_records_without_losing_wire_prefix() {
        let (private, public) = reality_pair();
        let short_id = [9; 8];
        let hello = reality_hello(&public, &short_id, "example.com").unwrap();
        let mut wire = Vec::new();
        for fragment in hello[5..].chunks(37) {
            wire.extend_from_slice(&[22, 3, 1, 0, fragment.len() as u8]);
            wire.extend_from_slice(fragment);
        }
        let (canonical, prefix) = read_client_hello(&mut wire.as_slice()).unwrap();
        assert_eq!(canonical, hello);
        assert_eq!(prefix, wire);
        assert!(reality_accept(&canonical, &private, &short_id));
    }

    #[test]
    fn session_id_seals_the_first_half() {
        let shared = [9u8; 32];
        let random = [4u8; 32];
        let key = auth_key(&shared, &random);
        let mut hello = vec![0u8; 80];
        hello[..32].copy_from_slice(&random);
        let mut plain = [0u8; 16];
        plain[8..].copy_from_slice(b"shortid!");
        let sealed = seal_session(&key, &hello, &random, &plain).unwrap();
        assert_ne!(&sealed[..16], &plain);
        let opened = open_session(&key, &hello, &random, &sealed).unwrap();
        assert_eq!(opened, plain);
        hello[70] ^= 1;
        assert!(open_session(&key, &hello, &random, &sealed).is_none());
    }

    #[test]
    fn client_hello_opens_with_the_server_key() {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let secret = x25519_dalek::StaticSecret::from(secret);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let record = reality_hello(&public, &short_id, "www.example.com").unwrap();
        assert!(reality_accept(&record, &secret.to_bytes(), &short_id));
        assert!(!reality_accept(&record, &secret.to_bytes(), &[0; 8]));
        assert!(record.len() >= 512);
        assert!(record.windows(2).any(|bytes| bytes == b"h2"));
    }
}
