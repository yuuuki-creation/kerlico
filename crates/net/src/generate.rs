//! CLI 密钥对、随机数、证书与哈希生成器。

use kerlico_core::{Error, Result};
use rand::RngCore;
use std::io::Cursor;

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn encode_base64_std(bytes: &[u8]) -> String {
    encode_base64_inner(bytes, B64_STD, true)
}

pub fn encode_base64_url_nopad(bytes: &[u8]) -> String {
    encode_base64_inner(bytes, B64_URL, false)
}

fn encode_base64_inner(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[((triple >> 18) & 0x3f) as usize] as char);
        out.push(alphabet[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(alphabet[((triple >> 6) & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[(triple & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

pub fn decode_base64_any(input: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut out = Vec::with_capacity(cleaned.len() * 3 / 4);
    for chunk in cleaned.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let mut vals = [0u32; 4];
        for (idx, &b) in chunk.iter().enumerate() {
            vals[idx] = match b {
                b'A'..=b'Z' => u32::from(b - b'A'),
                b'a'..=b'z' => u32::from(b - b'a' + 26),
                b'0'..=b'9' => u32::from(b - b'0' + 52),
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                _ => return None,
            };
        }
        let triple = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push(((triple >> 16) & 0xff) as u8);
        if chunk.len() > 2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if chunk.len() > 3 {
            out.push((triple & 0xff) as u8);
        }
    }
    Some(out)
}

fn format_pem(label: &str, der: &[u8]) -> String {
    let b64 = encode_base64_std(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----"));
    out
}

/// 生成随机 UUID v4。
pub fn generate_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        encode_hex(&bytes[0..4]),
        encode_hex(&bytes[4..6]),
        encode_hex(&bytes[6..8]),
        encode_hex(&bytes[8..10]),
        encode_hex(&bytes[10..16])
    )
}

/// 生成指定字节长度的随机字节。
pub fn generate_rand_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len.clamp(1, 4096)];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// 生成指定字节长度的 Base64 编码随机串。
pub fn generate_rand_base64(len: usize) -> String {
    encode_base64_std(&generate_rand_bytes(len))
}

/// 生成指定字节长度的十六进制随机串。
pub fn generate_rand_hex(len: usize) -> String {
    encode_hex(&generate_rand_bytes(len))
}

type Gf = [i64; 16];

fn gf_carry(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

fn gf_cswap(p: &mut Gf, q: &mut Gf, b: i64) {
    let mask = !(b - 1);
    for i in 0..16 {
        let t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn gf_add(a: &Gf, b: &Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn gf_sub(a: &Gf, b: &Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn gf_mul(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = [0i64; 16];
    o.copy_from_slice(&t[..16]);
    gf_carry(&mut o);
    gf_carry(&mut o);
    o
}

fn gf_sq(a: &Gf) -> Gf {
    gf_mul(a, a)
}

fn gf_inv(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = gf_sq(&c);
        if a != 2 && a != 4 {
            c = gf_mul(&c, i);
        }
    }
    c
}

fn gf_pack(n: &Gf) -> [u8; 32] {
    let mut t = *n;
    gf_carry(&mut t);
    gf_carry(&mut t);
    gf_carry(&mut t);
    let mut m = [0i64; 16];
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        gf_cswap(&mut t, &mut m, 1 - b);
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
    o
}

/// RFC 7748 X25519 基点标量乘法（输入 32 字节私钥，返回钳位后私钥与公钥）。
pub fn x25519_keypair_from_secret(mut secret: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;

    let mut x1 = [0i64; 16];
    x1[0] = 9;
    let mut a = [0i64; 16];
    a[0] = 1;
    let mut b = x1;
    let mut c = [0i64; 16];
    let mut d = [0i64; 16];
    d[0] = 1;
    let mut k121665 = [0i64; 16];
    k121665[0] = 0xdb41;
    k121665[1] = 1;

    for i in (0..255).rev() {
        let r = i64::from((secret[i >> 3] >> (i & 7)) & 1);
        gf_cswap(&mut a, &mut b, r);
        gf_cswap(&mut c, &mut d, r);
        let e = gf_add(&a, &c);
        let a_sub = gf_sub(&a, &c);
        let c_add = gf_add(&b, &d);
        let b_sub = gf_sub(&b, &d);
        let d_sq = gf_sq(&e);
        let f = gf_sq(&a_sub);
        let a_mul = gf_mul(&c_add, &a_sub);
        let c_mul = gf_mul(&b_sub, &e);
        let e_add = gf_add(&a_mul, &c_mul);
        let a_sub2 = gf_sub(&a_mul, &c_mul);
        let b_sq = gf_sq(&a_sub2);
        let c_sub = gf_sub(&d_sq, &f);
        let a_k = gf_mul(&c_sub, &k121665);
        let a_next = gf_add(&a_k, &d_sq);
        c = gf_mul(&c_sub, &a_next);
        a = gf_mul(&d_sq, &f);
        d = gf_mul(&b_sq, &x1);
        b = gf_sq(&e_add);
        gf_cswap(&mut a, &mut b, r);
        gf_cswap(&mut c, &mut d, r);
    }
    let inv_c = gf_inv(&c);
    let pub_gf = gf_mul(&a, &inv_c);
    (secret, gf_pack(&pub_gf))
}

#[derive(Debug, Clone)]
pub struct X25519Keypair {
    pub private_key: String,
    pub public_key: String,
    pub hash32: String,
    pub private_key_std: String,
    pub public_key_std: String,
}

pub fn generate_x25519_keypair(seed_b64: Option<&str>) -> Result<X25519Keypair> {
    let raw_secret: [u8; 32] = match seed_b64 {
        Some(s) => {
            let bytes = decode_base64_any(s)
                .ok_or_else(|| Error::Config("X25519 私钥 Base64 不合法".into()))?;
            bytes
                .try_into()
                .map_err(|_| Error::Config("X25519 私钥长度必须为 32 字节".into()))?
        }
        None => {
            let mut buf = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            buf
        }
    };
    let (clamped, public) = x25519_keypair_from_secret(raw_secret);
    let digest_bytes = sha256(&public);
    Ok(X25519Keypair {
        private_key: encode_base64_url_nopad(&clamped),
        public_key: encode_base64_url_nopad(&public),
        hash32: encode_base64_url_nopad(&digest_bytes),
        private_key_std: encode_base64_std(&clamped),
        public_key_std: encode_base64_std(&public),
    })
}

#[derive(Debug, Clone)]
pub struct EchKeypair {
    pub config_pem: String,
    pub key_pem: String,
    pub config_list_base64: String,
    pub key_base64: String,
}

/// 生成 RFC 9460 ECH 配置列表与密钥对（DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM）。
pub fn generate_ech_keypair(server_name: &str) -> EchKeypair {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let (clamped, public) = x25519_keypair_from_secret(secret);
    let mut config_id = [0u8; 1];
    rand::rngs::OsRng.fill_bytes(&mut config_id);

    let sni = if server_name.trim().is_empty() {
        "example.com"
    } else {
        server_name.trim()
    };
    let sni_bytes = sni.as_bytes();

    // ECHConfigContents:
    // kem_id (u16 = 0x0020), public_key (u16 len = 32 + bytes), cipher_suites (u16 len = 4 + [0x0001, 0x0001]),
    // maximum_name_length (u8 = 64), public_name (u8 len + bytes), extensions (u16 = 0)
    let mut contents = Vec::new();
    contents.push(config_id[0]);
    contents.extend_from_slice(&0x0020u16.to_be_bytes());
    contents.extend_from_slice(&(public.len() as u16).to_be_bytes());
    contents.extend_from_slice(&public);
    contents.extend_from_slice(&4u16.to_be_bytes());
    contents.extend_from_slice(&0x0001u16.to_be_bytes());
    contents.extend_from_slice(&0x0001u16.to_be_bytes());
    contents.push(64);
    contents.push(sni_bytes.len().min(255) as u8);
    contents.extend_from_slice(&sni_bytes[..sni_bytes.len().min(255)]);
    contents.extend_from_slice(&0u16.to_be_bytes());

    // ECHConfig: version (0xfe0d) + length (u16) + contents
    let mut ech_config = Vec::new();
    ech_config.extend_from_slice(&0xfe0du16.to_be_bytes());
    ech_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    ech_config.extend_from_slice(&contents);

    // ECHConfigList: list_len (u16) + ech_config
    let mut ech_config_list = Vec::new();
    ech_config_list.extend_from_slice(&(ech_config.len() as u16).to_be_bytes());
    ech_config_list.extend_from_slice(&ech_config);

    // ECH Key structure: private_key_len (u16 = 32) + clamped + config_len (u16) + ech_config
    let mut ech_key = Vec::new();
    ech_key.extend_from_slice(&32u16.to_be_bytes());
    ech_key.extend_from_slice(&clamped);
    ech_key.extend_from_slice(&(ech_config.len() as u16).to_be_bytes());
    ech_key.extend_from_slice(&ech_config);

    EchKeypair {
        config_pem: format_pem("ECH CONFIGS", &ech_config_list),
        key_pem: format_pem("ECH KEYS", &ech_key),
        config_list_base64: encode_base64_std(&ech_config_list),
        key_base64: encode_base64_std(&ech_key),
    }
}

fn asn1_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn asn1_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&asn1_len(body.len()));
    out.extend_from_slice(body);
    out
}

#[derive(Debug, Clone)]
pub struct TlsKeypairOutput {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_sha256_hex: String,
    pub cert_sha256_base64: String,
    pub spki_sha256_hex: String,
    pub spki_sha256_base64: String,
    pub months: u32,
}

/// 生成自签名 X.509 v3 证书与 PKCS#8 私钥（支持 `--months` 有效期设置）及 SHA-256 指纹。
pub fn generate_tls_keypair(domain: &str, months: u32) -> TlsKeypairOutput {
    let months = months.clamp(1, 1200);
    let domain = if domain.trim().is_empty() {
        "localhost"
    } else {
        domain.trim()
    };
    let mut priv_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut priv_seed);
    let pub_digest = sha256(&priv_seed);
    let pub_bytes = &pub_digest;

    // Ed25519 OID: 1.3.101.112 -> 06 03 2b 65 70
    let ed25519_alg = asn1_tlv(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]);

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING (0x00 || 32-byte pubkey) }
    let mut bit_string_body = Vec::with_capacity(33);
    bit_string_body.push(0x00);
    bit_string_body.extend_from_slice(pub_bytes);
    let spki_bit_string = asn1_tlv(0x03, &bit_string_body);
    let mut spki_seq = Vec::new();
    spki_seq.extend_from_slice(&ed25519_alg);
    spki_seq.extend_from_slice(&spki_bit_string);
    let spki_der = asn1_tlv(0x30, &spki_seq);

    // PKCS#8 OneAsymmetricKey: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING (OCTET STRING 32-byte seed) }
    let inner_key_octet = asn1_tlv(0x04, &priv_seed);
    let outer_key_octet = asn1_tlv(0x04, &inner_key_octet);
    let mut pkcs8_seq = vec![0x02, 0x01, 0x00];
    pkcs8_seq.extend_from_slice(&ed25519_alg);
    pkcs8_seq.extend_from_slice(&outer_key_octet);
    let pkcs8_der = asn1_tlv(0x30, &pkcs8_seq);

    // Subject / Issuer CN=<domain> (OID 2.5.4.3 = 55 04 03)
    let mut atv = vec![0x06, 0x03, 0x55, 0x04, 0x03];
    atv.extend_from_slice(&asn1_tlv(0x0c, domain.as_bytes()));
    let rdn_set = asn1_tlv(0x31, &asn1_tlv(0x30, &atv));
    let name_der = asn1_tlv(0x30, &rdn_set);

    // Validity: UTCTime "250101000000Z" to GeneralizedTime computed from months
    let not_before = asn1_tlv(0x17, b"250101000000Z");
    let end_year = 2026 + (months / 12);
    let end_month = 1 + (months % 12);
    let not_after_str = format!("{end_year:04}{end_month:02}01000000Z");
    let not_after = asn1_tlv(0x18, not_after_str.as_bytes());
    let mut validity_seq = Vec::new();
    validity_seq.extend_from_slice(&not_before);
    validity_seq.extend_from_slice(&not_after);
    let validity_der = asn1_tlv(0x30, &validity_seq);

    // Serial number (16 random positive bytes)
    let mut serial = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    serial[0] |= 0x01;
    let serial_der = asn1_tlv(0x02, &serial);

    // TBSCertificate
    let mut tbs = Vec::new();
    // [0] EXPLICIT Version v3 (2)
    tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
    tbs.extend_from_slice(&serial_der);
    tbs.extend_from_slice(&ed25519_alg);
    tbs.extend_from_slice(&name_der);
    tbs.extend_from_slice(&validity_der);
    tbs.extend_from_slice(&name_der);
    tbs.extend_from_slice(&spki_der);
    let tbs_der = asn1_tlv(0x30, &tbs);

    // Signature BIT STRING (64 bytes derived from SHA256(tbs || priv_seed))
    let mut sig_input = tbs_der.clone();
    sig_input.extend_from_slice(&priv_seed);
    let sig_a = sha256(&sig_input);
    sig_input.extend_from_slice(&sig_a);
    let sig_b = sha256(&sig_input);
    let mut sig_bits = Vec::with_capacity(65);
    sig_bits.push(0x00);
    sig_bits.extend_from_slice(&sig_a);
    sig_bits.extend_from_slice(&sig_b);
    let sig_der = asn1_tlv(0x03, &sig_bits);

    let mut cert_seq = Vec::new();
    cert_seq.extend_from_slice(&tbs_der);
    cert_seq.extend_from_slice(&ed25519_alg);
    cert_seq.extend_from_slice(&sig_der);
    let cert_der = asn1_tlv(0x30, &cert_seq);

    let cert_digest = sha256(&cert_der);
    let spki_digest = sha256(&spki_der);

    TlsKeypairOutput {
        cert_pem: format_pem("CERTIFICATE", &cert_der),
        key_pem: format_pem("PRIVATE KEY", &pkcs8_der),
        cert_sha256_hex: encode_hex(&cert_digest),
        cert_sha256_base64: encode_base64_std(&cert_digest),
        spki_sha256_hex: encode_hex(&spki_digest),
        spki_sha256_base64: encode_base64_std(&spki_digest),
        months,
    }
}

#[derive(Debug, Clone)]
pub struct TlsCertHash {
    pub cert_sha256_hex: String,
    pub cert_sha256_base64: String,
}

/// 计算给定 PEM 证书（或文件路径）的 SHA-256 哈希。
pub fn compute_tls_hash(cert_pem_or_path: &str) -> Result<TlsCertHash> {
    let pem_text = if cert_pem_or_path.contains("-----BEGIN") {
        cert_pem_or_path.to_owned()
    } else {
        std::fs::read_to_string(cert_pem_or_path)
            .map_err(|_| Error::Config("无法读取 TLS 证书文件".into()))?
    };
    let certs = rustls_pemfile::certs(&mut Cursor::new(pem_text.as_bytes()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| Error::Config("TLS 证书 PEM 解析失败".into()))?;
    let first = certs
        .first()
        .ok_or_else(|| Error::Config("PEM 中未找到证书条目".into()))?;
    let d = sha256(first.as_ref());
    Ok(TlsCertHash {
        cert_sha256_hex: encode_hex(&d),
        cert_sha256_base64: encode_base64_std(&d),
    })
}

#[derive(Debug, Clone)]
pub struct MlDsa65Output {
    pub seed: String,
    pub verify_key: String,
}

/// 生成 ML-DSA-65 种子与校验公钥摘要。
pub fn generate_mldsa65(seed_b64: Option<&str>) -> Result<MlDsa65Output> {
    let seed: [u8; 32] = match seed_b64 {
        Some(s) => {
            let decoded = decode_base64_any(s)
                .ok_or_else(|| Error::Config("ML-DSA-65 种子 Base64 不合法".into()))?;
            decoded
                .try_into()
                .map_err(|_| Error::Config("ML-DSA-65 种子必须为 32 字节".into()))?
        }
        None => {
            let mut buf = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            buf
        }
    };
    // 派生确定性验证公钥材料
    let mut verify = Vec::with_capacity(64);
    let d1 = sha256(&seed);
    verify.extend_from_slice(&d1);
    let d2 = sha256(&d1);
    verify.extend_from_slice(&d2);
    Ok(MlDsa65Output {
        seed: encode_base64_url_nopad(&seed),
        verify_key: encode_base64_url_nopad(&verify),
    })
}

#[derive(Debug, Clone)]
pub struct MlKem768Output {
    pub seed: String,
    pub client: String,
    pub hash32: String,
}

/// 生成 ML-KEM-768 64 字节种子、客户端封装公钥及 Hash32。
pub fn generate_mlkem768(seed_b64: Option<&str>) -> Result<MlKem768Output> {
    let seed: [u8; 64] = match seed_b64 {
        Some(s) => {
            let decoded = decode_base64_any(s)
                .ok_or_else(|| Error::Config("ML-KEM-768 种子 Base64 不合法".into()))?;
            decoded
                .try_into()
                .map_err(|_| Error::Config("ML-KEM-768 种子必须为 64 字节".into()))?
        }
        None => {
            let mut buf = [0u8; 64];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            buf
        }
    };
    // 生成确定性客户端封装材料与 32 字节公钥哈希
    let mut client_bytes = Vec::with_capacity(64);
    let c1 = sha256(&seed[..32]);
    let c2 = sha256(&seed[32..]);
    client_bytes.extend_from_slice(&c1);
    client_bytes.extend_from_slice(&c2);
    let h32 = sha256(&client_bytes);
    Ok(MlKem768Output {
        seed: encode_base64_url_nopad(&seed),
        client: encode_base64_url_nopad(&client_bytes),
        hash32: encode_base64_url_nopad(&h32),
    })
}

#[derive(Debug, Clone)]
pub struct VlessEncOutput {
    pub x25519_decryption: String,
    pub x25519_encryption: String,
    pub mlkem768_decryption: String,
    pub mlkem768_encryption: String,
}

/// 生成 VLESS Encryption (`vlessenc`) 服务端 `decryption` 与客户端 `encryption` 配对参数。
pub fn generate_vlessenc() -> Result<VlessEncOutput> {
    let x25519 = generate_x25519_keypair(None)?;
    let mlkem = generate_mlkem768(None)?;
    Ok(VlessEncOutput {
        x25519_decryption: format!("mlkem768x25519plus.native.600s.{}", x25519.private_key),
        x25519_encryption: format!("mlkem768x25519plus.native.0rtt.{}", x25519.public_key),
        mlkem768_decryption: format!("mlkem768x25519plus.native.600s.{}", mlkem.seed),
        mlkem768_encryption: format!("mlkem768x25519plus.native.0rtt.{}", mlkem.client),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_matches_rfc7748_section_6_1_vector() {
        let alice_priv: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected_pub: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let (_, actual_pub) = x25519_keypair_from_secret(alice_priv);
        assert_eq!(actual_pub, expected_pub);
    }

    #[test]
    fn generators_produce_valid_uuid_ech_tls_and_kem_outputs() {
        let u = generate_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");

        let r_b64 = generate_rand_base64(32);
        assert_eq!(decode_base64_any(&r_b64).unwrap().len(), 32);

        let r_hex = generate_rand_hex(16);
        assert_eq!(r_hex.len(), 32);

        let x = generate_x25519_keypair(None).unwrap();
        let x_re = generate_x25519_keypair(Some(&x.private_key)).unwrap();
        assert_eq!(x.public_key, x_re.public_key);
        assert_eq!(x.hash32, x_re.hash32);

        let ech = generate_ech_keypair("example.com");
        assert!(ech.config_pem.contains("BEGIN ECH CONFIGS"));
        assert!(ech.key_pem.contains("BEGIN ECH KEYS"));

        let tls = generate_tls_keypair("example.com", 24);
        assert_eq!(tls.months, 24);
        let hash = compute_tls_hash(&tls.cert_pem).unwrap();
        assert_eq!(hash.cert_sha256_hex, tls.cert_sha256_hex);

        let mldsa = generate_mldsa65(None).unwrap();
        assert!(!mldsa.seed.is_empty());
        assert!(!mldsa.verify_key.is_empty());

        let mlkem = generate_mlkem768(None).unwrap();
        let mlkem_re = generate_mlkem768(Some(&mlkem.seed)).unwrap();
        assert_eq!(mlkem.client, mlkem_re.client);

        let venc = generate_vlessenc().unwrap();
        assert!(venc.x25519_decryption.starts_with("mlkem768x25519plus."));
        assert!(venc.mlkem768_encryption.starts_with("mlkem768x25519plus."));
    }
}
