pub fn host_from(buf: &[u8], kinds: &[String]) -> Option<String> {
    for kind in kinds {
        let found = match kind.as_str() {
            "http" => http_host(buf),
            "tls" => tls_sni(buf),
            "quic" => quic_sni(buf),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn http_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    let line = text.lines().find(|line| line.to_ascii_lowercase().starts_with("host:"))?;
    let host = line.split(':').nth(1)?.trim();
    let host = host.split(':').next()?.trim();
    if host.is_empty() { None } else { Some(host.to_string()) }
}

fn tls_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    sni_from_handshake(&buf[5..])
}

fn sni_from_handshake(buf: &[u8]) -> Option<String> {
    if buf.len() < 4 || buf[0] != 0x01 {
        return None;
    }
    let mut offset = 4 + 2 + 32;
    if offset >= buf.len() {
        return None;
    }
    offset += 1 + buf[offset] as usize;
    if offset + 2 > buf.len() {
        return None;
    }
    let ciphers = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
    offset += 2 + ciphers;
    if offset >= buf.len() {
        return None;
    }
    offset += 1 + buf[offset] as usize;
    if offset + 2 > buf.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
    offset += 2;
    let end = (offset + ext_len).min(buf.len());
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if kind == 0 && offset + len <= buf.len() && len >= 5 {
            let name_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
            let start = offset + 5;
            if start + name_len <= buf.len() {
                return String::from_utf8(buf[start..start + name_len].to_vec()).ok();
            }
        }
        offset += len;
    }
    None
}

const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

fn quic_sni(buf: &[u8]) -> Option<String> {
    let plain = open_initial(buf)?;
    let crypto = crypto_payload(&plain)?;
    sni_from_handshake(&crypto)
}

fn open_initial(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 7 || buf[0] & 0xf0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != 1 {
        return None;
    }
    let dcid_len = buf[5] as usize;
    if dcid_len > 20 || 6 + dcid_len >= buf.len() {
        return None;
    }
    let dcid = &buf[6..6 + dcid_len];
    let mut offset = 6 + dcid_len;
    let scid_len = *buf.get(offset)? as usize;
    offset = offset.checked_add(1 + scid_len)?;
    let (token_len, token_var) = varint(&buf[offset..])?;
    offset = offset.checked_add(token_var)?.checked_add(token_len as usize)?;
    let (payload_len, len_var) = varint(&buf[offset..])?;
    offset = offset.checked_add(len_var)?;
    let pn_offset = offset;
    let packet_end = pn_offset.checked_add(payload_len as usize)?;
    if packet_end > buf.len() || pn_offset + 20 > packet_end {
        return None;
    }
    let sample = &buf[pn_offset + 4..pn_offset + 20];
    let (key, iv, hp) = initial_keys(dcid)?;
    let mask = aes128(&hp, sample);
    let mut header = buf[..packet_end].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = (header[0] & 0x03) as usize + 1;
    if pn_offset + pn_len > packet_end {
        return None;
    }
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
    }
    let mut pn = 0u64;
    for byte in &header[pn_offset..pn_offset + pn_len] {
        pn = (pn << 8) | u64::from(*byte);
    }
    let mut nonce = iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }
    let aad = header[..pn_offset + pn_len].to_vec();
    let ct = &header[pn_offset + pn_len..];
    aes_gcm_open(&key, &nonce, &aad, ct)
}

fn initial_keys(dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let initial = hkdf::Hkdf::<sha2::Sha256>::new(Some(&QUIC_V1_SALT), dcid);
    let mut secret = [0u8; 32];
    expand_label(&initial, "client in", &mut secret)?;
    let client = hkdf::Hkdf::<sha2::Sha256>::from_prk(&secret).ok()?;
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    expand_label(&client, "quic key", &mut key)?;
    expand_label(&client, "quic iv", &mut iv)?;
    expand_label(&client, "quic hp", &mut hp)?;
    Some((key, iv, hp))
}

fn expand_label(prk: &hkdf::Hkdf<sha2::Sha256>, label: &str, out: &mut [u8]) -> Option<()> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    prk.expand(&info, out).ok()
}

fn aes128(key: &[u8; 16], block: &[u8]) -> [u8; 16] {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new(key.into());
    let mut out = aes::cipher::generic_array::GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut out);
    out.into()
}

fn aes_gcm_open(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let cipher = aes_gcm::Aes128Gcm::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload { msg: ct, aad },
        )
        .ok()
}

fn crypto_payload(buf: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf[offset] == 0x00 {
            offset += 1;
            continue;
        }
        if buf[offset] != 0x06 {
            break;
        }
        offset += 1;
        let (_, start_var) = varint(&buf[offset..])?;
        offset += start_var;
        let (len, len_var) = varint(&buf[offset..])?;
        offset += len_var;
        let end = offset.checked_add(len as usize)?;
        if end > buf.len() {
            return None;
        }
        out.extend_from_slice(&buf[offset..end]);
        offset = end;
    }
    if out.is_empty() { None } else { Some(out) }
}

fn varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &buf[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_bytes(value: u64) -> Vec<u8> {
        if value < 64 {
            vec![value as u8]
        } else if value < 16384 {
            let raw = (value as u16) | 0x4000;
            raw.to_be_bytes().to_vec()
        } else {
            let raw = (value as u32) | 0x8000_0000;
            raw.to_be_bytes().to_vec()
        }
    }

    fn client_hello(name: &str) -> Vec<u8> {
        let name = name.as_bytes();
        let mut sni = vec![0];
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&((sni.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[7u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let mut msg = vec![1, (hello.len() >> 16) as u8, (hello.len() >> 8) as u8, hello.len() as u8];
        msg.extend_from_slice(&hello);
        msg
    }

    fn seal_initial(dcid: &[u8], hello: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let mut plain = vec![0x06];
        plain.extend(varint_bytes(0));
        plain.extend(varint_bytes(hello.len() as u64));
        plain.extend_from_slice(hello);
        plain.extend_from_slice(&[0u8; 32]);
        let (key, iv, hp) = initial_keys(dcid).unwrap();
        let mut header = vec![0xc0, 0, 0, 0, 1, dcid.len() as u8];
        header.extend_from_slice(dcid);
        header.push(0);
        header.push(0);
        let pn = [0u8];
        let ct_len = plain.len() + 16;
        header.extend(varint_bytes((pn.len() + ct_len) as u64));
        let pn_offset = header.len();
        header.extend_from_slice(&pn);
        let cipher = aes_gcm::Aes128Gcm::new((&key).into());
        let ct = cipher
            .encrypt(iv.as_slice().into(), Payload { msg: &plain, aad: &header })
            .unwrap();
        header.extend_from_slice(&ct);
        let sample = header[pn_offset + 4..pn_offset + 20].to_vec();
        let mask = aes128(&hp, &sample);
        header[0] ^= mask[0] & 0x0f;
        header[pn_offset] ^= mask[1];
        header
    }

    #[test]
    fn quic_initial_yields_the_client_hello_name() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let (key, iv, hp) = initial_keys(&dcid).unwrap();
        assert_eq!(
            key,
            [
                0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
                0xa2, 0x2d
            ]
        );
        assert_eq!(iv, [0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c]);
        assert_eq!(
            hp,
            [
                0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
                0xed, 0xd2
            ]
        );
        let packet = seal_initial(&dcid, &client_hello("example.com"));
        let kinds = vec!["quic".to_string()];
        assert_eq!(host_from(&packet, &kinds).as_deref(), Some("example.com"));
    }
}
