//! 双端 AEAD 首部。身份验证、重放与字段校验均早于目标访问。
use crate::crypto::{self, Cipher, Records, invalid};
use kerlico_core::{Address, BoxStream, Destination};
use rand::RngCore;
use std::{
    collections::HashMap,
    io,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

pub(crate) struct Account {
    pub id: [u8; 16],
    pub key: Zeroizing<[u8; 16]>,
}
impl Account {
    pub fn new(id: [u8; 16]) -> Self {
        Self {
            id,
            key: crypto::command_key(&id),
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct RecordOptions {
    pub cipher: Cipher,
    pub flags: u8,
    pub termination: bool,
}
pub(crate) struct Keys {
    key: Zeroizing<[u8; 16]>,
    iv: Zeroizing<[u8; 16]>,
    response_key: Zeroizing<[u8; 16]>,
    response_iv: Zeroizing<[u8; 16]>,
    marker: u8,
}
impl Keys {
    fn new(key: [u8; 16], iv: [u8; 16], marker: u8) -> Self {
        Self {
            response_key: Zeroizing::new(crypto::sha256(&key)[..16].try_into().unwrap()),
            response_iv: Zeroizing::new(crypto::sha256(&iv)[..16].try_into().unwrap()),
            key: Zeroizing::new(key),
            iv: Zeroizing::new(iv),
            marker,
        }
    }
    fn records(&self, options: RecordOptions, client: bool) -> (Records, Records) {
        let auth = (options.flags & 16 != 0).then_some((&*self.key, &*self.iv));
        let request = Records::new(options.cipher, &self.key, &self.iv, auth, options.flags);
        let response = Records::new(
            options.cipher,
            &self.response_key,
            &self.response_iv,
            auth,
            options.flags,
        );
        if client {
            (response, request)
        } else {
            (request, response)
        }
    }
}
pub(crate) struct Handshake {
    pub target: Destination,
    pub udp: bool,
    pub stream: crate::stream::RecordStream,
}
pub(crate) fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| invalid())
}
fn fnv(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |v, b| {
        (v ^ u32::from(*b)).wrapping_mul(0x1000193)
    })
}
fn address(target: &Destination, out: &mut Vec<u8>) {
    out.extend_from_slice(&target.port().to_be_bytes());
    match target.address() {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend(ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(3);
            out.extend(ip.octets());
        }
        Address::Domain(name) => {
            out.extend([2, name.len() as u8]);
            out.extend_from_slice(name.as_bytes());
        }
    }
}
fn decode_address(bytes: &[u8]) -> io::Result<(Destination, usize)> {
    if bytes.len() < 3 {
        return Err(invalid());
    }
    let port = u16::from_be_bytes(bytes[..2].try_into().unwrap());
    let (host, n) = match bytes[2] {
        1 if bytes.len() >= 7 => (
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[3..7]).unwrap()).to_string(),
            7,
        ),
        3 if bytes.len() >= 19 => (
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[3..19]).unwrap()).to_string(),
            19,
        ),
        2 if bytes.len() >= 4 => {
            let n = bytes[3] as usize;
            if n == 0 || bytes.len() < 4 + n {
                return Err(invalid());
            }
            (
                std::str::from_utf8(&bytes[4..4 + n])
                    .map_err(|_| invalid())?
                    .to_owned(),
                4 + n,
            )
        }
        _ => return Err(invalid()),
    };
    Ok((Destination::new(&host, port).map_err(|_| invalid())?, n))
}
pub(crate) fn request(
    account: &Account,
    target: &Destination,
    udp: bool,
    options: RecordOptions,
) -> io::Result<(Vec<u8>, Keys)> {
    let mut entropy = Zeroizing::new([0; 33]);
    rand::rngs::OsRng.fill_bytes(&mut *entropy);
    let keys = Keys::new(
        entropy[..16].try_into().unwrap(),
        entropy[16..32].try_into().unwrap(),
        entropy[32],
    );
    let mut random = [0; 4];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let auth = crypto::auth_id(&account.key, now()?, random);
    let mut nonce = [0; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let pad = (random[0] & 15) as usize;
    let mut plain = Zeroizing::new(vec![1]);
    plain.extend_from_slice(&*keys.iv);
    plain.extend_from_slice(&*keys.key);
    plain.extend([
        keys.marker,
        options.flags,
        ((pad as u8) << 4) | options.cipher.wire(),
        0,
        if udp { 2 } else { 1 },
    ]);
    address(target, &mut plain);
    let start = plain.len();
    plain.resize(start + pad, 0);
    rand::rngs::OsRng.fill_bytes(&mut plain[start..]);
    let checksum = fnv(&plain);
    plain.extend(checksum.to_be_bytes());
    let mut length = (plain.len() as u16).to_be_bytes().to_vec();
    crypto::header_seal(
        &*account.key,
        &*account.key,
        &[b"VMess Header AEAD Key_Length", &auth, &nonce],
        &[b"VMess Header AEAD Nonce_Length", &auth, &nonce],
        &auth,
        &mut length,
    )?;
    crypto::header_seal(
        &*account.key,
        &*account.key,
        &[b"VMess Header AEAD Key", &auth, &nonce],
        &[b"VMess Header AEAD Nonce", &auth, &nonce],
        &auth,
        &mut plain,
    )?;
    let mut out = auth.to_vec();
    out.extend(length);
    out.extend(nonce);
    out.extend_from_slice(&plain);
    Ok((out, keys))
}
pub(crate) async fn connect(
    mut inner: BoxStream,
    account: &Account,
    target: &Destination,
    udp: bool,
    options: RecordOptions,
) -> io::Result<crate::stream::RecordStream> {
    let (request, keys) = request(account, target, udp, options)?;
    inner.write_all(&request).await?;
    inner.flush().await?;
    let (reader, writer) = keys.records(options, true);
    Ok(crate::stream::RecordStream::new(
        inner,
        reader,
        writer,
        udp,
        options.termination,
        Some(keys),
        Vec::new(),
    )
    .flags(options.flags))
}

pub(crate) struct Replay {
    entries: Mutex<HashMap<[u8; 32], std::time::Instant>>,
    limit: usize,
}
impl Replay {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            limit: 65536,
        }
    }
    fn claim(&self, id: [u8; 32]) -> io::Result<()> {
        let mut entries = self.entries.lock().map_err(|_| invalid())?;
        let now = std::time::Instant::now();
        entries.retain(|_, time| now.duration_since(*time) < Duration::from_secs(300));
        if entries.contains_key(&id) || entries.len() >= self.limit {
            return Err(invalid());
        }
        entries.insert(id, now);
        Ok(())
    }
}
pub(crate) async fn accept(
    mut inner: BoxStream,
    accounts: &[Account],
    replay: &Replay,
) -> io::Result<Handshake> {
    let mut auth = [0; 16];
    inner.read_exact(&mut auth).await?;
    let current = now()?;
    let account = accounts
        .iter()
        .find(|a| {
            crypto::decode_auth(&a.key, &auth)
                .is_ok_and(|timestamp| timestamp.abs_diff(current) <= 120)
        })
        .ok_or_else(invalid)?;
    let mut stamp = Vec::with_capacity(32);
    stamp.extend(account.id);
    stamp.extend(auth);
    replay.claim(crypto::sha256(&stamp))?;
    let mut length = vec![0; 18];
    inner.read_exact(&mut length).await?;
    let mut nonce = [0; 8];
    inner.read_exact(&mut nonce).await?;
    crypto::header_open(
        &*account.key,
        &*account.key,
        &[b"VMess Header AEAD Key_Length", &auth, &nonce],
        &[b"VMess Header AEAD Nonce_Length", &auth, &nonce],
        &auth,
        &mut length,
    )?;
    if length.len() != 2 {
        return Err(invalid());
    }
    let size = u16::from_be_bytes(length.try_into().unwrap()) as usize;
    if !(45..=512).contains(&size) {
        return Err(invalid());
    }
    let mut plain = Zeroizing::new(vec![0; size + 16]);
    inner.read_exact(&mut plain).await?;
    crypto::header_open(
        &*account.key,
        &*account.key,
        &[b"VMess Header AEAD Key", &auth, &nonce],
        &[b"VMess Header AEAD Nonce", &auth, &nonce],
        &auth,
        &mut plain,
    )?;
    if plain.len() != size
        || plain[0] != 1
        || plain[36] != 0
        || plain[34] & !0x1d != 0
        || plain[34] & 1 == 0
        || plain[34] & 8 != 0 && plain[34] & 4 == 0
        || !matches!(plain[37], 1 | 2)
    {
        return Err(invalid());
    }
    let checksum = u32::from_be_bytes(plain[size - 4..].try_into().unwrap());
    if fnv(&plain[..size - 4]) != checksum {
        return Err(invalid());
    }
    let (target, address_size) = decode_address(&plain[38..size - 4])?;
    if 38 + address_size + (plain[35] >> 4) as usize + 4 != size {
        return Err(invalid());
    }
    let key: [u8; 16] = plain[17..33].try_into().unwrap();
    let iv: [u8; 16] = plain[1..17].try_into().unwrap();
    let mut session = Zeroizing::new(account.id.to_vec());
    session.extend(key);
    session.extend(iv);
    replay.claim(crypto::sha256(&session))?;
    let keys = Keys::new(key, iv, plain[33]);
    let options = RecordOptions {
        cipher: Cipher::from_wire(plain[35] & 15)?,
        flags: plain[34],
        termination: true,
    };
    let mut response = vec![keys.marker, 0, 0, 0];
    let mut size = (response.len() as u16).to_be_bytes().to_vec();
    crypto::header_seal(
        &*keys.response_key,
        &*keys.response_iv,
        &[b"AEAD Resp Header Len Key"],
        &[b"AEAD Resp Header Len IV"],
        &[],
        &mut size,
    )?;
    crypto::header_seal(
        &*keys.response_key,
        &*keys.response_iv,
        &[b"AEAD Resp Header Key"],
        &[b"AEAD Resp Header IV"],
        &[],
        &mut response,
    )?;
    size.extend(response);
    let udp = plain[37] == 2;
    let (reader, writer) = keys.records(options, false);
    Ok(Handshake {
        target,
        udp,
        stream: crate::stream::RecordStream::new(inner, reader, writer, udp, true, None, size),
    })
}
impl Keys {
    pub fn response_length(&self, bytes: &mut Vec<u8>) -> io::Result<usize> {
        crypto::header_open(
            &*self.response_key,
            &*self.response_iv,
            &[b"AEAD Resp Header Len Key"],
            &[b"AEAD Resp Header Len IV"],
            &[],
            bytes,
        )?;
        let size = u16::from_be_bytes(bytes.as_slice().try_into().map_err(|_| invalid())?) as usize;
        if !(4..=259).contains(&size) {
            return Err(invalid());
        }
        Ok(size + 16)
    }
    pub fn response_header(&self, bytes: &mut Vec<u8>, flags: u8) -> io::Result<()> {
        crypto::header_open(
            &*self.response_key,
            &*self.response_iv,
            &[b"AEAD Resp Header Key"],
            &[b"AEAD Resp Header IV"],
            &[],
            bytes,
        )?;
        if bytes.len() != 4
            || bytes[0] != self.marker
            || ![0, flags].contains(&bytes[1])
            || bytes[2..] != [0, 0]
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn authenticates_before_target_and_rejects_replayed_request() {
        let account = Account::new([7; 16]);
        let target = Destination::new("example.invalid", 443).unwrap();
        let options = RecordOptions {
            cipher: Cipher::ChaCha,
            flags: 29,
            termination: true,
        };
        let (wire, _) = request(&account, &target, false, options).unwrap();
        let replay = Replay::new();
        for valid in [true, false] {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(&wire).await.unwrap();
            let result = accept(Box::new(server), std::slice::from_ref(&account), &replay).await;
            if valid {
                assert_eq!(result.unwrap().target, target);
            } else {
                assert!(result.is_err());
            }
        }
        let mut forged = wire;
        forged[0] ^= 1;
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(&forged).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(
            accept(Box::new(server), &[account], &Replay::new())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn partial_header_and_wrong_authentication_are_rejected() {
        let account = Account::new([8; 16]);
        let target = Destination::new("127.0.0.1", 53).unwrap();
        let options = RecordOptions {
            cipher: Cipher::Aes,
            flags: 13,
            termination: true,
        };
        let (wire, _) = request(&account, &target, true, options).unwrap();
        for cut in [0, 1, 15, 16, 30, 42, wire.len() - 1] {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(&wire[..cut]).await.unwrap();
            client.shutdown().await.unwrap();
            assert!(
                accept(
                    Box::new(server),
                    std::slice::from_ref(&account),
                    &Replay::new()
                )
                .await
                .is_err()
            );
        }
        let replay = Replay::new();
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(&wire).await.unwrap();
        let mut session = accept(Box::new(server), &[account], &replay).await.unwrap();
        session.stream.write_all(b"hello").await.unwrap();
        session.stream.flush().await.unwrap();
        let mut response = [0; 43];
        client.read_exact(&mut response[..38]).await.unwrap();
        assert!(response.iter().any(|v| *v != 0));
    }
}
