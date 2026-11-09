//! VLESS Encryption record layer: a TLS-shaped header and an incrementing AEAD nonce.
//!
//! The forward-secret exchange is ML-KEM-768 plus X25519.

use std::io::{Read, Write};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use ml_kem::EncodedSizeUser;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_PLAIN: usize = 8192;

pub struct Record {
    key: [u8; 32],
    nonce: [u8; 12],
    aes: bool,
}

impl Record {
    pub fn new(context: &[u8], key: &[u8], aes: bool) -> Self {
        Self { key: derive(context, key), nonce: [0; 12], aes }
    }

    pub fn seal(&mut self, plain: &[u8], extra_nonce: Option<[u8; 12]>) -> Vec<u8> {
        let nonce = match extra_nonce {
            Some(nonce) => nonce,
            None => bump(&mut self.nonce),
        };
        self.seal_with(plain, &nonce, &[])
    }

    pub fn open(&mut self, cipher: &[u8], extra_nonce: Option<[u8; 12]>, aad: &[u8]) -> Option<Vec<u8>> {
        let nonce = match extra_nonce {
            Some(nonce) => nonce,
            None => bump(&mut self.nonce),
        };
        self.open_with(cipher, &nonce, aad)
    }

    fn seal_with(&self, plain: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Vec<u8> {
        let payload = Payload { msg: plain, aad };
        if self.aes {
            let cipher = Aes256Gcm::new_from_slice(&self.key).expect("aes key");
            cipher.encrypt(Nonce::from_slice(nonce), payload).expect("seal")
        } else {
            let cipher = ChaCha20Poly1305::new_from_slice(&self.key).expect("chacha key");
            cipher.encrypt(Nonce::from_slice(nonce), payload).expect("seal")
        }
    }

    fn open_with(&self, cipher_text: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Option<Vec<u8>> {
        let payload = Payload { msg: cipher_text, aad };
        if self.aes {
            let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
            cipher.decrypt(Nonce::from_slice(nonce), payload).ok()
        } else {
            let cipher = ChaCha20Poly1305::new_from_slice(&self.key).ok()?;
            cipher.decrypt(Nonce::from_slice(nonce), payload).ok()
        }
    }
}

fn derive(context: &[u8], material: &[u8]) -> [u8; 32] {
    use blake3::hazmat::HasherExt;
    let context_key = blake3::platform::le_bytes_from_words_32(&context_cv(context, 0, true));
    *blake3::Hasher::new_from_context_key(&context_key).update(material).finalize().as_bytes()
}

// Xray uses binary BLAKE3 derive-key contexts. The Rust API's context helper takes UTF-8.
fn context_cv(context: &[u8], chunk: u64, root: bool) -> [u32; 8] {
    const CHUNK: usize = 1024;
    const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 1 << 1;
    const PARENT: u8 = 1 << 2;
    const ROOT: u8 = 1 << 3;
    let platform = blake3::platform::Platform::detect();
    let mut cv = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let root = if root { ROOT } else { 0 };
    if context.len() > CHUNK {
        let split = context.len().next_power_of_two() / 2;
        let (left, right) = context.split_at(split);
        let left = context_cv(left, chunk, false);
        let right = context_cv(right, chunk + (split / CHUNK) as u64, false);
        let mut block = [0; 64];
        block[..32].copy_from_slice(&blake3::platform::le_bytes_from_words_32(&left));
        block[32..].copy_from_slice(&blake3::platform::le_bytes_from_words_32(&right));
        platform.compress_in_place(&mut cv, &block, 64, 0, DERIVE_KEY_CONTEXT | PARENT | root);
        return cv;
    }
    let blocks = context.len().max(1).div_ceil(64);
    for index in 0..blocks {
        let offset = index * 64;
        let bytes = &context[offset..context.len().min(offset + 64)];
        let mut block = [0; 64];
        block[..bytes.len()].copy_from_slice(bytes);
        let mut flags = DERIVE_KEY_CONTEXT;
        if index == 0 {
            flags |= CHUNK_START;
        }
        if index + 1 == blocks {
            flags |= CHUNK_END | root;
        }
        platform.compress_in_place(&mut cv, &block, bytes.len() as u8, chunk, flags);
    }
    cv
}

pub(crate) fn checked_x25519(secret: &StaticSecret, public: &PublicKey) -> Option<[u8; 32]> {
    let shared = secret.diffie_hellman(public);
    shared.was_contributory().then(|| shared.to_bytes())
}

fn bump(nonce: &mut [u8; 12]) -> [u8; 12] {
    for index in (0..12).rev() {
        nonce[index] = nonce[index].wrapping_add(1);
        if nonce[index] != 0 {
            break;
        }
    }
    *nonce
}

pub fn seal_record(record: &mut Record, plain: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 5 + plain.len() + 16];
    out[0] = 23;
    out[1] = 3;
    out[2] = 3;
    let len = (plain.len() + 16) as u16;
    out[3] = (len >> 8) as u8;
    out[4] = len as u8;
    let nonce = bump(&mut record.nonce);
    let sealed = record.seal_with(plain, &nonce, &out[..5]);
    out[5..].copy_from_slice(&sealed);
    out
}

pub fn open_record(record: &mut Record, header: &[u8; 5], body: &[u8]) -> Option<Vec<u8>> {
    let len = header_length(header)?;
    if len != body.len() || !(17..=16640).contains(&len) {
        return None;
    }
    record.open(body, None, header)
}

fn header_length(header: &[u8; 5]) -> Option<usize> {
    header.starts_with(&[23, 3, 3]).then(|| u16::from_be_bytes([header[3], header[4]]) as usize)
}

struct HeaderMask {
    stream: KeyStream,
    header: [u8; 5],
    filled: usize,
    skip: usize,
}

impl HeaderMask {
    fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        Self { stream: KeyStream::new(key, iv), header: [0; 5], filled: 0, skip: 0 }
    }

    fn apply(&mut self, mut bytes: &mut [u8], writing: bool) {
        while !bytes.is_empty() {
            let skip = bytes.len().min(self.skip);
            self.skip -= skip;
            bytes = &mut bytes[skip..];
            let width = bytes.len().min(5 - self.filled);
            let (head, rest) = bytes.split_at_mut(width);
            let saved = &mut self.header[self.filled..self.filled + width];
            if writing {
                saved.copy_from_slice(head);
                self.stream.apply(head);
            } else {
                self.stream.apply(head);
                saved.copy_from_slice(head);
            }
            self.filled += width;
            if self.filled == 5 {
                self.skip = header_length(&self.header).unwrap_or(0);
                self.filled = 0;
            }
            bytes = rest;
        }
    }
}

struct Encrypted<S> {
    inner: S,
    read: ReadState,
    write: WriteState,
}

impl<S> Encrypted<S> {
    fn into_halves<R, W>(self, split: impl FnOnce(S) -> (R, W)) -> (EncReader<R>, EncWriter<W>) {
        let (reader, writer) = split(self.inner);
        (EncReader { inner: reader, state: self.read }, EncWriter { inner: writer, state: self.write })
    }
}

impl<S: Read> Read for Encrypted<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read.read(&mut self.inner, buf)
    }
}

impl<S: Write> Write for Encrypted<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write.write(&mut self.inner, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write.flush(&mut self.inner)
    }
}

const MAX_NONCE: [u8; 12] = [0xff; 12];

fn client_handshake<S: Read + Write>(mut socket: S, server_public: &[NfsKey], mode: u8, reuse: bool, pad: &Pad) -> std::io::Result<Encrypted<S>> {
    if server_public.is_empty() {
        return Err(std::io::Error::other("vlessenc"));
    }
    let iv = random_bytes::<16>();
    let (relay, nfs) = client_relays(server_public, &iv, mode)?;
    let mut nfs_aead = Record::new(&iv, &nfs, false);
    let cache_key = ticket_id(server_public, mode);
    let mut hello = Vec::new();
    hello.extend(iv);
    hello.extend(relay);
    if reuse {
        if let Some((ticket, pfs)) = recall_client(&cache_key) {
            hello.extend(seal_length(&mut nfs_aead, 32));
            let ticket_cipher = nfs_aead.seal(&ticket, None);
            hello.extend(&ticket_cipher);
            let united = unite_pfs(&pfs, &nfs);
            let write = Record::new(&ticket_cipher, &united, false);
            let mask = (mode == 2).then(|| HeaderMask::new(&united, &iv));
            let resume = ClientResume { united, random_mask: mode == 2, cache_key, ticket };
            return Ok(Encrypted {
                inner: socket,
                read: ReadState { resume: Some(resume), ..ReadState::new(None, None) },
                write: WriteState { prefix: hello, ..WriteState::new(write, mask) },
            });
        }
    }
    let (mlkem_secret, mlkem_public) = mlkem_keypair();
    let (pfs_secret, pfs_public) = random_x25519();
    let mut pfs_plain = mlkem_public;
    pfs_plain.extend(pfs_public.to_bytes());
    hello.extend(seal_length(&mut nfs_aead, pfs_plain.len() + 16));
    hello.extend(nfs_aead.seal(&pfs_plain, None));
    write_hello(&mut socket, hello, &mut nfs_aead, pad)?;

    let server_pfs = read_exact(&mut socket, 1088 + 32 + 16)?;
    let server_pfs = nfs_aead.open(&server_pfs, Some(MAX_NONCE), &[]).ok_or_else(|| std::io::Error::other("vlessenc"))?;
    let mlkem = decapsulate(&mlkem_secret, &server_pfs[..1088])?;
    let server_x = PublicKey::from(copy32(&server_pfs[1088..1120])?);
    let x = checked_x25519(&pfs_secret, &server_x).ok_or_else(invalid_encryption)?;
    let united = unite(&mlkem, &x, &nfs);
    let mut read = Record::new(&server_pfs, &united, false);
    let write = Record::new(&pfs_plain, &united, false);
    let ticket = read_exact(&mut socket, 32)?;
    let ticket = read.open(&ticket, None, &[]).ok_or_else(|| std::io::Error::other("vlessenc"))?;
    open_padding(&mut read, &mut socket)?;
    let ticket = copy16(&ticket)?;
    let span = u16::from_be_bytes([ticket[0], ticket[1]]) as u64;
    if reuse && span > 0 {
        let mut pfs = [0u8; 64];
        pfs.copy_from_slice(&united[..64]);
        remember_client(cache_key, ticket, pfs, span);
    }
    Ok(finish(socket, read, write, mode, &united, &ticket, &iv))
}

fn server_handshake<S: Read + Write>(mut socket: S, secret: &[NfsKey], mode: u8, seconds: (u64, u64), pad: &Pad) -> std::io::Result<Encrypted<S>> {
    if secret.is_empty() {
        return Err(std::io::Error::other("vlessenc"));
    }
    let mut head = vec![0u8; 16 + relays_len(secret)];
    socket.read_exact(&mut head)?;
    let iv: [u8; 16] = head[..16].try_into().unwrap();
    let nfs = open_relays(secret, &mut head[16..], &iv, mode).ok_or_else(|| std::io::Error::other("vlessenc"))?;
    let cache_key = ticket_id(secret, mode);
    let mut length = [0u8; 18];
    socket.read_exact(&mut length)?;
    let (plain_len, mut nfs_aead) = open_first(&iv, &nfs, &length)?;
    let n = be_u16(&plain_len)?;
    if n == 32 {
        return resume(socket, &mut nfs_aead, &cache_key, &nfs, &iv, mode, seconds != (0, 0));
    }
    if n < 1184 + 32 + 16 {
        return Err(std::io::Error::other("vlessenc"));
    }
    let pfs_cipher = read_exact(&mut socket, n)?;
    let pfs_plain = nfs_aead.open(&pfs_cipher, None, &[]).ok_or_else(|| std::io::Error::other("vlessenc"))?;
    let (mlkem, mlkem_cipher) = encapsulate(&pfs_plain[..1184])?;
    let peer_x = PublicKey::from(copy32(&pfs_plain[1184..1216])?);
    let (pfs_secret, pfs_public) = random_x25519();
    let x = checked_x25519(&pfs_secret, &peer_x).ok_or_else(invalid_encryption)?;
    let united = unite(&mlkem, &x, &nfs);
    let mut server_pfs = mlkem_cipher;
    server_pfs.extend(pfs_public.to_bytes());
    let mut write = Record::new(&server_pfs, &united, nfs_aead.aes);
    let read = Record::new(&pfs_plain[..1216], &united, nfs_aead.aes);
    let mut hello = nfs_aead.seal(&server_pfs, Some(MAX_NONCE));
    let mut ticket = random_bytes::<16>();
    let span = pick_seconds(seconds.0, seconds.1) as u16;
    ticket[0] = (span >> 8) as u8;
    ticket[1] = span as u8;
    hello.extend(write.seal(&ticket, None));
    if span > 0 {
        let mut pfs = [0u8; 64];
        pfs.copy_from_slice(&united[..64]);
        // The ticket's advertised lifetime starts when the client receives it.
        let retention = seconds.0.max(seconds.1).min(u16::MAX as u64) + 120;
        remember_server(&cache_key, ticket, pfs, retention);
    }
    write_hello(&mut socket, hello, &mut write, pad)?;
    open_padding(&mut nfs_aead, &mut socket)?;
    Ok(finish(socket, read, write, mode, &united, &iv, &ticket))
}

fn resume<S: Read + Write>(mut socket: S, nfs_aead: &mut Record, cache_key: &[u8; 32], nfs: &[u8; 32], iv: &[u8; 16], mode: u8, allowed: bool) -> std::io::Result<Encrypted<S>> {
    if !allowed {
        return Err(std::io::Error::other("vlessenc"));
    }
    let cipher = read_exact(&mut socket, 32)?;
    let ticket = nfs_aead.open(&cipher, None, &[]).ok_or_else(|| std::io::Error::other("vlessenc"))?;
    let ticket = copy16(&ticket)?;
    let pfs = match recall_server(cache_key, ticket, *nfs) {
        Ok(pfs) => pfs,
        Err(TicketError::Expired) => {
            let mut noise = vec![0; 1279 + random_below(1000) as usize];
            getrandom::getrandom(&mut noise).map_err(|e| std::io::Error::other(e.to_string()))?;
            // The first 16 bytes occupy the resumed server's random prefix.
            if header_length(noise[16..21].try_into().unwrap()).is_some() {
                noise[16] ^= 1;
            }
            socket.write_all(&noise)?;
            socket.flush()?;
            return Err(invalid_encryption());
        }
        Err(TicketError::Replay) => return Err(invalid_encryption()),
    };
    let united = unite_pfs(&pfs, nfs);
    let server_random = random_bytes::<16>();
    let aes = nfs_aead.aes;
    let write = Record::new(&server_random, &united, aes);
    let read = Record::new(&cipher, &united, aes);
    let mut session = finish(socket, read, write, mode, &united, iv, &server_random);
    session.write.prefix.extend_from_slice(&server_random);
    Ok(session)
}

fn finish<S>(inner: S, read: Record, write: Record, mode: u8, united: &[u8], read_iv: &[u8; 16], write_iv: &[u8; 16]) -> Encrypted<S> {
    let (read_mask, write_mask) = if mode == 2 {
        (Some(HeaderMask::new(united, read_iv)), Some(HeaderMask::new(united, write_iv)))
    } else {
        (None, None)
    };
    Encrypted {
        inner,
        read: ReadState::new(Some(read), read_mask),
        write: WriteState::new(write, write_mask),
    }
}

fn seal_length(record: &mut Record, len: usize) -> Vec<u8> {
    record.seal(&(len as u16).to_be_bytes(), None)
}

fn write_hello<W: Write>(writer: &mut W, mut hello: Vec<u8>, record: &mut Record, pad: &Pad) -> std::io::Result<()> {
    let (mut lengths, gaps) = pad.plan();
    let total: usize = lengths.iter().sum();
    lengths[0] += hello.len();
    let body = total - 18 - 16;
    hello.extend(seal_length(record, total - 18));
    hello.extend(record.seal(&vec![0u8; body], None));
    let mut bytes = hello.as_slice();
    for (index, len) in lengths.into_iter().enumerate() {
        let (chunk, remaining) = bytes.split_at(len);
        if !chunk.is_empty() {
            writer.write_all(chunk)?;
            writer.flush()?;
        }
        bytes = remaining;
        if let Some(gap) = gaps.get(index).filter(|gap| !gap.is_zero()) {
            std::thread::sleep(*gap);
        }
    }
    Ok(())
}

fn open_padding<S: Read>(record: &mut Record, socket: &mut S) -> std::io::Result<()> {
    let mut header = [0u8; 18];
    socket.read_exact(&mut header)?;
    let length = record.open(&header, None, &[]).ok_or_else(|| std::io::Error::other("vlessenc"))?;
    let n = be_u16(&length)?;
    let mut body = vec![0u8; n];
    socket.read_exact(&mut body)?;
    record.open(&body, None, &[]).ok_or_else(|| std::io::Error::other("vlessenc"))?;
    Ok(())
}

fn open_first(iv: &[u8], nfs: &[u8], length: &[u8]) -> std::io::Result<(Vec<u8>, Record)> {
    for aes in [true, false] {
        let mut record = Record::new(iv, nfs, aes);
        if let Some(plain) = record.open(length, None, &[]) {
            return Ok((plain, record));
        }
    }
    Err(std::io::Error::other("vlessenc"))
}

fn unite(mlkem: &[u8], x25519: &[u8], nfs: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend(mlkem);
    key.extend(x25519);
    key.extend(nfs);
    key
}

fn mlkem_keypair() -> (ml_kem::Encoded<ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>>, Vec<u8>) {
    use ml_kem::KemCore;
    let mut rng = rand_core::OsRng;
    let (secret, public) = ml_kem::MlKem768::generate(&mut rng);
    let public_bytes = public.as_bytes().to_vec();
    (secret.as_bytes(), public_bytes)
}

fn encapsulate(public: &[u8]) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    use ml_kem::kem::Encapsulate;
    use ml_kem::{EncodedSizeUser, KemCore};
    type Public = <ml_kem::MlKem768 as KemCore>::EncapsulationKey;
    let encoded = ml_kem::Encoded::<Public>::try_from(public).map_err(|_| std::io::Error::other("vlessenc"))?;
    let key = Public::from_bytes(&encoded);
    let mut rng = rand_core::OsRng;
    let (cipher, shared) = key.encapsulate(&mut rng).map_err(|_| std::io::Error::other("vlessenc"))?;
    Ok((shared.to_vec(), cipher.to_vec()))
}

fn decapsulate(secret: &ml_kem::Encoded<ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>>, cipher: &[u8]) -> std::io::Result<Vec<u8>> {
    use ml_kem::kem::Decapsulate;
    use ml_kem::{EncodedSizeUser, KemCore};
    type Secret = <ml_kem::MlKem768 as KemCore>::DecapsulationKey;
    type Cipher = ml_kem::Ciphertext<ml_kem::MlKem768>;
    let secret = Secret::from_bytes(secret);
    let encoded = Cipher::try_from(cipher).map_err(|_| std::io::Error::other("vlessenc"))?;
    let shared = secret.decapsulate(&encoded).map_err(|_| std::io::Error::other("vlessenc"))?;
    Ok(shared.to_vec())
}

fn read_exact<S: Read>(socket: &mut S, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf)?;
    Ok(buf)
}

fn be_u16(bytes: &[u8]) -> std::io::Result<usize> {
    if bytes.len() != 2 {
        return Err(std::io::Error::other("vlessenc"));
    }
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
}

fn copy16(bytes: &[u8]) -> std::io::Result<[u8; 16]> {
    bytes.try_into().map_err(|_| std::io::Error::other("vlessenc"))
}

fn copy32(bytes: &[u8]) -> std::io::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| std::io::Error::other("vlessenc"))
}

fn invalid_encryption() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "vless encryption")
}

struct ClientResume {
    united: Vec<u8>,
    random_mask: bool,
    cache_key: [u8; 32],
    ticket: [u8; 16],
}

struct ReadState {
    record: Option<Record>,
    pending: Vec<u8>,
    cipher: Vec<u8>,
    mask: Option<HeaderMask>,
    resume: Option<ClientResume>,
    direct: bool,
}

impl ReadState {
    fn new(record: Option<Record>, mask: Option<HeaderMask>) -> Self {
        Self { record, pending: Vec::new(), cipher: Vec::new(), mask, resume: None, direct: false }
    }

    fn read(&mut self, reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pending.is_empty() {
            if self.direct {
                let read = reader.read(buf)?;
                if let Some(mask) = &mut self.mask {
                    mask.apply(&mut buf[..read], false);
                }
                return Ok(read);
            }
            let next = self.next_record(reader);
            if matches!(&next, Err(err) if matches!(err.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::InvalidData))
                || matches!(&next, Ok(false))
            {
                if let Some(resume) = self.resume.take() {
                    forget_client(&resume.cache_key, &resume.ticket);
                }
            }
            if !next? {
                return Ok(0);
            }
        }
        let n = self.pending.len().min(buf.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }

    fn next_record(&mut self, reader: &mut impl Read) -> std::io::Result<bool> {
        if self.record.is_none() {
            let resume = self.resume.as_ref().ok_or_else(invalid_encryption)?;
            if !fill_cipher(reader, &mut self.cipher, 16, None)? {
                return Ok(false);
            }
            let random: [u8; 16] = self.cipher.as_slice().try_into().unwrap();
            self.record = Some(Record::new(&random, &resume.united, false));
            self.mask = resume.random_mask.then(|| HeaderMask::new(&resume.united, &random));
            self.cipher.clear();
        }
        if !fill_cipher(reader, &mut self.cipher, 5, self.mask.as_mut())? {
            return Ok(false);
        }
        let header: [u8; 5] = self.cipher[..5].try_into().unwrap();
        let len = header_length(&header).filter(|len| (17..=16640).contains(len)).ok_or_else(invalid_encryption)?;
        fill_cipher(reader, &mut self.cipher, 5 + len, self.mask.as_mut())?;
        let record = self.record.as_mut().expect("initialized record");
        self.pending = open_record(record, &header, &self.cipher[5..]).ok_or_else(invalid_encryption)?;
        self.cipher.clear();
        self.resume = None;
        Ok(true)
    }
}

fn fill_cipher(reader: &mut impl Read, bytes: &mut Vec<u8>, end: usize, mut mask: Option<&mut HeaderMask>) -> std::io::Result<bool> {
    use std::io::ErrorKind;
    let mut offset = bytes.len();
    if offset >= end {
        return Ok(true);
    }
    bytes.resize(end, 0);
    while offset < end {
        match reader.read(&mut bytes[offset..]) {
            Ok(0) => {
                bytes.truncate(offset);
                return if offset == 0 { Ok(false) } else { Err(ErrorKind::UnexpectedEof.into()) };
            }
            Ok(n) => {
                if let Some(mask) = mask.as_deref_mut() {
                    mask.apply(&mut bytes[offset..offset + n], false);
                }
                offset += n;
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                bytes.truncate(offset);
                return Err(err);
            }
        }
    }
    Ok(true)
}

struct WriteState {
    record: Record,
    mask: Option<HeaderMask>,
    prefix: Vec<u8>,
    queued: Vec<u8>,
    sent: usize,
    accepted: usize,
    direct: bool,
}

impl WriteState {
    fn new(record: Record, mask: Option<HeaderMask>) -> Self {
        Self { record, mask, prefix: Vec::new(), queued: Vec::new(), sent: 0, accepted: 0, direct: false }
    }

    fn write(&mut self, writer: &mut impl Write, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.direct && self.mask.is_none() && self.queued.is_empty() {
            return writer.write(buf);
        }
        if self.queued.is_empty() {
            self.accepted = buf.len().min(MAX_PLAIN);
            let bytes = &buf[..self.accepted];
            let mut record = if self.direct { bytes.to_vec() } else { seal_record(&mut self.record, bytes) };
            if let Some(mask) = &mut self.mask {
                mask.apply(&mut record, true);
            }
            self.queued = std::mem::take(&mut self.prefix);
            self.queued.extend_from_slice(&record);
            self.sent = 0;
        }
        self.flush_queue(writer)?;
        self.queued.clear();
        Ok(self.accepted)
    }

    fn flush_queue(&mut self, writer: &mut impl Write) -> std::io::Result<()> {
        use std::io::ErrorKind;
        while self.sent < self.queued.len() {
            match writer.write(&self.queued[self.sent..]) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(n) => self.sent += n,
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn flush(&mut self, writer: &mut impl Write) -> std::io::Result<()> {
        self.flush_queue(writer)?;
        writer.flush()
    }
}

pub struct EncReader<S> {
    inner: S,
    state: ReadState,
}

impl<S> EncReader<S> {
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn start_direct(&mut self) -> std::io::Result<()> {
        if !self.state.cipher.is_empty() || self.state.resume.is_some() {
            return Err(invalid_encryption());
        }
        self.state.direct = true;
        Ok(())
    }
}

impl<S: Read> Read for EncReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state.read(&mut self.inner, buf)
    }
}

impl EncReader<std::net::TcpStream> {
    pub fn set_timeout(&self, timeout: Duration) {
        self.inner.set_read_timeout(Some(timeout)).ok();
    }
}

pub struct EncWriter<S> {
    inner: S,
    state: WriteState,
}

impl<S> EncWriter<S> {
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Write> EncWriter<S> {
    pub fn start_direct(&mut self) -> std::io::Result<()> {
        if !self.state.prefix.is_empty() {
            return Err(invalid_encryption());
        }
        self.flush()?;
        self.state.direct = true;
        Ok(())
    }
}

impl<S: Write> Write for EncWriter<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.write(&mut self.inner, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.state.flush(&mut self.inner)
    }
}

impl EncWriter<std::net::TcpStream> {
    pub fn set_timeout(&self, timeout: Duration) {
        self.inner.set_write_timeout(Some(timeout)).ok();
    }
}

pub fn accept_encrypted<R: Read, W: Write>(reader: R, writer: W, secret: &[NfsKey], mode: u8, from: u64, to: u64, pad: &Pad) -> std::io::Result<(EncReader<R>, EncWriter<W>)> {
    use crate::reality_tls::RealityDuplex;
    let session = server_handshake(RealityDuplex::new(reader, writer), secret, mode, (from, to), pad)?;
    Ok(session.into_halves(RealityDuplex::into_halves))
}

pub fn connect_encrypted<R: Read, W: Write>(reader: R, writer: W, public: &[NfsKey], mode: u8, reuse: bool, pad: &Pad) -> std::io::Result<(EncReader<R>, EncWriter<W>)> {
    use crate::reality_tls::RealityDuplex;
    let session = client_handshake(RealityDuplex::new(reader, writer), public, mode, reuse, pad)?;
    Ok(session.into_halves(RealityDuplex::into_halves))
}

pub fn accept_native(socket: std::net::TcpStream, secret: &[NfsKey], mode: u8, from: u64, to: u64, pad: &Pad) -> std::io::Result<(EncReader<std::net::TcpStream>, EncWriter<std::net::TcpStream>)> {
    let reader = socket.try_clone()?;
    accept_encrypted(reader, socket, secret, mode, from, to, pad)
}

pub fn connect_native(socket: std::net::TcpStream, public: &[NfsKey], mode: u8, reuse: bool, pad: &Pad) -> std::io::Result<(EncReader<std::net::TcpStream>, EncWriter<std::net::TcpStream>)> {
    let reader = socket.try_clone()?;
    connect_encrypted(reader, socket, public, mode, reuse, pad)
}

pub fn native_pair() -> ([u8; 32], [u8; 32]) {
    let (secret, public) = random_x25519();
    (secret.to_bytes(), public.to_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pad {
    lens: Vec<[i32; 3]>,
    gaps: Vec<[i32; 3]>,
}

impl Pad {
    pub fn empty() -> Self {
        Self { lens: Vec::new(), gaps: Vec::new() }
    }

    fn plan(&self) -> (Vec<usize>, Vec<Duration>) {
        const DEFAULT_LENGTHS: [[i32; 3]; 2] = [[100, 111, 1111], [50, 0, 3333]];
        const DEFAULT_GAPS: [[i32; 3]; 1] = [[75, 0, 111]];
        let (lengths, gaps) = if self.lens.is_empty() {
            (DEFAULT_LENGTHS.as_slice(), DEFAULT_GAPS.as_slice())
        } else {
            (self.lens.as_slice(), self.gaps.as_slice())
        };
        let pick = |&[chance, min, max]: &[i32; 3]| {
            if chance as u64 >= random_below(100) { rand_between(min as i64, max as i64) as u64 } else { 0 }
        };
        (lengths.iter().map(|spec| pick(spec) as usize).collect(), gaps.iter().map(|spec| Duration::from_millis(pick(spec))).collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NfsKey {
    X25519([u8; 32]),
    MlKem(Vec<u8>),
}

pub fn server_key(text: &str) -> Option<(Vec<NfsKey>, u8, u64, u64, Pad)> {
    let (mode, round, pad, keys) = appearance(text)?;
    let (from, to) = ticket_span(round)?;
    let mut out = Vec::new();
    for key in keys {
        out.push(match key.len() {
            32 => NfsKey::X25519(key.try_into().ok()?),
            64 => NfsKey::MlKem(key),
            _ => return None,
        });
    }
    Some((out, mode, from, to, pad))
}

fn ticket_span(round: &str) -> Option<(u64, u64)> {
    let body = round.strip_suffix('s')?;
    if let Some((from, to)) = body.split_once('-') {
        let from = from.parse().ok()?;
        let to = to.parse().ok()?;
        if to <= from {
            return None;
        }
        return Some((from, to));
    }
    Some((body.parse().ok()?, 0))
}

pub fn pick_seconds(from: u64, to: u64) -> u64 {
    if to == 0 {
        return (from as u128 * (50 + random_below(50)) as u128 / 100) as u64;
    }
    if from == to {
        return from;
    }
    let (from, to) = if from < to { (from, to) } else { (to, from) };
    from + random_below(to - from)
}

fn random_below(span: u64) -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("random");
    u64::from_le_bytes(bytes) % span
}

pub fn client_key(text: &str) -> Option<(Vec<NfsKey>, u8, u64, Pad)> {
    let (mode, round, pad, keys) = appearance(text)?;
    let reuse = match round {
        "1rtt" => 0,
        "0rtt" => 1,
        _ => return None,
    };
    let mut out = Vec::new();
    for key in keys {
        out.push(match key.len() {
            32 => NfsKey::X25519(key.try_into().ok()?),
            1184 => NfsKey::MlKem(key),
            _ => return None,
        });
    }
    Some((out, mode, reuse, pad))
}

fn appearance(text: &str) -> Option<(u8, &str, Pad, Vec<Vec<u8>>)> {
    let rest = text.strip_prefix("mlkem768x25519plus.")?;
    let (name, rest) = rest.split_once('.')?;
    let (round, rest) = rest.split_once('.')?;
    let mode = match name {
        "native" => 0,
        "xorpub" => 1,
        "random" => 2,
        _ => return None,
    };
    let mut parts: Vec<&str> = rest.split('.').collect();
    let mut specs = Vec::new();
    while parts.first().is_some_and(|part| part.len() < 20) {
        specs.push(parts.remove(0));
    }
    if parts.is_empty() {
        return None;
    }
    let mut keys = Vec::new();
    for part in parts {
        keys.push(b64_decode(part)?);
    }
    Some((mode, round, parse_pad(&specs)?, keys))
}

fn ticket_id(keys: &[NfsKey], mode: u8) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("Kerlico VLESS ticket configuration");
    hash.update(&[mode]);
    for key in keys {
        let bytes = key_material(key);
        hash.update(&(bytes.len() as u32).to_be_bytes());
        hash.update(bytes);
    }
    *hash.finalize().as_bytes()
}

fn share_len(key: &NfsKey) -> usize {
    match key {
        NfsKey::X25519(_) => 32,
        NfsKey::MlKem(_) => 1088,
    }
}

fn relays_len(keys: &[NfsKey]) -> usize {
    keys.iter().map(|key| share_len(key) + 32).sum::<usize>() - 32
}

fn key_material(key: &NfsKey) -> &[u8] {
    match key {
        NfsKey::X25519(bytes) => bytes,
        NfsKey::MlKem(bytes) => bytes,
    }
}

fn client_relays(keys: &[NfsKey], iv: &[u8; 16], mode: u8) -> std::io::Result<(Vec<u8>, [u8; 32])> {
    let mut out = vec![0u8; relays_len(keys)];
    let mut cursor = 0;
    let mut carried: Option<KeyStream> = None;
    let mut nfs = [0u8; 32];
    for (index, key) in keys.iter().enumerate() {
        let (mut block, shared) = match key {
            NfsKey::X25519(public) => {
                let (ephemeral, ephemeral_public) = random_x25519();
                let shared = checked_x25519(&ephemeral, &PublicKey::from(*public)).ok_or_else(invalid_encryption)?;
                (ephemeral_public.to_bytes().to_vec(), shared)
            }
            NfsKey::MlKem(public) => {
                let (shared, cipher) = encapsulate(public)?;
                (cipher, copy32(&shared)?)
            }
        };
        nfs = shared;
        if mode >= 1 {
            xor_stream(key_material(key), iv, &mut block);
        }
        if let Some(stream) = carried.as_mut() {
            stream.apply(&mut block[..32]);
        }
        out[cursor..cursor + block.len()].copy_from_slice(&block);
        cursor += block.len();
        if index + 1 == keys.len() {
            break;
        }
        let mut tag = *blake3::hash(key_material(&keys[index + 1])).as_bytes();
        let mut stream = KeyStream::new(&nfs, iv);
        stream.apply(&mut tag);
        out[cursor..cursor + 32].copy_from_slice(&tag);
        cursor += 32;
        carried = Some(stream);
    }
    Ok((out, nfs))
}

fn open_relays(keys: &[NfsKey], relays: &mut [u8], iv: &[u8; 16], mode: u8) -> Option<[u8; 32]> {
    if relays.len() != relays_len(keys) {
        return None;
    }
    let mut cursor = 0;
    let mut carried: Option<KeyStream> = None;
    let mut nfs = [0u8; 32];
    for (index, key) in keys.iter().enumerate() {
        let width = share_len(key);
        if let Some(stream) = carried.as_mut() {
            stream.apply(&mut relays[cursor..cursor + 32]);
        }
        let public = public_material(key)?;
        if mode >= 1 {
            xor_stream(&public, iv, &mut relays[cursor..cursor + width]);
        }
        nfs = match key {
            NfsKey::X25519(secret) => {
                let peer = PublicKey::from(copy32(&relays[cursor..cursor + 32]).ok()?);
                if peer.to_bytes()[31] > 127 {
                    return None;
                }
                checked_x25519(&StaticSecret::from(*secret), &peer)?
            }
            NfsKey::MlKem(seed) => copy32(&decapsulate_seed(seed, &relays[cursor..cursor + width]).ok()?).ok()?,
        };
        cursor += width;
        if index + 1 == keys.len() {
            break;
        }
        let next = public_material(&keys[index + 1])?;
        let expect = *blake3::hash(&next).as_bytes();
        let mut stream = KeyStream::new(&nfs, iv);
        stream.apply(&mut relays[cursor..cursor + 32]);
        if relays[cursor..cursor + 32] != expect {
            return None;
        }
        cursor += 32;
        carried = Some(stream);
    }
    Some(nfs)
}

fn public_material(key: &NfsKey) -> Option<Vec<u8>> {
    match key {
        NfsKey::X25519(secret) => Some(PublicKey::from(&StaticSecret::from(*secret)).to_bytes().to_vec()),
        NfsKey::MlKem(seed) => mlkem_public(seed),
    }
}

fn mlkem_public(seed: &[u8]) -> Option<Vec<u8>> {
    use ml_kem::{EncodedSizeUser, KemCore};
    if seed.len() != 64 {
        return None;
    }
    let d = ml_kem::B32::try_from(&seed[..32]).ok()?;
    let z = ml_kem::B32::try_from(&seed[32..]).ok()?;
    let (_, public) = ml_kem::MlKem768::generate_deterministic(&d, &z);
    Some(public.as_bytes().to_vec())
}

fn decapsulate_seed(seed: &[u8], cipher: &[u8]) -> std::io::Result<Vec<u8>> {
    use ml_kem::kem::Decapsulate;
    use ml_kem::KemCore;
    if seed.len() != 64 {
        return Err(std::io::Error::other("vlessenc"));
    }
    let d = ml_kem::B32::try_from(&seed[..32]).map_err(|_| std::io::Error::other("vlessenc"))?;
    let z = ml_kem::B32::try_from(&seed[32..]).map_err(|_| std::io::Error::other("vlessenc"))?;
    let (secret, _) = ml_kem::MlKem768::generate_deterministic(&d, &z);
    let encoded = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(cipher).map_err(|_| std::io::Error::other("vlessenc"))?;
    let shared = secret.decapsulate(&encoded).map_err(|_| std::io::Error::other("vlessenc"))?;
    Ok(shared.to_vec())
}

fn parse_pad(parts: &[&str]) -> Option<Pad> {
    if parts.is_empty() {
        return Some(Pad::empty());
    }
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    let mut max_len = 0i32;
    for (index, part) in parts.iter().enumerate() {
        let mut fields = part.split('-');
        let first: i32 = fields.next()?.parse().ok()?;
        let second: i32 = fields.next()?.parse().ok()?;
        let third: i32 = fields.next()?.parse().ok()?;
        if fields.next().is_some() || first < 0 || second < 0 || third < 0 {
            return None;
        }
        if index == 0 && (first < 100 || second < 35 || third < 35) {
            return None;
        }
        if index % 2 == 0 {
            lens.push([first, second, third]);
            max_len = max_len.checked_add(second.max(third))?;
        } else {
            gaps.push([first, second, third]);
        }
    }
    if max_len > 18 + 65535 {
        return None;
    }
    Some(Pad { lens, gaps })
}

fn rand_between(mut from: i64, mut to: i64) -> i64 {
    if from > to {
        std::mem::swap(&mut from, &mut to);
    }
    let span = to - from;
    if span <= 1 {
        return from;
    }
    from + random_below(span as u64) as i64
}

fn unite_pfs(pfs: &[u8; 64], nfs: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend(pfs);
    key.extend(nfs);
    key
}

struct SavedTicket {
    pfs: [u8; 64],
    expiry: Instant,
    seen: HashSet<[u8; 32]>,
}

type ServerTickets = HashMap<[u8; 32], HashMap<[u8; 16], SavedTicket>>;
type ClientTickets = HashMap<[u8; 32], ([u8; 16], [u8; 64], Instant)>;

fn server_table() -> &'static Mutex<ServerTickets> {
    static TABLE: OnceLock<Mutex<ServerTickets>> = OnceLock::new();
    TABLE.get_or_init(Mutex::default)
}

fn client_table() -> &'static Mutex<ClientTickets> {
    static TABLE: OnceLock<Mutex<ClientTickets>> = OnceLock::new();
    TABLE.get_or_init(Mutex::default)
}

fn remember_server(secret: &[u8; 32], ticket: [u8; 16], pfs: [u8; 64], seconds: u64) {
    let now = Instant::now();
    let mut table = server_table().lock().expect("tickets");
    let tickets = table.entry(*secret).or_default();
    tickets.retain(|_, saved| saved.expiry > now);
    tickets.insert(ticket, SavedTicket { pfs, expiry: now + Duration::from_secs(seconds), seen: HashSet::new() });
}

enum TicketError {
    Expired,
    Replay,
}

fn recall_server(secret: &[u8; 32], ticket: [u8; 16], nfs: [u8; 32]) -> Result<[u8; 64], TicketError> {
    let mut table = server_table().lock().expect("tickets");
    let tickets = table.get_mut(secret).ok_or(TicketError::Expired)?;
    let saved = tickets.get_mut(&ticket).ok_or(TicketError::Expired)?;
    if saved.expiry <= Instant::now() {
        tickets.remove(&ticket);
        return Err(TicketError::Expired);
    }
    if !saved.seen.insert(nfs) {
        return Err(TicketError::Replay);
    }
    Ok(saved.pfs)
}

fn remember_client(public: [u8; 32], ticket: [u8; 16], pfs: [u8; 64], seconds: u64) {
    let expiry = Instant::now() + Duration::from_secs(seconds);
    client_table().lock().expect("tickets").insert(public, (ticket, pfs, expiry));
}

fn recall_client(public: &[u8; 32]) -> Option<([u8; 16], [u8; 64])> {
    let mut table = client_table().lock().expect("tickets");
    let (ticket, pfs, expiry) = table.get(public).copied()?;
    if expiry <= Instant::now() {
        table.remove(public);
        return None;
    }
    Some((ticket, pfs))
}

fn forget_client(public: &[u8; 32], ticket: &[u8; 16]) {
    let mut table = client_table().lock().expect("tickets");
    if table.get(public).is_some_and(|(saved, _, _)| saved == ticket) {
        table.remove(public);
    }
}

struct KeyStream {
    stream: ctr::Ctr128BE<aes::Aes256>,
}

impl KeyStream {
    fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        use cipher::KeyIvInit;
        let derived = blake3::derive_key("VLESS", key);
        Self {
            stream: ctr::Ctr128BE::<aes::Aes256>::new(&derived.into(), iv.into()),
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        use cipher::StreamCipher;
        self.stream.apply_keystream(data);
    }
}

fn xor_stream(key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
    KeyStream::new(key, iv).apply(data);
}

pub fn encode_key(prefix: &str, key: &[u8; 32]) -> String {
    format!("{prefix}{}", b64_encode(key))
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
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

fn b64_encode(bytes: &[u8]) -> String {
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

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("random");
    bytes
}

pub fn random_x25519() -> (StaticSecret, PublicKey) {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("random");
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        if public.to_bytes()[31] <= 127 {
            return (secret, public);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_tls::RealityDuplex;

    #[test]
    fn derives_binary_contexts_like_blake3_raw_api() {
        let context: Vec<u8> = (0..1216).map(|index| (index * 37 + 193) as u8).collect();
        let material: Vec<u8> = (0..96).collect();
        // Reference values from blake3_hasher_init_derive_key_raw.
        for (len, expected) in [
            (16, "8636ec1d2f2c413a92a49e5ca4d05e61904711e016de7ce764edd4a57f167758"),
            (1216, "c75e205fe2fc802364337d2d650abe4e4618c671e72efe5585d3a6b108e02a23"),
        ] {
            let actual = derive(&context[..len], &material).map(|b| format!("{b:02x}")).concat();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn low_order_relay_has_no_known_nfs_key() {
        let secret = NfsKey::X25519([3; 32]);
        assert!(open_relays(&[secret], &mut [0; 32], &[0; 16], 0).is_none());
        assert!(client_relays(&[NfsKey::X25519([0; 32])], &[0; 16], 0).is_err());
    }

    #[test]
    fn resumed_request_precedes_server_random_for_each_mode() {
        use std::io::Cursor;
        for mode in [0, 1, 2] {
            let (secret, public) = random_x25519();
            let private = [NfsKey::X25519(secret.to_bytes())];
            let public = [NfsKey::X25519(public.to_bytes())];
            let pfs = [7; 64];
            let ticket = [42; 16];
            remember_client(ticket_id(&public, mode), ticket, pfs, 60);
            remember_server(&ticket_id(&private, mode), ticket, pfs, 60);

            let (mut read, mut write) = connect_encrypted(Cursor::new(Vec::new()), Vec::new(), &public, mode, true, &Pad::empty()).unwrap();
            assert!(write.inner_mut().is_empty());
            write.write_all(b"VLESS request").unwrap();
            let request = std::mem::take(write.inner_mut());
            let (mut peer_read, mut peer_write) = accept_encrypted(Cursor::new(request.clone()), Vec::new(), &private, mode, 60, 60, &Pad::empty()).unwrap();
            assert!(peer_write.inner_mut().is_empty());
            let mut message = [0; 13];
            peer_read.read_exact(&mut message).unwrap();
            assert_eq!(&message, b"VLESS request");
            peer_write.write_all(b"VLESS response").unwrap();
            *read.inner_mut() = Cursor::new(std::mem::take(peer_write.inner_mut()));
            let mut reply = [0; 14];
            read.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"VLESS response");
            assert!(accept_encrypted(Cursor::new(request), Vec::new(), &private, mode, 60, 60, &Pad::empty()).is_err());
        }
    }

    #[test]
    fn stale_ticket_is_discarded_after_the_peer_rejects_it() {
        use std::io::Cursor;
        let (secret, public) = random_x25519();
        let private = [NfsKey::X25519(secret.to_bytes())];
        let public = [NfsKey::X25519(public.to_bytes())];
        let cache_key = ticket_id(&public, 0);
        remember_client(cache_key, [42; 16], [7; 64], 60);
        let (mut read, mut write) = connect_encrypted(Cursor::new(Vec::new()), Vec::new(), &public, 0, true, &Pad::empty()).unwrap();
        write.write_all(b"request").unwrap();
        let mut noise = Vec::new();
        assert!(accept_encrypted(Cursor::new(std::mem::take(write.inner_mut())), &mut noise, &private, 0, 60, 60, &Pad::empty()).is_err());
        *read.inner_mut() = Cursor::new(noise);
        assert!(read.read(&mut [0]).is_err());
        assert!(recall_client(&cache_key).is_none());
    }

    #[test]
    fn random_direct_keeps_masking_headers_and_drains_final_record() {
        use std::io::Cursor;
        let united = [17; 96];
        let iv = [7; 16];
        let traffic = || Record::new(b"context", &united, false);
        let wire = RealityDuplex::new(Cursor::new(Vec::new()), Vec::new());
        let (mut read, mut write) = finish(wire, traffic(), traffic(), 2, &united, &iv, &iv).into_halves(RealityDuplex::into_halves);
        write.write_all(b"final").unwrap();
        let boundary = write.inner_mut().len();
        write.start_direct().unwrap();
        let mut inner = vec![23, 3, 3, 0, 17];
        inner.extend_from_slice(&[9; 17]);
        write.write_all(&inner[..2]).unwrap();
        write.write_all(&inner[2..]).unwrap();
        let wire = std::mem::take(write.inner_mut());
        assert_ne!(&wire[boundary..boundary + 5], &inner[..5]);
        assert_eq!(&wire[boundary + 5..], &inner[5..]);

        *read.inner_mut() = Cursor::new(wire);
        let mut prefix = [0; 2];
        read.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"fi");
        read.start_direct().unwrap();
        let mut after = Vec::new();
        read.read_to_end(&mut after).unwrap();
        assert_eq!(after, [b"nal".as_slice(), &inner].concat());
    }

    #[test]
    fn native_1rtt_carries_a_record() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        let (secret, public) = random_x25519();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut session = server_handshake(socket, &[NfsKey::X25519(secret.to_bytes())], 0, (0, 0), &Pad::empty()).unwrap();
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            session.write_all(b"pong").unwrap();
        });
        let socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut session = client_handshake(socket, &[NfsKey::X25519(public.to_bytes())], 0, false, &Pad::empty()).unwrap();
        session.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn xorpub_1rtt_carries_a_record() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        let (secret, public) = random_x25519();
        let encoded = encode_key("mlkem768x25519plus.xorpub.0s.", &secret.to_bytes());
        assert_eq!(server_key(&encoded), Some((vec![NfsKey::X25519(secret.to_bytes())], 1, 0, 0, Pad::empty())));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut session = server_handshake(socket, &[NfsKey::X25519(secret.to_bytes())], 1, (0, 0), &Pad::empty()).unwrap();
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            session.write_all(b"pong").unwrap();
        });
        let socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut session = client_handshake(socket, &[NfsKey::X25519(public.to_bytes())], 1, false, &Pad::empty()).unwrap();
        session.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn random_1rtt_carries_a_record() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        let (secret, public) = random_x25519();
        let encoded = encode_key("mlkem768x25519plus.random.0s.", &secret.to_bytes());
        assert_eq!(server_key(&encoded), Some((vec![NfsKey::X25519(secret.to_bytes())], 2, 0, 0, Pad::empty())));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut session = server_handshake(socket, &[NfsKey::X25519(secret.to_bytes())], 2, (0, 0), &Pad::empty()).unwrap();
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            session.write_all(b"pong").unwrap();
        });
        let socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut session = client_handshake(socket, &[NfsKey::X25519(public.to_bytes())], 2, false, &Pad::empty()).unwrap();
        session.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn second_connection_reuses_the_ticket() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        struct Counted {
            inner: std::net::TcpStream,
            read: Arc<AtomicUsize>,
        }
        impl Read for Counted {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.inner.read(buf)?;
                self.read.fetch_add(n, Ordering::Relaxed);
                Ok(n)
            }
        }
        impl Write for Counted {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.inner.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }
        let (secret, public) = random_x25519();
        let encoded = encode_key("mlkem768x25519plus.native.0rtt.", &public.to_bytes());
        assert_eq!(client_key(&encoded).map(|(_, mode, reuse, _)| (mode, reuse)), Some((0, 1)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let first_secret = secret.to_bytes();
        let server = thread::spawn(move || {
            let secret_2 = StaticSecret::from(first_secret);
            let (socket, _) = listener.accept().unwrap();
            let mut session = server_handshake(socket, &[NfsKey::X25519(secret_2.to_bytes())], 0, (60, 60), &Pad::empty()).unwrap();
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).unwrap();
            session.write_all(b"pong").unwrap();
        });
        let socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut session = client_handshake(socket, &[NfsKey::X25519(public.to_bytes())], 0, true, &Pad::empty()).unwrap();
        session.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).unwrap();
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let read = Arc::new(AtomicUsize::new(0));
        let read_2 = Arc::clone(&read);
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let socket = Counted { inner: socket, read: read_2 };
            let mut session = server_handshake(socket, &[NfsKey::X25519(secret.to_bytes())], 0, (60, 60), &Pad::empty()).unwrap();
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            session.write_all(b"pong").unwrap();
        });
        let socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut session = client_handshake(socket, &[NfsKey::X25519(public.to_bytes())], 0, true, &Pad::empty()).unwrap();
        session.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
        assert!(read.load(Ordering::Relaxed) < 400);
    }

    #[test]
    fn padding_spec_sets_the_record_length() {
        use std::io::{Read, Write};
        let (secret, public) = random_x25519();
        let server = encode_key("mlkem768x25519plus.native.0s.100-80-80.", &secret.to_bytes());
        let client = encode_key("mlkem768x25519plus.native.1rtt.100-80-80.", &public.to_bytes());
        let (_, _, _, _, pad) = server_key(&server).unwrap();
        assert_eq!(pad.plan().0, [80]);
        let (_, _, _, pad) = client_key(&client).unwrap();
        assert_eq!(pad.plan().0, [80]);
        assert_eq!(server_key(&format!("{server}.{}", b64_encode(&secret.to_bytes()))).unwrap().0.len(), 2);
        let (left_secret, left_public) = random_x25519();
        let (right_secret, right_public) = random_x25519();
        let server_text = format!(
            "mlkem768x25519plus.native.0s.{}.{}",
            b64_encode(&left_secret.to_bytes()),
            b64_encode(&right_secret.to_bytes())
        );
        let client_text = format!(
            "mlkem768x25519plus.native.1rtt.{}.{}",
            b64_encode(&left_public.to_bytes()),
            b64_encode(&right_public.to_bytes())
        );
        let (secrets, _, _, _, pad) = server_key(&server_text).unwrap();
        let (publics, _, _, _) = client_key(&client_text).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut session = server_handshake(socket, &secrets, 0, (0, 0), &pad).unwrap();
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            session.write_all(b"pong").unwrap();
        });
        let socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut session = client_handshake(socket, &publics, 0, false, &Pad::empty()).unwrap();
        session.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
        assert!(server_key("mlkem768x25519plus.native.0s.10-80-80.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_none());
    }

    #[test]
    fn mlkem_relay_carries_a_record() {
        use std::io::{Read, Write};
        let mut seed = [0u8; 64];
        getrandom::getrandom(&mut seed).unwrap();
        let public = mlkem_public(&seed).unwrap();
        assert_eq!(public.len(), 1184);
        let server_text = format!("mlkem768x25519plus.native.0s.{}", b64_encode(&seed));
        let client_text = format!("mlkem768x25519plus.native.1rtt.{}", b64_encode(&public));
        let (secrets, _, _, _, pad) = server_key(&server_text).unwrap();
        let (publics, _, _, _) = client_key(&client_text).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut session = server_handshake(socket, &secrets, 0, (0, 0), &pad).unwrap();
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            session.write_all(b"pong").unwrap();
        });
        let socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut session = client_handshake(socket, &publics, 0, false, &Pad::empty()).unwrap();
        session.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn ticket_span_stays_inside_the_range() {
        let text = encode_key("mlkem768x25519plus.native.300-600s.", &[7u8; 32]);
        assert_eq!(server_key(&text).map(|(_, mode, from, to, _)| (mode, from, to)), Some((0, 300, 600)));
        for _ in 0..64 {
            let seconds = pick_seconds(300, 600);
            assert!((300..600).contains(&seconds));
            let half = pick_seconds(600, 0);
            assert!((300..600).contains(&half));
        }
        assert_eq!(pick_seconds(0, 0), 0);
        assert_eq!(pick_seconds(60, 60), 60);
    }

    #[test]
    fn record_roundtrip() {
        let mut writer = Record::new(b"context", b"material", false);
        let mut reader = Record::new(b"context", b"material", false);
        let sealed = seal_record(&mut writer, b"ping");
        assert_eq!(&sealed[..3], &[23, 3, 3]);
        let mut header = [0u8; 5];
        header.copy_from_slice(&sealed[..5]);
        let opened = open_record(&mut reader, &header, &sealed[5..]).unwrap();
        assert_eq!(opened, b"ping");
    }
}
