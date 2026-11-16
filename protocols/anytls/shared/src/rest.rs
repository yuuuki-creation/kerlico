//! RestLS authenticated handshake and records.

mod tls12;

use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use kerlico_tls::advanced::{self, AdvancedTlsClientConfig, AdvancedTlsRead};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

use crate::shadow::{hello_extensions, is_tls13, record, server_random, sized, take, RecordRead};
use crate::tls::{ClientTls, Established, TransportWrite, MAX_PLAIN};

const AUTH: usize = 12;
const DEFAULT_SCRIPT: &str = "250?100<1,350~100<1,600~100,300~200,300~100";
const HRR: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

fn random_in(range: usize) -> io::Result<usize> {
    if range == 0 {
        return Ok(0);
    }
    let mut bytes = [0; 4];
    fill(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize % range)
}

fn fill(bytes: &mut [u8]) -> io::Result<()> {
    SystemRandom::new().fill(bytes).map_err(|_| io::Error::other("RestLS random data"))
}

#[derive(Clone, Copy)]
struct Line {
    size: usize,
    range: usize,
    response: Option<u8>,
}

#[derive(Clone)]
pub struct Config {
    key: [u8; 32],
    script: Arc<[Line]>,
    min_record_len: usize,
}

impl Config {
    pub fn new(password: &str, script: &str, min_record_len: usize) -> io::Result<Self> {
        let script = if script.is_empty() { DEFAULT_SCRIPT.into() } else { script.replace(' ', "") };
        let mut lines = Vec::new();
        for text in script.split(',').filter(|text| !text.is_empty()) {
            let (size, response) = if let Some((left, right)) = text.split_once('<') {
                let response = right.parse::<u8>().ok().filter(|&n| n < 255).ok_or_else(|| invalid("RestLS response count"))?;
                (left, Some(response))
            } else {
                (text, None)
            };
            let mut range = 0;
            let mut pick_once = false;
            let raw_size = if let Some((left, right)) = size.split_once(['~', '?']) {
                range = right.parse::<usize>().map_err(|_| invalid("RestLS record range"))?;
                pick_once = size.contains('?');
                left
            } else {
                size
            };
            let mut size = raw_size.parse::<usize>().map_err(|_| invalid("RestLS record size"))?;
            if size > 32767 || range > 32767 || size + range > 32768 || lines.len() >= 256 {
                return Err(invalid("RestLS script sizing is out of range"));
            }
            if pick_once {
                size += random_in(range)?;
                range = 0;
            }
            lines.push(Line { size, range, response });
        }
        Ok(Self {
            key: blake3::derive_key("restls-traffic-key", password.as_bytes()), script: lines.into(),
            min_record_len: if min_record_len == 0 { 15 } else { min_record_len.min(MAX_PLAIN - AUTH) },
        })
    }

    fn recognizes(&self, record: &[u8]) -> bool {
        let Some(hello) = record.get(5..) else { return false };
        if record.first() != Some(&22) || hello.get(38) != Some(&32) {
            return false;
        }
        matches!((hello_hash(&self.key, hello), hello.get(39..55)), (Some(hash), Some(tag)) if bool::from(hash.ct_eq(tag)))
    }

    pub fn candidate(&self, record: &[u8]) -> bool { tls12::client_hello(record).is_some() }
}

fn hello_hash(key: &[u8; 32], hello: &[u8]) -> Option<[u8; 16]> {
    let mut mac = blake3::Hasher::new_keyed(key);
    let mut ext = hello_extensions(hello)?;
    while let Some(kind) = take(&mut ext, 2) {
        let mut value = sized(&mut ext, 2)?;
        if kind == [0, 51] {
            let mut shares = sized(&mut value, 2)?;
            while !shares.is_empty() {
                mac.update(take(&mut shares, 2)?);
                mac.update(sized(&mut shares, 2)?);
            }
        }
        if kind == [0, 41] {
            let mut identities = sized(&mut value, 2)?;
            while !identities.is_empty() {
                mac.update(sized(&mut identities, 2)?);
                take(&mut identities, 4)?;
            }
        }
    }
    Some(mac.finalize().as_bytes()[..16].try_into().expect("RestLS handshake MAC"))
}

fn mask_server_record(frame: &mut [u8], key: &[u8; 32], random: &[u8; 32], explicit_nonce: bool) {
    let start = if explicit_nonce { 13 } else { 5 };
    for (byte, mask) in frame[start..].iter_mut().zip(&blake3::keyed_hash(key, random).as_bytes()[..16]) {
        *byte ^= mask;
    }
}

pub struct Client {
    wire: Config,
    tls: Arc<AdvancedTlsClientConfig>,
    tls12: bool,
}

impl Client {
    pub fn new(password: &str, hint: &str, script: &str, tls: &ClientTls) -> io::Result<Self> {
        let tls12 = hint.eq_ignore_ascii_case("tls12");
        if !tls12 && !hint.eq_ignore_ascii_case("tls13") { return Err(invalid("unsupported RestLS version hint")); }
        let wire = Config::new(password, script, 0)?;
        let mut options = tls.advanced();
        options.min_version = if tls12 { "1.2" } else { "1.3" }.into();
        options.max_version.clone_from(&options.min_version);
        options.enable_session_resumption = true;
        if tls12 {
            options.curve_preferences = vec!["X25519".into(), "P-256".into(), "P-384".into()];
        }
        if options.fingerprint.is_empty() {
            options.fingerprint = "chrome".into();
        }
        Ok(Self { wire, tls: advanced::advanced_client_config(&options)?, tls12 })
    }

    pub fn connect(&self, tcp: TcpStream, name: &str) -> io::Result<Established> {
        let info = Arc::new(Mutex::new(HandshakeInfo::default()));
        let finish = Arc::new(Mutex::new(Vec::new()));
        let key = self.wire.key;
        let read = HandshakeRx {
            tcp: tcp.try_clone()?, key, info: info.clone(), masked: false, pending: Cursor::new(Vec::new()),
            tls12: self.tls12, ccs: false, messages: tls12::Messages::default(),
        };
        let write = HandshakeTx { tcp: tcp.try_clone()?, finish: finish.clone(), tls12: self.tls12, ccs: false, pending: Vec::new() };
        let (read, _) = if self.tls12 {
            advanced::connect_advanced_tls_with_tls12_shares(read, write, self.tls.clone(), name, &tls12::CURVES,
                move |hello, shares, session| tls12::tag_hello(&key, hello, shares, session))?
        } else {
            advanced::connect_advanced_tls_with_hello(read, write, self.tls.clone(), name,
                move |hello, _, session| {
                    let Some(tag) = hello_hash(&key, hello) else { return false };
                    let Some(prefix) = session.get_mut(..16) else { return false };
                    prefix.copy_from_slice(&tag);
                    true
                })?
        };
        let info = info.lock().expect("RestLS handshake");
        let random = info.random.ok_or_else(|| invalid("RestLS ServerHello missing"))?;
        let mut finish = std::mem::take(&mut *finish.lock().expect("RestLS handshake"));
        if self.tls12 && !read.session_reused() {
            finish.clear();
        } else if finish.is_empty() {
            return Err(invalid("RestLS client Finished missing"));
        }
        let read_nonce = if info.parrot { Nonce::ExplicitSequence } else { Nonce::Implicit };
        let write_nonce = if info.gcm { Nonce::ExplicitSequence } else { Nonce::Implicit };
        attach(tcp, self.wire.clone(), random, Transition {
            finish, metadata: (!self.tls12).then(|| Box::new(read)), client: true, read_nonce, write_nonce,
            ..Default::default()
        })
    }
}

#[derive(Default)]
struct HandshakeInfo { random: Option<[u8; 32]>, gcm: bool, parrot: bool }

struct HandshakeRx {
    tcp: TcpStream,
    key: [u8; 32],
    info: Arc<Mutex<HandshakeInfo>>,
    masked: bool,
    pending: Cursor<Vec<u8>>,
    tls12: bool,
    ccs: bool,
    messages: tls12::Messages,
}

impl Read for HandshakeRx {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.pending.read(bytes)?;
        if count != 0 || bytes.is_empty() {
            return Ok(count);
        }
        let mut frame = record(&mut self.tcp)?;
        let mut info = self.info.lock().expect("RestLS handshake");
        if self.tls12 {
            if frame[0] == 20 {
                self.ccs = true;
            } else if frame[0] == 22 && !self.ccs && info.random.is_none() {
                self.messages.feed(&frame, |kind, body| {
                    if kind == 2 {
                        if let Some((random, gcm)) = tls12::server_hello(body) {
                            info.random = Some(random);
                            info.gcm = gcm;
                        }
                    }
                })?;
            } else if frame[0] == 22 && self.ccs && !self.masked {
                let random = info.random.ok_or_else(|| invalid("RestLS ServerHello missing"))?;
                info.parrot = info.gcm && frame.get(5..13) == Some(&[0; 8]);
                mask_server_record(&mut frame, &self.key, &random, info.parrot);
                self.masked = true;
            }
        } else if let Some(value) = server_random(&frame) {
            if value == HRR || !is_tls13(&frame) {
                return Err(invalid("RestLS target has no usable TLS 1.3 ServerHello"));
            }
            info.random = Some(value);
        }
        if !self.tls12 && frame[0] == 23 && !self.masked {
            mask_server_record(&mut frame, &self.key, &info.random.ok_or_else(|| invalid("RestLS ServerHello missing"))?, false);
            self.masked = true;
        }
        self.pending = Cursor::new(frame);
        self.pending.read(bytes)
    }
}

struct HandshakeTx {
    tcp: TcpStream,
    finish: Arc<Mutex<Vec<u8>>>,
    tls12: bool,
    ccs: bool,
    pending: Vec<u8>,
}

impl Write for HandshakeTx {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tcp.write_all(bytes)?;
        let written = bytes.len();
        self.pending.extend_from_slice(bytes);
        let mut pos = 0;
        while let Some((header, _)) = self.pending[pos..].split_first_chunk::<5>() {
            let size = 5 + u16::from_be_bytes([header[3], header[4]]) as usize;
            let Some(one) = self.pending.get(pos..pos + size) else { break };
            if self.tls12 && header[0] == 20 { self.ccs = true; }
            if (!self.tls12 && header[0] == 23) || (self.tls12 && self.ccs && header[0] == 22) {
                let mut finish = self.finish.lock().expect("RestLS handshake");
                finish.clear();
                finish.extend_from_slice(one);
            }
            pos += size;
        }
        self.pending.drain(..pos);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn accept(
    mut client: TcpStream, mut target: TcpStream, client_hello: &[u8], config: &Config,
    fallback: impl FnOnce(&TcpStream, &TcpStream) -> io::Result<()>,
) -> io::Result<Option<Established>> {
    let auth12 = tls12::client_hello(client_hello).ok_or_else(|| invalid("invalid RestLS ClientHello"))?;
    target.write_all(client_hello)?;
    let server = record(&mut target)?;
    client.write_all(&server)?;
    if !is_tls13(&server) {
        return tls12::accept(client, target, auth12, server, config, fallback);
    }
    let Some(random) = server_random(&server).filter(|random| *random != HRR && config.recognizes(client_hello)) else {
        fallback(&client, &target)?;
        return Ok(None);
    };
    accept_tls13(client, target, config, random).map(Some)
}

fn accept_tls13(client: TcpStream, target: TcpStream, config: &Config, random: [u8; 32]) -> io::Result<Established> {
    let finished = AtomicBool::new(false);
    let switching = AtomicBool::new(false);
    target.set_read_timeout(Some(std::time::Duration::from_millis(25)))?;
    let (prefix, reply, metadata) = thread::scope(|scope| {
        let from = &target;
        let mut to = &client;
        let seen_client = &finished;
        let switching = &switching;
        let download = scope.spawn(move || -> io::Result<usize> {
            let mut first = true;
            let mut metadata = 0;
            let mut receive = RecordRead::default();
            loop {
                match receive.recv(from) {
                    Ok(()) => (),
                    Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                        if switching.load(Ordering::Acquire) { break; }
                        continue;
                    }
                    Err(error) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset) => break,
                    Err(error) => return Err(error),
                }
                let frame = &mut receive.wire;
                if frame[0] == 23 && first {
                    first = false;
                    mask_server_record(frame, &config.key, &random, false);
                }
                if seen_client.load(Ordering::Acquire) {
                    if metadata == 8 || frame[0] != 23 { break; }
                    metadata += 1;
                }
                to.write_all(frame)?;
            }
            Ok(metadata)
        });
        let outcome = (|| {
            let mut from = &client;
            let mut to = &target;
            let mut finished = Vec::new();
            let mut codec = Codec::new(config.key, random, false, Vec::new());
            loop {
                let mut frame = record(&mut from)?;
                if frame[0] == 23 {
                    seen_client.store(true, Ordering::Release);
                    if !finished.is_empty() {
                        codec.finished.clone_from(&finished);
                        if codec.check(&frame) {
                            let (start, end, response) = codec.open(&mut frame)?;
                            return Ok((frame[start..end].to_vec(), response));
                        }
                    }
                    finished.clone_from(&frame);
                } else if frame[0] != 20 {
                    return Err(invalid("unexpected RestLS client handshake record"));
                }
                to.write_all(&frame)?;
            }
        })();
        switching.store(true, Ordering::Release);
        let _ = target.shutdown(if outcome.is_ok() { Shutdown::Write } else { Shutdown::Both });
        let metadata = download.join().map_err(|_| invalid("RestLS target reader"))?;
        let (prefix, reply) = outcome?;
        Ok::<_, io::Error>((prefix, reply, metadata?))
    })?;
    attach(client, config.clone(), random, Transition { prefix, reply, first_received: true, write_seq: metadata, ..Default::default() })
}

#[derive(Clone, Copy, Default)]
enum Nonce {
    #[default]
    Implicit,
    ExplicitSequence,
}

impl Nonce {
    fn bytes(self) -> usize { if matches!(self, Self::Implicit) { 0 } else { 8 } }
}

struct Codec {
    key: [u8; 32],
    random: [u8; 32],
    down: bool,
    seq: usize,
    finished: Vec<u8>,
    nonce: Nonce,
}

impl Codec {
    fn new(key: [u8; 32], random: [u8; 32], down: bool, finished: Vec<u8>) -> Self {
        Self { key, random, down, seq: 0, finished, nonce: Nonce::Implicit }
    }

    fn hash(&self) -> blake3::Hasher {
        let mut mac = blake3::Hasher::new_keyed(&self.key);
        mac.update(&self.random);
        mac.update(if self.down { b"server-to-client" } else { b"client-to-server" });
        mac.update(&(self.seq as u64).to_be_bytes());
        mac
    }

    fn mask(&self, frame: &mut [u8]) {
        let prefix = 5 + self.nonce.bytes();
        let mut mac = self.hash();
        mac.update(&frame[prefix + AUTH..][..(frame.len() - prefix - AUTH).min(32)]);
        for (byte, key) in frame[prefix + 8..prefix + AUTH].iter_mut().zip(mac.finalize().as_bytes()) {
            *byte ^= key;
        }
    }

    fn tag(&self, frame: &[u8]) -> [u8; 8] {
        let prefix = 5 + self.nonce.bytes();
        let mut mac = self.hash();
        mac.update(&self.finished);
        mac.update(&frame[..prefix]);
        mac.update(&frame[prefix + 8..]);
        mac.finalize().as_bytes()[..8].try_into().expect("RestLS MAC")
    }

    fn check(&self, frame: &[u8]) -> bool {
        let prefix = 5 + self.nonce.bytes();
        frame.len() >= prefix + AUTH && frame[..3] == [23, 3, 3]
            && (!matches!(self.nonce, Nonce::ExplicitSequence) || frame[5..13] == ((self.seq as u64) + 1).to_be_bytes())
            && bool::from(self.tag(frame).ct_eq(&frame[prefix..prefix + 8]))
    }

    fn open(&mut self, frame: &mut [u8]) -> io::Result<(usize, usize, u8)> {
        self.mask(frame);
        let start = 5 + self.nonce.bytes() + AUTH;
        let meta = &frame[start - 4..start];
        let end = start + u16::from_be_bytes([meta[0], meta[1]]) as usize;
        if end > frame.len() || meta[2] > 1 {
            return Err(invalid("RestLS record layout"));
        }
        self.finished.clear();
        self.seq += 1;
        Ok((start, end, if meta[2] == 1 { meta[3] } else { 0 }))
    }
}

#[derive(Default)]
struct Transition {
    finish: Vec<u8>,
    prefix: Vec<u8>,
    reply: u8,
    metadata: Option<Box<AdvancedTlsRead<HandshakeRx>>>,
    client: bool,
    first_received: bool,
    read_finish: Vec<u8>,
    read_nonce: Nonce,
    write_nonce: Nonce,
    write_seq: usize,
}

fn attach(tcp: TcpStream, config: Config, random: [u8; 32], transition: Transition) -> io::Result<Established> {
    let client = transition.client;
    let mut writer = Sender {
        tcp: tcp.try_clone()?, codec: Codec::new(config.key, random, !client, transition.finish),
        config: config.clone(), wire: Vec::new(),
    };
    writer.codec.nonce = transition.write_nonce;
    writer.codec.seq = transition.write_seq;
    writer.respond(transition.reply)?;
    let writer = Arc::new(Mutex::new(writer));
    let mut decoder = Codec::new(config.key, random, client, transition.read_finish);
    decoder.nonce = transition.read_nonce;
    if transition.first_received {
        decoder.seq = 1;
    }
    let read = Receiver {
        tcp: tcp.try_clone()?, record: RecordRead::default(), codec: decoder, writer: writer.clone(),
        pending: Cursor::new(transition.prefix), initial: client, metadata: transition.metadata,
    };
    Ok(Established::wrapped(tcp, read, Tx(writer)))
}

struct Receiver {
    tcp: TcpStream,
    record: RecordRead,
    codec: Codec,
    writer: Arc<Mutex<Sender>>,
    pending: Cursor<Vec<u8>>,
    initial: bool,
    metadata: Option<Box<AdvancedTlsRead<HandshakeRx>>>,
}

impl Read for Receiver {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.pending.read(bytes)?;
        if n != 0 || bytes.is_empty() {
            return Ok(n);
        }
        loop {
            self.record.recv(&self.tcp)?;
            let frame = &mut self.record.wire;
            if frame[0] == 21 {
                return Ok(0);
            }
            let mut matched = self.codec.check(frame);
            if !matched && self.initial {
                // The peer may have forwarded a TLS ticket just before it switched to RestLS.
                // If it still counted the ticket as part of the handshake, the first
                // authenticated RestLS record can have an earlier sequence.
                let current = self.codec.seq;
                for candidate in (current.saturating_sub(8)..current).rev() {
                    self.codec.seq = candidate;
                    if self.codec.check(frame) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    self.codec.seq = current;
                }
            }
            if !matched {
                let Some(tls) = &mut self.metadata else { return Err(invalid("RestLS record proof did not match")) };
                if !tls.consume_tls_metadata(frame)? {
                    return Ok(0);
                }
                self.codec.seq += 1;
                continue;
            }
            self.initial = false;
            let (start, end, response) = self.codec.open(frame)?;
            if response > 0 {
                self.writer.lock().expect("RestLS sender").respond(response)?;
            }
            if end != start {
                frame.truncate(end);
                std::mem::swap(self.pending.get_mut(), frame);
                self.pending.set_position(start as u64);
                return self.pending.read(bytes);
            }
        }
    }
}

struct Sender {
    tcp: TcpStream,
    codec: Codec,
    config: Config,
    wire: Vec<u8>,
}

impl Sender {
    fn send(&mut self, data: &[u8]) -> io::Result<(usize, u8)> {
        let line = self.config.script.get(self.codec.seq);
        let requested = if let Some(line) = line {
            line.size + random_in(line.range)?
        } else if self.codec.down || data.is_empty() {
            data.len().max(self.config.min_record_len + random_in(100)?)
        } else {
            data.len()
        };
        let nonce = self.codec.nonce.bytes();
        let size = requested.clamp(1, MAX_PLAIN - AUTH - nonce);
        let count = data.len().min(size);
        let response = line.and_then(|line| line.response).unwrap_or(0);
        let bytes = (size + AUTH + nonce) as u16;
        self.wire.clear();
        self.wire.extend_from_slice(&[23, 3, 3]);
        self.wire.extend_from_slice(&bytes.to_be_bytes());
        match self.codec.nonce {
            Nonce::Implicit => (),
            Nonce::ExplicitSequence => self.wire.extend_from_slice(&((self.codec.seq as u64) + 1).to_be_bytes()),
        }
        self.wire.extend_from_slice(&[0; 8]);
        self.wire.extend_from_slice(&(count as u16).to_be_bytes());
        self.wire.extend_from_slice(&[u8::from(response != 0), response]);
        self.wire.extend_from_slice(&data[..count]);
        self.wire.resize(5 + bytes as usize, 0);
        let prefix = 5 + nonce;
        fill(&mut self.wire[prefix + AUTH + count..])?;
        self.codec.mask(&mut self.wire);
        let tag = self.codec.tag(&self.wire);
        self.wire[prefix..prefix + 8].copy_from_slice(&tag);
        self.tcp.write_all(&self.wire)?;
        self.codec.finished.clear();
        self.codec.seq += 1;
        Ok((count, response))
    }

    fn respond(&mut self, count: u8) -> io::Result<()> {
        for _ in 0..count {
            self.send(&[])?;
        }
        Ok(())
    }
}

struct Tx(Arc<Mutex<Sender>>);

impl Write for Tx {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut sender = self.0.lock().expect("RestLS sender");
        let (count, response) = sender.send(data)?;
        sender.respond(response.saturating_sub(1))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TransportWrite for Tx {
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
