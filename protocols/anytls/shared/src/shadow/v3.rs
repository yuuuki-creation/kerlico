use super::{advanced, invalid, key, record, AdvancedTlsClientConfig, Established, APPLICATION, MAX_PLAIN, RecordRead};
use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use ring::hmac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::tls::TransportWrite;

const TAG: usize = 4;
const SID: usize = 1 + 3 + 2 + 32 + 1;
const SID_END: usize = SID + 32;

fn digest(key: &hmac::Key, random: &[u8; 32], direction: Option<u8>) -> hmac::Context {
    let mut mac = hmac::Context::with_key(key);
    mac.update(random);
    if let Some(direction) = direction {
        mac.update(&[direction]);
    }
    mac
}

fn tag(mac: &hmac::Context) -> [u8; TAG] {
    mac.clone().sign().as_ref()[..TAG].try_into().expect("ShadowTLS HMAC")
}

pub fn find_password<'a>(record: &[u8], passwords: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let hello = record.get(5..)?;
    if record.first() != Some(&22) || hello.first() != Some(&1) || hello.get(SID - 1) != Some(&32) {
        return None;
    }
    let auth = hello.get(SID_END - TAG..SID_END)?;
    passwords.into_iter().find(|password| {
        let mut mac = hmac::Context::with_key(&key(password));
        mac.update(&hello[..SID_END - TAG]);
        mac.update(&[0; TAG]);
        mac.update(&hello[SID_END..]);
        bool::from(tag(&mac).ct_eq(auth))
    })
}

pub(super) fn connect(
    tcp: TcpStream, sni: &str, config: Arc<AdvancedTlsClientConfig>, key: &hmac::Key, password: &str,
) -> io::Result<Established> {
    let state = Arc::new(Mutex::new(HandshakeState::default()));
    let mutator = key.clone();
    let customize = move |hello: &[u8], _: &mut [u8; 32], session: &mut [u8]| {
        if session.len() != 32 || hello.len() < SID_END {
            return false;
        }
        session[32 - TAG..].fill(0);
        let mut mac = hmac::Context::with_key(&mutator);
        mac.update(&hello[..SID]);
        mac.update(session);
        mac.update(&hello[SID_END..]);
        session[32 - TAG..].copy_from_slice(&tag(&mac));
        true
    };
    let read = HandshakeReader {
        socket: tcp.try_clone()?, state: state.clone(), key: key.clone(),
        password: password.as_bytes().to_vec(), pending: Cursor::new(Vec::new()),
    };
    let parts = advanced::connect_advanced_tls_with_hello(read, tcp.try_clone()?, config, sni, customize)?;
    drop(parts);
    let mut state = state.lock().expect("ShadowTLS handshake");
    let authenticated = state.authenticated;
    let random = state.random.filter(|_| authenticated).ok_or_else(|| invalid("ShadowTLS server did not prove its password"))?;
    verified(tcp, digest(key, &random, Some(b'S')), digest(key, &random, Some(b'C')),
             state.digest.take(), Vec::new())
}

#[derive(Default)]
struct HandshakeState {
    random: Option<[u8; 32]>,
    digest: Option<hmac::Context>,
    xor: [u8; 32],
    authenticated: bool,
}

struct HandshakeReader {
    socket: TcpStream,
    state: Arc<Mutex<HandshakeState>>,
    key: hmac::Key,
    password: Vec<u8>,
    pending: Cursor<Vec<u8>>,
}

impl Read for HandshakeReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.pending.read(bytes)?;
        if n > 0 || bytes.is_empty() {
            return Ok(n);
        }
        let mut frame = record(&mut self.socket)?;
        let mut state = self.state.lock().expect("ShadowTLS handshake");
        if state.random.is_none() {
            if let Some(random) = server_random(&frame) {
                state.random = Some(random);
                state.digest = Some(digest(&self.key, &random, None));
                state.xor = xor_key(&self.password, &random);
                state.authenticated = !is_tls13(&frame);
            }
        }
        if frame[0] == APPLICATION {
            let mac = state.digest.as_mut().ok_or_else(|| invalid("ShadowTLS ServerHello is missing"))?;
            if !verify_frame(mac, &frame, false) {
                return Err(invalid("ShadowTLS handshake record proof did not match"));
            }
            xor(&mut frame[5 + TAG..], &state.xor);
            frame.drain(5..5 + TAG);
            let count = (frame.len() - 5) as u16;
            frame[3..5].copy_from_slice(&count.to_be_bytes());
            state.authenticated = true;
        }
        self.pending = Cursor::new(frame);
        self.pending.read(bytes)
    }
}

pub(crate) fn server_random(frame: &[u8]) -> Option<[u8; 32]> {
    if frame.first() == Some(&22) && frame.get(5) == Some(&2) {
        frame.get(11..43)?.try_into().ok()
    } else {
        None
    }
}

pub(crate) fn is_tls13(frame: &[u8]) -> bool {
    let Some(session_len) = frame.get(43) else { return false };
    let Some(extensions) = frame.get(44 + *session_len as usize + 3..) else { return false };
    let Some((len, rest)) = extensions.split_first_chunk::<2>() else { return false };
    let Some(mut extensions) = rest.get(..u16::from_be_bytes(*len) as usize) else { return false };
    while let Some((head, rest)) = extensions.split_first_chunk::<4>() {
        let len = u16::from_be_bytes([head[2], head[3]]) as usize;
        let Some((value, following)) = rest.split_at_checked(len) else { break };
        if head[..2] == [0, 43] {
            return value == [3, 4];
        }
        extensions = following;
    }
    false
}

fn xor_key(password: &[u8], random: &[u8; 32]) -> [u8; 32] {
    let mut derive = Sha256::new();
    derive.update(password);
    derive.update(random);
    derive.finalize().into()
}

fn xor(bytes: &mut [u8], key: &[u8; 32]) {
    for (byte, key) in bytes.iter_mut().zip(key.iter().cycle()) {
        *byte ^= key;
    }
}

fn verify_frame(mac: &mut hmac::Context, frame: &[u8], chained: bool) -> bool {
    if frame.len() < 5 + TAG || frame[..3] != [APPLICATION, 3, 3] {
        return false;
    }
    mac.update(&frame[5 + TAG..]);
    let expected = tag(mac);
    let matches = bool::from(expected.ct_eq(&frame[5..5 + TAG]));
    if chained && matches {
        mac.update(&expected);
    }
    matches
}

pub fn accept(
    mut client: TcpStream, mut target: TcpStream, hello: &[u8], password: &str, strict: bool,
    fallback: impl FnOnce(&TcpStream, &TcpStream) -> io::Result<()>,
) -> io::Result<Option<Established>> {
    target.write_all(hello)?;
    let server = record(&mut target)?;
    client.write_all(&server)?;
    let Some(random) = server_random(&server).filter(|_| !strict || is_tls13(&server)) else {
        fallback(&client, &target)?;
        return Ok(None);
    };
    let key = key(password);
    let initial = digest(&key, &random, Some(b'C'));
    let handshake = digest(&key, &random, None);
    let mask = xor_key(password.as_bytes(), &random);
    let (first, reader) = relay(&client, &target, initial, handshake, mask)?;
    verified(client, reader, digest(&key, &random, Some(b'S')), None, first).map(Some)
}

fn relay(
    mut client: &TcpStream, mut target: &TcpStream, initial: hmac::Context,
    mut handshake: hmac::Context, mask: [u8; 32],
) -> io::Result<(Vec<u8>, hmac::Context)> {
    thread::scope(|scope| {
        let mut outgoing = client;
        let mut remote = target;
        let out = scope.spawn(move || -> io::Result<()> {
            loop {
                let mut frame = record(&mut remote)?;
                if frame[0] == APPLICATION {
                    xor(&mut frame[5..], &mask);
                    handshake.update(&frame[5..]);
                    let n = u16::try_from(frame.len() - 5 + TAG).map_err(|_| invalid("ShadowTLS target record is too large"))?;
                    frame[3..5].copy_from_slice(&n.to_be_bytes());
                    outgoing.write_all(&frame[..5])?;
                    outgoing.write_all(&tag(&handshake))?;
                    outgoing.write_all(&frame[5..])?;
                } else {
                    outgoing.write_all(&frame)?;
                }
            }
        });
        let result = (|| {
            loop {
                let frame = record(&mut client)?;
                let mut mac = initial.clone();
                if frame.len() > 5 + TAG && verify_frame(&mut mac, &frame, true) {
                    return Ok((frame[5 + TAG..].to_vec(), mac));
                }
                target.write_all(&frame)?;
            }
        })();
        let _ = target.shutdown(Shutdown::Both);
        let _ = out.join();
        result
    })
}

fn verified(
    tcp: TcpStream, read: hmac::Context, write: hmac::Context, ignore: Option<hmac::Context>, prefix: Vec<u8>,
) -> io::Result<Established> {
    let rx = Rx {
        tcp: tcp.try_clone()?, mac: read, ignore, pending: Cursor::new(prefix), record: RecordRead::default(),
    };
    let tx = Tx { tcp: tcp.try_clone()?, mac: write, wire: Vec::new() };
    Ok(Established::wrapped(tcp, rx, tx))
}

struct Rx {
    tcp: TcpStream,
    mac: hmac::Context,
    ignore: Option<hmac::Context>,
    pending: Cursor<Vec<u8>>,
    record: RecordRead,
}

impl Read for Rx {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.pending.read(bytes)?;
        if n > 0 || bytes.is_empty() {
            return Ok(n);
        }
        loop {
            self.record.recv(&self.tcp)?;
            if self.record.wire[0] == 21 {
                return Ok(0);
            }
            if let Some(ignore) = &mut self.ignore {
                if verify_frame(ignore, &self.record.wire, false) {
                    continue;
                }
                self.ignore = None;
            }
            if !verify_frame(&mut self.mac, &self.record.wire, true) {
                return Err(invalid("ShadowTLS data authentication failed"));
            }
            std::mem::swap(&mut self.record.wire, self.pending.get_mut());
            self.pending.set_position((5 + TAG) as u64);
            let n = self.pending.read(bytes)?;
            if n > 0 {
                return Ok(n);
            }
        }
    }
}

struct Tx {
    tcp: TcpStream,
    mac: hmac::Context,
    wire: Vec<u8>,
}

impl Write for Tx {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let count = data.len().min(MAX_PLAIN);
        if count == 0 {
            return Ok(0);
        }
        let body = &data[..count];
        self.mac.update(body);
        let tag = tag(&self.mac);
        self.mac.update(&tag);
        self.wire.clear();
        self.wire.extend_from_slice(&[APPLICATION, 3, 3]);
        self.wire.extend_from_slice(&((count + TAG) as u16).to_be_bytes());
        self.wire.extend_from_slice(&tag);
        self.wire.extend_from_slice(body);
        self.tcp.write_all(&self.wire)?;
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
