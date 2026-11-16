//! ShadowTLS carriers. TLS authenticates the handshake target; AnyTLS
//! continues on the same TCP stream after the handshake ends.

mod v3;
pub use v3::{accept as accept_v3, find_password};
pub(crate) use v3::{is_tls13, server_random};

use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kerlico_tls::advanced::{self, AdvancedTlsClientConfig};
use ring::hmac::{self, HMAC_SHA1_FOR_LEGACY_USE_ONLY};
use subtle::ConstantTimeEq;

use crate::tls::{ClientTls, Established, TransportWrite, MAX_PLAIN};

const APPLICATION: u8 = 23;

#[derive(Clone, Copy)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl Version {
    pub fn parse(version: u8) -> io::Result<Self> {
        match version {
            1 => Ok(Self::V1),
            0 | 2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            _ => Err(invalid("unsupported ShadowTLS version")),
        }
    }
}

pub struct Client {
    tls: Arc<AdvancedTlsClientConfig>,
    key: hmac::Key,
    password: String,
    version: Version,
}

impl Client {
    pub fn new(version: Version, password: &str, tls: &ClientTls, alpn_given: bool) -> io::Result<Self> {
        let mut options = tls.advanced();
        if !alpn_given {
            options.alpn = vec!["h2".into(), "http/1.1".into()];
        }
        if matches!(version, Version::V1) {
            options.max_version = "1.2".into();
            options.fingerprint.clear();
        } else if matches!(version, Version::V2) {
            options.curve_preferences = vec!["X25519".into(), "P-256".into(), "P-384".into()];
        }
        Ok(Self { tls: advanced::advanced_client_config(&options)?, key: key(password), password: password.into(), version })
    }

    pub fn connect(&self, tcp: TcpStream, name: &str) -> io::Result<Established> {
        if matches!(self.version, Version::V3) {
            return v3::connect(tcp, name, self.tls.clone(), &self.key, &self.password);
        }
        let digest = Arc::new(Mutex::new(hmac::Context::with_key(&self.key)));
        let reader = HashRead {
            tcp: tcp.try_clone()?,
            digest: matches!(self.version, Version::V2).then(|| digest.clone()),
        };
        let _handshake = advanced::connect_advanced_tls_over(reader, tcp.try_clone()?, self.tls.clone(), name)?;
        match self.version {
            Version::V1 => Ok(Established::plaintext(tcp)),
            Version::V2 => {
                let proof = sum(&digest.lock().expect("ShadowTLS handshake"));
                framed(tcp, Vec::new(), Some(proof))
            }
            Version::V3 => unreachable!("handled before the ordinary TLS handshake"),
        }
    }
}

struct HashRead {
    tcp: TcpStream,
    digest: Option<Arc<Mutex<hmac::Context>>>,
}

impl Read for HashRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.tcp.read(out)?;
        if let Some(digest) = &self.digest {
            digest.lock().expect("ShadowTLS handshake").update(&out[..n]);
        }
        Ok(n)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

fn key(password: &str) -> hmac::Key {
    hmac::Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, password.as_bytes())
}

fn sum(digest: &hmac::Context) -> [u8; 8] {
    digest.clone().sign().as_ref()[..8].try_into().expect("HMAC tag")
}

/// Record received during a blocking handshake. Session reads use the resumable parser below.
pub fn record(io: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0; 5];
    io.read_exact(&mut header)?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = Vec::with_capacity(5 + len);
    frame.extend_from_slice(&header);
    frame.resize(5 + len, 0);
    io.read_exact(&mut frame[5..])?;
    Ok(frame)
}

pub fn server_name(record: &[u8]) -> Option<&str> {
    let mut extensions = hello_extensions(record.get(5..)?)?;
    while !extensions.is_empty() {
        let id = take(&mut extensions, 2)?;
        let mut value = sized(&mut extensions, 2)?;
        if id == [0, 0] {
            let mut list = sized(&mut value, 2)?;
            while !list.is_empty() {
                let kind = take(&mut list, 1)?;
                let bytes = sized(&mut list, 2)?;
                if kind == [0] {
                    return std::str::from_utf8(bytes).ok();
                }
            }
        }
    }
    None
}

pub(crate) fn hello_extensions(mut hello: &[u8]) -> Option<&[u8]> {
    if take(&mut hello, 1)? != [1] {
        return None;
    }
    let mut hello = sized(&mut hello, 3)?;
    take(&mut hello, 34)?;
    sized(&mut hello, 1)?;
    sized(&mut hello, 2)?;
    sized(&mut hello, 1)?;
    sized(&mut hello, 2)
}

pub(crate) fn take<'a>(bytes: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (value, following) = bytes.split_at_checked(len)?;
    *bytes = following;
    Some(value)
}

pub(crate) fn sized<'a>(bytes: &mut &'a [u8], size: usize) -> Option<&'a [u8]> {
    let len = take(bytes, size)?.iter().fold(0, |len, byte| len * 256 + *byte as usize);
    take(bytes, len)
}

#[derive(Default)]
pub(crate) struct RecordRead {
    pub(crate) wire: Vec<u8>,
    used: usize,
}

impl RecordRead {
    pub(crate) fn recv(&mut self, mut tcp: &TcpStream) -> io::Result<()> {
        if self.used == 0 {
            self.wire.resize(5, 0);
        }
        while self.used < self.wire.len() {
            let n = tcp.read(&mut self.wire[self.used..])?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.used += n;
            if self.used == 5 && self.wire.len() == 5 {
                let size = u16::from_be_bytes([self.wire[3], self.wire[4]]) as usize;
                self.wire.resize(5 + size, 0);
            }
        }
        self.used = 0;
        Ok(())
    }
}

/// `target` was opened by the outbound owner. `first` is a pre-read ClientHello.
pub fn accept(
    tcp: TcpStream, target: TcpStream, first: Vec<u8>, version: Version, password: &str,
    fallback: impl FnOnce(&TcpStream, &TcpStream) -> io::Result<()>,
) -> io::Result<Option<Established>> {
    match version {
        Version::V1 => {
            relay_v1(&tcp, &target)?;
            Ok(Some(Established::plaintext(tcp)))
        }
        Version::V2 => {
            match relay_v2(&tcp, &target, first, password)? {
                Some(first_data) => framed(tcp, first_data, None).map(Some),
                None => { fallback(&tcp, &target)?; Ok(None) }
            }
        }
        Version::V3 => Err(invalid("ShadowTLS v3 needs a verified ClientHello")),
    }
}

fn copy_v1(mut source: &TcpStream, mut sink: &TcpStream) -> io::Result<()> {
    let mut ccs = false;
    loop {
        let frame = record(&mut source)?;
        sink.write_all(&frame)?;
        match frame[0] {
            20 if !ccs => ccs = true,
            20 | 22 if ccs => return Ok(()),
            22 => {}
            _ => return Err(invalid("expected a ShadowTLS v1 handshake record")),
        }
    }
}

fn relay_v1(client: &TcpStream, target: &TcpStream) -> io::Result<()> {
    thread::scope(|scope| {
        let down = scope.spawn(|| {
            let result = copy_v1(target, client);
            if result.is_err() {
                let _ = client.shutdown(Shutdown::Both);
            }
            result
        });
        let result = copy_v1(client, target);
        if result.is_err() {
            let _ = target.shutdown(Shutdown::Both);
        }
        let other = down.join().map_err(|_| invalid("ShadowTLS v1 handshake relay failed"))?;
        result.and(other)
    })
}

struct ServerHash {
    digest: hmac::Context,
    current: Option<[u8; 8]>,
    previous: Option<[u8; 8]>,
}

fn relay_v2(mut client: &TcpStream, mut target: &TcpStream, first: Vec<u8>, password: &str) -> io::Result<Option<Vec<u8>>> {
    target.write_all(&first)?;
    target.set_read_timeout(Some(Duration::from_millis(50)))?;
    let stopped = AtomicBool::new(false);
    let hashes = Mutex::new(ServerHash {
        digest: hmac::Context::with_key(&key(password)), current: None, previous: None,
    });
    thread::scope(|scope| {
        let shared = &hashes;
        let stopped = &stopped;
        let mut upstream = target;
        let mut downstream = client;
        let down = scope.spawn(move || -> io::Result<()> {
            let mut buf = [0u8; 16 * 1024];
            while !stopped.load(Ordering::Acquire) {
                let n = match upstream.read(&mut buf) {
                    Ok(count) => count,
                    Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => continue,
                    Err(error) => return Err(error),
                };
                if n == 0 { return Ok(()); }
                let mut hashes = shared.lock().expect("ShadowTLS handshake");
                downstream.write_all(&buf[..n])?;
                hashes.digest.update(&buf[..n]);
                let tag = sum(&hashes.digest);
                hashes.previous = hashes.current.replace(tag);
            }
            Ok(())
        });
        let result = (|| {
            let mut application = 0;
            loop {
                let frame = record(&mut client)?;
                if frame[0] == APPLICATION {
                    let body = &frame[5..];
                    let hashes = hashes.lock().expect("ShadowTLS handshake");
                    if let Some(proof) = body.get(..8) {
                        if [hashes.current, hashes.previous].into_iter().flatten().any(|tag| bool::from(tag.ct_eq(proof))) {
                            return Ok(Some(body[8..].to_vec()));
                        }
                    }
                    application += 1;
                }
                target.write_all(&frame)?;
                if application > 2 {
                    return Ok(None);
                }
            }
        })();
        stopped.store(true, Ordering::Release);
        if !matches!(result, Ok(None)) {
            let _ = target.shutdown(Shutdown::Both);
        }
        let downstream = down.join().map_err(|_| invalid("ShadowTLS handshake relay failed"))?;
        if matches!(result, Ok(None)) { downstream?; }
        result
    })
}

fn framed(tcp: TcpStream, prefix: Vec<u8>, proof: Option<[u8; 8]>) -> io::Result<Established> {
    let read = Receiver { tcp: tcp.try_clone()?, head: [0; 5], used: 0, left: 0, prefix: Cursor::new(prefix) };
    let write = Sender { tcp: tcp.try_clone()?, proof, frame: Vec::new() };
    Ok(Established::wrapped(tcp, read, write))
}

struct Receiver {
    tcp: TcpStream,
    head: [u8; 5],
    used: usize,
    left: usize,
    prefix: Cursor<Vec<u8>>,
}

impl Read for Receiver {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.prefix.read(out)?;
        if n != 0 || out.is_empty() {
            return Ok(n);
        }
        while self.left == 0 {
            let n = self.tcp.read(&mut self.head[self.used..])?;
            if n == 0 {
                return if self.used == 0 { Ok(0) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
            }
            self.used += n;
            if self.used == 5 {
                if self.head[0] != APPLICATION || self.head[1..3] != [3, 3] {
                    return Err(invalid("invalid ShadowTLS application record"));
                }
                self.left = u16::from_be_bytes([self.head[3], self.head[4]]) as usize;
                self.used = 0;
            }
        }
        let count = out.len().min(self.left);
        let n = self.tcp.read(&mut out[..count])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= n;
        Ok(n)
    }
}

struct Sender {
    tcp: TcpStream,
    proof: Option<[u8; 8]>,
    frame: Vec<u8>,
}

impl Write for Sender {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let proof = self.proof.take();
        let proof = proof.as_ref().map_or(&[][..], |proof| &proof[..]);
        let count = data.len().min(MAX_PLAIN - proof.len());
        self.frame.clear();
        self.frame.extend_from_slice(&[APPLICATION, 3, 3]);
        self.frame.extend_from_slice(&((count + proof.len()) as u16).to_be_bytes());
        self.frame.extend_from_slice(proof);
        self.frame.extend_from_slice(&data[..count]);
        self.tcp.write_all(&self.frame)?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TransportWrite for Sender {
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
