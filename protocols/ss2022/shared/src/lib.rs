//! Shadowsocks SIP022 and SIP023 transport helpers; no sockets are dialed here.

use std::borrow::Cow;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::{
    alphabet,
    engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD},
    Engine,
};
use kerlico_shared::{OpenError, PlaneFault};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use shadowsocks::relay::socks5::Address;
pub use shadowsocks::{config, context, crypto::CipherKind, relay};

pub const OPEN_WAIT: Duration = Duration::from_secs(10);
pub const FLOW_WAIT: Duration = Duration::from_millis(200);
pub const WRITE_WAIT: Duration = Duration::from_secs(30);
pub const UDP_IDLE: Duration = Duration::from_secs(300);

/// Maximum normal UDP payload on the outer socket, including the Shadowsocks envelope.
pub fn udp_wire_limit(peer: SocketAddr) -> usize {
    match peer.ip() {
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none() => 65_527,
        _ => 65_507,
    }
}

const KEY_DECODER: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

pub fn method(value: &str) -> Result<CipherKind, OpenError> {
    let kind: CipherKind = value.parse().map_err(|_| OpenError::Settings)?;
    kind.is_aead_2022()
        .then_some(kind)
        .ok_or(OpenError::Settings)
}

pub fn key(method: CipherKind, val: &str) -> Result<Vec<u8>, OpenError> {
    let raw = val.as_bytes();
    // Xray uses Go's standard Base64 decoder, which ignores CR and LF and
    // accepts unused trailing bits. Normalize to canonical Base64 on export.
    let encoded: Cow<'_, [u8]> = if raw.iter().any(|&byte| matches!(byte, b'\r' | b'\n')) {
        Cow::Owned(
            raw.iter()
                .copied()
                .filter(|&byte| !matches!(byte, b'\r' | b'\n'))
                .collect(),
        )
    } else {
        Cow::Borrowed(raw)
    };
    let key = KEY_DECODER.decode(encoded).unwrap_or_else(|_| raw.to_vec());
    if key.len() != method.key_len() {
        return Err(OpenError::Settings);
    }
    Ok(key)
}

pub fn remote(
    method: CipherKind,
    password: &str,
    host: &str,
    port: u16,
) -> Result<config::ServerConfig, OpenError> {
    let mut psks = Vec::new();
    for part in password.split(':') {
        psks.push(STANDARD.encode(key(method, part)?));
    }
    if psks.len() > 1 && !config::method_support_eih(method) {
        return Err(OpenError::Settings);
    }
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => config::ServerAddr::SocketAddr(SocketAddr::new(ip, port)),
        Err(_) => config::ServerAddr::DomainName(host.to_owned(), port),
    };
    config::ServerConfig::new(addr, psks.join(":"), method).map_err(|_| OpenError::Settings)
}

pub fn address(host: &str, port: u16) -> io::Result<Address> {
    if host.is_empty()
        || host.len() > 255
        || port == 0
        || host.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Shadowsocks address",
        ));
    }
    Ok(match host.parse::<IpAddr>() {
        Ok(ip) => Address::SocketAddress(SocketAddr::new(ip, port)),
        Err(_) => Address::DomainNameAddress(host.to_owned(), port),
    })
}

pub fn target(addr: &Address) -> (String, u16) {
    match addr {
        Address::SocketAddress(addr) => (addr.ip().to_string(), addr.port()),
        Address::DomainNameAddress(host, port) => (host.clone(), *port),
    }
}

pub fn runtime() -> io::Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<io::Result<tokio::runtime::Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))
}

pub fn block<T>(wait: Duration, op: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    runtime()?.block_on(async { tokio::time::timeout(wait, op).await? })
}

type Reader = Box<dyn AsyncRead + Send + Unpin>;
type Writer = Box<dyn AsyncWrite + Send + Unpin>;

pub struct TcpFlow {
    socket: TcpStream,
    read: Mutex<Reader>,
    write: Mutex<Writer>,
}

impl TcpFlow {
    pub fn new<T>(socket: TcpStream, stream: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::with_prefix(socket, stream, Vec::new())
    }

    pub fn with_prefix<T>(socket: TcpStream, stream: T, prefix: Vec<u8>) -> Self
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (read, write) = tokio::io::split(stream);
        let read = std::io::Cursor::new(prefix).chain(read);
        Self {
            socket,
            read: Mutex::new(Box::new(read)),
            write: Mutex::new(Box::new(write)),
        }
    }

    pub fn read(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        block(
            wait,
            self.read.lock().expect("Shadowsocks TCP read").read(buf),
        )
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<()> {
        let mut writer = self.write.lock().expect("Shadowsocks TCP write");
        block(WRITE_WAIT, async {
            writer.write_all(buf).await?;
            writer.flush().await
        })
    }

    pub fn finish(&self) -> io::Result<()> {
        block(
            WRITE_WAIT,
            self.write.lock().expect("Shadowsocks TCP write").shutdown(),
        )
    }

    pub fn close(&self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

pub fn map_io(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => PlaneFault::Again,
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

const REPLAY_WORDS: usize = 128;

/// A packet counter window; authenticated out-of-order packets can be delivered once.
pub struct Replay {
    largest: u64,
    bits: [u64; REPLAY_WORDS],
}

impl Default for Replay {
    fn default() -> Self {
        Self {
            largest: 0,
            bits: [0; REPLAY_WORDS],
        }
    }
}

impl Replay {
    const WORD_BITS: u64 = u64::BITS as u64;
    // Keep one word of overlap so clearing a reused word never discards an in-window ID.
    const WINDOW: u64 = (REPLAY_WORDS as u64 - 1) * Self::WORD_BITS;

    pub fn accept(&mut self, id: u64) -> bool {
        let word = id / Self::WORD_BITS;
        let slot = |word: u64| (word % REPLAY_WORDS as u64) as usize;
        if id > self.largest {
            let previous = self.largest / Self::WORD_BITS;
            if word - previous >= REPLAY_WORDS as u64 {
                self.bits.fill(0);
            } else {
                for next in previous + 1..=word {
                    self.bits[slot(next)] = 0;
                }
            }
            self.largest = id;
        } else if self.largest - id > Self::WINDOW {
            return false;
        }
        let bit = 1u64 << (id % Self::WORD_BITS);
        let bits = &mut self.bits[slot(word)];
        let unseen = *bits & bit == 0;
        *bits |= bit;
        unseen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_reordering_and_rejects_duplicates_and_stale_counter() {
        let mut replay = Replay::default();
        for packet in [0, 3, 1, 2, 8193, 65] {
            assert!(replay.accept(packet), "{packet}");
        }
        for packet in [0, 64, 65, 8193] {
            assert!(!replay.accept(packet), "{packet}");
        }
        assert!(replay.accept(u64::MAX));
        assert!(replay.accept(u64::MAX - 8128));
        for packet in [u64::MAX, u64::MAX - 8128, u64::MAX - 8129] {
            assert!(!replay.accept(packet), "{packet}");
        }
    }
}
