//! Shadowsocks SIP022 and SIP023 transport helpers; no sockets are dialed here.

use std::borrow::Cow;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::{ready, Context, Poll, Waker};
use std::time::Duration;

use base64::{
    alphabet,
    engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD},
    Engine,
};
use kerlico_shared::{OpenError, PlaneFault};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

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

use kerlico_shared::AsyncReadHalf as Reader;
type Writer = kerlico_shared::AsyncWriteHalf;

pub struct TcpFlow {
    socket: TcpStream,
    read: Mutex<Reader>,
    write: Mutex<Writer>,
}

impl TcpFlow {
    /// Move the existing cipher and buffering state to the outbound task.
    /// The extra native descriptor was only used by synchronous callers.
    pub fn into_async(self, executor: tokio::runtime::Handle) -> kerlico_shared::AsyncTcp {
        let Self { socket, read, write } = self;
        drop(socket);
        let read = read.into_inner().expect("SS2022 reader");
        kerlico_shared::AsyncTcp { executor, read, write: write.into_inner().expect("SS2022 writer") }
    }

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
        Self::from_halves(socket, read, write, prefix)
    }

    pub fn from_halves<R, W>(socket: TcpStream, read: R, write: W, prefix: Vec<u8>) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let read: Box<dyn AsyncRead + Send + Unpin> = if prefix.is_empty() {
            Box::new(read)
        } else {
            Box::new(std::io::Cursor::new(prefix).chain(read))
        };
        Self {
            socket,
            read: Mutex::new(Reader::Plain(read)),
            write: Mutex::new(Writer::plain(write)),
        }
    }

    /// Preserve the authenticated record buffer, including any handshake payload.
    pub fn from_buffered_halves<R, W>(socket: TcpStream, read: R, write: W, prefix: Vec<u8>) -> Self
    where
        R: AsyncBufRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let read: Box<dyn AsyncBufRead + Send + Unpin> = if prefix.is_empty() {
            Box::new(read)
        } else {
            Box::new(std::io::Cursor::new(prefix).chain(read))
        };
        Self {
            socket,
            read: Mutex::new(Reader::Buffered(read)),
            write: Mutex::new(Writer::plain(write)),
        }
    }

    pub fn read(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        let mut reader = self.read.lock().expect("Shadowsocks TCP read");
        let mut read = std::pin::pin!(reader.read(buf));
        // A buffered frame or a ready socket doesn't need a runtime entry or
        // a timer. If it needs more wire bytes, continue this same operation.
        match read.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => block(wait, read),
        }
    }

    pub fn from_vectored_halves<R, W>(socket: TcpStream, read: R, write: W, prefix: Vec<u8>) -> Self
    where
        R: kerlico_shared::AsyncBufReadVectored + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let mut read = Reader::Vectored(Box::new(read));
        read.prepend(prefix);
        Self { socket, read: Mutex::new(read), write: Mutex::new(Writer::plain(write)) }
    }

    pub fn from_input_halves<R, W>(socket: TcpStream, read: R, write: W, prefix: Vec<u8>) -> Self
    where
        R: kerlico_shared::AsyncBufReadVectored + Send + Unpin + 'static,
        W: kerlico_shared::AsyncWriteInput + Send + Unpin + 'static,
    {
        let mut read = Reader::Vectored(Box::new(read));
        read.prepend(prefix);
        Self { socket, read: Mutex::new(read), write: Mutex::new(Writer::Input(Box::new(write))) }
    }

    /// Pass an authenticated slice to the exit before consuming it. Readers that
    /// do not expose a buffer (clients and transparent relays) use the scratch.
    pub fn read_to(&self, buf: &mut [u8], wait: Duration, sink: &mut dyn FnMut(&[u8])) -> io::Result<usize> {
        let mut reader = self.read.lock().expect("Shadowsocks TCP read");
        let mut read = std::pin::pin!(std::future::poll_fn(|cx| {
            match &mut *reader {
                Reader::Buffered(reader) => {
                    let bytes = ready!(Pin::new(&mut **reader).poll_fill_buf(cx))?;
                    let n = bytes.len();
                    sink(bytes);
                    Pin::new(&mut **reader).consume(n);
                    Poll::Ready(Ok(n))
                }
                Reader::Vectored(reader) => {
                    let mut slices = [std::io::IoSlice::new(&[]); 16];
                    let len = ready!(Pin::new(&mut **reader).poll_fill_buf_vectored(cx, &mut slices))?;
                    let mut n = 0;
                    for bytes in &slices[..len] {
                        sink(bytes);
                        n += bytes.len();
                    }
                    Pin::new(&mut **reader).consume(n);
                    Poll::Ready(Ok(n))
                }
                Reader::Plain(reader) => {
                    let mut out = ReadBuf::new(buf);
                    ready!(Pin::new(&mut **reader).poll_read(cx, &mut out))?;
                    let n = out.filled().len();
                    sink(out.filled());
                    Poll::Ready(Ok(n))
                }
            }
        }));
        match read.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => block(wait, read),
        }
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<()> {
        let mut writer = self.write.lock().expect("Shadowsocks TCP write");
        let mut send = std::pin::pin!(async {
            writer.write_all(buf).await?;
            writer.flush().await
        });
        // A writable socket can seal and send the data without entering the runtime.
        // Keep the same future when it blocks, including any partial write progress.
        match send.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => block(WRITE_WAIT, send),
        }
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
    fn borrowed_tcp_read_preserves_prefix_and_lends_the_original_buffer() -> io::Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let socket = TcpStream::connect(listener.local_addr()?)?;
        let (_peer, _) = listener.accept()?;
        let payload: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let address = payload.as_ptr() as usize;
        let flow = TcpFlow::from_buffered_halves(socket, std::io::Cursor::new(payload), tokio::io::sink(), b"prefix".to_vec());
        let mut scratch = [0; 1];
        assert_eq!(flow.read_to(&mut scratch, FLOW_WAIT, &mut |b| assert_eq!(b, b"prefix"))?, 6);
        let mut sniff = [0; 7];
        assert_eq!(flow.read(&mut sniff, FLOW_WAIT)?, 7);
        assert_eq!(sniff, [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(flow.read_to(&mut scratch, FLOW_WAIT, &mut |bytes| {
            assert_eq!(bytes.as_ptr() as usize, address + 7);
            assert_eq!(bytes, (7..1000).map(|i| (i % 251) as u8).collect::<Vec<_>>());
        })?, 993);
        assert_eq!(flow.read_to(&mut scratch, FLOW_WAIT, &mut |bytes| assert!(bytes.is_empty()))?, 0);
        Ok(())
    }

    #[test]
    fn borrowed_tcp_read_rearms_after_timeout_and_delivers_every_byte() -> io::Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let socket = TcpStream::connect(listener.local_addr()?)?;
        let (_peer, _) = listener.accept()?;
        let (read, mut write) = tokio::io::duplex(3);
        let flow = TcpFlow::from_buffered_halves(socket, tokio::io::BufReader::new(read), tokio::io::sink(), Vec::new());
        let mut scratch = [0; 1];
        let error = flow.read_to(&mut scratch, Duration::from_millis(20), &mut |_| panic!("no data yet")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let send = runtime()?.spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            write.write_all(b"later payload").await
        });
        let mut actual = Vec::new();
        while flow.read_to(&mut scratch, Duration::from_secs(2), &mut |b| actual.extend_from_slice(b))? != 0 {}
        runtime()?.block_on(send).map_err(io::Error::other)??;
        assert_eq!(actual, b"later payload");
        Ok(())
    }

    #[test]
    fn tcp_write_preserves_bytes_when_the_first_poll_fills_the_socket() -> io::Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let socket = TcpStream::connect(listener.local_addr()?)?;
        let (local, _) = listener.accept()?;
        let (stream, mut peer) = tokio::io::duplex(3);
        let flow = TcpFlow::new(socket, stream);
        let payload = b"an SS2022 application write";
        let receive = runtime()?.spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut received = vec![0; payload.len()];
            peer.read_exact(&mut received).await?;
            Ok::<_, io::Error>(received)
        });
        flow.write(payload)?;
        let received = runtime()?.block_on(receive).map_err(io::Error::other)??;
        assert_eq!(received, payload);
        drop(local);
        Ok(())
    }

    #[test]
    fn tcp_read_rearms_after_timeout_and_keeps_the_first_poll_wakeup() -> io::Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let socket = TcpStream::connect(listener.local_addr()?)?;
        let (_local, _) = listener.accept()?;
        let (stream, mut peer) = tokio::io::duplex(16);
        let flow = TcpFlow::with_prefix(socket, stream, b"first".to_vec());
        let mut buf = [0; 16];
        let n = flow.read(&mut buf, Duration::from_secs(1))?;
        assert_eq!(&buf[..n], b"first");
        assert_eq!(flow.read(&mut buf, Duration::from_millis(25)).unwrap_err().kind(),
                   io::ErrorKind::TimedOut);
        let sender = runtime()?.spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            peer.write_all(b"later").await
        });
        let n = flow.read(&mut buf, Duration::from_secs(2))?;
        assert_eq!(&buf[..n], b"later");
        runtime()?.block_on(sender).map_err(io::Error::other)??;
        assert_eq!(flow.read(&mut buf, Duration::from_secs(1))?, 0);
        Ok(())
    }

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
