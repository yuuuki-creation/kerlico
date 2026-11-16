//! Raw HTTP/2 client used to compare how two servers apply the same `h2Params`.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::cases::{ID, TLS_NAME};
use super::support::{localhost, tcp_connect, Result};

pub const LIMIT_PARAMS: &str = r#"{"MaxConcurrentStreams":7,"MaxReadFrameSize":32768,"MaxDecoderHeaderTableSize":8192,"MaxReceiveBufferPerStream":524288,"MaxReceiveBufferPerConnection":2097152}"#;
pub const LIMIT_FRAME: usize = 32768;
pub const PING_PARAMS: &str = r#"{"sendpingtimeout":700000000,"PINGTIMEOUT":700000000}"#;

const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const ACK: u8 = 1;
const DATA: u8 = 0;
const HEADERS: u8 = 1;
pub const WRITE_PROBE_BYTES: usize = 8 * 1024 * 1024;

pub enum Wire {
    Plain(TcpStream),
    Tls(kerlico_vless::TlsLink),
    Advanced {
        socket: TcpStream,
        read: kerlico_vless::AdvancedTlsRead<TcpStream>,
        write: kerlico_vless::AdvancedTlsWrite<TcpStream>,
    },
}

pub const PROHIBITED_CIPHER: &str = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";

impl Wire {
    pub fn connect(port: u16, tls: bool) -> Result<Self> {
        let tcp = tcp_connect(port)?;
        if !tls {
            return Ok(Self::Plain(tcp));
        }
        let config = kerlico_vless::client_config(&["h2".to_owned()], true).map_err(|_| "h2 probe TLS config")?;
        Ok(Self::Tls(kerlico_vless::connect_tls(tcp, config, TLS_NAME)?))
    }

    fn wait(&self, timeout: Duration) {
        match self {
            Self::Plain(tcp) => {
                let _ = tcp.set_read_timeout(Some(timeout));
            }
            Self::Tls(link) => link.set_timeout(Some(timeout)),
            Self::Advanced { socket, .. } => { let _ = socket.set_read_timeout(Some(timeout)); }
        }
    }
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.read(buf),
            Self::Tls(link) => link.read(buf),
            Self::Advanced { read, .. } => read.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.write(buf),
            Self::Tls(link) => link.write(buf),
            Self::Advanced { write, .. } => write.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(tcp) => tcp.flush(),
            Self::Tls(link) => link.flush(),
            Self::Advanced { write, .. } => write.flush(),
        }
    }
}

pub fn prohibited_cipher(port: u16, permit: bool) -> Result<()> {
    let tcp = tcp_connect(port)?;
    let options = kerlico_vless::AdvancedTlsOptions {
        allow_insecure: true, fingerprint: "unsafe".into(), alpn: vec!["h2".into()],
        min_version: "1.2".into(), max_version: "1.2".into(), cipher_suites: PROHIBITED_CIPHER.into(),
        ..Default::default()
    };
    let config = kerlico_vless::advanced_client_config(&options)?;
    let (read, write) = kerlico_vless::connect_advanced_tls_over(tcp.try_clone()?, tcp.try_clone()?, config, TLS_NAME)?;
    let mut wire = Wire::Advanced { socket: tcp, read, write };
    if permit { handshake(&mut wire)?; return Ok(()); }
    wire.wait(Duration::from_secs(3));
    // Xray can answer before reading the preface; Kerlico needs it to distinguish H1 from H2.
    let _ = wire.write_all(kerlico_vless::HTTP2_PREFACE);
    let frame = loop {
        let frame = read_frame(&mut wire)?;
        if frame.kind != SETTINGS { break frame; }
    };
    let code = frame.payload.get(4..8).map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()));
    if frame.kind != GOAWAY || frame.stream != 0 || code != Some(0x0c) {
        return Err(format!("expected GOAWAY INADEQUATE_SECURITY, received frame type {} and error {code:?}", frame.kind).into());
    }
    Ok(())
}

struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

fn read_frame(wire: &mut Wire) -> io::Result<Frame> {
    let mut head = [0; 9];
    wire.read_exact(&mut head)?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut payload = vec![0; len];
    wire.read_exact(&mut payload)?;
    Ok(Frame {
        kind: head[3],
        flags: head[4],
        stream: u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff,
        payload,
    })
}

fn write_frame(wire: &mut Wire, kind: u8, flags: u8, stream: u32, payload: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    frame.extend_from_slice(&[kind, flags]);
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(payload);
    wire.write_all(&frame)?;
    wire.flush()
}

fn timed_out(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
    )
}

/// Keep H2 flow control open while stopping the TCP reads long enough to fill
/// the server's socket. The zero-timeout control must deliver every byte.
pub fn write_timeout(port: u16, origin: u16, enabled: bool) -> Result<()> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_recv_buffer_size(64 * 1024)?;
    socket.connect_timeout(&localhost(port).into(), Duration::from_secs(3))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut wire = Wire::Plain(socket.into());
    wire.wait(Duration::from_secs(5));
    wire.write_all(kerlico_vless::HTTP2_PREFACE)?;
    let window = 16u32 * 1024 * 1024;
    write_frame(&mut wire, SETTINGS, 0, 0, &[&[0, 4][..], &window.to_be_bytes()].concat())?;
    write_frame(&mut wire, WINDOW_UPDATE, 0, 0, &(window - 65_535).to_be_bytes())?;
    let referer = format!("http://{TLS_NAME}/matrix/?x_padding={}", "0".repeat(100));
    let fields: [(&[u8], &[u8]); 6] = [
        (b":method", b"POST"), (b":scheme", b"http"), (b":authority", TLS_NAME.as_bytes()),
        (b":path", b"/matrix/"), (b"content-type", b"application/grpc"), (b"referer", referer.as_bytes()),
    ];
    write_frame(&mut wire, HEADERS, 4, 1, &hpack::Encoder::new().encode(fields))?;
    let mut request = kerlico_vless::encode_request(&kerlico_vless::Request {
        id: kerlico_vless::parse_id(ID).map_err(|_| "invalid test account")?,
        flow: String::new(), seed: Vec::new(), command: kerlico_vless::Command::Tcp,
        port: origin, address: kerlico_vless::Addr::V4(std::net::Ipv4Addr::LOCALHOST),
    }).map_err(|_| "invalid test VLESS request")?;
    request.push(0x31);
    write_frame(&mut wire, DATA, 0, 1, &request)?;

    let mut data = Vec::new();
    while data.len() < 3 {
        let frame = read_frame(&mut wire)?;
        if frame.kind == SETTINGS && frame.flags & ACK == 0 { write_frame(&mut wire, SETTINGS, ACK, 0, &[])?; }
        if frame.kind == DATA && frame.stream == 1 { data.extend(frame.payload); }
        if frame.kind == GOAWAY { return Err("GOAWAY before test data".into()); }
    }
    if data[..2] != [0, 0] || !data[2..].iter().all(|&b| b == 0x42) {
        return Err("unexpected VLESS response before the stalled write".into());
    }
    let mut received = data.len() - 2;
    std::thread::sleep(Duration::from_millis(900));
    loop {
        match read_frame(&mut wire) {
            Ok(frame) if frame.kind == DATA && frame.stream == 1 => {
                if !frame.payload.iter().all(|&b| b == 0x42) { return Err("corrupt stalled-write payload".into()); }
                received += frame.payload.len();
                if received == WRITE_PROBE_BYTES {
                    return if enabled { Err("server drained all data after its write deadline".into()) } else { Ok(()) };
                }
            }
            Ok(frame) if frame.kind == GOAWAY && enabled => return Ok(()),
            Err(error) if closed(&error) && enabled => return Ok(()),
            Err(error) => return Err(format!("connection ended after {received} data bytes: {error}").into()),
            _ => {}
        }
    }
}

/// What a server announces before it has seen any request.
#[derive(Debug, Default)]
pub struct Hello {
    pub settings: BTreeMap<u16, u32>,
    pub settings_order: Vec<u16>,
    pub window: Option<u32>,
}

pub fn handshake(wire: &mut Wire) -> Result<Hello> {
    wire.write_all(kerlico_vless::HTTP2_PREFACE)?;
    write_frame(wire, SETTINGS, 0, 0, &[])?;
    wire.wait(Duration::from_secs(3));
    let mut hello = Hello::default();
    loop {
        let frame = match read_frame(wire) {
            Ok(frame) => frame,
            Err(error) if timed_out(&error) && !hello.settings.is_empty() => return Ok(hello),
            Err(error) => return Err(format!("server preface: {error}").into()),
        };
        match frame.kind {
            SETTINGS if frame.flags & ACK == 0 => {
                for pair in frame.payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([pair[0], pair[1]]);
                    hello.settings_order.push(id);
                    hello.settings.insert(
                        id,
                        u32::from_be_bytes(pair[2..6].try_into().unwrap()),
                    );
                }
                write_frame(wire, SETTINGS, ACK, 0, &[])?;
                wire.wait(Duration::from_millis(400));
            }
            WINDOW_UPDATE if frame.stream == 0 && hello.window.is_none() => {
                hello.window = Some(u32::from_be_bytes(frame.payload[..4].try_into().unwrap()));
            }
            _ => {}
        }
    }
}

pub fn expect_limits(hello: &Hello) -> std::result::Result<(), String> {
    let expected = [(1, 8192), (3, 7), (4, 524_288), (5, 32_768), (6, 8512), (9, 1)];
    for (id, value) in expected {
        if hello.settings.get(&id) != Some(&value) {
            return Err(format!("SETTINGS {id} is {:?}, expected {value}", hello.settings.get(&id)));
        }
    }
    if hello.window != Some(2_097_152 - 65_535) {
        return Err(format!("connection WINDOW_UPDATE is {:?}, expected {}", hello.window, 2_097_152 - 65_535));
    }
    Ok(())
}

/// A frame of exactly the advertised size is ignored as an unknown type. One byte more ends the connection.
pub fn frame_limit(port: u16, tls: bool, limit: usize) -> Result<()> {
    let mut wire = Wire::connect(port, tls)?;
    handshake(&mut wire)?;
    write_frame(&mut wire, 0xfa, 0, 0, &vec![0; limit])?;
    write_frame(&mut wire, PING, 0, 0, b"12345678")?;
    wire.wait(Duration::from_secs(2));
    loop {
        match read_frame(&mut wire) {
            Ok(frame) if frame.kind == PING && frame.flags & ACK != 0 => break,
            Ok(frame) if frame.kind == GOAWAY => return Err("frame of the advertised size ended the connection".into()),
            Ok(_) => {}
            Err(error) => return Err(format!("frame of the advertised size: {error}").into()),
        }
    }

    let mut wire = Wire::connect(port, tls)?;
    handshake(&mut wire)?;
    let _ = write_frame(&mut wire, 0xfa, 0, 0, &vec![0; limit + 1]);
    wire.wait(Duration::from_secs(3));
    loop {
        match read_frame(&mut wire) {
            Ok(frame) if frame.kind == GOAWAY => return Ok(()),
            Ok(_) => {}
            Err(error) if closed(&error) => return Ok(()),
            Err(error) => return Err(format!("oversized frame left the connection open: {error}").into()),
        }
    }
}

fn next_ping(wire: &mut Wire, within: Duration) -> Result<Vec<u8>> {
    wire.wait(within);
    let start = Instant::now();
    loop {
        match read_frame(wire) {
            Ok(frame) if frame.kind == PING && frame.flags & ACK == 0 => return Ok(frame.payload),
            Ok(_) => {}
            Err(error) => return Err(format!("no PING after {:?}: {error}", start.elapsed()).into()),
        }
    }
}

/// An idle connection gets pinged. An unanswered ping closes it and an answered one keeps it alive.
pub fn pings(port: u16, tls: bool) -> Result<()> {
    let mut wire = Wire::connect(port, tls)?;
    handshake(&mut wire)?;
    next_ping(&mut wire, Duration::from_secs(3))?;
    wire.wait(Duration::from_secs(3));
    loop {
        match read_frame(&mut wire) {
            Ok(_) => {}
            Err(error) if closed(&error) => break,
            Err(error) => return Err(format!("unanswered ping left the connection open: {error}").into()),
        }
    }

    let mut wire = Wire::connect(port, tls)?;
    handshake(&mut wire)?;
    for round in 0..2 {
        let data = next_ping(&mut wire, Duration::from_secs(3)).map_err(|error| format!("ping {round}: {error}"))?;
        write_frame(&mut wire, PING, ACK, 0, &data)?;
    }
    Ok(())
}
