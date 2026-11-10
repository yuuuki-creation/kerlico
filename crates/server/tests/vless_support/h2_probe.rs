//! Raw HTTP/2 client used to compare how two servers apply the same `h2Params`.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::cases::TLS_NAME;
use super::support::{tcp_connect, Result};

pub const LIMIT_PARAMS: &str = r#"{"MaxConcurrentStreams":7,"MaxReadFrameSize":32768,"MaxDecoderHeaderTableSize":8192,"MaxReceiveBufferPerStream":524288,"MaxReceiveBufferPerConnection":2097152}"#;
pub const LIMIT_FRAME: usize = 32768;
pub const PING_PARAMS: &str = r#"{"sendpingtimeout":700000000,"PINGTIMEOUT":700000000}"#;

const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const ACK: u8 = 1;

pub enum Wire {
    Plain(TcpStream),
    Tls(kerlico_vless::TlsLink),
}

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
        }
    }
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.read(buf),
            Self::Tls(link) => link.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.write(buf),
            Self::Tls(link) => link.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(tcp) => tcp.flush(),
            Self::Tls(link) => link.flush(),
        }
    }
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

/// What a server announces before it has seen any request.
#[derive(Debug, Default)]
pub struct Hello {
    pub settings: BTreeMap<u16, u32>,
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
                    hello.settings.insert(
                        u16::from_be_bytes([pair[0], pair[1]]),
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
    let expected = [(1, 8192), (3, 7), (4, 524_288), (5, 32_768), (6, 8512)];
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
