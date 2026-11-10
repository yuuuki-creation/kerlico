//! Xray gun gRPC over the VLESS HTTP/2 transport.

use std::io::{self, ErrorKind, Read, Write};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, OnceLock,
};
use std::time::Duration;

use crate::http::{H2Conn, H2Keepalive, H2Stream};

const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const WRITE_CHUNK: usize = 64 * 1024;

pub fn grpc_path(service: &str, multi: bool) -> String {
    if let Some(path) = service.strip_prefix('/') {
        let (service, streams) = path.rsplit_once('/').unwrap_or(("", path));
        let mut streams = streams.split('|');
        let single = streams.next().unwrap_or_default();
        let multiple = streams.next().unwrap_or(single);
        let service = service
            .split('/')
            .map(escape_segment)
            .collect::<Vec<_>>()
            .join("/");
        let stream = escape_segment(if multi { multiple } else { single });
        format!("/{service}/{stream}")
    } else {
        let service = escape_segment(service);
        let stream = if multi { "TunMulti" } else { "Tun" };
        format!("/{service}/{stream}")
    }
}

fn escape_segment(segment: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut escaped = String::new();
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~$&+:=@".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            escaped.push('%');
            escaped.push(char::from(HEX[(byte >> 4) as usize]));
            escaped.push(char::from(HEX[(byte & 15) as usize]));
        }
    }
    escaped
}

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, Default)]
pub struct GrpcOptions {
    keepalive: Option<H2Keepalive>,
    receive_window: Option<u32>,
    user_agent: Option<String>,
}

impl GrpcOptions {
    pub fn parse<'a>(get: impl Fn(&str) -> Option<&'a str>, server: bool) -> io::Result<Self> {
        let number = |name| {
            get(name)
                .unwrap_or("0")
                .parse::<i32>()
                .map(|value| value.max(0) as u32)
                .map_err(|_| invalid(name))
        };
        let idle = number("idle_timeout")?;
        let health = number("health_check_timeout")?;
        let timeout = if health == 0 {
            DEFAULT_HEALTH_TIMEOUT
        } else {
            Duration::from_secs(health.into())
        };
        if server {
            let interval = if idle == 0 {
                Duration::from_secs(2 * 60 * 60)
            } else {
                Duration::from_secs(idle.into())
            };
            return Ok(Self {
                keepalive: Some(H2Keepalive {
                    interval,
                    timeout,
                    without_stream: true,
                }),
                ..Self::default()
            });
        }

        let permit_without_stream = get("permit_without_stream")
            .unwrap_or("false")
            .parse::<bool>()
            .map_err(|_| invalid("permit_without_stream"))?;
        let window = number("initial_windows_size")?;
        Ok(Self {
            keepalive: (idle != 0).then_some(H2Keepalive {
                interval: Duration::from_secs(idle.max(10).into()),
                timeout,
                without_stream: permit_without_stream,
            }),
            receive_window: (window >= 65_535).then_some(window),
            user_agent: user_agent(get("user_agent").unwrap_or_default()),
        })
    }
}

fn user_agent(configured: &str) -> Option<String> {
    use time::{Date, Month, OffsetDateTime};

    static BROWSERS: OnceLock<[String; 3]> = OnceLock::new();
    let browser = match configured {
        "" | "chrome" => 0,
        "edge" => 1,
        "firefox" => 2,
        "golang" => return None,
        text => return Some(text.to_owned()),
    };
    let browsers = BROWSERS.get_or_init(|| {
        let today = OffsetDateTime::now_utc().date();
        let chrome_anchor = Date::from_calendar_date(2026, Month::January, 13).unwrap();
        let firefox_anchor = Date::from_calendar_date(2024, Month::July, 29).unwrap();
        let chrome_delay = (rand::random::<f64>().powi(2) * 105.0) as i64;
        let firefox_delay = (rand::random::<f64>().powi(2) * 50.0) as i64;
        let chrome = 144 + ((today - chrome_anchor).whole_days() - 35 - chrome_delay) / 35;
        let firefox = 128 + ((today - firefox_anchor).whole_days() - 25 - firefox_delay) / 30;
        let chromium = format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36");
        let edge = format!("{chromium}Edg/{chrome}.0.0.0");
        let firefox = format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{firefox}.0) Gecko/20100101 Firefox/{firefox}.0");
        [chromium, edge, firefox]
    });
    Some(browsers[browser].clone())
}

pub struct GrpcConnection<W: Write> {
    http: H2Conn<W>,
    user_agent: Option<String>,
}

impl<W: Write + Send + 'static> GrpcConnection<W> {
    pub fn connect<R: Read + Send + 'static>(read: R, write: W) -> io::Result<Self> {
        Self::connect_with(read, write, GrpcOptions::default())
    }

    pub fn connect_with<R: Read + Send + 'static>(
        read: R,
        write: W,
        options: GrpcOptions,
    ) -> io::Result<Self> {
        let http = H2Conn::start_grpc(
            read,
            write,
            false,
            options.receive_window,
            options.keepalive,
        )?;
        Ok(Self {
            http,
            user_agent: options.user_agent,
        })
    }

    pub fn serve<R: Read + Send + 'static>(read: R, write: W) -> io::Result<Self> {
        Self::serve_with(read, write, GrpcOptions::default())
    }

    pub fn serve_with<R: Read + Send + 'static>(
        read: R,
        write: W,
        options: GrpcOptions,
    ) -> io::Result<Self> {
        let http = H2Conn::start_grpc(read, write, true, None, options.keepalive)?;
        Ok(Self {
            http,
            user_agent: None,
        })
    }

    pub fn is_open(&self) -> bool {
        self.http.is_open()
    }

    pub fn open(&self, authority: &str, path: &str, scheme: &str) -> io::Result<GrpcStream<W>> {
        // Xray may wait for the first request message before sending response headers.
        let mut headers = vec![
            (":method", "POST"),
            (":scheme", scheme),
            (":path", path),
            (":authority", authority),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ];
        if let Some(agent) = self.user_agent.as_deref() {
            headers.push(("user-agent", agent));
        }
        let mut http =
            self.http
                .request_with_headers(&headers, false, false, Some(OPEN_TIMEOUT))?;
        http.mark_grpc();
        Ok(GrpcStream::new(http))
    }

    pub fn accept(&self, paths: &[&str]) -> io::Result<GrpcStream<W>> {
        loop {
            let mut http = self.http.accept()?;
            http.mark_grpc();
            let result = if !http
                .header("content-type")
                .is_some_and(|value| is_grpc(&value))
            {
                http.reply_with(415, &[], true)
            } else if http.header(":method").as_deref() != Some("POST")
                || !http
                    .header(":path")
                    .is_some_and(|path| paths.contains(&path.as_str()))
            {
                http.reply_with(
                    200,
                    &[("content-type", "application/grpc"), ("grpc-status", "12")],
                    true,
                )
            } else {
                match http.reply_with(200, &[("content-type", "application/grpc")], false) {
                    Ok(()) => return Ok(GrpcStream::new(http)),
                    Err(error) => Err(error),
                }
            };
            if let Err(error) = result {
                // A peer can cancel the RPC between HEADERS and the response.
                if !matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::TimedOut | ErrorKind::WouldBlock
                ) {
                    return Err(error);
                }
            }
        }
    }
}

fn is_grpc(value: &str) -> bool {
    value
        .strip_prefix("application/grpc")
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(['+', ';']))
}

pub struct GrpcStream<W: Write + Send + 'static> {
    http: H2Stream<W>,
    reader: Mutex<HunkReader>,
    writer: Mutex<HunkWriter>,
    timeout_ms: AtomicU64,
}

impl<W: Write + Send + 'static> GrpcStream<W> {
    fn new(http: H2Stream<W>) -> Self {
        Self {
            http,
            reader: Mutex::new(HunkReader::default()),
            writer: Mutex::new(HunkWriter::default()),
            timeout_ms: AtomicU64::new(OPEN_TIMEOUT.as_millis() as u64),
        }
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.http.header(name)
    }

    pub fn set_timeout(&self, timeout: Duration) {
        self.timeout_ms
            .store(timeout.as_millis() as u64, Ordering::Relaxed);
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed))
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let timeout = self.timeout();
        self.reader
            .lock()
            .expect("gRPC reader")
            .read(|bytes| self.http.read_for(bytes, timeout), buf)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let timeout = self.timeout();
        self.writer
            .lock()
            .expect("gRPC writer")
            .write(|bytes| self.http.write_for(bytes, timeout), buf)
    }

    pub fn flush(&self) -> io::Result<()> {
        let timeout = self.timeout();
        self.writer
            .lock()
            .expect("gRPC writer")
            .send(|bytes| self.http.write_for(bytes, timeout))?;
        self.http.flush()
    }
}

impl<W: Write + Send + 'static> Drop for GrpcStream<W> {
    fn drop(&mut self) {
        if !self
            .writer
            .get_mut()
            .expect("gRPC writer")
            .message
            .is_empty()
        {
            self.http.cancel();
        }
    }
}

impl<W: Write + Send + 'static> Read for GrpcStream<W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        GrpcStream::read(self, buf)
    }
}

impl<W: Write + Send + 'static> Write for GrpcStream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        GrpcStream::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        GrpcStream::flush(self)
    }
}

#[derive(Default)]
struct HunkReader {
    prefix: [u8; 5],
    prefix_len: usize,
    message: Vec<u8>,
    plain: Vec<u8>,
    read: usize,
}

impl HunkReader {
    fn read(
        &mut self,
        mut receive: impl FnMut(&mut [u8]) -> io::Result<usize>,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        let mut chunk = [0; 8192];
        while self.read == self.plain.len() {
            while self.prefix_len < self.prefix.len() {
                let len = receive(&mut self.prefix[self.prefix_len..])?;
                if len == 0 {
                    return if self.prefix_len == 0 {
                        Ok(0)
                    } else {
                        Err(truncated())
                    };
                }
                self.prefix_len += len;
            }
            let len = u32::from_be_bytes(self.prefix[1..].try_into().unwrap()) as usize;
            if self.prefix[0] != 0 || len > MAX_MESSAGE {
                return Err(invalid("gRPC message flags or length"));
            }
            while self.message.len() < len {
                let remaining = (len - self.message.len()).min(chunk.len());
                let received = receive(&mut chunk[..remaining])?;
                if received == 0 {
                    return Err(truncated());
                }
                self.message.extend_from_slice(&chunk[..received]);
            }
            self.plain.clear();
            self.read = 0;
            if let Err(error) = decode_hunk(&self.message, &mut self.plain) {
                self.plain.clear();
                return Err(error);
            }
            self.prefix_len = 0;
            self.message.clear();
        }
        let len = buf.len().min(self.plain.len() - self.read);
        buf[..len].copy_from_slice(&self.plain[self.read..self.read + len]);
        self.read += len;
        Ok(len)
    }
}

#[derive(Default)]
struct HunkWriter {
    message: Vec<u8>,
    sent: usize,
}

impl HunkWriter {
    fn send(&mut self, mut write: impl FnMut(&[u8]) -> io::Result<usize>) -> io::Result<()> {
        while self.sent < self.message.len() {
            match write(&self.message[self.sent..]) {
                Ok(0) => return Err(io::Error::new(ErrorKind::WriteZero, "gRPC message")),
                Ok(len) => self.sent += len,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        self.message.clear();
        self.sent = 0;
        Ok(())
    }

    fn write(
        &mut self,
        mut write: impl FnMut(&[u8]) -> io::Result<usize>,
        buf: &[u8],
    ) -> io::Result<usize> {
        self.send(&mut write)?;
        let len = buf.len().min(WRITE_CHUNK);
        if len == 0 {
            return Ok(0);
        }
        encode_hunk(&buf[..len], &mut self.message);
        match self.send(write) {
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if self.sent == 0 {
                    self.message.clear();
                    Err(error)
                } else {
                    Ok(len)
                }
            }
            Err(error) => Err(error),
            Ok(()) => Ok(len),
        }
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, reason)
}

fn truncated() -> io::Error {
    io::Error::new(ErrorKind::UnexpectedEof, "gRPC message truncated")
}

fn decode_hunk(mut body: &[u8], plain: &mut Vec<u8>) -> io::Result<()> {
    while !body.is_empty() {
        let tag = read_varint(&mut body)?;
        let field = tag >> 3;
        if field == 0 || field >= 1 << 29 {
            return Err(invalid("gRPC protobuf field"));
        }
        let len = match tag & 7 {
            0 => {
                read_varint(&mut body)?;
                continue;
            }
            1 => 8,
            2 => usize::try_from(read_varint(&mut body)?)
                .map_err(|_| invalid("gRPC protobuf length"))?,
            5 => 4,
            _ => return Err(invalid("gRPC protobuf wire type")),
        };
        let (value, rest) = body
            .split_at_checked(len)
            .ok_or_else(|| invalid("gRPC protobuf length"))?;
        if field == 1 && tag & 7 == 2 {
            plain.extend_from_slice(value);
        }
        body = rest;
    }
    Ok(())
}

fn read_varint(bytes: &mut &[u8]) -> io::Result<u64> {
    let mut value = 0;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = bytes
            .split_first()
            .ok_or_else(|| invalid("gRPC protobuf varint"))?;
        *bytes = rest;
        if shift == 63 && byte > 1 {
            break;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("gRPC protobuf varint"))
}

fn encode_hunk(data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0x0a]);
    let mut len = data.len();
    while len >= 0x80 {
        out.push(len as u8 | 0x80);
        len >>= 7;
    }
    out.push(len as u8);
    out.extend_from_slice(data);
    let message_len = (out.len() - 5) as u32;
    out[1..5].copy_from_slice(&message_len.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpIo;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    fn sockets() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
        }
        (client, server)
    }

    #[test]
    fn gun_sends_request_before_response_headers() {
        let (client, server) = sockets();
        let server = thread::spawn(move || {
            let mut http = HttpIo::receive_request(server, false).unwrap();
            assert_eq!(http.header(":path"), Some("/GunService/Tun"));
            let mut request = [0; 4];
            let mut reader = HunkReader::default();
            assert_eq!(reader.read(|buf| http.read(buf), &mut request).unwrap(), 4);
            assert_eq!(&request, b"ping");
            http.reply_with(&[(":status", "200"), ("content-type", "application/grpc")])
                .unwrap();
            let mut response = Vec::new();
            encode_hunk(b"pong", &mut response);
            http.write_all(&response).unwrap();
        });
        let connection = GrpcConnection::connect(client.try_clone().unwrap(), client).unwrap();
        let mut gun = connection
            .open("localhost", "/GunService/Tun", "http")
            .unwrap();
        gun.write_all(b"ping").unwrap();
        let mut response = [0; 4];
        gun.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn one_connection_carries_independent_tun_and_tun_multi_streams() {
        fn send(gun: &GrpcStream<TcpStream>, mut bytes: &[u8]) {
            while !bytes.is_empty() {
                let len = gun.write(bytes).unwrap();
                assert!(len > 0);
                bytes = &bytes[len..];
            }
            gun.flush().unwrap();
        }

        fn receive(gun: &GrpcStream<TcpStream>, expected: &[u8]) {
            let mut buf = [0; 17_000];
            let mut offset = 0;
            while offset < expected.len() {
                let len = gun.read(&mut buf).unwrap();
                assert!(len > 0);
                assert_eq!(&buf[..len], &expected[offset..offset + len]);
                offset += len;
            }
        }

        let (client, server) = sockets();
        let client = GrpcConnection::connect(client.try_clone().unwrap(), client).unwrap();
        let server = GrpcConnection::serve(server.try_clone().unwrap(), server).unwrap();
        let paths = ["/GunService/Tun", "/GunService/TunMulti"];
        let tun = client.open("localhost", paths[0], "http").unwrap();
        let multi = client.open("localhost", paths[1], "http").unwrap();
        let server_tun = server.accept(&paths).unwrap();
        let server_multi = server.accept(&paths).unwrap();

        let up: Vec<u8> = (0..2_000_000).map(|i| (i % 239) as u8).collect();
        let down: Vec<u8> = (0..2_300_000).map(|i| (i % 251) as u8).collect();
        thread::scope(|scope| {
            scope.spawn(|| send(&tun, &up));
            scope.spawn(|| send(&server_tun, &down));
            scope.spawn(|| receive(&tun, &down));
            scope.spawn(|| receive(&server_tun, &up));
            scope.spawn(|| send(&multi, &down));
            receive(&server_multi, &down);
        });

        send(&server_tun, b"last bytes");
        drop(server_tun);
        receive(&tun, b"last bytes");
        assert_eq!(tun.read(&mut [0; 1]).unwrap(), 0);
        send(&server_multi, b"still open");
        receive(&multi, b"still open");

        let next = client.open("localhost", paths[0], "http").unwrap();
        let server_next = server.accept(&paths).unwrap();
        drop(multi);
        assert_eq!(
            server_multi.read(&mut [0; 1]).unwrap_err().kind(),
            ErrorKind::ConnectionReset
        );
        send(&next, b"same connection");
        receive(&server_next, b"same connection");
    }

    #[test]
    fn grpc_configured_window_and_keepalive_on_the_wire() {
        fn frame(peer: &mut TcpStream) -> (u8, u8, Vec<u8>) {
            let mut header = [0; 9];
            peer.read_exact(&mut header).unwrap();
            let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            let mut payload = vec![0; len];
            peer.read_exact(&mut payload).unwrap();
            (header[3], header[4], payload)
        }

        let (client, mut peer) = sockets();
        client
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let mut options = GrpcOptions::parse(
            |name| match name {
                "initial_windows_size" => Some("131072"),
                "idle_timeout" => Some("1"),
                "permit_without_stream" => Some("true"),
                "user_agent" => Some("golang"),
                _ => None,
            },
            false,
        )
        .unwrap();
        assert_eq!(options.keepalive.unwrap().interval, Duration::from_secs(10));
        assert!(options.user_agent.is_none());
        options.keepalive = Some(H2Keepalive {
            interval: Duration::from_millis(25),
            timeout: Duration::from_millis(300),
            without_stream: true,
        });
        let client =
            GrpcConnection::connect_with(client.try_clone().unwrap(), client, options).unwrap();
        let mut preface = [0; 24];
        peer.read_exact(&mut preface).unwrap();
        assert_eq!(preface, crate::HTTP2_PREFACE);
        let (kind, flags, settings) = frame(&mut peer);
        assert_eq!((kind, flags), (4, 0));
        assert!(settings
            .as_chunks::<6>()
            .0
            .contains(&[0, 4, 0, 2, 0, 0]));
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(frame(&mut peer), (4, 1, Vec::new()));

        let (kind, flags, payload) = frame(&mut peer);
        assert_eq!((kind, flags, payload.len()), (6, 0, 8));
        peer.write_all(&[0, 0, 8, 6, 1, 0, 0, 0, 0]).unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(60))).unwrap();
        assert!(matches!(
            peer.read(&mut [0; 1]).unwrap_err().kind(),
            ErrorKind::TimedOut | ErrorKind::WouldBlock
        ));
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.write_all(&payload).unwrap();
        assert_eq!(frame(&mut peer).0, 6);
        let stream = client.open("localhost", "/GunService/Tun", "http").unwrap();
        let error = stream.read(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConnectionReset);
        assert!(error.to_string().contains("keepalive"));
        assert!(!client.is_open());
        assert_eq!(frame(&mut peer).0, 1);
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn malformed_hunk_is_rejected_on_each_read() {
        let mut messages = Vec::new();
        encode_hunk(b"valid", &mut messages);
        messages.extend_from_slice(&[0, 0, 0, 0, 5, 0x0a, 1, b'x', 0x0a, 0x80]);
        let mut wire = messages.as_slice();
        let mut reader = HunkReader::default();
        let mut out = [0; 5];
        assert_eq!(reader.read(|buf| wire.read(buf), &mut out).unwrap(), 5);
        assert_eq!(&out, b"valid");
        for _ in 0..2 {
            assert_eq!(
                reader
                    .read(|buf| wire.read(buf), &mut out)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn grpc_paths_match_xray_service_and_stream_names() {
        assert_eq!(grpc_path("", false), "//Tun");
        assert_eq!(
            grpc_path("chat/代理", true),
            "/chat%2F%E4%BB%A3%E7%90%86/TunMulti"
        );
        assert_eq!(
            grpc_path("/api/v 1/single|multi", false),
            "/api/v%201/single"
        );
        assert_eq!(grpc_path("/api/v 1/single|multi", true), "/api/v%201/multi");
        assert_eq!(grpc_path("/api/v 1/multi", true), "/api/v%201/multi");
    }
}
