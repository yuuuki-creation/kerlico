//! Request metadata and HTTP/1 framing shared by XHTTP clients and listeners.

mod config;

pub use config::{XhttpConfig, XhttpDownload, XhttpMode, XhttpRequest, XhttpRequestKind};

use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;

pub fn new_session() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn session_path(base: &str, session: &str, seq: Option<u64>) -> String {
    let base = if base == "/" {
        String::new()
    } else {
        base.trim_end_matches('/').to_string()
    };
    match seq {
        Some(seq) => format!("{base}/{session}/{seq}"),
        None => format!("{base}/{session}"),
    }
}

pub fn split_session(base: &str, path: &str) -> Option<(String, Option<u64>)> {
    let base = if base == "/" {
        ""
    } else {
        base.trim_end_matches('/')
    };
    let rest = path.strip_prefix(base)?;
    let rest = rest.strip_prefix('/')?;
    if rest.is_empty() {
        return None;
    }
    let mut parts = rest.splitn(2, '/');
    let session = parts.next()?.to_string();
    if session.is_empty() {
        return None;
    }
    let seq = match parts.next() {
        None => None,
        Some(text) => Some(text.parse().ok()?),
    };
    Some((session, seq))
}

pub struct HttpHead {
    pub method: String,
    pub target: String,
    pub path: String,
    pub host: String,
    pub length: Option<usize>,
    pub chunked: bool,
    pub rest: Vec<u8>,
    headers: Vec<(String, String)>,
}

impl HttpHead {
    pub fn header(&self, name: &str) -> Option<String> {
        let mut values = self
            .headers
            .iter()
            .filter_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()));
        let mut result = values.next()?.to_owned();
        if name.eq_ignore_ascii_case("cookie") {
            for value in values {
                result.push_str("; ");
                result.push_str(value);
            }
        }
        Some(result)
    }
}

pub fn read_http_head(socket: &mut dyn Read) -> io::Result<HttpHead> {
    read_http_head_with_limit(socket, 16384)
}

pub fn read_http_head_with_limit(socket: &mut dyn Read, limit: usize) -> io::Result<HttpHead> {
    let mut buf = Vec::new();
    let end = read_head_bytes(socket, &mut buf, limit)?;
    let rest = buf.split_off(end + 4);
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| invalid("XHTTP request header"))?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("XHTTP request line"));
    };
    if ::http::Method::from_bytes(method.as_bytes()).is_err()
        || target.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(invalid("XHTTP request line"));
    }
    let mut request = HttpHead {
        method: method.to_owned(),
        target: target.to_owned(),
        path: target.split('?').next().unwrap_or("").to_owned(),
        host: String::new(),
        length: None,
        chunked: false,
        rest,
        headers: Vec::new(),
    };
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("XHTTP request header"))?;
        let name = ::http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("XHTTP request header name"))?;
        let value = value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
        {
            return Err(invalid("XHTTP request header value"));
        }
        match name.as_str() {
            "host" if !request.host.is_empty() => return Err(invalid("XHTTP duplicate Host")),
            "host" => request.host = value.to_owned(),
            "content-length" => {
                let length = value.parse().map_err(|_| invalid("XHTTP content length"))?;
                if request.length.is_some_and(|previous| previous != length) {
                    return Err(invalid("XHTTP conflicting content lengths"));
                }
                request.length = Some(length);
            }
            "transfer-encoding" if value.eq_ignore_ascii_case("chunked") && !request.chunked => {
                request.chunked = true;
            }
            "transfer-encoding" => return Err(invalid("XHTTP transfer encoding")),
            _ => {}
        }
        request.headers.push((name.to_string(), value.to_owned()));
    }
    if request.chunked && request.length.is_some() {
        return Err(invalid("XHTTP conflicting transfer framing"));
    }
    Ok(request)
}

pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub body: Vec<u8>,
}

pub fn read_http_request(socket: &mut dyn Read) -> io::Result<HttpRequest> {
    let HttpHead {
        method,
        path,
        host,
        length,
        rest: mut body,
        ..
    } = read_http_head(socket)?;
    let length = length.unwrap_or(0);
    body.truncate(length);
    let missing = (length - body.len()) as u64;
    if socket.take(missing).read_to_end(&mut body)? as u64 != missing {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "XHTTP request body",
        ));
    }
    Ok(HttpRequest {
        method,
        path,
        host,
        body,
    })
}

pub fn write_get(socket: &mut dyn Write, host: &str, path: &str) -> std::io::Result<()> {
    let padding = "0".repeat(100);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nReferer: http://{host}{path}?x_padding={padding}\r\n\r\n"
    );
    socket.write_all(request.as_bytes())
}

pub fn write_post(
    socket: &mut dyn Write,
    host: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let padding = "0".repeat(100);
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nReferer: http://{host}{path}?x_padding={padding}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    socket.write_all(head.as_bytes())?;
    socket.write_all(body)
}

pub fn write_empty_ok(socket: &mut dyn Write) -> std::io::Result<()> {
    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
}

pub fn write_stream_post(socket: &mut dyn Write, host: &str, path: &str) -> std::io::Result<()> {
    let padding = "0".repeat(100);
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\nReferer: http://{host}{path}?x_padding={padding}\r\n\r\n"
    );
    socket.write_all(request.as_bytes())
}

pub fn write_chunked_ok(socket: &mut dyn Write) -> std::io::Result<()> {
    socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
}

pub fn write_xhttp_response(
    socket: &mut dyn Write,
    status: u16,
    headers: &[(&str, &str)],
    chunked: bool,
) -> io::Result<()> {
    let status = ::http::StatusCode::from_u16(status).map_err(|_| invalid("XHTTP status"))?;
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    for (name, value) in headers {
        ::http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("XHTTP response header name"))?;
        ::http::HeaderValue::from_str(value).map_err(|_| invalid("XHTTP response header value"))?;
        push_header(&mut head, name, value);
    }
    head.push_str(if chunked {
        "Transfer-Encoding: chunked\r\n"
    } else {
        "Content-Length: 0\r\n"
    });
    head.push_str("\r\n");
    socket.write_all(head.as_bytes())
}

fn push_header(head: &mut String, name: &str, value: &str) {
    head.push_str(name);
    head.push_str(": ");
    head.push_str(value);
    head.push_str("\r\n");
}

/// Writes one complete chunk to a blocking output.
pub fn write_chunk(socket: &mut dyn Write, data: &[u8]) -> std::io::Result<()> {
    let mut writer = ChunkWriter::new(socket);
    if data.is_empty() {
        writer.finish()
    } else {
        writer.write_all(data)
    }
}

enum ChunkWriteState {
    Idle,
    Data { start: usize, len: usize },
    Ending,
    End,
}

/// Encodes HTTP/1 chunks across partial writes, including the final chunk.
pub struct ChunkWriter<W> {
    inner: W,
    wire: Vec<u8>,
    sent: usize,
    state: ChunkWriteState,
}

impl<W> ChunkWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            wire: Vec::new(),
            sent: 0,
            state: ChunkWriteState::Idle,
        }
    }
}

impl<W: Write> ChunkWriter<W> {
    fn emit(&mut self) -> io::Result<()> {
        while self.sent < self.wire.len() {
            match self.inner.write(&self.wire[self.sent..]) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(n) => self.sent += n,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn finish(&mut self) -> io::Result<()> {
        match self.state {
            ChunkWriteState::End => return Ok(()),
            ChunkWriteState::Ending => {}
            ChunkWriteState::Idle | ChunkWriteState::Data { .. } => {
                self.emit()?;
                self.wire.clear();
                self.wire.extend_from_slice(b"0\r\n\r\n");
                self.sent = 0;
                self.state = ChunkWriteState::Ending;
            }
        }
        self.flush()?;
        self.wire.clear();
        self.sent = 0;
        self.state = ChunkWriteState::End;
        Ok(())
    }
}

impl<W: Write> Write for ChunkWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let len = match self.state {
            ChunkWriteState::Idle => {
                write!(&mut self.wire, "{:x}\r\n", data.len())?;
                let start = self.wire.len();
                let len = data.len();
                self.wire.extend_from_slice(data);
                self.wire.extend_from_slice(b"\r\n");
                self.state = ChunkWriteState::Data { start, len };
                len
            }
            ChunkWriteState::Data { start, len } => {
                if !data.starts_with(&self.wire[start..start + len]) {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "XHTTP chunk retry buffer changed",
                    ));
                }
                len
            }
            ChunkWriteState::Ending | ChunkWriteState::End => {
                return Err(ErrorKind::BrokenPipe.into())
            }
        };
        self.flush()?;
        self.wire.clear();
        self.sent = 0;
        self.state = ChunkWriteState::Idle;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.inner.flush()
    }
}

pub enum XhttpBodyWriter<W: Write> {
    Chunked(ChunkWriter<W>),
    Stream(W),
}

impl<W: Write> XhttpBodyWriter<W> {
    pub fn new(inner: W, chunked: bool) -> Self {
        if chunked {
            Self::Chunked(ChunkWriter::new(inner))
        } else {
            Self::Stream(inner)
        }
    }
}

impl<W: Write> Write for XhttpBodyWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Chunked(writer) => writer.write(buf),
            Self::Stream(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Chunked(writer) => writer.flush(),
            Self::Stream(writer) => writer.flush(),
        }
    }
}

impl<W: Write> Drop for XhttpBodyWriter<W> {
    fn drop(&mut self) {
        if let Self::Chunked(writer) = self {
            let _ = writer.finish();
        }
    }
}

pub fn read_response_head(socket: &mut dyn Read) -> io::Result<Vec<u8>> {
    read_ok_response(socket).map(|(mut bytes, end)| bytes.split_off(end + 4))
}

/// Reads a packet acknowledgment and reports whether its HTTP/1 connection is reusable.
pub fn read_packet_ack(socket: &mut dyn Read, method: &str) -> io::Result<bool> {
    let (bytes, end) = read_ok_response(socket)?;
    let head = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid("XHTTP response header"))?;
    let mut lines = head.split("\r\n");
    if !lines.next().unwrap_or("").starts_with("HTTP/1.1 ") || bytes.len() != end + 4 {
        return Ok(false);
    }
    let mut empty = method == "HEAD";
    for (name, value) in lines.filter_map(|line| line.split_once(':')) {
        if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
        {
            return Ok(false);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Ok(false);
        }
        if name.eq_ignore_ascii_case("content-length") {
            empty |= value.trim() == "0";
        }
    }
    Ok(empty)
}

fn read_ok_response(socket: &mut dyn Read) -> io::Result<(Vec<u8>, usize)> {
    let mut buf = Vec::new();
    loop {
        let end = read_head_bytes(socket, &mut buf, 65536)?;
        let head =
            std::str::from_utf8(&buf[..end]).map_err(|_| invalid("XHTTP response header"))?;
        let mut status = head.split("\r\n").next().unwrap_or("").splitn(3, ' ');
        if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(invalid("XHTTP response version"));
        }
        match status.next().and_then(|text| text.parse::<u16>().ok()) {
            Some(200) => return Ok((buf, end)),
            Some(100 | 102 | 103) => drop(buf.drain(..end + 4)),
            _ => return Err(invalid("XHTTP response status")),
        }
    }
}

fn read_head_bytes(socket: &mut dyn Read, buf: &mut Vec<u8>, limit: usize) -> io::Result<usize> {
    let mut from = 0;
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(index) = buf[from..]
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
        {
            let end = from + index;
            return if end + 4 <= limit {
                Ok(end)
            } else {
                Err(invalid("XHTTP header too large"))
            };
        }
        if buf.len() >= limit {
            return Err(invalid("XHTTP header too large"));
        }
        from = buf.len().saturating_sub(3);
        let n = socket.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "XHTTP header"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

pub struct ChunkPair {
    reader: std::sync::Mutex<Box<dyn Read + Send>>,
    writer: std::sync::Mutex<XhttpBodyWriter<Box<dyn Write + Send>>>,
}

impl ChunkPair {
    pub fn split(
        download: impl Read + Send + 'static,
        rest: Vec<u8>,
        upload: impl Write + Send + 'static,
    ) -> Self {
        Self::with_reader(ChunkReader::new(download, rest), upload)
    }

    pub fn with_reader(
        download: impl Read + Send + 'static,
        upload: impl Write + Send + 'static,
    ) -> Self {
        Self {
            reader: std::sync::Mutex::new(Box::new(download)),
            writer: std::sync::Mutex::new(XhttpBodyWriter::new(Box::new(upload), true)),
        }
    }

    pub fn open(socket: TcpStream, rest: Vec<u8>) -> std::io::Result<Self> {
        let writer = socket.try_clone()?;
        Ok(Self::split(socket, rest, writer))
    }

    pub fn pull(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.lock().expect("xhttp").read(buf)
    }

    pub fn push(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.lock().expect("xhttp").write(buf)
    }

    pub fn flush(&self) -> io::Result<()> {
        self.writer.lock().expect("xhttp").flush()
    }
}

pub struct ChunkReader {
    socket: Box<dyn Read + Send>,
    rest: Vec<u8>,
    offset: usize,
    state: ChunkState,
}

enum ChunkState {
    Size,
    Body(usize),
    Separator,
    Trailers,
    End,
}

impl ChunkReader {
    pub fn new(socket: impl Read + Send + 'static, prelude: Vec<u8>) -> Self {
        Self {
            socket: Box::new(socket),
            rest: prelude,
            offset: 0,
            state: ChunkState::Size,
        }
    }

    pub fn pull(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read(buf)
    }

    fn read_line(&mut self) -> io::Result<&[u8]> {
        const MAX_LINE: usize = 4096;
        loop {
            if let Some(end) = self.rest[self.offset..]
                .windows(2)
                .position(|bytes| bytes == b"\r\n")
            {
                if end > MAX_LINE {
                    return Err(invalid("XHTTP chunk line too large"));
                }
                let start = self.offset;
                self.offset += end + 2;
                return Ok(&self.rest[start..start + end]);
            }
            if self.rest.len() - self.offset > MAX_LINE + 1 {
                return Err(invalid("XHTTP chunk line too large"));
            }
            self.rest.drain(..self.offset);
            self.offset = 0;
            let mut tmp = [0u8; 1024];
            let n = self.socket.read(&mut tmp)?;
            if n == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "XHTTP chunk framing",
                ));
            }
            self.rest.extend_from_slice(&tmp[..n]);
        }
    }

    fn read_body(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = &self.rest[self.offset..];
        if remaining.is_empty() {
            return self.socket.read(buf);
        }
        let n = buf.len().min(remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.offset += n;
        Ok(n)
    }
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            self.state = match self.state {
                ChunkState::Size => {
                    let line = self.read_line()?;
                    let size = line.split(|byte| *byte == b';').next().unwrap_or_default();
                    let size =
                        std::str::from_utf8(size).map_err(|_| invalid("XHTTP chunk size"))?;
                    let size = usize::from_str_radix(size.trim_end(), 16)
                        .map_err(|_| invalid("XHTTP chunk size"))?;
                    if size == 0 {
                        ChunkState::Trailers
                    } else {
                        ChunkState::Body(size)
                    }
                }
                ChunkState::Body(remaining) => {
                    let limit = remaining.min(buf.len());
                    let n = self.read_body(&mut buf[..limit])?;
                    if n == 0 {
                        return Err(io::Error::new(ErrorKind::UnexpectedEof, "XHTTP chunk body"));
                    }
                    self.state = if remaining == n {
                        ChunkState::Separator
                    } else {
                        ChunkState::Body(remaining - n)
                    };
                    return Ok(n);
                }
                ChunkState::Separator => {
                    if !self.read_line()?.is_empty() {
                        return Err(invalid("XHTTP chunk separator"));
                    }
                    ChunkState::Size
                }
                ChunkState::Trailers => {
                    if self.read_line()?.is_empty() {
                        ChunkState::End
                    } else {
                        ChunkState::Trailers
                    }
                }
                ChunkState::End => return Ok(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct PausingWriter {
        bytes: Vec<u8>,
        pause_at: Option<usize>,
        pause_flush: bool,
    }

    impl Write for PausingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let n = match self.pause_at {
                Some(at) if self.bytes.len() == at => {
                    self.pause_at = None;
                    return Err(ErrorKind::WouldBlock.into());
                }
                Some(at) => (at - self.bytes.len()).min(bytes.len()),
                None => bytes.len(),
            };
            self.bytes.extend_from_slice(&bytes[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            if std::mem::take(&mut self.pause_flush) {
                return Err(ErrorKind::WouldBlock.into());
            }
            Ok(())
        }
    }

    #[test]
    fn chunk_write_retries_every_wire_boundary_without_repeating_bytes() {
        let chunk = b"3\r\nabc\r\n";
        for boundary in 0..chunk.len() {
            let mut writer = ChunkWriter::new(PausingWriter {
                bytes: Vec::new(),
                pause_at: Some(boundary),
                pause_flush: false,
            });
            assert_eq!(
                writer.write(b"abc").unwrap_err().kind(),
                ErrorKind::WouldBlock
            );
            assert_eq!(writer.inner.bytes, chunk[..boundary]);
            assert_eq!(
                writer.write(b"changed").unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
            writer.flush().unwrap();
            assert_eq!(writer.write(b"abc-plus").unwrap(), 3);
            writer.write_all(b"def").unwrap();
            writer.finish().unwrap();
            writer.finish().unwrap();
            assert_eq!(writer.inner.bytes, b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n");
        }
    }

    #[test]
    fn chunk_flush_and_terminal_retries_keep_one_frame() {
        for boundary in 0..b"0\r\n\r\n".len() {
            let mut writer = ChunkWriter::new(PausingWriter {
                bytes: Vec::new(),
                pause_at: None,
                pause_flush: true,
            });
            assert_eq!(
                writer.write(b"abc").unwrap_err().kind(),
                ErrorKind::WouldBlock
            );
            assert_eq!(writer.write(b"abc").unwrap(), 3);
            let data_end = writer.inner.bytes.len();
            writer.inner.pause_at = Some(data_end + boundary);
            writer.inner.pause_flush = true;
            assert_eq!(writer.finish().unwrap_err().kind(), ErrorKind::WouldBlock);
            assert_eq!(writer.flush().unwrap_err().kind(), ErrorKind::WouldBlock);
            writer.finish().unwrap();
            assert_eq!(
                writer.write(b"too late").unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );
            assert_eq!(writer.inner.bytes, b"3\r\nabc\r\n0\r\n\r\n");
        }
    }

    #[test]
    fn session_path_splits_back() {
        assert_eq!(session_path("/", "abc", None), "/abc");
        assert_eq!(session_path("/", "abc", Some(3)), "/abc/3");
        assert_eq!(session_path("/xh", "abc", Some(0)), "/xh/abc/0");
        assert_eq!(
            split_session("/", "/abc/3"),
            Some(("abc".to_string(), Some(3)))
        );
        assert_eq!(
            split_session("/xh", "/xh/abc"),
            Some(("abc".to_string(), None))
        );
    }

    #[test]
    fn request_head_retains_query_cookies_and_prefetched_body() {
        let mut wire = b"PUT /xh?q=a%26b HTTP/1.1\r\nHost: example.org\r\nCookie: a=1\r\ncOoKiE: b=2\r\nContent-Length: 3\r\n\r\nabcGET".as_slice();
        let head = read_http_head_with_limit(&mut wire, 120).unwrap();
        assert_eq!(head.method, "PUT");
        assert_eq!(head.target, "/xh?q=a%26b");
        assert_eq!(head.path, "/xh");
        assert_eq!(head.host, "example.org");
        assert_eq!(head.header("Cookie").as_deref(), Some("a=1; b=2"));
        assert_eq!(head.length, Some(3));
        assert_eq!(head.rest, b"abcGET");
    }

    #[test]
    fn chunk_reader_resumes_after_timeouts_and_streams_partial_chunks() {
        struct Segments(VecDeque<Option<&'static [u8]>>);
        impl Read for Segments {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let Some(segment) = self.0.pop_front() else {
                    return Ok(0);
                };
                let mut bytes = segment.ok_or(ErrorKind::TimedOut)?;
                let n = bytes.read(buf)?;
                if !bytes.is_empty() {
                    self.0.push_front(Some(bytes));
                }
                Ok(n)
            }
        }
        let parts: [Option<&[u8]>; 6] = [
            None,
            Some(b"\nab"),
            None,
            Some(b"cde\r"),
            None,
            Some(b"\n2;tag=x\r\nfg\r\n0\r\nTrailer: yes\r\n\r\n"),
        ];
        let segments = Segments(VecDeque::from(parts));
        let mut reader = ChunkReader::new(segments, b"5\r".to_vec());
        let mut buf = [0; 16];
        for (expected, actual) in [(b"ab".as_slice(), 2), (b"cde", 3), (b"fg", 2)] {
            assert_eq!(
                reader.read(&mut buf).unwrap_err().kind(),
                ErrorKind::TimedOut
            );
            assert_eq!(reader.read(&mut buf).unwrap(), actual);
            assert_eq!(&buf[..actual], expected);
        }
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }
}
