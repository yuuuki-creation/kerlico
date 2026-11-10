use super::socks;
use super::{interrupted, invalid, timed_out, Client, State};
use kerlico_shared::Stream;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEAD_LIMIT: usize = 32768;
const LINE_LIMIT: usize = 8192;
const IDLE: Duration = Duration::from_secs(300);

struct LocalInput {
    stream: TcpStream,
    state: Arc<State>,
    last: Instant,
}
impl Read for LocalInput {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.state.stopped() {
                return Err(interrupted());
            }
            if self.last.elapsed() >= IDLE {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match self.stream.read(data) {
                Err(e) if timed_out(&e) => continue,
                Ok(n) => {
                    if n != 0 {
                        self.last = Instant::now();
                    }
                    return Ok(n);
                }
                Err(e) => return Err(e),
            }
        }
    }
}
struct RemoteInput<'a> {
    conn: &'a dyn Stream,
    state: &'a State,
    last: Instant,
}
impl Read for RemoteInput<'_> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.state.stopped() {
                return Err(interrupted());
            }
            if self.last.elapsed() >= IDLE {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match self.conn.read_for(data, Duration::from_millis(200)) {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) if timed_out(&e) => continue,
                Ok(n) => {
                    if n != 0 {
                        self.last = Instant::now();
                    }
                    return Ok(n);
                }
                Err(e) => return Err(e),
            }
        }
    }
}
struct Input<R> {
    reader: R,
    data: Vec<u8>,
}
impl<R: Read> Input<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            data: Vec::new(),
        }
    }
    fn fill(&mut self) -> io::Result<bool> {
        let mut buf = [0; 8192];
        let n = self.reader.read(&mut buf)?;
        self.data.extend_from_slice(&buf[..n]);
        Ok(n != 0)
    }
    fn until(&mut self, marker: &[u8], limit: usize) -> io::Result<Vec<u8>> {
        loop {
            if let Some(at) = self.data.windows(marker.len()).position(|w| w == marker) {
                let end = at + marker.len();
                if end > limit {
                    return Err(invalid());
                }
                return Ok(self.data.drain(..end).collect());
            }
            if self.data.len() >= limit || !self.fill()? {
                return Err(invalid());
            }
        }
    }
    fn copy_exact(
        &mut self,
        mut n: u64,
        mut write: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        while n > 0 {
            if self.data.is_empty() && !self.fill()? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let take = self.data.len().min(n.min(usize::MAX as u64) as usize);
            write(&self.data[..take])?;
            self.data.drain(..take);
            n -= take as u64;
        }
        Ok(())
    }
    fn chunked(&mut self, mut write: impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
        loop {
            let line = self.until(b"\r\n", LINE_LIMIT)?;
            let text = std::str::from_utf8(&line[..line.len() - 2]).map_err(|_| invalid())?;
            let number = text.split(';').next().unwrap_or("");
            if number.is_empty() || !number.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            let n = u64::from_str_radix(number, 16).map_err(|_| invalid())?;
            write(&line)?;
            if n == 0 {
                loop {
                    let trailer = self.until(b"\r\n", LINE_LIMIT)?;
                    if trailer != b"\r\n"
                        && (!trailer.contains(&b':') || trailer[0].is_ascii_whitespace())
                    {
                        return Err(invalid());
                    }
                    write(&trailer)?;
                    if trailer == b"\r\n" {
                        return Ok(());
                    }
                }
            }
            self.copy_exact(n, &mut write)?;
            let ending = self.until(b"\r\n", 2)?;
            if ending != b"\r\n" {
                return Err(invalid());
            }
            write(&ending)?;
        }
    }
}
#[derive(Clone, Copy)]
enum Body {
    None,
    Length(u64),
    Chunked,
    Eof,
}
struct Headers {
    lines: Vec<(String, String)>,
    body: Body,
    close: bool,
}
fn headers(headers: &[httparse::Header<'_>], version: u8, response: bool) -> io::Result<Headers> {
    let mut lines = Vec::new();
    let mut length = None;
    let mut transfer = false;
    let mut close = version == 0;
    for h in headers {
        let name = h.name.to_ascii_lowercase();
        let value = std::str::from_utf8(h.value)
            .map_err(|_| invalid())?
            .trim()
            .to_string();
        if value.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
            return Err(invalid());
        }
        match name.as_str() {
            "content-length" => {
                if length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(invalid());
                }
                length = Some(value.parse::<u64>().map_err(|_| invalid())?);
            }
            "transfer-encoding" => {
                if transfer || !value.eq_ignore_ascii_case("chunked") {
                    return Err(invalid());
                }
                transfer = true;
            }
            "connection" | "proxy-connection" => {
                for token in value.split(',').map(str::trim) {
                    if token.eq_ignore_ascii_case("close") {
                        close = true;
                    }
                    if token.eq_ignore_ascii_case("keep-alive") && version == 0 {
                        close = false;
                    }
                    // 任意 Connection 扩展头可能改变转发语义，拒绝而非透传。
                    if !token.eq_ignore_ascii_case("close")
                        && !token.eq_ignore_ascii_case("keep-alive")
                    {
                        return Err(invalid());
                    }
                }
                continue;
            }
            "proxy-authorization" | "proxy-authenticate" => continue,
            "expect" => return Err(invalid()),
            _ => {}
        }
        lines.push((h.name.to_owned(), value));
    }
    if transfer && length.is_some() {
        return Err(invalid());
    }
    let body = if transfer {
        Body::Chunked
    } else if let Some(n) = length {
        Body::Length(n)
    } else if response {
        Body::Eof
    } else {
        Body::None
    };
    Ok(Headers { lines, body, close })
}
fn authority(value: &str, default_port: Option<u16>) -> io::Result<(String, u16)> {
    if value.contains('@') || value.contains('/') || value.is_empty() {
        return Err(invalid());
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(invalid)?;
        let host = &rest[..end];
        host.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
        let after = &rest[end + 1..];
        let p = if after.is_empty() {
            default_port.ok_or_else(invalid)?
        } else {
            after
                .strip_prefix(':')
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())?
        };
        (host.to_owned(), p)
    } else {
        if value.matches(':').count() > 1 {
            return Err(invalid());
        }
        match value.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), port.parse().map_err(|_| invalid())?),
            None => (value.to_owned(), default_port.ok_or_else(invalid)?),
        }
    };
    if host.is_empty() || port == 0 || host.bytes().any(|b| b <= 32 || b >= 127) {
        return Err(invalid());
    }
    Ok((host, port))
}
fn pump<R: Read>(
    input: &mut Input<R>,
    body: Body,
    mut write: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    match body {
        Body::None => Ok(()),
        Body::Length(n) => input.copy_exact(n, write),
        Body::Chunked => input.chunked(write),
        Body::Eof => loop {
            if !input.data.is_empty() {
                write(&input.data)?;
                input.data.clear();
            }
            if !input.fill()? {
                return Ok(());
            }
        },
    }
}
pub(super) fn serve(mut local: TcpStream, client: Client, state: Arc<State>) -> io::Result<()> {
    let mut response_status = Some(400);
    let result = serve_inner(&mut local, client, state, &mut response_status);
    if result.is_err() {
        let reply = match response_status {
            Some(400) => Some(
                &b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"[..],
            ),
            Some(502) => Some(
                &b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"[..],
            ),
            _ => None,
        };
        if let Some(reply) = reply {
            let _ = local.write_all(reply);
        }
    }
    result
}
fn serve_inner(
    local: &mut TcpStream,
    client: Client,
    state: Arc<State>,
    response_status: &mut Option<u16>,
) -> io::Result<()> {
    let input_stream = local.try_clone()?;
    let mut input = Input::new(LocalInput {
        stream: input_stream,
        state: state.clone(),
        last: Instant::now(),
    });
    while !state.stopped() {
        *response_status = Some(400);
        let raw = input.until(b"\r\n\r\n", HEAD_LIMIT)?;
        let mut slots = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut slots);
        if !request.parse(&raw).map_err(|_| invalid())?.is_complete() {
            return Err(invalid());
        }
        let method = request.method.ok_or_else(invalid)?.to_owned();
        let target = request.path.ok_or_else(invalid)?.to_owned();
        let version = request.version.ok_or_else(invalid)?;
        let parsed = headers(request.headers, version, false)?;
        let host_headers: Vec<_> = parsed
            .lines
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("host"))
            .collect();
        if host_headers.len() > 1 {
            return Err(invalid());
        }
        if method == "CONNECT" {
            if !matches!(parsed.body, Body::None | Body::Length(0)) {
                return Err(invalid());
            }
            let (host, port) = authority(&target, None)?;
            *response_status = Some(502);
            let conn = client.open_stream(&host, port)?;
            *response_status = None;
            local.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
            return socks::relay(local.try_clone()?, conn, input.data, state);
        }
        let rest = target.strip_prefix("http://").ok_or_else(invalid)?;
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let endpoint = &rest[..split];
        let path = if split == rest.len() {
            "/".to_owned()
        } else if rest.as_bytes()[split] == b'?' {
            format!("/{}", &rest[split..])
        } else {
            rest[split..].to_owned()
        };
        let (host, port) = authority(endpoint, Some(80))?;
        if let Some((_, value)) = host_headers.first() {
            let (header_host, header_port) = authority(value, Some(80))?;
            if !header_host.eq_ignore_ascii_case(&host) || header_port != port {
                return Err(invalid());
            }
        }
        *response_status = Some(502);
        let conn = client.open_stream(&host, port)?;
        let mut outgoing = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, endpoint);
        for (name, value) in &parsed.lines {
            if !name.eq_ignore_ascii_case("host") {
                outgoing.push_str(&format!("{}: {}\r\n", name, value));
            }
        }
        outgoing.push_str("Connection: close\r\n\r\n");
        conn.write_all(outgoing.as_bytes())?;
        *response_status = Some(400);
        let mut remote_write_failed = false;
        let result = pump(&mut input, parsed.body, |b| {
            let result = conn.write_all(b);
            if result.is_err() {
                remote_write_failed = true;
            }
            result
        });
        if remote_write_failed {
            *response_status = Some(502);
        }
        result?;
        *response_status = Some(502);
        let mut remote = Input::new(RemoteInput {
            conn: &*conn,
            state: &state,
            last: Instant::now(),
        });
        let close = loop {
            let raw = remote.until(b"\r\n\r\n", HEAD_LIMIT)?;
            let mut slots = [httparse::EMPTY_HEADER; 128];
            let mut response = httparse::Response::new(&mut slots);
            if !response.parse(&raw).map_err(|_| invalid())?.is_complete() {
                return Err(invalid());
            }
            let code = response.code.ok_or_else(invalid)?;
            let parsed_response = headers(
                response.headers,
                response.version.ok_or_else(invalid)?,
                true,
            )?;
            let body =
                if method == "HEAD" || (100..200).contains(&code) || code == 204 || code == 304 {
                    Body::None
                } else {
                    parsed_response.body
                };
            let must_close = parsed.close || matches!(body, Body::Eof) || code == 101;
            let reason = response.reason.unwrap_or("");
            let mut head = format!("HTTP/1.1 {} {}\r\n", code, reason);
            for (name, value) in &parsed_response.lines {
                head.push_str(&format!("{}: {}\r\n", name, value));
            }
            if !(100..200).contains(&code) || code == 101 {
                head.push_str(if must_close {
                    "Connection: close\r\n"
                } else {
                    "Connection: keep-alive\r\n"
                });
            }
            head.push_str("\r\n");
            *response_status = None;
            local.write_all(head.as_bytes())?;
            if (100..200).contains(&code) && code != 101 {
                *response_status = Some(502);
                continue;
            }
            pump(&mut remote, body, |b| local.write_all(b))?;
            break must_close;
        };
        conn.close();
        if close {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn 分块消息不吞后续请求() {
        let mut input = Input::new(Cursor::new(b"3\r\nabc\r\n0\r\n\r\nNEXT".to_vec()));
        let mut sent = Vec::new();
        input
            .chunked(|b| {
                sent.extend_from_slice(b);
                Ok(())
            })
            .unwrap();
        assert_eq!(sent, b"3\r\nabc\r\n0\r\n\r\n");
        assert_eq!(input.data, b"NEXT");
    }
    #[test]
    fn 拒绝冲突长度与传输编码() {
        let raw = b"POST http://example.test/ HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut slots = [httparse::EMPTY_HEADER; 8];
        let mut req = httparse::Request::new(&mut slots);
        req.parse(raw).unwrap();
        assert!(headers(req.headers, 1, false).is_err());
    }
    #[test]
    fn 解析目标地址() {
        assert_eq!(
            authority("[::1]:8080", None).unwrap(),
            ("::1".to_owned(), 8080)
        );
        assert_eq!(
            authority("example.test", Some(80)).unwrap(),
            ("example.test".to_owned(), 80)
        );
        assert!(authority("anonymous@example.invalid", Some(80)).is_err());
    }
}
