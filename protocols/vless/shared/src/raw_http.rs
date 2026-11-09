//! One HTTP camouflage preface per direction on Xray RAW connections.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::time::SystemTime;

use percent_encoding::percent_decode_str;
use serde::Deserialize;

const MAX_HEAD: usize = 8192;
pub(crate) const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";
pub(crate) const CHROME_HINT: &str =
    "\"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\", \"Not A Brand\";v=\"99\"";

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Config {
    None,
    Http {
        #[serde(default)]
        request: Option<Request>,
        #[serde(default)]
        response: Option<Response>,
    },
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Request {
    version: String,
    method: String,
    path: Option<StringList>,
    headers: Option<BTreeMap<String, StringList>>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Response {
    version: String,
    status: String,
    reason: String,
    headers: Option<BTreeMap<String, StringList>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringList {
    Text(String),
    List(Vec<String>),
}

impl StringList {
    fn into_values(self) -> Vec<String> {
        match self {
            Self::Text(text) => text.split(',').map(str::to_owned).collect(),
            Self::List(values) => values,
        }
    }
}

type Fields = Vec<(String, Vec<String>)>;

pub struct RawHttpConfig {
    request_method: String,
    request_version: String,
    request_paths: Vec<String>,
    request_headers: Fields,
    response_version: String,
    response_status: String,
    response_reason: String,
    response_headers: Fields,
}

impl RawHttpConfig {
    pub fn parse(text: Option<&str>) -> io::Result<Option<Self>> {
        let Some(text) = text.filter(|text| *text != "none") else {
            return Ok(None);
        };
        let Config::Http { request, response } = serde_json::from_str(text)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?
        else {
            return Ok(None);
        };
        let request = request.unwrap_or_default();
        let response = response.unwrap_or_default();
        let request_version = default(request.version, "1.1");
        let response_version = default(response.version, "1.1");
        if !http_version(&request_version) || !http_version(&response_version) {
            return Err(config_error("RAW HTTP version"));
        }
        let request_method = default(request.method, "GET");
        http::Method::from_bytes(request_method.as_bytes())
            .map_err(|_| config_error("RAW HTTP method"))?;
        let mut request_paths = request
            .path
            .map(StringList::into_values)
            .unwrap_or_default();
        if request_paths.is_empty() {
            request_paths.push("/".into());
        }
        for path in &request_paths {
            request_path(path).ok_or_else(|| config_error("RAW HTTP request target"))?;
        }
        let response_status = default(response.status, "200");
        if response_status.len() != 3 || !response_status.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(config_error("RAW HTTP response status"));
        }
        let response_reason = default(response.reason, "OK");
        http::HeaderValue::from_str(&response_reason)
            .map_err(|_| config_error("RAW HTTP response reason"))?;
        Ok(Some(Self {
            request_method,
            request_version,
            request_paths,
            request_headers: fields(request.headers, DEFAULT_REQUEST)?,
            response_version,
            response_status,
            response_reason,
            response_headers: fields(response.headers, DEFAULT_RESPONSE)?,
        }))
    }

    pub fn connect<R: Read, W: Write>(
        &self,
        read: R,
        mut write: W,
    ) -> io::Result<(HttpPrefaceRead<R>, W)> {
        let path = choose(&self.request_paths)?;
        let start = format!(
            "{} {path} HTTP/{}",
            self.request_method, self.request_version
        );
        write.write_all(&head(start, &self.request_headers, false)?)?;
        Ok((
            HttpPrefaceRead {
                inner: read,
                buffer: Vec::new(),
                offset: 0,
                ready: false,
            },
            write,
        ))
    }

    pub fn accept<R: Read, W: Write>(
        &self,
        mut read: R,
        mut write: W,
    ) -> io::Result<(HttpPrefaceRead<R>, RawHttpWrite<W>)> {
        let mut buffer = Vec::new();
        let parsed = read_prelude(&mut read, &mut buffer, MAX_HEAD).and_then(|end| {
            let path = parse_request(&buffer[..end])?;
            if self.request_paths.contains(&path) {
                Ok(end)
            } else {
                Err(io::Error::new(ErrorKind::NotFound, "RAW HTTP request path"))
            }
        });
        let end = match parsed {
            Ok(end) => end,
            Err(error) => {
                let _ = write_error(&mut write, error.kind() == ErrorKind::NotFound);
                return Err(error);
            }
        };
        let start = format!(
            "HTTP/{} {} {}",
            self.response_version, self.response_status, self.response_reason,
        );
        let response = head(start, &self.response_headers, true)?;
        Ok((
            HttpPrefaceRead::after_header(read, buffer.split_off(end)),
            RawHttpWrite {
                inner: write,
                response,
                written: 0,
            },
        ))
    }
}

pub struct HttpPrefaceRead<R> {
    inner: R,
    buffer: Vec<u8>,
    offset: usize,
    ready: bool,
}

impl<R> HttpPrefaceRead<R> {
    pub fn after_header(inner: R, payload: Vec<u8>) -> Self {
        Self {
            inner,
            buffer: payload,
            offset: 0,
            ready: true,
        }
    }

    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> Read for HttpPrefaceRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.ready {
            self.offset = read_prelude(&mut self.inner, &mut self.buffer, MAX_HEAD)?;
            self.ready = true;
        }
        let n = (self.buffer.len() - self.offset).min(buf.len());
        if n == 0 {
            return self.inner.read(buf);
        }
        let end = self.offset + n;
        buf[..n].copy_from_slice(&self.buffer[self.offset..end]);
        self.offset = end;
        if self.offset == self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        }
        Ok(n)
    }
}

pub struct RawHttpWrite<W: Write> {
    inner: W,
    response: Vec<u8>,
    written: usize,
}

impl<W: Write> RawHttpWrite<W> {
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

impl<W: Write> Write for RawHttpWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.written < self.response.len() {
            match self.inner.write(&self.response[self.written..]) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(n) => self.written += n,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Drop for RawHttpWrite<W> {
    fn drop(&mut self) {
        if self.written == 0 {
            let _ = write_error(&mut self.inner, false);
        }
    }
}

pub(crate) fn read_prelude(
    read: &mut dyn Read,
    bytes: &mut Vec<u8>,
    limit: usize,
) -> io::Result<usize> {
    let mut scan = 0;
    let mut scratch = [0u8; 1024];
    loop {
        if let Some(end) = bytes[scan..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            let end = scan + end + 4;
            if end <= limit {
                return Ok(end);
            }
        }
        if bytes.len() >= limit {
            return Err(io::Error::new(ErrorKind::FileTooLarge, "HTTP/1 preface"));
        }
        scan = bytes.len().saturating_sub(3);
        match read.read(&mut scratch) {
            Ok(0) => return Err(io::Error::new(ErrorKind::UnexpectedEof, "HTTP/1 preface")),
            Ok(n) => bytes.extend_from_slice(&scratch[..n]),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn parse_request(head: &[u8]) -> io::Result<String> {
    let bad = || io::Error::new(ErrorKind::InvalidData, "RAW HTTP request");
    let mut lines = std::str::from_utf8(head).map_err(|_| bad())?.split("\r\n");
    let mut parts = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    if http::Method::from_bytes(method.as_bytes()).is_err()
        || !version.strip_prefix("HTTP/").is_some_and(http_version)
    {
        return Err(bad());
    }
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        validate_field(name, value.trim_matches([' ', '\t'])).map_err(|_| bad())?;
    }
    request_path(target).ok_or_else(bad)
}

fn request_path(target: &str) -> Option<String> {
    if target.contains('#')
        || target.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
        || !valid_percent_encoding(target)
    {
        return None;
    }
    let uri;
    let path = if target.starts_with('/') {
        target.split('?').next()?
    } else {
        uri = target.parse::<http::Uri>().ok()?;
        uri.path()
    };
    if path.is_empty() {
        return None;
    }
    percent_decode_str(path)
        .decode_utf8()
        .ok()
        .map(|value| value.into_owned())
}

pub(crate) fn valid_percent_encoding(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.iter().enumerate().any(|(index, &byte)| {
        byte == b'%'
            && !bytes
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    })
}

pub(crate) fn validate_field(name: &str, value: &str) -> io::Result<()> {
    http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| config_error("HTTP header name"))?;
    http::HeaderValue::from_str(value).map_err(|_| config_error("HTTP header value"))?;
    Ok(())
}

pub(crate) fn config_error(label: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, label)
}

fn http_version(version: &str) -> bool {
    matches!(version.as_bytes(), [b'0'..=b'9', b'.', b'0'..=b'9'])
}

fn default(value: String, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}

fn fields(
    input: Option<BTreeMap<String, StringList>>,
    defaults: &[(&str, &[&str])],
) -> io::Result<Fields> {
    let fields = if let Some(input) = input.filter(|input| !input.is_empty()) {
        input
            .into_iter()
            .map(|(name, values)| (name, values.into_values()))
            .collect::<Fields>()
    } else {
        defaults
            .iter()
            .map(|(name, values)| {
                (
                    name.to_string(),
                    values.iter().map(|value| value.to_string()).collect(),
                )
            })
            .collect()
    };
    for (name, values) in &fields {
        validate_field(name, "")?;
        for value in values {
            validate_field(name, value)?;
        }
    }
    Ok(fields)
}

fn choose(values: &[String]) -> io::Result<&str> {
    match values {
        [] => Ok(""),
        [value] => Ok(value),
        values => {
            let mut random = [0; 8];
            getrandom::getrandom(&mut random)
                .map_err(|error| io::Error::other(error.to_string()))?;
            Ok(&values[(u64::from_ne_bytes(random) % values.len() as u64) as usize])
        }
    }
}

fn head(mut first_line: String, fields: &Fields, date: bool) -> io::Result<Vec<u8>> {
    first_line.push_str("\r\n");
    for (name, values) in fields {
        push_field(&mut first_line, name, choose(values)?);
    }
    if date
        && !fields
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("date"))
    {
        push_field(
            &mut first_line,
            "Date",
            &httpdate::fmt_http_date(SystemTime::now()),
        );
    }
    first_line.push_str("\r\n");
    if first_line.len() > MAX_HEAD {
        return Err(config_error("RAW HTTP preface length"));
    }
    Ok(first_line.into_bytes())
}

pub(crate) fn push_field(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

fn write_error(write: &mut dyn Write, path_mismatch: bool) -> io::Result<()> {
    let status = if path_mismatch {
        "404 Not Found"
    } else {
        "400 Bad Request"
    };
    let date = httpdate::fmt_http_date(SystemTime::now());
    write.write_all(format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nCache-Control: private\r\nContent-Length: 0\r\nDate: {date}\r\n\r\n",
    ).as_bytes())
}

const DEFAULT_REQUEST: &[(&str, &[&str])] = &[
    ("Host", &["www.baidu.com", "www.bing.com"]),
    ("User-Agent", &[CHROME_UA]),
    ("Sec-CH-UA", &[CHROME_HINT]),
    ("Sec-CH-UA-Mobile", &["?0"]),
    ("Sec-CH-UA-Platform", &["Windows"]),
    ("Sec-Fetch-Mode", &["no-cors", "cors", "same-origin"]),
    ("Sec-Fetch-Dest", &["empty"]),
    ("Sec-Fetch-Site", &["none"]),
    ("Sec-Fetch-User", &["?1"]),
    ("Accept-Encoding", &["gzip, deflate"]),
    ("Connection", &["keep-alive"]),
    ("Pragma", &["no-cache"]),
];

const DEFAULT_RESPONSE: &[(&str, &[&str])] = &[
    ("Content-Type", &["application/octet-stream", "video/mpeg"]),
    ("Transfer-Encoding", &["chunked"]),
    ("Connection", &["keep-alive"]),
    ("Pragma", &["no-cache"]),
    ("Cache-Control", &["private", "no-cache"]),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_camouflage_is_one_prefix_in_each_direction() {
        let config = RawHttpConfig::parse(Some(r#"{
            "type":"http",
            "request":{"version":"1.0","method":"PUT","path":"/one","headers":{"Host":["cover.example"],"X-Test":[]}},
            "response":{"status":"404","reason":"Cover","headers":{"Transfer-Encoding":["chunked"]}}
        }"#)).unwrap().unwrap();
        let mut response = Vec::new();
        let request = b"GET /one?cache=1 HTTP/1.1\r\nHost: another.example\r\n\r\n\0\x01data";
        {
            let (mut read, mut write) = config.accept(&request[..], &mut response).unwrap();
            let mut payload = Vec::new();
            read.read_to_end(&mut payload).unwrap();
            assert_eq!(payload, b"\0\x01data");
            write.write_all(b"\0\0reply").unwrap();
            write.write_all(b"-tail").unwrap();
        }
        assert!(response.starts_with(b"HTTP/1.1 404 Cover\r\nTransfer-Encoding: chunked\r\nDate: "));
        let (mut read, wire) = config.connect(response.as_slice(), Vec::new()).unwrap();
        assert_eq!(
            wire,
            b"PUT /one HTTP/1.0\r\nHost: cover.example\r\nX-Test: \r\n\r\n"
        );
        let mut payload = Vec::new();
        read.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, b"\0\0reply-tail");
    }

    #[test]
    fn rejects_illegal_fields_and_sends_xray_path_mismatch_status() {
        for invalid in [
            r#"{"type":"other"}"#,
            r#"{"type":"http","request":{"headers":{"Bad:Field":"x"}}}"#,
            r#"{"type":"http","request":{"headers":{"X-Test":"bad\r\nInjected: field"}}}"#,
            r#"{"type":"http","request":{"method":"GET\r\nx"}}"#,
            r#"{"type":"http","response":{"status":"2 0"}}"#,
        ] {
            assert_eq!(
                RawHttpConfig::parse(Some(invalid)).err().unwrap().kind(),
                ErrorKind::InvalidInput
            );
        }
        let config = RawHttpConfig::parse(Some(r#"{"type":"http"}"#))
            .unwrap()
            .unwrap();
        let mut response = Vec::new();
        let error = config
            .accept(
                &b"GET /bad HTTP/1.1\r\nHost: localhost\r\n\r\n"[..],
                &mut response,
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }
}
