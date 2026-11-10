//! HTTP/1.1 upgrade used by Xray `httpupgrade`. After 101 the bytes are raw.

use base64::{
    alphabet,
    engine::{
        general_purpose::{GeneralPurpose, NO_PAD, STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    },
};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::mpsc;

use crate::raw_http::{
    config_error, push_field, read_prelude, valid_percent_encoding, validate_field,
    HttpPrefaceRead, CHROME_HINT, CHROME_UA,
};
use crate::ws::{
    accept_value, switch_response, switch_response_with_early_data, websocket_pair, WsRead, WsWrite,
};

const RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
const MAX_HEAD: usize = 12_288;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeError {
    Short,
    Bad,
}

pub fn normalize_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or("/");
    if path.is_empty() {
        return "/".to_string();
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

pub fn upgrade_request(host: &str, path: &str) -> Vec<u8> {
    upgrade_request_with_early_data(host, path, &[])
}

pub fn early_data_limit(path: &str) -> usize {
    path_and_early_data(path).1
}

pub struct UpgradeConfig {
    host: String,
    path: String,
    target: String,
    headers: Vec<(String, String)>,
    websocket: bool,
    early: usize,
}

impl UpgradeConfig {
    pub fn new(
        websocket: bool,
        path: &str,
        host: &str,
        default_host: &str,
        headers: Option<&str>,
    ) -> io::Result<Self> {
        let mut headers: Vec<(String, String)> = match headers {
            Some(json) => serde_json::from_str::<Option<BTreeMap<String, String>>>(json)
                .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?
                .unwrap_or_default()
                .into_iter()
                .collect(),
            None => Vec::new(),
        };
        for (name, value) in &headers {
            validate_field(name, value)?;
            if !websocket && name.eq_ignore_ascii_case("Host") {
                return Err(config_error("HTTPUpgrade headers cannot contain Host"));
            }
            if websocket
                && matches!(
                    name.to_ascii_lowercase().as_str(),
                    "connection"
                        | "upgrade"
                        | "sec-websocket-key"
                        | "sec-websocket-version"
                        | "sec-websocket-extensions"
                )
            {
                return Err(config_error("reserved WebSocket header"));
            }
        }
        let header_host = field(&headers, "host").unwrap_or_default();
        let authority = [host, header_host, default_host]
            .into_iter()
            .find(|host| !host.is_empty())
            .unwrap_or_default();
        let host = if authority.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{authority}]")
        } else {
            authority.to_owned()
        };
        if !host.is_empty() && host.parse::<http::uri::Authority>().is_err() {
            return Err(config_error("HTTP upgrade host"));
        }
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));

        let (configured, early) = path_and_early_data(path);
        let configured = if configured.starts_with('/') {
            configured
        } else {
            format!("/{configured}")
        };
        let (path, target) = if websocket {
            let configured = configured.split('#').next().unwrap_or_default();
            let (path, query) = configured.split_once('?').unwrap_or((configured, ""));
            if !valid_percent_encoding(path) {
                return Err(config_error("WebSocket path"));
            }
            let mut target = utf8_percent_encode(path, ESCAPED_PATH).to_string();
            if !query.is_empty() {
                target.push('?');
                target.push_str(query);
            }
            (path.to_owned(), target)
        } else {
            let target = utf8_percent_encode(&configured, PATH_ESCAPE).to_string();
            (configured, target)
        };
        if target.parse::<http::uri::PathAndQuery>().is_err() {
            return Err(config_error("HTTP upgrade path"));
        }
        Ok(Self {
            host,
            path,
            target,
            headers,
            websocket,
            early,
        })
    }

    pub fn websocket(&self) -> bool {
        self.websocket
    }

    /// Returns the bytes after the request, WebSocket early data, and the request head for header policies.
    pub fn accept(
        &self,
        read: &mut dyn Read,
        write: &mut dyn Write,
    ) -> io::Result<(Vec<u8>, Vec<u8>, String)> {
        let bad = || io::Error::new(ErrorKind::InvalidData, "HTTP upgrade request");
        let mut buffer = Vec::new();
        let end = read_prelude(read, &mut buffer, MAX_HEAD)?;
        let (path, host, _) = take_upgrade_request(&buffer[..end]).map_err(|_| bad())?;
        if path != self.path || (!self.host.is_empty() && !host_matches(&host, &self.host)) {
            return Err(bad());
        }
        let head = std::str::from_utf8(&buffer[..end]).map_err(|_| bad())?.to_owned();
        let mut early = Vec::new();
        if self.websocket {
            let key = websocket_key(&head).ok_or_else(bad)?;
            let token = header_value(&head, "sec-websocket-protocol").filter(|token| {
                if let Some(data) = decode_websocket_early_data(token) {
                    early = data;
                    true
                } else {
                    false
                }
            });
            write.write_all(&switch_response_with_early_data(&key, token.as_deref()))?;
        } else if let Some(key) =
            header_value(&head, "sec-websocket-key").filter(|key| !key.is_empty())
        {
            write.write_all(&switch_response(&key))?;
        } else {
            write.write_all(upgrade_response())?;
        }
        Ok((buffer.split_off(end), early, head))
    }

    fn request(&self, early: &[u8]) -> io::Result<(Vec<u8>, String)> {
        let mut headers = self.headers.clone();
        upgrade_defaults(&mut headers);
        set_field(&mut headers, "Connection", "Upgrade");
        set_field(&mut headers, "Upgrade", "websocket");
        if field(&headers, "sec-websocket-key").is_none() {
            let mut nonce = [0; 16];
            getrandom::getrandom(&mut nonce)
                .map_err(|error| io::Error::other(error.to_string()))?;
            set_field(&mut headers, "Sec-WebSocket-Key", &b64(&nonce));
        }
        if field(&headers, "sec-websocket-version").is_none() {
            set_field(&mut headers, "Sec-WebSocket-Version", "13");
        }
        if !early.is_empty() {
            set_field(
                &mut headers,
                "Sec-WebSocket-Protocol",
                &URL_SAFE_NO_PAD.encode(early),
            );
        }
        let mut wire = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", self.target, self.host);
        for (name, value) in &headers {
            push_field(&mut wire, name, value);
        }
        wire.push_str("\r\n");
        if wire.len() > MAX_HEAD {
            return Err(config_error("HTTP upgrade preface length"));
        }
        let key = field(&headers, "sec-websocket-key")
            .unwrap_or_default()
            .to_owned();
        Ok((wire.into_bytes(), key))
    }
}

const PATH_ESCAPE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b',')
    .remove(b'/')
    .remove(b':')
    .remove(b';')
    .remove(b'=')
    .remove(b'@');
const ESCAPED_PATH: &AsciiSet = &PATH_ESCAPE
    .remove(b'%')
    .remove(b'!')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*');

fn path_and_early_data(path: &str) -> (String, usize) {
    let (before_fragment, fragment) = path.split_once('#').unwrap_or((path, ""));
    let Some((base, query)) = before_fragment.split_once('?') else {
        return (path.to_owned(), 0);
    };
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    for field in query.split('&') {
        if field.contains(';') || !valid_percent_encoding(field) {
            continue;
        }
        for (name, value) in url::form_urlencoded::parse(field.as_bytes()) {
            fields
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }
    }
    let Some(value) = fields
        .get("ed")
        .and_then(|values| values.first())
        .filter(|value| !value.is_empty())
    else {
        return (path.to_owned(), 0);
    };
    let early = value.parse::<i64>().unwrap_or(0) as u32 as usize;
    fields.remove("ed");
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (name, values) in fields {
        for value in values {
            encoded.append_pair(&name, &value);
        }
    }
    let encoded = encoded.finish().replace("%7E", "~").replace('*', "%2A");
    let mut configured = base.to_owned();
    if !encoded.is_empty() {
        configured.push('?');
        configured.push_str(&encoded);
    }
    if !fragment.is_empty() {
        configured.push('#');
        configured.push_str(fragment);
    }
    (configured, early)
}

fn field<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

fn set_field(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    headers.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
    headers.push((name.to_owned(), value.to_owned()));
}

fn upgrade_defaults(headers: &mut Vec<(String, String)>) {
    let (agent, chrome, safari) = match field(headers, "user-agent") {
        None | Some("chrome") => (CHROME_UA, true, false),
        Some("edge") => (
            concat!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ",
                "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"
            ),
            true,
            false,
        ),
        Some("firefox") => (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            false,
            false,
        ),
        Some("safari") => (
            concat!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 ",
                "(KHTML, like Gecko) Version/26.0 Safari/605.1.15"
            ),
            false,
            true,
        ),
        Some("golang") => {
            set_field(headers, "User-Agent", "Go-http-client/1.1");
            return;
        }
        Some("curl") => {
            set_field(headers, "User-Agent", "curl/8.0.0");
            return;
        }
        Some(_) => return,
    };
    set_field(headers, "User-Agent", agent);
    if chrome {
        set_field(headers, "Sec-CH-UA", CHROME_HINT);
        set_field(headers, "Sec-CH-UA-Mobile", "?0");
        set_field(headers, "Sec-CH-UA-Platform", "\"Windows\"");
    }
    if !safari {
        set_field(headers, "DNT", "1");
    }
    set_field(
        headers,
        "Accept-Language",
        if chrome || safari {
            "en-US,en;q=0.9"
        } else {
            "en-US,en;q=0.5"
        },
    );
    set_field(headers, "Sec-Fetch-Mode", "websocket");
    set_field(
        headers,
        "Sec-Fetch-Dest",
        if safari { "websocket" } else { "empty" },
    );
    set_field(headers, "Sec-Fetch-Site", "same-origin");
    for (name, value) in [
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Accept", "*/*"),
    ] {
        if field(headers, name).is_none_or(str::is_empty) {
            set_field(headers, name, value);
        }
    }
}

enum ReadSide<R, W> {
    Raw(HttpPrefaceRead<R>),
    WebSocket(WsRead<R, W>),
}

pub struct UpgradeRead<R, W> {
    ready: mpsc::Receiver<ReadSide<R, W>>,
    open: Option<ReadSide<R, W>>,
    map: Option<Box<dyn FnOnce(&mut R) + Send>>,
}

enum WriteSide<W> {
    Raw(W),
    WebSocket(WsWrite<W>),
}

struct Pending<R, W> {
    read: R,
    write: W,
    config: UpgradeConfig,
    ready: mpsc::Sender<ReadSide<R, W>>,
    sent: bool,
}

pub struct UpgradeWrite<R, W> {
    pending: Option<Pending<R, W>>,
    open: Option<WriteSide<W>>,
}

pub fn upgrade_pair<R, W>(
    read: R,
    write: W,
    config: UpgradeConfig,
) -> (UpgradeRead<R, W>, UpgradeWrite<R, W>) {
    let (tx, rx) = mpsc::channel();
    (
        UpgradeRead {
            ready: rx,
            open: None,
            map: None,
        },
        UpgradeWrite {
            pending: Some(Pending {
                read,
                write,
                config,
                ready: tx,
                sent: false,
            }),
            open: None,
        },
    )
}

impl<R, W: Write> UpgradeWrite<R, W> {
    /// Sends a raw HTTPUpgrade request now, as Xray's dialer does before any payload exists.
    /// Xray's server drops payload bytes that arrive in the same read as the request head, so
    /// writing both back to back on the first payload loses data against it. A WebSocket
    /// request waits for the first write because its early data rides in a header.
    pub fn start(&mut self) -> io::Result<()> {
        if let Some(pending) = self.pending.as_mut().filter(|pending| !pending.config.websocket && !pending.sent) {
            let (request, _) = pending.config.request(&[])?;
            pending.write.write_all(&request)?;
            pending.write.flush()?;
            pending.sent = true;
        }
        Ok(())
    }
}

impl<R, W> UpgradeRead<R, W> {
    pub fn map_io(&mut self, map: impl FnOnce(&mut R) + Send + 'static) {
        match &mut self.open {
            Some(ReadSide::Raw(read)) => map(read.inner_mut()),
            Some(ReadSide::WebSocket(read)) => map(read.inner_mut()),
            None => self.map = Some(Box::new(map)),
        }
    }
}

impl<R: Read, W: Write> Read for UpgradeRead<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.open.is_none() {
            let mut side = self
                .ready
                .recv()
                .map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;
            if let Some(map) = self.map.take() {
                match &mut side {
                    ReadSide::Raw(read) => map(read.inner_mut()),
                    ReadSide::WebSocket(read) => map(read.inner_mut()),
                }
            }
            self.open = Some(side);
        }
        match self.open.as_mut().expect("HTTP upgrade reader") {
            ReadSide::Raw(read) => read.read(buf),
            ReadSide::WebSocket(read) => read.read(buf),
        }
    }
}

impl<R, W> UpgradeWrite<R, W> {
    pub fn map_io(&mut self, read: impl FnOnce(&mut R), write: impl FnOnce(&mut W)) {
        match &mut self.open {
            Some(WriteSide::Raw(inner)) => write(inner),
            Some(WriteSide::WebSocket(inner)) => inner.map_io(write),
            None => {
                if let Some(pending) = &mut self.pending {
                    read(&mut pending.read);
                    write(&mut pending.write);
                }
            }
        }
    }
}

impl<R: Read, W: Write> Write for UpgradeWrite<R, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.open.is_none() {
            let Pending {
                mut read,
                mut write,
                config,
                ready,
                sent,
            } = self
                .pending
                .take()
                .ok_or_else(|| io::Error::from(ErrorKind::BrokenPipe))?;
            let websocket_early = config.websocket && buf.len() <= config.early;
            let raw_early = !config.websocket && config.early != 0;
            let mut key = String::new();
            if !sent {
                let request;
                (request, key) = config.request(if websocket_early { buf } else { &[] })?;
                write.write_all(&request)?;
            }
            if raw_early {
                // Xray's HTTPUpgrade ed sends the first raw write before reading 101.
                write.write_all(buf)?;
            }
            let mut response = Vec::new();
            let end = read_prelude(&mut read, &mut response, MAX_HEAD)?;
            take_upgrade_response(&response[..end]).map_err(|_| invalid_response())?;
            let prelude = response.split_off(end);
            let (read, write) = if config.websocket {
                let response = std::str::from_utf8(&response).map_err(|_| invalid_response())?;
                if header_value(response, "sec-websocket-accept").as_deref()
                    != Some(accept_value(&key).as_str())
                {
                    return Err(invalid_response());
                }
                let (read, write) = websocket_pair(read, write, false, true, &prelude)
                    .map_err(|_| invalid_response())?;
                (ReadSide::WebSocket(read), WriteSide::WebSocket(write))
            } else {
                (
                    ReadSide::Raw(HttpPrefaceRead::after_header(read, prelude)),
                    WriteSide::Raw(write),
                )
            };
            ready
                .send(read)
                .map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;
            self.open = Some(write);
            if websocket_early || raw_early {
                return Ok(buf.len());
            }
        }
        match self.open.as_mut().expect("HTTP upgrade writer") {
            WriteSide::Raw(write) => write.write(buf),
            WriteSide::WebSocket(write) => write.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.open {
            Some(WriteSide::Raw(write)) => write.flush(),
            Some(WriteSide::WebSocket(write)) => write.flush(),
            None => Ok(()),
        }
    }
}

fn invalid_response() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "HTTP upgrade response")
}

pub fn upgrade_request_with_early_data(host: &str, path: &str, early: &[u8]) -> Vec<u8> {
    UpgradeConfig::new(true, path, host, "", None)
        .and_then(|config| config.request(early))
        .map(|(wire, _)| wire)
        .unwrap_or_default()
}

pub fn decode_websocket_early_data(value: &str) -> Option<Vec<u8>> {
    const RAW_URL: GeneralPurpose = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        NO_PAD.with_decode_allow_trailing_bits(true),
    );
    let normalized = value.replace('+', "-").replace('/', "_").replace('=', "");
    let bytes = RAW_URL.decode(normalized).ok()?;
    (!bytes.is_empty()).then_some(bytes)
}

pub fn upgrade_response() -> &'static [u8] {
    RESPONSE
}

/// Path, Host, and how many leading bytes the request used.
pub fn take_upgrade_request(buf: &[u8]) -> Result<(String, String, usize), UpgradeError> {
    let end = header_end(buf)?;
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| UpgradeError::Bad)?;
    let mut lines = text.split("\r\n");
    let start = lines.next().ok_or(UpgradeError::Bad)?;
    let mut parts = start.split(' ');
    if parts.next() != Some("GET") {
        return Err(UpgradeError::Bad);
    }
    let target = parts.next().ok_or(UpgradeError::Bad)?;
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) || parts.next().is_some() {
        return Err(UpgradeError::Bad);
    }
    let target: http::Uri = target.parse().map_err(|_| UpgradeError::Bad)?;
    if !valid_percent_encoding(target.path()) {
        return Err(UpgradeError::Bad);
    }
    let path = percent_decode_str(target.path())
        .decode_utf8()
        .map_err(|_| UpgradeError::Bad)?
        .into_owned();
    let mut host = String::new();
    let mut connection = String::new();
    let mut upgrade = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(UpgradeError::Bad);
        };
        validate_field(name, value).map_err(|_| UpgradeError::Bad)?;
        match name.trim().to_ascii_lowercase().as_str() {
            "host" => host = value.trim().to_string(),
            "connection" => connection = value.trim().to_ascii_lowercase(),
            "upgrade" => upgrade = value.trim().to_ascii_lowercase(),
            _ => {}
        }
    }
    if !connection.split(',').any(|token| token.trim() == "upgrade")
        || upgrade != "websocket"
        || host.is_empty()
    {
        return Err(UpgradeError::Bad);
    }
    Ok((path, host, end))
}

fn websocket_key(head: &str) -> Option<String> {
    let version = header_value(head, "sec-websocket-version")?;
    if !version.split(',').any(|value| value.trim() == "13") {
        return None;
    }
    let key = header_value(head, "sec-websocket-key")?;
    if STANDARD.decode(&key).ok()?.len() != 16 {
        return None;
    }
    Some(key)
}

pub fn take_upgrade_response(buf: &[u8]) -> Result<usize, UpgradeError> {
    let end = header_end(buf)?;
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| UpgradeError::Bad)?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or(UpgradeError::Bad)?;
    if status.split_whitespace().take(2).collect::<Vec<_>>() != ["HTTP/1.1", "101"] {
        return Err(UpgradeError::Bad);
    }
    let mut connection = String::new();
    let mut upgrade = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(UpgradeError::Bad);
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "connection" => connection = value.trim().to_ascii_lowercase(),
            "upgrade" => upgrade = value.trim().to_ascii_lowercase(),
            _ => {}
        }
    }
    if !connection.split(',').any(|token| token.trim() == "upgrade") || upgrade != "websocket" {
        return Err(UpgradeError::Bad);
    }
    Ok(end)
}

pub fn host_matches(got: &str, want: &str) -> bool {
    fn hostname(host: &str) -> &str {
        if let Some(rest) = host.strip_prefix('[') {
            return rest.split(']').next().unwrap_or(rest);
        }
        if host.matches(':').count() == 1 {
            return host.split(':').next().unwrap_or(host);
        }
        host
    }
    hostname(got).eq_ignore_ascii_case(hostname(want))
}

fn header_end(buf: &[u8]) -> Result<usize, UpgradeError> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or(UpgradeError::Short)
}

pub fn header_value(head: &str, name: &str) -> Option<String> {
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (found, value) = line.split_once(':')?;
        if found.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim().to_string());
        }
    }
    None
}

pub(crate) fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::{encode_frame, WsIo};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Capture(Rc<RefCell<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Peer {
        request: Rc<RefCell<Vec<u8>>>,
        response: Option<io::Cursor<Vec<u8>>>,
        websocket: bool,
        early: bool,
    }

    impl Read for Peer {
        fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
            let response = self.response.get_or_insert_with(|| {
                let sent = self.request.borrow();
                let (path, host, end) = take_upgrade_request(&sent).unwrap();
                assert_eq!(host, "cover.example");
                let head = std::str::from_utf8(&sent[..end]).unwrap();
                assert_eq!(header_value(head, "x-custom").as_deref(), Some("fixture"));
                assert_eq!(
                    header_value(head, "user-agent").as_deref(),
                    Some("fixture-agent")
                );
                let key = header_value(head, "sec-websocket-key").unwrap();
                let response = if self.websocket {
                    assert_eq!(path, "/carrier");
                    assert!(head.starts_with("GET /carrier?q=1 HTTP/1.1\r\n"));
                    assert!(sent[end..].is_empty());
                    let token = header_value(head, "sec-websocket-protocol");
                    assert_eq!(
                        token.as_deref().and_then(decode_websocket_early_data),
                        self.early.then(|| b"first".to_vec()),
                    );
                    let mut response = switch_response_with_early_data(&key, token.as_deref());
                    response.extend_from_slice(&encode_frame(2, b"reply", false));
                    response
                } else {
                    assert_eq!(path, "/carrier?q=1");
                    assert!(head.starts_with("GET /carrier%3Fq=1 HTTP/1.1\r\n"));
                    assert_eq!(key, "custom-upgrade-key");
                    assert_eq!(
                        &sent[end..],
                        if self.early { b"first".as_slice() } else { b"" }
                    );
                    let mut response = switch_response(&key);
                    response.extend_from_slice(b"reply");
                    response
                };
                io::Cursor::new(response)
            });
            response.read(data)
        }
    }

    #[test]
    fn first_write_uses_configured_early_data_and_custom_headers() {
        for (websocket, ed, early) in [
            (true, 2048, true),
            (true, 2, false),
            (false, 1, true),
            (false, 0, false),
        ] {
            let headers = if websocket {
                r#"{"Host":"cover.example","x-custom":"fixture","User-Agent":"fixture-agent"}"#
            } else {
                r#"{"x-custom":"fixture","User-Agent":"fixture-agent","Sec-WebSocket-Key":"custom-upgrade-key"}"#
            };
            let config = UpgradeConfig::new(
                websocket,
                &format!("/carrier?ed={ed}&q=1"),
                "",
                if websocket {
                    "unused.example"
                } else {
                    "cover.example"
                },
                Some(headers),
            )
            .unwrap();
            let wire = Rc::new(RefCell::new(Vec::new()));
            let peer = Peer {
                request: wire.clone(),
                response: None,
                websocket,
                early,
            };
            let (mut read, mut write) = upgrade_pair(peer, Capture(wire.clone()), config);
            assert!(wire.borrow().is_empty());
            write.write_all(b"first").unwrap();
            write.write_all(b"tail").unwrap();
            let mut reply = [0; 5];
            read.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"reply");

            let wire = wire.borrow();
            let (_, _, end) = take_upgrade_request(&wire).unwrap();
            let expected = if websocket && early {
                b"tail".as_slice()
            } else {
                b"firsttail"
            };
            if websocket {
                let mut ws =
                    WsIo::new(io::Cursor::new(wire[end..].to_vec()), true, false, &[]).unwrap();
                let mut frames = vec![0; expected.len()];
                ws.read_exact(&mut frames).unwrap();
                assert_eq!(frames, expected);
            } else {
                assert_eq!(&wire[end..], expected);
            }
        }
    }

    #[test]
    fn raw_start_sends_the_request_before_any_payload() {
        for (websocket, ed) in [(false, 2048), (false, 0), (true, 2048)] {
            let headers = r#"{"x-custom":"fixture","User-Agent":"fixture-agent","Sec-WebSocket-Key":"custom-upgrade-key"}"#;
            let config = UpgradeConfig::new(websocket, &format!("/carrier?ed={ed}&q=1"), "", "cover.example", Some(headers).filter(|_| !websocket)).unwrap();
            let wire = Rc::new(RefCell::new(Vec::new()));
            let peer = Peer { request: wire.clone(), response: None, websocket, early: ed != 0 };
            let (mut read, mut write) = upgrade_pair(peer, Capture(wire.clone()), config);
            write.start().unwrap();
            let sent = wire.borrow().len();
            if websocket {
                assert_eq!(sent, 0, "a WebSocket request waits for its early data");
                continue;
            }
            let (_, _, end) = take_upgrade_request(&wire.borrow()).unwrap();
            assert_eq!(end, sent, "start writes exactly the request head");
            write.write_all(b"first").unwrap();
            let mut reply = [0; 5];
            read.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"reply");
            assert_eq!(&wire.borrow()[end..], b"first", "ed={ed}: payload follows a single request");
        }
    }

    #[test]
    fn upgrade_settings_reject_bad_fields_before_dial() {
        for (websocket, headers) in [
            (false, r#"{"hOsT":"bad.example"}"#),
            (true, r#"{"Sec-WebSocket-Key":"forged"}"#),
            (true, r#"{"Header\n":""}"#),
            (false, r#"{"x-test":"wrong\r\nInjected: x"}"#),
        ] {
            assert!(UpgradeConfig::new(websocket, "/", "example.org", "", Some(headers)).is_err());
        }
    }

    #[test]
    fn request_roundtrip_ignores_the_query() {
        let bytes = upgrade_request("Example.com", "/vless?ed=2560");
        let (path, host, used) = take_upgrade_request(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(path, "/vless");
        assert_eq!(host, "Example.com");
        assert!(host_matches(&host, "example.com"));
        let response = upgrade_response();
        assert_eq!(take_upgrade_response(response).unwrap(), response.len());
    }

    #[test]
    fn websocket_early_data_matches_xray() {
        let request = upgrade_request_with_early_data("localhost", "/vless?ed=2048", &[0xfb, 0xff]);
        let head = std::str::from_utf8(&request).unwrap();
        let token = header_value(head, "sec-websocket-protocol").unwrap();
        assert_eq!(token, "-_8");
        assert_eq!(decode_websocket_early_data(&token), Some(vec![0xfb, 0xff]));
        assert_eq!(decode_websocket_early_data("+/8="), Some(vec![0xfb, 0xff]));
        assert_eq!(decode_websocket_early_data("proto1, proto2"), None);
        assert_eq!(early_data_limit("/vless?other=1&%65d=2048#ignored"), 2048);
        assert_eq!(early_data_limit("/vless?ed=+2048"), 0);
    }

    #[test]
    fn httpupgrade_leaves_coalesced_vless_bytes_after_headers() {
        let payload = [0, 0, 255, 0, b'\r', b'\n', b'\r', b'\n'];
        let mut request = upgrade_request("localhost", "/vless");
        let mut response = upgrade_response().to_vec();
        let request_end = request.len();
        let response_end = response.len();
        request.extend_from_slice(&payload);
        response.extend_from_slice(&payload);
        for len in 0..request_end {
            assert_eq!(
                take_upgrade_request(&request[..len]),
                Err(UpgradeError::Short)
            );
        }
        for len in 0..response_end {
            assert_eq!(
                take_upgrade_response(&response[..len]),
                Err(UpgradeError::Short)
            );
        }
        assert_eq!(
            &request[take_upgrade_request(&request).unwrap().2..],
            &payload
        );
        assert_eq!(
            &response[take_upgrade_response(&response).unwrap()..],
            &payload
        );
    }
}
