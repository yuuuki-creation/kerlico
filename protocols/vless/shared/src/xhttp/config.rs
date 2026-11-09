use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Write};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::Value;

use super::{invalid, push_header};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XhttpMode {
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XhttpRequestKind<S = String> {
    Download { session: S },
    StreamOne,
    StreamUp { session: S },
    PacketUp { session: S, seq: u64 },
    Preflight,
}

pub struct XhttpDownload {
    pub address: String,
    pub port: u16,
    pub settings: Vec<(String, String)>,
}

pub struct XhttpRequest<'a> {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: &'a [u8],
    streaming: bool,
    packet: bool,
}

impl XhttpRequest<'_> {
    pub fn header_pairs(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .filter(|(name, _)| {
                !matches!(
                    name.as_str(),
                    "connection"
                        | "keep-alive"
                        | "proxy-connection"
                        | "upgrade"
                        | "te"
                        | "transfer-encoding"
                )
            })
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    pub fn write_h1(&self, socket: &mut dyn Write, authority: &str) -> io::Result<()> {
        ::http::HeaderValue::from_str(authority).map_err(|_| invalid("XHTTP Host"))?;
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {authority}\r\n",
            self.method, self.target
        );
        for (name, value) in &self.headers {
            if name == "content-length"
                || name == "transfer-encoding"
                || (!self.packet && name == "connection")
            {
                continue;
            }
            push_header(&mut head, name, value);
        }
        // Go's HTTP/1 server can drain an open request body before writing a response
        // on a reusable connection. Xray also disables reuse for streaming requests.
        if !self.packet {
            head.push_str("Connection: close\r\n");
        }
        if self.streaming {
            head.push_str("Transfer-Encoding: chunked\r\n");
        } else if self.packet {
            push_header(&mut head, "Content-Length", &self.body.len().to_string());
        }
        head.push_str("\r\n");
        socket.write_all(head.as_bytes())?;
        socket.write_all(self.body)
    }
}

#[derive(Clone, Debug)]
pub struct XhttpConfig {
    host: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    mode: Option<XhttpMode>,
    method: String,
    session: MetaField,
    sequence: MetaField,
    session_table: String,
    session_length: Range,
    padding: Padding,
    uplink_data: UplinkData,
    uplink_key: String,
    uplink_chunk: Range,
    post_bytes: Range,
    post_interval: Range,
    buffered_posts: usize,
    stream_up_interval: Range,
    max_header_bytes: usize,
    no_grpc: bool,
    no_sse: bool,
    download: Option<Value>,
    xmux: crate::xmux::XmuxConfig,
}

impl XhttpConfig {
    pub fn from_settings<'a>(get: impl Fn(&str) -> Option<&'a str>) -> io::Result<Self> {
        let extra = get("extra")
            .map(serde_json::from_str::<Option<BTreeMap<String, Value>>>)
            .transpose()
            .map_err(|_| setting_error("extra"))?
            .flatten();
        let field = |key: &str| {
            if let Some(extra) = extra
                .as_ref()
                .filter(|_| !matches!(key, "host" | "path" | "mode"))
            {
                match extra.get(key) {
                    Some(Value::String(text)) => text.clone(),
                    Some(value) if !value.is_null() => value.to_string(),
                    _ => String::new(),
                }
            } else {
                get(key).unwrap_or_default().to_owned()
            }
        };
        let mode = match field("mode").as_str() {
            "" | "auto" => None,
            "packet-up" => Some(XhttpMode::PacketUp),
            "stream-up" => Some(XhttpMode::StreamUp),
            "stream-one" => Some(XhttpMode::StreamOne),
            _ => return Err(setting_error("mode")),
        };
        let method = nonempty(field("uplinkHTTPMethod"), "POST").to_ascii_uppercase();
        if ::http::Method::from_bytes(method.as_bytes()).is_err()
            || (method == "GET" && mode != Some(XhttpMode::PacketUp))
        {
            return Err(setting_error("uplinkHTTPMethod"));
        }
        let session = MetaField::parse(
            &field("sessionIDPlacement"),
            field("sessionIDKey"),
            "X-Session",
            "x_session",
        )?;
        let sequence = MetaField::parse(&field("seqPlacement"), field("seqKey"), "X-Seq", "x_seq")?;
        let path_and_query = field("path");
        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((&path_and_query, ""));
        let mut path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        if (session.placement == MetaPlacement::Path || sequence.placement == MetaPlacement::Path)
            && !path.ends_with('/')
        {
            path.push('/');
        }

        let session_table = field("sessionIDTable");
        let session_table = predefined_table(&session_table)
            .unwrap_or(&session_table)
            .to_owned();
        let session_length = Range::parse(&field("sessionIDLength"), "sessionIDLength")?;
        if !session_table.is_empty()
            && (!session_table.is_ascii()
                || session_length.min <= 0
                || !session_length.enough_ids(session_table.len()))
        {
            return Err(setting_error("sessionIDTable or sessionIDLength"));
        }
        let padding = Padding::parse(&field)?;
        let uplink_data = match field("uplinkDataPlacement").as_str() {
            "" | "auto" => UplinkData::Auto,
            "body" => UplinkData::Body,
            "header" if mode == Some(XhttpMode::PacketUp) => UplinkData::Header,
            "cookie" if mode == Some(XhttpMode::PacketUp) => UplinkData::Cookie,
            _ => return Err(setting_error("uplinkDataPlacement")),
        };
        let uplink_key = nonempty(
            field("uplinkDataKey"),
            if uplink_data == UplinkData::Cookie {
                "x_data"
            } else {
                "X-Data"
            },
        );
        if matches!(uplink_data, UplinkData::Header | UplinkData::Cookie) {
            check_name(&uplink_key, "uplinkDataKey")?;
        }
        let post_bytes = Range::parse(&field("scMaxEachPostBytes"), "scMaxEachPostBytes")?
            .default_to(1_000_000, 1_000_000);
        if post_bytes.min <= 0 {
            return Err(setting_error("scMaxEachPostBytes"));
        }
        let uplink_chunk = Range::parse(&field("uplinkChunkSize"), "uplinkChunkSize")?;
        let uplink_chunk = if uplink_chunk.max == 0 {
            match uplink_data {
                UplinkData::Header => Range {
                    min: 3000,
                    max: 4000,
                },
                UplinkData::Cookie => Range {
                    min: 2048,
                    max: 3072,
                },
                _ => post_bytes,
            }
        } else {
            Range {
                min: uplink_chunk.min.max(64),
                max: uplink_chunk.max.max(64),
            }
        };
        let post_interval = Range::parse(&field("scMinPostsIntervalMs"), "scMinPostsIntervalMs")?
            .default_to(30, 30);
        let stream_up_interval =
            Range::parse(&field("scStreamUpServerSecs"), "scStreamUpServerSecs")?
                .default_to(20, 80);
        let max_header_bytes =
            parse_limit(&field("serverMaxHeaderBytes"), "serverMaxHeaderBytes", 8192)?;
        if max_header_bytes > i32::MAX as usize {
            return Err(setting_error("serverMaxHeaderBytes"));
        }
        let buffered_posts = parse_limit(&field("scMaxBufferedPosts"), "scMaxBufferedPosts", 30)?;

        let headers = field("headers");
        let mut headers = if headers.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str::<Option<BTreeMap<String, String>>>(&headers)
                .map_err(|_| setting_error("headers"))?
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>()
        };
        for (name, value) in &mut headers {
            check_name(name, "headers")?;
            if name.eq_ignore_ascii_case("host") || ::http::HeaderValue::from_str(value).is_err() {
                return Err(setting_error("headers"));
            }
            name.make_ascii_lowercase();
        }
        let download = field("downloadSettings");
        let download = if download.is_empty() {
            None
        } else {
            serde_json::from_str::<Option<Value>>(&download)
                .map_err(|_| setting_error("downloadSettings"))?
        };
        if download
            .as_ref()
            .is_some_and(|value| !value.is_object() || mode == Some(XhttpMode::StreamOne))
        {
            return Err(setting_error("downloadSettings"));
        }
        let xmux = field("xmux");
        let xmux = if xmux.is_empty() { None } else {
            Some(serde_json::from_str::<Value>(&xmux).map_err(|_| setting_error("xmux"))?)
        };
        Ok(Self {
            host: field("host"),
            path,
            query: query.to_owned(),
            headers,
            mode,
            method,
            session,
            sequence,
            session_table,
            session_length,
            padding,
            uplink_data,
            uplink_key,
            uplink_chunk,
            post_bytes,
            post_interval,
            buffered_posts,
            stream_up_interval,
            max_header_bytes,
            no_grpc: parse_flag(&field("noGRPCHeader"), "noGRPCHeader")?,
            no_sse: parse_flag(&field("noSSEHeader"), "noSSEHeader")?,
            download,
            xmux: crate::xmux::XmuxConfig::xhttp(xmux.as_ref())?,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn xmux(&self) -> &crate::xmux::XmuxConfig { &self.xmux }

    pub fn mode(&self, reality: bool, separate_download: bool) -> XhttpMode {
        self.mode.unwrap_or(match (reality, separate_download) {
            (true, true) => XhttpMode::StreamUp,
            (true, false) => XhttpMode::StreamOne,
            (false, _) => XhttpMode::PacketUp,
        })
    }

    pub fn download_settings(&self) -> Option<&Value> {
        self.download.as_ref()
    }

    pub fn download_endpoint(&self) -> io::Result<Option<XhttpDownload>> {
        let Some(stream) = self.download_settings() else {
            return Ok(None);
        };
        let get = |key: &str| stream.get(key).and_then(Value::as_str).unwrap_or_default();
        let address = get("address");
        let address = address
            .strip_prefix('[')
            .and_then(|ip| ip.strip_suffix(']'))
            .unwrap_or(address);
        let port = stream
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0);
        let Some(port) = port.filter(|_| !address.is_empty()) else {
            return Err(setting_error("downloadSettings address or port"));
        };
        let network = nonempty(get("method").to_owned(), get("network"));
        if !matches!(network.as_str(), "xhttp" | "splithttp") {
            return Err(setting_error("downloadSettings network"));
        }
        let security = nonempty(get("security").to_ascii_lowercase(), "none");
        let mut fields = BTreeMap::new();
        for (value, label) in [
            (
                stream
                    .get("xhttpSettings")
                    .or_else(|| stream.get("splithttpSettings")),
                "downloadSettings xhttpSettings",
            ),
            (
                match security.as_str() {
                    "none" => None,
                    "tls" => stream.get("tlsSettings"),
                    "reality" => stream.get("realitySettings"),
                    _ => return Err(setting_error("downloadSettings security")),
                },
                "downloadSettings security settings",
            ),
        ] {
            let Some(value) = value.filter(|value| !value.is_null()) else {
                continue;
            };
            let object = value.as_object().ok_or_else(|| setting_error(label))?;
            for (key, value) in object {
                let text = match value {
                    Value::Null => continue,
                    Value::String(text) => text.clone(),
                    value => value.to_string(),
                };
                fields.insert(key.clone(), text);
            }
        }
        if security == "reality" {
            if let Some(password) = fields.remove("password").filter(|value| !value.is_empty()) {
                fields.insert("publicKey".to_owned(), password);
            }
        }
        for key in ["sockopt", "finalmask"] {
            if let Some(value) = stream.get(key).filter(|value| !value.is_null()) {
                fields.insert(key.to_owned(), value.to_string());
            }
        }
        fields.insert("network".to_owned(), "xhttp".to_owned());
        fields.insert("security".to_owned(), security);
        Ok(Some(XhttpDownload {
            address: address.to_owned(),
            port,
            settings: fields.into_iter().collect(),
        }))
    }

    pub fn obfs_padding(&self) -> bool {
        self.padding.obfs
    }

    pub fn max_header_bytes(&self) -> usize {
        self.max_header_bytes
    }

    pub fn buffered_posts(&self) -> usize {
        self.buffered_posts
    }

    pub fn upload_limit(&self) -> io::Result<usize> {
        Ok(self.post_bytes.sample()? as usize)
    }

    pub fn packet_limit(&self) -> usize {
        self.post_bytes.max as usize
    }

    pub fn post_interval(&self) -> io::Result<Duration> {
        let ms = if self.post_interval.min > 0 {
            self.post_interval.sample()? as u64
        } else {
            0
        };
        Ok(Duration::from_millis(ms))
    }

    pub fn stream_up_interval(&self) -> io::Result<Option<Duration>> {
        if self.stream_up_interval.max <= 0 {
            return Ok(None);
        }
        Ok(Some(Duration::from_secs(
            self.stream_up_interval.sample()?.max(0) as u64,
        )))
    }

    pub fn stream_up_padding(&self) -> io::Result<Vec<u8>> {
        Ok(vec![b'X'; self.padding.bytes.sample()? as usize])
    }

    pub fn session_id(&self) -> io::Result<String> {
        if !self.session_table.is_empty() {
            let length = self.session_length.sample()? as usize;
            return random_text(length, self.session_table.as_bytes());
        }
        let mut bytes = [0u8; 16];
        random(&mut bytes)?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let mut uuid = String::with_capacity(36);
        use std::fmt::Write;
        for (index, byte) in bytes.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                uuid.push('-');
            }
            write!(uuid, "{byte:02x}").expect("UUID formatting");
        }
        Ok(uuid)
    }

    pub fn request<'a>(
        &self,
        kind: XhttpRequestKind<&str>,
        authority: &str,
        scheme: &str,
        payload: &'a [u8],
    ) -> io::Result<XhttpRequest<'a>> {
        let (method, session, sequence, streaming, packet) = match kind {
            XhttpRequestKind::Download { session } => ("GET", session, None, false, false),
            XhttpRequestKind::StreamOne => (self.method.as_str(), "", None, true, false),
            XhttpRequestKind::StreamUp { session } => {
                (self.method.as_str(), session, None, true, false)
            }
            XhttpRequestKind::PacketUp { session, seq } => {
                (self.method.as_str(), session, Some(seq), false, true)
            }
            XhttpRequestKind::Preflight => ("OPTIONS", "", None, false, false),
        };
        let mut path = self.path.clone();
        let mut query = self.query.clone();
        let mut headers = self.headers.clone();
        let mut body = &[][..];
        if packet {
            match self.uplink_data {
                UplinkData::Auto | UplinkData::Body => {
                    body = payload;
                    set_header(&mut headers, "content-length", body.len().to_string());
                }
                placement => {
                    let encoded = URL_SAFE_NO_PAD.encode(payload);
                    let mut remaining = encoded.as_str();
                    let mut index = 0;
                    while !remaining.is_empty() {
                        let size = remaining.len().min(self.uplink_chunk.sample()? as usize);
                        let (value, rest) = remaining.split_at(size);
                        match placement {
                            UplinkData::Header => set_header(
                                &mut headers,
                                &format!("{}-{index}", self.uplink_key),
                                value.to_owned(),
                            ),
                            UplinkData::Cookie => add_cookie(
                                &mut headers,
                                &format!("{}_{index}", self.uplink_key),
                                value,
                            ),
                            _ => unreachable!(),
                        }
                        remaining = rest;
                        index += 1;
                    }
                }
            }
        }
        let raw_url = format!(
            "{scheme}://{authority}{}",
            utf8_percent_encode(&path, PATH_ESCAPE)
        );
        self.padding
            .apply_request(&raw_url, &mut query, &mut headers)?;
        self.session
            .apply(session, &mut path, &mut query, &mut headers);
        if let Some(sequence) = sequence {
            self.sequence
                .apply(&sequence.to_string(), &mut path, &mut query, &mut headers);
        }
        if streaming && !self.no_grpc {
            set_header(&mut headers, "content-type", "application/grpc".to_owned());
        }
        let mut target = utf8_percent_encode(&path, PATH_ESCAPE).to_string();
        if !query.is_empty() {
            target.push('?');
            target.push_str(&query);
        }
        if target.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
            || headers
                .iter()
                .any(|(_, value)| ::http::HeaderValue::from_str(value).is_err())
        {
            return Err(invalid("XHTTP request metadata"));
        }
        Ok(XhttpRequest {
            method: method.to_owned(),
            target,
            headers,
            body,
            streaming,
            packet,
        })
    }

    pub fn classify(
        &self,
        method: &str,
        target: &str,
        header: impl Fn(&str) -> Option<String>,
    ) -> io::Result<XhttpRequestKind> {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let path = percent_decode_str(path)
            .decode_utf8()
            .map_err(|_| invalid("XHTTP path"))?;
        let suffix = path
            .strip_prefix(&self.path)
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "XHTTP path"))?;
        if method == "OPTIONS"
            && header("access-control-request-method").is_some_and(|value| !value.is_empty())
        {
            return Ok(XhttpRequestKind::Preflight);
        }
        let query = parse_query(query);
        let cookie = header("cookie").unwrap_or_default();
        if !self.padding.valid(&query, &cookie, &header) {
            return Err(invalid("XHTTP padding"));
        }
        let mut parts = suffix.split('/');
        let session = self.session.extract(&mut parts, &query, &cookie, &header);
        let sequence = self.sequence.extract(&mut parts, &query, &cookie, &header);
        if session.is_empty() {
            return match self.mode {
                Some(XhttpMode::PacketUp) => Err(invalid("XHTTP stream-one is disabled")),
                _ => Ok(XhttpRequestKind::StreamOne),
            };
        }
        if method == "GET" && sequence.is_empty() {
            return Ok(XhttpRequestKind::Download { session });
        }
        if sequence.is_empty() {
            return match self.mode {
                None | Some(XhttpMode::StreamUp) => Ok(XhttpRequestKind::StreamUp { session }),
                _ => Err(invalid("XHTTP stream-up is disabled")),
            };
        }
        if self.mode.is_some_and(|mode| mode != XhttpMode::PacketUp) {
            return Err(invalid("XHTTP packet-up is disabled"));
        }
        let seq = sequence.parse().map_err(|_| invalid("XHTTP sequence"))?;
        Ok(XhttpRequestKind::PacketUp { session, seq })
    }

    pub fn packet_payload(
        &self,
        body: Vec<u8>,
        header: impl Fn(&str) -> Option<String>,
    ) -> io::Result<Vec<u8>> {
        let mut payload = Vec::new();
        if matches!(self.uplink_data, UplinkData::Auto | UplinkData::Header) {
            let key = self.uplink_key.to_ascii_lowercase();
            decode_chunks(&mut payload, |index| {
                header(&format!("{key}-{index}")).filter(|value| !value.is_empty())
            })?;
        }
        if matches!(self.uplink_data, UplinkData::Auto | UplinkData::Cookie) {
            let cookies = header("cookie").unwrap_or_default();
            decode_chunks(&mut payload, |index| {
                cookie_value(&cookies, &format!("{}_{index}", self.uplink_key)).map(str::to_owned)
            })?;
        }
        let body_enabled = matches!(self.uplink_data, UplinkData::Auto | UplinkData::Body);
        if payload
            .len()
            .saturating_add(if body_enabled { body.len() } else { 0 })
            > self.packet_limit()
        {
            return Err(io::Error::new(
                ErrorKind::FileTooLarge,
                "XHTTP packet exceeds scMaxEachPostBytes",
            ));
        }
        if body_enabled {
            if payload.is_empty() {
                return Ok(body);
            }
            payload.extend(body);
        }
        Ok(payload)
    }

    pub fn response_headers(
        &self,
        kind: &XhttpRequestKind,
        method: &str,
        header: impl Fn(&str) -> Option<String>,
    ) -> io::Result<Vec<(String, String)>> {
        let mut headers = Vec::new();
        let origin = header("origin").unwrap_or_default();
        set_header(
            &mut headers,
            "access-control-allow-origin",
            nonempty(origin, "*"),
        );
        if self.session.placement == MetaPlacement::Cookie
            || self.sequence.placement == MetaPlacement::Cookie
            || self.padding.placement == PaddingPlacement::Cookie
            || self.uplink_data == UplinkData::Cookie
        {
            set_header(
                &mut headers,
                "access-control-allow-credentials",
                "true".to_owned(),
            );
        }
        if method == "OPTIONS" {
            let requested_method = header("access-control-request-method").unwrap_or_default();
            let requested_headers = header("access-control-request-headers").unwrap_or_default();
            set_header(
                &mut headers,
                "access-control-allow-methods",
                nonempty(requested_method, "*"),
            );
            set_header(
                &mut headers,
                "access-control-allow-headers",
                nonempty(requested_headers, "*"),
            );
        }
        match kind {
            XhttpRequestKind::Download { .. }
            | XhttpRequestKind::StreamOne
            | XhttpRequestKind::StreamUp { .. } => {
                set_header(&mut headers, "x-accel-buffering", "no".to_owned());
                set_header(&mut headers, "cache-control", "no-store".to_owned());
                if !self.no_sse && !matches!(kind, XhttpRequestKind::StreamUp { .. }) {
                    set_header(&mut headers, "content-type", "text/event-stream".to_owned());
                }
            }
            XhttpRequestKind::PacketUp { .. }
                if self.uplink_data == UplinkData::Header
                    || self.uplink_data == UplinkData::Cookie
                    || header("content-length")
                        .as_deref()
                        .is_none_or(|value| value == "0") =>
            {
                set_header(&mut headers, "cache-control", "no-store".to_owned());
            }
            _ => {}
        }
        self.padding.apply_response(&mut headers)?;
        Ok(headers)
    }
}

#[derive(Clone, Debug)]
struct MetaField {
    placement: MetaPlacement,
    key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetaPlacement {
    Path,
    Header,
    Cookie,
    Query,
}

impl MetaField {
    fn parse(placement: &str, key: String, header_key: &str, other_key: &str) -> io::Result<Self> {
        let placement = match placement {
            "" | "path" => MetaPlacement::Path,
            "header" => MetaPlacement::Header,
            "cookie" => MetaPlacement::Cookie,
            "query" => MetaPlacement::Query,
            _ => return Err(setting_error("metadata placement")),
        };
        let mut key = nonempty(
            key,
            if placement == MetaPlacement::Header {
                header_key
            } else {
                other_key
            },
        );
        if placement == MetaPlacement::Header {
            check_name(&key, "metadata key")?;
            key.make_ascii_lowercase();
        }
        Ok(Self { placement, key })
    }

    fn apply(
        &self,
        value: &str,
        path: &mut String,
        query: &mut String,
        headers: &mut Vec<(String, String)>,
    ) {
        if value.is_empty() {
            return;
        }
        match self.placement {
            MetaPlacement::Path => {
                if !path.ends_with('/') {
                    path.push('/');
                }
                path.push_str(value);
            }
            MetaPlacement::Header => set_header(headers, &self.key, value.to_owned()),
            MetaPlacement::Cookie => add_cookie(headers, &self.key, value),
            MetaPlacement::Query => set_query(query, &self.key, value),
        }
    }

    fn extract(
        &self,
        path: &mut std::str::Split<'_, char>,
        query: &Query,
        cookie: &str,
        header: impl Fn(&str) -> Option<String>,
    ) -> String {
        match self.placement {
            MetaPlacement::Path => path.next().unwrap_or_default().to_owned(),
            MetaPlacement::Header => header(&self.key).unwrap_or_default(),
            MetaPlacement::Cookie => cookie_value(cookie, &self.key)
                .unwrap_or_default()
                .to_owned(),
            MetaPlacement::Query => query_get(query, &self.key).to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UplinkData {
    Auto,
    Body,
    Header,
    Cookie,
}

#[derive(Clone, Debug)]
struct Padding {
    obfs: bool,
    placement: PaddingPlacement,
    key: String,
    header: String,
    bytes: Range,
    tokenish: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaddingPlacement {
    Cookie,
    Header,
    Query,
    QueryInHeader,
}

impl Padding {
    fn parse(field: impl Fn(&str) -> String) -> io::Result<Self> {
        let bytes = Range::parse(&field("xPaddingBytes"), "xPaddingBytes")?;
        if bytes != (Range { min: 0, max: 0 }) && bytes.min <= 0 {
            return Err(setting_error("xPaddingBytes"));
        }
        let placement = match field("xPaddingPlacement").as_str() {
            "" | "queryInHeader" => PaddingPlacement::QueryInHeader,
            "cookie" => PaddingPlacement::Cookie,
            "header" => PaddingPlacement::Header,
            "query" => PaddingPlacement::Query,
            _ => return Err(setting_error("xPaddingPlacement")),
        };
        let tokenish = match field("xPaddingMethod").as_str() {
            "" | "repeat-x" => false,
            "tokenish" => true,
            _ => return Err(setting_error("xPaddingMethod")),
        };
        let header = nonempty(field("xPaddingHeader"), "X-Padding");
        check_name(&header, "xPaddingHeader")?;
        let key = nonempty(field("xPaddingKey"), "x_padding");
        let obfs = parse_flag(&field("xPaddingObfsMode"), "xPaddingObfsMode")?;
        if obfs && placement == PaddingPlacement::Cookie {
            check_name(&key, "xPaddingKey")?;
        }
        Ok(Self {
            obfs,
            placement,
            key,
            header: header.to_ascii_lowercase(),
            bytes: bytes.default_to(100, 1000),
            tokenish,
        })
    }

    fn apply_request(
        &self,
        raw_url: &str,
        query: &mut String,
        headers: &mut Vec<(String, String)>,
    ) -> io::Result<()> {
        let value = self.generate()?;
        if !self.obfs {
            set_header(headers, "referer", format!("{raw_url}?x_padding={value}"));
            return Ok(());
        }
        match self.placement {
            PaddingPlacement::Header => set_header(headers, &self.header, value),
            PaddingPlacement::QueryInHeader => set_header(
                headers,
                &self.header,
                format!("{raw_url}?{}={value}", self.key),
            ),
            PaddingPlacement::Cookie => add_cookie(headers, &self.key, &value),
            PaddingPlacement::Query => set_query(query, &self.key, &value),
        }
        Ok(())
    }

    fn apply_response(&self, headers: &mut Vec<(String, String)>) -> io::Result<()> {
        if !self.obfs {
            set_header(headers, "x-padding", self.generate()?);
            return Ok(());
        }
        match self.placement {
            PaddingPlacement::Header => set_header(headers, &self.header, self.generate()?),
            PaddingPlacement::QueryInHeader => set_header(
                headers,
                &self.header,
                format!("?{}={}", self.key, self.generate()?),
            ),
            PaddingPlacement::Cookie => headers.push((
                "set-cookie".to_owned(),
                format!("{}={}; Path=/", self.key, self.generate()?),
            )),
            PaddingPlacement::Query => {}
        }
        Ok(())
    }

    fn generate(&self) -> io::Result<String> {
        let length = self.bytes.sample()? as usize;
        if !self.obfs || !self.tokenish {
            return Ok("X".repeat(length));
        }
        let mut text = random_text(length.saturating_mul(5).div_ceil(4), BASE62)?;
        let mut bits = huffman_bits(&text);
        while bits.div_ceil(8) > length + 2 {
            let byte = text.pop().expect("padding is nonempty") as usize;
            bits -= usize::from(HPACK_BITS[byte]);
        }
        while bits.div_ceil(8) + 2 < length {
            text.push(if bits % 16 < 8 { 'X' } else { 'Z' });
            bits += 8;
        }
        Ok(text)
    }

    fn valid(&self, query: &Query, cookies: &str, header: impl Fn(&str) -> Option<String>) -> bool {
        if !self.obfs {
            let referer = header("referer").unwrap_or_default();
            return if referer.is_empty() {
                self.valid_value(query_get(query, "x_padding"))
            } else {
                self.valid_value(query_get(&parse_query(url_query(&referer)), "x_padding"))
            };
        }
        if let Some(value) = cookie_value(cookies, &self.key).filter(|value| !value.is_empty()) {
            return self.valid_value(value);
        }
        if let Some(value) = header(&self.header).filter(|value| !value.is_empty()) {
            if self.placement == PaddingPlacement::Header {
                return self.valid_value(&value);
            }
            return self.valid_value(query_get(&parse_query(url_query(&value)), &self.key));
        }
        self.valid_value(query_get(query, &self.key))
    }

    fn valid_value(&self, value: &str) -> bool {
        if value.is_empty() {
            return false;
        }
        let min = self.bytes.min as usize;
        let max = self.bytes.max as usize;
        if self.tokenish {
            (min.saturating_sub(2)..=max + 2).contains(&huffman_bits(value).div_ceil(8))
        } else {
            (min..=max).contains(&value.len())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Range {
    min: i32,
    max: i32,
}

impl Range {
    fn parse(text: &str, key: &str) -> io::Result<Self> {
        if text.is_empty() {
            return Ok(Self { min: 0, max: 0 });
        }
        let text = text.trim();
        if let Ok(value) = text.parse() {
            return Ok(Self {
                min: value,
                max: value,
            });
        }
        let separator = text
            .strip_prefix('-')
            .unwrap_or(text)
            .find('-')
            .map(|index| index + usize::from(text.starts_with('-')))
            .ok_or_else(|| setting_error(key))?;
        let left: i32 = text[..separator].parse().map_err(|_| setting_error(key))?;
        let right: i32 = text[separator + 1..]
            .parse()
            .map_err(|_| setting_error(key))?;
        Ok(Self {
            min: left.min(right),
            max: left.max(right),
        })
    }

    fn default_to(self, min: i32, max: i32) -> Self {
        if self.max == 0 {
            Self { min, max }
        } else {
            self
        }
    }

    fn sample(self) -> io::Result<i32> {
        let span = (i64::from(self.max) - i64::from(self.min)) as u32;
        if span <= 1 {
            return Ok(self.min);
        }
        let cutoff = u32::MAX - u32::MAX % span;
        loop {
            let mut bytes = [0; 4];
            random(&mut bytes)?;
            let value = u32::from_ne_bytes(bytes);
            if value < cutoff {
                return Ok((i64::from(self.min) + i64::from(value % span)) as i32);
            }
        }
    }

    fn enough_ids(self, table_len: usize) -> bool {
        const MIN_ROOM: u64 = 1 << 31;
        if table_len < 2 {
            return false;
        }
        let mut room = 0u64;
        for len in self.min..=self.max {
            room = room.saturating_add((table_len as u64).saturating_pow(len as u32));
            if room >= MIN_ROOM {
                return true;
            }
        }
        false
    }
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn predefined_table(name: &str) -> Option<&'static str> {
    match name {
        "ALPHABET" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Alphabet" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        "BASE36" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Base62" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        "HEX" => Some("0123456789ABCDEF"),
        "alphabet" => Some("abcdefghijklmnopqrstuvwxyz"),
        "base36" => Some("0123456789abcdefghijklmnopqrstuvwxyz"),
        "hex" => Some("0123456789abcdef"),
        "number" => Some("0123456789"),
        _ => None,
    }
}

fn random(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::getrandom(bytes).map_err(|error| io::Error::other(error.to_string()))
}

fn random_text(length: usize, table: &[u8]) -> io::Result<String> {
    let mut text = Vec::with_capacity(length);
    let mut bytes = [0; 256];
    if table.len() <= 256 {
        let cutoff = 256 - 256 % table.len();
        while text.len() < length {
            random(&mut bytes)?;
            text.extend(
                bytes
                    .iter()
                    .map(|&byte| usize::from(byte))
                    .filter(|&byte| byte < cutoff)
                    .take(length - text.len())
                    .map(|byte| table[byte % table.len()]),
            );
        }
    } else {
        let index = Range {
            min: 0,
            max: i32::try_from(table.len()).map_err(|_| setting_error("sessionIDTable"))?,
        };
        while text.len() < length {
            text.push(table[index.sample()? as usize]);
        }
    }
    String::from_utf8(text).map_err(|_| invalid("XHTTP random alphabet"))
}

fn parse_limit(text: &str, key: &str, default: usize) -> io::Result<usize> {
    match text {
        "" | "0" => Ok(default),
        _ => text.parse().map_err(|_| setting_error(key)),
    }
}

fn parse_flag(text: &str, key: &str) -> io::Result<bool> {
    match text {
        "" | "false" => Ok(false),
        "true" => Ok(true),
        _ => Err(setting_error(key)),
    }
}

fn nonempty(value: String, default: &str) -> String {
    if value.is_empty() {
        default.to_owned()
    } else {
        value
    }
}

fn check_name(name: &str, key: &str) -> io::Result<()> {
    ::http::HeaderName::from_bytes(name.as_bytes())
        .map(|_| ())
        .map_err(|_| setting_error(key))
}

fn setting_error(key: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, format!("XHTTP setting {key}"))
}

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    headers.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
    headers.push((name.to_ascii_lowercase(), value));
}

fn add_cookie(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    let name = name.replace(['\r', '\n'], "-");
    let value: String = value
        .bytes()
        .filter(|&byte| (b' '..=b'~').contains(&byte) && !matches!(byte, b'"' | b';' | b'\\'))
        .map(char::from)
        .collect();
    let cookie = if value.contains([' ', ',']) {
        format!("{name}=\"{value}\"")
    } else {
        format!("{name}={value}")
    };
    if let Some((_, current)) = headers.iter_mut().find(|(key, _)| key == "cookie") {
        current.push_str("; ");
        current.push_str(&cookie);
    } else {
        headers.push(("cookie".to_owned(), cookie));
    }
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    cookies
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| {
            (key.trim() == name).then(|| {
                value
                    .strip_prefix('"')
                    .and_then(|text| text.strip_suffix('"'))
                    .unwrap_or(value)
            })
        })
}

fn decode_chunks(payload: &mut Vec<u8>, chunk: impl Fn(usize) -> Option<String>) -> io::Result<()> {
    let mut encoded = String::new();
    for index in 0.. {
        let Some(value) = chunk(index) else { break };
        encoded.push_str(&value);
    }
    URL_SAFE_NO_PAD
        .decode_vec(encoded, payload)
        .map_err(|_| invalid("XHTTP packet base64"))
}

const QUERY_ESCAPE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
const PATH_ESCAPE: &AsciiSet = &QUERY_ESCAPE
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b',')
    .remove(b'/')
    .remove(b':')
    .remove(b';')
    .remove(b'=')
    .remove(b'@');

type Query = BTreeMap<String, Vec<String>>;

fn parse_query(query: &str) -> Query {
    let mut values = Query::new();
    for part in query
        .split('&')
        .filter(|part| !part.is_empty() && !part.contains(';'))
    {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let (Some(key), Some(value)) = (unescape_query(key), unescape_query(value)) else {
            continue;
        };
        values.entry(key).or_default().push(value);
    }
    values
}

fn unescape_query(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.iter().enumerate().any(|(index, &byte)| {
        byte == b'%'
            && !bytes
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    }) {
        return None;
    }
    percent_decode_str(&text.replace('+', " "))
        .decode_utf8()
        .ok()
        .map(|text| text.into_owned())
}

fn url_query(url: &str) -> &str {
    let without_fragment = url.split('#').next().unwrap_or_default();
    without_fragment
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default()
}

fn query_get<'a>(query: &'a Query, key: &str) -> &'a str {
    query
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
        .unwrap_or_default()
}

fn set_query(query: &mut String, key: &str, value: &str) {
    let mut values = parse_query(query);
    values.insert(key.to_owned(), vec![value.to_owned()]);
    query.clear();
    for (key, entries) in values {
        let key = utf8_percent_encode(&key, QUERY_ESCAPE)
            .to_string()
            .replace("%20", "+");
        for value in entries {
            if !query.is_empty() {
                query.push('&');
            }
            query.push_str(&key);
            query.push('=');
            query.push_str(
                &utf8_percent_encode(&value, QUERY_ESCAPE)
                    .to_string()
                    .replace("%20", "+"),
            );
        }
    }
}

fn huffman_bits(value: &str) -> usize {
    value
        .bytes()
        .map(|byte| usize::from(HPACK_BITS[byte as usize]))
        .sum()
}

// Code widths for each octet in RFC 7541, Appendix B. QPACK uses the same table.
const HPACK_BITS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];
