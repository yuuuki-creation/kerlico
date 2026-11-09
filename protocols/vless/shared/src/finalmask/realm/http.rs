use std::io;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use percent_encoding::percent_decode_str;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use tokio::time::timeout;
use url::{Position, Url};

use super::super::http_tls::{HttpConnection, TlsClient, TlsUsage};
use super::super::{invalid, malformed};
use super::packets::PunchMetadata;

const HTTP_LIMIT: Duration = Duration::from_secs(20);
const BODY_LIMIT: usize = 64 * 1024;
const EVENT_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
pub(super) struct Control {
    base: Url,
    realm: String,
    token: http::HeaderValue,
    tls: Option<TlsClient>,
    carrier: Option<std::sync::Arc<crate::runtime::CarrierNetwork>>,
}

#[derive(Serialize)]
struct Addresses {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
}

#[derive(Serialize)]
struct Connect<'a> {
    addresses: Vec<String>,
    #[serde(flatten)]
    meta: &'a PunchMetadata,
}

#[derive(Deserialize)]
pub(super) struct Registration {
    pub(super) session_id: String,
    pub(super) ttl: u64,
}

#[derive(Deserialize)]
pub(super) struct Heartbeat {
    pub(super) ttl: u64,
}

#[derive(Deserialize)]
struct Connected {
    addresses: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct Event {
    pub(super) addresses: Vec<String>,
    #[serde(flatten)]
    pub(super) meta: PunchMetadata,
}

impl Control {
    pub(super) fn parse(
        raw_url: &str,
        config: Value,
        network: Option<std::sync::Arc<dyn crate::TlsNetwork>>,
        cache: Option<std::sync::Arc<crate::AdvancedTlsClientCache>>,
    ) -> io::Result<Self> {
        let url = Url::parse(raw_url).map_err(invalid)?;
        let scheme = match url.scheme() {
            "realm" => "https",
            "realm+http" => "http",
            _ => return Err(invalid("Realm URL scheme must be realm or realm+http")),
        };
        let authority = &url[Position::BeforeHost..Position::AfterPort];
        if authority.is_empty() {
            return Err(invalid("Realm URL is missing its host"));
        }
        let base = Url::parse(&format!("{scheme}://{authority}")).map_err(invalid)?;
        let auth = match url.password() {
            Some(password) => format!("{}:{password}", url.username()),
            None => url.username().to_owned(),
        };
        let token = percent_decode_str(&auth).decode_utf8().map_err(invalid)?;
        let realm = percent_decode_str(url.path().strip_prefix('/').unwrap_or(url.path()))
            .decode_utf8()
            .map_err(invalid)?;
        if token.is_empty() || realm.is_empty() {
            return Err(invalid("Realm URL needs its bearer token and realm ID"));
        }
        let token = bearer(&token)?;
        let tls = if scheme == "https" {
            Some(TlsClient::parse(
                config,
                host(&base),
                TlsUsage::Realm,
                network,
                cache.as_deref(),
            )?)
        } else {
            None
        };
        Ok(Self {
            base,
            realm: escape_segment(&realm),
            token,
            tls,
            carrier: None,
        })
    }

    pub(super) fn set_network(&mut self, network: std::sync::Arc<crate::runtime::CarrierNetwork>) { self.carrier = Some(network); }
    pub(super) fn network(&self) -> Option<&crate::runtime::CarrierNetwork> { self.carrier.as_deref() }

    pub(super) async fn register(&self, addresses: Vec<String>) -> io::Result<Registration> {
        self.call(
            Method::POST,
            "",
            &self.token,
            Some(&Addresses { addresses }),
        )
        .await
    }

    pub(super) async fn connect(
        &self,
        addresses: Vec<String>,
        meta: &PunchMetadata,
    ) -> io::Result<Vec<String>> {
        let connected: Connected = self
            .call(
                Method::POST,
                "connect",
                &self.token,
                Some(&Connect { addresses, meta }),
            )
            .await?;
        Ok(connected.addresses)
    }

    pub(super) async fn heartbeat(
        &self,
        sid: &str,
        addresses: Vec<String>,
    ) -> io::Result<Heartbeat> {
        self.call(
            Method::POST,
            "heartbeat",
            &bearer(sid)?,
            Some(&Addresses { addresses }),
        )
        .await
    }

    pub(super) async fn acknowledge(
        &self,
        sid: &str,
        nonce: &str,
        addresses: Vec<String>,
    ) -> io::Result<()> {
        let suffix = format!("connects/{}", escape_segment(nonce));
        self.empty(Method::POST, &suffix, sid, Some(&Addresses { addresses }))
            .await
    }

    pub(super) async fn deregister(&self, sid: &str) -> io::Result<()> {
        self.empty(Method::DELETE, "", sid, None::<&Addresses>)
            .await
    }

    pub(super) async fn events(&self, sid: &str) -> io::Result<Events> {
        let token = bearer(sid)?;
        let request = self.request(Method::GET, "events", &token, None::<&Addresses>);
        let response = timeout(HTTP_LIMIT, request)
            .await
            .map_err(|_| timed_out())??;
        status(response.status(), StatusCode::OK)?;
        Ok(Events {
            body: response.into_body(),
            buffer: BytesMut::new(),
        })
    }

    async fn call<T: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: &http::HeaderValue,
        value: Option<&T>,
    ) -> io::Result<R> {
        let exchange = async {
            let response = self.request(method, path, token, value).await?;
            status(response.status(), StatusCode::OK)?;
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
                    if bytes.len() + data.len() > BODY_LIMIT {
                        return Err(malformed("Realm HTTP response too large"));
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            serde_json::from_slice(&bytes).map_err(io::Error::other)
        };
        timeout(HTTP_LIMIT, exchange)
            .await
            .map_err(|_| timed_out())?
    }

    async fn empty<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        token: &str,
        value: Option<&T>,
    ) -> io::Result<()> {
        let token = bearer(token)?;
        let response = timeout(HTTP_LIMIT, self.request(method, path, &token, value))
            .await
            .map_err(|_| timed_out())??;
        status(response.status(), StatusCode::NO_CONTENT)
    }

    async fn request<T: Serialize>(
        &self,
        method: Method,
        suffix: &str,
        token: &http::HeaderValue,
        value: Option<&T>,
    ) -> io::Result<Response<Incoming>> {
        let mut path = format!("/v1/{}", self.realm);
        if !suffix.is_empty() {
            path.push('/');
            path.push_str(suffix);
        }
        // Xray escapes the path segment before escaping the URL path.
        let path = path.replace('%', "%25");
        let host = host(&self.base);
        let port = self
            .base
            .port_or_known_default()
            .expect("Realm HTTP scheme");
        let authority = &self.base[Position::BeforeHost..Position::AfterPort];
        let mut connection = HttpConnection::connect(host, port, self.tls.as_ref(), self.carrier.as_deref()).await?;
        let uri = if connection.h2() {
            format!("{}://{authority}{path}", self.base.scheme())
        } else {
            path
        };
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, token)
            .header(header::HOST, authority);
        let body = if let Some(value) = value {
            request = request.header(header::CONTENT_TYPE, "application/json");
            serde_json::to_vec(value).map_err(io::Error::other)?
        } else {
            Vec::new()
        };
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(io::Error::other)?;
        connection.request(request).await
    }
}

fn host(base: &Url) -> &str {
    base.host_str()
        .expect("Realm host")
        .trim_start_matches('[')
        .trim_end_matches(']')
}

fn bearer(token: &str) -> io::Result<http::HeaderValue> {
    http::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| invalid("invalid Realm bearer token"))
}

fn escape_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~$&+:=@".contains(&byte) {
            out.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut out, "%{byte:02X}").expect("write to string");
        }
    }
    out
}

#[derive(Debug)]
struct HttpStatus(StatusCode);

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Realm HTTP status {}", self.0)
    }
}

impl std::error::Error for HttpStatus {}

fn status(actual: StatusCode, expected: StatusCode) -> io::Result<()> {
    if actual == expected {
        return Ok(());
    }
    Err(io::Error::other(HttpStatus(actual)))
}

pub(super) fn session_invalid(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<HttpStatus>())
        .is_some_and(|status| matches!(status.0, StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED))
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "Realm control request timed out")
}

pub(super) struct Events {
    body: Incoming,
    buffer: BytesMut,
}

impl Events {
    pub(super) async fn next(&mut self) -> io::Result<Event> {
        let mut punch = false;
        let mut data = Vec::new();
        loop {
            while let Some(newline) = self.buffer.iter().position(|&byte| byte == b'\n') {
                let line = self.buffer.split_to(newline + 1);
                let line = line[..newline]
                    .strip_suffix(b"\r")
                    .unwrap_or(&line[..newline]);
                if line.is_empty() {
                    if punch && !data.is_empty() {
                        return serde_json::from_slice(&data).map_err(io::Error::other);
                    }
                    punch = false;
                    data.clear();
                } else if let Some(field) = line.strip_prefix(b"event:") {
                    punch = field.strip_prefix(b" ").unwrap_or(field) == b"punch";
                } else if let Some(field) = line.strip_prefix(b"data:") {
                    if !data.is_empty() {
                        data.push(b'\n');
                    }
                    data.extend_from_slice(field.strip_prefix(b" ").unwrap_or(field));
                    if data.len() > EVENT_LIMIT {
                        return Err(malformed("Realm event too large"));
                    }
                }
            }
            let frame = self
                .body
                .frame()
                .await
                .ok_or(io::ErrorKind::UnexpectedEof)?
                .map_err(io::Error::other)?;
            if let Ok(bytes) = frame.into_data() {
                if self.buffer.len() + bytes.len() > EVENT_LIMIT {
                    return Err(malformed("Realm event line too large"));
                }
                self.buffer.extend_from_slice(&bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_token_only_and_username_password_realm_urls() {
        let plain =
            Control::parse(concat!("realm+http://", "abc@127.0.0.1:8080/worker"), Value::Null, None, None).unwrap();
        assert_eq!(plain.token, "Bearer abc");
        let encoded = Control::parse(
            concat!("realm+http://", "a%3Ab:secret@[::1]:8080/name%2Fsub"),
            Value::Null,
            None,
            None,
        )
        .unwrap();
        assert_eq!(encoded.token, "Bearer a:b:secret");
        assert_eq!(encoded.realm, "name%2Fsub");
        assert_eq!(host(&encoded.base), "::1");
    }
}
