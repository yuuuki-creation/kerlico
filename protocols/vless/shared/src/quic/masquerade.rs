use bytes::{Buf, Bytes};
use futures_util::stream;
use h3::server::RequestStream;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use url::{Position, Url};

mod file;

pub(super) type H3Request = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3Recv = RequestStream<h3_quinn::RecvStream, Bytes>;
type H3Send = RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type Body = UnsyncBoxBody<Bytes, io::Error>;
trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}

/// Configured origin for Hysteria's masquerade proxy.
#[derive(Clone, Debug)]
pub enum MasqueradeTarget {
    Tcp { host: String, port: u16 },
    Unix(PathBuf),
}

/// Socket opened for a masquerade origin by the outbound module.
pub enum MasqueradeSocket {
    Network(kerlico_shared::runtime::NetworkConnection),
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

/// Dials a fixed masquerade origin. The Hysteria transport owns HTTP and TLS.
pub type MasqueradeDialer = Arc<
    dyn Fn(&MasqueradeTarget) -> io::Result<MasqueradeSocket> + Send + Sync,
>;

#[derive(Clone, Default)]
pub struct HysteriaMasquerade {
    mode: Mode,
}

#[derive(Clone, Default)]
enum Mode {
    #[default]
    NotFound,
    String { status: StatusCode, headers: HeaderMap, body: Bytes },
    File(PathBuf),
    Proxy(Arc<Proxy>),
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Raw {
    #[serde(rename = "type")]
    mode: String,
    dir: String,
    url: String,
    rewrite_host: bool,
    x_forwarded: bool,
    insecure: bool,
    content: String,
    headers: BTreeMap<String, String>,
    status_code: u16,
}

impl HysteriaMasquerade {
    pub fn parse(value: Option<&str>) -> io::Result<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let raw: Raw = serde_json::from_str(value).map_err(invalid)?;
        let mode = match raw.mode.to_ascii_lowercase().as_str() {
            "" | "404" => Mode::NotFound,
            "file" => Mode::File(PathBuf::from(if raw.dir.is_empty() { ".".to_owned() } else { raw.dir })),
            "string" => {
                let status = if raw.status_code == 0 {
                    StatusCode::OK
                } else {
                    StatusCode::from_u16(raw.status_code).map_err(invalid)?
                };
                let mut headers = HeaderMap::new();
                for (name, value) in raw.headers {
                    let name = header::HeaderName::from_bytes(name.as_bytes()).map_err(invalid)?;
                    headers.insert(name, value.parse().map_err(invalid)?);
                }
                Mode::String { status, headers, body: Bytes::from(raw.content) }
            }
            "proxy" => Mode::Proxy(Arc::new(Proxy::parse(raw)?)),
            _ => return Err(invalid("unknown Hysteria masquerade type")),
        };
        Ok(Self { mode })
    }

    pub fn with_dialer(mut self, dialer: MasqueradeDialer) -> Self {
        if let Mode::Proxy(proxy) = &mut self.mode {
            Arc::make_mut(proxy).dialer = Some(dialer);
        }
        self
    }

    pub(super) async fn serve(
        &self,
        request: Request<()>,
        peer: SocketAddr,
        stream: H3Request,
    ) -> io::Result<()> {
        let is_head = request.method() == Method::HEAD;
        let (mut send, receive) = stream.split();
        let response = match &self.mode {
            Mode::NotFound => http_error(StatusCode::NOT_FOUND),
            Mode::String { status, headers, body } => {
                let mut response = Response::new(full(body.clone()));
                *response.status_mut() = *status;
                *response.headers_mut() = headers.clone();
                let headers = response.headers_mut();
                if !body.is_empty() && !headers.contains_key(header::CONTENT_TYPE)
                    && !headers.contains_key(header::CONTENT_ENCODING)
                {
                    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static(file::sniff(body)));
                }
                if !matches!(*status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED) {
                    headers.entry(header::CONTENT_LENGTH).or_insert_with(|| body.len().into());
                }
                response
            }
            Mode::File(root) => file::response(root, &request).await,
            Mode::Proxy(proxy) => {
                match tokio::time::timeout(Duration::from_secs(30), proxy.request(request, peer, receive)).await {
                    Ok(Ok(response)) => response.map(|body| body.map_err(io::Error::other).boxed_unsync()),
                    _ => Response::builder().status(StatusCode::BAD_GATEWAY).body(empty()).unwrap(),
                }
            }
        };
        respond(&mut send, response, is_head).await
    }
}

async fn respond(send: &mut H3Send, response: Response<Body>, is_head: bool) -> io::Result<()> {
    let (mut parts, mut body) = response.into_parts();
    if parts.status.is_informational() {
        send.send_response(Response::from_parts(parts.clone(), ())).await.map_err(io::Error::other)?;
        parts.status = StatusCode::OK;
    }
    parts.headers.entry(header::DATE).or_insert_with(date);
    let no_body = is_head || matches!(parts.status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED);
    send.send_response(Response::from_parts(parts, ())).await.map_err(io::Error::other)?;
    if !no_body {
        while let Some(frame) = body.frame().await {
            match frame?.into_data() {
                Ok(data) if !data.is_empty() => send.send_data(data).await.map_err(io::Error::other)?,
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        send.send_trailers(trailers).await.map_err(io::Error::other)?;
                    }
                }
                _ => {}
            }
        }
    }
    send.finish().await.map_err(io::Error::other)
}

#[derive(Clone)]
struct Proxy {
    target: MasqueradeTarget,
    scheme: &'static str,
    authority: String,
    path: String,
    query: String,
    rewrite_host: bool,
    x_forwarded: bool,
    tls: Option<Arc<rustls::ClientConfig>>,
    dialer: Option<MasqueradeDialer>,
}

impl Proxy {
    fn parse(raw: Raw) -> io::Result<Self> {
        let (target, scheme, authority, path, query) = match Url::parse(&raw.url) {
            Ok(url) if matches!(url.scheme(), "http" | "https") => {
                let host = url.host_str().ok_or_else(|| invalid("Hysteria proxy URL requires a host"))?;
                let port = url.port_or_known_default().ok_or_else(|| invalid("Hysteria proxy URL requires a port"))?;
                let scheme = if url.scheme() == "https" { "https" } else { "http" };
                (
                    MasqueradeTarget::Tcp { host: host.trim_matches(['[', ']']).to_owned(), port },
                    scheme,
                    url[Position::BeforeHost..Position::AfterPort].to_owned(),
                    url.path().to_owned(),
                    url.query().unwrap_or_default().to_owned(),
                )
            }
            Ok(url) if url.scheme() == "unix" => {
                let path = percent_encoding::percent_decode_str(url.path()).decode_utf8().map_err(invalid)?;
                if path.is_empty() {
                    return Err(invalid("Hysteria proxy Unix socket path is empty"));
                }
                (MasqueradeTarget::Unix(PathBuf::from(path.as_ref())), "http", "localhost".into(), String::new(), String::new())
            }
            Err(url::ParseError::RelativeUrlWithoutBase) if !raw.url.is_empty() => {
                (MasqueradeTarget::Unix(PathBuf::from(raw.url)), "http", "localhost".into(), String::new(), String::new())
            }
            _ => return Err(invalid("unknown or invalid Hysteria masquerade proxy URL")),
        };
        let tls = (scheme == "https").then(|| proxy_tls(raw.insecure)).transpose()?;
        Ok(Self {
            target,
            scheme,
            authority,
            path,
            query,
            rewrite_host: raw.rewrite_host,
            x_forwarded: raw.x_forwarded,
            tls,
            dialer: None,
        })
    }

    async fn request(
        &self,
        request: Request<()>,
        peer: SocketAddr,
        receive: H3Recv,
    ) -> io::Result<Response<Incoming>> {
        let (mut parts, ()) = request.into_parts();
        let original_host = parts.uri.authority().map(|value| value.as_str()).unwrap_or_default().to_owned();
        let host = if self.rewrite_host || original_host.is_empty() { &self.authority } else { &original_host };
        let path = join_paths(&self.path, parts.uri.path());
        let incoming_query = parts.uri.query().unwrap_or_default();
        let query = match (self.query.is_empty(), incoming_query.is_empty()) {
            (true, true) => String::new(),
            (true, false) => format!("?{incoming_query}"),
            (false, true) => format!("?{}", self.query),
            (false, false) => format!("?{}&{incoming_query}", self.query),
        };
        let path = format!("{path}{query}");
        let stream = self.connect().await?;
        let h2 = stream.1;
        parts.version = if h2 { http::Version::HTTP_2 } else { http::Version::HTTP_11 };
        parts.uri = if h2 {
            Uri::builder().scheme(self.scheme).authority(host.as_str()).path_and_query(path.as_str()).build()
                .map_err(invalid)?
        } else {
            path.parse().map_err(invalid)?
        };
        let request_trailers = parts.headers.get_all(header::TE).iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("trailers"));
        strip_hop_headers(&mut parts.headers);
        if request_trailers {
            parts.headers.insert(header::TE, header::HeaderValue::from_static("trailers"));
        }
        for name in ["forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"] {
            parts.headers.remove(name);
        }
        parts.headers.insert(header::HOST, host.parse().map_err(invalid)?);
        if self.x_forwarded {
            parts.headers.insert("x-forwarded-for", peer.ip().to_string().parse().map_err(invalid)?);
            parts.headers.insert("x-forwarded-host", original_host.parse().map_err(invalid)?);
            parts.headers.insert("x-forwarded-proto", header::HeaderValue::from_static("https"));
        }
        let request = Request::from_parts(parts, receive_body(receive));
        let io = TokioIo::new(stream.0);
        let mut response = if h2 {
            let (mut sender, driver) = http2::handshake(TokioExecutor::new(), io).await.map_err(io::Error::other)?;
            tokio::spawn(driver);
            sender.send_request(request).await
        } else {
            let (mut sender, driver) = http1::handshake(io).await.map_err(io::Error::other)?;
            tokio::spawn(driver);
            sender.send_request(request).await
        }.map_err(io::Error::other)?;
        strip_hop_headers(response.headers_mut());
        Ok(response)
    }

    async fn connect(&self) -> io::Result<(Box<dyn AsyncIo>, bool)> {
        let dialer = self.dialer.clone().ok_or_else(|| io::Error::other("Hysteria masquerade dialer is unavailable"))?;
        let target = self.target.clone();
        let socket = tokio::task::spawn_blocking(move || dialer(&target)).await.map_err(io::Error::other)??;
        match socket {
            MasqueradeSocket::Network(connection) => {
                let local = "0.0.0.0:0".parse().expect("logical origin local");
                let peer = match &self.target { MasqueradeTarget::Tcp { host, port } => SocketAddr::new(host.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into()), *port), MasqueradeTarget::Unix(_) => local };
                let stream = crate::tls_async::connect_async_network(connection, None, "localhost", &crate::finalmask::FinalMask::default(), local, peer).await?;
                if let (Some(tls), MasqueradeTarget::Tcp { host, .. }) = (&self.tls, &self.target) {
                    let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(invalid)?;
                    let stream = tokio_rustls::TlsConnector::from(tls.clone()).connect(name, stream).await?;
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    Ok((Box::new(stream), h2))
                } else { Ok((Box::new(stream), false)) }
            }
            MasqueradeSocket::Tcp(socket) => {
                socket.set_nonblocking(true)?;
                let stream = tokio::net::TcpStream::from_std(socket)?;
                if let (Some(tls), MasqueradeTarget::Tcp { host, .. }) = (&self.tls, &self.target) {
                    let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(invalid)?;
                    let stream = tokio_rustls::TlsConnector::from(tls.clone()).connect(name, stream).await?;
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    Ok((Box::new(stream), h2))
                } else {
                    Ok((Box::new(stream), false))
                }
            }
            #[cfg(unix)]
            MasqueradeSocket::Unix(socket) => {
                socket.set_nonblocking(true)?;
                Ok((Box::new(tokio::net::UnixStream::from_std(socket)?), false))
            }
        }
    }
}

fn proxy_tls(insecure: bool) -> io::Result<Arc<rustls::ClientConfig>> {
    if insecure {
        return crate::client_config(&["h2".into(), "http/1.1".into()], true)
            .map_err(|()| invalid("Hysteria proxy TLS configuration"));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub(super) fn date() -> header::HeaderValue {
    httpdate::fmt_http_date(SystemTime::now()).parse().expect("HTTP date")
}

fn receive_body(receive: H3Recv) -> Body {
    let frames = stream::try_unfold(Some(receive), |receive| async {
        let Some(mut receive) = receive else { return Ok(None); };
        if let Some(mut data) = receive.recv_data().await.map_err(io::Error::other)? {
            let bytes = data.copy_to_bytes(data.remaining());
            return Ok(Some((Frame::data(bytes), Some(receive))));
        }
        Ok(receive.recv_trailers().await.map_err(io::Error::other)?.map(|trailers| (Frame::trailers(trailers), None)))
    });
    StreamBody::new(frames).boxed_unsync()
}

fn join_paths(base: &str, path: &str) -> String {
    if base.is_empty() {
        return path.to_owned();
    }
    match (base.ends_with('/'), path.starts_with('/')) {
        (true, true) => format!("{base}{}", &path[1..]),
        (false, false) => format!("{base}/{path}"),
        _ => format!("{base}{path}"),
    }
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let named: Vec<_> = headers.get_all(header::CONNECTION).iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
    ] {
        headers.remove(name);
    }
}

fn full(data: Bytes) -> Body {
    Full::new(data).map_err(|error| match error {}).boxed_unsync()
}

fn empty() -> Body {
    Empty::new().map_err(|error| match error {}).boxed_unsync()
}

fn http_error(status: StatusCode) -> Response<Body> {
    let message = match status {
        StatusCode::NOT_FOUND => "404 page not found\n",
        StatusCode::FORBIDDEN => "403 Forbidden\n",
        StatusCode::RANGE_NOT_SATISFIABLE => "invalid range: failed to overlap\n",
        _ => "500 Internal Server Error\n",
    };
    Response::builder().status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(full(Bytes::from_static(message.as_bytes())))
        .unwrap()
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
