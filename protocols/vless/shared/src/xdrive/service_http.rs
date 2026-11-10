use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http::{header, HeaderMap, Request};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use percent_encoding::percent_decode_str;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::timeout;
use url::{Position, Url};

use super::{invalid, timed_out, XdriveHttpOptions, MAX_SEGMENT_BYTES};

const HTTP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE: usize = MAX_SEGMENT_BYTES + 1024 * 1024;
pub(super) const ATTEMPTS: usize = 8;

pub(super) type Headers = BTreeMap<String, String>;

pub(super) struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
    headers: HeaderMap,
}

impl HttpReply {
    fn closes_connection(&self) -> bool {
        self.headers.get_all(header::CONNECTION).iter().any(|value| value.to_str().is_ok_and(|text| text.split(',').any(|token| token.trim().eq_ignore_ascii_case("close"))))
    }
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn error(&self, operation: &str) -> io::Error {
        // A service response may contain a credential or signed URL.
        io::Error::other(format!("XDrive {operation} answered HTTP {}", self.status))
    }

    pub fn retry_after(&self) -> Option<Duration> {
        let text = self.headers.get(header::RETRY_AFTER)?.to_str().ok()?;
        text.parse().ok().map(Duration::from_secs).or_else(|| {
            httpdate::parse_http_date(text)
                .ok()?
                .duration_since(SystemTime::now())
                .ok()
        })
    }
}

pub(super) fn backoff(attempt: usize, hint: Option<Duration>) {
    let delay = hint.unwrap_or_else(|| Duration::from_millis(200 << attempt.min(6)));
    std::thread::sleep(delay.min(Duration::from_secs(8)));
}

pub(super) struct ServiceHttp {
    shared: Arc<ServiceShared>,
    selected: Option<Mutex<Option<Arc<crate::xmux::XmuxLease<TransportClient>>>>>,
    concurrency: usize,
    active: Mutex<usize>,
    available: Condvar,
}

pub(super) struct ServiceShared {
    options: XdriveHttpOptions,
    tls: Arc<crate::AdvancedTlsClientConfig>,
    redirects: Redirects,
    xmux: crate::xmux::XmuxConfig,
    pool: crate::xmux::XmuxPool<TransportClient>,
    control: Arc<TransportClient>,
}

#[derive(Default)]
struct TransportClient {
    connections: tokio::sync::Mutex<HashMap<String, Vec<Arc<Connection>>>>,
    h3_connections: Mutex<HashMap<String, Arc<crate::H3Conn>>>,
    available: Arc<tokio::sync::Notify>,
}

impl crate::xmux::XmuxConnection for TransportClient {
    fn is_closed(&self) -> bool { false }
}

enum RequestClient {
    Control(Arc<TransportClient>),
    Session(Arc<crate::xmux::XmuxLease<TransportClient>>),
}

impl std::ops::Deref for RequestClient {
    type Target = TransportClient;
    fn deref(&self) -> &Self::Target {
        match self { Self::Control(client) => client, Self::Session(lease) => lease.connection() }
    }
}

impl std::ops::Deref for ServiceHttp {
    type Target = ServiceShared;
    fn deref(&self) -> &Self::Target { &self.shared }
}

impl Clone for ServiceHttp {
    fn clone(&self) -> Self {
        Self { shared: self.shared.clone(), selected: Some(Mutex::new(None)), concurrency: self.concurrency, active: Mutex::new(0), available: Condvar::new() }
    }
}

struct Permit<'a>(&'a ServiceHttp);
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.active.lock().expect("storage concurrency") -= 1;
        self.0.available.notify_one();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Redirects {
    Follow,
    Disabled,
}

enum Connection {
    H1(tokio::sync::Mutex<http1::SendRequest<Full<Bytes>>>, std::sync::atomic::AtomicBool),
    H2(http2::SendRequest<Full<Bytes>>),
}

struct ConnectionLease {
    connection: Arc<Connection>,
    available: Arc<tokio::sync::Notify>,
}
impl std::ops::Deref for ConnectionLease {
    type Target = Connection;
    fn deref(&self) -> &Connection { &self.connection }
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if let Connection::H1(_, occupied) = &*self.connection { occupied.store(false, std::sync::atomic::Ordering::Release); }
        self.available.notify_waiters();
    }
}

struct SendFailure { error: io::Error, unsent: bool }
impl From<io::Error> for SendFailure {
    fn from(error: io::Error) -> Self { Self { error, unsent: false } }
}
impl SendFailure {
    fn unsent(error: hyper::Error) -> Self { Self { error: io::Error::other(error), unsent: true } }
    fn dispatch<T>(error: hyper::client::conn::TrySendError<T>) -> Self {
        Self { unsent: error.message().is_some(), error: io::Error::other(error.into_error()) }
    }
}

impl ServiceHttp {
    #[cfg(test)]
    pub fn new(options: XdriveHttpOptions, redirects: Redirects) -> io::Result<Self> {
        let config = crate::xmux::XmuxConfig::xdrive(None, false, options.quic.is_some())?;
        Self::configured(options, redirects, config, 32)
    }

    pub fn configured(options: XdriveHttpOptions, redirects: Redirects, xmux: crate::xmux::XmuxConfig, concurrency: usize) -> io::Result<Self> {
        let tls = match &options.tls {
            Some(config) => config.clone(),
            None => crate::advanced_client_config(&crate::AdvancedTlsOptions {
                alpn: vec!["h2".into(), "http/1.1".into()],
                ..Default::default()
            })?,
        };
        Ok(Self {
            shared: Arc::new(ServiceShared { options, tls, redirects, pool: crate::xmux::XmuxPool::new(xmux.clone()), xmux, control: Arc::default() }),
            selected: None,
            concurrency,
            active: Mutex::new(0),
            available: Condvar::new(),
        })
    }

    fn permit(&self) -> Permit<'_> {
        let mut active = self.active.lock().expect("storage concurrency");
        while *active >= self.concurrency {
            active = self.available.wait(active).expect("storage concurrency");
        }
        *active += 1;
        Permit(self)
    }

    fn client(&self) -> io::Result<RequestClient> {
        let Some(selected) = &self.selected else { return Ok(RequestClient::Control(self.control.clone())); };
        let mut selected = selected.lock().expect("storage session transport");
        if selected.as_ref().is_none_or(|client| !client.request()) {
            let client = Arc::new(self.pool.acquire(|| Ok(TransportClient::default()))?);
            if !client.request() { return Err(io::Error::other("storage request budget exhausted")); }
            *selected = Some(client);
        }
        Ok(RequestClient::Session(selected.as_ref().expect("storage session transport").clone()))
    }

    pub fn call(
        &self,
        method: &str,
        target: &str,
        headers: &Headers,
        body: &[u8],
    ) -> io::Result<HttpReply> {
        let _permit = self.permit();
        let mut url = Url::parse(target).map_err(|_| invalid("XDrive storage URL"))?;
        let mut method = method;
        let mut body = body;
        let mut headers = headers.clone();
        for _ in 0..10 {
            let reply = self.request(method, &url, &headers, body)?;
            if self.redirects == Redirects::Disabled
                || !matches!(reply.status, 301 | 302 | 303 | 307 | 308)
            {
                return Ok(reply);
            }
            let Some(location) = reply.headers.get(header::LOCATION) else {
                return Ok(reply);
            };
            let location = location
                .to_str()
                .map_err(|_| invalid("XDrive redirect location"))?;
            let next = url
                .join(location)
                .map_err(|_| invalid("XDrive redirect location"))?;
            if url.host() != next.host()
                || url.port_or_known_default() != next.port_or_known_default()
                || url.scheme() != next.scheme()
            {
                headers.retain(|name, _| {
                    !matches!(
                        name.to_ascii_lowercase().as_str(),
                        "authorization" | "www-authenticate" | "cookie" | "cookie2" | "host"
                    )
                });
            }
            if matches!(reply.status, 301..=303) && !matches!(method, "GET" | "HEAD") {
                method = "GET";
                body = &[];
                headers.remove("content-length");
            }
            url = next;
        }
        Err(invalid("too many XDrive storage redirects"))
    }

    fn request(
        &self,
        method: &str,
        url: &Url,
        headers: &Headers,
        body: &[u8],
    ) -> io::Result<HttpReply> {
        if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
            return Err(invalid("XDrive storage URL must be HTTP(S)"));
        }
        let authority = &url[Position::BeforeHost..Position::AfterPort];
        let key = format!("{}://{authority}", url.scheme());
        let client = self.client()?;
        let mut headers = headers.clone();
        if !url.username().is_empty()
            && !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("authorization"))
        {
            let user = percent_decode_str(url.username()).decode_utf8_lossy();
            let password = percent_decode_str(url.password().unwrap_or("")).decode_utf8_lossy();
            headers.insert(
                "authorization".into(),
                format!("Basic {}", STANDARD.encode(format!("{user}:{password}"))),
            );
        }
        if url.scheme() == "https"
            && self.options.quic.is_some()
        {
            return self.h3(&client, &key, method, url, &headers, body);
        }
        let run = async {
            let conn = self.connection(&client, &key, url).await?;
            let result = Self::send(&conn, method, url, authority, &headers, body).await;
            if result.as_ref().map_or(true, HttpReply::closes_connection) {
                self.forget(&client, &key, &conn.connection).await;
            }
            match result {
                Err(error) if error.unsent => {
                    let conn = self.connection(&client, &key, url).await?;
                    let result = Self::send(&conn, method, url, authority, &headers, body).await;
                    if result.as_ref().map_or(true, HttpReply::closes_connection) { self.forget(&client, &key, &conn.connection).await; }
                    result.map_err(|error| error.error)
                }
                result => result.map_err(|error| error.error),
            }
        };
        runtime()?.block_on(async { timeout(HTTP_TIMEOUT, run).await.map_err(|_| timed_out())? })
    }

    fn h3(
        &self,
        client: &TransportClient,
        key: &str,
        method: &str,
        url: &Url,
        headers: &Headers,
        body: &[u8],
    ) -> io::Result<HttpReply> {
        let authority = &url[Position::BeforeHost..Position::AfterPort];
        let cached = client
            .h3_connections
            .lock()
            .expect("XDrive HTTP/3 pool")
            .get(key)
            .cloned();
        let connection = match cached {
            Some(connection) => connection,
            None => {
                let (host, port, name) = self.endpoint(url);
                let mut last = io::Error::new(
                    io::ErrorKind::NotFound,
                    "XDrive HTTP/3 endpoint resolved no address",
                );
                let mut connected = None;
                let endpoints = if let Some(network) = self.options.masks.network() {
                    let (network, peer) = network.endpoint(host, port)?;
                    vec![(peer, self.options.masks.clone().with_network(network))]
                } else {
                    (host, port).to_socket_addrs()?.map(|peer| (peer, self.options.masks.clone())).collect()
                };
                for (remote, masks) in endpoints {
                    let options = crate::QuicOptions::parse(self.options.masks.quic_params())?;
                    match crate::H3Conn::connect_crypto_with_options(remote, self.options.quic.as_ref().expect("HTTP/3 config").clone(), name, &masks, &options, crate::QuicCarrier::Xdrive, self.xmux.keepalive_seconds) {
                        Ok(connection) => {
                            connected = Some(Arc::new(connection));
                            break;
                        }
                        Err(error) => last = error,
                    }
                }
                let connection = connected.ok_or(last)?;
                client.h3_connections
                    .lock()
                    .expect("XDrive HTTP/3 pool")
                    .insert(key.into(), connection.clone());
                connection
            }
        };
        let response = (|| {
            let authority = headers.get("host").map_or(authority, String::as_str);
            let extra = headers
                .iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            let mut stream = connection.request(
                method,
                &url[Position::BeforePath..Position::AfterQuery],
                authority,
                "https",
                &extra,
                false,
            )?;
            stream.set_timeout(HTTP_TIMEOUT);
            stream.write_all(body)?;
            stream.finish_write()?;
            let status = stream.response_status()?;
            let mut headers = HeaderMap::new();
            for name in [header::RETRY_AFTER, header::LOCATION] {
                if let Some(value) = stream
                    .header(name.as_str())
                    .and_then(|value| http::HeaderValue::from_str(&value).ok())
                {
                    headers.insert(name, value);
                }
            }
            let mut body = Vec::new();
            stream
                .take((MAX_RESPONSE + 1) as u64)
                .read_to_end(&mut body)?;
            if body.len() > MAX_RESPONSE {
                return Err(invalid("XDrive HTTP response too large"));
            }
            Ok(HttpReply {
                status,
                body,
                headers,
            })
        })();
        if response.is_err() {
            let mut pool = client.h3_connections.lock().expect("XDrive HTTP/3 pool");
            if pool
                .get(key)
                .is_some_and(|prior| Arc::ptr_eq(prior, &connection))
            {
                pool.remove(key);
            }
        }
        response
    }

    fn endpoint<'a>(&'a self, url: &'a Url) -> (&'a str, u16, &'a str) {
        let port = url.port_or_known_default().expect("HTTP port");
        let host = url.host_str().expect("HTTP host").trim_matches(['[', ']']);
        let (connect_host, connect_port) =
            self.options
                .connect_to
                .as_ref()
                .map_or((host, port), |(addr, requested)| {
                    (
                        addr.as_str(),
                        if *requested == 0 { port } else { *requested },
                    )
                });
        (
            connect_host,
            connect_port,
            self.options.server_name.as_deref().unwrap_or(host),
        )
    }

    async fn connection(&self, client: &TransportClient, key: &str, url: &Url) -> io::Result<ConnectionLease> {
        loop {
        let notified = client.available.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let mut pool = client.connections.lock().await;
        let connections = pool.entry(key.to_owned()).or_default();
        connections.retain(|conn| !conn.closed());
        if let Some(conn) = connections.iter().find(|conn| match &***conn {
            Connection::H2(_) => true,
            Connection::H1(_, occupied) => occupied.compare_exchange(false, true, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire).is_ok(),
        }) {
            return Ok(ConnectionLease { connection: conn.clone(), available: client.available.clone() });
        }
        if connections.len() >= self.concurrency {
            drop(pool);
            notified.await;
            continue;
        }
        let (connect_host, connect_port, name) = self.endpoint(url);
        let connection = if let Some(network) = self.options.masks.network() {
            let network = network.clone();
            let host = connect_host.to_owned();
            tokio::task::spawn_blocking(move || network.tcp(&host, connect_port)).await.map_err(io::Error::other)??
        } else {
            let socket = TcpStream::connect((connect_host, connect_port)).await?;
            socket.set_nodelay(true)?;
            kerlico_shared::runtime::NetworkConnection::Tcp(socket.into_std()?)
        };
        let (local, peer) = match &connection {
            kerlico_shared::runtime::NetworkConnection::Tcp(socket) => (socket.local_addr()?, socket.peer_addr()?),
            _ => ("0.0.0.0:0".parse().expect("logical local"), std::net::SocketAddr::new(connect_host.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into()), connect_port)),
        };
        let stream = crate::tls_async::connect_async_network(connection, (url.scheme() == "https").then(|| self.tls.clone()), name, &self.options.masks, local, peer).await?;
        let h2 = stream.alpn().as_deref() == Some(b"h2");
        let io = TokioIo::new(stream);
        let conn = if h2 {
            let keepalive = match self.xmux.keepalive_seconds { 0 => Some(Duration::from_secs(45)), n if n > 0 => Some(Duration::from_secs(n as u64)), _ => None };
            let (sender, driver) = http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .keep_alive_interval(keepalive)
                .keep_alive_timeout(Duration::from_secs(15))
                .keep_alive_while_idle(true)
                .handshake(io)
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(driver);
            Connection::H2(sender)
        } else {
            let (sender, driver) = http1::handshake(io).await.map_err(io::Error::other)?;
            tokio::spawn(driver);
            Connection::H1(tokio::sync::Mutex::new(sender), std::sync::atomic::AtomicBool::new(true))
        };
        let conn = Arc::new(conn);
        connections.push(conn.clone());
        return Ok(ConnectionLease { connection: conn, available: client.available.clone() });
        }
    }

    async fn forget(&self, client: &TransportClient, key: &str, conn: &Arc<Connection>) {
        let mut pool = client.connections.lock().await;
        if let Some(connections) = pool.get_mut(key) {
            connections.retain(|prior| !Arc::ptr_eq(prior, conn));
            if connections.is_empty() { pool.remove(key); }
        }
    }

    async fn send(
        conn: &Connection,
        method: &str,
        url: &Url,
        authority: &str,
        headers: &Headers,
        body: &[u8],
    ) -> Result<HttpReply, SendFailure> {
        let path = &url[Position::BeforePath..Position::AfterQuery];
        let uri = if matches!(conn, Connection::H2(_)) {
            format!("{}://{authority}{path}", url.scheme())
        } else {
            path.to_owned()
        };
        let mut request = Request::builder().method(method).uri(uri);
        if !headers.keys().any(|name| name.eq_ignore_ascii_case("host")) {
            request = request.header(header::HOST, authority);
        }
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let request = request
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(invalid)?;
        match conn {
            Connection::H1(sender, _) => {
                let mut sender = sender.lock().await;
                sender.ready().await.map_err(SendFailure::unsent)?;
                read_response(
                    sender
                        .try_send_request(request)
                        .await
                        .map_err(SendFailure::dispatch)?,
                )
                .await.map_err(Into::into)
            }
            Connection::H2(sender) => {
                let mut sender = sender.clone();
                sender.ready().await.map_err(SendFailure::unsent)?;
                read_response(
                    sender
                        .try_send_request(request)
                        .await
                        .map_err(SendFailure::dispatch)?,
                )
                .await.map_err(Into::into)
            }
        }
    }
}

impl Connection {
    fn closed(&self) -> bool {
        match self {
            Self::H1(sender, _) => sender.try_lock().is_ok_and(|sender| sender.is_closed()),
            Self::H2(sender) => sender.is_closed(),
        }
    }
}

async fn read_response(response: http::Response<Incoming>) -> io::Result<HttpReply> {
    let (head, mut incoming) = response.into_parts();
    let mut body = Vec::new();
    while let Some(frame) = incoming.frame().await {
        if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
            if body.len() + data.len() > MAX_RESPONSE {
                return Err(invalid("XDrive HTTP response too large"));
            }
            body.extend_from_slice(&data);
        }
    }
    Ok(HttpReply {
        status: head.status.as_u16(),
        body,
        headers: head.headers,
    })
}

fn runtime() -> io::Result<&'static Runtime> {
    static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| io::Error::other(error.clone()))
}
