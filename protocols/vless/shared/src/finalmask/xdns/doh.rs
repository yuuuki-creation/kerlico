use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::{http1, http2};
use percent_encoding::percent_decode_str;
use serde_json::Value;
use tokio::sync::{mpsc as async_mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use url::{Position, Url};

use crate::{H3Conn, TlsNetwork};

use super::super::http_tls::{runtime, HttpConnection, TlsClient, TlsUsage};
use super::super::{copy_packet, invalid, malformed, FinalMask, UDP_SIZE};
use super::resolver::Resolver;
use super::POLL;

const DNS_MESSAGE: &str = "application/dns-message";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const REPLY_QUEUE: usize = 128;

pub(super) fn open(
    url: Url,
    workers: u16,
    tls: Value,
    quic: Option<Value>,
    network: Option<Arc<dyn TlsNetwork>>,
    carrier: Option<Arc<crate::runtime::CarrierNetwork>>,
    cache: Option<Arc<crate::AdvancedTlsClientCache>>,
) -> io::Result<Arc<dyn Resolver>> {
    let endpoint = Arc::new(HttpEndpoint::parse(url, tls, quic, network, carrier, cache)?);
    let workers = usize::from(workers);
    let (send, queries) =
        async_mpsc::channel((workers.clamp(1, 256) * 2).max(usize::from(u8::MAX)));
    let (answers, read) = mpsc::sync_channel(REPLY_QUEUE);
    let (stop, closed) = watch::channel(false);
    runtime()?.spawn(run(endpoint, workers, queries, answers, closed));
    Ok(Arc::new(Doh {
        send,
        read: Mutex::new(read),
        stop,
    }))
}

struct Doh {
    send: async_mpsc::Sender<Vec<u8>>,
    read: Mutex<mpsc::Receiver<Vec<u8>>>,
    stop: watch::Sender<bool>,
}

impl Resolver for Doh {
    fn send(&self, query: &[u8]) -> io::Result<()> {
        self.send
            .try_send(query.to_vec())
            .map_err(|error| match error {
                async_mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                async_mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe.into(),
            })
    }

    fn recv(&self, reply: &mut [u8], _: &AtomicBool) -> io::Result<usize> {
        match self
            .read
            .lock()
            .expect("XDNS DoH replies")
            .recv_timeout(POLL)
        {
            Ok(packet) => Ok(copy_packet(reply, &packet)),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::WouldBlock.into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn close(&self) {
        self.stop.send_replace(true);
    }
}

async fn run(
    endpoint: Arc<HttpEndpoint>,
    workers: usize,
    mut queries: async_mpsc::Receiver<Vec<u8>>,
    answers: mpsc::SyncSender<Vec<u8>>,
    mut closed: watch::Receiver<bool>,
) {
    let mut work = JoinSet::new();
    loop {
        tokio::select! {
            _ = closed.changed() => break,
            query = queries.recv(), if work.len() < workers => {
                let Some(query) = query else { break; };
                let endpoint = endpoint.clone();
                work.spawn(async move { endpoint.query(query).await });
            }
            ready = work.join_next(), if !work.is_empty() => {
                if let Some(Ok(Ok(reply))) = ready {
                    let _ = answers.try_send(reply);
                }
            }
        }
    }
}

struct HttpEndpoint {
    host: String,
    port: u16,
    path: String,
    authority: String,
    auth: Option<String>,
    tls: TlsClient,
    protocol: Protocol,
    cooldown: Mutex<Option<Instant>>,
    carrier: Option<Arc<crate::runtime::CarrierNetwork>>,
}

enum Protocol {
    H12(tokio::sync::Mutex<Pool>),
    H3 {
        conn: Mutex<Option<Arc<H3Conn>>>,
        quic: FinalMask,
    },
}

type H1Sender = http1::SendRequest<Full<Bytes>>;
type H2Sender = http2::SendRequest<Full<Bytes>>;

#[derive(Default)]
struct Pool {
    h1: Vec<H1Sender>,
    h2: Option<Arc<H2Sender>>,
}

impl HttpEndpoint {
    fn parse(
        url: Url,
        tls: Value,
        quic: Option<Value>,
        network: Option<Arc<dyn TlsNetwork>>,
        carrier: Option<Arc<crate::runtime::CarrierNetwork>>,
        cache: Option<Arc<crate::AdvancedTlsClientCache>>,
    ) -> io::Result<Self> {
        let host = url
            .host_str()
            .ok_or_else(|| invalid("XDNS DoH endpoint has no host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url.port().unwrap_or(443);
        let tls = TlsClient::parse(tls, &host, TlsUsage::Doh, network, cache.as_deref())?;
        let protocol = if tls.h3() {
            let config = quic
                .map(|settings| serde_json::json!({ "quicParams": settings }).to_string())
                .unwrap_or_default();
            Protocol::H3 {
                conn: Mutex::new(None),
                quic: {
                    let masks = FinalMask::parse(&config)?;
                    if let Some(carrier) = &carrier { masks.with_network(carrier.clone()) } else { masks }
                },
            }
        } else {
            if quic.is_some() {
                return Err(invalid("XDNS DoH quicConfig requires h3 ALPN"));
            }
            Protocol::H12(tokio::sync::Mutex::new(Pool::default()))
        };
        let auth = if url.username().is_empty() {
            None
        } else {
            let user = percent_decode_str(url.username())
                .decode_utf8()
                .map_err(invalid)?;
            let pass = percent_decode_str(url.password().unwrap_or(""))
                .decode_utf8()
                .map_err(invalid)?;
            Some(format!(
                "Basic {}",
                STANDARD.encode(format!("{user}:{pass}"))
            ))
        };
        Ok(Self {
            host,
            port,
            authority: url[Position::BeforeHost..Position::AfterPort].to_owned(),
            path: url[Position::BeforePath..Position::AfterQuery].to_owned(),
            tls,
            auth,
            protocol,
            cooldown: Mutex::new(None),
            carrier,
        })
    }

    async fn query(self: Arc<Self>, packet: Vec<u8>) -> io::Result<Vec<u8>> {
        if self
            .cooldown
            .lock()
            .expect("XDNS DoH cooldown")
            .is_some_and(|until| until > Instant::now())
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let operation = async {
            match &self.protocol {
                Protocol::H12(pool) => self.query_tcp(pool, &packet).await,
                Protocol::H3 { .. } => {
                    let this = self.clone();
                    tokio::task::spawn_blocking(move || this.query_h3(&packet))
                        .await
                        .map_err(io::Error::other)?
                }
            }
        };
        timeout(REQUEST_TIMEOUT, operation)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    async fn query_tcp(
        &self,
        pool: &tokio::sync::Mutex<Pool>,
        packet: &[u8],
    ) -> io::Result<Vec<u8>> {
        for attempt in 0..2 {
            let (mut conn, shared) = self.take(pool).await?;
            let uri = if conn.h2() {
                format!("https://{}{}", self.authority, self.path)
            } else {
                self.path.clone()
            };
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::HOST, &self.authority)
                .header(header::ACCEPT, DNS_MESSAGE)
                .header(header::CONTENT_TYPE, DNS_MESSAGE);
            if let Some(auth) = &self.auth {
                request = request.header(header::AUTHORIZATION, auth);
            }
            let request = request
                .body(Full::new(Bytes::copy_from_slice(packet)))
                .map_err(io::Error::other)?;
            match conn.request(request).await {
                Ok(response) => {
                    let status = response.status();
                    let retry = response
                        .headers()
                        .get(header::RETRY_AFTER)
                        .and_then(|header| header.to_str().ok());
                    self.status(status, retry)?;
                    let mut body = response.into_body();
                    let mut answer = Vec::new();
                    while let Some(frame) = body.frame().await {
                        if let Ok(bytes) = frame.map_err(io::Error::other)?.into_data() {
                            if answer.len() + bytes.len() > UDP_SIZE {
                                return Err(malformed("XDNS DoH response exceeds 4096 bytes"));
                            }
                            answer.extend_from_slice(&bytes);
                        }
                    }
                    if let HttpConnection::H1(send) = conn {
                        if !send.is_closed() {
                            let mut pool = pool.lock().await;
                            if pool.h1.len() < 64 {
                                pool.h1.push(send);
                            }
                        }
                    }
                    return Ok(answer);
                }
                Err(error) => {
                    if let Some(shared) = shared {
                        let mut pool = pool.lock().await;
                        if pool
                            .h2
                            .as_ref()
                            .is_some_and(|conn| Arc::ptr_eq(conn, &shared))
                        {
                            pool.h2 = None;
                        }
                    }
                    if attempt == 1 {
                        return Err(error);
                    }
                }
            }
        }
        unreachable!("DoH TCP connection retries")
    }

    async fn take(
        &self,
        pool: &tokio::sync::Mutex<Pool>,
    ) -> io::Result<(HttpConnection, Option<Arc<H2Sender>>)> {
        {
            let mut pool = pool.lock().await;
            if let Some(send) = pool.h2.as_ref() {
                return Ok((HttpConnection::H2((**send).clone()), Some(send.clone())));
            }
            if let Some(send) = pool.h1.pop() {
                return Ok((HttpConnection::H1(send), None));
            }
        }
        match HttpConnection::connect(&self.host, self.port, Some(&self.tls), self.carrier.as_deref()).await? {
            HttpConnection::H2(send) => {
                let mut pool = pool.lock().await;
                let owner = pool.h2.get_or_insert_with(|| Arc::new(send)).clone();
                Ok((HttpConnection::H2((*owner).clone()), Some(owner)))
            }
            h1 => Ok((h1, None)),
        }
    }

    fn query_h3(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let Protocol::H3 { conn: cache, quic } = &self.protocol else {
            return Err(invalid("XDNS DoH HTTP/3 configuration"));
        };
        let conn = {
            let mut cache = cache.lock().expect("XDNS DoH HTTP/3 connection");
            if let Some(conn) = cache.as_ref() {
                conn.clone()
            } else {
                let conn = self.h3_connect(quic)?;
                *cache = Some(conn.clone());
                conn
            }
        };
        let mut headers = vec![("accept", DNS_MESSAGE), ("content-type", DNS_MESSAGE)];
        if let Some(auth) = &self.auth {
            headers.push(("authorization", auth));
        }
        let exchange = (|| {
            let mut stream = conn.request(
                "POST",
                &self.path,
                &self.authority,
                "https",
                &headers,
                false,
            )?;
            stream.set_timeout(REQUEST_TIMEOUT);
            stream.write_all(packet)?;
            stream.finish_write()?;
            let status =
                StatusCode::from_u16(stream.response_status()?).map_err(io::Error::other)?;
            let retry = stream.header("retry-after");
            self.status(status, retry.as_deref())?;
            let mut answer = Vec::new();
            stream
                .take((UDP_SIZE + 1) as u64)
                .read_to_end(&mut answer)?;
            if answer.len() > UDP_SIZE {
                return Err(malformed("XDNS DoH response exceeds 4096 bytes"));
            }
            Ok(answer)
        })();
        if exchange.is_err() {
            let mut cache = cache.lock().expect("XDNS DoH HTTP/3 connection");
            if cache
                .as_ref()
                .is_some_and(|cached| Arc::ptr_eq(cached, &conn))
            {
                *cache = None;
            }
        }
        exchange
    }

    fn h3_connect(&self, masks: &FinalMask) -> io::Result<Arc<H3Conn>> {
        if let Some(carrier) = &self.carrier {
            let (carrier, remote) = carrier.endpoint(&self.host, self.port)?;
            let masks = masks.clone().with_network(carrier);
            let (config, name) = self.tls.quic()?;
            return H3Conn::connect_crypto_masked(remote, config, name, &masks).map(Arc::new);
        }
        let mut last = io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "XDNS DoH resolver has no IP address",
        );
        let (config, name) = self.tls.quic()?;
        let addresses: Vec<SocketAddr> = (self.host.as_str(), self.port).to_socket_addrs()?.collect();
        for remote in addresses {
            match H3Conn::connect_crypto_masked(remote, config.clone(), name, masks) {
                Ok(conn) => return Ok(Arc::new(conn)),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    fn status(&self, status: StatusCode, retry: Option<&str>) -> io::Result<()> {
        if status == StatusCode::OK {
            return Ok(());
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            let delay = retry.and_then(|value| {
                value
                    .parse::<u32>()
                    .ok()
                    .map(|n| Duration::from_secs(u64::from(n)))
                    .or_else(|| {
                        httpdate::parse_http_date(value)
                            .ok()?
                            .duration_since(SystemTime::now())
                            .ok()
                    })
            });
            if let Some(until) = delay.and_then(|delay| Instant::now().checked_add(delay)) {
                let mut cooldown = self.cooldown.lock().expect("XDNS DoH cooldown");
                if cooldown.is_none_or(|current| current < until) {
                    *cooldown = Some(until);
                }
            }
        }
        Err(io::Error::other(format!(
            "XDNS DoH HTTP status {}",
            status.as_u16()
        )))
    }
}
