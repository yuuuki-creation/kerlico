use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use super::cases::{Security, TLS_NAME};
use super::support::{localhost, Result, TIMEOUT};

const SECRET: &str = "mock-storage-secret";
const ACCESS: &str = "mock-storage-access";
const TOKEN: &str = "mock-storage-token";
const FOLDER: &str = "matrix-fixture";
const BUCKET: &str = "matrix-bucket";
const MAX_BODY: usize = 2 * 1024 * 1024;
const STORAGE_HEADERS: &[&str] = &[
    "authorization",
    "content-type",
    "x-amz-content-sha256",
    "x-amz-date",
    "x-amz-security-token",
];

type Headers = BTreeMap<String, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Service {
    Template,
    S3 { virtual_host: bool },
    Drive,
}

impl Service {
    pub fn config(self, addr: SocketAddr, security: Security) -> Value {
        let base = format!("{}://{addr}", scheme(security));
        let mut config = match self {
            Self::Template => json!({
                "service": "template", "remoteFolder": FOLDER, "secrets": [SECRET],
                "template": {
                    "flatten": true,
                    "auth": {"type": "oauth2", "tokenUrl": format!("{base}/template/token"),
                        "form": {"client_secret": "{secret0}"},
                        "header": {"Authorization": "Bearer {token}"}},
                    "put": {"url": format!("{base}/template/resolve/{{name}}"),
                        "hrefPath": "href", "hrefMethod": "PUT"},
                    "get": {"url": format!("{base}/template/objects/{{name}}")},
                    "delete": {"method": "DELETE", "url": format!("{base}/template/objects/{{name}}")},
                    "list": {"url": format!("{base}/template/list/{{prefix}}"), "namesRegex": "name=([^\\n]+)"},
                },
            }),
            Self::S3 { virtual_host } => {
                let endpoint = if virtual_host {
                    format!("{}://storage.test/s3", scheme(security))
                } else {
                    format!("{base}/s3")
                };
                json!({
                    "service": "s3", "remoteFolder": FOLDER, "secrets": [ACCESS, SECRET, TOKEN],
                    "s3": {"endpoint": endpoint, "bucket": BUCKET, "region": "us-east-1", "pathStyle": !virtual_host},
                })
            }
            Self::Drive => {
                json!({"service": "google-drive", "remoteFolder": FOLDER, "secrets": [ACCESS, SECRET, TOKEN]})
            }
        };
        config["segmentBytes"] = json!(24_576);
        config["concurrency"] = json!(2);
        config["flushIntervalMs"] = json!(10);
        config["pollIntervalMs"] = json!(10);
        config["maxPollIntervalMs"] = json!(100);
        config
    }
}

fn scheme(security: Security) -> &'static str {
    if matches!(security, Security::Tls(_)) {
        "https"
    } else {
        "http"
    }
}

pub(super) struct Mock {
    pub addr: SocketAddr,
    state: Arc<Mutex<Storage>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    h3: bool,
}

impl Mock {
    pub fn start(
        service: Service,
        security: Security,
        certificate: &str,
        key: &str,
    ) -> Result<Self> {
        let tls = match security {
            Security::Tls(alpn) => Some(
                kerlico_vless::server_config(certificate, key, &[alpn.into()])
                    .map_err(|_| "XDrive mock TLS configuration")?,
            ),
            _ => None,
        };
        let state = Arc::new(Mutex::new(Storage::new(service, security)));
        let stop = Arc::new(AtomicBool::new(false));
        let serving = state.clone();
        let stopped = stop.clone();
        let h3 = matches!(security, Security::Tls("h3"));
        let (addr, worker) = if h3 {
            let listener =
                kerlico_vless::H3Listener::bind(localhost(0).into(), tls.expect("H3 TLS"))?;
            let addr = listener.local_addr()?;
            let worker = thread::spawn(move || {
                while let Ok((_, stream)) = listener.accept() {
                    if stopped.load(Ordering::Relaxed) {
                        stream.set_timeout(Duration::from_secs(1));
                        let _ = stream
                            .reply_with(204, &[])
                            .and_then(|_| stream.finish_write());
                        break;
                    }
                    let serving = serving.clone();
                    thread::spawn(move || {
                        let _ = serve_h3(stream, addr, &serving);
                    });
                }
            });
            (addr, worker)
        } else if matches!(security, Security::Tls("h2")) {
            let listener = TcpListener::bind(localhost(0))?;
            let addr = listener.local_addr()?;
            listener.set_nonblocking(true)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let acceptor = TlsAcceptor::from(tls.expect("H2 TLS"));
            let worker = thread::spawn(move || {
                runtime.block_on(serve_h2(listener, acceptor, stopped, addr, serving));
            });
            (addr, worker)
        } else {
            let listener = TcpListener::bind(localhost(0))?;
            let addr = listener.local_addr()?;
            listener.set_nonblocking(true)?;
            let worker = thread::spawn(move || {
                while !stopped.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            let tls = tls.clone();
                            let serving = serving.clone();
                            thread::spawn(move || {
                                let _ = socket.set_nonblocking(false);
                                let _ = socket.set_nodelay(true);
                                let _ = socket.set_read_timeout(Some(TIMEOUT));
                                let _ = socket.set_write_timeout(Some(TIMEOUT));
                                if let Some(tls) = tls {
                                    if let Ok(stream) = kerlico_vless::accept_tls(socket, tls) {
                                        let _ = serve_h1(stream, addr, &serving);
                                    }
                                } else {
                                    let _ = serve_h1(socket, addr, &serving);
                                }
                            });
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(_) => break,
                    }
                }
            });
            (addr, worker)
        };
        Ok(Self {
            addr,
            state,
            stop,
            worker: Some(worker),
            h3,
        })
    }

    pub fn verify(&self, large_stream: bool) -> Result<()> {
        let state = self.state.lock().expect("mock storage");
        let trace = &state.trace;
        eprintln!("XDRIVE {:?} {:?}", state.service, trace);
        if let Some(error) = &state.error {
            return Err(error.clone().into());
        }
        if trace.announce == 0 || trace.uplink == 0 || trace.downlink == 0 || trace.lists == 0 {
            return Err("XDrive did not use both directions of mock storage".into());
        }
        if matches!(state.service, Service::Template | Service::Drive) && trace.tokens < 2 {
            return Err("XDrive peers did not both authenticate to mock storage".into());
        }
        if matches!(state.service, Service::S3 { .. }) && trace.signed == 0 {
            return Err("XDrive S3 made no validated signed requests".into());
        }
        if state.service == Service::Drive
            && (trace.slot_updates == 0
                || trace.watermarks == 0
                || large_stream && (trace.slot_reused == 0 || trace.media == 0))
        {
            return Err("XDrive Google Drive did not exercise expected ring storage".into());
        }
        Ok(())
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let wake = if self.h3 {
            (|| -> Result<()> {
                let tls = kerlico_vless::client_config(&["h3".into()], true)
                    .map_err(|_| "H3 mock wake")?;
                let conn = kerlico_vless::H3Conn::connect(self.addr, tls, TLS_NAME)?;
                let request = conn.request("GET", "/stop", TLS_NAME, "https", &[], false)?;
                request.set_timeout(Duration::from_secs(1));
                request.finish_write()?;
                request.response_status()?;
                Ok(())
            })()
            .is_ok()
        } else {
            true
        };
        if wake {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
        if let Some(error) = &self.state.lock().expect("mock storage").error {
            eprintln!("XDRIVE mock rejection {error}");
        }
    }
}

struct Request {
    method: String,
    target: String,
    headers: Headers,
    body: Vec<u8>,
}

impl Request {
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    fn args(&self) -> std::result::Result<Headers, String> {
        let query = self.target.split_once('?').map_or("", |(_, query)| query);
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| Ok((unescape(key, true)?, unescape(value, true)?)))
            .collect()
    }

    fn header(&self, key: &str) -> &str {
        self.headers.get(key).map_or("", String::as_str)
    }
}

type Reply = (u16, Vec<u8>);

fn serve_h1(
    mut stream: impl Read + Write,
    addr: SocketAddr,
    state: &Mutex<Storage>,
) -> io::Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let mut words = line.split_whitespace();
    let method = words.next().unwrap_or("").to_owned();
    let target = words.next().unwrap_or("").to_owned();
    let mut headers = Headers::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::other("mock HTTP header"))?;
        headers.insert(name.to_ascii_lowercase(), value.trim().into());
    }
    let size = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(io::Error::other)?
        .unwrap_or(0);
    if size > MAX_BODY || headers.contains_key("transfer-encoding") {
        return Err(io::Error::other("mock requires a bounded Content-Length"));
    }
    let mut body = vec![0; size];
    reader.read_exact(&mut body)?;
    let (status, body) = state.lock().expect("mock storage").reply(
        addr,
        Request {
            method,
            target,
            headers,
            body,
        },
    );
    write!(
        stream,
        "HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

fn serve_h3(
    mut stream: kerlico_vless::H3Stream,
    addr: SocketAddr,
    state: &Mutex<Storage>,
) -> io::Result<()> {
    stream.set_timeout(TIMEOUT);
    let method = stream.header(":method").unwrap_or_default();
    let target = stream.header(":path").unwrap_or_default();
    let mut headers = Headers::new();
    for &key in STORAGE_HEADERS {
        if let Some(value) = stream.header(key) {
            headers.insert(key.into(), value);
        }
    }
    headers.insert(
        "host".into(),
        stream.header(":authority").unwrap_or_default(),
    );
    let mut body = Vec::new();
    (&mut stream)
        .take((MAX_BODY + 1) as u64)
        .read_to_end(&mut body)?;
    if body.len() > MAX_BODY {
        return Err(io::Error::other("mock HTTP/3 body too large"));
    }
    let (status, body) = state.lock().expect("mock storage").reply(
        addr,
        Request {
            method,
            target,
            headers,
            body,
        },
    );
    stream.reply_with(status, &[])?;
    if !body.is_empty() {
        stream.write_all(&body)?;
    }
    stream.finish_write()
}

async fn serve_h2(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
    storage: Arc<Mutex<Storage>>,
) {
    let listener = tokio::net::TcpListener::from_std(listener).expect("mock HTTP/2 listener");
    while !stop.load(Ordering::Relaxed) {
        let (socket, _) = match timeout(Duration::from_millis(20), listener.accept()).await {
            Ok(Ok(socket)) => socket,
            Ok(Err(_)) => return,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let storage = storage.clone();
        tokio::spawn(async move {
            let Ok(Ok(stream)) = timeout(TIMEOUT, acceptor.accept(socket)).await else {
                return;
            };
            if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                return;
            }
            let service = service_fn(move |request| handle_h2(request, addr, storage.clone()));
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn handle_h2(
    request: hyper::Request<Incoming>,
    addr: SocketAddr,
    storage: Arc<Mutex<Storage>>,
) -> io::Result<hyper::Response<Full<Bytes>>> {
    let (head, body) = request.into_parts();
    let mut headers = Headers::new();
    for &key in STORAGE_HEADERS {
        if let Some(value) = head.headers.get(key).and_then(|value| value.to_str().ok()) {
            headers.insert(key.into(), value.into());
        }
    }
    let authority = head
        .uri
        .authority()
        .map(|value| value.as_str())
        .unwrap_or_default();
    headers.insert("host".into(), authority.into());
    let target = head
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_default()
        .to_owned();
    let body = timeout(TIMEOUT, Limited::new(body, MAX_BODY).collect())
        .await?
        .map_err(io::Error::other)?
        .to_bytes()
        .to_vec();
    let request = Request {
        method: head.method.to_string(),
        target,
        headers,
        body,
    };
    let (status, body) = storage.lock().expect("mock storage").reply(addr, request);
    hyper::Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body)))
        .map_err(io::Error::other)
}

fn json_reply(value: Value) -> Reply {
    (200, serde_json::to_vec(&value).expect("mock JSON"))
}

fn bearer(request: &Request) -> std::result::Result<(), String> {
    if request.header("authorization") == format!("Bearer {TOKEN}") {
        Ok(())
    } else {
        Err("invalid OAuth bearer header".into())
    }
}

fn unescape(text: &str, form: bool) -> std::result::Result<String, String> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let first = bytes.next().and_then(|byte| (byte as char).to_digit(16));
                let second = bytes.next().and_then(|byte| (byte as char).to_digit(16));
                let (Some(high), Some(low)) = (first, second) else {
                    return Err("invalid URL escape".into());
                };
                out.push((high * 16 + low) as u8);
            }
            b'+' if form => out.push(b' '),
            byte => out.push(byte),
        }
    }
    String::from_utf8(out).map_err(|_| "invalid URL UTF-8".into())
}

fn verify_signature(request: &Request) -> std::result::Result<(), String> {
    let authorization = request.header("authorization");
    let attributes = authorization
        .strip_prefix("AWS4-HMAC-SHA256 Credential=")
        .ok_or("S3 authorization algorithm")?;
    let (credential, attributes) = attributes
        .split_once(", SignedHeaders=")
        .ok_or("S3 signed headers")?;
    let (signed, signature) = attributes
        .split_once(", Signature=")
        .ok_or("S3 signature")?;
    let stamp = request.header("x-amz-date");
    let date = stamp.get(..8).ok_or("S3 date")?;
    let scope = format!("{date}/us-east-1/s3/aws4_request");
    if credential != format!("{ACCESS}/{scope}") {
        return Err("S3 credential scope".into());
    }
    let digest = format!("{:x}", Sha256::digest(&request.body));
    if request.header("x-amz-content-sha256") != digest
        || request.header("x-amz-security-token") != TOKEN
    {
        return Err("S3 payload hash or session token".into());
    }
    let required = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
    let signed_put = format!("content-type;{required}");
    if signed != required && signed != signed_put {
        return Err("S3 signed header coverage".into());
    }
    let headers = signed
        .split(';')
        .map(|name| format!("{name}:{}\n", request.header(name)))
        .collect::<String>();
    let (path, query) = request
        .target
        .split_once('?')
        .unwrap_or((&request.target, ""));
    let canonical = format!(
        "{}\n{path}\n{query}\n{headers}\n{signed}\n{digest}",
        request.method
    );
    let request_hash = Sha256::digest(canonical);
    let to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{request_hash:x}");
    let mut key = hmac_sha256(format!("AWS4{SECRET}").as_bytes(), date);
    for step in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, step);
    }
    let expected = hmac_sha256(&key, &to_sign)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if signature != expected {
        return Err("S3 signature mismatch".into());
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], value: &str) -> [u8; 32] {
    assert!(key.len() <= 64, "fixture keys fit a SHA-256 block");
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for (index, byte) in key.iter().enumerate() {
        inner[index] ^= byte;
        outer[index] ^= byte;
    }
    let mut hash = Sha256::new();
    hash.update(inner);
    hash.update(value);
    let sum = hash.finalize_reset();
    hash.update(outer);
    hash.update(sum);
    hash.finalize().into()
}

fn drive_body(request: &Request) -> std::result::Result<(Value, Option<Vec<u8>>), String> {
    let content_type = request.header("content-type");
    let Some(boundary) = content_type.strip_prefix("multipart/related; boundary=") else {
        return serde_json::from_slice(&request.body)
            .map(|metadata| (metadata, None))
            .map_err(|error| error.to_string());
    };
    let begin = format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n");
    let middle = format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n");
    let end = format!("\r\n--{boundary}--\r\n");
    let parts = request
        .body
        .strip_prefix(begin.as_bytes())
        .and_then(|body| body.strip_suffix(end.as_bytes()))
        .ok_or("Drive multipart envelope")?;
    let split = parts
        .windows(middle.len())
        .position(|window| window == middle.as_bytes())
        .ok_or("Drive multipart media")?;
    let metadata = serde_json::from_slice(&parts[..split]).map_err(|error| error.to_string())?;
    Ok((metadata, Some(parts[split + middle.len()..].to_vec())))
}

#[derive(Default, Debug)]
struct Trace {
    tokens: usize,
    signed: usize,
    announce: usize,
    uplink: usize,
    downlink: usize,
    lists: usize,
    slot_updates: usize,
    slot_reused: usize,
    watermarks: usize,
    media: usize,
}

struct Storage {
    service: Service,
    security: Security,
    objects: BTreeMap<String, Vec<u8>>,
    drive: BTreeMap<String, DriveObject>,
    next_id: usize,
    trace: Trace,
    error: Option<String>,
}

struct DriveObject {
    name: String,
    description: String,
    body: Vec<u8>,
    updates: usize,
}

impl Storage {
    fn new(service: Service, security: Security) -> Self {
        Self {
            service,
            security,
            objects: BTreeMap::new(),
            drive: BTreeMap::new(),
            next_id: 0,
            trace: Trace::default(),
            error: None,
        }
    }

    fn reply(&mut self, addr: SocketAddr, request: Request) -> Reply {
        let result = match self.service {
            Service::Template => self.template(addr, &request),
            Service::S3 { virtual_host } => self.s3(&request, virtual_host),
            Service::Drive => self.google_drive(&request),
        };
        result.unwrap_or_else(|error| {
            self.error
                .get_or_insert_with(|| format!("{} {} {error}", request.method, request.path()));
            (400, error.into_bytes())
        })
    }

    fn token(&mut self) -> Reply {
        self.trace.tokens += 1;
        json_reply(json!({"access_token": TOKEN, "expires_in": 3600}))
    }

    fn record(&mut self, name: &str) {
        if name.starts_with("sessions/") {
            self.trace.announce += 1;
        } else if name.contains("/c2s/") {
            self.trace.uplink += 1;
        } else if name.contains("/s2c/") {
            self.trace.downlink += 1;
        }
    }

    fn template(
        &mut self,
        addr: SocketAddr,
        request: &Request,
    ) -> std::result::Result<Reply, String> {
        let path = request.path();
        if path == "/template/token" && request.method == "POST" {
            if request.body != format!("client_secret={SECRET}").as_bytes() {
                return Err("bad template OAuth form".into());
            }
            return Ok(self.token());
        }
        if let Some(name) = path.strip_prefix("/template/signed/") {
            if request.method != "PUT" || !request.header("authorization").is_empty() {
                return Err("bad presigned PUT headers".into());
            }
            let name = unescape(name, false)?;
            self.record(&name.replace('~', "/"));
            self.objects.insert(name, request.body.clone());
            return Ok((200, Vec::new()));
        }
        bearer(request)?;
        if let Some(name) = path.strip_prefix("/template/resolve/") {
            let scheme = scheme(self.security);
            return Ok(json_reply(
                json!({"href": format!("{scheme}://{addr}/template/signed/{name}")}),
            ));
        }
        if let Some(prefix) = path.strip_prefix("/template/list/") {
            let prefix = format!("{}~", unescape(prefix, false)?);
            self.trace.lists += 1;
            let body = self
                .objects
                .keys()
                .filter(|name| name.starts_with(&prefix))
                .map(|name| format!("name={name}\n"))
                .collect::<String>();
            return Ok((200, body.into_bytes()));
        }
        let name = unescape(
            path.strip_prefix("/template/objects/")
                .ok_or("template URL")?,
            false,
        )?;
        match request.method.as_str() {
            "GET" => Ok(self
                .objects
                .get(&name)
                .map_or((404, Vec::new()), |body| (200, body.clone()))),
            "DELETE" => {
                let prefix = format!("{name}~");
                self.objects
                    .retain(|key, _| key != &name && !key.starts_with(&prefix));
                Ok((204, Vec::new()))
            }
            _ => Err("template method".into()),
        }
    }

    fn s3(&mut self, request: &Request, virtual_host: bool) -> std::result::Result<Reply, String> {
        verify_signature(request)?;
        self.trace.signed += 1;
        let prefix = if virtual_host {
            if request.header("host") != format!("{BUCKET}.storage.test") {
                return Err("virtual-host S3 authority".into());
            }
            "/s3/".to_owned()
        } else {
            format!("/s3/{BUCKET}/")
        };
        let key = unescape(
            request.path().strip_prefix(&prefix).ok_or("S3 path")?,
            false,
        )?;
        let args = request.args()?;
        if request.method == "GET" && args.get("list-type").map(String::as_str) == Some("2") {
            let wanted = args.get("prefix").ok_or("S3 listing prefix")?;
            let delimiter = args.get("delimiter").map(String::as_str) == Some("/");
            self.trace.lists += 1;
            let mut dirs = BTreeSet::new();
            let mut xml = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
            for key in self.objects.keys() {
                let Some(rest) = key.strip_prefix(wanted) else {
                    continue;
                };
                if let Some((child, _)) = rest.split_once('/').filter(|_| delimiter) {
                    dirs.insert(format!("{wanted}{child}/"));
                } else {
                    xml.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
                }
            }
            for dir in dirs {
                xml.push_str(&format!(
                    "<CommonPrefixes><Prefix>{dir}</Prefix></CommonPrefixes>"
                ));
            }
            xml.push_str("</ListBucketResult>");
            return Ok((200, xml.into_bytes()));
        }
        let name = key.strip_prefix(&format!("{FOLDER}/")).ok_or("S3 folder")?;
        match request.method.as_str() {
            "PUT" => {
                self.record(name);
                self.objects.insert(key, request.body.clone());
                Ok((200, Vec::new()))
            }
            "GET" => Ok(self.objects.get(&key).map_or(
                (404, b"<Error><Code>NoSuchKey</Code></Error>".to_vec()),
                |body| (200, body.clone()),
            )),
            "DELETE" => {
                self.objects.remove(&key);
                Ok((204, Vec::new()))
            }
            _ => Err("S3 method".into()),
        }
    }

    fn google_drive(&mut self, request: &Request) -> std::result::Result<Reply, String> {
        let path = request.path();
        if path == "/token"
            && request.method == "POST"
            && request.header("host") == "oauth2.googleapis.com"
        {
            let form = std::str::from_utf8(&request.body).map_err(|_| "Drive OAuth form")?;
            for pair in [
                format!("client_id={ACCESS}"),
                format!("client_secret={SECRET}"),
                format!("refresh_token={TOKEN}"),
                "grant_type=refresh_token".into(),
            ] {
                if !form.split('&').any(|value| value == pair) {
                    return Err("bad Drive OAuth form".into());
                }
            }
            return Ok(self.token());
        }
        if request.header("host") != "www.googleapis.com" {
            return Err("Drive authority".into());
        }
        bearer(request)?;
        let path = path
            .strip_prefix("/upload/drive/v3/files")
            .or_else(|| path.strip_prefix("/drive/v3/files"))
            .ok_or("Drive URL")?;
        let args = request.args()?;
        if path.is_empty() && request.method == "GET" {
            let filter = args.get("q").ok_or("Drive list filter")?;
            let prefix = format!("'{FOLDER}' in parents and trashed = false and name ");
            let filter = filter.strip_prefix(&prefix).ok_or("Drive folder filter")?;
            let (wanted, starts) = if let Some(wanted) = filter.strip_prefix("contains '") {
                (wanted, true)
            } else {
                (
                    filter.strip_prefix("= '").ok_or("Drive exact filter")?,
                    false,
                )
            };
            let wanted = wanted.strip_suffix('\'').ok_or("Drive filter quote")?;
            self.trace.lists += 1;
            let files: Vec<_> = self.drive.iter().filter(|(_, file)| if starts { file.name.starts_with(wanted) } else { file.name == wanted })
                .map(|(id, file)| json!({"id": id, "name": file.name, "description": file.description})).collect();
            return Ok(json_reply(json!({"files": files})));
        }
        if path.is_empty() && request.method == "POST" {
            let (metadata, body) = drive_body(request)?;
            let name = metadata
                .get("name")
                .and_then(Value::as_str)
                .ok_or("Drive name")?
                .to_owned();
            if metadata["parents"] != json!([FOLDER]) {
                return Err("Drive create folder".into());
            }
            if name.starts_with("sessions~") {
                self.trace.announce += 1;
            }
            self.next_id += 1;
            let id = format!("id-{}", self.next_id);
            self.drive.insert(
                id.clone(),
                DriveObject {
                    name,
                    description: metadata["description"].as_str().unwrap_or("").into(),
                    body: body.unwrap_or_default(),
                    updates: 0,
                },
            );
            return Ok(json_reply(json!({"id": id})));
        }
        let id = unescape(path.strip_prefix('/').ok_or("Drive file ID")?, false)?;
        if request.method == "DELETE" {
            self.drive.remove(&id);
            return Ok((204, Vec::new()));
        }
        let Some(file) = self.drive.get_mut(&id) else {
            return Ok((404, Vec::new()));
        };
        match request.method.as_str() {
            "GET" if args.get("alt").map(String::as_str) == Some("media") => {
                Ok((200, file.body.clone()))
            }
            "GET" => Ok(json_reply(json!({"description": file.description}))),
            "PATCH" => {
                let (metadata, body) = drive_body(request)?;
                let description = metadata["description"]
                    .as_str()
                    .ok_or("Drive patch description")?;
                if description.starts_with("WERSVlNMMDE") {
                    self.trace.slot_updates += 1;
                    self.trace.slot_reused += usize::from(file.updates > 0);
                    file.updates += 1;
                    if file.name.contains("~c2s~") {
                        self.trace.uplink += 1;
                    }
                    if file.name.contains("~s2c~") {
                        self.trace.downlink += 1;
                    }
                } else if description.parse::<u64>().is_ok() && file.name.ends_with("~w") {
                    self.trace.watermarks += 1;
                } else {
                    return Err("Drive slot marker".into());
                }
                file.description = description.to_owned();
                if let Some(body) = body {
                    file.body = body;
                    self.trace.media += 1;
                }
                Ok(json_reply(json!({"id": id})))
            }
            _ => Err("Drive method".into()),
        }
    }
}
