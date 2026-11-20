use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use url::Url;

use super::drive::DriveStorage;
use super::ring::{Ring, Writer};
use super::s3::S3Storage;
use super::service_http::Headers;
use super::template::TemplateStorage;
use super::{Config, ObjectKind, Storage, Xdrive, XdriveHttpOptions};

/// The specified settings must point at a disposable test prefix or dedicated Drive folder.
/// Settings stay in the worker's private file; do not print the file or provider responses.
#[test]
#[ignore = "requires XDRIVE_LIVE_SETTINGS pointing to private settings for a disposable cloud folder"]
fn cloud_storage_round_trips() {
    let path = std::env::var_os("XDRIVE_LIVE_SETTINGS").expect("set XDRIVE_LIVE_SETTINGS to a private file");
    let settings = std::fs::read_to_string(path).expect("read private XDrive test settings");
    let config: Config = serde_json::from_str(&settings).unwrap_or_else(|_| panic!("invalid XDrive settings"));
    assert!(matches!(config.service.as_str(), "template" | "s3" | "google-drive" | "Google Drive"));
    assert!(!config.remote_folder.as_os_str().is_empty(), "a dedicated test folder is required");
    let drive = Xdrive::new(&settings, XdriveHttpOptions::default())
        .unwrap_or_else(|_| panic!("build the cloud XDrive transport"));
    let mut listener = drive.listen().unwrap_or_else(|_| panic!("create a cloud listener"));
    let (ready, finished) = std::sync::mpsc::sync_channel(1);
    let pattern = |len: usize, salt: u8| -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt)).collect()
    };
    thread::spawn(move || {
        let result = (|| -> io::Result<()> {
            let (mut rx, mut tx) = listener.accept()?;
            rx.set_timeout(Some(Duration::from_secs(40)));
            tx.set_timeout(Some(Duration::from_secs(40)));
            let mut reply = vec![0; 64 * 1024 + 5];
            rx.read_exact(&mut reply)?;
            if reply != pattern(reply.len(), 23) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            tx.write_all(&pattern(96 * 1024 + 7, 11))?;
            tx.flush()
        })();
        let _ = ready.send(result.is_ok());
    });
    let (mut rx, mut tx) = drive.dial().unwrap_or_else(|error| panic!("announce a session on the cloud provider: {}", cloud_error(&error)));
    rx.set_timeout(Some(Duration::from_secs(40)));
    tx.set_timeout(Some(Duration::from_secs(40)));
    tx.write_all(&pattern(64 * 1024 + 5, 23)).unwrap_or_else(|_| panic!("upload payload"));
    tx.flush().unwrap_or_else(|_| panic!("finish upload"));
    let expected = pattern(96 * 1024 + 7, 11);
    let mut back = vec![0; expected.len()];
    rx.read_exact(&mut back).unwrap_or_else(|_| panic!("download response"));
    assert!(back == expected, "XDrive cloud payload differs");
    assert_eq!(finished.recv_timeout(Duration::from_secs(5)).ok(), Some(true));
}

fn cloud_error(error: &io::Error) -> String {
    let status = error.to_string().rsplit_once(" answered HTTP ")
        .and_then(|(_, status)| status.parse::<u16>().ok());
    if let Some(status) = status {
        format!("HTTP {status}")
    } else {
        format!("{:?}", error.kind())
    }
}

struct Mock {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

struct Request {
    method: String,
    target: String,
    headers: Headers,
    body: Vec<u8>,
}

struct PersistentMock {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    sockets: Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl PersistentMock {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let sockets = Arc::new(std::sync::Mutex::new(Vec::new()));
        let live = sockets.clone();
        let worker = thread::spawn(move || {
            let mut id = 0;
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        id += 1;
                        let id = id.to_string();
                        live.lock().unwrap().push(stream.try_clone().unwrap());
                        thread::spawn(move || {
                            let mut reader = BufReader::new(stream.try_clone().unwrap());
                            loop {
                                let mut line = String::new();
                                if !reader.read_line(&mut line).is_ok_and(|n| n > 0) { break; }
                                let mut length = 0;
                                loop {
                                    line.clear();
                                    if !reader.read_line(&mut line).is_ok_and(|n| n > 0) { return; }
                                    if line == "\r\n" { break; }
                                    if let Some((name, value)) = line.split_once(':') {
                                        if name.eq_ignore_ascii_case("content-length") { length = value.trim().parse().unwrap(); }
                                    }
                                }
                                if reader.read_exact(&mut vec![0; length]).is_err() { break; }
                                if write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{id}", id.len()).is_err() { break; }
                            }
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                    Err(error) => panic!("persistent mock: {error}"),
                }
            }
        });
        Self { addr, stop, sockets, thread: Some(worker) }
    }
}

impl Drop for PersistentMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
        for socket in self.sockets.lock().unwrap().iter() { let _ = socket.shutdown(std::net::Shutdown::Both); }
    }
}

#[test]
fn storage_xmux_budgets_control_actual_http_connections() {
    use super::service_http::{Redirects, ServiceHttp};
    let server = PersistentMock::start();
    let url = format!("http://{}/object", server.addr);
    let request = |client: &ServiceHttp| client.call("GET", &url, &Headers::new(), &[]).unwrap().body;

    let config = crate::xmux::XmuxConfig::xdrive(Some(&json!({"maxConnections": 1})), false, false).unwrap();
    let base = ServiceHttp::configured(XdriveHttpOptions::default(), Redirects::Follow, config, 32).unwrap();
    let first = base.clone();
    let first_peer = request(&first);
    drop(first);
    let second = base.clone();
    assert_eq!(request(&second), first_peer, "new session reuses the HTTP connection");

    let config = crate::xmux::XmuxConfig::xdrive(Some(&json!({"cMaxReuseTimes": 1})), false, false).unwrap();
    let base = ServiceHttp::configured(XdriveHttpOptions::default(), Redirects::Follow, config, 32).unwrap();
    let first = base.clone();
    let first_peer = request(&first);
    let second = base.clone();
    assert_ne!(request(&second), first_peer, "session budget opens a new HTTP connection");
    assert_eq!(request(&first), first_peer, "retiring a connection preserves an active session");

    let config = crate::xmux::XmuxConfig::xdrive(Some(&json!({"hMaxRequestTimes": 1})), false, false).unwrap();
    let base = ServiceHttp::configured(XdriveHttpOptions::default(), Redirects::Follow, config, 32).unwrap();
    let session = base.clone();
    assert_ne!(request(&session), request(&session), "request budget rotates within a session");
}

impl Mock {
    fn start(
        tls: Option<Arc<crate::ServerConfig>>,
        mut handle: impl FnMut(SocketAddr, Request) -> (u16, Vec<u8>) + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        socket
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        socket
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        if let Some(tls) = &tls {
                            let socket = crate::accept_tls(socket, tls.clone()).unwrap();
                            respond(socket, addr, &mut handle).unwrap();
                        } else {
                            respond(socket, addr, &mut handle).unwrap();
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("mock accept: {error}"),
                }
            }
        });
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

#[test]
fn h3_storage_retains_response_status_and_error_body() {
    use super::service_http::{Redirects, ServiceHttp};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = crate::server_config(
        &cert.cert.pem(),
        &cert.key_pair.serialize_pem(),
        &["h3".into()],
    )
    .unwrap();
    let server = Arc::new(crate::H3Listener::bind("127.0.0.1:0".parse().unwrap(), tls).unwrap());
    let port = server.local_addr().unwrap().port();
    let peer = server.clone();
    let reply = thread::spawn(move || {
        let (_, mut stream) = peer.accept().unwrap();
        stream.set_timeout(Duration::from_secs(3));
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"data");
        assert_eq!(
            stream.header("authorization").as_deref(),
            Some("Bearer fixture")
        );
        stream
            .reply_with(307, &[("location", "https://other.test/object")])
            .unwrap();
        stream.finish_write().unwrap();

        let (_, mut stream) = peer.accept().unwrap();
        stream.set_timeout(Duration::from_secs(3));
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"data");
        assert!(stream.header("authorization").is_none());
        stream.reply_with(429, &[("retry-after", "1")]).unwrap();
        stream.write_all(b"limited").unwrap();
        stream.finish_write().unwrap();
    });
    let client = ServiceHttp::new(
        XdriveHttpOptions {
            quic: Some(crate::advanced_quic_client_config(&crate::AdvancedTlsOptions { alpn: vec!["h3".into()], allow_insecure: true, ..Default::default() }, true).unwrap()),
            server_name: Some("localhost".into()),
            connect_to: Some(("127.0.0.1".into(), port)),
            ..Default::default()
        },
        Redirects::Follow,
    )
    .unwrap();
    let received = client
        .call(
            "PUT",
            "https://mock.test/object",
            &Headers::from([("authorization".into(), "Bearer fixture".into())]),
            b"data",
        )
        .unwrap();
    assert_eq!(received.status, 429);
    assert_eq!(received.body, b"limited");
    assert_eq!(received.retry_after(), Some(Duration::from_secs(1)));
    reply.join().unwrap();
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let result = self.thread.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

fn respond(
    mut stream: impl Read + Write,
    addr: SocketAddr,
    handle: &mut impl FnMut(SocketAddr, Request) -> (u16, Vec<u8>),
) -> io::Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let mut start = line.split_whitespace();
    let method = start.next().unwrap().to_owned();
    let target = start.next().unwrap().to_owned();
    let mut headers = Headers::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        headers.insert(name.to_ascii_lowercase(), value.trim().into());
    }
    let len = headers
        .get("content-length")
        .map(|text| text.parse::<usize>().unwrap())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body)?;
    let (status, body) = handle(
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

#[test]
fn template_oauth_and_presigned_upload_keep_headers_separate() {
    let mut token_requests = 0;
    let server = Mock::start(None, move |addr, request| match request.target.as_str() {
        "/token" => {
            token_requests += 1;
            assert_eq!(token_requests, 1);
            assert_eq!(request.method, "POST");
            assert_eq!(request.body, b"secret=fixture");
            (
                200,
                br#"{"oauth":{"access":"mock-token","lifetime":3600}}"#.to_vec(),
            )
        }
        "/resolve/sessions~example" => {
            assert_eq!(request.headers["authorization"], "Bearer mock-token");
            assert!(request.body.is_empty());
            (
                200,
                json!({"links":{"upload":format!("http://{addr}/upload")}})
                    .to_string()
                    .into_bytes(),
            )
        }
        "/upload" => {
            assert_eq!(request.method, "PUT");
            assert!(!request.headers.contains_key("authorization"));
            assert_eq!(request.body, b"aGk=");
            (201, Vec::new())
        }
        "/list/sessions" => {
            assert_eq!(request.headers["authorization"], "Bearer mock-token");
            (
                200,
                b"name=sessions~example\nname=sessions~child~data\nname=ignore~else\n".to_vec(),
            )
        }
        target => panic!("unexpected template target {target}"),
    });
    let base = format!("http://{}", server.addr);
    let config: Config = serde_json::from_value(json!({
        "secrets":["fixture"], "template": {
            "flatten":true,
            "auth":{"type":"oauth2","tokenUrl":format!("{base}/token"),"form":{"secret":"{secret0}"},
                "tokenPath":"oauth.access","expiryPath":"oauth.lifetime","header":{"Authorization":"Bearer {token}"}},
            "put":{"url":format!("{base}/resolve/{{name}}"),"hrefPath":"links.upload","hrefMethod":"PUT","body":"{data}"},
            "get":{"url":format!("{base}/get/{{name}}")}, "delete":{"url":format!("{base}/delete/{{name}}")},
            "list":{"url":format!("{base}/list/{{prefix}}"),"namesRegex":"name=([^\\n]+)"}
        }
    })).unwrap();
    let storage = TemplateStorage::new(&config, XdriveHttpOptions::default()).unwrap();
    storage.put("sessions/example", b"hi").unwrap();
    let names: Vec<_> = storage
        .list("sessions")
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(names, ["example", "child"]);
}

#[test]
fn s3_upload_signs_exact_path_and_lists_continuations() {
    let server = Mock::start(None, move |_, request| {
        assert!(
            request.headers["authorization"].starts_with("AWS4-HMAC-SHA256 Credential=mock-id/")
        );
        assert_eq!(request.headers["x-amz-security-token"], "mock-token");
        if request.method == "PUT" {
            if request.target.ends_with("/sessions/announce") {
                assert_eq!(request.headers["content-length"], "0");
                assert!(request.body.is_empty());
                return (200, Vec::new());
            }
            assert_eq!(
                request.target,
                "/prefix%2Fescape/bucket/folder%20name/sessions/hello"
            );
            assert_eq!(
                request.headers["x-amz-content-sha256"],
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            );
            assert_eq!(request.body, b"hello");
            return (200, Vec::new());
        }
        let url = Url::parse(&format!("http://localhost{}", request.target)).unwrap();
        let args: Headers = url.query_pairs().into_owned().collect();
        assert_eq!(url.path(), "/prefix%2Fescape/bucket/");
        assert_eq!(args["prefix"], "folder name/sessions/");
        assert_eq!(args["delimiter"], "/");
        if let Some(next) = args.get("continuation-token") {
            assert_eq!(next, "two + /");
            (200, b"<ListBucketResult><IsTruncated>false</IsTruncated><CommonPrefixes><Prefix>folder name/sessions/child/</Prefix></CommonPrefixes></ListBucketResult>".to_vec())
        } else {
            (200, b"<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>two + /</NextContinuationToken><Contents><Key>folder name/sessions/hello</Key></Contents></ListBucketResult>".to_vec())
        }
    });
    let config: Config = serde_json::from_value(json!({
        "remoteFolder":"folder name", "secrets":["mock-id","mock-secret","mock-token"],
        "s3":{"endpoint":format!("http://{}/prefix%2Fescape", server.addr),"bucket":"bucket","region":"test"}
    })).unwrap();
    let storage = S3Storage::new(&config, XdriveHttpOptions::default()).unwrap();
    storage.put("sessions/announce", b"").unwrap();
    storage.put("sessions/hello", b"hello").unwrap();
    let names: Vec<_> = storage
        .list("sessions")
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(names, ["child", "hello"]);
}

#[test]
fn google_drive_slot_uses_oauth_and_writes_media_with_frame_description() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = crate::server_config(&cert.cert.pem(), &cert.key_pair.serialize_pem(), &[]).unwrap();
    let mut slot_id = 0;
    let server = Mock::start(Some(tls), move |_, request| {
        if request.target == "/token" {
            assert_eq!(request.headers["host"], "oauth2.googleapis.com");
            assert_eq!(request.method, "POST");
            assert!(String::from_utf8(request.body)
                .unwrap()
                .contains("grant_type=refresh_token"));
            return (
                200,
                br#"{"access_token":"mock-token","expires_in":3600}"#.to_vec(),
            );
        }
        assert_eq!(request.headers["host"], "www.googleapis.com");
        assert_eq!(request.headers["authorization"], "Bearer mock-token");
        if request.method == "POST" {
            slot_id += 1;
            let metadata: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(metadata["parents"], json!(["mock-folder"]));
            assert!(metadata["name"]
                .as_str()
                .unwrap()
                .starts_with("streams~session~"));
            return (
                200,
                json!({"id":format!("id-{slot_id}")})
                    .to_string()
                    .into_bytes(),
            );
        }
        assert_eq!(request.method, "PATCH");
        assert!(request.target.starts_with("/upload/drive/v3/files/"));
        assert_eq!(
            request.headers["content-type"],
            "multipart/related; boundary=xdrive-boundary"
        );
        let body = String::from_utf8(request.body).unwrap();
        assert!(body.contains(r#"{"description":"WERSVlNMMDE"#));
        assert!(body.contains(&"m".repeat(16_000)));
        (200, b"{}".to_vec())
    });
    let config: Config = serde_json::from_value(json!({"remoteFolder":"mock-folder","secrets":["mock-client","mock-secret","mock-refresh"]})).unwrap();
    let options = XdriveHttpOptions {
        tls: Some(crate::advanced_client_config(&crate::AdvancedTlsOptions { allow_insecure: true, ..Default::default() }).unwrap()),
        server_name: Some("localhost".into()),
        connect_to: Some((server.addr.ip().to_string(), server.addr.port())),
        ..Default::default()
    };
    let storage = DriveStorage::new(&config, options).unwrap();
    let slots = storage.slots().unwrap();
    let ring = Ring::make(slots, "session", 2).unwrap();
    let (uplink, _) = ring.directions(true);
    Writer::new(slots, &uplink)
        .write(0, ObjectKind::Segment, &vec![b'm'; 16_000])
        .unwrap();
}
