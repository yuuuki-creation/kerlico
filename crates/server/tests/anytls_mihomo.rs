#![cfg(all(feature = "anytls", feature = "landing-anytls"))]

//! AnyTLS against mihomo 1.19.33 in both directions, with real payloads. These tests are ignored by
//! default and need the peer binary:
//!
//! ```text
//! MIHOMO=/path/to/mihomo cargo test -p kerlico-server --no-default-features \
//!     --features anytls,landing-anytls --test anytls_mihomo -- --ignored --test-threads=1
//! ```
//!
//! Without `MIHOMO`, or with a binary of another version, every test fails: a missing peer never
//! counts as a pass. A TCP relay between the client and the server records what an observer sees
//! (connections and TLS record lengths) so padding and session reuse are checked on the wire.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kerlico_anytls::{password_hash, tls, Family, Scheme, SchemeCell, Session, Target};
use kerlico_shared::Settings;
use landing_anytls::Client;
use serde_json::json;
use sha2::{Digest, Sha256};

const VERSION: &str = "Mihomo Meta 1.19.33";
const PASSWORD: &str = "interop-secret";
/// Fixed sizes, so both clients must produce the same record lengths.
const FIXED_SCHEME: &str = "stop=5\n0=20-20\n1=150-150\n2=200-200\n3=300-300,c,90-90\n4=64-64";

fn mihomo() -> PathBuf {
    let path = PathBuf::from(std::env::var("MIHOMO").expect("MIHOMO is not set: the mihomo interop tests did not run"));
    let output = Command::new(&path).arg("-v").output().expect("mihomo binary does not start: not run");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with(VERSION), "peer is {text:?}, not {VERSION}: not run");
    path
}

fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

fn wait_port(port: u16) {
    let started = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(started.elapsed() < Duration::from_secs(15), "port {port} never opened");
        thread::sleep(Duration::from_millis(50));
    }
}

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kerlico-anytls-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Peer {
    child: Child,
    log: PathBuf,
}

impl Peer {
    /// `files` land in mihomo's home directory, the only place it reads certificates from.
    fn start(name: &str, yaml: &str, files: &[(&str, &str)]) -> Self {
        let dir = workdir(name);
        std::fs::write(dir.join("config.yaml"), yaml).unwrap();
        for (file, text) in files {
            std::fs::write(dir.join(file), text).unwrap();
        }
        let log = dir.join("mihomo.log");
        let child = Command::new(mihomo())
            .arg("-d")
            .arg(&dir)
            .arg("-f")
            .arg(dir.join("config.yaml"))
            .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
            .stderr(Stdio::from(std::fs::File::create(dir.join("mihomo.err")).unwrap()))
            .spawn()
            .unwrap();
        Self { child, log }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn certificate() -> (String, String) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (key.cert.pem(), key.key_pair.serialize_pem())
}

/// mihomo as the server: an anytls listener whose traffic goes out DIRECT.
fn mihomo_server(port: u16, scheme: Option<&str>) -> Peer {
    mihomo_server_with_ech(port, scheme, None)
}

fn mihomo_server_with_ech(port: u16, scheme: Option<&str>, ech: Option<&str>) -> Peer {
    let (cert, key) = certificate();
    let scheme = scheme.map(|text| format!("    padding-scheme: {}\n", serde_json::to_string(text).unwrap())).unwrap_or_default();
    let ech_setting = if ech.is_some() { "    ech-key: ech.pem\n" } else { "" };
    let yaml = format!(
        "log-level: debug\nallow-lan: false\nipv6: true\nmode: rule\nlisteners:\n  - name: any-in\n    type: anytls\n    listen: 127.0.0.1\n    port: {port}\n    users:\n      interop: {PASSWORD}\n    certificate: cert.pem\n    private-key: key.pem\n{scheme}{ech_setting}rules:\n  - MATCH,DIRECT\n"
    );
    let mut files = vec![("cert.pem", cert.as_str()), ("key.pem", key.as_str())];
    if let Some(ech) = ech {
        files.push(("ech.pem", ech));
    }
    let peer = Peer::start(&format!("server-{port}"), &yaml, &files);
    wait_port(port);
    // mihomo opens its listeners before its tunnel runs and closes the streams that arrive in
    // between, so wait until one stream really gets through.
    let (echo, _) = tcp_echo();
    let ready = wait_until(Duration::from_secs(15), || {
        let client = kerlico_client(port, PASSWORD);
        let ok = client
            .open_stream(&echo.ip().to_string(), echo.port())
            .and_then(|stream| {
                stream.write_all(b"r")?;
                let mut byte = [0u8; 1];
                let n = stream.read_for(&mut byte, Duration::from_secs(1))?;
                Ok(n == 1)
            })
            .unwrap_or(false);
        client.close();
        ok
    });
    assert!(ready, "mihomo server never started passing streams");
    peer
}

fn socks_roundtrip(proxy: u16, target: SocketAddr) -> bool {
    let attempt = || -> std::io::Result<bool> {
        let mut tcp = TcpStream::connect(("127.0.0.1", proxy))?;
        tcp.set_read_timeout(Some(Duration::from_secs(1)))?;
        tcp.write_all(&[5, 1, 0])?;
        let mut reply = [0u8; 2];
        tcp.read_exact(&mut reply)?;
        let SocketAddr::V4(v4) = target else { return Ok(false) };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&v4.ip().octets());
        request.extend_from_slice(&v4.port().to_be_bytes());
        tcp.write_all(&request)?;
        let mut reply = [0u8; 10];
        tcp.read_exact(&mut reply)?;
        tcp.write_all(b"r")?;
        let mut byte = [0u8; 1];
        tcp.read_exact(&mut byte)?;
        Ok(reply[1] == 0 && byte == *b"r")
    };
    attempt().unwrap_or(false)
}

/// mihomo as the client: a mixed (SOCKS5 and HTTP) port in front of an anytls proxy.
fn mihomo_client(mixed: u16, server: u16, password: &str) -> Peer {
    mihomo_client_with_ech(mixed, server, password, None)
}

fn mihomo_client_with_ech(mixed: u16, server: u16, password: &str, ech: Option<&str>) -> Peer {
    let ech = ech.map(|config| format!("    client-fingerprint: chrome\n    ech-opts:\n      enable: true\n      config: {config}\n")).unwrap_or_default();
    mihomo_client_with_transport(mixed, server, password, &ech)
}

fn mihomo_client_with_transport(mixed: u16, server: u16, password: &str, extra: &str) -> Peer {
    let yaml = format!(
        "log-level: debug\nallow-lan: false\nbind-address: 127.0.0.1\nipv6: true\nmode: rule\nmixed-port: {mixed}\nproxies:\n  - name: any\n    type: anytls\n    server: 127.0.0.1\n    port: {server}\n    password: {password}\n    sni: localhost\n    skip-cert-verify: true\n    udp: true\n    idle-session-check-interval: 6\n    idle-session-timeout: 6\n{extra}rules:\n  - IP-CIDR,127.0.0.2/32,DIRECT,no-resolve\n  - MATCH,any\n"
    );
    let peer = Peer::start(&format!("client-{mixed}"), &yaml, &[]);
    wait_port(mixed);
    wait_mihomo_client(mixed);
    peer
}

fn mihomo_server_with_transport(port: u16, extra: &str) -> Peer {
    let yaml = format!(
        "log-level: debug\nallow-lan: false\nipv6: true\nmode: rule\nlisteners:\n  - name: any-in\n    type: anytls\n    listen: 127.0.0.1\n    port: {port}\n    users:\n      interop: {PASSWORD}\n{extra}rules:\n  - MATCH,DIRECT\n"
    );
    let peer = Peer::start(&format!("transport-server-{port}"), &yaml, &[]);
    wait_port(port);
    peer
}

/// Waits until mihomo's tunnel runs (see `mihomo_server`). The probe goes to 127.0.0.2, which
/// the client's rules send DIRECT, so it opens no AnyTLS session that a test would then count.
fn wait_mihomo_client(mixed: u16) {
    let listener = TcpListener::bind("127.0.0.2:0").unwrap();
    let echo = listener.local_addr().unwrap();
    thread::spawn(move || {
        for mut tcp in listener.incoming().flatten() {
            let mut byte = [0u8; 1];
            if tcp.read_exact(&mut byte).is_ok() {
                let _ = tcp.write_all(&byte);
            }
        }
    });
    assert!(wait_until(Duration::from_secs(15), || socks_roundtrip(mixed, echo)), "mihomo client never started passing streams");
}

/// A Kerlico AnyTLS node in this process.
fn kerlico_server(scheme: Option<&str>) -> u16 {
    kerlico_server_with_ech(scheme, None)
}

fn kerlico_server_with_ech(scheme: Option<&str>, ech: Option<&str>) -> u16 {
    let (cert, key) = certificate();
    let mut settings = json!({ "certificate": cert, "private-key": key });
    if let Some(scheme) = scheme {
        settings["padding-scheme"] = json!(scheme);
    }
    if let Some(ech) = ech {
        settings["ech-key"] = json!(ech);
    }
    kerlico_server_with_transport(settings)
}

fn kerlico_server_with_transport(mut settings: serde_json::Value) -> u16 {
    settings["users"] = json!([{ "email": "interop@test", "password": PASSWORD }]);
    for _ in 0..5 {
        let port = free_port();
        let config = json!({
            "inbounds": [{ "tag": "any", "protocol": "anytls", "listen": "127.0.0.1", "port": port, "outbound": "native-v4", "settings": settings }]
        });
        let Ok(mut loaded) = kerlico_server::Server::from_config(&config.to_string()) else { continue };
        thread::spawn(move || {
            let _ = loaded.server.run(loaded.dns);
        });
        wait_port(port);
        return port;
    }
    panic!("no port for the Kerlico node");
}

#[test]
#[ignore]
fn kerlico_client_interoperates_with_mihomo_jls() {
    let (echo, _) = tcp_echo();
    let port = free_port();
    let _peer = mihomo_server_with_transport(port, &format!(
        "    jls-config:\n      enable: true\n      dest: {echo}\n      sni: localhost\n      users:\n        - username: outer-user\n          password: outer-secret\n"
    ));
    let mut settings = Settings::default();
    settings.insert_text("password", PASSWORD);
    settings.insert_text("sni", "localhost");
    settings.insert_text("jls-opts", r#"{"username":"outer-user","password":"outer-secret"}"#);
    let client = Client::new("127.0.0.1", port, &settings).unwrap();
    let stream = ready_stream(&client, echo);
    let data = pattern(192 * 1024, 11);
    stream.write_all(&data).unwrap();
    assert_eq!(read_exact(&stream, data.len()), data);
    settings.insert_text("client-fingerprint", "chrome");
    let chrome = Client::new("127.0.0.1", port, &settings).unwrap();
    let stream = chrome.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    stream.write_all(&data).unwrap();
    assert_eq!(read_exact(&stream, data.len()), data);
}

#[test]
#[ignore]
fn mihomo_client_interoperates_with_kerlico_jls_and_ordinary_tls_reaches_the_fallback() {
    let (echo, _) = tcp_echo();
    let port = kerlico_server_with_transport(json!({ "jls-config": {
        "enable": true, "dest": echo.to_string(), "sni": "localhost",
        "users": [{"username":"outer-user","password":"outer-secret"}]
    }}));
    let mixed = free_port();
    let _peer = mihomo_client_with_transport(mixed, port, PASSWORD,
        "    client-fingerprint: chrome\n    jls-opts:\n      username: outer-user\n      password: outer-secret\n");
    large(socks_connect(mixed, echo), 192 * 1024);

    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    // A complete record with an invalid handshake can only be sent back by the TCP fallback.
    let bad = [22, 3, 3, 0, 4, 2, 0, 0, 0];
    tcp.write_all(&bad).unwrap();
    let mut back = [0u8; 9];
    tcp.read_exact(&mut back).unwrap();
    assert_eq!(back, bad);
}

fn shadow_tls_target(version: u8) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (cert, key) = certificate();
    let tls = if version == 1 { "1.2" } else { "1.3" };
    let mut config = kerlico_vless::server_config_versions(&cert, &key, &["http/1.1".into()], tls, tls).unwrap();
    if version == 2 {
        // V2 cannot distinguish a late encrypted target record from the first unencrypted
        // application record. V3 runs with tickets to exercise its authenticated discard path.
        Arc::get_mut(&mut config).unwrap().send_tls13_tickets = 0;
    }
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let config = config.clone();
            thread::spawn(move || {
                let mut link = kerlico_vless::accept_tls(tcp, config).unwrap();
                let _ = link.read(&mut [0; 1024]);
            });
        }
    });
    addr
}

#[test]
#[ignore]
fn shadowtls_versions_one_two_and_three_interoperate_with_mihomo() {
    let (echo, _) = tcp_echo();
    for version in [1, 2, 3] {
        let target = shadow_tls_target(version);
        let port = kerlico_server_with_transport(json!({ "shadow-tls": {
            "enable": true, "version": version, "password": "outer-secret",
            "users": [{"name":"outer-user","password":"outer-secret"}],
            "handshake": {"dest": target.to_string()},
        }}));
        let mixed = free_port();
        let _client = mihomo_client_with_transport(mixed, port, PASSWORD,
            &format!("    shadow-tls-opts:\n      version: {version}\n      password: outer-secret\n"));
        large(socks_connect(mixed, echo), 96 * 1024);

        let offer = free_port();
        let _server = mihomo_server_with_transport(offer, &format!(
            "    shadow-tls:\n      enable: true\n      version: {version}\n      password: outer-secret\n      users:\n        - name: outer-user\n          password: outer-secret\n      handshake:\n        dest: {target}\n"
        ));
        let mut settings = Settings::default();
        settings.insert_text("password", PASSWORD);
        settings.insert_text("sni", "localhost");
        settings.insert_text("skip-cert-verify", "true");
        settings.insert_text("shadow-tls-opts", json!({"version":version,"password":"outer-secret"}).to_string());
        let client = Client::new("127.0.0.1", offer, &settings).unwrap();
        let stream = ready_stream(&client, echo);
        let data = pattern(96 * 1024, 12);
        stream.write_all(&data).unwrap();
        assert_eq!(read_exact(&stream, data.len()), data, "ShadowTLS v{version}");
    }
}

#[test]
#[ignore]
fn restls_tls13_interoperates_with_mihomo() {
    let (echo, _) = tcp_echo();
    let target = shadow_tls_target(3);
    let port = kerlico_server_with_transport(json!({ "res-tls": {
        "enable": true, "password": "outer-secret", "dest": target.to_string(),
    }}));
    let mixed = free_port();
    let _client = mihomo_client_with_transport(mixed, port, PASSWORD,
        "    restls-opts:\n      version-hint: tls13\n      password: outer-secret\n");
    large(socks_connect(mixed, echo), 96 * 1024);

    let offered = free_port();
    let _server = mihomo_server_with_transport(offered, &format!(
        "    res-tls:\n      enable: true\n      password: outer-secret\n      dest: {target}\n"
    ));
    let mut settings = Settings::default();
    settings.insert_text("password", PASSWORD);
    settings.insert_text("sni", "localhost");
    settings.insert_text("skip-cert-verify", "true");
    settings.insert_text("restls-opts", json!({"version-hint":"tls13","password":"outer-secret"}).to_string());
    let client = Client::new("127.0.0.1", offered, &settings).unwrap();
    let stream = ready_stream(&client, echo);
    let data = pattern(96 * 1024, 12);
    stream.write_all(&data).unwrap();
    assert_eq!(read_exact(&stream, data.len()), data);
}

#[test]
#[ignore]
fn restls_tls12_interoperates_with_mihomo() {
    let (echo, _) = tcp_echo();
    let target = shadow_tls_target(1);
    let port = kerlico_server_with_transport(json!({ "res-tls": {
        "enable": true, "password": "outer-secret", "dest": target.to_string(),
    }}));
    let mixed = free_port();
    let _client = mihomo_client_with_transport(mixed, port, PASSWORD,
        "    restls-opts:\n      version-hint: tls12\n      password: outer-secret\n");
    large(socks_connect(mixed, echo), 96 * 1024);

    let offered = free_port();
    let _server = mihomo_server_with_transport(offered, &format!(
        "    res-tls:\n      enable: true\n      password: outer-secret\n      dest: {target}\n"
    ));
    let mut settings = Settings::default();
    settings.insert_text("password", PASSWORD);
    settings.insert_text("sni", "localhost");
    settings.insert_text("skip-cert-verify", "true");
    settings.insert_text("restls-opts", json!({"version-hint":"tls12","password":"outer-secret"}).to_string());
    let client = Client::new("127.0.0.1", offered, &settings).unwrap();
    let stream = ready_stream(&client, echo);
    let data = pattern(96 * 1024, 12);
    stream.write_all(&data).unwrap();
    assert_eq!(read_exact(&stream, data.len()), data);
}

#[test]
fn restls_resumes_tls12_and_tls13_against_the_same_target() {
    use tokio_rustls::rustls::{crypto::ring::Ticketer, HandshakeKind, ServerConnection, StreamOwned};

    let (echo, _) = tcp_echo();
    for (version, hint) in [("1.2", "tls12"), ("1.3", "tls13")] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap();
        let (cert, key) = certificate();
        let mut tls = kerlico_vless::server_config_versions(&cert, &key, &[], version, version).unwrap();
        Arc::get_mut(&mut tls).unwrap().ticketer = Ticketer::new().unwrap();
        let (report, observed) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for mut tcp in listener.incoming().flatten() {
                let tls = tls.clone();
                let report = report.clone();
                thread::spawn(move || {
                    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                    let mut conn = ServerConnection::new(tls).unwrap();
                    while conn.is_handshaking() {
                        if conn.complete_io(&mut tcp).is_err() { return; }
                    }
                    let mut link = StreamOwned::new(conn, tcp);
                    report.send(link.conn.handshake_kind().expect("handshake kind")).unwrap();
                    let _ = link.read(&mut [0; 16]);
                });
            }
        });
        let port = kerlico_server_with_transport(json!({ "res-tls": {
            "enable": true, "password": "outer-secret", "dest": target.to_string(),
        }}));
        let mut settings = Settings::default();
        settings.insert_text("password", PASSWORD);
        settings.insert_text("sni", "localhost");
        settings.insert_text("skip-cert-verify", "true");
        settings.insert_text("restls-opts", json!({"version-hint":hint,"password":"outer-secret"}).to_string());
        let client = Client::new("127.0.0.1", port, &settings).unwrap();
        let first = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
        first.write_all(b"first").unwrap();
        assert_eq!(read_exact(&first, 5), b"first");
        assert_eq!(observed.recv_timeout(Duration::from_secs(5)).unwrap(), HandshakeKind::Full, "first {hint}");
        // Keep the first AnyTLS stream active so opening another must dial a new carrier.
        let second = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
        second.write_all(b"next").unwrap();
        assert_eq!(read_exact(&second, 4), b"next");
        assert_eq!(observed.recv_timeout(Duration::from_secs(5)).unwrap(), HandshakeKind::Resumed, "second {hint}");
    }
}

fn generated_ech() -> (String, String) {
    let output = Command::new(mihomo())
        .args(["generate", "ech-keypair", "public.example.invalid"])
        .output().unwrap();
    assert!(output.status.success());
    let output = String::from_utf8(output.stdout).unwrap();
    let (config, keys) = output.trim().strip_prefix("Config: ").unwrap().split_once("\nKey: ").unwrap();
    (config.trim().into(), keys.into())
}

#[test]
#[ignore]
fn kerlico_client_interoperates_with_mihomo_ech_using_a_browser_profile() {
    let (config, keys) = generated_ech();
    let port = free_port();
    let _peer = mihomo_server_with_ech(port, None, Some(&keys));
    let (echo, _) = tcp_echo();
    let mut settings = Settings::default();
    settings.insert_text("password", PASSWORD);
    settings.insert_text("sni", "localhost");
    settings.insert_text("skip-cert-verify", "true");
    settings.insert_text("client-fingerprint", "chrome");
    settings.insert_text("ech-opts", json!({"enable": true, "config": config}).to_string());
    let client = Client::new("127.0.0.1", port, &settings).unwrap();
    let stream = client.open_stream("127.0.0.1", echo.port()).unwrap();
    let payload = vec![0xa5; 192 * 1024];
    stream.write_all(&payload).unwrap();
    assert_eq!(read_exact(&stream, payload.len()), payload);
    client.close();
}

#[test]
#[ignore]
fn mihomo_client_interoperates_with_kerlico_ech() {
    let (config, keys) = generated_ech();
    let port = kerlico_server_with_ech(None, Some(&keys));
    let mixed = free_port();
    let _peer = mihomo_client_with_ech(mixed, port, PASSWORD, Some(&config));
    let (echo, _) = tcp_echo();
    assert!(socks_roundtrip(mixed, echo));
}

fn kerlico_client(port: u16, password: &str) -> Client {
    let mut settings = Settings::default();
    settings.insert_text("password", password);
    settings.insert_text("sni", "localhost");
    settings.insert_text("skip-cert-verify", "true");
    settings.insert_text("udp", "true");
    settings.insert_text("idle-session-check-interval", "6");
    settings.insert_text("idle-session-timeout", "6");
    Client::new("127.0.0.1", port, &settings).unwrap()
}

// --- fixtures ---------------------------------------------------------------------------------

#[derive(Default)]
struct Seen {
    connections: Vec<Arc<Mutex<Recorded>>>,
}

#[derive(Default)]
struct Recorded {
    upstream: Vec<u8>,
    closed: bool,
}

/// A TCP relay in front of `target` that keeps the client-to-server bytes of every connection.
fn relay(target: u16) -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(server) = TcpStream::connect(("127.0.0.1", target)) else { continue };
            let entry = Arc::new(Mutex::new(Recorded::default()));
            record.lock().unwrap().connections.push(Arc::clone(&entry));
            let (mut client_read, mut server_write) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            let (mut server_read, mut client_write) = (server, client);
            let up = Arc::clone(&entry);
            thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                loop {
                    match client_read.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            up.lock().unwrap().upstream.extend_from_slice(&buf[..n]);
                            if server_write.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = server_write.shutdown(Shutdown::Write);
            });
            let down = Arc::clone(&entry);
            thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                loop {
                    match server_read.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if client_write.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = client_write.shutdown(Shutdown::Both);
                down.lock().unwrap().closed = true;
            });
        }
    });
    (port, seen)
}

/// Lengths of the TLS application-data records the client sent, without its Finished.
fn app_records(bytes: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut at = 0;
    while at + 5 <= bytes.len() {
        let len = usize::from(u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]));
        if at + 5 + len > bytes.len() {
            break;
        }
        if bytes[at] == 23 {
            lengths.push(len);
        }
        at += 5 + len;
    }
    lengths.drain(..1.min(lengths.len()));
    lengths
}

fn tcp_echo() -> (SocketAddr, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(Mutex::new(0));
    let count = Arc::clone(&accepted);
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            *count.lock().unwrap() += 1;
            thread::spawn(move || {
                let mut tcp = tcp;
                let mut buf = vec![0u8; 65536];
                loop {
                    match tcp.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if tcp.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, accepted)
}

fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], peer);
        }
    });
    addr
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed)).collect()
}

// --- SOCKS5 against mihomo's mixed port --------------------------------------------------------

fn socks_connect(proxy: u16, target: SocketAddr) -> TcpStream {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    tcp.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    let SocketAddr::V4(v4) = target else { panic!("v4") };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    tcp.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "SOCKS CONNECT refused");
    tcp
}

struct SocksUdp {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

fn socks_udp(proxy: u16) -> SocksUdp {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let local = socket.local_addr().unwrap();
    let SocketAddr::V4(v4) = local else { panic!("v4") };
    let mut request = vec![5, 3, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    tcp.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "SOCKS UDP ASSOCIATE refused");
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    SocksUdp { _control: tcp, socket, relay: SocketAddr::from(([127, 0, 0, 1], port)) }
}

impl SocksUdp {
    fn exchange(&self, target: SocketAddr, payload: &[u8]) -> (SocketAddr, Vec<u8>) {
        let SocketAddr::V4(v4) = target else { panic!("v4") };
        let mut packet = vec![0, 0, 0, 1];
        packet.extend_from_slice(&v4.ip().octets());
        packet.extend_from_slice(&v4.port().to_be_bytes());
        packet.extend_from_slice(payload);
        self.socket.send_to(&packet, self.relay).unwrap();
        let mut buf = vec![0u8; 65536];
        let n = self.socket.recv(&mut buf).unwrap();
        assert_eq!(buf[3], 1, "reply source is IPv4");
        let from = SocketAddr::from(([buf[4], buf[5], buf[6], buf[7]], u16::from_be_bytes([buf[8], buf[9]])));
        (from, buf[10..n].to_vec())
    }
}

fn round_trips(tcp: &mut TcpStream, seed: u8) {
    for round in 0..16 {
        let block = pattern(32 * 1024 + round, seed);
        tcp.write_all(&block).unwrap();
        let mut back = vec![0u8; block.len()];
        tcp.read_exact(&mut back).unwrap();
        assert_eq!(back, block, "round {round}");
    }
}

fn large(tcp: TcpStream, len: usize) {
    let data = pattern(len, 77);
    let mut reader = tcp.try_clone().unwrap();
    let expect = Sha256::digest(&data);
    let read = thread::spawn(move || {
        let mut back = vec![0u8; len];
        reader.read_exact(&mut back).unwrap();
        Sha256::digest(&back)
    });
    let mut writer = tcp;
    writer.write_all(&data).unwrap();
    assert_eq!(read.join().unwrap(), expect);
}

fn read_exact(stream: &landing_anytls::ClientStream, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut have = 0;
    while have < len {
        let n = stream.read_for(&mut out[have..], Duration::from_secs(20)).unwrap();
        assert!(n > 0, "EOF after {have} of {len}");
        have += n;
    }
    out
}

fn ready_stream(client: &Client, echo: SocketAddr) -> landing_anytls::ClientStream {
    let mut stream = None;
    assert!(wait_until(Duration::from_secs(10), || {
        let Ok(candidate) = client.open_stream(&echo.ip().to_string(), echo.port()) else { return false };
        let mut byte = [0u8];
        if candidate.write_all(b"q").is_ok()
            && candidate.read_for(&mut byte, Duration::from_secs(1)).ok() == Some(1) && byte == [b'q']
        {
            stream = Some(candidate);
        }
        stream.is_some()
    }), "transport peer never returned the readiness payload");
    stream.unwrap()
}

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    done()
}

// --- mihomo client to Kerlico server -----------------------------------------------------------

#[test]
#[ignore]
fn mihomo_client_tcp_concurrent_and_large() {
    let (echo, _) = tcp_echo();
    let server = kerlico_server(None);
    let mixed = free_port();
    let _client = mihomo_client(mixed, server, PASSWORD);
    let workers: Vec<_> = (0..4u8)
        .map(|seed| {
            thread::spawn(move || {
                let mut tcp = socks_connect(mixed, echo);
                round_trips(&mut tcp, seed);
                large(tcp, 8 << 20);
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
#[ignore]
fn mihomo_client_udp_over_tcp() {
    let (first, second) = (udp_echo(), udp_echo());
    let server = kerlico_server(None);
    let mixed = free_port();
    let _client = mihomo_client(mixed, server, PASSWORD);
    let udp = socks_udp(mixed);
    for (target, payload) in [(first, b"one".to_vec()), (second, b"two".to_vec()), (first, pattern(1400, 1)), (second, Vec::new())] {
        let (from, reply) = udp.exchange(target, &payload);
        assert_eq!(from, target);
        assert_eq!(reply, payload);
    }
}

#[test]
#[ignore]
fn mihomo_client_takes_the_kerlico_padding_scheme() {
    let (echo, _) = tcp_echo();
    let server = kerlico_server(Some(FIXED_SCHEME));
    let (front, seen) = relay(server);
    let mixed = free_port();
    let client = mihomo_client(mixed, front, PASSWORD);
    // The first session starts with the default scheme and learns the new one.
    let mut first = socks_connect(mixed, echo);
    first.write_all(b"x").unwrap();
    first.read_exact(&mut [0u8; 1]).unwrap();
    assert!(wait_until(Duration::from_secs(5), || client.log().contains("Update padding succeed")), "mihomo logged the update");
    // While it is busy, a second stream needs a new session, which pads with the fixed scheme.
    let mut second = socks_connect(mixed, echo);
    second.write_all(&[9u8; 100]).unwrap();
    second.read_exact(&mut [0u8; 100]).unwrap();
    let records = {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.connections.len(), 2);
        let recorded = seen.connections[1].lock().unwrap().upstream.clone();
        app_records(&recorded)
    };
    // auth 34+20, packet 1 to 150, packet 2 (100-byte write) to 200; 17 bytes of TLS overhead each.
    assert_eq!(&records[..3], &[54 + 17, 150 + 17, 200 + 17], "{records:?}");
    drop(first);
    drop(second);
}

#[test]
#[ignore]
fn mihomo_client_reuses_and_closes_idle_sessions() {
    let (echo, _) = tcp_echo();
    let server = kerlico_server(None);
    let (front, seen) = relay(server);
    let mixed = free_port();
    let _client = mihomo_client(mixed, front, PASSWORD);
    let mut tcp = socks_connect(mixed, echo);
    round_trips(&mut tcp, 1);
    drop(tcp);
    thread::sleep(Duration::from_millis(500));
    let mut tcp = socks_connect(mixed, echo);
    round_trips(&mut tcp, 2);
    drop(tcp);
    assert_eq!(seen.lock().unwrap().connections.len(), 1, "the second stream reused the idle session");
    let closed = wait_until(Duration::from_secs(25), || seen.lock().unwrap().connections[0].lock().unwrap().closed);
    assert!(closed, "mihomo closed the idle session after its timeout");
}

#[test]
#[ignore]
fn mihomo_client_with_a_wrong_password_reaches_nothing() {
    let (echo, accepted) = tcp_echo();
    let server = kerlico_server(None);
    let mixed = free_port();
    let _client = mihomo_client(mixed, server, "not-the-password");
    if let Ok(mut tcp) = TcpStream::connect(("127.0.0.1", mixed)) {
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = tcp.write_all(&[5, 1, 0]);
        let mut reply = [0u8; 2];
        let _ = tcp.read_exact(&mut reply);
        let SocketAddr::V4(v4) = echo else { panic!() };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&v4.ip().octets());
        request.extend_from_slice(&v4.port().to_be_bytes());
        let _ = tcp.write_all(&request);
        let _ = tcp.write_all(b"hello");
        let mut buf = [0u8; 64];
        let mut got = Vec::new();
        while let Ok(n) = tcp.read(&mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert!(!got.windows(5).any(|window| window == b"hello"), "no echo came back");
    }
    thread::sleep(Duration::from_millis(300));
    assert_eq!(*accepted.lock().unwrap(), 0, "the target saw no connection");
}

// --- Kerlico client to mihomo server -----------------------------------------------------------

#[test]
#[ignore]
fn kerlico_client_tcp_concurrent_and_large() {
    let (echo, _) = tcp_echo();
    let port = free_port();
    let _server = mihomo_server(port, None);
    let client = Arc::new(kerlico_client(port, PASSWORD));
    let workers: Vec<_> = (0..4u8)
        .map(|seed| {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                let stream = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
                for round in 0..16 {
                    let block = pattern(32 * 1024 + round, seed);
                    stream.write_all(&block).unwrap();
                    assert_eq!(read_exact(&stream, block.len()), block);
                }
                let big = pattern(8 << 20, seed);
                let back = thread::scope(|scope| {
                    let reader = scope.spawn(|| read_exact(&stream, big.len()));
                    for chunk in big.chunks(64 * 1024) {
                        stream.write_all(chunk).unwrap();
                    }
                    reader.join().unwrap()
                });
                assert_eq!(Sha256::digest(&back), Sha256::digest(&big));
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
#[ignore]
fn kerlico_session_multiplexes_streams_on_mihomo() {
    let (echo, _) = tcp_echo();
    let port = free_port();
    let _server = mihomo_server(port, None);
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let config = tls::client_config(&tls::ClientTls { insecure: true, ..Default::default() }).unwrap();
    let link = tls::connect(tcp, config, "localhost").unwrap();
    let session = Session::client(link, SchemeCell::new(Scheme::default_scheme()), "", &password_hash(PASSWORD)).unwrap();
    let streams: Vec<_> = (0..6u8)
        .map(|seed| {
            let stream = session.open_stream().unwrap();
            let mut addr = Vec::new();
            Target::new(echo.ip().to_string(), echo.port()).encode(Family::Socks, &mut addr).unwrap();
            stream.write(&addr).unwrap();
            (seed, stream)
        })
        .collect();
    let workers: Vec<_> = streams
        .into_iter()
        .map(|(seed, stream)| {
            thread::spawn(move || {
                let block = pattern(2 << 20, seed);
                thread::scope(|scope| {
                    let reader = scope.spawn(|| {
                        let mut out = vec![0u8; block.len()];
                        let mut have = 0;
                        while have < out.len() {
                            let n = stream.read_for(&mut out[have..], Duration::from_secs(20)).unwrap();
                            assert!(n > 0);
                            have += n;
                        }
                        out
                    });
                    for chunk in block.chunks(32 * 1024) {
                        stream.write(chunk).unwrap();
                    }
                    assert_eq!(reader.join().unwrap(), block);
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(session.peer_version(), 2, "mihomo answered with cmdServerSettings");
    session.close();
}

#[test]
#[ignore]
fn kerlico_client_udp_over_tcp() {
    let (first, second) = (udp_echo(), udp_echo());
    let port = free_port();
    let _server = mihomo_server(port, None);
    let client = kerlico_client(port, PASSWORD);
    let assoc = client.associate().unwrap();
    for (target, payload) in [(first, b"one".to_vec()), (second, b"two".to_vec()), (first, pattern(1400, 2)), (second, Vec::new())] {
        assoc.send_to(&target.ip().to_string(), target.port(), &payload).unwrap();
        let (host, reply_port, reply) = assoc.recv_for(Duration::from_secs(10)).unwrap();
        assert_eq!((host, reply_port), (target.ip().to_string(), target.port()));
        assert_eq!(reply, payload);
    }
}

#[test]
#[ignore]
fn kerlico_client_takes_the_mihomo_padding_scheme() {
    let (echo, _) = tcp_echo();
    let port = free_port();
    let _server = mihomo_server(port, Some(FIXED_SCHEME));
    let (front, seen) = relay(port);
    let client = kerlico_client(front, PASSWORD);
    let first = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    first.write_all(b"x").unwrap();
    read_exact(&first, 1);
    let expected = Scheme::parse(FIXED_SCHEME.as_bytes()).unwrap().md5().to_string();
    assert!(wait_until(Duration::from_secs(5), || client.padding_md5() == expected));
    let second = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    second.write_all(&[9u8; 100]).unwrap();
    read_exact(&second, 100);
    let records = {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.connections.len(), 2);
        let recorded = seen.connections[1].lock().unwrap().upstream.clone();
        app_records(&recorded)
    };
    // The same lengths mihomo's own client produces in `mihomo_client_takes_the_kerlico_padding_scheme`.
    assert_eq!(&records[..3], &[54 + 17, 150 + 17, 200 + 17], "{records:?}");
}

#[test]
#[ignore]
fn kerlico_client_reuses_and_closes_idle_sessions() {
    let (echo, _) = tcp_echo();
    let port = free_port();
    let _server = mihomo_server(port, None);
    let (front, seen) = relay(port);
    let client = kerlico_client(front, PASSWORD);
    let stream = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    stream.write_all(b"one").unwrap();
    read_exact(&stream, 3);
    drop(stream);
    thread::sleep(Duration::from_millis(500));
    let stream = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    stream.write_all(b"two").unwrap();
    read_exact(&stream, 3);
    drop(stream);
    assert_eq!(seen.lock().unwrap().connections.len(), 1, "the idle session was reused");
    let closed = wait_until(Duration::from_secs(25), || seen.lock().unwrap().connections[0].lock().unwrap().closed);
    assert!(closed, "the idle session closed after its timeout");
    assert_eq!(client.session_count(), 0);
}

#[test]
#[ignore]
fn kerlico_client_with_a_wrong_password_reaches_nothing() {
    let (echo, accepted) = tcp_echo();
    let port = free_port();
    let _server = mihomo_server(port, None);
    let client = kerlico_client(port, "not-the-password");
    if let Ok(stream) = client.open_stream(&echo.ip().to_string(), echo.port()) {
        let _ = stream.write_all(b"hello");
        let mut buf = [0u8; 16];
        let result = stream.read_for(&mut buf, Duration::from_secs(5));
        assert!(matches!(result, Ok(0) | Err(_)), "{result:?}");
    }
    thread::sleep(Duration::from_millis(300));
    assert_eq!(*accepted.lock().unwrap(), 0, "the target saw no connection");
}
