#![cfg(all(feature = "vless", feature = "landing-vless"))]

//! Run with `XRAY=/path/to/xray cargo test -p kerlico-server --no-default-features
//! --features vless,landing-vless --test vless_xray vless_xray_matrix -- --ignored --nocapture`.
//! `VLESS_CASE` filters case/direction labels by comma-separated substrings.
//! `VLESS_XRAY_CONTROL=1` adds an Xray-to-Xray run. `VLESS_RUN_DIR` holds logs and configs.
//! The separate `vless_xray_rejections` test checks Xray's config rejection boundaries.

#[path = "vless_support/cases.rs"]
mod cases;
#[path = "vless_support/mod.rs"]
mod support;
#[path = "vless_support/xdrive_mock.rs"]
mod xdrive_mock;

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use cases::{Case, Keys, Network, Payload, Security, INGRESS_ID, ORIGIN_NAME, TLS_NAME};
use support::{
    available_port, localhost, print_logs, run_dir, tcp_connect, write_json, Echo, Process, Result,
    TIMEOUT,
};

const XRAY_VERSION: &str = "26.10.31";
const XRAY_BUILD: &str = "a4a3dff";
const KERLICO_CHILD: &str = "KERLICO_VLESS_XRAY_PEER_CONFIG";

/// The matrix and the paced REALITY target checks run one at a time. Run together,
/// the cleartext HTTPUpgrade early-data row loses bytes against the pinned Xray
/// although it passes alone, and the pacing bounds would measure the extra load.
static PEER_RUNS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn exclusive_peer_run() -> std::sync::MutexGuard<'static, ()> {
    PEER_RUNS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Copy)]
enum Direction {
    XrayControl,
    XrayToKerlico,
    KerlicoToXray,
}

impl Direction {
    fn name(self) -> &'static str {
        match self {
            Self::XrayControl => "xray-control",
            Self::XrayToKerlico => "xray-to-kerlico",
            Self::KerlicoToXray => "kerlico-to-xray",
        }
    }
}

#[test]
#[ignore = "requires XRAY pointing to Xray 26.10.31 a4a3dff"]
fn vless_xray_matrix() {
    if let Some(config) = std::env::var_os(KERLICO_CHILD) {
        serve_kerlico(Path::new(&config)).expect("Kerlico peer");
        return;
    }
    let _exclusive = exclusive_peer_run();
    let root = run_dir("matrix").expect("matrix directory");
    let xray = xray_binary(&root).expect("pinned Xray peer");
    let filter = std::env::var("VLESS_CASE").unwrap_or_default();
    let mut directions = vec![Direction::XrayToKerlico, Direction::KerlicoToXray];
    if std::env::var("VLESS_XRAY_CONTROL").as_deref() == Ok("1") || filter.contains("xray-control")
    {
        directions.insert(0, Direction::XrayControl);
    }
    let mut runs = 0;
    let mut failed = Vec::new();
    for case in cases::cases() {
        for &direction in &directions {
            let label = format!("{}/{}", case.name, direction.name());
            if !selected(&filter, &label) {
                continue;
            }
            runs += 1;
            let dir = root.join(&case.name).join(direction.name());
            let result = fs::create_dir_all(&dir)
                .map_err(Into::into)
                .and_then(|_| run_case(&xray, &dir, &case, direction));
            report(&label, result, &dir, &mut failed);
        }
    }
    finish_report(runs, &failed, &root);
}

fn run_case(xray: &Path, dir: &Path, case: &Case, direction: Direction) -> Result<()> {
    let mut keys = Keys::generate(dir, case)?;
    let storage = case.mock.map(|service| {
        xdrive_mock::Mock::start(service, case.security, &keys.cert_pem, &keys.key_pem)
    }).transpose()?;
    keys.mock_addr = storage.as_ref().map(|storage| storage.addr);
    let decoy = if matches!(case.security, Security::Reality) {
        let config = kerlico_vless::server_config(
            &keys.cert_pem,
            &keys.key_pem,
            &["h2".into(), "http/1.1".into()],
        )
        .map_err(|_| "make REALITY TLS target")?;
        let echo = Echo::tcp(Some(config))?;
        keys.decoy = echo.port;
        Some(echo)
    } else {
        None
    };
    let origin = if case.payload.udp() {
        let port = if case.payload == Payload::Udp443 {
            443
        } else {
            0
        };
        Echo::udp(port).map_err(|error| format!("UDP echo origin on port {port}: {error}"))?
    } else {
        let tls = if case.payload == Payload::InnerTls {
            Some(
                kerlico_vless::server_config(&keys.cert_pem, &keys.key_pem, &[])
                    .map_err(|_| "make inner TLS echo origin")?,
            )
        } else {
            None
        };
        Echo::tcp(tls)?
    };
    let peer = available_port()?;
    let download = if case.separate_download() {
        let (port, used) = download_proxy(peer)?;
        keys.download = port;
        Some(used)
    } else {
        None
    };
    let mut front = available_port()?;
    while front == peer
        || front == origin.port
        || decoy.as_ref().is_some_and(|target| front == target.port)
    {
        front = available_port()?;
    }

    let carrier = if case.name.starts_with("grpc-") && case.payload == Payload::TwoTcp {
        Some(count_tcp_carriers(peer)?)
    } else {
        None
    };
    let client_peer = carrier.as_ref().map_or(peer, |(port, _)| *port);
    let peers = match direction {
        Direction::XrayToKerlico => (
            start_kerlico(dir, &case.kerlico_server(&keys, peer))?,
            start_xray(
                xray,
                dir,
                "xray-client",
                &case.xray_client(&keys, front, client_peer, origin.port),
            )?,
        ),
        Direction::KerlicoToXray => (
            start_xray(
                xray,
                dir,
                "xray-server",
                &case.xray_server(&keys, peer, origin.port),
            )?,
            start_kerlico(dir, &case.kerlico_landing(&keys, front, client_peer))?,
        ),
        Direction::XrayControl => (
            start_xray(
                xray,
                dir,
                "xray-server",
                &case.xray_server(&keys, peer, origin.port),
            )?,
            start_xray(
                xray,
                dir,
                "xray-client",
                &case.xray_client(&keys, front, client_peer, origin.port),
            )?,
        ),
    };

    let inject = matches!(direction, Direction::KerlicoToXray);
    let rounds = if case.resume { 3 } else { 1 };
    for round in 0..rounds {
        let result = if case.payload.udp() {
            exercise_udp(front, origin.port, inject)
        } else {
            exercise_tcp(front, origin.port, inject, case.payload, carrier.is_some())
        };
        result.map_err(|error| format!("traffic round {}: {error}", round + 1))?;
    }
    if case.name.starts_with("hysteria-quic-") {
        exercise_hysteria_http(peer, &case.name)?;
    }
    if download.is_some_and(|used| !used.load(Ordering::Relaxed)) {
        return Err("XHTTP did not use the downloadSettings endpoint".into());
    }
    if let Some((_, count)) = carrier {
        let count = count.load(Ordering::Acquire);
        if count != 1 {
            return Err(format!("two gRPC calls opened {count} TCP connections").into());
        }
    }
    drop(peers);
    if let Some(storage) = storage {
        storage.verify(!case.payload.udp())?;
    }
    Ok(())
}

fn exercise_hysteria_http(peer: u16, case: &str) -> Result<()> {
    let tls = kerlico_vless::client_config(&[], true).map_err(|_| "HTTP/3 probe TLS")?;
    let conn = kerlico_vless::H3Conn::connect(std::net::SocketAddr::from(([127, 0, 0, 1], peer)), tls, TLS_NAME)?;
    let request = |method: &str, path: &str, authority: &str, headers: &[(&str, &str)]| -> Result<kerlico_vless::H3Stream> {
        let stream = conn.request(method, path, authority, "https", headers, false)?;
        stream.finish_write()?;
        Ok(stream)
    };
    let masquerade = case == "hysteria-quic-masquerade-string";
    let status = if masquerade { 418 } else { 404 };
    let expected = if masquerade { "matrix Hysteria cover\n" } else { "404 page not found\n" };
    let mut hidden = request("POST", "/auth", "hysteria", &[("hysteria-auth", "invalid")])?;
    assert_eq!(hidden.response_status()?, status);
    let mut body = String::new();
    hidden.read_to_string(&mut body)?;
    assert_eq!(body, expected);
    let headers = [("hysteria-auth", cases::AUTH), ("hysteria-cc-rx", "786432")];
    let auth = request("POST", "/auth", "hysteria", &headers)?;
    assert_eq!(auth.response_status()?, 233);
    assert_eq!(auth.header("hysteria-udp").as_deref(), Some("false"));
    let rate = if case == "hysteria-quic-negotiated-brutal" { "524288" } else { "0" };
    assert_eq!(auth.header("hysteria-cc-rx").as_deref(), Some(rate));
    let mut cover = request("GET", "/cover", TLS_NAME, &[])?;
    assert_eq!(cover.response_status()?, status);
    assert_eq!(cover.header("x-cover").as_deref(), masquerade.then_some("matrix"));
    body.clear();
    cover.read_to_string(&mut body)?;
    assert_eq!(body, expected);
    Ok(())
}

fn count_tcp_carriers(peer: u16) -> Result<(u16, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT * 2;
        while Instant::now() < deadline {
            let mut client = match listener.accept() {
                Ok((socket, _)) => socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(_) => return,
            };
            observed.fetch_add(1, Ordering::Release);
            thread::spawn(move || {
                let Ok(mut server) = TcpStream::connect(("127.0.0.1", peer)) else { return };
                let (Ok(mut input), Ok(mut output)) = (client.try_clone(), server.try_clone()) else { return };
                thread::spawn(move || {
                    let _ = std::io::copy(&mut input, &mut output);
                    let _ = output.shutdown(Shutdown::Write);
                });
                let _ = std::io::copy(&mut server, &mut client);
                let _ = client.shutdown(Shutdown::Write);
            });
        }
    });
    Ok((port, count))
}

fn download_proxy(peer: u16) -> Result<(u16, Arc<AtomicBool>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let used = Arc::new(AtomicBool::new(false));
    let observed = used.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT * 2;
        let mut client = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => return,
            }
        };
        let Ok(mut server) = TcpStream::connect(("127.0.0.1", peer)) else {
            return;
        };
        let (Ok(mut input), Ok(mut output)) = (client.try_clone(), server.try_clone()) else {
            return;
        };
        observed.store(true, Ordering::Relaxed);
        thread::spawn(move || {
            let _ = std::io::copy(&mut input, &mut output);
            let _ = output.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut server, &mut client);
        let _ = client.shutdown(Shutdown::Write);
    });
    Ok((port, used))
}

fn xray_binary(dir: &Path) -> Result<PathBuf> {
    let xray = PathBuf::from(std::env::var_os("XRAY").ok_or("set XRAY to the pinned executable")?)
        .canonicalize()?;
    let mut command = Command::new(&xray);
    command.arg("version");
    let mut process = Process::spawn(command, dir, "xray-version")?;
    let status = process.finish()?;
    let output = process.output()?;
    let version = output.lines().next().unwrap_or_default();
    if !status.success()
        || !version.starts_with(&format!("Xray {XRAY_VERSION} "))
        || !version.split_whitespace().any(|word| word == XRAY_BUILD)
    {
        return Err(
            format!("expected Xray {XRAY_VERSION} {XRAY_BUILD}, got {status}: {output}").into(),
        );
    }
    eprintln!("XRAY {version}");
    Ok(xray)
}

fn start_xray(xray: &Path, dir: &Path, name: &str, config: &Value) -> Result<Process> {
    let path = write_json(dir, &format!("{name}.json"), config)?;
    let mut command = Command::new(xray);
    command.args(["run", "-c"]).arg(path);
    // Keep un-muxed UDP cases on VLESS command 2. Vision and explicit mux still use XUDP.
    command.env("xray.cone.disabled", "true");
    let mut process = Process::spawn(command, dir, name)?;
    process.wait_for_log(&format!("Xray {XRAY_VERSION} started"))?;
    Ok(process)
}

fn start_kerlico(dir: &Path, config: &Value) -> Result<Process> {
    let config = write_json(dir, "kerlico.json", config)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--ignored", "--exact", "vless_xray_matrix", "--nocapture"])
        .env(KERLICO_CHILD, config);
    let mut process = Process::spawn(command, dir, "kerlico")?;
    process.wait_ready(|| dir.join("kerlico.ready").is_file())?;
    Ok(process)
}

fn serve_kerlico(path: &Path) -> Result<()> {
    let config = fs::read_to_string(path)?;
    let mut loaded = kerlico_server::Server::from_config(&config)
        .map_err(|error| format!("load Kerlico peer: {error:?}"))?;
    fs::write(path.with_file_name("kerlico.ready"), b"")?;
    loaded
        .server
        .run(loaded.dns)
        .map_err(|error| format!("Kerlico run: {error:?}").into())
}

fn open_front(port: u16, origin: u16, inject: bool, udp: bool) -> Result<TcpStream> {
    let mut stream = tcp_connect(port).map_err(|error| format!("connect front {port}: {error}"))?;
    if inject {
        // The ingress fixture is VLESS version 0, no addons, a DNS target, and command 1 or 2.
        let mut request = vec![0];
        request.extend_from_slice(&INGRESS_ID);
        request.extend_from_slice(&[0, if udp { 2 } else { 1 }]);
        request.extend_from_slice(&origin.to_be_bytes());
        request.extend_from_slice(&[2, ORIGIN_NAME.len() as u8]);
        request.extend_from_slice(ORIGIN_NAME.as_bytes());
        stream.write_all(&request)?;
        let mut response = [0; 2];
        stream
            .read_exact(&mut response)
            .map_err(|error| format!("Kerlico injection header: {error}"))?;
        if response != [0, 0] {
            return Err(format!("unexpected Kerlico injection response {response:?}").into());
        }
    }
    Ok(stream)
}

fn exercise_tcp(front: u16, origin: u16, inject: bool, payload: Payload, shared_grpc: bool) -> Result<()> {
    let mut stream = open_front(front, origin, inject, false)?;
    if payload == Payload::InnerTls {
        let tls = kerlico_vless::client_config(&[], true).map_err(|_| "make inner TLS client")?;
        let mut stream = kerlico_vless::connect_tls(stream, tls, TLS_NAME)
            .map_err(|error| format!("inner TLS handshake: {error}"))?;
        return tcp_exchange(&mut stream, 17, 33)
            .and_then(|_| tcp_exchange(&mut stream, 196_613, 123));
    }
    tcp_exchange(&mut stream, 17, 33)?;
    if payload == Payload::TwoTcp {
        let mut second = open_front(front, origin, inject, false)?;
        tcp_exchange(&mut second, 19, 77)?;
        if shared_grpc {
            thread::scope(|scope| {
                let first = scope.spawn(|| tcp_exchange(&mut stream, 2_300_013, 123).map_err(|error| error.to_string()));
                tcp_exchange(&mut second, 2_000_017, 11)?;
                first.join().unwrap()?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        } else {
            tcp_exchange(&mut stream, 196_613, 123)?;
            tcp_exchange(&mut second, 131_077, 11)?;
        }
        return tcp_exchange(&mut stream, 29, 222);
    }
    tcp_exchange(&mut stream, 196_613, 123)
}

fn tcp_exchange(stream: &mut (impl Read + Write), len: usize, seed: usize) -> Result<()> {
    let expected = pattern(len, seed);
    stream
        .write_all(&expected)
        .map_err(|error| format!("write {len} TCP bytes: {error}"))?;
    stream.flush()?;
    let mut bytes = vec![0; len];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| format!("read {len} TCP bytes: {error}"))?;
    compare(&expected, &bytes, "TCP")
}

fn exercise_udp(front: u16, origin: u16, inject: bool) -> Result<()> {
    let sizes = [1, 7171, 39, 4103];
    if inject {
        let mut stream = open_front(front, origin, true, true)?;
        for (index, len) in sizes.into_iter().enumerate() {
            let expected = pattern(len, index);
            stream.write_all(&(len as u16).to_be_bytes())?;
            stream.write_all(&expected)?;
            let mut prefix = [0; 2];
            stream
                .read_exact(&mut prefix)
                .map_err(|error| format!("receive {len}-byte UDP reply header: {error}"))?;
            let received = u16::from_be_bytes(prefix) as usize;
            if received != len {
                return Err(format!("UDP frame length {received}, expected {len}").into());
            }
            let mut bytes = vec![0; received];
            stream.read_exact(&mut bytes)?;
            compare(&expected, &bytes, "UDP")?;
        }
    } else {
        let socket = UdpSocket::bind(localhost(0))?;
        socket.connect(localhost(front))?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.set_write_timeout(Some(TIMEOUT))?;
        let mut bytes = [0; 65536];
        for (index, len) in sizes.into_iter().enumerate() {
            let expected = pattern(len, index);
            let written = socket.send(&expected)?;
            if written != len {
                return Err(format!("sent {written}/{len} UDP bytes").into());
            }
            let received = socket
                .recv(&mut bytes)
                .map_err(|error| format!("receive {len}-byte UDP reply: {error}"))?;
            compare(&expected, &bytes[..received], "UDP")?;
        }
    }
    Ok(())
}

fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 37 + seed) % 251) as u8)
        .collect()
}

fn compare(expected: &[u8], actual: &[u8], transport: &str) -> Result<()> {
    if actual.len() != expected.len() {
        return Err(format!(
            "{transport} length {}, expected {}",
            actual.len(),
            expected.len()
        )
        .into());
    }
    if let Some(index) = expected
        .iter()
        .zip(actual)
        .position(|(left, right)| left != right)
    {
        return Err(format!(
            "{transport} byte {index} differs ({} != {})",
            actual[index], expected[index]
        )
        .into());
    }
    Ok(())
}

fn selected(filter: &str, label: &str) -> bool {
    filter.is_empty()
        || filter
            .split(',')
            .map(str::trim)
            .any(|term| !term.is_empty() && label.contains(term))
}

fn report(label: &str, result: Result<()>, dir: &Path, failures: &mut Vec<String>) {
    match result {
        Ok(()) => eprintln!("PASS {label}"),
        Err(error) => {
            eprintln!("FAIL {label}: {error}");
            print_logs(dir);
            failures.push(label.into());
        }
    }
}

fn finish_report(runs: usize, failures: &[String], root: &Path) {
    assert!(runs > 0, "no cases matched VLESS_CASE");
    eprintln!(
        "VLESS matrix: {}/{} passed. Artifacts: {}",
        runs - failures.len(),
        runs,
        root.display()
    );
    assert!(failures.is_empty(), "failed cases: {}", failures.join(", "));
}

#[test]
#[ignore = "requires XRAY pointing to Xray 26.10.31 a4a3dff"]
fn vless_xray_rejections() {
    let root = run_dir("rejections").expect("rejections directory");
    let xray = xray_binary(&root).expect("pinned Xray peer");
    let filter = std::env::var("VLESS_CASE").unwrap_or_default();
    let mut runs = 0;
    let mut failed = Vec::new();
    for (name, config) in rejection_configs(&root).expect("rejection fixtures") {
        if !selected(&filter, &name) {
            continue;
        }
        runs += 1;
        let dir = root.join(&name);
        let result = (|| -> Result<()> {
            fs::create_dir(&dir)?;
            let path = write_json(&dir, "xray-invalid.json", &config)?;
            let mut command = Command::new(&xray);
            command.args(["run", "-test", "-c"]).arg(path);
            let mut process = Process::spawn(command, &dir, "xray")?;
            let status = process.finish()?;
            if status.code() != Some(23) {
                return Err(
                    format!("expected Xray config rejection (exit 23), got {status}").into(),
                );
            }
            Ok(())
        })();
        report(&name, result, &dir, &mut failed);
    }
    finish_report(runs, &failed, &root);
}

fn rejection_configs(dir: &Path) -> Result<Vec<(String, Value)>> {
    let raw = Case::new("raw", Network::Raw, Security::None, Payload::Tcp);
    let keys = Keys::generate(dir, &raw)?;
    let client = raw.xray_client(&keys, 20501, 20502, 20503);
    let server = raw.xray_server(&keys, 20502, 20503);
    let mut configs = Vec::new();
    for network in ["http", "h2", "h3", "quic", "masque"] {
        let mut config = client.clone();
        config["outbounds"][0]["streamSettings"]["network"] = json!(network);
        configs.push((format!("reject-vless-{network}"), config));
    }
    let mut config = client.clone();
    config["outbounds"][0]["streamSettings"]["security"] = json!("xtls");
    configs.push(("reject-legacy-xtls".into(), config));
    let mut config = client.clone();
    config["outbounds"][0]["settings"]["address"] = json!("203.0.113.1");
    configs.push(("reject-public-cleartext".into(), config));
    let mut config = client;
    config["outbounds"][0]["streamSettings"] = json!({"network": "ws", "security": "reality"});
    configs.push(("reject-ws-reality".into(), config));

    let mut config = server.clone();
    config["inbounds"][0]["settings"]["users"][0]["flow"] = json!("xtls-rprx-vision-udp443");
    configs.push(("reject-inbound-vision-udp443-suffix".into(), config));
    let mut config = server;
    config["inbounds"][0]["streamSettings"] = json!({"network": "xdrive", "xdriveSettings": {"service": "local", "remoteFolder": keys.storage}});
    configs.push(("reject-xdrive-without-encryption".into(), config));

    let encrypted =
        Case::new("enc", Network::Raw, Security::None, Payload::Tcp).encryption("native", false);
    let encrypted_dir = dir.join("encryption-keys");
    fs::create_dir(&encrypted_dir)?;
    let keys = Keys::generate(&encrypted_dir, &encrypted)?;
    let mut config = encrypted.xray_server(&keys, 20502, 20503);
    config["inbounds"][0]["settings"]["fallbacks"] = json!([{"dest": 20503}]);
    configs.push(("reject-encryption-with-fallback".into(), config));
    Ok(configs)
}

const LIMITED_BYTES: usize = 1024 * 1024;
const LIMIT_AFTER: u64 = 64 * 1024;
const LIMIT_BURST: u64 = 384 * 1024;
const LIMIT_RATE: u64 = 256 * 1024;
/// Xray leaves its first 17 KiB read of the target unmetered, and the whole
/// 32 KiB read that crosses afterBytes.
const LIMIT_SLACK: u64 = 64 * 1024;

#[derive(Clone, Copy)]
enum RealityServer {
    Xray,
    Kerlico,
}

#[derive(Clone, Copy)]
enum DecoyAddress {
    Tcp,
    UnixPath,
    UnixAbstract,
    UnixPadded,
}

/// Each REALITY server gets the same target settings. Unauthenticated probes must reach
/// the decoy with the PROXY header and pacing the settings ask for, and an Xray client's
/// handshake must carry the record lengths the decoy sent for that client's ClientHello.
#[test]
#[ignore = "requires XRAY pointing to Xray 26.10.31 a4a3dff"]
fn vless_xray_reality_target() {
    let _exclusive = exclusive_peer_run();
    let root = run_dir("reality-target").expect("reality target directory");
    let xray = xray_binary(&root).expect("pinned Xray peer");
    let filter = std::env::var("VLESS_CASE").unwrap_or_default();
    let mut targets = vec![("tcp-xver1", DecoyAddress::Tcp, 1), ("tcp-xver2", DecoyAddress::Tcp, 2)];
    if cfg!(target_os = "linux") {
        targets.extend([
            ("unix-path-xver2", DecoyAddress::UnixPath, 2),
            ("unix-abstract-xver1", DecoyAddress::UnixAbstract, 1),
            ("unix-padded-xver2", DecoyAddress::UnixPadded, 2),
        ]);
    }
    let mut runs = 0;
    let mut failed = Vec::new();
    for (name, address, xver) in targets {
        for (server, side) in [(RealityServer::Xray, "xray-server"), (RealityServer::Kerlico, "kerlico-server")] {
            let label = format!("reality-target-{name}/{side}");
            if !selected(&filter, &label) {
                continue;
            }
            runs += 1;
            let dir = root.join(name).join(side);
            let result = fs::create_dir_all(&dir)
                .map_err(Into::into)
                .and_then(|_| reality_target(&xray, &dir, server, address, xver));
            report(&label, result, &dir, &mut failed);
        }
    }
    finish_report(runs, &failed, &root);
}

fn reality_target(xray: &Path, dir: &Path, server: RealityServer, address: DecoyAddress, xver: u8) -> Result<()> {
    let case = Case::new("reality-target", Network::Raw, Security::Reality, Payload::Tcp);
    let keys = Keys::generate(dir, &case)?;
    let decoy = Decoy::start(address, &keys)?;
    let origin = Echo::tcp(None)?;
    let port = available_port()?;
    let limit = json!({"afterBytes": LIMIT_AFTER, "bytesPerSec": LIMIT_RATE, "burstBytesPerSec": LIMIT_BURST});
    let reality = json!({"target": decoy.target, "xver": xver,
        "limitFallbackUpload": limit, "limitFallbackDownload": limit});
    let (mut config, settings) = match server {
        RealityServer::Xray => (case.xray_server(&keys, port, origin.port), "/inbounds/0/streamSettings/realitySettings"),
        RealityServer::Kerlico => (case.kerlico_server(&keys, port), "/inbounds/0/settings"),
    };
    let fields = config.pointer_mut(settings).and_then(Value::as_object_mut).ok_or("REALITY settings")?;
    fields.extend(reality.as_object().cloned().unwrap_or_default());
    let _server = match server {
        RealityServer::Xray => start_xray(xray, dir, "xray-server", &config)?,
        RealityServer::Kerlico => start_kerlico(dir, &config)?,
    };
    let mut failures = Vec::new();
    let mut check = |label: &str, result: Result<()>| {
        if let Err(error) = result {
            failures.push(format!("{label}: {error}"));
        }
    };
    match tls_probe(&keys, port) {
        Err(error) => check("TLS probe with the decoy certificate", Err(error)),
        Ok((mut read, mut write, prober)) => {
            let header = proxy_header(xver, prober, port);
            check("PROXY header", wait_recording(&decoy.recordings, |session| session.header == header).map(drop));
            check("limited download", limited_download(&mut read, &mut write));
            check("limited upload", limited_upload(&mut read, &mut write));
        }
    }
    check("plaintext probe", plaintext_probe(&decoy, port, xver));
    check("authenticated flight", authenticated_flight(xray, dir, &case, &keys, &decoy, port, origin.port));
    if failures.is_empty() {
        return Ok(());
    }
    Err(failures.join("; ").into())
}

/// Completes TLS before returning, so a pin mismatch means the prober did not see the decoy certificate.
fn tls_probe(keys: &Keys, port: u16) -> Result<(kerlico_vless::TlsRead, kerlico_vless::TlsWrite, std::net::SocketAddr)> {
    let stream = tcp_connect(port)?;
    let prober = stream.local_addr()?;
    let tls = kerlico_vless::client_config_pinned(&[], false, &keys.pin).map_err(|_| "prober TLS")?;
    let (read, write) = kerlico_vless::connect_tls_split(stream, tls, TLS_NAME)?;
    Ok((read, write, prober))
}

fn limited_download(read: &mut kerlico_vless::TlsRead, write: &mut kerlico_vless::TlsWrite) -> Result<()> {
    let started = Instant::now();
    write.write_all(&decoy_command(b'D', LIMITED_BYTES))?;
    write.flush()?;
    let mut bytes = vec![0; LIMITED_BYTES];
    read.read_exact(&mut bytes)?;
    compare(&pattern(LIMITED_BYTES, 3), &bytes, "download")?;
    paced(started.elapsed())
}

fn limited_upload(read: &mut kerlico_vless::TlsRead, write: &mut kerlico_vless::TlsWrite) -> Result<()> {
    let started = Instant::now();
    write.write_all(&decoy_command(b'U', LIMITED_BYTES))?;
    write.write_all(&pattern(LIMITED_BYTES, 5))?;
    write.flush()?;
    let mut done = [0; 2];
    read.read_exact(&mut done)?;
    paced(started.elapsed())
}

fn plaintext_probe(decoy: &Decoy, port: u16, xver: u8) -> Result<()> {
    let mut plain = tcp_connect(port)?;
    let header = proxy_header(xver, plain.local_addr()?, port);
    let request = b"GET /reality-probe HTTP/1.1\r\nHost: probe\r\n\r\n";
    plain.write_all(request)?;
    wait_recording(&decoy.recordings, |session| session.header == header && session.input.starts_with(request))?;
    Ok(())
}

fn paced(elapsed: Duration) -> Result<()> {
    // The bucket holds at least one second of the rate, whatever burstBytesPerSec says.
    let metered = LIMITED_BYTES as u64 - LIMIT_AFTER - LIMIT_BURST.max(LIMIT_RATE) - LIMIT_SLACK;
    let least = Duration::from_secs_f64(metered as f64 / LIMIT_RATE as f64);
    let most = Duration::from_secs_f64(2.0 * LIMITED_BYTES as f64 / LIMIT_RATE as f64) + Duration::from_secs(2);
    eprintln!("{LIMITED_BYTES} limited bytes took {elapsed:?}; expected {least:?}..{most:?}");
    if elapsed < least || elapsed > most {
        return Err(format!("{LIMITED_BYTES} bytes took {elapsed:?}, expected {least:?}..{most:?}").into());
    }
    Ok(())
}

fn authenticated_flight(xray: &Path, dir: &Path, case: &Case, keys: &Keys, decoy: &Decoy, port: u16, origin: u16) -> Result<()> {
    let (tap, carriers) = record_tcp(port)?;
    let front = available_port()?;
    let _client = start_xray(xray, dir, "xray-client", &case.xray_client(keys, front, tap, origin))?;
    let mut stream = tcp_connect(front)?;
    // Xray's REALITY server holds its first handshakes until its post-handshake probe of the target ends.
    stream.set_read_timeout(Some(TIMEOUT * 3))?;
    tcp_exchange(&mut stream, 196_613, 41)?;
    let carrier = wait_recording(&carriers, |carrier| record_lengths(&carrier.output).len() >= 3)?;
    let random = carrier.input.get(11..43).ok_or("the client sent no ClientHello")?.to_vec();
    let target = wait_recording(&decoy.recordings, |session| session.input.windows(32).any(|window| window == random))
        .map_err(|error| format!("decoy never received the client's ClientHello: {error}"))?;
    let sent = record_lengths(&target.output);
    let mirrored = record_lengths(&carrier.output);
    eprintln!("decoy flight records {sent:?}; server flight records {mirrored:?}");
    if sent.len() < 3 || mirrored.get(..sent.len()) != Some(&sent[..]) {
        return Err(format!("server flight records {mirrored:?}, decoy sent {sent:?}").into());
    }
    Ok(())
}

fn record_lengths(mut bytes: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    while bytes.len() >= 5 {
        let length = 5 + u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        if length > bytes.len() {
            break;
        }
        lengths.push(length);
        bytes = &bytes[length..];
    }
    lengths
}

fn proxy_header(xver: u8, source: std::net::SocketAddr, port: u16) -> Vec<u8> {
    let std::net::SocketAddr::V4(source) = source else { unreachable!("loopback prober is IPv4") };
    if xver == 1 {
        return format!("PROXY TCP4 {} 127.0.0.1 {} {port}\r\n", source.ip(), source.port()).into_bytes();
    }
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.extend([0x21, 0x11, 0, 12]);
    header.extend(source.ip().octets());
    header.extend([127, 0, 0, 1]);
    header.extend(source.port().to_be_bytes());
    header.extend(port.to_be_bytes());
    header
}

fn decoy_command(kind: u8, len: usize) -> Vec<u8> {
    let mut command = vec![kind];
    command.extend((len as u32).to_be_bytes());
    command
}

#[derive(Clone, Default)]
struct Recording {
    header: Vec<u8>,
    input: Vec<u8>,
    output: Vec<u8>,
}

type Recordings = Arc<std::sync::Mutex<Vec<Arc<std::sync::Mutex<Recording>>>>>;

fn wait_recording(recordings: &Recordings, matches: impl Fn(&Recording) -> bool) -> Result<Recording> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let found = recordings.lock().unwrap().iter().map(|entry| entry.lock().unwrap().clone()).find(|entry| matches(entry));
        if let Some(found) = found {
            return Ok(found);
        }
        if Instant::now() >= deadline {
            let seen = recordings.lock().unwrap().len();
            return Err(format!("no matching connection among {seen}").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct Recorder<T> {
    inner: T,
    record: Arc<std::sync::Mutex<Recording>>,
}

const RECORDED: usize = 64 * 1024;

impl<T: Read> Read for Recorder<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buf)?;
        let mut record = self.record.lock().unwrap();
        let keep = count.min(RECORDED.saturating_sub(record.input.len()));
        record.input.extend_from_slice(&buf[..keep]);
        Ok(count)
    }
}

impl<T: Write> Write for Recorder<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(buf)?;
        let mut record = self.record.lock().unwrap();
        let keep = count.min(RECORDED.saturating_sub(record.output.len()));
        record.output.extend_from_slice(&buf[..keep]);
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Records what a client sends (`input`) and what the server returns (`output`) on each connection.
fn record_tcp(upstream: u16) -> Result<(u16, Recordings)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let recordings = Recordings::default();
    let sessions = recordings.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT * 4;
        while Instant::now() < deadline {
            let client = match listener.accept() {
                Ok((socket, _)) => socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(_) => return,
            };
            let record = Arc::new(std::sync::Mutex::new(Recording::default()));
            sessions.lock().unwrap().push(record.clone());
            thread::spawn(move || {
                let Ok(mut server) = TcpStream::connect(("127.0.0.1", upstream)) else { return };
                let (Ok(input), Ok(mut output)) = (client.try_clone(), server.try_clone()) else { return };
                let mut input = Recorder { inner: input, record: record.clone() };
                thread::spawn(move || {
                    let _ = std::io::copy(&mut input, &mut output);
                    let _ = output.shutdown(Shutdown::Write);
                });
                let mut client = Recorder { inner: client, record };
                let _ = std::io::copy(&mut server, &mut client);
                let _ = client.inner.shutdown(Shutdown::Write);
            });
        }
    });
    Ok((port, recordings))
}

/// A TLS target that records the PROXY header, the bytes it receives and the bytes it
/// sends. After the handshake, `D n` asks for n bytes and `U n` sends n bytes.
struct Decoy {
    target: String,
    recordings: Recordings,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Decoy {
    fn start(address: DecoyAddress, keys: &Keys) -> Result<Self> {
        let tls = kerlico_vless::server_config(&keys.cert_pem, &keys.key_pem, &["h2".into(), "http/1.1".into()])
            .map_err(|_| "decoy TLS")?;
        let recordings = Recordings::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (target, worker) = match address {
            DecoyAddress::Tcp => {
                let listener = TcpListener::bind(localhost(0))?;
                listener.set_nonblocking(true)?;
                let target = format!("127.0.0.1:{}", listener.local_addr()?.port());
                (target, decoy_loop(move || listener.accept().map(|(stream, _)| stream), tls, recordings.clone(), stop.clone()))
            }
            #[cfg(target_os = "linux")]
            address => {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::net::{SocketAddr, UnixListener};
                static NEXT: AtomicUsize = AtomicUsize::new(0);
                let name = format!("kerlico-reality-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
                let (target, listener) = match address {
                    DecoyAddress::UnixPath => {
                        // sun_path holds 108 bytes, too few for the run directory.
                        let path = std::env::temp_dir().join(format!("{name}.sock"));
                        let _ = fs::remove_file(&path);
                        (path.display().to_string(), UnixListener::bind(&path)?)
                    }
                    DecoyAddress::UnixAbstract => (format!("@{name}"), UnixListener::bind_addr(&SocketAddr::from_abstract_name(&name)?)?),
                    _ => {
                        let mut padded = name.clone().into_bytes();
                        padded.resize(107, 0);
                        (format!("@@{name}"), UnixListener::bind_addr(&SocketAddr::from_abstract_name(&padded)?)?)
                    }
                };
                listener.set_nonblocking(true)?;
                (target, decoy_loop(move || listener.accept().map(|(stream, _)| stream), tls, recordings.clone(), stop.clone()))
            }
            #[cfg(not(target_os = "linux"))]
            _ => return Err("Unix targets need Linux".into()),
        };
        Ok(Self { target, recordings, stop, worker: Some(worker) })
    }
}

impl Drop for Decoy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

trait DecoyStream: Read + Write + Send + Sized + 'static {
    fn split(self) -> std::io::Result<(Self, Self)>;
}

impl DecoyStream for TcpStream {
    fn split(self) -> std::io::Result<(Self, Self)> {
        self.set_read_timeout(Some(TIMEOUT))?;
        self.set_write_timeout(Some(TIMEOUT))?;
        Ok((self.try_clone()?, self))
    }
}

#[cfg(unix)]
impl DecoyStream for std::os::unix::net::UnixStream {
    fn split(self) -> std::io::Result<(Self, Self)> {
        self.set_read_timeout(Some(TIMEOUT))?;
        self.set_write_timeout(Some(TIMEOUT))?;
        Ok((self.try_clone()?, self))
    }
}

fn decoy_loop<S: DecoyStream>(
    accept: impl Fn() -> std::io::Result<S> + Send + 'static,
    tls: Arc<kerlico_vless::ServerConfig>,
    recordings: Recordings,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match accept() {
                Ok(stream) => {
                    let record = Arc::new(std::sync::Mutex::new(Recording::default()));
                    recordings.lock().unwrap().push(record.clone());
                    let tls = tls.clone();
                    thread::spawn(move || {
                        if let Ok((read, write)) = stream.split() {
                            let _ = decoy_session(read, write, tls, record);
                        }
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    })
}

fn decoy_session<S: Read + Write>(
    mut read: S,
    write: S,
    tls: Arc<kerlico_vless::ServerConfig>,
    record: Arc<std::sync::Mutex<Recording>>,
) -> std::io::Result<()> {
    let mut header = vec![0; 1];
    read.read_exact(&mut header)?;
    let mut lead = match header[0] {
        b'P' => {
            while !header.ends_with(b"\r\n") && header.len() < 108 {
                let mut byte = [0; 1];
                read.read_exact(&mut byte)?;
                header.push(byte[0]);
            }
            vec![0; 1]
        }
        b'\r' => {
            header.resize(16, 0);
            read.read_exact(&mut header[1..])?;
            let length = u16::from_be_bytes([header[14], header[15]]) as usize;
            header.resize(16 + length, 0);
            read.read_exact(&mut header[16..])?;
            vec![0; 1]
        }
        _ => Vec::new(),
    };
    if lead.is_empty() {
        lead = std::mem::take(&mut header);
    } else {
        read.read_exact(&mut lead)?;
    }
    record.lock().unwrap().header = header;
    let handshake = lead == [0x16];
    let mut read = Recorder { inner: std::io::Cursor::new(lead).chain(read), record: record.clone() };
    if !handshake {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") && request.len() < RECORDED {
            let mut byte = [0; 1];
            read.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        return Ok(());
    }
    let write = Recorder { inner: write, record };
    let (mut read, mut write) = kerlico_vless::accept_tls_over(read, write, tls)?;
    let mut command = [0; 5];
    while read.read_exact(&mut command).is_ok() {
        let len = u32::from_be_bytes([command[1], command[2], command[3], command[4]]) as usize;
        match command[0] {
            b'D' => write.write_all(&pattern(len, 3))?,
            b'U' => {
                let received = std::io::copy(&mut (&mut read).take(len as u64), &mut std::io::sink())?;
                if received != len as u64 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                write.write_all(b"ok")?;
            }
            _ => break,
        }
        write.flush()?;
    }
    Ok(())
}
