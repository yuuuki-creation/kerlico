#![cfg(all(feature = "vless", feature = "landing-vless"))]

//! Run with `XRAY=/path/to/xray cargo test -p kerlico-server --no-default-features
//! --features vless,landing-vless --test vless_xray vless_xray_matrix -- --ignored --nocapture`.
//! `VLESS_CASE` filters case/direction labels by comma-separated substrings.
//! `VLESS_XRAY_CONTROL=1` adds an Xray-to-Xray run. `VLESS_RUN_DIR` holds logs and configs.
//! The separate `vless_xray_rejections` test checks the configs Xray refuses and the flows it refuses at dispatch.

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
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use cases::{Carriers, Case, Keys, Network, Payload, Security, INGRESS_ID, ORIGIN_NAME, TLS_NAME};
use support::{
    available_port, localhost, print_logs, run_dir, tcp_connect, write_json, Echo, Process, Result,
    TIMEOUT,
};

const XRAY_VERSION: &str = "26.10.31";
const XRAY_BUILD: &str = "a4a3dff";
const KERLICO_CHILD: &str = "KERLICO_VLESS_XRAY_PEER_CONFIG";

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

/// The matrix and rejection tests run in parallel in one process, and only one case at a
/// time can hold a fixed origin port such as UDP 443.
static FIXED_ORIGIN: Mutex<()> = Mutex::new(());

fn run_case(xray: &Path, dir: &Path, case: &Case, direction: Direction) -> Result<()> {
    let _fixed_origin = (case.payload.origin_port() != 0)
        .then(|| FIXED_ORIGIN.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
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
        let port = case.payload.origin_port();
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

    let tap = case.carriers.map(|_| tap_carriers(peer)).transpose()?;
    let client_peer = tap.as_ref().map_or(peer, |(port, _)| *port);
    let cone = case.cone;
    let peers = match direction {
        Direction::XrayToKerlico => (
            start_kerlico(dir, &case.kerlico_server(&keys, peer))?,
            start_xray(
                xray,
                dir,
                "xray-client",
                &case.xray_client(&keys, front, client_peer, origin.port),
                cone,
            )?,
        ),
        Direction::KerlicoToXray => (
            start_xray(
                xray,
                dir,
                "xray-server",
                &case.xray_server(&keys, peer, origin.port),
                cone,
            )?,
            start_kerlico(dir, &case.kerlico_landing(&keys, front, client_peer))?,
        ),
        Direction::XrayControl => (
            start_xray(
                xray,
                dir,
                "xray-server",
                &case.xray_server(&keys, peer, origin.port),
                cone,
            )?,
            start_xray(
                xray,
                dir,
                "xray-client",
                &case.xray_client(&keys, front, client_peer, origin.port),
                cone,
            )?,
        ),
    };

    let inject = matches!(direction, Direction::KerlicoToXray);
    let rounds = if case.resume { 3 } else { 1 };
    let traffic = (0..rounds).try_for_each(|round| {
        let result = if case.payload.udp() {
            exercise_udp(front, origin.port, inject)
        } else {
            exercise_tcp(front, origin.port, inject, case.payload, case.carriers.is_some())
        };
        result.map_err(|error| format!("traffic round {}: {error}", round + 1))
    });
    if case.rejected && traffic.is_ok() {
        return Err("the client delivered a flow it must reject".into());
    }
    if !case.rejected {
        traffic?;
    }
    if case.name.starts_with("hysteria-quic-") {
        exercise_hysteria_http(peer, &case.name)?;
    }
    if download.is_some_and(|used| !used.load(Ordering::Relaxed)) {
        return Err("XHTTP did not use the downloadSettings endpoint".into());
    }
    if let (Some((_, heads)), Some(expected)) = (&tap, case.carriers) {
        check_carriers(&heads.lock().expect("tap"), expected)?;
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

type CarrierHeads = Arc<Mutex<Vec<Vec<u8>>>>;

/// Forwards each client carrier to `peer` and keeps its first bytes.
fn tap_carriers(peer: u16) -> Result<(u16, CarrierHeads)> {
    const HEAD: usize = 64;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let heads = CarrierHeads::default();
    let observed = heads.clone();
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
            let index = {
                let mut heads = observed.lock().expect("tap");
                heads.push(Vec::new());
                heads.len() - 1
            };
            let heads = observed.clone();
            thread::spawn(move || {
                let Ok(mut server) = TcpStream::connect(("127.0.0.1", peer)) else { return };
                let (Ok(mut input), Ok(mut output)) = (client.try_clone(), server.try_clone()) else { return };
                thread::spawn(move || {
                    let mut bytes = [0; 16 * 1024];
                    while let Ok(n) = input.read(&mut bytes) {
                        if n == 0 {
                            break;
                        }
                        {
                            let mut heads = heads.lock().expect("tap");
                            let head = &mut heads[index];
                            let room = HEAD.saturating_sub(head.len());
                            head.extend_from_slice(&bytes[..n.min(room)]);
                        }
                        if output.write_all(&bytes[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = output.shutdown(Shutdown::Write);
                });
                let _ = std::io::copy(&mut server, &mut client);
                let _ = client.shutdown(Shutdown::Write);
            });
        }
    });
    Ok((port, heads))
}

fn check_carriers(heads: &[Vec<u8>], expected: Carriers) -> Result<()> {
    if heads.len() != expected.count {
        return Err(format!("{} carriers, expected {}", heads.len(), expected.count).into());
    }
    let Some(command) = expected.command else { return Ok(()) };
    for head in heads {
        // A plaintext VLESS request: version, UUID, addons length, addons, command.
        let seen = head.get(17).and_then(|addons| head.get(18 + *addons as usize));
        if seen != Some(&command) {
            return Err(format!("carrier command {seen:?}, expected {command}").into());
        }
    }
    Ok(())
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

fn start_xray(xray: &Path, dir: &Path, name: &str, config: &Value, cone: bool) -> Result<Process> {
    let path = write_json(dir, &format!("{name}.json"), config)?;
    let mut command = Command::new(xray);
    command.args(["run", "-c"]).arg(path);
    // Keep most un-muxed Xray UDP cases on VLESS command 2. Vision and explicit mux still use XUDP.
    if !cone {
        command.env("xray.cone.disabled", "true");
    }
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

fn exercise_tcp(front: u16, origin: u16, inject: bool, payload: Payload, concurrent: bool) -> Result<()> {
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
        if concurrent {
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
    for case in cases::rejected_cases() {
        for direction in [Direction::XrayControl, Direction::KerlicoToXray] {
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

#[test]
#[ignore = "requires XRAY pointing to Xray 26.10.31 a4a3dff"]
fn vless_xray_xudp_destinations() {
    use kerlico_shared::{Destination, PlaneFault, Settings, Transport};

    let root = run_dir("xudp-destinations").expect("XUDP directory");
    let xray = xray_binary(&root).expect("pinned Xray peer");
    let case = Case::new("xudp-destinations", Network::Raw, Security::None, Payload::Udp);
    let keys = Keys::generate(&root, &case).expect("keys");
    let origins = [Echo::udp(0).expect("first origin"), Echo::udp(0).expect("second origin")];
    let peer = available_port().expect("peer port");
    let mut config = case.xray_server(&keys, peer, origins[0].port);
    config["outbounds"][0]["settings"]["finalRules"][0]["port"] =
        json!(format!("{},{}", origins[0].port, origins[1].port));
    let _server = start_xray(&xray, &root, "xray-server", &config, true).expect("Xray server");

    let mut settings = Settings::default();
    for (key, value) in [("network", "raw"), ("security", "none"), ("encryption", "none"), ("id", cases::ID)] {
        settings.insert_text(key, value);
    }
    let targets = origins
        .each_ref()
        .map(|origin| Destination::new("127.0.0.1", origin.port, Transport::Udp).expect("origin destination"));
    let session = landing_vless::land_udp("127.0.0.1", peer, &settings, &targets[0]).expect("XUDP session");
    let mut buf = [0; 65536];
    for (index, target) in [&targets[0], &targets[1], &targets[0], &targets[1]].into_iter().enumerate() {
        let datagram = pattern(1000 + index, index);
        assert_eq!(session.send_to(target, &datagram), Ok(datagram.len()), "send datagram {index}");
        let deadline = Instant::now() + TIMEOUT;
        let (n, source) = loop {
            match session.recv_from(&mut buf) {
                Err(PlaneFault::Again) if Instant::now() < deadline => {}
                received => break received.unwrap_or_else(|error| panic!("reply {index}: {error:?}")),
            }
        };
        assert_eq!(&buf[..n], datagram.as_slice(), "reply {index} payload");
        assert_eq!(&source, target, "reply {index} source");
    }
}
