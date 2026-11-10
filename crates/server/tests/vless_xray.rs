#![cfg(all(feature = "vless", feature = "landing-vless"))]

//! Run with `XRAY=/path/to/xray cargo test -p kerlico-server --no-default-features
//! --features vless,landing-vless --test vless_xray vless_xray_matrix -- --ignored --nocapture`.
//! `VLESS_CASE` filters case/direction labels by comma-separated substrings.
//! `VLESS_XRAY_CONTROL=1` adds an Xray-to-Xray run. `VLESS_RUN_DIR` holds logs and configs.
//! The separate `vless_xray_rejections` test checks the configs Xray refuses and the flows it refuses at dispatch.
//! `vless_xray_bridge` runs a Kerlico reverse bridge and an Xray control bridge against an Xray portal.

#[path = "vless_support/cases.rs"]
mod cases;
#[path = "vless_support/mod.rs"]
mod support;
#[path = "vless_support/xdrive_mock.rs"]
mod xdrive_mock;

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use cases::{Carriers, Case, Keys, Network, Payload, Security, ID, INGRESS_ID, ORIGIN_NAME, TLS_NAME};
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
    finish_report("VLESS matrix", runs, &failed, &root);
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

fn count_tcp_carriers(peer: u16, lifetime: Duration) -> Result<(u16, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + lifetime;
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
    // Keep most un-muxed Xray UDP cases on VLESS command 2. Vision and explicit mux still use XUDP.
    let env: &[(&str, &str)] = if cone { &[] } else { &[("xray.cone.disabled", "true")] };
    launch_xray(xray, dir, name, config, env)
}

fn launch_xray(xray: &Path, dir: &Path, name: &str, config: &Value, env: &[(&str, &str)]) -> Result<Process> {
    let path = write_json(dir, &format!("{name}.json"), config)?;
    let mut command = Command::new(xray);
    command.args(["run", "-c"]).arg(path).envs(env.iter().copied());
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

fn finish_report(title: &str, runs: usize, failures: &[String], root: &Path) {
    assert!(runs > 0, "no cases matched VLESS_CASE");
    eprintln!(
        "{title}: {}/{} passed. Artifacts: {}",
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
    finish_report("VLESS rejections", runs, &failed, &root);
}

#[test]
#[ignore = "requires XRAY pointing to Xray 26.10.31 a4a3dff"]
fn vless_xray_xudp_reattach() {
    let root = run_dir("xudp").expect("xudp directory");
    let xray = xray_binary(&root).expect("pinned Xray peer");
    let directions = [Direction::XrayControl, Direction::XrayToKerlico];
    let results = thread::scope(|scope| {
        let runs = directions.map(|direction| {
            let (xray, dir) = (&xray, root.join(direction.name()));
            scope.spawn(move || {
                let result = fs::create_dir(&dir).map_err(Into::into).and_then(|_| xudp_reattach(xray, &dir, direction));
                result.map_err(|error| error.to_string())
            })
        });
        runs.map(|run| run.join().expect("XUDP run thread"))
    });
    let mut failed = Vec::new();
    for (direction, result) in directions.into_iter().zip(results) {
        let label = format!("xudp-reattach/{}", direction.name());
        report(&label, result.map_err(Into::into), &root.join(direction.name()), &mut failed);
    }
    eprintln!("XUDP reattach: {}/{} passed. Artifacts: {}", directions.len() - failed.len(), directions.len(), root.display());
    assert!(failed.is_empty(), "failed cases: {}", failed.join(", "));
}

/// An Xray client with a cone SOCKS inbound and Mux/XUDP sends one GlobalID per UDP source.
/// The server keeps the same outbound socket when the carrier changes, and drops it once the
/// session has waited more than a minute without a carrier.
fn xudp_reattach(xray: &Path, dir: &Path, direction: Direction) -> Result<()> {
    let case = Case::new("xudp-reattach", Network::Raw, Security::None, Payload::Udp);
    let keys = Keys::generate(dir, &case)?;
    let origin = Echo::udp_source_port()?;
    let peer = available_port()?;
    let tap = Tap::start(peer)?;
    let front = available_port()?;
    let (_server, detached) = match direction {
        Direction::XrayToKerlico => (start_kerlico(dir, &case.kerlico_server(&keys, peer))?, Duration::from_secs(62)),
        // Xray sweeps its XUDP map once a minute, so an entry can outlive its 60 s deadline by up to a minute.
        _ => (start_xray(xray, dir, "xray-server", &case.xray_server(&keys, peer, origin.port), false)?, Duration::from_secs(122)),
    };
    let mut client = case.xray_client(&keys, front, tap.port, origin.port);
    client["inbounds"] = json!([{"protocol": "socks", "listen": "127.0.0.1", "port": front,
        "settings": {"udp": true, "ip": "127.0.0.1"}}]);
    client["outbounds"][0]["mux"] = json!({"enabled": true, "concurrency": 8,
        "xudpConcurrency": 8, "xudpProxyUDP443": "allow"});
    let _client = launch_xray(xray, dir, "xray-client", &client, &[])?;
    let socks = SocksUdp::associate(front)?;

    let first = socks.origin_port(origin.port, 1)?;
    let carriers = tap.accepted();
    tap.drop_clients();
    let stolen = socks.origin_port(origin.port, 2)?;
    if tap.accepted() == carriers {
        return Err("the client reused its carrier after the tap closed it".into());
    }
    if stolen != first {
        return Err(format!("origin saw port {first}, then {stolen} after the client end of the carrier closed and the server end stayed open").into());
    }
    let carriers = tap.accepted();
    tap.cut();
    let resumed = socks.origin_port(origin.port, 3)?;
    if tap.accepted() == carriers {
        return Err("the client reused its carrier after the tap cut it".into());
    }
    if resumed != first {
        return Err(format!("origin saw port {first}, then {resumed} after the carrier closed on both ends").into());
    }
    tap.cut();
    thread::sleep(detached);
    let expired = socks.origin_port(origin.port, 4)?;
    if expired == first {
        return Err(format!("origin still saw port {first} after the session waited {detached:?} without a carrier").into());
    }
    Ok(())
}

/// A TCP relay between the client and the server that drops carriers on demand.
struct Tap {
    port: u16,
    links: Arc<Mutex<Vec<(TcpStream, TcpStream)>>>,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Tap {
    fn start(peer: u16) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let tap = Self {
            port: listener.local_addr()?.port(),
            links: Arc::default(),
            accepted: Arc::default(),
            stop: Arc::default(),
        };
        let (links, accepted, stop) = (tap.links.clone(), tap.accepted.clone(), tap.stop.clone());
        thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let client = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => return,
                };
                accepted.fetch_add(1, Ordering::AcqRel);
                let Ok(server) = TcpStream::connect(("127.0.0.1", peer)) else { continue };
                let (Ok(up_in), Ok(up_out), Ok(down_in), Ok(down_out), Ok(client_end), Ok(server_end)) =
                    (client.try_clone(), server.try_clone(), server.try_clone(), client.try_clone(), client.try_clone(), server.try_clone())
                else { continue };
                links.lock().expect("tap links").push((client_end, server_end));
                // A finished copy leaves the other end open, so a dropped client leaves a silent server end.
                for (mut from, mut to) in [(up_in, up_out), (down_in, down_out)] {
                    thread::spawn(move || { let _ = std::io::copy(&mut from, &mut to); });
                }
            }
        });
        Ok(tap)
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }

    /// Closes the client end of every carrier. The server end stays open and receives nothing.
    fn drop_clients(&self) {
        for (client, _) in self.links.lock().expect("tap links").iter() {
            let _ = client.shutdown(Shutdown::Both);
        }
    }

    /// Closes both ends of every carrier.
    fn cut(&self) {
        for (client, server) in self.links.lock().expect("tap links").drain(..) {
            let _ = client.shutdown(Shutdown::Both);
            let _ = server.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.cut();
    }
}

/// A SOCKS5 UDP association whose datagrams all leave from one local socket.
struct SocksUdp {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

impl SocksUdp {
    fn associate(front: u16) -> Result<Self> {
        let mut control = tcp_connect(front)?;
        control.write_all(&[5, 1, 0])?;
        let mut method = [0; 2];
        control.read_exact(&mut method)?;
        if method != [5, 0] {
            return Err(format!("SOCKS method reply {method:?}").into());
        }
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])?;
        let mut reply = [0; 10];
        control.read_exact(&mut reply)?;
        if reply[..4] != [5, 0, 0, 1] {
            return Err(format!("SOCKS UDP ASSOCIATE reply {reply:?}").into());
        }
        let relay = SocketAddr::from(([reply[4], reply[5], reply[6], reply[7]], u16::from_be_bytes([reply[8], reply[9]])));
        let socket = UdpSocket::bind(localhost(0))?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        Ok(Self { _control: control, socket, relay })
    }

    /// Sends datagrams tagged with `round` to the origin until one comes back, and returns the
    /// source port the origin saw. The first datagram after a carrier drop may be lost.
    fn origin_port(&self, origin: u16, round: u8) -> Result<u16> {
        let deadline = Instant::now() + TIMEOUT * 2;
        let mut bytes = [0; 512];
        for attempt in 0u8.. {
            let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
            packet.extend_from_slice(&origin.to_be_bytes());
            packet.extend_from_slice(&[round, attempt]);
            self.socket.send_to(&packet, self.relay)?;
            let sent = Instant::now();
            while sent.elapsed() < Duration::from_millis(500) {
                match self.socket.recv(&mut bytes) {
                    // A 10-byte SOCKS header, the port the origin saw, then our round and attempt.
                    Ok(14) if bytes[12] == round => return Ok(u16::from_be_bytes([bytes[10], bytes[11]])),
                    Ok(_) => {}
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("no UDP reply in round {round} after {} datagrams", attempt + 1).into());
            }
        }
        unreachable!("the deadline ends the attempts")
    }
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
fn vless_xray_bridge() {
    let root = run_dir("bridge").expect("bridge directory");
    let xray = xray_binary(&root).expect("pinned Xray peer");
    let mut failed = Vec::new();
    for (label, kerlico) in [("bridge/xray-control", false), ("bridge/kerlico", true)] {
        let dir = root.join(label);
        let result = fs::create_dir_all(&dir)
            .map_err(Into::into)
            .and_then(|_| run_bridge(&xray, &dir, kerlico));
        report(label, result, &dir, &mut failed);
    }
    finish_report("VLESS bridge", 2, &failed, &root);
}

/// Only the bridge resolves the origin name and the portal's default outbound is blackhole,
/// so every echoed byte crossed the bridge and left through the bridge's exit.
fn run_bridge(xray: &Path, dir: &Path, kerlico: bool) -> Result<()> {
    let tcp = Echo::tcp(None)?;
    let udp = Echo::udp(0)?;
    let mut ports = Vec::new();
    while ports.len() < 3 {
        let port = available_port()?;
        if ![tcp.port, udp.port].contains(&port) && !ports.contains(&port) {
            ports.push(port);
        }
    }
    let (portal, front_tcp, front_udp) = (ports[0], ports[1], ports[2]);
    let (link, carriers) = count_tcp_carriers(portal, Duration::from_secs(300))?;
    let _portal = start_xray(xray, dir, "xray-portal", &json!({
        "log": {"loglevel": "info"},
        "inbounds": [
            {"tag": "portal-link", "protocol": "vless", "listen": "127.0.0.1", "port": portal,
                "settings": {"decryption": "none", "users": [{"id": ID, "reverse": {"tag": "portal-out"}}]}},
            {"tag": "front-tcp", "protocol": "tunnel", "listen": "127.0.0.1", "port": front_tcp,
                "settings": {"address": ORIGIN_NAME, "port": tcp.port, "network": "tcp"}},
            {"tag": "front-udp", "protocol": "tunnel", "listen": "127.0.0.1", "port": front_udp,
                "settings": {"address": ORIGIN_NAME, "port": udp.port, "network": "udp"}},
        ],
        "outbounds": [{"protocol": "blackhole"}],
        "routing": {"rules": [{"inboundTag": ["front-tcp", "front-udp"], "outboundTag": "portal-out"}]},
    }), false)?;
    let _bridge = if kerlico {
        start_kerlico(dir, &json!({
            "inbounds": [],
            "dns": {"hosts": {ORIGIN_NAME: "127.0.0.1"}},
            "bridges": [{"tag": "bridge", "address": "127.0.0.1", "port": link,
                "outbound": "warp-v4",
                "rules": [{"domain": [format!("full:{ORIGIN_NAME}")], "outbound": "native-v4"}],
                "settings": {"id": ID, "encryption": "none"}}],
        }))?
    } else {
        start_xray(xray, dir, "xray-bridge", &json!({
            "log": {"loglevel": "info"},
            "dns": {"hosts": {ORIGIN_NAME: "127.0.0.1"}},
            "outbounds": [
                {"tag": "bridge-link", "protocol": "vless", "settings": {"address": "127.0.0.1", "port": link,
                    "id": ID, "encryption": "none", "reverse": {"tag": "bridge"}}},
                {"tag": "direct", "protocol": "freedom",
                    "streamSettings": {"sockopt": {"domainStrategy": "ForceIPv4"}},
                    "settings": {"finalRules": [{"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"],
                        "port": format!("{},{}", tcp.port, udp.port)}]}},
            ],
            "routing": {"rules": [{"inboundTag": ["bridge"], "outboundTag": "direct"}]},
        }), false)?
    };
    let deadline = Instant::now() + TIMEOUT * 2;
    while let Err(error) = open_front(front_tcp, 0, false, false).and_then(|mut stream| tcp_exchange(&mut stream, 17, 33)) {
        if Instant::now() >= deadline {
            return Err(format!("no flow crossed the bridge: {error}").into());
        }
        thread::sleep(Duration::from_millis(200));
    }
    exercise_tcp(front_tcp, tcp.port, false, Payload::Tcp, false)?;
    exercise_udp(front_udp, udp.port, false)?;
    settle_carriers(&carriers, 1, "light traffic")?;

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut flows = 0;
    while carriers.load(Ordering::Acquire) == 1 {
        if Instant::now() >= deadline {
            return Err(format!("{flows} sequential flows never replaced the connection the portal drains after 256 sessions").into());
        }
        let mut stream = open_front(front_tcp, 0, false, false)?;
        tcp_exchange(&mut stream, 1, flows).map_err(|error| format!("sequential flow {flows}: {error}"))?;
        flows += 1;
    }
    eprintln!("bridge replaced the drained connection after {flows} sequential flows");
    settle_carriers(&carriers, 2, "after the drain")?;

    let mut held = Vec::new();
    for seed in 0..20 {
        let mut stream = open_front(front_tcp, 0, false, false)?;
        tcp_exchange(&mut stream, 64, seed).map_err(|error| format!("concurrent flow {seed}: {error}"))?;
        held.push(stream);
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    while carriers.load(Ordering::Acquire) < 3 {
        if Instant::now() >= deadline {
            return Err("20 concurrent flows on one connection did not open another".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    // The echo origin drops a connection after 6 idle seconds, so check the held flows first.
    for (seed, stream) in held.iter_mut().enumerate() {
        tcp_exchange(stream, 4099, seed).map_err(|error| format!("held flow {seed}: {error}"))?;
    }
    settle_carriers(&carriers, 3, "with 20 concurrent flows")
}

/// Two 2-second supervision rounds pass before the count is final.
fn settle_carriers(carriers: &AtomicUsize, expected: usize, when: &str) -> Result<()> {
    thread::sleep(Duration::from_millis(4500));
    let count = carriers.load(Ordering::Acquire);
    if count != expected {
        return Err(format!("{when}: the tap saw {count} bridge connections, expected {expected}").into());
    }
    Ok(())
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
