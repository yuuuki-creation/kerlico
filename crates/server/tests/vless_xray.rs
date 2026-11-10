#![cfg(all(feature = "vless", feature = "landing-vless"))]

//! Run with `XRAY=/path/to/xray cargo test -p kerlico-server --no-default-features
//! --features vless,landing-vless --test vless_xray vless_xray_matrix -- --ignored --nocapture`.
//! `VLESS_CASE` filters case/direction labels by comma-separated substrings.
//! `VLESS_XRAY_CONTROL=1` adds an Xray-to-Xray run. `VLESS_RUN_DIR` holds logs and configs.
//! The separate `vless_xray_rejections` test checks the configs Xray refuses and the flows it refuses at dispatch.
//! `vless_xray_bridge` runs a Kerlico reverse bridge and an Xray control bridge against an Xray portal.
//! `vless_xray_h2_params` compares raw HTTP/2 server behavior under the same `h2Params`.
//! `vless_xray_udp_size` sends datagrams at and over Xray's size limit for each UDP framing.

#[path = "vless_support/cases.rs"]
mod cases;
#[path = "vless_support/h2_probe.rs"]
mod h2_probe;
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
        let mut carriers = Vec::new();
        for &direction in &directions {
            let label = format!("{}/{}", case.name, direction.name());
            if !selected(&filter, &label) {
                continue;
            }
            runs += 1;
            let dir = root.join(&case.name).join(direction.name());
            let result = fs::create_dir_all(&dir)
                .map_err(Into::into)
                .and_then(|_| run_case(&xray, &dir, &case, direction))
                .map(|count| carriers.extend(count.map(|count| (direction, count))));
            report(&label, result, &dir, &mut failed);
        }
        compare_carriers(&case.name, &carriers, &mut failed);
    }
    finish_report("VLESS matrix", runs, &failed, &root);
}

fn compare_carriers(case: &str, carriers: &[(Direction, usize)], failures: &mut Vec<String>) {
    let summary: Vec<_> = carriers
        .iter()
        .map(|(direction, count)| format!("{}={count}", direction.name()))
        .collect();
    if !summary.is_empty() {
        eprintln!("CARRIERS {case}: {}", summary.join(" "));
    }
    let Some(&(_, control)) = carriers
        .iter()
        .find(|(direction, _)| matches!(direction, Direction::XrayControl))
    else {
        return;
    };
    for (direction, count) in carriers {
        if *count != control {
            eprintln!("FAIL {case}/{}: {count} TCP carriers, Xray control opened {control}", direction.name());
            failures.push(format!("{case}/{}/carriers", direction.name()));
        }
    }
}

/// The matrix and rejection tests run in parallel in one process, and only one case at a
/// time can hold a fixed origin port such as UDP 443.
static FIXED_ORIGIN: Mutex<()> = Mutex::new(());

fn run_case(xray: &Path, dir: &Path, case: &Case, direction: Direction) -> Result<Option<usize>> {
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

    let tap = (case.carriers.is_some() || case.counts_carriers())
        .then(|| tap_carriers(peer))
        .transpose()?;
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
    if let Some(trusted) = case.forwarded().filter(|_| !matches!(direction, Direction::XrayToKerlico)) {
        let log = fs::read_to_string(dir.join("xray-server.log"))?;
        let source = format!("from {}:0 accepted", cases::FORWARDED);
        if log.contains(&source) != trusted {
            return Err(format!(
                "Xray server {} X-Forwarded-For {}",
                if trusted { "ignored" } else { "trusted" },
                if trusted { "with the trusted marker" } else { "without the trusted marker" },
            )
            .into());
        }
    }
    let carriers = tap
        .as_ref()
        .filter(|_| case.counts_carriers())
        .map(|(_, heads)| heads.lock().expect("tap").len());
    if let (Some((_, heads)), Some(expected)) = (&tap, case.carriers) {
        check_carriers(&heads.lock().expect("tap"), expected)?;
    }
    drop(peers);
    if let Some(storage) = storage {
        storage.verify(!case.payload.udp())?;
    }
    Ok(carriers)
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

fn open_front(port: u16) -> Result<TcpStream> {
    Ok(tcp_connect(port).map_err(|error| format!("connect front {port}: {error}"))?)
}

/// Kerlico's ingress, like Xray's inbound, sends the VLESS response only with the first reply
/// bytes, so the response is read on the first read.
fn open_ingress(port: u16, origin: u16, udp: bool) -> Result<kerlico_vless::ResponseReader<TcpStream>> {
    let mut stream = open_front(port)?;
    // The ingress fixture is VLESS version 0, no addons, a DNS target, and command 1 or 2.
    let mut request = vec![0];
    request.extend_from_slice(&INGRESS_ID);
    request.extend_from_slice(&[0, if udp { 2 } else { 1 }]);
    request.extend_from_slice(&origin.to_be_bytes());
    request.extend_from_slice(&[2, ORIGIN_NAME.len() as u8]);
    request.extend_from_slice(ORIGIN_NAME.as_bytes());
    stream.write_all(&request)?;
    Ok(kerlico_vless::ResponseReader::new(stream))
}

fn exercise_tcp(front: u16, origin: u16, inject: bool, payload: Payload, concurrent: bool) -> Result<()> {
    if inject {
        exercise_tcp_over(|| open_ingress(front, origin, false), payload, concurrent)
    } else {
        exercise_tcp_over(|| open_front(front), payload, concurrent)
    }
}

fn exercise_tcp_over<S: Read + Write + Send>(open: impl Fn() -> Result<S>, payload: Payload, concurrent: bool) -> Result<()> {
    use tokio_rustls::rustls::{pki_types::ServerName, ClientConnection, StreamOwned};
    let mut stream = open()?;
    if let Payload::Rounds(rounds) = payload {
        return (0..rounds).try_for_each(|round| tcp_exchange(&mut stream, 17, 33 + round));
    }
    if payload == Payload::InnerTls {
        let tls = kerlico_vless::client_config(&[], true).map_err(|_| "make inner TLS client")?;
        let client = ClientConnection::new(tls, ServerName::try_from(TLS_NAME)?)
            .map_err(|error| format!("inner TLS client: {error}"))?;
        let mut stream = StreamOwned::new(client, stream);
        return tcp_exchange(&mut stream, 17, 33)
            .and_then(|_| tcp_exchange(&mut stream, 196_613, 123));
    }
    tcp_exchange(&mut stream, 17, 33)?;
    if payload == Payload::TwoTcp {
        let mut second = open()?;
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
        let mut stream = open_ingress(front, origin, true)?;
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
                .and_then(|_| run_case(&xray, &dir, &case, direction))
                .map(|_| ());
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

fn run_bridge(xray: &Path, dir: &Path, kerlico: bool) -> Result<()> {
    let tcp = Echo::tcp(None)?;
    let udp = Echo::udp(0)?;
    let portal = BridgedPortal::start(xray, dir, kerlico, tcp.port, udp.port)?;
    let (front_tcp, front_udp, carriers) = (portal.front_tcp, portal.front_udp, &portal.carriers);
    exercise_tcp(front_tcp, tcp.port, false, Payload::Tcp, false)?;
    exercise_udp(front_udp, udp.port, false)?;
    settle_carriers(carriers, 1, "light traffic")?;

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut flows = 0;
    while carriers.load(Ordering::Acquire) == 1 {
        if Instant::now() >= deadline {
            return Err(format!("{flows} sequential flows never replaced the connection the portal drains after 256 sessions").into());
        }
        let mut stream = open_front(front_tcp)?;
        tcp_exchange(&mut stream, 1, flows).map_err(|error| format!("sequential flow {flows}: {error}"))?;
        flows += 1;
    }
    eprintln!("bridge replaced the drained connection after {flows} sequential flows");
    settle_carriers(carriers, 2, "after the drain")?;

    let mut held = Vec::new();
    for seed in 0..20 {
        let mut stream = open_front(front_tcp)?;
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
    settle_carriers(carriers, 3, "with 20 concurrent flows")
}

/// An Xray portal whose fronts reach the origins only through a Kerlico or Xray bridge. Only
/// the bridge resolves the origin name and the portal's default outbound is blackhole, so every
/// echoed byte crossed the bridge and left through the bridge's exit.
struct BridgedPortal {
    front_tcp: u16,
    front_udp: u16,
    /// Reverse connections the bridge opened to the portal.
    carriers: Arc<AtomicUsize>,
    _processes: [Process; 2],
}

impl BridgedPortal {
    fn start(xray: &Path, dir: &Path, kerlico: bool, tcp: u16, udp: u16) -> Result<Self> {
        let mut ports = Vec::new();
        while ports.len() < 3 {
            let port = available_port()?;
            if ![tcp, udp].contains(&port) && !ports.contains(&port) {
                ports.push(port);
            }
        }
        let (portal, front_tcp, front_udp) = (ports[0], ports[1], ports[2]);
        let (link, carriers) = count_tcp_carriers(portal, Duration::from_secs(300))?;
        let portal = start_xray(xray, dir, "xray-portal", &json!({
            "log": {"loglevel": "info"},
            "inbounds": [
                {"tag": "portal-link", "protocol": "vless", "listen": "127.0.0.1", "port": portal,
                    "settings": {"decryption": "none", "users": [{"id": ID, "reverse": {"tag": "portal-out"}}]}},
                {"tag": "front-tcp", "protocol": "tunnel", "listen": "127.0.0.1", "port": front_tcp,
                    "settings": {"address": ORIGIN_NAME, "port": tcp, "network": "tcp"}},
                {"tag": "front-udp", "protocol": "tunnel", "listen": "127.0.0.1", "port": front_udp,
                    "settings": {"address": ORIGIN_NAME, "port": udp, "network": "udp"}},
            ],
            "outbounds": [{"protocol": "blackhole"}],
            "routing": {"rules": [{"inboundTag": ["front-tcp", "front-udp"], "outboundTag": "portal-out"}]},
        }), false)?;
        let bridge = if kerlico {
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
                            "port": format!("{tcp},{udp}")}]}},
                ],
                "routing": {"rules": [{"inboundTag": ["bridge"], "outboundTag": "direct"}]},
            }), false)?
        };
        let deadline = Instant::now() + TIMEOUT * 2;
        while let Err(error) = open_front(front_tcp).and_then(|mut stream| tcp_exchange(&mut stream, 17, 33)) {
            if Instant::now() >= deadline {
                return Err(format!("no flow crossed the bridge: {error}").into());
            }
            thread::sleep(Duration::from_millis(200));
        }
        Ok(Self { front_tcp, front_udp, carriers, _processes: [portal, bridge] })
    }
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

/// Xray's `buf.Size`: every Xray UDP read fills at most one buffer this large.
const XRAY_BUFFER: usize = 8192;

#[test]
#[ignore = "requires XRAY pointing to Xray 26.10.31 a4a3dff"]
fn vless_xray_udp_size() {
    let root = run_dir("udp-size").expect("UDP size directory");
    let xray = xray_binary(&root).expect("pinned Xray peer");
    let mut runs = 0;
    let mut failed = Vec::new();
    for framing in [SizeFraming::Mux, SizeFraming::Xudp, SizeFraming::Plain] {
        for direction in [Direction::XrayControl, Direction::XrayToKerlico, Direction::KerlicoToXray] {
            let label = format!("udp-size-{}/{}", framing.name(), direction.name());
            let dir = root.join(&label);
            let result = fs::create_dir_all(&dir).map_err(Into::into).and_then(|_| udp_size(&xray, &dir, &label, framing, direction));
            report(&label, result, &dir, &mut failed);
            runs += 1;
        }
    }
    for (label, kerlico) in [("udp-size-reverse/xray-control", false), ("udp-size-reverse/kerlico-bridge", true)] {
        let dir = root.join(label);
        let result = fs::create_dir_all(&dir).map_err(Into::into).and_then(|_| udp_size_reverse(&xray, &dir, label, kerlico));
        report(label, result, &dir, &mut failed);
        runs += 1;
    }
    finish_report("VLESS UDP size", runs, &failed, &root);
}

/// How the client under test carries its UDP flow, and the largest datagram the client and
/// the server may each write in it.
#[derive(Clone, Copy)]
enum SizeFraming {
    /// Sessions on one Mux carrier, which also carries the TCP flow.
    Mux,
    /// A client XUDP carrier of its own, Xray's `v1.mux.cool:666`.
    Xudp,
    /// The UDP command, which both clients keep for port 443 without Mux.
    Plain,
}

impl SizeFraming {
    fn name(self) -> &'static str {
        match self {
            Self::Mux => "mux",
            Self::Xudp => "xudp",
            Self::Plain => "plain",
        }
    }

    fn limits(self) -> (usize, usize) {
        match self {
            Self::Mux => (XRAY_BUFFER, XRAY_BUFFER),
            Self::Xudp => (XRAY_BUFFER - 666, XRAY_BUFFER),
            Self::Plain => (XRAY_BUFFER - 2, XRAY_BUFFER - 2),
        }
    }

    fn udp_port(self) -> u16 {
        if matches!(self, Self::Plain) { 443 } else { 0 }
    }

    fn carriers(self) -> usize {
        if matches!(self, Self::Mux) { 1 } else { 2 }
    }
}

fn udp_size(xray: &Path, dir: &Path, label: &str, framing: SizeFraming, direction: Direction) -> Result<()> {
    let _fixed_origin = (framing.udp_port() != 0)
        .then(|| FIXED_ORIGIN.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
    let case = Case::new("udp-size", Network::Raw, Security::None, Payload::Udp);
    let keys = Keys::generate(dir, &case)?;
    let tcp = Echo::tcp(None)?;
    let udp = sized_origin(framing.udp_port())?;
    let peer = available_port()?;
    let (link, carriers) = count_tcp_carriers(peer, Duration::from_secs(120))?;
    let _server = if matches!(direction, Direction::XrayToKerlico) {
        start_kerlico(dir, &case.kerlico_server(&keys, peer))?
    } else {
        let mut config = case.xray_server(&keys, peer, udp.port);
        config["outbounds"][0]["settings"]["finalRules"][0]["port"] = json!(format!("{},{}", tcp.port, udp.port));
        start_xray(xray, dir, "xray-server", &config, true)?
    };
    let mux = matches!(framing, SizeFraming::Mux).then(|| json!({"enabled": true}));
    let (mut client, _client) = if matches!(direction, Direction::KerlicoToXray) {
        let mut settings = kerlico_shared::Settings::default();
        for (key, value) in [("network", "raw"), ("security", "none"), ("encryption", "none"), ("id", cases::ID)] {
            settings.insert_text(key, value);
        }
        if let Some(mux) = mux {
            settings.insert_text("mux", mux.to_string());
        }
        (SizeClient::kerlico(link, &settings, tcp.port, udp.port)?, None)
    } else {
        let (front_tcp, front_udp) = (available_port()?, available_port()?);
        let mut config = case.xray_client(&keys, front_udp, link, udp.port);
        config["inbounds"].as_array_mut().ok_or("client inbounds")?.push(json!({
            "protocol": "tunnel", "listen": "127.0.0.1", "port": front_tcp,
            "settings": {"address": "127.0.0.1", "port": tcp.port, "network": "tcp"},
        }));
        if let Some(mux) = mux {
            config["outbounds"][0]["mux"] = mux;
        }
        let process = launch_xray(xray, dir, "xray-client", &config, &[])?;
        (SizeClient::xray(front_tcp, front_udp)?, Some(process))
    };
    let xray_client = !matches!(direction, Direction::KerlicoToXray);
    let xray_server = !matches!(direction, Direction::XrayToKerlico);
    size_sequence(&mut client, label, framing.limits(), xray_client, xray_server)?;
    let count = carriers.load(Ordering::Acquire);
    if count != framing.carriers() {
        return Err(format!("{count} carriers, expected {}", framing.carriers()).into());
    }
    Ok(())
}

/// The Xray portal writes the client side of each datagram and the bridge writes the replies.
fn udp_size_reverse(xray: &Path, dir: &Path, label: &str, kerlico: bool) -> Result<()> {
    let tcp = Echo::tcp(None)?;
    let udp = sized_origin(0)?;
    let portal = BridgedPortal::start(xray, dir, kerlico, tcp.port, udp.port)?;
    let mut client = SizeClient::xray(portal.front_tcp, portal.front_udp)?;
    size_sequence(&mut client, label, (XRAY_BUFFER, XRAY_BUFFER), true, !kerlico)?;
    settle_carriers(&portal.carriers, 1, "after the datagrams")
}

/// Echoes each datagram, except that `[b'Z', length as big-endian u16, seed]` asks for a reply
/// of `pattern(length, seed)`.
fn sized_origin(port: u16) -> Result<Echo> {
    Echo::udp_with(port, |_, bytes| match *bytes {
        [b'Z', high, low, seed] => pattern(u16::from_be_bytes([high, low]).into(), seed.into()),
        _ => bytes.to_vec(),
    })
}

/// The client writes a datagram at its limit, the datagrams over it, then a short one. It then
/// asks the origin for replies of the same sizes and for an empty one. Each short datagram must
/// be the next to arrive, and the TCP flow must keep working.
fn size_sequence(client: &mut SizeClient, label: &str, (client_limit, server_limit): (usize, usize), xray_client: bool, xray_server: bool) -> Result<()> {
    let over = |limit: usize| {
        let mut sizes = vec![limit + 1, XRAY_BUFFER + 1];
        sizes.dedup();
        sizes
    };
    let ask = |len: usize, seed: u8| [&[b'Z'][..], &(len as u16).to_be_bytes()[..], &[seed][..]].concat();
    client.tcp_exchange(17, 33).map_err(|error| format!("TCP before the datagrams: {error}"))?;

    let at_limit = pattern(client_limit, 1);
    client.send(&at_limit)?;
    next_datagram(client, &at_limit, &[], false)?;
    let oversized: Vec<_> = over(client_limit).into_iter().zip(10..).map(|(len, seed)| pattern(len, seed)).collect();
    for datagram in &oversized {
        client.send(datagram)?;
    }
    let short = pattern(100, 3);
    client.send(&short)?;
    let from_client = next_datagram(client, &short, &oversized, xray_client)
        .map_err(|error| format!("after the client wrote {:?} bytes: {error}", over(client_limit)))?;

    client.send(&ask(server_limit, 4))?;
    next_datagram(client, &pattern(server_limit, 4), &[], false)?;
    let mut replies = Vec::new();
    for (len, seed) in over(server_limit).into_iter().zip(20u8..) {
        client.send(&ask(len, seed))?;
        replies.push(pattern(len, seed.into()));
    }
    client.send(&ask(0, 6))?;
    let short = pattern(100, 7);
    client.send(&short)?;
    let from_server = next_datagram(client, &short, &replies, xray_server)
        .map_err(|error| format!("after the server wrote {:?} bytes: {error}", over(server_limit)))?;
    client.tcp_exchange(19, 77).map_err(|error| format!("TCP after the datagrams: {error}"))?;
    eprintln!(
        "UDP-SIZE {label}: client oversized truncated {}, server oversized truncated {}, empty replies delivered {}",
        from_client.truncated, from_server.truncated, from_server.empty,
    );
    Ok(())
}

#[derive(Default)]
struct Skipped {
    truncated: usize,
    empty: usize,
}

/// Reads until `expected` arrives. Empty datagrams are counted. An oversized datagram may come
/// back only from an Xray writer, cut to its read buffer, because Xray truncates rather than drops.
fn next_datagram(client: &SizeClient, expected: &[u8], oversized: &[Vec<u8>], xray_wrote: bool) -> Result<Skipped> {
    let mut skipped = Skipped::default();
    loop {
        let received = client
            .recv()
            .map_err(|error| format!("waiting for the {}-byte datagram: {error}", expected.len()))?;
        if received == expected {
            return Ok(skipped);
        }
        if received.is_empty() {
            skipped.empty += 1;
        } else if xray_wrote && oversized.iter().any(|sent| sent.len() > XRAY_BUFFER && received == sent[..XRAY_BUFFER]) {
            skipped.truncated += 1;
        } else {
            return Err(format!("a {}-byte datagram arrived before the {}-byte one", received.len(), expected.len()).into());
        }
    }
}

/// The application end of one TCP flow and one UDP flow through the client under test.
enum SizeClient {
    Xray {
        tcp: TcpStream,
        udp: UdpSocket,
    },
    Kerlico {
        tcp: Box<dyn kerlico_shared::InboundStream>,
        udp: landing_vless::UdpSession,
        target: kerlico_shared::Destination,
    },
}

impl SizeClient {
    fn xray(front_tcp: u16, front_udp: u16) -> Result<Self> {
        let udp = UdpSocket::bind(localhost(0))?;
        udp.connect(localhost(front_udp))?;
        udp.set_read_timeout(Some(TIMEOUT))?;
        Ok(Self::Xray { tcp: open_front(front_tcp)?, udp })
    }

    fn kerlico(peer: u16, settings: &kerlico_shared::Settings, tcp: u16, udp: u16) -> Result<Self> {
        use kerlico_shared::{Destination, Transport};
        let origin = |port, transport| Destination::new("127.0.0.1", port, transport).map_err(|_| "origin destination");
        let target = origin(udp, Transport::Udp)?;
        let tcp = landing_vless::land("127.0.0.1", peer, settings, &origin(tcp, Transport::Tcp)?)
            .map_err(|error| format!("Kerlico TCP flow: {error:?}"))?;
        let udp = landing_vless::land_udp("127.0.0.1", peer, settings, &target)
            .map_err(|error| format!("Kerlico UDP flow: {error:?}"))?;
        Ok(Self::Kerlico { tcp, udp, target })
    }

    fn send(&self, datagram: &[u8]) -> Result<()> {
        let sent = match self {
            Self::Xray { udp, .. } => udp.send(datagram)?,
            Self::Kerlico { udp, target, .. } => retry_flow(|| udp.send_to(target, datagram))?,
        };
        if sent != datagram.len() {
            return Err(format!("sent {sent}/{} UDP bytes", datagram.len()).into());
        }
        Ok(())
    }

    fn recv(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; 65536];
        let len = match self {
            Self::Xray { udp, .. } => udp.recv(&mut bytes)?,
            Self::Kerlico { udp, .. } => retry_flow(|| udp.recv_from(&mut bytes))?.0,
        };
        bytes.truncate(len);
        Ok(bytes)
    }

    fn tcp_exchange(&mut self, len: usize, seed: usize) -> Result<()> {
        match self {
            Self::Xray { tcp, .. } => tcp_exchange(tcp, len, seed),
            Self::Kerlico { tcp, .. } => tcp_exchange(&mut FlowIo(&**tcp), len, seed),
        }
    }
}

/// Repeats a Kerlico flow call that returns `Again` until `TIMEOUT`.
fn retry_flow<T>(mut call: impl FnMut() -> std::result::Result<T, kerlico_shared::PlaneFault>) -> std::io::Result<T> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match call() {
            Ok(value) => return Ok(value),
            Err(kerlico_shared::PlaneFault::Again) if Instant::now() < deadline => {}
            Err(fault) => return Err(std::io::Error::other(format!("Kerlico flow: {fault:?}"))),
        }
    }
}

struct FlowIo<'a>(&'a dyn kerlico_shared::InboundStream);

impl Read for FlowIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let flow = self.0;
        retry_flow(|| match flow.read_from_user(buf) {
            Err(kerlico_shared::PlaneFault::Closed) => Ok(0),
            read => read,
        })
    }
}

impl Write for FlowIo<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let flow = self.0;
        retry_flow(|| flow.write_to_user(buf))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
#[ignore = "requires XRAY pointing to Xray 26.10.31 a4a3dff"]
fn vless_xray_h2_params() {
    let root = run_dir("h2-params").expect("h2 params directory");
    let xray = xray_binary(&root).expect("pinned Xray peer");
    let mut runs = 0;
    let mut failed = Vec::new();
    for (name, security) in [("h2c", Security::None), ("tls", Security::Tls("h2"))] {
        runs += 1;
        let label = format!("h2-params-{name}");
        let dir = root.join(&label);
        let result = fs::create_dir(&dir)
            .map_err(Into::into)
            .and_then(|_| h2_params_case(&xray, &dir, security));
        report(&label, result, &dir, &mut failed);
    }
    finish_report("VLESS h2Params", runs, &failed, &root);
}

fn h2_params_case(xray: &Path, root: &Path, security: Security) -> Result<()> {
    let tls = matches!(security, Security::Tls(_));
    let mut hellos = Vec::new();
    for (probe, params) in [("limits", h2_probe::LIMIT_PARAMS), ("pings", h2_probe::PING_PARAMS)] {
        for server in ["kerlico", "xray"] {
            let dir = root.join(format!("{probe}-{server}"));
            fs::create_dir(&dir)?;
            let case = Case::new("h2-probe", Network::Xhttp("packet-up"), security, Payload::Tcp)
                .h2_params(params);
            let keys = Keys::generate(&dir, &case)?;
            let origin = Echo::tcp(None)?;
            let peer = available_port()?;
            let _server = if server == "kerlico" {
                start_kerlico(&dir, &case.kerlico_server(&keys, peer))?
            } else {
                start_xray(xray, &dir, "xray-server", &case.xray_server(&keys, peer, origin.port), false)?
            };
            if probe == "pings" {
                h2_probe::pings(peer, tls).map_err(|error| format!("{server} pings: {error}"))?;
                continue;
            }
            let hello = h2_probe::handshake(&mut h2_probe::Wire::connect(peer, tls)?)
                .map_err(|error| format!("{server} hello: {error}"))?;
            eprintln!("H2 {server} {hello:?}");
            h2_probe::expect_limits(&hello).map_err(|error| format!("{server}: {error}"))?;
            h2_probe::frame_limit(peer, tls, h2_probe::LIMIT_FRAME)
                .map_err(|error| format!("{server} frame limit: {error}"))?;
            hellos.push(hello);
        }
    }
    let [kerlico, xray] = &hellos[..] else {
        return Err("missing a server hello".into());
    };
    for (id, value) in &kerlico.settings {
        if xray.settings.get(id).is_some_and(|other| other != value) {
            return Err(format!("SETTINGS {id}: Kerlico {value}, Xray {:?}", xray.settings.get(id)).into());
        }
    }
    Ok(())
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
    finish_report("VLESS REALITY target", runs, &failed, &root);
}

fn reality_target(xray: &Path, dir: &Path, server: RealityServer, address: DecoyAddress, xver: u8) -> Result<()> {
    let case = Case::new("reality-target", Network::Raw, Security::Reality, Payload::Tcp);
    let keys = Keys::generate(dir, &case)?;
    // Both servers probe the decoy with a TLS client that verifies its certificate and learn nothing
    // from a decoy they do not trust. Go and Kerlico read their root certificates from SSL_CERT_FILE.
    // The peers inherit it; this test runs alone.
    struct Trusted;
    impl Drop for Trusted {
        fn drop(&mut self) {
            std::env::remove_var("SSL_CERT_FILE");
        }
    }
    std::env::set_var("SSL_CERT_FILE", &keys.cert);
    let _trusted = Trusted;
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
        RealityServer::Xray => start_xray(xray, dir, "xray-server", &config, false)?,
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
    let _client = start_xray(xray, dir, "xray-client", &case.xray_client(keys, front, tap, origin), false)?;
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
    // Behind the flight come records as long as the ones the decoy sends a real client after its
    // Finished: its tickets. The decoy saw those in the server's own probes and in the prober's TLS
    // session. The ECDSA signature makes the encrypted flight a few bytes longer or shorter from
    // session to session, so only the ServerHello and the ChangeCipherSpec identify a flight.
    let tickets = decoy
        .recordings
        .lock()
        .unwrap()
        .iter()
        .map(|entry| entry.lock().unwrap().clone())
        .filter(|session| !session.input.windows(32).any(|window| window == random))
        .map(|session| record_lengths(&session.output))
        .filter(|lengths| lengths.len() > sent.len() && lengths[..2] == sent[..2])
        .map(|lengths| lengths[sent.len()..].to_vec())
        .collect::<Vec<_>>();
    eprintln!("decoy ticket records {tickets:?}; records behind the server flight {:?}", &mirrored[sent.len()..mirrored.len().min(sent.len() + 6)]);
    if tickets.is_empty() {
        return Err("the decoy never completed a handshake with a prober, so there are no tickets to compare".into());
    }
    if !tickets.iter().any(|tail| mirrored[sent.len()..].starts_with(tail)) {
        return Err(format!("records behind the server flight {:?} do not start with the decoy's ticket records {tickets:?}", &mirrored[sent.len()..]).into());
    }
    replay_probe(&carrier.input, port, sent.len())
}

/// A prober that replays a client's ClientHello gets the server's flight but cannot seal what comes
/// next. Xray answers a record it cannot authenticate with a fatal alert sealed under the server's
/// application key, 24 bytes long, and closes. So must Kerlico.
fn replay_probe(client_bytes: &[u8], port: u16, flight_records: usize) -> Result<()> {
    let length = 5 + u16::from_be_bytes([*client_bytes.get(3).ok_or("no ClientHello")?, *client_bytes.get(4).ok_or("no ClientHello")?]) as usize;
    let mut stream = tcp_connect(port)?;
    stream.set_read_timeout(Some(TIMEOUT * 3))?;
    stream.write_all(client_bytes.get(..length).ok_or("short ClientHello")?)?;
    for _ in 0..flight_records {
        let mut header = [0; 5];
        stream.read_exact(&mut header)?;
        let mut body = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
        stream.read_exact(&mut body)?;
    }
    stream.write_all(&[23, 3, 3, 0, 32])?;
    stream.write_all(&[0x5a; 32])?;
    let mut reply = Vec::new();
    let mut buffer = [0; 256];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => reply.extend_from_slice(&buffer[..count]),
        }
    }
    eprintln!("answer to a record that cannot be authenticated: {} bytes {:02x?}", reply.len(), &reply[..reply.len().min(5)]);
    if reply.len() != 24 || reply[..5] != [23, 3, 3, 0, 19] {
        return Err(format!("expected one 24-byte alert record and a close, got {} bytes", reply.len()).into());
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
