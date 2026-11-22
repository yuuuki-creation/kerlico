#![cfg(all(feature = "vless", feature = "landing-vless"))]

//! Load comparison of Kerlico and the pinned Xray over loopback, one 20 second round per case and direction.
//!
//! ```text
//! XRAY=/path/to/xray PERF_OUT=/path/results.jsonl cargo test --release -p kerlico-server \
//!     --no-default-features --features vless,landing-vless --test vless_perf -- --ignored --nocapture
//! ```
//!
//! Every case of the matrix that carries a data path is measured three ways, so each side of Kerlico
//! is compared with Xray while the other side stays Xray:
//! - `xray-control`: Xray client and Xray server,
//! - `xray-to-kerlico`: Xray client and Kerlico server (the server under test),
//! - `kerlico-to-xray`: Kerlico client and Xray server (the client under test).
//!
//! Kerlico runs as the `kerlico-server` binary and Xray as its own process. The processes of the
//! tunnel are pinned with `taskset`, the load generator and the echo origin to their own cores.
//! TCP cases open `PERF_STREAMS` persistent streams that write a bounded flight of numbered 32 KiB blocks and verify every echo, plus one
//! probe stream that exchanges 64 bytes every 10 ms. UDP cases keep a window of datagrams in flight.
//!
//! Environment: `PERF_OUT` (JSON lines), `PERF_CASE` (comma separated substrings of case names, or
//! `=name` for one exact name), `PERF_DIRECTION` (the same for direction names),
//! `PERF_SHARD` (`i/n`: this run takes every n-th case starting at i), `PERF_SECONDS` (window, 20),
//! `PERF_TCP_FLIGHT_BLOCKS` (1–32 per stream, default 1),
//! `PERF_WARMUP` (seconds of load before the window, 3), `PERF_STREAMS` (4), `PERF_ROUNDS` (1),
//! `PERF_SERVER_CPUS`, `PERF_CLIENT_CPUS`, `PERF_LOAD_CPUS` (taskset lists), `PERF_WORKER` (label).

#[path = "vless_support/cases.rs"]
mod cases;
#[path = "vless_support/mod.rs"]
mod support;
#[path = "vless_support/xdrive_mock.rs"]
mod xdrive_mock;
#[path = "vless_support/study.rs"]
mod study;

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use cases::{Case, Keys, Payload, Security, INGRESS_ID, TLS_NAME};
use support::{available_port, localhost, run_dir, tcp_connect, write_json, Echo, Process, Result};

const XRAY_VERSION: &str = "26.10.31";
const BLOCK: usize = 32 * 1024;
const DATAGRAM: usize = 1200;
const CLOCK_TICKS: f64 = 100.0;

trait Duplex: Read + Write + Send {}
impl<T: Read + Write + Send> Duplex for T {}
type Open<'a> = &'a (dyn Fn() -> Result<Box<dyn Duplex>> + Sync);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    XrayControl,
    XrayToKerlico,
    KerlicoToXray,
    KerlicoControl,
}

impl Direction {
    const ALL: [Self; 3] = [Self::XrayControl, Self::XrayToKerlico, Self::KerlicoToXray];
    const BOTH_ENDS: [Self; 4] = [Self::XrayControl, Self::XrayToKerlico, Self::KerlicoToXray, Self::KerlicoControl];

    fn name(self) -> &'static str {
        match self {
            Self::XrayControl => "xray-control",
            Self::XrayToKerlico => "xray-to-kerlico",
            Self::KerlicoToXray => "kerlico-to-xray",
            Self::KerlicoControl => "kerlico-control",
        }
    }

    /// Who runs the server and the client.
    fn implementations(self) -> (&'static str, &'static str) {
        match self {
            Self::XrayControl => ("xray", "xray"),
            Self::XrayToKerlico => ("kerlico", "xray"),
            Self::KerlicoToXray => ("xray", "kerlico"),
            Self::KerlicoControl => ("kerlico", "kerlico"),
        }
    }
}

struct Settings {
    seconds: u64,
    target_mbps: u64,
    warmup: u64,
    streams: usize,
    tcp_flight_blocks: usize,
    /// Datagrams in flight per UDP flow.
    window: usize,
    server_cpus: String,
    client_cpus: String,
    worker: String,
}

fn number(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}

fn text(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

/// Cases that only vary a setting which leaves the data path alone, or that need a fixture the load
/// cannot drive, are not measured: the protocol matrix already covers them.
fn measurable(case: &Case) -> bool {
    const SKIPPED: &[&str] = &[
        "forwarded-",
        "sockopt-mixed-case",
        "xmux-",
        "max-streams-1",
        "custom-headers",
        "early-data",
        "ticket-reconnect",
        "-pinned",
        "separate-download",
        "xhttp-h1-header-get",
        "xhttp-h2-cookie-options",
        "xhttp-h3-query-get",
        "xhttp-h1-stream-patch",
        "udp53",
        "udp443",
    ];
    !case.rejected
        && case.mock.is_none()
        && !case.resume
        && !case.separate_download()
        && !SKIPPED.iter().any(|skipped| case.name.contains(skipped))
}

/// A term selects the names that contain it; `=name` selects that one name.
fn selected(filter: &str, name: &str) -> bool {
    filter.is_empty()
        || filter.split(',').map(str::trim).any(|term| match term.strip_prefix('=') {
            Some(exact) => name == exact,
            None => !term.is_empty() && name.contains(term),
        })
}

fn pin_self(cpus: &str) {
    let pid = std::process::id().to_string();
    let _ = Command::new("taskset").args(["-a", "-c", "-p", cpus, &pid]).status();
}

fn xray_binary() -> Result<PathBuf> {
    let xray = PathBuf::from(std::env::var_os("XRAY").ok_or("set XRAY to the pinned executable")?).canonicalize()?;
    let output = Command::new(&xray).arg("version").output()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let version = text.lines().next().unwrap_or_default().to_owned();
    if !version.starts_with(&format!("Xray {XRAY_VERSION} ")) {
        return Err(format!("expected Xray {XRAY_VERSION}, got {version}").into());
    }
    eprintln!("XRAY {version}");
    Ok(xray)
}

fn start_xray(xray: &Path, cpus: &str, dir: &Path, name: &str, config: &Value, cone: bool) -> Result<Process> {
    let client = name.ends_with("-client");
    let path = write_json(dir, &format!("{name}.json"), &study::config(config, client))?;
    let mut command = study::command(cpus, xray, client);
    command.args(["run", "-c"]).arg(path);
    if !cone {
        command.env("xray.cone.disabled", "true");
    }
    let mut process = Process::spawn(command, dir, name)?;
    process.wait_for_log(&format!("Xray {XRAY_VERSION} started"))?;
    Ok(process)
}

fn start_kerlico(kerlico: &Path, cpus: &str, dir: &Path, name: &str, config: &Value) -> Result<Process> {
    let client = name.ends_with("-client");
    let path = write_json(dir, &format!("{name}.json"), &study::config(config, client))?;
    let mut command = study::command(cpus, kerlico, client);
    command.arg(path);
    let process = Process::spawn(command, dir, name)?;
    // The binary prints the protocols it compiled in once the configuration is loaded; a debug build takes seconds.
    let started = Instant::now();
    while !process.output()?.contains("vless") {
        if started.elapsed() > Duration::from_secs(60) {
            return Err(format!("{name} did not finish loading").into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    thread::sleep(Duration::from_millis(500));
    Ok(process)
}

/// A TCP echo origin that does not hold small writes back (`support::Echo` leaves Nagle on, which
/// makes a 32 KiB block wait for a delayed ACK) and copies in large reads.
struct Origin {
    port: u16,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Origin {
    fn tcp(tls: Option<Arc<kerlico_vless::ServerConfig>>) -> Result<Self> {
        let listener = std::net::TcpListener::bind(localhost(0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let running = stop.clone();
        let worker = thread::spawn(move || {
            while !running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let tls = tls.clone();
                        thread::spawn(move || {
                            let _ = stream.set_nodelay(true);
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
                            match tls {
                                Some(config) => {
                                    if let Ok(stream) = kerlico_vless::accept_tls(stream, config) {
                                        let _ = echo(stream);
                                    }
                                }
                                None => {
                                    let _ = echo(stream);
                                }
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        });
        Ok(Self { port, stop, worker: Some(worker) })
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn echo(mut stream: impl Read + Write) -> std::io::Result<()> {
    let mut bytes = vec![0; 64 * 1024];
    loop {
        let len = stream.read(&mut bytes)?;
        if len == 0 {
            return Ok(());
        }
        stream.write_all(&bytes[..len])?;
        stream.flush()?;
    }
}

fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|index| ((index * 37 + seed) % 251) as u8).collect()
}

/// Every client, Xray's and Kerlico's, gets its traffic through the same VLESS ingress, so the load
/// takes the same path whichever client is measured. The destination is an address, not a name:
/// Kerlico's server has no host table for the origin name.
const INGRESS_TEXT: &str = "01020304-0506-0708-090a-0b0c0d0e0f10";

/// Kerlico's ingress sends the VLESS response with the first reply bytes, so the first read skips it.
fn open_ingress(port: u16, origin: u16, udp: bool, read_timeout: Option<Duration>) -> Result<Box<dyn Duplex>> {
    let mut stream = study::connect_front(port)?;
    if read_timeout.is_some() {
        stream.set_read_timeout(read_timeout)?;
    }
    let mut request = vec![0];
    request.extend_from_slice(&INGRESS_ID);
    request.extend_from_slice(&[0, if udp { 2 } else { 1 }]);
    request.extend_from_slice(&origin.to_be_bytes());
    request.extend_from_slice(&[1, 127, 0, 0, 1]);
    stream.write_all(&request)?;
    Ok(Box::new(kerlico_vless::ResponseReader::new(stream)))
}

fn open_tcp(front: u16, origin: u16, inject: bool, inner_tls: bool) -> Result<Box<dyn Duplex>> {
    use tokio_rustls::rustls::{pki_types::ServerName, ClientConnection, StreamOwned};
    let stream: Box<dyn Duplex> = if inject { open_ingress(front, origin, false, None)? } else { Box::new(tcp_connect(front)?) };
    if !inner_tls {
        return Ok(stream);
    }
    let tls = kerlico_vless::client_config(&[], true).map_err(|_| "make inner TLS client")?;
    let client = ClientConnection::new(tls, ServerName::try_from(TLS_NAME)?).map_err(|error| format!("inner TLS client: {error}"))?;
    Ok(Box::new(StreamOwned::new(client, stream)))
}

#[derive(Default)]
struct Counters {
    bytes: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
    errors: AtomicU64,
    /// The first few reasons a load stream gave up, to tell a broken tunnel from a measurement artifact.
    notes: std::sync::Mutex<Vec<String>>,
}

impl Counters {
    fn fail(&self, why: impl std::fmt::Display) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        let mut notes = self.notes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if notes.len() < 4 {
            notes.push(why.to_string());
        }
    }
}

fn bulk(open: Open, stop: &AtomicBool, counters: &Counters, settings: &Settings, rate: u64) {
    let mut stream = match open() {
        Ok(stream) => stream,
        Err(error) => return counters.fail(format!("open: {error}")),
    };
    let block = pattern(BLOCK, 7);
    let flight = settings.tcp_flight_blocks;
    let mut out = block.repeat(flight);
    let mut sequence = 0_u64;
    let mut input = vec![0; BLOCK];
    let mut pace = study::Pace::new(rate, settings.streams, out.len());
    while !stop.load(Ordering::Relaxed) {
        pace.wait();
        for payload in out.chunks_exact_mut(BLOCK) {
            payload[..8].copy_from_slice(&sequence.to_be_bytes());
            sequence += 1;
        }
        if let Err(error) = stream.write_all(&out).and_then(|()| stream.flush()) {
            if !stop.load(Ordering::Relaxed) {
                counters.fail(format!("block: {error}"));
            }
            return;
        }
        for expected in out.chunks_exact(BLOCK) {
            if let Err(error) = stream.read_exact(&mut input) {
                if !stop.load(Ordering::Relaxed) { counters.fail(format!("echo: {error}")); }
                return;
            }
            if input != expected { return counters.fail("TCP echo payload mismatch"); }
            counters.bytes.fetch_add(BLOCK as u64, Ordering::Relaxed);
        }
    }
}

/// A 64 byte request and reply every 10 ms; returns when each exchange finished and how long it took.
fn probe(open: Open, stop: &AtomicBool) -> Vec<(Instant, u64)> {
    let mut samples = Vec::new();
    let Ok(mut stream) = open() else { return samples };
    let out = pattern(64, 3);
    let mut input = [0; 64];
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        if stream.write_all(&out).and_then(|()| stream.flush()).is_err() || stream.read_exact(&mut input).is_err() {
            break;
        }
        if input.as_slice() != out.as_slice() { break; }
        samples.push((Instant::now(), started.elapsed().as_micros() as u64));
        thread::sleep(Duration::from_millis(10));
    }
    samples
}

fn udp_plain(front: u16, window: usize, stop: &AtomicBool, counters: &Counters) {
    let Ok(socket) = UdpSocket::bind(localhost(0)) else { return };
    if socket.connect(localhost(front)).is_err() || socket.set_read_timeout(Some(Duration::from_millis(300))).is_err() {
        return;
    }
    let payload = pattern(DATAGRAM, 5);
    let mut buffer = [0; 2048];
    while !stop.load(Ordering::Relaxed) {
        for _ in 0..window {
            if let Err(error) = socket.send(&payload) {
                return counters.fail(format!("udp send: {error}"));
            }
            counters.sent.fetch_add(1, Ordering::Relaxed);
        }
        let mut got = 0;
        while got < window {
            match socket.recv(&mut buffer) {
                Ok(_) => {
                    got += 1;
                    counters.received.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                Err(error) => return counters.fail(format!("udp recv: {error}")),
            }
        }
    }
}

/// Reads one framed datagram. `Ok(false)` means nothing arrived in time: the datagram was lost, which
/// UDP allows, and the framing is still in step because nothing of the frame had been read.
fn read_datagram(stream: &mut dyn Duplex, body: &mut [u8]) -> std::io::Result<bool> {
    let mut prefix = [0; 2];
    let mut got = 0;
    while got < prefix.len() {
        match stream.read(&mut prefix[got..]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => got += count,
            Err(error) if got == 0 && matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Ok(false),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => {}
            Err(error) => return Err(error),
        }
    }
    let length = u16::from_be_bytes(prefix) as usize;
    if length != body.len() {
        return Err(std::io::Error::other(format!("frame of {length} bytes")));
    }
    stream.read_exact(body)?;
    Ok(true)
}

fn udp_ingress(front: u16, origin: u16, window: usize, stop: &AtomicBool, counters: &Counters, mut pace: study::Pace) {
    // The carrier's usual read timeout is seconds. A lost datagram must cost a batch a fraction of one.
    let mut stream = match open_ingress(front, origin, true, Some(Duration::from_millis(300))) {
        Ok(stream) => stream,
        Err(error) => return counters.fail(format!("ingress open: {error}")),
    };
    let mut frame = (DATAGRAM as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&pattern(DATAGRAM, 5));
    let mut body = vec![0; DATAGRAM];
    let mut sequence = 0_u64;
    let mut seen = vec![u64::MAX; 65536];
    while !stop.load(Ordering::Relaxed) {
        pace.wait();
        for _ in 0..window {
            frame[2..10].copy_from_slice(&sequence.to_be_bytes());
            sequence += 1;
            if let Err(error) = stream.write_all(&frame) {
                return counters.fail(format!("ingress write: {error}"));
            }
            counters.sent.fetch_add(1, Ordering::Relaxed);
        }
        if let Err(error) = stream.flush() {
            return counters.fail(format!("ingress flush: {error}"));
        }
        for _ in 0..window {
            match read_datagram(stream.as_mut(), &mut body) {
                Ok(true) => {
                    let id = u64::from_be_bytes(body[..8].try_into().unwrap());
                    if body[8..] != frame[10..] || id >= sequence || sequence - id > seen.len() as u64 {
                        return counters.fail("UDP echo sequence or payload mismatch");
                    }
                    let slot = id as usize % seen.len();
                    if seen[slot] == id { return counters.fail("duplicate UDP echo"); }
                    seen[slot] = id;
                    counters.received.fetch_add(1, Ordering::Relaxed);
                }
                Ok(false) => break,
                Err(error) => {
                    if !stop.load(Ordering::Relaxed) {
                        counters.fail(format!("ingress read: {error}"));
                    }
                    return;
                }
            }
        }
    }
}

/// One datagram out and back before the load starts, so the tunnel's flow exists.
fn warm_udp(rig: &Rig) -> Result<()> {
    let payload = pattern(DATAGRAM, 5);
    if rig.inject {
        let mut stream = open_ingress(rig.front, rig.origin, true, None)?;
        stream.write_all(&(DATAGRAM as u16).to_be_bytes())?;
        stream.write_all(&payload)?;
        let mut prefix = [0; 2];
        stream.read_exact(&mut prefix)?;
        let mut body = vec![0; u16::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut body)?;
        if body != payload { return Err("unexpected UDP warmup echo".into()); }
        return Ok(());
    }
    let socket = UdpSocket::bind(localhost(0))?;
    socket.connect(localhost(rig.front))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buffer = [0; 2048];
    for _ in 0..5 {
        socket.send(&payload)?;
        if socket.recv(&mut buffer).is_ok() {
            return Ok(());
        }
    }
    Err("the UDP tunnel never answered".into())
}

#[derive(Clone, Copy, Default)]
struct Sample {
    ticks: u64,
    user_ticks: u64,
    system_ticks: u64,
    minor_faults: u64,
    major_faults: u64,
    rss_kb: u64,
    hwm_kb: u64,
    threads: u64,
    fds: usize,
}

fn sample(pid: u32) -> Option<Sample> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    let user_ticks = fields.get(11)?.parse::<u64>().ok()?;
    let system_ticks = fields.get(12)?.parse::<u64>().ok()?;
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let value = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
    };
    Some(Sample {
        ticks: user_ticks + system_ticks,
        user_ticks,
        system_ticks,
        minor_faults: fields.get(7)?.parse().ok()?,
        major_faults: fields.get(9)?.parse().ok()?,
        rss_kb: value("VmRSS:")?,
        hwm_kb: value("VmHWM:")?,
        threads: value("Threads:")?,
        fds: fs::read_dir(format!("/proc/{pid}/fd")).map(|entries| entries.count()).unwrap_or(0),
    })
}

fn percentile(sorted: &[u64], fraction: f64) -> Option<u64> {
    (!sorted.is_empty()).then(|| sorted[((sorted.len() - 1) as f64 * fraction).round() as usize])
}

/// What one load run measured about a process.
fn role(name: &str, idle: Option<Sample>, before: Option<Sample>, after: Option<Sample>, rss: &[u64], threads: u64, fds: usize, seconds: f64) -> Value {
    let cpu = match (before, after) {
        (Some(before), Some(after)) => Some((after.ticks.saturating_sub(before.ticks)) as f64 / CLOCK_TICKS),
        _ => None,
    };
    json!({
        "implementation": name,
        "cpu_seconds": cpu,
        "user_seconds": before.zip(after).map(|(a,b)| b.user_ticks.saturating_sub(a.user_ticks) as f64 / CLOCK_TICKS),
        "system_seconds": before.zip(after).map(|(a,b)| b.system_ticks.saturating_sub(a.system_ticks) as f64 / CLOCK_TICKS),
        "minor_faults": before.zip(after).map(|(a,b)| b.minor_faults.saturating_sub(a.minor_faults)),
        "major_faults": before.zip(after).map(|(a,b)| b.major_faults.saturating_sub(a.major_faults)),
        "cpu_percent": cpu.map(|cpu| cpu / seconds * 100.0),
        "rss_idle_kb": idle.map(|sample| sample.rss_kb),
        "rss_avg_kb": (!rss.is_empty()).then(|| rss.iter().sum::<u64>() / rss.len() as u64),
        "rss_max_kb": rss.iter().max(),
        "rss_peak_kb": after.map(|sample| sample.hwm_kb),
        "threads_max": threads,
        "fds_max": fds,
    })
}

struct Rig {
    front: u16,
    origin: u16,
    inject: bool,
    udp: bool,
    inner_tls: bool,
}

/// Runs the load against the tunnel and returns the measurements of one round.
fn load(rig: &Rig, settings: &Settings, pids: &[(&str, u32)]) -> Result<Value> {
    let stop = AtomicBool::new(false);
    let counters = Counters::default();
    let open: Box<dyn Fn() -> Result<Box<dyn Duplex>> + Sync> = {
        let (front, origin, inject, inner_tls) = (rig.front, rig.origin, rig.inject, rig.inner_tls);
        Box::new(move || open_tcp(front, origin, inject, inner_tls))
    };
    // A first exchange proves the tunnel works before anything is counted. A REALITY server may hold it
    // while it probes its decoy.
    if !rig.udp {
        let mut last = String::new();
        let mut ready = false;
        for _ in 0..8 {
            match open().and_then(|mut stream| {
                let out = pattern(4096, 1);
                stream.write_all(&out)?;
                stream.flush()?;
                let mut input = vec![0; out.len()];
                stream.read_exact(&mut input)?;
                Ok(input == out)
            }) {
                Ok(true) => {
                    ready = true;
                    break;
                }
                Ok(false) => last = "echo differs".into(),
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(500));
        }
        if !ready {
            return Err(format!("the tunnel never answered: {last}").into());
        }
    }
    if rig.udp {
        warm_udp(rig)?;
    }
    let idle: Vec<Option<Sample>> = pids.iter().map(|(_, pid)| sample(*pid)).collect();
    let window = Duration::from_secs(settings.seconds);
    let mut rss: Vec<Vec<u64>> = vec![Vec::new(); pids.len()];
    let mut threads = vec![0u64; pids.len()];
    let mut fds = vec![0usize; pids.len()];
    let (before, after, started, elapsed, base, end, samples) = thread::scope(|scope| {
        for _ in 0..settings.streams {
            if rig.udp {
                if rig.inject {
                    scope.spawn(|| udp_ingress(rig.front, rig.origin, settings.window, &stop, &counters, study::Pace::new(settings.target_mbps, settings.streams, settings.window * DATAGRAM)));
                } else {
                    scope.spawn(|| udp_plain(rig.front, settings.window, &stop, &counters));
                }
            } else {
                scope.spawn(|| bulk(open.as_ref(), &stop, &counters, settings, settings.target_mbps));
            }
        }
        let probing = (!rig.udp).then(|| scope.spawn(|| probe(open.as_ref(), &stop)));
        thread::sleep(Duration::from_secs(settings.warmup));
        let before: Vec<Option<Sample>> = pids.iter().map(|(_, pid)| sample(*pid)).collect();
        let base = (
            counters.bytes.load(Ordering::Relaxed),
            counters.sent.load(Ordering::Relaxed),
            counters.received.load(Ordering::Relaxed),
        );
        let started = Instant::now();
        while started.elapsed() < window {
            thread::sleep(Duration::from_millis(200));
            for (index, (_, pid)) in pids.iter().enumerate() {
                if let Some(now) = sample(*pid) {
                    rss[index].push(now.rss_kb);
                    threads[index] = threads[index].max(now.threads);
                    fds[index] = fds[index].max(now.fds);
                }
            }
        }
        let elapsed = started.elapsed();
        let after: Vec<Option<Sample>> = pids.iter().map(|(_, pid)| sample(*pid)).collect();
        let end = (
            counters.bytes.load(Ordering::Relaxed),
            counters.sent.load(Ordering::Relaxed),
            counters.received.load(Ordering::Relaxed),
        );
        let now = Instant::now();
        stop.store(true, Ordering::Relaxed);
        let samples = probing.map(|handle| handle.join().unwrap_or_default()).unwrap_or_default();
        (before, after, started, elapsed, base, end, (samples, now))
    });
    let seconds = elapsed.as_secs_f64();
    let (samples, _) = samples;
    let mut latency: Vec<u64> = samples
        .iter()
        .filter(|(finished, _)| *finished >= started && *finished <= started + elapsed)
        .map(|(_, micros)| *micros)
        .collect();
    latency.sort_unstable();
    let bytes = end.0 - base.0;
    let sent = end.1 - base.1;
    let received = end.2 - base.2;
    let errors = counters.errors.load(Ordering::Relaxed);
    let roles: Vec<Value> = pids
        .iter()
        .enumerate()
        .map(|(index, (name, _))| role(name, idle[index], before[index], after[index], &rss[index], threads[index], fds[index], seconds))
        .collect();
    let mut result = json!({
        "seconds": seconds,
        "verified_bytes": if rig.udp { received * DATAGRAM as u64 } else { bytes },
        "received_datagrams": received, "sent_datagrams": sent,
        "rss_samples_kib": rss,
        "errors": errors,
        "error_notes": counters.notes.lock().map(|notes| notes.clone()).unwrap_or_default(),
        "server": roles[0],
        "client": roles[1],
    });
    if rig.udp {
        result["kind"] = "udp".into();
        result["datagrams_per_second"] = (received as f64 / seconds).into();
        result["mbps"] = (received as f64 * DATAGRAM as f64 * 8.0 / seconds / 1e6).into();
        result["loss_percent"] = (sent.saturating_sub(received) as f64 / sent.max(1) as f64 * 100.0).into();
    } else {
        result["kind"] = "tcp".into();
        result["tcp_flight_blocks"] = settings.tcp_flight_blocks.into();
        result["mbps"] = (bytes as f64 * 8.0 / seconds / 1e6).into();
        result["blocks_per_second"] = (bytes as f64 / BLOCK as f64 / seconds).into();
        result["probe_p50_us"] = percentile(&latency, 0.5).into();
        result["probe_p99_us"] = percentile(&latency, 0.99).into();
        result["probe_samples"] = latency.len().into();
        let gib = bytes as f64 / (1u64 << 30) as f64;
        for side in ["server", "client"] {
            if let (Some(cpu), true) = (result[side]["cpu_seconds"].as_f64(), gib > 0.0) {
                result[side]["cpu_seconds_per_gib"] = (cpu / gib).into();
            }
        }
    }
    Ok(result)
}

fn xray_ingress_client(case: &Case, keys: &Keys, front: u16, peer: u16, origin: u16) -> Value {
    let mut config = case.xray_client(keys, front, peer, origin);
    config["inbounds"] = json!([{
        "protocol": "vless", "listen": "127.0.0.1", "port": front,
        "settings": {"decryption": "none", "users": [{"id": INGRESS_TEXT}]},
    }]);
    config
}

fn kerlico_ingress_client(case: &Case, keys: &Keys, front: u16, peer: u16) -> Value {
    let mut config = case.kerlico_landing(keys, front, peer);
    config["inbounds"][0]["rules"] = json!([{"geoip": ["private"], "outbound": "landing"}]);
    config
}

fn measure(xray: &Path, kerlico: &Path, dir: &Path, case: &Case, direction: Direction, settings: &Settings) -> Result<Value> {
    let mut keys = Keys::generate(dir, case)?;
    let bind = if study::veth() { std::net::SocketAddrV4::new(study::SERVER, 0) } else { localhost(0) };
    let storage = case.mock.map(|service| xdrive_mock::Mock::start_on(bind, service, case.security, &keys.cert_pem, &keys.key_pem)).transpose()?;
    keys.mock_addr = storage.as_ref().map(|storage| storage.addr);
    let decoy = if matches!(case.security, Security::Reality) {
        let config = kerlico_vless::server_config(&keys.cert_pem, &keys.key_pem, &["h2".into(), "http/1.1".into()]).map_err(|_| "make REALITY TLS target")?;
        let echo = Echo::tcp(Some(config))?;
        keys.decoy = echo.port;
        Some(echo)
    } else {
        None
    };
    enum Origins {
        Udp(Echo),
        Tcp(Origin),
    }
    impl Origins {
        fn port(&self) -> u16 {
            match self {
                Self::Udp(echo) => echo.port,
                Self::Tcp(origin) => origin.port,
            }
        }
    }
    let origin = if case.payload.udp() {
        Origins::Udp(Echo::udp(case.payload.origin_port())?)
    } else {
        let tls = (case.payload == Payload::InnerTls)
            .then(|| kerlico_vless::server_config(&keys.cert_pem, &keys.key_pem, &[]).map_err(|_| "make inner TLS echo origin"))
            .transpose()?;
        Origins::Tcp(Origin::tcp(tls)?)
    };
    let peer = available_port()?;
    if case.separate_download() { keys.download = peer; }
    let mut front = available_port()?;
    while front == peer || front == origin.port() || decoy.as_ref().is_some_and(|target| front == target.port) {
        front = available_port()?;
    }
    let server_cpus = &settings.server_cpus;
    let client_cpus = &settings.client_cpus;
    let cone = case.cone;
    let (server, client) = match direction {
        Direction::XrayToKerlico => (
            start_kerlico(kerlico, server_cpus, dir, "kerlico-server", &case.kerlico_server(&keys, peer))?,
            start_xray(xray, client_cpus, dir, "xray-client", &xray_ingress_client(case, &keys, front, peer, origin.port()), cone)?,
        ),
        Direction::KerlicoToXray => (
            start_xray(xray, server_cpus, dir, "xray-server", &case.xray_server(&keys, peer, origin.port()), cone)?,
            start_kerlico(kerlico, client_cpus, dir, "kerlico-client", &kerlico_ingress_client(case, &keys, front, peer))?,
        ),
        Direction::KerlicoControl => (
            start_kerlico(kerlico, server_cpus, dir, "kerlico-server", &case.kerlico_server(&keys, peer))?,
            start_kerlico(kerlico, client_cpus, dir, "kerlico-client", &kerlico_ingress_client(case, &keys, front, peer))?,
        ),
        Direction::XrayControl => (
            start_xray(xray, server_cpus, dir, "xray-server", &case.xray_server(&keys, peer, origin.port()), cone)?,
            start_xray(xray, client_cpus, dir, "xray-client", &xray_ingress_client(case, &keys, front, peer, origin.port()), cone)?,
        ),
    };
    let (server_name, client_name) = direction.implementations();
    let rig = Rig {
        front,
        origin: origin.port(),
        inject: true,
        udp: case.payload.udp(),
        inner_tls: case.payload == Payload::InnerTls,
    };
    let result = load(&rig, settings, &[(server_name, server.id()), (client_name, client.id())]);
    drop((server, client));
    if result.is_ok() { if let Some(mock) = storage { mock.verify(false)?; } }
    result
}

#[test]
#[ignore = "requires XRAY pointing to Xray 26.10.31 and a release build"]
fn vless_perf() {
    if let Ok(value) = std::env::var("PERF_TLS_TARGET") {
        study::tls_target(value.parse().expect("TLS target port")).expect("local TLS target");
        return;
    }
    if let Some(path) = std::env::var_os("PERF_CATALOG") {
        let catalog: Vec<Value> = cases::cases().into_iter().chain(cases::rejected_cases()).map(|case|
            json!({"case":case.name,"allowed":!case.rejected,"udp":case.payload.udp(),
                   "origin_port":case.payload.origin_port(),"inner_tls":case.payload==Payload::InnerTls,
                   "mock":case.mock.is_some(),"reconnect":case.resume,"separate_download":case.separate_download(),
                   "legacy_benchmark":measurable(&case)})).collect();
        fs::write(path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();
        return;
    }
    let xray = xray_binary().expect("pinned Xray peer");
    let kerlico = PathBuf::from(text("PERF_KERLICO", env!("CARGO_BIN_EXE_kerlico-server")));
    let settings = Settings {
        seconds: number("PERF_SECONDS", 20),
        target_mbps: number("PERF_TARGET_MBPS", 0),
        warmup: number("PERF_WARMUP", 3),
        streams: number("PERF_STREAMS", 4) as usize,
        tcp_flight_blocks: number("PERF_TCP_FLIGHT_BLOCKS", 1) as usize,
        window: number("PERF_WINDOW", 16) as usize,
        server_cpus: text("PERF_SERVER_CPUS", "0-2"),
        client_cpus: text("PERF_CLIENT_CPUS", "3-5"),
        worker: text("PERF_WORKER", "worker"),
    };
    assert!((1..=32).contains(&settings.tcp_flight_blocks));
    pin_self(&text("PERF_LOAD_CPUS", "6-7"));
    let filter = text("PERF_CASE", "");
    let directions = text("PERF_DIRECTION", "");
    let rounds = number("PERF_ROUNDS", 1) as usize;
    let (shard, shards) = text("PERF_SHARD", "0/1")
        .split_once('/')
        .and_then(|(index, count)| Some((index.parse::<usize>().ok()?, count.parse::<usize>().ok()?)))
        .filter(|(index, count)| *count > 0 && index < count)
        .unwrap_or((0, 1));
    let output = std::env::var_os("PERF_OUT").map(PathBuf::from);
    let root = run_dir("perf").expect("perf directory");
    let record = |line: Value| {
        eprintln!("PERF {line}");
        if let Some(path) = &output {
            let mut file = OpenOptions::new().create(true).append(true).open(path).expect("PERF_OUT");
            writeln!(file, "{line}").expect("PERF_OUT");
        }
    };
    // The tunnel is never faster than the load generator and the echo origin on their own cores.
    for (kind, udp) in [("tcp", false), ("udp", true)] {
        let udp_echo = udp.then(|| Echo::udp(0).expect("direct UDP origin"));
        let tcp_echo = (!udp).then(|| Origin::tcp(None).expect("direct TCP origin"));
        let port = udp_echo.as_ref().map_or_else(|| tcp_echo.as_ref().map_or(0, |origin| origin.port), |echo| echo.port);
        let stop = AtomicBool::new(false);
        let counters = Counters::default();
        let open: Box<dyn Fn() -> Result<Box<dyn Duplex>> + Sync> = {
            Box::new(move || Ok(Box::new(tcp_connect(port)?) as Box<dyn Duplex>))
        };
        let started = Instant::now();
        thread::scope(|scope| {
            for _ in 0..settings.streams {
                if udp {
                    scope.spawn(|| udp_plain(port, settings.window, &stop, &counters));
                } else {
                    scope.spawn(|| bulk(open.as_ref(), &stop, &counters, &settings, 0));
                }
            }
            thread::sleep(Duration::from_secs(5));
            stop.store(true, Ordering::Relaxed);
        });
        let seconds = started.elapsed().as_secs_f64();
        let value = if udp {
            counters.received.load(Ordering::Relaxed) as f64 * DATAGRAM as f64 * 8.0 / seconds / 1e6
        } else {
            counters.bytes.load(Ordering::Relaxed) as f64 * 8.0 / seconds / 1e6
        };
        record(json!({"case": "direct", "kind": kind, "worker": settings.worker, "mbps": value}));
    }
    let mut measured = 0;
    let pairings: &[Direction] = if std::env::var("PERF_BOTH_ENDS").as_deref() == Ok("1") {
        &Direction::BOTH_ENDS
    } else {
        &Direction::ALL
    };
    for (index, case) in cases::cases().into_iter().enumerate() {
        let eligible = if study::veth() { !case.rejected } else { measurable(&case) };
        if !eligible || !selected(&filter, &case.name) || index % shards != shard {
            continue;
        }
        for round in 0..rounds {
            for step in 0..pairings.len() {
                let direction = pairings[(step + round) % pairings.len()];
                if !selected(&directions, direction.name()) {
                    continue;
                }
                let dir = root.join(&case.name).join(format!("{}-{round}", direction.name()));
                let result = fs::create_dir_all(&dir)
                    .map_err(Into::into)
                    .and_then(|()| measure(&xray, &kerlico, &dir, &case, direction, &settings));
                let mut line = match result {
                    Ok(value) => value,
                    Err(error) => json!({"error": error.to_string()}),
                };
                line["target_mbps"] = settings.target_mbps.into();
                line["topology"] = (if study::veth() { "isolated-veth" } else { "loopback" }).into();
                line["case"] = case.name.clone().into();
                line["direction"] = direction.name().into();
                line["round"] = round.into();
                line["worker"] = settings.worker.clone().into();
                record(line);
                measured += 1;
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
    assert!(measured > 0, "no case matched PERF_CASE");
}
