#![cfg(feature = "anytls")]

//! Load comparison of Kerlico and mihomo 1.19.33 AnyTLS over loopback. Ignored by default.
//!
//! ```text
//! MIHOMO=/path/mihomo KERLICO_SERVER=/path/kerlico-server KERLICO_CLIENT=/path/kerlico-client \
//! PERF_OUT=/path/results.jsonl cargo test --release -p kerlico-server --no-default-features \
//!     --features anytls --test anytls_perf -- --ignored --nocapture
//! ```
//!
//! Four pairs, each a separate window: mihomo client and server, Kerlico client and server, and the
//! two mixed pairs, so each side of Kerlico is also measured against mihomo's other side. Each
//! client exposes its local SOCKS5 port. `PERF_STREAMS` persistent streams write a 32 KiB block and
//! read it back from an echo origin; one probe stream exchanges 64 bytes every 10 ms. Payload bytes
//! count both directions (written plus read back). CPU is utime + stime from `/proc` over the
//! window. The tunnel's server and client are pinned to their own cores with `taskset`, the load
//! generator and the origin share the rest.
//!
//! Environment: `PERF_SECONDS` (30), `PERF_WARMUP` (3), `PERF_STREAMS` (4), `PERF_PAIRS` (comma
//! separated pair names), `PERF_SERVER_CPUS` (0), `PERF_CLIENT_CPUS` (1), `PERF_LOAD_CPUS` (2-3).

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const BLOCK: usize = 32 * 1024;
const PASSWORD: &str = "perf-secret";
const CLOCK_TICKS: f64 = 100.0;

fn env_number(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}

fn env_text(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

fn binary(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set: not run")))
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
    let dir = std::env::temp_dir().join(format!("kerlico-anytls-perf-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(cpus: &str, program: &PathBuf, args: &[&str], dir: &PathBuf) -> Process {
    let log = std::fs::File::create(dir.join("process.log")).unwrap();
    let child = Command::new("taskset")
        .arg("-c")
        .arg(cpus)
        .arg(program)
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    Process(child)
}

fn certificate() -> (String, String) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (key.cert.pem(), key.key_pair.serialize_pem())
}

fn start_server(kind: &str, cpus: &str, port: u16) -> Process {
    let dir = workdir(&format!("{kind}-server"));
    let (cert, key) = certificate();
    let process = match kind {
        "kerlico" => {
            let config = json!({
                "inbounds": [{
                    "tag": "any", "protocol": "anytls", "listen": "127.0.0.1", "port": port, "outbound": "native-v4",
                    "settings": { "certificate": cert, "private-key": key, "users": [{ "email": "perf@test", "password": PASSWORD }] }
                }]
            });
            std::fs::write(dir.join("server.json"), config.to_string()).unwrap();
            let path = dir.join("server.json");
            spawn(cpus, &binary("KERLICO_SERVER"), &[path.to_str().unwrap()], &dir)
        }
        _ => {
            std::fs::write(dir.join("cert.pem"), cert).unwrap();
            std::fs::write(dir.join("key.pem"), key).unwrap();
            let yaml = format!(
                "log-level: warning\nallow-lan: false\nmode: rule\nlisteners:\n  - name: any-in\n    type: anytls\n    listen: 127.0.0.1\n    port: {port}\n    users:\n      perf: {PASSWORD}\n    certificate: cert.pem\n    private-key: key.pem\nrules:\n  - MATCH,DIRECT\n"
            );
            std::fs::write(dir.join("config.yaml"), yaml).unwrap();
            let home = dir.to_str().unwrap().to_string();
            spawn(cpus, &binary("MIHOMO"), &["-d", &home, "-f", "config.yaml"], &dir)
        }
    };
    wait_port(port);
    process
}

fn start_client(kind: &str, cpus: &str, server: u16, socks: u16) -> Process {
    let dir = workdir(&format!("{kind}-client"));
    let process = match kind {
        "kerlico" => {
            let config = json!({
                "protocol": "anytls",
                "peer": format!("127.0.0.1:{server}"),
                "settings": {
                    "password": PASSWORD, "sni": "localhost", "skip-cert-verify": true,
                    "socks5Port": socks, "httpProxyPort": free_port()
                }
            });
            std::fs::write(dir.join("client.json"), config.to_string()).unwrap();
            let path = dir.join("client.json");
            spawn(cpus, &binary("KERLICO_CLIENT"), &[path.to_str().unwrap()], &dir)
        }
        _ => {
            let yaml = format!(
                "log-level: warning\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nmixed-port: {socks}\nproxies:\n  - name: any\n    type: anytls\n    server: 127.0.0.1\n    port: {server}\n    password: {PASSWORD}\n    sni: localhost\n    skip-cert-verify: true\nrules:\n  - MATCH,any\n"
            );
            std::fs::write(dir.join("config.yaml"), yaml).unwrap();
            let home = dir.to_str().unwrap().to_string();
            spawn(cpus, &binary("MIHOMO"), &["-d", &home, "-f", "config.yaml"], &dir)
        }
    };
    wait_port(socks);
    process
}

fn origin(cpus: &str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cpus = cpus.to_string();
    thread::spawn(move || {
        pin_thread(&cpus);
        for tcp in listener.incoming().flatten() {
            let _ = tcp.set_nodelay(true);
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
    addr
}

fn pin_thread(cpus: &str) {
    let _ = Command::new("taskset").args(["-a", "-c", "-p", cpus, &std::process::id().to_string()]).status();
}

fn socks_connect(proxy: u16, target: SocketAddr) -> TcpStream {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    tcp.set_nodelay(true).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    tcp.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply).unwrap();
    let SocketAddr::V4(v4) = target else { panic!("v4") };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    tcp.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0);
    tcp
}

fn roundtrip(proxy: u16, target: SocketAddr) -> bool {
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
        Ok(reply[1] == 0)
    };
    attempt().unwrap_or(false)
}

fn cpu_seconds(pid: u32) -> f64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<&str> = stat.rsplit_once(')').unwrap().1.split_whitespace().collect();
    let utime: f64 = fields[11].parse().unwrap();
    let stime: f64 = fields[12].parse().unwrap();
    (utime + stime) / CLOCK_TICKS
}

/// The tunnel process's pid: `taskset` execs the program, so the child pid is the program's.
fn pid(process: &Process) -> u32 {
    process.0.id()
}

fn percentile(sorted: &[u64], fraction: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * fraction).round() as usize]
}

fn measure(server_kind: &str, client_kind: &str) -> Value {
    let seconds = env_number("PERF_SECONDS", 30);
    let warmup = env_number("PERF_WARMUP", 3);
    let streams = env_number("PERF_STREAMS", 4) as usize;
    let load_cpus = env_text("PERF_LOAD_CPUS", "2-3");
    let target = origin(&load_cpus);
    let server_port = free_port();
    let server = start_server(server_kind, &env_text("PERF_SERVER_CPUS", "0"), server_port);
    let socks = free_port();
    let client = start_client(client_kind, &env_text("PERF_CLIENT_CPUS", "1"), server_port, socks);
    // mihomo listens before its tunnel runs and closes streams that arrive in between.
    let started = Instant::now();
    while !roundtrip(socks, target) {
        assert!(started.elapsed() < Duration::from_secs(15), "the tunnel never passed a stream");
        thread::sleep(Duration::from_millis(100));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let counting = Arc::new(AtomicBool::new(false));
    let bytes = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    // `PERF_MODE=trickle`: every stream sends 64 bytes and reads them back every
    // `PERF_INTERVAL_MS` (100), to see what many quiet sessions cost.
    let trickle = env_text("PERF_MODE", "bulk") == "trickle";
    let interval = Duration::from_millis(env_number("PERF_INTERVAL_MS", 100));
    for seed in 0..streams {
        let (stop, counting, bytes) = (Arc::clone(&stop), Arc::clone(&counting), Arc::clone(&bytes));
        let mut tcp = socks_connect(socks, target);
        if trickle {
            workers.push(thread::spawn(move || {
                thread::sleep(interval * seed as u32 / streams.max(1) as u32);
                let mut back = [0u8; 64];
                while !stop.load(Ordering::Acquire) {
                    tcp.write_all(&[seed as u8; 64]).unwrap();
                    tcp.read_exact(&mut back).unwrap();
                    if counting.load(Ordering::Acquire) {
                        bytes.fetch_add(128, Ordering::Relaxed);
                    }
                    thread::sleep(interval);
                }
            }));
            continue;
        }
        workers.push(thread::spawn(move || {
            let block: Vec<u8> = (0..BLOCK).map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed as u8)).collect();
            let mut back = vec![0u8; BLOCK];
            while !stop.load(Ordering::Acquire) {
                tcp.write_all(&block).unwrap();
                tcp.read_exact(&mut back).unwrap();
                assert!(back == block, "payload changed");
                if counting.load(Ordering::Acquire) {
                    bytes.fetch_add(2 * BLOCK as u64, Ordering::Relaxed);
                }
            }
        }));
    }
    let latencies = Arc::new(Mutex::new(Vec::new()));
    {
        let (stop, counting, latencies) = (Arc::clone(&stop), Arc::clone(&counting), Arc::clone(&latencies));
        let mut tcp = socks_connect(socks, target);
        workers.push(thread::spawn(move || {
            let probe = [7u8; 64];
            let mut back = [0u8; 64];
            while !stop.load(Ordering::Acquire) {
                let started = Instant::now();
                tcp.write_all(&probe).unwrap();
                tcp.read_exact(&mut back).unwrap();
                if counting.load(Ordering::Acquire) {
                    latencies.lock().unwrap().push(started.elapsed().as_micros() as u64);
                }
                thread::sleep(Duration::from_millis(10));
            }
        }));
    }
    pin_thread(&load_cpus);
    thread::sleep(Duration::from_secs(warmup));
    let (server_before, client_before) = (cpu_seconds(pid(&server)), cpu_seconds(pid(&client)));
    let started = Instant::now();
    counting.store(true, Ordering::Release);
    // `PERF_RECORD_DIR`: profile both tunnel processes over the window (`perf record` without call
    // graphs, and the counts of the main syscalls). A profiled window is not a measurement.
    let recorders: Vec<Child> = match std::env::var("PERF_RECORD_DIR") {
        Err(_) => Vec::new(),
        Ok(dir) => {
            let mut children = Vec::new();
            for (side, process) in [("server", &server), ("client", &client)] {
                let name = format!("{dir}/{client_kind}-to-{server_kind}-{side}");
                let pid = pid(process).to_string();
                let window = seconds.to_string();
                children.push(
                    Command::new("perf")
                        .args(["record", "-F", "1999", "-o", &format!("{name}.data"), "-p", &pid, "--", "sleep", &window])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                );
                let events = "syscalls:sys_enter_read,syscalls:sys_enter_write,syscalls:sys_enter_futex,syscalls:sys_enter_recvfrom,syscalls:sys_enter_sendto,syscalls:sys_enter_writev,context-switches";
                children.push(
                    Command::new("perf")
                        .args(["stat", "-e", events, "-o", &format!("{name}.stat"), "-p", &pid, "--", "sleep", &window])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                );
            }
            children
        }
    };
    thread::sleep(Duration::from_secs(seconds));
    counting.store(false, Ordering::Release);
    let elapsed = started.elapsed().as_secs_f64();
    let (server_after, client_after) = (cpu_seconds(pid(&server)), cpu_seconds(pid(&client)));
    for mut recorder in recorders {
        let _ = recorder.wait();
    }
    stop.store(true, Ordering::Release);
    for worker in workers {
        worker.join().unwrap();
    }
    let total = bytes.load(Ordering::Relaxed) as f64;
    let gib = total / f64::from(1u32 << 30);
    let mut latencies = latencies.lock().unwrap().clone();
    latencies.sort_unstable();
    let side = |cpu: f64| json!({ "cpu_seconds": cpu, "cpu_percent": cpu / elapsed * 100.0, "cpu_seconds_per_gib": cpu / gib });
    json!({
        "pair": format!("{client_kind}-client-to-{server_kind}-server"),
        "seconds": elapsed,
        "streams": streams,
        "mode": env_text("PERF_MODE", "bulk"),
        "payload_gib": gib,
        "throughput_mib_s": total / elapsed / f64::from(1u32 << 20),
        "server": side(server_after - server_before),
        "client": side(client_after - client_before),
        "probe_p50_us": percentile(&latencies, 0.5),
        "probe_p99_us": percentile(&latencies, 0.99),
        "probe_samples": latencies.len(),
        "worker": env_text("PERF_WORKER", "perf-02"),
    })
}

#[test]
#[ignore]
fn anytls_perf() {
    let pairs = env_text("PERF_PAIRS", "mihomo-mihomo,kerlico-kerlico,mihomo-kerlico,kerlico-mihomo");
    let out = std::env::var("PERF_OUT").ok();
    for pair in pairs.split(',').map(str::trim).filter(|pair| !pair.is_empty()) {
        // Written as client-server.
        let (client, server) = pair.split_once('-').expect("pair is client-server");
        let result = measure(server, client);
        println!("{result}");
        if let Some(out) = &out {
            let mut file = OpenOptions::new().create(true).append(true).open(out).unwrap();
            writeln!(file, "{result}").unwrap();
        }
    }
}
