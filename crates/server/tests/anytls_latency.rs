#![cfg(all(feature = "anytls", feature = "landing-anytls"))]

//! Latency of short connections on reused AnyTLS sessions. Ignored by default.
//!
//! ```text
//! MIHOMO=/path/mihomo KERLICO_SERVER=/path/kerlico-server LAT_OUT=/path/lat.jsonl LAT_LABEL=final \
//! cargo test --release -p kerlico-server --no-default-features --features anytls,landing-anytls \
//!     --test anytls_latency -- --ignored --nocapture
//! ```
//!
//! The Kerlico server runs as its own process behind a relay that counts TCP connections, so the
//! results show whether the client really reused its session. Three cases:
//! - mihomo's client (local SOCKS5 port): each round connects, sends 64 bytes, reads the echo and
//!   closes; the next round starts a fixed gap after the close.
//! - Kerlico's client library, the same rounds with `open_stream` and `close`.
//! - one session from the Kerlico session API: a stream does ping-pong with 3 ms pauses while a
//!   second stream is opened every 50 ms; the result is that stream's open-to-first-echo.
//!
//! Environment: `LAT_ROUNDS` (100 per gap), `LAT_GAPS` (comma separated milliseconds,
//! `0,5,20,50,150,400`), `LAT_SERVER_CPUS` (0-2), `LAT_CLIENT_CPUS` (3-5), `LAT_LOAD_CPUS` (6-7).

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use kerlico_anytls::{password_hash, tls, Family, Scheme, SchemeCell, Session, Target};
use kerlico_shared::Settings;
use serde_json::{json, Value};

const PASSWORD: &str = "latency-secret";

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
    let dir = std::env::temp_dir().join(format!("kerlico-anytls-lat-{}-{name}", std::process::id()));
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
    Process(
        Command::new("taskset")
            .arg("-c")
            .arg(cpus)
            .arg(program)
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    )
}

fn kerlico_server(cpus: &str, port: u16) -> Process {
    let dir = workdir("server");
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = json!({
        "inbounds": [{
            "tag": "any", "protocol": "anytls", "listen": "127.0.0.1", "port": port, "outbound": "native-v4",
            "settings": { "certificate": key.cert.pem(), "private-key": key.key_pair.serialize_pem(),
                          "users": [{ "email": "lat@test", "password": PASSWORD }] }
        }]
    });
    std::fs::write(dir.join("server.json"), config.to_string()).unwrap();
    let path = dir.join("server.json");
    let process = spawn(cpus, &binary("KERLICO_SERVER"), &[path.to_str().unwrap()], &dir);
    wait_port(port);
    process
}

fn mihomo_client(cpus: &str, server: u16, mixed: u16) -> Process {
    let dir = workdir("mihomo-client");
    let yaml = format!(
        "log-level: warning\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nmixed-port: {mixed}\nproxies:\n  - name: any\n    type: anytls\n    server: 127.0.0.1\n    port: {server}\n    password: {PASSWORD}\n    sni: localhost\n    skip-cert-verify: true\nrules:\n  - MATCH,any\n"
    );
    std::fs::write(dir.join("config.yaml"), yaml).unwrap();
    let home = dir.to_str().unwrap().to_string();
    let process = spawn(cpus, &binary("MIHOMO"), &["-d", &home, "-f", "config.yaml"], &dir);
    wait_port(mixed);
    process
}

fn pin_self(cpus: &str) {
    let _ = Command::new("taskset").args(["-a", "-c", "-p", cpus, &std::process::id().to_string()]).status();
}

/// A relay in front of `target` that counts the connections it carried.
fn relay(target: u16) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(server) = TcpStream::connect(("127.0.0.1", target)) else { continue };
            seen.fetch_add(1, Ordering::Relaxed);
            let _ = client.set_nodelay(true);
            let _ = server.set_nodelay(true);
            for (mut from, mut to) in [(client.try_clone().unwrap(), server.try_clone().unwrap()), (server, client)] {
                thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = from.read(&mut buf) {
                        if n == 0 || to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = to.shutdown(Shutdown::Both);
                });
            }
        }
    });
    (port, count)
}

fn echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let _ = tcp.set_nodelay(true);
            thread::spawn(move || {
                let mut tcp = tcp;
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = tcp.read(&mut buf) {
                    if n == 0 || tcp.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// One SOCKS5 round: connect, CONNECT, 64 bytes out, 64 back, close. `None` if anything failed.
fn socks_round(proxy: u16, target: SocketAddr) -> Option<Duration> {
    let started = Instant::now();
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).ok()?;
    tcp.set_nodelay(true).ok()?;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    tcp.write_all(&[5, 1, 0]).ok()?;
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply).ok()?;
    let SocketAddr::V4(v4) = target else { return None };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    tcp.write_all(&request).ok()?;
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).ok()?;
    tcp.write_all(&[7u8; 64]).ok()?;
    let mut back = [0u8; 64];
    tcp.read_exact(&mut back).ok()?;
    let took = started.elapsed();
    drop(tcp);
    Some(took)
}

fn percentiles(mut samples: Vec<Duration>) -> Value {
    samples.sort();
    let at = |fraction: f64| -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        samples[((samples.len() - 1) as f64 * fraction).round() as usize].as_secs_f64() * 1e6
    };
    json!({ "n": samples.len(), "p50_us": at(0.5), "p90_us": at(0.9), "p99_us": at(0.99), "max_us": at(1.0) })
}

fn gaps() -> Vec<u64> {
    env_text("LAT_GAPS", "0,5,20,50,150,400").split(',').filter_map(|gap| gap.trim().parse().ok()).collect()
}

fn rounds() -> usize {
    env_text("LAT_ROUNDS", "100").parse().unwrap()
}

fn emit(result: Value) {
    println!("{result}");
    if let Ok(path) = std::env::var("LAT_OUT") {
        let mut file = OpenOptions::new().create(true).append(true).open(path).unwrap();
        writeln!(file, "{result}").unwrap();
    }
}

fn kerlico_client(port: u16) -> landing_anytls::Client {
    let mut settings = Settings::default();
    settings.insert_text("password", PASSWORD);
    settings.insert_text("sni", "localhost");
    settings.insert_text("skip-cert-verify", "true");
    landing_anytls::Client::new("127.0.0.1", port, &settings).unwrap()
}

#[test]
#[ignore]
fn anytls_reuse_latency() {
    let label = env_text("LAT_LABEL", "current");
    let load_cpus = env_text("LAT_LOAD_CPUS", "6-7");
    let target = echo();
    let server_port = free_port();
    let _server = kerlico_server(&env_text("LAT_SERVER_CPUS", "0-2"), server_port);
    pin_self(&load_cpus);

    // mihomo's client through its local SOCKS5 port.
    {
        let (front, count) = relay(server_port);
        let mixed = free_port();
        let _client = mihomo_client(&env_text("LAT_CLIENT_CPUS", "3-5"), front, mixed);
        let started = Instant::now();
        while socks_round(mixed, target).is_none() {
            assert!(started.elapsed() < Duration::from_secs(15), "mihomo client never passed a stream");
            thread::sleep(Duration::from_millis(100));
        }
        for gap in gaps() {
            let before = count.load(Ordering::Relaxed);
            let mut samples = Vec::new();
            let mut failed = 0;
            for _ in 0..rounds() {
                match socks_round(mixed, target) {
                    Some(took) => samples.push(took),
                    None => failed += 1,
                }
                thread::sleep(Duration::from_millis(gap));
            }
            let mut result = percentiles(samples);
            result["case"] = "mihomo-client".into();
            result["label"] = label.clone().into();
            result["gap_ms"] = gap.into();
            result["failed"] = failed.into();
            result["new_connections"] = (count.load(Ordering::Relaxed) - before).into();
            emit(result);
        }
    }

    // Kerlico's client library.
    {
        let (front, count) = relay(server_port);
        let client = kerlico_client(front);
        for gap in gaps() {
            let before = count.load(Ordering::Relaxed);
            let mut samples = Vec::new();
            for _ in 0..rounds() {
                let started = Instant::now();
                let stream = client.open_stream(&target.ip().to_string(), target.port()).unwrap();
                stream.write_all(&[7u8; 64]).unwrap();
                let mut back = [0u8; 64];
                let mut have = 0;
                while have < 64 {
                    let n = stream.read_for(&mut back[have..], Duration::from_secs(5)).unwrap();
                    assert!(n > 0);
                    have += n;
                }
                samples.push(started.elapsed());
                stream.close();
                thread::sleep(Duration::from_millis(gap));
            }
            let mut result = percentiles(samples);
            result["case"] = "kerlico-client".into();
            result["label"] = label.clone().into();
            result["gap_ms"] = gap.into();
            result["new_connections"] = (count.load(Ordering::Relaxed) - before).into();
            emit(result);
        }
        client.close();
    }

    // One session: ping-pong with 3 ms pauses, a second stream every 50 ms.
    {
        let (front, count) = relay(server_port);
        let tcp = TcpStream::connect(("127.0.0.1", front)).unwrap();
        tcp.set_nodelay(true).unwrap();
        let config = tls::client_config(&tls::ClientTls { insecure: true, ..Default::default() }).unwrap();
        let link = tls::connect(tcp, config, "localhost").unwrap();
        let session = Session::client(link, SchemeCell::new(Scheme::default_scheme()), "", &password_hash(PASSWORD)).unwrap();
        let open = |session: &Session| {
            let stream = session.open_stream().unwrap();
            let mut addr = Vec::new();
            Target::new(target.ip().to_string(), target.port()).encode(Family::Socks, &mut addr).unwrap();
            stream.write(&addr).unwrap();
            stream
        };
        let read64 = |stream: &kerlico_anytls::Stream| {
            let mut back = [0u8; 64];
            let mut have = 0;
            while have < 64 {
                let n = stream.read_for(&mut back[have..], Duration::from_secs(5)).unwrap();
                assert!(n > 0);
                have += n;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let pinger = {
            let stream = open(&session);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    stream.write(&[1u8; 64]).unwrap();
                    read64(&stream);
                    thread::sleep(Duration::from_millis(3));
                }
            })
        };
        thread::sleep(Duration::from_millis(200));
        let mut samples = Vec::new();
        for _ in 0..rounds() {
            let started = Instant::now();
            let stream = open(&session);
            stream.write(&[2u8; 64]).unwrap();
            read64(&stream);
            samples.push(started.elapsed());
            stream.close();
            thread::sleep(Duration::from_millis(50));
        }
        stop.store(true, Ordering::Release);
        pinger.join().unwrap();
        let mut result = percentiles(samples);
        result["case"] = "second-stream".into();
        result["label"] = label.clone().into();
        result["gap_ms"] = 50.into();
        result["new_connections"] = count.load(Ordering::Relaxed).into();
        emit(result);
        session.close();
    }
}
