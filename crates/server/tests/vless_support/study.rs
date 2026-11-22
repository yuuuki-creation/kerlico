//! Helpers specific to the rate-controlled local veth benchmark.
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use serde_json::{json, Value};

pub(super) const SERVER: Ipv4Addr = Ipv4Addr::new(10, 51, 0, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 51, 0, 2);
const DOWNLOAD: &str = "10.51.0.3";

/// Match the concurrent rustls target used by the existing AnyTLS interoperability tests.
pub(super) fn tls_target(port: u16) -> super::Result<()> {
    use std::{fs, io::Read, net::TcpListener, sync::Arc, thread};
    let version = std::env::var("PERF_TARGET_TLS_VERSION")?;
    let tls = if version == "tls12" { "1.2" } else { "1.3" };
    let cert = fs::read_to_string(std::env::var_os("PERF_TARGET_CERT").ok_or("missing certificate")?)?;
    let key = fs::read_to_string(std::env::var_os("PERF_TARGET_KEY").ok_or("missing key")?)?;
    let mut config = kerlico_vless::server_config_versions(&cert, &key, &["http/1.1".into()], tls, tls)
        .map_err(|_| "invalid target TLS configuration")?;
    if version == "tls13-no-tickets" {
        Arc::get_mut(&mut config).ok_or("shared initial TLS configuration")?.send_tls13_tickets = 0;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    println!("listening");
    for stream in listener.incoming() {
        let stream = stream?;
        let config = Arc::clone(&config);
        thread::spawn(move || {
            if let Ok(mut session) = kerlico_vless::accept_tls(stream, config) {
                let _ = session.read(&mut [0; 1024]);
            }
        });
    }
    Ok(())
}

pub(super) fn veth() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("PERF_VETH").as_deref() == Ok("1"))
}

pub(super) fn connect_front(port: u16) -> std::io::Result<TcpStream> {
    if !veth() {
        return super::support::tcp_connect(port);
    }
    let timeout = super::support::TIMEOUT;
    let stream = TcpStream::connect_timeout(&SocketAddrV4::new(CLIENT, port).into(), timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

pub(super) fn command(cpus: &str, program: &Path, client: bool) -> Command {
    let mut command = if client && veth() {
        let mut netns = Command::new("ip");
        netns.args(["netns", "exec", "socks-end", "taskset"]);
        netns
    } else {
        Command::new("taskset")
    };
    command.args(["-c", cpus]).arg(program);
    command
}

pub(super) fn config(input: &Value, client: bool) -> Value {
    let mut config = input.clone();
    if !veth() {
        return config;
    }
    // The second address on the same server interface is used by XHTTP's separate download.
    config["inbounds"][0]["listen"] = json!(if client { CLIENT } else { Ipv4Addr::UNSPECIFIED });
    if client {
        let landing = config.get("landing").is_some();
        let settings = if config.get("landing").is_some() {
            config["landing"]["address"] = json!(SERVER);
            &mut config["landing"]["settings"]
        } else {
            config["outbounds"][0]["settings"]["address"] = json!(SERVER);
            &mut config["outbounds"][0]["streamSettings"]
        };
        let path = if landing { "/extra/downloadSettings" } else { "/xhttpSettings/extra/downloadSettings" };
        if let Some(download) = settings.pointer_mut(path) {
            download["address"] = json!(DOWNLOAD);
        }
    }
    config
}

pub(super) struct Pace {
    next: Instant,
    interval: Duration,
}

impl Pace {
    pub(super) fn new(mbps: u64, streams: usize, bytes: usize) -> Self {
        let interval = if mbps == 0 { Duration::ZERO } else {
            Duration::from_secs_f64((bytes * streams) as f64 * 8.0 / (mbps as f64 * 1e6))
        };
        Self { next: Instant::now(), interval }
    }

    pub(super) fn wait(&mut self) {
        if self.interval.is_zero() {
            return;
        }
        let now = Instant::now();
        if self.next > now {
            std::thread::sleep(self.next - now);
        }
        // Limit catch-up to one interval after a stall.
        self.next = (self.next + self.interval).max(now);
    }
}
