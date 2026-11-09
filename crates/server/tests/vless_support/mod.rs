use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

pub const TIMEOUT: Duration = Duration::from_secs(6);
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn localhost(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

pub fn available_port() -> io::Result<u16> {
    for _ in 0..16 {
        let tcp = TcpListener::bind(localhost(0))?;
        let port = tcp.local_addr()?.port();
        if UdpSocket::bind(localhost(port)).is_ok() {
            return Ok(port);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no free TCP/UDP port",
    ))
}

pub fn tcp_connect(port: u16) -> io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&localhost(port).into(), TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

pub fn run_dir(label: &str) -> Result<PathBuf> {
    let root = std::env::var_os("VLESS_RUN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join(format!("vless-{label}-{}-{now}", std::process::id()));
    fs::create_dir(&path)?;
    Ok(path)
}

pub fn write_json(dir: &Path, name: &str, config: &Value) -> Result<PathBuf> {
    let path = dir.join(name);
    fs::write(&path, serde_json::to_vec_pretty(config)?)?;
    Ok(path)
}

pub struct Process {
    name: String,
    log: PathBuf,
    child: Child,
}

impl Process {
    pub fn spawn(mut command: Command, dir: &Path, name: &str) -> Result<Self> {
        let log = dir.join(format!("{name}.log"));
        let output = File::create(&log)?;
        let child = command
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()
            .map_err(|error| format!("start {name}: {error}"))?;
        Ok(Self {
            name: name.into(),
            log,
            child,
        })
    }

    pub fn wait_ready(&mut self, ready: impl Fn() -> bool) -> Result<()> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Err(format!("{} exited before readiness: {status}", self.name).into());
            }
            if ready() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{} readiness timed out", self.name).into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn wait_for_log(&mut self, marker: &str) -> Result<()> {
        let log = self.log.clone();
        self.wait_ready(|| fs::read_to_string(&log).is_ok_and(|output| output.contains(marker)))
    }

    pub fn finish(&mut self) -> Result<ExitStatus> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!("{} did not exit", self.name).into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn output(&self) -> Result<String> {
        Ok(fs::read_to_string(&self.log)?)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn print_logs(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "log") {
            if let Ok(output) = fs::read_to_string(&path) {
                let lines: Vec<_> = output.lines().collect();
                eprintln!(
                    "{}\n{}",
                    path.display(),
                    lines[lines.len().saturating_sub(16)..].join("\n")
                );
            }
        }
    }
}

pub struct Echo {
    pub port: u16,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Echo {
    pub fn tcp(tls: Option<Arc<kerlico_vless::ServerConfig>>) -> Result<Self> {
        let listener = TcpListener::bind(localhost(0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        Ok(Self::start(port, move |stop| {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let tls = tls.clone();
                        thread::spawn(move || {
                            let _ = stream.set_read_timeout(Some(TIMEOUT));
                            let _ = stream.set_write_timeout(Some(TIMEOUT));
                            if let Some(config) = tls {
                                if let Ok(stream) = kerlico_vless::accept_tls(stream, config) {
                                    let _ = echo_stream(stream);
                                }
                            } else {
                                let _ = echo_stream(stream);
                            }
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        }))
    }

    pub fn udp(port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(localhost(port))?;
        let port = socket.local_addr()?.port();
        socket.set_read_timeout(Some(Duration::from_millis(25)))?;
        Ok(Self::start(port, move |stop| {
            let mut bytes = [0; 65536];
            while !stop.load(Ordering::Relaxed) {
                match socket.recv_from(&mut bytes) {
                    Ok((len, peer)) => {
                        let _ = socket.send_to(&bytes[..len], peer);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                        ) => {}
                    Err(_) => break,
                }
            }
        }))
    }

    fn start(port: u16, run: impl FnOnce(Arc<AtomicBool>) + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let running = stop.clone();
        let worker = thread::spawn(move || run(running));
        Self {
            port,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn echo_stream(mut stream: impl Read + Write) -> io::Result<()> {
    let mut bytes = [0; 16384];
    loop {
        let len = stream.read(&mut bytes)?;
        if len == 0 {
            return Ok(());
        }
        stream.write_all(&bytes[..len])?;
        stream.flush()?;
    }
}
