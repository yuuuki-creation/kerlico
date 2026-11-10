use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::Client;
use kerlico_shared::{OpenError, Settings};
use socket2::{Domain, Protocol, Socket, Type};

#[path = "http.rs"]
mod http;
#[path = "socks.rs"]
mod socks;

pub struct Proxy {
    state: Arc<State>,
    client: Client,
    socks: Vec<SocketAddr>,
    http: Vec<SocketAddr>,
    listeners: Mutex<Vec<JoinHandle<()>>>,
    shutdown: Mutex<()>,
}

struct State {
    closed: AtomicBool,
    failed: AtomicBool,
    workers: Mutex<Vec<JoinHandle<()>>>,
    sockets: Mutex<HashMap<u64, TcpStream>>,
    next_id: AtomicU64,
    wait_lock: Mutex<()>,
    wake: Condvar,
}

impl State {
    fn stopped(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    fn stop(&self, failed: bool) {
        let _guard = self.wait_lock.lock().unwrap();
        if failed {
            self.failed.store(true, Ordering::Release);
        }
        self.closed.store(true, Ordering::Release);
        self.wake.notify_all();
    }
}

impl Proxy {
    pub fn start(client: Client, settings: &Settings) -> Result<Self, OpenError> {
        let socks_port = port(settings, "socks5Port", 1080)?;
        let http_port = port(settings, "httpProxyPort", 8080)?;
        if socks_port == http_port {
            return Err(OpenError::Settings);
        }
        let socks_lan = flag(settings, "socks5ListenLAN")?;
        let http_lan = flag(settings, "httpProxyListenLAN")?;
        let socks = bind_all(socks_port, socks_lan)?;
        let http = bind_all(http_port, http_lan)?;
        let socks_addrs = socks
            .iter()
            .map(|l| l.local_addr().map_err(|_| OpenError::Transport))
            .collect::<Result<Vec<_>, _>>()?;
        let http_addrs = http
            .iter()
            .map(|l| l.local_addr().map_err(|_| OpenError::Transport))
            .collect::<Result<Vec<_>, _>>()?;
        let state = Arc::new(State {
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            workers: Mutex::new(Vec::new()),
            sockets: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            wait_lock: Mutex::new(()),
            wake: Condvar::new(),
        });
        let mut listeners = Vec::new();
        for (listener, is_socks) in socks
            .into_iter()
            .map(|x| (x, true))
            .chain(http.into_iter().map(|x| (x, false)))
        {
            let state = state.clone();
            let client = client.clone();
            listeners.push(thread::spawn(move || {
                accept_loop(listener, client, state, is_socks)
            }));
        }
        Ok(Self {
            state,
            client,
            socks: socks_addrs,
            http: http_addrs,
            listeners: Mutex::new(listeners),
            shutdown: Mutex::new(()),
        })
    }
    pub fn socks5_addrs(&self) -> &[SocketAddr] {
        &self.socks
    }
    pub fn http_addrs(&self) -> &[SocketAddr] {
        &self.http
    }
    pub fn wait(&self) -> Result<(), OpenError> {
        let mut lock = self.state.wait_lock.lock().unwrap();
        while !self.state.stopped() {
            lock = self.state.wake.wait(lock).unwrap();
        }
        if self.state.failed.load(Ordering::Acquire) {
            Err(OpenError::Transport)
        } else {
            Ok(())
        }
    }
    pub fn close(&self) {
        let _guard = self.shutdown.lock().unwrap();
        self.state.stop(false);
        for task in self.listeners.lock().unwrap().drain(..) {
            let _ = task.join();
        }
        for stream in self.state.sockets.lock().unwrap().values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.client.close();
        for task in self.state.workers.lock().unwrap().drain(..) {
            let _ = task.join();
        }
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.close();
    }
}

fn port(settings: &Settings, key: &str, default: u16) -> Result<u16, OpenError> {
    match settings.optional_text(key)? {
        Some(s) => s
            .parse::<u16>()
            .ok()
            .filter(|p| *p >= 1025)
            .ok_or(OpenError::Settings),
        None => Ok(default),
    }
}
fn flag(settings: &Settings, key: &str) -> Result<bool, OpenError> {
    match settings.optional_text(key)? {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        _ => Err(OpenError::Settings),
    }
}
fn lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => v.is_unique_local() || v.is_unicast_link_local(),
    }
}
fn bind_all(port: u16, lan: bool) -> Result<Vec<TcpListener>, OpenError> {
    let mut addresses = Vec::new();
    if lan {
        for interface in if_addrs::get_if_addrs().map_err(|_| OpenError::Transport)? {
            let ip = interface.ip();
            if !lan_ip(ip) {
                continue;
            }
            let address = match ip {
                IpAddr::V4(v) => SocketAddr::new(IpAddr::V4(v), port),
                IpAddr::V6(v) => {
                    // 链路本地地址的作用域必须指向所属接口。
                    let scope = if v.is_unicast_link_local() {
                        interface.index.ok_or(OpenError::Settings)?
                    } else {
                        0
                    };
                    SocketAddr::V6(SocketAddrV6::new(v, port, 0, scope))
                }
            };
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            return Err(OpenError::Settings);
        }
    } else {
        addresses.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        // 回环入口默认仅使用 IPv4，避免在禁用 IPv6 的主机上启动失败。
    }
    let mut listeners = Vec::new();
    for address in addresses {
        let socket = Socket::new(
            if address.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::STREAM,
            Some(Protocol::TCP),
        )
        .map_err(|_| OpenError::Transport)?;
        socket
            .set_reuse_address(true)
            .map_err(|_| OpenError::Transport)?;
        if address.is_ipv6() {
            socket.set_only_v6(true).map_err(|_| OpenError::Transport)?;
        }
        socket
            .bind(&address.into())
            .map_err(|_| OpenError::Transport)?;
        socket.listen(128).map_err(|_| OpenError::Transport)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| OpenError::Transport)?;
        listeners.push(socket.into());
    }
    Ok(listeners)
}
fn accept_loop(listener: TcpListener, client: Client, state: Arc<State>, is_socks: bool) {
    while !state.stopped() {
        match listener.accept() {
            Ok((stream, _)) => {
                let socket = match stream.try_clone() {
                    Ok(socket) => socket,
                    Err(_) => continue,
                };
                let id = state.next_id.fetch_add(1, Ordering::Relaxed);
                state.sockets.lock().unwrap().insert(id, socket);
                let state2 = state.clone();
                let client = client.clone();
                let task = thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    if is_socks {
                        let _ = socks::serve(stream, client, state2.clone());
                    } else {
                        let _ = http::serve(stream, client, state2.clone());
                    }
                    state2.sockets.lock().unwrap().remove(&id);
                });
                let mut workers = state.workers.lock().unwrap();
                let mut index = 0;
                while index < workers.len() {
                    if workers[index].is_finished() {
                        let _ = workers.swap_remove(index).join();
                    } else {
                        index += 1;
                    }
                }
                workers.push(task);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(_) => {
                state.stop(true);
                break;
            }
        }
    }
}
fn timed_out(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "无效代理请求")
}
fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "代理已停止")
}
fn read_exact(stream: &mut TcpStream, data: &mut [u8], state: &State) -> io::Result<()> {
    use std::io::Read;
    let mut off = 0;
    let deadline = Instant::now() + Duration::from_secs(20);
    while off < data.len() {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if state.stopped() {
            return Err(interrupted());
        }
        match stream.read(&mut data[off..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => off += n,
            Err(e) if timed_out(&e) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 校验端口和布尔值() {
        let mut s = Settings::default();
        assert_eq!(port(&s, "socks5Port", 1080).unwrap(), 1080);
        assert!(!flag(&s, "socks5ListenLAN").unwrap());
        s.insert_text("socks5Port", "1024");
        assert!(port(&s, "socks5Port", 1080).is_err());
        s.insert_text("socks5Port", "65535");
        assert_eq!(port(&s, "socks5Port", 1080).unwrap(), 65535);
        s.insert_text("socks5ListenLAN", "yes");
        assert!(flag(&s, "socks5ListenLAN").is_err());
    }
    #[test]
    fn 只选择局域网地址() {
        assert!(lan_ip("192.168.2.1".parse().unwrap()));
        assert!(lan_ip("fd00::1".parse().unwrap()));
        assert!(lan_ip("fe80::1".parse().unwrap()));
        assert!(!lan_ip("8.8.8.8".parse().unwrap()));
        assert!(!lan_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(!lan_ip("127.0.0.1".parse().unwrap()));
    }
}
