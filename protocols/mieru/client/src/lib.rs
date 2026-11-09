//! mieru 客户端：本机代理和落地共用一套连接池及线协议。

mod config;
mod proxy;

use kerlico_mieru::{Assoc, Client as WireClient, Conn, Target};
use kerlico_shared::{
    DataPlane, Destination, InboundStream, OpenError, PeerAddr, PlaneFault, Settings, Transport,
};
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub use proxy::Proxy;

/// 同一账号和节点配置下的可复用客户端；关闭会取消它拥有的会话。
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}
struct ClientInner {
    wire: WireClient,
}

impl Client {
    pub fn new(host: &str, port: u16, settings: &Settings) -> Result<Self, OpenError> {
        let plan = config::Plan::parse(host, port, settings)?;
        let peers = plan.peers()?;
        let wire =
            WireClient::new(peers, plan.account, plan.options).map_err(|_| OpenError::Settings)?;
        Ok(Self {
            inner: Arc::new(ClientInner { wire }),
        })
    }
    pub fn open_stream(&self, host: &str, port: u16) -> io::Result<Conn> {
        validate_target(host, port)?;
        self.inner.wire.open(&Target {
            host: host.to_string(),
            port,
        })
    }
    pub fn associate(&self) -> io::Result<Assoc> {
        self.inner.wire.associate()
    }
    pub fn close(&self) {
        self.inner.wire.close();
    }
    pub fn active_connections(&self) -> usize {
        self.inner.wire.active_connections()
    }
    pub fn active_sessions(&self) -> usize {
        self.inner.wire.active_sessions()
    }
}

fn validate_target(host: &str, port: u16) -> io::Result<()> {
    if port == 0
        || host.is_empty()
        || host.len() > 255
        || host.chars().any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "目标地址无效"));
    }
    Ok(())
}

/// mieru 没有 IP 数据包平面；调用 Proxy::start 或会话接口。
pub fn connect(_peer: &PeerAddr, _settings: &Settings) -> Result<Box<dyn DataPlane>, OpenError> {
    Err(OpenError::Settings)
}

/// 无状态落地接口按完整配置隔离连接池；TCP 与 UDP 保持各自语义。
pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    destination: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    let client = cached_client(host, port, settings)?;
    match destination.transport() {
        Transport::Tcp => {
            let conn = client
                .open_stream(destination.host(), destination.port())
                .map_err(|_| OpenError::Transport)?;
            Ok(Box::new(Relay {
                conn,
                _client: client,
            }))
        }
        Transport::Udp => {
            let assoc = client.associate().map_err(|_| OpenError::Transport)?;
            Ok(Box::new(DatagramRelay {
                assoc,
                host: destination.host().to_string(),
                port: destination.port(),
                pending: Mutex::new(None),
                _client: client,
            }))
        }
    }
}

pub fn open_stream(
    host: &str,
    port: u16,
    settings: &Settings,
    destination_host: &str,
    destination_port: u16,
) -> Result<Conn, OpenError> {
    cached_client(host, port, settings)?
        .open_stream(destination_host, destination_port)
        .map_err(|_| OpenError::Transport)
}

struct Relay {
    conn: Conn,
    _client: Client,
}
impl InboundStream for Relay {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.conn
            .read_for(buf, Duration::from_millis(200))
            .map_err(map_io)
    }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.conn.write_user(buf).map_err(map_io)?;
        Ok(buf.len())
    }
}

struct DatagramRelay {
    assoc: Assoc,
    host: String,
    port: u16,
    pending: Mutex<Option<Vec<u8>>>,
    _client: Client,
}
impl InboundStream for DatagramRelay {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        let mut pending = self.pending.lock().map_err(|_| PlaneFault::Transport)?;
        if pending.is_none() {
            let (_, port, payload) = self
                .assoc
                .recv_for(Duration::from_millis(200))
                .map_err(map_io)?;
            if port != self.port {
                return Err(PlaneFault::Transport);
            }
            *pending = Some(payload);
        }
        let payload = pending.as_ref().ok_or(PlaneFault::Transport)?;
        if buf.len() < payload.len() {
            return Err(PlaneFault::Transport);
        }
        let payload = pending.take().ok_or(PlaneFault::Transport)?;
        buf[..payload.len()].copy_from_slice(&payload);
        Ok(payload.len())
    }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.assoc
            .send_to(&self.host, self.port, buf)
            .map_err(map_io)?;
        Ok(buf.len())
    }
}

fn map_io(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => PlaneFault::Again,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

struct CacheEntry {
    host: String,
    port: u16,
    settings: Settings,
    client: Client,
    seen: Instant,
}
const CACHE_CAPACITY: usize = 64;
const CACHE_IDLE: Duration = Duration::from_secs(60);

fn cache() -> &'static Mutex<Vec<CacheEntry>> {
    static CACHE: OnceLock<Mutex<Vec<CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        std::thread::spawn(|| loop {
            std::thread::sleep(Duration::from_secs(5));
            if let Some(cache) = CACHE.get() {
                if let Ok(mut entries) = cache.lock() {
                    prune(&mut entries);
                }
            }
        });
        Mutex::new(Vec::new())
    })
}
fn idle(entry: &CacheEntry) -> bool {
    Arc::strong_count(&entry.client.inner) == 1 && entry.client.active_sessions() == 0
}
fn prune(entries: &mut Vec<CacheEntry>) {
    entries.retain(|entry| !idle(entry) || entry.seen.elapsed() < CACHE_IDLE);
}

fn cached_client(host: &str, port: u16, settings: &Settings) -> Result<Client, OpenError> {
    {
        let mut entries = cache().lock().map_err(|_| OpenError::Transport)?;
        prune(&mut entries);
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.host == host && entry.port == port && &entry.settings == settings)
        {
            entry.seen = Instant::now();
            return Ok(entry.client.clone());
        }
    }
    let client = Client::new(host, port, settings)?;
    let mut entries = cache().lock().map_err(|_| OpenError::Transport)?;
    if let Some(entry) = entries
        .iter_mut()
        .find(|entry| entry.host == host && entry.port == port && &entry.settings == settings)
    {
        entry.seen = Instant::now();
        return Ok(entry.client.clone());
    }
    if entries.len() == CACHE_CAPACITY {
        let candidate = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| idle(entry))
            .min_by_key(|(_, entry)| entry.seen)
            .map(|(index, _)| index);
        if let Some(index) = candidate {
            entries.remove(index);
        } else {
            return Err(OpenError::Again);
        }
    }
    entries.push(CacheEntry {
        host: host.to_string(),
        port,
        settings: settings.clone(),
        client: client.clone(),
        seen: Instant::now(),
    });
    Ok(client)
}

/// 从客户端配置启动本机 SOCKS5/HTTP 代理；错误不携带配置原文。
pub fn run_proxy(document: &str) -> Result<(), OpenError> {
    let (host, port, settings) = config::parse_document(document)?;
    let client = Client::new(&host, port, &settings)?;
    Proxy::start(client, &settings)?.wait()
}
