//! Native sockets and the WARP packet device the copy loop dials through.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kerlico_shared::{InboundStream, NodeTag, OpenError, Traffic, Transport, UserEmail};

use crate::copy::{self, PipeRead, PipeWrite};
use crate::{DialTarget, Exit};

/// Whether this host has a usable default route for each family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Native {
    pub v4: bool,
    pub v6: bool,
}

impl Native {
    pub fn detect() -> Self {
        Self {
            v4: probe("1.1.1.1:443", true),
            v6: probe("[2606:4700:4700::1111]:443", false),
        }
    }
}

fn probe(target: &str, v4: bool) -> bool {
    let socket = if v4 {
        UdpSocket::bind("0.0.0.0:0")
    } else {
        UdpSocket::bind("[::]:0")
    };
    let Ok(socket) = socket else {
        return false;
    };
    if socket.connect(target).is_err() {
        return false;
    }
    let Ok(local) = socket.local_addr() else {
        return false;
    };
    match local {
        SocketAddr::V4(addr) => {
            let ip = *addr.ip();
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_broadcast()
        }
        SocketAddr::V6(addr) => {
            let ip = *addr.ip();
            let head = ip.segments()[0];
            (0x2000..0x4000).contains(&head)
        }
    }
}

/// IP packets in and out of the userspace WARP tunnel.
pub trait PacketDevice: Send + Sync {
    fn connect_tcp(&self, addr: SocketAddr) -> Result<Box<dyn BytePipe + Send>, OpenError>;
    fn connect_udp(&self, addr: SocketAddr) -> Result<Box<dyn BytePipe + Send>, OpenError>;
}

pub trait BytePipe: Send {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<usize, OpenError>;
    fn write_pipe(&mut self, buf: &[u8]) -> Result<usize, OpenError>;
}

pub struct WarpSlot {
    device: Mutex<Option<Arc<dyn PacketDevice>>>,
}

impl WarpSlot {
    pub fn empty() -> Self {
        Self {
            device: Mutex::new(None),
        }
    }

    pub fn install(&self, device: Arc<dyn PacketDevice>) {
        *self.device.lock().expect("warp") = Some(device);
    }

    fn get(&self) -> Result<Arc<dyn PacketDevice>, OpenError> {
        self.device
            .lock()
            .expect("warp")
            .clone()
            .ok_or(OpenError::Transport)
    }
}

pub fn dial_native(
    target: &DialTarget,
    stream: &Box<dyn InboundStream>,
    user: &UserEmail,
    node: &NodeTag,
    exit: Exit,
    traffic: &dyn Traffic,
) -> Result<(), OpenError> {
    let addr = pick(target, exit)?;
    match target.transport {
        Transport::Tcp => {
            let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
                .map_err(|_| OpenError::Transport)?;
            tcp.set_nodelay(true).ok();
            let read = tcp.try_clone().map_err(|_| OpenError::Transport)?;
            copy::bridge(
                stream.as_ref(),
                TcpWrite(tcp),
                TcpRead(read),
                user,
                node,
                exit,
                traffic,
            )
        }
        Transport::Udp => {
            let socket = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
                .map_err(|_| OpenError::Transport)?;
            socket.connect(addr).map_err(|_| OpenError::Transport)?;
            socket
                .set_read_timeout(Some(Duration::from_millis(200)))
                .ok();
            let read = socket.try_clone().map_err(|_| OpenError::Transport)?;
            copy::bridge(
                stream.as_ref(),
                UdpWrite(socket),
                UdpRead(read),
                user,
                node,
                exit,
                traffic,
            )
        }
    }
}

pub fn dial_warp(
    slot: &WarpSlot,
    target: &DialTarget,
    stream: &Box<dyn InboundStream>,
    user: &UserEmail,
    node: &NodeTag,
    exit: Exit,
    traffic: &dyn Traffic,
) -> Result<(), OpenError> {
    let device = slot.get()?;
    let addr = pick(target, exit)?;
    let pipe = match target.transport {
        Transport::Tcp => device.connect_tcp(addr)?,
        Transport::Udp => device.connect_udp(addr)?,
    };
    let (read, write) = split_pipe(pipe);
    copy::bridge(stream.as_ref(), write, read, user, node, exit, traffic)
}

fn split_pipe(pipe: Box<dyn BytePipe + Send>) -> (WarpRead, WarpWrite) {
    let shared = Arc::new(Mutex::new(pipe));
    (
        WarpRead {
            pipe: Arc::clone(&shared),
        },
        WarpWrite { pipe: shared },
    )
}

pub fn exchange_native(peer: SocketAddr, tcp: bool, request: &[u8]) -> Result<Vec<u8>, OpenError> {
    if tcp {
        exchange_tcp(peer, request)
    } else {
        exchange_udp(peer, request)
    }
}

pub fn exchange_warp(
    slot: &WarpSlot,
    peer: SocketAddr,
    tcp: bool,
    request: &[u8],
) -> Result<Vec<u8>, OpenError> {
    let device = slot.get()?;
    let mut pipe = if tcp {
        device.connect_tcp(peer)?
    } else {
        device.connect_udp(peer)?
    };
    if tcp {
        let len = (request.len() as u16).to_be_bytes();
        write_pipe(&mut pipe, &len)?;
    }
    write_pipe(&mut pipe, request)?;
    if tcp {
        let mut len_buf = [0u8; 2];
        read_exact_pipe(&mut pipe, &mut len_buf)?;
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        read_exact_pipe(&mut pipe, &mut body)?;
        Ok(body)
    } else {
        let mut buf = vec![0u8; 2048];
        let n = read_once_pipe(&mut pipe, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

fn exchange_udp(peer: SocketAddr, request: &[u8]) -> Result<Vec<u8>, OpenError> {
    let socket = UdpSocket::bind(if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|_| OpenError::Transport)?;
    socket.connect(peer).map_err(|_| OpenError::Transport)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok();
    socket.send(request).map_err(|_| OpenError::Transport)?;
    let mut buf = [0u8; 2048];
    let n = socket.recv(&mut buf).map_err(|_| OpenError::Transport)?;
    Ok(buf[..n].to_vec())
}

fn exchange_tcp(peer: SocketAddr, request: &[u8]) -> Result<Vec<u8>, OpenError> {
    let mut tcp = TcpStream::connect_timeout(&peer, Duration::from_secs(3))
        .map_err(|_| OpenError::Transport)?;
    tcp.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let len = (request.len() as u16).to_be_bytes();
    tcp.write_all(&len).map_err(|_| OpenError::Transport)?;
    tcp.write_all(request).map_err(|_| OpenError::Transport)?;
    let mut len_buf = [0u8; 2];
    tcp.read_exact(&mut len_buf).map_err(|_| OpenError::Transport)?;
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    tcp.read_exact(&mut body).map_err(|_| OpenError::Transport)?;
    Ok(body)
}

fn write_pipe(pipe: &mut Box<dyn BytePipe + Send>, mut bytes: &[u8]) -> Result<(), OpenError> {
    let start = std::time::Instant::now();
    while !bytes.is_empty() {
        match pipe.write_pipe(bytes) {
            Ok(0) => return Err(OpenError::Transport),
            Ok(n) => bytes = &bytes[n..],
            Err(OpenError::Again) if start.elapsed() < Duration::from_secs(3) => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(OpenError::Transport),
        }
    }
    Ok(())
}

fn read_exact_pipe(pipe: &mut Box<dyn BytePipe + Send>, buf: &mut [u8]) -> Result<(), OpenError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = read_once_pipe(pipe, &mut buf[filled..])?;
        if n == 0 {
            return Err(OpenError::Transport);
        }
        filled += n;
    }
    Ok(())
}

fn read_once_pipe(pipe: &mut Box<dyn BytePipe + Send>, buf: &mut [u8]) -> Result<usize, OpenError> {
    let start = std::time::Instant::now();
    loop {
        match pipe.read_pipe(buf) {
            Ok(n) => return Ok(n),
            Err(OpenError::Again) if start.elapsed() < Duration::from_secs(3) => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(OpenError::Transport),
        }
    }
}

fn pick(target: &DialTarget, exit: Exit) -> Result<SocketAddr, OpenError> {
    target
        .addresses
        .iter()
        .copied()
        .find(|addr| exit.is_v4() == addr.is_ipv4())
        .ok_or(OpenError::Transport)
}

struct TcpRead(TcpStream);

impl PipeRead for TcpRead {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<usize, OpenError> {
        self.0
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        match self.0.read(buf) {
            Ok(n) => Ok(n),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                Err(OpenError::Again)
            }
            Err(_) => Err(OpenError::Transport),
        }
    }
}

struct TcpWrite(TcpStream);

impl PipeWrite for TcpWrite {
    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError> {
        self.0.write_all(buf).map_err(|_| OpenError::Transport)
    }
}

struct UdpRead(UdpSocket);

impl PipeRead for UdpRead {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<usize, OpenError> {
        match self.0.recv(buf) {
            Ok(n) => Ok(n),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                Err(OpenError::Again)
            }
            Err(_) => Err(OpenError::Transport),
        }
    }
}

struct UdpWrite(UdpSocket);

impl PipeWrite for UdpWrite {
    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError> {
        self.0
            .send(buf)
            .map(|_| ())
            .map_err(|_| OpenError::Transport)
    }
}

struct WarpRead {
    pipe: Arc<Mutex<Box<dyn BytePipe + Send>>>,
}

impl PipeRead for WarpRead {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<usize, OpenError> {
        self.pipe.lock().expect("warp pipe").read_pipe(buf)
    }
}

struct WarpWrite {
    pipe: Arc<Mutex<Box<dyn BytePipe + Send>>>,
}

impl PipeWrite for WarpWrite {
    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError> {
        let mut pipe = self.pipe.lock().expect("warp pipe");
        let mut sent = 0;
        while sent < buf.len() {
            let n = pipe.write_pipe(&buf[sent..])?;
            if n == 0 {
                return Err(OpenError::Transport);
            }
            sent += n;
        }
        Ok(())
    }
}
