//! Native sockets and the WARP packet device the copy loop dials through.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kerlico_shared::{Association, InboundStream, NodeTag, OpenError, Traffic, Transport, UserEmail};

use crate::association_session::AssociationSessions;
use crate::copy::{self, PipeRead, PipeWrite, ReadEvent};
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
    fn supports_udp_associations(&self) -> bool { false }
    fn associate_udp(&self, _ipv4: bool) -> Result<Box<dyn Association>, OpenError> { Err(OpenError::Settings) }
}

pub trait BytePipe: Send + Sync {
    fn read_pipe(&self, buf: &mut [u8]) -> Result<usize, OpenError>;
    fn write_pipe(&self, buf: &[u8]) -> Result<usize, OpenError>;
}

pub struct WarpSlot {
    device: Mutex<Option<WarpDevice>>,
}

struct WarpDevice {
    device: Arc<dyn PacketDevice>,
    udp: [Option<Arc<AssociationSessions>>; 2],
}

impl WarpSlot {
    pub fn empty() -> Self {
        Self {
            device: Mutex::new(None),
        }
    }

    pub fn install(&self, device: Arc<dyn PacketDevice>) {
        let udp = [false, true].map(|ipv4| {
            device.supports_udp_associations().then(|| {
                let device = device.clone();
                Arc::new(AssociationSessions::with_opener(move || device.associate_udp(ipv4)))
            })
        });
        *self.device.lock().expect("warp") = Some(WarpDevice { device, udp });
    }

    pub(crate) fn associations(&self, ipv4: bool) -> Option<Arc<AssociationSessions>> {
        self.device.lock().expect("warp").as_ref()?.udp[usize::from(ipv4)].clone()
    }

    pub(crate) fn get(&self) -> Result<Arc<dyn PacketDevice>, OpenError> {
        self.device
            .lock()
            .expect("warp")
            .as_ref()
            .map(|installed| installed.device.clone())
            .ok_or(OpenError::Transport)
    }
}

pub fn dial_native(
    target: &DialTarget,
    mut stream: Box<dyn InboundStream>,
    user: &UserEmail,
    node: &NodeTag,
    exit: Exit,
    traffic: &dyn Traffic,
    detached: bool,
) -> Result<(), OpenError> {
    let addr = pick(target, exit).inspect_err(|_| {
        let _ = stream.report_connect(Err(OpenError::Transport));
    })?;
    match target.transport {
        Transport::Tcp => {
            let tcp = copy::report_connect(stream.as_ref(), TcpStream::connect_timeout(&addr, Duration::from_secs(10))
                .map_err(|_| OpenError::Transport))?;
            tcp.set_nodelay(true).ok();
            #[cfg(target_os = "linux")]
            if let Some(inbound) = stream.take_splice_socket() {
                if let Some(relay) = copy::splice::reactor() {
                    return relay.dispatch(inbound, tcp, traffic.bind(user, node, exit.tag()), detached);
                }
            }
            if let Some(inbound) = stream.take_async_tcp().map_err(|_| OpenError::Transport)? {
                return crate::async_copy::dispatch(tcp, inbound, traffic.bind(user, node, exit.tag()), detached);
            }
            tcp.set_read_timeout(Some(Duration::from_millis(200)))
                .map_err(|_| OpenError::Transport)?;
            let read = tcp.try_clone().map_err(|_| OpenError::Transport)?;
            copy::bridge(
                stream.as_ref(),
                TcpWrite(tcp),
                TcpRead(read),
                copy::Flow {
                    user,
                    node,
                    exit,
                    traffic,
                    transport: Transport::Tcp,
                },
            )
        }
        Transport::Udp => {
            let socket = UdpSocket::bind(if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
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
                copy::Flow {
                    user,
                    node,
                    exit,
                    traffic,
                    transport: Transport::Udp,
                },
            )
        }
    }
}

pub fn dial_warp(
    slot: &WarpSlot,
    target: &DialTarget,
    stream: &dyn InboundStream,
    user: &UserEmail,
    node: &NodeTag,
    exit: Exit,
    traffic: &dyn Traffic,
) -> Result<(), OpenError> {
    let pipe = copy::report_connect(stream, (|| {
        let device = slot.get()?;
        let addr = pick(target, exit)?;
        match target.transport {
            Transport::Tcp => device.connect_tcp(addr),
            Transport::Udp => device.connect_udp(addr),
        }
    })())?;
    let (read, write) = split_pipe(pipe, target.transport);
    copy::bridge(
        stream,
        write,
        read,
        copy::Flow {
            user,
            node,
            exit,
            traffic,
            transport: target.transport,
        },
    )
}

fn split_pipe(pipe: Box<dyn BytePipe + Send>, transport: Transport) -> (WarpRead, WarpWrite) {
    let shared: Arc<dyn BytePipe + Send> = Arc::from(pipe);
    (
        WarpRead {
            pipe: Arc::clone(&shared),
            transport,
        },
        WarpWrite {
            pipe: shared,
            transport,
        },
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
    let socket = UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|_| OpenError::Transport)?;
    socket.connect(peer).map_err(|_| OpenError::Transport)?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
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
    tcp.read_exact(&mut len_buf)
        .map_err(|_| OpenError::Transport)?;
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    tcp.read_exact(&mut body)
        .map_err(|_| OpenError::Transport)?;
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
    #[cfg(target_os = "linux")]
    fn native_tcp(&self) -> Option<&TcpStream> { Some(&self.0) }

    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<ReadEvent, OpenError> {
        match self.0.read(buf) {
            Ok(0) => Ok(ReadEvent::Eof),
            Ok(n) => Ok(ReadEvent::Data(n)),
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
    #[cfg(target_os = "linux")]
    fn native_tcp(&self) -> Option<&TcpStream> { Some(&self.0) }

    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError> {
        self.0.write_all(buf).map_err(|_| OpenError::Transport)
    }
    fn write_pipe_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> Result<(), OpenError> {
        if bufs.len() == 1 { return self.write_pipe(&bufs[0]); }
        write_all_vectored(&mut self.0, bufs).map_err(|_| OpenError::Transport)
    }
    fn finish(&mut self) -> Result<(), OpenError> {
        self.0
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| OpenError::Transport)
    }
}

fn write_all_vectored(writer: &mut impl Write, mut parts: &[std::io::IoSlice<'_>]) -> std::io::Result<()> {
    // A fixed stack batch also bounds callers larger than the OS IOV limit.
    let mut offset = 0;
    while !parts.is_empty() {
        let mut slices = [std::io::IoSlice::new(&[]); 64];
        let count = parts.len().min(slices.len());
        slices[0] = std::io::IoSlice::new(&parts[0][offset..]);
        for (out, bytes) in slices[1..count].iter_mut().zip(&parts[1..count]) {
            *out = std::io::IoSlice::new(bytes);
        }
        let mut written = match writer.write_vectored(&slices[..count]) {
            Ok(0) if slices[..count].iter().all(|part| part.is_empty()) => {
                parts = &parts[count..];
                offset = 0;
                continue;
            }
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        while !parts.is_empty() && written >= parts[0].len() - offset {
            written -= parts[0].len() - offset;
            parts = &parts[1..];
            offset = 0;
        }
        offset += written;
    }
    Ok(())
}

#[cfg(test)]
mod vectored_tests {
    use super::*;
    use std::io::{self, IoSlice};

    #[test]
    fn partial_writes_and_interrupts_preserve_every_region() {
        struct Sink { bytes: Vec<u8>, calls: usize }
        impl Write for Sink {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> { panic!("expected vector write") }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
            fn write_vectored(&mut self, parts: &[IoSlice<'_>]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls % 3 == 0 { return Err(io::ErrorKind::Interrupted.into()); }
                let bytes: Vec<_> = parts.iter().flat_map(|part| part.iter().copied()).take(7).collect();
                self.bytes.extend_from_slice(&bytes);
                Ok(bytes.len())
            }
        }
        let regions: Vec<Vec<u8>> = (0..130).map(|i| vec![i as u8; i % 5]).collect();
        let parts: Vec<_> = regions.iter().map(|part| IoSlice::new(part)).collect();
        let mut sink = Sink { bytes: Vec::new(), calls: 0 };
        write_all_vectored(&mut sink, &parts).unwrap();
        assert_eq!(sink.bytes, regions.concat());
        assert!(sink.calls > 3);
        let error = write_all_vectored(&mut &mut [0u8; 0][..], &[IoSlice::new(b"lost")]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }
}

struct UdpRead(UdpSocket);

impl PipeRead for UdpRead {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<ReadEvent, OpenError> {
        match self.0.recv(buf) {
            Ok(n) => Ok(ReadEvent::Data(n)),
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
            .and_then(|n| {
                if n == buf.len() {
                    Ok(())
                } else {
                    Err(std::io::ErrorKind::WriteZero.into())
                }
            })
            .map_err(|_| OpenError::Transport)
    }
}

struct WarpRead {
    pipe: Arc<dyn BytePipe + Send>,
    transport: Transport,
}

impl PipeRead for WarpRead {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<ReadEvent, OpenError> {
        let n = self.pipe.read_pipe(buf)?;
        Ok(if n == 0 && self.transport == Transport::Tcp {
            ReadEvent::Eof
        } else {
            ReadEvent::Data(n)
        })
    }
}

struct WarpWrite {
    pipe: Arc<dyn BytePipe + Send>,
    transport: Transport,
}

impl PipeWrite for WarpWrite {
    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError> {
        if self.transport == Transport::Udp {
            return if self.pipe.write_pipe(buf)? == buf.len() {
                Ok(())
            } else {
                Err(OpenError::Transport)
            };
        }
        let mut sent = 0;
        while sent < buf.len() {
            let n = self.pipe.write_pipe(&buf[sent..])?;
            if n == 0 {
                return Err(OpenError::Transport);
            }
            sent += n;
        }
        Ok(())
    }
}
