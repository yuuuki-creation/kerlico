//! Native sockets and the WARP packet device the copy loop dials through.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kerlico_shared::{Association, ConnectBound, InboundStream, NodeTag, OpenError, Traffic, Transport, UserEmail};

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
    fn local_addr(&self) -> Option<SocketAddr> { None }
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
            let tcp = copy::report_connect_with(
                stream.as_ref(),
                TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|_| OpenError::Transport),
                |tcp| tcp.local_addr().ok().map(ConnectBound::Socket),
            )?;
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
            #[cfg(target_os = "linux")]
            if stream.connected_datagrams() {
                socket.set_nonblocking(true).map_err(|_| OpenError::Transport)?;
                kerlico_shared::grow_udp_receive_buffer(&socket);
                let relay = ConnectedUdp {
                    socket,
                    counters: traffic.bind(user, node, exit.tag()),
                    gso: true,
                    batch_receive: true,
                    tried_burst_buffer: false,
                };
                return stream.attach_datagrams(Box::new(relay)).map_err(|_| OpenError::Transport);
            }
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
    let pipe = copy::report_connect_with(stream, (|| {
        let device = slot.get()?;
        let addr = pick(target, exit)?;
        match target.transport {
            Transport::Tcp => device.connect_tcp(addr),
            Transport::Udp => device.connect_udp(addr),
        }
    })(), |pipe| pipe.local_addr().map(ConnectBound::Socket))?;
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
        loop {
            match self.0.read(buf) {
                Ok(0) => return Ok(ReadEvent::Eof),
                Ok(n) => return Ok(ReadEvent::Data(n)),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error)
                    if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
                {
                    return Err(OpenError::Again);
                }
                Err(_) => return Err(OpenError::Transport),
            }
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

#[cfg(target_os = "linux")]
const CONNECTED_RECEIVE_BUDGET: usize = 32;

#[cfg(target_os = "linux")]
struct ConnectedUdp {
    socket: UdpSocket,
    counters: kerlico_shared::TrafficCounters,
    gso: bool,
    batch_receive: bool,
    tried_burst_buffer: bool,
}

#[cfg(target_os = "linux")]
impl ConnectedUdp {
    fn send(&mut self, requests: &mut std::collections::VecDeque<Vec<u8>>) -> std::io::Result<()> {
        use std::io::ErrorKind;

        let mut sent = 0;
        let mut status = Ok(());
        while let Some(first) = requests.front() {
            let size = first.len();
            if self.gso && size != 0 {
                let cap = (65_507 / size).min(32);
                let packets = requests.make_contiguous();
                let count = packets.iter().take(cap).take_while(|p| p.len() == size).count();
                if count > 1 {
                    match udp_segments(&self.socket, &packets[..count], size as u16) {
                        Ok(n) => {
                            sent += n as u64;
                            requests.drain(..count);
                            continue;
                        }
                        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                            requests.drain(..count);
                            continue;
                        }
                        Err(error) if matches!(error.raw_os_error(), Some(
                            libc::EINVAL | libc::EMSGSIZE | libc::EIO | libc::ENOPROTOOPT
                            | libc::EOPNOTSUPP | libc::EPERM | libc::ENOSYS
                        )) => self.gso = false,
                        Err(error) => {
                            status = Err(error);
                            break;
                        }
                    }
                }
            }
            let packet = requests.pop_front().expect("first UDP packet");
            match self.socket.send(&packet) {
                Ok(n) => sent += n as u64,
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                Err(error) => {
                    status = Err(error);
                    break;
                }
            }
        }
        if sent != 0 {
            self.counters.add_uplink(sent);
        }
        status
    }

    fn receive_ready(
        &mut self,
        buf: &mut [u8],
        reply: &mut dyn FnMut(&[u8]) -> bool,
    ) -> std::io::Result<()> {
        use std::io::ErrorKind;
        let mut received = 0;
        let mut packets = 0;
        let mut report = |packet: &[u8]| {
            packets += 1;
            if reply(packet) {
                received += packet.len() as u64;
            }
        };
        let result = if self.batch_receive {
            match receive_udp_batch(&self.socket, buf, &mut report) {
                Err(error) if matches!(error.raw_os_error(), Some(
                    libc::ENOSYS | libc::EPERM | libc::EOPNOTSUPP
                )) => {
                    self.batch_receive = false;
                    Ok(())
                }
                result => result,
            }
        } else {
            let mut result = Ok(());
            for _ in 0..CONNECTED_RECEIVE_BUDGET {
                match self.socket.recv(buf) {
                    Ok(n) => report(&buf[..n]),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => {
                        result = Err(error);
                        break;
                    }
                }
            }
            result
        };
        if packets == CONNECTED_RECEIVE_BUDGET && !self.tried_burst_buffer {
            // This flow exhausted a full read turn. Give its next burst room
            // to queue while other ready sockets are being serviced.
            kerlico_shared::grow_udp_carrier_receive_buffer(&self.socket);
            self.tried_burst_buffer = true;
        }
        if received != 0 {
            self.counters.add_downlink(received);
        }
        result
    }
}

#[cfg(target_os = "linux")]
fn receive_udp_batch(
    socket: &UdpSocket,
    buf: &mut [u8],
    deliver: &mut dyn FnMut(&[u8]),
) -> std::io::Result<()> {
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd;

    const COUNT: usize = 4;
    const SIZE: usize = 65_536;
    if buf.len() < COUNT * SIZE {
        return Err(ErrorKind::InvalidInput.into());
    }
    // Each message points to one exclusive slot for the duration of the call.
    let mut messages: [libc::mmsghdr; COUNT] = unsafe { std::mem::zeroed() };
    let mut vectors: [libc::iovec; COUNT] = unsafe { std::mem::zeroed() };
    for ((slot, message), vector) in buf.chunks_exact_mut(SIZE).zip(&mut messages).zip(&mut vectors) {
        vector.iov_base = slot.as_mut_ptr().cast();
        vector.iov_len = slot.len();
        message.msg_hdr.msg_iov = vector;
        message.msg_hdr.msg_iovlen = 1;
    }
    for _ in 0..(CONNECTED_RECEIVE_BUDGET / COUNT) {
        // Only initialized headers and equally sized live slots are supplied.
        let n = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(), messages.as_mut_ptr(), COUNT as _,
                libc::MSG_DONTWAIT, std::ptr::null_mut(),
            )
        };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            match error.kind() {
                ErrorKind::WouldBlock => break,
                ErrorKind::Interrupted => continue,
                _ => return Err(error),
            }
        }
        for (slot, message) in buf.chunks_exact(SIZE).zip(&messages[..n as usize]) {
            if message.msg_hdr.msg_flags & libc::MSG_TRUNC == 0 {
                deliver(&slot[..message.msg_len as usize]);
            }
        }
        if (n as usize) < COUNT {
            break;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn udp_segments(socket: &UdpSocket, packets: &[Vec<u8>], size: u16) -> std::io::Result<usize> {
    use std::mem::{size_of, zeroed};
    use std::os::fd::AsRawFd;

    // The kernel reads one live slice per datagram and a single aligned control message.
    let mut vectors: [libc::iovec; 32] = unsafe { zeroed() };
    for (vector, packet) in vectors.iter_mut().zip(packets) {
        vector.iov_base = packet.as_ptr().cast_mut().cast();
        vector.iov_len = packet.len();
    }
    let mut message: libc::msghdr = unsafe { zeroed() };
    let mut control = [0usize; 4];
    message.msg_iov = vectors.as_mut_ptr();
    message.msg_iovlen = packets.len();
    message.msg_control = control.as_mut_ptr().cast();
    // The aligned control array has room for the header and its two-byte value.
    let sent = unsafe {
        message.msg_controllen = libc::CMSG_SPACE(size_of::<u16>() as _) as _;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::IPPROTO_UDP;
        (*header).cmsg_type = libc::UDP_SEGMENT;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<u16>() as _) as _;
        libc::CMSG_DATA(header).cast::<u16>().write_unaligned(size);
        libc::sendmsg(socket.as_raw_fd(), &message, 0)
    };
    if sent < 0 {
        Err(std::io::Error::last_os_error())
    } else if sent as usize != packets.len() * usize::from(size) {
        Err(std::io::ErrorKind::WriteZero.into())
    } else {
        Ok(sent as usize)
    }
}

#[cfg(target_os = "linux")]
impl kerlico_shared::ConnectedDatagrams for ConnectedUdp {
    fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.socket)
    }

    fn drive(
        &mut self,
        requests: &mut std::collections::VecDeque<Vec<u8>>,
        receive: Option<&mut [u8]>,
        reply: &mut dyn FnMut(&[u8]) -> bool,
    ) -> std::io::Result<()> {
        self.send(requests)?;
        if let Some(buf) = receive {
            self.receive_ready(buf, reply)?;
        }
        Ok(())
    }
}

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
