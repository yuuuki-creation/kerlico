use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg(unix)]
use kerlico_openvpn::SocketWake;
use kerlico_openvpn::{Carrier, MAX_FRAME, POLL};
#[cfg(target_os = "linux")]
use kerlico_openvpn::SocketRegistration;

use super::{Config, Peer, MAX_SESSIONS};

const UDP_INBOX_LIMIT: usize = 64;

pub(super) type Datagram<'a> = (SocketAddr, &'a [u8]);

pub(super) struct DatagramWait {
    #[cfg(unix)]
    socket_wake: SocketWake,
}

impl DatagramWait {
    pub(super) fn new(socket: &UdpSocket) -> io::Result<(Self, impl Fn() + Send + Sync + 'static)> {
        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            kerlico_shared::grow_udp_carrier_receive_buffer(socket);
            let (socket_wake, wake) = SocketWake::new(socket)?;
            socket.set_nonblocking(true)?;
            Ok((Self { socket_wake }, wake))
        }
        #[cfg(not(unix))]
        {
            let _ = socket;
            Ok((Self {}, || {}))
        }
    }

    fn readable(&mut self, socket: &UdpSocket, timeout: Duration) -> io::Result<bool> {
        #[cfg(unix)]
        return self.socket_wake.wait(socket, timeout);
        #[cfg(not(unix))]
        {
            let _ = socket;
            Ok(!timeout.is_zero())
        }
    }
}

pub(super) fn run(
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    mut wait: DatagramWait,
    wake: impl Fn() + Send + Sync + 'static,
) {
    let (send, events) = mpsc::channel();
    let signal = DatagramSignal {
        send,
        wake: Arc::new(wake),
    };
    let mut sessions = HashMap::<SocketAddr, DatagramSession>::new();
    let mut frames = Receiver::new();
    let mut epoch = 0u64;
    let mut timer = Instant::now() + POLL;
    let mut events_pending = false;
    #[cfg(target_os = "linux")]
    let registration = wait.socket_wake.registration();
    #[cfg(target_os = "linux")]
    let mut ready_peers = Vec::new();
    while !config.stopped.load(Ordering::Acquire) {
        let timeout = if events_pending {
            Duration::ZERO
        } else {
            timer.saturating_duration_since(Instant::now())
        };
        let readable = match wait.readable(&socket, timeout) {
            Ok(readable) => readable,
            Err(_) => break,
        };
        #[cfg(target_os = "linux")]
        if let Some(registry) = &registration {
            registry.take_datagram_peers(&mut ready_peers);
            for addr in &ready_peers {
                if let Some(entry) = sessions.get_mut(addr) {
                    if let DatagramState::Active(peer) = &mut entry.state {
                        if !peer.live() || peer.drive(&config, Some((&[], false)), true).is_err() {
                            sessions.remove(addr);
                        }
                    }
                }
            }
        }
        if readable {
            let result = frames.read(&socket, |batch| {
                #[cfg(target_os = "linux")]
                wait.socket_wake.note_receive_batch(batch.len() >= linux::SLOTS / 2);
                for packets in batch.chunk_by(|a, b| a.0 == b.0) {
                    let addr = packets[0].0;
                    if let Some(entry) = sessions.get_mut(&addr) {
                        if entry.drive(&config, packets) {
                            continue;
                        }
                        sessions.remove(&addr);
                    }
                    if sessions.len() >= MAX_SESSIONS {
                        continue;
                    }
                    let Some(reset) = packets
                        .iter()
                        .position(|(_, frame)| kerlico_openvpn::is_initial_reset(frame))
                    else {
                        continue;
                    };
                    epoch = epoch.wrapping_add(1);
                    if let Ok(inbox) = start_datagram_handshake(
                        &socket,
                        &config,
                        &signal,
                        addr,
                        epoch,
                        &packets[reset..],
                        #[cfg(target_os = "linux")]
                        registration.clone(),
                    ) {
                        sessions.insert(
                            addr,
                            DatagramSession {
                                epoch,
                                state: DatagramState::Handshake(inbox),
                            },
                        );
                    }
                }
            });
            if result.is_err_and(|error| {
                !kerlico_openvpn::retry(&error) && error.kind() != io::ErrorKind::ConnectionReset
            }) {
                break;
            }
        }
        let mut processed = 0;
        for event in events.try_iter().take(2 * MAX_SESSIONS) {
            processed += 1;
            handle_datagram_event(&mut sessions, &config, event);
        }
        events_pending = processed == 2 * MAX_SESSIONS;
        let now = Instant::now();
        if now >= timer {
            sessions.retain(|_, session| session.drive(&config, &[]));
            timer = now + POLL;
        }
    }
    config.stopped.store(true, Ordering::Release);
}

struct DatagramSession {
    epoch: u64,
    state: DatagramState,
}

enum DatagramState {
    Handshake(Arc<UdpInbox>),
    Active(Box<Peer>),
}

impl DatagramSession {
    fn drive(&mut self, config: &Config, packets: &[Datagram<'_>]) -> bool {
        match &mut self.state {
            DatagramState::Handshake(inbox) => inbox.push(packets),
            DatagramState::Active(peer) => {
                peer.live() && peer.drive(config, Some((packets, false)), false).is_ok()
            }
        }
    }
}

#[derive(Clone)]
struct DatagramSignal {
    send: mpsc::Sender<DatagramEvent>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl DatagramSignal {
    fn send(&self, event: DatagramEvent) {
        if self.send.send(event).is_ok() {
            (self.wake)();
        }
    }
}

enum DatagramEvent {
    Handshake(SocketAddr, u64, Option<Box<Peer>>),
    Egress(SocketAddr, u64, Arc<AtomicBool>),
}

fn start_datagram_handshake(
    socket: &Arc<UdpSocket>,
    config: &Arc<Config>,
    signal: &DatagramSignal,
    addr: SocketAddr,
    epoch: u64,
    first: &[Datagram<'_>],
    #[cfg(target_os = "linux")] registration: Option<SocketRegistration>,
) -> io::Result<Arc<UdpInbox>> {
    let inbox = Arc::new(UdpInbox::default());
    inbox.push(first);
    let carrier = UdpPeer {
        socket: socket.clone(),
        addr,
        inbox: inbox.clone(),
        pending: VecDeque::new(),
        #[cfg(target_os = "linux")]
        gso: true,
    };
    let config = config.clone();
    let signal = signal.clone();
    std::thread::Builder::new()
        .name("openvpn-handshake".into())
        .spawn(move || {
            let outbound = signal.clone();
            let queued = Arc::new(AtomicBool::new(false));
            let wake = move || {
                if !queued.swap(true, Ordering::AcqRel) {
                    outbound.send(DatagramEvent::Egress(addr, epoch, queued.clone()));
                }
            };
            let peer = Peer::establish(
                Box::new(carrier), addr, &config, wake,
                #[cfg(target_os = "linux")]
                registration,
            )
                .ok()
                .map(Box::new);
            signal.send(DatagramEvent::Handshake(addr, epoch, peer));
        })?;
    Ok(inbox)
}

fn handle_datagram_event(
    sessions: &mut HashMap<SocketAddr, DatagramSession>,
    config: &Config,
    event: DatagramEvent,
) {
    match event {
        DatagramEvent::Handshake(addr, epoch, peer) => {
            let Some(entry) = sessions.get_mut(&addr).filter(|entry| entry.epoch == epoch) else {
                return;
            };
            if let Some(mut peer) = peer {
                if peer.live() && peer.drive(config, Some((&[], true)), false).is_ok() {
                    entry.state = DatagramState::Active(peer);
                    return;
                }
            }
            sessions.remove(&addr);
        }
        DatagramEvent::Egress(addr, epoch, queued) => {
            queued.store(false, Ordering::Release);
            if let Some(entry) = sessions.get_mut(&addr).filter(|entry| entry.epoch == epoch) {
                if !entry.drive(config, &[]) {
                    sessions.remove(&addr);
                }
            }
        }
    }
}

#[derive(Default)]
struct UdpInbox {
    input: Mutex<UdpInput>,
    ready: Condvar,
}

#[derive(Default)]
struct UdpInput {
    frames: VecDeque<Vec<u8>>,
    waiting: bool,
    closed: bool,
}

impl UdpInbox {
    fn push(&self, packets: &[Datagram<'_>]) -> bool {
        let mut input = self.input.lock().expect("OpenVPN UDP input");
        if input.closed {
            return false;
        }
        let space = UDP_INBOX_LIMIT - input.frames.len();
        let waiting = input.waiting && input.frames.is_empty() && !packets.is_empty();
        input
            .frames
            .extend(packets.iter().take(space).map(|(_, frame)| frame.to_vec()));
        if waiting {
            self.ready.notify_one();
        }
        true
    }

    fn take(&self, pending: &mut VecDeque<Vec<u8>>, wait: bool) {
        let mut input = self.input.lock().expect("OpenVPN UDP input");
        if wait && input.frames.is_empty() {
            input.waiting = true;
            (input, _) = self
                .ready
                .wait_timeout_while(input, POLL, |input| input.frames.is_empty())
                .expect("OpenVPN UDP input");
            input.waiting = false;
        }
        std::mem::swap(pending, &mut input.frames);
    }
}

struct UdpPeer {
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    inbox: Arc<UdpInbox>,
    pending: VecDeque<Vec<u8>>,
    #[cfg(target_os = "linux")]
    gso: bool,
}

fn udp_send(socket: &UdpSocket, addr: SocketAddr, frame: &[u8]) -> io::Result<()> {
    match socket.send_to(frame, addr) {
        Ok(n) if n == frame.len() => Ok(()),
        Ok(_) => Err(io::ErrorKind::WriteZero.into()),
        Err(error) if kerlico_openvpn::retry(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

impl Drop for UdpPeer {
    fn drop(&mut self) {
        self.inbox.input.lock().expect("OpenVPN UDP input").closed = true;
    }
}

impl Carrier for UdpPeer {
    fn datagrams(&self) -> bool {
        true
    }
    fn ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        udp_send(&self.socket, self.addr, frame)
    }
    #[cfg(target_os = "linux")]
    fn send_batch(&mut self, frames: &[Vec<u8>]) -> io::Result<()> {
        send_batch(&self.socket, self.addr, frames, &mut self.gso, |frame| {
            udp_send(&self.socket, self.addr, frame)
        })
    }
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.pending.is_empty() {
            self.inbox.take(&mut self.pending, true);
        }
        Ok(self.pending.pop_front())
    }
    fn receive_ready(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.pending.is_empty() {
            self.inbox.take(&mut self.pending, false);
        }
        Ok(self.pending.pop_front())
    }
}

struct Receiver {
    single: [u8; MAX_FRAME + 1],
    #[cfg(target_os = "linux")]
    batch: Option<linux::Batch>,
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn udp_batches_preserve_packet_boundaries_and_sources() -> io::Result<()> {
        for host in ["127.0.0.1:0", "[::1]:0"] {
            let receive = UdpSocket::bind(host)?;
            let send = UdpSocket::bind(host)?;
            receive.set_read_timeout(Some(Duration::from_secs(1)))?;
            let dst = receive.local_addr()?;
            let src = send.local_addr()?;
            let frames = [vec![1; 180], vec![2; 180], vec![3; 49], vec![4; 180]];
            for mut gso in [false, true] {
                send_batch(&send, dst, &frames, &mut gso, |frame| {
                    assert_eq!(send.send_to(frame, dst)?, frame.len());
                    Ok(())
                })?;
                let mut input = Receiver::new();
                let mut got = Vec::new();
                while got.len() < frames.len() {
                    input.read(&receive, |batch| {
                        for (addr, frame) in batch {
                            assert_eq!(*addr, src);
                            got.push(frame.to_vec());
                        }
                    })?;
                }
                assert_eq!(got, frames);
            }
        }
        Ok(())
    }
}

impl Receiver {
    fn new() -> Self {
        Self {
            single: [0; MAX_FRAME + 1],
            #[cfg(target_os = "linux")]
            batch: Some(linux::Batch::new()),
        }
    }

    pub(super) fn read(
        &mut self,
        socket: &UdpSocket,
        mut deliver: impl FnMut(&[Datagram<'_>]),
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(batch) = &mut self.batch {
            match batch.read(socket, &mut deliver) {
                Err(error) if linux::unsupported(&error) => self.batch = None,
                result => return result,
            }
        }
        let (len, address) = socket.recv_from(&mut self.single)?;
        if len <= MAX_FRAME {
            deliver(&[(address, &self.single[..len])]);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) use linux::send_batch;

#[cfg(target_os = "linux")]
mod linux {
    use std::mem::{size_of, zeroed};
    use std::net::{Ipv4Addr, SocketAddrV6};
    use std::os::fd::AsRawFd;
    use std::ptr;

    use kerlico_openvpn::FRAME_BATCH;
    use socket2::SockAddr;

    use super::*;

    pub(super) const SLOTS: usize = 16;
    const SLOT_LEN: usize = MAX_FRAME + 1;

    pub(super) struct Batch {
        bytes: Vec<u8>,
        addresses: [libc::sockaddr_storage; SLOTS],
        messages: [libc::mmsghdr; SLOTS],
        buffers: [libc::iovec; SLOTS],
    }

    impl Batch {
        pub(super) fn new() -> Self {
            // These ABI structs contain only integers and raw pointers.
            let (addresses, messages, buffers) = unsafe { zeroed() };
            Self {
                bytes: vec![0; SLOTS * SLOT_LEN],
                addresses,
                messages,
                buffers,
            }
        }

        pub(super) fn read(
            &mut self,
            socket: &UdpSocket,
            deliver: &mut impl FnMut(&[Datagram<'_>]),
        ) -> io::Result<()> {
            for (i, slot) in self.bytes.chunks_exact_mut(SLOT_LEN).enumerate() {
                self.buffers[i] = libc::iovec {
                    iov_base: slot.as_mut_ptr().cast(),
                    iov_len: SLOT_LEN,
                };
                let header = &mut self.messages[i].msg_hdr;
                header.msg_name = ptr::from_mut(&mut self.addresses[i]).cast();
                header.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
                header.msg_iov = &mut self.buffers[i];
                header.msg_iovlen = 1;
            }
            // The syscall borrows distinct, live slots. Only the first read
            // may wait, subject to the socket's existing receive timeout.
            let count = unsafe {
                libc::recvmmsg(
                    socket.as_raw_fd(),
                    self.messages.as_mut_ptr(),
                    SLOTS as _,
                    libc::MSG_WAITFORONE,
                    ptr::null_mut(),
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut packets = [(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), &[][..]); SLOTS];
            let mut used = 0;
            for i in 0..count as usize {
                let message = &self.messages[i];
                let len = message.msg_len as usize;
                if message.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 || len > MAX_FRAME {
                    continue;
                }
                if let Some(address) = address(&self.addresses[i], message.msg_hdr.msg_namelen) {
                    packets[used] = (address, &self.bytes[i * SLOT_LEN..][..len]);
                    used += 1;
                }
            }
            deliver(&packets[..used]);
            Ok(())
        }
    }

    fn address(raw: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
        let raw_ptr = ptr::from_ref(raw);
        // The family and length identify an initialized address in aligned storage.
        match raw.ss_family as libc::c_int {
            libc::AF_INET if len as usize == size_of::<libc::sockaddr_in>() => {
                let v4 = unsafe { &*raw_ptr.cast::<libc::sockaddr_in>() };
                Some(SocketAddr::from((
                    v4.sin_addr.s_addr.to_ne_bytes(),
                    u16::from_be(v4.sin_port),
                )))
            }
            libc::AF_INET6 if len as usize == size_of::<libc::sockaddr_in6>() => {
                let v6 = unsafe { &*raw_ptr.cast::<libc::sockaddr_in6>() };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    v6.sin6_addr.s6_addr.into(),
                    u16::from_be(v6.sin6_port),
                    u32::from_be(v6.sin6_flowinfo),
                    v6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }

    pub(super) fn unsupported(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EPERM | libc::EOPNOTSUPP)
        )
    }

    pub(in super::super) fn send_batch(
        socket: &UdpSocket,
        address: SocketAddr,
        frames: &[Vec<u8>],
        gso: &mut bool,
        mut send_one: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let address = SockAddr::from(address);
        for frames in frames.chunks(FRAME_BATCH) {
            // These ABI structs contain only integers and raw pointers.
            let mut messages: [libc::mmsghdr; FRAME_BATCH] = unsafe { zeroed() };
            let mut buffers: [libc::iovec; FRAME_BATCH] = unsafe { zeroed() };
            let mut controls = [[0usize; 4]; FRAME_BATCH];
            let mut starts = [0; FRAME_BATCH + 1];
            let mut groups = 0;
            for (i, frame) in frames.iter().enumerate() {
                buffers[i] = libc::iovec {
                    iov_base: frame.as_ptr().cast_mut().cast(),
                    iov_len: frame.len(),
                };
                if i == 0 || !*gso || frames[i - 1].len() != frame.len() {
                    starts[groups] = i;
                    groups += 1;
                }
            }
            starts[groups] = frames.len();
            for (i, span) in starts[..=groups].windows(2).enumerate() {
                let start = span[0];
                let count = span[1] - start;
                let header = &mut messages[i].msg_hdr;
                header.msg_name = address.as_ptr().cast_mut().cast();
                header.msg_namelen = address.len();
                header.msg_iov = &mut buffers[start];
                header.msg_iovlen = count;
                if count > 1 {
                    segment(header, &mut controls[i], frames[start].len() as u16);
                }
            }
            let mut offset = 0;
            while offset < groups {
                // sendmmsg reads the live addresses and buffers, and writes only
                // the number of bytes sent into each initialized message.
                let count = unsafe {
                    libc::sendmmsg(
                        socket.as_raw_fd(),
                        messages[offset..].as_mut_ptr(),
                        (groups - offset) as _,
                        0,
                    )
                };
                if count > 0 {
                    offset += count as usize;
                } else {
                    let error = io::Error::last_os_error();
                    let segmented = starts[offset + 1] - starts[offset] > 1;
                    let reject_segment = segmented
                        && matches!(
                            error.raw_os_error(),
                            Some(libc::EINVAL | libc::EIO | libc::EMSGSIZE | libc::ENOPROTOOPT)
                        );
                    if count < 0
                        && !reject_segment
                        && !unsupported(&error)
                        && !kerlico_openvpn::retry(&error)
                    {
                        return Err(error);
                    }
                    if reject_segment || (segmented && unsupported(&error)) {
                        *gso = false;
                    }
                    for frame in &frames[starts[offset]..] {
                        send_one(frame)?;
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn segment(header: &mut libc::msghdr, control: &mut [usize; 4], size: u16) {
        header.msg_control = control.as_mut_ptr().cast();
        // The aligned buffer accommodates one native-endian UDP segment size.
        unsafe {
            let len = size_of::<u16>() as _;
            header.msg_controllen = libc::CMSG_SPACE(len) as _;
            assert!(header.msg_controllen <= std::mem::size_of_val(control));
            let info = libc::CMSG_FIRSTHDR(header);
            (*info).cmsg_len = libc::CMSG_LEN(len) as _;
            (*info).cmsg_level = libc::IPPROTO_UDP;
            (*info).cmsg_type = libc::UDP_SEGMENT;
            libc::CMSG_DATA(info).cast::<u16>().write_unaligned(size);
        }
    }
}
