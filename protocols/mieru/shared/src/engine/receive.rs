use std::io;
use std::net::{SocketAddr, UdpSocket};

const MAX_PACKET: usize = 65535;
#[cfg(target_os = "linux")]
const BATCH: usize = 16;
#[cfg(not(target_os = "linux"))]
const BATCH: usize = 1;

/// Only the receiver owns these buffers. A read waits for the first packet using
/// the socket's existing timeout, then takes at most the packets already queued.
pub(super) struct Packets {
    bytes: Vec<u8>,
    #[cfg(target_os = "linux")]
    single: bool,
    #[cfg(target_os = "linux")]
    messages: Messages,
}

impl Packets {
    pub(super) fn new() -> Self {
        Self {
            bytes: vec![0; BATCH * MAX_PACKET],
            #[cfg(target_os = "linux")]
            single: false,
            #[cfg(target_os = "linux")]
            messages: Messages::new(),
        }
    }

    pub(super) fn read(
        &mut self,
        socket: &UdpSocket,
        visit: impl FnMut(SocketAddr, &mut [u8]),
    ) -> io::Result<usize> {
        self.read_impl(socket, true, visit)
    }

    /// The native reactor already waited for readiness. Every syscall here is
    /// nonblocking, including the first packet and the single-packet fallback.
    /// A final WouldBlock is returned even if earlier packets were delivered
    /// to the visitor, so try_io can clear the readiness that produced them.
    pub(super) fn read_ready(
        &mut self,
        socket: &UdpSocket,
        visit: impl FnMut(SocketAddr, &mut [u8]),
    ) -> io::Result<usize> {
        self.read_impl(socket, false, visit)
    }

    fn read_impl(
        &mut self,
        socket: &UdpSocket,
        wait_first: bool,
        mut visit: impl FnMut(SocketAddr, &mut [u8]),
    ) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        if !self.single {
            let mut received = 0;
            loop {
                // A packet may arrive while the previous ones are being opened
                // and dispatched. Take those too before releasing the readers,
                // but never wait again and never exceed the same batch budget.
                let flags = if received == 0 && wait_first {
                    libc::MSG_WAITFORONE
                } else {
                    libc::MSG_DONTWAIT
                };
                match self.messages.read(
                    socket,
                    &mut self.bytes,
                    BATCH - received,
                    flags,
                    &mut visit,
                ) {
                    Ok(count) => {
                        received += count;
                        if count == 0 || received == BATCH {
                            return Ok(received);
                        }
                    }
                    Err(error) if !wait_first && error.kind() == io::ErrorKind::WouldBlock => {
                        return Err(error);
                    }
                    Err(error)
                        if received != 0
                            && matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                                    | io::ErrorKind::Interrupted
                            ) =>
                    {
                        return Ok(received);
                    }
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::ENOSYS | libc::EPERM | libc::EOPNOTSUPP)
                        ) =>
                    {
                        self.single = true;
                        if received != 0 {
                            return Ok(received);
                        }
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = wait_first;
        let (n, peer) = socket.recv_from(&mut self.bytes[..MAX_PACKET])?;
        visit(peer, &mut self.bytes[..n]);
        Ok(1)
    }
}

#[cfg(target_os = "linux")]
struct Messages {
    names: [libc::sockaddr_storage; BATCH],
    headers: [libc::mmsghdr; BATCH],
    iovecs: [libc::iovec; BATCH],
}

// SAFETY: only the receiver owns these headers. read rewrites every pointer
// for the current borrow, uses them in a synchronous syscall, and never
// dereferences a pointer from an earlier call.
#[cfg(target_os = "linux")]
unsafe impl Send for Messages {}

#[cfg(target_os = "linux")]
impl Messages {
    fn new() -> Self {
        // SAFETY: these Linux ABI structures contain only integers and raw
        // pointers. Ancillary fields remain null throughout the receiver's life.
        unsafe { std::mem::zeroed() }
    }

    fn read(
        &mut self,
        socket: &UdpSocket,
        bytes: &mut [u8],
        slots: usize,
        flags: libc::c_int,
        visit: &mut impl FnMut(SocketAddr, &mut [u8]),
    ) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let Self {
            names,
            headers,
            iovecs,
        } = self;
        for (i, packet) in bytes.chunks_exact_mut(MAX_PACKET).take(slots).enumerate() {
            let header = &mut headers[i].msg_hdr;
            header.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
            header.msg_name = std::ptr::from_mut(&mut names[i]).cast();
            iovecs[i] = libc::iovec {
                iov_base: packet.as_mut_ptr().cast(),
                iov_len: packet.len(),
            };
            header.msg_iov = &mut iovecs[i];
            header.msg_iovlen = 1;
        }
        // SAFETY: All pointers refer to distinct, live writable slots for this call.
        // Only the initial call uses WAITFORONE and SO_RCVTIMEO like recv_from;
        // every follow-up uses DONTWAIT. No recvmmsg timeout or batch-fill wait.
        let count = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                headers.as_mut_ptr(),
                slots as _,
                flags,
                std::ptr::null_mut(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        for (i, name) in names.iter().take(count as usize).enumerate() {
            let header = &headers[i];
            let len = header.msg_len as usize;
            if header.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 || len > MAX_PACKET {
                continue;
            }
            let namelen = header.msg_hdr.msg_namelen as usize;
            let addr = std::ptr::from_ref(name);
            // SAFETY: these sockaddr types fit the aligned, initialized storage.
            // Check the kernel's family and exact returned length before reading one.
            let peer = match name.ss_family as libc::c_int {
                libc::AF_INET if namelen == std::mem::size_of::<libc::sockaddr_in>() => {
                    let v4 = unsafe { &*addr.cast::<libc::sockaddr_in>() };
                    SocketAddr::from((v4.sin_addr.s_addr.to_ne_bytes(), u16::from_be(v4.sin_port)))
                }
                libc::AF_INET6 if namelen == std::mem::size_of::<libc::sockaddr_in6>() => {
                    let v6 = unsafe { &*addr.cast::<libc::sockaddr_in6>() };
                    SocketAddr::V6(std::net::SocketAddrV6::new(
                        v6.sin6_addr.s6_addr.into(),
                        u16::from_be(v6.sin6_port),
                        v6.sin6_flowinfo,
                        v6.sin6_scope_id,
                    ))
                }
                _ => continue,
            };
            visit(peer, &mut bytes[i * MAX_PACKET..][..len]);
        }
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn readiness_reads_never_wait_for_a_first_or_following_packet() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut packets = Packets::new();
        for fallback in [false, true] {
            #[cfg(target_os = "linux")]
            {
                packets.single = fallback;
            }
            #[cfg(not(target_os = "linux"))]
            let _ = fallback;
            assert_eq!(
                packets
                    .read_ready(&socket, |_, _| panic!("empty socket"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            sender
                .send_to(b"ready", socket.local_addr().unwrap())
                .unwrap();
            let mut visits = 0;
            let deadline = Instant::now() + Duration::from_millis(200);
            let result = loop {
                let result = packets.read_ready(&socket, |peer, bytes| {
                    assert_eq!(peer, sender.local_addr().unwrap());
                    assert_eq!(bytes, b"ready");
                    visits += 1;
                });
                if visits != 0 || Instant::now() >= deadline {
                    break result;
                }
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
                std::thread::sleep(Duration::from_millis(1));
            };
            assert_eq!(visits, 1);
            #[cfg(target_os = "linux")]
            let batched = !packets.single;
            #[cfg(not(target_os = "linux"))]
            let batched = false;
            if batched {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            } else {
                assert_eq!(result.unwrap(), 1);
            }
            assert_eq!(
                packets
                    .read_ready(&socket, |_, _| panic!("drained socket"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn preserves_datagrams_sources_and_short_batches() -> io::Result<()> {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let socket = UdpSocket::bind(address)?;
            socket.set_read_timeout(Some(Duration::from_millis(200)))?;
            let sources = [UdpSocket::bind(address)?, UdpSocket::bind(address)?];
            let mut expected = Vec::new();
            #[cfg(target_os = "macos")]
            let sizes = [0, 1, 1400, 4096];
            #[cfg(not(target_os = "macos"))]
            let sizes = [0, 1, 1400, 32000, 65000];
            for (i, len) in sizes.into_iter().enumerate() {
                let payload = vec![i as u8; len];
                let source = &sources[i % sources.len()];
                source.send_to(&payload, socket.local_addr()?)?;
                expected.push((source.local_addr()?, payload));
            }
            let mut packets = Packets::new();
            let mut actual = Vec::new();
            while actual.len() < expected.len() {
                packets.read(&socket, |peer, bytes| actual.push((peer, bytes.to_vec())))?;
            }
            assert_eq!(actual, expected);
            let start = Instant::now();
            let error = packets
                .read(&socket, |_, _| panic!("unexpected data"))
                .unwrap_err();
            assert!(matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ));
            assert!(start.elapsed() < Duration::from_secs(2));

            sources[0].send_to(b"sparse", socket.local_addr()?)?;
            let start = Instant::now();
            assert_eq!(
                packets.read(&socket, |peer, bytes| {
                    assert_eq!(peer, sources[0].local_addr().unwrap());
                    assert_eq!(bytes, b"sparse");
                })?,
                1
            );
            assert!(
                start.elapsed() < Duration::from_millis(150),
                "waited to fill a batch"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounds_each_batch_and_preserves_single_receive_fallback() -> io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let source = UdpSocket::bind("127.0.0.1:0")?;
        for n in 0..BATCH + 3 {
            source.send_to(&[n as u8], socket.local_addr()?)?;
        }
        let mut packets = Packets::new();
        let mut received = Vec::new();
        assert_eq!(
            packets.read(&socket, |_, bytes| received.extend_from_slice(bytes))?,
            BATCH
        );
        packets.single = true;
        assert_eq!(
            packets.read(&socket, |_, bytes| received.extend_from_slice(bytes))?,
            1
        );
        packets.single = false;
        assert_eq!(
            packets.read(&socket, |_, bytes| received.extend_from_slice(bytes))?,
            2
        );
        assert_eq!(
            received,
            (0..BATCH + 3).map(|n| n as u8).collect::<Vec<_>>()
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drains_packets_arriving_during_dispatch_without_waiting_for_more() -> io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let source = UdpSocket::bind("127.0.0.1:0")?;
        let addr = socket.local_addr()?;
        source.send_to(b"first", addr)?;
        let mut packets = Packets::new();
        let mut actual = Vec::new();
        let start = Instant::now();
        assert_eq!(
            packets.read(&socket, |_, bytes| {
                actual.push(bytes.to_vec());
                if bytes == b"first" {
                    source.send_to(b"next", addr).unwrap();
                }
            })?,
            2
        );
        assert_eq!(actual, [b"first".to_vec(), b"next".to_vec()]);
        assert!(start.elapsed() < Duration::from_millis(150));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn continuous_arrivals_cannot_extend_the_notification_batch() -> io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let source = UdpSocket::bind("127.0.0.1:0")?;
        let addr = socket.local_addr()?;
        source.send_to(&[0], addr)?;
        let mut packets = Packets::new();
        let mut count = 0;
        assert_eq!(
            packets.read(&socket, |_, bytes| {
                assert_eq!(bytes, &[count as u8]);
                count += 1;
                source.send_to(&[count as u8], addr).unwrap();
            })?,
            BATCH
        );
        assert_eq!(count, BATCH);
        assert_eq!(
            packets.read(&socket, |_, bytes| assert_eq!(bytes, &[BATCH as u8]))?,
            1
        );
        Ok(())
    }
}
