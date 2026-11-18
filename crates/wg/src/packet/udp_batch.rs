use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

use crate::wire::WIRE_BUFFER;

// Bound the work before the next socket read. A batch never waits for more packets.
const LIMIT: usize = 64;
// Leave room for the IPv6 and UDP headers in a non-jumbo IP packet.
const MAX_BYTES: usize = u16::MAX as usize - 48;

// Receive whole datagrams, using a bounded batch of reusable packet buffers.
const RECEIVE_BATCH: usize = 8;

pub(super) struct ReceiveBatch {
    packets: Vec<u8>,
    unavailable: bool,
}

impl ReceiveBatch {
    pub(super) fn new() -> Self {
        Self {
            packets: vec![0; RECEIVE_BATCH * WIRE_BUFFER],
            unavailable: false,
        }
    }

    pub(super) fn read(
        &mut self,
        socket: &UdpSocket,
        budget: usize,
        mut visit: impl FnMut(SocketAddr, &mut [u8]),
    ) -> io::Result<usize> {
        if !self.unavailable {
            match receive_batch(
                socket,
                &mut self.packets,
                budget.min(RECEIVE_BATCH),
                &mut visit,
            ) {
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENOSYS | libc::EPERM | libc::EOPNOTSUPP)
                    ) =>
                {
                    self.unavailable = true
                }
                result => return result,
            }
        }
        let packet = &mut self.packets[..WIRE_BUFFER];
        let (len, peer) = socket.recv_from(packet)?;
        visit(peer, &mut packet[..len]);
        Ok(1)
    }
}

fn receive_batch(
    socket: &UdpSocket,
    bytes: &mut [u8],
    slots: usize,
    visit: &mut impl FnMut(SocketAddr, &mut [u8]),
) -> io::Result<usize> {
    let mut names: [_; RECEIVE_BATCH] = std::array::from_fn(|_| socket2::SockAddrStorage::zeroed());
    // SAFETY: These C structures contain only integer and pointer fields.
    let mut hdrs: [libc::mmsghdr; RECEIVE_BATCH] = unsafe { std::mem::zeroed() };
    let mut iovs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; RECEIVE_BATCH];
    for (i, packet) in bytes.chunks_exact_mut(WIRE_BUFFER).take(slots).enumerate() {
        let hdr = &mut hdrs[i].msg_hdr;
        hdr.msg_namelen = names[i].size_of();
        // SAFETY: The queried type is Linux's sockaddr_storage used by socket2.
        hdr.msg_name = (unsafe { names[i].view_as::<libc::sockaddr_storage>() }
            as *mut libc::sockaddr_storage)
            .cast();
        iovs[i] = libc::iovec {
            iov_base: packet.as_mut_ptr().cast(),
            iov_len: packet.len(),
        };
        hdr.msg_iov = &mut iovs[i];
        hdr.msg_iovlen = 1;
    }
    // SAFETY: Every name and iovec points to a distinct live writable slot;
    // recvmmsg uses the pointers only during this nonblocking call.
    let count = unsafe {
        libc::recvmmsg(
            socket.as_raw_fd(),
            hdrs.as_mut_ptr(),
            slots as _,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    for (i, mut name) in names.into_iter().take(count as usize).enumerate() {
        let hdr = &hdrs[i];
        let len = hdr.msg_len as usize;
        if hdr.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 || len > WIRE_BUFFER {
            continue;
        }
        let family = unsafe { name.view_as::<libc::sockaddr_storage>() }.ss_family as libc::c_int;
        let expected = match family {
            libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
            libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
            _ => continue,
        };
        let namelen = hdr.msg_hdr.msg_namelen;
        if namelen as usize != expected {
            continue;
        }
        // SAFETY: Linux wrote a complete IP socket address of the checked family and length.
        if let Some(peer) = unsafe { socket2::SockAddr::new(name, namelen) }.as_socket() {
            visit(peer, &mut bytes[i * WIRE_BUFFER..][..len]);
        }
    }
    Ok(count as usize)
}

#[derive(Default)]
pub(super) struct SendBatch {
    endpoint: Option<SocketAddr>,
    payload: Vec<u8>,
    used: usize,
    segment: usize,
    unavailable: bool,
}

impl SendBatch {
    pub(super) fn encode(
        &mut self,
        socket: &UdpSocket,
        encode: impl FnOnce(&mut Vec<u8>, usize) -> Option<(SocketAddr, usize)>,
    ) {
        // Keep the initialized high-water mark. The encoder writes just the
        // next datagram at the end of the pending train.
        let start = self.used;
        let Some((endpoint, len)) = encode(&mut self.payload, start) else {
            return;
        };
        let end = start + len;
        if self.unavailable || self.payload[start..end].first() != Some(&4) || len > MAX_BYTES {
            self.flush(socket);
            let _ = socket.send_to(&self.payload[start..end], endpoint);
            return;
        }
        if self.endpoint.is_some()
            && (self.endpoint != Some(endpoint) || len > self.segment || end > MAX_BYTES)
        {
            self.flush(socket);
            if self.unavailable {
                let _ = socket.send_to(&self.payload[start..end], endpoint);
                return;
            }
            self.payload.copy_within(start..end, 0);
        }
        if self.endpoint.is_none() {
            self.endpoint = Some(endpoint);
            self.segment = len;
        }
        self.used += len;
        if len < self.segment || self.used >= LIMIT * self.segment {
            self.flush(socket);
        }
    }

    pub(super) fn flush(&mut self, socket: &UdpSocket) {
        let Some(endpoint) = self.endpoint.take() else {
            return;
        };
        let used = std::mem::take(&mut self.used);
        let payload = &self.payload[..used];
        if used > self.segment {
            match send_segmented(socket, endpoint, payload, self.segment as u16) {
                Ok(()) => return,
                Err(error) => {
                    self.unavailable =
                        matches!(error.raw_os_error(), Some(libc::ENOPROTOOPT | libc::ENOSYS));
                }
            }
        }
        for frame in payload.chunks(self.segment) {
            let _ = socket.send_to(frame, endpoint);
        }
    }
}

fn send_segmented(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    data: &[u8],
    segment: u16,
) -> io::Result<()> {
    let address = socket2::SockAddr::from(endpoint);
    let mut part = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    // Send one aligned ancillary header whose payload is a native-endian u16.
    let mut control = [0usize; 8];
    // SAFETY: All fields are integers or pointers. The address, iovecs, payloads
    // and aligned control storage remain live for this synchronous syscall.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = address.as_ptr().cast_mut().cast();
    message.msg_namelen = address.len();
    message.msg_iov = &mut part;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    let value_len = std::mem::size_of_val(&segment) as libc::c_uint;
    // SAFETY: CMSG_SPACE/LEN describe how much space the configured u16 needs.
    unsafe {
        message.msg_controllen = libc::CMSG_SPACE(value_len) as _;
        assert!(message.msg_controllen as usize <= std::mem::size_of_val(&control));
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_len = libc::CMSG_LEN(value_len) as _;
        (*header).cmsg_level = libc::IPPROTO_UDP;
        (*header).cmsg_type = libc::UDP_SEGMENT;
        libc::CMSG_DATA(header)
            .cast::<u16>()
            .write_unaligned(segment);
        if libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_DONTWAIT) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::time::Duration;

    #[test]
    fn receives_individual_datagrams_from_two_peers_with_a_fixed_budget() -> io::Result<()> {
        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        receiver.set_nonblocking(true)?;
        let a = UdpSocket::bind("127.0.0.1:0")?;
        let b = UdpSocket::bind("127.0.0.1:0")?;
        let packets = [
            (&a, vec![1; 64]),
            (&b, vec![2; 4096]),
            (&a, vec![]),
            (&b, vec![4; 160]),
        ];
        let expected: Vec<_> = packets
            .iter()
            .map(|(peer, packet)| Ok((peer.local_addr()?, packet.clone())))
            .collect::<io::Result<_>>()?;
        for unavailable in [false, true] {
            for (sender, packet) in &packets {
                sender.send_to(packet, receiver.local_addr()?)?;
            }
            let mut batch = ReceiveBatch::new();
            batch.unavailable = unavailable;
            let mut actual = Vec::new();
            for limit in [2, 4] {
                while actual.len() < limit {
                    let budget = limit - actual.len();
                    let n = batch.read(&receiver, budget, |peer, packet| {
                        actual.push((peer, packet.to_vec()));
                    })?;
                    assert!((1..=budget).contains(&n));
                }
                assert_eq!(actual, expected[..limit]);
            }
            let error = batch
                .read(&receiver, 8, |_, _| panic!("unexpected datagram"))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }
        Ok(())
    }

    #[test]
    fn preserves_short_tail_and_retries_other_peers_in_order() -> io::Result<()> {
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let a = UdpSocket::bind("127.0.0.1:0")?;
        let b = UdpSocket::bind("127.0.0.1:0")?;
        for socket in [&a, &b] {
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        }
        let mut batch = SendBatch::default();
        let frame = |len, value| {
            let mut data = vec![value; len];
            data[0] = 4;
            data
        };
        let invalid = "[::1]:9".parse().unwrap();
        for (addr, len, value) in [
            (a.local_addr()?, 128, 1),
            (a.local_addr()?, 128, 2),
            (a.local_addr()?, 64, 3),
            (invalid, 128, 255),
            (invalid, 128, 255),
            (b.local_addr()?, 128, 4),
            (b.local_addr()?, 64, 5),
            (a.local_addr()?, 128, 6),
        ] {
            batch.encode(&sender, |storage, offset| {
                let packet = frame(len, value);
                if offset + len > storage.len() {
                    storage.resize(offset + len, 0);
                }
                storage[offset..offset + len].copy_from_slice(&packet);
                Some((addr, len))
            });
        }
        batch.flush(&sender);
        for (socket, size, value) in [
            (&a, 128, 1),
            (&a, 128, 2),
            (&a, 64, 3),
            (&a, 128, 6),
            (&b, 128, 4),
            (&b, 64, 5),
        ] {
            let mut received = [0; 256];
            let (len, peer) = socket.recv_from(&mut received)?;
            assert_eq!(peer, sender.local_addr()?);
            assert_eq!(&received[..len], frame(size, value));
        }
        Ok(())
    }
}
