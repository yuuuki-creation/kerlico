use std::collections::VecDeque;
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

struct Received {
    peer: SocketAddr,
    next: usize,
    end: usize,
    segment: usize,
}

pub(super) struct ReceiveBatch {
    packets: Vec<u8>,
    ready: VecDeque<Received>,
    unavailable: bool,
}

pub(super) fn enable_gro(socket: &UdpSocket) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: UDP_GRO accepts one native integer on this live UDP socket.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_UDP,
            libc::UDP_GRO,
            std::ptr::from_ref(&enabled).cast(),
            std::mem::size_of_val(&enabled) as _,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl ReceiveBatch {
    pub(super) fn new() -> Self {
        Self {
            packets: vec![0; RECEIVE_BATCH * WIRE_BUFFER],
            ready: VecDeque::with_capacity(RECEIVE_BATCH),
            unavailable: false,
        }
    }

    pub(super) fn has_pending(&self) -> bool {
        !self.ready.is_empty()
    }

    pub(super) fn discard_pending(&mut self) {
        self.ready.clear();
    }

    pub(super) fn read(
        &mut self,
        socket: &UdpSocket,
        budget: usize,
        mut visit: impl FnMut(SocketAddr, &mut [u8]),
    ) -> io::Result<usize> {
        if budget == 0 {
            return Ok(0);
        }
        if self.ready.is_empty() {
            let slots = budget.min(RECEIVE_BATCH);
            let count = receive_batch(
                socket,
                &mut self.packets,
                slots,
                &mut self.ready,
                &mut self.unavailable,
            )?;
            // Invalid kernel metadata consumes its input without becoming a WG frame.
            if self.ready.is_empty() {
                return Ok(count);
            }
        }
        let mut delivered = 0;
        while delivered < budget {
            let Some(run) = self.ready.front_mut() else {
                break;
            };
            let end = run.end.min(run.next + run.segment);
            visit(run.peer, &mut self.packets[run.next..end]);
            run.next = end;
            if run.next == run.end {
                self.ready.pop_front();
            }
            delivered += 1;
        }
        Ok(delivered)
    }
}

fn receive_batch(
    socket: &UdpSocket,
    bytes: &mut [u8],
    slots: usize,
    ready: &mut VecDeque<Received>,
    unavailable: &mut bool,
) -> io::Result<usize> {
    let mut controls = [[0usize; 8]; RECEIVE_BATCH];
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
        hdr.msg_control = controls[i].as_mut_ptr().cast();
        hdr.msg_controllen = std::mem::size_of_val(&controls[i]);
    }
    // SAFETY: Every name and iovec points to a distinct live writable slot;
    // recvmmsg uses the pointers only during this nonblocking call.
    let mut count = -1;
    if !*unavailable {
        count = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                hdrs.as_mut_ptr(),
                slots as _,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if count < 0 {
            let e = io::Error::last_os_error();
            if !matches!(
                e.raw_os_error(),
                Some(libc::ENOSYS | libc::EPERM | libc::EOPNOTSUPP)
            ) {
                return Err(e);
            }
            *unavailable = true;
        }
    }
    if count < 0 {
        // recvmsg retains the GRO ancillary data even without recvmmsg support.
        let n =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut hdrs[0].msg_hdr, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        hdrs[0].msg_len = n as _;
        count = 1;
    }
    for (i, mut name) in names.into_iter().take(count as usize).enumerate() {
        let hdr = &hdrs[i];
        let len = hdr.msg_len as usize;
        if hdr.msg_hdr.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || len > WIRE_BUFFER {
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
            let start = i * WIRE_BUFFER;
            if let Some(segment) = segment_size(&hdr.msg_hdr, len) {
                ready.push_back(Received {
                    peer,
                    next: start,
                    end: start + len,
                    segment,
                });
            }
        }
    }
    Ok(count as usize)
}

fn segment_size(msg: &libc::msghdr, len: usize) -> Option<usize> {
    // SAFETY: recvmsg filled this aligned ancillary buffer. The kernel wrote
    // the control length, and MSG_CTRUNC has already been excluded.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                if (*cmsg).cmsg_len
                    != libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as usize
                {
                    return None;
                }
                let segment = libc::CMSG_DATA(cmsg).cast::<libc::c_int>().read_unaligned();
                return (segment > 0 && segment as usize <= len).then_some(segment as usize);
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    Some(len.max(1))
}

const GROUPS: usize = 8;

struct DatagramGroup {
    endpoint: SocketAddr,
    start: usize,
    end: usize,
    segment: usize,
    frames: usize,
    short_tail: bool,
}

#[derive(Default)]
pub(super) struct SendBatch {
    payload: Vec<u8>,
    used: usize,
    groups: Vec<DatagramGroup>,
    no_gso: bool,
    no_mmsg: bool,
}

impl SendBatch {
    #[cfg(test)]
    pub(super) fn encode(
        &mut self,
        socket: &UdpSocket,
        encode: impl FnOnce(&mut Vec<u8>, usize) -> Option<(SocketAddr, usize)>,
    ) {
        if self.groups.len() == GROUPS {
            self.flush(socket);
        }
        let start = self.used;
        let Some((endpoint, len)) = encode(&mut self.payload, start) else {
            return;
        };
        self.append(socket, start, endpoint, len);
    }

    pub(super) fn reserve_tun(&mut self, len: usize) -> (usize, &mut [u8]) {
        let start = self.used;
        let end = start + len;
        if self.payload.len() < end {
            self.payload.resize(end, 0);
        }
        (start, &mut self.payload[start..end])
    }

    pub(super) fn encode_prepared(
        &mut self,
        socket: &UdpSocket,
        from: usize,
        stride: usize,
        seal: impl FnOnce(&mut [u8]) -> Option<(SocketAddr, usize)>,
    ) {
        let Some((endpoint, len)) = seal(&mut self.payload[from..from + stride]) else {
            return;
        };
        self.append(socket, from, endpoint, len);
    }

    fn append(&mut self, socket: &UdpSocket, from: usize, endpoint: SocketAddr, len: usize) {
        if self.groups.len() == GROUPS {
            self.flush(socket);
        }
        let start = self.used;
        debug_assert!(start <= from);
        if start != from {
            self.payload.copy_within(from..from + len, start);
        }
        let end = start + len;
        // Control packets are sent separately, after every preceding data packet.
        if len > MAX_BYTES || self.payload[start..end].first() != Some(&4) {
            self.flush(socket);
            let _ = socket.send_to(&self.payload[start..end], endpoint);
            return;
        }
        self.used = end;
        if let Some(group) = self.groups.last_mut() {
            if !self.no_gso
                && group.endpoint == endpoint
                && !group.short_tail
                && len <= group.segment
                && group.frames < LIMIT
                && end - group.start <= MAX_BYTES
            {
                group.end = end;
                group.frames += 1;
                group.short_tail = len < group.segment;
                return;
            }
        }
        self.groups.push(DatagramGroup {
            endpoint,
            start,
            end,
            segment: len,
            frames: 1,
            short_tail: false,
        });
    }

    pub(super) fn flush(&mut self, socket: &UdpSocket) {
        let mut sent = 0;
        if self.groups.len() > 1 && !self.no_mmsg {
            match send_groups(socket, &self.groups, &self.payload) {
                Ok(n) => sent = n,
                Err(e) => self.no_mmsg = e.raw_os_error() == Some(libc::ENOSYS),
            }
        }
        // Linux may accept a prefix and suppress the error from the next
        // message. Retry only unaccepted groups, in original order.
        for group in &self.groups[sent..] {
            let data = &self.payload[group.start..group.end];
            if group.frames > 1 && !self.no_gso {
                match send_segmented(socket, group.endpoint, data, group.segment as u16) {
                    Ok(()) => continue,
                    Err(e) => {
                        self.no_gso =
                            matches!(e.raw_os_error(), Some(libc::ENOPROTOOPT | libc::ENOSYS))
                    }
                }
            }
            for frame in data.chunks(group.segment) {
                let _ = socket.send_to(frame, group.endpoint);
            }
        }
        self.groups.clear();
        self.used = 0;
    }
}

fn send_segmented(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    data: &[u8],
    segment: u16,
) -> io::Result<()> {
    let addr = socket2::SockAddr::from(endpoint);
    let mut part = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut control = [0usize; 8];
    // SAFETY: these fields accept all-zero initial state.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    setup_message(&mut msg, &addr, &mut part, &mut control, Some(segment));
    // SAFETY: descriptor fields point into live storage for this synchronous syscall.
    if unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_DONTWAIT) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn send_groups(socket: &UdpSocket, groups: &[DatagramGroup], data: &[u8]) -> io::Result<usize> {
    let count = groups.len();
    assert!(count <= GROUPS);
    let addrs: [_; GROUPS] =
        std::array::from_fn(|i| groups.get(i).map(|g| socket2::SockAddr::from(g.endpoint)));
    let mut parts = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; GROUPS];
    let mut controls = [[0usize; 8]; GROUPS];
    // SAFETY: all mmsghdr scalar fields and pointers have valid zero values.
    let mut msgs: [libc::mmsghdr; GROUPS] = unsafe { std::mem::zeroed() };
    for (i, g) in groups.iter().enumerate() {
        let bytes = &data[g.start..g.end];
        parts[i] = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        setup_message(
            &mut msgs[i].msg_hdr,
            addrs[i].as_ref().unwrap(),
            &mut parts[i],
            &mut controls[i],
            (g.frames > 1).then_some(g.segment as u16),
        );
    }
    // SAFETY: all headers, addresses and control/data storage stay alive
    // until the call returns. No descriptor contains a retained Rust borrow.
    let n = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            msgs.as_mut_ptr(),
            count as _,
            libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn setup_message(
    msg: &mut libc::msghdr,
    addr: &socket2::SockAddr,
    part: &mut libc::iovec,
    control: &mut [usize; 8],
    segment: Option<u16>,
) {
    msg.msg_name = addr.as_ptr().cast_mut().cast();
    msg.msg_namelen = addr.len();
    msg.msg_iov = part;
    msg.msg_iovlen = 1;
    if let Some(segment) = segment {
        let len = std::mem::size_of_val(&segment) as libc::c_uint;
        msg.msg_control = control.as_mut_ptr().cast();
        // SAFETY: this aligned control array accommodates one native-endian u16.
        unsafe {
            msg.msg_controllen = libc::CMSG_SPACE(len) as _;
            assert!(msg.msg_controllen <= std::mem::size_of_val(control));
            let header = libc::CMSG_FIRSTHDR(msg);
            (*header).cmsg_len = libc::CMSG_LEN(len) as _;
            (*header).cmsg_level = libc::IPPROTO_UDP;
            (*header).cmsg_type = libc::UDP_SEGMENT;
            libc::CMSG_DATA(header)
                .cast::<u16>()
                .write_unaligned(segment);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::time::Duration;

    #[test]
    fn prepared_slots_keep_order_across_a_short_data_frame_and_control_flush() -> io::Result<()> {
        let rx = UdpSocket::bind("127.0.0.1:0")?;
        rx.set_read_timeout(Some(Duration::from_secs(2)))?;
        let tx = UdpSocket::bind("127.0.0.1:0")?;
        let dst = rx.local_addr()?;
        let mut batch = SendBatch::default();
        let lengths = [64, 64, 33, 48, 44, 64];
        let stride = 160;
        let (first, bytes) = batch.reserve_tun(stride * lengths.len());
        for (i, slot) in bytes.chunks_exact_mut(stride).enumerate() {
            slot[..lengths[i]].fill(i as u8 + 11);
            slot[0] = if i == 3 { 1 } else { 4 };
        }
        for (i, &len) in lengths.iter().enumerate() {
            batch.encode_prepared(&tx, first + i * stride, stride, |_| Some((dst, len)));
        }
        batch.flush(&tx);
        for (i, &len) in lengths.iter().enumerate() {
            let mut wire = [0; 160];
            assert_eq!(rx.recv(&mut wire)?, len);
            assert_eq!(wire[0], if i == 3 { 1 } else { 4 });
            assert!(wire[1..len].iter().all(|&v| v == i as u8 + 11));
        }
        Ok(())
    }
    #[test]
    fn gro_splits_a_short_tail_in_order_across_read_budgets() -> io::Result<()> {
        let rx = UdpSocket::bind("127.0.0.1:0")?;
        let tx = UdpSocket::bind("127.0.0.1:0")?;
        rx.set_nonblocking(true)?;
        enable_gro(&rx)?;
        let packets = [vec![11u8; 176], vec![22; 176], vec![33; 71]];
        for single_message in [false, true] {
            let mut batch = ReceiveBatch::new();
            batch.unavailable = single_message;
            send_segmented(&tx, rx.local_addr()?, &packets.concat(), 176)?;
            let mut got = Vec::new();
            for (i, expected) in packets.iter().enumerate() {
                assert_eq!(
                    batch.read(&rx, 1, |peer, frame| got.push((peer, frame.to_vec())))?,
                    1
                );
                assert_eq!(got[i], (tx.local_addr()?, expected.clone()));
                assert_eq!(batch.has_pending(), i < 2);
            }
            assert!(
                matches!(batch.read(&rx, 1, |_, _| unreachable!()), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
            );
        }
        Ok(())
    }

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
    fn control_is_emitted_after_prior_trains_and_before_later_data() -> io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let sink = UdpSocket::bind("127.0.0.1:0")?;
        sink.set_read_timeout(Some(Duration::from_secs(2)))?;
        for fallback in [false, true] {
            let mut batch = SendBatch {
                no_mmsg: fallback,
                ..Default::default()
            };
            let mut expected = Vec::new();
            for (kind, len, mark) in [
                (4, 160, 1),
                (4, 160, 2),
                (4, 32, 3),
                (4, 100, 4),
                (4, 100, 5),
                (1, 148, 6),
                (4, 92, 7),
            ] {
                let mut frame = vec![mark; len];
                frame[0] = kind;
                let peer = sink.local_addr()?;
                batch.encode(&socket, |store, offset| {
                    if store.len() < offset + len {
                        store.resize(offset + len, 0);
                    }
                    store[offset..offset + len].copy_from_slice(&frame);
                    Some((peer, len))
                });
                expected.push(frame);
            }
            batch.flush(&socket);
            for frame in expected {
                let mut packet = [0; 192];
                let n = sink.recv(&mut packet)?;
                assert_eq!(&packet[..n], frame);
            }
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
    #[test]
    fn unread_slots_survive_a_flush_and_a_skipped_route() -> io::Result<()> {
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
        let addr = receiver.local_addr()?;
        let mut batch = SendBatch::default();
        let stride = 160;
        let sizes = [128, 64, 96, 64, 96];
        let (_, arena) = batch.reserve_tun(stride * sizes.len());
        for (i, slot) in arena.chunks_exact_mut(stride).enumerate() {
            slot.fill(i as u8 + 10);
            slot[0] = if i == 3 { 2 } else { 4 };
        }
        for (i, &n) in sizes.iter().enumerate() {
            batch.encode_prepared(&sender, i * stride, stride, |data| {
                assert_eq!(data[n - 1], i as u8 + 10);
                (i != 2).then_some((addr, n))
            });
        }
        batch.flush(&sender);
        for i in [0usize, 1, 3, 4] {
            let mut actual = [0; 160];
            let (n, peer) = receiver.recv_from(&mut actual)?;
            assert_eq!((n, peer), (sizes[i], sender.local_addr()?));
            assert_eq!(actual[0], if i == 3 { 2 } else { 4 });
            assert!(actual[1..n].iter().all(|&b| b == i as u8 + 10));
        }
        Ok(())
    }
}
