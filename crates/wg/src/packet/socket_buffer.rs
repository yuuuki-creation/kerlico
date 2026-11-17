//! Linux TUN UDP sockets use bounded queues to absorb bursts from the device.

use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use socket2::SockRef;

// Linux doubles SO_RCVBUF and SO_SNDBUF when storing the accounting limit.
// wireguard-go requests 7 MiB; Linux accounts twice the requested value.
const ACCOUNTED_BYTES: usize = 14 * 1024 * 1024;
const REQUESTED_BYTES: libc::c_int = (ACCOUNTED_BYTES / 2) as libc::c_int;

pub(super) fn tune(socket: &UdpSocket) {
    let options = SockRef::from(socket);
    grow(
        || options.recv_buffer_size(),
        || options.set_recv_buffer_size(REQUESTED_BYTES as usize),
        || force(socket, libc::SO_RCVBUFFORCE),
        "/proc/sys/net/core/rmem_max",
    );
    grow(
        || options.send_buffer_size(),
        || options.set_send_buffer_size(REQUESTED_BYTES as usize),
        || force(socket, libc::SO_SNDBUFFORCE),
        "/proc/sys/net/core/wmem_max",
    );
}

fn grow(
    current: impl Fn() -> io::Result<usize>,
    ordinary: impl FnOnce() -> io::Result<()>,
    force: impl FnOnce(),
    limit: &str,
) {
    let Ok(previous) = current() else { return };
    if previous >= ACCOUNTED_BYTES {
        return;
    }
    // The host may clamp the ordinary request. Trying it could shrink an
    // existing buffer previously set above that clamp, so first try the
    // per-socket override and keep any already larger queue.
    force();
    let Ok(applied) = current() else { return };
    if applied >= ACCOUNTED_BYTES {
        return;
    }
    // The ordinary request must not replace a larger queue on a socket
    // supplied by the caller, even if this process cannot set it again.
    let capped = std::fs::read_to_string(limit)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .map(|cap| 2 * cap.min(REQUESTED_BYTES as usize));
    if capped.is_some_and(|cap| cap > applied) {
        let _ = ordinary();
    }
}

fn force(socket: &UdpSocket, option: libc::c_int) {
    // The kernel checks the process's existing CAP_NET_ADMIN. If it is
    // unavailable, using the ordinary capped limit is sufficient to start.
    // SAFETY: the live socket and a pointer to a single C int match the opt ABI.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&REQUESTED_BYTES).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}
