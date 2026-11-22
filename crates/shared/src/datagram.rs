//! A per-destination UDP route that can forward borrowed datagrams directly.

use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::net::UdpSocket;

use crate::PlaneFault;

pub trait DatagramUplink: Send + Sync {
    /// A closed route can be resolved again. A temporarily blocked route drops
    /// just this datagram.
    fn send(&self, payload: &[u8]) -> Result<(), PlaneFault>;

    fn is_live(&self) -> bool;
}

pub type DatagramReply = Box<dyn Fn(SocketAddr, &[u8]) -> Result<(), PlaneFault> + Send + Sync>;
pub type InstallDatagramUplink =
    Box<dyn FnOnce(Box<dyn DatagramUplink>) -> Result<(), PlaneFault> + Send>;

/// Offered after protocol parsing. The outbound still owns the socket and the
/// resolved destination. The reply callback must work without blocking.
pub struct DirectDatagram {
    pub install: InstallDatagramUplink,
    pub reply: DatagramReply,
}

/// Give UDP sockets drained in a readiness loop room to absorb short bursts.
#[cfg(target_os = "linux")]
pub fn grow_udp_receive_buffer(socket: &UdpSocket) {
    grow_receive_buffer(socket, 512 * 1024);
}

/// Give multiplexed carriers and UDP flows that exhaust a read turn a larger queue.
/// Linux allocates packet memory on arrival, up to this per-socket limit.
#[cfg(target_os = "linux")]
pub fn grow_udp_carrier_receive_buffer(socket: &UdpSocket) {
    grow_udp_carrier_receive_buffer_to(socket, 2 * 1024 * 1024);
}

/// Request a larger Linux UDP receive buffer for a shared carrier.
#[cfg(target_os = "linux")]
pub fn grow_udp_carrier_receive_buffer_to(socket: &UdpSocket, requested: usize) {
    use std::os::fd::AsRawFd;

    let Ok(request) = libc::c_int::try_from(requested) else {
        return;
    };
    let Ok(current) = socket2::SockRef::from(socket).recv_buffer_size() else {
        return;
    };
    if current >= 2 * requested {
        return;
    }
    // The kernel checks CAP_NET_ADMIN. Without it, use the ordinary limit.
    // SAFETY: the socket is live and the argument is one initialized C int.
    let applied = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            std::ptr::from_ref(&request).cast(),
            std::mem::size_of_val(&request) as libc::socklen_t,
        )
    };
    if applied != 0 {
        grow_receive_buffer(socket, requested);
    }
}

#[cfg(target_os = "linux")]
fn grow_receive_buffer(socket: &UdpSocket, requested: usize) {
    let options = socket2::SockRef::from(socket);
    let Ok(current) = options.recv_buffer_size() else {
        return;
    };
    if current >= 2 * requested {
        return;
    }
    // Older kernels hide rmem_max inside child network namespaces. Measure
    // the clamped value on a fresh socket before changing the live queue.
    let capacity = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|limit| 2 * requested.min(limit))
        .or_else(|| {
            let domain = socket2::Domain::for_address(socket.local_addr().ok()?);
            let probe = socket2::Socket::new(domain, socket2::Type::DGRAM, None).ok()?;
            probe.set_recv_buffer_size(requested).ok()?;
            probe.recv_buffer_size().ok()
        });
    if capacity.is_some_and(|size| size > current) {
        let _ = options.set_recv_buffer_size(requested);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn udp_receive_tuning_preserves_larger_socket_queues() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let options = socket2::SockRef::from(&socket);
        let default = options.recv_buffer_size().unwrap();
        grow_udp_receive_buffer(&socket);
        let destination = options.recv_buffer_size().unwrap();
        assert!(destination >= default);
        grow_udp_carrier_receive_buffer(&socket);
        let carrier = options.recv_buffer_size().unwrap();
        assert!(carrier >= destination);
        grow_udp_carrier_receive_buffer_to(&socket, 8 * 1024 * 1024);
        let larger = options.recv_buffer_size().unwrap();
        assert!(larger >= carrier);
        grow_udp_carrier_receive_buffer(&socket);
        grow_udp_receive_buffer(&socket);
        assert_eq!(options.recv_buffer_size().unwrap(), larger);
    }
}

#[cfg(target_os = "linux")]
pub trait ConnectedDatagrams: Send {
    fn descriptor(&self) -> std::os::fd::BorrowedFd<'_>;

    /// Flush pending requests and drain ready replies. A reply is counted only
    /// if the inbound accepts it.
    fn drive(
        &mut self,
        requests: &mut std::collections::VecDeque<Vec<u8>>,
        receive: Option<&mut [u8]>,
        reply: &mut dyn FnMut(&[u8]) -> bool,
    ) -> std::io::Result<()>;
}
