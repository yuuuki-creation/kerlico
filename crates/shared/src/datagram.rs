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
    const REQUESTED: usize = 512 * 1024;
    let options = socket2::SockRef::from(socket);
    let limit = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok());
    // Linux doubles the capped SO_RCVBUF value when accounting for packets.
    // Preserve an administrator's larger default when rmem_max is lower.
    if let (Some(limit), Ok(current)) = (limit, options.recv_buffer_size()) {
        let requested = REQUESTED.min(limit);
        if requested.saturating_mul(2) > current {
            let _ = options.set_recv_buffer_size(requested);
        }
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
