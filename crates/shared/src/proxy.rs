//! What a client protocol crate gives the client leaf. The leaf owns the local SOCKS5 and HTTP
//! entry; a proxy protocol only opens streams and UDP associations behind it.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::{DataPlane, OpenError, PeerAddr, Settings};

/// One validated client document of a proxy protocol. `close` is idempotent and cancels every
/// stream and association it opened.
pub trait Upstream: Send + Sync {
    fn open_stream(&self, host: &str, port: u16) -> io::Result<Box<dyn Stream>>;
    fn associate(&self) -> io::Result<Box<dyn Association>>;
    fn close(&self);
}

/// One TCP flow to a target. `read_for` returns `TimedOut` or `WouldBlock` when nothing arrived
/// within `wait`, and `Ok(0)` or `UnexpectedEof` at the end of the flow.
pub trait Stream: Send + Sync {
    fn read_for(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize>;
    fn write_all(&self, buf: &[u8]) -> io::Result<()>;
    fn close(&self);
}

/// One SOCKS5 UDP association. `source` is the local application's UDP address, the same for
/// every datagram of the association. A datagram the protocol refuses is dropped with `Ok`;
/// `Err` from either call means the association is finished. `recv_for` gives one whole datagram
/// and the address it came from, or `TimedOut` when none arrived within `wait`.
pub trait Association: Send + Sync {
    fn send_to(&self, source: SocketAddr, host: &str, port: u16, payload: &[u8]) -> io::Result<()>;
    fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)>;
    fn close(&self);
}

pub type TunnelFn = fn(&PeerAddr, &Settings) -> Result<Box<dyn DataPlane>, OpenError>;
pub type ProxyFn = fn(&PeerAddr, &Settings) -> Result<Arc<dyn Upstream>, OpenError>;

/// The one thing a client protocol crate exports to the client leaf, as `CLIENT`. A protocol is a
/// packet tunnel or a proxy behind the local entry, never both.
#[derive(Clone, Copy)]
pub enum ClientEntry {
    Tunnel(TunnelFn),
    Proxy(ProxyFn),
}
