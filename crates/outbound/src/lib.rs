//! The only server egress. Inbound nodes hand off a flow. They do not pick an exit.

mod copy;
mod native;
mod network;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kerlico_shared::{Destination, Handoff, InboundStream, OpenError, PlaneFault, Settings, Traffic, Transport};

pub use native::{BytePipe, Native, PacketDevice};

pub use kerlico_shared::{Exit, OutboundChoice};

/// What DNS, or an address literal, said about the destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reachability {
    /// At least one IPv4. AAAA may also exist.
    HasV4,
    /// IPv6 addresses only.
    V6Only,
    /// The name produced no address.
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectError {
    NoAddress,
}

/// Manual choice wins. The default prefers v4, and uses v6 only when the destination has no IPv4.
/// A missing native family for that choice becomes the same family's WARP exit.
pub fn select_exit(
    choice: OutboundChoice,
    reach: Reachability,
    native: Native,
) -> Result<Exit, SelectError> {
    match choice {
        OutboundChoice::Manual(exit) => Ok(exit),
        OutboundChoice::Default => match reach {
            Reachability::HasV4 => Ok(if native.v4 {
                Exit::NativeV4
            } else {
                Exit::WarpV4
            }),
            Reachability::V6Only => Ok(if native.v6 {
                Exit::NativeV6
            } else {
                Exit::WarpV6
            }),
            Reachability::None => Err(SelectError::NoAddress),
        },
    }
}

/// Addresses the chosen exit will dial. Landing keeps the original host name.
#[derive(Clone, Debug)]
pub struct DialTarget {
    pub host: String,
    pub port: u16,
    pub transport: Transport,
    pub addresses: Vec<SocketAddr>,
}

impl DialTarget {
    pub fn from_destination(destination: &Destination, addresses: Vec<SocketAddr>) -> Self {
        Self {
            host: destination.host().to_string(),
            port: destination.port(),
            transport: destination.transport(),
            addresses,
        }
    }
}

pub type LandFn = fn(&str, u16, &Settings, &Destination) -> Result<Box<dyn InboundStream>, OpenError>;

/// One outbound module for every inbound on this process.
#[derive(Clone)]
pub struct Outbound {
    warp: Arc<native::WarpSlot>,
    landing: Arc<Mutex<Option<kerlico_shared::ReverseDial>>>,
}

/// Runtime callbacks do not keep the egress owner or its landing alive.
#[derive(Clone)]
pub struct WeakOutbound {
    warp: std::sync::Weak<native::WarpSlot>,
    landing: std::sync::Weak<Mutex<Option<kerlico_shared::ReverseDial>>>,
}

impl WeakOutbound {
    pub fn upgrade(&self) -> Option<Outbound> {
        Some(Outbound { warp: self.warp.upgrade()?, landing: self.landing.upgrade()? })
    }
}

impl Outbound {
    pub fn downgrade(&self) -> WeakOutbound {
        WeakOutbound { warp: Arc::downgrade(&self.warp), landing: Arc::downgrade(&self.landing) }
    }
    pub fn new() -> Self {
        Self {
            warp: Arc::new(native::WarpSlot::empty()),
            landing: Arc::new(Mutex::new(None)),
        }
    }

    pub fn install_landing(&self, land: LandFn, host: String, port: u16, settings: Settings) {
        *self.landing.lock().expect("landing") = Some(Arc::new(move |destination| land(&host, port, &settings, destination)));
    }

    pub fn install_reverse_landing(&self, dial: kerlico_shared::ReverseDial) {
        *self.landing.lock().expect("landing") = Some(dial);
    }

    pub fn install_warp(&self, device: Arc<dyn native::PacketDevice>) {
        self.warp.install(device);
    }

    /// Dials `exit` once and copies bytes until the flow ends.
    /// A dial failure does not switch to another exit.
    pub fn dispatch(
        &self,
        handoff: Handoff,
        exit: Exit,
        target: DialTarget,
        traffic: &dyn Traffic,
    ) -> Result<(), OpenError> {
        let user = handoff.user().clone();
        let node = handoff.node().clone();
        let destination = handoff.destination().clone();
        let stream = handoff.stream();
        match exit {
            Exit::NativeV4 | Exit::NativeV6 => {
                native::dial_native(&target, &stream, &user, &node, exit, traffic)
            }
            Exit::WarpV4 | Exit::WarpV6 => {
                native::dial_warp(&self.warp, &target, &stream, &user, &node, exit, traffic)
            }
            Exit::Landing => self.dial_landing(&destination, &stream, &user, &node, traffic),
        }
    }

    fn dial_landing(
        &self,
        destination: &Destination,
        stream: &Box<dyn InboundStream>,
        user: &kerlico_shared::UserEmail,
        node: &kerlico_shared::NodeTag,
        traffic: &dyn Traffic,
    ) -> Result<(), OpenError> {
        let installed = self
            .landing
            .lock()
            .expect("landing")
            .clone()
            .ok_or(OpenError::Transport)?;
        let remote = installed(destination)?;
        let remote: Arc<dyn InboundStream> = Arc::from(remote);
        copy::bridge(
            stream.as_ref(),
            RemoteWrite(remote.clone()),
            RemoteRead(remote),
            user,
            node,
            Exit::Landing,
            traffic,
        )
    }

    /// One request and one response on the chosen exit. DNS uses this. A user flow does not.
    pub fn exchange(
        &self,
        exit: Exit,
        peer: SocketAddr,
        tcp: bool,
        request: &[u8],
    ) -> Result<Vec<u8>, OpenError> {
        let family_ok = match exit {
            Exit::NativeV4 | Exit::WarpV4 => peer.is_ipv4(),
            Exit::NativeV6 | Exit::WarpV6 => peer.is_ipv6(),
            Exit::Landing => false,
        };
        if !family_ok {
            return Err(OpenError::Transport);
        }
        match exit {
            Exit::NativeV4 | Exit::NativeV6 => native::exchange_native(peer, tcp, request),
            Exit::WarpV4 | Exit::WarpV6 => native::exchange_warp(&self.warp, peer, tcp, request),
            Exit::Landing => Err(OpenError::Transport),
        }
    }
}

struct RemoteRead(Arc<dyn InboundStream>);

impl copy::PipeRead for RemoteRead {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<usize, OpenError> {
        match self.0.read_from_user(buf) {
            Ok(n) => Ok(n),
            Err(PlaneFault::Again) => Err(OpenError::Again),
            Err(PlaneFault::Closed) => Ok(0),
            Err(PlaneFault::Transport) => Err(OpenError::Transport),
        }
    }
}

struct RemoteWrite(Arc<dyn InboundStream>);

impl copy::PipeWrite for RemoteWrite {
    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError> {
        let mut sent = 0;
        while sent < buf.len() {
            match self.0.write_to_user(&buf[sent..]) {
                Ok(0) => return Err(OpenError::Transport),
                Ok(n) => sent += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(5)),
                Err(_) => return Err(OpenError::Transport),
            }
        }
        Ok(())
    }
}

impl Default for Outbound {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefers_native_v4_and_switches_for_v6_only() {
        let native = Native { v4: true, v6: true };
        assert_eq!(
            select_exit(OutboundChoice::Default, Reachability::HasV4, native),
            Ok(Exit::NativeV4)
        );
        assert_eq!(
            select_exit(OutboundChoice::Default, Reachability::V6Only, native),
            Ok(Exit::NativeV6)
        );
        assert_eq!(
            select_exit(OutboundChoice::Default, Reachability::None, native),
            Err(SelectError::NoAddress)
        );
    }

    #[test]
    fn missing_native_uses_the_same_family_warp() {
        assert_eq!(
            select_exit(
                OutboundChoice::Default,
                Reachability::HasV4,
                Native { v4: false, v6: true }
            ),
            Ok(Exit::WarpV4)
        );
        assert_eq!(
            select_exit(
                OutboundChoice::Default,
                Reachability::V6Only,
                Native { v4: true, v6: false }
            ),
            Ok(Exit::WarpV6)
        );
    }

    #[test]
    fn native_exchange_round_trips_one_udp_payload() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut buf = [0u8; 32];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            socket.send_to(&buf[..n], from).unwrap();
        });
        let outbound = Outbound::new();
        let got = outbound
            .exchange(Exit::NativeV4, peer, false, b"dns")
            .unwrap();
        assert_eq!(got, b"dns");
        server.join().unwrap();
    }

    #[test]
    fn manual_exit_does_not_switch() {
        let native = Native { v4: false, v6: false };
        assert_eq!(
            select_exit(
                OutboundChoice::Manual(Exit::WarpV4),
                Reachability::V6Only,
                native
            ),
            Ok(Exit::WarpV4)
        );
        assert_eq!(
            select_exit(
                OutboundChoice::Manual(Exit::Landing),
                Reachability::HasV4,
                native
            ),
            Ok(Exit::Landing)
        );
    }
}
