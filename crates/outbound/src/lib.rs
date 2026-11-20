//! The only server egress. Inbound nodes hand off a flow. They do not pick an exit.

mod copy;
mod async_copy;
mod native;
mod network;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kerlico_shared::{
    Destination, Handoff, InboundStream, OpenError, PlaneFault, Settings, Traffic, Transport,
};

pub use native::{BytePipe, Native, PacketDevice};
pub use network::{
    connect_system_peer,
    connect_system_tcp, lookup_system_addresses, open_system_datagram, open_tunnel_datagram,
    open_tunnel_datagram_at,
};
#[cfg(feature = "system-dns")]
pub use network::exchange_system_dns;

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

pub type LandFn =
    fn(&str, u16, &Settings, &Destination) -> Result<Box<dyn InboundStream>, OpenError>;

/// One outbound module for every inbound on this process.
#[derive(Clone)]
pub struct Outbound {
    warp: Arc<native::WarpSlot>,
    landing: Arc<Mutex<Option<Landing>>>,
    datagrams: Arc<native_session::Sessions>,
}

mod datagram_mux;
mod association_session;
mod native_session;

#[derive(Clone)]
struct Landing {
    dial: kerlico_shared::ReverseDial,
    udp: Option<Arc<association_session::AssociationSessions>>,
}

/// Runtime callbacks do not keep the egress owner or its landing alive.
#[derive(Clone)]
pub struct WeakOutbound {
    warp: std::sync::Weak<native::WarpSlot>,
    landing: std::sync::Weak<Mutex<Option<Landing>>>,
    datagrams: std::sync::Weak<native_session::Sessions>,
}

impl WeakOutbound {
    pub fn upgrade(&self) -> Option<Outbound> {
        Some(Outbound { warp: self.warp.upgrade()?, landing: self.landing.upgrade()?, datagrams: self.datagrams.upgrade()? })
    }
}

impl Outbound {
    pub fn downgrade(&self) -> WeakOutbound {
        WeakOutbound { warp: Arc::downgrade(&self.warp), landing: Arc::downgrade(&self.landing), datagrams: Arc::downgrade(&self.datagrams) }
    }
    pub fn new() -> Self {
        Self {
            warp: Arc::new(native::WarpSlot::empty()),
            landing: Arc::new(Mutex::new(None)),
            datagrams: Arc::new(native_session::Sessions::default()),
        }
    }

    pub fn install_landing(&self, land: LandFn, host: String, port: u16, settings: Settings) {
        self.set_landing(land, host, port, settings, None);
    }

    pub fn install_landing_entry(&self, land: LandFn, entry: kerlico_shared::ClientEntry, host: String, port: u16, settings: Settings) {
        let udp = match entry {
            kerlico_shared::ClientEntry::ProxyWithDatagramLanding(open) => {
                Some(Arc::new(association_session::AssociationSessions::new(open, host.clone(), port, settings.clone())))
            }
            kerlico_shared::ClientEntry::PacketTunnel(_, _, associate) => {
                let (host, settings) = (host.clone(), settings.clone());
                Some(Arc::new(association_session::AssociationSessions::with_opener(move || associate(&host, port, &settings))))
            }
            _ => None,
        };
        self.set_landing(land, host, port, settings, udp);
    }

    fn set_landing(&self, land: LandFn, host: String, port: u16, settings: Settings, udp: Option<Arc<association_session::AssociationSessions>>) {
        let dial = Arc::new(move |destination: &Destination| land(&host, port, &settings, destination));
        *self.landing.lock().expect("landing") = Some(Landing { dial, udp });
    }

    fn landing_dial(&self) -> Option<kerlico_shared::ReverseDial> {
        self.landing.lock().expect("landing").as_ref().map(|landing| landing.dial.clone())
    }

    pub fn install_reverse_landing(&self, dial: kerlico_shared::ReverseDial) {
        *self.landing.lock().expect("landing") = Some(Landing { dial, udp: None });
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
        self.dispatch_inner(handoff, exit, target, traffic, false)
    }

    /// Moves eligible native flows to their I/O executor. Other
    /// flows finish on the caller, which already owns their preparation thread.
    pub fn dispatch_on_executor(
        &self,
        handoff: Handoff,
        exit: Exit,
        target: DialTarget,
        traffic: &dyn Traffic,
    ) -> Result<(), OpenError> {
        self.dispatch_inner(handoff, exit, target, traffic, true)
    }

    fn dispatch_inner(
        &self,
        handoff: Handoff,
        exit: Exit,
        target: DialTarget,
        traffic: &dyn Traffic,
        detached: bool,
    ) -> Result<(), OpenError> {
        let user = handoff.user().clone();
        let node = handoff.node().clone();
        let destination = handoff.destination().clone();
        let datagram_session = handoff.datagram_session().cloned();
        let peer = handoff.peer();
        let stream = handoff.stream();
        match exit {
            Exit::NativeV4 | Exit::NativeV6 if target.transport == kerlico_shared::Transport::Udp && datagram_session.is_some() => {
                self.datagrams.dial(datagram_session.expect("UDP session"), &target, stream.as_ref(), copy::Flow {
                    user: &user, node: &node, exit, traffic, transport: kerlico_shared::Transport::Udp,
                }, detached)
            }
            Exit::NativeV4 | Exit::NativeV6 => {
                native::dial_native(&target, stream, &user, &node, exit, traffic, detached)
            }
            Exit::WarpV4 | Exit::WarpV6 => {
                if target.transport == Transport::Udp {
                    if let (Some(session), Some(sessions)) = (datagram_session, self.warp.associations(exit.is_v4())) {
                        let remote = target.addresses.iter().find(|address| address.is_ipv4() == exit.is_v4());
                        let destination = remote.and_then(|address| Destination::new(address.ip().to_string(), address.port(), Transport::Udp).ok());
                        let Some(destination) = destination else {
                            return copy::report_connect(stream.as_ref(), Err(OpenError::Transport));
                        };
                        return sessions.dial(session, peer, &destination, stream.as_ref(), copy::Flow {
                            user: &user, node: &node, exit, traffic, transport: Transport::Udp,
                        });
                    }
                }
                native::dial_warp(&self.warp, &target, stream.as_ref(), &user, &node, exit, traffic)
            }
            Exit::Landing => {
                self.dial_landing(&destination, stream.as_ref(), datagram_session, peer, &user, &node, traffic)
            }
        }
    }

    fn dial_landing(
        &self,
        destination: &Destination,
        stream: &dyn InboundStream,
        datagram_session: Option<Arc<kerlico_shared::DatagramSession>>,
        peer: Option<SocketAddr>,
        user: &kerlico_shared::UserEmail,
        node: &kerlico_shared::NodeTag,
        traffic: &dyn Traffic,
    ) -> Result<(), OpenError> {
        let installed = self
            .landing
            .lock()
            .expect("landing")
            .clone()
            .ok_or(OpenError::Transport);
        let flow = copy::Flow { user, node, exit: Exit::Landing, traffic, transport: destination.transport() };
        let landing = installed.inspect_err(|error| { let _ = stream.report_connect(Err(error.clone())); })?;
        if destination.transport() == kerlico_shared::Transport::Udp {
            if let (Some(session), Some(udp)) = (datagram_session, landing.udp) {
                return udp.dial(session, peer, destination, stream, flow);
            }
        }
        let remote = copy::report_connect_with(stream, (landing.dial)(destination), |remote| remote.connect_bound())?;
        let remote: Arc<dyn InboundStream> = Arc::from(remote);
        copy::bridge(
            stream,
            RemoteWrite {
                stream: remote.clone(),
                transport: destination.transport(),
            },
            RemoteRead {
                stream: remote,
                transport: destination.transport(),
            },
            flow,
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
            Exit::Landing => true,
        };
        if !family_ok {
            return Err(OpenError::Transport);
        }
        match exit {
            Exit::NativeV4 | Exit::NativeV6 => native::exchange_native(peer, tcp, request),
            Exit::WarpV4 | Exit::WarpV6 => native::exchange_warp(&self.warp, peer, tcp, request),
            Exit::Landing => {
                let dial = self.landing_dial().ok_or(OpenError::Transport)?;
                dns_landing::exchange(dial, peer, tcp, request)
            }
        }
    }
}

mod dns_landing;

struct RemoteRead {
    stream: Arc<dyn InboundStream>,
    transport: Transport,
}

impl copy::PipeRead for RemoteRead {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<copy::ReadEvent, OpenError> {
        match self.stream.read_from_user(buf) {
            Ok(0) if self.transport == Transport::Tcp => Ok(copy::ReadEvent::Eof),
            Ok(n) => Ok(copy::ReadEvent::Data(n)),
            Err(PlaneFault::Again) => Err(OpenError::Again),
            Err(PlaneFault::Closed) => Ok(copy::ReadEvent::Eof),
            Err(PlaneFault::Transport) => Err(OpenError::Transport),
        }
    }
}

struct RemoteWrite {
    stream: Arc<dyn InboundStream>,
    transport: Transport,
}

impl copy::PipeWrite for RemoteWrite {
    fn finish(&mut self) -> Result<(), OpenError> {
        if self.transport == Transport::Tcp {
            self.stream.finish_to_user().map_err(|_| OpenError::Transport)?;
        }
        Ok(())
    }

    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError> {
        if self.transport == Transport::Udp {
            return if self
                .stream
                .write_to_user(buf)
                .map_err(|_| OpenError::Transport)?
                == buf.len()
            {
                Ok(())
            } else {
                Err(OpenError::Transport)
            };
        }
        let mut sent = 0;
        while sent < buf.len() {
            match self.stream.write_to_user(&buf[sent..]) {
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
                Native {
                    v4: false,
                    v6: true
                }
            ),
            Ok(Exit::WarpV4)
        );
        assert_eq!(
            select_exit(
                OutboundChoice::Default,
                Reachability::V6Only,
                Native {
                    v4: true,
                    v6: false
                }
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
        let native = Native {
            v4: false,
            v6: false,
        };
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
