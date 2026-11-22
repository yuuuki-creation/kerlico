use std::{io, sync::Arc, time::Duration};

use kerlico_openvpn::{Carrier, Session, TcpCarrier, UdpCarrier};
use kerlico_outbound::{connect_system_tcp, lookup_system_addresses};
use kerlico_shared::runtime::NetworkConnection;
use kerlico_shared::{
    ClientEntry, DataPlane, OpenError, Packet, PeerAddr, PlaneFault, Settings, Transport,
};

#[cfg(unix)]
pub const CLIENT: ClientEntry = ClientEntry::TunnelWithTun(connect, run_tun);
#[cfg(not(unix))]
pub const CLIENT: ClientEntry = ClientEntry::Tunnel(connect);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn connect(peer: &PeerAddr, settings: &Settings) -> Result<Box<dyn DataPlane>, OpenError> {
    Ok(Box::new(OpenvpnPlane(open(peer, settings)?)))
}

fn open(peer: &PeerAddr, settings: &Settings) -> Result<Session, OpenError> {
    if settings.keys().any(|key| {
        !matches!(
            key,
            "ca" | "certificate" | "privateKey" | "serverName" | "transport"
        )
    }) {
        return Err(OpenError::Settings);
    }
    let tls = kerlico_openvpn::client_tls(
        settings.text("ca")?,
        settings.text("certificate")?,
        settings.text("privateKey")?,
    )
    .map_err(|_| OpenError::Settings)?;
    let server_name = settings.optional_text("serverName")?.unwrap_or(peer.host());
    let carrier: Box<dyn Carrier> = match settings.optional_text("transport")?.unwrap_or("udp") {
        "tcp" => Box::new(
            connect_system_tcp(peer.host(), peer.port(), CONNECT_TIMEOUT)
                .and_then(TcpCarrier::new)
                .map_err(|_| OpenError::Transport)?,
        ),
        "udp" => {
            let addresses = lookup_system_addresses(peer.host(), peer.port())
                .map_err(|_| OpenError::Transport)?;
            let socket = addresses
                .into_iter()
                .find_map(|address| {
                    match kerlico_outbound::connect_system_peer(
                        address,
                        Transport::Udp,
                        CONNECT_TIMEOUT,
                    )
                    .ok()?
                    {
                        NetworkConnection::Udp(socket) => Some(socket),
                        _ => None,
                    }
                })
                .ok_or(OpenError::Transport)?;
            #[cfg(target_os = "linux")]
            kerlico_shared::grow_udp_carrier_receive_buffer(&socket);
            Box::new(UdpCarrier::new(socket).map_err(|_| OpenError::Transport)?)
        }
        _ => return Err(OpenError::Settings),
    };
    kerlico_openvpn::client(carrier, Arc::new(tls), server_name).map_err(|error| {
        eprintln!("OpenVPN: {error}");
        OpenError::Transport
    })
}

struct OpenvpnPlane(Session);

impl DataPlane for OpenvpnPlane {
    fn send(&mut self, packet: Packet) -> Result<(), PlaneFault> {
        self.0.send(packet.as_bytes()).map_err(fault)
    }

    fn recv(&mut self) -> Result<Packet, PlaneFault> {
        let packet = self.0.receive().map_err(fault)?.ok_or(PlaneFault::Again)?;
        Packet::from_ip_packet(packet).map_err(|_| PlaneFault::Transport)
    }
}

fn fault(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => PlaneFault::Again,
        io::ErrorKind::TimedOut
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

#[cfg(unix)]
fn run_tun(peer: &PeerAddr, settings: &Settings, interface: &str) -> Result<(), OpenError> {
    let mut session = open(peer, settings)?;
    let tunnel = session.tunnel();
    let result = (|| -> io::Result<()> {
        let destination = if cfg!(target_os = "macos") {
            tunnel.gateway
        } else {
            None
        };
        let device = tun_rs::DeviceBuilder::new()
            .name(interface)
            .mtu(tunnel.mtu)
            .ipv4(tunnel.address, tunnel.netmask, destination)
            .enable(true)
            .build_sync()?;
        device.set_nonblocking(true)?;
        let mut input = vec![0; usize::from(tunnel.mtu) + 1];
        loop {
            for _ in 0..64 {
                match device.recv(&mut input) {
                    Ok(0) => return Ok(()),
                    Ok(n) if n <= usize::from(tunnel.mtu) => session.send(&input[..n])?,
                    Ok(_) => continue,
                    Err(error) if kerlico_openvpn::retry(&error) => break,
                    Err(error) => return Err(error),
                }
            }
            if let Some(packet) = session.receive()? {
                match device.send(&packet) {
                    Ok(n) if n == packet.len() => {}
                    Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                    Err(error) if kerlico_openvpn::retry(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    })();
    result.map_err(|error| {
        eprintln!("OpenVPN TUN: {error}");
        OpenError::Transport
    })
}
