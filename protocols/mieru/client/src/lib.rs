use std::io::ErrorKind;

use kerlico_mieru::{connect as dial, resolve_peer, Account, Conn, Target};
use kerlico_shared::{
    DataPlane, Destination, InboundStream, OpenError, Packet, PeerAddr, PlaneFault, Settings,
};

struct IdlePlane;

impl DataPlane for IdlePlane {
    fn send(&mut self, _packet: Packet) -> Result<(), PlaneFault> {
        Err(PlaneFault::Transport)
    }

    fn recv(&mut self) -> Result<Packet, PlaneFault> {
        Err(PlaneFault::Transport)
    }
}

pub fn connect(
    _peer: &PeerAddr,
    _settings: &Settings,
) -> Result<Box<dyn DataPlane>, OpenError> {
    Ok(Box::new(IdlePlane))
}

pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    destination: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    let conn = open_stream(host, port, settings, destination.host(), destination.port())?;
    Ok(Box::new(Relay(conn)))
}

struct Relay(Conn);

impl InboundStream for Relay {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        match self.0.read_user(buf) {
            Ok(0) => Err(PlaneFault::Closed),
            Ok(n) => Ok(n),
            Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {
                Err(PlaneFault::Again)
            }
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => Err(PlaneFault::Closed),
            Err(_) => Err(PlaneFault::Transport),
        }
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.0.write_user(buf).map_err(|_| PlaneFault::Transport)?;
        Ok(buf.len())
    }
}

pub fn open_stream(host: &str, port: u16, settings: &Settings, destination_host: &str, destination_port: u16) -> Result<Conn, OpenError> {
    let username = settings.text("username")?.to_string();
    let password = settings.text("password")?.to_string();
    let peer = resolve_peer(host, port).map_err(|_| OpenError::Transport)?;
    dial(
        peer,
        &Account { username, password },
        &Target {
            host: destination_host.to_string(),
            port: destination_port,
        },
    )
    .map_err(|_| OpenError::Transport)
}
