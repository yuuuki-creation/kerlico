use kerlico_shared::{
    ClientEntry, DataPlane, Destination, InboundStream, OpenError, Packet, PeerAddr, PlaneFault,
    Settings,
};

pub const CLIENT: ClientEntry = ClientEntry::Tunnel(connect);

struct WireguardPlane;

impl DataPlane for WireguardPlane {
    fn send(&mut self, packet: Packet) -> Result<(), PlaneFault> {
        let _ = packet;
        unimplemented!("wireguard send")
    }

    fn recv(&mut self) -> Result<Packet, PlaneFault> {
        unimplemented!("wireguard recv")
    }
}

pub fn connect(
    peer: &PeerAddr,
    settings: &Settings,
) -> Result<Box<dyn DataPlane>, OpenError> {
    let _ = (peer, settings, WireguardPlane, kerlico_wireguard::label());
    unimplemented!("wireguard connect")
}

pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    destination: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    let _ = (host, port, settings, destination);
    unimplemented!("wireguard land")
}
