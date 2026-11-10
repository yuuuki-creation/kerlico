use kerlico_shared::{
    ClientEntry, DataPlane, Destination, InboundStream, OpenError, Packet, PeerAddr, PlaneFault,
    Settings,
};

pub const CLIENT: ClientEntry = ClientEntry::Tunnel(connect);

struct OpenvpnPlane;

impl DataPlane for OpenvpnPlane {
    fn send(&mut self, packet: Packet) -> Result<(), PlaneFault> {
        let _ = packet;
        unimplemented!("openvpn send")
    }

    fn recv(&mut self) -> Result<Packet, PlaneFault> {
        unimplemented!("openvpn recv")
    }
}

pub fn connect(
    peer: &PeerAddr,
    settings: &Settings,
) -> Result<Box<dyn DataPlane>, OpenError> {
    let _ = (peer, settings, OpenvpnPlane, kerlico_openvpn::label());
    unimplemented!("openvpn connect")
}

pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    destination: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    let _ = (host, port, settings, destination);
    unimplemented!("openvpn land")
}
