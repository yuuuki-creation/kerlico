//! Client leaf. Protocol crates stay behind the generated registry.

use kerlico_shared::{
    AddrError, DocError, IdError, OpenError, Packet, PacketError, PeerAddr, PlaneFault, ProtocolId,
    Settings,
};

mod gen {
    include!(concat!(env!("OUT_DIR"), "/registry.rs"));
}

/// Proof that `id` is in this build's client registry.
pub struct ClientConfig {
    id: ProtocolId,
    peer: PeerAddr,
    settings: Settings,
    connect: gen::ConnectFn,
}

/// Client leaf failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Config,
    Connect,
    Packet,
    Plane,
}

impl From<DocError> for Error {
    fn from(_: DocError) -> Self {
        Self::Config
    }
}

impl From<IdError> for Error {
    fn from(_: IdError) -> Self {
        Self::Config
    }
}

impl From<AddrError> for Error {
    fn from(_: AddrError) -> Self {
        Self::Config
    }
}

impl From<PacketError> for Error {
    fn from(_: PacketError) -> Self {
        Self::Packet
    }
}

impl From<OpenError> for Error {
    fn from(_: OpenError) -> Self {
        Self::Connect
    }
}

impl From<PlaneFault> for Error {
    fn from(_: PlaneFault) -> Self {
        Self::Plane
    }
}

impl ClientConfig {
    /// Parses the document, requires `peer`, and keeps the registry entry whose id equals `protocol`.
    pub fn parse(document: &str) -> Result<Self, Error> {
        let _ = document;
        let _ = gen::REGISTRY;
        unimplemented!("client config parse")
    }

    pub fn id(&self) -> ProtocolId {
        self.id
    }
}

pub struct Client;

impl Client {
    /// Enabled protocol ids, in id order.
    pub fn compiled() -> &'static [ProtocolId] {
        gen::COMPILED
    }

    /// Calls the function pointer stored on `config`.
    pub fn connect(config: &ClientConfig) -> Result<Session, Error> {
        let _ = (config.id, &config.peer, &config.settings, config.connect);
        unimplemented!("client connect")
    }
}

/// One client session. Drop releases the data plane.
pub struct Session {
    plane: Box<dyn kerlico_shared::DataPlane>,
}

impl Session {
    pub fn send(&mut self, packet: Packet) -> Result<(), Error> {
        let _ = packet;
        let _ = &self.plane;
        unimplemented!("client send")
    }

    pub fn recv(&mut self) -> Result<Packet, Error> {
        let _ = &self.plane;
        unimplemented!("client recv")
    }
}
