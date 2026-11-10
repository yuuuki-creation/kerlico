//! Client leaf. Protocol crates stay behind the generated registry. A proxy protocol runs behind
//! the one local SOCKS5 and HTTP entry in `proxy`.

use kerlico_shared::{
    AddrError, ClientEntry, DocError, Document, IdError, OpenError, Packet, PacketError, PeerAddr,
    PlaneFault, ProtocolId, ProxyFn, Settings, TunnelFn,
};

mod proxy;
pub use proxy::{LocalEntry, Proxy};

mod gen {
    include!(concat!(env!("OUT_DIR"), "/registry.rs"));
}

/// A document whose protocol is in this build's client registry, with its settings checked
/// against the kind of entry the protocol has.
pub struct ClientConfig {
    id: ProtocolId,
    peer: PeerAddr,
    settings: Settings,
    run: Run,
}

enum Run {
    Tunnel(TunnelFn),
    Proxy(ProxyFn, LocalEntry),
}

/// Client leaf failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Config,
    /// The document names a protocol this build does not include.
    NotCompiled(String),
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
    /// Parses the document and keeps the registry entry whose id equals `protocol`. `pinned`
    /// stands in for an absent `protocol` and must equal a present one.
    pub fn parse(document: &str, pinned: Option<&str>) -> Result<Self, Error> {
        let (protocol, peer, mut settings) = Document::parse(document)?.into_parts();
        let name = match (protocol.as_deref(), pinned) {
            (Some(named), Some(pinned)) if named != pinned => return Err(Error::Config),
            (Some(named), _) => named,
            (None, Some(pinned)) => pinned,
            (None, None) => return Err(Error::Config),
        };
        let registration = gen::REGISTRY
            .iter()
            .find(|registration| registration.id.as_str() == name)
            .ok_or_else(|| Error::NotCompiled(name.to_string()))?;
        let run = match registration.entry {
            ClientEntry::Tunnel(connect) => Run::Tunnel(connect),
            ClientEntry::Proxy(open) => {
                Run::Proxy(open, LocalEntry::take(&mut settings).map_err(|_| Error::Config)?)
            }
        };
        Ok(Self { id: registration.id, peer, settings, run })
    }

    pub fn id(&self) -> ProtocolId {
        self.id
    }
}

pub struct Client;

/// What `Client::start` runs: the local entry of a proxy protocol, or a tunnel's data plane.
pub enum Running {
    Proxy(Proxy),
    Tunnel(Session),
}

impl Client {
    /// Enabled protocol ids, in id order.
    pub fn compiled() -> &'static [ProtocolId] {
        gen::COMPILED
    }

    /// Opens the protocol and, for a proxy protocol, binds the local entry.
    pub fn start(config: ClientConfig) -> Result<Running, Error> {
        match config.run {
            Run::Proxy(open, entry) => {
                let upstream = open(&config.peer, &config.settings)?;
                Ok(Running::Proxy(Proxy::start(upstream, &entry)?))
            }
            Run::Tunnel(connect) => Ok(Running::Tunnel(Session {
                plane: connect(&config.peer, &config.settings)?,
            })),
        }
    }
}

/// One client tunnel session. Drop releases the data plane.
pub struct Session {
    plane: Box<dyn kerlico_shared::DataPlane>,
}

impl Session {
    pub fn send(&mut self, packet: Packet) -> Result<(), Error> {
        Ok(self.plane.send(packet)?)
    }

    pub fn recv(&mut self) -> Result<Packet, Error> {
        Ok(self.plane.recv()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_protocol_outside_the_build_is_named() {
        let document = r#"{"protocol":"absent-test","peer":"127.0.0.1:2000","settings":{}}"#;
        assert_eq!(
            ClientConfig::parse(document, None).err(),
            Some(Error::NotCompiled("absent-test".into()))
        );
        assert_eq!(ClientConfig::parse(document, Some("mieru")).err(), Some(Error::Config));
        let unnamed = r#"{"peer":"127.0.0.1:2000","settings":{}}"#;
        assert_eq!(ClientConfig::parse(unnamed, None).err(), Some(Error::Config));
    }
}
