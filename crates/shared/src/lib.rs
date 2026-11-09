//! Domain types for both roles.
//! This crate has no role feature and no dependency on a role crate.

use std::net::SocketAddr;

pub mod runtime;
mod egress;
pub use egress::{Exit, OutboundChoice};

/// Grammar-checked protocol id.
/// The text is one or more `[a-z0-9]+` segments separated by single hyphens.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolId(&'static str);

/// The static text failed the protocol-id grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdError;

impl ProtocolId {
    /// Checks the id grammar. Leaf config checks registry membership.
    pub const fn from_static(name: &'static str) -> Result<Self, IdError> {
        if valid_id(name) {
            Ok(Self(name))
        } else {
            Err(IdError)
        }
    }

    /// Same grammar as `from_static`. Panics when `name` is not a protocol id.
    pub const fn must(name: &'static str) -> Self {
        match Self::from_static(name) {
            Ok(id) => id,
            Err(IdError) => panic!("protocol id grammar"),
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

const fn valid_id(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut index = 0;
    let mut segment = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'-' {
            if segment == 0 {
                return false;
            }
            segment = 0;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            segment += 1;
        } else {
            return false;
        }
        index += 1;
    }
    segment != 0
}

/// Host string and port of a remote peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAddr {
    host: String,
    port: u16,
}

/// Host string and port a server listens on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindAddr {
    host: String,
    port: u16,
}

/// One inbound listen address. A node is v4 or v6, never both.
/// The v6 arm is opened with `IPV6_V6ONLY`, so `::` does not accept v4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenAddr {
    V4(std::net::SocketAddrV4),
    V6(std::net::SocketAddrV6),
}

/// Address text had no host, no port, or a port outside `u16`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddrError;

impl PeerAddr {
    pub fn parse(text: &str) -> Result<Self, AddrError> {
        let _ = text;
        unimplemented!("peer address parse")
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl ListenAddr {
    pub fn v4(addr: std::net::Ipv4Addr, port: u16) -> Result<Self, AddrError> {
        if port == 0 {
            return Err(AddrError);
        }
        Ok(Self::V4(std::net::SocketAddrV4::new(addr, port)))
    }

    pub fn v6(addr: std::net::Ipv6Addr, port: u16) -> Result<Self, AddrError> {
        if port == 0 || addr.to_ipv4_mapped().is_some() {
            return Err(AddrError);
        }
        Ok(Self::V6(std::net::SocketAddrV6::new(addr, port, 0, 0)))
    }

    pub fn socket_addr(self) -> std::net::SocketAddr {
        match self {
            Self::V4(addr) => addr.into(),
            Self::V6(addr) => addr.into(),
        }
    }
}

impl BindAddr {
    pub fn parse(text: &str) -> Result<Self, AddrError> {
        let _ = text;
        unimplemented!("bind address parse")
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Plaintext IP packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    bytes: Vec<u8>,
}

/// `from_ip_packet` rejected the buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketError;

impl Packet {
    /// Rejects an empty buffer and a version nibble other than 4 or 6.
    pub fn from_ip_packet(bytes: Vec<u8>) -> Result<Self, PacketError> {
        let _ = bytes;
        unimplemented!("ip packet check")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Settings keys for one protocol.
/// The protocol crate accepts or rejects a key when it reads this value.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    entries: std::collections::BTreeMap<String, Setting>,
    runtime: Option<std::sync::Arc<runtime::RuntimeContext>>,
}

impl PartialEq for Settings {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries && match (&self.runtime, &other.runtime) {
            (None, None) => true,
            (Some(left), Some(right)) => std::sync::Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}
impl Eq for Settings {}

/// One settings value. The TOML parser builds these values and stays private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Setting {
    Text(String),
    List(Vec<String>),
    Table(Settings),
}

/// The document was not the shared config grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DocError;

/// Failure while opening a session or accepting one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenError {
    Settings,
    Transport,
    Again,
}

/// Failure on an open data plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlaneFault {
    Closed,
    Transport,
    Again,
}

impl Settings {
    pub fn set_runtime(&mut self, runtime: std::sync::Arc<runtime::RuntimeContext>) {
        self.runtime = Some(runtime);
    }

    pub fn runtime(&self) -> Option<&std::sync::Arc<runtime::RuntimeContext>> {
        self.runtime.as_ref()
    }

    pub fn without_runtime(&self) -> Self {
        Self { entries: self.entries.clone(), runtime: None }
    }

    pub fn insert_text(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), Setting::Text(value.into()));
    }

    pub fn text(&self, key: &str) -> Result<&str, OpenError> {
        match self.entries.get(key) {
            Some(Setting::Text(value)) => Ok(value),
            _ => Err(OpenError::Settings),
        }
    }

    pub fn table(&self, key: &str) -> Result<&Settings, OpenError> {
        match self.entries.get(key) {
            Some(Setting::Table(value)) => Ok(value),
            _ => Err(OpenError::Settings),
        }
    }
}

/// Parsed config document.
/// `ClientConfig::parse` and `ServerConfig::parse` are what produce a session config.
#[derive(Clone, Debug)]
pub struct Document {
    protocol: String,
    peer: Option<String>,
    bind: Option<String>,
    settings: Settings,
}

impl Document {
    pub fn parse(text: &str) -> Result<Self, DocError> {
        let _ = text;
        unimplemented!("config document parse")
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }

    pub fn bind(&self) -> Option<&str> {
        self.bind.as_deref()
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }
}

/// Plaintext send and recv for a client tunnel. Implementors keep sockets private.
pub trait DataPlane {
    fn send(&mut self, packet: Packet) -> Result<(), PlaneFault>;
    fn recv(&mut self) -> Result<Packet, PlaneFault>;
}

/// Xray-style stats key. `>` is reserved for the `>>>` separator.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserEmail(String);

/// One inbound node on this server.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeTag(String);

/// Where the authenticated user asked to go.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    host: String,
    port: u16,
    transport: Transport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Plaintext after the inbound protocol. The outbound module is the only dialer.
/// Read and write do not share a lock, so the copy can run both at once.
pub trait InboundStream: Send + Sync {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault>;
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault>;

    /// Raw user socket once this direction has no protocol bytes left to transform.
    fn raw_read(&self) -> Option<std::net::TcpStream> {
        None
    }

    fn raw_write(&self) -> Option<std::net::TcpStream> {
        None
    }
}

/// One accepted user flow. Protocol crates build this. They do not choose an exit.
pub struct Handoff {
    node: NodeTag,
    user: UserEmail,
    destination: Destination,
    stream: Box<dyn InboundStream>,
    prefix: Vec<u8>,
    peer: Option<SocketAddr>,
}

/// Byte counters. The server owns the map. The outbound module calls this while copying.
pub trait Traffic: Send + Sync {
    fn add_uplink(&self, user: &UserEmail, node: &NodeTag, bytes: u64);
    fn add_downlink(&self, user: &UserEmail, node: &NodeTag, bytes: u64);
    fn add_exit_uplink(&self, exit: &str, bytes: u64);
    fn add_exit_downlink(&self, exit: &str, bytes: u64);
}

/// Server accept loop. `accept` returns a handoff, not a dialed socket.
pub type ReverseDial = std::sync::Arc<dyn Fn(&Destination) -> Result<Box<dyn InboundStream>, OpenError> + Send + Sync>;

pub trait Accept: Send {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError>;
    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError>;
    fn accept(&mut self) -> Result<Handoff, OpenError>;
    fn reverse_landing(&self, _tag: &str) -> Result<ReverseDial, OpenError> { Err(OpenError::Settings) }
}

impl UserEmail {
    pub fn parse(text: &str) -> Result<Self, IdError> {
        if text.is_empty() || text.contains('>') || text.chars().any(char::is_whitespace) {
            return Err(IdError);
        }
        Ok(Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl NodeTag {
    pub fn parse(text: &str) -> Result<Self, IdError> {
        if text.is_empty() || text.contains('>') || text.chars().any(char::is_whitespace) {
            return Err(IdError);
        }
        Ok(Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Destination {
    pub fn new(host: impl Into<String>, port: u16, transport: Transport) -> Result<Self, AddrError> {
        let host = host.into();
        if host.is_empty() || port == 0 {
            return Err(AddrError);
        }
        Ok(Self {
            host,
            port,
            transport,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }
}

impl Handoff {
    pub fn new(
        node: NodeTag,
        user: UserEmail,
        destination: Destination,
        stream: Box<dyn InboundStream>,
    ) -> Self {
        Self {
            node,
            user,
            destination,
            stream,
            prefix: Vec::new(),
            peer: None,
        }
    }

    /// UDP sessions are keyed by this address and the destination.
    pub fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = Some(peer);
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// FakeDNS replaces the dial target and the name later rules see.
    pub fn retarget(&mut self, host: impl Into<String>) {
        self.destination.host = host.into();
    }

    /// Reads one handshake flight and keeps those bytes for the copy loop.
    pub fn read_into_prefix(&mut self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        let n = self.stream.read_from_user(buf)?;
        self.prefix.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    pub fn node(&self) -> &NodeTag {
        &self.node
    }

    pub fn user(&self) -> &UserEmail {
        &self.user
    }

    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    pub fn stream(self) -> Box<dyn InboundStream> {
        if self.prefix.is_empty() {
            self.stream
        } else {
            Box::new(PrefixStream {
                pending: std::sync::Mutex::new(self.prefix),
                inner: self.stream,
            })
        }
    }
}

struct PrefixStream {
    pending: std::sync::Mutex<Vec<u8>>,
    inner: Box<dyn InboundStream>,
}

impl InboundStream for PrefixStream {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        let mut pending = self.pending.lock().expect("prefix");
        if pending.is_empty() {
            drop(pending);
            return self.inner.read_from_user(buf);
        }
        let n = pending.len().min(buf.len());
        buf[..n].copy_from_slice(&pending[..n]);
        pending.drain(..n);
        Ok(n)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.inner.write_to_user(buf)
    }

    fn raw_read(&self) -> Option<std::net::TcpStream> {
        if !self.pending.lock().expect("prefix").is_empty() {
            return None;
        }
        self.inner.raw_read()
    }

    fn raw_write(&self) -> Option<std::net::TcpStream> {
        self.inner.raw_write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn listen_addr_is_one_family() {
        assert!(ListenAddr::v4(Ipv4Addr::UNSPECIFIED, 443).is_ok());
        assert!(ListenAddr::v4(Ipv4Addr::LOCALHOST, 0).is_err());
        assert!(ListenAddr::v6(Ipv6Addr::UNSPECIFIED, 443).is_ok());
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert!(ListenAddr::v6(mapped, 443).is_err());
    }
}
