//! Domain types for both roles.
//! This crate has no role feature and no dependency on a role crate.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub mod runtime;
mod egress;
mod proxy;
pub use egress::{Exit, OutboundChoice};
pub use proxy::{Association, ClientEntry, ProxyFn, Stream, TunnelFn, Upstream};

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
    /// `host:port`, `ipv4:port` or `[ipv6]:port`. An IPv6 host is kept without brackets.
    pub fn parse(text: &str) -> Result<Self, AddrError> {
        let (host, port) = match text.parse::<SocketAddr>() {
            Ok(address) => (address.ip().to_string(), address.port()),
            Err(_) => {
                let (host, port) = text.rsplit_once(':').ok_or(AddrError)?;
                if host.is_empty() || host.contains([':', '[', ']']) {
                    return Err(AddrError);
                }
                (host.to_string(), port.parse().map_err(|_| AddrError)?)
            }
        };
        if port == 0 {
            return Err(AddrError);
        }
        Ok(Self { host, port })
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

/// One settings value. `Settings::insert_json` builds the text values from a JSON document.
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

    /// The one rule from a JSON value to a setting, for client and server documents. Strings
    /// stay, numbers and booleans become their JSON text, and arrays and objects stay JSON text
    /// for the protocol to read. `null` is rejected.
    pub fn insert_json(&mut self, key: &str, value: &serde_json::Value) -> Result<(), DocError> {
        let text = match value {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Null => return Err(DocError),
            other => other.to_string(),
        };
        self.insert_text(key, text);
        Ok(())
    }

    pub fn remove(&mut self, key: &str) -> Option<Setting> {
        self.entries.remove(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn text(&self, key: &str) -> Result<&str, OpenError> {
        match self.entries.get(key) {
            Some(Setting::Text(value)) => Ok(value),
            _ => Err(OpenError::Settings),
        }
    }

    /// 缺少可选项时返回 None；已有键的类型错误仍然拒绝。
    pub fn optional_text(&self, key: &str) -> Result<Option<&str>, OpenError> {
        match self.entries.get(key) {
            None => Ok(None),
            Some(Setting::Text(value)) => Ok(Some(value)),
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

/// A client document, JSON `{"protocol", "peer", "settings"}`. The endpoint is `peer`, or
/// `settings.address` with `settings.port`, which must agree with `peer` when both are given.
/// `ClientConfig::parse` checks the protocol against the registry.
#[derive(Clone, Debug)]
pub struct Document {
    protocol: Option<String>,
    peer: PeerAddr,
    settings: Settings,
}

impl Document {
    pub fn parse(text: &str) -> Result<Self, DocError> {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|_| DocError)?;
        let object = value.as_object().ok_or(DocError)?;
        if object.keys().any(|key| !matches!(key.as_str(), "protocol" | "peer" | "settings")) {
            return Err(DocError);
        }
        let protocol = match object.get("protocol") {
            None => None,
            Some(protocol) => Some(protocol.as_str().ok_or(DocError)?.to_string()),
        };
        let mut settings = Settings::default();
        for (key, value) in object.get("settings").and_then(serde_json::Value::as_object).ok_or(DocError)? {
            settings.insert_json(key, value)?;
        }
        let address = match settings.remove("address") {
            None => None,
            Some(Setting::Text(address)) => Some(address),
            Some(_) => return Err(DocError),
        };
        let port = match settings.remove("port") {
            None => None,
            Some(Setting::Text(port)) => Some(port.parse::<u16>().map_err(|_| DocError)?),
            Some(_) => return Err(DocError),
        };
        let peer = match object.get("peer") {
            Some(peer) => {
                let peer = PeerAddr::parse(peer.as_str().ok_or(DocError)?).map_err(|_| DocError)?;
                if address.is_some_and(|address| address != peer.host) || port.is_some_and(|port| port != peer.port) {
                    return Err(DocError);
                }
                peer
            }
            None => {
                let host = address.filter(|host| !host.is_empty()).ok_or(DocError)?;
                PeerAddr { host, port: port.filter(|port| *port != 0).ok_or(DocError)? }
            }
        };
        Ok(Self { protocol, peer, settings })
    }

    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    pub fn peer(&self) -> &PeerAddr {
        &self.peer
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn into_parts(self) -> (Option<String>, PeerAddr, Settings) {
        (self.protocol, self.peer, self.settings)
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
    prefix_packet: bool,
    peer: Option<SocketAddr>,
}

/// The server resolves names once when the outbound module starts copying a flow.
pub trait Traffic: Send + Sync {
    fn bind(&self, user: &UserEmail, node: &NodeTag, exit: &str) -> TrafficCounters;
}

/// User, inbound, and outbound counters shared with the server's query API.
pub struct TrafficCounters {
    uplink: [Arc<AtomicU64>; 3],
    downlink: [Arc<AtomicU64>; 3],
}

impl TrafficCounters {
    pub fn new(uplink: [Arc<AtomicU64>; 3], downlink: [Arc<AtomicU64>; 3]) -> Self {
        Self { uplink, downlink }
    }

    pub fn add_uplink(&self, bytes: u64) {
        for counter in &self.uplink {
            counter.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn add_downlink(&self, bytes: u64) {
        for counter in &self.downlink {
            counter.fetch_add(bytes, Ordering::Relaxed);
        }
    }
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
    pub fn new(
        host: impl Into<String>,
        port: u16,
        transport: Transport,
    ) -> Result<Self, AddrError> {
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
            prefix_packet: false,
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
        self.prefix_packet = self.destination.transport == Transport::Udp;
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
        if self.prefix.is_empty() && !self.prefix_packet {
            self.stream
        } else {
            Box::new(PrefixStream {
                pending: std::sync::Mutex::new(Some(self.prefix)),
                datagram: self.prefix_packet,
                inner: self.stream,
            })
        }
    }
}

struct PrefixStream {
    pending: std::sync::Mutex<Option<Vec<u8>>>,
    datagram: bool,
    inner: Box<dyn InboundStream>,
}

impl InboundStream for PrefixStream {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        let mut pending = self.pending.lock().expect("prefix");
        let Some(bytes) = pending.as_ref() else {
            drop(pending);
            return self.inner.read_from_user(buf);
        };
        if self.datagram {
            if bytes.len() > buf.len() {
                return Err(PlaneFault::Transport);
            }
            let bytes = pending.take().expect("预读数据报");
            buf[..bytes.len()].copy_from_slice(&bytes);
            return Ok(bytes.len());
        }
        let bytes = pending.as_mut().expect("预读字节");
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        bytes.drain(..n);
        if bytes.is_empty() {
            *pending = None;
        }
        Ok(n)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.inner.write_to_user(buf)
    }

    fn raw_read(&self) -> Option<std::net::TcpStream> {
        if self.pending.lock().expect("prefix").is_some() {
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
    fn document_takes_the_endpoint_from_peer_or_settings() {
        let document = Document::parse(
            r#"{"protocol":"vless","peer":"[::1]:2000","settings":{"address":"::1","port":2000,"mtu":1280,"lan":false,"alpn":["h2"]}}"#,
        )
        .unwrap();
        assert_eq!(document.protocol(), Some("vless"));
        assert_eq!((document.peer().host(), document.peer().port()), ("::1", 2000));
        let settings = document.settings();
        assert_eq!(settings.text("mtu").unwrap(), "1280");
        assert_eq!(settings.text("lan").unwrap(), "false");
        assert_eq!(settings.text("alpn").unwrap(), r#"["h2"]"#);
        assert!(settings.optional_text("address").unwrap().is_none(), "the endpoint leaves the protocol settings");
        let document = Document::parse(r#"{"settings":{"address":"node.test","port":"2001"}}"#).unwrap();
        assert_eq!(document.protocol(), None);
        assert_eq!((document.peer().host(), document.peer().port()), ("node.test", 2001));
    }

    #[test]
    fn document_rejects_ambiguous_and_malformed_input() {
        for document in [
            r#"{"peer":"127.0.0.1:2000","settings":{"address":"127.0.0.2"}}"#,
            r#"{"peer":"127.0.0.1:2000","settings":{"port":2001}}"#,
            r#"{"peer":"127.0.0.1:2000","settings":{"mtu":null}}"#,
            r#"{"peer":"127.0.0.1:2000","settings":{},"extra":1}"#,
            r#"{"peer":"127.0.0.1:2000"}"#,
            r#"{"protocol":7,"peer":"127.0.0.1:2000","settings":{}}"#,
            r#"{"settings":{"address":"127.0.0.1"}}"#,
            r#"{"peer":"::1:2000","settings":{}}"#,
            r#"{"peer":"127.0.0.1:0","settings":{}}"#,
            r#"[]"#,
        ] {
            assert!(Document::parse(document).is_err(), "{document}");
        }
    }

    #[test]
    fn listen_addr_is_one_family() {
        assert!(ListenAddr::v4(Ipv4Addr::UNSPECIFIED, 443).is_ok());
        assert!(ListenAddr::v4(Ipv4Addr::LOCALHOST, 0).is_err());
        assert!(ListenAddr::v6(Ipv6Addr::UNSPECIFIED, 443).is_ok());
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert!(ListenAddr::v6(mapped, 443).is_err());
    }

    struct Datagram(std::sync::Mutex<Option<Vec<u8>>>);
    impl InboundStream for Datagram {
        fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
            let mut data = self.0.lock().unwrap();
            let packet = data.as_ref().ok_or(PlaneFault::Closed)?;
            if buf.len() < packet.len() {
                return Err(PlaneFault::Transport);
            }
            let packet = data.take().unwrap();
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
        fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
            Ok(buf.len())
        }
    }

    #[test]
    fn udp_prefix_preserves_empty_packets_and_rejects_splitting() {
        for packet in [Vec::new(), vec![1, 2, 3]] {
            let mut handoff = Handoff::new(
                NodeTag::parse("test-node").unwrap(),
                UserEmail::parse("test-user").unwrap(),
                Destination::new("127.0.0.1", 9000, Transport::Udp).unwrap(),
                Box::new(Datagram(std::sync::Mutex::new(Some(packet.clone())))),
            );
            assert_eq!(
                handoff.read_into_prefix(&mut [0; 64]).unwrap(),
                packet.len()
            );
            let stream = handoff.stream();
            if !packet.is_empty() {
                assert!(stream.read_from_user(&mut [0; 1]).is_err());
            }
            let mut buf = [0; 64];
            assert_eq!(stream.read_from_user(&mut buf).unwrap(), packet.len());
            assert_eq!(&buf[..packet.len()], packet);
            assert_eq!(stream.read_from_user(&mut buf), Err(PlaneFault::Closed));
        }
    }
}
