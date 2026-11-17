//! Domain types for both roles.
//! This crate has no role feature and no dependency on a role crate.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub mod dispatch;
pub mod runtime;
mod async_stream;
mod egress;
mod proxy;
pub use egress::{Exit, OutboundChoice};
pub use async_stream::{AsyncBufReadVectored, AsyncReadHalf, AsyncTcp};
mod write_input;
pub use write_input::{AsyncWriteHalf, AsyncWriteInput, WriteInput, MAX_WRITE_INPUT_PARTS};
pub use proxy::{Association, ClientEntry, ProxyFn, Stream, TunFn, TunnelFn, Upstream};

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
    pub fn from_host_port(host: String, port: u16) -> Result<Self, AddrError> {
        if host.contains(':') && !host.starts_with('[') {
            return Self::parse(&format!("[{host}]:{port}"));
        }
        Self::parse(&format!("{host}:{port}"))
    }

    /// `host:port`, `ipv4:port` or `[ipv6%scope]:port`. The scope is kept for the protocol.
    pub fn parse(text: &str) -> Result<Self, AddrError> {
        let (host, port) = match text.parse::<SocketAddr>() {
            Ok(SocketAddr::V6(addr)) if addr.scope_id() != 0 => {
                (format!("{}%{}", addr.ip(), addr.scope_id()), addr.port())
            }
            Ok(address) => (address.ip().to_string(), address.port()),
            Err(_) if text.starts_with('[') => {
                let (host, port) = text[1..].split_once("]:").ok_or(AddrError)?;
                let (ip, scope) = host.split_once('%').ok_or(AddrError)?;
                let ip: std::net::Ipv6Addr = ip.parse().map_err(|_| AddrError)?;
                if scope.is_empty() || scope.contains(['[', ']', ':', '%'])
                    || scope.chars().any(|ch| ch.is_control() || ch.is_whitespace())
                {
                    return Err(AddrError);
                }
                (format!("{ip}%{scope}"), port.parse().map_err(|_| AddrError)?)
            }
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
    /// Takes one complete IPv4 or IPv6 packet, without link-layer padding.
    pub fn from_ip_packet(bytes: Vec<u8>) -> Result<Self, PacketError> {
        let length = match bytes.first().map(|tag| tag >> 4) {
            Some(4) if bytes.len() >= 20 => {
                let header = usize::from(bytes[0] & 15) * 4;
                let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                if header < 20 || header > length { return Err(PacketError); }
                length
            }
            Some(6) if bytes.len() >= 40 => 40 + usize::from(u16::from_be_bytes([bytes[4], bytes[5]])),
            _ => return Err(PacketError),
        };
        if bytes.len() != length { return Err(PacketError); }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> { self.bytes }
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

    pub fn dispatch_wake(&self) -> Option<&dispatch::Wake> {
        self.runtime()?.dispatch.as_ref()
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
    /// Transfers the established TCP state exactly once. Called only with
    /// exclusive ownership, after sniffing and reporting the dial result.
    /// A successful transfer leaves this wrapper unused; no synchronous reader
    /// or writer may remain active while the halves are moved.
    fn take_async_tcp(&mut self) -> Result<Option<AsyncTcp>, PlaneFault> { Ok(None) }
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault>;
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault>;
    /// Gives a UDP reply its actual origin when the outbound socket carries several targets.
    fn write_datagram_to_user(&self, buf: &[u8], _source: SocketAddr) -> Result<usize, PlaneFault> {
        self.write_to_user(buf)
    }
    /// Lets protocols acknowledge or reject a request only once the exit has been dialed.
    fn report_connect(&self, _result: Result<(), OpenError>) -> Result<(), PlaneFault> { Ok(()) }
    /// Says whether uplink can remain open after gracefully ending the downlink.
    fn finish_to_user(&self) -> Result<bool, PlaneFault> { Ok(false) }

    /// Reads like `read_from_user` and gives the bytes to `sink`, in one or more slices in
    /// order. A stream that already holds the bytes can give them where they lie instead of
    /// copying them into `buf`, and may give more than `buf` holds. Returns how many bytes `sink`
    /// got. The default reads into `buf` and calls `sink` once, also with zero bytes.
    fn read_from_user_to(
        &self,
        buf: &mut [u8],
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<usize, PlaneFault> {
        let n = self.read_from_user(buf)?;
        sink(&buf[..n]);
        Ok(n)
    }

    /// Gives one ready batch of disjoint plaintext regions to the same outbound
    /// copy loop. Regions stay valid until `sink` returns. The default preserves
    /// the existing single-slice reader, including empty UDP datagrams.
    fn read_from_user_vectored_to(
        &self,
        buf: &mut [u8],
        sink: &mut dyn FnMut(&[std::io::IoSlice<'_>]),
    ) -> Result<usize, PlaneFault> {
        self.read_from_user_to(buf, &mut |bytes| sink(&[std::io::IoSlice::new(bytes)]))
    }

    /// Raw user socket once this direction has no protocol bytes left to transform.
    fn raw_read(&self) -> Option<std::net::TcpStream> {
        None
    }

    fn raw_write(&self) -> Option<std::net::TcpStream> {
        None
    }

    /// The raw socket hooks may become available after consuming protocol bytes.
    #[cfg(target_os = "linux")]
    fn can_splice(&self) -> bool { false }
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
    datagram_session: Option<std::sync::Arc<DatagramSession>>,
}

/// Opaque identity of one UDP session that can carry multiple destinations.
#[derive(Default)]
pub struct DatagramSession {
    allow_other_sources: bool,
}

impl DatagramSession {
    pub fn new(allow_other_sources: bool) -> Self { Self { allow_other_sources } }
    pub fn allows_other_sources(&self) -> bool { self.allow_other_sources }
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
    /// Takes a ready handoff without waiting. Skip discarded entries before returning `Again`.
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
            datagram_session: None,
        }
    }

    /// UDP sessions are keyed by this address and the destination.
    pub fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = Some(peer);
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub fn set_datagram_session(&mut self, session: std::sync::Arc<DatagramSession>) {
        debug_assert_eq!(self.destination.transport, Transport::Udp);
        self.datagram_session = Some(session);
    }

    pub fn datagram_session(&self) -> Option<&std::sync::Arc<DatagramSession>> {
        self.datagram_session.as_ref()
    }

    pub fn report_connect(&self, result: Result<(), OpenError>) -> Result<(), PlaneFault> {
        self.stream.report_connect(result)
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
    fn take_async_tcp(&mut self) -> Result<Option<AsyncTcp>, PlaneFault> {
        if self.datagram { return Ok(None); }
        let Some(mut stream) = self.inner.take_async_tcp()? else { return Ok(None); };
        if let Some(bytes) = self.pending.get_mut().expect("prefix").take() {
            stream.prepend(bytes);
        }
        Ok(Some(stream))
    }
    fn report_connect(&self, result: Result<(), OpenError>) -> Result<(), PlaneFault> {
        self.inner.report_connect(result)
    }

    fn finish_to_user(&self) -> Result<bool, PlaneFault> { self.inner.finish_to_user() }

    fn write_datagram_to_user(&self, buf: &[u8], source: SocketAddr) -> Result<usize, PlaneFault> {
        self.inner.write_datagram_to_user(buf, source)
    }

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

    fn read_from_user_to(
        &self,
        buf: &mut [u8],
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<usize, PlaneFault> {
        if self.pending.lock().expect("prefix").is_none() {
            return self.inner.read_from_user_to(buf, sink);
        }
        let n = self.read_from_user(buf)?;
        sink(&buf[..n]);
        Ok(n)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.inner.write_to_user(buf)
    }

    fn read_from_user_vectored_to(
        &self,
        buf: &mut [u8],
        sink: &mut dyn FnMut(&[std::io::IoSlice<'_>]),
    ) -> Result<usize, PlaneFault> {
        if self.pending.lock().expect("prefix").is_none() {
            return self.inner.read_from_user_vectored_to(buf, sink);
        }
        let n = self.read_from_user(buf)?;
        sink(&[std::io::IoSlice::new(&buf[..n])]);
        Ok(n)
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

    #[cfg(target_os = "linux")]
    fn can_splice(&self) -> bool { self.inner.can_splice() }
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
    fn peer_addr_preserves_the_ipv6_zone() {
        for host in ["fe80::2%7", "fe80::2%veth-right"] {
            let text = format!(r#"{{"peer":"[{host}]:51820","settings":{{"address":"{host}","port":51820}}}}"#);
            let document = Document::parse(&text).unwrap();
            assert_eq!(document.peer(), &PeerAddr::from_host_port(host.to_owned(), 51820).unwrap());
            assert_eq!(document.peer().host(), host);
        }
        for bad in ["[invalid%eth0]:80", "[fe80::1%]:80", "[fe80::1%eth0%eth1]:80", "[fe80::1%eth0]:0"] {
            assert!(PeerAddr::parse(bad).is_err());
        }
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

    #[test]
    fn async_handoff_preserves_sniffed_bytes_and_transfers_state_once() {
        use std::io::{Cursor, Read};
        use std::sync::Mutex;
        use tokio::io::AsyncReadExt;

        struct Flow {
            read: Mutex<Option<Cursor<Vec<u8>>>>,
            executor: tokio::runtime::Handle,
        }
        impl InboundStream for Flow {
            fn read_from_user(&self, out: &mut [u8]) -> Result<usize, PlaneFault> {
                Read::read(self.read.lock().unwrap().as_mut().ok_or(PlaneFault::Closed)?, out)
                    .map_err(|_| PlaneFault::Transport)
            }
            fn write_to_user(&self, bytes: &[u8]) -> Result<usize, PlaneFault> { Ok(bytes.len()) }
            fn take_async_tcp(&mut self) -> Result<Option<AsyncTcp>, PlaneFault> {
                let Some(read) = self.read.get_mut().unwrap().take() else { return Ok(None); };
                Ok(Some(AsyncTcp {
                    executor: self.executor.clone(),
                    read: AsyncReadHalf::Plain(Box::new(read)),
                    write: AsyncWriteHalf::plain(tokio::io::sink()),
                }))
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let payload = b"sniffed header then application payload";
        let mut handoff = Handoff::new(
            NodeTag::parse("node").unwrap(),
            UserEmail::parse("user").unwrap(),
            Destination::new("127.0.0.1", 9000, Transport::Tcp).unwrap(),
            Box::new(Flow { read: Mutex::new(Some(Cursor::new(payload.to_vec()))), executor: runtime.handle().clone() }),
        );
        assert_eq!(handoff.read_into_prefix(&mut [0; 7]).unwrap(), 7);
        let mut stream = handoff.stream();
        let transferred = stream.take_async_tcp().unwrap().unwrap();
        assert!(stream.take_async_tcp().unwrap().is_none());
        drop(stream);
        let mut received = Vec::new();
        runtime.block_on(transferred.read.into_buffered(1024).read_to_end(&mut received)).unwrap();
        assert_eq!(received, payload);
    }

    #[test]
    fn vector_borrowing_preserves_sniffed_prefix_then_forwards_the_batch() {
        use std::io::IoSlice;
        struct Borrowed;
        impl InboundStream for Borrowed {
            fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
                buf[..4].copy_from_slice(b"head");
                Ok(4)
            }
            fn write_to_user(&self, bytes: &[u8]) -> Result<usize, PlaneFault> { Ok(bytes.len()) }
            fn read_from_user_vectored_to(&self, _: &mut [u8], sink: &mut dyn FnMut(&[IoSlice<'_>])) -> Result<usize, PlaneFault> {
                sink(&[IoSlice::new(b"tail"), IoSlice::new(b"body")]);
                Ok(8)
            }
        }
        let mut handoff = Handoff::new(
            NodeTag::parse("node").unwrap(), UserEmail::parse("user").unwrap(),
            Destination::new("127.0.0.1", 9000, Transport::Tcp).unwrap(), Box::new(Borrowed),
        );
        assert_eq!(handoff.read_into_prefix(&mut [0; 4]).unwrap(), 4);
        let stream = handoff.stream();
        let mut scratch = [0; 8];
        let mut received = Vec::new();
        let mut widths = Vec::new();
        for expected in [4, 8] {
            assert_eq!(stream.read_from_user_vectored_to(&mut scratch, &mut |parts| {
                widths.push(parts.len());
                for part in parts { received.extend_from_slice(part); }
            }).unwrap(), expected);
        }
        assert_eq!(received, b"headtailbody");
        assert_eq!(widths, [1, 2]);
        let datagram = Datagram(std::sync::Mutex::new(Some(Vec::new())));
        let mut calls = 0;
        assert_eq!(datagram.read_from_user_vectored_to(&mut scratch, &mut |parts| {
            calls += 1;
            assert_eq!(parts.len(), 1);
            assert!(parts[0].is_empty());
        }).unwrap(), 0);
        assert_eq!(calls, 1);
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
