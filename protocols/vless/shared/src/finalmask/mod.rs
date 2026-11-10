//! Xray final masks between the carrier socket and the transport protocol.

mod custom;
mod xmc;
mod filter;
mod fragment;
mod http_tls;
mod noise;
mod realm;
mod salamander;
mod sudoku;
mod udphop;
mod wire_writer;
mod xdns;
mod xicmp;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::{kcp_mask, KcpMask, TlsNetwork};

const UDP_SIZE: usize = 4096;
const UDP_POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}

pub type TcpPair = (Box<dyn Read + Send>, Box<dyn Write + Send>);

/// The listener and dialer supply unconnected sockets. Carriers may use an
/// address other than the transport peer for their underlying datagrams.
pub trait PacketIo: Send + Sync {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize>;
}

impl PacketIo for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, out)
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, packet, peer)
    }
}

pub use filter::GeoIpMatcher;

#[derive(Clone, Default)]
pub struct FinalMask {
    tcp: Vec<TcpMask>,
    udp: Vec<UdpMask>,
    quic_params: Option<Value>,
    network: Option<Arc<crate::runtime::CarrierNetwork>>,
}

#[derive(Clone)]
enum TcpMask {
    Xmc(xmc::Xmc),
    Custom(custom::TcpHeader),
    Filter(filter::Filter),
    Fragment(fragment::Fragment),
    Sudoku(sudoku::Sudoku),
}

#[derive(Clone)]
enum UdpMask {
    Custom(custom::UdpHeader),
    Filter(filter::Filter),
    Kcp(KcpMask),
    Noise(noise::Noise),
    Realm(realm::Realm),
    Salamander(salamander::Salamander),
    Sudoku(sudoku::Sudoku),
    Hop(udphop::Hop),
    Xdns(xdns::Xdns),
    Icmp(xicmp::Icmp),
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct RawFinalMask {
    tcp: Vec<RawMask>,
    udp: Vec<RawMask>,
    quic_params: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMask {
    #[serde(rename = "type")]
    name: String,
    #[serde(default)]
    settings: Value,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LegacyKcp {
    header: String,
    value: String,
}

impl LegacyKcp {
    fn build(self) -> io::Result<KcpMask> {
        let header = self.header.to_ascii_lowercase();
        let mask = match header.as_str() {
            "" if self.value.is_empty() => kcp_mask("original", "", ""),
            "" => kcp_mask("", "", &self.value),
            "dns" => kcp_mask("dns", &self.value, ""),
            "dtls" | "srtp" | "utp" | "wechat" | "wireguard" => kcp_mask(&header, "", ""),
            _ => None,
        };
        mask.ok_or_else(|| invalid("invalid mkcp-legacy header"))
    }
}

impl FinalMask {
    pub fn parse(json: &str) -> io::Result<Self> {
        Self::parse_with_geoip(json, |_, _| Err(invalid("finalmask filter requires a GeoIP catalog")))
    }

    pub fn parse_with_geoip(
        json: &str,
        geoip: impl Fn(&str, &str) -> io::Result<GeoIpMatcher>,
    ) -> io::Result<Self> {
        Self::parse_with_context(json, geoip, None)
    }

    pub fn parse_with_context(
        json: &str,
        geoip: impl Fn(&str, &str) -> io::Result<GeoIpMatcher>,
        tls_network: Option<Arc<dyn TlsNetwork>>,
    ) -> io::Result<Self> {
        Self::parse_with_cache(json, geoip, tls_network, None)
    }

    pub(crate) fn parse_with_cache(
        json: &str,
        geoip: impl Fn(&str, &str) -> io::Result<GeoIpMatcher>,
        tls_network: Option<Arc<dyn TlsNetwork>>,
        tls_cache: Option<Arc<crate::AdvancedTlsClientCache>>,
    ) -> io::Result<Self> {
        let config: RawFinalMask = if json.trim().is_empty() {
            RawFinalMask::default()
        } else {
            serde_json::from_str(json).map_err(invalid)?
        };
        let tcp = config.tcp.into_iter().map(|mask| {
            Ok(match mask.name.as_str() {
                "header-custom" => TcpMask::Custom(custom::TcpHeader::parse(mask.settings)?),
                "filter" => TcpMask::Filter(filter::Filter::parse(mask.settings, &geoip)?),
                "fragment" => TcpMask::Fragment(fragment::Fragment::parse(mask.settings)?),
                "xmc" => TcpMask::Xmc(xmc::Xmc::parse(mask.settings)?),
                "sudoku" => TcpMask::Sudoku(sudoku::Sudoku::parse(mask.settings)?),
                other => return Err(invalid(format!("unsupported TCP finalmask {other:?}"))),
            })
        }).collect::<io::Result<_>>()?;
        let udp = config.udp.into_iter().map(|mask| {
            Ok(match mask.name.as_str() {
                "header-custom" => UdpMask::Custom(custom::UdpHeader::parse(mask.settings)?),
                "filter" => UdpMask::Filter(filter::Filter::parse(mask.settings, &geoip)?),
                "mkcp-legacy" => UdpMask::Kcp(settings::<LegacyKcp>(mask.settings)?.build()?),
                "noise" => UdpMask::Noise(noise::Noise::parse(mask.settings)?),
                "realm" => UdpMask::Realm(realm::Realm::parse(mask.settings, tls_network.clone(), tls_cache.clone())?),
                "salamander" => UdpMask::Salamander(salamander::Salamander::parse(mask.settings)?),
                "sudoku" => UdpMask::Sudoku(sudoku::Sudoku::parse(mask.settings)?),
                "udphop" => UdpMask::Hop(udphop::Hop::parse(mask.settings)?),
                "xdns" => UdpMask::Xdns(xdns::Xdns::parse(mask.settings, tls_network.clone(), tls_cache.clone())?),
                "xicmp" => UdpMask::Icmp(xicmp::Icmp::parse(mask.settings)?),
                other => return Err(invalid(format!("unsupported UDP finalmask {other:?}"))),
            })
        }).collect::<io::Result<_>>()?;
        Ok(Self { tcp, udp, quic_params: config.quic_params, network: None })
    }

    pub fn with_network(mut self, network: Arc<crate::runtime::CarrierNetwork>) -> Self {
        for mask in &mut self.udp {
            match mask {
                UdpMask::Realm(realm) => realm.set_network(network.clone()),
                UdpMask::Xdns(xdns) => xdns.set_network(network.clone()),
                _ => {},
            }
        }
        self.network = Some(network);
        self
    }

    pub fn network(&self) -> Option<&Arc<crate::runtime::CarrierNetwork>> { self.network.as_ref() }

    pub fn has_tcp(&self) -> bool {
        !self.tcp.is_empty()
    }

    pub fn has_udp(&self) -> bool {
        !self.udp.is_empty()
    }

    /// Whether a packet source is its actual peer address on a listener.
    pub fn preserves_peer_address(&self) -> bool {
        !self.udp.iter().any(|mask| matches!(mask, UdpMask::Icmp(_) | UdpMask::Xdns(_)))
    }

    pub fn quic_params(&self) -> Option<&Value> {
        self.quic_params.as_ref()
    }

    pub fn validate(&self, side: Side) -> io::Result<()> {
        for (index, mask) in self.udp.iter().rev().enumerate() {
            if matches!(mask, UdpMask::Hop(_)) {
                if side == Side::Server {
                    return Err(invalid("udphop is a client mask"));
                }
                if index > 0 {
                    return Err(invalid("udphop must be last in finalmask.udp"));
                }
            }
            if index > 0 && matches!(mask, UdpMask::Icmp(_)) {
                return Err(invalid("xicmp must be last in finalmask.udp"));
            }
            if let UdpMask::Xdns(config) = mask {
                if side == Side::Client {
                    if index > 0 {
                        return Err(invalid("xdns must be last in client finalmask.udp"));
                    }
                    config.validate_client()?;
                }
            }
        }
        Ok(())
    }

    pub fn wrap_tcp(
        &self,
        mut halves: TcpPair,
        local: SocketAddr,
        peer: SocketAddr,
        side: Side,
    ) -> io::Result<TcpPair> {
        for mask in self.tcp.iter().rev() {
            match mask {
                TcpMask::Xmc(config) => halves = config.wrap(halves, peer, side)?,
                TcpMask::Custom(config) => config.exchange(&mut halves, local, peer, side)?,
                TcpMask::Filter(filter) if side == Side::Server && filter.rejects(peer.ip()) => {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "TCP source rejected by finalmask filter"));
                }
                TcpMask::Filter(_) => {}
                TcpMask::Fragment(config) => halves.1 = Box::new(config.writer(halves.1)),
                TcpMask::Sudoku(config) => halves = config.tcp(halves, side),
            }
        }
        Ok(halves)
    }

    pub fn udp_client(
        &self,
        peer: SocketAddr,
        dial: impl Fn(SocketAddr) -> io::Result<Arc<dyn PacketIo>> + Send + Sync + 'static,
    ) -> io::Result<Arc<dyn PacketIo>> {
        self.validate(Side::Client)?;
        let mut masks = self.udp.as_slice();
        let inner = match masks.split_last() {
            Some((UdpMask::Hop(hop), rest)) => {
                masks = rest;
                hop.open(peer, Arc::new(dial))?
            }
            Some((UdpMask::Icmp(icmp), rest)) => {
                masks = rest;
                icmp.client(peer)?
            }
            Some((UdpMask::Xdns(xdns), rest)) => {
                masks = rest;
                xdns.client(peer, Arc::new(dial))?
            }
            _ => dial(peer)?,
        };
        Self::wrap_udp(inner, masks, Some(peer))
    }

    pub fn udp_server(
        &self,
        local: SocketAddr,
        bind: impl FnOnce(SocketAddr) -> io::Result<Arc<dyn PacketIo>>,
    ) -> io::Result<Arc<dyn PacketIo>> {
        self.validate(Side::Server)?;
        let mut masks = self.udp.as_slice();
        let inner = if let Some((UdpMask::Icmp(icmp), rest)) = masks.split_last() {
            masks = rest;
            icmp.server(local)?
        } else {
            bind(local)?
        };
        Self::wrap_udp(inner, masks, None)
    }

    fn wrap_udp(mut inner: Arc<dyn PacketIo>, masks: &[UdpMask], peer: Option<SocketAddr>) -> io::Result<Arc<dyn PacketIo>> {
        let side = if peer.is_some() { Side::Client } else { Side::Server };
        for mask in masks.iter().rev() {
            inner = match mask {
                UdpMask::Custom(config) => config.wrap(inner, side),
                UdpMask::Filter(filter) if side == Side::Server => filter.wrap(inner),
                UdpMask::Filter(_) => inner,
                UdpMask::Kcp(mask) => Arc::new(LegacyPackets { inner, mask: Mutex::new(mask.clone()) }),
                UdpMask::Noise(config) => config.wrap(inner),
                UdpMask::Realm(config) => config.wrap(inner, peer)?,
                UdpMask::Salamander(mask) => mask.wrap(inner),
                UdpMask::Sudoku(config) => config.udp(inner),
                UdpMask::Xdns(config) if side == Side::Server => config.server(inner)?,
                UdpMask::Xdns(_) => return Err(invalid("incorrect client xdns position")),
                UdpMask::Hop(_) => return Err(invalid("incorrect udphop position")),
                UdpMask::Icmp(_) => return Err(invalid("incorrect xicmp position")),
            };
        }
        Ok(inner)
    }
}

struct LegacyPackets {
    inner: Arc<dyn PacketIo>,
    mask: Mutex<KcpMask>,
}

impl PacketIo for LegacyPackets {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = [0; UDP_SIZE];
        let deadline = Instant::now() + UDP_POLL;
        while Instant::now() < deadline {
            let (len, peer) = self.inner.recv_from(&mut wire)?;
            if let Some(packet) = self.mask.lock().expect("KCP mask").open(&wire[..len]) {
                return Ok((copy_packet(out, &packet), peer));
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        check_udp_size(packet.len())?;
        let wire = self.mask.lock().expect("KCP mask").seal(packet);
        send_packet(&*self.inner, packet.len(), &wire, peer)
    }
}

fn settings<T: for<'de> Deserialize<'de>>(value: Value) -> io::Result<T> {
    let value = if value.is_null() { Value::Object(Default::default()) } else { value };
    serde_json::from_value(value).map_err(invalid)
}

fn invalid(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, err.to_string())
}

fn decode_bytes(value: Value, kind: &str) -> io::Result<Vec<u8>> {
    let string = || value.as_str().ok_or_else(|| invalid("expected a packet string"));
    let base64 = |text: &str| {
        let text: Vec<_> = text.bytes().filter(|byte| !matches!(byte, b'\r' | b'\n')).collect();
        STANDARD.decode(text).map_err(invalid)
    };
    match kind.to_ascii_lowercase().as_str() {
        "" | "array" => match value {
            Value::Null => Ok(Vec::new()),
            Value::String(text) => base64(&text),
            other => serde_json::from_value(other).map_err(invalid),
        },
        "str" => Ok(string()?.as_bytes().to_vec()),
        "base64" => base64(string()?),
        "hex" => {
            let bytes = string()?.as_bytes();
            if !bytes.len().is_multiple_of(2) {
                return Err(invalid("odd hexadecimal packet length"));
            }
            bytes.as_chunks::<2>().0.iter().map(|pair| {
                let digit = |b: u8| char::from(b).to_digit(16).map(|n| n as u8).ok_or_else(|| invalid("invalid hexadecimal packet"));
                Ok(digit(pair[0])? << 4 | digit(pair[1])?)
            }).collect()
        }
        _ => Err(invalid(format!("invalid packet type {kind:?}"))),
    }
}

fn malformed(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn copy_packet(out: &mut [u8], packet: &[u8]) -> usize {
    let len = out.len().min(packet.len());
    out[..len].copy_from_slice(&packet[..len]);
    len
}

fn check_udp_size(len: usize) -> io::Result<()> {
    if len > UDP_SIZE {
        return Err(invalid("masked UDP packet exceeds 4096 bytes"));
    }
    Ok(())
}

fn send_packet(inner: &dyn PacketIo, len: usize, wire: &[u8], peer: SocketAddr) -> io::Result<usize> {
    check_udp_size(wire.len())?;
    if inner.send_to(wire, peer)? != wire.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "partial masked UDP packet"));
    }
    Ok(len)
}

#[derive(Clone, Copy, Default)]
struct Range {
    min: u32,
    max: u32,
}

impl Range {
    fn fixed(value: u32) -> Self {
        Self { min: value, max: value }
    }

    fn parse(value: &str) -> io::Result<Self> {
        let parse = |part: &str| part.parse::<u32>().map_err(invalid);
        if value.is_empty() {
            return Ok(Self::default());
        }
        if let Some((left, right)) = value.split_once('-') {
            let left = parse(left)?;
            let right = parse(right)?;
            return Ok(Self { min: left.min(right), max: left.max(right) });
        }
        parse(value).map(Self::fixed)
    }

    /// Xray uses a half-open interval, except when both endpoints are equal.
    fn pick(self) -> u32 {
        self.min + random_below(self.max - self.min)
    }

    fn pick_inclusive(self) -> u32 {
        let delta = self.max - self.min;
        if delta == u32::MAX {
            return OsRng.next_u32();
        }
        self.min + random_below(delta + 1)
    }
}

type UdpDial = Arc<dyn Fn(SocketAddr) -> io::Result<Arc<dyn PacketIo>> + Send + Sync>;

fn retryable(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input {
            Number(u32),
            String(String),
        }
        match Input::deserialize(deserializer)? {
            Input::Number(n) => Ok(Self::fixed(n)),
            Input::String(s) => Self::parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

fn random_below(span: u32) -> u32 {
    if span <= 1 {
        return 0;
    }
    let threshold = span.wrapping_neg() % span;
    loop {
        let value = OsRng.next_u32();
        if value >= threshold {
            return value % span;
        }
    }
}
