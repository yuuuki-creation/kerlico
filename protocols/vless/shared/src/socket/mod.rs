//! Xray carrier socket settings. Callers own resolution, bind, and connect.

mod dial;
mod native;
#[cfg(test)]
mod tests;

pub use dial::{
    AddressFamily, DialPlan, DirectDialPlan, ProxyDialPlan, ResolutionSource, SrvRecord,
    TransportResolver,
};

use crate::{go_json, TrustedForwardedFor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketKind {
    Tcp,
    Udp,
}

impl SocketKind {
    fn network(self, ipv6: bool) -> &'static str {
        match (self, ipv6) {
            (Self::Tcp, false) => "tcp4",
            (Self::Tcp, true) => "tcp6",
            (Self::Udp, false) => "udp4",
            (Self::Udp, true) => "udp6",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketRole {
    Listener,
    Dialer,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(try_from = "String")]
pub enum TProxyMode {
    #[default]
    Off,
    TProxy,
    Redirect,
}

impl TryFrom<String> for TProxyMode {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "" | "off" => Ok(Self::Off),
            "tproxy" => Ok(Self::TProxy),
            "redirect" => Ok(Self::Redirect),
            _ => Err(format!("unsupported tproxy mode {value:?}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(try_from = "String")]
enum DomainStrategy {
    #[default]
    AsIs,
    UseIp,
    UseV4,
    UseV6,
    UseV4V6,
    UseV6V4,
    ForceIp,
    ForceV4,
    ForceV6,
    ForceV4V6,
    ForceV6V4,
}

impl TryFrom<String> for DomainStrategy {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "" | "asis" => Ok(Self::AsIs),
            "useip" => Ok(Self::UseIp),
            "useipv4" => Ok(Self::UseV4),
            "useipv6" => Ok(Self::UseV6),
            "useipv4v6" => Ok(Self::UseV4V6),
            "useipv6v4" => Ok(Self::UseV6V4),
            "forceip" => Ok(Self::ForceIp),
            "forceipv4" => Ok(Self::ForceV4),
            "forceipv6" => Ok(Self::ForceV6),
            "forceipv4v6" => Ok(Self::ForceV4V6),
            "forceipv6v4" => Ok(Self::ForceV6V4),
            _ => Err(format!("unsupported domainStrategy {value:?}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(try_from = "String")]
enum AddressPortStrategy {
    #[default]
    None,
    SrvPortOnly,
    SrvAddressOnly,
    SrvPortAndAddress,
    TxtPortOnly,
    TxtAddressOnly,
    TxtPortAndAddress,
}

impl TryFrom<String> for AddressPortStrategy {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "" | "none" => Ok(Self::None),
            "srvportonly" => Ok(Self::SrvPortOnly),
            "srvaddressonly" => Ok(Self::SrvAddressOnly),
            "srvportandaddress" => Ok(Self::SrvPortAndAddress),
            "txtportonly" => Ok(Self::TxtPortOnly),
            "txtaddressonly" => Ok(Self::TxtAddressOnly),
            "txtportandaddress" => Ok(Self::TxtPortAndAddress),
            _ => Err(format!("unsupported addressPortStrategy {value:?}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct HappyEyeballs {
    #[serde(rename = "prioritizeIPv6")]
    prioritize_ipv6: bool,
    try_delay_ms: u64,
    interleave: u32,
    max_concurrent_try: u32,
}

impl Default for HappyEyeballs {
    fn default() -> Self {
        Self {
            prioritize_ipv6: false,
            try_delay_ms: 0,
            interleave: 1,
            max_concurrent_try: 4,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct CustomSockopt {
    system: String,
    network: String,
    level: String,
    opt: String,
    value: String,
    #[serde(rename = "type")]
    value_type: String,
}

/// Options from the Xray `streamSettings.sockopt` object.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SocketOptions {
    mark: i32,
    #[serde(deserialize_with = "fast_open")]
    tcp_fast_open: Option<i32>,
    #[serde(deserialize_with = "default_on_null")]
    pub tproxy: TProxyMode,
    pub accept_proxy_protocol: bool,
    #[serde(deserialize_with = "default_on_null")]
    domain_strategy: DomainStrategy,
    pub dialer_proxy: Option<String>,
    tcp_keep_alive_interval: i32,
    tcp_keep_alive_idle: i32,
    tcp_congestion: String,
    tcp_window_clamp: i32,
    tcp_max_seg: i32,
    pub penetrate: bool,
    tcp_user_timeout: i32,
    #[serde(rename = "v6only")]
    v6_only: bool,
    interface: String,
    tcp_mptcp: bool,
    #[serde(deserialize_with = "default_on_null")]
    custom_sockopt: Vec<CustomSockopt>,
    #[serde(deserialize_with = "default_on_null")]
    address_port_strategy: AddressPortStrategy,
    #[serde(deserialize_with = "default_on_null")]
    happy_eyeballs: HappyEyeballs,
    #[serde(rename = "trustedXForwardedFor", deserialize_with = "default_on_null")]
    pub trusted_forwarded_for: TrustedForwardedFor,
}

impl SocketOptions {
    pub fn requires_native_socket(&self) -> bool {
        self.mark != 0 || self.tcp_fast_open.is_some() || self.tproxy != TProxyMode::Off
            || self.tcp_keep_alive_interval != 0 || self.tcp_keep_alive_idle != 0
            || !self.tcp_congestion.is_empty() || self.tcp_window_clamp != 0
            || self.tcp_max_seg != 0 || self.tcp_user_timeout != 0 || self.v6_only
            || !self.interface.is_empty() || self.tcp_mptcp || !self.custom_sockopt.is_empty()
    }

    pub fn parse(json: Option<&str>) -> io::Result<Self> {
        let mut options = match json {
            None => Self::default(),
            Some(json) => decode(json).map_err(|err| invalid(format!("sockopt: {err}")))?.unwrap_or_default(),
        };
        options.dialer_proxy = options.dialer_proxy.filter(|selector| !selector.is_empty());
        if (options.tcp_keep_alive_idle > 0 && options.tcp_keep_alive_interval < 0)
            || (options.tcp_keep_alive_idle < 0 && options.tcp_keep_alive_interval > 0)
        {
            return Err(invalid("sockopt TCP keepalive values have opposite signs"));
        }
        Ok(options)
    }

    /// Creates a configured carrier socket. The address is the listener's bind
    /// address or the dialer's resolved peer. This does not bind or connect it.
    pub fn open(&self, kind: SocketKind, role: SocketRole, addr: SocketAddr) -> io::Result<Socket> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let (socket_type, protocol) = match kind {
            SocketKind::Tcp if self.tcp_mptcp => (Type::STREAM, native::mptcp()?),
            SocketKind::Tcp => (Type::STREAM, Protocol::TCP),
            SocketKind::Udp => (Type::DGRAM, Protocol::UDP),
        };
        let socket = Socket::new(domain, socket_type, Some(protocol))?;
        if kind == SocketKind::Tcp {
            socket.set_tcp_nodelay(true)?;
            if role == SocketRole::Listener {
                socket.set_reuse_address(true)?;
            }
        }
        self.configure(&socket, kind, role, addr)?;
        Ok(socket)
    }

    /// Applies native options before bind or connect. Custom options run in
    /// their configured order. IPv6 listeners always remain IPv6-only.
    pub fn configure(
        &self,
        socket: &Socket,
        kind: SocketKind,
        role: SocketRole,
        addr: SocketAddr,
    ) -> io::Result<()> {
        if matches!(addr, SocketAddr::V6(_)) && matches!(addr.ip().to_canonical(), IpAddr::V4(_)) {
            return Err(invalid("IPv4-mapped IPv6 carrier socket address"));
        }
        if kind == SocketKind::Tcp && self.tcp_mptcp {
            native::check_mptcp(socket)?;
        }
        native::configure(socket, self, kind, role, addr)?;
        if addr.is_ipv6() && (role == SocketRole::Listener || self.v6_only) {
            option("v6only", socket.set_only_v6(true))?;
        }
        Ok(())
    }
}

const OPTION_FIELDS: [&str; 20] = [
    "mark", "tcpFastOpen", "tproxy", "acceptProxyProtocol", "domainStrategy", "dialerProxy",
    "tcpKeepAliveInterval", "tcpKeepAliveIdle", "tcpCongestion", "tcpWindowClamp", "tcpMaxSeg", "penetrate",
    "tcpUserTimeout", "v6only", "interface", "tcpMptcp", "customSockopt", "addressPortStrategy",
    "happyEyeballs", "trustedXForwardedFor",
];
const HAPPY_EYEBALLS_FIELDS: [&str; 4] = ["prioritizeIPv6", "tryDelayMs", "interleave", "maxConcurrentTry"];
const CUSTOM_SOCKOPT_FIELDS: [&str; 6] = ["system", "network", "level", "opt", "value", "type"];

/// Go matches keys case-insensitively and ignores keys no field has, so both are settled before serde sees the object.
fn decode(json: &str) -> serde_json::Result<Option<SocketOptions>> {
    let Some(pairs) = go_json::object(json)? else {
        return Ok(None);
    };
    let mut map = go_json::fields(pairs, &OPTION_FIELDS);
    let nested = |value: Value, names: &[&str]| match value {
        Value::Object(object) => Value::Object(go_json::fields(object.into_iter().collect(), names)),
        other => other,
    };
    if let Some(value) = map.remove("happyEyeballs") {
        map.insert("happyEyeballs".to_owned(), nested(value, &HAPPY_EYEBALLS_FIELDS));
    }
    if let Some(value) = map.remove("customSockopt") {
        let value = match value {
            Value::Array(items) => Value::Array(items.into_iter().map(|item| nested(item, &CUSTOM_SOCKOPT_FIELDS)).collect()),
            other => other,
        };
        map.insert("customSockopt".to_owned(), value);
    }
    serde_json::from_value(Value::Object(map)).map(Some)
}

fn default_on_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn fast_open<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i32>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Boolean(bool),
        Number(f64),
    }

    let count = match Option::<Value>::deserialize(deserializer)? {
        None => 0,
        Some(Value::Boolean(true)) => 256,
        Some(Value::Boolean(false)) => -1,
        Some(Value::Number(count)) => count as i32,
    };
    Ok((count != 0).then_some(count.max(0)))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

fn option<T>(name: &str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| io::Error::new(error.kind(), format!("sockopt.{name}: {error}")))
}
