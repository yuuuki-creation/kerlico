use base64::{Engine, engine::general_purpose::STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use kerlico_core::{Address, Destination, Error, Result};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_flows: usize,
    pub tcp_buffer_bytes: usize,
    pub queue_packets: usize,
    pub queue_bytes: usize,
    pub fragment_packets: usize,
    pub fragment_bytes: usize,
    pub udp_idle_timeout_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_flows: 256,
            tcp_buffer_bytes: 1_048_560,
            queue_packets: 8192,
            queue_bytes: 32 * 1024 * 1024,
            fragment_packets: 256,
            fragment_bytes: 8 * 1024 * 1024,
            udp_idle_timeout_ms: 60_000,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=4096).contains(&self.max_flows)
            || !(4096..=16 * 1024 * 1024).contains(&self.tcp_buffer_bytes)
            || !(8..=65536).contains(&self.queue_packets)
            || !(65536..=128 * 1024 * 1024).contains(&self.queue_bytes)
            || !(1..=4096).contains(&self.fragment_packets)
            || !(65536..=64 * 1024 * 1024).contains(&self.fragment_bytes)
            || !(100..=86_400_000).contains(&self.udp_idle_timeout_ms)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn udp_idle(&self) -> Duration {
        Duration::from_millis(self.udp_idle_timeout_ms)
    }
}

#[derive(Clone, Debug)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}
impl Network {
    pub fn address(&self) -> IpAddr {
        self.address
    }
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
    pub fn is_host(&self) -> bool {
        self.prefix == if self.address.is_ipv4() { 32 } else { 128 }
    }
    pub fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').ok_or_else(invalid)?;
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        if prefix > if address.is_ipv4() { 32 } else { 128 } || address.to_canonical() != address {
            return Err(invalid());
        }
        let result = Self { address, prefix };
        if result.mask(address) != address {
            return Err(Error::Config(
                "WireGuard AllowedIPs必须使用规范网络地址".into(),
            ));
        }
        Ok(result)
    }
    fn mask(&self, address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V4(address) => IpAddr::V4(
                (u32::from(address)
                    & u32::MAX
                        .checked_shl(u32::from(32 - self.prefix))
                        .unwrap_or(0))
                .into(),
            ),
            IpAddr::V6(address) => IpAddr::V6(
                (u128::from(address)
                    & u128::MAX
                        .checked_shl(u32::from(128 - self.prefix))
                        .unwrap_or(0))
                .into(),
            ),
        }
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        self.address.is_ipv4() == address.is_ipv4() && self.mask(address) == self.address
    }
    pub fn overlaps(&self, other: &Self) -> bool {
        self.contains(other.address) || other.contains(self.address)
    }
}

#[derive(Clone)]
pub(crate) struct Addresses {
    pub v4: Option<IpAddr>,
    pub v6: Option<IpAddr>,
}
impl Addresses {
    pub(crate) fn parse(values: Vec<IpAddr>) -> Result<Self> {
        if values.is_empty() || values.len() > 2 {
            return Err(invalid());
        }
        let mut result = Self { v4: None, v6: None };
        for address in values {
            if !unicast(address) {
                return Err(invalid());
            }
            let slot = if address.is_ipv4() {
                &mut result.v4
            } else {
                &mut result.v6
            };
            if slot.replace(address).is_some() {
                return Err(Error::Config(
                    "WireGuard每个内部地址族只能配置一个接口地址".into(),
                ));
            }
        }
        Ok(result)
    }
    pub fn for_target(&self, target: IpAddr) -> Result<IpAddr> {
        (if target.is_ipv4() { self.v4 } else { self.v6 })
            .ok_or(Error::Unsupported("WireGuard未配置该内部地址族"))
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        self.v4 == Some(address) || self.v6 == Some(address)
    }
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> {
        self.v4.into_iter().chain(self.v6)
    }
}

pub(crate) fn unicast(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && address.to_canonical() == address
        && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast())
        && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
}
pub(crate) fn target(value: &Destination) -> Result<SocketAddr> {
    match value.address() {
        Address::Ip(ip) if unicast(*ip) => Ok(SocketAddr::new(*ip, value.port())),
        Address::Ip(_) => Err(Error::InvalidAddress),
        Address::Domain(_) => Err(Error::Unsupported("WireGuard需要共享调度器提供字面IP目标")),
    }
}
pub(crate) fn destination(value: SocketAddr) -> Result<Destination> {
    Destination::new(&value.ip().to_string(), value.port())
}
pub(crate) fn key(value: &str) -> Result<[u8; 32]> {
    let mut output = [0; 32];
    if value.len() != 44
        || STANDARD.decode_slice(value, &mut output).ok() != Some(32)
        || output == [0; 32]
    {
        return Err(Error::Config(
            "WireGuard密钥必须为非零32字节的标准Base64".into(),
        ));
    }
    Ok(output)
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum ReservedSpec {
    Bytes([u8; 3]),
    Base64(String),
}
impl ReservedSpec {
    pub fn parse(&self) -> Result<[u8; 3]> {
        match self {
            Self::Bytes(bytes) => Ok(*bytes),
            Self::Base64(text) => {
                let mut out = [0u8; 3];
                if text.len() != 4 || STANDARD.decode_slice(text, &mut out).ok() != Some(3) {
                    return Err(Error::Config(
                        "WireGuard reserved必须为3字节数组或4字符Base64".into(),
                    ));
                }
                Ok(out)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerOptions {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive: u16,
    #[serde(default)]
    pub reserved: Option<ReservedSpec>,
    #[serde(default)]
    pub level: u32,
}
#[derive(Clone)]
pub(crate) struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<Zeroizing<[u8; 32]>>,
    pub allowed: Vec<Network>,
    pub keepalive: Option<u16>,
    pub reserved: [u8; 3],
    pub level: u32,
}
impl PeerOptions {
    pub fn prepare(self) -> Result<PeerConfig> {
        if self.allowed_ips.is_empty() || self.allowed_ips.len() > 256 {
            return Err(invalid());
        }
        let allowed = self
            .allowed_ips
            .iter()
            .map(|s| Network::parse(s))
            .collect::<Result<Vec<_>>>()?;
        for (index, network) in allowed.iter().enumerate() {
            if allowed[..index].iter().any(|other| network.overlaps(other)) {
                return Err(Error::Config(
                    "WireGuard单peer的AllowedIPs不能重复或重叠".into(),
                ));
            }
        }
        let reserved = match self.reserved {
            Some(spec) => spec.parse()?,
            None => [0; 3],
        };
        Ok(PeerConfig {
            public_key: key(&self.public_key)?,
            preshared_key: self
                .preshared_key
                .as_deref()
                .map(key)
                .transpose()?
                .map(Zeroizing::new),
            allowed,
            keepalive: (self.persistent_keepalive != 0).then_some(self.persistent_keepalive),
            reserved,
            level: self.level,
        })
    }
}
impl PeerConfig {
    pub fn allows(&self, ip: IpAddr) -> bool {
        unicast(ip) && self.allowed.iter().any(|network| network.contains(ip))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommonOptions {
    pub private_key: String,
    pub addresses: Vec<IpAddr>,
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    #[serde(default)]
    pub limits: Limits,
}
fn default_mtu() -> usize {
    1420
}
#[derive(Clone)]
pub(crate) struct Prepared {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
    pub addresses: Addresses,
    pub mtu: usize,
    pub limits: Limits,
}
impl Prepared {
    pub fn validate_peer(&self, peer: &PeerConfig) -> Result<()> {
        if peer.public_key == *self.public_key.as_bytes()
            || self
                .private_key
                .diffie_hellman(&PublicKey::from(peer.public_key))
                .to_bytes()
                == [0; 32]
        {
            return Err(Error::Config(
                "WireGuard对端公钥不能等于本机公钥或使用低阶点".into(),
            ));
        }
        Ok(())
    }
}
impl CommonOptions {
    pub fn prepare(self) -> Result<Prepared> {
        if !(1280..=9000).contains(&self.mtu) {
            return Err(Error::Config("WireGuard MTU必须为1280至9000字节".into()));
        }
        self.limits.validate()?;
        let private_key = StaticSecret::from(key(&self.private_key)?);
        Ok(Prepared {
            public_key: PublicKey::from(&private_key),
            private_key,
            addresses: Addresses::parse(self.addresses)?,
            mtu: self.mtu,
            limits: self.limits,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub tunnel: CommonOptions,
    pub endpoint: Endpoint,
    pub peer: PeerOptions,
    pub bind: Option<SocketAddr>,
    #[serde(default)]
    pub reserved: Option<ReservedSpec>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Endpoint {
    pub host: String,
    pub port: u16,
}
pub(crate) fn invalid() -> Error {
    Error::Config("WireGuard配置或资源边界不合法".into())
}
