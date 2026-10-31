//! 配置阶段不拨号、不解析 DNS；不安全 UDP 不能借密码字段进入公网节点。
use kerlico_core::{Address, Destination, Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{net::IpAddr, sync::Arc, time::Duration};
use zeroize::Zeroizing;
pub(crate) fn invalid() -> Error {
    Error::Config("Mieru 配置无效".into())
}
fn transport_default() -> String {
    "tcp".into()
}
fn yes() -> bool {
    true
}
fn max_sessions() -> usize {
    128
}
fn idle_secs() -> u64 {
    60
}
fn mtu() -> usize {
    1400
}
fn padding() -> u8 {
    32
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Endpoint {
    pub host: String,
    pub port: u16,
}
impl Endpoint {
    pub fn destination(self) -> Result<Destination> {
        Destination::new(&self.host, self.port)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Tcp,
    LocalUnsafeUdp,
}
impl Transport {
    pub fn parse(value: &str, unsafe_udp: bool) -> Result<Self> {
        match (value, unsafe_udp) {
            ("tcp", false) => Ok(Self::Tcp),
            ("udp", true) => Ok(Self::LocalUnsafeUdp),
            ("udp", false) => Err(Error::Config(
                "Mieru UDP 载体仅允许显式本地不安全兼容模式".into(),
            )),
            _ => Err(invalid()),
        }
    }
}
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Traffic {
    #[serde(default)]
    pub low_entropy_mode: u8,
    #[serde(default)]
    pub mask_rotation: u8,
    #[serde(default = "padding")]
    pub max_padding: u8,
}
impl Default for Traffic {
    fn default() -> Self {
        Self {
            low_entropy_mode: 0,
            mask_rotation: 0,
            max_padding: padding(),
        }
    }
}
impl Traffic {
    pub fn validate(&self) -> Result<()> {
        if self.low_entropy_mode > 4
            || !crate::entropy::valid_rotation(self.mask_rotation)
            || self.low_entropy_mode == 0 && self.mask_rotation != 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: Endpoint,
    pub username: String,
    pub password: String,
    #[serde(default = "transport_default")]
    pub transport: String,
    #[serde(default)]
    pub unsafe_udp_compatibility: bool,
    #[serde(default = "yes")]
    pub multiplexing: bool,
    #[serde(default)]
    pub no_wait: bool,
    #[serde(default = "max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "idle_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "mtu")]
    pub mtu: usize,
    #[serde(default)]
    pub traffic: Traffic,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserOptions {
    pub username: String,
    pub password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerOptions {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub users: Vec<UserOptions>,
    #[serde(default = "transport_default")]
    pub transport: String,
    #[serde(default)]
    pub unsafe_udp_compatibility: bool,
    #[serde(default = "yes")]
    pub user_hint_required: bool,
    #[serde(default = "mtu")]
    pub mtu: usize,
    #[serde(default)]
    pub traffic: Traffic,
}
pub(crate) struct User {
    pub name: String,
    pub secret: Zeroizing<[u8; 32]>,
}
impl User {
    pub fn new(username: String, password: String) -> Result<Arc<Self>> {
        let password = Zeroizing::new(password);
        if username.is_empty()
            || username.len() > 64
            || username.contains('\0')
            || password.is_empty()
            || password.len() > 4096
            || password.contains('\0')
        {
            return Err(invalid());
        }
        let mut hash = Sha256::new();
        hash.update(password.as_bytes());
        hash.update([0]);
        hash.update(username.as_bytes());
        Ok(Arc::new(Self {
            name: username,
            secret: Zeroizing::new(hash.finalize().into()),
        }))
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kerlico-mieru-secret\0");
        hash.update(&self.secret[..]);
        hash.finalize().into()
    }
    pub fn identity_fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kerlico-mieru-user\0");
        hash.update(self.name.as_bytes());
        hash.finalize().into()
    }
}
pub(crate) fn validate_limits(sessions: usize, idle: u64, value_mtu: usize) -> Result<Duration> {
    if !(1..=128).contains(&sessions)
        || !(1..=600).contains(&idle)
        || !(576..=1500).contains(&value_mtu)
    {
        return Err(invalid());
    }
    Ok(Duration::from_secs(idle))
}
pub(crate) fn require_literal_loopback(target: &Destination) -> Result<IpAddr> {
    match target.address() {
        Address::Ip(ip) if ip.is_loopback() && ip.to_canonical() == *ip => Ok(*ip),
        _ => Err(Error::Config(
            "Mieru 不安全 UDP 载体仅允许 IP 字面量回环端点".into(),
        )),
    }
}
