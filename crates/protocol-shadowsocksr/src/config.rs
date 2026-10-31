use crate::{
    crypto::{self, Method},
    replay::Replay,
};
use kerlico_core::{Destination, Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

pub const PROTOCOLS: &[&str] = &[
    "origin",
    "auth_sha1_v4",
    "auth_aes128_md5",
    "auth_aes128_sha1",
    "auth_chain_a",
    "auth_chain_b",
];
pub const OBFS: &[&str] = &[
    "plain",
    "http_simple",
    "http_post",
    "random_head",
    "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth",
];
pub const CIPHERS: &[&str] = &[
    "none",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb1",
    "aes-128-cfb8",
    "aes-128-cfb128",
    "aes-192-cfb1",
    "aes-192-cfb8",
    "aes-192-cfb128",
    "aes-256-cfb1",
    "aes-256-cfb8",
    "aes-256-cfb128",
    "aes-128-ofb",
    "aes-192-ofb",
    "aes-256-ofb",
    "camellia-128-ctr",
    "camellia-192-ctr",
    "camellia-256-ctr",
    "camellia-128-cfb1",
    "camellia-128-cfb8",
    "camellia-128-cfb128",
    "camellia-192-cfb1",
    "camellia-192-cfb8",
    "camellia-192-cfb128",
    "camellia-256-cfb1",
    "camellia-256-cfb8",
    "camellia-256-cfb128",
    "camellia-128-ofb",
    "camellia-192-ofb",
    "camellia-256-ofb",
    "chacha20-ietf",
    "rc4-md5",
    "rc4",
    "table",
    "chacha20",
    "xchacha20",
    "salsa20",
    "rc4-md5-6",
];
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Origin,
    V4,
    AesMd5,
    AesSha1,
    ChainA,
    ChainB,
}
impl Protocol {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "origin" => Ok(Self::Origin),
            "auth_sha1_v4" => Ok(Self::V4),
            "auth_aes128_md5" => Ok(Self::AesMd5),
            "auth_aes128_sha1" => Ok(Self::AesSha1),
            "auth_chain_a" => Ok(Self::ChainA),
            "auth_chain_b" => Ok(Self::ChainB),
            _ => Err(invalid()),
        }
    }
    pub(crate) fn salt(self) -> &'static [u8] {
        match self {
            Self::Origin => b"origin",
            Self::V4 => b"auth_sha1_v4",
            Self::AesMd5 => b"auth_aes128_md5",
            Self::AesSha1 => b"auth_aes128_sha1",
            Self::ChainA => b"auth_chain_a",
            Self::ChainB => b"auth_chain_b",
        }
    }
    pub(crate) fn users(self) -> bool {
        matches!(
            self,
            Self::AesMd5 | Self::AesSha1 | Self::ChainA | Self::ChainB
        )
    }
    pub(crate) fn udp_mac(self) -> bool {
        self.users()
    }
    pub(crate) fn chain(self) -> bool {
        matches!(self, Self::ChainA | Self::ChainB)
    }
    pub(crate) fn hash(self) -> crypto::Hash {
        if matches!(self, Self::AesSha1 | Self::V4) {
            crypto::Hash::Sha1
        } else {
            crypto::Hash::Md5
        }
    }
    pub(crate) fn overhead(self) -> usize {
        match self {
            Self::Origin => 0,
            Self::V4 => 7,
            Self::AesMd5 | Self::AesSha1 => 9,
            _ => 4,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Obfs {
    Plain,
    HttpGet,
    HttpPost,
    Random,
    Tls,
    TlsFast,
}
impl Obfs {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "plain" => Ok(Self::Plain),
            "http_simple" => Ok(Self::HttpGet),
            "http_post" => Ok(Self::HttpPost),
            "random_head" => Ok(Self::Random),
            "tls1.2_ticket_auth" => Ok(Self::Tls),
            "tls1.2_ticket_fastauth" => Ok(Self::TlsFast),
            _ => Err(invalid()),
        }
    }
    pub(crate) fn tls(self) -> bool {
        matches!(self, Self::Tls | Self::TlsFast)
    }
    pub(crate) fn overhead(self) -> usize {
        if self.tls() { 5 } else { 0 }
    }
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub max_sessions: usize,
    pub udp_queue_packets: usize,
    pub udp_queue_bytes: usize,
    pub max_replay_entries: usize,
    pub auth_window_secs: u32,
    pub obfs_window_secs: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            udp_queue_packets: 16,
            udp_queue_bytes: 4 * 1024 * 1024,
            max_replay_entries: 65536,
            auth_window_secs: 86400,
            obfs_window_secs: 86400,
        }
    }
}
impl Limits {
    fn validate(&self) -> Result<()> {
        if !(1..=4096).contains(&self.max_sessions)
            || !(1..=64).contains(&self.udp_queue_packets)
            || !(65536..=16 * 1024 * 1024).contains(&self.udp_queue_bytes)
            || !(64..=1_048_576).contains(&self.max_replay_entries)
            || !(1..=86400).contains(&self.auth_window_secs)
            || !(1..=86400).contains(&self.obfs_window_secs)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClientLimits {
    max_sessions: Option<usize>,
}
impl ClientLimits {
    fn full(self) -> Limits {
        let mut limits = Limits::default();
        if let Some(value) = self.max_sessions {
            limits.max_sessions = value;
        }
        limits
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct User {
    pub id: u32,
    pub password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Server {
    host: String,
    port: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientOptions {
    server: Server,
    method: String,
    password: String,
    protocol: String,
    obfs: String,
    #[serde(default)]
    protocol_param: String,
    #[serde(default)]
    obfs_param: String,
    #[serde(default)]
    user: Option<User>,
    #[serde(default = "yes")]
    udp: bool,
    #[serde(default)]
    allow_insecure: bool,
    #[serde(default)]
    limits: ClientLimits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeOptions {
    method: String,
    password: String,
    protocol: String,
    obfs: String,
    #[serde(default)]
    obfs_param: String,
    #[serde(default)]
    users: Vec<User>,
    #[serde(default = "yes")]
    udp: bool,
    #[serde(default)]
    allow_insecure: bool,
    #[serde(default)]
    limits: Limits,
}
fn yes() -> bool {
    true
}
fn invalid() -> Error {
    Error::Config("ShadowsocksR 参数、组合或资源限制不合法".into())
}
fn secret(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) struct Shared {
    pub method: Method,
    pub key: Vec<u8>,
    pub protocol: Protocol,
    pub obfs: Obfs,
    pub obfs_param: String,
    pub users: BTreeMap<u32, Vec<u8>>,
    pub user: Option<User>,
    pub udp: bool,
    pub limits: Limits,
    pub replay: Arc<Replay>,
    pub client_id: [u8; 4],
    pub counter: AtomicU32,
    fingerprints: Vec<[u8; 32]>,
}
impl Shared {
    #[allow(clippy::too_many_arguments)]
    fn build(
        method: &str,
        password: &str,
        protocol: &str,
        obfs: &str,
        obfs_param: String,
        udp: bool,
        allow: bool,
        limits: Limits,
    ) -> Result<Self> {
        if !allow {
            return Err(Error::Config(
                "SSR 必须显式设置 allow_insecure 以启用旧式兼容协议".into(),
            ));
        }
        secret(password)?;
        limits.validate()?;
        let mut method_name = method.to_ascii_lowercase();
        if method_name.ends_with("-cfb") {
            method_name.push_str("128");
        }
        if !CIPHERS.contains(&method_name.as_str()) {
            return Err(invalid());
        }
        let method = Method::parse(&method_name)?;
        let key = crypto::key(password.as_bytes(), method.key_len());
        let protocol = Protocol::parse(protocol)?;
        let obfs = Obfs::parse(obfs)?;
        if matches!(obfs, Obfs::Plain | Obfs::Random) && !obfs_param.is_empty() {
            return Err(invalid());
        }
        if obfs_param.len() > 8192 || obfs_param.contains('\0') {
            return Err(invalid());
        }
        let mut fingerprints = BTreeSet::new();
        for (tag, data) in [
            (b"ssr/secret\0".as_slice(), password.as_bytes()),
            (b"ssr/effective-key\0".as_slice(), key.as_slice()),
        ] {
            let mut hash = Sha256::new();
            hash.update(tag);
            hash.update(data);
            fingerprints.insert(hash.finalize().into());
        }
        Ok(Self {
            method,
            key,
            protocol,
            obfs,
            obfs_param,
            users: BTreeMap::new(),
            user: None,
            udp,
            replay: Arc::new(Replay::new(limits.max_replay_entries)),
            limits,
            client_id: rand::random(),
            counter: AtomicU32::new(rand::random::<u32>() & 0x00ff_ffff),
            fingerprints: fingerprints.into_iter().collect(),
        })
    }
    pub(crate) fn client(value: &serde_json::Value) -> Result<(Arc<Self>, Destination)> {
        let options: ClientOptions =
            serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        let target = Destination::new(&options.server.host, options.server.port)?;
        let mut shared = Self::build(
            &options.method,
            &options.password,
            &options.protocol,
            &options.obfs,
            options.obfs_param,
            options.udp,
            options.allow_insecure,
            options.limits.full(),
        )?;
        if options.user.is_some() && !options.protocol_param.is_empty() {
            return Err(invalid());
        }
        shared.user = if !options.protocol_param.is_empty() {
            let (id, password) = options.protocol_param.split_once(':').ok_or_else(invalid)?;
            if password.contains(':') {
                return Err(invalid());
            }
            Some(User {
                id: id.parse().map_err(|_| invalid())?,
                password: password.into(),
            })
        } else {
            options.user
        };
        if let Some(user) = &shared.user {
            if !shared.protocol.users() {
                return Err(invalid());
            }
            secret(&user.password)?;
        }
        if matches!(shared.obfs, Obfs::HttpGet | Obfs::HttpPost)
            && shared
                .obfs_param
                .split('#')
                .next()
                .is_some_and(|host| host.contains('\r') || host.contains('\n'))
        {
            return Err(invalid());
        }
        Ok((Arc::new(shared), target))
    }
    pub(crate) fn node(value: &serde_json::Value) -> Result<Arc<Self>> {
        let options: NodeOptions = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        let mut shared = Self::build(
            &options.method,
            &options.password,
            &options.protocol,
            &options.obfs,
            options.obfs_param,
            options.udp,
            options.allow_insecure,
            options.limits,
        )?;
        if !options.users.is_empty() && !shared.protocol.users() || options.users.len() > 1024 {
            return Err(invalid());
        }
        let mut fingerprints: BTreeSet<_> = shared.fingerprints.iter().copied().collect();
        for user in options.users {
            secret(&user.password)?;
            if shared
                .users
                .insert(user.id, user.password.as_bytes().to_vec())
                .is_some()
            {
                return Err(invalid());
            }
            let mut hash = Sha256::new();
            hash.update(b"ssr/secret\0");
            hash.update(user.password.as_bytes());
            fingerprints.insert(hash.finalize().into());
            let effective = if shared.protocol.chain() {
                user.password.as_bytes().to_vec()
            } else {
                crypto::digest(shared.protocol.hash(), user.password.as_bytes())
            };
            let mut hash = Sha256::new();
            hash.update(b"ssr/effective-key\0");
            hash.update(&effective);
            fingerprints.insert(hash.finalize().into());
        }
        shared.fingerprints = fingerprints.into_iter().collect();
        if shared.obfs.tls() && !shared.obfs_param.is_empty() {
            shared.limits.obfs_window_secs = shared.obfs_param.parse().map_err(|_| invalid())?;
            shared.limits.validate()?;
        }
        if matches!(shared.obfs, Obfs::HttpGet | Obfs::HttpPost)
            && shared.obfs_param.contains(['\r', '\n', '#'])
        {
            return Err(invalid());
        }
        Ok(Arc::new(shared))
    }
    pub(crate) fn authenticated(&self) -> bool {
        (self.protocol != Protocol::Origin || self.obfs.tls())
            && (!self.udp || self.protocol.udp_mac())
    }
    pub(crate) fn fingerprints(&self) -> Vec<[u8; 32]> {
        if self.authenticated() {
            self.fingerprints.clone()
        } else {
            Vec::new()
        }
    }
    pub(crate) fn next_connection(&self) -> Result<u32> {
        let value = self.counter.fetch_add(1, Ordering::Relaxed);
        if value >= 0xff00_0000 {
            return Err(Error::ResourceLimit);
        }
        Ok(value + 1)
    }
    pub(crate) fn overhead(&self) -> usize {
        self.protocol.overhead() + self.obfs.overhead()
    }
}
