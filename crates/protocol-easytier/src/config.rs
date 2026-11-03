use crate::invalid;
use cidr::{Ipv4Inet, Ipv6Inet};
use easytier::common::config::{ConfigLoader, NetworkIdentity, TomlConfigLoader};
use kerlico_core::Result;
use serde::Deserialize;
use std::net::IpAddr;
use url::Url;

/// 上游虚拟网卡在开启加密时从默认 1380 再减 20，这里取同一内层 MTU。
pub(crate) const TUNNEL_MTU: usize = 1200;
const MAX_PEERS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    network_name: String,
    network_secret: String,
    peers: Vec<String>,
    ipv4: Option<String>,
    ipv6: Option<String>,
    #[serde(default = "default_hostname")]
    hostname: String,
    #[serde(default)]
    encryption: Encryption,
    #[serde(default, alias = "exit-nodes")]
    exit_nodes: Vec<IpAddr>,
    #[serde(default, alias = "secure-mode")]
    secure_mode: bool,
}
fn default_hostname() -> String {
    "kerlico".into()
}

/// 只列默认 feature 集合内可用且线上与官方节点一致的算法。
#[derive(Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Encryption {
    #[default]
    AesGcm,
    Aes256Gcm,
    Xor,
    None,
}
impl Encryption {
    fn algorithm(self) -> Option<&'static str> {
        match self {
            Self::AesGcm => Some("aes-gcm"),
            Self::Aes256Gcm => Some("aes-256-gcm"),
            Self::Xor => Some("xor"),
            Self::None => None,
        }
    }
}

pub(crate) struct Prepared {
    pub network_name: String,
    pub network_secret: String,
    pub peers: Vec<Url>,
    /// `None` 表示由网络内已有路由分配地址（上游 `--dhcp`）。
    pub ipv4: Option<Ipv4Inet>,
    pub ipv6: Option<Ipv6Inet>,
    pub hostname: String,
    pub encryption: Encryption,
    pub exit_nodes: Vec<IpAddr>,
}

impl ClientOptions {
    pub fn prepare(self) -> Result<Prepared> {
        if self.network_name.is_empty()
            || self.network_secret.is_empty()
            || self.hostname.is_empty()
            || self.peers.is_empty()
            || self.peers.len() > MAX_PEERS
            || self.exit_nodes.len() > MAX_PEERS
            || self.exit_nodes.iter().any(|ip| !unicast(*ip))
            || (self.secure_mode && matches!(self.encryption, Encryption::None))
        {
            return Err(invalid());
        }
        let peers = self
            .peers
            .iter()
            .map(|peer| parse_peer(peer))
            .collect::<Result<Vec<_>>>()?;
        let ipv4 = self
            .ipv4
            .map(|value| value.parse::<Ipv4Inet>().map_err(|_| invalid()))
            .transpose()?;
        let ipv6 = self
            .ipv6
            .map(|value| value.parse::<Ipv6Inet>().map_err(|_| invalid()))
            .transpose()?;
        if ipv4.is_some_and(|inet| !unicast(IpAddr::V4(inet.address())))
            || ipv6.is_some_and(|inet| !unicast(IpAddr::V6(inet.address())))
        {
            return Err(invalid());
        }
        Ok(Prepared {
            network_name: self.network_name,
            network_secret: self.network_secret,
            peers,
            ipv4,
            ipv6,
            hostname: self.hostname,
            encryption: self.encryption,
            exit_nodes: self.exit_nodes,
        })
    }
}

fn unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()
}

fn parse_peer(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "tcp" | "udp")
        || url.host().is_none()
        || url.port().is_none()
        || !matches!(url.path(), "" | "/")
    {
        return Err(invalid());
    }
    Ok(url)
}

impl Prepared {
    /// 本节点只有配置的主动连接：不监听、不打洞、不接收 KCP/QUIC 代理流量。
    pub fn node_config(&self) -> TomlConfigLoader {
        let config = TomlConfigLoader::default();
        config.set_hostname(Some(self.hostname.clone()));
        config.set_network_identity(NetworkIdentity::new(
            self.network_name.clone(),
            self.network_secret.clone(),
        ));
        config.set_listeners(Vec::new());
        config.set_ipv4(self.ipv4);
        config.set_ipv6(self.ipv6);
        config.set_dhcp(self.ipv4.is_none());
        config.set_exit_nodes(self.exit_nodes.clone());
        let mut flags = config.get_flags();
        flags.no_tun = true;
        flags.bind_device = false;
        flags.disable_p2p = true;
        flags.disable_tcp_hole_punching = true;
        flags.disable_udp_hole_punching = true;
        flags.disable_kcp_input = true;
        flags.disable_quic_input = true;
        match self.encryption.algorithm() {
            Some(algorithm) => algorithm.clone_into(&mut flags.encryption_algorithm),
            None => flags.enable_encryption = false,
        }
        config.set_flags(flags);
        config
    }
}
