//! `tailcfg` 的 netmap 子集、增量合并与由 AllowedIPs 导出的路由表。

use crate::{
    config::RouteOptions,
    keys::{DiscoKey, NodeKey},
};
use kerlico_wireguard::ip::Network;
use serde::{Deserialize, Deserializer, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

/// Go 的 nil 切片和 map 序列化成 `null`，按空值接收。
fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + DeserializeOwned,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "StableID", deserialize_with = "nullable")]
    pub stable_id: String,
    #[serde(rename = "Name", deserialize_with = "nullable")]
    pub name: String,
    #[serde(rename = "Key")]
    pub key: Option<NodeKey>,
    #[serde(rename = "DiscoKey")]
    pub disco: Option<DiscoKey>,
    #[serde(rename = "Addresses", deserialize_with = "nullable")]
    pub addresses: Vec<String>,
    /// `None` 与上游 capver 112 一致，表示与 `Addresses` 相同。
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(rename = "Endpoints", deserialize_with = "nullable")]
    pub endpoints: Vec<SocketAddr>,
    #[serde(rename = "DERP", deserialize_with = "nullable")]
    pub legacy_derp: String,
    #[serde(rename = "HomeDERP")]
    pub home_derp: i32,
    #[serde(rename = "Expired")]
    pub expired: bool,
    #[serde(rename = "IsWireGuardOnly")]
    pub wireguard_only: bool,
}
impl Node {
    /// 新控制面用 `HomeDERP`，旧控制面用 `DERP: "127.3.3.40:<区域>"`。
    pub fn derp_region(&self) -> Option<i32> {
        if self.home_derp > 0 {
            return Some(self.home_derp);
        }
        let (host, port) = self.legacy_derp.rsplit_once(':')?;
        (host == "127.3.3.40")
            .then(|| port.parse().ok())
            .flatten()
            .filter(|region| *region > 0)
    }
    fn networks(&self) -> Vec<Network> {
        self.allowed_ips
            .as_ref()
            .unwrap_or(&self.addresses)
            .iter()
            .filter_map(|network| Network::parse(network).ok())
            .collect()
    }
    fn host_addresses(&self) -> Vec<IpAddr> {
        self.addresses
            .iter()
            .filter_map(|network| Network::parse(network).ok())
            .map(|network| network.address())
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
struct PeerChange {
    #[serde(rename = "NodeID")]
    id: i64,
    #[serde(rename = "DERPRegion")]
    derp_region: i32,
    #[serde(rename = "Endpoints")]
    endpoints: Option<Vec<SocketAddr>>,
    #[serde(rename = "Key")]
    key: Option<NodeKey>,
    #[serde(rename = "DiscoKey")]
    disco: Option<DiscoKey>,
}

#[derive(Clone, Debug, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct DerpNode {
    #[serde(rename = "HostName", deserialize_with = "nullable")]
    pub host_name: String,
    #[serde(rename = "CertName", deserialize_with = "nullable")]
    pub cert_name: String,
    #[serde(rename = "IPv4", deserialize_with = "nullable")]
    pub ipv4: String,
    #[serde(rename = "IPv6", deserialize_with = "nullable")]
    pub ipv6: String,
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
    #[serde(rename = "DERPPort")]
    pub derp_port: i32,
}
impl DerpNode {
    pub fn tls_port(&self) -> Option<u16> {
        match self.derp_port {
            0 => Some(443),
            port => u16::try_from(port).ok().filter(|port| *port != 0),
        }
    }
    pub fn stun_port(&self) -> Option<u16> {
        match self.stun_port {
            0 => Some(3478),
            port => u16::try_from(port).ok().filter(|port| *port != 0),
        }
    }
    /// 依次尝试的连接地址：控制面给出的 IP 优先，否则解析域名；`none` 等非 IP 值表示不用该地址族。
    pub fn dial_hosts(&self) -> Vec<String> {
        let literal: Vec<String> = [&self.ipv4, &self.ipv6]
            .into_iter()
            .filter(|host| host.parse::<IpAddr>().is_ok())
            .cloned()
            .collect();
        if literal.is_empty() {
            vec![self.host_name.clone()]
        } else {
            literal
        }
    }
}

#[derive(Clone, Debug, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub id: i32,
    #[serde(rename = "Avoid")]
    pub avoid: bool,
    #[serde(rename = "NoMeasureNoHome")]
    pub no_home: bool,
    #[serde(rename = "Nodes", deserialize_with = "nullable")]
    pub nodes: Vec<DerpNode>,
}

#[derive(Clone, Debug, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct DerpMap {
    #[serde(rename = "Regions", deserialize_with = "nullable")]
    pub regions: BTreeMap<i32, DerpRegion>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct MapResponse {
    #[serde(rename = "Node")]
    node: Option<Node>,
    #[serde(rename = "DERPMap")]
    derp_map: Option<DerpMap>,
    #[serde(rename = "Peers")]
    peers: Option<Vec<Node>>,
    #[serde(rename = "PeersChanged", deserialize_with = "nullable")]
    peers_changed: Vec<Node>,
    #[serde(rename = "PeersRemoved", deserialize_with = "nullable")]
    peers_removed: Vec<i64>,
    #[serde(rename = "PeersChangedPatch", deserialize_with = "nullable")]
    peers_patched: Vec<PeerChange>,
}

#[derive(Clone, Debug, Default)]
pub struct NetMap {
    pub own: Option<Node>,
    pub derp: DerpMap,
    pub peers: BTreeMap<i64, Node>,
}
impl NetMap {
    /// 返回本次响应是否改变了状态；纯保活帧不触发数据面重算。
    pub fn apply(&mut self, response: MapResponse) -> bool {
        let mut changed = false;
        if let Some(node) = response.node {
            self.own = Some(node);
            changed = true;
        }
        if let Some(derp) = response.derp_map {
            self.derp = derp;
            changed = true;
        }
        if let Some(peers) = response.peers {
            self.peers = peers.into_iter().map(|peer| (peer.id, peer)).collect();
            changed = true;
        }
        for peer in response.peers_changed {
            self.peers.insert(peer.id, peer);
            changed = true;
        }
        for id in response.peers_removed {
            changed |= self.peers.remove(&id).is_some();
        }
        for patch in response.peers_patched {
            let Some(peer) = self.peers.get_mut(&patch.id) else {
                continue;
            };
            if patch.derp_region != 0 {
                peer.home_derp = patch.derp_region;
            }
            if let Some(endpoints) = patch.endpoints {
                peer.endpoints = endpoints;
            }
            if let Some(key) = patch.key {
                peer.key = Some(key);
            }
            if let Some(disco) = patch.disco {
                peer.disco = Some(disco);
            }
            changed = true;
        }
        changed
    }
    pub fn own_addresses(&self) -> Vec<IpAddr> {
        self.own
            .as_ref()
            .map(Node::host_addresses)
            .unwrap_or_default()
    }
    pub fn usable_peers(&self) -> impl Iterator<Item = &Node> {
        self.peers.values().filter(|peer| {
            !peer.expired && !peer.wireguard_only && peer.key.is_some_and(|key| !key.is_zero())
        })
    }
    pub fn routes(&self, options: &RouteOptions) -> Routes {
        let exit = options.exit_node.as_deref().and_then(|selector| {
            self.usable_peers()
                .find(|peer| matches_exit(peer, selector))
                .map(|peer| peer.id)
        });
        let mut entries = Vec::new();
        for peer in self.usable_peers() {
            let Some(key) = peer.key else { continue };
            let hosts = peer.host_addresses();
            for network in peer.networks() {
                let accepted = if network.prefix() == 0 {
                    exit == Some(peer.id)
                } else {
                    network.is_host() && hosts.contains(&network.address()) || options.accept_routes
                };
                if accepted {
                    entries.push((network, key));
                }
            }
        }
        entries.sort_by_key(|(network, _)| std::cmp::Reverse(network.prefix()));
        Routes(entries)
    }
}
fn matches_exit(peer: &Node, selector: &str) -> bool {
    let name = peer.name.trim_end_matches('.');
    selector
        .parse::<IpAddr>()
        .is_ok_and(|ip| peer.host_addresses().contains(&ip))
        || peer.stable_id == selector
        || name == selector
        || name.split('.').next() == Some(selector)
}

/// 最长前缀优先的密钥路由表；无匹配的目标不发送，也不回退到其他路径。
#[derive(Clone, Default)]
pub struct Routes(Vec<(Network, NodeKey)>);
impl Routes {
    pub fn lookup(&self, ip: IpAddr) -> Option<NodeKey> {
        self.0
            .iter()
            .find(|(network, _)| network.contains(ip))
            .map(|(_, key)| *key)
    }
}

/// 把流式 `/machine/map` 响应切成 4 字节小端长度前缀的 JSON 消息。
#[derive(Default)]
pub struct MapFrames(Vec<u8>);
impl MapFrames {
    const LIMIT: usize = 64 * 1024 * 1024;
    pub fn push(&mut self, chunk: &[u8]) {
        self.0.extend_from_slice(chunk);
    }
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ()> {
        let Some(header) = self.0.first_chunk::<4>() else {
            return Ok(None);
        };
        let length = u32::from_le_bytes(*header) as usize;
        if length > Self::LIMIT {
            return Err(());
        }
        if self.0.len() < 4 + length {
            return Ok(None);
        }
        let frame = self.0[4..4 + length].to_vec();
        self.0.drain(..4 + length);
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(byte: u8) -> String {
        format!("nodekey:{}", hex::encode([byte; 32]))
    }
    fn respond(map: &mut NetMap, value: serde_json::Value) -> bool {
        map.apply(serde_json::from_value(value).unwrap())
    }
    fn options(exit: Option<&str>, accept_routes: bool) -> RouteOptions {
        RouteOptions {
            exit_node: exit.map(str::to_owned),
            accept_routes,
        }
    }
    fn sample() -> NetMap {
        let mut map = NetMap::default();
        respond(
            &mut map,
            json!({
                "Node":{"ID":1,"Key":key(1),"Addresses":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],"AllowedIPs":null},
                "DERPMap":{"Regions":{"999":{"RegionID":999,"Nodes":[{"HostName":"derp.test","DERPPort":8443,"STUNPort":-1}]}}},
                "Peers":[
                    {"ID":2,"Name":"plain.tail.test.","Key":key(2),"Addresses":["100.64.0.2/32"],"AllowedIPs":["100.64.0.2/32","10.9.0.0/16"],"DERP":"127.3.3.40:999","Endpoints":["192.0.2.1:41641"]},
                    {"ID":3,"Name":"exit.tail.test.","Key":key(3),"Addresses":["100.64.0.3/32"],"AllowedIPs":["100.64.0.3/32","0.0.0.0/0","::/0"],"HomeDERP":999},
                    {"ID":4,"Name":"gone.tail.test.","Key":key(4),"Addresses":["100.64.0.4/32"],"Expired":true}
                ]
            }),
        );
        map
    }

    #[test]
    fn deltas_replace_patch_and_remove_peers() {
        let mut map = sample();
        assert!(!respond(&mut map, json!({"KeepAlive":true})));
        assert_eq!(map.peers[&2].derp_region(), Some(999));
        assert_eq!(map.peers[&3].derp_region(), Some(999));
        assert!(respond(
            &mut map,
            json!({"PeersChangedPatch":[{"NodeID":2,"DERPRegion":7,"Endpoints":["192.0.2.9:1"]}]})
        ));
        assert_eq!(map.peers[&2].derp_region(), Some(7));
        assert_eq!(
            map.peers[&2].endpoints,
            vec!["192.0.2.9:1".parse::<SocketAddr>().unwrap()]
        );
        assert!(respond(&mut map, json!({"PeersRemoved":[3]})));
        assert!(!map.peers.contains_key(&3));
        assert!(respond(&mut map, json!({"Peers":[]})));
        assert!(map.peers.is_empty());
    }

    #[test]
    fn routes_follow_exit_and_subnet_selection() {
        let map = sample();
        let plain = NodeKey([2; 32]);
        let exit = NodeKey([3; 32]);
        let public: IpAddr = "198.51.100.1".parse().unwrap();
        let subnet: IpAddr = "10.9.1.1".parse().unwrap();

        let routes = map.routes(&options(None, false));
        assert_eq!(routes.lookup("100.64.0.2".parse().unwrap()), Some(plain));
        assert_eq!(routes.lookup("100.64.0.3".parse().unwrap()), Some(exit));
        assert_eq!(routes.lookup("100.64.0.4".parse().unwrap()), None);
        assert_eq!(routes.lookup(public), None);
        assert_eq!(routes.lookup(subnet), None);

        let routes = map.routes(&options(Some("exit"), true));
        assert_eq!(routes.lookup(public), Some(exit));
        assert_eq!(routes.lookup("2001:db8::1".parse().unwrap()), Some(exit));
        assert_eq!(routes.lookup(subnet), Some(plain));

        for selector in ["100.64.0.3", "exit.tail.test"] {
            assert_eq!(
                map.routes(&options(Some(selector), false)).lookup(public),
                Some(exit)
            );
        }
        assert_eq!(
            map.routes(&options(Some("plain"), false)).lookup(public),
            None
        );
        assert_eq!(
            map.routes(&options(Some("absent"), false)).lookup(public),
            None
        );
    }

    #[test]
    fn nil_allowed_ips_mean_addresses() {
        let mut map = NetMap::default();
        respond(
            &mut map,
            json!({"Peers":[{"ID":2,"Key":key(2),"Addresses":["100.64.0.2/32"]}]}),
        );
        assert_eq!(
            map.routes(&options(None, false))
                .lookup("100.64.0.2".parse().unwrap()),
            Some(NodeKey([2; 32]))
        );
    }

    #[test]
    fn map_frames_split_on_little_endian_length() {
        let mut frames = MapFrames::default();
        frames.push(&[2, 0, 0]);
        assert_eq!(frames.next_frame(), Ok(None));
        frames.push(&[0, b'{', b'}', 1, 0, 0, 0]);
        assert_eq!(frames.next_frame(), Ok(Some(b"{}".to_vec())));
        assert_eq!(frames.next_frame(), Ok(None));
        frames.push(b"x");
        assert_eq!(frames.next_frame(), Ok(Some(b"x".to_vec())));
        frames.push(&u32::MAX.to_le_bytes());
        assert_eq!(frames.next_frame(), Err(()));
    }

    #[test]
    fn derp_node_defaults_follow_upstream() {
        let node: DerpNode = serde_json::from_value(json!({"HostName":"d.test"})).unwrap();
        assert_eq!(node.tls_port(), Some(443));
        assert_eq!(node.stun_port(), Some(3478));
        let node: DerpNode = serde_json::from_value(
            json!({"HostName":"d.test","IPv4":"192.0.2.1","STUNPort":-1,"DERPPort":8443}),
        )
        .unwrap();
        assert_eq!(node.tls_port(), Some(8443));
        assert_eq!(node.stun_port(), None);
        assert_eq!(node.dial_hosts(), ["192.0.2.1"]);
        let node: DerpNode =
            serde_json::from_value(json!({"HostName":"d.test","IPv4":"none"})).unwrap();
        assert_eq!(node.dial_hosts(), ["d.test"]);
    }
}
