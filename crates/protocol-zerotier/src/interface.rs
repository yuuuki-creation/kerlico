//! 虚拟以太网接口：把 ZeroTier 帧桥接到用户态 IP 栈。ARP（RFC 826）与 NDP（RFC 4861）自行应答，
//! 其余 IP 包交给 `ClientTunnel`。

use kerlico_core::{CancellationToken, Result};
use kerlico_wireguard::ip::{ClientTunnel, StackLimits, StackOptions};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use zerotier_node::{Frame, Mac, MulticastGroup, NetworkConfig, Node, Route, embedded_address};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ICMPV6: u8 = 58;
const NEIGHBOR_SOLICITATION: u8 = 135;
const NEIGHBOR_ADVERTISEMENT: u8 = 136;

const NEIGHBOR_TTL_MS: i64 = 300_000;
const QUERY_INTERVAL_MS: i64 = 1_000;
const QUERY_ATTEMPTS: u8 = 5;
const MAX_NEIGHBORS: usize = 256;
const MAX_QUEUED_PER_NEIGHBOR: usize = 16;
const MAX_TUNNEL_MTU: u32 = 9000;

/// 由网络配置推导的数据面参数；只有它变化时才重建 IP 栈。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    v4: Option<(Ipv4Addr, u8)>,
    v6: Option<(Ipv6Addr, u8)>,
    allowed: Vec<String>,
    routes: Vec<(IpAddr, u8, Option<IpAddr>)>,
    mtu: u32,
}

fn masked(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(Ipv4Addr::from(
            u32::from(address) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0),
        )),
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(
            u128::from(address) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0),
        )),
    }
}

fn valid_prefix(address: IpAddr, prefix: u8) -> bool {
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

fn route_contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    network.is_ipv4() == address.is_ipv4() && masked(address, prefix) == masked(network, prefix)
}

impl Plan {
    /// 没有分配地址时返回 `None`：此时网络尚不可用。
    pub(crate) fn from_config(config: &NetworkConfig) -> Option<Self> {
        let mut v4 = None;
        let mut v6 = None;
        for (ip, prefix) in &config.static_ips {
            match ip {
                IpAddr::V4(ip) if v4.is_none() && valid_prefix(IpAddr::V4(*ip), *prefix) => {
                    v4 = Some((*ip, *prefix));
                }
                IpAddr::V6(ip) if v6.is_none() && valid_prefix(IpAddr::V6(*ip), *prefix) => {
                    v6 = Some((*ip, *prefix));
                }
                _ => {}
            }
        }
        if v4.is_none() && v6.is_none() {
            return None;
        }
        let assigned = v4
            .map(|(ip, prefix)| (IpAddr::V4(ip), prefix))
            .into_iter()
            .chain(v6.map(|(ip, prefix)| (IpAddr::V6(ip), prefix)));
        let usable = |route: &&Route| {
            valid_prefix(route.target, route.prefix)
                && (route.target.is_ipv4() && v4.is_some()
                    || route.target.is_ipv6() && v6.is_some())
        };
        let routes: Vec<(IpAddr, u8, Option<IpAddr>)> = config
            .routes
            .iter()
            .filter(usable)
            .map(|route| (masked(route.target, route.prefix), route.prefix, route.via))
            .collect();

        // ClientTunnel 不接受重叠范围：短前缀已覆盖的网络不再列出。
        let mut networks: Vec<(IpAddr, u8)> = routes
            .iter()
            .map(|(network, prefix, _)| (*network, *prefix))
            .chain(assigned.map(|(ip, prefix)| (masked(ip, prefix), prefix)))
            .collect();
        networks.sort_by_key(|(_, prefix)| *prefix);
        let mut kept: Vec<(IpAddr, u8)> = Vec::new();
        for (network, prefix) in networks {
            if !kept
                .iter()
                .any(|(wider, bits)| route_contains(*wider, *bits, network))
            {
                kept.push((network, prefix));
            }
        }
        kept.truncate(256);
        kept.sort();
        Some(Self {
            v4,
            v6,
            allowed: kept
                .iter()
                .map(|(network, prefix)| format!("{network}/{prefix}"))
                .collect(),
            routes,
            mtu: config.mtu.min(MAX_TUNNEL_MTU),
        })
    }

    /// 最长前缀匹配；带网关的路由解析网关，其余直接解析目标。
    fn next_hop(&self, destination: IpAddr) -> IpAddr {
        let own = |address: IpAddr| {
            self.v4.is_some_and(|(ip, _)| IpAddr::V4(ip) == address)
                || self.v6.is_some_and(|(ip, _)| IpAddr::V6(ip) == address)
        };
        self.routes
            .iter()
            .filter(|(network, prefix, _)| route_contains(*network, *prefix, destination))
            .max_by_key(|(_, prefix, _)| *prefix)
            .and_then(|(_, _, via)| *via)
            .filter(|via| !own(*via))
            .unwrap_or(destination)
    }
}

enum Neighbor {
    Known {
        mac: Mac,
        learned: i64,
    },
    Resolving {
        queued: VecDeque<Vec<u8>>,
        last_query: i64,
        attempts: u8,
    },
}

pub(crate) struct Interface {
    pub tunnel: ClientTunnel,
    pub plan: Plan,
    config: Arc<NetworkConfig>,
    mac: Mac,
    neighbors: HashMap<IpAddr, Neighbor>,
}

impl Interface {
    pub(crate) fn new(
        plan: Plan,
        config: Arc<NetworkConfig>,
        mac: Mac,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        let addresses = plan
            .v4
            .map(|(ip, _)| IpAddr::V4(ip))
            .into_iter()
            .chain(plan.v6.map(|(ip, _)| IpAddr::V6(ip)))
            .collect();
        let tunnel = ClientTunnel::new(
            StackOptions {
                addresses,
                allowed_ips: plan.allowed.clone(),
                mtu: plan.mtu as usize,
                limits: StackLimits::default(),
            },
            cancel.clone(),
        )?;
        Ok(Self {
            tunnel,
            plan,
            config,
            mac,
            neighbors: HashMap::new(),
        })
    }

    pub(crate) fn update_config(&mut self, config: Arc<NetworkConfig>) {
        self.config = config;
    }

    pub(crate) fn tick(&mut self, node: &mut Node, now: i64) {
        let mut retries = Vec::new();
        self.neighbors.retain(|address, neighbor| match neighbor {
            Neighbor::Known { learned, .. } => now - *learned < NEIGHBOR_TTL_MS,
            Neighbor::Resolving {
                last_query,
                attempts,
                ..
            } => {
                if now - *last_query < QUERY_INTERVAL_MS {
                    return true;
                }
                if *attempts >= QUERY_ATTEMPTS {
                    return false;
                }
                *last_query = now;
                *attempts += 1;
                retries.push(*address);
                true
            }
        });
        for address in retries {
            self.query(node, now, address);
        }
    }

    /// 发送 IP 栈产生的数据包。邻居未知时入队并发起查询。
    pub(crate) fn send_ip(&mut self, node: &mut Node, now: i64, packet: Vec<u8>) {
        let Some((ethertype, destination)) = ip_destination(&packet) else {
            return;
        };
        let hop = self.plan.next_hop(destination);
        if let IpAddr::V6(v6) = hop
            && let Some(address) = embedded_address(&self.config, v6)
        {
            node.send_frame(
                now,
                Mac::from_address(address, node.network_id()),
                ethertype,
                &packet,
            );
            return;
        }
        match self.neighbors.get_mut(&hop) {
            Some(Neighbor::Known { mac, learned }) if now - *learned < NEIGHBOR_TTL_MS => {
                node.send_frame(now, *mac, ethertype, &packet);
            }
            Some(Neighbor::Resolving { queued, .. }) => {
                if queued.len() < MAX_QUEUED_PER_NEIGHBOR {
                    queued.push_back(packet);
                }
            }
            _ => {
                if self.neighbors.len() >= MAX_NEIGHBORS && !self.neighbors.contains_key(&hop) {
                    return;
                }
                self.neighbors.insert(
                    hop,
                    Neighbor::Resolving {
                        queued: VecDeque::from([packet]),
                        last_query: now,
                        attempts: 1,
                    },
                );
                self.query(node, now, hop);
            }
        }
    }

    fn query(&self, node: &mut Node, now: i64, address: IpAddr) {
        let group = MulticastGroup::for_address_resolution(address);
        match address {
            IpAddr::V4(target) => {
                if let Some((own, _)) = self.plan.v4 {
                    let request = arp_packet(1, self.mac, own, Mac::from_bytes(&[0; 6]), target);
                    node.send_multicast(now, group, ETHERTYPE_ARP, &request);
                }
            }
            IpAddr::V6(target) => {
                if let Some((own, _)) = self.plan.v6 {
                    let solicitation = neighbor_solicitation(self.mac, own, target);
                    node.send_multicast(now, group, ETHERTYPE_IPV6, &solicitation);
                }
            }
        }
    }

    fn learn(&mut self, node: &mut Node, now: i64, address: IpAddr, mac: Mac) {
        let previous = self
            .neighbors
            .insert(address, Neighbor::Known { mac, learned: now });
        if let Some(Neighbor::Resolving { queued, .. }) = previous {
            for packet in queued {
                if let Some((ethertype, _)) = ip_destination(&packet) {
                    node.send_frame(now, mac, ethertype, &packet);
                }
            }
        }
    }

    /// 处理网络收到的帧。回程包目标不属于本接口时由 IP 栈拒绝。
    pub(crate) fn receive(&mut self, node: &mut Node, now: i64, frame: Frame) {
        match frame.ethertype {
            ETHERTYPE_ARP => self.receive_arp(node, now, &frame),
            ETHERTYPE_IPV6 if parse_ndp(&frame.payload).is_some() => {
                self.receive_ndp(node, now, &frame);
            }
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
                let _ = self.tunnel.receive(&frame.payload);
            }
            _ => {}
        }
    }

    fn receive_arp(&mut self, node: &mut Node, now: i64, frame: &Frame) {
        let Some(arp) = parse_arp(&frame.payload) else {
            return;
        };
        let Some((own, _)) = self.plan.v4 else {
            return;
        };
        if arp.target_ip != own || arp.sender_mac != frame.from {
            return;
        }
        self.learn(node, now, IpAddr::V4(arp.sender_ip), arp.sender_mac);
        if arp.operation == 1 {
            let reply = arp_packet(2, self.mac, own, arp.sender_mac, arp.sender_ip);
            node.send_frame(now, arp.sender_mac, ETHERTYPE_ARP, &reply);
        }
    }

    fn receive_ndp(&mut self, node: &mut Node, now: i64, frame: &Frame) {
        let Some(message) = parse_ndp(&frame.payload) else {
            return;
        };
        let Some((own, _)) = self.plan.v6 else {
            return;
        };
        match message.kind {
            NEIGHBOR_SOLICITATION if message.target == own => {
                self.learn(node, now, IpAddr::V6(message.source), frame.from);
                let reply = neighbor_advertisement(self.mac, own, message.source);
                node.send_frame(now, frame.from, ETHERTYPE_IPV6, &reply);
            }
            NEIGHBOR_ADVERTISEMENT => {
                self.learn(node, now, IpAddr::V6(message.target), frame.from);
            }
            _ => {}
        }
    }
}

fn ip_destination(packet: &[u8]) -> Option<(u16, IpAddr)> {
    match packet.first()? >> 4 {
        4 => {
            let bytes: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some((ETHERTYPE_IPV4, IpAddr::from(bytes)))
        }
        6 => {
            let bytes: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some((ETHERTYPE_IPV6, IpAddr::from(bytes)))
        }
        _ => None,
    }
}

struct ArpMessage {
    operation: u16,
    sender_mac: Mac,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
}

fn parse_arp(payload: &[u8]) -> Option<ArpMessage> {
    let header = payload.get(..28)?;
    if header[..6] != [0, 1, 8, 0, 6, 4] {
        return None;
    }
    let sender_mac: [u8; 6] = header[8..14].try_into().ok()?;
    let sender_ip: [u8; 4] = header[14..18].try_into().ok()?;
    let target_ip: [u8; 4] = header[24..28].try_into().ok()?;
    Some(ArpMessage {
        operation: u16::from_be_bytes([header[6], header[7]]),
        sender_mac: Mac::from_bytes(&sender_mac),
        sender_ip: sender_ip.into(),
        target_ip: target_ip.into(),
    })
}

fn arp_packet(
    operation: u16,
    sender_mac: Mac,
    sender_ip: Ipv4Addr,
    target_mac: Mac,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(28);
    packet.extend_from_slice(&[0, 1, 8, 0, 6, 4]);
    packet.extend_from_slice(&operation.to_be_bytes());
    packet.extend_from_slice(&sender_mac.to_bytes());
    packet.extend_from_slice(&sender_ip.octets());
    packet.extend_from_slice(&target_mac.to_bytes());
    packet.extend_from_slice(&target_ip.octets());
    packet
}

struct NdpMessage {
    kind: u8,
    source: Ipv6Addr,
    target: Ipv6Addr,
}

fn parse_ndp(payload: &[u8]) -> Option<NdpMessage> {
    if payload.first()? >> 4 != 6 || *payload.get(6)? != ICMPV6 || *payload.get(7)? != 255 {
        return None;
    }
    let kind = *payload.get(40)?;
    if kind != NEIGHBOR_SOLICITATION && kind != NEIGHBOR_ADVERTISEMENT {
        return None;
    }
    let source: [u8; 16] = payload.get(8..24)?.try_into().ok()?;
    let target: [u8; 16] = payload.get(48..64)?.try_into().ok()?;
    Some(NdpMessage {
        kind,
        source: source.into(),
        target: target.into(),
    })
}

fn icmpv6_packet(source: Ipv6Addr, destination: Ipv6Addr, mut body: Vec<u8>) -> Vec<u8> {
    let checksum = icmpv6_checksum(source, destination, &body);
    body[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = Vec::with_capacity(40 + body.len());
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
    packet.push(ICMPV6);
    packet.push(255);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(&body);
    packet
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, body: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        for chunk in bytes.chunks(2) {
            let high = u32::from(chunk[0]) << 8;
            sum += high | chunk.get(1).map_or(0, |low| u32::from(*low));
        }
    };
    add(&source.octets());
    add(&destination.octets());
    add(&(body.len() as u32).to_be_bytes());
    add(&[0, 0, 0, ICMPV6]);
    add(body);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn neighbor_solicitation(mac: Mac, source: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
    let octets = target.octets();
    let destination = Ipv6Addr::from([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, octets[13], octets[14], octets[15],
    ]);
    let mut body = vec![NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&octets);
    body.extend_from_slice(&[1, 1]);
    body.extend_from_slice(&mac.to_bytes());
    icmpv6_packet(source, destination, body)
}

fn neighbor_advertisement(mac: Mac, own: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
    // 标志位：Solicited 与 Override。
    let mut body = vec![NEIGHBOR_ADVERTISEMENT, 0, 0, 0, 0x60, 0, 0, 0];
    body.extend_from_slice(&own.octets());
    body.extend_from_slice(&[2, 1]);
    body.extend_from_slice(&mac.to_bytes());
    icmpv6_packet(own, destination, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(last: u8) -> Mac {
        Mac::from_bytes(&[2, 0, 0, 0, 0, last])
    }

    fn route(target: &str, prefix: u8, via: Option<&str>) -> Route {
        Route {
            target: target.parse().unwrap(),
            prefix,
            via: via.map(|via| via.parse().unwrap()),
            flags: 0,
            metric: 0,
        }
    }

    fn plan(ips: &[(&str, u8)], routes: Vec<Route>) -> Option<Plan> {
        let mut config = NetworkConfig::empty(1, zerotier_node::Address::new(1));
        config.static_ips = ips
            .iter()
            .map(|(ip, prefix)| (ip.parse().unwrap(), *prefix))
            .collect();
        config.routes = routes;
        Plan::from_config(&config)
    }

    #[test]
    fn plan_requires_an_address_and_merges_overlapping_routes() {
        assert!(plan(&[], vec![route("10.0.0.0", 24, None)]).is_none());
        let plan = plan(
            &[("10.9.0.7", 24), ("fd00::7", 88)],
            vec![
                route("10.9.0.0", 24, None),
                route("0.0.0.0", 0, Some("10.9.0.1")),
                route("192.168.1.0", 24, Some("10.9.0.2")),
            ],
        )
        .unwrap();
        assert_eq!(plan.v4.unwrap().0, "10.9.0.7".parse::<Ipv4Addr>().unwrap());
        assert_eq!(plan.allowed, ["0.0.0.0/0", "fd00::/88"]);
        assert_eq!(plan.mtu, 2800);
    }

    #[test]
    fn next_hop_follows_longest_prefix_and_gateway() {
        let plan = plan(
            &[("10.9.0.7", 24)],
            vec![
                route("10.9.0.0", 24, None),
                route("0.0.0.0", 0, Some("10.9.0.1")),
                route("192.168.1.0", 24, Some("10.9.0.2")),
                route("172.16.0.0", 12, Some("10.9.0.7")),
            ],
        )
        .unwrap();
        let hop = |value: &str| plan.next_hop(value.parse().unwrap()).to_string();
        assert_eq!(hop("10.9.0.20"), "10.9.0.20");
        assert_eq!(hop("192.168.1.5"), "10.9.0.2");
        assert_eq!(hop("8.8.8.8"), "10.9.0.1");
        assert_eq!(
            hop("172.16.0.1"),
            "172.16.0.1",
            "own address is not a gateway"
        );
    }

    #[test]
    fn arp_layout_matches_rfc826() {
        let packet = arp_packet(
            1,
            mac(1),
            "10.0.0.1".parse().unwrap(),
            Mac::from_bytes(&[0; 6]),
            "10.0.0.2".parse().unwrap(),
        );
        assert_eq!(packet.len(), 28);
        assert_eq!(packet[..8], [0, 1, 8, 0, 6, 4, 0, 1]);
        let parsed = parse_arp(&packet).unwrap();
        assert_eq!(parsed.operation, 1);
        assert_eq!(parsed.sender_mac, mac(1));
        assert_eq!(parsed.sender_ip, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(parsed.target_ip, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert!(parse_arp(&packet[..27]).is_none());
        let mut other_protocol = packet;
        other_protocol[3] = 6;
        assert!(parse_arp(&other_protocol).is_none());
    }

    #[test]
    fn neighbor_discovery_targets_solicited_node_group_with_valid_checksum() {
        let source: Ipv6Addr = "fd00::1".parse().unwrap();
        let target: Ipv6Addr = "fd00::ab:cdef".parse().unwrap();
        let packet = neighbor_solicitation(mac(1), source, target);
        assert_eq!(packet.len(), 72);
        assert_eq!(
            packet[24..40],
            "ff02::1:ffab:cdef".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(packet[7], 255);
        let parsed = parse_ndp(&packet).unwrap();
        assert_eq!(parsed.kind, NEIGHBOR_SOLICITATION);
        assert_eq!(parsed.source, source);
        assert_eq!(parsed.target, target);
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
        assert_eq!(icmpv6_checksum(source, destination, &packet[40..]), 0);

        let reply = neighbor_advertisement(mac(2), target, source);
        let parsed = parse_ndp(&reply).unwrap();
        assert_eq!(parsed.kind, NEIGHBOR_ADVERTISEMENT);
        assert_eq!(parsed.target, target);
        assert_eq!(reply[44], 0x60);
        assert_eq!(icmpv6_checksum(target, source, &reply[40..]), 0);
    }

    #[test]
    fn ndp_with_forwarded_hop_limit_is_not_trusted() {
        let mut packet = neighbor_solicitation(
            mac(1),
            "fd00::1".parse().unwrap(),
            "fd00::2".parse().unwrap(),
        );
        packet[7] = 64;
        assert!(parse_ndp(&packet).is_none());
    }
}
