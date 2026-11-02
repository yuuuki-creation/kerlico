use super::*;
use crate::{config::{CommonOptions, PeerOptions}, packet::{self, FragmentBudget, IpPacket, Reassembler}, queue::PacketBudget, stack::SharedStack, tcp::TcpStream};
use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory};
use kerlico_core::{CancellationToken, Error, TargetPolicy};
use std::{net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::sync::Notify;

#[test]
fn factory_is_pure_local_policy_and_rejects_ambiguous_peers() {
    let plan = crate::WireGuardFactory.compile(&json!({"tunnel": tunnel(1, 2), "peer": peer(2, None, None),
        "endpoint": {"host": "peer.invalid", "port": 51820}})).unwrap();
    assert_eq!(plan.target_policy(), TargetPolicy::Local);
    assert!(plan.capabilities().tcp_eof && plan.supports_udp_association());
    for native in [vec![peer(1, Some(2), None), peer(1, Some(3), None)],
        vec![peer(1, Some(2), None), peer(3, Some(2), None)],
        vec![peer(1, None, None)]] {
        let input = NodeBuildContext::for_test(json!({"tunnel": tunnel(2, 1)}), native);
        assert!(crate::WireGuardNodeFactory.build(&input).is_err());
    }
    let local = NodeBuildContext::local_for_test(json!({"tunnel": tunnel(2, 1)}));
    assert!(crate::WireGuardNodeFactory.build(&local).is_err());
    let mut options = tunnel(2, 1);
    options["mtu"] = json!(1279);
    assert!(serde_json::from_value::<CommonOptions>(options).unwrap().prepare().is_err());
    assert!(PeerOptions { public_key: public(1), preshared_key: None,
        persistent_keepalive: 0, allowed_ips: vec!["10.77.0.1/24".into()] }.prepare().is_err());
}

#[test]
fn node_key_and_peer_credentials_have_distinct_manifests() {
    let first = crate::WireGuardNodeFactory.build(&NodeBuildContext::for_test(
        json!({"tunnel": tunnel(2, 1)}), vec![peer(1, Some(2), Some(9))])).unwrap();
    let second = crate::WireGuardNodeFactory.build(&NodeBuildContext::for_test(
        json!({"tunnel": tunnel(4, 1)}), vec![peer(3, Some(2), Some(8))])).unwrap();
    let a = first.credential_manifest();
    let b = second.credential_manifest();
    assert_eq!(a.entries().len(), 3);
    assert!(a.entries().iter().all(|a| b.entries().iter().all(|b| a.fingerprint != b.fingerprint)));
    assert!(!first.supports_tcp() && first.supports_udp() && first.requires_udp_association());
}

#[test]
fn registry_rejects_cross_node_static_and_preshared_credential_reuse() {
    let mut registry = kerlico_config::Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register_node(crate::WireGuardNodeFactory).unwrap();
    let account = |id: &str| json!({"user_id":id,"username":format!("fixture_{id}"),
        "password_hash":"$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXRlc3Q$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
    let ids = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"];
    let config = json!({"version":2,"accounts":[account(ids[0]),account(ids[1])],"outbounds":[{"tag":"native","type":"direct"}],
        "nodes":[
            {"tag":"outer4","type":"wireguard","listen":"127.0.0.1:0","outbound":"native","options":{"tunnel":tunnel(2,1)},
             "members":[{"user_id":ids[0],"native_credential":peer(1,Some(2),Some(9))}]},
            {"tag":"outer6","type":"wireguard","listen":"[::1]:0","outbound":"native","options":{"tunnel":tunnel(4,1)},
             "members":[{"user_id":ids[1],"native_credential":peer(3,Some(2),Some(8))}]}]});
    assert!(registry.prepare(serde_json::from_value(config.clone()).unwrap()).is_ok());
    for domain in 0..3 {
        let mut invalid = config.clone();
        match domain {
            0 => invalid["nodes"][1]["options"]["tunnel"]["private_key"] = json!(private(2)),
            1 => invalid["nodes"][1]["members"][0]["native_credential"]["public_key"] = json!(public(1)),
            _ => invalid["nodes"][1]["members"][0]["native_credential"]["preshared_key"] = json!(private(9)),
        }
        assert!(registry.prepare(serde_json::from_value(invalid).unwrap()).is_err());
    }
}

#[test]
fn packet_and_byte_budgets_both_release_on_drop() {
    let budget = PacketBudget::new(2, 5);
    let one = budget.packet(vec![1; 3], false).unwrap();
    assert!(budget.packet(vec![2; 3], false).is_err());
    let two = budget.packet(vec![2; 2], false).unwrap();
    assert!(budget.packet(Vec::new(), false).is_err());
    drop(one);
    let three = budget.packet(vec![3; 3], false).unwrap();
    drop(two);
    drop(three);
    assert!(budget.packet(vec![4; 5], false).is_ok());
}

#[test]
fn udp_empty_and_large_payloads_survive_reverse_fragment_order_for_both_families() {
    for (source, target, maximum) in [("10.77.0.2:1234", "192.0.2.7:4321", 65507),
        ("[fd77::2]:1234", "[2001:db8::7]:4321", 65527)] {
        let source: SocketAddr = source.parse().unwrap();
        let target: SocketAddr = target.parse().unwrap();
        for size in [0, 1, 1233, 4096, maximum] {
            let payload = (0..size).map(|index| (index % 251) as u8).collect::<Vec<_>>();
            let wire = packet::udp_packet(source, target, &payload).unwrap();
            let mut fragments = packet::fragment(wire, 1280, 71).unwrap();
            assert!(fragments.iter().all(|packet| packet.len() <= 1280));
            let mut assembler = Reassembler::new(FragmentBudget::new(4, 131072));
            let mut complete = None;
            fragments.reverse();
            for fragment in fragments { if let Some(packet) = assembler.accept(&fragment, Instant::now()).unwrap() { assert!(complete.replace(packet).is_none()); } }
            let complete = complete.unwrap();
            let parsed = IpPacket::parse(&complete).unwrap();
            let (tuple, body) = parsed.udp().unwrap();
            assert_eq!(tuple, packet::FlowTuple { source, target });
            assert_eq!(body, payload);
            assert!(packet::udp_packet(source, target, &vec![0; maximum + 1]).is_err());
        }
    }
}

#[test]
fn fragment_overlap_is_rejected_and_global_budget_is_released_on_expiry() {
    let source = "10.77.0.2:1200".parse().unwrap();
    let target = "192.0.2.5:1200".parse().unwrap();
    let wire = packet::udp_packet(source, target, &vec![0x5a; 6000]).unwrap();
    let fragments = packet::fragment(wire.clone(), 1280, 1).unwrap();
    let other = packet::fragment(wire, 1280, 2).unwrap();
    let now = Instant::now();
    let budget = FragmentBudget::new(1, 16384);
    let mut first = Reassembler::new(budget.clone());
    let mut second = Reassembler::new(budget);
    assert!(first.accept(&fragments[0], now).unwrap().is_none());
    assert!(matches!(second.accept(&other[0], now), Err(Error::ResourceLimit)));
    assert!(first.accept(&fragments[0], now).is_err());
    assert!(first.accept(&fragments[1], now).is_err());
    assert!(second.accept(&other[0], now).unwrap().is_none());
    first.expire(now + Duration::from_secs(31));
    second.expire(now + Duration::from_secs(31));
    assert!(first.accept(&fragments[0], now + Duration::from_secs(31)).unwrap().is_none());
}

#[test]
fn invalid_udp_checksum_and_nested_fragment_are_not_business_packets() {
    for (source, target) in [("10.77.0.2:1234", "192.0.2.5:4321"), ("[fd77::2]:1234", "[2001:db8::5]:4321")] {
        let mut wire = packet::udp_packet(source.parse().unwrap(), target.parse().unwrap(), b"payload").unwrap();
        *wire.last_mut().unwrap() ^= 1;
        assert!(IpPacket::parse(&wire).unwrap().udp().is_err());
    }
    let nested = packet::ip_packet("fd77::2".parse().unwrap(), "2001:db8::5".parse().unwrap(), 44, &[44, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 8], 64).unwrap();
    let mut assembler = Reassembler::new(FragmentBudget::new(2, 65536));
    assert!(assembler.accept(&nested, Instant::now()).is_err());
}

pub(super) fn syn(source: SocketAddr, target: SocketAddr) -> Vec<u8> {
    let mut payload = vec![0; 20];
    payload[..2].copy_from_slice(&source.port().to_be_bytes());
    payload[2..4].copy_from_slice(&target.port().to_be_bytes());
    payload[4..8].copy_from_slice(&12345u32.to_be_bytes());
    payload[12] = 0x50;
    payload[13] = 2;
    payload[14..16].copy_from_slice(&65535u16.to_be_bytes());
    let check = packet::transport_checksum(source.ip(), target.ip(), 6, &payload);
    payload[16..18].copy_from_slice(&check.to_be_bytes());
    packet::ip_packet(source.ip(), target.ip(), 6, &payload, 64).unwrap()
}

#[test]
fn same_source_port_and_two_targets_keep_distinct_synack_and_reset_sources() {
    for (source, targets) in [("10.77.0.2:1200", ["192.0.2.5:80", "198.51.100.7:443"]),
        ("[fd77::2]:1200", ["[2001:db8::5]:80", "[2001:db8::7]:443"])] {
        let prepared = serde_json::from_value::<CommonOptions>(tunnel(2, 1)).unwrap().prepare().unwrap();
        let allowed = serde_json::from_value::<PeerOptions>(peer(1, Some(2), None)).unwrap().prepare().unwrap().allowed;
        let stack = SharedStack::new(&prepared, CancellationToken::new(), Arc::new(Notify::new()), allowed, PacketBudget::new(128, 2 * 1024 * 1024)).unwrap();
        let source: SocketAddr = source.parse().unwrap();
        let targets = targets.map(|target| target.parse::<SocketAddr>().unwrap());
        let mut streams = Vec::new();
        for target in targets {
            let wire = packet::FlowTuple { source, target };
            let stream = TcpStream::accept(stack.clone(), wire, CancellationToken::new()).unwrap();
            stack.input_tcp(syn(source, target)).unwrap();
            stack.poll().unwrap();
            assert!(stack.drain(8).unwrap().is_empty());
            streams.push(stream);
        }
        for stream in &streams { stream.resume_accept().unwrap(); }
        stack.poll().unwrap();
        let output = stack.drain(8).unwrap();
        assert_eq!(output.len(), 2);
        for target in targets {
            assert!(output.iter().any(|bytes| {
                let packet = IpPacket::parse(bytes).unwrap();
                packet.tcp_tuple().unwrap() == packet::FlowTuple { source: target, target: source } && packet.payload[13] & 0x12 == 0x12
            }));
        }
        drop(streams);
        stack.poll().unwrap();
        let output = stack.drain(8).unwrap();
        assert_eq!(output.len(), 2);
        assert!(output.iter().all(|bytes| IpPacket::parse(bytes).unwrap().payload[13] & 4 != 0));
        for target in targets { assert!(output.iter().any(|bytes| IpPacket::parse(bytes).unwrap().tcp_tuple().unwrap().source == target)); }
        assert_eq!(stack.flow_count(), 0);
    }
}

#[test]
fn reset_before_target_connect_cancels_pending_operation() {
    let prepared = serde_json::from_value::<CommonOptions>(tunnel(2, 1)).unwrap().prepare().unwrap();
    let allowed = serde_json::from_value::<PeerOptions>(peer(1, Some(2), None)).unwrap().prepare().unwrap().allowed;
    let stack = SharedStack::new(&prepared, CancellationToken::new(), Arc::new(Notify::new()), allowed, PacketBudget::new(128, 2 * 1024 * 1024)).unwrap();
    let source: SocketAddr = "10.77.0.2:1200".parse().unwrap();
    let target: SocketAddr = "192.0.2.5:80".parse().unwrap();
    let stream = TcpStream::accept(stack.clone(), packet::FlowTuple { source, target }, CancellationToken::new()).unwrap();
    stack.input_tcp(syn(source, target)).unwrap();
    stack.poll().unwrap();
    assert!(!stream.pending_cancel().is_cancelled());
    let initial = syn(source, target);
    let mut reset = IpPacket::parse(&initial).unwrap().payload.to_vec();
    reset[4..8].copy_from_slice(&12346u32.to_be_bytes());
    reset[13] = 4;
    reset[16..18].fill(0);
    let check = packet::transport_checksum(source.ip(), target.ip(), 6, &reset);
    reset[16..18].copy_from_slice(&check.to_be_bytes());
    stack.input_tcp(packet::ip_packet(source.ip(), target.ip(), 6, &reset, 64).unwrap()).unwrap();
    stack.poll().unwrap();
    assert!(stream.pending_cancel().is_cancelled());
}

#[test]
fn remote_echo_gets_control_refusal_and_local_echo_is_exact() {
    let local = serde_json::from_value::<CommonOptions>(tunnel(2, 1)).unwrap().prepare().unwrap().addresses;
    for (source, own, remote, protocol, kind) in [("10.77.0.2", "10.77.0.1", "192.0.2.5", 1, 8),
        ("fd77::2", "fd77::1", "2001:db8::5", 58, 128)] {
        let source = source.parse().unwrap();
        for target in [own, remote] {
            let target = target.parse().unwrap();
            let mut echo = vec![kind, 0, 0, 0, 0x12, 0x34, 0, 1, 0xaa];
            let check = if protocol == 1 { packet::checksum(&echo) } else { packet::transport_checksum(source, target, 58, &echo) };
            echo[2..4].copy_from_slice(&check.to_be_bytes());
            let request = packet::ip_packet(source, target, protocol, &echo, 64).unwrap();
            let reply = packet::control_reply(&request, &local).unwrap().unwrap();
            let parsed = IpPacket::parse(&reply).unwrap();
            assert_eq!(parsed.target, source);
            if target.to_string() == own { assert_eq!(&parsed.payload[4..], &echo[4..]); assert_eq!(parsed.payload[0], if protocol == 1 { 0 } else { 129 }); }
            else { assert_eq!(parsed.payload[0], if protocol == 1 { 3 } else { 1 }); assert_eq!(&parsed.payload[8..], &request); }
        }
    }
}
