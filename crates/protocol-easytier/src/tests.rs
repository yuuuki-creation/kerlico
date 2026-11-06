use crate::{
    client::{node_context, packet_target, select_dhcp_address, start},
    config::ClientOptions,
};
use cidr::Ipv4Inet;
use easytier::{
    common::config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
    peers::{
        create_packet_recv_chan,
        peer_manager::{PeerManager, RouteAlgoType},
    },
    tunnel::{TunnelListener, tcp::TcpTunnelListener},
};
use kerlico_core::{Error, ServiceContext};
use serde_json::json;
use std::{collections::HashSet, net::IpAddr, sync::Arc, time::Duration};

fn options(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "network_name": "n",
        "network_secret": "s",
        "peers": ["tcp://192.0.2.1:11010"],
    });
    for (key, value) in overrides.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}
fn prepare(value: serde_json::Value) -> kerlico_core::Result<crate::config::Prepared> {
    serde_json::from_value::<ClientOptions>(value)
        .map_err(|_| Error::Config("字段".into()))?
        .prepare()
}

#[test]
fn peers_accept_only_explicit_tcp_and_udp_endpoints() {
    for peer in ["tcp://192.0.2.1:11010", "udp://relay.example.net:11010"] {
        assert!(prepare(options(json!({"peers": [peer]}))).is_ok(), "{peer}");
    }
    for peer in [
        "quic://192.0.2.1:11012",
        "wss://192.0.2.1:11011",
        "tcp://192.0.2.1",
        "tcp://192.0.2.1:11010/path",
        "192.0.2.1:11010",
    ] {
        assert!(
            prepare(options(json!({"peers": [peer]}))).is_err(),
            "{peer}"
        );
    }
    assert!(prepare(options(json!({"peers": []}))).is_err());
}

#[test]
fn identity_and_addresses_are_validated_at_compile_time() {
    assert!(prepare(options(json!({"network_name": ""}))).is_err());
    assert!(prepare(options(json!({"network_secret": ""}))).is_err());
    assert!(prepare(options(json!({"ipv4": "not-an-address"}))).is_err());
    assert!(prepare(options(json!({"ipv4": "127.0.0.1/8"}))).is_err());
    assert!(prepare(options(json!({"encryption": "chacha20"}))).is_err());
    assert!(prepare(options(json!({"unknown": 1}))).is_err());
    let prepared = prepare(options(
        json!({"ipv4": "10.144.144.5/24", "ipv6": "fd00::5/64"}),
    ))
    .unwrap();
    assert_eq!(prepared.ipv4.unwrap().to_string(), "10.144.144.5/24");
    assert_eq!(prepared.ipv6.unwrap().to_string(), "fd00::5/64");
}

#[test]
fn dialer_options_that_cannot_reach_upstream_sockets_are_rejected() {
    use kerlico_config::OutboundFactory;
    let marked = kerlico_core::DialerOptions {
        routing_mark: Some(0x2333),
        ..kerlico_core::DialerOptions::default()
    };
    let result = kerlico_core::with_compile_dialer(marked, || {
        crate::EasyTierFactory.compile(&options(json!({})))
    });
    assert!(matches!(result, Err(Error::Config(_))));
    assert!(crate::EasyTierFactory.compile(&options(json!({}))).is_ok());
}

#[test]
fn packet_target_reads_ipv4_and_ipv6_destination() {
    let mut ipv4 = [0u8; 20];
    ipv4[0] = 0x45;
    ipv4[16..20].copy_from_slice(&[10, 144, 144, 1]);
    assert_eq!(packet_target(&ipv4), Some(IpAddr::from([10, 144, 144, 1])));
    let mut ipv6 = [0u8; 40];
    ipv6[0] = 0x60;
    ipv6[39] = 5;
    assert_eq!(packet_target(&ipv6), "::5".parse().ok());
    assert_eq!(packet_target(&ipv4[..19]), None);
    assert_eq!(packet_target(&[0x10; 40]), None);
    assert_eq!(packet_target(&[]), None);
}

#[test]
fn dhcp_selection_follows_the_network_and_avoids_conflicts() {
    let inet = |value: &str| value.parse::<Ipv4Inet>().unwrap();
    assert_eq!(
        select_dhcp_address(&HashSet::new(), None),
        Some(inet("10.126.126.1/24"))
    );
    let used = HashSet::from([inet("10.144.144.1/24"), inet("10.144.144.2/24")]);
    assert_eq!(
        select_dhcp_address(&used, None),
        Some(inet("10.144.144.3/24"))
    );
    assert_eq!(
        select_dhcp_address(&used, Some(inet("10.144.144.9/24"))),
        Some(inet("10.144.144.9/24")),
        "可用地址保持不变"
    );
    assert_eq!(
        select_dhcp_address(&used, Some(inet("10.144.144.2/24"))),
        Some(inet("10.144.144.3/24")),
        "冲突时换地址"
    );
    assert_eq!(
        select_dhcp_address(&used, Some(inet("10.126.126.1/24"))),
        Some(inet("10.144.144.3/24")),
        "网段变化时换地址"
    );
    let full = HashSet::from([inet("10.0.0.1/30"), inet("10.0.0.2/30")]);
    assert_eq!(select_dhcp_address(&full, None), None);
}

/// 用上游库本身作对端：网络名与密钥一致时路由互通，服务关闭后对端能看到节点离开。
#[tokio::test]
async fn joins_network_and_leaves_on_service_shutdown() {
    let config = TomlConfigLoader::default();
    config.set_network_identity(NetworkIdentity::new("n".into(), "s".into()));
    config.set_ipv4(Some("10.144.144.1/24".parse().unwrap()));
    let (sender, _nic) = create_packet_recv_chan();
    let server = Arc::new(PeerManager::new(
        RouteAlgoType::Ospf,
        node_context(config),
        sender,
    ));
    server.run().await.unwrap();

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut listener = TcpTunnelListener::new(format!("tcp://127.0.0.1:{port}").parse().unwrap());
    listener.listen().await.unwrap();
    let accepting = server.clone();
    let accept = tokio::spawn(async move {
        while let Ok(tunnel) = listener.accept().await {
            let _ = accepting.add_tunnel_as_server(tunnel, true).await;
        }
    });

    let prepared = prepare(options(json!({
        "peers": [format!("tcp://127.0.0.1:{port}")],
        "ipv4": "10.144.144.5/24",
    })))
    .unwrap();
    let host = ServiceContext::for_test();
    let outbound = start(prepared, host.clone()).await.unwrap();

    tokio::time::timeout(Duration::from_secs(30), async {
        while !server.list_routes().await.iter().any(|route| {
            route.ipv4_addr.is_some_and(|ip| {
                Ipv4Inet::from(ip).address() == std::net::Ipv4Addr::new(10, 144, 144, 5)
            })
        }) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("对端应通过路由同步看到本节点地址");

    outbound.shutdown().await.unwrap();
    drop(outbound);
    host.shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
        .await;
    tokio::time::timeout(Duration::from_secs(30), async {
        while !server
            .get_peer_map()
            .list_peers_with_conn()
            .await
            .is_empty()
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("服务关闭后对端连接应结束");
    accept.abort();
}
