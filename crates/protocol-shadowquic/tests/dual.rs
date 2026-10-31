mod common;
use common::*;
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{AddressedDatagram, ConnectContext, DatagramAssociation, Destination};
use kerlico_shadowquic::{ShadowQuicFactory, ShadowQuicNodeFactory};
use serde_json::json;
use std::{sync::atomic::Ordering, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinSet,
};
async fn tcp_echo(host: &str) -> (Destination, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let target = Destination::new(host, listener.local_addr().unwrap().port()).unwrap();
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {accepted=listener.accept()=>{let(mut stream,_)=accepted.unwrap();tasks.spawn(async move{let(mut read,mut write)=stream.split();let _=tokio::io::copy(&mut read,&mut write).await;});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
    });
    (target, task)
}
async fn receive(association: &mut DatagramAssociation) -> AddressedDatagram {
    tokio::time::timeout(Duration::from_secs(5), association.receiver.recv_from())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
async fn tcp(f: &Fixture, target: &Destination) {
    let mut stream = f
        .outbound
        .connect_tcp(target, &ConnectContext::new(Duration::from_secs(4)))
        .await
        .unwrap();
    let bytes = vec![7; 25000];
    stream.write_all(&bytes).await.unwrap();
    let mut answer = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer, bytes);
    stream.shutdown().await.unwrap();
    let mut out = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), stream.read(&mut out))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
#[tokio::test]
async fn complete_versions_modes_node_families_and_congestion_matrix() {
    let (four, t4) = tcp_echo("127.0.0.1").await;
    let (six, t6) = tcp_echo("::1").await;
    for version in ["v1", "v2"] {
        for mode in ["datagram", "stream"] {
            for host in ["127.0.0.1", "::1"] {
                for congestion in ["cubic", "newreno", "bbr"] {
                    let f = fixture(version, mode, host, congestion).await;
                    tcp(&f, &four).await;
                    tcp(&f, &six).await;
                    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let target =
                        Destination::new("127.0.0.1", socket.local_addr().unwrap().port()).unwrap();
                    let mut association = f
                        .outbound
                        .associate_udp(&ConnectContext::new(Duration::from_secs(4)))
                        .await
                        .unwrap();
                    let mut buffer = vec![0; 65535];
                    for size in if mode == "datagram" {
                        vec![0, 17, 900]
                    } else {
                        vec![0, 17, 12000, 65507]
                    } {
                        let data = vec![9; size];
                        association.sender.send_to(&data, &target).await.unwrap();
                        let (n, peer) = tokio::time::timeout(
                            Duration::from_secs(5),
                            socket.recv_from(&mut buffer),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        assert_eq!(&buffer[..n], data);
                        socket.send_to(&buffer[..n], peer).await.unwrap();
                        assert_eq!(receive(&mut association).await, (target.clone(), data));
                    }
                    assert!(
                        association
                            .sender
                            .send_to(&vec![0; 65508], &target)
                            .await
                            .is_err()
                    );
                    if mode == "datagram" {
                        assert!(
                            association
                                .sender
                                .send_to(&vec![0; 12000], &target)
                                .await
                                .is_err()
                        );
                    }
                    association
                        .sender
                        .send_to(b"after-rejection", &target)
                        .await
                        .unwrap();
                    let (n, peer) =
                        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
                            .await
                            .unwrap()
                            .unwrap();
                    socket.send_to(&buffer[..n], peer).await.unwrap();
                    assert_eq!(receive(&mut association).await.1, b"after-rejection");
                }
            }
        }
    }
    t4.abort();
    t6.abort();
}
#[tokio::test]
async fn full_cone_cross_family_unsolicited_source_domain_and_identity_separated_chain() {
    for version in ["v1", "v2"] {
        for mode in ["datagram", "stream"] {
            let downstream = fixture("v2", "stream", "::1", "cubic").await;
            let upstream = fixture_custom(
                version,
                mode,
                "127.0.0.1",
                "cubic",
                Some(downstream.outbound.clone()),
                2,
                64,
                Duration::from_secs(10),
            )
            .await;
            let mut association = upstream
                .outbound
                .associate_udp(&ConnectContext::new(Duration::from_secs(4)))
                .await
                .unwrap();
            let four = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let six = UdpSocket::bind("[::1]:0").await.unwrap();
            let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut bytes = [0; 64];
            let target = Destination::new("127.0.0.1", four.local_addr().unwrap().port()).unwrap();
            association.sender.send_to(b"four", &target).await.unwrap();
            let (n, peer4) =
                tokio::time::timeout(Duration::from_secs(5), four.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            four.send_to(&bytes[..n], peer4).await.unwrap();
            assert_eq!(receive(&mut association).await, (target, b"four".to_vec()));
            let target = Destination::new("::1", six.local_addr().unwrap().port()).unwrap();
            association.sender.send_to(b"six", &target).await.unwrap();
            let (n, peer6) =
                tokio::time::timeout(Duration::from_secs(5), six.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            six.send_to(&bytes[..n], peer6).await.unwrap();
            assert_eq!(receive(&mut association).await, (target, b"six".to_vec()));
            assert_eq!(peer4.port(), peer6.port());
            other.send_to(b"uncontacted", peer4).await.unwrap();
            assert_eq!(receive(&mut association).await.1, b"uncontacted");
            let target = Destination::new("localhost", four.local_addr().unwrap().port()).unwrap();
            association
                .sender
                .send_to(b"domain", &target)
                .await
                .unwrap();
            let (n, peer) =
                tokio::time::timeout(Duration::from_secs(5), four.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&bytes[..n], b"domain");
            assert_eq!(peer.port(), peer4.port());
        }
    }
}
#[tokio::test]
async fn wrong_credentials_and_server_name_never_open_target_access() {
    let (target, task) = tcp_echo("127.0.0.1").await;
    for version in ["v1", "v2"] {
        let f = fixture(version, "stream", "127.0.0.1", "cubic").await;
        for (key, value) in [
            ("username", "another-node"),
            ("password", "another-password"),
            ("server_name", "wrong.invalid"),
        ] {
            let mut options = f.options.clone();
            options[key] = json!(value);
            let outbound = ShadowQuicFactory.build(&options).unwrap();
            assert!(
                outbound
                    .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(3)))
                    .await
                    .is_err()
            );
            assert_eq!(f.count.load(Ordering::Acquire), 0);
        }
        let context = ConnectContext::new(Duration::from_secs(3));
        context.cancel.cancel();
        assert!(matches!(
            f.outbound.associate_udp(&context).await,
            Err(kerlico_core::Error::Cancelled)
        ));
    }
    task.abort();
}
#[tokio::test]
async fn ordinary_quic_is_forwarded_to_real_cover_and_reclaimed_without_business_access() {
    for (version_name, version) in [("v1", 1), ("v2", 0x6b3343cf)] {
        let f = fixture_custom(
            version_name,
            "stream",
            "127.0.0.1",
            "cubic",
            None,
            1,
            64,
            Duration::from_millis(700),
        )
        .await;
        let (endpoint, connection) = plain_connection(&f, version).await;
        assert_ne!(connection.is_jls(), Some(true));
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"cover-only").await.unwrap();
        let mut answer = [0; 10];
        tokio::time::timeout(Duration::from_secs(3), recv.read_exact(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&answer, b"cover-only");
        assert_eq!(f.count.load(Ordering::Acquire), 0);
        connection.close(0u32.into(), b"");
        endpoint.close(0u32.into(), b"");
        drop(connection);
        drop(endpoint);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if f.global.available_permits() == 64 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
}
#[tokio::test]
async fn bounded_cover_sources_do_not_crash_authenticated_endpoint() {
    let f = fixture_custom(
        "v2",
        "stream",
        "127.0.0.1",
        "cubic",
        None,
        1,
        2,
        Duration::from_secs(5),
    )
    .await;
    let (first, one) = plain_connection(&f, 0x6b3343cf).await;
    let (second, two) = plain_connection(&f, 0x6b3343cf).await;
    let third = jls_quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let attempt = third
        .connect_with(
            client_config(0x6b3343cf, Some(&f.cover.certificate), None),
            f.address,
            NAME,
        )
        .unwrap();
    let result = tokio::time::timeout(Duration::from_millis(800), attempt).await;
    assert!(!matches!(result, Ok(Ok(_))));
    let (target, echo) = tcp_echo("127.0.0.1").await;
    tcp(&f, &target).await;
    echo.abort();
    one.close(0u32.into(), b"");
    two.close(0u32.into(), b"");
    first.close(0u32.into(), b"");
    second.close(0u32.into(), b"");
    third.close(0u32.into(), b"");
}
#[tokio::test]
async fn half_close_and_node_exit_release_same_port() {
    for version in ["v1", "v2"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            stream.write_all(b"after-fin").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut f = fixture(version, "stream", "127.0.0.1", "cubic").await;
        let mut stream = f
            .outbound
            .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(4)))
            .await
            .unwrap();
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"after-fin");
        task.await.unwrap();
        drop(stream);
        f.stop().await;
        let socket = UdpSocket::bind(f.address).await.unwrap();
        drop(socket);
        assert_eq!(f.global.available_permits(), 64);
    }
}
#[tokio::test]
async fn multiplexed_tcp_and_udp_associations_keep_payloads_and_ports_separate() {
    let (target, echo) = tcp_echo("127.0.0.1").await;
    for version in ["v1", "v2"] {
        for mode in ["datagram", "stream"] {
            let f = fixture(version, mode, "127.0.0.1", "cubic").await;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_target =
                Destination::new("127.0.0.1", socket.local_addr().unwrap().port()).unwrap();
            let replying = tokio::spawn(async move {
                let mut ports = std::collections::BTreeSet::new();
                let mut bytes = [0; 2048];
                for _ in 0..8 {
                    let (n, peer) =
                        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut bytes))
                            .await
                            .unwrap()
                            .unwrap();
                    ports.insert(peer.port());
                    socket.send_to(&bytes[..n], peer).await.unwrap();
                }
                ports
            });
            let mut tasks = JoinSet::new();
            for index in 0..16 {
                let outbound = f.outbound.clone();
                let target = target.clone();
                tasks.spawn(async move {
                    let mut stream = outbound
                        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(4)))
                        .await
                        .unwrap();
                    let data = vec![index; 4096];
                    stream.write_all(&data).await.unwrap();
                    let mut answer = vec![0; data.len()];
                    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut answer))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(answer, data);
                    stream.shutdown().await.unwrap();
                });
            }
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
            for index in 0..8 {
                let outbound = f.outbound.clone();
                let target = udp_target.clone();
                let barrier = barrier.clone();
                tasks.spawn(async move {
                    let mut association = outbound
                        .associate_udp(&ConnectContext::new(Duration::from_secs(4)))
                        .await
                        .unwrap();
                    let data = vec![index + 40; 256];
                    association.sender.send_to(&data, &target).await.unwrap();
                    assert_eq!(receive(&mut association).await, (target, data));
                    barrier.wait().await;
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
            assert_eq!(replying.await.unwrap().len(), 8);
            assert_eq!(f.count.load(Ordering::Acquire), 24);
        }
    }
    echo.abort();
}
#[test]
fn rejects_unsupported_fields_duplicate_identity_and_non_association_egress() {
    let base = json!({"server":{"host":"127.0.0.1","port":10443},"server_name":NAME,"username":"node-1","password":"synthetic-password"});
    for (key, value) in [
        ("quic_version", json!("v3")),
        ("udp_mode", json!("fragmented")),
        ("zero_rtt", json!(true)),
        ("server_name", json!("127.0.0.1")),
        ("congestion_control", json!("brutal")),
    ] {
        let mut bad = base.clone();
        bad[key] = value;
        assert!(ShadowQuicFactory.build(&bad).is_err());
    }
    let options = json!({"server_name":NAME,"upstream":{"host":"127.0.0.1","port":443},"users":[{"username":"node-1","password":"first-password"},{"username":"node-1","password":"another-password"}]});
    assert!(ShadowQuicNodeFactory.build(&options).is_err());
    let options = json!({"server_name":NAME,"upstream":{"host":"127.0.0.1","port":443},"username":"node-1","password":"synthetic-password"});
    let mut registry = kerlico_config::Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register(kerlico_net::RejectFactory).unwrap();
    registry.register_node(ShadowQuicNodeFactory).unwrap();
    let mut config = json!({"version":1,"outbounds":[{"tag":"access","type":"direct"}],"inbounds":[],"nodes":[{"tag":"node4","type":"shadowquic","listen":"127.0.0.1:10443","outbound":"access","options":options},{"tag":"node6","type":"shadowquic","listen":"[::1]:10443","outbound":"access","options":options}]});
    config["nodes"][1]["options"]["password"] = json!("independent-password");
    let error = registry
        .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
        .err()
        .unwrap();
    assert!(error.to_string().contains("凭据重复"));
    config["nodes"][1]["options"]["username"] = json!("node-2");
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_ok()
    );
    config["outbounds"][0]["type"] = json!("reject");
    let error = registry
        .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
        .err()
        .unwrap();
    assert!(error.to_string().contains("多目标 UDP 关联"));
}
