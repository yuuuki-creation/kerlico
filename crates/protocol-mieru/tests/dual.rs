mod common;
use common::*;
use kerlico_config::{Config, NodeFactory, OutboundFactory, Registry};
use kerlico_core::{CancellationToken, ConnectContext, Destination};
use kerlico_mieru::{MieruFactory, MieruNodeFactory};
use serde_json::{Value, json};
use std::{sync::atomic::Ordering, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinSet,
};

#[tokio::test]
async fn tcp_and_explicit_local_udp_transports_mux_lazy_and_address_families() {
    let t4 = tcp_echo("127.0.0.1").await;
    let t6 = tcp_echo("::1").await;
    let u4 = udp_echo("127.0.0.1").await;
    let u6 = udp_echo("::1").await;
    for transport in ["tcp", "udp"] {
        for host in ["127.0.0.1", "::1"] {
            for multiplex in [false, true] {
                for no_wait in [false, true] {
                    let mut setup = Setup::new(transport, host);
                    setup.multiplex = multiplex;
                    setup.no_wait = no_wait;
                    let mut f = fixture(setup).await;
                    assert!(!f.outbound.capabilities().tcp_eof);
                    tcp(&f, &t4.target, 32768).await;
                    tcp(&f, &t6.target, 8193).await;
                    let mut association = f.outbound.associate_udp(&f.context()).await.unwrap();
                    for target in [&u4.target, &u6.target] {
                        for size in [0, 17, 12000, 65507] {
                            let body = vec![(size % 251) as u8; size];
                            association.sender.send_to(&body, target).await.unwrap();
                            let result = tokio::time::timeout(
                                Duration::from_secs(8),
                                association.receiver.recv_from(),
                            )
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap();
                            assert_eq!(result, (target.clone(), body));
                        }
                    }
                    assert!(
                        association
                            .sender
                            .send_to(&[0; 65508], &u4.target)
                            .await
                            .is_err()
                    );
                    association
                        .sender
                        .send_to(b"after-limit", &u4.target)
                        .await
                        .unwrap();
                    assert_eq!(
                        association.receiver.recv_from().await.unwrap().unwrap().1,
                        b"after-limit"
                    );
                    drop(association);
                    assert_eq!(f.count.load(Ordering::Acquire), 3);
                    f.stop().await;
                }
            }
        }
    }
}
#[tokio::test]
async fn all_low_entropy_modes_rotations_and_32768_boundary_use_complete_wire_codec() {
    let target = tcp_echo("127.0.0.1").await;
    let packet = udp_echo("127.0.0.1").await;
    for transport in ["tcp", "udp"] {
        for mode in 1..=4 {
            for rotation in [0, 7, 48] {
                let mut setup = Setup::new(transport, "127.0.0.1");
                setup.mode = mode;
                setup.rotation = rotation;
                let mut f = fixture(setup).await;
                tcp(&f, &target.target, 32768).await;
                let mut channel = f
                    .outbound
                    .connect_udp(&packet.target, &f.context())
                    .await
                    .unwrap();
                for size in [0, 17, 4096] {
                    let data = vec![mode; size];
                    channel.sender.send(&data).await.unwrap();
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(5), channel.receiver.recv())
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap(),
                        data
                    );
                }
                drop(channel);
                f.stop().await;
            }
        }
    }
}
#[tokio::test]
async fn actual_tcp_multiplex_reuses_carrier_and_concurrent_sessions_stay_separate() {
    let target = tcp_echo("127.0.0.1").await;
    let packet = udp_echo("127.0.0.1").await;
    let mut f = fixture(Setup::new("tcp", "127.0.0.1")).await;
    for _ in 0..3 {
        tcp(&f, &target.target, 257024).await;
    }
    assert_eq!(f.accepts.load(Ordering::Acquire), 1);
    let mut work = JoinSet::new();
    for index in 0..16 {
        let out = f.outbound.clone();
        let target = target.target.clone();
        let context = f.context();
        work.spawn(async move {
            let mut stream = out.connect_tcp(&target, &context).await.unwrap();
            let data = vec![index; 65536 + usize::from(index)];
            stream.write_u32(data.len() as u32).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.flush().await.unwrap();
            let mut echo = vec![0; data.len()];
            stream.read_exact(&mut echo).await.unwrap();
            assert_eq!(echo, data);
            let mut end = [0];
            assert_eq!(stream.read(&mut end).await.unwrap(), 0);
        });
    }
    for index in 0..8 {
        let out = f.outbound.clone();
        let target = packet.target.clone();
        let context = f.context();
        work.spawn(async move {
            let mut association = out.associate_udp(&context).await.unwrap();
            let data = vec![index; 12000];
            association.sender.send_to(&data, &target).await.unwrap();
            assert_eq!(
                association.receiver.recv_from().await.unwrap().unwrap(),
                (target, data)
            );
        });
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(result) = work.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(f.accepts.load(Ordering::Acquire), 1);
    f.stop().await;
}
#[tokio::test]
async fn full_cone_cross_family_same_source_port_unsolicited_and_identity_separated_chain() {
    for transport in ["tcp", "udp"] {
        let mut second_setup = Setup::new("tcp", "::1");
        second_setup.identity = 2;
        let mut second = fixture(second_setup).await;
        let mut first_setup = Setup::new(transport, "127.0.0.1");
        first_setup.outbound = Some(second.outbound.clone());
        let mut first = fixture(first_setup).await;
        let ipv4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = ipv4.local_addr().unwrap().port();
        let ipv6 = UdpSocket::bind(("::1", port)).await.unwrap();
        let target4 = Destination::new("localhost", port).unwrap();
        let target6 = Destination::new("::1", port).unwrap();
        let mut association = first
            .outbound
            .associate_udp(&first.context())
            .await
            .unwrap();
        let mut bytes = [0; 32];
        association.sender.send_to(b"four", &target4).await.unwrap();
        let (n, from4) = ipv4.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], b"four");
        ipv4.send_to(b"reply4", from4).await.unwrap();
        let (source, body) = association.receiver.recv_from().await.unwrap().unwrap();
        assert_eq!(source, Destination::new("127.0.0.1", port).unwrap());
        assert_eq!(body, b"reply4");
        association.sender.send_to(b"six", &target6).await.unwrap();
        let (n, from6) = ipv6.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], b"six");
        assert_eq!(from4.port(), from6.port());
        ipv6.send_to(b"reply6", from6).await.unwrap();
        assert_eq!(
            association.receiver.recv_from().await.unwrap().unwrap(),
            (target6, b"reply6".to_vec())
        );
        let unsolicited = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        unsolicited.send_to(b"unsolicited", from4).await.unwrap();
        let (source, body) =
            tokio::time::timeout(Duration::from_secs(3), association.receiver.recv_from())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(source.port(), unsolicited.local_addr().unwrap().port());
        assert_eq!(body, b"unsolicited");
        assert_eq!(first.count.load(Ordering::Acquire), 1);
        assert_eq!(second.count.load(Ordering::Acquire), 1);
        drop(association);
        first.stop().await;
        second.stop().await;
    }
}
#[tokio::test]
async fn one_cancelled_context_does_not_break_another_stream_or_implicit_nonce_order() {
    let hold = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", hold.local_addr().unwrap().port()).unwrap();
    let holding = tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok((stream, _)) = hold.accept().await {
            streams.push(stream);
        }
    });
    let echo = tcp_echo("127.0.0.1").await;
    let mut f = fixture(Setup::new("tcp", "127.0.0.1")).await;
    let cancel = CancellationToken::new();
    let context = ConnectContext {
        cancel: cancel.clone(),
        timeout: Duration::from_secs(4),
    };
    let mut first = f.outbound.connect_tcp(&target, &context).await.unwrap();
    let survivor = f.outbound.connect_tcp(&target, &f.context()).await.unwrap();
    cancel.cancel();
    let mut byte = [0];
    let end = tokio::time::timeout(Duration::from_secs(1), first.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(end, Ok(0) | Err(_)));
    tcp(&f, &echo.target, 65536).await;
    assert_eq!(f.accepts.load(Ordering::Acquire), 1);
    drop(first);
    drop(survivor);
    holding.abort();
    f.stop().await;
}
fn registry() -> Registry {
    let mut registry = Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register(MieruFactory).unwrap();
    registry.register_node(MieruNodeFactory).unwrap();
    registry
}
fn config(node: Value, local: bool) -> Config {
    let mut value =
        json!({"version":1,"inbounds":[],"outbounds":[{"tag":"direct","type":"direct"}]});
    value.as_object_mut().unwrap().insert(
        if local { "local_inbounds" } else { "nodes" }.into(),
        json!([node]),
    );
    serde_json::from_value(value).unwrap()
}
#[test]
fn unsafe_udp_is_not_a_public_authenticated_node_and_unknown_options_are_rejected() {
    let safe = json!({"username":"node-user","password":"synthetic-password"});
    let udp = json!({"username":"node-user","password":"synthetic-password","transport":"udp","unsafe_udp_compatibility":true});
    let node = MieruNodeFactory.build(&safe).unwrap();
    assert!(!node.credential_fingerprints().is_empty());
    assert!(!node.requires_loopback());
    let local = MieruNodeFactory.build(&udp).unwrap();
    assert!(local.credential_fingerprints().is_empty());
    assert!(local.requires_loopback());
    let spec = json!({"tag":"node","type":"mieru","listen":"127.0.0.1:10443","outbound":"direct","options":udp});
    assert!(registry().prepare(config(spec.clone(), false)).is_err());
    assert!(registry().prepare(config(spec.clone(), true)).is_ok());
    let mut public = spec.clone();
    public["listen"] = json!("0.0.0.0:10443");
    assert!(registry().prepare(config(public, true)).is_err());
    let secure_node = json!({"tag":"secure","type":"mieru","listen":"127.0.0.1:11443","outbound":"direct","options":safe});
    let crossing: Config = serde_json::from_value(json!({"version":1,"inbounds":[],"outbounds":[{"tag":"direct","type":"direct"}],"nodes":[secure_node],"local_inbounds":[spec]})).unwrap();
    assert!(registry().prepare(crossing).is_err());
    for options in [
        json!({"username":"node-user","password":"synthetic-password","transport":"udp"}),
        json!({"username":"node-user","password":"synthetic-password","transport":"tcp","unsafe_udp_compatibility":true}),
        json!({"username":"node-user","password":"synthetic-password","transport":"both"}),
        json!({"username":"node-user","password":"synthetic-password","unknown":true}),
        json!({"username":"node-user","password":"synthetic-password","traffic":{"low_entropy_mode":1,"mask_rotation":17}}),
    ] {
        assert!(MieruNodeFactory.build(&options).is_err());
    }
    for host in ["localhost", "192.0.2.1", "::ffff:127.0.0.1"] {
        let options = json!({"server":{"host":host,"port":10443},"username":"node-user","password":"synthetic-password","transport":"udp","unsafe_udp_compatibility":true});
        assert!(MieruFactory.build(&options).is_err());
    }
    let a = json!({"tag":"a","type":"mieru","listen":"127.0.0.1:10443","outbound":"direct","options":safe});
    let mut b = a.clone();
    b["tag"] = json!("b");
    b["listen"] = json!("[::1]:10443");
    b["options"]["password"] = json!("other-synthetic-password");
    let cfg: Config = serde_json::from_value(json!({"version":1,"inbounds":[],"outbounds":[{"tag":"direct","type":"direct"}],"nodes":[a,b]})).unwrap();
    assert!(registry().prepare(cfg).is_err());
}
#[tokio::test]
async fn wrong_tcp_credentials_and_local_udp_decode_mismatch_open_no_target() {
    let echo = tcp_echo("127.0.0.1").await;
    for transport in ["tcp", "udp"] {
        for no_wait in [false, true] {
            let mut f = fixture(Setup::new(transport, "127.0.0.1")).await;
            for field in ["username", "password"] {
                let mut options = f.options.clone();
                options[field] = json!("wrong-synthetic-value");
                options["no_wait"] = json!(no_wait);
                let out = MieruFactory.build(&options).unwrap();
                let context = ConnectContext {
                    cancel: f.cancel.clone(),
                    timeout: Duration::from_millis(300),
                };
                match out.connect_tcp(&echo.target, &context).await {
                    Err(_) => {}
                    Ok(mut stream) => {
                        assert!(no_wait);
                        let result = tokio::time::timeout(Duration::from_secs(2), async {
                            stream.write_all(b"synthetic").await?;
                            stream.flush().await
                        })
                        .await
                        .unwrap();
                        assert!(result.is_err());
                    }
                }
                drop(out);
                assert_eq!(f.count.load(Ordering::Acquire), 0);
            }
            f.stop().await;
        }
    }
}
#[test]
fn nodes_require_association_capability_and_eof_capability_is_not_invented() {
    let mut r = registry();
    r.register(kerlico_net::RejectFactory).unwrap();
    let config: Config = serde_json::from_value(json!({"version":1,"inbounds":[],"outbounds":[{"tag":"reject","type":"reject"}],"nodes":[{"tag":"node","type":"mieru","listen":"127.0.0.1:10443","outbound":"reject","options":{"username":"node-user","password":"synthetic-password"}}]})).unwrap();
    assert!(r.prepare(config).is_err());
    let config: Config = serde_json::from_value(json!({"version":1,"inbounds":[{"tag":"input","type":"tcp-forward","listen":"127.0.0.1:12443","outbound":"proxy","target":{"host":"127.0.0.1","port":13443},"require_remote_eof":true}],"outbounds":[{"tag":"proxy","type":"mieru","options":{"server":{"host":"127.0.0.1","port":10443},"username":"node-user","password":"synthetic-password"}}]})).unwrap();
    assert!(r.prepare(config).is_err());
}
#[test]
fn identity_and_actual_secret_fingerprints_have_separate_domains() {
    let one = MieruNodeFactory
        .build(&json!({"username":"node-user","password":"synthetic-password"}))
        .unwrap();
    let changed = MieruNodeFactory
        .build(&json!({"username":"node-user","password":"different-synthetic-password"}))
        .unwrap();
    let local = MieruNodeFactory.build(&json!({"username":"node-user","password":"synthetic-password","transport":"udp","unsafe_udp_compatibility":true})).unwrap();
    assert_ne!(
        one.credential_fingerprints(),
        changed.credential_fingerprints()
    );
    assert!(local.credential_fingerprints().is_empty());
    let a = one.credential_isolation_fingerprints("mieru");
    let b = changed.credential_isolation_fingerprints("mieru");
    let u = local.credential_isolation_fingerprints("mieru");
    let fingerprint = |values: &[kerlico_core::ScopedCredentialFingerprint], domain: &str| {
        values
            .iter()
            .find(|value| value.protocol == domain)
            .unwrap()
            .fingerprint
    };
    assert_eq!(fingerprint(&a, "mieru-user"), fingerprint(&b, "mieru-user"));
    assert_ne!(fingerprint(&a, "mieru"), fingerprint(&b, "mieru"));
    assert_eq!(fingerprint(&a, "mieru"), fingerprint(&u, "mieru"));
    let different = MieruNodeFactory.build(&json!({"username":"local-user","password":"synthetic-password","transport":"udp","unsafe_udp_compatibility":true})).unwrap().credential_isolation_fingerprints("mieru");
    assert_ne!(fingerprint(&a, "mieru"), fingerprint(&different, "mieru"));
    assert_ne!(
        fingerprint(&a, "mieru-user"),
        fingerprint(&different, "mieru-user")
    );
    let cfg: Config = serde_json::from_value(json!({"version":1,"inbounds":[],"outbounds":[{"tag":"direct","type":"direct"}],"nodes":[{"tag":"remote","type":"mieru","listen":"127.0.0.1:10443","outbound":"direct","options":{"username":"node-user","password":"synthetic-password"}}],"local_inbounds":[{"tag":"local","type":"mieru","listen":"127.0.0.1:11443","outbound":"direct","options":{"username":"local-user","password":"synthetic-password","transport":"udp","unsafe_udp_compatibility":true}}]})).unwrap();
    assert!(registry().prepare(cfg).is_ok());
}
