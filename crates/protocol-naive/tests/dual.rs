mod common;
use common::*;
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{Destination, Error};
use kerlico_naive::{NaiveFactory, NaiveNodeFactory};
use serde_json::json;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
async fn all_transports_both_node_families_tcp_udp_and_domain_targets() {
    for transport in ["h1", "h2", "h3"] {
        for host in ["127.0.0.1", "::1"] {
            let mut fixture = fixture(transport, host, 2).await;
            let context = fixture.context();
            for target_host in ["127.0.0.1", "::1"] {
                let echo = tcp_echo(target_host).await;
                tcp(&fixture.outbound, &context, &echo.target, 257024).await;
                let echo = udp_echo(target_host).await;
                for size in [0, 17, 12000, 65507] {
                    udp(&fixture.outbound, &context, &echo.target, size).await;
                }
            }
            let echo = tcp_echo("127.0.0.1").await;
            let target = Destination::new("localhost", echo.target.port()).unwrap();
            tcp(&fixture.outbound, &context, &target, 17).await;
            fixture.stop().await;
        }
    }
}
#[tokio::test]
async fn legacy_uot_fixed_and_full_cone_both_families() {
    for transport in ["h1", "h2", "h3"] {
        let mut fixture = fixture(transport, "127.0.0.1", 1).await;
        let context = fixture.context();
        for host in ["127.0.0.1", "::1"] {
            let echo = udp_echo(host).await;
            udp(&fixture.outbound, &context, &echo.target, 0).await;
            udp(&fixture.outbound, &context, &echo.target, 12000).await;
        }
        let first = udp_echo("127.0.0.1").await;
        let second = udp_echo("::1").await;
        let mut association = fixture.outbound.associate_udp(&context).await.unwrap();
        for (target, bytes) in [
            (&first.target, b"first".as_slice()),
            (&second.target, b"second".as_slice()),
        ] {
            association.sender.send_to(bytes, target).await.unwrap();
            let (source, packet) =
                tokio::time::timeout(Duration::from_secs(4), association.receiver.recv_from())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(&source, target);
            assert_eq!(&packet, bytes);
        }
        assert!(fixture.associations.load(Ordering::Acquire) >= 3);
        drop(association);
        fixture.stop().await;
    }
}
#[tokio::test]
async fn h2_h3_concurrent_streams_share_session_and_survive_neighbor_drop() {
    for transport in ["h2", "h3"] {
        let mut fixture = fixture(transport, "127.0.0.1", 2).await;
        let context = fixture.context();
        let echo = Arc::new(tcp_echo("127.0.0.1").await);
        let udp_echo = Arc::new(udp_echo("127.0.0.1").await);
        let mut tasks = tokio::task::JoinSet::new();
        let barrier = Arc::new(tokio::sync::Barrier::new(24));
        for i in 0..24 {
            let outbound = fixture.outbound.clone();
            let context = context.clone();
            let echo = echo.clone();
            let datagram = udp_echo.clone();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                if i < 16 {
                    tcp(&outbound, &context, &echo.target, 65536 + i).await;
                } else {
                    udp(&outbound, &context, &datagram.target, 12000).await;
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(fixture.accepts.load(Ordering::Acquire), 1);
        let dropped = fixture
            .outbound
            .connect_tcp(&echo.target, &context)
            .await
            .unwrap();
        drop(dropped);
        tcp(&fixture.outbound, &context, &echo.target, 17).await;
        fixture.stop().await;
    }
}
#[tokio::test]
async fn full_cone_preserves_socket_port_across_targets_and_uncontacted_source() {
    for transport in ["h1", "h2", "h3"] {
        let mut fixture = fixture(transport, "127.0.0.1", 2).await;
        let context = fixture.context();
        let mut association = fixture.outbound.associate_udp(&context).await.unwrap();
        let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let third = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut remote_port = None;
        for socket in [&first, &second] {
            let target = Destination::new(
                &socket.local_addr().unwrap().ip().to_string(),
                socket.local_addr().unwrap().port(),
            )
            .unwrap();
            association.sender.send_to(b"probe", &target).await.unwrap();
            let mut bytes = [0; 32];
            let (n, source) =
                tokio::time::timeout(Duration::from_secs(4), socket.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&bytes[..n], b"probe");
            if let Some(port) = remote_port {
                assert_eq!(source.port(), port);
            } else {
                remote_port = Some(source.port());
            }
        }
        third
            .send_to(b"uncontacted", ("127.0.0.1", remote_port.unwrap()))
            .await
            .unwrap();
        let (source, packet) =
            tokio::time::timeout(Duration::from_secs(4), association.receiver.recv_from())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(source.port(), third.local_addr().unwrap().port());
        assert_eq!(packet, b"uncontacted");
        assert_eq!(fixture.associations.load(Ordering::Acquire), 1);
        drop(association);
        fixture.stop().await;
    }
}
#[tokio::test]
async fn native_half_close_delivers_target_eof_then_reverse_reply() {
    for transport in ["h1", "h2", "h3"] {
        let mut fixture = fixture(transport, "127.0.0.1", 2).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"request");
            stream.write_all(b"after EOF").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = fixture
            .outbound
            .connect_tcp(&target, &fixture.context())
            .await
            .unwrap();
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        let result = tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut bytes))
            .await
            .unwrap();
        assert!(
            result.is_ok(),
            "{transport} 半关闭后读取失败：{result:?}，已收{}字节",
            bytes.len()
        );
        assert_eq!(bytes, b"after EOF");
        server.await.unwrap();
        fixture.stop().await;
    }
}
#[tokio::test]
async fn authentication_name_ca_and_reserved_address_fail_before_target_access() {
    for transport in ["h1", "h2", "h3"] {
        let mut fixture = fixture(transport, "127.0.0.1", 2).await;
        let echo = tcp_echo("127.0.0.1").await;
        for change in ["password", "name", "ca"] {
            let mut options = fixture.options.clone();
            match change {
                "password" => options["password"] = json!("wrong-secret"),
                "name" => options["tls"]["server_name"] = json!("wrong.invalid"),
                _ => {
                    options["tls"].as_object_mut().unwrap().remove("ca_pem");
                }
            }
            let bad = NaiveFactory.build(&options).unwrap();
            assert!(
                bad.connect_tcp(&echo.target, &fixture.context())
                    .await
                    .is_err()
            );
        }
        let magic = Destination::new("sp.v2.udp-over-tcp.arpa", 1).unwrap();
        assert!(
            fixture
                .outbound
                .connect_tcp(&magic, &fixture.context())
                .await
                .is_err()
        );
        assert_eq!(fixture.accesses.load(Ordering::Acquire), 0);
        tcp(&fixture.outbound, &fixture.context(), &echo.target, 17).await;
        fixture.stop().await;
    }
}
#[tokio::test]
async fn configuration_rejects_unimplemented_flags_and_invalid_combinations() {
    let mut fixture = fixture("h2", "127.0.0.1", 2).await;
    for (key, value) in [
        ("transport", json!("h2c")),
        ("max_sessions", json!(0)),
        ("max_streams", json!(0)),
        ("insecure", json!(true)),
        ("utls", json!({})),
        ("quic_version", json!("v2")),
    ] {
        let mut options = fixture.options.clone();
        options[key] = value;
        assert!(NaiveFactory.build(&options).is_err());
    }
    let mut options = fixture.options.clone();
    options["transport"] = json!("h3");
    assert!(
        NaiveFactory::build_with_connector(&options, Arc::new(kerlico_net::TcpConnector::plain()))
            .is_err()
    );
    let mut node = fixture.node_options.clone();
    node["transports"] = json!(["h2", "h2"]);
    assert!(NaiveNodeFactory.build(&node).is_err());
    let mut options = fixture.options.clone();
    options["udp_over_tcp"]["enabled"] = json!(false);
    let outbound = NaiveFactory.build(&options).unwrap();
    assert!(!outbound.supports_udp_association());
    assert!(matches!(
        outbound.associate_udp(&fixture.context()).await,
        Err(Error::Unsupported(_))
    ));
    fixture.stop().await;
}
#[tokio::test]
async fn independent_ipv4_ipv6_nodes_reject_each_others_real_credentials() {
    for transport in ["h1", "h2", "h3"] {
        let mut left = fixture_named(
            transport,
            "127.0.0.1",
            2,
            1,
            Duration::from_secs(2),
            "node4",
            "independent-four",
        )
        .await;
        let mut right = fixture_named(
            transport,
            "::1",
            2,
            1,
            Duration::from_secs(2),
            "node6",
            "independent-six",
        )
        .await;
        let four = tcp_echo("127.0.0.1").await;
        let six = tcp_echo("::1").await;
        let mut crossed = left.options.clone();
        crossed["server"] = right.options["server"].clone();
        crossed["tls"] = right.options["tls"].clone();
        let bad = NaiveFactory.build(&crossed).unwrap();
        assert!(
            bad.connect_tcp(&four.target, &right.context())
                .await
                .is_err()
        );
        assert_eq!(right.accesses.load(Ordering::Acquire), 0);
        let mut crossed = right.options.clone();
        crossed["server"] = left.options["server"].clone();
        crossed["tls"] = left.options["tls"].clone();
        let bad = NaiveFactory.build(&crossed).unwrap();
        assert!(bad.connect_tcp(&six.target, &left.context()).await.is_err());
        assert_eq!(left.accesses.load(Ordering::Acquire), 0);
        tcp(&left.outbound, &left.context(), &six.target, 12000).await;
        tcp(&right.outbound, &right.context(), &four.target, 12000).await;
        left.stop().await;
        right.stop().await;
    }
}
#[tokio::test]
async fn actual_stream_limit_waits_with_timeout_then_recovers_after_release() {
    for transport in ["h1", "h2", "h3"] {
        let mut fixture = fixture(transport, "127.0.0.1", 2).await;
        let mut options = fixture.options.clone();
        options["max_streams"] = json!(1);
        let outbound = NaiveFactory.build(&options).unwrap();
        let echo = tcp_echo("127.0.0.1").await;
        let held = outbound
            .connect_tcp(&echo.target, &fixture.context())
            .await
            .unwrap();
        let mut short = fixture.context();
        short.timeout = Duration::from_millis(70);
        assert!(matches!(
            outbound.connect_tcp(&echo.target, &short).await,
            Err(Error::Timeout)
        ));
        assert_eq!(fixture.accesses.load(Ordering::Acquire), 1);
        drop(held);
        tcp(&outbound, &fixture.context(), &echo.target, 17).await;
        fixture.stop().await;
    }
}
#[tokio::test]
async fn slow_download_does_not_block_neighbor_and_idle_session_is_reaped() {
    for transport in ["h2", "h3"] {
        let mut fixture = fixture(transport, "127.0.0.1", 2).await;
        let echo = tcp_echo("127.0.0.1").await;
        let mut slow = fixture
            .outbound
            .connect_tcp(&echo.target, &fixture.context())
            .await
            .unwrap();
        slow.write_u32(2 * 1024 * 1024).await.unwrap();
        slow.write_all(&vec![51; 2 * 1024 * 1024]).await.unwrap();
        slow.flush().await.unwrap();
        tcp(&fixture.outbound, &fixture.context(), &echo.target, 17).await;
        assert_eq!(fixture.accepts.load(Ordering::Acquire), 1);
        drop(slow);
        tokio::time::sleep(Duration::from_millis(2200)).await;
        tcp(&fixture.outbound, &fixture.context(), &echo.target, 17).await;
        assert_eq!(fixture.accepts.load(Ordering::Acquire), 2);
        fixture.stop().await;
    }
}
#[tokio::test]
async fn default_node_binds_tcp_and_udp_same_port_and_prefers_h2_alpn() {
    use kerlico_core::{
        AccessService, CancellationToken, InboundContext, NodeEvent, NodeObserver, StreamBudget,
    };
    struct Observer;
    impl NodeObserver for Observer {
        fn record(&self, _: NodeEvent) {}
    }
    let certificate = rcgen::generate_simple_self_signed(vec!["proxy.invalid".into()]).unwrap();
    let cert = certificate.cert.pem();
    let key = certificate.signing_key.serialize_pem();
    let node=NaiveNodeFactory.build(&json!({"users":[{"username":"dual-node","password":"dual-secret"}],"tls":{"certificate_pem":cert,"private_key_pem":key},"udp_over_tcp":true})).unwrap();
    assert!(node.supports_tcp() && node.supports_udp());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let socket = Arc::new(tokio::net::UdpSocket::bind(address).await.unwrap());
    let cancel = CancellationToken::new();
    let context = InboundContext {
        peer_addr: None,
        local_addr: Some(address),
        cancel: cancel.clone(),
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 16,
        stream_budget: StreamBudget::new(
            Arc::new(tokio::sync::Semaphore::new(32)),
            Arc::new(tokio::sync::Semaphore::new(32)),
        ),
        events: Arc::new(Observer),
    };
    let access: Arc<dyn AccessService> = Arc::new(kerlico_egress::Egress::new(
        kerlico_net::DirectFactory.build(&json!({})).unwrap(),
    ));
    let udp_node = node.clone();
    let udp_access = access.clone();
    let udp_context = context.clone();
    let udp_task = tokio::spawn(async move {
        udp_node
            .handle_udp(socket, udp_access, udp_context)
            .await
            .unwrap();
    });
    let tcp_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {biased;_=context.cancel.cancelled()=>break,_=tasks.join_next(),if !tasks.is_empty()=>{},incoming=listener.accept()=>{let(stream,peer)=incoming.unwrap();let lease=context.stream_budget.try_acquire().unwrap();let node=node.clone();let access=access.clone();let mut context=context.clone();context.peer_addr=Some(peer);tasks.spawn(async move{let _lease=lease;let _=node.handle(Box::new(stream),access,context).await;});}}
        }
        while tasks.join_next().await.is_some() {}
    });
    let echo = tcp_echo("127.0.0.1").await;
    let connection = kerlico_core::ConnectContext::new(Duration::from_secs(5));
    for transport in ["h1", "h2", "h3"] {
        let outbound=NaiveFactory.build(&json!({"server":{"host":"127.0.0.1","port":address.port()},"username":"dual-node","password":"dual-secret","tls":{"server_name":"proxy.invalid","ca_pem":cert},"transport":transport})).unwrap();
        tcp(&outbound, &connection, &echo.target, 12000).await;
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(&cert))
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap()
    {
        roots.add(certificate).unwrap();
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let raw = tokio::net::TcpStream::connect(address).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(
            rustls::pki_types::ServerName::try_from("proxy.invalid").unwrap(),
            raw,
        )
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    drop(tls);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(3), tcp_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), udp_task)
        .await
        .unwrap()
        .unwrap();
}
