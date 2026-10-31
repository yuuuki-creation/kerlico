mod common;

use common::*;
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination};
use kerlico_sudoku::SudokuFactory;
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

#[tokio::test]
async fn six_carriers_three_methods_dual_stack_tcp_and_uot() {
    for ipv6 in [false, true] {
        for mode in ["raw", "legacy", "stream", "poll", "auto", "ws"] {
            for aead in ["aes-128-gcm", "chacha20-poly1305", "none"] {
                let fixture = Fixture::start(mode, aead, "off", ipv6).await;
                for host in ["127.0.0.1", "::1", "localhost"] {
                    let target = Destination::new(host, 443).unwrap();
                    exchange(
                        &fixture.outbound,
                        &target,
                        (0..96000).map(|i| (i % 251) as u8).collect(),
                    )
                    .await;
                    let context = ConnectContext::new(WAIT);
                    let mut udp = fixture
                        .outbound
                        .connect_udp(&target, &context)
                        .await
                        .unwrap();
                    for size in [0, 1, 4096, 65507] {
                        let packet = vec![(size % 251) as u8; size];
                        udp.sender.send(&packet).await.unwrap();
                        assert_eq!(
                            timeout(WAIT, udp.receiver.recv())
                                .await
                                .unwrap()
                                .unwrap()
                                .unwrap(),
                            packet,
                            "mode={mode} aead={aead} ipv6={ipv6} host={host} size={size}"
                        );
                    }
                }
                assert!(
                    fixture
                        .state
                        .decoded
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|target| target.host() == "localhost")
                );
                assert!(
                    fixture
                        .state
                        .resolved
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|target| target.host() == "127.0.0.1")
                );
                fixture.close().await;
            }
        }
    }
}

#[tokio::test]
async fn table_directions_pure_packed_padding_and_rotated_layouts() {
    for mode in ["raw", "stream", "poll", "ws"] {
        for table in [
            "prefer_ascii",
            "prefer_entropy",
            "up_ascii_down_entropy",
            "up_entropy_down_ascii",
        ] {
            for pure in [false, true] {
                let state = Arc::new(State::default());
                let mut options = node_options(mode, KEY, "chacha20-poly1305");
                options["protocol"]["table_type"] = json!(table);
                options["protocol"]["pure_downlink"] = json!(pure);
                options["protocol"]["padding_min"] = json!(20);
                options["protocol"]["padding_max"] = json!(40);
                if table != "prefer_ascii" {
                    options["protocol"]["custom_tables"] = json!(["xpxvvpvv", "pxxvvpvv"]);
                }
                let server =
                    Running::start(configuration(options.clone(), false, false), state).await;
                let mut client = client_options(
                    server.addresses["node"],
                    mode,
                    KEY,
                    "chacha20-poly1305",
                    "off",
                );
                client["protocol"] = options["protocol"].clone();
                let outbound = SudokuFactory.build(&client).unwrap();
                for port in [443, 8443, 9443] {
                    exchange(
                        &outbound,
                        &Destination::new("127.0.0.1", port).unwrap(),
                        vec![port as u8; 16000],
                    )
                    .await;
                }
                drop(outbound);
                server.close().await;
            }
        }
    }
}

#[tokio::test]
async fn tls_h1_h2_split_and_h1_websocket_validate_chain_and_name() {
    for ipv6 in [false, true] {
        for (mode, version) in [
            ("stream", "h1"),
            ("stream", "h2"),
            ("poll", "h1"),
            ("poll", "h2"),
            ("auto", "h1"),
            ("auto", "h2"),
            ("ws", "h1"),
        ] {
            let (cert, key) = certificates();
            let mut node = node_options(mode, KEY, "aes-128-gcm");
            node["http_mask"]["tls"] = json!({"cert_pem":cert,"key_pem":key});
            node["http_mask"]["path_root"] = json!("secret-segment");
            let server =
                Running::start(configuration(node, ipv6, false), Arc::new(State::default())).await;
            let mut options =
                client_options(server.addresses["node"], mode, KEY, "aes-128-gcm", "off");
            options["http_mask"] = json!({"mode":mode,"tls":{"server_name":"localhost","ca_pem":cert},"host":"localhost","http_version":version,"path_root":"secret-segment"});
            let outbound = SudokuFactory.build(&options).unwrap();
            exchange(
                &outbound,
                &Destination::new("localhost", 443).unwrap(),
                vec![0xa5; 24000],
            )
            .await;
            let context = ConnectContext::new(WAIT);
            let target = Destination::new("::1", 53).unwrap();
            let mut udp = outbound.connect_udp(&target, &context).await.unwrap();
            udp.sender.send(&[]).await.unwrap();
            assert_eq!(
                timeout(WAIT, udp.receiver.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
                Vec::<u8>::new()
            );
            drop(udp);
            drop(outbound);
            for (name, ca) in [
                ("wrong.invalid", cert.clone()),
                ("localhost", certificates().0),
            ] {
                options["http_mask"]["tls"] = json!({"server_name":name,"ca_pem":ca});
                let bad = SudokuFactory.build(&options).unwrap();
                assert!(
                    bad.connect_tcp(&target, &context).await.is_err(),
                    "mode={mode} version={version} name={name}"
                );
            }
            server.close().await;
        }
    }
}

#[tokio::test]
async fn two_node_credentials_never_cross_accept_or_fallback() {
    let state = Arc::new(State::default());
    let mut value = configuration(node_options("auto", KEY, "chacha20-poly1305"), false, false);
    let mut second = value["nodes"][0].clone();
    second["tag"] = json!("node6");
    second["listen"] = json!("[::1]:0");
    second["options"]["protocol"]["key"] = json!(OTHER_KEY);
    value["nodes"].as_array_mut().unwrap().push(second);
    let server = Running::start(value, state.clone()).await;
    for (tag, key, wrong) in [("node", KEY, OTHER_KEY), ("node6", OTHER_KEY, KEY)] {
        for mode in ["raw", "legacy", "stream", "poll", "auto", "ws"] {
            eprintln!("验证独立节点正向接入: 节点={tag} 载体={mode}");
            let target = Destination::new("127.0.0.1", 443).unwrap();
            let good = SudokuFactory
                .build(&client_options(
                    server.addresses[tag],
                    mode,
                    key,
                    "chacha20-poly1305",
                    "off",
                ))
                .unwrap();
            exchange(&good, &target, vec![1; 1024]).await;
            let before = state.decoded.lock().unwrap().len();
            let bad = SudokuFactory
                .build(&client_options(
                    server.addresses[tag],
                    mode,
                    wrong,
                    "chacha20-poly1305",
                    "off",
                ))
                .unwrap();
            let result = bad.connect_tcp(&target, &ConnectContext::new(WAIT)).await;
            if let Ok(mut stream) = result {
                let mut byte = [0; 1];
                assert!(
                    !matches!(timeout(WAIT, stream.read(&mut byte)).await, Ok(Ok(1))),
                    "错误凭据收到目标数据: tag={tag} mode={mode}"
                );
            }
            assert_eq!(state.decoded.lock().unwrap().len(), before);
        }
    }
    assert!(server.node_stats["node"].accepted.load(Ordering::Relaxed) > 0);
    assert!(server.node_stats["node6"].accepted.load(Ordering::Relaxed) > 0);
    server.close().await;
}

#[test]
fn normalized_seed_aliases_and_none_obey_registry_gates() {
    let scalar = (1u64..64)
        .map(Scalar::from)
        .find(|s| CompressedEdwardsY(s.to_bytes()).decompress().is_none())
        .unwrap();
    let public = hex(EdwardsPoint::mul_base(&scalar).compress().as_bytes());
    let r = Scalar::from(2u64);
    let mut split = Vec::from(r.to_bytes());
    split.extend_from_slice(&(scalar - r).to_bytes());
    let aliases = [
        hex(&scalar.to_bytes()),
        public.clone(),
        public.to_uppercase(),
        hex(&split),
    ];
    for key in &aliases {
        let mut value = configuration(node_options("raw", &public, "aes-128-gcm"), false, false);
        let mut second = value["nodes"][0].clone();
        second["tag"] = json!("node6");
        second["listen"] = json!("[::1]:0");
        second["options"]["protocol"]["key"] = json!(key);
        value["nodes"].as_array_mut().unwrap().push(second);
        assert!(prepare(value, Arc::new(State::default())).is_err());
    }
    let options = node_options("raw", KEY, "none");
    assert!(
        prepare(
            configuration(options.clone(), false, false),
            Arc::new(State::default())
        )
        .is_err()
    );
    assert!(
        prepare(
            configuration(options.clone(), false, true),
            Arc::new(State::default())
        )
        .is_ok()
    );
    let mut nonlocal = configuration(options, false, true);
    nonlocal["local_inbounds"][0]["listen"] = json!("0.0.0.0:10443");
    assert!(prepare(nonlocal, Arc::new(State::default())).is_err());
    let mut shared = configuration(node_options("raw", KEY, "aes-128-gcm"), false, false);
    shared["local_inbounds"] = json!([{"tag":"local","type":"sudoku","listen":"[::1]:0","outbound":"exit","options":node_options("raw",KEY,"none")}]);
    assert!(prepare(shared, Arc::new(State::default())).is_err());
    let mut unsafe_out = client_options(
        "127.0.0.1:10443".parse().unwrap(),
        "raw",
        KEY,
        "none",
        "off",
    );
    unsafe_out["server"]["host"] = json!("localhost");
    assert!(SudokuFactory.build(&unsafe_out).is_err());
}

#[tokio::test]
async fn public_looking_and_split_key_aliases_use_the_same_real_secret() {
    let scalar = (1u64..64)
        .map(Scalar::from)
        .find(|s| CompressedEdwardsY(s.to_bytes()).decompress().is_none())
        .unwrap();
    let public = hex(EdwardsPoint::mul_base(&scalar).compress().as_bytes());
    let server = Running::start(
        configuration(node_options("raw", &public, "aes-128-gcm"), false, false),
        Arc::new(State::default()),
    )
    .await;
    let r = Scalar::from(5u64);
    let mut split = Vec::from(r.to_bytes());
    split.extend_from_slice(&(scalar - r).to_bytes());
    for key in [public, hex(&scalar.to_bytes()), hex(&split)] {
        let outbound = SudokuFactory
            .build(&client_options(
                server.addresses["node"],
                "raw",
                &key,
                "aes-128-gcm",
                "off",
            ))
            .unwrap();
        exchange(
            &outbound,
            &Destination::new("127.0.0.1", 443).unwrap(),
            vec![9; 512],
        )
        .await;
    }
    server.close().await;
}

#[tokio::test]
async fn uot_multi_target_empty_maximum_reject_oversize_and_keep_association() {
    for mode in ["raw", "legacy", "stream", "poll", "auto", "ws"] {
        let fixture = Fixture::start(mode, "chacha20-poly1305", "off", false).await;
        let context = ConnectContext::new(WAIT);
        let mut udp = fixture.outbound.associate_udp(&context).await.unwrap();
        for (host, port) in [("127.0.0.1", 53), ("::1", 5353), ("localhost", 853)] {
            let target = Destination::new(host, port).unwrap();
            for size in [0, 65507] {
                let packet = vec![0x42; size];
                udp.sender.send_to(&packet, &target).await.unwrap();
                let (from, received) = timeout(WAIT, udp.receiver.recv_from())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(from.port(), port);
                assert_eq!(received, packet);
                if host != "localhost" {
                    assert_eq!(from, target);
                }
            }
            assert!(udp.sender.send_to(&vec![1; 65508], &target).await.is_err());
            udp.sender
                .send_to(b"after-oversize", &target)
                .await
                .unwrap();
            assert_eq!(
                timeout(WAIT, udp.receiver.recv_from())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .1,
                b"after-oversize"
            );
        }
        assert_eq!(fixture.state.associations.load(Ordering::SeqCst), 1);
        context.cancel.cancel();
        assert!(
            timeout(WAIT, udp.receiver.recv_from())
                .await
                .unwrap()
                .is_err()
        );
        drop(udp);
        fixture.close().await;
    }
}

#[tokio::test]
async fn real_direct_egress_preserves_source_port_and_full_cone_unsolicited_source() {
    let mut config = configuration(node_options("stream", KEY, "aes-128-gcm"), false, false);
    config["outbounds"][0]["type"] = json!("direct");
    let server = Running::start(config, Arc::new(State::default())).await;
    let outbound = SudokuFactory
        .build(&client_options(
            server.addresses["node"],
            "stream",
            KEY,
            "aes-128-gcm",
            "off",
        ))
        .unwrap();
    let context = ConnectContext::new(WAIT);
    let mut channel = outbound.associate_udp(&context).await.unwrap();
    let mut port = None;
    let mut reached4 = None;
    for host in ["127.0.0.1", "::1", "127.0.0.1"] {
        let socket = UdpSocket::bind((host, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let target = Destination::new(host, address.port()).unwrap();
        for bytes in [vec![], vec![0x12; 65507]] {
            channel.sender.send_to(&bytes, &target).await.unwrap();
            let mut buffer = vec![0; 65535];
            let (count, source) = timeout(WAIT, socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..count], bytes);
            if let Some(port) = port {
                assert_eq!(source.port(), port);
            } else {
                port = Some(source.port());
            }
            if source.is_ipv4() {
                reached4 = Some(source);
            }
            socket.send_to(&buffer[..count], source).await.unwrap();
            let (from, received) = timeout(WAIT, channel.receiver.recv_from())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(from, target);
            assert_eq!(received, bytes);
        }
    }
    let unsolicited = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    unsolicited
        .send_to(b"uncontacted-source", reached4.unwrap())
        .await
        .unwrap();
    let (from, packet) = timeout(WAIT, channel.receiver.recv_from())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(from.port(), unsolicited.local_addr().unwrap().port());
    assert_eq!(packet, b"uncontacted-source");
    drop(channel);
    drop(outbound);
    server.close().await;
}

#[tokio::test]
async fn tcp_rekey_crosses_32_mib_in_both_directions_without_tail_loss() {
    let fixture = Fixture::start("raw", "aes-128-gcm", "off", false).await;
    let target = Destination::new("127.0.0.1", 443).unwrap();
    let context = ConnectContext::new(std::time::Duration::from_secs(30));
    let mut stream = fixture
        .outbound
        .connect_tcp(&target, &context)
        .await
        .unwrap();
    banner(&mut stream).await;
    let (mut read, mut write) = tokio::io::split(stream);
    let send = async {
        let chunk = vec![0x7c; 32768];
        for index in 0..1025usize {
            write.write_all(&chunk).await.unwrap();
            if index.is_multiple_of(128) {eprintln!("重钥发送进度: 已接纳{}个32768字节块", index+1);}
        }
        write.shutdown().await.unwrap();
    };
    let receive = async {
        let mut bytes = vec![0; 32768];
        for index in 0..1025usize {
            read.read_exact(&mut bytes).await.unwrap();
            assert!(bytes.iter().all(|b| *b == 0x7c));
            if index.is_multiple_of(128) {eprintln!("重钥接收进度: 已校验{}个32768字节块", index+1);}
        }
        let mut tail = Vec::new();
        read.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, TAIL);
    };
    timeout(std::time::Duration::from_secs(120), async {
        tokio::join!(send, receive);
    })
    .await
    .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn both_engines_forward_tcp_udp_and_validate_websocket_eof_capability() {
    for mode in ["raw", "legacy", "stream", "poll", "auto", "ws"] {
        let fixture = Fixture::start(mode, "chacha20-poly1305", "off", false).await;
        let options = client_options(
            fixture.server.addresses["node"],
            mode,
            KEY,
            "chacha20-poly1305",
            "off",
        );
        let mut value = json!({"version":1,"outbounds":[{"tag":"proxy","type":"sudoku","options":options}],"inbounds":[{"tag":"tcp","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"localhost","port":443},"outbound":"proxy","require_remote_eof":mode!="ws"},{"tag":"udp","type":"udp-forward","listen":"127.0.0.1:0","target":{"host":"::1","port":53},"outbound":"proxy"}],"limits":{"connect_timeout_ms":3000,"drain_timeout_ms":300,"max_datagram_size":65507}});
        let client = Running::start(value.clone(), Arc::new(State::default())).await;
        let mut stream = TcpStream::connect(client.addresses["tcp"]).await.unwrap();
        let mut banner_bytes = [0; 5];
        stream.read_exact(&mut banner_bytes).await.unwrap();
        assert_eq!(&banner_bytes, BANNER);
        stream.write_all(b"two-engines").await.unwrap();
        let mut bytes = [0; 11];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"two-engines");
        if mode != "ws" {
            stream.shutdown().await.unwrap();
            let mut tail = Vec::new();
            timeout(WAIT, stream.read_to_end(&mut tail))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(tail, TAIL);
        }
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for bytes in [vec![], vec![2; 65507]] {
            socket
                .send_to(&bytes, client.addresses["udp"])
                .await
                .unwrap();
            let mut buf = vec![0; 65535];
            let (n, _) = timeout(WAIT, socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], bytes);
        }
        drop(stream);
        client.close().await;
        if mode == "ws" {
            value["inbounds"][0]["require_remote_eof"] = json!(true);
            assert!(prepare(value, Arc::new(State::default())).is_err());
        }
        fixture.close().await;
    }
}

#[tokio::test]
async fn disabled_udp_and_rejected_target_do_not_create_association() {
    let state = Arc::new(State::default());
    let mut node = node_options("raw", KEY, "chacha20-poly1305");
    node["protocol"]["udp_enabled"] = json!(false);
    let server = Running::start(configuration(node, false, false), state.clone()).await;
    let options = client_options(
        server.addresses["node"],
        "raw",
        KEY,
        "chacha20-poly1305",
        "off",
    );
    let outbound = SudokuFactory.build(&options).unwrap();
    assert!(
        outbound
            .associate_udp(&ConnectContext::new(WAIT))
            .await
            .is_err()
    );
    assert_eq!(state.associations.load(Ordering::SeqCst), 0);
    let mut disabled = options;
    disabled["protocol"]["udp_enabled"] = json!(false);
    let no_udp = SudokuFactory.build(&disabled).unwrap();
    assert!(!no_udp.capabilities().udp);
    assert!(!no_udp.supports_udp_association());
    assert!(
        no_udp
            .associate_udp(&ConnectContext::new(WAIT))
            .await
            .is_err()
    );
    let target = Destination::new("127.0.0.1", 1).unwrap();
    if let Ok(mut stream) = outbound
        .connect_tcp(&target, &ConnectContext::new(WAIT))
        .await
    {
        let mut byte = [0; 1];
        assert!(!matches!(
            timeout(WAIT, stream.read(&mut byte)).await,
            Ok(Ok(1))
        ));
    }
    exchange(
        &outbound,
        &Destination::new("127.0.0.1", 443).unwrap(),
        vec![5; 1024],
    )
    .await;
    drop(outbound);
    drop(no_udp);
    server.close().await;
}

#[tokio::test]
async fn tls_h2_mux_concurrent_streams_share_transport_and_independent_fin() {
    let (cert, key) = certificates();
    let state = Arc::new(State::default());
    let mut node = node_options("auto", KEY, "chacha20-poly1305");
    node["http_mask"]["tls"] = json!({"cert_pem":cert,"key_pem":key});
    let server = Running::start(configuration(node, false, false), state.clone()).await;
    for version in ["h1", "h2"] {
        let mut options = client_options(
            server.addresses["node"],
            "stream",
            KEY,
            "chacha20-poly1305",
            "on",
        );
        options["http_mask"] = json!({"mode":"stream","tls":{"server_name":"localhost","ca_pem":cert},"http_version":version});
        let outbound = SudokuFactory.build(&options).unwrap();
        let mut held = outbound
            .connect_tcp(
                &Destination::new("127.0.0.1", 443).unwrap(),
                &ConnectContext::new(WAIT),
            )
            .await
            .unwrap();
        banner(&mut held).await;
        let count = state.physical.load(Ordering::SeqCst);
        let mut jobs = tokio::task::JoinSet::new();
        for index in 0..8 {
            let outbound = outbound.clone();
            jobs.spawn(async move {
                exchange(
                    &outbound,
                    &Destination::new("::1", 10000 + index).unwrap(),
                    vec![index as u8; 32768],
                )
                .await;
            });
        }
        while let Some(result) = jobs.join_next().await {
            result.unwrap();
        }
        assert_eq!(state.physical.load(Ordering::SeqCst), count);
        held.shutdown().await.unwrap();
        let mut tail = Vec::new();
        timeout(WAIT, held.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, TAIL);
        drop(held);
        drop(outbound);
    }
    server.close().await;
}
