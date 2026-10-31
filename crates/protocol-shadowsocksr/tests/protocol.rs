use kerlico_core::{
    AccessService, AddressedDatagram, BoxFuture, BoxStream, CancellationToken, ConnectContext,
    DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel,
    Destination, Error, InboundContext, InboundProtocol, NodeEvent, NodeObserver, Outbound, Result,
    StreamBudget,
};
use kerlico_shadowsocksr::{
    CIPHERS, OBFS, PROTOCOLS, ShadowsocksRNode, ShadowsocksRNodeFactory, ShadowsocksROutbound,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{Semaphore, mpsc},
    task::JoinSet,
};

#[derive(Default)]
struct Events;
impl NodeObserver for Events {
    fn record(&self, _: NodeEvent) {}
}
fn context(global: Arc<Semaphore>) -> InboundContext {
    InboundContext {
        cancel: CancellationToken::new(),
        connect_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65000,
        max_streams: 64,
        stream_budget: StreamBudget::new(global, Arc::new(Semaphore::new(128))),
        events: Arc::new(Events),
        local_addr: None,
        peer_addr: None,
    }
}
#[derive(Default)]
struct Echo(AtomicUsize);
struct Sender(mpsc::Sender<AddressedDatagram>);
struct Receiver(mpsc::Receiver<AddressedDatagram>);
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        data: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .send((target.clone(), data.to_vec()))
                .await
                .map_err(|_| Error::Cancelled)
        })
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
impl AccessService for Echo {
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (sender, receiver) = mpsc::channel(32);
            Ok(DatagramAssociation {
                sender: Box::new(Sender(sender)),
                receiver: Box::new(Receiver(receiver)),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("测试要求统一多目标关联")) })
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (public, mut server) = tokio::io::duplex(65536);
            tokio::spawn(async move {
                if server.write_all(b"B|").await.is_err() {
                    return;
                }
                let mut buffer = vec![0; 8192];
                while let Ok(count) = server.read(&mut buffer).await {
                    if count == 0 {
                        let _ = server.write_all(b"|EOF").await;
                        let _ = server.shutdown().await;
                        break;
                    }
                    if server.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(public) as BoxStream)
        })
    }
}
fn users(protocol: &str) -> bool {
    protocol.starts_with("auth_aes128") || protocol.starts_with("auth_chain")
}
fn common(method: &str, protocol: &str, obfs: &str) -> Value {
    json!({"method":method,"password":"synthetic-ssr-secret","protocol":protocol,"obfs":obfs,"allow_insecure":true})
}
struct Fixture {
    outbound: ShadowsocksROutbound,
    context: InboundContext,
    tcp: tokio::task::JoinHandle<()>,
    udp: tokio::task::JoinHandle<Result<()>>,
    access: Arc<Echo>,
    global: Arc<Semaphore>,
    client_options: Value,
}
async fn endpoints(method: &str, protocol: &str, obfs: &str, multi: bool, ipv6: bool) -> Fixture {
    endpoints_timeout(method, protocol, obfs, multi, ipv6, Duration::from_secs(30)).await
}
async fn endpoints_timeout(
    method: &str,
    protocol: &str,
    obfs: &str,
    multi: bool,
    ipv6: bool,
    idle: Duration,
) -> Fixture {
    let mut node_options = common(method, protocol, obfs);
    if multi {
        node_options["users"] = json!([{"id":7,"password":"synthetic-user-seven"},{"id":8,"password":"synthetic-user-eight"}]);
    }
    let node = Arc::new(ShadowsocksRNode::from_options(&node_options).unwrap());
    let host = if ipv6 { "::1" } else { "127.0.0.1" };
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let socket = Arc::new(UdpSocket::bind((host, port)).await.unwrap());
    let global = Arc::new(Semaphore::new(256));
    let mut context = context(global.clone());
    context.idle_timeout = idle;
    let access = Arc::new(Echo::default());
    let tcp = {
        let node = node.clone();
        let context = context.clone();
        let access = access.clone();
        tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {biased;_ = context.cancel.cancelled()=>break,_ = tasks.join_next(),if !tasks.is_empty()=>{},accepted=listener.accept()=>{let (stream,peer)=accepted.unwrap();let Ok(lease)=context.stream_budget.try_acquire() else{continue};let node=node.clone();let mut context=context.clone();context.local_addr=stream.local_addr().ok();context.peer_addr=Some(peer);let access=access.clone();tasks.spawn(async move{let _lease=lease;if let Err(error)=node.handle(Box::new(stream),access,context).await{eprintln!("SSR测试服务端会话结束：{error:?}");}});}}
            }
            while tasks.join_next().await.is_some() {}
        })
    };
    let udp = {
        let context = context.clone();
        let access = access.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, context).await })
    };
    let mut client_options = common(method, protocol, obfs);
    client_options["server"] = json!({"host":host,"port":port});
    if multi {
        client_options["user"] = json!({"id":7,"password":"synthetic-user-seven"});
    }
    let outbound = ShadowsocksROutbound::from_options(&client_options).unwrap();
    Fixture {
        outbound,
        context,
        tcp,
        udp,
        access,
        global,
        client_options,
    }
}
async fn close(fixture: Fixture) {
    fixture.context.cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), fixture.tcp)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), fixture.udp)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(fixture.global.available_permits(), 256);
}
async fn tcp(outbound: &ShadowsocksROutbound, target: &Destination, size: usize) {
    let mut stream = outbound
        .connect_tcp(target, &ConnectContext::new(Duration::from_secs(10)))
        .await
        .unwrap();
    let mut banner = [0; 2];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut banner))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&banner, b"B|");
    let payload = vec![0x45; size];
    let (mut receive, mut send) = tokio::io::split(stream);
    let writing = async {
        send.write_all(&payload).await.unwrap();
        send.shutdown().await.unwrap();
    };
    let reading = async {
        let mut reply = Vec::new();
        receive.read_to_end(&mut reply).await.unwrap();
        let mut expected = payload.clone();
        expected.extend_from_slice(b"|EOF");
        assert_eq!(reply, expected);
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(writing, reading);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn all_cipher_and_protocol_pairs_preserve_tcp_and_udp() {
    for method in CIPHERS {
        for protocol in PROTOCOLS {
            eprintln!("SSR 方法 {method} 协议 {protocol}");
            let fixture = endpoints(method, protocol, "plain", false, false).await;
            let target = Destination::new("example.invalid", 443).unwrap();
            tcp(&fixture.outbound, &target, 1024).await;
            let mut packet = fixture
                .outbound
                .connect_udp(&target, &ConnectContext::new(Duration::from_secs(10)))
                .await
                .unwrap();
            for payload in [vec![], vec![0x22; 257]] {
                packet.sender.send(&payload).await.unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(10), packet.receiver.recv())
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap(),
                    payload
                );
            }
            drop(packet);
            assert_eq!(fixture.access.0.load(Ordering::Relaxed), 2);
            close(fixture).await;
        }
    }
}
#[tokio::test]
async fn all_protocol_obfs_pairs_cover_dual_stack_and_packet_boundaries() {
    for protocol in PROTOCOLS {
        for obfs in OBFS {
            for ipv6 in [false, true] {
                let fixture = endpoints("aes-128-cfb", protocol, obfs, users(protocol), ipv6).await;
                for host in ["127.0.0.1", "::1", "example.invalid"] {
                    eprintln!("SSR 协议 {protocol} 混淆 {obfs} IPv6 {ipv6} 目标 {host}");
                    let target = Destination::new(host, 443).unwrap();
                    tcp(&fixture.outbound, &target, 32768).await;
                    if *obfs == "plain" {
                        let mut channel = fixture
                            .outbound
                            .connect_udp(&target, &ConnectContext::new(Duration::from_secs(10)))
                            .await
                            .unwrap();
                        for payload in [vec![], vec![1; 4096], vec![2; 64000]] {
                            channel.sender.send(&payload).await.unwrap();
                            assert_eq!(
                                tokio::time::timeout(
                                    Duration::from_secs(10),
                                    channel.receiver.recv()
                                )
                                .await
                                .unwrap()
                                .unwrap()
                                .unwrap(),
                                payload
                            );
                        }
                    }
                }
                close(fixture).await;
            }
        }
    }
}
#[tokio::test]
async fn duplex_progress_does_not_depend_on_a_detached_actor() {
    for obfs in ["plain", "http_simple", "tls1.2_ticket_auth"] {
        let fixture = endpoints("chacha20-ietf", "auth_chain_b", obfs, true, false).await;
        tcp(
            &fixture.outbound,
            &Destination::new("example.invalid", 443).unwrap(),
            2 * 1024 * 1024,
        )
        .await;
        close(fixture).await;
    }
}
#[tokio::test]
async fn invalid_password_uid_and_user_key_never_open_a_target() {
    for protocol in PROTOCOLS {
        if *protocol == "origin" {
            continue;
        }
        let fixture = endpoints("aes-128-cfb", protocol, "plain", users(protocol), false).await;
        let mut mutations = vec![("password", json!("different-base-secret"))];
        if users(protocol) {
            mutations.push(("user", json!({"id":99,"password":"synthetic-user-seven"})));
            mutations.push(("user", json!({"id":7,"password":"incorrect-user-key"})));
        }
        for (field, value) in mutations {
            let mut options = fixture.client_options.clone();
            options[field] = value;
            let outbound = ShadowsocksROutbound::from_options(&options).unwrap();
            if let Ok(mut stream) = outbound
                .connect_tcp(
                    &Destination::new("example.invalid", 443).unwrap(),
                    &ConnectContext::new(Duration::from_secs(2)),
                )
                .await
            {
                let mut data = [0; 1];
                let result =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut data)).await;
                if let Ok(Ok(count)) = result {
                    assert_eq!(count, 0);
                }
            }
        }
        assert_eq!(fixture.access.0.load(Ordering::Relaxed), 0);
        close(fixture).await;
    }
}
#[test]
fn missing_authentication_is_local_only_and_unknown_settings_are_rejected() {
    use kerlico_config::{Registry, parse};
    let mut registry = Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register_node(ShadowsocksRNodeFactory).unwrap();
    for protocol in PROTOCOLS {
        for obfs in OBFS {
            for udp in [false, true] {
                let mut options = common("none", protocol, obfs);
                options["udp"] = json!(udp);
                let node = ShadowsocksRNode::from_options(&options).unwrap();
                let authenticated = (*protocol != "origin" || obfs.starts_with("tls1.2"))
                    && (!udp || users(protocol));
                assert_eq!(!node.credential_fingerprints().is_empty(), authenticated);
                let spec = json!({"tag":"ssr","type":"shadowsocksr","listen":"127.0.0.1:0","outbound":"direct","options":options});
                let config = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[spec]});
                let parsed = parse(&serde_json::to_vec(&config).unwrap()).unwrap();
                assert_eq!(
                    registry.prepare(parsed).is_ok(),
                    authenticated,
                    "{protocol} {obfs} udp={udp}"
                );
                let mut local = config.clone();
                local["nodes"] = json!([]);
                local["local_inbounds"] = config["nodes"].clone();
                assert!(
                    registry
                        .prepare(parse(&serde_json::to_vec(&local).unwrap()).unwrap())
                        .is_ok()
                );
            }
        }
    }
    for mutate in [
        json!({"method":"aes-128-gcm"}),
        json!({"protocol":"auth_sha1_v4_compatible"}),
        json!({"obfs":"unknown"}),
        json!({"user":{"id":1,"password":"x"}}),
    ] {
        let mut options = common("aes-128-cfb", "origin", "plain");
        for (key, value) in mutate.as_object().unwrap() {
            options[key] = value.clone();
        }
        assert!(ShadowsocksRNode::from_options(&options).is_err());
    }
    let mut options = common("aes-128-cfb", "auth_chain_a", "plain");
    options["allow_insecure"] = json!(false);
    assert!(ShadowsocksRNode::from_options(&options).is_err());
}

#[tokio::test]
async fn association_idle_limit_and_cancel_are_observable() {
    let fixture = endpoints_timeout(
        "aes-128-cfb",
        "auth_aes128_md5",
        "plain",
        true,
        false,
        Duration::from_millis(100),
    )
    .await;
    let mut options = fixture.client_options.clone();
    options["limits"] = json!({"max_sessions":1});
    let outbound = ShadowsocksROutbound::from_options(&options).unwrap();
    let establish = ConnectContext::new(Duration::from_secs(2));
    let target = Destination::new("127.0.0.1", 53).unwrap();
    let mut channel = outbound.associate_udp(&establish).await.unwrap();
    channel.sender.send_to(b"first", &target).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .1,
        b"first"
    );
    assert!(outbound.connect_tcp(&target, &establish).await.is_err());
    tokio::time::sleep(Duration::from_millis(350)).await;
    channel.sender.send_to(b"renewed", &target).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .1,
        b"renewed"
    );
    assert_eq!(fixture.access.0.load(Ordering::Relaxed), 2);
    establish.cancel.cancel();
    assert!(channel.sender.send_to(b"cancelled", &target).await.is_err());
    assert!(channel.receiver.recv_from().await.is_err());
    drop(channel);
    close(fixture).await;
}
#[tokio::test]
async fn real_egress_keeps_full_cone_port_across_families_and_zero_packets() {
    use kerlico_config::OutboundFactory;
    let mut options = common("none", "auth_chain_b", "tls1.2_ticket_auth");
    options["users"] = json!([{"id":7,"password":"synthetic-user-seven"}]);
    let node = ShadowsocksRNode::from_options(&options).unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy = socket.local_addr().unwrap();
    let global = Arc::new(Semaphore::new(128));
    let context = context(global.clone());
    let direct = kerlico_net::DirectFactory.build(&json!({})).unwrap();
    let access = Arc::new(kerlico_egress::Egress::new(direct));
    let task = {
        let context = context.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, context).await })
    };
    options.as_object_mut().unwrap().remove("users");
    options["server"] = json!({"host":"127.0.0.1","port":proxy.port()});
    options["user"] = json!({"id":7,"password":"synthetic-user-seven"});
    let outbound = ShadowsocksROutbound::from_options(&options).unwrap();
    let mut channel = outbound
        .associate_udp(&ConnectContext::new(Duration::from_secs(3)))
        .await
        .unwrap();
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind(("::1", a.local_addr().unwrap().port()))
        .await
        .unwrap();
    let target4 = Destination::new("127.0.0.1", a.local_addr().unwrap().port()).unwrap();
    let target6 = Destination::new("::1", b.local_addr().unwrap().port()).unwrap();
    let mut buffer = vec![0; 65536];
    channel.sender.send_to(b"four", &target4).await.unwrap();
    let (count, peer4) = tokio::time::timeout(Duration::from_secs(2), a.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..count], b"four");
    a.send_to(b"four-reply", peer4).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (target4.clone(), b"four-reply".to_vec())
    );
    channel.sender.send_to(b"six", &target6).await.unwrap();
    let (count, peer6) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..count], b"six");
    assert_eq!(peer4.port(), peer6.port());
    b.send_to(b"six-reply", peer6).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (target6, b"six-reply".to_vec())
    );
    let third = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    third.send_to(b"full-cone", peer4).await.unwrap();
    let source = Destination::new("127.0.0.1", third.local_addr().unwrap().port()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (source, b"full-cone".to_vec())
    );
    channel.sender.send_to(b"", &target4).await.unwrap();
    let (count, peer) = tokio::time::timeout(Duration::from_secs(2), a.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(peer.port(), peer4.port());
    a.send_to(b"", peer4).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (target4, Vec::new())
    );
    context.cancel.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(global.available_permits(), 128);
}

#[test]
fn duplicate_effective_secrets_are_rejected_across_nodes_and_users() {
    use kerlico_config::{Registry, parse};
    let mut registry = Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register_node(ShadowsocksRNodeFactory).unwrap();
    let a = common("none", "auth_chain_a", "plain");
    let mut b = a.clone();
    b["password"] = json!("different-base-key");
    b["users"] = json!([{"id":7,"password":"synthetic-ssr-secret"}]);
    let config = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[{"tag":"v4","type":"shadowsocksr","listen":"127.0.0.1:0","outbound":"direct","options":a},{"tag":"v6","type":"shadowsocksr","listen":"[::1]:0","outbound":"direct","options":b}]});
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_err()
    );
    let mut config = config;
    config["nodes"][1]["options"]["users"][0]["password"] = json!("independent-user-key");
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_ok()
    );
}
#[tokio::test]
async fn untrusted_public_context_cannot_enable_unauthenticated_combinations() {
    let node = ShadowsocksRNode::from_options(&common("none", "origin", "plain")).unwrap();
    let mut context = context(Arc::new(Semaphore::new(8)));
    context.local_addr = Some("0.0.0.0:1".parse().unwrap());
    let access = Arc::new(Echo::default());
    let (raw, _) = tokio::io::duplex(1024);
    assert!(
        node.handle(Box::new(raw), access.clone(), context.clone())
            .await
            .is_err()
    );
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
    assert!(
        node.serve_udp(socket, access.clone(), context)
            .await
            .is_err()
    );
    assert_eq!(access.0.load(Ordering::Relaxed), 0);
}
