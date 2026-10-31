use bytes::BytesMut;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, InboundContext, InboundProtocol, NodeEvent,
    NodeObserver, Outbound, Result, StreamBudget,
};
use kerlico_shadowsocks::{AEAD_METHODS, LEGACY_METHODS, ShadowsocksNode, ShadowsocksOutbound};
use serde_json::json;
use shadowsocks::{
    ServerConfig,
    config::ServerType,
    context::Context,
    crypto::CipherKind,
    relay::{
        socks5::Address,
        udprelay::{crypto_io, options::UdpSocketControlData},
    },
};
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
};

#[derive(Default)]
struct Events;
impl NodeObserver for Events {
    fn record(&self, _: NodeEvent) {}
}
fn context() -> InboundContext {
    InboundContext {
        cancel: CancellationToken::new(),
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65_000,
        max_streams: 32,
        events: Arc::new(Events),
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(64)),
            Arc::new(Semaphore::new(64)),
        ),
        peer_addr: None,
        local_addr: None,
    }
}
#[derive(Default)]
struct Echo(AtomicUsize);
struct Send(mpsc::Sender<Vec<u8>>);
struct Receive(mpsc::Receiver<Vec<u8>>);
impl DatagramSender for Send {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .send(packet.to_vec())
                .await
                .map_err(|_| kerlico_core::Error::Cancelled)
        })
    }
}
impl DatagramReceiver for Receive {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
impl AccessService for Echo {
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (client, mut server) = tokio::io::duplex(128 * 1024);
            tokio::spawn(async move {
                server.write_all(b"banner").await.unwrap();
                let mut buf = vec![0; 8192];
                loop {
                    let n = server.read(&mut buf).await.unwrap();
                    if n == 0 {
                        server.shutdown().await.unwrap();
                        break;
                    }
                    server.write_all(&buf[..n]).await.unwrap();
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::channel(32);
            Ok(DatagramChannel {
                sender: Box::new(Send(tx)),
                receiver: Box::new(Receive(rx)),
            })
        })
    }
}
async fn endpoints(
    method: &str,
    ipv6: bool,
) -> (
    ShadowsocksOutbound,
    InboundContext,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<Result<()>>,
    Arc<Echo>,
) {
    let node = Arc::new(ShadowsocksNode::from_options(&json!({"method":method,"password":"synthetic-shadowsocks-secret","allow_insecure":true})).unwrap());
    let host = if ipv6 { "::1" } else { "127.0.0.1" };
    let mut sockets = None;
    for _ in 0..32 {
        let listener = TcpListener::bind((host, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        match UdpSocket::bind((host, port)).await {
            Ok(socket) => {
                sockets = Some((listener, port, Arc::new(socket)));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("测试 UDP 监听失败：{error}"),
        }
    }
    let (listener, port, socket) = sockets.expect("无法为测试取得 TCP/UDP 同端口监听");
    let access = Arc::new(Echo::default());
    let mut ctx = context();
    // 完整方法矩阵包含逐 bit 的旧式密码，debug 构建的大包处理需要独立预算。
    ctx.idle_timeout = Duration::from_secs(30);
    let tcp = {
        let node = node.clone();
        let access = access.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! { biased; _ = ctx.cancel.cancelled() => break, _ = tasks.join_next(), if !tasks.is_empty() => {}, stream = listener.accept() => { let (stream, _) = stream.unwrap(); let node = node.clone(); let access = access.clone(); let ctx = ctx.clone(); tasks.spawn(async move { let _ = node.handle(Box::new(stream), access, ctx).await; }); } }
            }
            while tasks.join_next().await.is_some() {}
        })
    };
    let udp = {
        let access = access.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, ctx).await })
    };
    let outbound = ShadowsocksOutbound::from_options(&json!({"server":host,"port":port,"method":method,"password":"synthetic-shadowsocks-secret","allow_insecure":true})).unwrap();
    (outbound, ctx, tcp, udp, access)
}
#[tokio::test]
async fn complete_cipher_tcp_udp_matrix() {
    for method in AEAD_METHODS
        .iter()
        .chain(LEGACY_METHODS)
        .copied()
        .chain(["none"])
    {
        if std::env::var("SHADOWSOCKS_TEST_METHOD")
            .ok()
            .is_some_and(|selected| selected != method)
        {
            continue;
        }
        eprintln!("正在验证方法 {method}");
        let (outbound, ctx, tcp, udp, access) = endpoints(method, false).await;
        for host in ["example.invalid", "127.0.0.1", "::1"] {
            let target = Destination::new(host, 443).unwrap();
            let connect = ConnectContext::new(Duration::from_secs(3));
            let mut stream = outbound.connect_tcp(&target, &connect).await.unwrap();
            let mut banner = [0; 6];
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut banner))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&banner, b"banner", "{method}");
            let payload = vec![
                0x59;
                if AEAD_METHODS.contains(&method) {
                    50_000
                } else {
                    2048
                }
            ];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, payload, "{method}");
            let mut channel = outbound.connect_udp(&target, &connect).await.unwrap();
            for payload in [vec![], vec![1, 2, 3], vec![0x65; 64_000]] {
                channel.sender.send(&payload).await.unwrap();
                let got = tokio::time::timeout(Duration::from_secs(20), channel.receiver.recv())
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "UDP 回包超时 method={method} target={host} payload={}",
                            payload.len()
                        )
                    })
                    .unwrap()
                    .unwrap();
                assert_eq!(got, payload, "{method}");
            }
            assert!(channel.sender.send(&vec![0; 65_001]).await.is_err());
        }
        assert_eq!(access.0.load(Ordering::Relaxed), 6, "{method}");
        ctx.cancel.cancel();
        tcp.await.unwrap();
        udp.await.unwrap().unwrap();
    }
}
#[tokio::test]
async fn ipv6_proxy_carrier_is_independent_of_target_family() {
    for method in ["aes-128-gcm", "aes-128-cfb", "none"] {
        let (outbound, ctx, tcp, udp, _) = endpoints(method, true).await;
        for host in ["127.0.0.1", "::1"] {
            let target = Destination::new(host, 53).unwrap();
            let connect = ConnectContext::new(Duration::from_secs(2));
            let mut stream = outbound.connect_tcp(&target, &connect).await.unwrap();
            let mut banner = [0; 6];
            stream.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"banner");
            let mut channel = outbound.connect_udp(&target, &connect).await.unwrap();
            channel.sender.send(b"v6-carrier").await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
                b"v6-carrier"
            );
        }
        ctx.cancel.cancel();
        tcp.await.unwrap();
        udp.await.unwrap().unwrap();
    }
}
#[test]
fn rejects_unsafe_unknown_or_inapplicable_options() {
    for method in LEGACY_METHODS.iter().copied().chain(["none", "plain"]) {
        assert!(
            ShadowsocksNode::from_options(&json!({"method":method,"password":"secret"})).is_err()
        );
        assert!(
            ShadowsocksNode::from_options(
                &json!({"method":method,"password":"secret","allow_insecure":true})
            )
            .is_ok()
        );
    }
    for method in ["", "aes-192-gcm", "2022-blake3-aes-128-gcm", "unknown"] {
        assert!(
            ShadowsocksNode::from_options(
                &json!({"method":method,"password":"secret","allow_insecure":true})
            )
            .is_err()
        );
    }
    assert!(ShadowsocksNode::from_options(&json!({"method":"aes-128-gcm","password":""})).is_err());
    assert!(
        ShadowsocksNode::from_options(
            &json!({"method":"aes-128-gcm","password":"secret","plugin":"obfs"})
        )
        .is_err()
    );
    assert!(
        ShadowsocksNode::from_options(&json!({"method":"aes-128-gcm","password":"x".repeat(4097)}))
            .is_err()
    );
    let a =
        ShadowsocksNode::from_options(&json!({"method":"aes-128-gcm","password":"first"})).unwrap();
    let b = ShadowsocksNode::from_options(&json!({"method":"aes-128-gcm","password":"second"}))
        .unwrap();
    let c = ShadowsocksNode::from_options(
        &json!({"method":"aes-128-cfb","password":"first","allow_insecure":true}),
    )
    .unwrap();
    assert_ne!(a.credential_fingerprints(), b.credential_fingerprints());
    assert_eq!(a.credential_fingerprints(), c.credential_fingerprints());
    let d =
        ShadowsocksNode::from_options(&json!({"method":"aes-256-gcm","password":"first"})).unwrap();
    assert!(
        a.credential_fingerprints()
            .iter()
            .any(|value| d.credential_fingerprints().contains(value))
    );
    assert!(
        ShadowsocksNode::from_options(
            &json!({"method":"none","password":"","allow_insecure":true})
        )
        .unwrap()
        .requires_loopback()
    );
    let none = ShadowsocksNode::from_options(
        &json!({"method":"none","password":"ignored","allow_insecure":true}),
    )
    .unwrap();
    assert!(none.credential_fingerprints().is_empty());
    let mut registry = kerlico_config::Registry::default();
    registry
        .register(kerlico_shadowsocks::ShadowsocksFactory)
        .unwrap();
    registry
        .register_node(kerlico_shadowsocks::ShadowsocksNodeFactory)
        .unwrap();
    let entry = json!({"tag":"local","type":"shadowsocks","listen":"127.0.0.1:0","outbound":"proxy","options":{"method":"none","password":"","allow_insecure":true}});
    let mut config = json!({"version":1,"outbounds":[{"tag":"proxy","type":"shadowsocks","options":{"server":"127.0.0.1","port":1,"method":"none","password":"","allow_insecure":true}}],"inbounds":[],"nodes":[entry.clone()]});
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_err()
    );
    config["nodes"] = json!([]);
    config["local_inbounds"] = json!([entry]);
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_ok()
    );
    config["local_inbounds"][0]["listen"] = json!("0.0.0.0:1");
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_err()
    );
}
#[tokio::test]
async fn wrong_aead_password_never_opens_target() {
    for method in AEAD_METHODS {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = ShadowsocksOutbound::from_options(&json!({"server":"127.0.0.1","port":listener.local_addr().unwrap().port(),"method":method,"password":"wrong"})).unwrap();
        let node =
            ShadowsocksNode::from_options(&json!({"method":method,"password":"correct"})).unwrap();
        let access = Arc::new(Echo::default());
        let task = {
            let access = access.clone();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                node.handle(Box::new(stream), access, context()).await
            })
        };
        let mut stream = outbound
            .connect_tcp(
                &Destination::new("127.0.0.1", 9).unwrap(),
                &ConnectContext::new(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        let _ = stream.write_all(b"reject").await;
        assert!(task.await.unwrap().is_err());
        assert_eq!(access.0.load(Ordering::Relaxed), 0);
    }
}
#[tokio::test]
async fn udp_replay_and_invalid_authentication_are_rejected() {
    for method in AEAD_METHODS
        .iter()
        .copied()
        .chain(["aes-128-cfb", "chacha20-ietf"])
    {
        let node = Arc::new(
            ShadowsocksNode::from_options(
                &json!({"method":method,"password":"secret","allow_insecure":true}),
            )
            .unwrap(),
        );
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = socket.local_addr().unwrap();
        let ctx = context();
        let access = Arc::new(Echo::default());
        let task = {
            let ctx = ctx.clone();
            let access = access.clone();
            tokio::spawn(async move { node.serve_udp(socket, access, ctx).await })
        };
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let kind: CipherKind = method.parse().unwrap();
        let config = ServerConfig::new(peer, "secret", kind).unwrap();
        let crypto = Context::new(ServerType::Local);
        let mut wire = BytesMut::new();
        let target = Address::DomainNameAddress("example.invalid".into(), 53);
        crypto_io::encrypt_client_payload(
            &crypto,
            kind,
            config.key(),
            &target,
            &UdpSocketControlData::default(),
            &[],
            b"once",
            &mut wire,
        );
        client.send_to(&wire, peer).await.unwrap();
        let mut buf = vec![0; 65_536];
        tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        client.send_to(&wire, peer).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(40), client.recv_from(&mut buf))
                .await
                .is_err(),
            "{method}"
        );
        if AEAD_METHODS.contains(&method) {
            wire.clear();
            crypto_io::encrypt_client_payload(
                &crypto,
                kind,
                config.key(),
                &target,
                &UdpSocketControlData::default(),
                &[],
                b"fresh",
                &mut wire,
            );
            let last = wire.len() - 1;
            wire[last] ^= 1;
            client.send_to(&wire, peer).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(40), client.recv_from(&mut buf))
                    .await
                    .is_err()
            );
            wire[last] ^= 1;
            client.send_to(&wire, peer).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(access.0.load(Ordering::Relaxed), 1);
        ctx.cancel.cancel();
        task.await.unwrap().unwrap();
    }
}
#[tokio::test]
async fn udp_budget_idle_cleanup_and_cancel() {
    let node = Arc::new(
        ShadowsocksNode::from_options(&json!({"method":"aes-128-gcm","password":"secret"}))
            .unwrap(),
    );
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = socket.local_addr().unwrap().port();
    let access = Arc::new(Echo::default());
    let mut ctx = context();
    ctx.max_streams = 1;
    ctx.idle_timeout = Duration::from_millis(80);
    let task = {
        let ctx = ctx.clone();
        let access = access.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, ctx).await })
    };
    let outbound = ShadowsocksOutbound::from_options(
        &json!({"server":"127.0.0.1","port":port,"method":"aes-128-gcm","password":"secret"}),
    )
    .unwrap();
    let connect = ConnectContext::new(Duration::from_secs(1));
    let mut first = outbound
        .connect_udp(&Destination::new("127.0.0.1", 53).unwrap(), &connect)
        .await
        .unwrap();
    let mut second = outbound
        .connect_udp(&Destination::new("::1", 54).unwrap(), &connect)
        .await
        .unwrap();
    first.sender.send(b"first").await.unwrap();
    assert_eq!(first.receiver.recv().await.unwrap().unwrap(), b"first");
    second.sender.send(b"limited").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), second.receiver.recv())
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    second.sender.send(b"after-idle").await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), second.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        b"after-idle"
    );
    connect.cancel.cancel();
    assert!(first.sender.send(b"cancel").await.is_err());
    assert!(second.receiver.recv().await.is_err());
    ctx.cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn tcp_salt_or_iv_replay_never_reopens_target() {
    use shadowsocks::relay::tcprelay::ProxyClientStream;
    for method in AEAD_METHODS.iter().chain(LEGACY_METHODS) {
        let kind: CipherKind = method.parse().unwrap();
        if !kind.is_aead() && kind.iv_len() == 0 {
            continue;
        }
        let config = ServerConfig::new(
            "127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap(),
            "secret",
            kind,
        )
        .unwrap();
        let (plain, mut capture) = tokio::io::duplex(65536);
        let mut encoder = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local),
            plain,
            &config,
            Address::DomainNameAddress("example.invalid".into(), 443),
        );
        encoder.write_all(b"only-once").await.unwrap();
        encoder.shutdown().await.unwrap();
        let mut wire = Vec::new();
        capture.read_to_end(&mut wire).await.unwrap();
        let node = ShadowsocksNode::from_options(
            &json!({"method":method,"password":"secret","allow_insecure":true}),
        )
        .unwrap();
        let access = Arc::new(Echo::default());
        for replay in [false, true] {
            let (mut client, server) = tokio::io::duplex(65536);
            client.write_all(&wire).await.unwrap();
            client.shutdown().await.unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                node.handle(Box::new(server), access.clone(), context()),
            )
            .await
            .unwrap();
            assert_eq!(result.is_err(), replay, "{method}");
        }
        assert_eq!(access.0.load(Ordering::Relaxed), 1, "{method}");
    }
}
