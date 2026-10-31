use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, InboundContext, InboundProtocol, NodeEvent,
    NodeObserver, Outbound, Result, StreamBudget,
};
use kerlico_ss2022::{Ss2022Node, Ss2022Outbound};
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

const METHODS: [&str; 3] = [
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];
fn key(method: &str, value: u8) -> String {
    STANDARD.encode(vec![
        value;
        if method.contains("aes-128") { 16 } else { 32 }
    ])
}
#[derive(Default)]
struct Events {
    accepted: AtomicUsize,
    completed: AtomicUsize,
}
impl NodeObserver for Events {
    fn record(&self, event: NodeEvent) {
        match event {
            NodeEvent::Accepted => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Completed => {
                self.completed.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}
fn context() -> InboundContext {
    InboundContext {
        peer_addr: None,
        local_addr: None,
        cancel: CancellationToken::new(),
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65_000,
        max_streams: 32,
        events: Arc::new(Events::default()),
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(64)),
            Arc::new(Semaphore::new(64)),
        ),
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
    multi: bool,
) -> (
    Ss2022Outbound,
    InboundContext,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<Result<()>>,
    Arc<Echo>,
) {
    let user_key = key(method, 11);
    let service_key = key(method, 22);
    let node = Arc::new(Ss2022Node::from_options(&json!({"method":method,"key":if multi { &service_key } else { &user_key }, "users":if multi { vec![user_key.clone(),key(method,33)] } else {vec![]} })).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let socket = Arc::new(UdpSocket::bind(("127.0.0.1", port)).await.unwrap());
    let access = Arc::new(Echo::default());
    let ctx = context();
    let tcp = {
        let node = node.clone();
        let access = access.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! { biased; _ = ctx.cancel.cancelled() => break, stream = listener.accept() => { let (stream, _) = stream.unwrap(); let node = node.clone(); let access = access.clone(); let ctx = ctx.clone(); tokio::spawn(async move { let _ = node.handle(Box::new(stream),access,ctx).await; }); } }
            }
        })
    };
    let udp = {
        let access = access.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, ctx).await })
    };
    let outbound = Ss2022Outbound::from_options(&json!({"server":"127.0.0.1","port":port,"method":method,"key":user_key,"identity_keys":if multi {vec![service_key]} else {vec![]} })).unwrap();
    (outbound, ctx, tcp, udp, access)
}

#[tokio::test]
async fn three_methods_tcp_udp_and_eih() {
    for method in METHODS {
        for multi in [false, true] {
            if multi && method.contains("chacha") {
                continue;
            }
            let (outbound, ctx, tcp, udp, access) = endpoints(method, multi).await;
            let target = Destination::new("example.invalid", 443).unwrap();
            let connect = ConnectContext::new(Duration::from_secs(3));
            let mut stream = outbound.connect_tcp(&target, &connect).await.unwrap();
            let payload = vec![0x59; 100_000];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, payload);
            let mut channel = outbound.connect_udp(&target, &connect).await.unwrap();
            for payload in [vec![], vec![1, 2, 3], vec![0x65; 64_000]] {
                channel.sender.send(&payload).await.unwrap();
                let got = tokio::time::timeout(Duration::from_secs(3), channel.receiver.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(got, payload);
            }
            assert!(channel.sender.send(&vec![0; 65_001]).await.is_err());
            assert_eq!(access.0.load(Ordering::Relaxed), 2);
            ctx.cancel.cancel();
            tcp.await.unwrap();
            assert!(udp.await.unwrap().is_err());
        }
    }
}

#[test]
fn rejects_invalid_config_and_isolates_keys() {
    for method in METHODS {
        assert!(Ss2022Node::from_options(&json!({"method":method,"key":"password"})).is_err());
        assert!(Ss2022Outbound::from_options(&json!({"server":"127.0.0.1","port":8388,"method":method,"key":key(method,1),"plugin":"anything"})).is_err());
        let a = Ss2022Node::from_options(&json!({"method":method,"key":key(method,1)})).unwrap();
        let b = Ss2022Node::from_options(&json!({"method":method,"key":key(method,2)})).unwrap();
        assert_ne!(a.credential_fingerprints(), b.credential_fingerprints());
        assert!(
            Ss2022Node::from_options(
                &json!({"method":method,"key":key(method,1),"users":[key(method,1)]})
            )
            .is_err()
        );
        if method.contains("chacha") {
            assert!(
                Ss2022Node::from_options(
                    &json!({"method":method,"key":key(method,1),"users":[key(method,2)]})
                )
                .is_err()
            );
            assert!(Ss2022Outbound::from_options(&json!({"server":"127.0.0.1","port":8388,"method":method,"key":key(method,1),"identity_keys":[key(method,2)]})).is_err());
        }
    }
}

#[tokio::test]
async fn authentication_failure_never_opens_target() {
    for method in METHODS {
        let (outbound, ctx, tcp, udp, access) = endpoints(method, false).await;
        // 地址从已构造出站配置中独立建立，错误 key 不得触发目标服务。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = Ss2022Node::from_options(&json!({"method":method,"key":key(method,2)})).unwrap();
        let wrong = Ss2022Outbound::from_options(&json!({"server":"127.0.0.1","port":listener.local_addr().unwrap().port(),"method":method,"key":key(method,1)})).unwrap();
        let other_access = Arc::new(Echo::default());
        let task = {
            let access = other_access.clone();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                node.handle(Box::new(stream), access, context()).await
            })
        };
        let mut stream = wrong
            .connect_tcp(
                &Destination::new("127.0.0.1", 9).unwrap(),
                &ConnectContext::new(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        stream.write_all(b"reject").await.unwrap();
        assert!(task.await.unwrap().is_err());
        assert_eq!(other_access.0.load(Ordering::Relaxed), 0);
        assert_eq!(access.0.load(Ordering::Relaxed), 0);
        drop(outbound);
        ctx.cancel.cancel();
        tcp.await.unwrap();
        let _ = udp.await.unwrap();
    }
}

#[tokio::test]
async fn udp_replay_rejection_migration_and_multiple_targets() {
    for method in METHODS {
        let node = Arc::new(
            Ss2022Node::from_options(&json!({"method":method,"key":key(method,7)})).unwrap(),
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
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let method_kind: CipherKind = method.parse().unwrap();
        let config = ServerConfig::new(peer, key(method, 7), method_kind).unwrap();
        let crypto = Context::new(ServerType::Local);
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 99;
        let mut wire = BytesMut::new();
        let target = Address::DomainNameAddress("example.invalid".into(), 53);
        crypto_io::encrypt_client_payload(
            &crypto,
            method_kind,
            config.key(),
            &target,
            &control,
            &[],
            b"first",
            &mut wire,
        );
        a.send_to(&wire, peer).await.unwrap();
        let mut buf = vec![0; 65_536];
        tokio::time::timeout(Duration::from_secs(2), a.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        // 同一包来自新地址仍为回放，不得更新会话目的地址。
        b.send_to(&wire, peer).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), b.recv_from(&mut buf))
                .await
                .is_err()
        );
        control.packet_id = 1;
        wire.clear();
        let target = Address::SocketAddress("[::1]:5353".parse().unwrap());
        crypto_io::encrypt_client_payload(
            &crypto,
            method_kind,
            config.key(),
            &target,
            &control,
            &[],
            b"moved",
            &mut wire,
        );
        b.send_to(&wire, peer).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (n, addr, ctrl) =
            crypto_io::decrypt_server_payload(&crypto, method_kind, config.key(), &mut buf[..n])
                .unwrap();
        assert_eq!(&buf[..n], b"moved");
        assert_eq!(addr, target);
        assert_eq!(ctrl.unwrap().client_session_id, 99);
        assert_eq!(access.0.load(Ordering::Relaxed), 2);
        control.packet_id = 2;
        wire.clear();
        crypto_io::encrypt_client_payload(
            &crypto,
            method_kind,
            config.key(),
            &target,
            &control,
            &[],
            b"tampered",
            &mut wire,
        );
        let last = wire.len() - 1;
        wire[last] ^= 1;
        b.send_to(&wire, peer).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), b.recv_from(&mut buf))
                .await
                .is_err()
        );
        assert_eq!(access.0.load(Ordering::Relaxed), 2);
        wire[last] ^= 1;
        b.send_to(&wire, peer).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (len, _, _) =
            crypto_io::decrypt_server_payload(&crypto, method_kind, config.key(), &mut buf[..len])
                .unwrap();
        assert_eq!(&buf[..len], b"tampered");
        ctx.cancel.cancel();
        let _ = task.await.unwrap();
    }
}

#[tokio::test]
async fn eih_users_with_identical_session_ids_remain_independent() {
    for method in &METHODS[..2] {
        let service = key(method, 22);
        let users = [key(method, 11), key(method, 33)];
        let node = Ss2022Node::from_options(&json!({"method":method,"key":service,"users":users}))
            .unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = socket.local_addr().unwrap();
        let ctx = context();
        let access = Arc::new(Echo::default());
        let task = {
            let ctx = ctx.clone();
            let access = access.clone();
            tokio::spawn(async move { node.serve_udp(socket, access, ctx).await })
        };
        let crypto = Context::new(ServerType::Local);
        let method_kind: CipherKind = method.parse().unwrap();
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for user in users {
            let config = ServerConfig::new(peer, format!("{service}:{user}"), method_kind).unwrap();
            let mut control = UdpSocketControlData::default();
            control.client_session_id = 123;
            let target = Address::DomainNameAddress("example.invalid".into(), 53);
            let mut wire = BytesMut::new();
            crypto_io::encrypt_client_payload(
                &crypto,
                method_kind,
                config.key(),
                &target,
                &control,
                config.identity_keys(),
                user.as_bytes(),
                &mut wire,
            );
            source.send_to(&wire, peer).await.unwrap();
            let mut response = vec![0; 65_536];
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(2), source.recv_from(&mut response))
                    .await
                    .unwrap()
                    .unwrap();
            let (len, _, _) = crypto_io::decrypt_server_payload(
                &crypto,
                method_kind,
                config.key(),
                &mut response[..len],
            )
            .unwrap();
            assert_eq!(&response[..len], user.as_bytes());
        }
        assert_eq!(access.0.load(Ordering::Relaxed), 2);
        ctx.cancel.cancel();
        let _ = task.await.unwrap();
    }
}

struct FailsOnce(AtomicUsize);
impl AccessService for FailsOnce {
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async { Err(kerlico_core::Error::Rejected) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                return Err(kerlico_core::Error::Rejected);
            }
            let (tx, rx) = mpsc::channel(32);
            Ok(DatagramChannel {
                sender: Box::new(Send(tx)),
                receiver: Box::new(Receive(rx)),
            })
        })
    }
}
#[tokio::test]
async fn udp_new_packet_recovers_closed_target_without_replaying_old_payload() {
    let method = METHODS[0];
    let user_key = key(method, 11);
    let node = Ss2022Node::from_options(&json!({"method":method,"key":user_key})).unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = socket.local_addr().unwrap().port();
    let ctx = context();
    let access = Arc::new(FailsOnce(AtomicUsize::new(0)));
    let task = {
        let ctx = ctx.clone();
        let access = access.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, ctx).await })
    };
    let outbound = Ss2022Outbound::from_options(
        &json!({"server":"127.0.0.1","port":port,"method":method,"key":user_key}),
    )
    .unwrap();
    let target = Destination::new("example.invalid", 53).unwrap();
    let mut channel = outbound
        .connect_udp(&target, &ConnectContext::new(Duration::from_secs(2)))
        .await
        .unwrap();
    channel.sender.send(b"old").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), channel.receiver.recv())
            .await
            .is_err()
    );
    channel.sender.send(b"new").await.unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&packet, b"new");
    assert_eq!(access.0.load(Ordering::Relaxed), 2);
    ctx.cancel.cancel();
    let _ = task.await.unwrap();
}
