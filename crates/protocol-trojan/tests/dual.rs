//! 真实回环网络覆盖双端载体、鉴权和 UDP 多目标。
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramChannel,
    Destination, InboundContext, NodeEvent, NodeObserver, Outbound, Result, StreamBudget,
};
use kerlico_trojan::{TrojanFactory, TrojanNodeFactory};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
};
struct Access(Arc<dyn Outbound>);
impl AccessService for Access {
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        self.0.connect_tcp(target, context)
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.0.connect_udp(target, context)
    }
}
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
fn context(cancel: CancellationToken) -> InboundContext {
    InboundContext {
        cancel,
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(2),
        max_datagram_size: 65535,
        max_streams: 32,
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(64)),
            Arc::new(Semaphore::new(64)),
        ),
        events: Arc::new(Observer),
        peer_addr: None,
        local_addr: None,
    }
}
struct Harness {
    tasks: JoinSet<()>,
    cancel: CancellationToken,
    server: Destination,
    tcp: Destination,
    udp: Destination,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.abort_all();
    }
}
impl Harness {
    async fn new(transport: Value, tls: bool, ipv6: bool) -> (Self, Value) {
        let host = if ipv6 { "::1" } else { "127.0.0.1" };
        let certificate =
            rcgen::generate_simple_self_signed(vec!["trojan.example.invalid".into()]).unwrap();
        let cert = certificate.cert.pem();
        let private = certificate.signing_key.serialize_pem();
        let server_security = if tls {
            json!({"type":"tls","certificate_pem":cert,"private_key_pem":private})
        } else {
            json!({"type":"none"})
        };
        let client_security = if tls {
            json!({"type":"tls","server_name":"trojan.example.invalid","ca_pem":cert})
        } else {
            json!({"type":"none"})
        };
        let node=TrojanNodeFactory.build(&json!({"passwords":["primary-test-only","secondary-test-only"],"security":server_security,"transport":transport})).unwrap();
        let listener = TcpListener::bind((host, 0)).await.unwrap();
        let server = Destination::new(host, listener.local_addr().unwrap().port()).unwrap();
        let tcp = TcpListener::bind((host, 0)).await.unwrap();
        let tcp_destination = Destination::new(host, tcp.local_addr().unwrap().port()).unwrap();
        let udp = UdpSocket::bind((host, 0)).await.unwrap();
        let udp_destination = Destination::new(host, udp.local_addr().unwrap().port()).unwrap();
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let access: Arc<dyn AccessService> = Arc::new(Access(
            kerlico_net::DirectFactory.build(&json!({})).unwrap(),
        ));
        let token = cancel.clone();
        tasks.spawn(async move {let mut peers=JoinSet::new();loop {tokio::select! {_=token.cancelled()=>break,result=listener.accept()=>{let Ok((stream,peer))=result else {break;};let node=node.clone();let access=access.clone();let mut context=context(token.clone());context.peer_addr=Some(peer);context.local_addr=stream.local_addr().ok();peers.spawn(async move {let _=node.handle(Box::new(stream),access,context).await;});},_ = peers.join_next(),if !peers.is_empty()=>{}}}});
        let token = cancel.clone();
        tasks.spawn(async move {let mut peers=JoinSet::new();loop {tokio::select! {_=token.cancelled()=>break,result=tcp.accept()=>{let Ok((mut stream,_))=result else {break;};peers.spawn(async move {let mut bytes=vec![0;8192];loop {let Ok(n)=stream.read(&mut bytes).await else{return;};if n==0 {let _=stream.write_all(b"after-eof").await;let _=stream.shutdown().await;return;}
if stream.write_all(&bytes[..n]).await.is_err(){return;}}});},_ = peers.join_next(),if !peers.is_empty()=>{}}}});
        let token = cancel.clone();
        tasks.spawn(async move {let mut bytes=vec![0;65535];loop {tokio::select! {_=token.cancelled()=>break,result=udp.recv_from(&mut bytes)=>{let Ok((n,peer))=result else {break;};let _=udp.send_to(&bytes[..n],peer).await;}}}});
        let options = json!({"server":{"host":host,"port":server.port()},"password":"primary-test-only","security":client_security,"transport":transport});
        (
            Self {
                tasks,
                cancel,
                server,
                tcp: tcp_destination,
                udp: udp_destination,
            },
            options,
        )
    }
}
#[tokio::test]
async fn all_carriers_dual_role_tcp_udp() {
    tokio::time::timeout(Duration::from_secs(90), async {
        for transport in [
            json!("tcp"),
            json!({"type":"ws","path":"/trojan"}),
            json!({"type":"httpupgrade","path":"/trojan"}),
            json!({"type":"grpc","service_name":"trojan","multi_mode":false}),
            json!({"type":"grpc","service_name":"trojan","multi_mode":true}),
        ] {
            for tls in [false, true] {
                eprintln!("正在验证载体 {transport} TLS={tls}");
                let (harness, options) = Harness::new(transport.clone(), tls, false).await;
                let outbound = TrojanFactory.build(&options).unwrap();
                let budget = ConnectContext::new(Duration::from_secs(4));
                let mut stream = outbound.connect_tcp(&harness.tcp, &budget).await.unwrap();
                let payload = vec![37; 65536];
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut received = vec![0; payload.len()];
                stream
                    .read_exact(&mut received)
                    .await
                    .unwrap_or_else(|error| panic!("载体 {transport} TLS={tls}: {error}"));
                assert_eq!(received, payload, "载体 {transport} TLS={tls}");
                if transport == json!("tcp")
                    || transport["type"] == "httpupgrade"
                    || transport["type"] == "grpc"
                {
                    stream.shutdown().await.unwrap();
                    let mut tail = Vec::new();
                    stream.read_to_end(&mut tail).await.unwrap();
                    assert_eq!(tail, b"after-eof");
                }
                drop(stream);
                let mut channel = outbound.connect_udp(&harness.udp, &budget).await.unwrap();
                for size in [0, 17, 4096, 8192] {
                    let payload = vec![size as u8; size];
                    channel.sender.send(&payload).await.unwrap();
                    let received = channel.receiver.recv().await.unwrap().unwrap();
                    assert_eq!(
                        received, payload,
                        "UDP载体 {transport} TLS={tls} 长度={size}"
                    );
                }
                drop(channel);
            }
        }
    })
    .await
    .expect("完整载体矩阵超时");
}
#[tokio::test]
async fn ipv6_nodes_and_domain_targets() {
    let (harness, options) = Harness::new(json!("tcp"), true, true).await;
    let outbound = TrojanFactory.build(&options).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(4));
    let mut stream = outbound.connect_tcp(&harness.tcp, &budget).await.unwrap();
    stream.write_all(b"ipv6").await.unwrap();
    let mut received = [0; 4];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"ipv6");
    let (ipv4, options) = Harness::new(json!("tcp"), false, false).await;
    let outbound = TrojanFactory.build(&options).unwrap();
    let target = Destination::new("localhost", ipv4.tcp.port()).unwrap();
    let mut stream = outbound.connect_tcp(&target, &budget).await.unwrap();
    stream.write_all(b"domain").await.unwrap();
    let mut received = [0; 6];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"domain");
    let mut cross = outbound.connect_tcp(&harness.tcp, &budget).await.unwrap();
    cross.write_all(b"cross").await.unwrap();
    let mut received = [0; 5];
    cross.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"cross");
}
#[tokio::test]
async fn bad_password_certificate_name_and_cancellation() {
    let (harness, mut options) = Harness::new(json!("tcp"), true, false).await;
    options["password"] = json!("wrong-test-only");
    let outbound = TrojanFactory.build(&options).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(3));
    let mut stream = outbound.connect_tcp(&harness.tcp, &budget).await.unwrap();
    let _ = stream.write_all(b"denied").await;
    let mut byte = [0];
    assert!(matches!(stream.read(&mut byte).await, Ok(0) | Err(_)));
    options["password"] = json!("primary-test-only");
    options["security"]["server_name"] = json!("wrong.example.invalid");
    let outbound = TrojanFactory.build(&options).unwrap();
    assert!(outbound.connect_tcp(&harness.tcp, &budget).await.is_err());
    options["security"]["server_name"] = json!("trojan.example.invalid");
    options["security"]
        .as_object_mut()
        .unwrap()
        .remove("ca_pem");
    let outbound = TrojanFactory.build(&options).unwrap();
    assert!(outbound.connect_tcp(&harness.tcp, &budget).await.is_err());
    let cancelled = ConnectContext::new(Duration::from_secs(3));
    cancelled.cancel.cancel();
    assert!(
        outbound
            .connect_tcp(&harness.tcp, &cancelled)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn udp_multiple_targets_one_authenticated_stream() {
    let (harness, _) = Harness::new(json!("tcp"), false, false).await;
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other_address = other.local_addr().unwrap();
    let mut task = JoinSet::new();
    task.spawn(async move {
        let mut bytes = [0; 128];
        let (n, peer) = other.recv_from(&mut bytes).await.unwrap();
        other.send_to(&bytes[..n], peer).await.unwrap();
    });
    let mut stream =
        tokio::net::TcpStream::connect((harness.server.host().as_str(), harness.server.port()))
            .await
            .unwrap();
    let mut header = b"".to_vec();
    use sha2::{Digest, Sha224};
    for byte in Sha224::digest(b"primary-test-only") {
        header.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    header.extend_from_slice(b"\r\n\x03\x01\x7f\x00\x00\x01");
    header.extend_from_slice(&harness.udp.port().to_be_bytes());
    header.extend_from_slice(b"\r\n");
    stream.write_all(&header).await.unwrap();
    for (port, payload) in [
        (harness.udp.port(), b"first".as_slice()),
        (other_address.port(), b"second".as_slice()),
    ] {
        let mut frame = vec![1, 127, 0, 0, 1];
        frame.extend_from_slice(&port.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await.unwrap();
    }
    let mut responses = Vec::new();
    for _ in 0..2 {
        let mut address = [0; 7];
        stream.read_exact(&mut address).await.unwrap();
        let len = stream.read_u16().await.unwrap();
        let mut crlf = [0; 2];
        stream.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut bytes = vec![0; len as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        responses.push(bytes);
    }
    responses.sort();
    assert_eq!(responses, vec![b"first".to_vec(), b"second".to_vec()]);
}
#[test]
fn credential_separation_and_config_rejections() {
    let node = |password: &str| {
        TrojanNodeFactory
            .build(&json!({"password":password,"security":{"type":"none"}}))
            .unwrap()
    };
    assert_eq!(
        node("test-only-a").credential_fingerprints(),
        node("test-only-a").credential_fingerprints()
    );
    assert_ne!(
        node("test-only-a").credential_fingerprints(),
        node("test-only-b").credential_fingerprints()
    );
    for options in [
        json!({"passwords":["x","x"],"security":{"type":"none"}}),
        json!({"password":"x","passwords":["y"],"security":{"type":"none"}}),
        json!({"password":"x","security":{"type":"none"},"flow":"xtls-rprx-vision"}),
    ] {
        assert!(TrojanNodeFactory.build(&options).is_err());
    }
    assert!(TrojanFactory.build(&json!({"server":{"host":"example.invalid","port":443},"password":"x","security":{"type":"none"}})).is_err());
}

#[tokio::test]
async fn upgraded_streams_drain_and_release_the_listening_port() {
    tokio::time::timeout(Duration::from_secs(12), async {
        let (target, _) = Harness::new(json!("tcp"), false, false).await;
        for transport in [json!({"type":"ws","path":"/drain"}), json!({"type":"httpupgrade","path":"/drain"}), json!({"type":"grpc","service_name":"drain"})] {
            let mut registry = kerlico_config::Registry::default();
            registry.register(kerlico_net::DirectFactory).unwrap();
            registry.register_node(TrojanNodeFactory).unwrap();
            let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[{"tag":"drain","type":"trojan","listen":"127.0.0.1:0","outbound":"direct","options":{"password":"drain-test-only","security":{"type":"none"},"transport":transport}}],"limits":{"connect_timeout_ms":1000,"idle_timeout_ms":2000,"drain_timeout_ms":400,"max_sessions":32}});
            let prepared = registry.prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
            let engine = kerlico_engine::Engine::bind(prepared).await.unwrap();
            let address = engine.listeners().unwrap()[0].1;
            let cancel = CancellationToken::new();
            let running = tokio::spawn(engine.run(cancel.clone()));
            let outbound = TrojanFactory.build(&json!({"server":{"host":"127.0.0.1","port":address.port()},"password":"drain-test-only","security":{"type":"none"},"transport":transport})).unwrap();
            let budget = ConnectContext::new(Duration::from_secs(2));
            let mut stream = outbound.connect_tcp(&target.tcp, &budget).await.unwrap();
            stream.write_all(b"before-stop").await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = [0;11];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply,b"before-stop");
            cancel.cancel();
            tokio::time::sleep(Duration::from_millis(20)).await;
            stream.write_all(b"during-drain").await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = [0;12];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply,b"during-drain");
            drop(stream);
            drop(outbound);
            tokio::time::timeout(Duration::from_secs(2),running).await.unwrap().unwrap().unwrap();
            let listener = TcpListener::bind(address).await.unwrap();
            drop(listener);
        }
    }).await.expect("HTTP 载体排空或端口回收超时");
}

#[test]
fn registry_rejects_cross_node_reused_credentials() {
    let mut registry = kerlico_config::Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register_node(TrojanNodeFactory).unwrap();
    let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[{"tag":"node4","type":"trojan","listen":"127.0.0.1:0","outbound":"direct","options":{"password":"must-stay-node-local","security":{"type":"none"}}},{"tag":"node6","type":"trojan","listen":"[::1]:0","outbound":"direct","options":{"password":"must-stay-node-local","security":{"type":"none"}}}]});
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .is_err()
    );
}
