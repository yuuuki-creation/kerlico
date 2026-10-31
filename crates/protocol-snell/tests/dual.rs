//! 自端版本/角色矩阵与真实网络，全部在 worker 执行。
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramChannel,
    Destination, InboundContext, NodeEvent, NodeObserver, Outbound, Result, StreamBudget,
};
use kerlico_snell::{SnellFactory, SnellNodeFactory};
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
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 32,
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(128)),
            Arc::new(Semaphore::new(128)),
        ),
        events: Arc::new(Observer),
        peer_addr: None,
        local_addr: None,
    }
}
struct Harness {
    tasks: JoinSet<()>,
    cancel: CancellationToken,
    tcp: Destination,
    udp: Destination,
    accepted: Arc<AtomicUsize>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.abort_all();
    }
}
impl Harness {
    async fn new(mode: &str, obfs: &str, reuse: bool, ipv6: bool) -> (Self, Value) {
        let version = if mode == "v4" { 4 } else { 6 };
        let node_version = if version == 4 { 5 } else { 6 };
        let host = if ipv6 { "::1" } else { "127.0.0.1" };
        let mut node = json!({"version":node_version,"psk":"snell-test-psk-long-enough","users":[{"userkey":"primary-test-only"},{"userkey":"secondary-test-only"}],"obfs_mode":obfs});
        let mut options = json!({"version":version,"psk":"snell-test-psk-long-enough","userkey":"primary-test-only","reuse":reuse,"obfs_mode":obfs});
        if version == 6 {
            node["mode"] = json!(mode);
            options["mode"] = json!(mode);
        }
        let node = SnellNodeFactory.build(&node).unwrap();
        let listener = TcpListener::bind((host, 0)).await.unwrap();
        let server = Destination::new(host, listener.local_addr().unwrap().port()).unwrap();
        let echo = TcpListener::bind((host, 0)).await.unwrap();
        let tcp = Destination::new(host, echo.local_addr().unwrap().port()).unwrap();
        let socket = UdpSocket::bind((host, 0)).await.unwrap();
        let udp = Destination::new(host, socket.local_addr().unwrap().port()).unwrap();
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let access: Arc<dyn AccessService> = Arc::new(Access(
            kerlico_net::DirectFactory.build(&json!({})).unwrap(),
        ));
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let token = cancel.clone();
        tasks.spawn(async move {
            let mut peers=JoinSet::new();
            loop{tokio::select!{
                _=token.cancelled()=>break,
                result=listener.accept()=>{
                    let Ok((stream,peer))=result else{break;};count.fetch_add(1,Ordering::SeqCst);
                    let node=node.clone();let access=access.clone();let mut context=context(token.clone());context.peer_addr=Some(peer);context.local_addr=stream.local_addr().ok();
                    peers.spawn(async move{let _=node.handle(Box::new(stream),access,context).await;});
                },
                _=peers.join_next(),if !peers.is_empty()=>{},
            }}
        });
        let token = cancel.clone();
        tasks.spawn(async move{
            let mut peers=JoinSet::new();
            loop{tokio::select!{
                _=token.cancelled()=>break,
                result=echo.accept()=>{
                    let Ok((mut stream,_))=result else{break;};
                    peers.spawn(async move{
                        let mut bytes=vec![0;16384];
                        loop{
                            let Ok(n)=stream.read(&mut bytes).await else{return;};
                            if n==0{let _=stream.write_all(b"after-eof").await;let _=stream.shutdown().await;return;}
                            if stream.write_all(&bytes[..n]).await.is_err(){return;}
                        }
                    });
                },
                _=peers.join_next(),if !peers.is_empty()=>{},
            }}
        });
        let token = cancel.clone();
        tasks.spawn(async move{let mut bytes=vec![0;65535];loop{tokio::select!{_=token.cancelled()=>break,result=socket.recv_from(&mut bytes)=>{let Ok((n,peer))=result else{break;};let _=socket.send_to(&bytes[..n],peer).await;}}}});
        options["server"] = json!({"host":host,"port":server.port()});
        (
            Self {
                tasks,
                cancel,
                tcp,
                udp,
                accepted,
            },
            options,
        )
    }
}
#[tokio::test]
async fn complete_roles_modes_obfs_reuse_and_datagrams() {
    tokio::time::timeout(Duration::from_secs(90), async {
        for (mode, obfs) in [
            ("v4", "none"),
            ("v4", "http"),
            ("default", "none"),
            ("unshaped", "none"),
            ("unsafe-raw", "none"),
        ] {
            for reuse in [false, true] {
                eprintln!("验证 Snell {mode} obfs={obfs} reuse={reuse}");
                let (harness, options) = Harness::new(mode, obfs, reuse, false).await;
                let outbound = SnellFactory.build(&options).unwrap();
                let budget = ConnectContext::new(Duration::from_secs(3));
                for index in 0..3 {
                    let mut stream = outbound.connect_tcp(&harness.tcp, &budget).await.unwrap();
                    let payload = vec![37 + index; 65536];
                    stream.write_all(&payload).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut received = vec![0; payload.len()];
                    stream.read_exact(&mut received).await.unwrap();
                    assert_eq!(received, payload);
                    stream.shutdown().await.unwrap();
                    let mut tail = Vec::new();
                    stream.read_to_end(&mut tail).await.unwrap();
                    assert_eq!(tail, b"after-eof");
                    drop(stream);
                }
                assert_eq!(
                    harness.accepted.load(Ordering::SeqCst),
                    if reuse { 1 } else { 3 },
                    "复用连接数量不正确"
                );
                let mut udp = outbound.connect_udp(&harness.udp, &budget).await.unwrap();
                for size in [0, 17, 17, 17, 17, 17, 17, 17, 17, 4096, 8192] {
                    let payload = vec![size as u8; size];
                    udp.sender.send(&payload).await.unwrap();
                    assert_eq!(udp.receiver.recv().await.unwrap(), Some(payload));
                }
            }
        }
    })
    .await
    .expect("Snell 完整自端矩阵超时");
}
#[tokio::test]
async fn bad_psk_userkey_and_cancellation() {
    for mode in ["v4", "default", "unshaped", "unsafe-raw"] {
        let (harness, mut options) = Harness::new(mode, "none", false, false).await;
        options["userkey"] = json!("invalid-test-userkey");
        let outbound = SnellFactory.build(&options).unwrap();
        let budget = ConnectContext::new(Duration::from_secs(2));
        let mut data = [0; 16];
        if let Ok(mut stream) = outbound.connect_tcp(&harness.tcp, &budget).await {
            let _ = stream.write_all(b"denied").await;
            let _ = stream.flush().await;
            assert!(matches!(stream.read(&mut data).await, Ok(0) | Err(_)));
        }
        if mode != "unsafe-raw" {
            options["userkey"] = json!("primary-test-only");
            options["psk"] = json!("wrong-test-psk-long-enough");
            let outbound = SnellFactory.build(&options).unwrap();
            if let Ok(mut stream) = outbound.connect_tcp(&harness.tcp, &budget).await {
                let _ = stream.write_all(b"denied").await;
                let _ = stream.flush().await;
                assert!(matches!(stream.read(&mut data).await, Ok(0) | Err(_)));
            }
        }
        let cancelled = ConnectContext::new(Duration::from_secs(1));
        cancelled.cancel.cancel();
        assert!(
            outbound
                .connect_tcp(&harness.tcp, &cancelled)
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn ipv6_and_business_peer_metadata() {
    let (harness, options) = Harness::new("default", "none", true, true).await;
    let outbound = SnellFactory.build(&options).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(3));
    let mut channel = outbound.connect_udp(&harness.udp, &budget).await.unwrap();
    channel.sender.send(b"v6-data").await.unwrap();
    assert_eq!(
        channel.receiver.recv().await.unwrap(),
        Some(b"v6-data".to_vec())
    );
    assert_eq!(channel.receiver.peer_addr(), Some(harness.udp.clone()));
    let target = Destination::new("localhost", harness.tcp.port()).unwrap();
    let mut stream = outbound.connect_tcp(&target, &budget).await.unwrap();
    stream.write_all(b"domain").await.unwrap();
    stream.flush().await.unwrap();
    let mut bytes = [0; 6];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"domain");
}
#[test]
fn configuration_roles_plaintext_and_credentials() {
    for value in [
        json!({"server":{"host":"127.0.0.1","port":1},"version":5,"psk":"test"}),
        json!({"server":{"host":"127.0.0.1","port":1},"version":6,"psk":"too-short"}),
        json!({"server":{"host":"127.0.0.1","port":1},"version":4,"psk":"test","mode":"default"}),
        json!({"server":{"host":"127.0.0.1","port":1},"version":6,"psk":"valid-test-only-key","mode":"unsafe-raw"}),
        json!({"server":{"host":"192.0.2.1","port":1},"version":6,"psk":"valid-test-only-key","mode":"unsafe-raw","userkey":"test-user"}),
        json!({"server":{"host":"127.0.0.1","port":1},"version":6,"psk":"valid-test-only-key","obfs_mode":"http"}),
    ] {
        assert!(SnellFactory.build(&value).is_err());
    }
    let raw = |psk: &str| {
        SnellNodeFactory.build(&json!({"version":6,"psk":psk,"mode":"unsafe-raw","users":[{"userkey":"same-test-only-key"}]})).unwrap()
    };
    assert_eq!(
        raw("first-test-psk-long").credential_fingerprints(),
        raw("other-test-psk-long").credential_fingerprints()
    );
    let mut registry = kerlico_config::Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register_node(SnellNodeFactory).unwrap();
    let node = |tag: &str, listen: &str, psk: &str| json!({"tag":tag,"type":"snell","listen":listen,"outbound":"direct","options":{"version":6,"psk":psk,"mode":"unsafe-raw","users":[{"userkey":"same-test-only-key"}]}});
    let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[node("node4","127.0.0.1:0","first-test-psk-long"),node("node6","[::1]:0","other-test-psk-long")]});
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .is_err()
    );
}

#[tokio::test]
async fn unified_domain_udp_and_active_drain_release_port() {
    tokio::time::timeout(Duration::from_secs(15),async{
        let (target,_)=Harness::new("v4","none",false,false).await;
        for (mode,obfs) in [("v4","none"),("v4","http"),("default","none"),("unshaped","none"),("unsafe-raw","none")]{
            let mut registry=kerlico_config::Registry::default();registry.register(kerlico_net::DirectFactory).unwrap();registry.register_node(SnellNodeFactory).unwrap();
            let mut options=json!({"version":if mode=="v4"{5}else{6},"psk":"snell-engine-test-psk","users":[{"userkey":"engine-test-user"}],"obfs_mode":obfs});
            if mode!="v4"{options["mode"]=json!(mode);}
            let value=json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[{"tag":"node","type":"snell","listen":"127.0.0.1:0","outbound":"direct","options":options}],"limits":{"connect_timeout_ms":1000,"idle_timeout_ms":2000,"drain_timeout_ms":500,"max_sessions":64}});
            let engine=kerlico_engine::Engine::bind(registry.prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap()).await.unwrap();let address=engine.listeners().unwrap()[0].1;let cancel=CancellationToken::new();let running=tokio::spawn(engine.run(cancel.clone()));
            let mut client=json!({"version":if mode=="v4"{4}else{6},"psk":"snell-engine-test-psk","userkey":"engine-test-user","obfs_mode":obfs,"reuse":true,"server":{"host":"127.0.0.1","port":address.port()}});if mode!="v4"{client["mode"]=json!(mode);}
            let outbound=SnellFactory.build(&client).unwrap();let budget=ConnectContext::new(Duration::from_secs(2));let domain=Destination::new("localhost",target.udp.port()).unwrap();
            let mut udp=outbound.connect_udp(&domain,&budget).await.unwrap();udp.sender.send(b"domain-udp").await.unwrap();assert_eq!(udp.receiver.recv().await.unwrap(),Some(b"domain-udp".to_vec()));let peer=udp.receiver.peer_addr().unwrap();assert_eq!(peer.host(),"127.0.0.1");assert_eq!(peer.port(),target.udp.port());drop(udp);
            let mut stream=outbound.connect_tcp(&target.tcp,&budget).await.unwrap();stream.write_all(b"before").await.unwrap();stream.flush().await.unwrap();let mut bytes=[0;6];stream.read_exact(&mut bytes).await.unwrap();assert_eq!(&bytes,b"before");
            cancel.cancel();tokio::time::sleep(Duration::from_millis(20)).await;stream.write_all(b"during").await.unwrap();stream.flush().await.unwrap();stream.read_exact(&mut bytes).await.unwrap();assert_eq!(&bytes,b"during");stream.shutdown().await.unwrap();let mut tail=Vec::new();stream.read_to_end(&mut tail).await.unwrap();assert_eq!(tail,b"after-eof");drop(stream);drop(outbound);
            tokio::time::timeout(Duration::from_secs(2),running).await.unwrap().unwrap().unwrap();let listener=TcpListener::bind(address).await.unwrap();drop(listener);
        }
    }).await.expect("统一域名 UDP 或活动排空超时");
}

#[tokio::test]
async fn target_can_speak_before_client_sends_business_payload() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            loop {
                let Ok((mut stream, _)) = target.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let _ = stream.write_all(b"greeting").await;
                    let mut bytes = [0; 64];
                    if let Ok(n) = stream.read(&mut bytes).await {
                        let _ = stream.write_all(&bytes[..n]).await;
                    }
                });
            }
        });
        for (mode, obfs) in [
            ("v4", "none"),
            ("v4", "http"),
            ("default", "none"),
            ("unshaped", "none"),
            ("unsafe-raw", "none"),
        ] {
            let (_harness, options) = Harness::new(mode, obfs, false, false).await;
            let outbound = SnellFactory.build(&options).unwrap();
            let budget = ConnectContext::new(Duration::from_secs(2));
            let destination = Destination::new("127.0.0.1", address.port()).unwrap();
            let mut stream = outbound.connect_tcp(&destination, &budget).await.unwrap();
            let mut greeting = [0; 8];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"greeting");
            stream.write_all(b"client").await.unwrap();
            stream.flush().await.unwrap();
            let mut bytes = [0; 6];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"client");
        }
    })
    .await
    .expect("目标先发数据的握手被阻塞");
}
