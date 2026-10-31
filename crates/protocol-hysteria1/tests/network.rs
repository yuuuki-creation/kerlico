//! 使用 worker 回环网络验证独立 v1 双端、数据语义与节点生命周期。
use kerlico_config::{OutboundFactory, Registry};
use kerlico_core::{CancellationToken, ConnectContext, Destination, Outbound, Result};
use kerlico_hysteria1::{Hysteria1Factory, Hysteria1NodeFactory};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::{JoinHandle, JoinSet},
};
struct Engine {
    cancel: CancellationToken,
    running: Option<JoinHandle<Result<()>>>,
    addresses: Vec<(String, SocketAddr)>,
    stats: std::collections::BTreeMap<String, Arc<kerlico_engine::Stats>>,
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = &self.running {
            task.abort();
        }
    }
}
impl Engine {
    async fn start(nodes: Value) -> Self {
        Self::start_with_limit(nodes, 65507).await
    }
    async fn start_with_limit(nodes: Value, maximum: usize) -> Self {
        let mut registry = Registry::default();
        registry.register(kerlico_net::DirectFactory).unwrap();
        registry.register_node(Hysteria1NodeFactory).unwrap();
        let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":nodes,"limits":{"connect_timeout_ms":3000,"idle_timeout_ms":2000,"drain_timeout_ms":400,"max_sessions":128,"max_datagram_size":maximum}});
        let engine = kerlico_engine::Engine::bind(
            registry
                .prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();
        let addresses = engine.listeners().unwrap();
        let stats = engine.node_stats();
        let cancel = CancellationToken::new();
        let running = tokio::spawn(engine.run(cancel.clone()));
        Self {
            cancel,
            running: Some(running),
            addresses,
            stats,
        }
    }
    async fn stop(mut self) {
        self.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(3), self.running.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
fn certificate() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["hy1.example.invalid".into()]).unwrap();
    (cert.cert.pem(), cert.signing_key.serialize_pem())
}
fn node(
    tag: &str,
    listen: &str,
    credential: &str,
    cert: &str,
    key: &str,
    mode: (&str, bool, &str, bool),
) -> Value {
    let (carrier, obfs, cc, udp) = mode;
    json!({"tag":tag,"type":"hysteria1","listen":listen,"outbound":"direct","options":{"auth_str":credential,"up_bps":10000000,"down_bps":10000000,"transport":carrier,"obfs":if obfs{Some("xplus-test-key")}else{None},"udp":udp,"tls":{"certificate_pem":cert,"private_key_pem":key},"limits":{"congestion_control":cc,"idle_timeout_ms":2000}}})
}
fn client(
    address: SocketAddr,
    credential: &str,
    cert: &str,
    carrier: &str,
    obfs: bool,
    cc: &str,
) -> Value {
    json!({"server":{"host":address.ip().to_string(),"port":address.port()},"auth_str":credential,"up_bps":10000000,"down_bps":10000000,"transport":carrier,"obfs":if obfs{Some("xplus-test-key")}else{None},"tls":{"server_name":"hy1.example.invalid","ca_pem":cert},"limits":{"congestion_control":cc,"idle_timeout_ms":2000}})
}
struct Targets {
    tcp4: Destination,
    tcp6: Destination,
    udp4: Destination,
    udp6: Destination,
    tasks: JoinSet<()>,
    accepted: Arc<AtomicUsize>,
    sources: Arc<Mutex<HashMap<Vec<u8>, Vec<SocketAddr>>>>,
}
impl Drop for Targets {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}
impl Targets {
    async fn new() -> Self {
        let mut tasks = JoinSet::new();
        let accepted = Arc::new(AtomicUsize::new(0));
        let sources = Arc::new(Mutex::new(HashMap::<Vec<u8>, Vec<SocketAddr>>::new()));
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        for host in ["127.0.0.1", "::1"] {
            let listener = TcpListener::bind((host, 0)).await.unwrap();
            tcp.push(Destination::new(host, listener.local_addr().unwrap().port()).unwrap());
            let count = accepted.clone();
            tasks.spawn(async move{
                let mut peers=JoinSet::new();
                loop{tokio::select!{
                    incoming=listener.accept()=>{let Ok((mut stream,_))=incoming else{break;};count.fetch_add(1,Ordering::SeqCst);peers.spawn(async move{let _=stream.write_all(b"hi").await;let mut bytes=vec![0;16384];loop{let Ok(n)=stream.read(&mut bytes).await else{return;};if n==0{let _=stream.write_all(b"eof").await;let _=stream.shutdown().await;return;}
if stream.write_all(&bytes[..n]).await.is_err(){return;}}});},
                    _=peers.join_next(),if !peers.is_empty()=>{},
                }}
            });
            let socket = UdpSocket::bind((host, 0)).await.unwrap();
            udp.push(Destination::new(host, socket.local_addr().unwrap().port()).unwrap());
            let peers = sources.clone();
            tasks.spawn(async move {
                let mut bytes = vec![0; 65535];
                loop {
                    let Ok((n, source)) = socket.recv_from(&mut bytes).await else {
                        break;
                    };
                    if n <= 32 {
                        peers
                            .lock()
                            .unwrap()
                            .entry(bytes[..n].to_vec())
                            .or_default()
                            .push(source);
                    }
                    if socket.send_to(&bytes[..n], source).await.is_err() {
                        break;
                    }
                }
            });
        }
        Self {
            tcp4: tcp[0].clone(),
            tcp6: tcp[1].clone(),
            udp4: udp[0].clone(),
            udp6: udp[1].clone(),
            tasks,
            accepted,
            sources,
        }
    }
}
async fn tcp(outbound: &dyn Outbound, target: &Destination, payload: &[u8]) {
    let context = ConnectContext::new(Duration::from_secs(3));
    let mut stream = outbound.connect_tcp(target, &context).await.unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hi");
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut bytes = vec![0; payload.len()];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, payload);
    stream.shutdown().await.unwrap();
    let mut tail = Vec::new();
    stream.read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail, b"eof");
}
#[tokio::test]
async fn all_v1_carriers_obfuscation_and_standard_controllers_are_dual_role() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        for carrier in ["udp", "wechat-video"] {
            for obfs in [false, true] {
                for cc in ["cubic", "newreno", "bbr"] {
                    eprintln!("验证Hysteria v1 {carrier} xplus={obfs} cc={cc}");
                    let engine = Engine::start(json!([node(
                        "node4",
                        "127.0.0.1:0",
                        "hy1-test-node4",
                        &cert,
                        &key,
                        (carrier, obfs, cc, true)
                    )]))
                    .await;
                    let options = client(
                        engine.addresses[0].1,
                        "hy1-test-node4",
                        &cert,
                        carrier,
                        obfs,
                        cc,
                    );
                    let outbound = Hysteria1Factory.build(&options).unwrap();
                    tcp(outbound.as_ref(), &targets.tcp4, &vec![37; 65536]).await;
                    tcp(outbound.as_ref(), &targets.tcp6, b"cross-family").await;
                    let context = ConnectContext::new(Duration::from_secs(3));
                    let mut channel = outbound.connect_udp(&targets.udp4, &context).await.unwrap();
                    for size in [0, 17, 4096, 12000] {
                        let payload = vec![size as u8; size];
                        channel.sender.send(&payload).await.unwrap();
                        assert_eq!(channel.receiver.recv().await.unwrap(), Some(payload));
                    }
                    drop(channel);
                    let mut association = outbound.associate_udp(&context).await.unwrap();
                    for target in [&targets.udp4, &targets.udp6] {
                        association
                            .sender
                            .send_to(b"multi-target", target)
                            .await
                            .unwrap();
                        let (source, packet) =
                            association.receiver.recv_from().await.unwrap().unwrap();
                        assert_eq!(source, target.clone());
                        assert_eq!(packet, b"multi-target");
                    }
                    drop(association);
                    drop(outbound);
                    let address = engine.addresses[0].1;
                    engine.stop().await;
                    let socket = UdpSocket::bind(address).await.unwrap();
                    drop(socket);
                }
            }
        }
    })
    .await
    .expect("Hysteria v1 完整自端矩阵超时");
}
#[tokio::test]
async fn ipv6_independent_auth_binary_alias_and_same_socket_associations() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        let mut six = node(
            "node6",
            "[::1]:0",
            "hy1-node6-test",
            &cert,
            &key,
            ("udp", false, "cubic", true),
        );
        use base64::Engine as _;
        let binary = [0, 255, 1, 128, 2, 127];
        six["options"].as_object_mut().unwrap().remove("auth_str");
        six["options"]["auth"] = json!(base64::engine::general_purpose::STANDARD.encode(binary));
        let engine = Engine::start(json!([
            node(
                "node4",
                "127.0.0.1:0",
                "hy1-node4-test",
                &cert,
                &key,
                ("udp", false, "cubic", true)
            ),
            six
        ]))
        .await;
        for (tag, address) in &engine.addresses {
            let mut options = client(
                *address,
                if tag == "node4" {
                    "hy1-node4-test"
                } else {
                    "hy1-node6-test"
                },
                &cert,
                "udp",
                false,
                "cubic",
            );
            if tag == "node6" {
                options.as_object_mut().unwrap().remove("auth_str");
                options["auth"] = json!(base64::engine::general_purpose::STANDARD.encode(binary));
            }
            let outbound = Hysteria1Factory.build(&options).unwrap();
            tcp(outbound.as_ref(), &targets.tcp4, b"target4").await;
            tcp(outbound.as_ref(), &targets.tcp6, b"target6").await;
            let context = ConnectContext::new(Duration::from_secs(3));
            let mut one = outbound.associate_udp(&context).await.unwrap();
            let mut two = outbound.associate_udp(&context).await.unwrap();
            let first = format!("{tag}-first").into_bytes();
            let second = format!("{tag}-second").into_bytes();
            for target in [&targets.udp4, &targets.udp6] {
                one.sender.send_to(&first, target).await.unwrap();
                assert_eq!(
                    one.receiver.recv_from().await.unwrap().unwrap(),
                    (target.clone(), first.clone())
                );
            }
            two.sender.send_to(&second, &targets.udp4).await.unwrap();
            assert_eq!(two.receiver.recv_from().await.unwrap().unwrap().1, second);
            {
                let observed = targets.sources.lock().unwrap();
                let one_peers = observed.get(&first).unwrap();
                assert_eq!(one_peers.len(), 2);
                assert_eq!(one_peers[0].port(), one_peers[1].port());
                assert_ne!(
                    one_peers[0].port(),
                    observed.get(&second).unwrap()[0].port()
                );
            }
            drop(one);
            drop(two);
            let before = targets.accepted.load(Ordering::SeqCst);
            options["auth_str"] = json!("other-node-credential");
            options.as_object_mut().unwrap().remove("auth");
            let invalid = Hysteria1Factory.build(&options).unwrap();
            assert!(invalid.connect_tcp(&targets.tcp4, &context).await.is_err());
            assert_eq!(targets.accepted.load(Ordering::SeqCst), before);
        }
        engine.stop().await;
    })
    .await
    .expect("独立节点或多目标关联超时");
}
#[tokio::test]
async fn active_tcp_drains_and_concurrent_streams_do_not_share_payloads() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        let engine = Engine::start(json!([node(
            "node",
            "127.0.0.1:0",
            "hy1-drain-test",
            &cert,
            &key,
            ("udp", true, "newreno", true)
        )]))
        .await;
        let address = engine.addresses[0].1;
        let outbound = Hysteria1Factory
            .build(&client(
                address,
                "hy1-drain-test",
                &cert,
                "udp",
                true,
                "newreno",
            ))
            .unwrap();
        let mut flows = JoinSet::new();
        for n in 0..4 {
            let outbound = outbound.clone();
            let target = targets.tcp4.clone();
            flows.spawn(async move {
                tcp(outbound.as_ref(), &target, &vec![n; 32768]).await;
            });
        }
        while let Some(result) = flows.join_next().await {
            result.unwrap();
        }
        let context = ConnectContext::new(Duration::from_secs(3));
        let mut stream = outbound.connect_tcp(&targets.tcp4, &context).await.unwrap();
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        engine.cancel.cancel();
        tokio::time::sleep(Duration::from_millis(20)).await;
        stream.write_all(b"during").await.unwrap();
        stream.flush().await.unwrap();
        let mut bytes = [0; 6];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"during");
        stream.shutdown().await.unwrap();
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"eof");
        drop(stream);
        drop(outbound);
        engine.stop().await;
        let socket = UdpSocket::bind(address).await.unwrap();
        drop(socket);
    })
    .await
    .expect("并发、排空或端点回收超时");
}
#[tokio::test]
async fn tcp_only_and_bad_tls_alpn_cancellation_are_explicit() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        let engine = Engine::start(json!([node(
            "node",
            "127.0.0.1:0",
            "hy1-tcp-only-test",
            &cert,
            &key,
            ("udp", false, "cubic", false)
        )]))
        .await;
        let options = client(
            engine.addresses[0].1,
            "hy1-tcp-only-test",
            &cert,
            "udp",
            false,
            "cubic",
        );
        let outbound = Hysteria1Factory.build(&options).unwrap();
        let context = ConnectContext::new(Duration::from_secs(2));
        tcp(outbound.as_ref(), &targets.tcp4, b"tcp-only").await;
        assert!(outbound.connect_udp(&targets.udp4, &context).await.is_err());
        for mutation in ["name", "ca", "alpn"] {
            let mut invalid = options.clone();
            match mutation {
                "name" => invalid["tls"]["server_name"] = json!("wrong.example.invalid"),
                "ca" => {
                    invalid["tls"].as_object_mut().unwrap().remove("ca_pem");
                }
                _ => invalid["tls"]["alpn"] = json!(["wrong-alpn"]),
            }
            let outbound = Hysteria1Factory.build(&invalid).unwrap();
            assert!(outbound.connect_tcp(&targets.tcp4, &context).await.is_err());
        }
        let cancelled = ConnectContext::new(Duration::from_secs(2));
        cancelled.cancel.cancel();
        assert!(
            outbound
                .connect_tcp(&targets.tcp4, &cancelled)
                .await
                .is_err()
        );
        engine.stop().await;
    })
    .await
    .expect("无效条件检查超时");
}
#[test]
fn credential_aliases_and_unsupported_branches_are_rejected() {
    let (cert, key) = certificate();
    let base = node(
        "one",
        "127.0.0.1:0",
        "same-test-auth",
        &cert,
        &key,
        ("udp", false, "cubic", true),
    );
    let mut second = base.clone();
    second["tag"] = json!("two");
    second["listen"] = json!("[::1]:0");
    second["options"]
        .as_object_mut()
        .unwrap()
        .remove("auth_str");
    use base64::Engine as _;
    second["options"]["auth"] =
        json!(base64::engine::general_purpose::STANDARD.encode(b"same-test-auth"));
    let mut registry = Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register_node(Hysteria1NodeFactory).unwrap();
    let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[base,second]});
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .is_err()
    );
    let mut options = client(
        "127.0.0.1:1".parse().unwrap(),
        "test-auth",
        &cert,
        "udp",
        false,
        "cubic",
    );
    options["transport"] = json!("faketcp");
    assert!(Hysteria1Factory.build(&options).is_err());
    options["transport"] = json!("udp");
    options["limits"]["congestion_control"] = json!("brutal");
    assert!(Hysteria1Factory.build(&options).is_err());
    options["limits"]["congestion_control"] = json!("cubic");
    options["server_ports"] = json!([1, 2]);
    assert!(Hysteria1Factory.build(&options).is_err());
}

#[tokio::test]
async fn datagram_limits_apply_before_site_send_and_before_reply() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let site = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = Destination::new("127.0.0.1", site.local_addr().unwrap().port()).unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut bytes = [0; 64];
            loop {
                let Ok((n, source)) = site.recv_from(&mut bytes).await else {
                    break;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let mut reply = bytes[..n].to_vec();
                reply.extend_from_slice(&bytes[..n]);
                let _ = site.send_to(&reply, source).await;
            }
        });
        let (cert, key) = certificate();
        let engine = Engine::start_with_limit(
            json!([node(
                "node",
                "127.0.0.1:0",
                "hy1-packet-limit",
                &cert,
                &key,
                ("udp", false, "cubic", true)
            )]),
            4,
        )
        .await;
        let outbound = Hysteria1Factory
            .build(&client(
                engine.addresses[0].1,
                "hy1-packet-limit",
                &cert,
                "udp",
                false,
                "cubic",
            ))
            .unwrap();
        let context = ConnectContext::new(Duration::from_secs(3));
        let mut channel = outbound.connect_udp(&target, &context).await.unwrap();
        channel.sender.send(b"ok").await.unwrap();
        assert_eq!(
            channel.receiver.recv().await.unwrap(),
            Some(b"okok".to_vec())
        );
        channel.sender.send(b"five!").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), channel.receiver.recv())
                .await
                .is_err()
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        channel.sender.send(b"four").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), channel.receiver.recv())
                .await
                .is_err()
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        channel.sender.send(b"ok").await.unwrap();
        assert_eq!(
            channel.receiver.recv().await.unwrap(),
            Some(b"okok".to_vec())
        );
        drop(channel);
        drop(outbound);
        engine.stop().await;
    })
    .await
    .expect("UDP 节点包长策略验证超时");
}

#[tokio::test]
async fn multiple_auth_materials_are_verified_in_one_node() {
    tokio::time::timeout(Duration::from_secs(15),async{
        use base64::Engine as _;
        let targets=Targets::new().await;let(cert,key)=certificate();let mut configured=node("node","127.0.0.1:0","unused",&cert,&key,("udp",false,"cubic",true));configured["options"].as_object_mut().unwrap().remove("auth_str");let binary=[0,255,1,128];configured["options"]["users"]=json!([{"auth_str":"first-valid-auth"},{"auth":base64::engine::general_purpose::STANDARD.encode(binary)}]);
        let engine=Engine::start(json!([configured])).await;
        for encoded in [false,true]{let mut options=client(engine.addresses[0].1,"first-valid-auth",&cert,"udp",false,"cubic");if encoded{options.as_object_mut().unwrap().remove("auth_str");options["auth"]=json!(base64::engine::general_purpose::STANDARD.encode(binary));}let outbound=Hysteria1Factory.build(&options).unwrap();tcp(outbound.as_ref(),&targets.tcp4,b"allowed").await;}
        let before=targets.accepted.load(Ordering::SeqCst);let invalid=Hysteria1Factory.build(&client(engine.addresses[0].1,"not-a-valid-auth",&cert,"udp",false,"cubic")).unwrap();assert!(invalid.connect_tcp(&targets.tcp4,&ConnectContext::new(Duration::from_secs(3))).await.is_err());assert_eq!(targets.accepted.load(Ordering::SeqCst),before);engine.stop().await;
    }).await.expect("同节点多凭据鉴权超时");
}

#[tokio::test]
async fn idle_client_cache_releases_the_old_connection() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        let engine = Engine::start(json!([node(
            "node",
            "127.0.0.1:0",
            "idle-cache-test",
            &cert,
            &key,
            ("udp", false, "cubic", true)
        )]))
        .await;
        let mut options = client(
            engine.addresses[0].1,
            "idle-cache-test",
            &cert,
            "udp",
            false,
            "cubic",
        );
        options["limits"]["idle_timeout_ms"] = json!(150);
        let outbound = Hysteria1Factory.build(&options).unwrap();
        tcp(outbound.as_ref(), &targets.tcp4, b"first").await;
        let before = engine.stats["node"]
            .accepted
            .load(std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(400)).await;
        tcp(outbound.as_ref(), &targets.tcp4, b"second").await;
        let after = engine.stats["node"]
            .accepted
            .load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(after - before, 2, "应重新创建载体及一条业务流");
        drop(outbound);
        engine.stop().await;
    })
    .await
    .expect("客户端空闲连接未回收");
}
