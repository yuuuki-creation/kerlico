//! 完整首轮矩阵与统一出口边界；只在专用 worker 执行。
use kerlico_config::{NodeFactory, OutboundFactory, Registry};
use kerlico_core::{CancellationToken, ConnectContext, Destination, Error, Outbound, Result};
use kerlico_trusttunnel::{TrustTunnelFactory, TrustTunnelNodeFactory};
use serde_json::{Value, json};
use std::{
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
    task: Option<JoinHandle<Result<()>>>,
    addresses: Vec<(String, SocketAddr)>,
    stats: std::collections::BTreeMap<String, Arc<kerlico_engine::Stats>>,
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Engine {
    async fn start(nodes: Value, idle: u64) -> Self {
        let registry = registry();
        let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":nodes,"limits":{"connect_timeout_ms":2000,"idle_timeout_ms":idle,"drain_timeout_ms":300,"max_sessions":256,"max_datagram_size":65507}});
        let prepared = registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap();
        let engine = kerlico_engine::Engine::bind(prepared).await.unwrap();
        let addresses = engine.listeners().unwrap();
        let stats = engine.node_stats();
        let cancel = CancellationToken::new();
        let task = Some(tokio::spawn(engine.run(cancel.clone())));
        Self {
            cancel,
            task,
            addresses,
            stats,
        }
    }
    async fn stop(mut self) {
        self.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(3), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
fn registry() -> Registry {
    let mut registry = Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register(TrustTunnelFactory).unwrap();
    registry.register_node(TrustTunnelNodeFactory).unwrap();
    registry
        .register_node(kerlico_http::HttpNodeFactory)
        .unwrap();
    registry
}
fn certificate() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["tt.example.invalid".into()]).unwrap();
    (cert.cert.pem(), cert.signing_key.serialize_pem())
}
fn node(
    tag: &str,
    listen: &str,
    password: &str,
    cert: &str,
    key: &str,
    transport: &str,
    version: &str,
) -> Value {
    json!({"tag":tag,"type":"trusttunnel","listen":listen,"outbound":"direct","options":{"transport":transport,"users":[{"username":"test","password":password}],"tls":{"certificate_pem":cert,"private_key_pem":key,"version":version},"limits":{"idle_timeout_ms":4000}}})
}
fn client(
    address: SocketAddr,
    password: &str,
    cert: &str,
    transport: &str,
    version: &str,
) -> Value {
    json!({"server":{"host":address.ip().to_string(),"port":address.port()},"auth":{"username":"test","password":password},"transport":transport,"tls":{"server_name":"tt.example.invalid","ca_pem":cert,"version":version},"app_name":"worker-test","limits":{"idle_timeout_ms":4000}})
}
struct Targets {
    tcp: Vec<Destination>,
    udp: Vec<Destination>,
    accepted: Arc<AtomicUsize>,
    sources: Arc<Mutex<std::collections::HashMap<Vec<u8>, SocketAddr>>>,
    tasks: JoinSet<()>,
}
impl Drop for Targets {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}
impl Targets {
    async fn new() -> Self {
        let mut tasks = JoinSet::new();
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        let accepted = Arc::new(AtomicUsize::new(0));
        let sources = Arc::new(Mutex::new(std::collections::HashMap::new()));
        for host in ["127.0.0.1", "::1"] {
            let listener = TcpListener::bind((host, 0)).await.unwrap();
            tcp.push(Destination::new(host, listener.local_addr().unwrap().port()).unwrap());
            let count = accepted.clone();
            tasks.spawn(async move{let mut peers=JoinSet::new();loop{tokio::select!{incoming=listener.accept()=>{let Ok((mut stream,_))=incoming else{break;};count.fetch_add(1,Ordering::SeqCst);peers.spawn(async move{if stream.write_all(b"hi").await.is_err(){return;}let mut bytes=vec![0;16384];loop{let Ok(n)=stream.read(&mut bytes).await else{return;};if n==0{let _=stream.write_all(b"eof").await;let _=stream.shutdown().await;return;}
if stream.write_all(&bytes[..n]).await.is_err(){return;}}});},_=peers.join_next(),if !peers.is_empty()=>{}}}});
            let socket = UdpSocket::bind((host, 0)).await.unwrap();
            udp.push(Destination::new(host, socket.local_addr().unwrap().port()).unwrap());
            let seen = sources.clone();
            tasks.spawn(async move {
                let mut bytes = vec![0; 65535];
                loop {
                    let Ok((n, source)) = socket.recv_from(&mut bytes).await else {
                        break;
                    };
                    if n <= 32 {
                        seen.lock().unwrap().insert(bytes[..n].to_vec(), source);
                    }
                    if socket.send_to(&bytes[..n], source).await.is_err() {
                        break;
                    }
                }
            });
        }
        Self {
            tcp,
            udp,
            accepted,
            sources,
            tasks,
        }
    }
}
async fn tcp(outbound: &dyn Outbound, target: &Destination, size: usize) {
    let context = ConnectContext::new(Duration::from_secs(3));
    let mut io = outbound.connect_tcp(target, &context).await.unwrap();
    let mut hi = [0; 2];
    io.read_exact(&mut hi).await.unwrap();
    assert_eq!(&hi, b"hi");
    let payload = vec![size as u8; size];
    let (read, write) = tokio::io::split(&mut io);
    let mut write = write;
    let mut read = read;
    let sending = async {
        write.write_all(&payload).await.unwrap();
        write.flush().await.unwrap();
        write.shutdown().await.unwrap();
    };
    let receiving = async {
        let mut bytes = vec![0; size];
        read.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, payload);
        let mut tail = Vec::new();
        read.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"eof");
    };
    tokio::join!(sending, receiving);
}
#[tokio::test]
async fn all_five_tls_paths_both_node_families_and_both_business_families() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        for (transport, version) in [
            ("h1", "tls12"),
            ("h1", "tls13"),
            ("h2", "tls12"),
            ("h2", "tls13"),
            ("h3", "tls13"),
        ] {
            eprintln!("TrustTunnel 自端 {transport}/{version}");
            let engine = Engine::start(
                json!([
                    node(
                        "v4",
                        "127.0.0.1:0",
                        "four-secret",
                        &cert,
                        &key,
                        transport,
                        version
                    ),
                    node(
                        "v6",
                        "[::1]:0",
                        "six-secret",
                        &cert,
                        &key,
                        transport,
                        version
                    )
                ]),
                4000,
            )
            .await;
            for (tag, address) in &engine.addresses {
                let options = client(
                    *address,
                    if tag == "v4" {
                        "four-secret"
                    } else {
                        "six-secret"
                    },
                    &cert,
                    transport,
                    version,
                );
                let outbound = TrustTunnelFactory.build(&options).unwrap();
                assert!(!outbound.capabilities().tcp_eof);
                assert!(!outbound.supports_udp_association());
                for target in &targets.tcp {
                    for size in [17, 4096, 65536, 262144] {
                        tcp(outbound.as_ref(), target, size).await;
                    }
                }
                let context = ConnectContext::new(Duration::from_secs(3));
                for target in &targets.udp {
                    let mut channel = outbound.connect_udp(target, &context).await.unwrap();
                    for size in [0, 17, 4096, 12000, 65507] {
                        let payload = vec![size as u8; size];
                        channel.sender.send(&payload).await.unwrap();
                        assert_eq!(channel.receiver.recv().await.unwrap(), Some(payload));
                    }
                    drop(channel);
                }
                assert!(outbound.associate_udp(&context).await.is_err());
            }
            let addresses = engine.addresses.clone();
            engine.stop().await;
            for (_, address) in addresses {
                if transport == "h3" {
                    drop(UdpSocket::bind(address).await.unwrap());
                } else {
                    drop(TcpListener::bind(address).await.unwrap());
                }
            }
        }
    })
    .await
    .expect("TrustTunnel 完整自端矩阵超时");
}

#[tokio::test]
async fn same_target_udp_channels_keep_distinct_fixed_flows_and_domain_uses_egress() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        for transport in ["h1", "h2", "h3"] {
            let engine = Engine::start(
                json!([node(
                    "node",
                    "127.0.0.1:0",
                    "flow-secret",
                    &cert,
                    &key,
                    transport,
                    "tls13"
                )]),
                4000,
            )
            .await;
            let outbound = TrustTunnelFactory
                .build(&client(
                    engine.addresses[0].1,
                    "flow-secret",
                    &cert,
                    transport,
                    "tls13",
                ))
                .unwrap();
            let context = ConnectContext::new(Duration::from_secs(3));
            let mut a = outbound
                .connect_udp(&targets.udp[0], &context)
                .await
                .unwrap();
            let mut b = outbound
                .connect_udp(&targets.udp[0], &context)
                .await
                .unwrap();
            a.sender.send(b"alpha").await.unwrap();
            b.sender.send(b"beta").await.unwrap();
            assert_eq!(b.receiver.recv().await.unwrap().unwrap(), b"beta");
            assert_eq!(a.receiver.recv().await.unwrap().unwrap(), b"alpha");
            {
                let seen = targets.sources.lock().unwrap();
                assert_ne!(seen[b"alpha".as_slice()], seen[b"beta".as_slice()]);
            }
            let domain = Destination::new("localhost", targets.udp[0].port()).unwrap();
            assert!(outbound.connect_udp(&domain, &context).await.is_err());
            let egress = kerlico_egress::Egress::new(outbound);
            let mut channel = egress.connect_udp(&domain, &context).await.unwrap();
            channel.sender.send(b"domain").await.unwrap();
            assert_eq!(channel.receiver.recv().await.unwrap().unwrap(), b"domain");
            drop(channel);
            drop(a);
            drop(b);
            drop(egress);
            engine.stop().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn authentication_and_tls_failure_never_reach_business_target() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        for transport in ["h1", "h2", "h3"] {
            let engine = Engine::start(
                json!([node(
                    "node",
                    "127.0.0.1:0",
                    "right-secret",
                    &cert,
                    &key,
                    transport,
                    "tls13"
                )]),
                4000,
            )
            .await;
            let context = ConnectContext::new(Duration::from_secs(2));
            for change in ["password", "name", "ca"] {
                let mut options = client(
                    engine.addresses[0].1,
                    "right-secret",
                    &cert,
                    transport,
                    "tls13",
                );
                match change {
                    "password" => options["auth"]["password"] = json!("wrong"),
                    "name" => options["tls"]["server_name"] = json!("wrong.example.invalid"),
                    _ => options["tls"]["ca_pem"] = json!(certificate().0),
                }
                let outbound = TrustTunnelFactory.build(&options).unwrap();
                assert!(
                    outbound
                        .connect_tcp(&targets.tcp[0], &context)
                        .await
                        .is_err()
                );
                assert!(
                    outbound
                        .connect_udp(&targets.udp[0], &context)
                        .await
                        .is_err()
                );
            }
            assert_eq!(targets.accepted.load(Ordering::SeqCst), 0);
            engine.stop().await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn real_credentials_and_additional_secret_domain_both_reject_cross_node_reuse() {
    let (cert, key) = certificate();
    let first = node(
        "one",
        "127.0.0.1:0",
        "same-password",
        &cert,
        &key,
        "h2",
        "tls13",
    );
    let mut second = node(
        "two",
        "[::1]:0",
        "same-password",
        &cert,
        &key,
        "h3",
        "tls13",
    );
    second["options"]["users"][0]["username"] = json!("another-name");
    let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[first,second]});
    assert!(
        registry()
            .prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .is_err()
    );
    let protocol = TrustTunnelNodeFactory
        .build(&value["nodes"][0]["options"])
        .unwrap();
    assert_eq!(
        protocol.scoped_credential_fingerprints("trusttunnel").len(),
        2
    );
    assert_eq!(
        protocol
            .credential_isolation_fingerprints("trusttunnel")
            .len(),
        3
    );
    let mut http = value.clone();
    http["nodes"][1] = json!({"tag":"native-http","type":"http","listen":"[::1]:0","outbound":"direct","options":{"auth":{"username":"test","password":"same-password"}}});
    assert!(
        registry()
            .prepare(kerlico_config::parse(&serde_json::to_vec(&http).unwrap()).unwrap())
            .is_err()
    );
    http["nodes"][1]["options"]["auth"]["password"] = json!("independent-http-secret");
    assert!(
        registry()
            .prepare(kerlico_config::parse(&serde_json::to_vec(&http).unwrap()).unwrap())
            .is_ok()
    );
}

#[test]
fn invalid_options_are_rejected_and_capabilities_match_physical_carrier() {
    let (cert, key) = certificate();
    let address = "127.0.0.1:443".parse().unwrap();
    for field in ["icmp", "skip_verification", "auto", "auth_key"] {
        let mut value = client(address, "secret", &cert, "h2", "tls13");
        value[field] = json!(true);
        assert!(TrustTunnelFactory.build(&value).is_err());
    }
    let mut options = client(address, "secret", &cert, "h3", "tls12");
    assert!(TrustTunnelFactory.build(&options).is_err());
    options["transport"] = json!("h1");
    options["udp"] = json!(false);
    let outbound = TrustTunnelFactory.build(&options).unwrap();
    assert!(!outbound.capabilities().udp);
    for transport in ["h1", "h2", "h3"] {
        let value = node(
            "node",
            "127.0.0.1:0",
            "secret",
            &cert,
            &key,
            transport,
            "tls13",
        );
        let protocol = TrustTunnelNodeFactory.build(&value["options"]).unwrap();
        assert_eq!(protocol.supports_tcp(), transport != "h3");
        assert_eq!(protocol.supports_udp(), transport == "h3");
        assert!(!protocol.requires_udp_association());
    }
}

#[tokio::test]
async fn h1_health_and_icmp_responses_authenticate_before_unsupported() {
    use base64::Engine as _;
    tokio::time::timeout(Duration::from_secs(15),async{let(cert,key)=certificate();let engine=Engine::start(json!([node("node","127.0.0.1:0","secret",&cert,&key,"h1","tls13")]),4000).await;for(authority,secret,expected)in[("_check","secret",200),("_icmp","secret",501),("_icmp","bad",407)]{let roots=rustls_pemfile::certs(&mut std::io::Cursor::new(&cert)).collect::<std::io::Result<Vec<_>>>().unwrap();let mut store=rustls::RootCertStore::empty();for cert in roots{store.add(cert).unwrap();}let config=rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().with_root_certificates(store).with_no_client_auth();let raw=tokio::net::TcpStream::connect(engine.addresses[0].1).await.unwrap();let mut io=tokio_rustls::TlsConnector::from(Arc::new(config)).connect("tt.example.invalid".try_into().unwrap(),raw).await.unwrap();let basic=base64::engine::general_purpose::STANDARD.encode(format!("test:{secret}"));io.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: linux test\r\nProxy-Authorization: Basic {basic}\r\n\r\n").as_bytes()).await.unwrap();let mut bytes=Vec::new();while !bytes.ends_with(b"\r\n\r\n"){bytes.push(io.read_u8().await.unwrap());}assert!(String::from_utf8(bytes).unwrap().starts_with(&format!("HTTP/1.1 {expected} ")));}engine.stop().await;}).await.unwrap();
}

#[tokio::test]
async fn bounded_pool_rejects_excess_streams_and_releases_cancelled_udp() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        for transport in ["h1", "h2", "h3"] {
            let engine = Engine::start(
                json!([node(
                    "node",
                    "127.0.0.1:0",
                    "bounded",
                    &cert,
                    &key,
                    transport,
                    "tls13"
                )]),
                4000,
            )
            .await;
            let mut options = client(engine.addresses[0].1, "bounded", &cert, transport, "tls13");
            options["limits"]["max_connections"] = json!(2);
            options["limits"]["max_streams"] = json!(2);
            options["limits"]["max_udp_flows"] = json!(1);
            let outbound = TrustTunnelFactory.build(&options).unwrap();
            let context = ConnectContext::new(Duration::from_secs(3));
            let mut streams = Vec::new();
            for _ in 0..2 {
                streams.push(
                    outbound
                        .connect_tcp(&targets.tcp[0], &context)
                        .await
                        .unwrap(),
                );
            }
            assert!(matches!(
                outbound.connect_tcp(&targets.tcp[0], &context).await,
                Err(Error::ResourceLimit)
            ));
            drop(streams);
            let mut channel = outbound
                .connect_udp(&targets.udp[0], &context)
                .await
                .unwrap();
            assert!(matches!(
                outbound.connect_udp(&targets.udp[0], &context).await,
                Err(Error::ResourceLimit)
            ));
            channel.sender.send(b"active").await.unwrap();
            assert_eq!(channel.receiver.recv().await.unwrap().unwrap(), b"active");
            context.cancel.cancel();
            assert!(matches!(
                channel.sender.send(b"cancelled").await,
                Err(Error::Cancelled)
            ));
            let fresh_context = ConnectContext::new(Duration::from_secs(3));
            let kerlico_core::DatagramChannel { sender, receiver } = channel;
            drop(sender);
            assert!(matches!(
                outbound.connect_udp(&targets.udp[0], &fresh_context).await,
                Err(Error::ResourceLimit)
            ));
            drop(receiver);
            let mut fresh = outbound
                .connect_udp(&targets.udp[0], &fresh_context)
                .await
                .unwrap();
            fresh.sender.send(b"released-slot").await.unwrap();
            assert_eq!(
                fresh.receiver.recv().await.unwrap().unwrap(),
                b"released-slot"
            );
            drop(fresh);
            drop(outbound);
            assert!(
                engine.stats["node"].accepted.load(Ordering::Relaxed)
                    <= if transport == "h1" { 4 } else { 2 }
            );
            engine.stop().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn multiuser_basic_remains_required_with_optional_mtls() {
    tokio::time::timeout(Duration::from_secs(40), async {
        // 独立自签客户端证书作为显式信任锚；不借用服务器名称作为 Basic 凭据。
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        let (client_cert, client_key) = certificate();
        for (transport, version) in [
            ("h1", "tls12"),
            ("h1", "tls13"),
            ("h2", "tls12"),
            ("h2", "tls13"),
            ("h3", "tls13"),
        ] {
            let mut spec = node(
                "node",
                "127.0.0.1:0",
                "first-user",
                &cert,
                &key,
                transport,
                version,
            );
            spec["options"]["users"]
                .as_array_mut()
                .unwrap()
                .push(json!({"username":"second","password":"second-user"}));
            spec["options"]["tls"]["client_ca_pem"] = json!(client_cert);
            let engine = Engine::start(json!([spec]), 4000).await;
            let context = ConnectContext::new(Duration::from_secs(3));
            let mut options = client(
                engine.addresses[0].1,
                "first-user",
                &cert,
                transport,
                version,
            );
            let no_cert = TrustTunnelFactory.build(&options).unwrap();
            assert!(
                no_cert
                    .connect_tcp(&targets.tcp[0], &context)
                    .await
                    .is_err()
            );
            options["tls"]["certificate_pem"] = json!(client_cert);
            options["tls"]["private_key_pem"] = json!(client_key);
            let outbound = TrustTunnelFactory.build(&options).unwrap();
            tcp(outbound.as_ref(), &targets.tcp[0], 65536).await;
            let mut channel = outbound
                .connect_udp(&targets.udp[0], &context)
                .await
                .unwrap();
            channel.sender.send(b"mtls-udp").await.unwrap();
            assert_eq!(channel.receiver.recv().await.unwrap().unwrap(), b"mtls-udp");
            options["auth"] = json!({"username":"second","password":"second-user"});
            let other = TrustTunnelFactory.build(&options).unwrap();
            tcp(other.as_ref(), &targets.tcp[1], 17).await;
            options["auth"]["password"] = json!("wrong");
            assert!(
                TrustTunnelFactory
                    .build(&options)
                    .unwrap()
                    .connect_tcp(&targets.tcp[0], &context)
                    .await
                    .is_err()
            );
            drop(channel);
            drop(outbound);
            drop(other);
            engine.stop().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn immediate_target_eof_keeps_all_queued_data_across_http_flow_control() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let (cert, key) = certificate();
        for transport in ["h1", "h2", "h3"] {
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = target.local_addr().unwrap();
            let fixture = tokio::spawn(async move {
                let (mut io, _) = target.accept().await.unwrap();
                io.write_all(&vec![61; 262144]).await.unwrap();
                io.shutdown().await.unwrap();
            });
            let engine = Engine::start(
                json!([node(
                    "node",
                    "127.0.0.1:0",
                    "eof",
                    &cert,
                    &key,
                    transport,
                    "tls13"
                )]),
                4000,
            )
            .await;
            let outbound = TrustTunnelFactory
                .build(&client(
                    engine.addresses[0].1,
                    "eof",
                    &cert,
                    transport,
                    "tls13",
                ))
                .unwrap();
            let context = ConnectContext::new(Duration::from_secs(3));
            let mut io = outbound
                .connect_tcp(
                    &Destination::new("127.0.0.1", address.port()).unwrap(),
                    &context,
                )
                .await
                .unwrap();
            let mut bytes = Vec::new();
            io.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, vec![61; 262144]);
            io.shutdown().await.unwrap();
            fixture.await.unwrap();
            drop(io);
            drop(outbound);
            engine.stop().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn idle_pool_is_reaped_health_uses_no_business_target_and_active_shutdown_is_bounded() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let targets = Targets::new().await;
        let (cert, key) = certificate();
        for transport in ["h2", "h3"] {
            let engine = Engine::start(
                json!([node(
                    "node",
                    "127.0.0.1:0",
                    "lifecycle",
                    &cert,
                    &key,
                    transport,
                    "tls13"
                )]),
                4000,
            )
            .await;
            let mut options = client(
                engine.addresses[0].1,
                "lifecycle",
                &cert,
                transport,
                "tls13",
            );
            options["limits"]["health_check_ms"] = json!(100);
            options["limits"]["idle_timeout_ms"] = json!(1000);
            let outbound = TrustTunnelFactory.build(&options).unwrap();
            tcp(outbound.as_ref(), &targets.tcp[0], 17).await;
            let before = targets.accepted.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(150)).await;
            tcp(outbound.as_ref(), &targets.tcp[0], 17).await;
            assert_eq!(targets.accepted.load(Ordering::SeqCst), before + 1);
            assert_eq!(engine.stats["node"].accepted.load(Ordering::Relaxed), 1);
            tokio::time::sleep(Duration::from_millis(1300)).await;
            tcp(outbound.as_ref(), &targets.tcp[0], 17).await;
            assert_eq!(engine.stats["node"].accepted.load(Ordering::Relaxed), 2);
            let context = ConnectContext::new(Duration::from_secs(2));
            let mut io = outbound
                .connect_tcp(&targets.tcp[0], &context)
                .await
                .unwrap();
            let mut greeting = [0; 2];
            io.read_exact(&mut greeting).await.unwrap();
            let mut channel = outbound
                .connect_udp(&targets.udp[0], &context)
                .await
                .unwrap();
            channel.sender.send(b"active-stop").await.unwrap();
            assert_eq!(
                channel.receiver.recv().await.unwrap().unwrap(),
                b"active-stop"
            );
            let address = engine.addresses[0].1;
            engine.stop().await;
            assert!(
                tokio::time::timeout(Duration::from_secs(2), io.read_u8())
                    .await
                    .is_ok()
            );
            drop(io);
            drop(channel);
            drop(outbound);
            if transport == "h3" {
                drop(UdpSocket::bind(address).await.unwrap());
            } else {
                drop(TcpListener::bind(address).await.unwrap());
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn disabled_udp_and_connect_deadline_are_explicit() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (cert, _) = certificate();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut options = client(
            listener.local_addr().unwrap(),
            "deadline",
            &cert,
            "h2",
            "tls13",
        );
        options["udp"] = json!(false);
        let outbound = TrustTunnelFactory.build(&options).unwrap();
        let target = Destination::new("192.0.2.1", 443).unwrap();
        let cancelled = ConnectContext::new(Duration::from_secs(1));
        cancelled.cancel.cancel();
        assert!(matches!(
            outbound.connect_tcp(&target, &cancelled).await,
            Err(Error::Cancelled)
        ));
        let context = ConnectContext::new(Duration::from_millis(100));
        assert!(matches!(
            outbound.connect_udp(&target, &context).await,
            Err(Error::Unsupported(_))
        ));
        let connecting = outbound.connect_tcp(&target, &context);
        let incoming = listener.accept();
        let (result, accepted) = tokio::join!(connecting, incoming);
        assert!(accepted.is_ok());
        assert!(matches!(result, Err(Error::Timeout)));
    })
    .await
    .unwrap();
}
