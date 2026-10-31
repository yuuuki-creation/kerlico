//! 仅在 worker 回环验证真实内层目标语义、所有方法及生命周期。
use base64::{Engine as _, engine::general_purpose::STANDARD};
use kerlico_config::{NodeFactory, OutboundFactory, Registry};
use kerlico_core::{CancellationToken, ConnectContext, Destination, Outbound, Result};
use kerlico_shadowtls::{ShadowTlsFactory, ShadowTlsNodeFactory};
use serde_json::{Value, json};
use std::{
    io::Cursor,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
struct Engine {
    cancel: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
    addresses: Vec<(String, SocketAddr)>,
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
    async fn start(nodes: Value) -> Self {
        let mut registry = Registry::default();
        registry.register(kerlico_net::DirectFactory).unwrap();
        registry.register_node(ShadowTlsNodeFactory).unwrap();
        registry
            .register_node(kerlico_ss2022::Ss2022NodeFactory)
            .unwrap();
        let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":nodes,"limits":{"connect_timeout_ms":3000,"idle_timeout_ms":1500,"drain_timeout_ms":300,"max_sessions":128}});
        let prepared = registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap();
        let engine = kerlico_engine::Engine::bind(prepared).await.unwrap();
        let addresses = engine.listeners().unwrap();
        let cancel = CancellationToken::new();
        let task = Some(tokio::spawn(engine.run(cancel.clone())));
        Self {
            cancel,
            task,
            addresses,
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
struct Origin {
    address: SocketAddr,
    certificate: String,
    task: JoinHandle<()>,
    accepted: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Origin {
    async fn new(tls13: bool, retry: bool) -> Self {
        Self::new_with_tickets(tls13, retry, 2).await
    }
    async fn new_with_tickets(tls13: bool, retry: bool, tickets: usize) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec![
            "shadowtls.example.invalid".into(),
            "mapped.example.invalid".into(),
        ])
        .unwrap();
        let certificate = cert.cert.pem();
        let chain = rustls_pemfile::certs(&mut Cursor::new(certificate.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key_pem = cert.signing_key.serialize_pem();
        let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem.as_bytes()))
            .unwrap()
            .unwrap();
        let mut provider = rustls::crypto::ring::default_provider();
        if retry {
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
        }
        let versions = if tls13 {
            vec![&rustls::version::TLS13]
        } else {
            vec![&rustls::version::TLS12]
        };
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.send_tls13_tickets = tickets;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let requests = Arc::new(AtomicUsize::new(0));
        let seen = requests.clone();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    incoming=listener.accept()=>{let Ok((socket,_))=incoming else{break};count.fetch_add(1,Ordering::SeqCst);let acceptor=acceptor.clone();let seen=seen.clone();children.spawn(async move{
                        let Ok(mut stream)=acceptor.accept(socket).await else{return};let mut bytes=[0;4096];
                        if let Ok(Ok(n))=tokio::time::timeout(Duration::from_secs(5),stream.read(&mut bytes)).await && bytes[..n].starts_with(b"GET "){seen.fetch_add(1,Ordering::SeqCst);let _=stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin").await;}
                        let _=stream.shutdown().await;
                    });},
                    _=children.join_next(),if !children.is_empty()=>{},
                }
            }
        });
        Self {
            address,
            certificate,
            task,
            accepted,
            requests,
        }
    }
}
struct Targets {
    addresses: Vec<Destination>,
    accepted: Arc<AtomicUsize>,
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
        let mut addresses = Vec::new();
        let accepted = Arc::new(AtomicUsize::new(0));
        for host in ["127.0.0.1", "::1"] {
            let listener = TcpListener::bind((host, 0)).await.unwrap();
            addresses.push(Destination::new(host, listener.local_addr().unwrap().port()).unwrap());
            let count = accepted.clone();
            tasks.spawn(async move{let mut peers=JoinSet::new();loop{tokio::select!{
                incoming=listener.accept()=>{let Ok((mut stream,_))=incoming else{break};count.fetch_add(1,Ordering::SeqCst);peers.spawn(async move{let _=stream.write_all(b"hi").await;let mut bytes=[0;16384];loop{let Ok(n)=stream.read(&mut bytes).await else{return};if n==0{let _=stream.write_all(b"after-fin").await;let _=stream.shutdown().await;return;}
if stream.write_all(&bytes[..n]).await.is_err(){return;}}});},
                _=peers.join_next(),if !peers.is_empty()=>{},
            }}});
        }
        Self {
            addresses,
            accepted,
            tasks,
        }
    }
}
fn ss(method: &str, index: u8, server: Option<SocketAddr>) -> Value {
    let mut value = if method.starts_with("2022-") {
        json!({"method":method,"key":STANDARD.encode(vec![index;if method=="2022-blake3-aes-128-gcm"{16}else{32}])})
    } else {
        json!({"method":method,"password":format!("inner-test-{index}-{method}")})
    };
    if let Some(server) = server {
        value["server"] = json!(server.ip().to_string());
        value["port"] = json!(server.port());
    }
    value
}
fn inner(method: &str, index: u8, server: Option<SocketAddr>) -> Value {
    json!({"type":if method.starts_with("2022-"){ "ss2022" }else{ "shadowsocks" },"options":ss(method,index,server)})
}
fn node(
    origin: &Origin,
    version: u8,
    strict: bool,
    method: &str,
    index: u8,
    listen: &str,
) -> Value {
    let mut value = json!({"tag":format!("node-{index}"),"type":"shadowtls","listen":listen,"outbound":"direct","options":{"version":version,"handshake":{"host":origin.address.ip().to_string(),"port":origin.address.port()},"inner":inner(method,index,None)}});
    if version != 1 {
        value["options"]["password"] = json!(format!("outer-test-{index}"));
    }
    if version == 3 {
        value["options"]["strict"] = json!(strict);
    }
    value
}
fn client(
    origin: &Origin,
    address: SocketAddr,
    version: u8,
    strict: bool,
    tls13: bool,
    method: &str,
    index: u8,
) -> Value {
    let mut value = json!({"version":version,"tls":{"server_name":"shadowtls.example.invalid","ca_pem":origin.certificate,"version":if tls13{"1.3"}else{"1.2"}},"inner":inner(method,index,Some(address))});
    if version != 1 {
        value["password"] = json!(format!("outer-test-{index}"));
    }
    if version == 3 {
        value["strict"] = json!(strict);
    }
    value
}
async fn tcp(outbound: &dyn Outbound, target: &Destination, payload: &[u8], fin: bool) {
    let mut stream = outbound
        .connect_tcp(target, &ConnectContext::new(Duration::from_secs(3)))
        .await
        .unwrap();
    let mut hi = [0; 2];
    stream.read_exact(&mut hi).await.unwrap();
    assert_eq!(&hi, b"hi");
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut bytes = vec![0; payload.len()];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, payload);
    stream.shutdown().await.unwrap();
    if fin {
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"after-fin");
    }
}
#[tokio::test]
async fn every_inner_aead_and_all_six_tls_version_paths_are_real_dual_role() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let origin12 = Origin::new(false, false).await;
        let origin13 = Origin::new(true, false).await;
        let targets = Targets::new().await;
        let methods = kerlico_shadowsocks::AEAD_METHODS.iter().copied().chain([
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ]);
        for method in methods {
            for (version, strict, tls13) in [
                (1, false, false),
                (2, false, false),
                (2, false, true),
                (3, true, true),
                (3, false, false),
                (3, false, true),
            ] {
                eprintln!("ShadowTLS v{version} strict={strict} tls13={tls13} inner={method}");
                let origin = if tls13 { &origin13 } else { &origin12 };
                let engine = Engine::start(json!([node(
                    origin,
                    version,
                    strict,
                    method,
                    11,
                    "127.0.0.1:0"
                )]))
                .await;
                let outbound = ShadowTlsFactory
                    .build(&client(
                        origin,
                        engine.addresses[0].1,
                        version,
                        strict,
                        tls13,
                        method,
                        11,
                    ))
                    .unwrap();
                assert!(!outbound.capabilities().udp);
                assert!(!outbound.capabilities().tcp_eof);
                assert!(
                    outbound
                        .connect_udp(
                            &targets.addresses[0],
                            &ConnectContext::new(Duration::from_secs(1))
                        )
                        .await
                        .is_err()
                );
                for target in &targets.addresses {
                    tcp(outbound.as_ref(), target, &vec![19; 65536], true).await;
                }
                let domain = Destination::new("localhost", targets.addresses[0].port()).unwrap();
                tcp(outbound.as_ref(), &domain, b"domain-target", false).await;
                drop(outbound);
                let address = engine.addresses[0].1;
                engine.stop().await;
                drop(TcpListener::bind(address).await.unwrap());
            }
        }
    })
    .await
    .expect("ShadowTLS 完整方法与版本矩阵超时");
}

async fn rejected(options: &Value, target: &Destination) {
    let outbound = ShadowTlsFactory.build(options).unwrap();
    if let Ok(mut stream) = outbound
        .connect_tcp(target, &ConnectContext::new(Duration::from_secs(2)))
        .await
    {
        let mut bytes = [0; 2];
        let result =
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes)).await;
        assert!(!matches!(result, Ok(Ok(_))), "错误凭据路径收到业务应答");
    }
}
#[tokio::test]
async fn independent_ipv6_nodes_and_each_layer_credentials_gate_site_access() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let origin = Origin::new(true, false).await;
        let targets = Targets::new().await;
        let engine = Engine::start(json!([
            node(&origin, 3, true, "aes-128-gcm", 21, "127.0.0.1:0"),
            node(&origin, 3, true, "aes-128-gcm", 22, "[::1]:0")
        ]))
        .await;
        for (tag, address) in &engine.addresses {
            let index = if tag == "node-21" { 21 } else { 22 };
            let options = client(&origin, *address, 3, true, true, "aes-128-gcm", index);
            tcp(
                ShadowTlsFactory.build(&options).unwrap().as_ref(),
                &targets.addresses[0],
                b"independent-node",
                true,
            )
            .await;
            tcp(
                ShadowTlsFactory.build(&options).unwrap().as_ref(),
                &targets.addresses[1],
                b"other-target-family",
                false,
            )
            .await;
            let before = targets.accepted.load(Ordering::SeqCst);
            for field in ["outer", "inner", "certificate", "name", "alpn"] {
                let mut invalid = options.clone();
                match field {
                    "outer" => invalid["password"] = json!("other-node-outer-test"),
                    "inner" => {
                        invalid["inner"]["options"]["password"] = json!("other-node-inner-test")
                    }
                    "certificate" => {
                        invalid["tls"].as_object_mut().unwrap().remove("ca_pem");
                    }
                    "name" => invalid["tls"]["server_name"] = json!("wrong.example.invalid"),
                    _ => invalid["tls"]["alpn"] = json!(["unsupported-alpn"]),
                }
                rejected(&invalid, &targets.addresses[0]).await;
                assert_eq!(
                    targets.accepted.load(Ordering::SeqCst),
                    before,
                    "失败层={field}"
                );
            }
            let outbound = ShadowTlsFactory.build(&options).unwrap();
            let context = ConnectContext::new(Duration::from_secs(1));
            context.cancel.cancel();
            assert!(
                outbound
                    .connect_tcp(&targets.addresses[0], &context)
                    .await
                    .is_err()
            );
        }
        engine.stop().await;
    })
    .await
    .expect("独立节点或认证失败边界超时");
}
#[tokio::test]
async fn v3_multi_user_and_ss2022_eih_are_both_real_authentication() {
    let origin = Origin::new(true, false).await;
    let targets = Targets::new().await;
    let method = "2022-blake3-aes-128-gcm";
    let mut spec = node(&origin, 3, true, method, 31, "127.0.0.1:0");
    spec["options"].as_object_mut().unwrap().remove("password");
    spec["options"]["users"] =
        json!([{"password":"outer-first-test"},{"password":"outer-second-test"}]);
    let service = STANDARD.encode([31; 16]);
    let user = STANDARD.encode([32; 16]);
    spec["options"]["inner"]["options"]["users"] = json!([user]);
    let engine = Engine::start(json!([spec])).await;
    for password in ["outer-first-test", "outer-second-test"] {
        let mut options = client(&origin, engine.addresses[0].1, 3, true, true, method, 32);
        options["password"] = json!(password);
        options["inner"]["options"]["identity_keys"] = json!([service]);
        tcp(
            ShadowTlsFactory.build(&options).unwrap().as_ref(),
            &targets.addresses[0],
            b"both-layers",
            true,
        )
        .await;
    }
    let before = targets.accepted.load(Ordering::SeqCst);
    let mut invalid = client(&origin, engine.addresses[0].1, 3, true, true, method, 33);
    invalid["password"] = json!("outer-second-test");
    invalid["inner"]["options"]["identity_keys"] = json!([service]);
    rejected(&invalid, &targets.addresses[0]).await;
    assert_eq!(targets.accepted.load(Ordering::SeqCst), before);
    engine.stop().await;
}
#[tokio::test]
async fn sni_mapping_retry_and_unauthed_browser_fallback_never_choose_site_target() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let default = Origin::new(true, false).await;
        let mapped = Origin::new(true, true).await;
        let targets = Targets::new().await;
        let mut spec = node(&default, 3, true, "aes-256-gcm", 41, "127.0.0.1:0");
        spec["options"]["handshake_for_server_name"] =
            json!({"mapped.example.invalid":{"host":"127.0.0.1","port":mapped.address.port()}});
        let engine = Engine::start(json!([spec])).await;
        let mut options = client(
            &mapped,
            engine.addresses[0].1,
            3,
            true,
            true,
            "aes-256-gcm",
            41,
        );
        options["tls"]["server_name"] = json!("mapped.example.invalid");
        tcp(
            ShadowTlsFactory.build(&options).unwrap().as_ref(),
            &targets.addresses[0],
            b"retry-and-map",
            false,
        )
        .await;
        assert_eq!(default.accepted.load(Ordering::SeqCst), 0);
        assert!(mapped.accepted.load(Ordering::SeqCst) > 0);
        let before = targets.accepted.load(Ordering::SeqCst);
        let chain = rustls_pemfile::certs(&mut Cursor::new(default.certificate.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in chain {
            roots.add(cert).unwrap();
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let socket = TcpStream::connect(engine.addresses[0].1).await.unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect("shadowtls.example.invalid".try_into().unwrap(), socket)
            .await
            .unwrap();
        tls.write_all(
            b"GET / HTTP/1.1\r\nHost: shadowtls.example.invalid\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut bytes = Vec::new();
        tls.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.ends_with(b"origin"));
        assert_eq!(default.requests.load(Ordering::SeqCst), 1);
        assert_eq!(targets.accepted.load(Ordering::SeqCst), before);
        engine.stop().await;
    })
    .await
    .expect("SNI 映射、HRR 或探测回退超时");
}
#[tokio::test]
async fn active_streams_drain_and_transport_cannot_bypass_into_native_udp() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let origin = Origin::new(true, false).await;
        let targets = Targets::new().await;
        let engine = Engine::start(json!([node(
            &origin,
            3,
            true,
            "chacha20-ietf-poly1305",
            51,
            "127.0.0.1:0"
        )]))
        .await;
        let outbound = ShadowTlsFactory
            .build(&client(
                &origin,
                engine.addresses[0].1,
                3,
                true,
                true,
                "chacha20-ietf-poly1305",
                51,
            ))
            .unwrap();
        let mut flows = JoinSet::new();
        for n in 0..4 {
            let outbound = outbound.clone();
            let target = targets.addresses[n % 2].clone();
            flows.spawn(async move {
                tcp(outbound.as_ref(), &target, &vec![n as u8; 32768], true).await;
            });
        }
        while let Some(result) = flows.join_next().await {
            result.unwrap();
        }
        let mut stream = outbound
            .connect_tcp(
                &targets.addresses[0],
                &ConnectContext::new(Duration::from_secs(3)),
            )
            .await
            .unwrap();
        let mut hi = [0; 2];
        stream.read_exact(&mut hi).await.unwrap();
        engine.cancel.cancel();
        tokio::time::sleep(Duration::from_millis(20)).await;
        stream.write_all(b"during-drain").await.unwrap();
        stream.flush().await.unwrap();
        let mut bytes = [0; 12];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"during-drain");
        stream.shutdown().await.unwrap();
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"after-fin");
        drop(stream);
        drop(outbound);
        let address = engine.addresses[0].1;
        engine.stop().await;
        drop(TcpListener::bind(address).await.unwrap());
    })
    .await
    .expect("并发、活动排空或端点回收超时");
}
#[test]
fn unsupported_inner_and_alias_credentials_do_not_create_fake_node_identity() {
    let base = json!({"version":3,"password":"outer-test","handshake":{"host":"127.0.0.1","port":14443},"inner":inner("aes-128-gcm",61,None)});
    let wrapped = ShadowTlsNodeFactory.build(&base).unwrap();
    assert!(!wrapped.supports_udp());
    let scopes = wrapped.scoped_credential_fingerprints("shadowtls");
    assert!(scopes.iter().any(|v| v.protocol == "shadowsocks"));
    assert!(scopes.iter().any(|v| v.protocol == "shadowtls"));
    let native = kerlico_shadowsocks::ShadowsocksNodeFactory
        .build(&base["inner"]["options"])
        .unwrap();
    assert!(
        native
            .scoped_credential_fingerprints("shadowsocks")
            .iter()
            .all(|v| scopes
                .iter()
                .any(|w| w.protocol == v.protocol && w.fingerprint == v.fingerprint))
    );
    for method in ["none", "plain", "aes-128-cfb128"] {
        let mut invalid = base.clone();
        invalid["inner"]["options"]["method"] = json!(method);
        invalid["inner"]["options"]["allow_insecure"] = json!(true);
        assert!(ShadowTlsNodeFactory.build(&invalid).is_err());
    }
    for mutation in [
        "empty",
        "duplicates",
        "wildcard",
        "version",
        "unused-v1-password",
        "unknown-inner",
    ] {
        let mut invalid = base.clone();
        match mutation {
            "empty" => invalid["password"] = json!(""),
            "duplicates" => {
                invalid.as_object_mut().unwrap().remove("password");
                invalid["users"] = json!([{"password":"same"},{"password":"same"}]);
            }
            "wildcard" => invalid["wildcard_sni"] = json!("all"),
            "version" => invalid["version"] = json!(4),
            "unused-v1-password" => invalid["version"] = json!(1),
            _ => invalid["inner"]["type"] = json!("vless"),
        };
        assert!(ShadowTlsNodeFactory.build(&invalid).is_err(), "{mutation}");
    }
    let mut v1 = base.clone();
    v1["version"] = json!(1);
    v1.as_object_mut().unwrap().remove("password");
    let scopes = ShadowTlsNodeFactory
        .build(&v1)
        .unwrap()
        .scoped_credential_fingerprints("shadowtls");
    assert!(scopes.iter().all(|v| v.protocol == "shadowsocks"));
    let mut registry = Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register_node(ShadowTlsNodeFactory).unwrap();
    registry
        .register_node(kerlico_shadowsocks::ShadowsocksNodeFactory)
        .unwrap();
    let config = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[{"tag":"native","type":"shadowsocks","listen":"127.0.0.1:14444","outbound":"direct","options":base["inner"]["options"]},{"tag":"wrapped","type":"shadowtls","listen":"[::1]:14445","outbound":"direct","options":base}]});
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_err()
    );
}

#[tokio::test]
async fn v1_v2_wrong_keys_and_strict_tls12_never_reach_the_site() {
    tokio::time::timeout(Duration::from_secs(35), async {
        let origin12 = Origin::new(false, false).await;
        let origin13 = Origin::new(true, false).await;
        let targets = Targets::new().await;
        for version in [1, 2] {
            let origin = if version == 1 { &origin12 } else { &origin13 };
            let tls13 = version != 1;
            let engine = Engine::start(json!([node(
                origin,
                version,
                false,
                "aes-128-gcm",
                71,
                "127.0.0.1:0"
            )]))
            .await;
            let options = client(
                origin,
                engine.addresses[0].1,
                version,
                false,
                tls13,
                "aes-128-gcm",
                71,
            );
            let before = targets.accepted.load(Ordering::SeqCst);
            let mut wrong = options.clone();
            wrong["inner"]["options"]["password"] = json!("wrong-inner-test");
            rejected(&wrong, &targets.addresses[0]).await;
            if version == 2 {
                let mut wrong = options.clone();
                wrong["password"] = json!("wrong-outer-test");
                rejected(&wrong, &targets.addresses[0]).await;
            }
            let mut wrong = options.clone();
            wrong["tls"]["server_name"] = json!("wrong.example.invalid");
            rejected(&wrong, &targets.addresses[0]).await;
            assert_eq!(targets.accepted.load(Ordering::SeqCst), before);
            engine.stop().await;
        }
        let engine = Engine::start(json!([node(
            &origin12,
            3,
            true,
            "aes-128-gcm",
            72,
            "127.0.0.1:0"
        )]))
        .await;
        let options = client(
            &origin12,
            engine.addresses[0].1,
            3,
            false,
            false,
            "aes-128-gcm",
            72,
        );
        let before = targets.accepted.load(Ordering::SeqCst);
        rejected(&options, &targets.addresses[0]).await;
        assert_eq!(targets.accepted.load(Ordering::SeqCst), before);
        let mut invalid = options;
        invalid["strict"] = json!(true);
        assert!(ShadowTlsFactory.build(&invalid).is_err());
        engine.stop().await;
    })
    .await
    .expect("旧版本认证与严格 TLS 约束超时");
}

#[tokio::test]
async fn unfinished_handshakes_are_cancelled_and_release_the_listener() {
    let origin = Origin::new(true, false).await;
    let targets = Targets::new().await;
    let engine = Engine::start(json!([node(
        &origin,
        3,
        true,
        "aes-128-gcm",
        81,
        "127.0.0.1:0"
    )]))
    .await;
    let address = engine.addresses[0].1;
    let mut unfinished = TcpStream::connect(address).await.unwrap();
    unfinished.write_all(&[22, 3, 1, 0, 100, 1]).await.unwrap();
    engine.stop().await;
    let mut bytes = [0; 1];
    let outcome = tokio::time::timeout(Duration::from_secs(1), unfinished.read(&mut bytes))
        .await
        .unwrap();
    assert!(outcome.is_err() || outcome.unwrap() == 0);
    assert_eq!(targets.accepted.load(Ordering::SeqCst), 0);
    drop(TcpListener::bind(address).await.unwrap());
}

#[tokio::test]
async fn immediate_target_eof_preserves_large_ss2022_replies_with_and_without_wrapper() {
    tokio::time::timeout(Duration::from_secs(60),async{
        let origin12=Origin::new(false,false).await;let origin13=Origin::new(true,false).await;let mut failures=Vec::new();
        for method in ["2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"]{
            for (version,tls13) in [(1,false),(2,false),(3,true)]{
                let origin=if tls13{&origin13}else{&origin12};
                let native=json!({"tag":"native","type":"ss2022","listen":"[::1]:0","outbound":"direct","options":ss(method,92,None)});
                let engine=Engine::start(json!([node(origin,version,true,method,91,"127.0.0.1:0"),native])).await;
                for wrapped in [false,true]{
                    let listener=TcpListener::bind(("127.0.0.1",0)).await.unwrap();let target=Destination::new("127.0.0.1",listener.local_addr().unwrap().port()).unwrap();
                    let echo=tokio::spawn(async move{let(mut peer,_)=listener.accept().await.unwrap();let mut data=vec![0;65536];peer.read_exact(&mut data).await.unwrap();peer.write_all(&data).await.unwrap();peer.shutdown().await.unwrap();});
                    let outbound:Arc<dyn Outbound>=if wrapped{
                        let address=engine.addresses.iter().find(|(tag,_)|tag=="node-91").unwrap().1;
                        ShadowTlsFactory.build(&client(origin,address,version,true,tls13,method,91)).unwrap()
                    }else{
                        let address=engine.addresses.iter().find(|(tag,_)|tag=="native").unwrap().1;
                        Arc::new(kerlico_ss2022::Ss2022Outbound::from_options(&ss(method,92,Some(address))).unwrap())
                    };
                    let started=std::time::Instant::now();eprintln!("开始立即EOF inner={method} v{version} wrapped={wrapped}");
                    let mut stream=outbound.connect_tcp(&target,&ConnectContext::new(Duration::from_secs(3))).await.unwrap_or_else(|e|panic!("立即EOF建连失败 {method} v{version} wrapped={wrapped} elapsed={:?} {e:?}",started.elapsed()));
                    stream.write_all(&vec![79;65536]).await.unwrap_or_else(|e|panic!("立即EOF发送失败 {method} v{version} wrapped={wrapped} elapsed={:?} {e:?}",started.elapsed()));
                    stream.flush().await.unwrap_or_else(|e|panic!("立即EOF排空失败 {method} v{version} wrapped={wrapped} elapsed={:?} {e:?}",started.elapsed()));
                    let mut reply=Vec::new();let result=tokio::time::timeout(Duration::from_secs(3),stream.read_to_end(&mut reply)).await;
                    let good=matches!(result,Ok(Ok(_)))&&reply==vec![79;65536];
                    eprintln!("immediate EOF inner={method} v{version} wrapped={wrapped} length={} result={result:?}",reply.len());
                    if !good{failures.push(format!("{method} v{version} wrapped={wrapped} length={}",reply.len()));}
                    drop(stream);echo.await.unwrap();
                }
                engine.stop().await;
            }
        }
        assert!(failures.is_empty(),"{failures:?}");
    }).await.expect("目标立即 EOF 对照超时");
}

#[tokio::test]
async fn v2_late_tickets_are_gated_until_switch_and_normal_browser_fallback_is_preserved() {
    tokio::time::timeout(Duration::from_secs(25), async {
        for tls13 in [false, true] {
            let origin = Origin::new_with_tickets(tls13, false, 8).await;
            let targets = Targets::new().await;
            let engine = Engine::start(json!([node(
                &origin,
                2,
                false,
                "aes-128-gcm",
                101,
                "127.0.0.1:0"
            )]))
            .await;
            let chain = rustls_pemfile::certs(&mut Cursor::new(origin.certificate.as_bytes()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            for cert in chain {
                roots.add(cert).unwrap();
            }
            let versions = if tls13 {
                vec![&rustls::version::TLS13]
            } else {
                vec![&rustls::version::TLS12]
            };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let socket = TcpStream::connect(engine.addresses[0].1).await.unwrap();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let mut tls = connector
                .clone()
                .connect("shadowtls.example.invalid".try_into().unwrap(), socket)
                .await
                .unwrap();
            tls.write_all(
                b"GET / HTTP/1.1\r\nHost: shadowtls.example.invalid\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut reply = Vec::new();
            tls.read_to_end(&mut reply).await.unwrap();
            assert!(reply.ends_with(b"origin"));
            assert_eq!(targets.accepted.load(Ordering::SeqCst), 0);
            let socket = TcpStream::connect(engine.addresses[0].1).await.unwrap();
            let mut closing = connector
                .connect("shadowtls.example.invalid".try_into().unwrap(), socket)
                .await
                .unwrap();
            closing.shutdown().await.unwrap();
            let mut extra = Vec::new();
            closing.read_to_end(&mut extra).await.unwrap();
            assert!(extra.is_empty());
            let options = client(
                &origin,
                engine.addresses[0].1,
                2,
                false,
                tls13,
                "aes-128-gcm",
                101,
            );
            tcp(
                ShadowTlsFactory.build(&options).unwrap().as_ref(),
                &targets.addresses[0],
                b"after-browser",
                true,
            )
            .await;
            assert_eq!(origin.requests.load(Ordering::SeqCst), 1);
            engine.stop().await;
        }
    })
    .await
    .expect("v2 完成事件、票据或普通浏览器回退超时");
}
