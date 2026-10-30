use kerlico_config::{Registry, parse};
use kerlico_core::{CancellationToken, ConnectContext, Destination, Outbound, Result};
use kerlico_engine::Engine;
use kerlico_net::DirectFactory;
use kerlico_vless::{VlessFactory, VlessNodeFactory};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const V4_USER: &str = "00000000-0000-0000-0000-000000000001";
const V6_USER: &str = "00000000-0000-0000-0000-000000000002";

fn registry() -> Registry {
    let mut r = Registry::default();
    r.register(DirectFactory).unwrap();
    r.register_node(VlessNodeFactory).unwrap();
    r
}
fn certificate() -> (String, String) {
    let rcgen::CertifiedKey {
        cert, signing_key, ..
    } = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
    ])
    .unwrap();
    (cert.pem(), signing_key.serialize_pem())
}
fn node(tag: &str, listen: &str, uuid: &str, cert: &str, key: &str) -> Value {
    json!({"tag":tag,"type":"vless","listen":listen,"outbound":"direct","max_sessions":8,"options":{"uuid":uuid,"security":{"type":"tls","certificate_pem":cert,"private_key_pem":key}}})
}
fn configuration(nodes: Value) -> Value {
    json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":nodes,"limits":{"connect_timeout_ms":500,"idle_timeout_ms":1000,"drain_timeout_ms":30,"max_sessions":16}})
}
fn client(address: SocketAddr, uuid: &str, cert: &str) -> Arc<dyn Outbound> {
    use kerlico_config::OutboundFactory;
    VlessFactory.build(&json!({"server":{"host":address.ip().to_string(),"port":address.port()},"uuid":uuid,"security":{"type":"tls","server_name":"localhost","ca_pem":cert}})).unwrap()
}
async fn exchange(client: &dyn Outbound, target: SocketAddr, bytes: &[u8]) -> Result<Vec<u8>> {
    let context = ConnectContext::new(Duration::from_millis(500));
    let mut stream = client
        .connect_tcp(
            &Destination::new(&target.ip().to_string(), target.port())?,
            &context,
        )
        .await?;
    stream.write_all(bytes).await?;
    let mut output = vec![0; bytes.len()];
    stream.read_exact(&mut output).await?;
    Ok(output)
}

#[tokio::test]
async fn independent_node_credentials_and_both_target_families() {
    let (cert, key) = certificate();
    let value = configuration(json!([
        node("node4", "127.0.0.1:0", V4_USER, &cert, &key),
        node("node6", "[::1]:0", V6_USER, &cert, &key)
    ]));
    let prepared = registry()
        .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
        .unwrap();
    let engine = Engine::bind(prepared).await.unwrap();
    let addresses = engine.listeners().unwrap();
    let stats = engine.node_stats();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let task = tokio::spawn(engine.run(stop));
    let accepted = Arc::new(AtomicUsize::new(0));
    let target4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a4 = target4.local_addr().unwrap();
    let target6 = TcpListener::bind("[::1]:0").await.unwrap();
    let a6 = target6.local_addr().unwrap();
    let mut targets = tokio::task::JoinSet::new();
    for listener in [target4, target6] {
        let counter = accepted.clone();
        targets.spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut bytes = [0; 128];
                    if let Ok(n) = stream.read(&mut bytes).await {
                        let _ = stream.write_all(&bytes[..n]).await;
                    }
                });
            }
        });
    }
    for (tag, address) in addresses {
        let user = if tag == "node4" { V4_USER } else { V6_USER };
        let good = client(address, user, &cert);
        for target in [a4, a6] {
            assert_eq!(
                exchange(good.as_ref(), target, b"owned-node-flow")
                    .await
                    .unwrap(),
                b"owned-node-flow"
            );
        }
        let wrong = client(
            address,
            if user == V4_USER { V6_USER } else { V4_USER },
            &cert,
        );
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                exchange(wrong.as_ref(), a4, b"must-fail-auth")
            )
            .await
            .unwrap()
            .is_err()
        );
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        4,
        "认证失败不应建立目标连接"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(stats["node4"].accepted.load(Ordering::Relaxed), 3);
    assert_eq!(stats["node6"].accepted.load(Ordering::Relaxed), 3);
    targets.abort_all();
    while targets.join_next().await.is_some() {}
}

#[test]
fn duplicate_node_credentials_are_rejected_without_disclosure() {
    let (cert, key) = certificate();
    let value = configuration(json!([
        node("node4", "127.0.0.1:0", V4_USER, &cert, &key),
        node("node6", "[::1]:0", V4_USER, &cert, &key)
    ]));
    let error = registry()
        .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
        .err()
        .unwrap();
    assert!(error.to_string().contains("认证凭据重复"));
    assert!(!error.to_string().contains(V4_USER));
}

#[tokio::test]
async fn ipv6_node_is_v6_only_and_incomplete_handshake_drains() {
    let (cert, key) = certificate();
    let value = configuration(json!([node("node6", "[::]:0", V6_USER, &cert, &key)]));
    let engine = Engine::bind(
        registry()
            .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let port = engine.listeners().unwrap()[0].1.port();
    let stats = engine.node_stats()["node6"].clone();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(engine.run(cancel.clone()));
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
    );
    let mut incomplete = tokio::net::TcpStream::connect(("::1", port)).await.unwrap();
    incomplete.write_all(&[22, 3]).await.unwrap();
    tokio::time::timeout(Duration::from_millis(200), async {
        while stats.accepted.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut byte = [0; 1];
    let result = tokio::time::timeout(Duration::from_millis(200), incomplete.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
}

#[tokio::test]
async fn one_engine_runs_client_and_server_roles_together() {
    let (cert, key) = certificate();
    let reservation = TcpListener::bind("[::1]:0").await.unwrap();
    let node_port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut bytes = [0; 16];
        socket.read_exact(&mut bytes).await.unwrap();
        socket.write_all(&bytes).await.unwrap();
    });
    let value = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"},{"tag":"client","type":"vless","options":{"server":{"host":"::1","port":node_port},"uuid":V6_USER,"security":{"type":"tls","server_name":"localhost","ca_pem":cert}}}],
        "inbounds":[{"tag":"local","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":target_port},"outbound":"client"}],
        "nodes":[node("server",&format!("[::1]:{node_port}"),V6_USER,&cert,&key)],"limits":{"connect_timeout_ms":1000,"idle_timeout_ms":1000,"drain_timeout_ms":30}});
    let mut registry = registry();
    registry.register(VlessFactory).unwrap();
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let address = engine
        .listeners()
        .unwrap()
        .into_iter()
        .find(|(tag, _)| tag == "local")
        .unwrap()
        .1;
    let cancel = CancellationToken::new();
    let task = tokio::spawn(engine.run(cancel.clone()));
    let mut local = tokio::net::TcpStream::connect(address).await.unwrap();
    local.write_all(b"same-core-both!!").await.unwrap();
    let mut output = [0; 16];
    tokio::time::timeout(Duration::from_secs(2), local.read_exact(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&output, b"same-core-both!!");
    drop(local);
    echo.await.unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
}
