use kerlico_config::{Registry, parse};
use kerlico_core::CancellationToken;
use kerlico_engine::Engine;
use kerlico_net::{DirectFactory, RejectFactory};
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

async fn first_read(address: std::net::SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .expect("连接应在期限内结束");
    bytes
}

#[tokio::test]
async fn rules_choose_the_outbound_and_unmatched_traffic_keeps_the_node_binding() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let serving = tokio::spawn(async move {
        loop {
            let (mut stream, _) = target.accept().await.unwrap();
            stream.write_all(b"ok").await.unwrap();
        }
    });
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(RejectFactory).unwrap();
    let forward = |tag: &str| {
        json!({"tag":tag,"type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"127.0.0.1","port":port},"outbound":"exit"})
    };
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"},{"tag":"block","type":"reject"}],
        "inbounds": [forward("allowed"), forward("blocked")],
        "routes": [{"outbound":"block","node":["blocked"]}],
        "limits": {"drain_timeout_ms":1000}
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let listeners = engine.listeners().unwrap();
    let address = |name: &str| {
        listeners
            .iter()
            .find(|(tag, _)| tag == name)
            .map(|(_, address)| *address)
            .unwrap()
    };
    let (allowed, blocked) = (address("allowed"), address("blocked"));
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    assert_eq!(
        first_read(allowed).await,
        b"ok",
        "未命中规则走节点绑定的出站"
    );
    assert!(
        first_read(blocked).await.is_empty(),
        "命中规则走 reject 出站"
    );
    stop.cancel();
    running.await.unwrap().unwrap();
    serving.abort();
}
