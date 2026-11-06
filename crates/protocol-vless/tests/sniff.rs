//! VLESS 服务端入站经共享嗅探阶段：经 VLESS 到达的 IP 目标按嗅探域名分流。

mod support;
#[path = "../../net/tests/support/handshakes.rs"]
mod handshakes;

use handshakes::*;
use kerlico_config::{Registry, parse};
use kerlico_core::CancellationToken;
use kerlico_engine::Engine;
use kerlico_net::{DirectFactory, RejectFactory};
use kerlico_vless::{VlessFactory, VlessNodeFactory};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "00000000-0000-0000-0000-000000000011";

async fn forwarded_echoes(sni: &str) -> bool {
    let echo = tcp_echo().await;
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let rcgen::CertifiedKey {
        cert, signing_key, ..
    } = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (cert.pem(), signing_key.serialize_pem());
    let config = json!({
        "version": 1,
        "outbounds": [
            {"tag":"exit","type":"direct"},
            {"tag":"block","type":"reject"},
            {"tag":"client","type":"vless","options":{"server":{"host":"127.0.0.1","port":node_port},"uuid":USER,"security":{"type":"tls","server_name":"localhost","ca_pem":cert}}}
        ],
        "inbounds": [{"tag":"local","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":echo.port()},"outbound":"client"}],
        "nodes": [{"tag":"server","type":"vless","listen":format!("127.0.0.1:{node_port}"),"outbound":"block","max_sessions":8,
            "options":{"uuid":USER,"security":{"type":"tls","certificate_pem":cert,"private_key_pem":key}}}],
        "routes": [
            {"outbound":"client","node":["local"]},
            {"outbound":"exit","domain":["allowed.test"]}
        ],
        "sniffer": sniffer(json!({})),
        "limits": {"connect_timeout_ms":2000,"idle_timeout_ms":3000,"drain_timeout_ms":100}
    });
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(RejectFactory).unwrap();
    registry.register(VlessFactory).unwrap();
    registry.register_node(VlessNodeFactory).unwrap();
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&support::configuration(config)).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let local = engine
        .listeners()
        .unwrap()
        .into_iter()
        .find(|(tag, _)| tag == "local")
        .unwrap()
        .1;
    let stop = CancellationToken::new();
    let task = tokio::spawn(engine.run(stop.clone()));
    let mut stream = TcpStream::connect(local).await.unwrap();
    let result = echoes(&mut stream, &tls_client_hello(sni)).await;
    drop(stream);
    stop.cancel();
    task.await.unwrap().unwrap();
    result
}

#[tokio::test]
async fn vless_server_routes_raw_ip_tls_by_sniffed_sni() {
    assert!(forwarded_echoes("allowed.test").await, "VLESS 会话内 TLS SNI 命中域名规则");
    assert!(!forwarded_echoes("other.test").await, "其他 SNI 走节点绑定的 reject");
}
