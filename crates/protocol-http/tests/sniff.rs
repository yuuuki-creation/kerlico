//! HTTP CONNECT 与 mixed（SOCKS5 分支）入站经共享嗅探阶段按嗅探域名分流。

#[path = "../../net/tests/support/handshakes.rs"]
mod handshakes;

use handshakes::*;
use kerlico_config::{Registry, parse};
use kerlico_core::CancellationToken;
use kerlico_engine::Engine;
use kerlico_http::{HttpNodeFactory, MixedNodeFactory};
use kerlico_net::{DirectFactory, RejectFactory};
use serde_json::json;

#[tokio::test]
async fn http_and_mixed_inbounds_route_raw_ip_by_sniffed_domain() {
    let echo = tcp_echo().await;
    let udp = udp_echo().await;
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(RejectFactory).unwrap();
    registry.register_node(HttpNodeFactory).unwrap();
    registry.register_node(MixedNodeFactory).unwrap();
    let inbound = |tag: &str, kind: &str| json!({"tag":tag,"type":kind,"listen":"127.0.0.1:0","outbound":"block","options":{}});
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"},{"tag":"block","type":"reject"}],
        "inbounds": [],
        "local_inbounds": [inbound("http-in","http"), inbound("mixed-in","mixed")],
        "routes": [{"outbound":"exit","domain":["allowed.test","www.google.com"]}],
        "sniffer": sniffer(json!({})),
        "limits": {"connect_timeout_ms":2000,"idle_timeout_ms":3000,"drain_timeout_ms":100}
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let listeners = engine.listeners().unwrap();
    let address = |name: &str| listeners.iter().find(|(tag, _)| tag == name).unwrap().1;
    let (http, mixed) = (address("http-in"), address("mixed-in"));
    let stop = CancellationToken::new();
    let task = tokio::spawn(engine.run(stop.clone()));

    let mut stream = http_connect(http, echo).await;
    assert!(
        echoes(&mut stream, &tls_client_hello("allowed.test")).await,
        "HTTP CONNECT + TLS SNI"
    );
    let mut stream = http_connect(http, echo).await;
    assert!(
        !echoes(&mut stream, &tls_client_hello("other.test")).await,
        "HTTP CONNECT 其他 SNI 被拒"
    );
    let mut stream = http_connect(http, echo).await;
    assert!(
        echoes(&mut stream, &http_request("allowed.test")).await,
        "HTTP CONNECT + HTTP Host"
    );

    let mut stream = socks5_connect(mixed, echo).await;
    assert!(
        echoes(&mut stream, &tls_client_hello("allowed.test")).await,
        "mixed SOCKS5 + TLS SNI"
    );
    let mut stream = socks5_connect(mixed, echo).await;
    assert!(
        !echoes(&mut stream, &http_request("other.test")).await,
        "mixed 其他 Host 被拒"
    );
    assert!(
        socks5_udp_echoes(mixed, udp, &quic_chrome_initials()).await,
        "mixed UDP：拆成三个 Initial 的 Chrome ClientHello 重组后命中规则"
    );

    stop.cancel();
    task.await.unwrap().unwrap();
}
