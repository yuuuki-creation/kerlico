//! SOCKS5 入站经共享嗅探阶段：IP 目标按嗅探出的域名或协议分流，跳过与强制名单按 Mihomo 语义生效。

#[path = "../../net/tests/support/handshakes.rs"]
mod handshakes;

use handshakes::*;
use kerlico_config::{Registry, parse};
use kerlico_core::CancellationToken;
use kerlico_engine::Engine;
use kerlico_net::{DirectFactory, RejectFactory};
use kerlico_socks::SocksNodeFactory;
use serde_json::{Value, json};
use std::net::SocketAddr;

struct Running {
    proxy: SocketAddr,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<kerlico_core::Result<()>>,
}
impl Running {
    async fn stop(self) {
        self.stop.cancel();
        self.task.await.unwrap().unwrap();
    }
}

/// 未命中规则的流量走节点绑定的 `block`；只有嗅探到 `allowed.test` 或 SSH 才走 `exit`。
async fn start(sniffer: Value) -> Running {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(RejectFactory).unwrap();
    registry.register_node(SocksNodeFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"},{"tag":"block","type":"reject"}],
        "inbounds": [],
        "local_inbounds": [{"tag":"socks-in","type":"socks","listen":"127.0.0.1:0","outbound":"block","options":{}}],
        "routes": [
            {"outbound":"exit","domain":["allowed.test","quic.example.com"]},
            {"outbound":"exit","protocol":["ssh"]}
        ],
        "sniffer": sniffer,
        "limits": {"connect_timeout_ms":2000,"idle_timeout_ms":3000,"drain_timeout_ms":100}
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let proxy = engine.listeners().unwrap()[0].1;
    let stop = CancellationToken::new();
    let task = tokio::spawn(engine.run(stop.clone()));
    Running { proxy, stop, task }
}

async fn tls_via(proxy: SocketAddr, target: SocketAddr, sni: &str) -> bool {
    let mut stream = socks5_connect(proxy, target).await;
    echoes(&mut stream, &tls_client_hello(sni)).await
}

#[tokio::test]
async fn socks_routes_raw_ip_tls_http_and_ssh_by_sniffed_result() {
    let echo = tcp_echo().await;
    let running = start(sniffer(json!({}))).await;
    assert!(
        tls_via(running.proxy, echo, "allowed.test").await,
        "TLS SNI 命中域名规则"
    );
    assert!(
        !tls_via(running.proxy, echo, "other.test").await,
        "其他 SNI 走绑定的 reject"
    );
    let mut http = socks5_connect(running.proxy, echo).await;
    assert!(
        echoes(&mut http, &http_request("allowed.test:8080")).await,
        "HTTP Host 命中域名规则"
    );
    let mut ssh = socks5_connect(running.proxy, echo).await;
    assert!(
        !echoes(&mut ssh, &openssh_banner()).await,
        "SSH 未在 Mihomo sniff 中声明，不嗅探，走 reject"
    );
    running.stop().await;
}

#[tokio::test]
async fn sing_box_style_route_sniff_action_detects_ssh_for_protocol_rules() {
    let echo = tcp_echo().await;
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(RejectFactory).unwrap();
    registry.register_node(SocksNodeFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"},{"tag":"block","type":"reject"}],
        "inbounds": [],
        "local_inbounds": [{"tag":"socks-in","type":"socks","listen":"127.0.0.1:0","outbound":"block","options":{}}],
        "routes": [
            {"action":"sniff","sniffer":["ssh","tls"],"timeout":"500ms"},
            {"outbound":"exit","protocol":["ssh"]}
        ],
        "limits": {"connect_timeout_ms":2000,"idle_timeout_ms":3000,"drain_timeout_ms":100}
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let proxy = engine.listeners().unwrap()[0].1;
    let stop = CancellationToken::new();
    let task = tokio::spawn(engine.run(stop.clone()));
    let mut ssh = socks5_connect(proxy, echo).await;
    assert!(
        echoes(&mut ssh, &openssh_banner()).await,
        "路由 sniff 动作识别 SSH"
    );
    let mut tls = socks5_connect(proxy, echo).await;
    assert!(
        !echoes(&mut tls, &tls_client_hello("allowed.test")).await,
        "TLS 不是 SSH，走 reject"
    );
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn skip_and_force_lists_follow_mihomo() {
    let echo = tcp_echo().await;
    let cases = [
        (
            json!({"skip_domain":["+.allowed.test"]}),
            false,
            "skip-domain 丢弃嗅探域名",
        ),
        (
            json!({"skip_dst_address":["127.0.0.0/8"]}),
            false,
            "skip-dst-address 不嗅探",
        ),
        (
            json!({"skip_src_address":["127.0.0.1/32"]}),
            false,
            "skip-src-address 不嗅探",
        ),
        (
            json!({"parse_pure_ip":false}),
            false,
            "parse-pure-ip 关闭时纯 IP 不嗅探",
        ),
        (json!({"enable":false}), false, "未启用不嗅探"),
    ];
    for (extra, expected, why) in cases {
        let running = start(sniffer(extra)).await;
        assert_eq!(
            tls_via(running.proxy, echo, "allowed.test").await,
            expected,
            "{why}"
        );
        running.stop().await;
    }
    let plain = start(sniffer(json!({}))).await;
    let mut domain = socks5_connect_domain(plain.proxy, "localhost", echo.port()).await;
    assert!(
        !echoes(&mut domain, &tls_client_hello("allowed.test")).await,
        "域名目标默认不嗅探"
    );
    plain.stop().await;
    let forced = start(sniffer(json!({"force_domain":["localhost"]}))).await;
    let mut domain = socks5_connect_domain(forced.proxy, "localhost", echo.port()).await;
    assert!(
        echoes(&mut domain, &tls_client_hello("allowed.test")).await,
        "force-domain 命中的域名目标按嗅探结果分流"
    );
    forced.stop().await;
}

#[tokio::test]
async fn socks_udp_association_routes_by_sniffed_quic_sni() {
    let echo = udp_echo().await;
    let running = start(sniffer(json!({}))).await;
    assert!(
        socks5_udp_echoes(running.proxy, echo, &quic_curl_initial()).await,
        "QUIC Initial SNI quic.example.com 命中规则"
    );
    running.stop().await;
    let unsniffed = start(sniffer(json!({"enable":false}))).await;
    assert!(
        !socks5_udp_echoes(unsniffed.proxy, echo, &quic_curl_initial()).await,
        "不嗅探时按首个 IP 目标走 reject"
    );
    unsniffed.stop().await;
}
