//! `bind-address: '*'` 的快捷入站同时接收 IPv4 与 IPv6 客户端。

use kerlico_config::{Registry, parse};
use kerlico_core::CancellationToken;
use kerlico_engine::Engine;
use kerlico_http::{HttpNodeFactory, MixedNodeFactory};
use kerlico_net::DirectFactory;
use serde_json::json;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn socks_greeting(address: SocketAddr) -> [u8; 2] {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    reply
}

#[tokio::test]
async fn bind_address_star_listens_on_both_families() {
    let port = std::net::TcpListener::bind("[::]:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(HttpNodeFactory).unwrap();
    registry.register_node(MixedNodeFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"}],
        "inbounds": [],
        "allow_lan": true,
        "bind_address": "*",
        "mixed_port": port,
        "limits": {"drain_timeout_ms":100}
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let listen = engine.listeners().unwrap()[0].1;
    assert!(
        listen.ip().is_unspecified() && listen.is_ipv6(),
        "监听 [::]：{listen}"
    );
    let stop = CancellationToken::new();
    let task = tokio::spawn(engine.run(stop.clone()));
    assert_eq!(
        socks_greeting(SocketAddr::from(([127, 0, 0, 1], port))).await,
        [5, 0]
    );
    assert_eq!(
        socks_greeting(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))).await,
        [5, 0]
    );
    stop.cancel();
    task.await.unwrap().unwrap();
}
