use kerlico_config::{ControlSpec, Registry, parse};
use kerlico_control::ControlServer;
use kerlico_core::CancellationToken;
use kerlico_engine::Engine;
use kerlico_net::DirectFactory;
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn get(address: SocketAddr, path: &str, secret: Option<&str>) -> (u16, Value) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let authorization = secret
        .map(|secret| format!("Authorization: Bearer {secret}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: control\r\nConnection: close\r\n{authorization}\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let status = text.split(' ').nth(1).unwrap().parse().unwrap();
    let body = text.split_once("\r\n\r\n").unwrap().1;
    (status, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn control_requires_the_secret_and_reports_runtime_state() {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"}],
        "inbounds": [{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"127.0.0.1","port":9},"outbound":"exit"}]
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let spec = ControlSpec {
        listen: "127.0.0.1:0".parse().unwrap(),
        secret: Some("synthetic-control-secret".into()),
    };
    let server = ControlServer::bind(&spec, &engine).await.unwrap();
    let address = server.local_addr().unwrap();
    let stop = CancellationToken::new();
    let serving = tokio::spawn(server.serve(stop.clone()));

    assert_eq!(get(address, "/v1/health", None).await.0, 401);
    assert_eq!(get(address, "/v1/health", Some("wrong")).await.0, 401);
    let secret = Some("synthetic-control-secret");
    let (status, health) = get(address, "/v1/health", secret).await;
    assert_eq!(status, 200);
    assert_eq!(health["status"], "ok");
    let (status, usage) = get(address, "/v1/usage", secret).await;
    assert_eq!(status, 200);
    assert_eq!(usage["active_flows"], 0);
    assert_eq!(get(address, "/v1/online", secret).await.1, json!([]));
    assert_eq!(
        get(address, "/v1/flows?limit=10", secret).await.1,
        json!([])
    );
    assert_eq!(get(address, "/v1/flows?limit=0", secret).await.0, 400);
    assert_eq!(get(address, "/v1/stats", secret).await.0, 200);
    assert_eq!(get(address, "/v1/nothing", secret).await.0, 404);

    stop.cancel();
    serving.await.unwrap();
}
