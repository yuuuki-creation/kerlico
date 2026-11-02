use kerlico_config::{Registry, parse};
use kerlico_core::CancellationToken;
use kerlico_egress::{FlowEnd, Telemetry};
use kerlico_engine::Engine;
use kerlico_http::HttpNodeFactory;
use kerlico_net::DirectFactory;
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn proxy(
    idle: u64,
) -> (
    std::net::SocketAddr,
    Telemetry,
    CancellationToken,
    tokio::task::JoinHandle<kerlico_core::Result<()>>,
) {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(HttpNodeFactory).unwrap();
    let config = json!({"version":2,"outbounds":[{"tag":"direct","type":"direct"}],"local_inbounds":[{"tag":"node","type":"http","listen":"127.0.0.1:0","outbound":"direct","options":{}}],"limits":{"idle_timeout_ms":idle,"connect_timeout_ms":1000,"drain_timeout_ms":300}});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let telemetry = engine.telemetry();
    let address = engine.listeners().unwrap()[0].1;
    let stop = CancellationToken::new();
    let task = tokio::spawn(engine.run(stop.clone()));
    (address, telemetry, stop, task)
}
async fn header(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() < 16384);
    }
    bytes
}
async fn ended(telemetry: &Telemetry) -> kerlico_egress::FlowRecord {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(record) = telemetry
                .records(0, 8)
                .unwrap()
                .into_iter()
                .find(|record| record.end.is_some())
            {
                return record;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn ordinary_http_waits_for_delayed_body_and_driver_before_completed() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        header(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        waiting.await.unwrap();
        stream.write_all(b"tail").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let (proxy, telemetry, stop, task) = proxy(2000).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    header(&mut client).await;
    assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    assert_eq!(telemetry.records(0, 8).unwrap()[0].end, None);
    release.send(()).unwrap();
    let mut tail = Vec::new();
    client.read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail, b"tail");
    assert_eq!(ended(&telemetry).await.end, Some(FlowEnd::Completed));
    server.await.unwrap();
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn truncated_http_body_records_failed_in_the_real_ledger() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        header(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntail")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let (proxy, telemetry, stop, task) = proxy(1000).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let _ = client.read_to_end(&mut bytes).await;
    assert_eq!(ended(&telemetry).await.end, Some(FlowEnd::Failed));
    server.await.unwrap();
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn ordinary_http_outer_idle_records_timeout_before_cleanup() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        header(&mut stream).await;
        let _ = waiting.await;
    });
    let (proxy, telemetry, stop, task) = proxy(80).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(format!("GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let record = ended(&telemetry).await;
    assert_eq!(record.end, Some(FlowEnd::Timeout));
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    release.send(()).unwrap();
    server.await.unwrap();
    stop.cancel();
    task.await.unwrap().unwrap();
}
