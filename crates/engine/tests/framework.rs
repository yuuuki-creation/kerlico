use kerlico_config::{Registry, parse};
use kerlico_core::CancellationToken;
use kerlico_engine::Engine;
use kerlico_net::{DirectFactory, RejectFactory};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, timeout},
};

fn prepare(value: serde_json::Value) -> kerlico_core::Result<kerlico_config::PreparedConfig> {
    let mut registry = Registry::default();
    registry.register(DirectFactory)?;
    registry.register(RejectFactory)?;
    registry.prepare(parse(&serde_json::to_vec(&value).unwrap())?)
}

struct TcpOnly;
impl kerlico_core::Outbound for TcpOnly {
    fn capabilities(&self) -> kerlico_core::Capabilities {
        kerlico_core::Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a kerlico_core::Destination,
        _: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<kerlico_core::BoxStream>> {
        Box::pin(async { Err(kerlico_core::Error::Rejected) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a kerlico_core::Destination,
        _: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<kerlico_core::DatagramChannel>> {
        Box::pin(async { Err(kerlico_core::Error::Unsupported("UDP")) })
    }
}
struct TcpOnlyFactory;
impl kerlico_config::OutboundFactory for TcpOnlyFactory {
    fn kind(&self) -> &'static str {
        "tcp-only-test"
    }
    fn build(
        &self,
        _: &serde_json::Value,
    ) -> kerlico_core::Result<std::sync::Arc<dyn kerlico_core::Outbound>> {
        let outbound: std::sync::Arc<dyn kerlico_core::Outbound> = std::sync::Arc::new(TcpOnly);
        Ok(outbound)
    }
}

#[test]
fn udp_cannot_use_tcp_only_module_and_limits_are_checked() {
    let mut registry = Registry::default();
    registry.register(TcpOnlyFactory).unwrap();
    let mut value = json!({"version":1,"outbounds":[{"tag":"exit","type":"tcp-only-test"}],"inbounds":[{"tag":"entry","type":"udp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":1},"outbound":"exit"}]});
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .is_err()
    );
    value["inbounds"] = json!([]);
    value["limits"] = json!({"connect_timeout_ms":u64::MAX});
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .is_err()
    );
}

#[tokio::test]
async fn max_sessions_and_shutdown_deadline_are_enforced() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
    });
    let config=prepare(json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":port},"outbound":"exit"}],"limits":{"max_sessions":1,"drain_timeout_ms":30}})).unwrap();
    let engine = Engine::bind(config).await.unwrap();
    let stats = engine.stats();
    let address = engine.listeners().unwrap()[0].1;
    let stop = CancellationToken::new();
    let run = tokio::spawn(engine.run(stop.clone()));
    let _first = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while stats.accepted.load(std::sync::atomic::Ordering::Relaxed) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(1), second.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(stats.dropped.load(std::sync::atomic::Ordering::Relaxed), 1);
    stop.cancel();
    timeout(Duration::from_secs(1), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    peer.await.unwrap();
}

#[test]
fn rejects_unknown_fields_capabilities_and_references() {
    let base = json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[]});
    assert!(prepare(base.clone()).is_ok());
    let mut value = base.clone();
    value["outbounds"][0]["type"] = json!("absent");
    assert!(prepare(value).is_err());
    let mut value = base.clone();
    value["outbounds"][0]["options"] = json!({"ignored":true});
    assert!(prepare(value).is_err());
    let mut value = base.clone();
    value["inbounds"] = json!([{"tag":"entry","type":"tcp-forward","listen":"0.0.0.0:0","target":{"host":"127.0.0.1","port":1},"outbound":"exit"}]);
    assert!(prepare(value).is_err());
    let mut value = base;
    value["inbounds"] = json!([{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":1},"outbound":"absent"}]);
    assert!(prepare(value).is_err());
}

#[tokio::test]
async fn tcp_half_close_preserves_delayed_response() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let config=prepare(json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":port},"outbound":"exit"}]})).unwrap();
    let engine = Engine::bind(config).await.unwrap();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let runner = tokio::spawn(engine.run(cancel.clone()));
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"half-close").await.unwrap();
    client.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"half-close");
    cancel.cancel();
    runner.await.unwrap().unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn udp_keeps_independent_senders_and_packet_boundaries() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let mut data = vec![0; 65_535];
        for _ in 0..4 {
            let (size, address) = echo.recv_from(&mut data).await.unwrap();
            echo.send_to(&data[..size], address).await.unwrap();
        }
    });
    let config=prepare(json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"udp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":port},"outbound":"exit"}],"limits":{"drain_timeout_ms":30}})).unwrap();
    let engine = Engine::bind(config).await.unwrap();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let runner = tokio::spawn(engine.run(cancel.clone()));
    for body in [b"first".as_slice(), b"second".as_slice()] {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for payload in [body, b"".as_slice()] {
            client.send_to(payload, address).await.unwrap();
            let mut data = [0; 64];
            let (size, _) = timeout(Duration::from_secs(3), client.recv_from(&mut data))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&data[..size], payload);
        }
    }
    cancel.cancel();
    runner.await.unwrap().unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn failed_bind_releases_prepared_listeners() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let used = occupied.local_addr().unwrap();
    let temporary = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let free = temporary.local_addr().unwrap();
    drop(temporary);
    let config=prepare(json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"first","type":"tcp-forward","listen":free,"target":{"host":"127.0.0.1","port":1},"outbound":"exit"},{"tag":"second","type":"tcp-forward","listen":used,"target":{"host":"127.0.0.1","port":1},"outbound":"exit"}]})).unwrap();
    assert!(Engine::bind(config).await.is_err());
    assert!(TcpListener::bind(free).await.is_ok());
}
