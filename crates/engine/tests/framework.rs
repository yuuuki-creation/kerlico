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

#[tokio::test]
async fn tcp_forward_idle_records_timeout_with_real_engine_telemetry() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = prepare(json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":target.local_addr().unwrap().port()},"outbound":"exit"}],"limits":{"idle_timeout_ms":40,"drain_timeout_ms":200}})).unwrap();
    let engine = Engine::bind(config).await.unwrap();
    let telemetry = engine.telemetry();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let running = tokio::spawn(engine.run(cancel.clone()));
    let _client = TcpStream::connect(address).await.unwrap();
    let (_target, _) = target.accept().await.unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            let records = telemetry.records(0, 10).unwrap();
            if records.first().is_some_and(|record| record.end.is_some()) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let records = telemetry.records(0, 10).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, kerlico_egress::FlowKind::Tcp);
    assert_eq!(records[0].end, Some(kerlico_egress::FlowEnd::Timeout));
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    cancel.cancel();
    running.await.unwrap().unwrap();
}

#[tokio::test]
async fn udp_forward_idle_records_timeout_and_one_payload() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = prepare(json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"udp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":target.local_addr().unwrap().port()},"outbound":"exit"}],"limits":{"idle_timeout_ms":40,"drain_timeout_ms":200}})).unwrap();
    let engine = Engine::bind(config).await.unwrap();
    let telemetry = engine.telemetry();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let running = tokio::spawn(engine.run(cancel.clone()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"payload", address).await.unwrap();
    let mut packet = [0; 16];
    assert_eq!(target.recv_from(&mut packet).await.unwrap().0, 7);
    timeout(Duration::from_secs(2), async {
        loop {
            let records = telemetry.records(0, 10).unwrap();
            if records.first().is_some_and(|record| record.end.is_some()) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let records = telemetry.records(0, 10).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, kerlico_egress::FlowKind::FixedUdp);
    assert_eq!(records[0].end, Some(kerlico_egress::FlowEnd::Timeout));
    assert_eq!(records[0].usage.upload_bytes, 7);
    assert_eq!(records[0].usage.upload_packets, 1);
    assert_eq!(records[0].usage.download_bytes, 0);
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    cancel.cancel();
    running.await.unwrap().unwrap();
}

#[tokio::test]
async fn forced_outer_handler_still_joins_registered_socket_owner() {
    use kerlico_core::{
        BoxFuture, BoxStream, CredentialManifest, InboundContext, InboundProtocol, IngressBinding,
        Result,
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    struct Released(Arc<AtomicBool>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    struct Protocol {
        ready: tokio::sync::Notify,
        native_address: Mutex<Option<std::net::SocketAddr>>,
        native_released: Arc<AtomicBool>,
        handler_released: Arc<AtomicBool>,
    }
    impl InboundProtocol for Protocol {
        fn credential_manifest(&self) -> CredentialManifest {
            CredentialManifest::new()
        }
        fn handle<'a>(
            &'a self,
            _: BoxStream,
            _: IngressBinding,
            context: InboundContext,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                let _handler = Released(self.handler_released.clone());
                let socket = UdpSocket::bind("127.0.0.1:0").await?;
                *self.native_address.lock().unwrap() = Some(socket.local_addr()?);
                let released = Released(self.native_released.clone());
                let (started, observed) = tokio::sync::oneshot::channel();
                context.tasks.spawn(async move {
                    let _released = released;
                    let _socket = socket;
                    let _ = started.send(());
                    std::future::pending::<()>().await;
                })?;
                observed.await.unwrap();
                self.ready.notify_one();
                std::future::pending().await
            })
        }
    }
    struct Factory(Arc<Protocol>);
    impl kerlico_config::NodeFactory for Factory {
        fn kind(&self) -> &'static str {
            "owned-socket-test"
        }
        fn allows_local_inbound(&self) -> bool {
            true
        }
        fn build(&self, _: &kerlico_config::NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
            Ok(self.0.clone())
        }
    }
    let protocol = Arc::new(Protocol {
        ready: tokio::sync::Notify::new(),
        native_address: Mutex::new(None),
        native_released: Arc::new(AtomicBool::new(false)),
        handler_released: Arc::new(AtomicBool::new(false)),
    });
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(Factory(protocol.clone())).unwrap();
    let input = json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"local_inbounds":[{"tag":"owned-node","type":"owned-socket-test","listen":"127.0.0.1:0","outbound":"exit","options":{}}],"limits":{"drain_timeout_ms":200}});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&input).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let stats = engine.stats();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let run = tokio::spawn(engine.run(cancel.clone()));
    let _client = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(1), protocol.ready.notified())
        .await
        .unwrap();
    assert!(!protocol.native_released.load(Ordering::Acquire));
    assert_eq!(stats.forced_cleanup.load(Ordering::Acquire), 0);
    cancel.cancel();
    timeout(Duration::from_secs(1), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(protocol.handler_released.load(Ordering::Acquire));
    assert!(protocol.native_released.load(Ordering::Acquire));
    assert_eq!(stats.forced_cleanup.load(Ordering::Acquire), 1);
    let address = protocol.native_address.lock().unwrap().unwrap();
    let _rebound = UdpSocket::bind(address).await.unwrap();
}

#[tokio::test]
async fn handed_off_physical_io_keeps_its_permit_and_peer_cancel() {
    use kerlico_core::{
        BoxFuture, BoxStream, CredentialManifest, InboundContext, InboundProtocol, IngressBinding,
        Result,
    };
    use std::sync::{Arc, Mutex, atomic::Ordering};
    struct Protocol {
        peers: Mutex<Vec<CancellationToken>>,
        budget: Mutex<Option<kerlico_core::StreamBudget>>,
    }
    impl InboundProtocol for Protocol {
        fn credential_manifest(&self) -> CredentialManifest {
            CredentialManifest::new()
        }
        fn handle<'a>(
            &'a self,
            mut stream: BoxStream,
            _: IngressBinding,
            context: InboundContext,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                let cancel = context.cancel.clone();
                self.peers.lock().unwrap().push(cancel.clone());
                *self.budget.lock().unwrap() = Some(context.stream_budget.clone());
                context.tasks.spawn(async move {
                    if stream.write_all(b"ready").await.is_err() { return; }
                    let mut bytes = [0; 32];
                    loop {
                        tokio::select! {
                            biased;
                            _=cancel.cancelled()=>break,
                            read=stream.read(&mut bytes)=>match read {
                                Ok(0)|Err(_)=>break,
                                Ok(count)=>{if stream.write_all(&bytes[..count]).await.is_err(){break;}}
                            }
                        }
                    }
                })?;
                Ok(())
            })
        }
    }
    struct Factory(Arc<Protocol>);
    impl kerlico_config::NodeFactory for Factory {
        fn kind(&self) -> &'static str {
            "handoff-test"
        }
        fn allows_local_inbound(&self) -> bool {
            true
        }
        fn build(&self, _: &kerlico_config::NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
            Ok(self.0.clone())
        }
    }
    let protocol = Arc::new(Protocol {
        peers: Mutex::new(Vec::new()),
        budget: Mutex::new(None),
    });
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(Factory(protocol.clone())).unwrap();
    let input = json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"local_inbounds":[{"tag":"handoff-node","type":"handoff-test","listen":"127.0.0.1:0","outbound":"exit","max_sessions":2,"options":{}}],"limits":{"max_sessions":2,"drain_timeout_ms":200}});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&input).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let stats = engine.stats();
    let address = engine.listeners().unwrap()[0].1;
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    let mut first = TcpStream::connect(address).await.unwrap();
    let mut hello = [0; 5];
    timeout(Duration::from_secs(1), first.read_exact(&mut hello))
        .await
        .unwrap()
        .unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(1), second.read_exact(&mut hello))
        .await
        .unwrap()
        .unwrap();
    first.write_all(b"first").await.unwrap();
    timeout(Duration::from_secs(1), first.read_exact(&mut hello))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&hello, b"first");
    let mut excess = TcpStream::connect(address).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), excess.read(&mut hello))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(stats.dropped.load(Ordering::Acquire), 1);
    protocol.peers.lock().unwrap()[0].cancel();
    assert_eq!(
        timeout(Duration::from_secs(1), first.read(&mut hello))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let budget = protocol.budget.lock().unwrap().clone().unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(lease) = budget.try_acquire() {
                drop(lease);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    second.write_all(b"other").await.unwrap();
    timeout(Duration::from_secs(1), second.read_exact(&mut hello))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&hello, b"other");
    let mut replacement = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(1), replacement.read_exact(&mut hello))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&hello, b"ready");
    replacement.shutdown().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), replacement.read(&mut hello))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    stop.cancel();
    timeout(Duration::from_secs(1), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), second.read(&mut hello))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        protocol
            .peers
            .lock()
            .unwrap()
            .iter()
            .all(CancellationToken::is_cancelled)
    );
}

#[tokio::test]
async fn one_native_node_panic_keeps_another_node_running() {
    use kerlico_core::{
        BoxFuture, BoxStream, CredentialManifest, InboundContext, InboundProtocol, IngressBinding,
        Result,
    };
    use std::sync::{Arc, Mutex};
    struct Protocol {
        fail: bool,
        failed_node: Arc<Mutex<Option<CancellationToken>>>,
    }
    impl InboundProtocol for Protocol {
        fn credential_manifest(&self) -> CredentialManifest {
            CredentialManifest::new()
        }
        fn handle<'a>(
            &'a self,
            mut stream: BoxStream,
            _: IngressBinding,
            context: InboundContext,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                if self.fail {
                    *self.failed_node.lock().unwrap() = Some(context.tasks.cancel());
                    context
                        .tasks
                        .spawn(async { panic!("受控原生节点任务异常") })?;
                    return Ok(());
                }
                let (mut reader, mut writer) = tokio::io::split(&mut stream);
                tokio::io::copy(&mut reader, &mut writer).await?;
                Ok(())
            })
        }
    }
    struct Factory(Arc<Mutex<Option<CancellationToken>>>);
    impl kerlico_config::NodeFactory for Factory {
        fn kind(&self) -> &'static str {
            "isolated-node-test"
        }
        fn allows_local_inbound(&self) -> bool {
            true
        }
        fn build(
            &self,
            input: &kerlico_config::NodeBuildContext,
        ) -> Result<Arc<dyn InboundProtocol>> {
            Ok(Arc::new(Protocol {
                fail: input.options()["fail"].as_bool().unwrap(),
                failed_node: self.0.clone(),
            }))
        }
    }
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let failed_node = Arc::new(Mutex::new(None));
    registry
        .register_node(Factory(failed_node.clone()))
        .unwrap();
    let input = json!({"version":2,"outbounds":[{"tag":"shared","type":"direct"}],"local_inbounds":[{"tag":"first","type":"isolated-node-test","listen":"127.0.0.1:0","outbound":"shared","options":{"fail":true}},{"tag":"second","type":"isolated-node-test","listen":"127.0.0.1:0","outbound":"shared","options":{"fail":false}}],"limits":{"drain_timeout_ms":200}});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&input).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let addresses = engine.listeners().unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    let mut sibling =
        TcpStream::connect(addresses.iter().find(|(tag, _)| tag == "second").unwrap().1)
            .await
            .unwrap();
    sibling.write_all(b"before").await.unwrap();
    let mut bytes = [0; 6];
    sibling.read_exact(&mut bytes).await.unwrap();
    let mut first = TcpStream::connect(addresses.iter().find(|(tag, _)| tag == "first").unwrap().1)
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), first.read(&mut bytes))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    timeout(Duration::from_secs(1), async {
        loop {
            if failed_node
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    sibling.write_all(b"after!").await.unwrap();
    timeout(Duration::from_secs(1), sibling.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"after!");
    assert!(!running.is_finished());
    assert!(!stop.is_cancelled());
    stop.cancel();
    let result = timeout(Duration::from_secs(1), running)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(result, Err(kerlico_core::Error::Shutdown { cleanup_failures, .. }) if cleanup_failures > 0)
    );
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
    ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<kerlico_core::OpenedTcp>> {
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
    fn compile(&self, _: &serde_json::Value) -> kerlico_core::Result<kerlico_config::OutboundPlan> {
        use kerlico_core::Outbound;
        Ok(kerlico_config::OutboundPlan::new(
            TcpOnly.capabilities(),
            false,
            kerlico_core::TargetPolicy::Remote,
            |_| {
                Box::pin(async {
                    Ok(std::sync::Arc::new(TcpOnly) as std::sync::Arc<dyn kerlico_core::Outbound>)
                })
            },
        ))
    }
}

#[test]
fn udp_cannot_use_tcp_only_module_and_limits_are_checked() {
    let mut registry = Registry::default();
    registry.register(TcpOnlyFactory).unwrap();
    let mut value = json!({"version":2,"outbounds":[{"tag":"exit","type":"tcp-only-test"}],"inbounds":[{"tag":"entry","type":"udp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":1},"outbound":"exit"}]});
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
    let config=prepare(json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":port},"outbound":"exit"}],"limits":{"max_sessions":1,"drain_timeout_ms":30}})).unwrap();
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
    let base = json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[]});
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
    let (half_closed, half_observed) = tokio::sync::oneshot::channel();
    let (continue_tail, tail_allowed) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        half_closed.send(()).unwrap();
        tail_allowed.await.unwrap();
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let config=prepare(json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":port},"outbound":"exit"}]})).unwrap();
    let engine = Engine::bind(config).await.unwrap();
    let telemetry = engine.telemetry();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let runner = tokio::spawn(engine.run(cancel.clone()));
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"half-close").await.unwrap();
    client.shutdown().await.unwrap();
    half_observed.await.unwrap();
    assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    assert!(telemetry.records(0, 1).unwrap()[0].end.is_none());
    continue_tail.send(()).unwrap();
    let mut reply = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"half-close");
    cancel.cancel();
    runner.await.unwrap().unwrap();
    peer.await.unwrap();
    let record = telemetry.records(0, 1).unwrap().remove(0);
    assert_eq!(record.end, Some(kerlico_egress::FlowEnd::Completed));
    assert_eq!(record.usage.upload_bytes, 10);
    assert_eq!(record.usage.download_bytes, 10);
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
    let config=prepare(json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"udp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":port},"outbound":"exit"}],"limits":{"drain_timeout_ms":30}})).unwrap();
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
    let config=prepare(json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"first","type":"tcp-forward","listen":free,"target":{"host":"127.0.0.1","port":1},"outbound":"exit"},{"tag":"second","type":"tcp-forward","listen":used,"target":{"host":"127.0.0.1","port":1},"outbound":"exit"}]})).unwrap();
    assert!(Engine::bind(config).await.is_err());
    assert!(TcpListener::bind(free).await.is_ok());
}

#[tokio::test]
async fn sibling_transport_keeps_node_context_alive_during_drain() {
    use kerlico_core::{
        BoxFuture, BoxStream, InboundContext, InboundProtocol, IngressBinding, Result,
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    struct Protocol {
        tcp: Mutex<Option<CancellationToken>>,
        ready: tokio::sync::Notify,
        checked: AtomicBool,
    }
    impl InboundProtocol for Protocol {
        fn credential_manifest(&self) -> kerlico_core::CredentialManifest {
            kerlico_core::CredentialManifest::new()
        }
        fn supports_udp(&self) -> bool {
            true
        }
        fn handle<'a>(
            &'a self,
            _: BoxStream,
            _: IngressBinding,
            context: InboundContext,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                *self.tcp.lock().unwrap() = Some(context.cancel);
                self.ready.notify_one();
                Ok(())
            })
        }
        fn handle_udp<'a>(
            &'a self,
            _: Arc<UdpSocket>,
            _: IngressBinding,
            context: InboundContext,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                while !context.stream_budget.is_closed() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
                assert!(self.tcp.lock().unwrap().as_ref().unwrap().is_cancelled());
                assert!(!context.cancel.is_cancelled());
                self.checked.store(true, Ordering::SeqCst);
                Ok(())
            })
        }
    }
    struct Factory(Arc<Protocol>);
    impl kerlico_config::NodeFactory for Factory {
        fn kind(&self) -> &'static str {
            "lifecycle-test"
        }
        fn allows_local_inbound(&self) -> bool {
            true
        }
        fn build(&self, _: &kerlico_config::NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
            Ok(self.0.clone())
        }
    }
    let protocol = Arc::new(Protocol {
        tcp: Mutex::new(None),
        ready: tokio::sync::Notify::new(),
        checked: AtomicBool::new(false),
    });
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(Factory(protocol.clone())).unwrap();
    let value = json!({"version":2,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"local_inbounds":[{"tag":"test-node","type":"lifecycle-test","listen":"127.0.0.1:0","outbound":"direct","options":{}}],"limits":{"max_sessions":8,"drain_timeout_ms":200}});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let running = tokio::spawn(engine.run(cancel.clone()));
    let connection = TcpStream::connect(address).await.unwrap();
    protocol.ready.notified().await;
    drop(connection);
    cancel.cancel();
    timeout(Duration::from_secs(1), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(protocol.checked.load(Ordering::SeqCst));
}

#[derive(Default)]
struct SharedCounts {
    compiled: std::sync::atomic::AtomicUsize,
    started: std::sync::atomic::AtomicUsize,
    stopped: std::sync::atomic::AtomicUsize,
    task_finished: std::sync::atomic::AtomicBool,
    resources: std::sync::Mutex<Vec<kerlico_core::ResourceKey>>,
}
struct SharedFactory(std::sync::Arc<SharedCounts>);
struct SharedBackend {
    counts: std::sync::Arc<SharedCounts>,
    host: kerlico_core::ServiceContext,
}
impl kerlico_core::Outbound for SharedBackend {
    fn capabilities(&self) -> kerlico_core::Capabilities {
        kerlico_core::Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a kerlico_core::Destination,
        context: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            self.counts
                .resources
                .lock()
                .unwrap()
                .push(context.resource_key().clone());
            let (client, mut server) = tokio::io::duplex(1024);
            self.host.spawn(async move {
                let mut bytes = Vec::new();
                if server.read_to_end(&mut bytes).await.is_ok() {
                    let _ = server.write_all(&bytes).await;
                }
            })?;
            Ok(kerlico_core::OpenedTcp {
                stream: Box::new(client),
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a kerlico_core::Destination,
        _: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<kerlico_core::DatagramChannel>> {
        Box::pin(async { Err(kerlico_core::Error::Unsupported("测试后端无UDP")) })
    }
    fn shutdown(&self) -> kerlico_core::BoxFuture<'_, kerlico_core::Result<()>> {
        Box::pin(async move {
            self.counts
                .stopped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}
impl kerlico_config::OutboundFactory for SharedFactory {
    fn kind(&self) -> &'static str {
        "shared-test"
    }
    fn compile(&self, _: &serde_json::Value) -> kerlico_core::Result<kerlico_config::OutboundPlan> {
        self.0
            .compiled
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let counts = self.0.clone();
        Ok(kerlico_config::OutboundPlan::new(
            kerlico_core::Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: false,
            },
            false,
            kerlico_core::TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    counts
                        .started
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let observed = counts.clone();
                    let cancel = host.cancel();
                    host.spawn(async move {
                        cancel.cancelled().await;
                        observed
                            .task_finished
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                    })?;
                    Ok(std::sync::Arc::new(SharedBackend { counts, host })
                        as std::sync::Arc<dyn kerlico_core::Outbound>)
                })
            },
        ))
    }
}
#[tokio::test]
async fn one_named_runtime_serves_two_entries_without_merging_source_identity() {
    use std::sync::{Arc, atomic::Ordering};
    let counts = Arc::new(SharedCounts::default());
    let mut registry = Registry::default();
    registry.register(SharedFactory(counts.clone())).unwrap();
    let value = json!({"version":2,"outbounds":[{"tag":"shared","type":"shared-test"}],"inbounds":[
        {"tag":"first","type":"tcp-forward","listen":"127.0.0.1:0","outbound":"shared","target":{"host":"remote.invalid","port":80}},
        {"tag":"second","type":"tcp-forward","listen":"127.0.0.1:0","outbound":"shared","target":{"host":"remote.invalid","port":80}}
    ]});
    let plan = registry
        .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
        .unwrap();
    assert_eq!(counts.compiled.load(Ordering::SeqCst), 1);
    assert_eq!(counts.started.load(Ordering::SeqCst), 0);
    let engine = Engine::bind(plan).await.unwrap();
    let listeners = engine.listeners().unwrap();
    let telemetry = engine.telemetry();
    assert_eq!(counts.started.load(Ordering::SeqCst), 1);
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    for (_, address) in listeners {
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket.write_all(b"shared").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(Duration::from_secs(1), socket.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"shared");
    }
    stop.cancel();
    running.await.unwrap().unwrap();
    let resources = counts.resources.lock().unwrap();
    assert_eq!(resources.len(), 2);
    assert_eq!(resources[0].instance(), resources[1].instance());
    assert_ne!(resources[0].source(), resources[1].source());
    assert_eq!(counts.stopped.load(Ordering::SeqCst), 1);
    assert!(counts.task_finished.load(Ordering::SeqCst));
    let usage = telemetry.usage().unwrap();
    assert_eq!(usage.engine.upload_bytes, 12);
    assert_eq!(usage.engine.download_bytes, 12);
    assert_eq!(usage.nodes.len(), 2);
    assert_eq!(usage.outbounds.len(), 1);
}
#[tokio::test]
async fn bind_failure_waits_for_started_service_tasks_and_keeps_primary_error() {
    use std::sync::{Arc, atomic::Ordering};
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let counts = Arc::new(SharedCounts::default());
    let mut registry = Registry::default();
    registry.register(SharedFactory(counts.clone())).unwrap();
    let value = json!({"version":2,"outbounds":[{"tag":"shared","type":"shared-test"}],"inbounds":[{"tag":"entry","type":"tcp-forward","listen":occupied.local_addr().unwrap(),"outbound":"shared","target":{"host":"remote.invalid","port":80}}]});
    let result = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap(),
    )
    .await;
    assert!(
        matches!(result,Err(kerlico_core::Error::Startup {primary,cleanup_timed_out:false,cleanup_failures:0}) if matches!(*primary,kerlico_core::Error::Io(_)))
    );
    assert_eq!(counts.started.load(Ordering::SeqCst), 1);
    assert_eq!(counts.stopped.load(Ordering::SeqCst), 1);
    assert!(counts.task_finished.load(Ordering::SeqCst));
}
