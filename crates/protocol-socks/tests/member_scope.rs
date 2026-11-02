use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
#[tokio::test]
async fn authenticated_members_keep_distinct_scopes_and_original_target() {
    let users = vec![
        json!({"username":"member-a","password":"synthetic-secret-a"}),
        json!({"username":"member-b","password":"synthetic-secret-b"}),
    ];
    let clients = users.iter().map(|user| json!({"auth":user})).collect();
    shared::assert_member_scope(
        &kerlico_socks::SocksNodeFactory,
        &kerlico_socks::SocksFactory,
        json!({}),
        users,
        clients,
    )
    .await;
}

#[tokio::test]
async fn fixed_udp_backend_keeps_tcp_and_rejects_associate_without_fanout() {
    use kerlico_config::NodeFactory;
    use kerlico_core::{
        BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination,
        InboundContext, NodeEvent, NodeObserver, Outbound, Result,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Observer;
    impl NodeObserver for Observer {
        fn record(&self, _: NodeEvent) {}
    }
    struct FixedOnly(Arc<AtomicUsize>);
    impl Outbound for FixedOnly {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
            Box::pin(async move {
                let opening: kerlico_core::BoxFuture<'_, Result<BoxStream>> = Box::pin(async {
                    let (stream, mut echo) = tokio::io::duplex(32);
                    tokio::spawn(async move {
                        let (mut read, mut write) = tokio::io::split(&mut echo);
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                    Ok(Box::new(stream) as BoxStream)
                });
                let stream = opening.await?;
                Ok(kerlico_core::OpenedTcp {
                    stream,
                    info: kerlico_core::TcpConnectInfo::unknown(),
                })
            })
        }
        fn connect_udp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(kerlico_core::Error::ResourceLimit)
            })
        }
    }
    let input = kerlico_config::NodeBuildContext::local_for_test(json!({}));
    let node = kerlico_socks::SocksNodeFactory.build(&input).unwrap();
    assert!(!node.requires_udp_association());
    let calls = Arc::new(AtomicUsize::new(0));
    let ingress = kerlico_egress::testing::ingress(
        &input,
        Arc::new(FixedOnly(calls.clone())),
        kerlico_core::TargetPolicy::Remote,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = kerlico_core::CancellationToken::new();
    let context = InboundContext {
        peer_lease: None,
        tasks: kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("test-node").unwrap(),
            kerlico_core::CancellationToken::new(),
        ),
        cancel: cancel.clone(),
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_millis(100),
        max_datagram_size: 65507,
        max_streams: 8,
        peer_addr: None,
        local_addr: Some(address),
        events: Arc::new(Observer),
        stream_budget: kerlico_core::StreamBudget::new(
            Arc::new(tokio::sync::Semaphore::new(8)),
            Arc::new(tokio::sync::Semaphore::new(8)),
        ),
    };
    let server = tokio::spawn(async move {
        let mut flows = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (stream, peer) = listener.accept().await.unwrap();
            let node = node.clone();
            let ingress = ingress.clone();
            let mut context = context.clone();
            context.peer_addr = Some(peer);
            flows.spawn(async move {
                let _ = node.handle(Box::new(stream), ingress, context).await;
            });
        }
        while flows.join_next().await.is_some() {}
    });
    let outbound = shared::outbound(
        &kerlico_socks::SocksFactory,
        &json!({"server":{"host":"127.0.0.1","port":address.port()}}),
    )
    .await
    .unwrap();
    assert!(outbound.supports_udp_association());
    let target = Destination::new("example.invalid", 443).unwrap();
    let mut tcp = outbound
        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
        .await
        .unwrap()
        .stream;
    tcp.write_all(b"tcp").await.unwrap();
    let mut bytes = [0; 3];
    tcp.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"tcp");
    drop(tcp);
    assert!(
        outbound
            .connect_udp(&target, &ConnectContext::new(Duration::from_secs(2)))
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    outbound.shutdown().await.unwrap();
}
