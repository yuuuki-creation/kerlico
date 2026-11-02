use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, Outbound};
use kerlico_core::{
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramReceiver, DatagramSender,
};
use kerlico_core::{PeerSession, ServiceContext, TargetPolicy};
use kerlico_net::DirectFactory;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn direct_tcp_binding_matches_target_observation_for_both_families() {
    for host in ["127.0.0.1", "::1"] {
        let listener = TcpListener::bind((host, 0)).await.unwrap();
        let target = listener.local_addr().unwrap();
        let peer = local_peer(
            DirectFactory
                .compile(&serde_json::json!({}))
                .unwrap()
                .start(ServiceContext::for_test())
                .await
                .unwrap(),
        )
        .await;
        let opened = peer
            .connect_tcp(
                &Destination::new(host, target.port()).unwrap(),
                &ConnectContext::new(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        let (_accepted, observed) = listener.accept().await.unwrap();
        assert_eq!(
            opened.info().target_bind(),
            &kerlico_core::TargetBind::Known {
                endpoint: Destination::new(&observed.ip().to_string(), observed.port()).unwrap(),
                evidence: kerlico_core::BindEvidence::LocalSocket,
            }
        );
        opened.finish(kerlico_core::FlowOutcome::ClosedByCaller);
    }
}

#[tokio::test]
async fn domain_prefers_ipv4_and_falls_back_before_payload() {
    let ipv4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ipv4.local_addr().unwrap().port();
    let ipv6 = TcpListener::bind(("::1", port)).await.unwrap();
    let egress = local_peer(
        DirectFactory
            .compile(&serde_json::json!({}))
            .unwrap()
            .start(ServiceContext::for_test())
            .await
            .unwrap(),
    )
    .await;
    let context = ConnectContext::new(Duration::from_secs(2));
    let target = Destination::new("localhost", port).unwrap();
    let send4 = tokio::spawn(async move {
        let (mut socket, _) = ipv4.accept().await.unwrap();
        socket.write_all(b"v4").await.unwrap();
    });
    let mut stream = egress.connect_tcp(&target, &context).await.unwrap();
    let mut bytes = [0; 2];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"v4");
    drop(stream);
    send4.await.unwrap();
    let send6 = tokio::spawn(async move {
        let (mut socket, _) = ipv6.accept().await.unwrap();
        socket.write_all(b"v6").await.unwrap();
    });
    let mut stream = egress.connect_tcp(&target, &context).await.unwrap();
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"v6");
    drop(stream);
    send6.await.unwrap();
}

#[tokio::test]
async fn udp_reports_business_peer_after_unified_resolution() {
    let egress = local_peer(
        DirectFactory
            .compile(&serde_json::json!({}))
            .unwrap()
            .start(ServiceContext::for_test())
            .await
            .unwrap(),
    )
    .await;
    let context = ConnectContext::new(Duration::from_secs(2));
    for (host, expected) in [("localhost", "127.0.0.1"), ("::1", "::1")] {
        let target = tokio::net::UdpSocket::bind((expected, 0)).await.unwrap();
        let address = target.local_addr().unwrap();
        let channel = egress
            .connect_udp(&Destination::new(host, address.port()).unwrap(), &context)
            .await
            .unwrap();
        let (mut sender, mut receiver, _completion) = channel.into_parts();
        assert_eq!(
            receiver.peer_addr(),
            Some(Destination::new(expected, address.port()).unwrap())
        );
        sender.send(b"metadata").await.unwrap();
        let mut bytes = [0; 32];
        let (count, source) = target.recv_from(&mut bytes).await.unwrap();
        target.send_to(&bytes[..count], source).await.unwrap();
        assert_eq!(receiver.recv().await.unwrap().unwrap(), b"metadata");
        assert_eq!(
            receiver.peer_addr(),
            Some(Destination::new(expected, address.port()).unwrap())
        );
    }
}

#[tokio::test]
async fn association_preserves_one_socket_across_targets_and_families() {
    let egress = local_peer(
        DirectFactory
            .compile(&serde_json::json!({}))
            .unwrap()
            .start(ServiceContext::for_test())
            .await
            .unwrap(),
    )
    .await;
    let context = ConnectContext::new(Duration::from_secs(2));
    assert!(egress.supports_udp_association());
    let (mut sender, mut receiver, _completion) =
        egress.associate_udp(&context).await.unwrap().into_parts();
    let mut source_port = None;
    for (host, dial_host, payload) in [
        ("127.0.0.1", "localhost", b"first".as_slice()),
        ("127.0.0.1", "127.0.0.1", b"".as_slice()),
        ("::1", "::1", b"third".as_slice()),
    ] {
        let echo = tokio::net::UdpSocket::bind((host, 0)).await.unwrap();
        let target = echo.local_addr().unwrap();
        sender
            .send_to(
                payload,
                &Destination::new(dial_host, target.port()).unwrap(),
            )
            .await
            .unwrap();
        let mut bytes = [0; 64];
        let (count, source) =
            tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&bytes[..count], payload);
        if let Some(port) = source_port {
            assert_eq!(source.port(), port);
        } else {
            source_port = Some(source.port());
        }
        echo.send_to(&bytes[..count], source).await.unwrap();
        let (source, response) = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(source, Destination::new(host, target.port()).unwrap());
        assert_eq!(response, payload);
    }
    let independent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    independent
        .send_to(b"independent-peer", ("127.0.0.1", source_port.unwrap()))
        .await
        .unwrap();
    let (source, payload) = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        source,
        Destination::new("127.0.0.1", independent.local_addr().unwrap().port()).unwrap()
    );
    assert_eq!(payload, b"independent-peer");
    context.cancel.cancel();
    assert!(matches!(
        receiver.recv_from().await,
        Err(kerlico_core::Error::Cancelled)
    ));
    assert!(matches!(
        sender
            .send_to(b"cancelled", &Destination::new("127.0.0.1", 9).unwrap())
            .await,
        Err(kerlico_core::Error::Cancelled)
    ));
}

#[tokio::test]
async fn unsupported_association_never_falls_back_to_direct() {
    use kerlico_net::RejectFactory;
    let egress = local_peer(
        RejectFactory
            .compile(&serde_json::json!({}))
            .unwrap()
            .start(ServiceContext::for_test())
            .await
            .unwrap(),
    )
    .await;
    assert!(!egress.supports_udp_association());
    assert!(matches!(
        egress
            .associate_udp(&ConnectContext::new(Duration::from_secs(1)))
            .await,
        Err(kerlico_core::Error::Unsupported(_))
    ));
}

struct AssociationNode;
impl kerlico_core::InboundProtocol for AssociationNode {
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn credential_manifest(&self) -> kerlico_core::CredentialManifest {
        kerlico_core::CredentialManifest::new()
    }
    fn handle<'a>(
        &'a self,
        _: kerlico_core::BoxStream,
        _: kerlico_core::IngressBinding,
        _: kerlico_core::InboundContext,
    ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<()>> {
        Box::pin(async {
            Err(kerlico_core::Error::Unsupported("仅用于验证配置能力门槛"))
        })
    }
}
struct AssociationNodeFactory;
impl kerlico_config::NodeFactory for AssociationNodeFactory {
    fn kind(&self) -> &'static str {
        "association-test"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(
        &self,
        _: &kerlico_config::NodeBuildContext,
    ) -> kerlico_core::Result<std::sync::Arc<dyn kerlico_core::InboundProtocol>> {
        Ok(std::sync::Arc::new(AssociationNode))
    }
}

#[test]
fn required_association_is_checked_before_binding() {
    let mut registry = kerlico_config::Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(kerlico_net::RejectFactory).unwrap();
    registry.register_node(AssociationNodeFactory).unwrap();
    for (outbound, allowed) in [("direct", true), ("reject", false)] {
        let value = serde_json::json!({"version":2,"outbounds":[{"tag":"exit","type":outbound}],"inbounds":[],"local_inbounds":[{"tag":"node","type":"association-test","listen":"127.0.0.1:0","outbound":"exit","options":{}}]});
        let result =
            registry.prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap());
        assert_eq!(result.is_ok(), allowed);
        if !allowed {
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("同一出口 socket")
            );
        }
    }
}

async fn local_peer(outbound: std::sync::Arc<dyn Outbound>) -> PeerSession {
    let input = kerlico_config::NodeBuildContext::local_for_test(serde_json::json!({}));
    let ingress = kerlico_egress::testing::ingress(&input, outbound, TargetPolicy::Local).unwrap();
    ingress.local(&context()).unwrap()
}
fn context() -> kerlico_core::InboundContext {
    use std::sync::Arc;
    struct Observer;
    impl kerlico_core::NodeObserver for Observer {
        fn record(&self, _: kerlico_core::NodeEvent) {}
    }
    kerlico_core::InboundContext {
        peer_lease: None,
        tasks: kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("test-node").unwrap(),
            kerlico_core::CancellationToken::new(),
        ),
        peer_addr: None,
        local_addr: None,
        cancel: kerlico_core::CancellationToken::new(),
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_millis(50),
        max_datagram_size: 65535,
        max_streams: 8,
        stream_budget: kerlico_core::StreamBudget::new(
            Arc::new(tokio::sync::Semaphore::new(8)),
            Arc::new(tokio::sync::Semaphore::new(8)),
        ),
        events: Arc::new(Observer),
    }
}
