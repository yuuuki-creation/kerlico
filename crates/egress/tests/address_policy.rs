use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, Outbound};
use kerlico_egress::Egress;
use kerlico_net::DirectFactory;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn domain_prefers_ipv4_and_falls_back_before_payload() {
    let ipv4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ipv4.local_addr().unwrap().port();
    let ipv6 = TcpListener::bind(("::1", port)).await.unwrap();
    let egress = Egress::new(DirectFactory.build(&serde_json::json!({})).unwrap());
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
    let egress = Egress::new(DirectFactory.build(&serde_json::json!({})).unwrap());
    let context = ConnectContext::new(Duration::from_secs(2));
    for (host, expected) in [("localhost", "127.0.0.1"), ("::1", "::1")] {
        let target = tokio::net::UdpSocket::bind((expected, 0)).await.unwrap();
        let address = target.local_addr().unwrap();
        let mut channel = egress
            .connect_udp(&Destination::new(host, address.port()).unwrap(), &context)
            .await
            .unwrap();
        assert_eq!(
            channel.receiver.peer_addr(),
            Some(Destination::new(expected, address.port()).unwrap())
        );
        channel.sender.send(b"metadata").await.unwrap();
        let mut bytes = [0; 32];
        let (count, source) = target.recv_from(&mut bytes).await.unwrap();
        target.send_to(&bytes[..count], source).await.unwrap();
        assert_eq!(channel.receiver.recv().await.unwrap().unwrap(), b"metadata");
        assert_eq!(
            channel.receiver.peer_addr(),
            Some(Destination::new(expected, address.port()).unwrap())
        );
    }
}

#[tokio::test]
async fn association_preserves_one_socket_across_targets_and_families() {
    let egress = Egress::new(DirectFactory.build(&serde_json::json!({})).unwrap());
    let context = ConnectContext::new(Duration::from_secs(2));
    assert!(egress.supports_udp_association());
    let mut association = egress.associate_udp(&context).await.unwrap();
    let mut source_port = None;
    for (host, dial_host, payload) in [
        ("127.0.0.1", "localhost", b"first".as_slice()),
        ("127.0.0.1", "127.0.0.1", b"".as_slice()),
        ("::1", "::1", b"third".as_slice()),
    ] {
        let echo = tokio::net::UdpSocket::bind((host, 0)).await.unwrap();
        let target = echo.local_addr().unwrap();
        association
            .sender
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
        let (source, response) =
            tokio::time::timeout(Duration::from_secs(2), association.receiver.recv_from())
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
    let (source, payload) =
        tokio::time::timeout(Duration::from_secs(2), association.receiver.recv_from())
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
        association.receiver.recv_from().await,
        Err(kerlico_core::Error::Cancelled)
    ));
    assert!(matches!(
        association
            .sender
            .send_to(b"cancelled", &Destination::new("127.0.0.1", 9).unwrap())
            .await,
        Err(kerlico_core::Error::Cancelled)
    ));
}

#[tokio::test]
async fn unsupported_association_never_falls_back_to_direct() {
    use kerlico_net::RejectFactory;
    let egress = Egress::new(RejectFactory.build(&serde_json::json!({})).unwrap());
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
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        vec![[1; 32]]
    }
    fn handle<'a>(
        &'a self,
        _: kerlico_core::BoxStream,
        _: std::sync::Arc<dyn kerlico_core::AccessService>,
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
    fn build(
        &self,
        _: &serde_json::Value,
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
        let value = serde_json::json!({"version":1,"outbounds":[{"tag":"exit","type":outbound}],"inbounds":[],"nodes":[{"tag":"node","type":"association-test","listen":"127.0.0.1:0","outbound":"exit","options":{}}]});
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
