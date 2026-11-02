use super::*;
use kerlico_core::{
    AddressedDatagram, Capabilities, DatagramAssociation, DatagramAssociationReceiver,
    DatagramAssociationSender, FamilyMode, NodeId, NodeTasks, OpenedTcp, Outbound, StreamBudget,
    TargetPolicy,
};
use kerlico_egress::{FlowEnd, FlowKind};
use std::{sync::Arc, time::Duration};
struct Observer;
impl kerlico_core::NodeObserver for Observer {
    fn record(&self, _: kerlico_core::NodeEvent) {}
}
struct Silent;
impl DatagramSender for Silent {
    fn send<'a>(&'a mut self, _: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
impl DatagramReceiver for Silent {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(std::future::pending())
    }
}
impl DatagramAssociationSender for Silent {
    fn send_to<'a>(&'a mut self, _: &'a [u8], _: &'a Destination) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
impl DatagramAssociationReceiver for Silent {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(std::future::pending())
    }
}
impl Outbound for Silent {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: false,
            tcp_eof: false,
            udp: true,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async { Err(Error::Unsupported("UDP 终因回归")) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async {
            Ok(DatagramChannel {
                sender: Box::new(Silent),
                receiver: Box::new(Silent),
            })
        })
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async {
            Ok(DatagramAssociation {
                sender: Box::new(Silent),
                receiver: Box::new(Silent),
            })
        })
    }
}
struct NoDns;
impl kerlico_egress::Resolver for NoDns {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
        Box::pin(async { Err(Error::Unsupported("远端目标不应解析")) })
    }
}
fn fixture() -> (PeerSession, kerlico_egress::Telemetry, InboundContext) {
    let input = kerlico_config::NodeBuildContext::local_for_test(serde_json::json!({}));
    let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
        &input,
        Arc::new(Silent),
        TargetPolicy::Remote,
        FamilyMode::DualV4Preferred,
        Arc::new(NoDns),
    )
    .unwrap();
    let cancel = kerlico_core::CancellationToken::new();
    let context = InboundContext {
        peer_lease: None,
        tasks: NodeTasks::new(NodeId::parse("test-node").unwrap(), cancel.clone()),
        cancel,
        peer_addr: None,
        local_addr: Some("127.0.0.1:1".parse().unwrap()),
        connect_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_millis(40),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 8,
        events: Arc::new(Observer),
        stream_budget: StreamBudget::new(
            Arc::new(tokio::sync::Semaphore::new(8)),
            Arc::new(tokio::sync::Semaphore::new(8)),
        ),
    };
    (ingress.local(&context).unwrap(), telemetry, context)
}
#[tokio::test]
async fn fixed_udp_idle_is_timeout_with_one_upload_and_no_replies() {
    let (peer, telemetry, context) = fixture();
    let (config, _) = crate::config::node(crate::config::NodeOptions {
        method: "aes-128-gcm".into(),
        password: "synthetic-flow-secret".into(),
        allow_insecure: false,
    })
    .unwrap();
    let config = Arc::new(config);
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let source = socket.local_addr().unwrap();
    let (send, packets) = mpsc::channel(2);
    send.send(b"one".to_vec()).await.unwrap();
    let result = target_session(
        socket,
        peer,
        context,
        config,
        crate::crypto(shadowsocks::config::ServerType::Server),
        source,
        Destination::new("silent.invalid", 53).unwrap(),
        packets,
    )
    .await;
    assert!(matches!(result, Err(Error::Timeout)));
    let records = telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].end, Some(FlowEnd::Timeout));
    assert_eq!(records[0].kind, FlowKind::FixedUdp);
    assert_eq!(records[0].usage.upload_bytes, 3);
    assert_eq!(records[0].usage.upload_packets, 1);
    assert_eq!(records[0].usage.download_bytes, 0);
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
}
