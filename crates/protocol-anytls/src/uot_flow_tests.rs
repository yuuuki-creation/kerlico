use super::*;
use kerlico_core::{
    AddressedDatagram, Capabilities, DatagramAssociation, DatagramAssociationReceiver,
    DatagramAssociationSender, FamilyMode, NodeId, NodeTasks, OpenedTcp, Outbound, StreamBudget,
    TargetPolicy,
};
use kerlico_egress::FlowEnd;
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
async fn parent_timeout_finishes_each_uot_target_once() {
    use tokio::io::AsyncWriteExt;
    let (peer, telemetry, mut context) = fixture();
    context.idle_timeout = Duration::from_secs(5);
    let (owner, ending) = tokio::sync::watch::channel(None);
    let (task_io, mut client) = tokio::io::duplex(8192);
    let node_tasks = context.tasks.clone();
    let running = tokio::spawn(serve(Box::new(task_io), peer, context, ending));
    let target = Destination::new("first.invalid", 53).unwrap();
    client.write_u8(0).await.unwrap();
    client
        .write_all(&codec::address(&target, false))
        .await
        .unwrap();
    for name in ["first.invalid", "second.invalid"] {
        let target = Destination::new(name, 53).unwrap();
        client
            .write_all(&codec::address(&target, true))
            .await
            .unwrap();
        write_packet(&mut client, b"one").await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if telemetry.usage().unwrap().engine.upload_packets == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    owner.send_replace(Some(kerlico_core::FlowOutcome::Failed(
        kerlico_core::FlowFailure::Timeout,
    )));
    assert!(matches!(running.await.unwrap(), Err(Error::Timeout)));
    let records = telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.end == Some(FlowEnd::Timeout)
                && record.usage.upload_bytes == 3
                && record.usage.upload_packets == 1)
    );
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    assert!(
        node_tasks
            .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .is_clean()
    );
}
