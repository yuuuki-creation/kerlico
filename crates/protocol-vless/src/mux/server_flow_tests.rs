use super::*;
use kerlico_config::{NodeBuildContext, OutboundFactory};
use kerlico_core::{
    FamilyMode, NodeId, NodeObserver, NodeTasks, ServiceContext, StreamBudget, TargetPolicy,
};
use kerlico_egress::{FlowEnd, Telemetry};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
fn test_migration(peer: &PeerSession, context: &InboundContext) -> Migration {
    Migration {
        table: Arc::new(crate::mux::Table::new(Duration::from_secs(1))),
        user: [0; 16],
        access: peer.clone(),
        context: context.clone(),
    }
}
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: kerlico_core::NodeEvent) {}
}
struct NoDns;
impl kerlico_egress::Resolver for NoDns {
    fn resolve<'a>(
        &'a self,
        _: &'a str,
    ) -> kerlico_core::BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
        Box::pin(async { Err(Error::Unsupported("此回归不解析域名")) })
    }
}
struct FailEnd(tokio::io::DuplexStream);
impl AsyncRead for FailEnd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buffer)
    }
}
impl AsyncWrite for FailEnd {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.get(4) == Some(&3) {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
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

async fn target_eof(fail_end: bool) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0; 4];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"head");
        stream.write_all(b"tail").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let host = ServiceContext::for_test();
    let backend = kerlico_net::DirectFactory
        .compile(&serde_json::json!({}))
        .unwrap()
        .start(host.clone())
        .await
        .unwrap();
    let input = NodeBuildContext::local_for_test(serde_json::json!({}));
    let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
        &input,
        backend,
        TargetPolicy::Local,
        FamilyMode::DualV4Preferred,
        Arc::new(NoDns),
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let owners = NodeTasks::new(NodeId::parse("test-node").unwrap(), cancel.clone());
    let context = InboundContext {
        peer_lease: None,
        tasks: owners.clone(),
        cancel: cancel.clone(),
        peer_addr: None,
        local_addr: Some("127.0.0.1:1".parse().unwrap()),
        connect_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 8,
        events: Arc::new(Observer),
        stream_budget: StreamBudget::new(
            Arc::new(tokio::sync::Semaphore::new(8)),
            Arc::new(tokio::sync::Semaphore::new(8)),
        ),
    };
    let peer = ingress.local(&context).unwrap();
    let (server, mut client) = tokio::io::duplex(8192);
    let server: BoxStream = if fail_end {
        Box::new(FailEnd(server))
    } else {
        Box::new(server)
    };
    let migration = test_migration(&peer, &context);
    let serving = tokio::spawn(serve(server, peer, context, false, migration));
    let mut request = Frame::data(
        1,
        b"head".to_vec(),
        Some(carrier::target(
            &Destination::new("127.0.0.1", address.port()).unwrap(),
            false,
        )),
    );
    request.status = Status::New;
    frame::write(&mut client, request).await.unwrap();
    let data = frame::read(&mut client).await.unwrap().unwrap();
    assert_eq!(data.payload, Some(b"tail".to_vec()));
    if !fail_end {
        let end = frame::read(&mut client).await.unwrap().unwrap();
        assert!(matches!(end.status, Status::End));
        assert!(!end.error);
    }
    let record = ended(&telemetry).await;
    assert_eq!(
        record.end,
        Some(if fail_end {
            FlowEnd::Failed
        } else {
            FlowEnd::Completed
        })
    );
    assert_eq!(record.usage.upload_bytes, 4);
    assert_eq!(record.usage.download_bytes, 4);
    drop(client);
    let result = serving.await.unwrap();
    assert_eq!(result.is_err(), fail_end);
    target.await.unwrap();
    assert!(
        owners
            .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .is_clean()
    );
    assert!(
        host.shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .is_clean()
    );
}
#[tokio::test]
async fn target_eof_completes_only_after_tail_and_mux_end_delivery() {
    target_eof(false).await;
}
#[tokio::test]
async fn mux_end_write_failure_does_not_become_completed() {
    target_eof(true).await;
}

#[tokio::test]
async fn carrier_eof_without_logical_end_records_closed_by_caller() {
    tokio::time::timeout(Duration::from_secs(4), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen, received) = tokio::sync::oneshot::channel();
        let (release, waiting) = tokio::sync::oneshot::channel();
        let target = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0; 4];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(&head, b"head");
            seen.send(()).unwrap();
            waiting.await.unwrap();
        });
        let host = ServiceContext::for_test();
        let backend = kerlico_net::DirectFactory
            .compile(&serde_json::json!({}))
            .unwrap()
            .start(host.clone())
            .await
            .unwrap();
        let input = NodeBuildContext::local_for_test(serde_json::json!({}));
        let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            backend,
            TargetPolicy::Local,
            FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let owners = NodeTasks::new(NodeId::parse("mux-eof-test").unwrap(), cancel.clone());
        let context = InboundContext {
            peer_lease: None,
            tasks: owners.clone(),
            cancel: cancel.child_token(),
            peer_addr: None,
            local_addr: Some("127.0.0.1:1".parse().unwrap()),
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(2),
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 8,
            events: Arc::new(Observer),
            stream_budget: StreamBudget::new(
                Arc::new(tokio::sync::Semaphore::new(8)),
                Arc::new(tokio::sync::Semaphore::new(8)),
            ),
        };
        let peer = ingress.local(&context).unwrap();
        let (server, mut client) = tokio::io::duplex(8192);
        let migration = test_migration(&peer, &context);
        let serving = tokio::spawn(serve(Box::new(server), peer, context, false, migration));
        let mut request = Frame::data(
            1,
            b"head".to_vec(),
            Some(carrier::target(
                &Destination::new("127.0.0.1", address.port()).unwrap(),
                false,
            )),
        );
        request.status = Status::New;
        frame::write(&mut client, request).await.unwrap();
        received.await.unwrap();
        assert_eq!(telemetry.records(0, 8).unwrap()[0].end, None);
        client.shutdown().await.unwrap();
        assert!(serving.await.unwrap().is_ok());
        let record = ended(&telemetry).await;
        assert_eq!(record.end, Some(FlowEnd::ClosedByCaller));
        assert_eq!(record.usage.upload_bytes, 4);
        assert_eq!(record.usage.download_bytes, 0);
        release.send(()).unwrap();
        target.await.unwrap();
        assert!(
            owners
                .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
                .await
                .is_clean()
        );
        assert!(
            host.shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
                .await
                .is_clean()
        );
    })
    .await
    .expect("Mux 无 END 的载体 EOF 回归超时");
}
