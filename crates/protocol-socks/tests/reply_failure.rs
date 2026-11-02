use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory};
use kerlico_core::{
    BoxFuture, CancellationToken, Error, FamilyMode, InboundContext, NodeEvent, NodeId,
    NodeObserver, NodeTasks, Result, ServiceContext, StreamBudget, TargetPolicy,
};
use kerlico_egress::FlowEnd;
use serde_json::json;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::TcpListener,
};
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
struct NoDns;
impl kerlico_egress::Resolver for NoDns {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
        Box::pin(async { Err(Error::Unsupported("字面目标不应解析")) })
    }
}
struct FailReply {
    io: DuplexStream,
    method_written: bool,
}
impl AsyncRead for FailReply {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buffer)
    }
}
impl AsyncWrite for FailReply {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.method_written {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let result = Pin::new(&mut this.io).poll_write(cx, bytes);
        if matches!(result,Poll::Ready(Ok(n)) if n>0) {
            this.method_written = true;
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn established_target_is_failed_when_connect_success_reply_cannot_be_written() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let target = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        let _ = waiting.await;
    });
    let host = ServiceContext::for_test();
    let backend = kerlico_net::DirectFactory
        .compile(&json!({}))
        .unwrap()
        .start(host.clone())
        .await
        .unwrap();
    let input = NodeBuildContext::local_for_test(json!({}));
    let node = kerlico_socks::SocksNodeFactory.build(&input).unwrap();
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
        cancel,
        peer_addr: None,
        local_addr: Some("127.0.0.1:1".parse().unwrap()),
        connect_timeout: Duration::from_secs(2),
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
    let (server, mut client) = tokio::io::duplex(128);
    let mut request = vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(port.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let result = node
        .handle(
            Box::new(FailReply {
                io: server,
                method_written: false,
            }),
            ingress,
            context,
        )
        .await;
    assert!(matches!(result, Err(Error::Io(_))));
    assert_eq!(client.read_u16().await.unwrap(), 0x0500);
    let records = telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].end, Some(FlowEnd::Failed));
    assert_eq!(records[0].usage.upload_bytes, 0);
    assert_eq!(records[0].usage.download_bytes, 0);
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
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
}
