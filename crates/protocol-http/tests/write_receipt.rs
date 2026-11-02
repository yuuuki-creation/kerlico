use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory};
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, Capabilities, ConnectContext, DatagramChannel,
    Destination, Error, FamilyMode, InboundContext, NodeEvent, NodeId, NodeObserver, NodeTasks,
    OpenedTcp, Outbound, Result, ServiceContext, StreamBudget, TargetPolicy,
};
use kerlico_egress::FlowEnd;
use serde_json::json;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::TcpListener,
    sync::oneshot,
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
struct ShutdownSignal {
    inner: BoxStream,
    sender: Option<oneshot::Sender<()>>,
}
impl AsyncRead for ShutdownSignal {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, out)
    }
}
impl AsyncWrite for ShutdownSignal {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Ok(())))
            && let Some(sender) = this.sender.take()
        {
            let _ = sender.send(());
        }
        result
    }
}
struct Backend {
    inner: Arc<dyn Outbound>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
}
impl Outbound for Backend {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            let mut opened = self.inner.connect_tcp(target, context).await?;
            opened.stream = Box::new(ShutdownSignal {
                inner: opened.stream,
                sender: self.shutdown.lock().unwrap().take(),
            });
            Ok(opened)
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("测试不使用 UDP")) })
    }
}
struct HoldTail {
    inner: DuplexStream,
    attempted: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<bool>,
    decision: Option<bool>,
    at_flush: bool,
    tail_seen: bool,
}
impl HoldTail {
    fn decide(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(sender) = self.attempted.take() {
            let _ = sender.send(());
        }
        if self.decision.is_none() {
            match Pin::new(&mut self.release).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => self.decision = Some(result.unwrap()),
            }
        }
        Poll::Ready(if self.decision == Some(true) {
            Ok(())
        } else {
            Err(io::ErrorKind::BrokenPipe.into())
        })
    }
}
impl AsyncRead for HoldTail {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, out)
    }
}
impl AsyncWrite for HoldTail {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if data.windows(4).any(|bytes| bytes == b"tail") {
            this.tail_seen = true;
            if !this.at_flush {
                match this.decide(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {}
                }
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.at_flush && this.tail_seen {
            match this.decide(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
async fn header(stream: &mut (impl AsyncRead + Unpin)) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() < 16384);
    }
}
async fn exercise_tail_write(accept: bool, at_flush: bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (send_body, body_allowed) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            header(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            body_allowed.await.unwrap();
            stream.write_all(b"tail").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let host = ServiceContext::for_test();
        let direct = kerlico_net::DirectFactory
            .compile(&json!({}))
            .unwrap()
            .start(host.clone())
            .await
            .unwrap();
        let (upstream_done, upstream_shutdown) = oneshot::channel();
        let backend = Arc::new(Backend {
            inner: direct,
            shutdown: Mutex::new(Some(upstream_done)),
        });
        let input = NodeBuildContext::local_for_test(json!({}));
        let node = kerlico_http::HttpNodeFactory.build(&input).unwrap();
        let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            backend,
            TargetPolicy::Local,
            FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let owners = NodeTasks::new(NodeId::parse("http-write-test").unwrap(), cancel.clone());
        let context = InboundContext {
            peer_lease: None,
            tasks: owners.clone(),
            cancel: cancel.child_token(),
            peer_addr: None,
            local_addr: Some("127.0.0.1:1".parse().unwrap()),
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(3),
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 8,
            events: Arc::new(Observer),
            stream_budget: StreamBudget::new(
                Arc::new(tokio::sync::Semaphore::new(8)),
                Arc::new(tokio::sync::Semaphore::new(8)),
            ),
        };
        let (front, mut client) = tokio::io::duplex(4096);
        let (attempted, writing_tail) = oneshot::channel();
        let (release, decision) = oneshot::channel();
        let handling = tokio::spawn(async move {
            node.handle(
                Box::new(HoldTail {
                    inner: front,
                    attempted: Some(attempted),
                    release: decision,
                    decision: None,
                    at_flush,
                    tail_seen: false,
                }),
                ingress,
                context,
            )
            .await
        });
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
        // 响应头已经真实 flush；它不能确认随后才被 Hyper 消费的最后 body。
        send_body.send(()).unwrap();
        writing_tail.await.unwrap();
        upstream_shutdown.await.unwrap();
        server.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(telemetry.records(0, 8).unwrap()[0].end, None);
        assert_eq!(telemetry.usage().unwrap().active_flows, 1);
        release.send(accept).unwrap();
        let mut tail = Vec::new();
        client.read_to_end(&mut tail).await.unwrap();
        let result = handling.await.unwrap();
        assert_eq!(result.is_ok(), accept);
        assert_eq!(
            tail,
            if accept || at_flush {
                b"tail".to_vec()
            } else {
                Vec::new()
            }
        );
        let records = telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].end,
            Some(if accept {
                FlowEnd::Completed
            } else {
                FlowEnd::Failed
            })
        );
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
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
    .expect("HTTP 最后响应写确认回归超时");
}
#[tokio::test]
async fn last_body_polled_then_front_write_failure_records_failed() {
    exercise_tail_write(false, false).await;
}
#[tokio::test]
async fn earlier_header_flush_does_not_complete_pending_last_body() {
    exercise_tail_write(true, false).await;
}
#[tokio::test]
async fn last_body_written_then_front_flush_failure_records_failed() {
    exercise_tail_write(false, true).await;
}
