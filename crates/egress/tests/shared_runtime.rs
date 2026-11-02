use kerlico_config::NodeBuildContext;
use kerlico_core::*;
use kerlico_egress::{Resolver, testing};
use serde_json::json;
use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod failure_during_poll {
    use super::*;
    use std::{
        io,
        pin::Pin,
        sync::atomic::AtomicBool,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Clone, Copy, PartialEq)]
    enum Operation {
        Read,
        Write,
        Flush,
        Shutdown,
    }
    #[derive(Clone, Copy)]
    enum Failure {
        Cancelled,
        Aborted,
        Timeout,
    }
    struct Fault {
        armed: AtomicBool,
        hits: AtomicUsize,
        operation: Operation,
        failure: Failure,
    }
    struct Backend(Arc<Fault>);
    struct Stream {
        fault: Arc<Fault>,
        cancel: CancellationToken,
        read: bool,
    }
    impl Stream {
        fn error(&self, operation: Operation) -> Option<io::Error> {
            if !self.fault.armed.load(Ordering::Acquire) || self.fault.operation != operation {
                return None;
            }
            self.fault.hits.fetch_add(1, Ordering::AcqRel);
            Some(match self.fault.failure {
                Failure::Cancelled => {
                    self.cancel.cancel();
                    io::Error::new(io::ErrorKind::ConnectionAborted, Error::Cancelled)
                }
                Failure::Aborted => io::ErrorKind::ConnectionAborted.into(),
                Failure::Timeout => io::Error::new(io::ErrorKind::TimedOut, Error::Timeout),
            })
        }
    }
    impl AsyncRead for Stream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(error) = self.error(Operation::Read) {
                return Poll::Ready(Err(error));
            }
            if !self.read && buf.remaining() >= 2 {
                self.read = true;
                buf.put_slice(b"dn");
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }
    impl AsyncWrite for Stream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(self.error(Operation::Write).map_or(Ok(bytes.len()), Err))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(self.error(Operation::Flush).map_or(Ok(()), Err))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(self.error(Operation::Shutdown).map_or(Ok(()), Err))
        }
    }
    impl Outbound for Backend {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: false,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<OpenedTcp>> {
            Box::pin(async move {
                Ok(OpenedTcp {
                    stream: Box::new(Stream {
                        fault: self.0.clone(),
                        cancel: context.cancel.clone(),
                        read: false,
                    }),
                    info: TcpConnectInfo::unknown(),
                })
            })
        }
        fn connect_udp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async { Err(Error::Unsupported("错误分类回归只使用TCP")) })
        }
    }
    async fn fixture(
        operation: Operation,
        failure: Failure,
    ) -> (
        TcpFlow,
        ConnectContext,
        kerlico_egress::Telemetry,
        Arc<Fault>,
        kerlico_core::IngressBinding,
    ) {
        let fault = Arc::new(Fault {
            armed: AtomicBool::new(false),
            hits: AtomicUsize::new(0),
            operation,
            failure,
        });
        let input = NodeBuildContext::local_for_test(json!({}));
        let (binding, telemetry) = testing::ingress_with_resolver(
            &input,
            Arc::new(Backend(fault.clone())),
            TargetPolicy::Remote,
            FamilyMode::V4Only,
            Arc::new(ResolverProbe::default()),
        )
        .unwrap();
        let peer = binding.local(&context()).unwrap();
        let request = ConnectContext::new(Duration::from_secs(1));
        let mut flow = peer
            .connect_tcp(
                &Destination::new("poll-error.invalid", 80).unwrap(),
                &request,
            )
            .await
            .unwrap();
        flow.write_all(b"up").await.unwrap();
        let mut bytes = [0; 2];
        flow.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"dn");
        assert!(!request.cancel.is_cancelled());
        fault.armed.store(true, Ordering::Release);
        (flow, request, telemetry, fault, binding)
    }
    fn expected(failure: Failure) -> (FlowFailure, kerlico_egress::FlowEnd) {
        match failure {
            Failure::Cancelled => (FlowFailure::Cancelled, kerlico_egress::FlowEnd::Cancelled),
            Failure::Aborted => (FlowFailure::Failed, kerlico_egress::FlowEnd::Failed),
            Failure::Timeout => (FlowFailure::Timeout, kerlico_egress::FlowEnd::Timeout),
        }
    }
    fn assert_record(telemetry: &kerlico_egress::Telemetry, failure: Failure) {
        let records = telemetry.records(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].end, Some(expected(failure).1));
        assert_eq!(records[0].usage.upload_bytes, 2);
        assert_eq!(records[0].usage.download_bytes, 2);
        let usage = telemetry.usage().unwrap();
        assert_eq!(usage.active_flows, 0);
        assert_eq!(usage.engine, records[0].usage);
    }
    #[tokio::test]
    async fn metered_errors_observed_inside_each_poll_keep_typed_cause_and_first_failure() {
        for operation in [
            Operation::Read,
            Operation::Write,
            Operation::Flush,
            Operation::Shutdown,
        ] {
            for failure in [Failure::Cancelled, Failure::Aborted, Failure::Timeout] {
                let (mut flow, request, telemetry, fault, _binding) =
                    fixture(operation, failure).await;
                let error = tokio::time::timeout(Duration::from_secs(1), async {
                    match operation {
                        Operation::Read => flow.read_exact(&mut [0; 1]).await.map(|_| ()),
                        Operation::Write => flow.write_all(b"not-written").await,
                        Operation::Flush => flow.flush().await,
                        Operation::Shutdown => flow.shutdown().await,
                    }
                })
                .await
                .unwrap()
                .unwrap_err();
                assert_eq!(FlowFailure::from_io_error(&error), expected(failure).0);
                assert_eq!(fault.hits.load(Ordering::Acquire), 1);
                request.cancel.cancel();
                let cleanup = flow.write_all(b"cleanup").await.unwrap_err();
                assert_eq!(FlowFailure::from_io_error(&cleanup), FlowFailure::Cancelled);
                flow.finish(FlowOutcome::ProtocolEnd);
                assert_record(&telemetry, failure);
            }
        }
    }
    #[tokio::test]
    async fn relay_and_real_record_agree_when_backend_cancels_inside_poll() {
        for failure in [Failure::Cancelled, Failure::Aborted, Failure::Timeout] {
            let (flow, _request, telemetry, fault, _binding) =
                fixture(Operation::Write, failure).await;
            let (front, mut peer) = tokio::io::duplex(32);
            peer.write_all(b"failed-write").await.unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                relay_tcp(
                    Box::new(front),
                    flow,
                    Duration::from_secs(1),
                    CancellationToken::new(),
                ),
            )
            .await
            .unwrap();
            let error = result.unwrap_err();
            assert_eq!(FlowFailure::from_error(&error), expected(failure).0);
            if matches!(failure, Failure::Cancelled) {
                assert!(matches!(error, Error::Cancelled));
            }
            assert_eq!(fault.hits.load(Ordering::Acquire), 1);
            assert_record(&telemetry, failure);
        }
    }
}

struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
fn context() -> InboundContext {
    InboundContext {
        peer_lease: None,
        tasks: kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("test-node").unwrap(),
            kerlico_core::CancellationToken::new(),
        ),
        peer_addr: Some("127.0.0.1:12345".parse().unwrap()),
        local_addr: None,
        cancel: CancellationToken::new(),
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_millis(50),
        max_datagram_size: 65535,
        max_streams: 8,
        stream_budget: StreamBudget::new(
            Arc::new(tokio::sync::Semaphore::new(8)),
            Arc::new(tokio::sync::Semaphore::new(8)),
        ),
        events: Arc::new(Observer),
    }
}
#[derive(Default)]
struct ResolverProbe {
    calls: AtomicUsize,
}
impl Resolver for ResolverProbe {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()]) })
    }
}
struct Backend {
    targets: Mutex<Vec<Destination>>,
    fail: bool,
}
impl Outbound for Backend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        self.targets.lock().unwrap().push(target.clone());
        Box::pin(async move {
            if self.fail {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "测试失败",
                )));
            }
            let (client, mut server) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let mut payload = Vec::new();
                server.read_to_end(&mut payload).await.unwrap();
                server.write_all(&payload).await.unwrap();
            });
            Ok(kerlico_core::OpenedTcp {
                stream: Box::new(client),
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("测试后端没有UDP")) })
    }
}

#[tokio::test]
async fn remote_keeps_domain_and_failure_never_uses_local_dns_or_retries() {
    for fail in [false, true] {
        let backend = Arc::new(Backend {
            targets: Mutex::new(Vec::new()),
            fail,
        });
        let resolver = Arc::new(ResolverProbe::default());
        let input = NodeBuildContext::local_for_test(json!({}));
        let (binding, telemetry) = testing::ingress_with_resolver(
            &input,
            backend.clone(),
            TargetPolicy::Remote,
            FamilyMode::V6Only,
            resolver.clone(),
        )
        .unwrap();
        let peer = binding.local(&context()).unwrap();
        let target = Destination::new("website.invalid", 443).unwrap();
        let result = peer
            .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
            .await;
        assert_eq!(result.is_err(), fail);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(*backend.targets.lock().unwrap(), vec![target.clone()]);
        drop(result);
        let records = telemetry.records(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].original.as_ref().unwrap().target(), &target);
        assert!(records[0].observed_target.is_none());
    }
}

#[tokio::test]
async fn local_modes_filter_families_and_dual_prefers_ipv4() {
    for (mode, expected) in [
        (FamilyMode::V4Only, "127.0.0.1"),
        (FamilyMode::V6Only, "::1"),
        (FamilyMode::DualV4Preferred, "127.0.0.1"),
    ] {
        let backend = Arc::new(Backend {
            targets: Mutex::new(Vec::new()),
            fail: false,
        });
        let input = NodeBuildContext::local_for_test(json!({}));
        let (binding, _) = testing::ingress_with_resolver(
            &input,
            backend.clone(),
            TargetPolicy::Local,
            mode,
            Arc::new(ResolverProbe::default()),
        )
        .unwrap();
        let peer = binding.local(&context()).unwrap();
        let stream = peer
            .connect_tcp(
                &Destination::new("website.invalid", 80).unwrap(),
                &ConnectContext::new(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        drop(stream);
        assert_eq!(
            backend.targets.lock().unwrap()[0],
            Destination::new(expected, 80).unwrap()
        );
        if mode != FamilyMode::DualV4Preferred {
            let forbidden = if mode == FamilyMode::V4Only {
                "::1"
            } else {
                "127.0.0.1"
            };
            assert!(matches!(
                peer.connect_tcp(
                    &Destination::new(forbidden, 80).unwrap(),
                    &ConnectContext::new(Duration::from_secs(1))
                )
                .await,
                Err(Error::Rejected)
            ));
            assert_eq!(backend.targets.lock().unwrap().len(), 1);
        }
        assert!(matches!(
            peer.connect_tcp(
                &Destination::new("::ffff:127.0.0.1", 80).unwrap(),
                &ConnectContext::new(Duration::from_secs(1))
            )
            .await,
            Err(Error::InvalidAddress)
        ));
        assert_eq!(backend.targets.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn verified_identity_cannot_cross_issuers_and_one_flow_has_one_usage() {
    let input = NodeBuildContext::for_test(
        json!({}),
        vec![json!({"key":"first"}), json!({"key":"second"})],
    );
    let credentials = input
        .credentials(vec![b"first".to_vec(), b"second".to_vec()])
        .unwrap();
    let backend = Arc::new(Backend {
        targets: Mutex::new(Vec::new()),
        fail: false,
    });
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        backend,
        TargetPolicy::Remote,
        FamilyMode::DualV4Preferred,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let other = NodeBuildContext::for_test(json!({}), vec![json!({"key":"first"})]);
    let other_binding = testing::ingress(
        &other,
        Arc::new(Backend {
            targets: Mutex::new(Vec::new()),
            fail: false,
        }),
        TargetPolicy::Remote,
    )
    .unwrap();
    let foreign = credentials
        .verify(&b"first".to_vec(), |key, evidence| {
            Ok((key == evidence).then_some(()))
        })
        .unwrap();
    assert!(matches!(
        other_binding.authenticated(foreign, &context()),
        Err(Error::Rejected)
    ));
    assert!(binding.local(&context()).is_err());
    assert!(
        credentials
            .verify(&b"wrong".to_vec(), |key, evidence| Ok(
                (key == evidence).then_some(())
            ))
            .is_err()
    );
    let verified = credentials
        .verify(&b"second".to_vec(), |key, evidence| {
            Ok((key == evidence).then_some("decoded"))
        })
        .unwrap();
    let (peer, decoded) = binding.authenticated(verified, &context()).unwrap();
    assert_eq!(decoded, "decoded");
    let mut stream = peer
        .connect_tcp(
            &Destination::new("website.invalid", 80).unwrap(),
            &ConnectContext::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    stream.write_all(b"payload").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"payload");
    stream.finish(FlowOutcome::DuplexEof);
    let usage = telemetry.usage().unwrap();
    assert_eq!(usage.engine.upload_bytes, 7);
    assert_eq!(usage.engine.download_bytes, 7);
    assert_eq!(usage.users.len(), 1);
    assert_eq!(usage.nodes.values().next().unwrap(), &usage.engine);
    assert_eq!(usage.outbounds.values().next().unwrap(), &usage.engine);
    assert_eq!(usage.active_flows, 0);
    assert_eq!(
        telemetry.records(0, 10).unwrap()[0].end,
        Some(kerlico_egress::FlowEnd::Completed)
    );
}

struct ScriptedStream {
    write_pending: bool,
    read_pending: bool,
    read: usize,
}
impl tokio::io::AsyncRead for ScriptedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.read_pending {
            this.read_pending = false;
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        let bytes = b"reply";
        let count = (bytes.len() - this.read).min(buffer.remaining());
        buffer.put_slice(&bytes[this.read..this.read + count]);
        this.read += count;
        std::task::Poll::Ready(Ok(()))
    }
}
impl tokio::io::AsyncWrite for ScriptedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.write_pending {
            this.write_pending = false;
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        this.write_pending = true;
        std::task::Poll::Ready(Ok(bytes.len().min(2)))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
struct ScriptedBackend;
impl Outbound for ScriptedBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async {
            Ok(OpenedTcp {
                stream: Box::new(ScriptedStream {
                    write_pending: true,
                    read_pending: true,
                    read: 0,
                }),
                info: TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("测试")) })
    }
}
#[tokio::test]
async fn short_writes_pending_and_eof_do_not_duplicate_payload() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(ScriptedBackend),
        TargetPolicy::Remote,
        FamilyMode::DualV4Preferred,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let mut stream = peer
        .connect_tcp(
            &Destination::new("payload.invalid", 80).unwrap(),
            &ConnectContext::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    stream.write_all(b"abcdef").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"reply");
    stream.read_to_end(&mut bytes).await.unwrap();
    stream.finish(FlowOutcome::DuplexEof);
    let usage = telemetry.usage().unwrap().engine;
    assert_eq!(usage.upload_bytes, 6);
    assert_eq!(usage.download_bytes, 5);
    assert_eq!(usage.upload_packets, 0);
    assert_eq!(
        telemetry.records(0, 1).unwrap()[0].end,
        Some(kerlico_egress::FlowEnd::Completed)
    );
}

struct PacketSender(tokio::sync::mpsc::Sender<Vec<u8>>);
struct PacketReceiver(tokio::sync::mpsc::Receiver<Vec<u8>>);
impl DatagramSender for PacketSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .send(packet.to_vec())
                .await
                .map_err(|_| Error::Cancelled)
        })
    }
}
impl DatagramReceiver for PacketReceiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
struct AssociationTx {
    send: tokio::sync::mpsc::Sender<AddressedDatagram>,
    targets: Arc<Mutex<Vec<Destination>>>,
}
struct AssociationRx(tokio::sync::mpsc::Receiver<AddressedDatagram>);
impl DatagramAssociationSender for AssociationTx {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.targets.lock().unwrap().push(target.clone());
            self.send
                .send((target.clone(), packet.to_vec()))
                .await
                .map_err(|_| Error::Cancelled)
        })
    }
}
impl DatagramAssociationReceiver for AssociationRx {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
struct DatagramBackend {
    targets: Arc<Mutex<Vec<Destination>>>,
}
impl Outbound for DatagramBackend {
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
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async { Err(Error::Unsupported("测试")) })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.targets.lock().unwrap().push(target.clone());
        Box::pin(async {
            let (send, recv) = tokio::sync::mpsc::channel(8);
            Ok(DatagramChannel {
                sender: Box::new(PacketSender(send)),
                receiver: Box::new(PacketReceiver(recv)),
            })
        })
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            let (send, recv) = tokio::sync::mpsc::channel(8);
            Ok(DatagramAssociation {
                sender: Box::new(AssociationTx {
                    send,
                    targets: self.targets.clone(),
                }),
                receiver: Box::new(AssociationRx(recv)),
            })
        })
    }
}
#[tokio::test]
async fn udp_zero_packets_and_bidirectional_association_share_one_lease() {
    let targets = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(ResolverProbe::default());
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(DatagramBackend {
            targets: targets.clone(),
        }),
        TargetPolicy::Local,
        FamilyMode::DualV4Preferred,
        resolver.clone(),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let target = Destination::new("target.invalid", 53).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(1));
    let (mut fixed_sender, mut fixed_receiver, fixed_completion) = peer
        .connect_udp(&target, &budget)
        .await
        .unwrap()
        .into_parts();
    let (sent, received) = tokio::join!(fixed_sender.send(b""), fixed_receiver.recv());
    sent.unwrap();
    assert_eq!(received.unwrap(), Some(Vec::new()));
    fixed_completion.finish(FlowOutcome::ProtocolEnd);
    drop((fixed_sender, fixed_receiver));
    let (mut sender, mut receiver, completion) =
        peer.associate_udp(&budget).await.unwrap().into_parts();
    for payload in [b"".as_slice(), b"abc".as_slice()] {
        let (sent, received) = tokio::join!(sender.send_to(payload, &target), receiver.recv_from());
        sent.unwrap();
        let (source, bytes) = received.unwrap().unwrap();
        assert_eq!(source, Destination::new("127.0.0.1", 53).unwrap());
        assert_eq!(bytes, payload);
    }
    completion.finish(FlowOutcome::ProtocolEnd);
    drop(sender);
    assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    drop(receiver);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(targets.lock().unwrap().len(), 3);
    let usage = telemetry.usage().unwrap();
    assert_eq!(usage.active_flows, 0);
    assert_eq!(usage.engine.upload_bytes, 3);
    assert_eq!(usage.engine.download_bytes, 3);
    assert_eq!(usage.engine.upload_packets, 3);
    assert_eq!(usage.engine.download_packets, 3);
    assert_eq!(telemetry.records(0, 10).unwrap().len(), 2);
}

#[tokio::test]
async fn remote_datagrams_keep_every_original_target_without_dns() {
    let targets = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(ResolverProbe::default());
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(DatagramBackend {
            targets: targets.clone(),
        }),
        TargetPolicy::Remote,
        FamilyMode::V6Only,
        resolver.clone(),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let first = Destination::new("first.invalid", 53).unwrap();
    let second = Destination::new("second.invalid", 443).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(1));
    let (mut fixed_sender, mut fixed_receiver, fixed_completion) = peer
        .connect_udp(&first, &budget)
        .await
        .unwrap()
        .into_parts();
    fixed_sender.send(b"").await.unwrap();
    assert_eq!(fixed_receiver.recv().await.unwrap(), Some(Vec::new()));
    fixed_completion.finish(FlowOutcome::ProtocolEnd);
    drop((fixed_sender, fixed_receiver));
    let (mut sender, mut receiver, completion) =
        peer.associate_udp(&budget).await.unwrap().into_parts();
    for target in [&first, &second] {
        sender.send_to(b"packet", target).await.unwrap();
        assert_eq!(receiver.recv_from().await.unwrap().unwrap().0, *target);
    }
    completion.finish(FlowOutcome::ProtocolEnd);
    drop((sender, receiver));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(*targets.lock().unwrap(), vec![first.clone(), first, second]);
    let records = telemetry.records(0, 10).unwrap();
    assert_eq!(records[1].datagram_targets.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.observed_target.is_none())
    );
}

#[tokio::test]
async fn peer_and_node_cancellation_do_not_cancel_the_named_service() {
    struct ScopeProbe(Mutex<Vec<CancellationToken>>);
    impl Outbound for ScopeProbe {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: false,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
            self.0.lock().unwrap().push(context.service_cancel());
            Box::pin(async {
                Ok(OpenedTcp {
                    stream: Box::new(ScriptedStream {
                        write_pending: false,
                        read_pending: false,
                        read: 0,
                    }),
                    info: TcpConnectInfo::unknown(),
                })
            })
        }
        fn connect_udp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async { Err(Error::Unsupported("测试")) })
        }
    }
    let backend = Arc::new(ScopeProbe(Mutex::new(Vec::new())));
    let input = NodeBuildContext::local_for_test(json!({}));
    let binding = testing::ingress(&input, backend.clone(), TargetPolicy::Remote).unwrap();
    let first = context();
    let second = context();
    let peer1 = binding.local(&first).unwrap();
    let peer2 = binding.local(&second).unwrap();
    let target = Destination::new("unresolved.invalid", 80).unwrap();
    let mut stream1 = peer1
        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(1)))
        .await
        .unwrap();
    let mut stream2 = peer2
        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(1)))
        .await
        .unwrap();
    first.cancel.cancel();
    assert!(stream1.write_all(b"first").await.is_err());
    assert!(stream1.write_all(b"again").await.is_err());
    assert!(stream1.flush().await.is_err());
    assert!(stream1.shutdown().await.is_err());
    assert!(stream1.read_u8().await.is_err());
    stream2.write_all(b"second").await.unwrap();
    assert!(!binding.node_cancel().is_cancelled());
    binding.node_cancel().cancel();
    assert!(stream2.write_all(b"stopped").await.is_err());
    assert!(matches!(
        peer2
            .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(1)))
            .await,
        Err(Error::Cancelled)
    ));
    assert!(
        backend
            .0
            .lock()
            .unwrap()
            .iter()
            .all(|cancel| !cancel.is_cancelled())
    );
}

#[tokio::test]
async fn completion_waits_for_last_tcp_half_and_timeout_survives_cleanup() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(ScriptedBackend),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let inbound = context();
    let peer = binding.local(&inbound).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(1));
    let flow = peer
        .connect_tcp(
            &Destination::new("completion.invalid", 80).unwrap(),
            &budget,
        )
        .await
        .unwrap();
    let (io, completion) = flow.into_parts();
    let (mut read, mut write) = tokio::io::split(io);
    write.write_all(b"once").await.unwrap();
    completion.finish(FlowOutcome::Failed(FlowFailure::Timeout));
    assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    assert!(telemetry.records(0, 1).unwrap()[0].end.is_none());
    budget.cancel.cancel();
    assert!(read.read_u8().await.is_err());
    assert!(write.shutdown().await.is_err());
    drop(write);
    assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    drop(read);
    for _ in 0..3 {
        let record = telemetry.records(0, 1).unwrap().remove(0);
        assert_eq!(record.end, Some(kerlico_egress::FlowEnd::Timeout));
        assert_eq!(record.usage.upload_bytes, 4);
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    }
}

#[tokio::test]
async fn three_flows_with_one_context_keep_independent_termination_and_totals() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(ScriptedBackend),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(1));
    let target = Destination::new("parallel.invalid", 80).unwrap();
    let second = budget.clone();
    let third = budget.clone();
    let (timed, clean, released) = tokio::join!(
        peer.connect_tcp(&target, &budget),
        peer.connect_tcp(&target, &second),
        peer.connect_tcp(&target, &third)
    );
    let (mut timed, mut clean, mut released) = (timed.unwrap(), clean.unwrap(), released.unwrap());
    let (first_write, second_write, third_write) = tokio::join!(
        timed.write_all(b"a"),
        clean.write_all(b"bb"),
        released.write_all(b"ccc")
    );
    first_write.unwrap();
    second_write.unwrap();
    third_write.unwrap();
    timed.finish(FlowOutcome::Failed(FlowFailure::Timeout));
    clean.shutdown().await.unwrap();
    let mut reply = Vec::new();
    clean.read_to_end(&mut reply).await.unwrap();
    clean.finish(FlowOutcome::DuplexEof);
    drop(released);
    let records = telemetry.records(0, 10).unwrap();
    assert_eq!(
        records.iter().map(|r| r.end).collect::<Vec<_>>(),
        vec![
            Some(kerlico_egress::FlowEnd::Timeout),
            Some(kerlico_egress::FlowEnd::Completed),
            Some(kerlico_egress::FlowEnd::ClosedByCaller)
        ]
    );
    let usage = telemetry.usage().unwrap();
    assert_eq!(usage.active_flows, 0);
    assert_eq!(usage.engine.upload_bytes, 6);
    assert_eq!(usage.engine.download_bytes, 5);
    assert_eq!(usage.nodes.values().next().unwrap(), &usage.engine);
    assert_eq!(usage.outbounds.values().next().unwrap(), &usage.engine);
    assert_eq!(records[0].id.run, records[1].id.run);
    assert_ne!(records[0].id, records[1].id);
}

#[tokio::test]
async fn udp_completion_keeps_both_halves_and_zero_packet_semantics() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(DatagramBackend {
            targets: Arc::new(Mutex::new(Vec::new())),
        }),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let flow = peer
        .connect_udp(
            &Destination::new("udp.invalid", 53).unwrap(),
            &ConnectContext::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    let (mut send, mut recv, completion) = flow.into_parts();
    let (packet, sent) = tokio::join!(recv.recv(), send.send(b""));
    assert_eq!(packet.unwrap(), Some(Vec::new()));
    sent.unwrap();
    drop(send);
    assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    assert_eq!(recv.recv().await.unwrap(), None);
    completion.finish(FlowOutcome::ProtocolEnd);
    assert!(telemetry.records(0, 1).unwrap()[0].end.is_none());
    drop(recv);
    let record = telemetry.records(0, 1).unwrap().remove(0);
    assert_eq!(record.end, Some(kerlico_egress::FlowEnd::Completed));
    assert_eq!(record.usage.upload_packets, 1);
    assert_eq!(record.usage.download_packets, 1);
    assert_eq!(record.usage.upload_bytes + record.usage.download_bytes, 0);
}

#[tokio::test]
async fn cancellation_observed_before_protocol_end_is_stable() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(ScriptedBackend),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(1));
    let mut flow = peer
        .connect_tcp(&Destination::new("cancel.invalid", 80).unwrap(), &budget)
        .await
        .unwrap();
    budget.cancel.cancel();
    let error = flow.write_all(b"not-written").await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    assert_eq!(
        FlowFailure::from_error(&Error::Io(error)),
        FlowFailure::Cancelled
    );
    let error = flow.read_exact(&mut [0; 1]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    assert_eq!(
        FlowFailure::from_error(&Error::Io(error)),
        FlowFailure::Cancelled
    );
    flow.finish(FlowOutcome::ProtocolEnd);
    let record = telemetry.records(0, 1).unwrap().remove(0);
    assert_eq!(record.end, Some(kerlico_egress::FlowEnd::Cancelled));
    assert_eq!(record.usage.upload_bytes, 0);
}

#[tokio::test]
async fn relay_distinguishes_typed_cancellation_from_connection_aborted() {
    struct AbortedFront;
    impl tokio::io::AsyncRead for AbortedFront {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionAborted.into()))
        }
    }
    impl tokio::io::AsyncWrite for AbortedFront {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionAborted.into()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    for cancelled in [true, false] {
        let input = NodeBuildContext::local_for_test(json!({}));
        let (binding, telemetry) = testing::ingress_with_resolver(
            &input,
            Arc::new(ScriptedBackend),
            TargetPolicy::Remote,
            FamilyMode::V4Only,
            Arc::new(ResolverProbe::default()),
        )
        .unwrap();
        let peer = binding.local(&context()).unwrap();
        let request = ConnectContext::new(Duration::from_secs(1));
        let flow = peer
            .connect_tcp(
                &Destination::new("relay-cancel.invalid", 80).unwrap(),
                &request,
            )
            .await
            .unwrap();
        let (front, _other) = tokio::io::duplex(1);
        let front: BoxStream = if cancelled {
            request.cancel.cancel();
            Box::new(front)
        } else {
            Box::new(AbortedFront)
        };
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            relay_tcp(
                front,
                flow,
                Duration::from_secs(1),
                CancellationToken::new(),
            ),
        )
        .await
        .unwrap();
        let expected = if cancelled {
            assert!(matches!(result, Err(Error::Cancelled)));
            kerlico_egress::FlowEnd::Cancelled
        } else {
            let Err(Error::Io(error)) = result else {
                panic!("普通连接中止必须保留I/O失败");
            };
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
            assert_eq!(
                FlowFailure::from_error(&Error::Io(error)),
                FlowFailure::Failed
            );
            kerlico_egress::FlowEnd::Failed
        };
        let records = telemetry.records(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].end, Some(expected));
        assert_eq!(records[0].usage.upload_bytes, 0);
        assert_eq!(records[0].usage.download_bytes, 0);
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    }
}

struct RefusingFront;
impl tokio::io::AsyncRead for RefusingFront {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

struct RefusingBackend;
impl Outbound for RefusingBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async {
            Ok(OpenedTcp {
                stream: Box::new(RefusingFront),
                info: TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("测试后端只有TCP")) })
    }
}

#[tokio::test]
async fn observed_io_failure_wins_over_later_protocol_end() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(RefusingBackend),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let mut flow = peer
        .connect_tcp(
            &Destination::new("failure.invalid", 80).unwrap(),
            &ConnectContext::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    assert!(flow.write_all(b"never-written").await.is_err());
    flow.shutdown().await.unwrap();
    flow.finish(FlowOutcome::ProtocolEnd);
    let record = telemetry.records(0, 1).unwrap().remove(0);
    assert_eq!(record.end, Some(kerlico_egress::FlowEnd::Failed));
    assert_eq!(record.usage.upload_bytes, 0);
}
impl tokio::io::AsyncWrite for RefusingFront {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn inbound_write_failure_reaches_the_real_flow_record() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(ScriptedBackend),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let flow = peer
        .connect_tcp(
            &Destination::new("front.invalid", 80).unwrap(),
            &ConnectContext::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    assert!(matches!(
        relay_tcp(
            Box::new(RefusingFront),
            flow,
            Duration::from_secs(1),
            CancellationToken::new()
        )
        .await,
        Err(Error::Io(_))
    ));
    let record = telemetry.records(0, 1).unwrap().remove(0);
    assert_eq!(record.end, Some(kerlico_egress::FlowEnd::Failed));
    assert_eq!(record.usage.download_bytes, 5);
    assert_eq!(record.usage.upload_bytes, 0);
}

#[tokio::test]
async fn archived_completed_usage_is_never_counted_twice() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(ScriptedBackend),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let peer = binding.local(&context()).unwrap();
    let target = Destination::new("archive.invalid", 80).unwrap();
    for _ in 0..4097 {
        let mut flow = peer
            .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(1)))
            .await
            .unwrap();
        flow.write_all(b"x").await.unwrap();
        flow.finish(FlowOutcome::ProtocolEnd);
    }
    for _ in 0..3 {
        let usage = telemetry.usage().unwrap();
        assert_eq!(usage.engine.upload_bytes, 4097);
        assert_eq!(usage.active_flows, 0);
        assert_eq!(usage.evicted_records, 1);
        let records = telemetry.records(0, 4096).unwrap();
        assert_eq!(records[0].id.sequence, 2);
        assert!(
            records
                .iter()
                .all(|record| record.end == Some(kerlico_egress::FlowEnd::Completed))
        );
    }
}

#[tokio::test]
async fn parent_owned_tcp_completion_records_timeout_failure_and_duplex_eof() {
    for mode in 0..3 {
        let input = NodeBuildContext::local_for_test(json!({}));
        let (binding, telemetry) = testing::ingress_with_resolver(
            &input,
            Arc::new(ScriptedBackend),
            TargetPolicy::Remote,
            FamilyMode::V4Only,
            Arc::new(ResolverProbe::default()),
        )
        .unwrap();
        let peer = binding.local(&context()).unwrap();
        let flow = peer
            .connect_tcp(
                &Destination::new("owned.invalid", 80).unwrap(),
                &ConnectContext::new(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        let (mut io, completion) = flow.into_parts();
        let (mut client, front) = tokio::io::duplex(64);
        if mode == 2 {
            client.write_all(b"front").await.unwrap();
            client.shutdown().await.unwrap();
        }
        let front: BoxStream = if mode == 1 {
            Box::new(RefusingFront)
        } else {
            Box::new(front)
        };
        let result = relay_tcp_io(
            front,
            &mut io,
            Duration::from_millis(10),
            CancellationToken::new(),
        )
        .await;
        let expected = match mode {
            0 => {
                assert!(matches!(result, Err(Error::Timeout)));
                kerlico_egress::FlowEnd::Timeout
            }
            1 => {
                assert!(matches!(result, Err(Error::Io(_))));
                kerlico_egress::FlowEnd::Failed
            }
            _ => {
                assert!(result.is_ok());
                kerlico_egress::FlowEnd::Completed
            }
        };
        completion.finish(match &result {
            Ok(()) => FlowOutcome::DuplexEof,
            Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
        });
        assert!(telemetry.records(0, 1).unwrap()[0].end.is_none());
        drop(io);
        let record = telemetry.records(0, 1).unwrap().remove(0);
        assert_eq!(record.end, Some(expected));
        assert_eq!(record.usage.download_bytes, 5);
        assert_eq!(record.usage.upload_bytes, if mode == 2 { 5 } else { 0 });
    }
}

#[tokio::test]
async fn trusted_peer_and_flow_keep_the_original_physical_permit() {
    let global = Arc::new(tokio::sync::Semaphore::new(1));
    let node = Arc::new(tokio::sync::Semaphore::new(1));
    let mut inbound = context();
    let cancel = inbound.cancel.clone();
    inbound.peer_lease = Some(PeerLease::new(
        cancel.clone(),
        StreamBudget::new(global.clone(), node.clone())
            .try_acquire()
            .unwrap(),
    ));
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(ScriptedBackend),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let peer = binding.local(&inbound).unwrap();
    drop(inbound);
    assert_eq!(global.available_permits(), 0);
    assert!(!cancel.is_cancelled());
    let flow = peer
        .connect_tcp(
            &Destination::new("lease.invalid", 80).unwrap(),
            &ConnectContext::new(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    drop(peer);
    assert_eq!(node.available_permits(), 0);
    assert!(!cancel.is_cancelled());
    drop(flow);
    assert!(cancel.is_cancelled());
    assert_eq!(global.available_permits(), 1);
    assert_eq!(node.available_permits(), 1);
    assert_eq!(
        telemetry.records(0, 1).unwrap()[0].end,
        Some(kerlico_egress::FlowEnd::ClosedByCaller)
    );
}

#[tokio::test]
async fn split_tcp_pending_halves_cancel_and_release_flow_and_peer_permits() {
    use std::{future::poll_fn, io, pin::Pin};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct HeldDuplex(Mutex<Option<tokio::io::DuplexStream>>);
    impl Outbound for HeldDuplex {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: false,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<OpenedTcp>> {
            Box::pin(async move {
                Ok(OpenedTcp {
                    stream: Box::new(self.0.lock().unwrap().take().unwrap()),
                    info: TcpConnectInfo::unknown(),
                })
            })
        }
        fn connect_udp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async { Err(Error::Unsupported("测试后端没有UDP")) })
        }
    }

    for read_first in [true, false] {
        let (client, _server) = tokio::io::duplex(1);
        let global = Arc::new(tokio::sync::Semaphore::new(1));
        let node = Arc::new(tokio::sync::Semaphore::new(1));
        let mut inbound = context();
        let peer_cancel = inbound.cancel.clone();
        inbound.peer_lease = Some(PeerLease::new(
            peer_cancel.clone(),
            StreamBudget::new(global.clone(), node.clone())
                .try_acquire()
                .unwrap(),
        ));
        let input = NodeBuildContext::local_for_test(json!({}));
        let (binding, telemetry) = testing::ingress_with_resolver(
            &input,
            Arc::new(HeldDuplex(Mutex::new(Some(client)))),
            TargetPolicy::Remote,
            FamilyMode::V4Only,
            Arc::new(ResolverProbe::default()),
        )
        .unwrap();
        let peer = binding.local(&inbound).unwrap();
        let request = ConnectContext::new(Duration::from_secs(1));
        let flow = peer
            .connect_tcp(&Destination::new("cancel.invalid", 80).unwrap(), &request)
            .await
            .unwrap();
        drop(peer);
        drop(inbound);
        let (io, completion) = flow.into_parts();
        let (mut read, mut write) = tokio::io::split(io);
        let (start_read, reading) = tokio::sync::oneshot::channel();
        let (read_pending, read_ready) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(async move {
            reading.await.unwrap();
            let mut pending = Some(read_pending);
            let mut bytes = [0; 1];
            let result = poll_fn(|cx| {
                let result = Pin::new(&mut read).poll_read(cx, &mut ReadBuf::new(&mut bytes));
                if result.is_pending()
                    && let Some(pending) = pending.take()
                {
                    let _ = pending.send(());
                }
                result
            })
            .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
            let error = read.read_exact(&mut bytes).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert_eq!(
                FlowFailure::from_error(&Error::Io(error)),
                FlowFailure::Cancelled
            );
        });
        let (start_write, writing) = tokio::sync::oneshot::channel();
        let (write_pending, write_ready) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            writing.await.unwrap();
            let mut pending = Some(write_pending);
            let mut written = 0;
            let error = poll_fn(|cx| {
                loop {
                    match Pin::new(&mut write).poll_write(cx, b"x") {
                        std::task::Poll::Ready(Ok(count)) => {
                            assert!(count > 0);
                            written += count;
                        }
                        std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(error),
                        std::task::Poll::Pending => {
                            if let Some(pending) = pending.take() {
                                let _ = pending.send(());
                            }
                            return std::task::Poll::Pending;
                        }
                    }
                }
            })
            .await;
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            let error = write.write_all(b"y").await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert_eq!(
                FlowFailure::from_error(&Error::Io(error)),
                FlowFailure::Cancelled
            );
            assert_eq!(
                write.flush().await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
            assert_eq!(
                write.shutdown().await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
            written
        });
        if read_first {
            start_read.send(()).unwrap();
            read_ready.await.unwrap();
            start_write.send(()).unwrap();
            write_ready.await.unwrap();
        } else {
            start_write.send(()).unwrap();
            write_ready.await.unwrap();
            start_read.send(()).unwrap();
            read_ready.await.unwrap();
        }
        assert!(!reader.is_finished());
        assert!(!writer.is_finished());
        assert_eq!(telemetry.usage().unwrap().active_flows, 1);
        assert_eq!(global.available_permits(), 0);
        assert_eq!(node.available_permits(), 0);
        request.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap();
        let written = tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(written, 1);
        assert!(telemetry.records(0, 1).unwrap()[0].end.is_none());
        assert_eq!(node.available_permits(), 0);
        assert!(!peer_cancel.is_cancelled());
        completion.finish(FlowOutcome::ProtocolEnd);
        let records = telemetry.records(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].end, Some(kerlico_egress::FlowEnd::Cancelled));
        assert_eq!(records[0].usage.upload_bytes, 1);
        assert_eq!(records[0].usage.download_bytes, 0);
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
        assert_eq!(global.available_permits(), 1);
        assert_eq!(node.available_permits(), 1);
        assert!(peer_cancel.is_cancelled());
    }
}

#[tokio::test]
async fn stopped_admission_rejects_existing_peer_new_targets_but_keeps_open_io() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        Arc::new(ScriptedBackend),
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let inbound = context();
    let peer = binding.local(&inbound).unwrap();
    let target = Destination::new("admission.invalid", 80).unwrap();
    let budget = ConnectContext::new(Duration::from_secs(1));
    let mut open = peer.connect_tcp(&target, &budget).await.unwrap();
    binding.stop_admission();
    binding.stop_admission();
    assert!(matches!(binding.local(&inbound), Err(Error::Cancelled)));
    assert!(matches!(
        peer.connect_tcp(&target, &budget).await,
        Err(Error::Cancelled)
    ));
    assert!(!binding.node_cancel().is_cancelled());
    assert!(!inbound.cancel.is_cancelled());
    open.write_all(b"existing").await.unwrap();
    open.shutdown().await.unwrap();
    let mut reply = Vec::new();
    open.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"reply");
    open.finish(FlowOutcome::DuplexEof);
    let records = telemetry.records(0, 10).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].end, Some(kerlico_egress::FlowEnd::Completed));
    assert_eq!(records[0].usage.upload_bytes, 8);
}

#[tokio::test]
async fn concurrent_admission_stop_keeps_every_accepted_operation_owned_and_recorded() {
    for _ in 0..32 {
        let input = NodeBuildContext::local_for_test(json!({}));
        let (binding, telemetry) = testing::ingress_with_resolver(
            &input,
            Arc::new(ScriptedBackend),
            TargetPolicy::Remote,
            FamilyMode::V4Only,
            Arc::new(ResolverProbe::default()),
        )
        .unwrap();
        let owner = NodeTasks::new(input.issuer().node().clone(), binding.node_cancel());
        let peer = binding.local(&context()).unwrap();
        let admitted_peer = peer.clone();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let close_barrier = barrier.clone();
        let closing = binding.clone();
        let close = std::thread::spawn(move || {
            close_barrier.wait();
            closing.stop_admission();
        });
        let operation = owner
            .spawn_tracked(async move {
                barrier.wait();
                admitted_peer
                    .connect_tcp(
                        &Destination::new("race.invalid", 80).unwrap(),
                        &ConnectContext::new(Duration::from_secs(2)),
                    )
                    .await
            })
            .unwrap();
        let result = operation.await.unwrap();
        close.join().unwrap();
        let accepted = match result {
            Ok(flow) => {
                flow.finish(FlowOutcome::ClosedByCaller);
                true
            }
            Err(Error::Cancelled) => false,
            Err(error) => panic!("并发准入返回非预期错误：{error}"),
        };
        assert!(matches!(
            peer.connect_tcp(
                &Destination::new("late.invalid", 80).unwrap(),
                &ConnectContext::new(Duration::from_secs(2))
            )
            .await,
            Err(Error::Cancelled)
        ));
        assert!(
            owner
                .shutdown_at(tokio::time::Instant::now() + Duration::from_millis(100))
                .await
                .is_clean()
        );
        let records = telemetry.records(0, 10).unwrap();
        assert_eq!(records.len(), usize::from(accepted));
        assert!(
            records
                .iter()
                .all(|record| record.end == Some(kerlico_egress::FlowEnd::ClosedByCaller))
        );
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    }
}

#[tokio::test]
async fn established_multi_target_association_drains_without_accepting_new_associations() {
    let input = NodeBuildContext::local_for_test(json!({}));
    let backend = Arc::new(DatagramBackend {
        targets: Arc::new(Mutex::new(Vec::new())),
    });
    let (binding, telemetry) = testing::ingress_with_resolver(
        &input,
        backend,
        TargetPolicy::Remote,
        FamilyMode::V4Only,
        Arc::new(ResolverProbe::default()),
    )
    .unwrap();
    let owner = NodeTasks::new(input.issuer().node().clone(), binding.node_cancel());
    let mut inbound = context();
    inbound.tasks = owner.clone();
    inbound.cancel = owner.cancel().child_token();
    let peer = binding.local(&inbound).unwrap();
    let association = peer
        .associate_udp(&ConnectContext::new(Duration::from_secs(1)))
        .await
        .unwrap();
    let (continue_send, send_allowed) = tokio::sync::oneshot::channel();
    let (delivered, observed) = tokio::sync::oneshot::channel();
    let cancel = owner.cancel();
    let task = owner
        .spawn_tracked(async move {
            let (mut sender, mut receiver, completion) = association.into_parts();
            send_allowed.await.unwrap();
            for (host, payload) in [
                ("192.0.2.1", b"first".as_slice()),
                ("2001:db8::1", b"second".as_slice()),
            ] {
                let target = Destination::new(host, 53).unwrap();
                let (send, receive) =
                    tokio::join!(sender.send_to(payload, &target), receiver.recv_from());
                send.unwrap();
                assert_eq!(receive.unwrap(), Some((target, payload.to_vec())));
            }
            delivered.send(()).unwrap();
            cancel.cancelled().await;
            assert!(matches!(receiver.recv_from().await, Err(Error::Cancelled)));
            completion.finish(FlowOutcome::Failed(FlowFailure::Cancelled));
        })
        .unwrap();
    binding.stop_admission();
    assert!(!binding.node_cancel().is_cancelled());
    assert!(matches!(
        peer.associate_udp(&ConnectContext::new(Duration::from_secs(1)))
            .await,
        Err(Error::Cancelled)
    ));
    continue_send.send(()).unwrap();
    observed.await.unwrap();
    assert_eq!(telemetry.usage().unwrap().active_flows, 1);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    assert!(
        tokio::time::timeout_at(
            deadline + Duration::from_millis(300),
            owner.shutdown_at(deadline)
        )
        .await
        .unwrap()
        .is_clean()
    );
    task.await.unwrap();
    let records = telemetry.records(0, 10).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].end, Some(kerlico_egress::FlowEnd::Cancelled));
    assert_eq!(records[0].usage.upload_packets, 2);
    assert_eq!(records[0].usage.download_packets, 2);
    assert_eq!(records[0].usage.upload_bytes, 11);
    assert_eq!(records[0].usage.download_bytes, 11);
    assert_eq!(telemetry.usage().unwrap().active_flows, 0);
}
