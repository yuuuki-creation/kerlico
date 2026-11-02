use super::*;
use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory};
use kerlico_core::{
    AddressedDatagram, BoxFuture, Capabilities, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, Destination,
    Error, FamilyMode, InboundContext, IngressBinding, NodeId, NodeObserver, NodeTasks,
    OpenedTcp, Outbound, Result, ServiceContext, Source, StreamBudget, TargetPolicy, TcpConnectInfo,
};
use std::{net::SocketAddr, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{Semaphore, mpsc}, time::{Instant, timeout}};

struct Observer;
impl NodeObserver for Observer { fn record(&self, _: kerlico_core::NodeEvent) {} }
struct NoDns;
impl kerlico_egress::Resolver for NoDns {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
        Box::pin(async { Err(Error::Unsupported("测试目标不得触发DNS")) })
    }
}
struct EchoOutbound { tasks: NodeTasks, associations: AtomicUsize }
struct EchoSender(mpsc::Sender<AddressedDatagram>);
struct EchoReceiver(mpsc::Receiver<AddressedDatagram>);
impl DatagramAssociationSender for EchoSender {
    fn send_to<'a>(&'a mut self, payload: &'a [u8], target: &'a Destination) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.0.send((target.clone(), payload.to_vec())).await.map_err(|_| Error::Cancelled) })
    }
}
impl DatagramAssociationReceiver for EchoReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
impl Outbound for EchoOutbound {
    fn capabilities(&self) -> Capabilities { Capabilities { tcp: true, tcp_eof: true, udp: true } }
    fn supports_udp_association(&self) -> bool { true }
    fn connect_tcp<'a>(&'a self, target: &'a Destination, _: &'a ConnectContext) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            if target.port() == 9 { return Err(Error::Rejected); }
            let (front, mut back) = tokio::io::duplex(65536);
            let port = target.port();
            self.tasks.spawn(async move {
                let mut data = Vec::new();
                if back.read_to_end(&mut data).await.is_ok() {
                    let _ = back.write_all(&port.to_be_bytes()).await;
                    let _ = back.write_all(&data).await;
                    let _ = back.shutdown().await;
                }
            })?;
            Ok(OpenedTcp { stream: Box::new(front), info: TcpConnectInfo::unknown() })
        })
    }
    fn connect_udp<'a>(&'a self, _: &'a Destination, _: &'a ConnectContext) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("入站必须使用真实多目标UDP关联")) })
    }
    fn associate_udp<'a>(&'a self, _: &'a ConnectContext) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.associations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            let (sender, receiver) = mpsc::channel(8);
            Ok(DatagramAssociation { sender: Box::new(EchoSender(sender)), receiver: Box::new(EchoReceiver(receiver)) })
        })
    }
}

struct Rig {
    outbound: Arc<dyn Outbound>,
    host: ServiceContext,
    context: InboundContext,
    ingress: IngressBinding,
    telemetry: kerlico_egress::Telemetry,
    echo: Arc<EchoOutbound>,
    endpoint: SocketAddr,
    serving: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Drop for Rig {
    fn drop(&mut self) { self.context.cancel.cancel(); self.host.cancel().cancel(); }
}
async fn client(endpoint: SocketAddr, number: u8, last: u8, psk: Option<u8>) -> (Arc<dyn Outbound>, ServiceContext) {
    let host = ServiceContext::for_test();
    let plan = crate::WireGuardFactory.compile(&json!({
        "tunnel": tunnel(number, last), "peer": peer(2, None, psk),
        "endpoint": {"host": endpoint.ip().to_string(), "port": endpoint.port()}
    })).unwrap();
    let outbound = plan.start(host.clone()).await.unwrap();
    (outbound, host)
}
impl Rig {
    async fn start(ipv6: bool, psk: Option<u8>, multi: bool) -> Self {
        let socket = Arc::new(tokio::net::UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }).await.unwrap());
        let endpoint = socket.local_addr().unwrap();
        let cancel = kerlico_core::CancellationToken::new();
        let context = InboundContext {
            peer_lease: None, peer_addr: None, local_addr: Some(endpoint),
            tasks: NodeTasks::new(NodeId::parse("test-node").unwrap(), cancel.clone()), cancel,
            connect_timeout: Duration::from_secs(4), idle_timeout: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(1), max_datagram_size: 65535, max_streams: 64,
            stream_budget: StreamBudget::new(Arc::new(Semaphore::new(64)), Arc::new(Semaphore::new(64))),
            events: Arc::new(Observer),
        };
        let mut members = vec![peer(1, Some(2), psk)];
        if multi { members.push(peer(3, Some(3), psk)); }
        let input = NodeBuildContext::for_test(json!({"tunnel": tunnel(2, 1)}), members);
        let node = crate::WireGuardNodeFactory.build(&input).unwrap();
        let echo = Arc::new(EchoOutbound { tasks: context.tasks.clone(), associations: AtomicUsize::new(0) });
        let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(&input, echo.clone(), TargetPolicy::Local,
            FamilyMode::DualV4Preferred, Arc::new(NoDns)).unwrap();
        let binding = ingress.clone();
        let node_context = context.clone();
        let serving = tokio::spawn(async move { node.handle_udp(socket, binding, node_context).await });
        let (outbound, host) = client(endpoint, 1, 2, psk).await;
        Self { outbound, host, context, ingress, telemetry, echo, endpoint, serving: Some(serving) }
    }
    async fn stop(&mut self) {
        self.outbound.shutdown().await.unwrap();
        assert!(self.host.shutdown(Instant::now() + Duration::from_secs(2)).await.is_clean());
        self.context.cancel.cancel();
        let result = timeout(Duration::from_secs(2), self.serving.take().unwrap()).await.unwrap().unwrap();
        assert!(matches!(result, Err(Error::Cancelled)));
        assert!(self.context.tasks.shutdown_at(Instant::now() + Duration::from_secs(2)).await.is_clean());
        assert_eq!(self.telemetry.usage().unwrap().active_flows, 0);
    }
}

async fn tcp_echo(outbound: &dyn Outbound, ip: &str, port: u16, length: usize) {
    let target = Destination::new(ip, port).unwrap();
    let context = ConnectContext::new(Duration::from_secs(4));
    let mut stream = outbound.connect_tcp(&target, &context).await.unwrap().stream;
    let data = (0..length).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    stream.write_all(&data).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await.unwrap().unwrap();
    let mut expected = port.to_be_bytes().to_vec();
    expected.extend_from_slice(&data);
    assert_eq!(response, expected);
}

#[tokio::test]
async fn dual_outer_and_inner_families_tcp_half_close_and_fragmented_fixed_udp() {
    for ipv6 in [false, true] {
        let mut rig = Rig::start(ipv6, Some(9), false).await;
        let mut bytes = 0usize;
        for (ip, maximum) in [("192.0.2.5", 65507), ("2001:db8::5", 65527)] {
            tcp_echo(&*rig.outbound, ip, 8080, 256 * 1024).await;
            bytes += 256 * 1024;
            let target = Destination::new(ip, 5353).unwrap();
            let context = ConnectContext::new(Duration::from_secs(2));
            let mut channel = rig.outbound.connect_udp(&target, &context).await.unwrap();
            for size in [0, 1, 4096, maximum] {
                let payload = vec![0x6d; size];
                channel.sender.send(&payload).await.unwrap();
                assert_eq!(timeout(Duration::from_secs(3), channel.receiver.recv()).await.unwrap().unwrap().unwrap(), payload);
                bytes += size;
            }
        }
        let usage = rig.telemetry.usage().unwrap();
        assert_eq!(usage.engine.upload_bytes, bytes as u64);
        assert_eq!(usage.engine.download_bytes, bytes as u64 + 4);
        assert_eq!(usage.users.len(), 1);
        let carrier = rig.host.carrier_usage();
        assert!(carrier.sent_bytes > bytes as u64 && carrier.received_bytes > bytes as u64);
        assert!(rig.ingress.carrier_usage().received_bytes > bytes as u64);
        rig.stop().await;
    }
}

#[tokio::test]
async fn a_single_udp_association_keeps_multiple_original_targets() {
    let mut rig = Rig::start(false, None, false).await;
    let context = ConnectContext::new(Duration::from_secs(2));
    let mut association = rig.outbound.associate_udp(&context).await.unwrap();
    for target in [Destination::new("192.0.2.5", 3001).unwrap(), Destination::new("198.51.100.7", 3002).unwrap(),
        Destination::new("2001:db8::5", 3003).unwrap(), Destination::new("2001:db8::7", 3004).unwrap()] {
        association.sender.send_to(b"target-owner", &target).await.unwrap();
        let (source, bytes) = timeout(Duration::from_secs(2), association.receiver.recv_from()).await.unwrap().unwrap().unwrap();
        assert_eq!(source, target);
        assert_eq!(bytes, b"target-owner");
    }
    assert_eq!(rig.echo.associations.load(Ordering::SeqCst), 2);
    let records = rig.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record.datagram_targets.len() == 2));
    drop(association);
    rig.stop().await;
}

#[tokio::test]
async fn authenticated_peers_have_distinct_users_and_one_request_cancel_preserves_the_service() {
    let mut rig = Rig::start(false, Some(9), true).await;
    let (second, second_host) = client(rig.endpoint, 3, 3, Some(9)).await;
    let first_cancel = kerlico_core::CancellationToken::new();
    let source = Source::Local { node: NodeId::parse("first-source").unwrap() };
    let context = ConnectContext::new(Duration::from_secs(2)).scoped(&rig.host, &source, first_cancel.clone(),
        kerlico_core::CancellationToken::new(), FamilyMode::DualV4Preferred);
    let target = Destination::new("192.0.2.5", 5353).unwrap();
    let mut one = rig.outbound.connect_udp(&target, &context).await.unwrap();
    one.sender.send(b"first").await.unwrap();
    assert_eq!(timeout(Duration::from_secs(2), one.receiver.recv()).await.unwrap().unwrap().unwrap(), b"first");
    first_cancel.cancel();
    assert!(matches!(timeout(Duration::from_secs(1), one.receiver.recv()).await.unwrap(), Err(Error::Cancelled)));
    let healthy = ConnectContext::new(Duration::from_secs(2));
    let mut same_service = rig.outbound.connect_udp(&target, &healthy).await.unwrap();
    same_service.sender.send(b"same-service").await.unwrap();
    assert_eq!(timeout(Duration::from_secs(2), same_service.receiver.recv()).await.unwrap().unwrap().unwrap(), b"same-service");
    tcp_echo(&*second, "2001:db8::5", 8081, 32768).await;
    assert_eq!(rig.telemetry.usage().unwrap().users.len(), 2);
    second.shutdown().await.unwrap();
    assert!(second_host.shutdown(Instant::now() + Duration::from_secs(2)).await.is_clean());
    drop(one);
    drop(same_service);
    rig.stop().await;
}

#[tokio::test]
async fn wrong_psk_and_spoofed_inner_source_create_no_business_flow() {
    for (psk, address) in [(Some(8), 2), (Some(9), 4)] {
        let mut rig = Rig::start(false, Some(9), false).await;
        let (bad, bad_host) = client(rig.endpoint, 1, address, psk).await;
        let context = ConnectContext::new(Duration::from_millis(300));
        let target = Destination::new("192.0.2.5", 5353).unwrap();
        let mut channel = bad.connect_udp(&target, &context).await.unwrap();
        channel.sender.send(b"untrusted").await.unwrap();
        assert!(timeout(Duration::from_millis(350), channel.receiver.recv()).await.is_err());
        assert!(rig.telemetry.records(0, 8).unwrap().is_empty());
        bad.shutdown().await.unwrap();
        assert!(bad_host.shutdown(Instant::now() + Duration::from_secs(2)).await.is_clean());
        drop(channel);
        tcp_echo(&*rig.outbound, "192.0.2.5", 8080, 128).await;
        rig.stop().await;
    }
}

#[tokio::test]
async fn rejected_target_resets_tcp_and_service_shutdown_wakes_udp_waiter() {
    let mut rig = Rig::start(false, None, false).await;
    let target = Destination::new("2001:db8::5", 9).unwrap();
    let context = ConnectContext::new(Duration::from_secs(2));
    assert!(rig.outbound.connect_tcp(&target, &context).await.is_err());
    let records = rig.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].original.as_ref().unwrap().target(), &target);
    assert_eq!(records[0].end, Some(kerlico_egress::FlowEnd::Failed));
    let mut channel = rig.outbound.connect_udp(&Destination::new("192.0.2.5", 5353).unwrap(), &context).await.unwrap();
    rig.outbound.shutdown().await.unwrap();
    assert!(matches!(timeout(Duration::from_secs(1), channel.receiver.recv()).await.unwrap(), Err(Error::Cancelled)));
    rig.stop().await;
}
