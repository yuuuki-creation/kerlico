use super::*;
use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory};
use kerlico_core::{
    AddressedDatagram, BoxFuture, Capabilities, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, Destination, Error,
    FamilyMode, InboundContext, IngressBinding, NodeId, NodeObserver, NodeTasks, OpenedTcp,
    Outbound, Result, ServiceContext, Source, StreamBudget, TargetPolicy, TcpConnectInfo,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Semaphore, mpsc},
    time::{Instant, timeout},
};

struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: kerlico_core::NodeEvent) {}
}
struct NoDns;
impl kerlico_egress::Resolver for NoDns {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
        Box::pin(async { Err(Error::Unsupported("测试目标不得触发DNS")) })
    }
}
struct EchoOutbound {
    tasks: NodeTasks,
    associations: AtomicUsize,
}
struct EchoSender(mpsc::Sender<AddressedDatagram>);
struct EchoReceiver(mpsc::Receiver<AddressedDatagram>);
impl DatagramAssociationSender for EchoSender {
    fn send_to<'a>(
        &'a mut self,
        payload: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .send((target.clone(), payload.to_vec()))
                .await
                .map_err(|_| Error::Cancelled)
        })
    }
}
impl DatagramAssociationReceiver for EchoReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
impl Outbound for EchoOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            if target.port() == 9 {
                return Err(Error::Rejected);
            }
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
            Ok(OpenedTcp {
                stream: Box::new(front),
                info: TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("入站必须使用真实多目标UDP关联")) })
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.associations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            let (sender, receiver) = mpsc::channel(8);
            Ok(DatagramAssociation {
                sender: Box::new(EchoSender(sender)),
                receiver: Box::new(EchoReceiver(receiver)),
            })
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
    fn drop(&mut self) {
        self.context.cancel.cancel();
        self.host.cancel().cancel();
    }
}
async fn client(
    endpoint: SocketAddr,
    number: u8,
    last: u8,
    psk: Option<u8>,
) -> (Arc<dyn Outbound>, ServiceContext) {
    let host = ServiceContext::for_test();
    let plan = crate::WireGuardFactory
        .compile(&json!({
            "tunnel": tunnel(number, last), "peer": peer(2, None, psk),
            "endpoint": {"host": endpoint.ip().to_string(), "port": endpoint.port()}
        }))
        .unwrap();
    let outbound = plan.start(host.clone()).await.unwrap();
    (outbound, host)
}
impl Rig {
    async fn start(ipv6: bool, psk: Option<u8>, multi: bool) -> Self {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .unwrap(),
        );
        let endpoint = socket.local_addr().unwrap();
        let cancel = kerlico_core::CancellationToken::new();
        let context = InboundContext {
            peer_lease: None,
            peer_addr: None,
            local_addr: Some(endpoint),
            tasks: NodeTasks::new(NodeId::parse("test-node").unwrap(), cancel.clone()),
            cancel,
            connect_timeout: Duration::from_secs(4),
            idle_timeout: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 64,
            stream_budget: StreamBudget::new(
                Arc::new(Semaphore::new(64)),
                Arc::new(Semaphore::new(64)),
            ),
            events: Arc::new(Observer),
        };
        let mut members = vec![peer(1, Some(2), psk)];
        if multi {
            members.push(peer(3, Some(3), psk));
        }
        let input = NodeBuildContext::for_test(json!({"tunnel": tunnel(2, 1)}), members);
        let node = crate::WireGuardNodeFactory.build(&input).unwrap();
        let echo = Arc::new(EchoOutbound {
            tasks: context.tasks.clone(),
            associations: AtomicUsize::new(0),
        });
        let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            echo.clone(),
            TargetPolicy::Local,
            FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let binding = ingress.clone();
        let node_context = context.clone();
        let serving =
            tokio::spawn(async move { node.handle_udp(socket, binding, node_context).await });
        let (outbound, host) = client(endpoint, 1, 2, psk).await;
        Self {
            outbound,
            host,
            context,
            ingress,
            telemetry,
            echo,
            endpoint,
            serving: Some(serving),
        }
    }
    async fn stop(&mut self) {
        self.outbound.shutdown().await.unwrap();
        assert!(
            self.host
                .shutdown(Instant::now() + Duration::from_secs(2))
                .await
                .is_clean()
        );
        self.context.cancel.cancel();
        let result = timeout(Duration::from_secs(2), self.serving.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(Error::Cancelled)));
        assert!(
            self.context
                .tasks
                .shutdown_at(Instant::now() + Duration::from_secs(2))
                .await
                .is_clean()
        );
        assert_eq!(self.telemetry.usage().unwrap().active_flows, 0);
    }
}

#[derive(Default)]
struct Drops(AtomicUsize);
impl NodeObserver for Drops {
    fn record(&self, event: kerlico_core::NodeEvent) {
        if matches!(event, kerlico_core::NodeEvent::Dropped) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}
struct DropCountingNode {
    socket: Arc<tokio::net::UdpSocket>,
    drops: Arc<Drops>,
    context: InboundContext,
    serving: tokio::task::JoinHandle<Result<()>>,
}
impl DropCountingNode {
    async fn start() -> Self {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let cancel = kerlico_core::CancellationToken::new();
        let drops = Arc::new(Drops::default());
        let context = InboundContext {
            peer_lease: None,
            peer_addr: None,
            local_addr: socket.local_addr().ok(),
            tasks: NodeTasks::new(NodeId::parse("test-node").unwrap(), cancel.clone()),
            cancel,
            connect_timeout: Duration::from_secs(4),
            idle_timeout: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 64,
            stream_budget: StreamBudget::new(
                Arc::new(Semaphore::new(64)),
                Arc::new(Semaphore::new(64)),
            ),
            events: drops.clone(),
        };
        let input = NodeBuildContext::for_test(
            json!({"tunnel": tunnel(2, 1)}),
            vec![peer(1, Some(2), None)],
        );
        let node = crate::WireGuardNodeFactory.build(&input).unwrap();
        let echo = Arc::new(EchoOutbound {
            tasks: context.tasks.clone(),
            associations: AtomicUsize::new(0),
        });
        let (ingress, _) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            echo,
            TargetPolicy::Local,
            FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let serving = {
            let (socket, context) = (socket.clone(), context.clone());
            tokio::spawn(async move { node.handle_udp(socket, ingress, context).await })
        };
        Self {
            socket,
            drops,
            context,
            serving,
        }
    }
    async fn wait_for_drops(&self, count: usize) {
        timeout(Duration::from_secs(2), async {
            while self.drops.0.load(Ordering::SeqCst) < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("数据报没有记为 Dropped");
        assert!(
            !self.serving.is_finished(),
            "一个数据报不应结束节点接收循环"
        );
    }
    async fn stop(self) {
        self.context.cancel.cancel();
        let result = timeout(Duration::from_secs(2), self.serving)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(Error::Cancelled)));
    }
}
/// 对端发往节点的握手发起包：每次新建会话，所以每个包都会得到一次回复。
fn handshake_init_for_node() -> Vec<u8> {
    let tunnel = serde_json::from_value::<crate::config::CommonOptions>(tunnel(1, 2))
        .unwrap()
        .prepare()
        .unwrap();
    let peer = serde_json::from_value::<crate::config::PeerOptions>(peer(2, None, None))
        .unwrap()
        .prepare()
        .unwrap();
    let index = crate::crypto::PeerIndex::new(&tunnel, std::slice::from_ref(&peer));
    crate::crypto::CryptoPeer::new(&tunnel, &peer, 1, None, index.limiter)
        .initiate()
        .unwrap()
}
#[tokio::test]
async fn reply_send_failure_costs_only_that_datagram() {
    let node = DropCountingNode::start().await;
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = node.socket.local_addr().unwrap();
    // 已连接且关闭写方向的 socket 仍能接收，发送必定 EPIPE。
    node.socket
        .connect(client.local_addr().unwrap())
        .await
        .unwrap();
    socket2::SockRef::from(node.socket.as_ref())
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    client
        .send_to(&handshake_init_for_node(), endpoint)
        .await
        .unwrap();
    node.wait_for_drops(1).await;
    client
        .send_to(&handshake_init_for_node(), endpoint)
        .await
        .unwrap();
    node.wait_for_drops(2).await;
    node.stop().await;
}
#[tokio::test]
async fn icmp_error_on_the_node_socket_costs_only_itself() {
    let node = DropCountingNode::start().await;
    let closed = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let closed_address = closed.local_addr().unwrap();
    drop(closed);
    node.socket.connect(closed_address).await.unwrap();
    node.socket.send(b"provoke-icmp").await.unwrap();
    node.wait_for_drops(1).await;
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    node.socket
        .connect(client.local_addr().unwrap())
        .await
        .unwrap();
    client
        .send_to(
            &handshake_init_for_node(),
            node.socket.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let mut response = [0; 256];
    let count = timeout(Duration::from_secs(2), client.recv(&mut response))
        .await
        .expect("节点没有回应握手")
        .unwrap();
    assert_eq!(response[0], 2, "握手响应，共 {count} 字节");
    node.stop().await;
}
#[tokio::test]
async fn outbound_reply_send_failure_keeps_the_tunnel_running() {
    use crate::{
        carrier::Carrier,
        client::run,
        config::{CommonOptions, PeerOptions},
        crypto::{CryptoPeer, PeerIndex},
        queue::PacketBudget,
        stack::SharedStack,
    };
    let prepared = serde_json::from_value::<CommonOptions>(tunnel(2, 1))
        .unwrap()
        .prepare()
        .unwrap();
    let remote = serde_json::from_value::<PeerOptions>(peer(1, Some(2), None))
        .unwrap()
        .prepare()
        .unwrap();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = client.local_addr().unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(sender.local_addr().unwrap()).await.unwrap();
    socket2::SockRef::from(&client)
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    let cancel = kerlico_core::CancellationToken::new();
    let stack = SharedStack::new(
        &prepared,
        cancel.clone(),
        Arc::new(tokio::sync::Notify::new()),
        remote.allowed.clone(),
        PacketBudget::new(prepared.limits.queue_packets, prepared.limits.queue_bytes),
    )
    .unwrap();
    let index = PeerIndex::new(&prepared, std::slice::from_ref(&remote));
    let crypto = CryptoPeer::new(&prepared, &remote, 1, None, index.limiter.clone());
    let host = ServiceContext::for_test();
    let running = tokio::spawn(run(
        client,
        prepared,
        remote,
        index,
        crypto,
        stack,
        Carrier::Outbound(host),
    ));
    sender
        .send_to(&handshake_init_for_node(), local)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!running.is_finished(), "回复发送失败不应结束隧道");
    cancel.cancel();
    assert!(running.await.unwrap().is_ok());
}

async fn tcp_echo(outbound: &dyn Outbound, ip: &str, port: u16, length: usize) {
    let target = Destination::new(ip, port).unwrap();
    let context = ConnectContext::new(Duration::from_secs(4));
    let mut stream = outbound
        .connect_tcp(&target, &context)
        .await
        .unwrap()
        .stream;
    let data = (0..length).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    stream.write_all(&data).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
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
                assert_eq!(
                    timeout(Duration::from_secs(3), channel.receiver.recv())
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap(),
                    payload
                );
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
    for target in [
        Destination::new("192.0.2.5", 3001).unwrap(),
        Destination::new("198.51.100.7", 3002).unwrap(),
        Destination::new("2001:db8::5", 3003).unwrap(),
        Destination::new("2001:db8::7", 3004).unwrap(),
    ] {
        association
            .sender
            .send_to(b"target-owner", &target)
            .await
            .unwrap();
        let (source, bytes) = timeout(Duration::from_secs(2), association.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(source, target);
        assert_eq!(bytes, b"target-owner");
    }
    assert_eq!(rig.echo.associations.load(Ordering::SeqCst), 2);
    let records = rig.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.datagram_targets.len() == 2)
    );
    drop(association);
    rig.stop().await;
}

#[tokio::test]
async fn authenticated_peers_have_distinct_users_and_one_request_cancel_preserves_the_service() {
    let mut rig = Rig::start(false, Some(9), true).await;
    let (second, second_host) = client(rig.endpoint, 3, 3, Some(9)).await;
    let first_cancel = kerlico_core::CancellationToken::new();
    let source = Source::Local {
        node: NodeId::parse("first-source").unwrap(),
    };
    let context = ConnectContext::new(Duration::from_secs(2)).scoped(
        &rig.host,
        &source,
        first_cancel.clone(),
        kerlico_core::CancellationToken::new(),
        FamilyMode::DualV4Preferred,
    );
    let target = Destination::new("192.0.2.5", 5353).unwrap();
    let mut one = rig.outbound.connect_udp(&target, &context).await.unwrap();
    one.sender.send(b"first").await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), one.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        b"first"
    );
    first_cancel.cancel();
    assert!(matches!(
        timeout(Duration::from_secs(1), one.receiver.recv())
            .await
            .unwrap(),
        Err(Error::Cancelled)
    ));
    let healthy = ConnectContext::new(Duration::from_secs(2));
    let mut same_service = rig.outbound.connect_udp(&target, &healthy).await.unwrap();
    same_service.sender.send(b"same-service").await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), same_service.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        b"same-service"
    );
    tcp_echo(&*second, "2001:db8::5", 8081, 32768).await;
    assert_eq!(rig.telemetry.usage().unwrap().users.len(), 2);
    second.shutdown().await.unwrap();
    assert!(
        second_host
            .shutdown(Instant::now() + Duration::from_secs(2))
            .await
            .is_clean()
    );
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
        assert!(
            timeout(Duration::from_millis(350), channel.receiver.recv())
                .await
                .is_err()
        );
        assert!(rig.telemetry.records(0, 8).unwrap().is_empty());
        bad.shutdown().await.unwrap();
        assert!(
            bad_host
                .shutdown(Instant::now() + Duration::from_secs(2))
                .await
                .is_clean()
        );
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
    let mut channel = rig
        .outbound
        .connect_udp(&Destination::new("192.0.2.5", 5353).unwrap(), &context)
        .await
        .unwrap();
    rig.outbound.shutdown().await.unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(1), channel.receiver.recv())
            .await
            .unwrap(),
        Err(Error::Cancelled)
    ));
    rig.stop().await;
}

#[tokio::test]
async fn shared_service_failure_is_returned_by_business_open_and_shutdown() {
    let (outbound, host) = client("127.0.0.1:9".parse().unwrap(), 1, 2, None).await;
    let first =
        kerlico_core::ServiceFailure::Io(std::io::ErrorKind::ConnectionReset, "受控WireGuard首因");
    host.fail(first);
    let target = Destination::new("192.0.2.5", 80).unwrap();
    let context = ConnectContext::new(Duration::from_secs(1));
    assert!(
        matches!(outbound.connect_tcp(&target,&context).await,Err(Error::Io(error)) if error.kind()==std::io::ErrorKind::ConnectionReset && error.to_string()=="受控WireGuard首因")
    );
    assert!(
        matches!(outbound.connect_udp(&target,&context).await,Err(Error::Io(error)) if error.kind()==std::io::ErrorKind::ConnectionReset)
    );
    host.fail(kerlico_core::ServiceFailure::Protocol(
        "受控WireGuard后续关闭失败",
    ));
    assert!(
        matches!(outbound.shutdown().await,Err(Error::Io(error)) if error.kind()==std::io::ErrorKind::ConnectionReset && error.to_string()=="受控WireGuard首因")
    );
    assert_eq!(host.failure(), Some(first));
    let report = host.shutdown(Instant::now() + Duration::from_secs(2)).await;
    assert!(!report.timed_out);
    assert!(host.retirement().is_finished());
}
