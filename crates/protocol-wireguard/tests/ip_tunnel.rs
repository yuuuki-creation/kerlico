use kerlico_config::{NodeBuildContext, OutboundFactory};
use kerlico_core::{
    BoxFuture, CancellationToken, ConnectContext, Destination, Error, FamilyMode, InboundContext,
    NodeEvent, NodeId, NodeObserver, NodeTasks, Result, ServiceContext, StreamBudget, TargetPolicy,
};
use kerlico_wireguard::ip::{ClientTunnel, ServerTunnel, StackLimits, StackOptions};
use serde_json::json;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    time::{Instant, timeout},
};

struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
struct NoDns;
impl kerlico_egress::Resolver for NoDns {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
        Box::pin(async { Err(Error::Protocol("纯IP数据面不得解析域名")) })
    }
}
fn options(addresses: &[&str], allowed: &[&str]) -> StackOptions {
    StackOptions {
        addresses: addresses
            .iter()
            .map(|address| address.parse().unwrap())
            .collect(),
        allowed_ips: allowed.iter().map(|network| network.to_string()).collect(),
        mtu: 1280,
        limits: StackLimits::default(),
    }
}
fn context(cancel: CancellationToken) -> InboundContext {
    InboundContext {
        peer_lease: None,
        tasks: NodeTasks::new(NodeId::parse("test-node").unwrap(), cancel.clone()),
        cancel,
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 32,
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(64)),
            Arc::new(Semaphore::new(64)),
        ),
        events: Arc::new(Observer),
        peer_addr: None,
        local_addr: None,
    }
}

#[tokio::test]
async fn plaintext_ip_bridge_preserves_tcp_fin_maximum_udp_and_trusted_usage() {
    timeout(Duration::from_secs(20), async {
        let input =
            NodeBuildContext::for_test(json!({}), vec![json!({"password":"synthetic-ip-member"})]);
        let credentials = input
            .credentials(vec![b"synthetic-ip-member".to_vec()])
            .unwrap();
        let direct = kerlico_net::DirectFactory
            .compile(&json!({}))
            .unwrap()
            .start(ServiceContext::for_test())
            .await
            .unwrap();
        let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            direct,
            TargetPolicy::Local,
            FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let stop = CancellationToken::new();
        let context = context(stop.clone());
        let tasks = context.tasks.clone();
        let verified = credentials
            .verify(&b"synthetic-ip-member".to_vec(), |expected, value| {
                Ok((expected == value).then_some(()))
            })
            .unwrap();
        let (access, ()) = ingress.authenticated(verified, &context).unwrap();
        let user = access.source().user().unwrap();
        let client = ClientTunnel::new(
            options(&["10.77.0.2", "fd77::2"], &["0.0.0.0/0", "::/0"]),
            stop.clone(),
        )
        .unwrap();
        let server = Arc::new(
            ServerTunnel::new(
                options(&["10.77.0.1", "fd77::1"], &["10.77.0.2/32", "fd77::2/128"]),
                access,
                context,
            )
            .unwrap(),
        );
        let other =
            ClientTunnel::new(options(&["10.77.0.3"], &["0.0.0.0/0"]), stop.clone()).unwrap();
        let mut forged = other
            .connect_udp(
                &Destination::new("127.0.0.1", 9).unwrap(),
                &ConnectContext::new(Duration::from_secs(1)),
            )
            .unwrap();
        forged.sender.send(b"unassigned-source").await.unwrap();
        assert!(matches!(
            server.receive(&other.next_packet().await.unwrap()),
            Err(Error::Rejected)
        ));
        assert_eq!(telemetry.usage().unwrap().retained_records, 0);
        other.close();
        let pump = {
            let (client, server, stop) = (client.clone(), server.clone(), stop.clone());
            tokio::spawn(async move {
                loop {
                    tokio::select! { biased;
                        _ = stop.cancelled() => return Ok::<_,Error>(()),
                        packet = client.next_packet() => server.receive(&packet?)?,
                        packet = server.next_packet() => client.receive(&packet?)?,
                    }
                }
            })
        };
        let mut expected_up = 0;
        let mut expected_down = 0;
        for listen in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(listen).await.unwrap();
            let address = listener.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let (mut peer, _) = listener.accept().await.unwrap();
                let mut payload = Vec::new();
                peer.read_to_end(&mut payload).await.unwrap();
                peer.write_all(&payload).await.unwrap();
                peer.write_all(b"fin-tail").await.unwrap();
                peer.shutdown().await.unwrap();
            });
            let destination = Destination::new(&address.ip().to_string(), address.port()).unwrap();
            let mut stream = client
                .connect_tcp(&destination, &ConnectContext::new(Duration::from_secs(3)))
                .await
                .unwrap()
                .stream;
            let payload = vec![0x5a; 65537];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(&reply[..payload.len()], &payload);
            assert_eq!(&reply[payload.len()..], b"fin-tail");
            expected_up += payload.len() as u64;
            expected_down += reply.len() as u64;
            echo.await.unwrap();
            let target = UdpSocket::bind(listen).await.unwrap();
            let address = target.local_addr().unwrap();
            let destination = Destination::new(&address.ip().to_string(), address.port()).unwrap();
            let mut channel = client
                .connect_udp(&destination, &ConnectContext::new(Duration::from_secs(3)))
                .unwrap();
            for size in [0, 1, 4096, if address.is_ipv4() { 65507 } else { 65527 }] {
                let payload = vec![0xa5; size];
                channel.sender.send(&payload).await.unwrap();
                let mut received = vec![0; 65535];
                let (count, source) = target.recv_from(&mut received).await.unwrap();
                assert_eq!(&received[..count], &payload);
                target.send_to(&received[..count], source).await.unwrap();
                assert_eq!(channel.receiver.recv().await.unwrap().unwrap(), payload);
                expected_up += size as u64;
                expected_down += size as u64;
            }
        }
        assert_eq!(telemetry.usage().unwrap().engine.upload_bytes, expected_up);
        assert_eq!(
            telemetry.usage().unwrap().engine.download_bytes,
            expected_down
        );
        assert_eq!(
            telemetry.usage().unwrap().users[&user].upload_bytes,
            expected_up
        );
        stop.cancel();
        client.close();
        server.close();
        pump.await.unwrap().unwrap();
        assert!(
            tasks
                .shutdown_at(Instant::now() + Duration::from_secs(2))
                .await
                .is_clean()
        );
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
        assert_eq!(telemetry.usage().unwrap().engine.upload_bytes, expected_up);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn plaintext_client_cannot_inject_another_assigned_address_or_a_domain_target() {
    let stop = CancellationToken::new();
    let client = ClientTunnel::new(options(&["10.77.0.2"], &["0.0.0.0/0"]), stop.clone()).unwrap();
    let destination = Destination::new("example.invalid", 443).unwrap();
    assert!(
        client
            .connect_tcp(&destination, &ConnectContext::new(Duration::from_secs(1)))
            .await
            .is_err()
    );
    assert!(
        client
            .connect_udp(&destination, &ConnectContext::new(Duration::from_secs(1)))
            .is_err()
    );
    let invalid = ClientTunnel::new(options(&["10.77.0.3"], &["0.0.0.0/0"]), stop.clone()).unwrap();
    let destination = Destination::new("127.0.0.1", 9).unwrap();
    let mut channel = invalid
        .connect_udp(&destination, &ConnectContext::new(Duration::from_secs(1)))
        .unwrap();
    channel.sender.send(b"source-check").await.unwrap();
    let packet = invalid.next_packet().await.unwrap();
    assert!(client.receive(&packet).is_err());
    stop.cancel();
    assert!(matches!(client.next_packet().await, Err(Error::Cancelled)));
}
