use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, AddressedDatagram, BoxFuture, BoxStream, CancellationToken, ConnectContext,
    DatagramAssociation, DatagramChannel, Destination, InboundContext, NodeEvent, NodeObserver,
    Outbound, Result, StreamBudget,
};
use kerlico_tuic::{TuicFactory, TuicNodeFactory};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
};
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
struct Access {
    egress: kerlico_egress::Egress,
    count: Arc<AtomicUsize>,
}
impl AccessService for Access {
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        c: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::associate_udp(&self.egress, c)
    }
    fn connect_tcp<'a>(
        &'a self,
        t: &'a Destination,
        c: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::connect_tcp(&self.egress, t, c)
    }
    fn connect_udp<'a>(
        &'a self,
        t: &'a Destination,
        c: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::connect_udp(&self.egress, t, c)
    }
}
struct Fixture {
    outbound: Arc<dyn Outbound>,
    options: Value,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    count: Arc<AtomicUsize>,
    address: std::net::SocketAddr,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
async fn fixture(version: u8, mode: &str, host: &str, congestion: &str) -> Fixture {
    fixture_egress(version, mode, host, congestion, None, 1).await
}
async fn fixture_egress(
    version: u8,
    mode: &str,
    host: &str,
    congestion: &str,
    egress: Option<Arc<dyn Outbound>>,
    identity: u8,
) -> Fixture {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = cert.cert.pem();
    let key = cert.signing_key.serialize_pem();
    let mut server = json!({"version":version,"tls":{"certificate_pem":pem,"private_key_pem":key},"congestion_control":congestion});
    let mut client = json!({"version":version,"tls":{"server_name":"localhost","ca_pem":pem},"udp_relay_mode":mode,"congestion_control":congestion,"idle_timeout_secs":30,"heartbeat_interval_secs":2});
    if version == 4 {
        server["token"] = json!(format!("synthetic-token-{identity}"));
        client["token"] = server["token"].clone();
    } else {
        server["uuid"] = json!(format!("00000000-0000-4000-8000-{identity:012}"));
        server["password"] = json!("synthetic-password");
        client["uuid"] = server["uuid"].clone();
        client["password"] = server["password"].clone();
    }
    let node = TuicNodeFactory.build(&server).unwrap();
    let socket = Arc::new(UdpSocket::bind((host, 0)).await.unwrap());
    let address = socket.local_addr().unwrap();
    client["server"] = json!({"host":host,"port":address.port()});
    let cancel = CancellationToken::new();
    let context = InboundContext {
        peer_addr: None,
        local_addr: Some(address),
        cancel: cancel.clone(),
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(20),
        drain_timeout: Duration::from_millis(300),
        max_datagram_size: 65535,
        max_streams: 64,
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(64)),
            Arc::new(Semaphore::new(64)),
        ),
        events: Arc::new(Observer),
    };
    let count = Arc::new(AtomicUsize::new(0));
    let access = Arc::new(Access {
        egress: kerlico_egress::Egress::new(
            egress.unwrap_or_else(|| kerlico_net::DirectFactory.build(&json!({})).unwrap()),
        ),
        count: count.clone(),
    });
    let task = tokio::spawn(async move {
        let _ = node.handle_udp(socket, access, context).await;
    });
    let outbound = TuicFactory.build(&client).unwrap();
    Fixture {
        outbound,
        options: client,
        cancel,
        task,
        count,
        address,
    }
}
async fn receive(association: &mut DatagramAssociation) -> AddressedDatagram {
    tokio::time::timeout(Duration::from_secs(5), association.receiver.recv_from())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
async fn echo_tcp(host: &str) -> (Destination, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let target = Destination::new(host, listener.local_addr().unwrap().port()).unwrap();
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {result=listener.accept()=>{let(mut stream,_)=result.unwrap();tasks.spawn(async move{let(mut read,mut write)=stream.split();let _=tokio::io::copy(&mut read,&mut write).await;});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
    });
    (target, task)
}
async fn tcp(f: &Fixture, target: &Destination) {
    let mut stream = f
        .outbound
        .connect_tcp(target, &ConnectContext::new(Duration::from_secs(3)))
        .await
        .unwrap();
    let request = vec![6; 20000];
    stream.write_all(&request).await.unwrap();
    let mut response = vec![0; request.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, request);
    stream.shutdown().await.unwrap();
    let mut byte = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
#[tokio::test]
async fn versions_modes_addresses_and_congestion_complete_matrix() {
    let (tcp4, t4) = echo_tcp("127.0.0.1").await;
    let (tcp6, t6) = echo_tcp("::1").await;
    for version in [4, 5] {
        for mode in ["native", "quic"] {
            for host in ["127.0.0.1", "::1"] {
                for congestion in ["cubic", "newreno", "bbr"] {
                    let f = fixture(version, mode, host, congestion).await;
                    tcp(&f, &tcp4).await;
                    tcp(&f, &tcp6).await;
                    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let target =
                        Destination::new("127.0.0.1", socket.local_addr().unwrap().port()).unwrap();
                    let mut association = f
                        .outbound
                        .associate_udp(&ConnectContext::new(Duration::from_secs(3)))
                        .await
                        .unwrap();
                    let sizes = if version == 4 && mode == "native" {
                        vec![0, 17, 900]
                    } else {
                        vec![0, 17, 12000, 65000, 65507]
                    };
                    let mut buffer = vec![0; 65535];
                    for size in sizes {
                        let bytes = vec![8; size];
                        association.sender.send_to(&bytes, &target).await.unwrap();
                        let (n, peer) = tokio::time::timeout(
                            Duration::from_secs(5),
                            socket.recv_from(&mut buffer),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        assert_eq!(&buffer[..n], bytes);
                        socket.send_to(&buffer[..n], peer).await.unwrap();
                        let (source, answer) = receive(&mut association).await;
                        assert_eq!(source, target);
                        assert_eq!(answer, bytes);
                    }
                    assert!(
                        association
                            .sender
                            .send_to(&vec![7; 65508], &target)
                            .await
                            .is_err()
                    );
                    if version == 4 && mode == "native" {
                        assert!(
                            association
                                .sender
                                .send_to(&vec![7; 12000], &target)
                                .await
                                .is_err()
                        );
                        association
                            .sender
                            .send_to(b"next-packet", &target)
                            .await
                            .unwrap();
                        let (n, _) = tokio::time::timeout(
                            Duration::from_secs(5),
                            socket.recv_from(&mut buffer),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        assert_eq!(&buffer[..n], b"next-packet");
                    }
                }
            }
        }
    }
    t4.abort();
    t6.abort();
}
#[tokio::test]
async fn full_cone_same_port_across_targets_families_and_uncontacted_source() {
    for version in [4, 5] {
        for mode in ["native", "quic"] {
            let f = fixture(version, mode, "::1", "cubic").await;
            let mut association = f
                .outbound
                .associate_udp(&ConnectContext::new(Duration::from_secs(3)))
                .await
                .unwrap();
            let four = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let six = UdpSocket::bind("[::1]:0").await.unwrap();
            let third = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut buffer = [0; 64];
            let target4 = Destination::new("127.0.0.1", four.local_addr().unwrap().port()).unwrap();
            let target6 = Destination::new("::1", six.local_addr().unwrap().port()).unwrap();
            association.sender.send_to(b"four", &target4).await.unwrap();
            let (n, peer4) =
                tokio::time::timeout(Duration::from_secs(5), four.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            four.send_to(&buffer[..n], peer4).await.unwrap();
            assert_eq!(receive(&mut association).await, (target4, b"four".to_vec()));
            association.sender.send_to(b"six", &target6).await.unwrap();
            let (n, peer6) =
                tokio::time::timeout(Duration::from_secs(5), six.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            six.send_to(&buffer[..n], peer6).await.unwrap();
            assert_eq!(receive(&mut association).await, (target6, b"six".to_vec()));
            assert_eq!(peer4.port(), peer6.port());
            third.send_to(b"uncontacted", peer4).await.unwrap();
            let (source, data) = receive(&mut association).await;
            assert_eq!(source.port(), third.local_addr().unwrap().port());
            assert_eq!(data, b"uncontacted");
            let target = Destination::new("localhost", four.local_addr().unwrap().port()).unwrap();
            association
                .sender
                .send_to(b"domain", &target)
                .await
                .unwrap();
            let (n, peer) =
                tokio::time::timeout(Duration::from_secs(5), four.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&buffer[..n], b"domain");
            assert_eq!(peer.port(), peer4.port());
        }
    }
}
#[tokio::test]
async fn authentication_certificate_and_cancellation_precede_target_access() {
    let (target, t) = echo_tcp("127.0.0.1").await;
    for version in [4, 5] {
        let f = fixture(version, "quic", "127.0.0.1", "cubic").await;
        let mut wrong = f.options.clone();
        if version == 4 {
            wrong["token"] = json!("another-token");
        } else {
            wrong["password"] = json!("another-password");
        }
        let outbound = TuicFactory.build(&wrong).unwrap();
        if let Ok(mut stream) = outbound
            .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
            .await
        {
            let _ = stream.write_all(b"must-not-pass").await;
            let mut bytes = [0; 1];
            let result =
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes)).await;
            assert!(matches!(result, Ok(Ok(0)) | Ok(Err(_))));
        }
        assert_eq!(f.count.load(Ordering::Acquire), 0);
        let mut wrong = f.options.clone();
        wrong["tls"]["server_name"] = json!("wrong.invalid");
        assert!(
            TuicFactory
                .build(&wrong)
                .unwrap()
                .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
                .await
                .is_err()
        );
        let context = ConnectContext::new(Duration::from_secs(2));
        context.cancel.cancel();
        assert!(matches!(
            f.outbound.associate_udp(&context).await,
            Err(kerlico_core::Error::Cancelled)
        ));
    }
    t.abort();
}
#[tokio::test]
async fn half_close_waits_for_target_response_and_port_is_reusable() {
    for version in [4, 5] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"request");
            stream.write_all(b"after-fin").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let f = fixture(version, "native", "127.0.0.1", "cubic").await;
        let mut stream = f
            .outbound
            .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(3)))
            .await
            .unwrap();
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, b"after-fin");
        task.await.unwrap();
        drop(stream);
        let address = f.address;
        drop(f);
        let mut rebound = false;
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if let Ok(socket) = UdpSocket::bind(address).await {
                drop(socket);
                rebound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(rebound);
    }
}
#[test]
fn rejects_mixed_versions_unknown_options_and_duplicate_users() {
    let tls = json!({"server_name":"localhost"});
    let base = json!({"server":{"host":"127.0.0.1","port":443},"uuid":"00000000-0000-4000-8000-000000000001","password":"test","tls":tls});
    for (key, value) in [
        ("token", json!("mixed")),
        ("version", json!(3)),
        ("udp_relay_mode", json!("uot")),
        ("congestion_control", json!("unknown")),
        ("zero_rtt", json!(true)),
    ] {
        let mut bad = base.clone();
        bad[key] = value;
        assert!(TuicFactory.build(&bad).is_err());
    }
    assert!(TuicFactory.build(&base).unwrap().supports_udp_association());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let options = json!({"version":5,"uuid":"00000000-0000-4000-8000-000000000001","password":"first-password","tls":{"certificate_pem":cert.cert.pem(),"private_key_pem":cert.signing_key.serialize_pem()}});
    let mut duplicate = options.clone();
    duplicate.as_object_mut().unwrap().remove("uuid");
    duplicate.as_object_mut().unwrap().remove("password");
    duplicate["users"] = json!([{"uuid":"00000000-0000-4000-8000-000000000001","password":"first-password"},{"uuid":"00000000-0000-4000-8000-000000000001","password":"another-password"}]);
    assert!(TuicNodeFactory.build(&duplicate).is_err());
    let mut registry = kerlico_config::Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register(kerlico_net::RejectFactory).unwrap();
    registry.register_node(TuicNodeFactory).unwrap();
    let mut config = json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[{"tag":"node4","type":"tuic","listen":"127.0.0.1:10443","outbound":"direct","options":options},{"tag":"node6","type":"tuic","listen":"[::1]:10443","outbound":"direct","options":options}]});
    config["nodes"][1]["options"]["password"] = json!("independent-password");
    let error = registry
        .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
        .err()
        .unwrap();
    assert!(error.to_string().contains("凭据重复"));
    config["nodes"][1]["options"]["uuid"] = json!("00000000-0000-4000-8000-000000000002");
    assert!(
        registry
            .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_ok()
    );
    config["outbounds"][0]["type"] = json!("reject");
    let error = registry
        .prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap())
        .err()
        .unwrap();
    assert!(error.to_string().contains("多目标 UDP 关联"));
}

#[tokio::test]
async fn chained_nodes_keep_identity_and_full_cone_udp_association() {
    for version in [4, 5] {
        for mode in ["native", "quic"] {
            let downstream = fixture(5, "quic", "::1", "cubic").await;
            let upstream = fixture_egress(
                version,
                mode,
                "127.0.0.1",
                "cubic",
                Some(downstream.outbound.clone()),
                2,
            )
            .await;
            let mut association = upstream
                .outbound
                .associate_udp(&ConnectContext::new(Duration::from_secs(3)))
                .await
                .unwrap();
            let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let second = UdpSocket::bind("[::1]:0").await.unwrap();
            let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut bytes = [0; 32];
            let target = Destination::new("127.0.0.1", first.local_addr().unwrap().port()).unwrap();
            association.sender.send_to(b"first", &target).await.unwrap();
            let (n, peer4) =
                tokio::time::timeout(Duration::from_secs(5), first.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            first.send_to(&bytes[..n], peer4).await.unwrap();
            assert_eq!(receive(&mut association).await, (target, b"first".to_vec()));
            let target = Destination::new("::1", second.local_addr().unwrap().port()).unwrap();
            association
                .sender
                .send_to(b"second", &target)
                .await
                .unwrap();
            let (n, peer6) =
                tokio::time::timeout(Duration::from_secs(5), second.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            second.send_to(&bytes[..n], peer6).await.unwrap();
            assert_eq!(
                receive(&mut association).await,
                (target, b"second".to_vec())
            );
            assert_eq!(peer4.port(), peer6.port());
            other.send_to(b"uncontacted", peer4).await.unwrap();
            assert_eq!(receive(&mut association).await.1, b"uncontacted");
        }
    }
}

#[tokio::test]
async fn multiplexed_tcp_and_independent_udp_associations_do_not_mix_payloads() {
    let (tcp_target, tcp_task) = echo_tcp("127.0.0.1").await;
    for version in [4, 5] {
        for mode in ["native", "quic"] {
            let f = fixture(version, mode, "127.0.0.1", "cubic").await;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_target =
                Destination::new("127.0.0.1", socket.local_addr().unwrap().port()).unwrap();
            let udp_task = tokio::spawn(async move {
                let mut ports = std::collections::BTreeSet::new();
                let mut bytes = [0; 2048];
                for _ in 0..8 {
                    let (n, peer) =
                        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut bytes))
                            .await
                            .unwrap()
                            .unwrap();
                    ports.insert(peer.port());
                    socket.send_to(&bytes[..n], peer).await.unwrap();
                }
                ports
            });
            let mut tasks = JoinSet::new();
            for index in 0..16 {
                let outbound = f.outbound.clone();
                let target = tcp_target.clone();
                tasks.spawn(async move {
                    let mut stream = outbound
                        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(3)))
                        .await
                        .unwrap();
                    let data = vec![index; 4096 + index as usize];
                    stream.write_all(&data).await.unwrap();
                    let mut answer = vec![0; data.len()];
                    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut answer))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(answer, data);
                    stream.shutdown().await.unwrap();
                });
            }
            let barrier = Arc::new(tokio::sync::Barrier::new(8));
            for index in 0..8 {
                let outbound = f.outbound.clone();
                let target = udp_target.clone();
                let barrier = barrier.clone();
                tasks.spawn(async move {
                    let mut association = outbound
                        .associate_udp(&ConnectContext::new(Duration::from_secs(3)))
                        .await
                        .unwrap();
                    let data = vec![50 + index; 256];
                    association.sender.send_to(&data, &target).await.unwrap();
                    let (source, answer) = receive(&mut association).await;
                    assert_eq!(source, target);
                    assert_eq!(answer, data);
                    barrier.wait().await;
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
            assert_eq!(udp_task.await.unwrap().len(), 8);
            assert_eq!(f.count.load(Ordering::Acquire), 24);
        }
    }
    tcp_task.abort();
}
