use kerlico_core::{
    AccessService, AddressedDatagram, BoxFuture, BoxStream, CancellationToken, ConnectContext,
    DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel,
    Destination, Error, InboundContext, InboundProtocol, NodeEvent, NodeObserver, Outbound, Result,
    StreamBudget,
};
use kerlico_hysteria2::{Hysteria2Node, Hysteria2Outbound};
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
    net::UdpSocket,
    sync::{Semaphore, mpsc},
};

#[derive(Default)]
struct Events;
impl NodeObserver for Events {
    fn record(&self, _: NodeEvent) {}
}
fn context(global: Arc<Semaphore>) -> InboundContext {
    InboundContext {
        cancel: CancellationToken::new(),
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(3),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65507,
        max_streams: 64,
        stream_budget: StreamBudget::new(global, Arc::new(Semaphore::new(128))),
        events: Arc::new(Events),
        peer_addr: None,
        local_addr: None,
    }
}
#[derive(Default)]
struct Echo(AtomicUsize);
struct Sender(mpsc::Sender<AddressedDatagram>);
struct Receiver(mpsc::Receiver<AddressedDatagram>);
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .send((target.clone(), packet.to_vec()))
                .await
                .map_err(|_| Error::Cancelled)
        })
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
impl AccessService for Echo {
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (sender, receiver) = mpsc::channel(32);
            Ok(DatagramAssociation {
                sender: Box::new(Sender(sender)),
                receiver: Box::new(Receiver(receiver)),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("测试要求同源口多目标关联")) })
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (client, mut server) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move {
                if server.write_all(b"server-first").await.is_err() {
                    return;
                }
                let mut bytes = vec![0; 16384];
                while let Ok(count) = server.read(&mut bytes).await {
                    if count == 0 {
                        let _ = server.shutdown().await;
                        break;
                    }
                    if server.write_all(&bytes[..count]).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    }
}
struct Fixture {
    outbound: Hysteria2Outbound,
    options: Value,
    context: InboundContext,
    task: tokio::task::JoinHandle<Result<()>>,
    access: Arc<Echo>,
    global: Arc<Semaphore>,
    certificate: String,
}
async fn start_fixture(
    ipv6: bool,
    salamander: bool,
    congestion: &str,
    udp: bool,
    permits: usize,
) -> Fixture {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.cert.pem();
    let key = cert.signing_key.serialize_pem();
    let host = if ipv6 { "::1" } else { "127.0.0.1" };
    let socket = Arc::new(UdpSocket::bind((host, 0)).await.unwrap());
    let port = socket.local_addr().unwrap().port();
    let obfs = if salamander {
        Some("synthetic-salamander-password")
    } else {
        None
    };
    let node=Hysteria2Node::from_options(&json!({"auth":"synthetic-node-password","tls":{"certificate_pem":certificate,"private_key_pem":key},"salamander_password":obfs,"udp":udp,"limits":{"congestion":congestion}})).unwrap();
    let options = json!({"server":{"host":host,"port":port},"auth":"synthetic-node-password","tls":{"server_name":"localhost","ca_pem":certificate},"salamander_password":obfs,"limits":{"congestion":congestion}});
    let outbound = Hysteria2Outbound::from_options(&options).unwrap();
    let global = Arc::new(Semaphore::new(permits));
    let context = context(global.clone());
    let access = Arc::new(Echo::default());
    let task = {
        let access = access.clone();
        let context = context.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, context).await })
    };
    Fixture {
        outbound,
        options,
        context,
        task,
        access,
        global,
        certificate,
    }
}
async fn close(fixture: Fixture) {
    fixture.context.cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), fixture.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn complete_native_and_salamander_dual_stack_matrix() {
    for ipv6 in [false, true] {
        for salamander in [false, true] {
            for congestion in ["bbr", "reno"] {
                let fixture = start_fixture(ipv6, salamander, congestion, true, 128).await;
                let establish = ConnectContext::new(Duration::from_secs(5));
                for host in ["127.0.0.1", "::1", "example.invalid"] {
                    let target = Destination::new(host, 443).unwrap();
                    let mut stream = fixture
                        .outbound
                        .connect_tcp(&target, &establish)
                        .await
                        .unwrap();
                    let mut banner = [0; 12];
                    stream.read_exact(&mut banner).await.unwrap();
                    assert_eq!(&banner, b"server-first");
                    let data = vec![0x55; 96_000];
                    stream.write_all(&data).await.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut received = Vec::new();
                    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(received, data);
                    let mut channel = fixture
                        .outbound
                        .connect_udp(&target, &establish)
                        .await
                        .unwrap();
                    for data in [vec![], vec![1], vec![2; 4096], vec![3; 64000]] {
                        channel.sender.send(&data).await.unwrap();
                        let received =
                            tokio::time::timeout(Duration::from_secs(5), channel.receiver.recv())
                                .await
                                .unwrap()
                                .unwrap()
                                .unwrap();
                        assert_eq!(
                            received, data,
                            "ipv6={ipv6} obfs={salamander} congestion={congestion} host={host}"
                        );
                    }
                }
                let mut channel = fixture.outbound.associate_udp(&establish).await.unwrap();
                for host in ["127.0.0.1", "::1", "example.invalid"] {
                    let target = Destination::new(host, 53).unwrap();
                    channel
                        .sender
                        .send_to(b"same-session", &target)
                        .await
                        .unwrap();
                    let (source, received) =
                        tokio::time::timeout(Duration::from_secs(5), channel.receiver.recv_from())
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap();
                    assert_eq!(source, target);
                    assert_eq!(received, b"same-session");
                }
                assert_eq!(fixture.access.0.load(Ordering::Relaxed), 7);
                drop(channel);
                establish.cancel.cancel();
                close(fixture).await;
            }
        }
    }
}
#[tokio::test]
async fn authentication_tls_and_obfuscation_fail_without_target_access() {
    let fixture = start_fixture(false, false, "bbr", true, 128).await;
    let target = Destination::new("127.0.0.1", 1).unwrap();
    for (field, value) in [
        ("auth", json!("wrong-password")),
        (
            "tls",
            json!({"server_name":"wrong.invalid","ca_pem":fixture.certificate}),
        ),
    ] {
        let mut options = fixture.options.clone();
        options[field] = value;
        let outbound = Hysteria2Outbound::from_options(&options).unwrap();
        assert!(
            outbound
                .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
                .await
                .is_err()
        );
    }
    assert_eq!(fixture.access.0.load(Ordering::Relaxed), 0);
    close(fixture).await;
    let fixture = start_fixture(false, true, "bbr", true, 128).await;
    let mut options = fixture.options.clone();
    options["salamander_password"] = json!("wrong-salamander-password");
    let outbound = Hysteria2Outbound::from_options(&options).unwrap();
    assert!(
        outbound
            .connect_tcp(&target, &ConnectContext::new(Duration::from_millis(300)))
            .await
            .is_err()
    );
    assert_eq!(fixture.access.0.load(Ordering::Relaxed), 0);
    close(fixture).await;
}
#[tokio::test]
async fn udp_disabled_tcp_concurrency_and_cancel() {
    let fixture = start_fixture(false, false, "reno", false, 128).await;
    let target = Destination::new("example.invalid", 443).unwrap();
    let establish = ConnectContext::new(Duration::from_secs(5));
    assert!(
        fixture
            .outbound
            .connect_udp(&target, &establish)
            .await
            .is_err()
    );
    let mut streams = Vec::new();
    for _ in 0..8 {
        streams.push(
            fixture
                .outbound
                .connect_tcp(&target, &establish)
                .await
                .unwrap(),
        );
    }
    for stream in &mut streams {
        let mut banner = [0; 12];
        stream.read_exact(&mut banner).await.unwrap();
        stream.write_all(b"concurrent").await.unwrap();
        let mut data = [0; 10];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"concurrent");
    }
    fixture.context.cancel.cancel();
    fixture.task.await.unwrap().unwrap();
    for mut stream in streams {
        let mut data = [0; 1];
        let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut data))
            .await
            .unwrap();
        assert!(result.is_err() || result.unwrap() == 0);
    }
    assert_eq!(fixture.global.available_permits(), 128);
}
#[test]
fn rejects_invalid_configuration_and_preserves_node_credentials() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let node = json!({"auth":"first-node-secret","tls":{"certificate_pem":cert.cert.pem(),"private_key_pem":cert.signing_key.serialize_pem()}});
    let first = Hysteria2Node::from_options(&node).unwrap();
    assert!(first.requires_udp_association());
    assert!(!first.supports_tcp());
    assert!(first.supports_udp());
    let mut second = node.clone();
    second["auth"] = json!("second-node-secret");
    assert_ne!(
        first.credential_fingerprints(),
        Hysteria2Node::from_options(&second)
            .unwrap()
            .credential_fingerprints()
    );
    for (field, value) in [
        ("auth", json!("")),
        ("salamander_password", json!("x")),
        ("limits", json!({"congestion":"brutal"})),
        ("gecko", json!(true)),
        ("bandwidth", json!(1000)),
    ] {
        let mut options = node.clone();
        options[field] = value;
        assert!(Hysteria2Node::from_options(&options).is_err());
    }
}

async fn native_h3(
    fixture: &Fixture,
) -> (
    quinn::Endpoint,
    quinn::Connection,
    h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(&fixture.certificate)) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));
    let peer = format!(
        "127.0.0.1:{}",
        fixture.options["server"]["port"].as_u64().unwrap()
    );
    let connection = endpoint
        .connect(peer.parse().unwrap(), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    (endpoint, connection, sender, task)
}
async fn http_request(
    sender: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    auth: Option<&str>,
) -> u16 {
    use bytes::Buf;
    let mut request = http::Request::builder()
        .method(if auth.is_some() { "POST" } else { "GET" })
        .uri(if auth.is_some() {
            "https://hysteria/auth"
        } else {
            "https://hysteria/page"
        });
    if let Some(auth) = auth {
        request = request
            .header("hysteria-auth", auth)
            .header("hysteria-cc-rx", "0");
    }
    let mut stream = sender
        .send_request(request.body(()).unwrap())
        .await
        .unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let status = response.status().as_u16();
    let mut size = 0;
    while let Some(data) = stream.recv_data().await.unwrap() {
        size += data.remaining();
        assert!(size <= 65536);
    }
    status
}
fn native_request() -> Vec<u8> {
    let target = "example.invalid:443";
    let mut header = vec![0x44, 0x01, target.len() as u8];
    header.extend_from_slice(target.as_bytes());
    header.push(0);
    header
}
#[tokio::test]
async fn ordinary_h3_authentication_and_proxy_streams_share_one_dispatcher() {
    let fixture = start_fixture(false, false, "bbr", true, 128).await;
    let (endpoint, connection, mut sender, driver) = native_h3(&fixture).await;
    assert_eq!(http_request(&mut sender, None).await, 404);
    assert_eq!(http_request(&mut sender, Some("incorrect")).await, 404);
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    send.write_all(&native_request()).await.unwrap();
    send.finish().unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), receive.read_to_end(4096))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap().is_empty());
    assert_eq!(fixture.access.0.load(Ordering::Relaxed), 0);
    connection.close(0x100u32.into(), b"");
    endpoint.close(0x100u32.into(), b"");
    driver.abort();
    let (endpoint, connection, mut sender, driver) = native_h3(&fixture).await;
    assert_eq!(
        http_request(&mut sender, Some("synthetic-node-password")).await,
        233
    );
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    send.write_all(&native_request()).await.unwrap();
    let mut response = [0; 3];
    receive.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0, 0, 0]);
    let mut banner = [0; 12];
    receive.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"server-first");
    send.write_all(b"after-authentication").await.unwrap();
    assert_eq!(http_request(&mut sender, None).await, 404);
    send.finish().unwrap();
    assert_eq!(
        receive.read_to_end(4096).await.unwrap(),
        b"after-authentication"
    );
    assert_eq!(fixture.access.0.load(Ordering::Relaxed), 1);
    connection.close(0x100u32.into(), b"");
    endpoint.close(0x100u32.into(), b"");
    driver.abort();
    close(fixture).await;
}
#[tokio::test]
async fn shared_budget_rejects_new_streams_and_existing_streams_drain() {
    let fixture = start_fixture(false, false, "bbr", true, 3).await;
    let target = Destination::new("example.invalid", 443).unwrap();
    let establish = ConnectContext::new(Duration::from_secs(3));
    let mut streams = Vec::new();
    for _ in 0..2 {
        let mut stream = fixture
            .outbound
            .connect_tcp(&target, &establish)
            .await
            .unwrap();
        let mut banner = [0; 12];
        stream.read_exact(&mut banner).await.unwrap();
        streams.push(stream);
    }
    assert!(
        fixture
            .outbound
            .connect_tcp(&target, &establish)
            .await
            .is_err()
    );
    fixture.global.close();
    for stream in &mut streams {
        stream.write_all(b"drain").await.unwrap();
        let mut response = [0; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"drain");
    }
    drop(streams);
    fixture.context.cancel.cancel();
    fixture.task.await.unwrap().unwrap();
    assert_eq!(fixture.global.available_permits(), 3);
}

#[tokio::test]
async fn real_unified_egress_preserves_full_cone_source_port_and_zero_packets() {
    use kerlico_config::OutboundFactory;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let node=Hysteria2Node::from_options(&json!({"auth":"real-egress-secret","tls":{"certificate_pem":cert.cert.pem(),"private_key_pem":cert.signing_key.serialize_pem()}})).unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy = socket.local_addr().unwrap();
    let outbound=Hysteria2Outbound::from_options(&json!({"server":{"host":"127.0.0.1","port":proxy.port()},"auth":"real-egress-secret","tls":{"server_name":"localhost","ca_pem":cert.cert.pem()}})).unwrap();
    let direct = kerlico_net::DirectFactory.build(&json!({})).unwrap();
    let access = Arc::new(kerlico_egress::Egress::new(direct));
    let context = context(Arc::new(Semaphore::new(128)));
    let task = {
        let context = context.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, context).await })
    };
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let v6 = UdpSocket::bind(("::1", v4.local_addr().unwrap().port()))
        .await
        .unwrap();
    let target4 = Destination::new("127.0.0.1", v4.local_addr().unwrap().port()).unwrap();
    let target6 = Destination::new("::1", v6.local_addr().unwrap().port()).unwrap();
    let mut channel = outbound
        .associate_udp(&ConnectContext::new(Duration::from_secs(3)))
        .await
        .unwrap();
    let mut buffer = vec![0; 65536];
    channel.sender.send_to(b"four", &target4).await.unwrap();
    let (count, peer4) = tokio::time::timeout(Duration::from_secs(2), v4.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..count], b"four");
    v4.send_to(b"reply-four", peer4).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (target4.clone(), b"reply-four".to_vec())
    );
    channel.sender.send_to(b"six", &target6).await.unwrap();
    let (count, peer6) = tokio::time::timeout(Duration::from_secs(2), v6.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..count], b"six");
    assert_eq!(peer4.port(), peer6.port());
    v6.send_to(b"reply-six", peer6).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (target6, b"reply-six".to_vec())
    );
    let domain = Destination::new("localhost", target4.port()).unwrap();
    channel
        .sender
        .send_to(b"prefer-four", &domain)
        .await
        .unwrap();
    let (count, peer) = tokio::time::timeout(Duration::from_secs(2), v4.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..count], b"prefer-four");
    assert_eq!(peer.port(), peer4.port());
    let unsolicited = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    unsolicited.send_to(b"full-cone", peer4).await.unwrap();
    let source = Destination::new("127.0.0.1", unsolicited.local_addr().unwrap().port()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (source, b"full-cone".to_vec())
    );
    channel.sender.send_to(b"", &target4).await.unwrap();
    let (count, peer) = tokio::time::timeout(Duration::from_secs(2), v4.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(peer.port(), peer4.port());
    v4.send_to(b"", peer4).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (target4, vec![])
    );
    context.cancel.cancel();
    task.await.unwrap().unwrap();
}
