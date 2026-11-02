use super::*;
use kerlico_core::{
    CancellationToken, Capabilities, DatagramChannel, DatagramReceiver, DatagramSender, FamilyMode,
    NodeObserver, NodeTasks, OpenedTcp, Outbound, StreamBudget, TargetPolicy,
};
use kerlico_egress::{FlowEnd, FlowKind, Resolver, Telemetry};
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinHandle,
};

struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
struct NoDns;
impl Resolver for NoDns {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
        Box::pin(async { panic!("生命周期回归只使用字面目标") })
    }
}
struct Udp {
    io: Arc<UdpSocket>,
    target: Destination,
}
impl DatagramSender for Udp {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.io.send(packet).await?;
            Ok(())
        })
    }
}
impl DatagramReceiver for Udp {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut packet = vec![0; 65535];
            let count = self.io.recv(&mut packet).await?;
            packet.truncate(count);
            Ok(Some(packet))
        })
    }
}
#[derive(Default)]
struct Backend {
    sockets: Mutex<Vec<SocketAddr>>,
    tcp_targets: Mutex<Vec<Destination>>,
}
impl Outbound for Backend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            self.tcp_targets.lock().unwrap().push(target.clone());
            Ok(OpenedTcp {
                stream: Box::new(TcpStream::connect(target.to_string()).await?),
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            socket.connect(target.to_string()).await?;
            self.sockets.lock().unwrap().push(socket.local_addr()?);
            Ok(DatagramChannel {
                sender: Box::new(Udp {
                    io: socket.clone(),
                    target: target.clone(),
                }),
                receiver: Box::new(Udp {
                    io: socket,
                    target: target.clone(),
                }),
            })
        })
    }
}
enum Client {
    H2(h2::client::SendRequest<Bytes>),
    H3(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>),
}
impl Client {
    async fn reset_rejected_before_response(&mut self, gate: &RejectionGate) {
        let auth = config::Auth {
            username: "synthetic-user".into(),
            password: "wrong-synthetic-secret".into(),
        };
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(http::Uri::builder().authority("_check").build().unwrap())
            .header("user-agent", "protocol-regression")
            .header("proxy-authorization", auth.header())
            .body(())
            .unwrap();
        match self {
            Self::H2(sender) => {
                let mut sender = sender.clone().ready().await.unwrap();
                let (_response, mut send) = sender.send_request(request, false).unwrap();
                gate.entered.acquire().await.unwrap().forget();
                send.send_reset(h2::Reason::CANCEL);
            }
            Self::H3(sender) => {
                let mut stream = sender.send_request(request).await.unwrap();
                gate.entered.acquire().await.unwrap().forget();
                stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            }
        }
        let (status, _) = self.open("_check", true).await.unwrap();
        assert_eq!(status, 200, "放行拒绝响应前应完成 RST 之后的真实控制往返");
        gate.release.add_permits(1);
    }
    async fn open(&mut self, authority: &str, good: bool) -> Result<(u16, BoxStream)> {
        let authentication = config::Auth {
            username: "synthetic-user".into(),
            password: if good {
                "synthetic-secret"
            } else {
                "wrong-synthetic-secret"
            }
            .into(),
        };
        let uri = http::Uri::builder().authority(authority).build().unwrap();
        let control = authority == "_check";
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(uri)
            .header("user-agent", "protocol-regression")
            .header("proxy-authorization", authentication.header())
            .body(())
            .unwrap();
        match self {
            Self::H2(sender) => {
                let mut sender = sender.clone().ready().await.map_err(|_| protocol())?;
                let (response, send) = sender
                    .send_request(request, control)
                    .map_err(|_| protocol())?;
                let response = response.await.map_err(|_| protocol())?;
                let status = response.status().as_u16();
                Ok((
                    status,
                    BodyIo::boxed(Writer::H2(send), Reader::H2(response.into_body())),
                ))
            }
            Self::H3(sender) => {
                let mut stream = sender.send_request(request).await.map_err(|_| protocol())?;
                if control {
                    stream.finish().await.map_err(|_| protocol())?;
                }
                let status = stream
                    .recv_response()
                    .await
                    .map_err(|_| protocol())?
                    .status()
                    .as_u16();
                let (send, receive) = stream.split();
                Ok((
                    status,
                    BodyIo::boxed(Writer::Client(send), Reader::Client(receive)),
                ))
            }
        }
    }
}
#[derive(Clone)]
struct H2TlsOwner(Arc<Mutex<BoxStream>>);
impl AsyncRead for H2TlsOwner {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self.0.lock().unwrap()).poll_read(cx, output)
    }
}
impl AsyncWrite for H2TlsOwner {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut **self.0.lock().unwrap()).poll_write(cx, input)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self.0.lock().unwrap()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self.0.lock().unwrap()).poll_shutdown(cx)
    }
}
struct Fixture {
    client: Client,
    h2_tls: Option<H2TlsOwner>,
    driver: JoinHandle<()>,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    server: JoinHandle<Result<()>>,
    context: InboundContext,
    telemetry: Telemetry,
    backend: Arc<Backend>,
    address: SocketAddr,
    permits: Arc<Semaphore>,
    transport: Transport,
}
async fn fixture(transport: Transport) -> Fixture {
    fixture_node(transport, false).await
}
async fn fixture_node(transport: Transport, complete_node: bool) -> Fixture {
    fixture_options(
        transport,
        complete_node,
        TargetPolicy::Remote,
        FamilyMode::DualV4Preferred,
        None,
    )
    .await
}
async fn fixture_options(
    transport: Transport,
    complete_node: bool,
    policy: TargetPolicy,
    family: FamilyMode,
    rejection_gate: Option<Arc<RejectionGate>>,
) -> Fixture {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = certificate.cert.pem();
    let input = NodeBuildContext::for_test(
        json!({}),
        vec![json!({"username":"synthetic-user","password":"synthetic-secret"})],
    );
    let backend = Arc::new(Backend::default());
    let (access, telemetry) = kerlico_egress::testing::ingress_with_resolver(
        &input,
        backend.clone(),
        policy,
        family,
        Arc::new(NoDns),
    )
    .unwrap();
    let limits = Limits::default();
    let tls = config::server_tls(
        serde_json::from_value(json!({
            "certificate_pem":pem, "private_key_pem":certificate.signing_key.serialize_pem()
        }))
        .unwrap(),
        transport,
    )
    .unwrap();
    let node = Node {
        tls,
        users: input
            .credentials(vec![config::Auth {
                username: "synthetic-user".into(),
                password: "synthetic-secret".into(),
            }])
            .unwrap(),
        transport,
        udp: true,
        limits,
        rejection_gate,
    };
    let cancel = CancellationToken::new();
    let permits = Arc::new(Semaphore::new(32));
    let mut context = InboundContext {
        peer_lease: None,
        tasks: NodeTasks::new(input.issuer().node().clone(), cancel.clone()),
        cancel,
        peer_addr: None,
        local_addr: None,
        events: Arc::new(Observer),
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65507,
        max_streams: 16,
        stream_budget: StreamBudget::new(permits.clone(), Arc::new(Semaphore::new(32))),
    };
    let (client_tls, _) = config::client_tls(
        serde_json::from_value(json!({"server_name":"localhost","ca_pem":pem})).unwrap(),
        transport,
    )
    .unwrap();
    if transport == Transport::H2 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_context = context.clone();
        let serving = async move {
            let (socket, _) = listener.accept().await?;
            node.tcp(Box::new(socket), access, server_context).await
        };
        let server = if complete_node {
            let owned = context.tasks.spawn_tracked(serving).unwrap();
            tokio::spawn(async move { owned.await? })
        } else {
            tokio::spawn(serving)
        };
        let socket = TcpStream::connect(address).await.unwrap();
        let socket = tokio_rustls::TlsConnector::from(client_tls)
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                socket,
            )
            .await
            .unwrap();
        let h2_tls = H2TlsOwner(Arc::new(Mutex::new(Box::new(socket))));
        let (sender, driver) = h2::client::handshake(h2_tls.clone()).await.unwrap();
        let driver = tokio::spawn(async move {
            let result = driver.await;
            eprintln!("TrustTunnel H2 夹具客户端驱动结束：{result:?}");
        });
        Fixture {
            client: Client::H2(sender),
            h2_tls: Some(h2_tls),
            driver,
            endpoint: None,
            connection: None,
            server,
            context,
            telemetry,
            backend,
            address,
            permits,
            transport,
        }
    } else {
        let (address, server) = if complete_node {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let address = socket.local_addr().unwrap();
            let server_context = context.clone();
            let owned = context
                .tasks
                .spawn_tracked(async move { node.quic(socket, access, server_context).await })
                .unwrap();
            let server = tokio::spawn(async move { owned.await? });
            (address, server)
        } else {
            let runtime = crate::runtime::NodeRuntime::new(&context.cancel, context.tasks.clone());
            context.cancel = runtime.cancel();
            let crypto =
                quinn::crypto::rustls::QuicServerConfig::try_from((*node.tls).clone()).unwrap();
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            server_config.transport_config(node.limits.quic(context.max_streams).unwrap());
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let address = socket.local_addr().unwrap();
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                socket,
                runtime.clone(),
            )
            .unwrap();
            let server_context = context.clone();
            let server = tokio::spawn(async move {
                let _guard = runtime.guard();
                let incoming = endpoint.accept().await.ok_or_else(protocol)?;
                let connection = incoming.await.map_err(|_| protocol())?;
                let drain = Arc::new(QuicDrain::default());
                let result = node
                    .h3(connection, access, server_context.clone(), drain.clone())
                    .await;
                let deadline = drain
                    .window(&server_context)
                    .unwrap_or_else(|| DrainWindow::new(server_context.drain_timeout))
                    .deadline;
                runtime
                    .shutdown_at(endpoint, &mut JoinSet::new(), deadline)
                    .await?;
                result
            });
            (address, server)
        };
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from((*client_tls).clone()).unwrap();
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Limits::default().quic(16).unwrap());
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Fixture {
            client: Client::H3(sender),
            h2_tls: None,
            driver,
            endpoint: Some(endpoint),
            connection: Some(connection),
            server,
            context,
            telemetry,
            backend,
            address,
            permits,
            transport,
        }
    }
}
async fn finish(fixture: Fixture, mut active: BoxStream, kind: FlowKind) {
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), fixture.server)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Rejected)
    ));
    let mut tail = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), active.read_to_end(&mut tail))
        .await
        .unwrap();
    assert!(tail.is_empty(), "载体拒绝后不能伪造业务尾部");
    drop(active);
    if let Some(connection) = &fixture.connection {
        connection.close(0x100u32.into(), b"");
    }
    if let Some(endpoint) = &fixture.endpoint {
        endpoint.close(0x100u32.into(), b"");
    }
    tokio::time::timeout(Duration::from_secs(2), fixture.driver)
        .await
        .unwrap()
        .unwrap();
    assert!(
        fixture
            .context
            .tasks
            .shutdown_at(tokio::time::Instant::now() + fixture.context.drain_timeout)
            .await
            .is_clean()
    );
    if let Some(endpoint) = &fixture.endpoint {
        endpoint.wait_idle().await;
    }
    drop(fixture.client);
    drop(fixture.connection);
    drop(fixture.endpoint);
    let records = fixture.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 1, "错误鉴权不能产生第二条业务账本");
    assert_eq!(records[0].kind, kind);
    assert_eq!(records[0].end, Some(FlowEnd::Failed));
    assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 0);
    assert_eq!(fixture.permits.available_permits(), 32);
    for address in fixture.backend.sockets.lock().unwrap().iter() {
        let _released = std::net::UdpSocket::bind(address).unwrap();
    }
    if fixture.transport == Transport::H3 {
        let _rebound = std::net::UdpSocket::bind(fixture.address).unwrap();
    } else {
        let _rebound = TcpListener::bind(fixture.address).await.unwrap();
    }
}
async fn rejected_with_active_tcp(transport: Transport) {
    let mut fixture = fixture(transport).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut packet = [0; 6];
        socket.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"active");
        socket.write_all(b"echoed").await.unwrap();
        let mut tail = Vec::new();
        let _ = socket.read_to_end(&mut tail).await;
        tail
    });
    let (status, mut active) = fixture
        .client
        .open(&address.to_string(), true)
        .await
        .unwrap();
    assert_eq!(status, 200);
    active.write_all(b"active").await.unwrap();
    active.flush().await.unwrap();
    let mut echoed = [0; 6];
    active.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"echoed");
    assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 1);
    assert!(fixture.telemetry.records(0, 8).unwrap()[0].end.is_none());
    let denied = fixture.client.open("_check", false).await;
    if let Ok((status, _)) = denied {
        assert_eq!(status, 407);
    }
    let telemetry = fixture.telemetry.clone();
    finish(fixture, active, FlowKind::Tcp).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), target_task)
            .await
            .unwrap()
            .unwrap()
            .is_empty()
    );
    let record = telemetry.records(0, 8).unwrap().pop().unwrap();
    assert_eq!(record.usage.upload_bytes, 6);
    assert_eq!(record.usage.download_bytes, 6);
}
async fn rejected_with_active_udp(transport: Transport) {
    let mut fixture = fixture(transport).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let source: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let (status, mut active) = fixture.client.open("_udp2", true).await.unwrap();
    assert_eq!(status, 200);
    let bytes = crate::udp::encode(
        crate::udp::Endpoint::Specified(source),
        crate::udp::Endpoint::Specified(address),
        Some(""),
        b"active-udp",
        65507,
    )
    .unwrap();
    active.write_all(&bytes).await.unwrap();
    active.flush().await.unwrap();
    let mut packet = [0; 32];
    let (count, peer) = tokio::time::timeout(Duration::from_secs(1), target.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&packet[..count], b"active-udp");
    target.send_to(b"echoed-udp", peer).await.unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        crate::udp::read(&mut active, false, 65507),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(reply.source, crate::udp::Endpoint::Specified(address));
    assert_eq!(reply.target, crate::udp::Endpoint::Specified(source));
    assert_eq!(reply.data, b"echoed-udp");
    assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 1);
    assert!(fixture.telemetry.records(0, 8).unwrap()[0].end.is_none());
    let denied = fixture.client.open("_check", false).await;
    if let Ok((status, _)) = denied {
        assert_eq!(status, 407);
    }
    let telemetry = fixture.telemetry.clone();
    finish(fixture, active, FlowKind::FixedUdp).await;
    let record = telemetry.records(0, 8).unwrap().pop().unwrap();
    assert_eq!(record.usage.upload_packets, 1);
    assert_eq!(record.usage.download_packets, 1);
}
#[tokio::test]
async fn h2_rejected_request_fails_concurrent_tcp_and_joins_socket_owner() {
    rejected_with_active_tcp(Transport::H2).await;
}
#[tokio::test]
async fn h3_rejected_request_fails_concurrent_tcp_and_joins_socket_owner() {
    rejected_with_active_tcp(Transport::H3).await;
}
#[tokio::test]
async fn h2_rejected_request_fails_concurrent_udp_and_releases_target_socket() {
    rejected_with_active_udp(Transport::H2).await;
}
#[tokio::test]
async fn h3_rejected_request_fails_concurrent_udp_and_releases_target_socket() {
    rejected_with_active_udp(Transport::H3).await;
}

mod rejection_kind_tests {
    use super::*;

    async fn active_tcp(fixture: &mut Fixture) -> (BoxStream, JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 32];
            let mut total = 0;
            loop {
                let count = match socket.read(&mut bytes).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => count,
                };
                total += count;
                if socket.write_all(&bytes[..count]).await.is_err() {
                    break;
                }
            }
            let _ = socket.shutdown().await;
            total
        });
        let (status, mut active) = fixture
            .client
            .open(&address.to_string(), true)
            .await
            .unwrap();
        assert_eq!(status, 200);
        exchange(&mut active, b"before").await;
        (active, target)
    }
    async fn exchange(active: &mut BoxStream, bytes: &[u8; 6]) {
        active.write_all(bytes).await.unwrap();
        active.flush().await.unwrap();
        let mut received = [0; 6];
        tokio::time::timeout(Duration::from_secs(1), active.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, bytes);
    }
    async fn policy_rejection(transport: Transport) {
        let mut fixture = fixture_options(
            transport,
            true,
            TargetPolicy::Local,
            FamilyMode::V4Only,
            None,
        )
        .await;
        let (mut active, target) = active_tcp(&mut fixture).await;
        let active_id = fixture.telemetry.records(0, 8).unwrap()[0].id;
        let (status, denied) = fixture.client.open("[::1]:443", true).await.unwrap();
        assert_eq!(status, 502, "合法凭据的目标策略拒绝应只返回本请求访问失败");
        drop(denied);
        assert_eq!(
            fixture.backend.tcp_targets.lock().unwrap().len(),
            1,
            "单栈策略拒绝应发生在真实出口拨号前"
        );
        assert!(
            !fixture.server.is_finished(),
            "目标拒绝不能终止同载体的正常请求"
        );
        assert!(
            fixture
                .telemetry
                .records(0, 8)
                .unwrap()
                .iter()
                .find(|record| record.id == active_id)
                .unwrap()
                .end
                .is_none()
        );
        exchange(&mut active, b"after!").await;
        let (status, _) = fixture.client.open("_check", true).await.unwrap();
        assert_eq!(status, 200, "同一已鉴权载体仍接受合法控制请求");
        active.shutdown().await.unwrap();
        let deadline = tokio::time::Instant::now()
            + fixture.context.drain_timeout
            + Duration::from_millis(100);
        fixture.permits.close();
        tokio::time::timeout_at(deadline, &mut fixture.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut tail = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(1), active.read_to_end(&mut tail))
            .await
            .unwrap();
        assert!(tail.is_empty());
        if let Some(connection) = &fixture.connection {
            tokio::time::timeout(Duration::from_secs(1), connection.closed())
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), fixture.driver)
            .await
            .unwrap()
            .unwrap();
        if let Some(mut h2_tls) = fixture.h2_tls.take() {
            let mut extra = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), h2_tls.read_to_end(&mut extra))
                .await
                .unwrap()
                .unwrap();
            let mut remaining = extra.as_slice();
            while !remaining.is_empty() {
                assert!(remaining.len() >= 9, "关闭控制帧头必须完整");
                let length = (usize::from(remaining[0]) << 16)
                    | (usize::from(remaining[1]) << 8)
                    | usize::from(remaining[2]);
                assert!(remaining.len() >= 9 + length, "关闭控制帧负载必须完整");
                let kind = remaining[3];
                let stream = u32::from_be_bytes(remaining[5..9].try_into().unwrap());
                assert_eq!(stream, 0, "关闭后不得残留业务流帧");
                match kind {
                    6 => assert_eq!(length, 8, "PING负载长度固定为8"),
                    7 => {
                        assert!(length >= 8);
                        assert_eq!(&remaining[13..17], &[0; 4], "正常GOAWAY必须为NO_ERROR");
                    }
                    _ => panic!("关闭后残留非预期HTTP/2帧 {kind}"),
                }
                eprintln!("TrustTunnel H2 正常关闭残余控制帧：type={kind},length={length}");
                remaining = &remaining[9 + length..];
            }
            tokio::time::timeout(Duration::from_secs(1), h2_tls.shutdown())
                .await
                .unwrap()
                .unwrap();
        }
        drop(active);
        assert!(fixture.context.tasks.shutdown_at(deadline).await.is_clean());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), target)
                .await
                .unwrap()
                .unwrap(),
            12
        );
        let records = fixture.telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 2);
        let kept = records
            .iter()
            .find(|record| record.id == active_id)
            .unwrap();
        assert_eq!(kept.end, Some(FlowEnd::Completed));
        assert_eq!(kept.usage.upload_bytes, 12);
        assert_eq!(kept.usage.download_bytes, 12);
        let rejected = records
            .iter()
            .find(|record| record.id != active_id)
            .unwrap();
        assert_eq!(rejected.end, Some(FlowEnd::Failed));
        assert_eq!(rejected.usage, kerlico_egress::Usage::default());
        assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 0);
        assert_eq!(fixture.permits.available_permits(), 32);
        drop(fixture.client);
        drop(fixture.connection);
        if let Some(endpoint) = fixture.endpoint {
            endpoint.close(0x100u32.into(), b"");
            tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
                .await
                .unwrap();
            let _rebound = std::net::UdpSocket::bind(fixture.address).unwrap();
        } else {
            let _rebound = TcpListener::bind(fixture.address).await.unwrap();
        }
    }
    async fn reset_authentication_rejection(transport: Transport) {
        let gate = Arc::new(RejectionGate {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            send_failed: std::sync::atomic::AtomicBool::new(false),
        });
        let mut fixture = fixture_options(
            transport,
            false,
            TargetPolicy::Remote,
            FamilyMode::DualV4Preferred,
            Some(gate.clone()),
        )
        .await;
        let (active, target) = active_tcp(&mut fixture).await;
        let telemetry = fixture.telemetry.clone();
        tokio::time::timeout(
            Duration::from_secs(2),
            fixture.client.reset_rejected_before_response(&gate),
        )
        .await
        .unwrap();
        finish(fixture, active, FlowKind::Tcp).await;
        assert!(
            gate.send_failed.load(std::sync::atomic::Ordering::Acquire),
            "真实 RST 必须使实际 407 发送失败"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), target)
                .await
                .unwrap()
                .unwrap(),
            6
        );
        let record = telemetry.records(0, 8).unwrap().pop().unwrap();
        assert_eq!(record.end, Some(FlowEnd::Failed));
        assert_eq!(record.usage.upload_bytes, 6);
        assert_eq!(record.usage.download_bytes, 6);
    }

    #[tokio::test]
    async fn h3_stream_budget_rejection_keeps_concurrent_tcp_alive() {
        let mut fixture = fixture_node(Transport::H3, true).await;
        let (mut active, target) = active_tcp(&mut fixture).await;
        let held = fixture
            .permits
            .clone()
            .acquire_many_owned(fixture.permits.available_permits() as u32)
            .await
            .unwrap();
        let Client::H3(sender) = &mut fixture.client else {
            panic!("预算拒绝回归必须使用真实 H3 客户端");
        };
        let auth = config::Auth {
            username: "synthetic-user".into(),
            password: "synthetic-secret".into(),
        };
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(
                http::Uri::builder()
                    .authority("127.0.0.1:443")
                    .build()
                    .unwrap(),
            )
            .header("user-agent", "protocol-regression")
            .header("proxy-authorization", auth.header())
            .body(())
            .unwrap();
        let mut denied = sender.send_request(request).await.unwrap();
        let error = tokio::time::timeout(Duration::from_millis(400), denied.recv_response())
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(
                error,
                h3::error::StreamError::RemoteTerminate {
                    code: h3::error::Code::H3_REQUEST_REJECTED,
                    ..
                }
            ),
            "预算不足必须只拒绝新流，实际为 {error:?}"
        );
        drop(denied);
        assert_eq!(fixture.backend.tcp_targets.lock().unwrap().len(), 1);
        assert_eq!(fixture.telemetry.records(0, 8).unwrap().len(), 1);
        assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 1);
        assert!(!fixture.server.is_finished());
        assert!(
            fixture
                .connection
                .as_ref()
                .unwrap()
                .close_reason()
                .is_none()
        );
        exchange(&mut active, b"after!").await;
        drop(held);
        let (status, _) = fixture.client.open("_check", true).await.unwrap();
        assert_eq!(status, 200, "归还配额后同载体应继续接受合法请求");
        active.shutdown().await.unwrap();
        let deadline = tokio::time::Instant::now()
            + fixture.context.drain_timeout
            + Duration::from_millis(100);
        fixture.permits.close();
        tokio::time::timeout_at(deadline, &mut fixture.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut tail = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(1), active.read_to_end(&mut tail))
            .await
            .unwrap();
        assert!(tail.is_empty());
        tokio::time::timeout(
            Duration::from_secs(1),
            fixture.connection.as_ref().unwrap().closed(),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), fixture.driver)
            .await
            .unwrap()
            .unwrap();
        drop(active);
        assert!(fixture.context.tasks.shutdown_at(deadline).await.is_clean());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), target)
                .await
                .unwrap()
                .unwrap(),
            12
        );
        let records = fixture.telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].end, Some(FlowEnd::Completed));
        assert_eq!(records[0].usage.upload_bytes, 12);
        assert_eq!(records[0].usage.download_bytes, 12);
        assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 0);
        assert_eq!(fixture.permits.available_permits(), 32);
        drop(fixture.client);
        drop(fixture.connection);
        let endpoint = fixture.endpoint.unwrap();
        endpoint.close(0x100u32.into(), b"");
        tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
            .await
            .unwrap();
        let _rebound = std::net::UdpSocket::bind(fixture.address).unwrap();
    }

    #[tokio::test]
    async fn h2_valid_credentials_target_policy_rejection_keeps_concurrent_tcp_alive() {
        policy_rejection(Transport::H2).await;
    }
    #[tokio::test]
    async fn h3_valid_credentials_target_policy_rejection_keeps_concurrent_tcp_alive() {
        policy_rejection(Transport::H3).await;
    }
    #[tokio::test]
    async fn h2_reset_before_407_keeps_authentication_rejection_and_fails_concurrent_tcp() {
        reset_authentication_rejection(Transport::H2).await;
    }
    #[tokio::test]
    async fn h3_reset_before_407_keeps_authentication_rejection_and_fails_concurrent_tcp() {
        reset_authentication_rejection(Transport::H3).await;
    }
}

mod drain_tests {
    use super::*;

    async fn begin(fixture: &mut Fixture) -> tokio::time::Instant {
        let started = tokio::time::Instant::now();
        fixture.permits.close();
        tokio::time::timeout(Duration::from_millis(400), async {
            loop {
                match fixture.client.open("_check", true).await {
                    Err(_) => break,
                    Ok((status, _)) => assert_eq!(status, 503),
                }
            }
        })
        .await
        .expect("客户端应观察到节点停止接纳新 CONNECT");
        assert!(!fixture.server.is_finished(), "已有业务仍应存活");
        assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 1);
        assert!(fixture.telemetry.records(0, 8).unwrap()[0].end.is_none());
        started
    }

    async fn finish_drain(
        mut fixture: Fixture,
        mut active: BoxStream,
        kind: FlowKind,
        end: FlowEnd,
        started: tokio::time::Instant,
    ) -> kerlico_egress::FlowRecord {
        let deadline = started + fixture.context.drain_timeout + Duration::from_millis(100);
        let result = tokio::time::timeout_at(deadline, &mut fixture.server)
            .await
            .expect("节点总排空预算不能在清理阶段重新开始")
            .unwrap();
        if end == FlowEnd::Timeout {
            assert!(
                matches!(result, Err(Error::Timeout)),
                "仍活跃业务到期应返回 Timeout，实际为 {result:?}"
            );
        } else {
            result.expect("已结束请求的节点收尾应成功");
        }
        let mut tail = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(1), active.read_to_end(&mut tail))
            .await
            .expect("对端必须实际关闭业务流");
        assert!(tail.is_empty(), "关闭不能伪造或重复最后业务包");
        if let Some(connection) = &fixture.connection {
            tokio::time::timeout(Duration::from_secs(1), connection.closed())
                .await
                .expect("完整节点必须实际关闭 QUIC 连接");
        }
        tokio::time::timeout(Duration::from_secs(1), fixture.driver)
            .await
            .expect("协议驱动应随服务端关闭而退出")
            .unwrap();
        drop(active);
        let report = fixture.context.tasks.shutdown_at(deadline).await;
        assert!(report.is_clean(), "实际 NodeTasks 未回收，{report:?}");
        if let Some(endpoint) = &fixture.endpoint {
            endpoint.close(0x100u32.into(), b"");
        }
        drop(fixture.client);
        drop(fixture.connection);
        if let Some(endpoint) = fixture.endpoint {
            tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
                .await
                .unwrap();
        }
        let records = fixture.telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 1, "排空控制请求不能建立第二条业务记录");
        let record = records.into_iter().next().unwrap();
        assert_eq!(record.kind, kind);
        assert_eq!(record.end, Some(end));
        let usage = fixture.telemetry.usage().unwrap();
        assert_eq!(usage.active_flows, 0);
        assert_eq!(usage.engine.upload_bytes, record.usage.upload_bytes);
        assert_eq!(usage.engine.download_bytes, record.usage.download_bytes);
        assert_eq!(fixture.permits.available_permits(), 32);
        for address in fixture.backend.sockets.lock().unwrap().iter() {
            let _released = std::net::UdpSocket::bind(address).expect("目标 UDP socket 应已释放");
        }
        if fixture.transport == Transport::H3 {
            let _rebound =
                std::net::UdpSocket::bind(fixture.address).expect("节点 UDP 监听应已释放");
        } else {
            let _rebound = TcpListener::bind(fixture.address)
                .await
                .expect("节点 TCP 监听应已释放");
        }
        record
    }

    fn stop_business(fixture: &Fixture, end: FlowEnd) {
        if end == FlowEnd::Failed {
            fixture
                .connection
                .as_ref()
                .expect("真实载体失败用例使用完整 H3 节点")
                .close(0x1fu32.into(), b"");
        }
    }

    async fn tcp(transport: Transport, end: FlowEnd) {
        let mut fixture = fixture_node(transport, true).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut initial = [0; 6];
            socket.read_exact(&mut initial).await.unwrap();
            assert_eq!(&initial, b"active");
            socket.write_all(b"echoed").await.unwrap();
            let mut last = [0; 4];
            socket.read_exact(&mut last).await.unwrap();
            assert_eq!(&last, b"last");
            socket.write_all(b"last").await.unwrap();
            let mut tail = Vec::new();
            let _ = socket.read_to_end(&mut tail).await;
            let _ = socket.shutdown().await;
            tail
        });
        let (status, mut active) = fixture
            .client
            .open(&address.to_string(), true)
            .await
            .unwrap();
        assert_eq!(status, 200);
        active.write_all(b"active").await.unwrap();
        active.flush().await.unwrap();
        let mut initial = [0; 6];
        active.read_exact(&mut initial).await.unwrap();
        assert_eq!(&initial, b"echoed");
        let started = begin(&mut fixture).await;
        active.write_all(b"last").await.unwrap();
        active.flush().await.unwrap();
        let mut last = [0; 4];
        tokio::time::timeout(Duration::from_millis(400), active.read_exact(&mut last))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&last, b"last", "停止准入后既有 TCP 仍可收发");
        if end == FlowEnd::Completed {
            active.shutdown().await.unwrap();
        }
        stop_business(&fixture, end);
        let record = finish_drain(fixture, active, FlowKind::Tcp, end, started).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), target_task)
                .await
                .expect("真实目标 TCP 所有者应退出")
                .unwrap()
                .is_empty()
        );
        assert_eq!(record.usage.upload_bytes, 10);
        assert_eq!(record.usage.download_bytes, 10);
    }

    async fn exchange_udp(
        active: &mut BoxStream,
        target: &UdpSocket,
        source: SocketAddr,
        data: &[u8],
        reply: &[u8],
    ) {
        let address = target.local_addr().unwrap();
        let bytes = crate::udp::encode(
            crate::udp::Endpoint::Specified(source),
            crate::udp::Endpoint::Specified(address),
            Some(""),
            data,
            65507,
        )
        .unwrap();
        active.write_all(&bytes).await.unwrap();
        active.flush().await.unwrap();
        let mut packet = [0; 32];
        let (count, peer) =
            tokio::time::timeout(Duration::from_millis(400), target.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&packet[..count], data);
        target.send_to(reply, peer).await.unwrap();
        let received = tokio::time::timeout(
            Duration::from_millis(400),
            crate::udp::read(active, false, 65507),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(received.source, crate::udp::Endpoint::Specified(address));
        assert_eq!(received.target, crate::udp::Endpoint::Specified(source));
        assert_eq!(received.data, reply);
    }

    async fn udp(transport: Transport, end: FlowEnd) {
        let mut fixture = fixture_node(transport, true).await;
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = "127.0.0.1:10001".parse().unwrap();
        let (status, mut active) = fixture.client.open("_udp2", true).await.unwrap();
        assert_eq!(status, 200);
        exchange_udp(&mut active, &target, source, b"active-udp", b"echoed-udp").await;
        let started = begin(&mut fixture).await;
        exchange_udp(&mut active, &target, source, b"last-udp", b"tail-udp").await;
        if end == FlowEnd::Completed {
            active.shutdown().await.unwrap();
        }
        stop_business(&fixture, end);
        let record = finish_drain(fixture, active, FlowKind::FixedUdp, end, started).await;
        assert_eq!(record.usage.upload_bytes, 18);
        assert_eq!(record.usage.download_bytes, 18);
        assert_eq!(record.usage.upload_packets, 2);
        assert_eq!(record.usage.download_packets, 2);
    }

    #[tokio::test]
    async fn h2_node_drain_deadline_records_tcp_timeout_and_joins_socket_owner() {
        tcp(Transport::H2, FlowEnd::Timeout).await;
    }
    #[tokio::test]
    async fn h3_full_node_drain_deadline_records_tcp_timeout_and_joins_socket_owner() {
        tcp(Transport::H3, FlowEnd::Timeout).await;
    }
    #[tokio::test]
    async fn h2_node_drain_deadline_records_udp_timeout_and_releases_target_socket() {
        udp(Transport::H2, FlowEnd::Timeout).await;
    }
    #[tokio::test]
    async fn h3_full_node_drain_deadline_records_udp_timeout_and_releases_target_socket() {
        udp(Transport::H3, FlowEnd::Timeout).await;
    }
    #[tokio::test]
    async fn h2_node_drain_keeps_completed_tcp_and_final_usage() {
        tcp(Transport::H2, FlowEnd::Completed).await;
    }
    #[tokio::test]
    async fn h3_full_node_drain_keeps_completed_tcp_and_final_usage() {
        tcp(Transport::H3, FlowEnd::Completed).await;
    }
    #[tokio::test]
    async fn h2_node_drain_keeps_completed_udp_and_final_usage() {
        udp(Transport::H2, FlowEnd::Completed).await;
    }
    #[tokio::test]
    async fn h3_full_node_drain_keeps_completed_udp_and_final_usage() {
        udp(Transport::H3, FlowEnd::Completed).await;
    }
    #[tokio::test]
    async fn h3_full_node_transport_failure_during_tcp_drain_preserves_failed() {
        tcp(Transport::H3, FlowEnd::Failed).await;
    }
    #[tokio::test]
    async fn h3_full_node_transport_failure_during_udp_drain_preserves_failed() {
        udp(Transport::H3, FlowEnd::Failed).await;
    }
}
