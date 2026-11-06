use super::*;
use bytes::Buf as _;
use h3::quic;
use kerlico_core::{
    AddressedDatagram, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, Destination,
    FamilyMode, NodeObserver, NodeTasks, OpenedTcp, Outbound, StreamBudget, TargetPolicy,
};
use kerlico_egress::{FlowEnd, FlowKind, Resolver, Telemetry};
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::AtomicUsize,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, oneshot},
    task::JoinHandle,
};

#[derive(Default)]
struct Events {
    accepted: AtomicUsize,
    failed: AtomicUsize,
}
impl NodeObserver for Events {
    fn record(&self, event: NodeEvent) {
        match event {
            NodeEvent::Accepted => {
                self.accepted.fetch_add(1, Ordering::AcqRel);
            }
            NodeEvent::Failed => {
                self.failed.fetch_add(1, Ordering::AcqRel);
            }
            _ => {}
        }
    }
}
#[derive(Clone, Copy)]
enum ControlField {
    StreamType,
    FrameType,
    Length(u64),
    Payload { remaining: u64, goaway: bool },
    OtherStream,
}
struct ControlRecv {
    inner: h3_quinn::RecvStream,
    field: ControlField,
    varint: Vec<u8>,
    goaway: Arc<Notify>,
}
impl ControlRecv {
    fn observe(&mut self, bytes: &[u8]) {
        for byte in bytes {
            match &mut self.field {
                ControlField::OtherStream => return,
                ControlField::Payload { remaining, goaway } => {
                    *remaining -= 1;
                    if *remaining == 0 {
                        if *goaway {
                            self.goaway.notify_one();
                        }
                        self.field = ControlField::FrameType;
                    }
                    continue;
                }
                _ => {}
            }
            self.varint.push(*byte);
            let width = 1usize << (self.varint[0] >> 6);
            if self.varint.len() < width {
                continue;
            }
            let value = self.varint[1..]
                .iter()
                .fold(u64::from(self.varint[0] & 63), |value, byte| {
                    (value << 8) | u64::from(*byte)
                });
            self.varint.clear();
            self.field = match self.field {
                ControlField::StreamType if value == 0 => ControlField::FrameType,
                ControlField::StreamType => ControlField::OtherStream,
                ControlField::FrameType => ControlField::Length(value),
                ControlField::Length(_) if value == 0 => ControlField::FrameType,
                ControlField::Length(kind) => ControlField::Payload {
                    remaining: value,
                    goaway: kind == 7,
                },
                _ => unreachable!(),
            };
        }
    }
}
impl quic::RecvStream for ControlRecv {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Option<Bytes>, quic::StreamErrorIncoming>> {
        let result = self.inner.poll_data(cx);
        if let Poll::Ready(Ok(Some(bytes))) = &result {
            self.observe(bytes);
        }
        result
    }
    fn stop_sending(&mut self, code: u64) {
        self.inner.stop_sending(code);
    }
    fn recv_id(&self) -> quic::StreamId {
        self.inner.recv_id()
    }
}
type SharedSend = Arc<Mutex<h3_quinn::SendStream<Bytes>>>;
#[derive(Default)]
struct ControlSend {
    stream: Mutex<Option<SharedSend>>,
}
impl ControlSend {
    fn wrap(self: &Arc<Self>, stream: h3_quinn::SendStream<Bytes>) -> ClientSend {
        ClientSend {
            inner: Arc::new(Mutex::new(stream)),
            control: self.clone(),
            first_write: true,
        }
    }
    fn reset(&self) {
        let stream = self
            .stream
            .lock()
            .unwrap()
            .as_ref()
            .expect("真实 H3 控制流必须先发送类型和 SETTINGS")
            .clone();
        quic::SendStream::reset(&mut *stream.lock().unwrap(), 0x1f);
    }
}
struct ClientSend {
    inner: SharedSend,
    control: Arc<ControlSend>,
    first_write: bool,
}
impl quic::SendStream<Bytes> for ClientSend {
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), quic::StreamErrorIncoming>> {
        quic::SendStream::poll_ready(&mut *self.inner.lock().unwrap(), cx)
    }
    fn send_data<T: Into<quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> std::result::Result<(), quic::StreamErrorIncoming> {
        let data: quic::WriteBuf<Bytes> = data.into();
        if self.first_write {
            if data.chunk().first() == Some(&0) {
                let previous = self
                    .control
                    .stream
                    .lock()
                    .unwrap()
                    .replace(self.inner.clone());
                assert!(previous.is_none(), "只能捕获一条真实 H3 控制发送流");
            }
            self.first_write = false;
        }
        quic::SendStream::send_data(&mut *self.inner.lock().unwrap(), data)
    }
    fn poll_finish(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), quic::StreamErrorIncoming>> {
        quic::SendStream::poll_finish(&mut *self.inner.lock().unwrap(), cx)
    }
    fn reset(&mut self, code: u64) {
        quic::SendStream::reset(&mut *self.inner.lock().unwrap(), code);
    }
    fn send_id(&self) -> quic::StreamId {
        quic::SendStream::send_id(&*self.inner.lock().unwrap())
    }
}
struct ClientOpen {
    inner: h3_quinn::OpenStreams,
    control: Arc<ControlSend>,
}
impl quic::OpenStreams<Bytes> for ClientOpen {
    type BidiStream = h3_quinn::BidiStream<Bytes>;
    type SendStream = ClientSend;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Self::BidiStream, quic::StreamErrorIncoming>> {
        self.inner.poll_open_bidi(cx)
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Self::SendStream, quic::StreamErrorIncoming>> {
        self.inner
            .poll_open_send(cx)
            .map_ok(|stream| self.control.wrap(stream))
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}
struct ClientConnection {
    inner: h3_quinn::Connection,
    goaway: Arc<Notify>,
    control: Arc<ControlSend>,
}
impl quic::OpenStreams<Bytes> for ClientConnection {
    type BidiStream = h3_quinn::BidiStream<Bytes>;
    type SendStream = ClientSend;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Self::BidiStream, quic::StreamErrorIncoming>> {
        self.inner.poll_open_bidi(cx)
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Self::SendStream, quic::StreamErrorIncoming>> {
        self.inner
            .poll_open_send(cx)
            .map_ok(|stream| self.control.wrap(stream))
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}
impl quic::Connection<Bytes> for ClientConnection {
    type RecvStream = ControlRecv;
    type OpenStreams = ClientOpen;
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<ControlRecv, quic::ConnectionErrorIncoming>> {
        let goaway = self.goaway.clone();
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.inner, cx)
            .map_ok(|inner| ControlRecv {
                inner,
                field: ControlField::StreamType,
                varint: Vec::new(),
                goaway,
            })
    }
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Self::BidiStream, quic::ConnectionErrorIncoming>> {
        self.inner.poll_accept_bidi(cx)
    }
    fn opener(&self) -> Self::OpenStreams {
        ClientOpen {
            inner: <h3_quinn::Connection as quic::Connection<Bytes>>::opener(&self.inner),
            control: self.control.clone(),
        }
    }
}
struct NoDns;
impl Resolver for NoDns {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
        Box::pin(async { panic!("回归使用字面目标，不应解析") })
    }
}
struct Association {
    socket: Arc<UdpSocket>,
    end: CancellationToken,
}
impl DatagramAssociationSender for Association {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let address: SocketAddr = target
                .to_string()
                .parse()
                .map_err(|_| Error::InvalidAddress)?;
            self.socket.send_to(packet, address).await?;
            Ok(())
        })
    }
}
impl DatagramAssociationReceiver for Association {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 65535];
            tokio::select! {
                biased;
                _ = self.end.cancelled() => Ok(None),
                packet = self.socket.recv_from(&mut bytes) => {
                    let (count, source) = packet?;
                    bytes.truncate(count);
                    Ok(Some((Destination::new(&source.ip().to_string(), source.port())?, bytes)))
                }
            }
        })
    }
}
#[derive(Default)]
struct Backend {
    tcp: AtomicUsize,
    opening: Notify,
    connect_gate: Option<Arc<Notify>>,
    associations: Mutex<Vec<(SocketAddr, CancellationToken)>>,
}
impl Outbound for Backend {
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
            self.opening.notify_one();
            if let Some(gate) = &self.connect_gate {
                gate.notified().await;
            }
            let io = TcpStream::connect(target.to_string()).await?;
            self.tcp.fetch_add(1, Ordering::AcqRel);
            Ok(OpenedTcp {
                stream: Box::new(io),
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("Hy2回归要求原多目标关联")) })
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            let end = CancellationToken::new();
            self.associations
                .lock()
                .unwrap()
                .push((socket.local_addr()?, end.clone()));
            Ok(DatagramAssociation {
                sender: Box::new(Association {
                    socket: socket.clone(),
                    end: end.clone(),
                }),
                receiver: Box::new(Association { socket, end }),
            })
        })
    }
}
struct Fixture {
    context: InboundContext,
    events: Arc<Events>,
    permits: Arc<Semaphore>,
    node_permits: Arc<Semaphore>,
    task: JoinHandle<Result<()>>,
    server_address: SocketAddr,
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    requests: h3::client::SendRequest<ClientOpen, Bytes>,
    driver: JoinHandle<()>,
    shutdown: mpsc::UnboundedSender<oneshot::Sender<()>>,
    goaway: Arc<Notify>,
    control: Arc<ControlSend>,
    telemetry: Telemetry,
    backend: Arc<Backend>,
}
async fn fixture(backend: Arc<Backend>) -> Fixture {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = certificate.cert.pem();
    let input = NodeBuildContext::for_test(
        json!({"tls":{"certificate_pem":pem,"private_key_pem":certificate.signing_key.serialize_pem()},
            "limits":{"idle_timeout_ms":5000}}),
        vec![json!({"auth":"synthetic-goaway-secret"})],
    );
    let node = Hysteria2Node::from_options(&input).unwrap();
    let (access, telemetry) = kerlico_egress::testing::ingress_with_resolver(
        &input,
        backend.clone(),
        TargetPolicy::Remote,
        FamilyMode::DualV4Preferred,
        Arc::new(NoDns),
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let events = Arc::new(Events::default());
    let permits = Arc::new(Semaphore::new(64));
    let node_permits = Arc::new(Semaphore::new(64));
    let context = InboundContext {
        peer_lease: None,
        tasks: NodeTasks::new(input.issuer().node().clone(), cancel.clone()),
        cancel,
        peer_addr: None,
        local_addr: None,
        events: events.clone(),
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65507,
        max_streams: 32,
        stream_budget: StreamBudget::new(permits.clone(), node_permits.clone()),
    };
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_address = socket.local_addr().unwrap();
    let task = {
        let context = context.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, context).await })
    };
    let tls = config::client_tls(
        &serde_json::from_value(json!({"server_name":"localhost","ca_pem":pem})).unwrap(),
    )
    .unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone()).unwrap();
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(
        Limits::default()
            .transport(32, false, Default::default())
            .unwrap(),
    );
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(server_address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let goaway = Arc::new(Notify::new());
    let control = Arc::new(ControlSend::default());
    let (mut h3, mut requests) = h3::client::new(ClientConnection {
        inner: h3_quinn::Connection::new(connection.clone()),
        goaway: goaway.clone(),
        control: control.clone(),
    })
    .await
    .unwrap();
    let (shutdown, mut commands) = mpsc::unbounded_channel::<oneshot::Sender<()>>();
    let driver = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                command = commands.recv() => {
                    let Some(reply) = command else { break; };
                    h3.shutdown(0).await.unwrap();
                    let _ = reply.send(());
                }
                _ = std::future::poll_fn(|cx| h3.poll_close(cx)) => break,
            }
        }
    });
    let request = http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("hysteria-auth", "synthetic-goaway-secret")
        .header("hysteria-cc-rx", "0")
        .body(())
        .unwrap();
    let mut auth = requests.send_request(request).await.unwrap();
    auth.finish().await.unwrap();
    assert_eq!(auth.recv_response().await.unwrap().status(), 233);
    while auth.recv_data().await.unwrap().is_some() {}
    drop(auth);
    until(|| permits.available_permits() == 63 && node_permits.available_permits() == 63).await;
    Fixture {
        context,
        events,
        permits,
        node_permits,
        task,
        server_address,
        endpoint,
        connection,
        requests,
        driver,
        shutdown,
        goaway,
        control,
        telemetry,
        backend,
    }
}
async fn goaway(fixture: &mut Fixture) {
    let (reply, received) = oneshot::channel();
    fixture.shutdown.send(reply).unwrap();
    received.await.unwrap();
    tokio::time::timeout(Duration::from_millis(500), fixture.goaway.notified())
        .await
        .unwrap();
    assert!(
        fixture.connection.close_reason().is_none(),
        "GOAWAY不能提前关闭活跃原生业务"
    );
}
async fn until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_millis(500), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn native(connection: &quinn::Connection, target: &Destination) -> crate::io::Stream {
    let (send, receive) = connection.open_bi().await.unwrap();
    let mut stream = crate::io::Stream {
        send,
        receive,
        prefix: Bytes::new(),
        _owner: Arc::new(()),
    };
    wire::send_request(&mut stream, &target.to_string())
        .await
        .unwrap();
    wire::response(&mut stream).await.unwrap();
    stream
}
async fn partial_native(fixture: &Fixture, target: &Destination) -> (crate::io::Stream, Vec<u8>) {
    let global_available = fixture.permits.available_permits();
    let node_available = fixture.node_permits.available_permits();
    let (send, receive) = fixture.connection.open_bi().await.unwrap();
    let mut stream = crate::io::Stream {
        send,
        receive,
        prefix: Bytes::new(),
        _owner: Arc::new(()),
    };
    let mut header = Vec::new();
    wire::send_request(&mut header, &target.to_string())
        .await
        .unwrap();
    assert_eq!(&header[..2], &[0x44, 0x01]);
    stream.write_all(&header[..1]).await.unwrap();
    stream.flush().await.unwrap();
    until(|| {
        fixture.permits.available_permits() == global_available - 1
            && fixture.node_permits.available_permits() == node_available - 1
    })
    .await;
    (stream, header)
}
async fn complete_partial(stream: &mut crate::io::Stream, header: &[u8]) {
    tokio::time::timeout(Duration::from_millis(500), async {
        stream.write_all(&header[1..]).await.unwrap();
        wire::response(stream).await.unwrap();
    })
    .await
    .unwrap();
}
async fn rejected_native(fixture: &Fixture, target: &Destination) {
    let (mut send, mut receive) = fixture.connection.open_bi().await.unwrap();
    let _ = wire::send_request(&mut send, &target.to_string()).await;
    let result = tokio::time::timeout(Duration::from_millis(500), receive.read_chunk(64, true))
        .await
        .unwrap();
    assert!(
        matches!(result, Err(quinn::ReadError::Reset(_))),
        "GOAWAY 后新流必须在载体仍活跃时被实际拒绝"
    );
    assert!(fixture.connection.close_reason().is_none());
}
async fn finish_native(stream: &mut crate::io::Stream) {
    stream.shutdown().await.unwrap();
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_millis(500), stream.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert!(tail.is_empty());
}
async fn roundtrip(stream: &mut crate::io::Stream, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    stream.flush().await.unwrap();
    let mut received = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, bytes);
}
async fn tcp_target() -> (Destination, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut all = Vec::new();
        let mut bytes = [0; 1024];
        while let Ok(count) = stream.read(&mut bytes).await {
            if count == 0 {
                let _ = stream.shutdown().await;
                break;
            }
            all.extend_from_slice(&bytes[..count]);
            if stream.write_all(&bytes[..count]).await.is_err() {
                break;
            }
        }
        all
    });
    (Destination::new("127.0.0.1", address.port()).unwrap(), task)
}
async fn udp_exchange(
    connection: &quinn::Connection,
    socket: &UdpSocket,
    session: u32,
    bytes: &[u8],
) {
    let address = socket.local_addr().unwrap();
    let target = Destination::new("127.0.0.1", address.port()).unwrap();
    let packet = wire::Packet {
        session,
        id: 1,
        index: 0,
        count: 1,
        address: target.to_string(),
        payload: bytes.to_vec(),
    };
    connection
        .send_datagram(Bytes::from(packet.encode().unwrap()))
        .unwrap();
    let mut payload = [0; 256];
    let (count, source) =
        tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut payload))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&payload[..count], bytes);
    socket.send_to(&payload[..count], source).await.unwrap();
    let packet = tokio::time::timeout(Duration::from_millis(500), connection.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let packet = wire::Packet::decode(&packet).unwrap();
    assert_eq!(packet.session, session);
    assert_eq!(packet.address, target.to_string());
    assert_eq!(packet.payload, bytes);
}
async fn finish(fixture: Fixture) {
    fixture.connection.close(0x100u32.into(), b"");
    fixture.endpoint.close(0x100u32.into(), b"");
    tokio::time::timeout(Duration::from_secs(2), fixture.driver)
        .await
        .unwrap()
        .unwrap();
    fixture.context.cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), fixture.task)
        .await
        .unwrap()
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
    fixture.endpoint.wait_idle().await;
    drop(fixture.requests);
    drop(fixture.connection);
    drop(fixture.endpoint);
    assert_eq!(fixture.permits.available_permits(), 64);
    assert_eq!(fixture.node_permits.available_permits(), 64);
    assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 0);
    let _rebound = std::net::UdpSocket::bind(fixture.server_address).unwrap();
    for (address, _) in fixture.backend.associations.lock().unwrap().iter() {
        let _released = std::net::UdpSocket::bind(address).unwrap();
    }
}
#[tokio::test]
async fn h3_goaway_drains_native_tcp_and_existing_multi_target_udp() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let (target, target_task) = tcp_target().await;
    let mut tcp = native(&fixture.connection, &target).await;
    roundtrip(&mut tcp, b"tcp-before").await;
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&fixture.connection, &first, 7, b"udp-before").await;
    goaway(&mut fixture).await;
    assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 2);
    assert!(
        fixture
            .telemetry
            .records(0, 8)
            .unwrap()
            .iter()
            .all(|record| record.end.is_none())
    );
    roundtrip(&mut tcp, b"tcp-during").await;
    udp_exchange(&fixture.connection, &second, 7, b"udp-new-target").await;
    let denied = wire::Packet {
        session: 8,
        id: 1,
        index: 0,
        count: 1,
        address: target.to_string(),
        payload: b"denied-association".to_vec(),
    };
    fixture
        .connection
        .send_datagram(Bytes::from(denied.encode().unwrap()))
        .unwrap();
    let (mut denied_tcp, mut denied_receive) = fixture.connection.open_bi().await.unwrap();
    wire::send_request(&mut denied_tcp, &target.to_string())
        .await
        .unwrap();
    udp_exchange(&fixture.connection, &first, 7, b"udp-after-denied").await;
    assert_eq!(backend.tcp.load(Ordering::Acquire), 1);
    assert_eq!(fixture.telemetry.records(0, 8).unwrap().len(), 2);
    tcp.shutdown().await.unwrap();
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_millis(500), tcp.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert!(tail.is_empty());
    backend.associations.lock().unwrap()[0].1.cancel();
    tokio::time::timeout(Duration::from_secs(2), fixture.connection.closed())
        .await
        .unwrap();
    assert!(denied_receive.read_chunk(64, true).await.is_err());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), target_task)
            .await
            .unwrap()
            .unwrap(),
        b"tcp-beforetcp-during"
    );
    let records = fixture.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.end == Some(FlowEnd::Completed))
    );
    let udp = records
        .iter()
        .find(|record| record.kind == FlowKind::UdpAssociation)
        .unwrap();
    assert_eq!(udp.usage.upload_packets, 3);
    assert_eq!(udp.usage.download_packets, 3);
    assert_eq!(udp.datagram_targets.len(), 2);
    finish(fixture).await;
}
#[tokio::test]
async fn h3_goaway_keeps_native_tcp_waiting_for_request_header() {
    let mut fixture = fixture(Arc::new(Backend::default())).await;
    let (target, target_task) = tcp_target().await;
    let (send, receive) = fixture.connection.open_bi().await.unwrap();
    let mut stream = crate::io::Stream {
        send,
        receive,
        prefix: Bytes::new(),
        _owner: Arc::new(()),
    };
    let mut header = Vec::new();
    wire::send_request(&mut header, &target.to_string())
        .await
        .unwrap();
    stream.write_all(&header[..2]).await.unwrap();
    until(|| fixture.events.accepted.load(Ordering::Acquire) >= 2).await;
    assert!(fixture.telemetry.records(0, 8).unwrap().is_empty());
    goaway(&mut fixture).await;
    stream.write_all(&header[2..]).await.unwrap();
    wire::response(&mut stream).await.unwrap();
    roundtrip(&mut stream, b"late-header").await;
    stream.shutdown().await.unwrap();
    let mut tail = Vec::new();
    stream.read_to_end(&mut tail).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), fixture.connection.closed())
        .await
        .unwrap();
    assert_eq!(target_task.await.unwrap(), b"late-header");
    assert_eq!(
        fixture.telemetry.records(0, 8).unwrap()[0].end,
        Some(FlowEnd::Completed)
    );
    finish(fixture).await;
}
#[tokio::test]
async fn h3_goaway_keeps_native_tcp_waiting_for_target_connect() {
    let gate = Arc::new(Notify::new());
    let backend = Arc::new(Backend {
        connect_gate: Some(gate.clone()),
        ..Backend::default()
    });
    let mut fixture = fixture(backend.clone()).await;
    let (target, target_task) = tcp_target().await;
    let (send, receive) = fixture.connection.open_bi().await.unwrap();
    let mut stream = crate::io::Stream {
        send,
        receive,
        prefix: Bytes::new(),
        _owner: Arc::new(()),
    };
    wire::send_request(&mut stream, &target.to_string())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(500), backend.opening.notified())
        .await
        .unwrap();
    goaway(&mut fixture).await;
    gate.notify_one();
    wire::response(&mut stream).await.unwrap();
    roundtrip(&mut stream, b"late-connect").await;
    stream.shutdown().await.unwrap();
    let mut tail = Vec::new();
    stream.read_to_end(&mut tail).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), fixture.connection.closed())
        .await
        .unwrap();
    assert_eq!(target_task.await.unwrap(), b"late-connect");
    assert_eq!(
        fixture.telemetry.records(0, 8).unwrap()[0].end,
        Some(FlowEnd::Completed)
    );
    finish(fixture).await;
}
#[tokio::test]
async fn h3_goaway_deadline_records_timeout_before_carrier_cleanup() {
    let mut fixture = fixture(Arc::new(Backend::default())).await;
    let (target, target_task) = tcp_target().await;
    let mut stream = native(&fixture.connection, &target).await;
    roundtrip(&mut stream, b"held-open").await;
    let started = tokio::time::Instant::now();
    goaway(&mut fixture).await;
    tokio::time::timeout_at(
        started + Duration::from_secs(2),
        fixture.connection.closed(),
    )
    .await
    .unwrap();
    assert_eq!(
        fixture.telemetry.records(0, 8).unwrap()[0].end,
        Some(FlowEnd::Timeout)
    );
    assert_eq!(target_task.await.unwrap(), b"held-open");
    finish(fixture).await;
}
#[tokio::test]
async fn quic_failure_during_h3_goaway_drain_records_failed() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend).await;
    let (target, target_task) = tcp_target().await;
    let mut stream = native(&fixture.connection, &target).await;
    roundtrip(&mut stream, b"before-failure").await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&fixture.connection, &udp, 9, b"before-failure").await;
    goaway(&mut fixture).await;
    fixture.connection.close(0x1fu32.into(), b"");
    until(|| fixture.telemetry.usage().unwrap().active_flows == 0).await;
    let records = fixture.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.end == Some(FlowEnd::Failed))
    );
    assert_eq!(target_task.await.unwrap(), b"before-failure");
    finish(fixture).await;
}

#[tokio::test]
async fn h3_goaway_keeps_native_tcp_waiting_for_type_varint() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let (target, target_task) = tcp_target().await;
    let (mut stream, header) = partial_native(&fixture, &target).await;
    assert_eq!(fixture.events.accepted.load(Ordering::Acquire), 1);
    assert!(fixture.telemetry.records(0, 8).unwrap().is_empty());
    goaway(&mut fixture).await;
    assert_eq!(fixture.permits.available_permits(), 62);
    assert_eq!(fixture.node_permits.available_permits(), 62);
    assert_eq!(backend.tcp.load(Ordering::Acquire), 0);
    assert!(fixture.telemetry.records(0, 8).unwrap().is_empty());
    complete_partial(&mut stream, &header).await;
    roundtrip(&mut stream, b"late-preface").await;
    finish_native(&mut stream).await;
    tokio::time::timeout(Duration::from_secs(2), fixture.connection.closed())
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), target_task)
            .await
            .unwrap()
            .unwrap(),
        b"late-preface"
    );
    until(|| fixture.telemetry.usage().unwrap().active_flows == 0).await;
    let records = fixture.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, FlowKind::Tcp);
    assert_eq!(records[0].end, Some(FlowEnd::Completed));
    assert_eq!(records[0].usage.upload_bytes, 12);
    assert_eq!(records[0].usage.download_bytes, 12);
    assert_eq!(backend.tcp.load(Ordering::Acquire), 1);
    assert_eq!(fixture.events.failed.load(Ordering::Acquire), 0);
    finish(fixture).await;
}

#[tokio::test]
async fn h3_goaway_pending_type_varint_keeps_existing_udp_and_rejects_new_native_streams() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&fixture.connection, &first, 21, b"udp-before-preface").await;
    let (target, target_task) = tcp_target().await;
    let (mut stream, header) = partial_native(&fixture, &target).await;
    assert_eq!(fixture.events.accepted.load(Ordering::Acquire), 2);
    assert_eq!(fixture.telemetry.records(0, 8).unwrap().len(), 1);
    goaway(&mut fixture).await;
    let global_available = fixture.permits.available_permits();
    let node_available = fixture.node_permits.available_permits();
    rejected_native(&fixture, &target).await;
    assert_eq!(fixture.permits.available_permits(), global_available);
    assert_eq!(fixture.node_permits.available_permits(), node_available);
    assert_eq!(backend.tcp.load(Ordering::Acquire), 0);
    assert_eq!(fixture.telemetry.records(0, 8).unwrap().len(), 1);
    udp_exchange(&fixture.connection, &second, 21, b"udp-during-preface").await;
    complete_partial(&mut stream, &header).await;
    roundtrip(&mut stream, b"preface-with-udp").await;
    rejected_native(&fixture, &target).await;
    udp_exchange(&fixture.connection, &first, 21, b"udp-after-preface").await;
    finish_native(&mut stream).await;
    backend.associations.lock().unwrap()[0].1.cancel();
    tokio::time::timeout(Duration::from_secs(2), fixture.connection.closed())
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), target_task)
            .await
            .unwrap()
            .unwrap(),
        b"preface-with-udp"
    );
    until(|| fixture.telemetry.usage().unwrap().active_flows == 0).await;
    let records = fixture.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.end == Some(FlowEnd::Completed))
    );
    let udp = records
        .iter()
        .find(|record| record.kind == FlowKind::UdpAssociation)
        .unwrap();
    assert_eq!(udp.usage.upload_packets, 3);
    assert_eq!(udp.usage.download_packets, 3);
    assert_eq!(udp.datagram_targets.len(), 2);
    let tcp = records
        .iter()
        .find(|record| record.kind == FlowKind::Tcp)
        .unwrap();
    assert_eq!(tcp.usage.upload_bytes, 16);
    assert_eq!(tcp.usage.download_bytes, 16);
    assert_eq!(backend.tcp.load(Ordering::Acquire), 1);
    finish(fixture).await;
}

#[tokio::test]
async fn h3_goaway_pending_type_varint_reaches_original_deadline_without_business_flow() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
    let (mut stream, _header) = partial_native(&fixture, &target).await;
    let started = tokio::time::Instant::now();
    goaway(&mut fixture).await;
    let acknowledged = tokio::time::Instant::now();
    assert!(
        tokio::time::timeout_at(
            started + fixture.context.drain_timeout - Duration::from_millis(150),
            fixture.connection.closed(),
        )
        .await
        .is_err(),
        "只有待识别流时也必须等待原排空期限"
    );
    assert_eq!(fixture.permits.available_permits(), 62);
    assert_eq!(fixture.node_permits.available_permits(), 62);
    assert!(fixture.telemetry.records(0, 8).unwrap().is_empty());
    tokio::time::timeout_at(
        acknowledged + fixture.context.drain_timeout + Duration::from_millis(200),
        fixture.connection.closed(),
    )
    .await
    .unwrap();
    until(|| {
        fixture.permits.available_permits() == 64
            && fixture.node_permits.available_permits() == 64
            && fixture.events.failed.load(Ordering::Acquire) == 1
    })
    .await;
    assert!(fixture.telemetry.records(0, 8).unwrap().is_empty());
    assert_eq!(fixture.telemetry.usage().unwrap().active_flows, 0);
    assert_eq!(backend.tcp.load(Ordering::Acquire), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(500), stream.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    finish(fixture).await;
}

#[tokio::test]
async fn h3_goaway_pending_type_varints_do_not_restart_drain_deadline() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&fixture.connection, &udp, 22, b"udp-before-deadline").await;
    let (target, target_task) = tcp_target().await;
    let (mut first, header) = partial_native(&fixture, &target).await;
    let (_pending, _header) = partial_native(&fixture, &target).await;
    goaway(&mut fixture).await;
    let acknowledged = tokio::time::Instant::now();
    assert!(
        tokio::time::timeout_at(
            acknowledged + fixture.context.drain_timeout / 2,
            fixture.connection.closed(),
        )
        .await
        .is_err()
    );
    complete_partial(&mut first, &header).await;
    roundtrip(&mut first, b"mid-drain-preface").await;
    rejected_native(&fixture, &target).await;
    udp_exchange(&fixture.connection, &udp, 22, b"udp-mid-deadline").await;
    assert!(
        fixture
            .telemetry
            .records(0, 8)
            .unwrap()
            .iter()
            .all(|record| record.end.is_none())
    );
    tokio::time::timeout_at(
        acknowledged + fixture.context.drain_timeout + Duration::from_millis(200),
        fixture.connection.closed(),
    )
    .await
    .unwrap();
    until(|| fixture.telemetry.usage().unwrap().active_flows == 0).await;
    let records = fixture.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.end == Some(FlowEnd::Timeout))
    );
    let tcp = records
        .iter()
        .find(|record| record.kind == FlowKind::Tcp)
        .unwrap();
    assert_eq!(tcp.usage.upload_bytes, 17);
    assert_eq!(tcp.usage.download_bytes, 17);
    let udp = records
        .iter()
        .find(|record| record.kind == FlowKind::UdpAssociation)
        .unwrap();
    assert_eq!(udp.usage.upload_packets, 2);
    assert_eq!(udp.usage.download_packets, 2);
    assert_eq!(backend.tcp.load(Ordering::Acquire), 1);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), target_task)
            .await
            .unwrap()
            .unwrap(),
        b"mid-drain-preface"
    );
    finish(fixture).await;
}

#[tokio::test]
async fn h3_goaway_pending_type_varint_keeps_node_cancellation_priority() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&fixture.connection, &udp, 23, b"udp-before-cancel").await;
    let target = Destination::new("127.0.0.1", udp.local_addr().unwrap().port()).unwrap();
    let (_pending, _header) = partial_native(&fixture, &target).await;
    goaway(&mut fixture).await;
    fixture.context.cancel.cancel();
    tokio::time::timeout(Duration::from_millis(500), fixture.connection.closed())
        .await
        .unwrap();
    until(|| fixture.telemetry.usage().unwrap().active_flows == 0).await;
    let records = fixture.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, FlowKind::UdpAssociation);
    assert_eq!(records[0].end, Some(FlowEnd::Cancelled));
    assert_eq!(records[0].usage.upload_packets, 1);
    assert_eq!(records[0].usage.download_packets, 1);
    assert_eq!(backend.tcp.load(Ordering::Acquire), 0);
    finish(fixture).await;
}

#[tokio::test]
async fn quic_failure_while_type_varint_is_pending_keeps_failed_outcome() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&fixture.connection, &udp, 24, b"udp-before-failure").await;
    let target = Destination::new("127.0.0.1", udp.local_addr().unwrap().port()).unwrap();
    let (_pending, _header) = partial_native(&fixture, &target).await;
    goaway(&mut fixture).await;
    fixture.connection.close(0x1fu32.into(), b"");
    until(|| fixture.telemetry.usage().unwrap().active_flows == 0).await;
    let records = fixture.telemetry.records(0, 8).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, FlowKind::UdpAssociation);
    assert_eq!(records[0].end, Some(FlowEnd::Failed));
    assert_eq!(records[0].usage.upload_packets, 1);
    assert_eq!(records[0].usage.download_packets, 1);
    assert_eq!(backend.tcp.load(Ordering::Acquire), 0);
    finish(fixture).await;
}

async fn reset_control_before_deadline(fixture: &Fixture, started: tokio::time::Instant) {
    assert!(fixture.connection.close_reason().is_none());
    assert!(!fixture.context.cancel.is_cancelled());
    assert!(fixture.telemetry.usage().unwrap().active_flows > 0);
    assert!(
        fixture
            .telemetry
            .records(0, 8)
            .unwrap()
            .iter()
            .all(|record| record.end.is_none())
    );
    fixture.control.reset();
    tokio::time::timeout_at(
        started + fixture.context.drain_timeout - Duration::from_millis(150),
        async {
            let error = fixture.connection.closed().await;
            assert!(
                matches!(error, quinn::ConnectionError::ApplicationClosed(close)
                    if close.error_code.into_inner() == h3::error::Code::H3_CLOSED_CRITICAL_STREAM.value()),
                "仅重置控制流必须触发真实 H3_CLOSED_CRITICAL_STREAM"
            );
            while fixture.telemetry.usage().unwrap().active_flows != 0
                || fixture.permits.available_permits() != 64
                || fixture.node_permits.available_permits() != 64
            {
                tokio::task::yield_now().await;
            }
        },
    )
    .await
    .expect("H3 控制流失败必须早于首次 GOAWAY 的原排空期限");
    assert!(!fixture.context.cancel.is_cancelled());
    assert!(fixture.events.failed.load(Ordering::Acquire) > 0);
    assert!(
        fixture
            .telemetry
            .records(0, 8)
            .unwrap()
            .iter()
            .all(|record| record.end == Some(FlowEnd::Failed))
    );
}

#[tokio::test]
async fn h3_control_reset_during_goaway_drain_fails_existing_tcp_before_deadline() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let (target, target_task) = tcp_target().await;
    let mut tcp = native(&fixture.connection, &target).await;
    roundtrip(&mut tcp, b"control-tcp-before").await;
    let started = tokio::time::Instant::now();
    goaway(&mut fixture).await;
    roundtrip(&mut tcp, b"control-tcp-drain").await;
    reset_control_before_deadline(&fixture, started).await;
    let deadline = started + fixture.context.drain_timeout;
    tokio::time::timeout_at(deadline, async {
        assert!(
            tokio::time::timeout(Duration::from_millis(500), tcp.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        let expected = b"control-tcp-beforecontrol-tcp-drain";
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), target_task)
                .await
                .unwrap()
                .unwrap(),
            expected
        );
        let records = fixture.telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, FlowKind::Tcp);
        assert_eq!(records[0].end, Some(FlowEnd::Failed));
        assert_eq!(records[0].usage.upload_bytes, expected.len() as u64);
        assert_eq!(records[0].usage.download_bytes, expected.len() as u64);
        assert_eq!(backend.tcp.load(Ordering::Acquire), 1);
        finish(fixture).await;
    })
    .await
    .expect("目标、节点任务和监听必须在原排空期限内回收");
}

#[tokio::test]
async fn h3_control_reset_during_goaway_drain_fails_udp_with_pending_type_varint() {
    let backend = Arc::new(Backend::default());
    let mut fixture = fixture(backend.clone()).await;
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&fixture.connection, &first, 25, b"control-udp-before").await;
    let target = Destination::new("127.0.0.1", first.local_addr().unwrap().port()).unwrap();
    let (mut pending, _header) = partial_native(&fixture, &target).await;
    let started = tokio::time::Instant::now();
    goaway(&mut fixture).await;
    udp_exchange(&fixture.connection, &second, 25, b"control-udp-drain").await;
    assert_eq!(fixture.permits.available_permits(), 61);
    assert_eq!(fixture.node_permits.available_permits(), 61);
    reset_control_before_deadline(&fixture, started).await;
    let deadline = started + fixture.context.drain_timeout;
    tokio::time::timeout_at(deadline, async {
        assert!(
            tokio::time::timeout(Duration::from_millis(500), pending.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        let records = fixture.telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, FlowKind::UdpAssociation);
        assert_eq!(records[0].end, Some(FlowEnd::Failed));
        assert_eq!(records[0].usage.upload_packets, 2);
        assert_eq!(records[0].usage.download_packets, 2);
        assert_eq!(records[0].datagram_targets.len(), 2);
        assert_eq!(backend.tcp.load(Ordering::Acquire), 0);
        assert_eq!(backend.associations.lock().unwrap().len(), 1);
        finish(fixture).await;
    })
    .await
    .expect("节点任务、原生流与UDP出口必须在原排空期限内回收");
}
