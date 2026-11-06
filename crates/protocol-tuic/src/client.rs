//! 客户端连接池按出站实例隔离；逻辑关联保留一个远端 Full Cone socket。
use crate::{
    codec::{self, Mode, Reassembler},
    config::{self, ClientOptions, Credential},
    wire,
};
use kerlico_config::OutboundPlan;
use kerlico_core::{
    AddressedDatagram, BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Outbound, ResourceKey, Result, ServiceContext, ServiceTask,
    TargetPolicy,
};
use std::{
    collections::HashMap,
    ops::RangeInclusive,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};

#[derive(Default)]
struct ConnectionPool {
    connections: tokio::sync::Mutex<Vec<Arc<Connection>>>,
    connecting: AtomicUsize,
}
type MemberConnection = ConnectionPool;
struct ConnectingGuard(Arc<MemberConnection>);
impl Drop for ConnectingGuard {
    fn drop(&mut self) {
        self.0.connecting.fetch_sub(1, Ordering::AcqRel);
    }
}
struct TcpReservation(Option<Arc<Connection>>);
impl Drop for TcpReservation {
    fn drop(&mut self) {
        if let Some(conn) = &self.0 {
            conn.release_tcp();
        }
    }
}
pub(crate) struct Client {
    server: Destination,
    port_ranges: Vec<RangeInclusive<u16>>,
    hop_interval: Duration,
    hop_interval_max: Duration,
    tls: quinn::ClientConfig,
    server_name: String,
    credential: Credential,
    mode: Mode,
    heartbeat: Duration,
    host: ServiceContext,
    current: tokio::sync::Mutex<HashMap<ResourceKey, Arc<MemberConnection>>>,
    dialer: kerlico_core::DialerOptions,
}
pub(crate) struct Connection {
    pub quic: quinn::Connection,
    _endpoint: quinn::Endpoint,
    _relay: Option<kerlico_core::dialer::RelayGuard>,
    version: u8,
    mode: Mode,
    next: AtomicU32,
    active: AtomicUsize,
    entries: Mutex<HashMap<u32, mpsc::Sender<AddressedDatagram>>>,
    fragments: Mutex<Reassembler>,
    tasks: Mutex<Vec<ServiceTask<()>>>,
    host: ServiceContext,
    activity: Mutex<Instant>,
}
impl Connection {
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.retain(|task| !task.is_finished());
            match self.host.spawn_tracked(future) {
                Ok(task) => tasks.push(task),
                Err(_) => self.quic.close(0u32.into(), b""),
            }
        }
    }
    fn touch(&self) {
        if let Ok(mut time) = self.activity.lock() {
            *time = Instant::now();
        }
    }
    fn dispatch(&self, bytes: &[u8], mode: Mode) -> Result<()> {
        if bytes == [self.version, 4] {
            return Ok(());
        }
        let packet = codec::decode_packet(self.version, bytes)?;
        let packet = self
            .fragments
            .lock()
            .map_err(|_| codec::malformed())?
            .feed(packet, mode)?;
        let Some(packet) = packet else {
            return Ok(());
        };
        let target = packet.target.ok_or_else(codec::malformed)?;
        if let Some(sender) = self
            .entries
            .lock()
            .map_err(|_| codec::malformed())?
            .get(&packet.assoc)
        {
            let _ = sender.try_send((target, packet.data));
        }
        self.touch();
        Ok(())
    }
    fn start(self: &Arc<Self>, heartbeat: Duration) {
        let weak = Arc::downgrade(self);
        let quic = self.quic.clone();
        self.spawn(async move {
            loop {
                let bytes = match quic.read_datagram().await {
                    Ok(bytes) => bytes,
                    Err(_) => break,
                };
                let Some(value) = weak.upgrade() else {
                    break;
                };
                let _ = value.dispatch(&bytes, Mode::Native);
            }
            if let Some(value) = weak.upgrade()
                && let Ok(mut entries) = value.entries.lock()
            {
                entries.clear();
            }
        });
        let weak = Arc::downgrade(self);
        let quic = self.quic.clone();
        self.spawn(async move {
            loop {
                let stream = match quic.accept_uni().await {
                    Ok(stream) => stream,
                    Err(_) => break,
                };
                let Some(value) = weak.upgrade() else {
                    break;
                };
                let weak = Arc::downgrade(&value);
                value.spawn(async move {
                    let mut stream = stream;
                    let bytes = tokio::time::timeout(
                        Duration::from_secs(5),
                        stream.read_to_end(codec::MAX_PACKET + 512),
                    )
                    .await;
                    if let Ok(Ok(bytes)) = bytes
                        && let Some(value) = weak.upgrade()
                    {
                        let _ = value.dispatch(&bytes, Mode::Quic);
                    }
                });
            }
        });
        let weak = Arc::downgrade(self);
        let quic = self.quic.clone();
        self.spawn(async move {
            loop {
                tokio::time::sleep(heartbeat).await;
                let Some(value) = weak.upgrade() else {
                    break;
                };
                let idle = value
                    .activity
                    .lock()
                    .map(|time| time.elapsed() > Duration::from_secs(30))
                    .unwrap_or(true);
                if value.active.load(Ordering::Acquire) == 0 && idle {
                    quic.close(0u32.into(), b"");
                    break;
                }
                if quic.close_reason().is_some() {
                    break;
                }
                if value.version == 4 {
                    let _ = tokio::time::timeout(Duration::from_secs(1), wire::uni(&quic, &[4, 4]))
                        .await;
                } else {
                    let _ = quic.send_datagram(bytes::Bytes::from(vec![5, 4]));
                }
            }
        });
    }
    fn association(self: &Arc<Self>) -> Result<DatagramAssociation> {
        let limit = if self.version == 4 { u32::MAX } else { 65535 };
        let id = self
            .next
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                if value >= limit {
                    None
                } else {
                    Some(value + 1)
                }
            })
            .map_err(|_| Error::ResourceLimit)?;
        let (sender, receiver) = mpsc::channel(32);
        let mut entries = self.entries.lock().map_err(|_| codec::malformed())?;
        if entries.len() >= 128 {
            return Err(Error::ResourceLimit);
        }
        entries.insert(id, sender);
        drop(entries);
        self.active.fetch_add(1, Ordering::AcqRel);
        self.touch();
        let guard = Arc::new(Association {
            connection: self.clone(),
            id,
        });
        Ok(DatagramAssociation {
            sender: Box::new(Sender {
                association: guard.clone(),
                failed: false,
                sequence: wire::PacketSequence::new(),
            }),
            receiver: Box::new(Receiver {
                _association: guard,
                receiver,
            }),
        })
    }
    pub fn release_tcp(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.touch();
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.quic.close(0u32.into(), b"");
        if let Ok(tasks) = self.tasks.get_mut() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }
}
struct Association {
    connection: Arc<Connection>,
    id: u32,
}
impl Drop for Association {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.connection.entries.lock() {
            entries.remove(&self.id);
        }
        if let Ok(mut fragments) = self.connection.fragments.lock() {
            fragments.remove(self.id);
        }
        self.connection.active.fetch_sub(1, Ordering::AcqRel);
        self.connection.touch();
        let quic = self.connection.quic.clone();
        let bytes = codec::dissociate(self.connection.version, self.id);
        self.connection.spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(1), wire::uni(&quic, &bytes)).await;
        });
    }
}
struct Sender {
    association: Arc<Association>,
    failed: bool,
    sequence: wire::PacketSequence,
}
struct Receiver {
    _association: Arc<Association>,
    receiver: mpsc::Receiver<AddressedDatagram>,
}
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.failed {
                return Err(Error::Protocol("TUIC UDP 写端已失效"));
            }
            if packet.len() > codec::MAX_PACKET {
                return Err(Error::ResourceLimit);
            }
            let connection = &self.association.connection;
            let sequence = self.sequence.next().await;
            self.failed = true;
            let result = wire::send(
                &connection.quic,
                connection.version,
                connection.mode,
                self.association.id,
                sequence,
                target,
                packet,
            )
            .await;
            self.failed = false;
            result?;
            connection.touch();
            Ok(())
        })
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.receiver.recv().await) })
    }
}
impl Client {
    pub fn compile(options: ClientOptions) -> Result<OutboundPlan> {
        if !(5..=3600).contains(&options.idle_timeout_secs)
            || options.heartbeat_interval_secs == 0
            || options.heartbeat_interval_secs >= options.idle_timeout_secs
        {
            return Err(config::invalid());
        }
        let transport = config::transport(
            &options.congestion_control,
            Duration::from_secs(options.idle_timeout_secs),
            Some(Duration::from_secs(options.heartbeat_interval_secs)),
            128,
        )?;
        let (tls, server_name) = config::client_tls(options.tls, transport)?;
        let server = options.server.destination()?;
        let port_ranges = match &options.ports {
            Some(spec) => spec.parse()?,
            None => Vec::new(),
        };
        let hop_interval = if let Some(ms) = options.hop_interval_ms {
            if !(10..=86_400_000).contains(&ms) {
                return Err(config::invalid());
            }
            Duration::from_millis(ms)
        } else {
            match &options.hop_interval {
                Some(spec) => spec.to_duration()?,
                None => Duration::from_secs(30),
            }
        };
        let hop_interval_max = match &options.hop_interval_max {
            Some(spec) => {
                let max = spec.to_duration()?;
                if max < hop_interval {
                    return Err(config::invalid());
                }
                max
            }
            None => hop_interval,
        };
        let dialer = kerlico_core::current_compile_dialer();
        if dialer.has_detour() && !port_ranges.is_empty() {
            return Err(Error::Config(
                "TUIC 端口跳跃不能与 detour 同用：链式 UDP 中继只转发到固定服务端端口".into(),
            ));
        }
        let credential = Credential::parse(
            options.version,
            options.token,
            options.uuid,
            options.password,
        )?;
        let mode = config::mode(&options.udp_relay_mode)?;
        let heartbeat = Duration::from_secs(options.heartbeat_interval_secs);
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            },
            true,
            TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(Self {
                        server,
                        port_ranges,
                        hop_interval,
                        hop_interval_max,
                        tls,
                        server_name,
                        credential,
                        mode,
                        heartbeat,
                        host,
                        current: tokio::sync::Mutex::new(HashMap::new()),
                        dialer,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
    async fn dial_connection(&self, initial_active: usize) -> Result<Arc<Connection>> {
        let mut detoured = if self.dialer.has_detour() {
            Some(self.dialer.udp_peer(&self.server).await?)
        } else {
            None
        };
        let candidates = match &detoured {
            Some(relayed) => vec![relayed.peer],
            None => kerlico_core::lookup_host((self.server.host().as_str(), self.server.port()))
                .await?
                .take(32)
                .collect::<Vec<_>>(),
        };
        let mut last = Error::InvalidAddress;
        for peer in candidates {
            let (socket, relay) = match detoured.take() {
                Some(relayed) => (relayed.socket, relayed.relay),
                None => (self.dialer.udp_socket_for(peer)?, None),
            };
            let hop = if self.port_ranges.is_empty() {
                None
            } else {
                Some((
                    peer,
                    self.port_ranges.clone(),
                    self.hop_interval,
                    self.hop_interval_max,
                ))
            };
            let endpoint = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                crate::socket::wrap_hopping(socket, hop)?,
                crate::runtime::ServiceRuntime::new(self.host.clone()),
            )?;
            let mut tls = self.tls.clone();
            tls.token_store(Arc::new(quinn::TokenMemoryCache::default()));
            let connecting = endpoint
                .connect_with(tls, peer, &self.server_name)
                .map_err(|_| config::invalid())?;
            let quic = match connecting.await {
                Ok(value) => value,
                Err(_) => {
                    last = Error::Protocol("TUIC QUIC 握手失败");
                    continue;
                }
            };
            wire::uni(&quic, &self.credential.authentication(&quic)?).await?;
            let connection = Arc::new(Connection {
                quic,
                _endpoint: endpoint,
                _relay: relay,
                version: self.credential.version(),
                mode: self.mode,
                next: AtomicU32::new(1),
                active: AtomicUsize::new(initial_active),
                entries: Mutex::new(HashMap::new()),
                fragments: Mutex::new(Reassembler::new()),
                tasks: Mutex::new(Vec::new()),
                host: self.host.clone(),
                activity: Mutex::new(Instant::now()),
            });
            connection.start(self.heartbeat);
            return Ok(connection);
        }
        Err(last)
    }
    async fn connection(
        &self,
        context: &ConnectContext,
        reserve_tcp: bool,
    ) -> Result<Arc<Connection>> {
        let bucket = {
            let mut buckets = self.current.lock().await;
            buckets
                .entry(context.resource_key().clone())
                .or_insert_with(|| Arc::new(ConnectionPool::default()))
                .clone()
        };
        let max_pool = if reserve_tcp { 4usize } else { 1usize };
        {
            let mut connections = bucket.connections.lock().await;
            connections.retain(|connection| {
                connection.quic.close_reason().is_none()
                    && connection.next.load(Ordering::Acquire)
                        < if connection.version == 4 {
                            u32::MAX
                        } else {
                            65535
                        }
            });
            if !reserve_tcp {
                if let Some(connection) = connections.first() {
                    return Ok(connection.clone());
                }
            } else {
                if let Some(idle) = connections
                    .iter()
                    .find(|c| c.active.load(Ordering::Acquire) == 0)
                {
                    idle.active.fetch_add(1, Ordering::AcqRel);
                    idle.touch();
                    return Ok(idle.clone());
                }
                if connections.len() + bucket.connecting.load(Ordering::Acquire) >= max_pool
                    && let Some(best) = connections
                        .iter()
                        .min_by_key(|c| c.active.load(Ordering::Acquire))
                {
                    best.active.fetch_add(1, Ordering::AcqRel);
                    best.touch();
                    return Ok(best.clone());
                }
            }
            bucket.connecting.fetch_add(1, Ordering::AcqRel);
        }
        let _guard = ConnectingGuard(bucket.clone());
        let connection = self
            .dial_connection(if reserve_tcp { 1 } else { 0 })
            .await?;
        let mut connections = bucket.connections.lock().await;
        if connections.len() < 8 {
            connections.push(connection.clone());
        }
        Ok(connection)
    }
}
impl Outbound for Client {
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.host.cancel().cancel();
            let buckets = { std::mem::take(&mut *self.current.lock().await) };
            for bucket in buckets.into_values() {
                let connections = { std::mem::take(&mut *bucket.connections.lock().await) };
                for connection in connections {
                    connection.quic.close(0u32.into(), b"");
                    connection._endpoint.close(0u32.into(), b"");
                    let tasks = connection
                        .tasks
                        .lock()
                        .map(|mut tasks| std::mem::take(&mut *tasks))
                        .unwrap_or_default();
                    for task in &tasks {
                        task.abort();
                    }
                    for task in tasks {
                        let _ = task.await;
                    }
                    let _ = tokio::time::timeout(
                        kerlico_core::QUIC_CLOSE_GRACE,
                        connection._endpoint.wait_idle(),
                    )
                    .await;
                }
            }
            Ok(())
        })
    }
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
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            context
                .run(async { self.connection(context, false).await?.association() })
                .await
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            context
                .run(async {
                    let connection = self.connection(context, true).await?;
                    let mut reservation = TcpReservation(Some(connection.clone()));
                    let (mut send, mut recv) = connection
                        .quic
                        .open_bi()
                        .await
                        .map_err(|_| codec::malformed())?;
                    let mut request = vec![connection.version, 1];
                    codec::address(&mut request, Some(target));
                    tokio::io::AsyncWriteExt::write_all(&mut send, &request).await?;
                    if connection.version == 4 {
                        let mut response = [0; 3];
                        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut response).await?;
                        if response != [4, 255, 0] {
                            return Err(Error::Rejected);
                        }
                    }
                    connection.touch();
                    Ok(Box::new(crate::io::QuicIo {
                        send,
                        recv,
                        owner: reservation.0.take(),
                    }) as BoxStream)
                })
                .await
                .map(|stream| kerlico_core::OpenedTcp {
                    stream,
                    info: kerlico_core::TcpConnectInfo::unknown(),
                })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let association = self.associate_udp(context).await?;
            Ok(DatagramChannel {
                sender: Box::new(FixedSender {
                    sender: association.sender,
                    target: target.clone(),
                }),
                receiver: Box::new(FixedReceiver {
                    receiver: association.receiver,
                    target: target.clone(),
                }),
            })
        })
    }
}
struct FixedSender {
    sender: Box<dyn DatagramAssociationSender>,
    target: Destination,
}
struct FixedReceiver {
    receiver: Box<dyn DatagramAssociationReceiver>,
    target: Destination,
}
impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.sender.send_to(bytes, &self.target)
    }
}
impl DatagramReceiver for FixedReceiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            loop {
                let Some((source, bytes)) = self.receiver.recv_from().await? else {
                    return Ok(None);
                };
                if source == self.target
                    || matches!(self.target.address(), kerlico_core::Address::Domain(_))
                        && source.port() == self.target.port()
                {
                    return Ok(Some(bytes));
                }
            }
        })
    }
}
