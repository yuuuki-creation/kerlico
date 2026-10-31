//! 客户端连接池按出站实例隔离；逻辑关联保留一个远端 Full Cone socket。
use crate::{
    codec::{self, Mode, Reassembler},
    config::{self, ClientOptions, Credential},
    wire,
};
use kerlico_core::{
    AddressedDatagram, BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Outbound, Result,
};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};

pub(crate) struct Client {
    server: Destination,
    tls: quinn::ClientConfig,
    server_name: String,
    credential: Credential,
    mode: Mode,
    heartbeat: Duration,
    current: tokio::sync::Mutex<Option<Arc<Connection>>>,
}
pub(crate) struct Connection {
    pub quic: quinn::Connection,
    _endpoint: quinn::Endpoint,
    version: u8,
    mode: Mode,
    next: AtomicU32,
    active: AtomicUsize,
    entries: Mutex<HashMap<u32, mpsc::Sender<AddressedDatagram>>>,
    fragments: Mutex<Reassembler>,
    tasks: Mutex<JoinSet<()>>,
    activity: Mutex<Instant>,
}
impl Connection {
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Ok(mut tasks) = self.tasks.lock() {
            while tasks.try_join_next().is_some() {}
            tasks.spawn(future);
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
            tasks.abort_all();
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
    pub fn build(options: ClientOptions) -> Result<Self> {
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
        Ok(Self {
            server: options.server.destination()?,
            tls,
            server_name,
            credential: Credential::parse(
                options.version,
                options.token,
                options.uuid,
                options.password,
            )?,
            mode: config::mode(&options.udp_relay_mode)?,
            heartbeat: Duration::from_secs(options.heartbeat_interval_secs),
            current: tokio::sync::Mutex::new(None),
        })
    }
    async fn connection(&self) -> Result<Arc<Connection>> {
        let mut current = self.current.lock().await;
        if let Some(connection) = current.as_ref()
            && connection.quic.close_reason().is_none()
            && connection.next.load(Ordering::Acquire)
                < if connection.version == 4 {
                    u32::MAX
                } else {
                    65535
                }
        {
            return Ok(connection.clone());
        }
        let candidates = tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
            .await?
            .take(32)
            .collect::<Vec<_>>();
        let mut last = Error::InvalidAddress;
        for peer in candidates {
            let endpoint = quinn::Endpoint::client(if peer.is_ipv6() {
                "[::]:0".parse().map_err(|_| config::invalid())?
            } else {
                "0.0.0.0:0".parse().map_err(|_| config::invalid())?
            })?;
            let connecting = endpoint
                .connect_with(self.tls.clone(), peer, &self.server_name)
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
                version: self.credential.version(),
                mode: self.mode,
                next: AtomicU32::new(1),
                active: AtomicUsize::new(0),
                entries: Mutex::new(HashMap::new()),
                fragments: Mutex::new(Reassembler::new()),
                tasks: Mutex::new(JoinSet::new()),
                activity: Mutex::new(Instant::now()),
            });
            connection.start(self.heartbeat);
            *current = Some(connection.clone());
            return Ok(connection);
        }
        Err(last)
    }
}
impl Outbound for Client {
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
                .run(async { self.connection().await?.association() })
                .await
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let connection = self.connection().await?;
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
                    connection.active.fetch_add(1, Ordering::AcqRel);
                    connection.touch();
                    Ok(Box::new(crate::io::QuicIo {
                        send,
                        recv,
                        owner: Some(connection),
                    }) as BoxStream)
                })
                .await
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
