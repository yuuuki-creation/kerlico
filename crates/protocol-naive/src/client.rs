//! 每个出站独有连接池；不跨身份共用TLS、HTTP会话或padding状态。
use crate::{
    config::{self, ClientOptions, Transport, UotOptions, User},
    http, padding, tls, transport, uot,
};
use bytes::Bytes;
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, Outbound, Result, StreamConnector,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
enum Sender {
    H2(AsyncMutex<h2::client::SendRequest<Bytes>>),
    H3(AsyncMutex<transport::H3Client>),
}
struct Session {
    sender: Sender,
    slots: Arc<Semaphore>,
    limit: usize,
    cancel: CancellationToken,
    closed: AtomicBool,
    last: Mutex<Instant>,
    _endpoint: Option<quinn::Endpoint>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct Lease {
    session: Arc<Session>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut last) = self.session.last.lock() {
            *last = Instant::now();
        }
    }
}
impl Session {
    fn permit(self: &Arc<Self>) -> Option<Lease> {
        self.slots
            .clone()
            .try_acquire_owned()
            .ok()
            .map(|permit| Lease {
                session: self.clone(),
                _permit: permit,
            })
    }
    fn start<F>(self: &Arc<Self>, driver: F, idle: Duration, quic: Option<quinn::Connection>)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let weak = Arc::downgrade(self);
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let watch = async {
                loop {
                    tokio::time::sleep(idle.min(Duration::from_secs(1))).await;
                    let Some(session) = weak.upgrade() else {
                        return;
                    };
                    let expired = session
                        .last
                        .lock()
                        .map(|last| last.elapsed() >= idle)
                        .unwrap_or(true);
                    if session.slots.available_permits() == session.limit && expired {
                        return;
                    }
                }
            };
            tokio::select! {biased;_=cancel.cancelled()=>{},_=driver=>{},_=watch=>{}}
            if let Some(session) = weak.upgrade() {
                session.closed.store(true, Ordering::Release);
                session.cancel.cancel();
            }
            if let Some(connection) = quic {
                connection.close(0u32.into(), b"session closed");
            }
        });
    }
}
pub(crate) struct Client {
    server: Destination,
    user: Arc<User>,
    transport: Transport,
    tls: Arc<rustls::ClientConfig>,
    server_name: String,
    uot: UotOptions,
    max_sessions: usize,
    max_streams: usize,
    idle: Duration,
    congestion: String,
    connector: Arc<dyn StreamConnector>,
    sessions: AsyncMutex<Vec<Arc<Session>>>,
    h1: Arc<Semaphore>,
    cancel: CancellationToken,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Client {
    pub(crate) fn new(
        options: ClientOptions,
        connector: Option<Arc<dyn StreamConnector>>,
    ) -> Result<Self> {
        options.udp_over_tcp.validate()?;
        let idle = config::limits(
            options.max_sessions,
            options.max_streams,
            options.idle_session_timeout_ms,
        )?;
        if !matches!(options.congestion_control.as_str(), "cubic" | "reno")
            || options.transport != Transport::H3 && options.congestion_control != "cubic"
            || connector.is_some() && options.transport == Transport::H3
        {
            return Err(config::invalid());
        }
        let config = tls::client(&options.tls, options.transport)?;
        Ok(Self {
            server: options.server.destination()?,
            user: Arc::new(User::new(options.username, options.password)?),
            transport: options.transport,
            tls: config,
            server_name: options.tls.server_name,
            uot: options.udp_over_tcp,
            max_sessions: options.max_sessions,
            max_streams: options.max_streams,
            idle,
            congestion: options.congestion_control,
            connector: connector.unwrap_or_else(|| Arc::new(kerlico_net::TcpConnector::plain())),
            sessions: AsyncMutex::new(Vec::new()),
            h1: Arc::new(Semaphore::new(options.max_sessions)),
            cancel: CancellationToken::new(),
        })
    }
    async fn tcp(&self, context: &ConnectContext) -> Result<BoxStream> {
        let carrier = self.connector.connect_tcp(&self.server, context).await?;
        let name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| config::invalid())?;
        let stream = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, carrier)
            .await?;
        let wanted = if self.transport == Transport::H1 {
            b"http/1.1".as_slice()
        } else {
            b"h2".as_slice()
        };
        if stream.get_ref().1.alpn_protocol() != Some(wanted) {
            return Err(config::malformed());
        }
        Ok(Box::new(stream))
    }
    async fn create_session(&self, context: &ConnectContext) -> Result<Arc<Session>> {
        let cancel = self.cancel.child_token();
        let last = Mutex::new(Instant::now());
        if self.transport == Transport::H2 {
            let stream = self.tcp(context).await?;
            let mut builder = h2::client::Builder::new();
            builder
                .initial_window_size(256 * 1024)
                .initial_connection_window_size(4 * 1024 * 1024)
                .max_header_list_size(config::HEADER_LIMIT as u32)
                .max_send_buffer_size(config::BUFFER * 2);
            let (sender, connection) = builder
                .handshake(stream)
                .await
                .map_err(|_| config::malformed())?;
            let session = Arc::new(Session {
                sender: Sender::H2(AsyncMutex::new(sender)),
                slots: Arc::new(Semaphore::new(self.max_streams)),
                limit: self.max_streams,
                cancel,
                closed: AtomicBool::new(false),
                last,
                _endpoint: None,
            });
            session.start(
                async move {
                    let _ = connection.await;
                },
                self.idle,
                None,
            );
            Ok(session)
        } else {
            let mut addresses = tokio::net::lookup_host((self.server.host(), self.server.port()))
                .await?
                .collect::<Vec<_>>();
            addresses.sort_by_key(|a| a.is_ipv6());
            let address = *addresses.first().ok_or(Error::InvalidAddress)?;
            let bind = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let mut endpoint_config = quinn::EndpointConfig::default();
            endpoint_config.supported_versions(vec![1]);
            let socket = std::net::UdpSocket::bind(bind)?;
            socket.set_nonblocking(true)?;
            let mut endpoint =
                quinn::Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))?;
            endpoint.set_default_client_config(tls::quic_client(
                self.tls.clone(),
                tls::quic_transport(self.idle, self.max_streams, &self.congestion)?,
            )?);
            let connection = endpoint
                .connect(address, &self.server_name)
                .map_err(|_| config::malformed())?
                .await
                .map_err(|_| config::malformed())?;
            let (mut driver, sender) = h3::client::builder()
                .max_field_section_size(config::HEADER_LIMIT as u64)
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(|_| config::malformed())?;
            let session = Arc::new(Session {
                sender: Sender::H3(AsyncMutex::new(sender)),
                slots: Arc::new(Semaphore::new(self.max_streams)),
                limit: self.max_streams,
                cancel,
                closed: AtomicBool::new(false),
                last,
                _endpoint: Some(endpoint),
            });
            session.start(
                async move {
                    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
                },
                self.idle,
                Some(connection),
            );
            Ok(session)
        }
    }
    async fn lease(&self, context: &ConnectContext) -> Result<Lease> {
        let mut pool = self.sessions.lock().await;
        pool.retain(|session| !session.closed.load(Ordering::Acquire));
        for session in pool.iter() {
            if let Some(lease) = session.permit() {
                return Ok(lease);
            }
        }
        if pool.len() < self.max_sessions {
            let session = self.create_session(context).await?;
            let lease = session.permit().ok_or(Error::ResourceLimit)?;
            pool.push(session);
            return Ok(lease);
        }
        let candidates = pool.clone();
        drop(pool);
        let mut waits = futures_util::stream::FuturesUnordered::new();
        for session in candidates {
            waits.push(async move {
                let permit = session
                    .slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::ResourceLimit)?;
                if session.closed.load(Ordering::Acquire) {
                    return Err(Error::Rejected);
                }
                Ok(Lease {
                    session,
                    _permit: permit,
                })
            });
        }
        use futures_util::StreamExt;
        waits.next().await.ok_or(Error::ResourceLimit)?
    }
    async fn raw(&self, target: &Destination, context: &ConnectContext) -> Result<BoxStream> {
        let request = http::request(target, &self.user)?;
        let raw = if self.transport == Transport::H1 {
            let permit = self
                .h1
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::ResourceLimit)?;
            let mut stream = self.tcp(context).await?;
            http::write_request(&mut stream, &request).await?;
            let response = http::read_response(&mut stream).await?;
            http::check_response(&response)?;
            crate::io::spawn(
                context.cancel.clone(),
                Some(Box::new(permit)),
                move |mut peer, complete| async move {
                    let (mut reader, mut writer) = tokio::io::split(stream);
                    let (mut local_read, mut local_write) = tokio::io::split(&mut peer);
                    let incoming = async {
                        let result = async {
                            tokio::io::copy(&mut reader, &mut local_write).await?;
                            tokio::io::AsyncWriteExt::shutdown(&mut local_write).await
                        }
                        .await;
                        complete.finish_read(&result);
                        result
                    };
                    let outgoing = complete.writing(async {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut bytes = vec![0; config::BUFFER];
                        loop {
                            let size = local_read.read(&mut bytes).await?;
                            if size == 0 {
                                break;
                            }
                            writer.write_all(&bytes[..size]).await?;
                            writer.flush().await?;
                            complete.advance_write(size);
                        }
                        writer.shutdown().await
                    });
                    tokio::try_join!(incoming, outgoing)?;
                    Ok(())
                },
            )
        } else {
            let lease = self.lease(context).await?;
            let session = lease.session.clone();
            match &session.sender {
                Sender::H2(sender) => {
                    let sender = sender.lock().await.clone();
                    let mut sender = sender.ready().await.map_err(|_| config::malformed())?;
                    let (response, writer) = sender
                        .send_request(request, false)
                        .map_err(|_| config::malformed())?;
                    let response = response.await.map_err(|_| config::malformed())?;
                    http::check_response(&response)?;
                    transport::h2(
                        response.into_body(),
                        writer,
                        context.cancel.clone(),
                        Some(Box::new(lease)),
                    )
                }
                Sender::H3(sender) => {
                    let mut stream = sender
                        .lock()
                        .await
                        .send_request(request)
                        .await
                        .map_err(|_| config::malformed())?;
                    let response = stream
                        .recv_response()
                        .await
                        .map_err(|_| config::malformed())?;
                    http::check_response(&response)?;
                    transport::h3_client(stream, context.cancel.clone(), Some(Box::new(lease)))
                }
            }
        };
        Ok(padding::wrap(raw, context.cancel.clone()))
    }
}
impl Outbound for Client {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: self.uot.enabled,
        }
    }
    fn supports_udp_association(&self) -> bool {
        self.uot.enabled
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            if uot::version(target).is_some() {
                return Err(Error::Rejected);
            }
            context.run(self.raw(target, context)).await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            if !self.uot.enabled {
                return Err(Error::Unsupported("Naive UDP 需要显式启用 UoT"));
            }
            context
                .run(async {
                    let mut stream = self.raw(&uot::magic(self.uot.version)?, context).await?;
                    uot::request(&mut stream, self.uot, Some(target)).await?;
                    Ok(uot::channel(
                        stream,
                        self.uot,
                        target,
                        context.cancel.clone(),
                    ))
                })
                .await
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            if !self.uot.enabled {
                return Err(Error::Unsupported("Naive UDP 需要显式启用 UoT"));
            }
            context
                .run(async {
                    let mut stream = self.raw(&uot::magic(self.uot.version)?, context).await?;
                    uot::request(&mut stream, self.uot, None).await?;
                    Ok(uot::association(stream, context.cancel.clone()))
                })
                .await
        })
    }
}
