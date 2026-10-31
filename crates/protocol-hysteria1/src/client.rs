//! v1 鉴权完成后才打开业务流；每个工厂维护本节点独立的 QUIC 连接缓存。
use crate::{
    config::{self, ClientOptions, Limits},
    dispatch::{Hub, Sender},
    io::QuicIo,
    protocol, wire,
};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Error, Outbound, Result,
};
use serde_json::Value;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task::JoinSet};
pub struct Hysteria1Factory;
type Cache = tokio::sync::Mutex<Option<Arc<Connection>>>;
pub(crate) struct Connection {
    pub connection: quinn::Connection,
    pub endpoint: quinn::Endpoint,
    pub hub: Hub,
    pub sender: Sender,
    pub cancel: kerlico_core::CancellationToken,
    pub slots: Arc<Semaphore>,
    pub udp: bool,
    pub limits: Limits,
    _socket: crate::socket::Close,
    control: Mutex<Option<QuicIo>>,
    tasks: Mutex<JoinSet<()>>,
    last: Mutex<Instant>,
}
impl Connection {
    pub fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Ok(mut tasks) = self.tasks.lock() {
            while tasks.try_join_next().is_some() {}
            tasks.spawn(future);
        }
    }
    pub fn touch(&self) {
        if let Ok(mut time) = self.last.lock() {
            *time = Instant::now();
        }
    }
    fn start(self: &Arc<Self>, cache: Weak<Cache>) {
        if self.udp {
            let weak = Arc::downgrade(self);
            let connection = self.connection.clone();
            let cancel = self.cancel.clone();
            self.spawn(async move{loop {let bytes=tokio::select!{biased;_=cancel.cancelled()=>break,result=connection.read_datagram()=>match result{Ok(bytes)=>bytes,Err(_)=>break}};let Some(state)=weak.upgrade()else{break;};state.hub.input(&bytes);}if let Some(state)=weak.upgrade(){state.cancel.cancel();state.hub.close();}});
        }
        let weak = Arc::downgrade(self);
        let connection = self.connection.clone();
        let cancel = self.cancel.clone();
        let idle = self.limits.idle();
        self.spawn(async move {
            let mut ticks=tokio::time::interval((idle/4).clamp(Duration::from_millis(20),Duration::from_secs(1)));
            loop {
                tokio::select! {
                    _=cancel.cancelled()=>break,
                    _=connection.closed()=>break,
                    _=ticks.tick()=>{
                        let Some(state)=weak.upgrade()else{break;};state.hub.prune();
                        let Some(cache)=cache.upgrade()else{continue;};let Ok(mut cached)=cache.try_lock()else{continue;};
                        let is_current=cached.as_ref().is_some_and(|current|Arc::ptr_eq(current,&state));
                        if is_current&&Arc::strong_count(&state)==2&&state.last.lock().is_ok_and(|time|time.elapsed()>=idle) {
                            cached.take();state.cancel.cancel();state.hub.close();connection.close(0u32.into(),b"");break;
                        }
                    }
                }
            }
            if let Some(state)=weak.upgrade(){state.cancel.cancel();state.hub.close();if let Some(cache)=cache.upgrade()&&let Ok(mut cached)=cache.try_lock()&&cached.as_ref().is_some_and(|current|Arc::ptr_eq(current,&state)){cached.take();}}
        });
    }
    pub fn weak(self: &Arc<Self>) -> Weak<Self> {
        Arc::downgrade(self)
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.hub.close();
        self.connection.close(0u32.into(), b"");
        self.endpoint.close(0u32.into(), b"");
        if let Ok(tasks) = self.tasks.get_mut() {
            tasks.abort_all();
        }
        if let Ok(control) = self.control.get_mut() {
            control.take();
        }
    }
}
struct Client {
    server: Destination,
    auth: Arc<[u8]>,
    up: u64,
    down: u64,
    tls: quinn::ClientConfig,
    name: String,
    socket: Arc<crate::socket::Settings>,
    limits: Limits,
    udp: bool,
    slots: Arc<Semaphore>,
    connected: Arc<Cache>,
}
impl OutboundFactory for Hysteria1Factory {
    fn kind(&self) -> &'static str {
        "hysteria1"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        let options: ClientOptions =
            serde_json::from_value(options.clone()).map_err(|_| crate::invalid())?;
        options.limits.validate()?;
        config::rate(options.up_bps, false)?;
        config::rate(options.down_bps, false)?;
        let auth = Arc::from(config::auth(options.auth_str, options.auth)?);
        let transport = options.limits.transport(0, options.udp)?;
        let (tls, name) = config::client_tls(options.tls, transport)?;
        let socket = Arc::new(crate::socket::Settings {
            carrier: options.transport,
            key: config::obfs(options.obfs)?,
        });
        let slots = Arc::new(Semaphore::new(options.limits.max_streams));
        Ok(Arc::new(Client {
            server: options.server.destination()?,
            auth,
            up: options.up_bps,
            down: options.down_bps,
            tls,
            name,
            socket,
            limits: options.limits,
            udp: options.udp,
            slots,
            connected: Arc::new(tokio::sync::Mutex::new(None)),
        }))
    }
}
impl Client {
    async fn offer(&self) -> Result<Arc<Connection>> {
        let mut cached = self.connected.lock().await;
        if let Some(state) = cached.as_ref()
            && state.connection.close_reason().is_none()
            && !state.cancel.is_cancelled()
        {
            state.touch();
            return Ok(state.clone());
        }
        cached.take();
        let mut addresses: Vec<SocketAddr> =
            tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
                .await?
                .collect();
        addresses.sort_by_key(|address| address.is_ipv6());
        let remote = addresses.first().copied().ok_or(Error::InvalidAddress)?;
        let socket = std::net::UdpSocket::bind(if remote.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })?;
        socket.set_nonblocking(true)?;
        let (socket, socket_close) = crate::socket::wrap(socket, self.socket.clone())?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.supported_versions(vec![1]);
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.tls.clone());
        let connection = endpoint
            .connect(remote, &self.name)
            .map_err(|_| protocol())?
            .await
            .map_err(|_| protocol())?;
        let (send, recv) = connection.open_bi().await.map_err(|_| protocol())?;
        let mut control = QuicIo::new(send, recv);
        wire::write_hello(&mut control, self.up, self.down, &self.auth).await?;
        let (_send, receive) = wire::read_server_hello(&mut control).await?;
        crate::congestion::negotiated(&connection, self.up.min(receive))?;
        let udp = self.udp && connection.max_datagram_size().is_some();
        let state = Arc::new(Connection {
            connection,
            endpoint,
            hub: Hub::new(
                self.limits.udp_queue_packets,
                self.limits.udp_queue_bytes,
                wire::MAX_PACKET,
            ),
            sender: Sender::new(),
            cancel: kerlico_core::CancellationToken::new(),
            slots: self.slots.clone(),
            udp,
            limits: self.limits.clone(),
            _socket: socket_close,
            control: Mutex::new(Some(control)),
            tasks: Mutex::new(JoinSet::new()),
            last: Mutex::new(Instant::now()),
        });
        state.start(Arc::downgrade(&self.connected));
        *cached = Some(state.clone());
        Ok(state)
    }
    async fn association(&self) -> Result<DatagramAssociation> {
        if !self.udp {
            return Err(Error::Unsupported("Hysteria v1 出站已禁用 UDP"));
        }
        let state = self.offer().await?;
        if !state.udp {
            return Err(Error::Unsupported("Hysteria v1 对端未启用 UDP"));
        }
        let permit = state
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        let (send, recv) = state.connection.open_bi().await.map_err(|_| protocol())?;
        let mut stream = QuicIo::new(send, recv);
        wire::write_request(&mut stream, true, None).await?;
        let session = wire::read_response(&mut stream).await?;
        crate::udp::client_channel(state, session, stream, permit)
    }
}
impl Outbound for Client {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: self.udp,
        }
    }
    fn supports_udp_association(&self) -> bool {
        self.udp
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move { context.run(self.association()).await })
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let state = self.offer().await?;
                    let permit = state
                        .slots
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| Error::ResourceLimit)?;
                    let (send, recv) = state.connection.open_bi().await.map_err(|_| protocol())?;
                    let mut stream = QuicIo::new(send, recv).with_owner(state, permit);
                    wire::write_request(&mut stream, false, Some(target)).await?;
                    wire::read_response(&mut stream).await?;
                    Ok(Box::new(stream) as BoxStream)
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
            context
                .run(async {
                    let association = self.association().await?;
                    Ok(crate::udp::fixed(association, target.clone()))
                })
                .await
        })
    }
}
