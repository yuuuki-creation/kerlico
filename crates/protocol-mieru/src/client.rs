//! 每个出站独立持有身份和连接池；单逻辑取消不取消其他逻辑流的共享载体。
use crate::{
    codec,
    config::{self, ClientOptions, Transport, User},
    crypto::{self, Key, StreamCipher},
    packet,
    session::{self, Link, Scope, SessionIo, TcpSettings},
    udp,
};
use kerlico_config::OutboundPlan;
use kerlico_core::{
    Address, BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, Outbound, ResourceKey, Result, ServiceContext,
    TargetPolicy,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{Mutex, Semaphore},
};
type MemberPool = Mutex<Vec<Arc<Link>>>;
pub(crate) struct Client {
    server: Destination,
    user: Arc<User>,
    transport: Transport,
    traffic: config::Traffic,
    multiplexing: bool,
    no_wait: bool,
    idle: Duration,
    mtu: usize,
    cancel: CancellationToken,
    slots: Arc<Semaphore>,
    pool: Mutex<HashMap<ResourceKey, Arc<MemberPool>>>,
    host: ServiceContext,
}
impl Client {
    pub fn compile(options: ClientOptions) -> Result<OutboundPlan> {
        let transport = Transport::parse(&options.transport, options.unsafe_udp_compatibility)?;
        let server = options.server.destination()?;
        if transport == Transport::LocalUnsafeUdp {
            config::require_literal_loopback(&server)?;
        }
        options.traffic.validate()?;
        let idle =
            config::validate_limits(options.max_sessions, options.idle_timeout_secs, options.mtu)?;
        let user = User::new(options.username, options.password)?;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: false,
                udp: true,
            },
            true,
            TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(Self {
                        server,
                        user,
                        transport,
                        traffic: options.traffic,
                        multiplexing: options.multiplexing,
                        no_wait: options.no_wait,
                        idle,
                        mtu: options.mtu,
                        cancel: host.cancel().child_token(),
                        slots: Arc::new(Semaphore::new(options.max_sessions)),
                        pool: Mutex::new(HashMap::new()),
                        host,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
    async fn connection(&self, context: &ConnectContext) -> Result<Arc<Link>> {
        let bucket = {
            let mut pools = self.pool.lock().await;
            pools
                .entry(context.resource_key().clone())
                .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
                .clone()
        };
        let mut pool = bucket.lock().await;
        pool.retain(|link| !link.scope.cancel.is_cancelled());
        if let Some(link) = pool.iter().find(|link| link.reusable()) {
            return Ok(link.clone());
        }
        if pool.len() >= 128 || self.cancel.is_cancelled() {
            return Err(Error::ResourceLimit);
        }
        let endpoint = match self.server.address() {
            Address::Ip(ip) => SocketAddr::new(*ip, self.server.port()),
            Address::Domain(name) => {
                let mut addresses = tokio::net::lookup_host((name.as_str(), self.server.port()))
                    .await?
                    .take(32)
                    .collect::<Vec<_>>();
                addresses.sort_by_key(|address| address.is_ipv6());
                *addresses.first().ok_or(Error::InvalidAddress)?
            }
        };
        let scope = Scope::shared(&self.host);
        let key = Key::new(self.user.clone(), crypto::epoch(crypto::now()?));
        let settings = TcpSettings {
            traffic: self.traffic.clone(),
            idle: self.idle,
            connect_timeout: context.timeout.min(self.idle),
            multiplexing: self.multiplexing,
            server: None,
        };
        let link = match self.transport {
            Transport::Tcp => {
                let stream = TcpStream::connect(endpoint).await?;
                stream.set_nodelay(true)?;
                session::tcp_link(
                    Box::new(stream),
                    StreamCipher::new(key.clone()),
                    StreamCipher::new(key),
                    scope,
                    settings,
                    None,
                )
            }
            Transport::LocalUnsafeUdp => {
                if !endpoint.ip().is_loopback() || endpoint.ip().to_canonical() != endpoint.ip() {
                    return Err(config::invalid());
                }
                let bind = if endpoint.is_ipv6() {
                    SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0)
                } else {
                    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)
                };
                let socket = Arc::new(UdpSocket::bind(bind).await?);
                packet::start(
                    socket,
                    scope,
                    packet::Settings {
                        common: settings,
                        mtu: self.mtu,
                        key: Some(key),
                        peer: Some(endpoint),
                        users: None,
                        replay: None,
                    },
                )?
            }
        };
        pool.push(link.clone());
        Ok(link)
    }
    async fn stream(
        &self,
        target: Option<&Destination>,
        context: &ConnectContext,
    ) -> Result<SessionIo> {
        context
            .run(async {
                let slot = self
                    .slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::Cancelled)?;
                let link = self.connection(context).await?;
                let (stream, response) = link
                    .open(codec::request(target).into(), self.no_wait, slot, context)
                    .await?;
                if !self.no_wait {
                    response.await.map_err(|_| Error::Rejected)??;
                }
                Ok(stream)
            })
            .await
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(pool) = self.pool.try_lock() {
            for bucket in pool.values() {
                if let Ok(links) = bucket.try_lock() {
                    for link in links.iter() {
                        link.stop();
                    }
                }
            }
        }
    }
}
impl Outbound for Client {
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.cancel.cancel();
            let buckets = { std::mem::take(&mut *self.pool.lock().await) };
            for bucket in buckets.into_values() {
                let links = { std::mem::take(&mut *bucket.lock().await) };
                for link in links {
                    link.scope.shutdown().await;
                }
            }
            Ok(())
        })
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: true,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            Ok(kerlico_core::OpenedTcp {
                stream: Box::new(self.stream(Some(target), context).await?),
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move { Ok(udp::association(self.stream(None, context).await?)) })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            if matches!(target.address(), Address::Domain(_)) {
                return Err(Error::Unsupported(
                    "固定 Mieru UDP 通道不支持远端域名目标；多目标使用 UDP 关联",
                ));
            }
            Ok(udp::fixed(
                self.associate_udp(context).await?,
                target.clone(),
            ))
        })
    }
}
