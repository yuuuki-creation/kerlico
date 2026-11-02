//! 客户端在完整 JLS 双向认证后暴露业务；不会把普通 TLS 成功当作认证成功。
use crate::{
    codec::Mode,
    config::{self, ClientOptions},
    runtime::{RuntimeGuard, ScopedRuntime},
    session::{Connection, EndpointOwner},
};
use jls_quinn::Runtime;
use kerlico_config::OutboundPlan;
use kerlico_core::{
    BoxFuture, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, Error, Outbound, ResourceKey, Result,
    ServiceContext, TargetPolicy,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
type MemberConnection = tokio::sync::Mutex<Option<Arc<Connection>>>;
pub(crate) struct Client {
    server: Destination,
    name: String,
    version: u32,
    mode: Mode,
    crypto: jls_quinn::ClientConfig,
    host: ServiceContext,
    current: tokio::sync::Mutex<HashMap<ResourceKey, Arc<MemberConnection>>>,
}
impl Client {
    pub fn compile(options: ClientOptions) -> Result<OutboundPlan> {
        if !(5..=3600).contains(&options.idle_timeout_secs) {
            return Err(config::invalid());
        }
        config::validate_name(&options.server_name)?;
        let version = config::version(&options.quic_version)?;
        let mode = config::mode(&options.udp_mode)?;
        let user = config::User::parse(options.username, options.password)?;
        let transport = config::transport(
            &options.congestion_control,
            Duration::from_secs(options.idle_timeout_secs),
            0,
            true,
        )?;
        let server = options.server.destination()?;
        let crypto =
            config::client_crypto(&user, config::alpn_bytes(options.alpn)?, transport, version)?;
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
                        name: options.server_name,
                        version,
                        mode,
                        crypto,
                        host,
                        current: tokio::sync::Mutex::new(HashMap::new()),
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
    async fn connection(&self, context: &ConnectContext) -> Result<Arc<Connection>> {
        let bucket = {
            let mut buckets = self.current.lock().await;
            buckets
                .entry(context.resource_key().clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                .clone()
        };
        let mut current = bucket.lock().await;
        if let Some(value) = current.as_ref()
            && value.quic.close_reason().is_none()
            && !value.exhausted()
        {
            return Ok(value.clone());
        }
        let mut candidates =
            tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
                .await?
                .take(32)
                .collect::<Vec<_>>();
        candidates.sort_by_key(|address| address.is_ipv6());
        let peer = *candidates.first().ok_or(Error::InvalidAddress)?;
        let runtime = ScopedRuntime::shared(&self.host);
        let mut guard = RuntimeGuard::new(runtime.clone());
        let socket = std::net::UdpSocket::bind(if peer.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })?;
        socket.set_nonblocking(true)?;
        let socket = runtime.wrap_udp_socket(socket)?;
        let endpoint = jls_quinn::Endpoint::new_with_jls_socket(
            config::endpoint(vec![self.version])?,
            None,
            socket,
            runtime.clone(),
            jls_quinn::JlsForwardConfig::default(),
        )?;
        let mut crypto = self.crypto.clone();
        crypto.token_store(Arc::new(jls_quinn::TokenMemoryCache::default()));
        let connection = endpoint
            .connect_with(crypto, peer, &self.name)
            .map_err(|_| config::invalid())?
            .await
            .map_err(|_| Error::Protocol("ShadowQUIC JLS 握手失败"))?;
        if connection.is_jls() != Some(true) {
            connection.close(0u32.into(), b"");
            return Err(Error::Rejected);
        }
        let value = Connection::new(
            connection,
            Some(EndpointOwner { endpoint, runtime }),
            None,
            None,
            Some(self.host.clone()),
        );
        guard.disarm();
        *current = Some(value.clone());
        Ok(value)
    }
}
impl Outbound for Client {
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.host.cancel().cancel();
            let buckets = { std::mem::take(&mut *self.current.lock().await) };
            for bucket in buckets.into_values() {
                let connection = { bucket.lock().await.take() };
                if let Some(connection) = connection {
                    connection.shutdown().await;
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
                .run(async {
                    self.connection(context)
                        .await?
                        .open_association(self.mode)
                        .await
                })
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
                .run(async { self.connection(context).await?.open_tcp(target).await })
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
    sender: Box<dyn kerlico_core::DatagramAssociationSender>,
    target: Destination,
}
struct FixedReceiver {
    receiver: Box<dyn kerlico_core::DatagramAssociationReceiver>,
    target: Destination,
}
impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.sender.send_to(bytes, &self.target)
    }
}
impl DatagramReceiver for FixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
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
