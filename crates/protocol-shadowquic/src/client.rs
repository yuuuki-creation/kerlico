//! 客户端在完整 JLS 双向认证后暴露业务；不会把普通 TLS 成功当作认证成功。
use crate::{
    codec::Mode,
    config::{self, ClientOptions},
    runtime::{RuntimeGuard, ScopedRuntime},
    session::{Connection, EndpointOwner},
};
use jls_quinn::Runtime;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, Error, Outbound, Result,
};
use std::{sync::Arc, time::Duration};
pub(crate) struct Client {
    server: Destination,
    name: String,
    version: u32,
    mode: Mode,
    crypto: jls_quinn::ClientConfig,
    current: tokio::sync::Mutex<Option<Arc<Connection>>>,
}
impl Client {
    pub fn build(options: ClientOptions) -> Result<Self> {
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
        Ok(Self {
            server: options.server.destination()?,
            name: options.server_name,
            version,
            mode,
            crypto: config::client_crypto(
                &user,
                config::alpn_bytes(options.alpn)?,
                transport,
                version,
            )?,
            current: tokio::sync::Mutex::new(None),
        })
    }
    async fn connection(&self) -> Result<Arc<Connection>> {
        let mut current = self.current.lock().await;
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
        let runtime = ScopedRuntime::new();
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
        let connection = endpoint
            .connect_with(self.crypto.clone(), peer, &self.name)
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
        );
        guard.disarm();
        *current = Some(value.clone());
        Ok(value)
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
                .run(async { self.connection().await?.open_association(self.mode).await })
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
                .run(async { self.connection().await?.open_tcp(target).await })
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
