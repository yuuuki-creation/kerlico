use crate::{address, config, crypto, udp};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Error, Outbound, Result, StreamConnector,
};
use serde_json::Value;
use shadowsocks::{
    ServerConfig, config::ServerType, context::SharedContext, relay::tcprelay::ProxyClientStream,
};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub struct ShadowsocksOutbound {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) server: Destination,
    pub(crate) crypto: SharedContext,
    connector: Option<Arc<dyn StreamConnector>>,
    pub(crate) dialer: kerlico_core::DialerOptions,
    uot_version: Option<u8>,
    mux: Option<Arc<kerlico_net::sing_mux::SingMuxClient>>,
}
impl ShadowsocksOutbound {
    pub fn compile_with_connector(
        options: &Value,
        connector: Option<Arc<dyn StreamConnector>>,
    ) -> Result<OutboundPlan> {
        let parsed = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Shadowsocks 出站字段不合法".into()))?;
        let prepared = config::client(parsed)?;
        let config = prepared.config;
        let server = prepared.target;
        let uot_version = prepared.uot_version;
        let mux = prepared
            .multiplex
            .map(|cfg| Arc::new(kerlico_net::sing_mux::SingMuxClient::new(cfg)));
        let dialer = kerlico_core::current_compile_dialer();
        let connector = match (connector, prepared.plugin) {
            (Some(c), _) => Some(c),
            (None, Some(plugin)) => {
                Some(crate::plugin::PluginConnector::new(plugin, dialer.clone())
                    as Arc<dyn StreamConnector>)
            }
            (None, None) => None,
        };
        let has_udp = connector.is_none()
            || uot_version.is_some()
            || mux.as_ref().is_some_and(|m| m.handles_udp());
        let has_assoc = uot_version.is_some() || mux.as_ref().is_some_and(|m| m.handles_udp());
        let capabilities = Capabilities {
            tcp: true,
            tcp_eof: connector
                .as_ref()
                .is_none_or(|connector| connector.tcp_eof()),
            udp: has_udp,
        };
        Ok(OutboundPlan::new(
            capabilities,
            has_assoc,
            kerlico_core::TargetPolicy::Remote,
            move |_host| {
                Box::pin(async move {
                    Ok(Arc::new(Self {
                        config: Arc::new(config),
                        server,
                        crypto: crypto(ServerType::Local),
                        connector,
                        dialer,
                        uot_version,
                        mux,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }

    async fn open_ss_stream(
        &self,
        target: &Destination,
        context: &ConnectContext,
    ) -> Result<BoxStream> {
        let mut carrier: BoxStream = if let Some(connector) = &self.connector {
            connector.connect_tcp(&self.server, context).await?
        } else {
            self.dialer.connect(&self.server).await?
        };
        if self.config.method() == shadowsocks::crypto::CipherKind::NONE {
            let mut buf = bytes::BytesMut::new();
            address(target).write_to_buf(&mut buf);
            carrier.write_all(&buf).await?;
            carrier.flush().await?;
            return Ok(carrier);
        }
        let mut stream = ProxyClientStream::from_stream(
            self.crypto.clone(),
            carrier,
            &self.config,
            address(target),
        );
        if stream.write(&[]).await? != 0 {
            return Err(crate::protocol_error());
        }
        stream.flush().await?;
        Ok(Box::new(stream))
    }
}
impl Outbound for ShadowsocksOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: self
                .connector
                .as_ref()
                .is_none_or(|connector| connector.tcp_eof()),
            udp: self.connector.is_none()
                || self.uot_version.is_some()
                || self.mux.as_ref().is_some_and(|m| m.handles_udp()),
        }
    }
    fn supports_udp_association(&self) -> bool {
        self.uot_version.is_some() || self.mux.as_ref().is_some_and(|m| m.handles_udp())
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            context
                .run(async {
                    if let Some(mux) = &self.mux
                        && mux.handles_tcp()
                    {
                        return mux
                            .connect_tcp(target, |magic| async move {
                                self.open_ss_stream(&magic, context).await
                            })
                            .await;
                    }
                    let stream = self.open_ss_stream(target, context).await?;
                    Ok(kerlico_core::OpenedTcp {
                        stream,
                        info: kerlico_core::TcpConnectInfo::unknown(),
                    })
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
            if let Some(mux) = &self.mux
                && mux.handles_udp()
            {
                return context
                    .run(mux.connect_udp(target, |magic| async move {
                        self.open_ss_stream(&magic, context).await
                    }))
                    .await;
            }
            if let Some(version) = self.uot_version {
                return context
                    .run(async {
                        let magic = kerlico_net::uot::magic_destination(version)?;
                        let mut stream = self.open_ss_stream(&magic, context).await?;
                        kerlico_net::uot::write_request(&mut stream, version, Some(target)).await?;
                        Ok(kerlico_net::uot::channel(
                            stream,
                            version,
                            target,
                            context.cancel.clone(),
                        ))
                    })
                    .await;
            }
            if self.connector.is_some() {
                return Err(Error::Unsupported("Shadowsocks 流包装出站不提供原生 UDP"));
            }
            context
                .run(udp::connect(self, target, context.cancel.clone()))
                .await
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            if let Some(mux) = &self.mux
                && mux.handles_udp()
            {
                return context
                    .run(mux.associate_udp(|magic| async move {
                        self.open_ss_stream(&magic, context).await
                    }))
                    .await;
            }
            if let Some(version) = self.uot_version {
                return context
                    .run(async {
                        let magic = kerlico_net::uot::magic_destination(version)?;
                        let mut stream = self.open_ss_stream(&magic, context).await?;
                        kerlico_net::uot::write_request(&mut stream, version, None).await?;
                        Ok(kerlico_net::uot::association(
                            stream,
                            context.cancel.clone(),
                        ))
                    })
                    .await;
            }
            Err(Error::Unsupported(
                "当前 Shadowsocks 出站未启用 UoT 或多路复用 UDP 关联",
            ))
        })
    }
}
pub struct ShadowsocksFactory;
impl OutboundFactory for ShadowsocksFactory {
    fn kind(&self) -> &'static str {
        "shadowsocks"
    }
    fn supports_detour(&self) -> bool {
        true
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        ShadowsocksOutbound::compile_with_connector(options, None)
    }
}
