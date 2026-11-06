use crate::{address, config, udp};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Error, Outbound, Result, StreamConnector,
};
use kerlico_net::sing_mux::SingMuxClient;
use serde_json::Value;
use shadowsocks::{
    ServerConfig,
    config::ServerType,
    context::{Context, SharedContext},
    relay::tcprelay::ProxyClientStream,
};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub struct Ss2022Outbound {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) server: Destination,
    pub(crate) crypto: SharedContext,
    connector: Option<Arc<dyn StreamConnector>>,
    pub(crate) dialer: kerlico_core::DialerOptions,
    mux: Option<Arc<SingMuxClient>>,
}

impl Ss2022Outbound {
    pub fn compile_with_connector(
        options: &Value,
        connector: Option<Arc<dyn StreamConnector>>,
    ) -> Result<OutboundPlan> {
        let parsed = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Ss2022 出站字段不合法".into()))?;
        let prepared = config::client(parsed)?;
        let (config, server) = (prepared.config, prepared.target);
        let mux = prepared
            .multiplex
            .map(|cfg| Arc::new(SingMuxClient::new(cfg)));
        let dialer = kerlico_core::current_compile_dialer();
        let mux_udp = mux.as_ref().is_some_and(|m| m.handles_udp());
        let capabilities = Capabilities {
            tcp: true,
            tcp_eof: connector
                .as_ref()
                .is_none_or(|connector| connector.tcp_eof()),
            udp: connector.is_none() || mux_udp,
        };
        Ok(OutboundPlan::new(
            capabilities,
            mux_udp,
            kerlico_core::TargetPolicy::Remote,
            move |_host| {
                Box::pin(async move {
                    Ok(Arc::new(Self {
                        config: Arc::new(config),
                        server,
                        crypto: Context::new_shared(ServerType::Local),
                        connector,
                        dialer,
                        mux,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }

    fn udp_mux(&self) -> Option<&SingMuxClient> {
        self.mux.as_deref().filter(|m| m.handles_udp())
    }

    async fn open_stream(
        &self,
        target: &Destination,
        context: &ConnectContext,
    ) -> Result<BoxStream> {
        let carrier: BoxStream = if let Some(connector) = &self.connector {
            connector.connect_tcp(&self.server, context).await?
        } else {
            self.dialer.connect(&self.server).await?
        };
        let mut stream = ProxyClientStream::from_stream(
            self.crypto.clone(),
            carrier,
            &self.config,
            address(target),
        );
        // 空写触发带随机 padding 的首部，允许目标先发送数据。
        let written = stream.write(&[]).await?;
        if written != 0 {
            return Err(Error::Protocol("SS2022 空首部写入长度异常"));
        }
        stream.flush().await?;
        Ok(Box::new(stream))
    }
}

impl Outbound for Ss2022Outbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: self
                .connector
                .as_ref()
                .is_none_or(|connector| connector.tcp_eof()),
            udp: self.connector.is_none() || self.udp_mux().is_some(),
        }
    }
    fn supports_udp_association(&self) -> bool {
        self.udp_mux().is_some()
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            context
                .run(async {
                    if let Some(mux) = self.mux.as_deref().filter(|m| m.handles_tcp()) {
                        return mux
                            .connect_tcp(target, |magic| async move {
                                self.open_stream(&magic, context).await
                            })
                            .await;
                    }
                    Ok(kerlico_core::OpenedTcp {
                        stream: self.open_stream(target, context).await?,
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
            if let Some(mux) = self.udp_mux() {
                return context
                    .run(mux.connect_udp(target, |magic| async move {
                        self.open_stream(&magic, context).await
                    }))
                    .await;
            }
            if self.connector.is_some() {
                return Err(Error::Unsupported("SS2022 流包装出站不提供原生 UDP"));
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
            let Some(mux) = self.udp_mux() else {
                return Err(Error::Unsupported("SS2022 出站未启用多路复用 UDP 关联"));
            };
            context
                .run(
                    mux.associate_udp(
                        |magic| async move { self.open_stream(&magic, context).await },
                    ),
                )
                .await
        })
    }
}

pub struct Ss2022Factory;
impl OutboundFactory for Ss2022Factory {
    fn kind(&self) -> &'static str {
        "ss2022"
    }
    fn supports_detour(&self) -> bool {
        true
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        Ss2022Outbound::compile_with_connector(options, None)
    }
}
