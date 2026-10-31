use crate::{address, config, udp};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result, StreamConnector,
};
use serde_json::Value;
use shadowsocks::{
    ServerConfig,
    config::ServerType,
    context::{Context, SharedContext},
    relay::tcprelay::ProxyClientStream,
};
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub struct Ss2022Outbound {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) server: Destination,
    pub(crate) crypto: SharedContext,
    connector: Option<Arc<dyn StreamConnector>>,
}

impl Ss2022Outbound {
    pub fn from_options(options: &Value) -> Result<Self> {
        let parsed = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("SS2022 出站字段不合法".into()))?;
        let (config, server) = config::client(parsed)?;
        Ok(Self {
            config: Arc::new(config),
            server,
            crypto: Context::new_shared(ServerType::Local),
            connector: None,
        })
    }
    pub fn from_options_with_connector(
        options: &Value,
        connector: Arc<dyn StreamConnector>,
    ) -> Result<Self> {
        let mut outbound = Self::from_options(options)?;
        outbound.connector = Some(connector);
        Ok(outbound)
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
            udp: self.connector.is_none(),
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let carrier: BoxStream = if let Some(connector) = &self.connector {
                        connector.connect_tcp(&self.server, context).await?
                    } else {
                        let tcp =
                            TcpStream::connect((self.server.host().as_str(), self.server.port()))
                                .await?;
                        tcp.set_nodelay(true)?;
                        Box::new(tcp)
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
            if self.connector.is_some() {
                return Err(Error::Unsupported("SS2022 流包装出站不提供原生 UDP"));
            }
            context
                .run(udp::connect(self, target, context.cancel.clone()))
                .await
        })
    }
}

pub struct Ss2022Factory;
impl OutboundFactory for Ss2022Factory {
    fn kind(&self) -> &'static str {
        "ss2022"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        Ok(Arc::new(Ss2022Outbound::from_options(options)?))
    }
}
