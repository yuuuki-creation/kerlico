use crate::{address, config, crypto, udp};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result, StreamConnector,
};
use serde_json::Value;
use shadowsocks::{
    ServerConfig, config::ServerType, context::SharedContext, relay::tcprelay::ProxyClientStream,
};
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub struct ShadowsocksOutbound {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) server: Destination,
    pub(crate) crypto: SharedContext,
    connector: Option<Arc<dyn StreamConnector>>,
}
impl ShadowsocksOutbound {
    pub fn from_options(options: &Value) -> Result<Self> {
        let parsed = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Shadowsocks 出站字段不合法".into()))?;
        let (config, server) = config::client(parsed)?;
        Ok(Self {
            config: Arc::new(config),
            server,
            crypto: crypto(ServerType::Local),
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
impl Outbound for ShadowsocksOutbound {
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
                    // 空写发送目标首部，目标可在本地尚未发送业务数据时回包。
                    if stream.write(&[]).await? != 0 {
                        return Err(crate::protocol_error());
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
                return Err(Error::Unsupported("Shadowsocks 流包装出站不提供原生 UDP"));
            }
            context
                .run(udp::connect(self, target, context.cancel.clone()))
                .await
        })
    }
}
pub struct ShadowsocksFactory;
impl OutboundFactory for ShadowsocksFactory {
    fn kind(&self) -> &'static str {
        "shadowsocks"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        Ok(Arc::new(ShadowsocksOutbound::from_options(options)?))
    }
}
