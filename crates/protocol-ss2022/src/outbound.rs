use crate::{address, config, udp};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result,
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
        })
    }
}

impl Outbound for Ss2022Outbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
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
                    let tcp = TcpStream::connect((self.server.host().as_str(), self.server.port()))
                        .await?;
                    tcp.set_nodelay(true)?;
                    let mut stream = ProxyClientStream::from_stream(
                        self.crypto.clone(),
                        tcp,
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
