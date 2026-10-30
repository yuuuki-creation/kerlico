use crate::{config, destination};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    Result,
};
use serde_json::Value;
use shadowsocks::{
    ServerConfig,
    config::ServerType,
    context::{Context, SharedContext},
    relay::tcprelay::ProxyServerStream,
};
use std::sync::Arc;

pub struct Ss2022Node {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) crypto: SharedContext,
    fingerprints: Vec<[u8; 32]>,
}
impl Ss2022Node {
    pub fn from_options(options: &Value) -> Result<Self> {
        let parsed = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("SS2022 节点字段不合法".into()))?;
        let (config, fingerprints) = config::node(parsed)?;
        Ok(Self {
            config: Arc::new(config),
            crypto: Context::new_shared(ServerType::Server),
            fingerprints,
        })
    }
}
impl InboundProtocol for Ss2022Node {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.fingerprints.clone()
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn supports_udp(&self) -> bool {
        true
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve_udp(socket, access, context))
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let handshake = ConnectContext {
                cancel: context.cancel.clone(),
                timeout: context.connect_timeout,
            };
            let (local, remote) = handshake
                .run(async {
                    let mut local = ProxyServerStream::from_stream_with_user_manager(
                        self.crypto.clone(),
                        stream,
                        self.config.method(),
                        self.config.key(),
                        self.config.clone_user_manager(),
                    );
                    let target = destination(&local.handshake().await?)?;
                    let remote = access.connect_tcp(&target, &handshake).await?;
                    Ok((Box::new(local) as BoxStream, remote))
                })
                .await?;
            kerlico_core::relay_tcp(local, remote, context.idle_timeout, context.cancel).await
        })
    }
}

pub struct Ss2022NodeFactory;
impl NodeFactory for Ss2022NodeFactory {
    fn kind(&self) -> &'static str {
        "ss2022"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(Ss2022Node::from_options(options)?))
    }
}
