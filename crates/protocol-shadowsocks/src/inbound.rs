use crate::{config, crypto, destination};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    Result,
};
use serde_json::Value;
use shadowsocks::{
    ServerConfig, config::ServerType, context::SharedContext, crypto::CipherKind,
    relay::tcprelay::ProxyServerStream,
};
use std::sync::Arc;

pub struct ShadowsocksNode {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) crypto: SharedContext,
    fingerprints: Vec<[u8; 32]>,
}
impl ShadowsocksNode {
    pub fn from_options(options: &Value) -> Result<Self> {
        let parsed = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Shadowsocks 节点字段不合法".into()))?;
        let (config, fingerprints) = config::node(parsed)?;
        Ok(Self {
            config: Arc::new(config),
            crypto: crypto(ServerType::Server),
            fingerprints,
        })
    }
}
impl InboundProtocol for ShadowsocksNode {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.fingerprints.clone()
    }
    fn requires_loopback(&self) -> bool {
        self.config.method() == CipherKind::NONE
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
                    let mut local = ProxyServerStream::from_stream(
                        self.crypto.clone(),
                        stream,
                        self.config.method(),
                        self.config.key(),
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
pub struct ShadowsocksNodeFactory;
impl NodeFactory for ShadowsocksNodeFactory {
    fn kind(&self) -> &'static str {
        "shadowsocks"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(ShadowsocksNode::from_options(options)?))
    }
}
