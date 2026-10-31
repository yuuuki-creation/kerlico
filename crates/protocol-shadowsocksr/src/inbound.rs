use crate::{config::Shared, destination, protocol::Role, stream};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    Result,
};
use serde_json::Value;
use shadowsocks::relay::socks5::Address;
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::Semaphore};

pub struct ShadowsocksRNode {
    pub(crate) cfg: Arc<Shared>,
    pub(crate) slots: Arc<Semaphore>,
}
impl ShadowsocksRNode {
    pub fn from_options(options: &Value) -> Result<Self> {
        let cfg = Shared::node(options)?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(cfg.limits.max_sessions)),
            cfg,
        })
    }
}
impl InboundProtocol for ShadowsocksRNode {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.cfg.fingerprints()
    }
    fn requires_loopback(&self) -> bool {
        !self.cfg.authenticated()
    }
    fn requires_udp_association(&self) -> bool {
        self.cfg.udp
    }
    fn supports_udp(&self) -> bool {
        self.cfg.udp
    }
    fn handle<'a>(
        &'a self,
        raw: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.cfg.authenticated()
                && !context
                    .local_addr
                    .is_some_and(|address| address.ip().is_loopback())
            {
                return Err(Error::Unsupported(
                    "未鉴权 SSR 组合只能用作明确的回环本地接入",
                ));
            }
            let _permit = self
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?;
            let establish = ConnectContext {
                cancel: context.cancel.clone(),
                timeout: context.connect_timeout,
            };
            let mut plain = stream::Stream::new(
                raw,
                self.cfg.clone(),
                Role::Server,
                context.cancel.clone(),
                String::new(),
                0,
            )?;
            let remote = establish
                .run(async {
                    let target = Address::read_from(&mut plain)
                        .await
                        .map_err(|_| crate::invalid())?;
                    let target = destination(&target)?;
                    access.connect_tcp(&target, &establish).await
                })
                .await?;
            kerlico_core::relay_tcp(
                Box::new(plain),
                remote,
                context.idle_timeout,
                context.cancel,
            )
            .await
        })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve_udp(socket, access, context))
    }
}
pub struct ShadowsocksRNodeFactory;
impl NodeFactory for ShadowsocksRNodeFactory {
    fn kind(&self) -> &'static str {
        "shadowsocksr"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(ShadowsocksRNode::from_options(options)?))
    }
}
