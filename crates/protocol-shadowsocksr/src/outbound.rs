use crate::{address, config::Shared, protocol::Role, stream, udp};
use bytes::BytesMut;
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Error, Outbound, Result,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Semaphore};

pub struct ShadowsocksROutbound {
    pub(crate) cfg: Arc<Shared>,
    pub(crate) server: Destination,
    pub(crate) slots: Arc<Semaphore>,
}
impl ShadowsocksROutbound {
    pub fn from_options(options: &Value) -> Result<Self> {
        let (cfg, server) = Shared::client(options)?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(cfg.limits.max_sessions)),
            cfg,
            server,
        })
    }
}
impl Outbound for ShadowsocksROutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: self.cfg.udp,
        }
    }
    fn supports_udp_association(&self) -> bool {
        self.cfg.udp
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let permit = self
                        .slots
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| Error::ResourceLimit)?;
                    let raw = TcpStream::connect((self.server.host().as_str(), self.server.port()))
                        .await?;
                    raw.set_nodelay(true)?;
                    let mut plain = stream::Stream::new(
                        Box::new(raw),
                        self.cfg.clone(),
                        Role::Client,
                        context.cancel.clone(),
                        self.server.host(),
                        self.server.port(),
                    )?;
                    let mut header = BytesMut::new();
                    address(target).write_to_buf(&mut header);
                    plain.write_all(&header).await?;
                    plain.flush().await?;
                    Ok(Box::new(plain.with_permit(permit)) as BoxStream)
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
                .run(udp::fixed(self, target, context.cancel.clone()))
                .await
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            context
                .run(udp::association(self, context.cancel.clone()))
                .await
        })
    }
}
pub struct ShadowsocksRFactory;
impl OutboundFactory for ShadowsocksRFactory {
    fn kind(&self) -> &'static str {
        "shadowsocksr"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        Ok(Arc::new(ShadowsocksROutbound::from_options(options)?))
    }
}
