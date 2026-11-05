use crate::{
    config::{Mode, Obfs, Settings, userkey},
    invalid, obfs,
    stream::{Pool, Session, Stream},
    wire,
};
use kerlico_config::{OutboundFactory, OutboundPlan, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Outbound,
    Result,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
pub struct SnellFactory;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    server: TargetSpec,
    version: u8,
    psk: String,
    #[serde(default)]
    cipher: Option<String>,
    #[serde(default)]
    userkey: String,
    #[serde(default)]
    reuse: bool,
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    obfs_mode: Obfs,
    #[serde(default)]
    obfs_host: Option<String>,
    #[serde(default)]
    obfs_uri: Option<String>,
}
struct SnellOutbound {
    server: Destination,
    settings: Arc<Settings>,
    userkey: Vec<u8>,
    reuse: bool,
    pools: Mutex<HashMap<kerlico_core::ResourceKey, Arc<Pool>>>,
    host: kerlico_core::ServiceContext,
}
impl OutboundFactory for SnellFactory {
    fn kind(&self) -> &'static str {
        "snell"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        let settings = Arc::new(
            Settings::new(
                options.version,
                options.psk,
                options.mode,
                options.obfs_mode,
                options.obfs_host,
                options.obfs_uri,
                false,
            )?
            .with_cipher(options.cipher.as_deref())?,
        );
        let server = options.server.destination()?;
        let userkey = userkey(&options.userkey)?;
        if settings.raw() && (!server.is_loopback() || userkey.is_empty()) {
            return Err(invalid());
        }
        let reuse = options.reuse;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            },
            false,
            kerlico_core::TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(SnellOutbound {
                        server,
                        settings,
                        userkey,
                        reuse,
                        pools: Mutex::new(HashMap::new()),
                        host,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}
impl SnellOutbound {
    fn pool(&self, context: &ConnectContext) -> Result<Arc<Pool>> {
        if self.host.cancel().is_cancelled() {
            return Err(kerlico_core::Error::Cancelled);
        }
        let mut pools = self.pools.lock().map_err(|_| invalid())?;
        Ok(pools
            .entry(context.resource_key().clone())
            .or_insert_with(|| Pool::new(10))
            .clone())
    }
    async fn session(&self, pool: &Arc<Pool>, reuse: bool) -> Result<Session> {
        if reuse {
            pool.start(&self.host)?;
            if let Some(session) = pool.take() {
                return Ok(session);
            }
        }
        let stream = kerlico_net::TcpConnector::plain()
            .connect(&self.server)
            .await?;
        let stream = obfs::wrap(stream, &self.settings, false).await?;
        Ok(Session::new(stream, self.settings.clone())?)
    }
}
impl Outbound for SnellOutbound {
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let pools = std::mem::take(&mut *self.pools.lock().map_err(|_| invalid())?);
            for pool in pools.into_values() {
                pool.shutdown().await?;
            }
            Ok(())
        })
    }
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
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            let opening: kerlico_core::BoxFuture<'_, Result<BoxStream>> = Box::pin(async move {
                context
                    .run(async {
                        let pool = self.pool(context)?;
                        let mut session = self.session(&pool, self.reuse).await?;
                        session
                            .send(&wire::request(
                                if self.reuse { 5 } else { 1 },
                                &self.userkey,
                                Some(target),
                            ))
                            .await?;
                        let pool = if self.reuse { Some(pool) } else { None };
                        Ok(
                            Box::new(Stream::new(session, true, Vec::new(), pool, self.reuse))
                                as BoxStream,
                        )
                    })
                    .await
            });
            let stream = opening.await?;
            Ok(kerlico_core::OpenedTcp {
                stream,
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            context
                .run(async {
                    let pool = self.pool(context)?;
                    let mut session = self.session(&pool, false).await?;
                    session.send(&wire::request(6, &self.userkey, None)).await?;
                    let reply = session.reader.next().await?.ok_or_else(crate::protocol)?;
                    if !wire::reply(reply)?.is_empty() {
                        return Err(crate::protocol());
                    }
                    Ok(crate::udp::channel(session, target.clone()))
                })
                .await
        })
    }
}
