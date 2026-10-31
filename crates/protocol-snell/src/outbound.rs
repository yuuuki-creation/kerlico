use crate::{
    config::{Mode, Obfs, Settings, userkey},
    invalid, obfs,
    stream::{Pool, Session, Stream},
    wire,
};
use kerlico_config::{OutboundFactory, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Outbound,
    Result,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
pub struct SnellFactory;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    server: TargetSpec,
    version: u8,
    psk: String,
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
    pool: Arc<Pool>,
}
impl OutboundFactory for SnellFactory {
    fn kind(&self) -> &'static str {
        "snell"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        let options: Options = serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        let settings = Arc::new(Settings::new(
            options.version,
            options.psk,
            options.mode,
            options.obfs_mode,
            options.obfs_host,
            options.obfs_uri,
            false,
        )?);
        let server = options.server.destination()?;
        let userkey = userkey(&options.userkey)?;
        if settings.raw() && (!server.is_loopback() || userkey.is_empty()) {
            return Err(invalid());
        }
        Ok(Arc::new(SnellOutbound {
            server,
            settings,
            userkey,
            reuse: options.reuse,
            pool: Pool::new(10),
        }))
    }
}
impl SnellOutbound {
    async fn session(&self, reuse: bool) -> Result<Session> {
        if reuse {
            self.pool.start();
            if let Some(session) = self.pool.take() {
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
                    let mut session = self.session(self.reuse).await?;
                    session
                        .send(&wire::request(
                            if self.reuse { 5 } else { 1 },
                            &self.userkey,
                            Some(target),
                        ))
                        .await?;
                    let pool = if self.reuse {
                        Some(self.pool.clone())
                    } else {
                        None
                    };
                    Ok(
                        Box::new(Stream::new(session, true, Vec::new(), pool, self.reuse))
                            as BoxStream,
                    )
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
                .run(async {
                    let mut session = self.session(false).await?;
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
