use crate::{
    config::{Config, Options},
    session::{self, Session},
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, OpenedTcp, Outbound, ResourceKey, Result, ServiceContext,
    TargetPolicy,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: true,
    udp: true,
};
/// ocserv 按错误口令累计封禁分；由流量驱动的重新认证必须限速，否则一次配错就会封禁本机地址。
const REJECTED_BACKOFF: Duration = Duration::from_secs(60);

pub struct OpenConnectFactory;
impl OutboundFactory for OpenConnectFactory {
    fn kind(&self) -> &'static str {
        "openconnect"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("OpenConnect 出站字段不合法".into()))?;
        let config = options.prepare()?;
        Ok(OutboundPlan::new(
            CAPABILITIES,
            true,
            TargetPolicy::Local,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(OpenConnect {
                        config,
                        cancel: host.cancel().child_token(),
                        host,
                        slots: Mutex::new(HashMap::new()),
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}

#[derive(Default)]
struct Slot {
    session: Option<Arc<Session>>,
    rejected_until: Option<Instant>,
}

struct OpenConnect {
    config: Config,
    host: ServiceContext,
    cancel: CancellationToken,
    slots: Mutex<HashMap<ResourceKey, Arc<Mutex<Slot>>>>,
}
impl Drop for OpenConnect {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl OpenConnect {
    async fn session(&self, context: &ConnectContext) -> Result<Arc<Session>> {
        context
            .run(async {
                let slot = self
                    .slots
                    .lock()
                    .await
                    .entry(context.resource_key().clone())
                    .or_default()
                    .clone();
                let mut slot = slot.lock().await;
                if let Some(session) = slot.session.as_ref().filter(|session| !session.is_closed())
                {
                    return Ok(session.clone());
                }
                if slot
                    .rejected_until
                    .is_some_and(|until| Instant::now() < until)
                {
                    return Err(Error::Rejected);
                }
                match session::establish(&self.config, &self.host, &self.cancel).await {
                    Ok(session) => {
                        let session = Arc::new(session);
                        slot.session = Some(session.clone());
                        slot.rejected_until = None;
                        Ok(session)
                    }
                    Err(Error::Rejected) => {
                        slot.rejected_until = Some(Instant::now() + REJECTED_BACKOFF);
                        Err(Error::Rejected)
                    }
                    Err(error) => Err(error),
                }
            })
            .await
    }
}
impl Outbound for OpenConnect {
    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async {
            self.cancel.cancel();
            Ok(())
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            let session = self.session(context).await?;
            session.tunnel.connect_tcp(target, context).await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let session = self.session(context).await?;
            session.tunnel.connect_udp(target, context)
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            let session = self.session(context).await?;
            session.tunnel.associate_udp(context)
        })
    }
}
