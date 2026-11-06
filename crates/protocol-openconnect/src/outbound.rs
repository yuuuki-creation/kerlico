use crate::{
    config::{Config, Options},
    session::{self, Session},
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, LoginBackoff, OpenedTcp, Outbound, ResourceKey, Result,
    ServiceContext, TargetPolicy,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::Mutex;

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: true,
    udp: true,
};

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
                        login: Mutex::default(),
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
    fn supports_detour(&self) -> bool {
        true
    }
}

type Slot = Arc<Mutex<Option<Arc<Session>>>>;

struct OpenConnect {
    config: Config,
    host: ServiceContext,
    cancel: CancellationToken,
    slots: Mutex<HashMap<ResourceKey, Slot>>,
    /// ocserv 按错误口令累计封禁分，而账号属于整个出站：不同来源也必须共用退避并串行登录。
    login: Mutex<LoginBackoff>,
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
                if let Some(session) = slot.as_ref().filter(|session| !session.is_closed()) {
                    return Ok(session.clone());
                }
                let mut login = self.login.lock().await;
                login.check(Instant::now())?;
                let established = session::establish(&self.config, &self.host, &self.cancel).await;
                login.record(Instant::now(), &established);
                let session = Arc::new(established?);
                *slot = Some(session.clone());
                Ok(session)
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

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_core::{FamilyMode, NodeId, Source};
    use serde_json::json;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn failed_login_backs_off_for_every_source_of_the_outbound() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let logins = Arc::new(AtomicUsize::new(0));
        let counted = logins.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let options: Options = serde_json::from_value(json!({
            "server": {"host": "127.0.0.1", "port": port},
            "username": "u",
            "password": "p",
        }))
        .unwrap();
        let host = ServiceContext::for_test();
        let outbound = OpenConnect {
            config: options.prepare().unwrap(),
            cancel: host.cancel().child_token(),
            host: host.clone(),
            slots: Mutex::new(HashMap::new()),
            login: Mutex::default(),
        };
        for node in ["source-a", "source-b", "source-c"] {
            let context = ConnectContext::new(Duration::from_secs(5)).scoped(
                &host,
                &Source::Local {
                    node: NodeId::parse(node).unwrap(),
                },
                CancellationToken::new(),
                CancellationToken::new(),
                FamilyMode::V4Only,
            );
            assert!(outbound.session(&context).await.is_err());
        }
        assert_eq!(logins.load(Ordering::SeqCst), 1);
    }
}
