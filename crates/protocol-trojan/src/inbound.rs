use crate::{
    codec,
    config::{ServerSecurity, Transport, TransportInput, server_tls},
    invalid, key,
};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, InboundContext, InboundProtocol, Result,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};
pub struct TrojanNodeFactory;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    passwords: Vec<String>,
    security: ServerSecurity,
    #[serde(default)]
    transport: TransportInput,
}
pub(crate) struct Payload {
    pub users: Vec<[u8; 56]>,
}
struct TrojanNode {
    payload: Arc<Payload>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    transport: Transport,
}
impl NodeFactory for TrojanNodeFactory {
    fn kind(&self) -> &'static str {
        "trojan"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let mut options: Options =
            serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        if let Some(password) = options.password {
            if !options.passwords.is_empty() {
                return Err(invalid());
            }
            options.passwords.push(password);
        }
        if options.passwords.is_empty() || options.passwords.len() > 256 {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for password in options.passwords {
            let value = key(&password)?;
            if !seen.insert(value) {
                return Err(invalid());
            }
            users.push(value);
        }
        let transport = options.transport.normalize()?;
        let tls = server_tls(options.security, &transport)?;
        Ok(Arc::new(TrojanNode {
            payload: Arc::new(Payload { users }),
            tls,
            transport,
        }))
    }
}
impl InboundProtocol for TrojanNode {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.payload
            .users
            .iter()
            .map(|key| {
                let mut hash = Sha256::new();
                hash.update(b"kerlico/trojan/node-password/");
                hash.update(key);
                hash.finalize().into()
            })
            .collect()
    }
    fn requires_loopback(&self) -> bool {
        self.tls.is_none()
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let connect = ConnectContext {
                cancel: context.cancel.clone(),
                timeout: context.connect_timeout,
            };
            let stream: BoxStream = connect
                .run(async {
                    match &self.tls {
                        Some(tls) => Ok(Box::new(tls.accept(stream).await?) as BoxStream),
                        None => Ok(stream),
                    }
                })
                .await?;
            let (stream, activity) = crate::io::observe(stream);
            if self.transport.raw() {
                crate::io::bounded(
                    self.payload.serve(stream, access, context.clone()),
                    activity,
                    context.idle_timeout,
                    context.cancel.clone(),
                )
                .await
            } else {
                crate::io::bounded(
                    crate::http_server::serve(
                        stream,
                        self.transport.clone(),
                        self.payload.clone(),
                        access,
                        context.clone(),
                    ),
                    activity,
                    context.idle_timeout,
                    context.cancel.clone(),
                )
                .await
            }
        })
    }
}
impl Payload {
    pub async fn serve(
        &self,
        mut stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let connect = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let (target, udp) = connect
            .run(codec::request(&mut stream, &self.users))
            .await?;
        if udp {
            return crate::udp::serve(stream, access, context).await;
        }
        let remote = access.connect_tcp(&target, &connect).await?;
        kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
    }
}
