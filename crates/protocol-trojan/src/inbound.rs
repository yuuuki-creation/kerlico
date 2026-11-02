use crate::{
    codec,
    config::{ServerSecurity, Transport, TransportInput, server_tls},
    invalid, key,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};
pub struct TrojanNodeFactory;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    security: ServerSecurity,
    #[serde(default)]
    transport: TransportInput,
}
pub(crate) struct Payload {
    pub users: CredentialSet<[u8; 56]>,
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
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options =
            serde_json::from_value(input.options().clone()).map_err(|_| invalid())?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Credential {
            password: String,
        }
        let credentials = input
            .native_credentials()
            .iter()
            .map(|value| serde_json::from_value::<Credential>(value.clone()).map_err(|_| invalid()))
            .collect::<Result<Vec<_>>>()?;
        if credentials.is_empty() || credentials.len() > 256 {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for credential in credentials {
            let value = key(&credential.password)?;
            if !seen.insert(value) {
                return Err(invalid());
            }
            users.push(value);
        }
        let transport = options.transport.normalize()?;
        let tls = server_tls(options.security, &transport)?;
        Ok(Arc::new(TrojanNode {
            payload: Arc::new(Payload {
                users: input.credentials(users)?,
            }),
            tls,
            transport,
        }))
    }
}
impl InboundProtocol for TrojanNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, key)) in self.payload.users.rows().enumerate() {
            let mut hash = Sha256::new();
            hash.update(b"kerlico/trojan/node-password/");
            hash.update(key);
            manifest.authentication("trojan", slot, hash.finalize().into());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        self.tls.is_none()
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let connect =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
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
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        let connect =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let (slot, target, udp) = connect
            .run(codec::request(&mut stream, &self.users))
            .await?;
        let (access, (target, udp)) =
            access.authenticated(self.users.verified(&slot, (target, udp))?, &context)?;
        if udp {
            return crate::udp::serve(stream, access, context).await;
        }
        let remote = access.connect_tcp(&target, &connect).await?;
        kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
    }
}
