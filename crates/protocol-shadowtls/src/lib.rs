//! ShadowTLS 代理载体包装；网站目标始终由真实内层协议编码并经统一出口访问。
mod client;
mod config;
mod prefix;
mod server;
mod stream;
mod tls;
mod v2;
mod wire;

use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, InboundContext, InboundProtocol,
    IngressBinding, Result,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct ShadowTlsFactory;
impl OutboundFactory for ShadowTlsFactory {
    fn kind(&self) -> &'static str {
        "shadowtls"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let value: config::Client = config::parse(options)?;
        let key = value.validate()?;
        let connector = Arc::new(client::Connector {
            version: value.version,
            strict: value.strict(),
            key,
            settings: tls::settings(&value.tls, value.version, value.strict())?,
            host: std::sync::OnceLock::new(),
        });
        let plan = match value.inner.kind.as_str() {
            "shadowsocks" => kerlico_shadowsocks::ShadowsocksOutbound::compile_with_connector(
                &value.inner.options,
                Some(connector.clone()),
            ),
            "ss2022" => kerlico_ss2022::Ss2022Outbound::compile_with_connector(
                &value.inner.options,
                Some(connector.clone()),
            ),
            _ => Err(config::invalid()),
        }?;
        Ok(OutboundPlan::new(
            plan.capabilities(),
            plan.supports_udp_association(),
            plan.target_policy(),
            move |host| {
                Box::pin(async move {
                    connector
                        .host
                        .set(host.clone())
                        .map_err(|_| kerlico_core::Error::Protocol("ShadowTLS 出站重复启动"))?;
                    plan.start(host).await
                })
            },
        ))
    }
}
pub struct ShadowTlsNodeFactory;
pub struct ShadowTlsNode {
    settings: config::Server,
    keys: Vec<Arc<[u8]>>,
    inner: Arc<dyn InboundProtocol>,
}
impl NodeFactory for ShadowTlsNodeFactory {
    fn kind(&self) -> &'static str {
        "shadowtls"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let settings: config::Server = config::parse(input.options())?;
        let keys = settings.validate()?;
        let inner: Arc<dyn InboundProtocol> = match settings.inner.kind.as_str() {
            "shadowsocks" => Arc::new(kerlico_shadowsocks::ShadowsocksNode::from_context(
                &input.with_options(settings.inner.options.clone()),
            )?),
            "ss2022" => Arc::new(kerlico_ss2022::Ss2022Node::from_context(
                &input.with_options(settings.inner.options.clone()),
            )?),
            _ => return Err(config::invalid()),
        };
        if !inner.credential_manifest().entries().iter().any(|entry| {
            matches!(
                entry.purpose,
                kerlico_core::CredentialPurpose::Authentication { .. }
            )
        }) {
            return Err(config::invalid());
        }
        Ok(Arc::new(ShadowTlsNode {
            settings,
            keys,
            inner,
        }))
    }
}
fn fingerprint(key: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"shadowtls/password\0");
    hash.update(key);
    hash.finalize().into()
}
impl InboundProtocol for ShadowTlsNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = self.inner.credential_manifest();
        for key in &self.keys {
            if !key.is_empty() {
                manifest.protection("shadowtls", fingerprint(key));
            }
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn supports_udp(&self) -> bool {
        false
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let handshake =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let outcome = handshake
                .run(server::negotiate(
                    stream,
                    &self.settings,
                    &self.keys,
                    context.cancel.clone(),
                    context.tasks.clone(),
                ))
                .await?;
            match outcome {
                server::Outcome::Ready(stream) => self.inner.handle(stream, access, context).await,
                server::Outcome::Fallback(front, origin) => {
                    kerlico_core::relay_streams(front, origin, context.idle_timeout, context.cancel)
                        .await
                }
            }
        })
    }
}
