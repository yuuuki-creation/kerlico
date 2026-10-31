//! ShadowTLS 代理载体包装；网站目标始终由真实内层协议编码并经统一出口访问。
mod client;
mod config;
mod prefix;
mod server;
mod stream;
mod tls;
mod v2;
mod wire;

use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, InboundContext, InboundProtocol, Outbound,
    Result, ScopedCredentialFingerprint, StreamConnector,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct ShadowTlsFactory;
impl OutboundFactory for ShadowTlsFactory {
    fn kind(&self) -> &'static str {
        "shadowtls"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        let value: config::Client = config::parse(options)?;
        let key = value.validate()?;
        let connector: Arc<dyn StreamConnector> = Arc::new(client::Connector {
            version: value.version,
            strict: value.strict(),
            key,
            settings: tls::settings(&value.tls, value.version, value.strict())?,
        });
        match value.inner.kind.as_str() {
            "shadowsocks" => Ok(Arc::new(
                kerlico_shadowsocks::ShadowsocksOutbound::from_options_with_connector(
                    &value.inner.options,
                    connector,
                )?,
            )),
            "ss2022" => Ok(Arc::new(
                kerlico_ss2022::Ss2022Outbound::from_options_with_connector(
                    &value.inner.options,
                    connector,
                )?,
            )),
            _ => Err(config::invalid()),
        }
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
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let settings: config::Server = config::parse(options)?;
        let keys = settings.validate()?;
        let inner: Arc<dyn InboundProtocol> = match settings.inner.kind.as_str() {
            "shadowsocks" => Arc::new(kerlico_shadowsocks::ShadowsocksNode::from_options(
                &settings.inner.options,
            )?),
            "ss2022" => Arc::new(kerlico_ss2022::Ss2022Node::from_options(
                &settings.inner.options,
            )?),
            _ => return Err(config::invalid()),
        };
        if inner.credential_fingerprints().is_empty() {
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
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        let mut keys = self.inner.credential_fingerprints();
        keys.extend(self.keys.iter().map(|key| fingerprint(key)));
        keys
    }
    fn scoped_credential_fingerprints(
        &self,
        _default_protocol: &str,
    ) -> Vec<ScopedCredentialFingerprint> {
        let mut keys = self
            .inner
            .scoped_credential_fingerprints(&self.settings.inner.kind);
        keys.extend(self.keys.iter().map(|key| ScopedCredentialFingerprint {
            protocol: "shadowtls".into(),
            fingerprint: fingerprint(key),
        }));
        keys
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
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let handshake = ConnectContext {
                cancel: context.cancel.clone(),
                timeout: context.connect_timeout,
            };
            let outcome = handshake
                .run(server::negotiate(
                    stream,
                    &self.settings,
                    &self.keys,
                    context.cancel.clone(),
                ))
                .await?;
            match outcome {
                server::Outcome::Ready(stream) => self.inner.handle(stream, access, context).await,
                server::Outcome::Fallback(front, origin) => {
                    kerlico_core::relay_tcp(front, origin, context.idle_timeout, context.cancel)
                        .await
                }
            }
        })
    }
}
