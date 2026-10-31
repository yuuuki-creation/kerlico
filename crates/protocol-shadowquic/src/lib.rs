//! ShadowQUIC 双端，JLS 鉴权、QUIC 传输与统一目标访问分离。
mod client;
mod codec;
mod config;
mod io;
mod runtime;
mod server;
mod session;
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{InboundProtocol, Outbound, Result};
use serde_json::Value;
use std::sync::Arc;
pub struct ShadowQuicFactory;
pub struct ShadowQuicNodeFactory;
impl OutboundFactory for ShadowQuicFactory {
    fn kind(&self) -> &'static str {
        "shadowquic"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn Outbound>> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        Ok(Arc::new(client::Client::build(options)?))
    }
}
impl NodeFactory for ShadowQuicNodeFactory {
    fn kind(&self) -> &'static str {
        "shadowquic"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        Ok(Arc::new(server::Node::build(options)?))
    }
}
