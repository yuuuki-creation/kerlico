//! TUIC v4/v5 双端，QUIC 多路复用与统一 Full Cone 目标访问分离。
mod client;
mod codec;
mod config;
mod io;
mod server;
mod wire;
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{InboundProtocol, Outbound, Result};
use serde_json::Value;
use std::sync::Arc;
pub struct TuicFactory;
pub struct TuicNodeFactory;
impl OutboundFactory for TuicFactory {
    fn kind(&self) -> &'static str {
        "tuic"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn Outbound>> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        Ok(Arc::new(client::Client::build(options)?))
    }
}
impl NodeFactory for TuicNodeFactory {
    fn kind(&self) -> &'static str {
        "tuic"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        Ok(Arc::new(server::Node::build(options)?))
    }
}
