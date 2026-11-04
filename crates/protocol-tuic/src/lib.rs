//! TUIC v4/v5 双端，QUIC 多路复用与统一 Full Cone 目标访问分离。
mod client;
mod codec;
mod config;
mod flow;
mod io;
mod runtime;
mod server;
mod socket;
mod wire;
use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory, OutboundPlan};
use kerlico_core::{InboundProtocol, Result};
use serde_json::Value;
use std::sync::Arc;
pub struct TuicFactory;
pub struct TuicNodeFactory;
impl OutboundFactory for TuicFactory {
    fn kind(&self) -> &'static str {
        "tuic"
    }
    fn compile(&self, value: &Value) -> Result<OutboundPlan> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        client::Client::compile(options)
    }
}
impl NodeFactory for TuicNodeFactory {
    fn kind(&self) -> &'static str {
        "tuic"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(server::Node::build(input)?))
    }
}
