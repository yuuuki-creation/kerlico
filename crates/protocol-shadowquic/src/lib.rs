//! ShadowQUIC 双端，JLS 鉴权、QUIC 传输与统一目标访问分离。
mod client;
mod codec;
mod config;
mod flow;
mod io;
mod runtime;
mod server;
mod session;
use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory, OutboundPlan};
use kerlico_core::{InboundProtocol, Result};
use serde_json::Value;
use std::sync::Arc;
pub struct ShadowQuicFactory;
pub struct ShadowQuicNodeFactory;
impl OutboundFactory for ShadowQuicFactory {
    fn kind(&self) -> &'static str {
        "shadowquic"
    }
    fn compile(&self, value: &Value) -> Result<OutboundPlan> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        client::Client::compile(options)
    }
    fn supports_detour(&self) -> bool {
        true
    }
}
impl NodeFactory for ShadowQuicNodeFactory {
    fn kind(&self) -> &'static str {
        "shadowquic"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(server::Node::build(input)?))
    }
}
