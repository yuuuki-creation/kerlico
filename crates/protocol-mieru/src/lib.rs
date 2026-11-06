//! Mieru 原生双端；有认证的 TCP 载体与明确限定回环的旧 UDP 兼容模式分开。
mod client;
mod codec;
mod config;
mod crypto;
mod entropy;
mod packet;
mod server;
mod session;
mod udp;
use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory, OutboundPlan};
use kerlico_core::{InboundProtocol, Result};
use serde_json::Value;
use std::sync::Arc;
pub struct MieruFactory;
pub struct MieruNodeFactory;
impl OutboundFactory for MieruFactory {
    fn kind(&self) -> &'static str {
        "mieru"
    }
    fn supports_detour(&self) -> bool {
        true
    }
    fn compile(&self, value: &Value) -> Result<OutboundPlan> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        client::Client::compile(options)
    }
}
impl NodeFactory for MieruNodeFactory {
    fn kind(&self) -> &'static str {
        "mieru"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(server::Node::build(input)?))
    }
}
