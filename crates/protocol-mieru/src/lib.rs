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
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{InboundProtocol, Outbound, Result};
use serde_json::Value;
use std::sync::Arc;
pub struct MieruFactory;
pub struct MieruNodeFactory;
impl OutboundFactory for MieruFactory {
    fn kind(&self) -> &'static str {
        "mieru"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn Outbound>> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        Ok(Arc::new(client::Client::build(options)?))
    }
}
impl NodeFactory for MieruNodeFactory {
    fn kind(&self) -> &'static str {
        "mieru"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options = serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
        Ok(Arc::new(server::Node::build(options)?))
    }
}
