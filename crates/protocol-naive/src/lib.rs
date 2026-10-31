//! Naive 原生双端；应用填充与浏览器网络栈行为分开登记。
mod client;
mod config;
mod http;
mod io;
mod padding;
mod server;
mod tls;
mod transport;
mod uot;
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{InboundProtocol, Outbound, Result, StreamConnector};
use serde_json::Value;
use std::sync::Arc;
pub struct NaiveFactory;
pub struct NaiveNodeFactory;
impl NaiveFactory {
    /// 连接器只承载 H1/H2 的 TCP 接入；H3 明确拒绝此构造，不能忽略注入后直连。
    pub fn build_with_connector(
        value: &Value,
        connector: Arc<dyn StreamConnector>,
    ) -> Result<Arc<dyn Outbound>> {
        Ok(Arc::new(client::Client::new(
            serde_json::from_value(value.clone()).map_err(|_| config::invalid())?,
            Some(connector),
        )?))
    }
}
impl OutboundFactory for NaiveFactory {
    fn kind(&self) -> &'static str {
        "naive"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn Outbound>> {
        Ok(Arc::new(client::Client::new(
            serde_json::from_value(value.clone()).map_err(|_| config::invalid())?,
            None,
        )?))
    }
}
impl NodeFactory for NaiveNodeFactory {
    fn kind(&self) -> &'static str {
        "naive"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(server::Node::new(
            serde_json::from_value(value.clone()).map_err(|_| config::invalid())?,
        )?))
    }
}
