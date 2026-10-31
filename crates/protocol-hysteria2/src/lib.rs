//! Hysteria2 原生 QUIC 双端，业务目标访问统一交给核心服务。

mod config;
mod dispatch;
mod inbound;
mod io;
mod outbound;
mod socket;
mod udp;
mod wire;

pub use inbound::{Hysteria2Node, Hysteria2NodeFactory};
pub use outbound::{Hysteria2Factory, Hysteria2Outbound};

use kerlico_core::{ConnectContext, Destination, Error, InboundContext, Result};
fn invalid() -> Error {
    Error::Protocol("Hysteria2 报文或握手不合法")
}
fn target(text: &str) -> Result<Destination> {
    if let Ok(address) = text.parse::<std::net::SocketAddr>() {
        return Destination::new(&address.ip().to_string(), address.port());
    }
    let (host, port) = text.rsplit_once(':').ok_or_else(invalid)?;
    Destination::new(host, port.parse().map_err(|_| invalid())?)
}
fn budget(context: &InboundContext) -> ConnectContext {
    ConnectContext {
        cancel: context.cancel.clone(),
        timeout: context.connect_timeout,
    }
}
