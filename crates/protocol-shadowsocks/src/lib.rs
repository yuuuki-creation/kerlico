//! 普通 Shadowsocks 的原生 TCP/UDP 双端；SS2022 使用独立模块。

mod config;
mod inbound;
mod outbound;
mod replay;
mod udp;

pub use config::{AEAD_METHODS, LEGACY_METHODS};
pub use inbound::{ShadowsocksNode, ShadowsocksNodeFactory};
pub use outbound::{ShadowsocksFactory, ShadowsocksOutbound};

use kerlico_core::{Address as CoreAddress, Destination, Error, Result};
use shadowsocks::{
    config::{ReplayAttackPolicy, ServerType},
    context::{Context, SharedContext},
    relay::socks5::Address,
};
use std::net::SocketAddr;

pub(crate) const MAX_PACKET: usize = 65_000;
pub(crate) const MAX_WIRE: usize = 65_507;

fn address(target: &Destination) -> Address {
    match target.address() {
        CoreAddress::Ip(ip) => Address::SocketAddress(SocketAddr::new(*ip, target.port())),
        CoreAddress::Domain(name) => Address::DomainNameAddress(name.clone(), target.port()),
    }
}
fn destination(target: &Address) -> Result<Destination> {
    match target {
        Address::SocketAddress(addr) => Destination::new(&addr.ip().to_string(), addr.port()),
        Address::DomainNameAddress(name, port) => Destination::new(name, *port),
    }
}
fn crypto(kind: ServerType) -> SharedContext {
    let mut context = Context::new(kind);
    context.set_replay_attack_policy(ReplayAttackPolicy::Reject);
    std::sync::Arc::new(context)
}
fn protocol_error() -> Error {
    Error::Protocol("Shadowsocks 报文认证或格式不合法")
}
