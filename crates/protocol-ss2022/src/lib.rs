//! Shadowsocks 2022 的 TCP 与原生 UDP 双端适配；目标访问统一交给核心服务。

mod config;
mod inbound;
mod outbound;
mod replay;
mod udp;

pub use inbound::{Ss2022Node, Ss2022NodeFactory};
pub use outbound::{Ss2022Factory, Ss2022Outbound};

use kerlico_core::{Address as CoreAddress, Destination, Error, Result};
use shadowsocks::relay::socks5::Address;
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

fn protocol_error() -> Error {
    Error::Protocol("SS2022 报文认证或格式不合法")
}
