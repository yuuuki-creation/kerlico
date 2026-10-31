//! ShadowsocksR 原生 Rust 双端；认证、混淆和密码分别实现并严格校验。

mod config;
mod crypto;
mod inbound;
mod obfs;
mod outbound;
mod protocol;
mod replay;
mod stream;
mod udp;

pub use config::{CIPHERS, OBFS, PROTOCOLS};
pub use inbound::{ShadowsocksRNode, ShadowsocksRNodeFactory};
pub use outbound::{ShadowsocksRFactory, ShadowsocksROutbound};

use kerlico_core::{Address as CoreAddress, Destination, Error, Result};
use shadowsocks::relay::socks5::Address;
use std::net::SocketAddr;
pub(crate) const MAX_PACKET: usize = 65000;
pub(crate) fn invalid() -> Error {
    Error::Protocol("ShadowsocksR 报文校验或握手不合法")
}
pub(crate) fn address(target: &Destination) -> Address {
    match target.address() {
        CoreAddress::Ip(ip) => Address::SocketAddress(SocketAddr::new(*ip, target.port())),
        CoreAddress::Domain(name) => Address::DomainNameAddress(name.clone(), target.port()),
    }
}
pub(crate) fn destination(target: &Address) -> Result<Destination> {
    match target {
        Address::SocketAddress(value) => Destination::new(&value.ip().to_string(), value.port()),
        Address::DomainNameAddress(name, port) => Destination::new(name, *port),
    }
}
pub(crate) fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}
