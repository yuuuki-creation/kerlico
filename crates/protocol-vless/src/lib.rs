//! VLESS version=0、普通 flow 的编解码与 TCP/固定目标 UDP 出站。
//! REALITY、Vision、XHTTP、Mux/XUDP 和 VLESS Encryption 尚未实现。

mod carrier;
pub mod codec;
mod inbound;
mod inbound_wire;
mod mux;
mod outbound;
mod packetaddr;
mod payload;
mod vision_io;
mod profile;
mod reality_io;
mod server_encryption;
mod server_h3;
mod server_http;
mod server_io;
mod server_reality;
mod stream;
mod xdrive;

pub use inbound::VlessNodeFactory;
pub use outbound::{VlessFactory, VlessOutbound};
pub use stream::VlessStream;

use kerlico_core::{Error, Result};
use std::fmt;
use subtle::ConstantTimeEq;

#[derive(Clone, Copy)]
pub struct UserId([u8; 16]);

impl UserId {
    pub fn parse(value: &str) -> Result<Self> {
        uuid::Uuid::parse_str(value)
            .map(|value| Self(*value.as_bytes()))
            .map_err(|_| Error::Config("VLESS 用户标识必须是 UUID".into()))
    }
    pub fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub fn matches(&self, expected: &Self) -> bool {
        bool::from(self.0.ct_eq(&expected.0))
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UserId([已隐藏])")
    }
}
