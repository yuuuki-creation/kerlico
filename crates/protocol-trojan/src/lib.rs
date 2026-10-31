//! Trojan 双端、独立节点认证及流载体；目标访问由统一访问服务提供。

mod carrier;
mod codec;
mod config;
mod http_server;
mod inbound;
mod io;
mod outbound;
mod udp;

pub use inbound::TrojanNodeFactory;
pub use outbound::TrojanFactory;

use kerlico_core::{Error, Result};
use sha2::{Digest, Sha224};

fn invalid() -> Error {
    Error::Config("Trojan 配置不合法".into())
}
fn protocol() -> Error {
    Error::Protocol("Trojan 报文认证或格式不合法")
}
fn key(password: &str) -> Result<[u8; 56]> {
    if password.is_empty() || password.len() > 4096 {
        return Err(invalid());
    }
    let mut output = [0; 56];
    for (n, byte) in Sha224::digest(password.as_bytes()).iter().enumerate() {
        output[n * 2] = b"0123456789abcdef"[(byte >> 4) as usize];
        output[n * 2 + 1] = b"0123456789abcdef"[(byte & 15) as usize];
    }
    Ok(output)
}
