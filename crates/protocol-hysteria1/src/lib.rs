//! Hysteria v1 家族的独立双端实现；线协议版本为 0x03。
mod client;
mod config;
mod congestion;
mod dispatch;
mod fragment;
mod io;
mod server;
mod socket;
mod udp;
mod wire;

pub use client::Hysteria1Factory;
pub use server::Hysteria1NodeFactory;

fn invalid() -> kerlico_core::Error {
    kerlico_core::Error::Config("Hysteria v1 配置不合法".into())
}
fn protocol() -> kerlico_core::Error {
    kerlico_core::Error::Protocol("Hysteria v1 鉴权、响应或报文不合法")
}
