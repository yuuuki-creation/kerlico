//! TrustTunnel 的 H1/H2/H3 双端；UDP 保持固定目标语义，ICMP 明确不支持。
mod client;
mod config;
mod http1;
mod io;
mod server;
mod socket;
mod udp;
pub use client::TrustTunnelFactory;
pub use server::TrustTunnelNodeFactory;
fn invalid() -> kerlico_core::Error {
    kerlico_core::Error::Config("TrustTunnel 配置不合法".into())
}
fn protocol() -> kerlico_core::Error {
    kerlico_core::Error::Protocol("TrustTunnel 请求、响应或数据不合法")
}
