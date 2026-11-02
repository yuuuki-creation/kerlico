//! HTTP/3 CONNECT-IP（RFC 9484）客户端出站；IP 包由共用用户态数据面处理。
mod capsule;
mod client;
mod config;
mod tunnel;
pub use client::MasqueFactory;

fn invalid() -> kerlico_core::Error {
    kerlico_core::Error::Config("MASQUE出站配置不合法".into())
}
fn protocol() -> kerlico_core::Error {
    kerlico_core::Error::Protocol("MASQUE CONNECT-IP协议失败")
}
