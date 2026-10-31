//! Snell 记录层与双端适配；节点身份和目标访问遵循统一内核契约。

mod config;
mod crypto;
mod inbound;
mod io;
mod obfs;
mod outbound;
mod profile;
mod record;
mod stream;
mod udp;
mod wire;

pub use inbound::SnellNodeFactory;
pub use outbound::SnellFactory;

fn invalid() -> kerlico_core::Error {
    kerlico_core::Error::Config("Snell 配置不合法".into())
}
fn protocol() -> kerlico_core::Error {
    kerlico_core::Error::Protocol("Snell 报文认证或格式不合法")
}
fn io_protocol() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Snell 报文认证或格式不合法",
    )
}
