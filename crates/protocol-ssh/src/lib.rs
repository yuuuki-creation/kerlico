//! 原生 SSH direct-tcpip 出站；不执行命令或使用用户的隐式 SSH 配置。

mod config;
mod outbound;
mod transport;

pub use outbound::SshFactory;
