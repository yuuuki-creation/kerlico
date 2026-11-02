//! 嵌入Arti的原生Tor客户端TCP出站，共享服务拥有后台任务和状态目录。

mod config;
mod error;
mod network;
mod outbound;
mod runtime;
mod storage;
mod stream;
#[cfg(test)]
mod tests;
#[cfg(all(test, unix))]
mod wiring_tests;

pub use outbound::TorFactory;
