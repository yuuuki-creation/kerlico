//! 原生 ZeroTier 客户端出站。协议实现位于 MPL-2.0 的 `zerotier-node`，本 crate 只提供配置、
//! 套接字驱动及以太网到 `kerlico_wireguard::ip::ClientTunnel` 的桥接。

mod config;
mod interface;
mod outbound;

pub use outbound::ZeroTierFactory;
