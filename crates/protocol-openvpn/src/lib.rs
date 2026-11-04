//! 原生 OpenVPN 2.x 双端：TLS 控制通道、AEAD 数据通道与用户态 IP 数据面。

mod client;
mod config;
mod data;
mod keys;
mod push;
mod reliable;
pub mod server;
mod session;
mod tls;
mod wire;
mod wrap;

pub use client::OpenVpnFactory;
pub use server::OpenVpnNodeFactory;
