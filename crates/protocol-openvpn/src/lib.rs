//! 原生 OpenVPN 2.x 客户端出站：TLS 控制通道、AEAD 数据通道与用户态 IP 数据面。

mod client;
mod config;
mod data;
mod keys;
mod push;
mod reliable;
mod session;
mod tls;
mod wire;
mod wrap;

pub use client::OpenVpnFactory;
