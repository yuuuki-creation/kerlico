//! 原生 Tailscale 客户端出站：TS2021 控制面、DERP 中继、直连 UDP 与共享 WireGuard 数据面。

mod config;
mod control;
mod dataplane;
mod derp;
mod disco;
mod keys;
mod netmap;
mod noise;
mod outbound;
mod stun;

pub use outbound::TailscaleFactory;
