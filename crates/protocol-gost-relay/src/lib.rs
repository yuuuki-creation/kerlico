//! Gost Relay CONNECT 出站，支持固定目标 UDP 与单流 SMUX v1 载体。

mod config;
mod io;
mod outbound;
mod response;
mod smux;
mod udp;
mod wire;

pub use outbound::GostRelayFactory;
