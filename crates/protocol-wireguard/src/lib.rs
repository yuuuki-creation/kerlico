//! 原生用户态WireGuard双端。业务流通过可信会话及共享出站访问目标。

mod carrier;
mod client;
mod config;
mod crypto;
pub mod ip;
mod packet;
mod queue;
mod server;
mod stack;
mod tcp;
mod udp;

pub use client::WireGuardFactory;
pub use server::WireGuardNodeFactory;

#[cfg(test)]
mod tests;
