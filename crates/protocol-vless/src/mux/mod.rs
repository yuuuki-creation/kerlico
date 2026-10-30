//! Mux.Cool 帧与有界的客户端/服务端会话管理。
mod client;
mod frame;
mod server;
pub(crate) use client::Pool;
pub(crate) use server::serve;
pub(crate) use server::serve_packetaddr;
