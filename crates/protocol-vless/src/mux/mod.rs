//! Mux.Cool 帧与有界的客户端/服务端会话管理。
mod client;
mod completion;
mod frame;
mod server;
mod xudp;
pub(crate) use client::Pool;
pub(crate) use server::serve;
pub(crate) use server::serve_packetaddr;
pub(crate) use xudp::{Migration, Table};
