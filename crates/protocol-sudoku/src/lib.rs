//! Sudoku独立双端协议；完整首轮已写齐，正在集中验证，尚未全部验收。

mod carrier;
mod classify;
mod client;
mod codec;
mod config;
mod cover;
mod handshake;
mod io;
mod key;
mod mux;
mod node;
mod replay;
mod scope;
mod service;
mod udp;

pub use client::SudokuFactory;
pub use node::SudokuNodeFactory;
mod wire;

pub(crate) fn invalid() -> kerlico_core::Error {
    kerlico_core::Error::Protocol("Sudoku 帧、序号或鉴权不合法")
}

#[cfg(test)]
#[path = "../tests/vectors/mod.rs"]
mod reference_vectors;
