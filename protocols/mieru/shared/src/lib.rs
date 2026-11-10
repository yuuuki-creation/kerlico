//! Mieru segments. TCP and UDP share XChaCha20-Poly1305, metadata, and SOCKS5.

mod crypto;
mod engine;
mod entropy;
mod meta;
mod options;
mod replay;

pub use engine::{
    accept, associate, connect, connect_udp, resolve_peer, serve_tcp, serve_udp, Account, Assoc,
    Client, Conn, Ready, ServerHandle, Target,
};
pub use options::{ClientOptions, HandshakeMode, Multiplexing, Transport};
