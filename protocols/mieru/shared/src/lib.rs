//! Mieru TCP segments. The username and password become an XChaCha20-Poly1305 key.
//! The published layout is the one mihomo's mieru client speaks.

mod crypto;
mod link;

pub use link::{accept, connect, resolve_peer, Account, Conn, Target};
