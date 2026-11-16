//! AnyTLS framing, padding and sessions shared by both roles. The wire format follows mihomo
//! 1.19.33 (`transport/anytls`); `docs/reference/anytls.md` records where Kerlico differs.

pub mod addr;
pub mod frame;
pub mod jls;
pub mod padding;
mod queue;
pub mod rest;
pub mod session;
pub mod shadow;
pub mod tls;
mod tx;
#[cfg(test)]
mod vectors;
#[cfg(test)]
mod tests;

pub use addr::{Family, Target, UOT_V1, UOT_V2};
pub use padding::{Scheme, SchemeCell, DEFAULT_SCHEME};
pub use session::{Flow, Inbound, Leg, Opened, Role, Session, Stream};

use sha2::{Digest, Sha256};

/// What the client sends first and the server looks users up by.
pub fn password_hash(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}
