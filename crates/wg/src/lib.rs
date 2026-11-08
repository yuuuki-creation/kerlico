//! Userspace WireGuard for the server's WARP exits. It does not install a host route.

mod engine;
mod noise;
mod register;

pub use engine::{Pipe, Profile, Tunnel};
pub use register::load_profile;
