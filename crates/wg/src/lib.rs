//! WireGuard link and userspace IP stack. This crate does not install host routes.

mod engine;
mod endpoint;
mod fragments;
mod hub;
#[cfg(all(feature = "tun-device", target_os = "linux"))]
mod linux_link;
#[cfg(all(feature = "tun-device", target_os = "linux"))]
mod linux_uapi;
mod packet;
mod register;
mod stack;
#[cfg(feature = "tun-device")]
mod tun_device;
#[cfg(all(feature = "tun-device", any(target_os = "linux", windows)))]
mod uapi;
#[cfg(all(feature = "tun-device", windows))]
mod windows_uapi;
mod wire;

pub use engine::{Datagrams, Pipe, Profile, Tunnel};
pub use endpoint::parse_endpoint;
pub use hub::{Hub, HubEvent, PeerId};
pub use ipnet::IpNet;
pub use packet::{LinkPeer, PacketLink, PacketRx, PacketTx, Reserved};
pub use register::load_profile;
pub use stack::{Incoming, Protocol, Stack};
#[cfg(feature = "tun-device")]
pub use tun_device::{bind_tun, run_tun};
#[cfg(all(feature = "tun-device", any(target_os = "linux", windows)))]
pub use tun_device::{run_interface, run_interface_ready};
pub use wire::{parse_key, PeerKeys};
