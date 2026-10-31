//! VMess AEAD 双端，节点鉴权与统一目标访问分离。
mod carrier;
mod codec;
mod crypto;
mod http;
mod inbound;
mod outbound;
mod stream;
pub use inbound::VmessNodeFactory;
pub use outbound::VmessFactory;
