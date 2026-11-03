//! 系统 TUN 入站：把内核交来的 IP 包还原成业务流，经本地会话进入共享调度器。
//!
//! 只创建接口并配置地址，不修改系统路由。
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, CredentialManifest, Error, InboundContext, InboundProtocol, IngressBinding,
    NodeEvent, Result,
};
use kerlico_wireguard::ip::{ServerTunnel, StackLimits, StackOptions};
use serde::Deserialize;
use std::{net::IpAddr, sync::Arc};
use tun_rs::DeviceBuilder;

fn default_name() -> String {
    "kerlico0".into()
}
fn default_mtu() -> u16 {
    1500
}
fn default_max_flows() -> usize {
    1024
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default = "default_name")]
    name: String,
    addresses: Vec<String>,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default = "default_max_flows")]
    max_flows: usize,
}

fn invalid() -> Error {
    Error::Config("TUN 选项不合法".into())
}

/// 内核在 TUN 接口拉起时自动发出的链路本地（如 `fe80::/10`、`169.254.0.0/16`）或组播/广播探针，不进入代理转发或计为损坏包。
fn is_ambient_link_packet(packet: &[u8]) -> bool {
    let Some(&first) = packet.first() else {
        return false;
    };
    match first >> 4 {
        4 if packet.len() >= 20 => {
            let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            src.is_link_local()
                || dst.is_link_local()
                || dst.is_multicast()
                || dst.is_broadcast()
                || packet[9] == 2
        }
        6 if packet.len() >= 40 => {
            let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
            let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
            src.is_unicast_link_local()
                || dst.is_unicast_link_local()
                || dst.is_multicast()
                || packet[6] == 0
        }
        _ => false,
    }
}

/// 接口已被销毁。tun 驱动对已摘除的 fd 返回 EBADFD。
fn device_gone(error: &std::io::Error) -> bool {
    const EBADFD: i32 = 77;
    error.raw_os_error() == Some(EBADFD)
}

/// 接口地址。用户态栈用它的下一个地址。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterfaceAddress {
    ip: IpAddr,
    prefix: u8,
}

impl InterfaceAddress {
    fn parse(text: &str) -> Result<Self> {
        let (ip, prefix) = text.split_once('/').ok_or_else(invalid)?;
        let ip: IpAddr = ip.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        let usable = match ip {
            IpAddr::V4(_) => prefix <= 30,
            IpAddr::V6(_) => prefix <= 126,
        };
        if !usable || ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            return Err(invalid());
        }
        let parsed = Self { ip, prefix };
        parsed.gateway()?;
        Ok(parsed)
    }

    fn gateway(&self) -> Result<IpAddr> {
        let next = match self.ip {
            IpAddr::V4(ip) => IpAddr::from(
                ip.to_bits()
                    .checked_add(1)
                    .ok_or_else(invalid)?
                    .to_be_bytes(),
            ),
            IpAddr::V6(ip) => IpAddr::from(
                ip.to_bits()
                    .checked_add(1)
                    .ok_or_else(invalid)?
                    .to_be_bytes(),
            ),
        };
        Ok(next)
    }
}

struct TunNode {
    name: String,
    mtu: u16,
    max_flows: usize,
    addresses: Vec<InterfaceAddress>,
}

impl TunNode {
    fn create(&self) -> Result<tun_rs::AsyncDevice> {
        let mut builder = DeviceBuilder::new().name(&self.name).mtu(self.mtu);
        for address in &self.addresses {
            builder = match address.ip {
                IpAddr::V4(ip) => builder.ipv4(ip, address.prefix, None),
                IpAddr::V6(ip) => builder.ipv6(ip, address.prefix),
            };
        }
        Ok(builder.build_async()?)
    }

    fn stack(&self) -> Result<StackOptions> {
        Ok(StackOptions {
            addresses: self
                .addresses
                .iter()
                .map(InterfaceAddress::gateway)
                .collect::<Result<_>>()?,
            // 作为网关时来源是被转发的主机，不限于接口地址。
            allowed_ips: self
                .addresses
                .iter()
                .map(|address| {
                    if address.ip.is_ipv4() {
                        "0.0.0.0/0".to_owned()
                    } else {
                        "::/0".to_owned()
                    }
                })
                .collect(),
            mtu: usize::from(self.mtu),
            limits: StackLimits {
                max_flows: self.max_flows,
                ..StackLimits::default()
            },
        })
    }
}

impl InboundProtocol for TunNode {
    fn credential_manifest(&self) -> CredentialManifest {
        CredentialManifest::new()
    }
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn supports_tcp(&self) -> bool {
        false
    }
    fn supports_virtual(&self) -> bool {
        true
    }
    fn reserved_sessions(&self) -> usize {
        1
    }
    fn handle<'a>(
        &'a self,
        _stream: kerlico_core::BoxStream,
        _ingress: IngressBinding,
        _context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("TUN 节点没有物理 TCP 入口")) })
    }
    fn handle_virtual<'a>(
        &'a self,
        ingress: IngressBinding,
        mut context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Engine 的 max_streams 是单条多路复用连接的上限；TUN 的流由 max_flows 和会话配额约束。
            context.max_streams = self.max_flows;
            let device = self.create()?;
            let access = ingress.local(&context)?;
            let cancel = context.cancel.clone();
            let events = context.events.clone();
            let tunnel = ServerTunnel::new(self.stack()?, access, context)?;
            // 留出链路层余量；过长的包由内核按 MTU 截断前已被拒绝。
            let mut buffer = vec![0; usize::from(self.mtu) + 64];
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Ok(()),
                    packet = tunnel.next_packet() => match packet {
                        Ok(packet) => match device.send(&packet).await {
                            Ok(_) => {}
                            Err(error) if device_gone(&error) => return Err(error.into()),
                            // 链路 down 的 EIO、缓冲不足等只影响这一个包。
                            Err(_) => events.record(NodeEvent::Dropped),
                        },
                        Err(Error::Cancelled) => return Ok(()),
                        Err(error) => return Err(error),
                    },
                    read = device.recv(&mut buffer) => {
                        let length = read?;
                        if is_ambient_link_packet(&buffer[..length]) {
                            continue;
                        }
                        match tunnel.receive(&buffer[..length]) {
                            Ok(()) => {}
                            Err(Error::Cancelled) => return Ok(()),
                            // 单个包不合法或超出配额不影响接口上的其他流量。
                            Err(_) => events.record(NodeEvent::Dropped),
                        }
                    }
                }
            }
        })
    }
}

pub struct TunNodeFactory;

impl NodeFactory for TunNodeFactory {
    fn kind(&self) -> &'static str {
        "tun"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options =
            serde_json::from_value(input.options().clone()).map_err(|_| invalid())?;
        if options.name.is_empty()
            || options.name.len() > 15
            || !options
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            || !(1280..=9000).contains(&options.mtu)
            || options.addresses.is_empty()
            || options.addresses.len() > 2
        {
            return Err(invalid());
        }
        let addresses = options
            .addresses
            .iter()
            .map(|text| InterfaceAddress::parse(text))
            .collect::<Result<Vec<_>>>()?;
        if addresses.len() == 2 && addresses[0].ip.is_ipv4() == addresses[1].ip.is_ipv4() {
            return Err(invalid());
        }
        let node = TunNode {
            name: options.name,
            mtu: options.mtu,
            max_flows: options.max_flows,
            addresses,
        };
        node.stack()?.validate().map_err(|_| invalid())?;
        Ok(Arc::new(node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_is_the_next_address() {
        let address = InterfaceAddress::parse("198.18.0.1/16").unwrap();
        assert_eq!(
            address.gateway().unwrap(),
            "198.18.0.2".parse::<IpAddr>().unwrap()
        );
        let address = InterfaceAddress::parse("fd00::1/64").unwrap();
        assert_eq!(
            address.gateway().unwrap(),
            "fd00::2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_unusable_addresses() {
        for text in [
            "198.18.0.1",
            "198.18.0.1/31",
            "0.0.0.0/8",
            "127.0.0.1/8",
            "224.0.0.1/24",
            "fd00::1/127",
            "::1/64",
        ] {
            assert!(InterfaceAddress::parse(text).is_err(), "{text}");
        }
    }
}
