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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default = "default_name")]
    name: String,
    addresses: Vec<String>,
    #[serde(default = "default_mtu")]
    mtu: u16,
}

fn invalid() -> Error {
    Error::Config("TUN 选项不合法".into())
}

/// 接口地址，内核发包的来源。用户态栈用它的下一个地址。
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

    fn host_network(&self) -> String {
        match self.ip {
            IpAddr::V4(ip) => format!("{ip}/32"),
            IpAddr::V6(ip) => format!("{ip}/128"),
        }
    }
}

struct TunNode {
    name: String,
    mtu: u16,
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
            allowed_ips: self
                .addresses
                .iter()
                .map(InterfaceAddress::host_network)
                .collect(),
            mtu: usize::from(self.mtu),
            limits: StackLimits::default(),
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
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
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
                        Ok(packet) => {
                            device.send(&packet).await?;
                        }
                        Err(Error::Cancelled) => return Ok(()),
                        Err(error) => return Err(error),
                    },
                    read = device.recv(&mut buffer) => {
                        let length = read?;
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
        Ok(Arc::new(TunNode {
            name: options.name,
            mtu: options.mtu,
            addresses,
        }))
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
        assert_eq!(address.host_network(), "198.18.0.1/32");
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
