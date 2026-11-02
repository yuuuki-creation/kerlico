//! 为 `Local` 路径解析网站域名：静态 hosts 优先，其余查询配置的上游并使用其缓存。
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use kerlico_core::{Address, Destination, Error, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, net::IpAddr, net::SocketAddr, sync::Arc};

/// 上游只接受字面 IP，避免解析上游本身时递归。
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSpec {
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default)]
    pub hosts: BTreeMap<String, Vec<IpAddr>>,
}

#[derive(Debug, Eq, PartialEq)]
enum Transport {
    Udp,
    Tcp,
    Tls(String),
}

fn invalid() -> Error {
    Error::Config("DNS 配置不合法".into())
}

fn parse_server(text: &str) -> Result<(Transport, SocketAddr)> {
    let (scheme, rest) = text.split_once("://").ok_or_else(invalid)?;
    let (authority, name) = match rest.split_once('#') {
        Some((authority, name)) => (authority, Some(name)),
        None => (rest, None),
    };
    let (transport, default_port) = match (scheme, name) {
        ("udp", None) => (Transport::Udp, 53),
        ("tcp", None) => (Transport::Tcp, 53),
        ("tls", Some(name)) if !name.is_empty() => (Transport::Tls(name.to_owned()), 853),
        _ => return Err(invalid()),
    };
    let address = authority
        .parse::<SocketAddr>()
        .or_else(|_| {
            authority
                .parse::<IpAddr>()
                .map(|ip| SocketAddr::new(ip, default_port))
        })
        .map_err(|_| invalid())?;
    if address.port() == 0 {
        return Err(invalid());
    }
    Ok((transport, address))
}

fn normalize(host: &str) -> Result<String> {
    match Destination::new(host, 1).map_err(|_| invalid())?.address() {
        Address::Domain(name) => Ok(name.strip_suffix('.').unwrap_or(name).to_owned()),
        Address::Ip(_) => Err(invalid()),
    }
}

impl DnsSpec {
    pub fn validate(&self) -> Result<()> {
        if self.servers.is_empty() && self.hosts.is_empty() {
            return Err(invalid());
        }
        for server in &self.servers {
            parse_server(server)?;
        }
        for (host, addresses) in &self.hosts {
            normalize(host)?;
            if addresses.is_empty() {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

pub struct DnsResolver {
    upstream: Option<TokioResolver>,
    hosts: BTreeMap<String, Vec<IpAddr>>,
}

impl DnsResolver {
    /// 需要在 Tokio 运行时内调用。
    pub fn new(spec: &DnsSpec) -> Result<Self> {
        spec.validate()?;
        let hosts = spec
            .hosts
            .iter()
            .map(|(host, addresses)| Ok((normalize(host)?, addresses.clone())))
            .collect::<Result<_>>()?;
        let upstream = if spec.servers.is_empty() {
            None
        } else {
            let servers = spec
                .servers
                .iter()
                .map(|server| {
                    let (transport, address) = parse_server(server)?;
                    let mut connection = match transport {
                        Transport::Udp => ConnectionConfig::udp(),
                        Transport::Tcp => ConnectionConfig::tcp(),
                        Transport::Tls(name) => ConnectionConfig::tls(Arc::from(name)),
                    };
                    connection.port = address.port();
                    Ok(NameServerConfig::new(address.ip(), true, vec![connection]))
                })
                .collect::<Result<Vec<_>>>()?;
            let mut builder = TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(servers),
                TokioRuntimeProvider::default(),
            );
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            Some(builder.build().map_err(|_| invalid())?)
        };
        Ok(Self { upstream, hosts })
    }

    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let key = host.strip_suffix('.').unwrap_or(host);
        if let Some(addresses) = self.hosts.get(key) {
            return Ok(addresses.clone());
        }
        let upstream = self.upstream.as_ref().ok_or(Error::InvalidAddress)?;
        let lookup = upstream
            .lookup_ip(format!("{key}."))
            .await
            .map_err(|_| Error::Io(std::io::Error::other("DNS 查询失败")))?;
        Ok(lookup.iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::UdpSocket;

    fn spec(value: serde_json::Value) -> DnsSpec {
        serde_json::from_value(value).unwrap()
    }

    /// 对任意查询回答一条 A 记录，AAAA 查询返回空答案。
    async fn fake_upstream() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let question_end = buffer[12..length]
                    .iter()
                    .position(|byte| *byte == 0)
                    .map(|index| 12 + index + 5)
                    .unwrap();
                let is_a = buffer[question_end - 4..question_end - 2] == [0, 1];
                let mut reply = buffer[..question_end].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                reply[6..12].copy_from_slice(&[0, u8::from(is_a), 0, 0, 0, 0]);
                if is_a {
                    reply.extend_from_slice(&[
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7,
                    ]);
                }
                socket.send_to(&reply, peer).await.unwrap();
            }
        });
        address
    }

    #[test]
    fn rejects_malformed_specs() {
        for value in [
            json!({}),
            json!({"servers":["1.1.1.1"]}),
            json!({"servers":["udp://dns.example:53"]}),
            json!({"servers":["udp://1.1.1.1:0"]}),
            json!({"servers":["tls://1.1.1.1"]}),
            json!({"servers":["udp://1.1.1.1#name"]}),
            json!({"hosts":{"10.0.0.1":["10.0.0.2"]}}),
            json!({"hosts":{"a.example":[]}}),
        ] {
            assert!(spec(value).validate().is_err());
        }
        assert!(
            spec(json!({"servers":["udp://1.1.1.1","tcp://[2606:4700:4700::1111]:53","tls://1.1.1.1#cloudflare-dns.com"]}))
                .validate()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn hosts_win_and_unknown_hosts_fail_without_upstream() {
        let resolver =
            DnsResolver::new(&spec(json!({"hosts":{"Svc.Internal":["10.0.0.5"]}}))).unwrap();
        assert_eq!(
            resolver.resolve("svc.internal").await.unwrap(),
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        assert!(resolver.resolve("other.internal").await.is_err());
    }

    #[tokio::test]
    async fn queries_the_configured_upstream() {
        let upstream = fake_upstream().await;
        let resolver =
            DnsResolver::new(&spec(json!({"servers":[format!("udp://{upstream}")]}))).unwrap();
        assert_eq!(
            resolver.resolve("www.example.com").await.unwrap(),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
    }
}
