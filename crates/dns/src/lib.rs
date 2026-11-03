//! 为 `Local` 路径解析网站域名：静态 hosts 优先，其余查询配置的上游并使用其缓存。
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use kerlico_core::{Address, Destination, Error, Result};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

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
            let ip = match authority
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                Some(bracketed) => bracketed.parse::<Ipv6Addr>().map(IpAddr::V6),
                None => authority.parse::<IpAddr>(),
            };
            ip.map(|ip| SocketAddr::new(ip, default_port))
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
            builder.options_mut().use_hosts_file = ResolveHosts::Never;
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

    pub async fn exchange_packet(&self, request: &[u8]) -> Result<Vec<u8>> {
        exchange_wire_query(request, Some(self)).await
    }
}

fn parse_question(packet: &[u8]) -> Result<(String, u16, usize)> {
    if packet.len() < 12 || packet.len() > 4096 {
        return Err(Error::Protocol("DNS 报文长度不合法"));
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return Err(Error::Protocol("DNS 查询缺少问题段"));
    }
    let mut cursor = 12usize;
    let mut labels = Vec::new();
    loop {
        if cursor >= packet.len() {
            return Err(Error::Protocol("DNS 域名标签截断"));
        }
        let len = usize::from(packet[cursor]);
        cursor += 1;
        if len == 0 {
            break;
        }
        if (len & 0xc0) != 0 || len > 63 || cursor + len > packet.len() {
            return Err(Error::Protocol("DNS 问题段标签不合法"));
        }
        let label = std::str::from_utf8(&packet[cursor..cursor + len])
            .map_err(|_| Error::Protocol("DNS 域名标签非 ASCII"))?;
        labels.push(label.to_ascii_lowercase());
        cursor += len;
    }
    if cursor + 4 > packet.len() || labels.is_empty() {
        return Err(Error::Protocol("DNS 问题尾部截断"));
    }
    let qtype = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    let qclass = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
    if qclass != 1 {
        return Err(Error::Protocol("DNS 仅支持 IN 类查询"));
    }
    Ok((labels.join("."), qtype, cursor + 4))
}

pub async fn exchange_wire_query(
    request: &[u8],
    resolver: Option<&DnsResolver>,
) -> Result<Vec<u8>> {
    let (domain, qtype, question_end) = parse_question(request)?;
    let rd = request[2] & 0x01;
    let resolved = match qtype {
        1 | 28 => match resolver {
            Some(resolver) => resolver.resolve(&domain).await,
            None => tokio::net::lookup_host((domain.as_str(), 0))
                .await
                .map(|iter| iter.map(|addr| addr.ip()).collect::<Vec<_>>())
                .map_err(Error::Io),
        },
        _ => Ok(Vec::new()),
    };
    let mut reply = Vec::with_capacity(512);
    reply.extend_from_slice(&request[0..2]);
    match resolved {
        Ok(ips) => {
            let matched: Vec<IpAddr> = ips
                .into_iter()
                .filter(|ip| matches!((qtype, ip), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))))
                .take(16)
                .collect();
            reply.push(0x80 | rd);
            reply.push(0x80);
            reply.extend_from_slice(&1u16.to_be_bytes());
            reply.extend_from_slice(&(matched.len() as u16).to_be_bytes());
            reply.extend_from_slice(&[0, 0, 0, 0]);
            reply.extend_from_slice(&request[12..question_end]);
            for ip in matched {
                reply.extend_from_slice(&[0xc0, 0x0c]);
                reply.extend_from_slice(&qtype.to_be_bytes());
                reply.extend_from_slice(&1u16.to_be_bytes());
                reply.extend_from_slice(&60u32.to_be_bytes());
                match ip {
                    IpAddr::V4(v4) => {
                        reply.extend_from_slice(&4u16.to_be_bytes());
                        reply.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        reply.extend_from_slice(&16u16.to_be_bytes());
                        reply.extend_from_slice(&v6.octets());
                    }
                }
            }
        }
        Err(_) => {
            reply.push(0x80 | rd);
            reply.push(0x82);
            reply.extend_from_slice(&1u16.to_be_bytes());
            reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            reply.extend_from_slice(&request[12..question_end]);
        }
    }
    Ok(reply)
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
            json!({"servers":["tcp://[2001:db8::1"]}),
            json!({"servers":["tcp://2001:db8::1]"]}),
            json!({"servers":["tcp://[192.0.2.1]"]}),
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

    #[test]
    fn bracketed_ipv6_without_port_uses_the_default_port() {
        assert_eq!(
            parse_server("tcp://[2001:db8::1]").unwrap(),
            (Transport::Tcp, "[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse_server("tcp://2001:db8::1").unwrap(),
            (Transport::Tcp, "[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse_server("tls://[2001:db8::1]#dns.example").unwrap(),
            (
                Transport::Tls("dns.example".into()),
                "[2001:db8::1]:853".parse().unwrap()
            )
        );
    }

    /// 需要私有挂载命名空间，把测试名字写进该空间的 `/etc/hosts`：
    /// `unshare -m sh -c 'echo "203.0.113.9 shadowed.example" > "$H"; mount --bind "$H" /etc/hosts; cargo test -p kerlico-dns --offline -- --ignored'`
    #[tokio::test]
    #[ignore = "需要 root，并在私有挂载命名空间内改写 /etc/hosts"]
    async fn system_hosts_file_does_not_override_configured_upstreams() {
        let hosts = std::fs::read_to_string("/etc/hosts").unwrap();
        assert!(
            hosts.contains("shadowed.example"),
            "未按说明准备 hosts 文件"
        );
        let upstream = fake_upstream().await;
        let resolver =
            DnsResolver::new(&spec(json!({"servers":[format!("udp://{upstream}")]}))).unwrap();
        assert_eq!(
            resolver.resolve("shadowed.example").await.unwrap(),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
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

    #[tokio::test]
    async fn exchange_packet_answers_wire_query_from_hosts() {
        let resolver =
            DnsResolver::new(&spec(json!({"hosts":{"svc.internal":["10.0.0.5"]}}))).unwrap();
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b's', b'v',
            b'c', 8, b'i', b'n', b't', b'e', b'r', b'n', b'a', b'l', 0, 0, 1, 0, 1,
        ];
        let reply = resolver.exchange_packet(&query).await.unwrap();
        assert_eq!(&reply[0..2], &[0x12, 0x34]);
        assert_eq!(&reply[6..8], &[0x00, 0x01]);
        assert_eq!(&reply[reply.len() - 4..], &[10, 0, 0, 5]);
    }
}
