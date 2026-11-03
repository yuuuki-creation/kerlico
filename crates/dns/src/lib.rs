//! 为 `Local` 路径解析网站域名：静态 hosts 优先，其余查询配置的上游并使用其缓存。
mod doh;
use doh::{Bootstrap, Dial, HttpsUpstream, Provider};
use hickory_resolver::{
    Resolver,
    config::{ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
};
use kerlico_core::{Address, Destination, Error, Result};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

/// `udp://`、`tcp://`、`tls://` 只接受字面 IP；`https://` 可写域名，由
/// `hosts` 或 `default_nameserver` 引导，引导解析不经过 `servers`。
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSpec {
    #[serde(default)]
    pub servers: Vec<ServerSpec>,
    #[serde(default)]
    pub default_nameserver: Vec<ServerSpec>,
    #[serde(default)]
    pub hosts: BTreeMap<String, Vec<IpAddr>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ServerSpec {
    Url(String),
    Https(HttpsServerSpec),
}

/// 字段名与 sing-box 的 `https` DNS 服务器一致。
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsServerSpec {
    #[serde(rename = "type")]
    kind: HttpsKind,
    server: String,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    tls: Option<HttpsTlsSpec>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum HttpsKind {
    #[serde(rename = "https")]
    Https,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpsTlsSpec {
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    ca_pem: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
enum Transport {
    Udp,
    Tcp,
    Tls(String),
}

enum Upstream {
    Plain(Transport, SocketAddr),
    Https(Box<HttpsUpstream>),
}

fn invalid() -> Error {
    Error::Config("DNS 配置不合法".into())
}

fn parse_plain(text: &str) -> Result<(Transport, SocketAddr)> {
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

fn parse_upstream(spec: &ServerSpec) -> Result<Upstream> {
    Ok(match spec {
        ServerSpec::Url(text) if text.starts_with("https://") => {
            Upstream::Https(Box::new(HttpsUpstream::from_url(text)?))
        }
        ServerSpec::Url(text) => {
            let (transport, address) = parse_plain(text)?;
            Upstream::Plain(transport, address)
        }
        ServerSpec::Https(spec) => Upstream::Https(Box::new(HttpsUpstream::from_spec(spec)?)),
    })
}

fn normalize(host: &str) -> Result<String> {
    match Destination::new(host, 1).map_err(|_| invalid())?.address() {
        Address::Domain(name) => Ok(name.strip_suffix('.').unwrap_or(name).to_owned()),
        Address::Ip(_) => Err(invalid()),
    }
}

/// 校验后的配置，`check` 和运行共用；不访问网络。
struct Compiled {
    servers: Vec<Upstream>,
    default_nameserver: Vec<Upstream>,
    hosts: BTreeMap<String, Vec<IpAddr>>,
}

impl Compiled {
    fn new(spec: &DnsSpec) -> Result<Self> {
        if spec.servers.is_empty() && spec.hosts.is_empty() {
            return Err(invalid());
        }
        let servers = spec
            .servers
            .iter()
            .map(parse_upstream)
            .collect::<Result<Vec<_>>>()?;
        let default_nameserver = spec
            .default_nameserver
            .iter()
            .map(parse_upstream)
            .collect::<Result<Vec<_>>>()?;
        let hosts = spec
            .hosts
            .iter()
            .map(|(host, addresses)| {
                if addresses.is_empty() {
                    return Err(invalid());
                }
                Ok((normalize(host)?, addresses.clone()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for upstream in &default_nameserver {
            if let Upstream::Https(https) = upstream
                && matches!(https.dial(), Dial::Domain(_))
            {
                return Err(invalid());
            }
        }
        for upstream in &servers {
            if let Upstream::Https(https) = upstream
                && let Dial::Domain(name) = https.dial()
                && default_nameserver.is_empty()
                && !hosts.contains_key(name)
            {
                return Err(invalid());
            }
        }
        for upstream in servers.iter().chain(&default_nameserver) {
            if let Upstream::Https(https) = upstream {
                https.client(None)?;
            }
        }
        Ok(Self {
            servers,
            default_nameserver,
            hosts,
        })
    }
}

impl DnsSpec {
    pub fn validate(&self) -> Result<()> {
        Compiled::new(self).map(|_| ())
    }
}

/// hickory 的连接池要求每个上游有固定 IP，DoH 域名的地址随引导解析变化，
/// 所以 DoH 上游在池内用占位地址，真正的拨号在 [`doh`] 内完成。
fn pool(upstreams: &[Upstream], bootstrap: Option<&Arc<Bootstrap>>) -> Result<Resolver<Provider>> {
    let mut provider = Provider::default();
    let servers = upstreams
        .iter()
        .map(|upstream| match upstream {
            Upstream::Plain(transport, address) => {
                let mut connection = match transport {
                    Transport::Udp => ConnectionConfig::udp(),
                    Transport::Tcp => ConnectionConfig::tcp(),
                    Transport::Tls(name) => ConnectionConfig::tls(Arc::from(name.as_str())),
                };
                connection.port = address.port();
                Ok(NameServerConfig::new(address.ip(), true, vec![connection]))
            }
            Upstream::Https(https) => {
                let placeholder = provider.add(https.client(bootstrap)?);
                Ok(NameServerConfig::new(
                    placeholder,
                    true,
                    vec![ConnectionConfig::tcp()],
                ))
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let mut builder =
        Resolver::builder_with_config(ResolverConfig::from_name_servers(servers), provider);
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    builder.build().map_err(|_| invalid())
}

pub struct DnsResolver {
    upstream: Option<Resolver<Provider>>,
    hosts: BTreeMap<String, Vec<IpAddr>>,
}

impl DnsResolver {
    /// 需要在 Tokio 运行时内调用。
    pub fn new(spec: &DnsSpec) -> Result<Self> {
        let compiled = Compiled::new(spec)?;
        let bootstrap = Arc::new(Bootstrap {
            hosts: compiled.hosts.clone(),
            resolver: if compiled.default_nameserver.is_empty() {
                None
            } else {
                Some(pool(&compiled.default_nameserver, None)?)
            },
        });
        let upstream = if compiled.servers.is_empty() {
            None
        } else {
            Some(pool(&compiled.servers, Some(&bootstrap))?)
        };
        Ok(Self {
            upstream,
            hosts: compiled.hosts,
        })
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
            parse_plain("tcp://[2001:db8::1]").unwrap(),
            (Transport::Tcp, "[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse_plain("tcp://2001:db8::1").unwrap(),
            (Transport::Tcp, "[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse_plain("tls://[2001:db8::1]#dns.example").unwrap(),
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
}
