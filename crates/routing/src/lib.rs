//! 按目标、网络、节点和用户选择命名出站。只看字面 IP，不查询 DNS。
use kerlico_core::{Address, Destination, Error, NodeId, OutId, Result, Source, UserId};
use serde::Deserialize;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}

/// 同一字段内任一值命中即可，不同字段须同时满足。
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub outbound: String,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub port: Vec<u16>,
    #[serde(default)]
    pub network: Option<Network>,
    #[serde(default)]
    pub node: Vec<String>,
    #[serde(default)]
    pub user: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(text: &str) -> Result<Self> {
        let (address, prefix) = text.split_once('/').unwrap_or((text, ""));
        let network: IpAddr = address.parse().map_err(|_| invalid())?;
        let bits = if network.is_ipv4() { 32 } else { 128 };
        let prefix = if prefix.is_empty() {
            bits
        } else {
            prefix.parse().map_err(|_| invalid())?
        };
        if prefix > bits {
            return Err(invalid());
        }
        Ok(Self { network, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => prefix_matches(
                network.to_bits().into(),
                ip.to_bits().into(),
                32,
                self.prefix,
            ),
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                prefix_matches(network.to_bits(), ip.to_bits(), 128, self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_matches(network: u128, ip: u128, bits: u8, prefix: u8) -> bool {
    u32::from(bits - prefix) >= u128::BITS || (network ^ ip) >> (bits - prefix) == 0
}

#[derive(Debug)]
struct Rule {
    outbound: OutId,
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    ip_cidr: Vec<Cidr>,
    port: Vec<u16>,
    network: Option<Network>,
    node: Vec<NodeId>,
    user: Vec<UserId>,
}

impl Rule {
    fn compile(spec: &RuleSpec) -> Result<Self> {
        let rule = Self {
            outbound: OutId::parse(&spec.outbound)?,
            domain: spec
                .domain
                .iter()
                .map(|v| domain(v))
                .collect::<Result<_>>()?,
            domain_suffix: spec
                .domain_suffix
                .iter()
                .map(|v| domain(v.strip_prefix('.').unwrap_or(v)))
                .collect::<Result<_>>()?,
            domain_keyword: spec
                .domain_keyword
                .iter()
                .map(|v| v.to_ascii_lowercase())
                .collect(),
            ip_cidr: spec
                .ip_cidr
                .iter()
                .map(|v| Cidr::parse(v))
                .collect::<Result<_>>()?,
            port: spec.port.clone(),
            network: spec.network,
            node: spec
                .node
                .iter()
                .map(|v| NodeId::parse(v))
                .collect::<Result<_>>()?,
            user: spec
                .user
                .iter()
                .map(|v| UserId::parse(v))
                .collect::<Result<_>>()?,
        };
        let empty = rule.domain.is_empty()
            && rule.domain_suffix.is_empty()
            && rule.domain_keyword.is_empty()
            && rule.ip_cidr.is_empty()
            && rule.port.is_empty()
            && rule.network.is_none()
            && rule.node.is_empty()
            && rule.user.is_empty();
        if empty || rule.domain_keyword.iter().any(String::is_empty) {
            return Err(invalid());
        }
        Ok(rule)
    }

    fn matches(&self, target: &Destination, network: Network, source: &Source) -> bool {
        let host = match target.address() {
            Address::Domain(name) => Some(name.strip_suffix('.').unwrap_or(name)),
            Address::Ip(_) => None,
        };
        let ip = match target.address() {
            Address::Ip(ip) => Some(*ip),
            Address::Domain(_) => None,
        };
        let names = self.domain.is_empty()
            && self.domain_suffix.is_empty()
            && self.domain_keyword.is_empty();
        let name_hit = host.is_some_and(|host| {
            self.domain.iter().any(|value| value == host)
                || self.domain_suffix.iter().any(|value| {
                    host == value
                        || host
                            .strip_suffix(value.as_str())
                            .is_some_and(|rest| rest.ends_with('.'))
                })
                || self
                    .domain_keyword
                    .iter()
                    .any(|value| host.contains(value.as_str()))
        });
        let ip_hit = ip.is_some_and(|ip| self.ip_cidr.iter().any(|cidr| cidr.contains(ip)));
        // 域名条件与 CIDR 都描述目标地址，任一命中即满足目标条件。
        (names && self.ip_cidr.is_empty() || name_hit || ip_hit)
            && (self.port.is_empty() || self.port.contains(&target.port()))
            && self.network.is_none_or(|value| value == network)
            && (self.node.is_empty() || self.node.contains(source.node()))
            && (self.user.is_empty() || source.user().is_some_and(|user| self.user.contains(&user)))
    }
}

fn invalid() -> Error {
    Error::Config("路由规则不合法".into())
}

fn domain(value: &str) -> Result<String> {
    match Destination::new(value, 1).map_err(|_| invalid())?.address() {
        Address::Domain(name) => Ok(name.strip_suffix('.').unwrap_or(name).to_owned()),
        Address::Ip(_) => Err(invalid()),
    }
}

/// 按配置顺序匹配，首条命中生效；未命中时由调用方使用节点绑定的出站。
#[derive(Debug, Default)]
pub struct RouteTable {
    rules: Vec<Rule>,
}

impl RouteTable {
    pub fn compile(specs: &[RuleSpec]) -> Result<Self> {
        Ok(Self {
            rules: specs.iter().map(Rule::compile).collect::<Result<_>>()?,
        })
    }

    pub fn select(
        &self,
        target: &Destination,
        network: Network,
        source: &Source,
    ) -> Option<&OutId> {
        self.rules
            .iter()
            .find(|rule| rule.matches(target, network, source))
            .map(|rule| &rule.outbound)
    }

    pub fn outbounds(&self) -> impl Iterator<Item = &OutId> {
        self.rules.iter().map(|rule| &rule.outbound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const USER: &str = "00000000-0000-4000-8000-000000000001";

    fn table(rules: serde_json::Value) -> RouteTable {
        RouteTable::compile(&serde_json::from_value::<Vec<RuleSpec>>(rules).unwrap()).unwrap()
    }
    fn local(node: &str) -> Source {
        Source::Local {
            node: NodeId::parse(node).unwrap(),
        }
    }
    fn pick(
        table: &RouteTable,
        host: &str,
        port: u16,
        network: Network,
        source: &Source,
    ) -> Option<String> {
        table
            .select(&Destination::new(host, port).unwrap(), network, source)
            .map(ToString::to_string)
    }

    #[test]
    fn domain_conditions_match_exact_suffix_and_keyword() {
        let table = table(json!([
            {"outbound":"exact","domain":["Example.COM"]},
            {"outbound":"suffix","domain_suffix":[".example.org"]},
            {"outbound":"keyword","domain_keyword":["TRACK"]},
        ]));
        let source = local("n");
        assert_eq!(
            pick(&table, "example.com", 443, Network::Tcp, &source).as_deref(),
            Some("exact")
        );
        assert_eq!(
            pick(&table, "www.example.com", 443, Network::Tcp, &source),
            None
        );
        assert_eq!(
            pick(&table, "example.org.", 443, Network::Tcp, &source).as_deref(),
            Some("suffix")
        );
        assert_eq!(
            pick(&table, "a.example.org", 443, Network::Tcp, &source).as_deref(),
            Some("suffix")
        );
        assert_eq!(
            pick(&table, "badexample.org", 443, Network::Tcp, &source),
            None
        );
        assert_eq!(
            pick(&table, "ads.tracker.net", 443, Network::Tcp, &source).as_deref(),
            Some("keyword")
        );
    }

    #[test]
    fn cidr_matches_literal_addresses_and_never_domains() {
        let table = table(json!([
            {"outbound":"v4","ip_cidr":["10.0.0.0/8"]},
            {"outbound":"v6","ip_cidr":["2001:db8::/32"]},
            {"outbound":"all","ip_cidr":["0.0.0.0/0"]},
        ]));
        let source = local("n");
        assert_eq!(
            pick(&table, "10.1.2.3", 80, Network::Tcp, &source).as_deref(),
            Some("v4")
        );
        assert_eq!(
            pick(&table, "::ffff:10.1.2.3", 80, Network::Tcp, &source).as_deref(),
            Some("v4")
        );
        assert_eq!(
            pick(&table, "2001:db8::1", 80, Network::Tcp, &source).as_deref(),
            Some("v6")
        );
        assert_eq!(
            pick(&table, "11.0.0.1", 80, Network::Tcp, &source).as_deref(),
            Some("all")
        );
        assert_eq!(pick(&table, "2001:db9::1", 80, Network::Tcp, &source), None);
        assert_eq!(pick(&table, "ten.example", 80, Network::Tcp, &source), None);
    }

    #[test]
    fn fields_combine_with_and_and_first_match_wins() {
        let table = table(json!([
            {"outbound":"a","domain_suffix":["example.com"],"port":[443],"network":"tcp"},
            {"outbound":"b","domain_suffix":["example.com"]},
            {"outbound":"c","domain_suffix":["example.com"]},
        ]));
        let source = local("n");
        assert_eq!(
            pick(&table, "example.com", 443, Network::Tcp, &source).as_deref(),
            Some("a")
        );
        assert_eq!(
            pick(&table, "example.com", 80, Network::Tcp, &source).as_deref(),
            Some("b")
        );
        assert_eq!(
            pick(&table, "example.com", 443, Network::Udp, &source).as_deref(),
            Some("b")
        );
    }

    #[test]
    fn node_and_user_conditions_use_the_trusted_source() {
        let table = table(json!([
            {"outbound":"user","user":[USER]},
            {"outbound":"node","node":["edge"]},
        ]));
        let user = Source::User {
            node: NodeId::parse("other").unwrap(),
            user: UserId::parse(USER).unwrap(),
            credential_epoch: 1,
        };
        assert_eq!(
            pick(&table, "example.com", 1, Network::Tcp, &user).as_deref(),
            Some("user")
        );
        assert_eq!(
            pick(&table, "example.com", 1, Network::Tcp, &local("edge")).as_deref(),
            Some("node")
        );
        assert_eq!(
            pick(&table, "example.com", 1, Network::Tcp, &local("other")),
            None
        );
    }

    #[test]
    fn rejects_rules_that_could_not_be_intended() {
        for rule in [
            json!({"outbound":"a"}),
            json!({"outbound":"a","domain":["10.0.0.1"]}),
            json!({"outbound":"a","domain_keyword":[""]}),
            json!({"outbound":"a","ip_cidr":["10.0.0.0/33"]}),
            json!({"outbound":"a","ip_cidr":["example.com/8"]}),
            json!({"outbound":"bad tag","port":[1]}),
        ] {
            let spec: RuleSpec = serde_json::from_value(rule).unwrap();
            assert!(RouteTable::compile(&[spec]).is_err());
        }
    }
}
