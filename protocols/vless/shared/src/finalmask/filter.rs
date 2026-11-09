use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use super::{invalid, settings, PacketIo, UDP_POLL};

#[derive(Clone)]
pub struct GeoIpMatcher {
    has_ipv4: bool,
    has_ipv6: bool,
    matches: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>,
}

impl GeoIpMatcher {
    pub fn new(
        has_ipv4: bool,
        has_ipv6: bool,
        matches: impl Fn(IpAddr) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            has_ipv4,
            has_ipv6,
            matches: Arc::new(matches),
        }
    }

    fn same_family(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() {
            self.has_ipv4
        } else {
            self.has_ipv6
        }
    }

    fn matches(&self, ip: IpAddr) -> bool {
        (self.matches)(ip)
    }
}

#[derive(Clone, Copy)]
pub(super) enum IpNetwork {
    V4(u32, u32),
    V6(u128, u128),
}

impl IpNetwork {
    pub(super) fn parse(text: &str) -> io::Result<Self> {
        let (addr, prefix) = text.split_once('/').unwrap_or((text, ""));
        let addr = addr.trim();
        let addr = addr
            .strip_prefix('[')
            .and_then(|addr| addr.strip_suffix(']'))
            .unwrap_or(addr);
        let addr = addr.parse::<IpAddr>().map_err(invalid)?.to_canonical();
        let width = if addr.is_ipv4() { 32 } else { 128 };
        let bits: u32 = if prefix.is_empty() {
            width
        } else {
            prefix.parse().map_err(invalid)?
        };
        if bits > width {
            return Err(invalid(format!("invalid prefix {text:?}")));
        }
        Ok(match addr {
            IpAddr::V4(ip) => {
                let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                Self::V4(u32::from(ip) & mask, mask)
            }
            IpAddr::V6(ip) => {
                let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                Self::V6(u128::from(ip) & mask, mask)
            }
        })
    }

    fn matches(self, addr: IpAddr) -> bool {
        match (self, addr) {
            (Self::V4(net, mask), IpAddr::V4(ip)) => u32::from(ip) & mask == net,
            (Self::V6(net, mask), IpAddr::V6(ip)) => u128::from(ip) & mask == net,
            _ => false,
        }
    }

    fn same_family(self, addr: IpAddr) -> bool {
        matches!(self, Self::V4(..)) == addr.is_ipv4()
    }

    pub(super) fn sample(self, entropy: u128) -> IpAddr {
        match self {
            Self::V4(net, mask) => Ipv4Addr::from(net | (entropy as u32 & !mask)).into(),
            Self::V6(net, mask) => Ipv6Addr::from(net | (entropy & !mask)).into(),
        }
    }
}

#[derive(Clone, Default)]
struct Rules {
    cidrs: Vec<IpNetwork>,
    inverse_cidrs: Vec<IpNetwork>,
    geoip: Vec<GeoIpMatcher>,
    inverse_geoip: Vec<GeoIpMatcher>,
}

impl Rules {
    fn parse(
        entries: Vec<String>,
        geoip: &impl Fn(&str, &str) -> io::Result<GeoIpMatcher>,
    ) -> io::Result<Self> {
        let mut rules = Self::default();
        for entry in entries {
            let (entry, invert) = reverse(&entry);
            let category = if let Some(category) = entry.strip_prefix("geoip:") {
                Some(("geoip.dat", category))
            } else if let Some(ext) = entry
                .strip_prefix("ext:")
                .or_else(|| entry.strip_prefix("ext-ip:"))
            {
                Some(
                    ext.split_once(':')
                        .ok_or_else(|| invalid("GeoIP filter expects a file and category"))?,
                )
            } else {
                None
            };
            if let Some((file, category)) = category {
                let (category, category_inverted) = reverse(category);
                if file.is_empty() || category.is_empty() {
                    return Err(invalid("GeoIP filter expects a file and category"));
                }
                let matcher = geoip(file, &category.to_ascii_uppercase())?;
                if invert ^ category_inverted {
                    rules.inverse_geoip.push(matcher);
                } else {
                    rules.geoip.push(matcher);
                }
            } else {
                let net = IpNetwork::parse(entry)?;
                if invert {
                    rules.inverse_cidrs.push(net);
                } else {
                    rules.cidrs.push(net);
                }
            }
        }
        Ok(rules)
    }

    fn matches(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.matches(ip))
            || self.geoip.iter().any(|matcher| matcher.matches(ip))
            || (self.inverse_cidrs.iter().any(|net| net.same_family(ip))
                && !self.inverse_cidrs.iter().any(|net| net.matches(ip)))
            || (self
                .inverse_geoip
                .iter()
                .any(|matcher| matcher.same_family(ip))
                && !self.inverse_geoip.iter().any(|matcher| matcher.matches(ip)))
    }
}

fn reverse(text: &str) -> (&str, bool) {
    let value = text.trim_start_matches('!');
    (value, (text.len() - value.len()) % 2 != 0)
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    #[serde(rename = "blockedSourceIPs")]
    blocked: Vec<String>,
    #[serde(rename = "allowedSourceIPs")]
    allowed: Vec<String>,
}

#[derive(Clone)]
pub(super) struct Filter {
    blocked: Rules,
    allowed: Option<Rules>,
}

impl Filter {
    pub(super) fn parse(
        value: Value,
        geoip: &impl Fn(&str, &str) -> io::Result<GeoIpMatcher>,
    ) -> io::Result<Self> {
        let config: Config = settings(value)?;
        let blocked = Rules::parse(config.blocked, geoip)?;
        let allowed = if config.allowed.is_empty() {
            None
        } else {
            Some(Rules::parse(config.allowed, geoip)?)
        };
        Ok(Self { blocked, allowed })
    }

    pub(super) fn rejects(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.blocked.matches(ip)
            || self
                .allowed
                .as_ref()
                .is_some_and(|allowed| !allowed.matches(ip))
    }

    pub(super) fn wrap(&self, inner: Arc<dyn PacketIo>) -> Arc<dyn PacketIo> {
        Arc::new(FilteredPackets {
            inner,
            filter: self.clone(),
        })
    }
}

struct FilteredPackets {
    inner: Arc<dyn PacketIo>,
    filter: Filter,
}

impl PacketIo for FilteredPackets {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let deadline = Instant::now() + UDP_POLL;
        while Instant::now() < deadline {
            let (n, peer) = self.inner.recv_from(out)?;
            if !self.filter.rejects(peer.ip()) {
                return Ok((n, peer));
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(packet, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_groups_inverted_cidrs_and_honors_block_precedence() {
        let filter = Filter::parse(
            serde_json::json!({
                "allowedSourceIPs": ["!10.0.0.0/8", "!192.168.0.0/16", "geoip:office"],
                "blockedSourceIPs": ["ext-ip:example.dat:block"]
            }),
            &|file, category| match (file, category) {
                ("geoip.dat", "OFFICE") => Ok(GeoIpMatcher::new(true, false, |ip| {
                    ip == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4))
                })),
                ("example.dat", "BLOCK") => Ok(GeoIpMatcher::new(true, false, |ip| {
                    ip == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))
                })),
                _ => Err(invalid("unknown GeoIP fixture")),
            },
        )
        .unwrap();
        for (source, blocked) in [
            ("10.0.0.4", false),
            ("::ffff:10.0.0.4", false),
            ("10.0.0.5", true),
            ("192.168.0.4", true),
            ("203.0.113.1", false),
            ("203.0.113.2", true),
            ("2001:db8::1", true),
        ] {
            assert_eq!(filter.rejects(source.parse().unwrap()), blocked, "{source}");
        }
    }

    #[test]
    fn inverted_geoip_matches_only_address_families_in_its_catalog() {
        let filter = Filter::parse(
            serde_json::json!({ "blockedSourceIPs": ["geoip:!office"] }),
            &|_, _| {
                Ok(GeoIpMatcher::new(false, true, |ip| {
                    ip == Ipv6Addr::LOCALHOST
                }))
            },
        )
        .unwrap();
        for (source, blocked) in [("192.0.2.1", false), ("::1", false), ("2001:db8::1", true)] {
            assert_eq!(filter.rejects(source.parse().unwrap()), blocked, "{source}");
        }
    }

    struct BlockedTraffic(Instant);

    impl PacketIo for BlockedTraffic {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            if Instant::now() >= self.0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            out[0] = 1;
            Ok((1, "192.0.2.1:1234".parse().unwrap()))
        }

        fn send_to(&self, packet: &[u8], _: SocketAddr) -> io::Result<usize> {
            Ok(packet.len())
        }
    }

    #[test]
    fn a_flood_of_blocked_datagrams_still_yields_to_the_caller() {
        let filter = Filter::parse(
            serde_json::json!({ "blockedSourceIPs": ["192.0.2.1"] }),
            &|_, _| unreachable!(),
        )
        .unwrap();
        let traffic = Arc::new(BlockedTraffic(Instant::now() + UDP_POLL * 4));
        let masked = filter.wrap(traffic);
        assert_eq!(
            masked.recv_from(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
