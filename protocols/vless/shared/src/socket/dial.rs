use super::{
    invalid, unsupported, AddressPortStrategy, DomainStrategy, HappyEyeballs, SocketKind,
    SocketOptions,
};
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    fn contains(self, address: SocketAddr) -> bool {
        match self {
            Self::V4 => address.is_ipv4(),
            Self::V6 => address.is_ipv6(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionSource {
    Configured,
    System,
}

#[derive(Clone, Debug)]
pub struct SrvRecord {
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

/// Resolves carrier addresses using the caller's DNS policy. `family = None`
/// requests both address families. The socket layer never sends DNS queries.
pub trait TransportResolver {
    fn lookup_ip(
        &self,
        host: &str,
        port: u16,
        family: Option<AddressFamily>,
        source: ResolutionSource,
    ) -> io::Result<Vec<SocketAddr>>;

    fn lookup_srv(&self, _: &str) -> io::Result<Vec<SrvRecord>> {
        Err(unsupported(
            "sockopt.addressPortStrategy needs an SRV resolver",
        ))
    }

    fn lookup_txt(&self, _: &str) -> io::Result<Vec<String>> {
        Err(unsupported(
            "sockopt.addressPortStrategy needs a TXT resolver",
        ))
    }
}

#[derive(Clone, Debug)]
pub enum DialPlan {
    Direct(DirectDialPlan),
    Proxy(ProxyDialPlan),
}

impl DialPlan {
    /// For callers without a carrier proxy provider.
    pub fn direct(self) -> io::Result<DirectDialPlan> {
        match self {
            Self::Direct(plan) => Ok(plan),
            Self::Proxy(_) => Err(unsupported(
                "sockopt.dialerProxy needs a carrier proxy provider",
            )),
        }
    }
}

/// A carrier request for the caller's outbound selector.
#[derive(Clone, Debug)]
pub struct ProxyDialPlan {
    pub selector: String,
    pub host: String,
    pub port: u16,
    pub kind: SocketKind,
}

#[derive(Clone, Debug)]
pub struct DirectDialPlan {
    addresses: Vec<SocketAddr>,
    race: Option<HappyEyeballs>,
}

impl DirectDialPlan {
    pub fn connect_race(&self) -> Option<(Duration, usize)> {
        self.race.map(|race| (Duration::from_millis(race.try_delay_ms), race.max_concurrent_try as usize))
    }

    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    pub fn is_racing(&self) -> bool {
        self.race.is_some()
    }

    /// Runs caller-provided dial futures in order or races them according to
    /// `happyEyeballs`. Dropping the plan's future cancels pending attempts.
    pub async fn dial<T, F, Fut>(&self, mut attempt: F) -> io::Result<T>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let mut last_error = no_addresses();
        let Some(race) = self.race else {
            for &address in &self.addresses {
                match attempt(address).await {
                    Ok(connection) => return Ok(connection),
                    Err(error) => last_error = error,
                }
            }
            return Err(last_error);
        };

        let mut addresses = self.addresses.iter().copied().peekable();
        let mut active = FuturesUnordered::new();
        let delay = Duration::from_millis(race.try_delay_ms);
        let limit = race.max_concurrent_try as usize;
        loop {
            if let Some(address) = addresses.next() {
                active.push(attempt(address));
            }
            let result = if active.len() < limit && addresses.peek().is_some() {
                match tokio::time::timeout(delay, active.next()).await {
                    Ok(result) => result,
                    Err(_) => continue,
                }
            } else {
                active.next().await
            };
            match result {
                Some(Ok(connection)) => return Ok(connection),
                Some(Err(error)) => last_error = error,
                None => return Err(last_error),
            }
        }
    }
}

impl SocketOptions {
    pub fn plan(
        &self,
        host: &str,
        port: u16,
        kind: SocketKind,
        local_family: Option<AddressFamily>,
        resolver: &dyn TransportResolver,
    ) -> io::Result<DialPlan> {
        if host.is_empty() || port == 0 {
            return Err(invalid("carrier endpoint needs a host and nonzero port"));
        }
        let (host, port) = self.address_port_strategy.rewrite(host, port, resolver)?;
        let host = host.as_str();
        let mut configured = None;
        if !ip_endpoint(host) && !matches!(self.domain_strategy, DomainStrategy::AsIs) {
            match self
                .domain_strategy
                .resolve(host, port, local_family, resolver)
            {
                Ok(addresses) => configured = Some(addresses),
                Err(error) if self.domain_strategy.is_forced() => return Err(error),
                Err(_) => {}
            }
        }

        if let Some(selector) = &self.dialer_proxy {
            let host = configured.as_ref().map_or_else(
                || unbracket(host).to_owned(),
                |addresses| {
                    addresses[rand::random_range(0..addresses.len())]
                        .ip()
                        .to_string()
                },
            );
            return Ok(DialPlan::Proxy(ProxyDialPlan {
                selector: selector.clone(),
                host,
                port,
                kind,
            }));
        }

        let mut race = None;
        let addresses = if let Some(mut addresses) = configured {
            let happy = self.happy_eyeballs;
            if kind == SocketKind::Tcp
                && addresses.len() > 1
                && happy.try_delay_ms != 0
                && happy.max_concurrent_try != 0
            {
                addresses = interleave(addresses, happy);
                race = Some(happy);
                addresses
            } else {
                vec![addresses[rand::random_range(0..addresses.len())]]
            }
        } else if let Some(address) = literal_address(host, port) {
            normalize(vec![address], port, local_family)?
        } else {
            lookup(
                resolver,
                unbracket(host),
                port,
                local_family,
                ResolutionSource::System,
            )?
        };
        Ok(DialPlan::Direct(DirectDialPlan { addresses, race }))
    }
}

impl DomainStrategy {
    fn is_forced(self) -> bool {
        matches!(
            self,
            Self::ForceIp | Self::ForceV4 | Self::ForceV6 | Self::ForceV4V6 | Self::ForceV6V4
        )
    }

    fn resolve(
        self,
        host: &str,
        port: u16,
        local_family: Option<AddressFamily>,
        resolver: &dyn TransportResolver,
    ) -> io::Result<Vec<SocketAddr>> {
        use AddressFamily::{V4, V6};

        let (preferred, fallback) = match self {
            Self::AsIs | Self::UseIp | Self::ForceIp => (None, None),
            Self::UseV4 | Self::ForceV4 => (Some(V4), None),
            Self::UseV6 | Self::ForceV6 => (Some(V6), None),
            Self::UseV4V6 | Self::ForceV4V6 => (Some(V4), Some(V6)),
            Self::UseV6V4 | Self::ForceV6V4 => (Some(V6), Some(V4)),
        };
        let query = |family| lookup(resolver, host, port, family, ResolutionSource::Configured);
        if let Some(local) = local_family {
            if preferred.is_some() && preferred != Some(local) && fallback != Some(local) {
                return Err(no_addresses());
            }
            return query(Some(local));
        }
        match (query(preferred), fallback) {
            (Err(_), Some(family)) => query(Some(family)),
            (result, _) => result,
        }
    }
}

impl AddressPortStrategy {
    fn rewrite(
        self,
        host: &str,
        port: u16,
        resolver: &dyn TransportResolver,
    ) -> io::Result<(String, u16)> {
        let (srv, change_host, change_port) = match self {
            Self::None => return Ok((host.to_owned(), port)),
            Self::SrvPortOnly => (true, false, true),
            Self::SrvAddressOnly => (true, true, false),
            Self::SrvPortAndAddress => (true, true, true),
            Self::TxtPortOnly => (false, false, true),
            Self::TxtAddressOnly => (false, true, false),
            Self::TxtPortAndAddress => (false, true, true),
        };
        if ip_endpoint(host) {
            return Ok((host.to_owned(), port));
        }
        let record = if srv {
            if !is_srv_name(host) {
                return Ok((host.to_owned(), port));
            }
            resolver.lookup_srv(host).map(select_srv)
        } else {
            resolver
                .lookup_txt(host)
                .map(|records| records.iter().find_map(|record| parse_txt_endpoint(record)))
        };
        match record {
            Ok(Some((target, target_port))) => Ok((
                if change_host { target } else { host.to_owned() },
                if change_port { target_port } else { port },
            )),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => Err(error),
            _ => Ok((host.to_owned(), port)),
        }
    }
}

fn is_srv_name(host: &str) -> bool {
    let mut parts = host.splitn(3, '.');
    let service = parts.next().and_then(|part| part.strip_prefix('_'));
    let protocol = parts.next().and_then(|part| part.strip_prefix('_'));
    service.is_some_and(|part| !part.is_empty())
        && protocol.is_some_and(|part| !part.is_empty())
        && parts.next().is_some_and(|part| !part.is_empty())
}

fn select_srv(mut records: Vec<SrvRecord>) -> Option<(String, u16)> {
    records.retain(|record| record.port != 0 && !record.target.is_empty() && record.target != ".");
    let priority = records.iter().map(|record| record.priority).min()?;
    records.retain(|record| record.priority == priority);
    let total: u64 = records.iter().map(|record| u64::from(record.weight)).sum();
    let index = if total == 0 {
        rand::random_range(0..records.len())
    } else {
        let draw = rand::random_range(0..total);
        let mut cumulative = 0;
        records.iter().position(|record| {
            cumulative += u64::from(record.weight);
            draw < cumulative
        })?
    };
    let record = records.swap_remove(index);
    Some((record.target, record.port))
}

fn parse_txt_endpoint(record: &str) -> Option<(String, u16)> {
    let (host, port) = record.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    let host = if let Some(host) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        host
    } else if host.contains([':', '[', ']']) {
        return None;
    } else {
        host
    };
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

fn ip_endpoint(host: &str) -> bool {
    let host = unbracket(host);
    host.split_once('%')
        .map_or(host, |(ip, _)| ip)
        .parse::<IpAddr>()
        .is_ok()
}

fn literal_address(host: &str, port: u16) -> Option<SocketAddr> {
    let host = unbracket(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    if host.contains(':') && host.contains('%') {
        return format!("[{host}]:{port}").parse().ok();
    }
    None
}

fn lookup(
    resolver: &dyn TransportResolver,
    host: &str,
    port: u16,
    family: Option<AddressFamily>,
    source: ResolutionSource,
) -> io::Result<Vec<SocketAddr>> {
    normalize(
        resolver.lookup_ip(host, port, family, source)?,
        port,
        family,
    )
}

fn normalize(
    addresses: Vec<SocketAddr>,
    port: u16,
    family: Option<AddressFamily>,
) -> io::Result<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    let addresses = addresses
        .into_iter()
        .filter_map(|address| {
            let mut address = match address.ip().to_canonical() {
                ip @ IpAddr::V4(_) => SocketAddr::new(ip, port),
                IpAddr::V6(_) => address,
            };
            address.set_port(port);
            (family.is_none_or(|family| family.contains(address)) && seen.insert(address))
                .then_some(address)
        })
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        Err(no_addresses())
    } else {
        Ok(addresses)
    }
}

fn interleave(addresses: Vec<SocketAddr>, happy: HappyEyeballs) -> Vec<SocketAddr> {
    let (mut first, second): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv6() == happy.prioritize_ipv6);
    if happy.interleave == 0 {
        first.extend(second);
        return first;
    }
    let block = happy.interleave as usize;
    let mut addresses = Vec::with_capacity(first.len() + second.len());
    let mut second = second.chunks(block);
    for group in first.chunks(block) {
        addresses.extend_from_slice(group);
        if let Some(group) = second.next() {
            addresses.extend_from_slice(group);
        }
    }
    addresses.extend(second.flatten().copied());
    addresses
}

fn no_addresses() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "carrier endpoint resolved no addresses",
    )
}
