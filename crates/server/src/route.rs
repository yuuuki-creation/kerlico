use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use kerlico_outbound::{Exit, Native, OutboundChoice, Reachability};
use kerlico_shared::{Destination, Transport};

use crate::geodata::Catalog;

#[derive(Clone, Debug)]
pub struct Rule {
    pub lines: Vec<String>,
    pub choice: OutboundChoice,
}

pub struct Resolved {
    pub reach: Reachability,
    pub addresses: Vec<SocketAddr>,
    pub host: String,
    pub port: u16,
}

pub fn choose(
    rule_host: Option<&str>,
    rules: &[Rule],
    fallback: OutboundChoice,
    native: Native,
    resolved: &mut Resolved,
    local: &[IpAddr],
    resolve: &mut dyn FnMut(&str) -> Vec<IpAddr>,
    catalog: &Catalog,
) -> Result<Exit, ()> {
    let mut asked = !resolved.addresses.is_empty();
    for rule in rules {
        if rule_hits(&rule.lines, rule_host, resolved, &mut asked, resolve, catalog) {
            return finish(rule.choice, resolved, native);
        }
    }
    fill(resolved, &mut asked, resolve);
    if let Some(ip) = resolved.addresses.first().map(|addr| addr.ip()) {
        if listed_private(catalog, ip) || local.contains(&ip) {
            return native_family(ip, native);
        }
    }
    finish(fallback, resolved, native)
}

pub fn resolved_from(host: &str, port: u16, ips: &[IpAddr]) -> Resolved {
    Resolved {
        reach: reach_of(ips),
        addresses: sockets(ips, port, Transport::Tcp),
        host: host.to_string(),
        port,
    }
}

fn finish(choice: OutboundChoice, resolved: &Resolved, native: Native) -> Result<Exit, ()> {
    let choice = match choice {
        OutboundChoice::Manual(exit) => return Ok(exit),
        OutboundChoice::Default => OutboundChoice::Default,
    };
    kerlico_outbound::select_exit(choice, resolved.reach, native).map_err(|_| ())
}

fn native_family(ip: IpAddr, native: Native) -> Result<Exit, ()> {
    match ip {
        IpAddr::V4(_) if native.v4 => Ok(Exit::NativeV4),
        IpAddr::V6(_) if native.v6 => Ok(Exit::NativeV6),
        _ => Err(()),
    }
}

fn rule_hits(
    lines: &[String],
    name: Option<&str>,
    resolved: &mut Resolved,
    asked: &mut bool,
    resolve: &mut dyn FnMut(&str) -> Vec<IpAddr>,
    catalog: &Catalog,
) -> bool {
    lines
        .iter()
        .any(|line| line_hits(line, name, resolved, asked, resolve, catalog))
}

fn line_hits(
    line: &str,
    name: Option<&str>,
    resolved: &mut Resolved,
    asked: &mut bool,
    resolve: &mut dyn FnMut(&str) -> Vec<IpAddr>,
    catalog: &Catalog,
) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    if let Some(rest) = line.strip_prefix("geoip:!") {
        fill(resolved, asked, resolve);
        return !resolved.addresses.is_empty()
            && resolved
                .addresses
                .iter()
                .all(|addr| !geo_hit(catalog, rest, addr.ip()));
    }
    if let Some(rest) = line.strip_prefix("geoip:") {
        fill(resolved, asked, resolve);
        return resolved.addresses.iter().any(|addr| geo_hit(catalog, rest, addr.ip()));
    }
    if let Some(rest) = line.strip_prefix("ext:") {
        let Some((file, category)) = rest.split_once(':') else {
            return false;
        };
        if catalog.ext_has_net(file, category) {
            fill(resolved, asked, resolve);
            return resolved
                .addresses
                .iter()
                .any(|addr| catalog.ext_net(file, category, addr.ip()));
        }
        let Some(name) = name else {
            return false;
        };
        return catalog.ext_site(file, category, name);
    }
    if let Some(rest) = line.strip_prefix("geosite:") {
        let Some(name) = name else {
            return false;
        };
        return catalog.site_hit(rest, name);
    }
    let Some(name) = name else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    if let Some(rest) = line.strip_prefix("full:") {
        return name == rest.to_ascii_lowercase();
    }
    if let Some(rest) = line.strip_prefix("domain:") {
        let rest = rest.to_ascii_lowercase();
        return name == rest || name.ends_with(&format!(".{rest}"));
    }
    if let Some(rest) = line.strip_prefix("keyword:") {
        return name.contains(&rest.to_ascii_lowercase());
    }
    if let Some(rest) = line.strip_prefix("regexp:") {
        return regex::Regex::new(rest).map(|pattern| pattern.is_match(&name)).unwrap_or(false);
    }
    name.contains(&line.to_ascii_lowercase())
}

fn geo_hit(catalog: &Catalog, category: &str, ip: IpAddr) -> bool {
    if catalog.has_net(category) {
        return catalog.net_hit(category, ip);
    }
    category.eq_ignore_ascii_case("private") && private_ip(ip)
}

fn listed_private(catalog: &Catalog, ip: IpAddr) -> bool {
    geo_hit(catalog, "private", ip)
}

fn fill(resolved: &mut Resolved, asked: &mut bool, resolve: &mut dyn FnMut(&str) -> Vec<IpAddr>) {
    if *asked || !resolved.addresses.is_empty() {
        return;
    }
    *asked = true;
    if resolved.host.parse::<IpAddr>().is_ok() {
        return;
    }
    let ips = resolve(&resolved.host);
    resolved.reach = reach_of(&ips);
    resolved.addresses = sockets(&ips, resolved.port, Transport::Tcp);
}

pub fn literal(destination: &Destination) -> Option<IpAddr> {
    destination.host().parse().ok()
}

pub fn reach_of(addresses: &[IpAddr]) -> Reachability {
    if addresses.iter().any(|addr| addr.is_ipv4()) {
        Reachability::HasV4
    } else if addresses.iter().any(|addr| addr.is_ipv6()) {
        Reachability::V6Only
    } else {
        Reachability::None
    }
}

pub fn sockets(addresses: &[IpAddr], port: u16, transport: Transport) -> Vec<SocketAddr> {
    let _ = transport;
    addresses
        .iter()
        .map(|addr| SocketAddr::new(*addr, port))
        .collect()
}

fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => private_v4(addr),
        IpAddr::V6(addr) => private_v6(addr),
    }
}

fn private_v4(addr: Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (b & 0xc0) == 64)
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 0)
        || (a == 192 && b == 168)
        || (a == 192 && b == 88)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51)
        || (a == 203 && b == 0)
        || a >= 224
}

fn private_v6(addr: Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr.is_unicast_link_local()
        || (addr.segments()[0] & 0xfe00) == 0xfc00
        || (addr.segments()[0] & 0xff00) == 0xff00
}

pub fn remember_locals() -> Vec<IpAddr> {
    if_addrs::get_if_addrs()
        .map(|items| items.into_iter().map(|item| item.ip()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_outbound::Exit;

    fn bare(host: &str) -> Resolved {
        Resolved {
            reach: Reachability::None,
            addresses: Vec::new(),
            host: host.to_string(),
            port: 80,
        }
    }

    #[test]
    fn private_literal_fails_when_that_family_has_no_native() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut resolved = resolved_from("10.0.0.1", 80, &[ip]);
        let result = choose(
            None,
            &[],
            OutboundChoice::Default,
            Native { v4: false, v6: true },
            &mut resolved,
            &[],
            &mut |_| Vec::new(),
            &crate::geodata::Catalog::empty(),
        );
        assert_eq!(result, Err(()));
    }

    #[test]
    fn geoip_resolves_once_after_a_domain_miss() {
        let mut resolved = bare("example.com");
        let mut calls = 0;
        let rules = vec![Rule {
            lines: vec!["full:other.test".to_string(), "geoip:private".to_string()],
            choice: OutboundChoice::Manual(Exit::Landing),
        }];
        let exit = choose(
            Some("example.com"),
            &rules,
            OutboundChoice::Default,
            Native { v4: true, v6: false },
            &mut resolved,
            &[],
            &mut |_| {
                calls += 1;
                vec![IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))]
            },
            &crate::geodata::Catalog::empty(),
        )
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(exit, Exit::Landing);
    }
}
