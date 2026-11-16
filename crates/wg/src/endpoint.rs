use std::io;
use std::net::{Ipv6Addr, SocketAddr, ToSocketAddrs};

/// Parses a numeric endpoint, resolving a named IPv6 zone through the local OS.
/// Hostnames are deliberately left to the outbound resolver.
pub fn parse_endpoint(text: &str) -> io::Result<SocketAddr> {
    if let Ok(address) = text.parse() {
        return Ok(address);
    }
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid WireGuard endpoint");
    let (host, port) = text
        .strip_prefix('[')
        .and_then(|value| value.split_once("]:"))
        .ok_or_else(invalid)?;
    let (ip, zone) = host.split_once('%').ok_or_else(invalid)?;
    let ip: Ipv6Addr = ip.parse().map_err(|_| invalid())?;
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if zone.is_empty()
        || zone.contains(['[', ']', ':', '%'])
        || zone.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(invalid());
    }
    // The host is already verified as a literal; getaddrinfo only maps its zone.
    (host, port)
        .to_socket_addrs()?
        .find(|addr| matches!(addr, SocketAddr::V6(addr) if *addr.ip() == ip && addr.scope_id() != 0))
        .ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_zone_is_preserved_without_resolving_hostnames() {
        let SocketAddr::V6(addr) = parse_endpoint("[fe80::2%7]:51820").unwrap() else {
            panic!("expected IPv6");
        };
        assert_eq!(addr.scope_id(), 7);
        assert_eq!(addr.port(), 51820);
        assert!(parse_endpoint("example.invalid:51820").is_err());
        assert!(parse_endpoint("[fe80::2%]:51820").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn named_zone_is_resolved_by_the_os() {
        let SocketAddr::V6(addr) = parse_endpoint("[fe80::2%lo]:51820").unwrap() else {
            panic!("expected IPv6");
        };
        assert_ne!(addr.scope_id(), 0);
        assert!(parse_endpoint("[fe80::2%no-such-wg-if]:51820").is_err());
    }
}
