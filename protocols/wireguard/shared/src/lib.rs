//! Text configuration shared by the two WireGuard roles.

use std::io;

use ipnet::IpNet;

pub use kerlico_wg::parse_key as key;

pub fn prefixes(values: &[String]) -> io::Result<Vec<IpNet>> {
    let mut prefixes = Vec::with_capacity(values.len());
    for value in values {
        let net: IpNet = value.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "expected a WireGuard CIDR")
        })?;
        let net = net.trunc();
        if !prefixes.contains(&net) {
            prefixes.push(net);
        }
    }
    Ok(prefixes)
}
