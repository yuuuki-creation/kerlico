use std::io;

pub fn private_peer(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local() || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1])),
        std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some_and(|v4| private_peer(v4.into())),
    }
}

pub fn reverse_tag(text: &str) -> io::Result<String> {
    if text.trim_start().starts_with('{') {
        #[derive(serde::Deserialize)]
        struct Reverse { tag: String }
        let value: Reverse = serde_json::from_str(text).map_err(io::Error::other)?;
        if value.tag.is_empty() { return Err(io::Error::other("reverse tag is empty")); }
        Ok(value.tag)
    } else { Ok(text.to_string()) }
}

pub fn string_list(text: &str) -> io::Result<Vec<String>> {
    if text.trim_start().starts_with('[') {
        serde_json::from_str(text).map_err(io::Error::other)
    } else if text.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(text.split(',').map(|part| part.trim().to_string()).collect())
    }
}
