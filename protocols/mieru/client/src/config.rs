use kerlico_mieru::{Account, ClientOptions, HandshakeMode, Multiplexing, Transport};
use kerlico_shared::{OpenError, Settings};
use std::net::{SocketAddr, ToSocketAddrs};

pub(crate) struct Plan {
    host: String,
    ports: std::ops::RangeInclusive<u16>,
    pub account: Account,
    pub options: ClientOptions,
}
impl Plan {
    pub fn parse(host: &str, port: u16, settings: &Settings) -> Result<Self, OpenError> {
        if host.is_empty()
            || host.len() > 255
            || host.chars().any(|ch| ch.is_whitespace() || ch.is_control())
            || port < 1025
        {
            return Err(OpenError::Settings);
        }
        let username = settings.text("username")?.to_string();
        let password = settings.text("password")?.to_string();
        if username.is_empty() || password.is_empty() {
            return Err(OpenError::Settings);
        }
        let ports = match settings.optional_text("portRange")? {
            None => port..=port,
            Some(text) => {
                let (first, last) = text.split_once('-').ok_or(OpenError::Settings)?;
                if first.is_empty()
                    || last.is_empty()
                    || !first.bytes().all(|byte| byte.is_ascii_digit())
                    || !last.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(OpenError::Settings);
                }
                let first: u16 = first.parse().map_err(|_| OpenError::Settings)?;
                let last: u16 = last.parse().map_err(|_| OpenError::Settings)?;
                if first < 1025 || first > last || !(first..=last).contains(&port) {
                    return Err(OpenError::Settings);
                }
                first..=last
            }
        };
        let transport = match settings.optional_text("transport")?.unwrap_or("TCP") {
            "TCP" => Transport::Tcp,
            "UDP" => Transport::Udp,
            _ => return Err(OpenError::Settings),
        };
        let mtu = settings
            .optional_text("mtu")?
            .unwrap_or("1400")
            .parse::<u16>()
            .map_err(|_| OpenError::Settings)?;
        if !(1280..=1400).contains(&mtu) {
            return Err(OpenError::Settings);
        }
        let multiplexing = match settings
            .optional_text("multiplexing")?
            .unwrap_or("MULTIPLEXING_LOW")
        {
            "MULTIPLEXING_OFF" => Multiplexing::Off,
            "MULTIPLEXING_DEFAULT" | "MULTIPLEXING_LOW" => Multiplexing::Low,
            "MULTIPLEXING_MIDDLE" => Multiplexing::Middle,
            "MULTIPLEXING_HIGH" => Multiplexing::High,
            _ => return Err(OpenError::Settings),
        };
        let handshake = match settings
            .optional_text("handshakeMode")?
            .unwrap_or("HANDSHAKE_STANDARD")
        {
            "HANDSHAKE_DEFAULT" | "HANDSHAKE_STANDARD" => HandshakeMode::Standard,
            "HANDSHAKE_NO_WAIT" => HandshakeMode::NoWait,
            _ => return Err(OpenError::Settings),
        };
        let low_entropy = match settings
            .optional_text("lowEntropyMode")?
            .unwrap_or("LOW_ENTROPY_MODE_OFF")
        {
            "0" | "LOW_ENTROPY_MODE_OFF" => 0,
            "1" | "LOW_ENTROPY_MODE_32" => 1,
            "2" | "LOW_ENTROPY_MODE_40" => 2,
            "3" | "LOW_ENTROPY_MODE_48" => 3,
            "4" | "LOW_ENTROPY_MODE_56" => 4,
            _ => return Err(OpenError::Settings),
        };
        Ok(Self {
            host: host.to_string(),
            ports,
            account: Account { username, password },
            options: ClientOptions {
                transport,
                mtu,
                multiplexing,
                handshake,
                low_entropy,
            },
        })
    }
    pub fn peers(&self) -> Result<Vec<SocketAddr>, OpenError> {
        let ips: std::collections::BTreeSet<_> = (self.host.as_str(), *self.ports.start())
            .to_socket_addrs()
            .map_err(|_| OpenError::Transport)?
            .map(|address| address.ip())
            .collect();
        if ips.is_empty() {
            return Err(OpenError::Transport);
        }
        Ok(self
            .ports
            .clone()
            .flat_map(|port| ips.iter().map(move |ip| SocketAddr::new(*ip, port)))
            .collect())
    }
}

pub(crate) fn parse_document(document: &str) -> Result<(String, u16, Settings), OpenError> {
    let value: serde_json::Value =
        serde_json::from_str(document).map_err(|_| OpenError::Settings)?;
    let object = value.as_object().ok_or(OpenError::Settings)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "protocol" | "peer" | "settings"))
    {
        return Err(OpenError::Settings);
    }
    if let Some(protocol) = object.get("protocol") {
        if protocol.as_str() != Some("mieru") {
            return Err(OpenError::Settings);
        }
    }
    let values = object
        .get("settings")
        .and_then(serde_json::Value::as_object)
        .ok_or(OpenError::Settings)?;
    let mut settings = Settings::default();
    for (key, value) in values {
        if !matches!(
            key.as_str(),
            "address"
                | "port"
                | "username"
                | "password"
                | "transport"
                | "portRange"
                | "mtu"
                | "multiplexing"
                | "handshakeMode"
                | "lowEntropyMode"
                | "socks5Port"
                | "httpProxyPort"
                | "socks5ListenLAN"
                | "httpProxyListenLAN"
        ) {
            return Err(OpenError::Settings);
        }
        if matches!(
            key.as_str(),
            "address"
                | "username"
                | "password"
                | "transport"
                | "portRange"
                | "multiplexing"
                | "handshakeMode"
        ) && !value.is_string()
        {
            return Err(OpenError::Settings);
        }
        if matches!(key.as_str(), "socks5ListenLAN" | "httpProxyListenLAN") && !value.is_boolean() {
            return Err(OpenError::Settings);
        }
        let text = match value {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Bool(value) => value.to_string(),
            serde_json::Value::Number(value) if value.as_u64().is_some() => value.to_string(),
            _ => return Err(OpenError::Settings),
        };
        settings.insert_text(key, text);
    }
    let endpoint = if let Some(peer) = object.get("peer") {
        let peer = peer.as_str().ok_or(OpenError::Settings)?;
        let (host, port) = split_peer(peer)?;
        if settings
            .optional_text("address")?
            .is_some_and(|address| address != host)
            || settings
                .optional_text("port")?
                .is_some_and(|value| value.parse::<u16>() != Ok(port))
        {
            return Err(OpenError::Settings);
        }
        (host, port)
    } else {
        (
            settings.text("address")?.to_string(),
            settings
                .text("port")?
                .parse::<u16>()
                .map_err(|_| OpenError::Settings)?,
        )
    };
    Ok((endpoint.0, endpoint.1, settings))
}
fn split_peer(text: &str) -> Result<(String, u16), OpenError> {
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    let (host, port) = text.rsplit_once(':').ok_or(OpenError::Settings)?;
    if host.is_empty() || host.contains(':') || host.contains('[') || host.contains(']') {
        return Err(OpenError::Settings);
    }
    Ok((
        host.to_string(),
        port.parse().map_err(|_| OpenError::Settings)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings {
        let mut s = Settings::default();
        s.insert_text("username", "test-user");
        s.insert_text("password", "test-password");
        s
    }
    #[test]
    fn validates_transport_options() {
        let mut s = settings();
        for (key, value) in [
            ("transport", "UDP"),
            ("portRange", "2000-2002"),
            ("mtu", "1280"),
            ("multiplexing", "MULTIPLEXING_HIGH"),
            ("handshakeMode", "HANDSHAKE_NO_WAIT"),
            ("lowEntropyMode", "LOW_ENTROPY_MODE_32"),
        ] {
            s.insert_text(key, value);
        }
        let plan = Plan::parse("127.0.0.1", 2001, &s).unwrap();
        assert_eq!(plan.peers().unwrap().len(), 3);
        assert!(matches!(plan.options.transport, Transport::Udp));
        assert!(matches!(plan.options.handshake, HandshakeMode::NoWait));
        for (key, bad) in [
            ("transport", "QUIC"),
            ("mtu", "1279"),
            ("multiplexing", "HIGH"),
            ("handshakeMode", "invalid"),
            ("portRange", "2002-2000"),
            ("lowEntropyMode", "5"),
        ] {
            let mut invalid = s.clone();
            invalid.insert_text(key, bad);
            assert!(
                Plan::parse("127.0.0.1", 2001, &invalid).is_err(),
                "无效配置必须拒绝：{key}"
            );
        }
    }
    #[test]
    fn rejects_ambiguous_and_non_scalar_configurations() {
        for document in [
            r#"{"peer":"127.0.0.1:2000","settings":{"address":"127.0.0.2"}}"#,
            r#"{"peer":"127.0.0.1:2000","settings":{"mtu":[]}}"#,
            r#"{"peer":"127.0.0.1:2000","settings":{"unknown":true}}"#,
        ] {
            assert!(parse_document(document).is_err());
        }
        let (_, port, s) = parse_document(r#"{"settings":{"address":"::1","port":2000,"username":"test-user","password":"test-password","mtu":1280,"socks5ListenLAN":false}}"#).unwrap();
        assert_eq!(port, 2000);
        assert_eq!(s.text("socks5ListenLAN").unwrap(), "false");
    }
}
