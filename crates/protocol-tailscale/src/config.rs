use kerlico_core::{Destination, Error, Result};
use kerlico_net::TcpConnector;
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    control_url: String,
    auth_key: String,
    #[serde(default = "default_hostname")]
    hostname: String,
    #[serde(default)]
    state_file: Option<PathBuf>,
    #[serde(default)]
    ephemeral: Option<bool>,
    #[serde(default)]
    exit_node: Option<String>,
    #[serde(default)]
    accept_routes: bool,
    #[serde(default = "default_direct")]
    direct: bool,
    #[serde(default)]
    ca_pem: Option<String>,
    #[serde(default = "default_start_timeout")]
    start_timeout_ms: u64,
}
fn default_hostname() -> String {
    "kerlico".into()
}
fn default_direct() -> bool {
    true
}
fn default_start_timeout() -> u64 {
    60_000
}

#[derive(Clone)]
pub struct RouteOptions {
    pub exit_node: Option<String>,
    pub accept_routes: bool,
}

#[derive(Clone)]
pub struct ControlEndpoint {
    pub connector: TcpConnector,
    pub destination: Destination,
    pub authority: String,
}

#[derive(Clone)]
pub struct Prepared {
    pub control: ControlEndpoint,
    pub auth_key: Zeroizing<String>,
    pub hostname: String,
    pub state_file: Option<PathBuf>,
    pub ephemeral: bool,
    pub routes: RouteOptions,
    pub direct: bool,
    pub ca_pem: Option<String>,
    pub start_timeout: Duration,
}

impl Options {
    pub fn prepare(self) -> Result<Prepared> {
        if self.auth_key.is_empty() || self.auth_key.len() > 4096 {
            return Err(Error::Config("Tailscale auth_key不合法".into()));
        }
        if self.hostname.is_empty()
            || self.hostname.len() > 63
            || !self
                .hostname
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::Config("Tailscale hostname不合法".into()));
        }
        if self.exit_node.as_deref() == Some("") {
            return Err(Error::Config("Tailscale exit_node不能为空".into()));
        }
        if !(1000..=600_000).contains(&self.start_timeout_ms) {
            return Err(Error::Config("Tailscale start_timeout_ms不合法".into()));
        }
        let control = parse_control(&self.control_url, self.ca_pem.as_deref())?;
        Ok(Prepared {
            control,
            auth_key: Zeroizing::new(self.auth_key),
            hostname: self.hostname,
            ephemeral: self.ephemeral.unwrap_or(self.state_file.is_none()),
            state_file: self.state_file,
            routes: RouteOptions {
                exit_node: self.exit_node,
                accept_routes: self.accept_routes,
            },
            direct: self.direct,
            ca_pem: self.ca_pem,
            start_timeout: Duration::from_millis(self.start_timeout_ms),
        })
    }
}

fn parse_control(url: &str, ca_pem: Option<&str>) -> Result<ControlEndpoint> {
    let invalid = || Error::Config("Tailscale control_url不合法".into());
    let uri: http::Uri = url.parse().map_err(|_| invalid())?;
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err(invalid());
    }
    let tls = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err(invalid()),
    };
    let authority = uri.authority().ok_or_else(invalid)?;
    if authority.as_str().contains('@') {
        return Err(invalid());
    }
    let host = authority.host().trim_matches(['[', ']']);
    let port = authority.port_u16().unwrap_or(if tls { 443 } else { 80 });
    Ok(ControlEndpoint {
        connector: if tls {
            TcpConnector::tls(host, ca_pem)?
        } else {
            TcpConnector::plain()
        },
        destination: Destination::new(host, port)?,
        authority: authority.as_str().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn prepare(value: serde_json::Value) -> Result<Prepared> {
        serde_json::from_value::<Options>(value).unwrap().prepare()
    }

    #[test]
    fn control_url_forms() {
        let prepared = prepare(json!({"control_url":"https://hs.test:8443","auth_key":"k"}));
        let prepared = prepared.unwrap_or_else(|_| panic!("https URL"));
        assert!(prepared.control.connector.is_tls());
        assert_eq!(prepared.control.authority, "hs.test:8443");
        assert_eq!(prepared.control.destination.port(), 8443);
        assert!(prepared.ephemeral);
        assert!(prepared.direct);
        let prepared = prepare(json!({"control_url":"http://[::1]","auth_key":"k"}));
        let prepared = prepared.unwrap_or_else(|_| panic!("http URL"));
        assert!(!prepared.control.connector.is_tls());
        assert_eq!(prepared.control.destination.port(), 80);
        for url in [
            "ftp://a",
            "https://a/path",
            "https://a?x=1",
            "https://u@a",
            "hs.test",
        ] {
            assert!(
                prepare(json!({"control_url":url,"auth_key":"k"})).is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn state_file_makes_registration_durable_by_default() {
        let prepared =
            prepare(json!({"control_url":"http://a","auth_key":"k","state_file":"s.json"}));
        assert!(!prepared.unwrap_or_else(|_| panic!("state file")).ephemeral);
        let prepared = prepare(
            json!({"control_url":"http://a","auth_key":"k","state_file":"s.json","ephemeral":true}),
        );
        assert!(prepared.unwrap_or_else(|_| panic!("explicit")).ephemeral);
        assert!(prepare(json!({"control_url":"http://a","auth_key":""})).is_err());
        assert!(
            prepare(json!({"control_url":"http://a","auth_key":"k","hostname":"a b"})).is_err()
        );
    }
}
