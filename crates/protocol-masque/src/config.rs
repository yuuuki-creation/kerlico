use crate::invalid;
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_config::TargetSpec;
use kerlico_core::{Destination, Result};
use serde::Deserialize;
use std::{io::Cursor, sync::Arc, time::Duration};

/// IPv6 最小 MTU 必须能放进一个 QUIC DATAGRAM，路径 MTU 下限与 Xray 客户端的初始包长相同。
const QUIC_PATH_MTU: u16 = 1350;
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(10);
const DATAGRAM_BUFFER: usize = 2 * 1024 * 1024;
const MAX_PEM: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    server: TargetSpec,
    uri: Option<String>,
    auth: Option<Auth>,
    tls: ClientTls,
    #[serde(default)]
    limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Auth {
    username: String,
    password: String,
}
impl Auth {
    fn header(&self) -> Result<http::HeaderValue> {
        if self.username.is_empty() || self.username.contains(':') {
            return Err(invalid());
        }
        let credentials = STANDARD.encode(format!("{}:{}", self.username, self.password));
        let mut value =
            http::HeaderValue::try_from(format!("Basic {credentials}")).map_err(|_| invalid())?;
        value.set_sensitive(true);
        Ok(value)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientTls {
    server_name: String,
    ca_pem: Option<String>,
    certificate_pem: Option<String>,
    private_key_pem: Option<String>,
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Limits {
    max_tunnels: usize,
    idle_timeout_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tunnels: 64,
            idle_timeout_ms: 60_000,
        }
    }
}

/// 编译期校验完成的出站配置；运行时只读。
pub(crate) struct Prepared {
    pub server: Destination,
    pub server_name: String,
    pub quic: quinn::ClientConfig,
    pub uri: http::Uri,
    pub authorization: Option<http::HeaderValue>,
    pub max_tunnels: usize,
    pub idle: Duration,
}
impl ClientOptions {
    pub fn prepare(self) -> Result<Prepared> {
        if !(1..=1024).contains(&self.limits.max_tunnels)
            || !(1000..=86_400_000).contains(&self.limits.idle_timeout_ms)
        {
            return Err(invalid());
        }
        let server = self.server.destination()?;
        let uri = request_uri(self.uri.as_deref(), &self.tls.server_name, self.server.port)?;
        let authorization = self.auth.as_ref().map(Auth::header).transpose()?;
        let server_name = self.tls.server_name.clone();
        let quic = quic_config(self.tls)?;
        Ok(Prepared {
            server,
            server_name,
            quic,
            uri,
            authorization,
            max_tunnels: self.limits.max_tunnels,
            idle: Duration::from_millis(self.limits.idle_timeout_ms),
        })
    }
}
fn request_uri(configured: Option<&str>, server_name: &str, port: u16) -> Result<http::Uri> {
    let text = match configured {
        Some(uri) => uri.to_owned(),
        None if port == 443 => format!("https://{server_name}/"),
        None => format!("https://{server_name}:{port}/"),
    };
    let uri: http::Uri = text.parse().map_err(|_| invalid())?;
    // URI Template 变量属于 IP Flow Forwarding，本出站固定请求全部目标和协议。
    if text.contains(['{', '}'])
        || uri.scheme_str() != Some("https")
        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
    {
        return Err(invalid());
    }
    Ok(uri)
}
fn certificates(pem: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    if pem.len() > MAX_PEM {
        return Err(invalid());
    }
    let certificates = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| invalid())?;
    if certificates.is_empty() {
        return Err(invalid());
    }
    Ok(certificates)
}
fn quic_config(tls: ClientTls) -> Result<quinn::ClientConfig> {
    rustls::pki_types::ServerName::try_from(tls.server_name.as_str()).map_err(|_| invalid())?;
    let roots = match &tls.ca_pem {
        Some(pem) => {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in certificates(pem)? {
                roots.add(certificate).map_err(|_| invalid())?;
            }
            roots
        }
        None => rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    };
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| invalid())?
    .with_root_certificates(roots);
    let mut crypto = match (&tls.certificate_pem, &tls.private_key_pem) {
        (None, None) => builder.with_no_client_auth(),
        (Some(certificate), Some(key)) if key.len() <= MAX_PEM => {
            let key = rustls_pemfile::private_key(&mut Cursor::new(key))
                .map_err(|_| invalid())?
                .ok_or_else(invalid)?;
            builder
                .with_client_auth_cert(certificates(certificate)?, key)
                .map_err(|_| invalid())?
        }
        _ => return Err(invalid()),
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|_| invalid())?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(0u32.into());
    transport.initial_mtu(QUIC_PATH_MTU);
    transport.min_mtu(QUIC_PATH_MTU);
    transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    transport.datagram_send_buffer_size(DATAGRAM_BUFFER);
    transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(QUIC_IDLE_TIMEOUT).map_err(|_| invalid())?,
    ));
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn prepare(value: serde_json::Value) -> Result<Prepared> {
        serde_json::from_value::<ClientOptions>(value)
            .map_err(|_| invalid())?
            .prepare()
    }

    #[test]
    fn default_uri_follows_server_name_and_port() {
        let port_443 = prepare(json!({
            "server": {"host": "192.0.2.1", "port": 443},
            "tls": {"server_name": "masque.example.net"},
        }))
        .unwrap();
        assert_eq!(port_443.uri, "https://masque.example.net/");
        assert!(port_443.authorization.is_none());
        let other_port = prepare(json!({
            "server": {"host": "192.0.2.1", "port": 8443},
            "tls": {"server_name": "masque.example.net"},
            "auth": {"username": "member", "password": "secret"},
        }))
        .unwrap();
        assert_eq!(other_port.uri, "https://masque.example.net:8443/");
        assert_eq!(
            other_port.authorization.unwrap(),
            "Basic bWVtYmVyOnNlY3JldA=="
        );
    }

    #[test]
    fn invalid_options_fail_at_compile_time() {
        for value in [
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": "h"}, "uri": "http://h/"}),
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": "h"}, "uri": "https://h/.well-known/masque/ip/{target}/{ipproto}/"}),
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": "h"}, "uri": "https://user@h/"}),
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": ""}}),
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": "h", "certificate_pem": "x"}}),
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": "h", "ca_pem": "not pem"}}),
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": "h"}, "auth": {"username": "a:b", "password": "p"}}),
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": "h"}, "limits": {"max_tunnels": 0}}),
            json!({"server": {"host": "h", "port": 1}, "tls": {"server_name": "h"}, "unknown": 1}),
        ] {
            assert!(prepare(value).is_err());
        }
    }
}
