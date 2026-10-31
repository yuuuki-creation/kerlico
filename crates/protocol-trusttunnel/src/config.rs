//! 字段白名单、真实 Basic 认证与 TLS；构造阶段不监听或拨号。
use crate::invalid;
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{Result, ScopedCredentialFingerprint};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{io::Cursor, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Transport {
    H1,
    #[default]
    H2,
    H3,
}
impl Transport {
    pub fn alpn(self) -> Vec<Vec<u8>> {
        vec![match self {
            Self::H1 => b"http/1.1".to_vec(),
            Self::H2 => b"h2".to_vec(),
            Self::H3 => b"h3".to_vec(),
        }]
    }
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub max_connections: usize,
    pub max_streams: usize,
    pub max_udp_flows: usize,
    pub idle_timeout_ms: u64,
    pub health_check_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 4,
            max_streams: 64,
            max_udp_flows: 64,
            idle_timeout_ms: 30000,
            health_check_ms: 10000,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=32).contains(&self.max_connections)
            || !(1..=1024).contains(&self.max_streams)
            || !(1..=1024).contains(&self.max_udp_flows)
            || !(100..=86400000).contains(&self.idle_timeout_ms)
            || !(100..=86400000).contains(&self.health_check_ms)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn idle(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }
    pub fn quic(&self, incoming: usize) -> Result<Arc<quinn::TransportConfig>> {
        let mut value = quinn::TransportConfig::default();
        value.max_concurrent_bidi_streams((incoming as u32).into());
        value.stream_receive_window(131072u32.into());
        value.receive_window((2 * 1024 * 1024u32).into());
        value.send_window(2 * 1024 * 1024);
        value.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(self.idle()).map_err(|_| invalid())?,
        ));
        value.datagram_receive_buffer_size(None);
        value.keep_alive_interval(None);
        Ok(Arc::new(value))
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Auth {
    pub username: String,
    pub password: String,
}
impl Auth {
    pub fn validate(&self) -> Result<()> {
        if self.username.is_empty()
            || self.password.is_empty()
            || self.username.contains(':')
            || self.username.len() + self.password.len() > 512
            || self
                .username
                .chars()
                .chain(self.password.chars())
                .any(char::is_control)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn header(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.username, self.password))
        )
    }
    pub fn hash(&self) -> [u8; 32] {
        hash(b"kerlico/trusttunnel/basic/", self.header().as_bytes())
    }
    pub fn http_hash(&self) -> [u8; 32] {
        hash(b"kerlico/http\0", self.header().as_bytes())
    }
    pub fn isolation(&self) -> ScopedCredentialFingerprint {
        ScopedCredentialFingerprint {
            protocol: "trusttunnel-password".into(),
            fingerprint: hash(b"kerlico/trusttunnel/password/", self.password.as_bytes()),
        }
    }
}
fn hash(scope: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(scope);
    h.update(bytes);
    h.finalize().into()
}
pub(crate) fn authenticate(headers: &http::HeaderMap, users: &[[u8; 32]]) -> bool {
    let mut values = headers.get_all("proxy-authorization").iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(value) = String::from_utf8(bytes) else {
        return false;
    };
    let Some((username, password)) = value.split_once(':') else {
        return false;
    };
    let auth = Auth {
        username: username.into(),
        password: password.into(),
    };
    if auth.validate().is_err() {
        return false;
    }
    let current = auth.hash();
    let mut yes = subtle::Choice::from(0);
    for expected in users {
        yes |= expected.ct_eq(&current);
    }
    bool::from(yes)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: kerlico_config::TargetSpec,
    pub auth: Auth,
    pub tls: ClientTls,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default = "yes")]
    pub udp: bool,
    #[serde(default)]
    pub app_name: String,
    #[serde(default)]
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeOptions {
    pub users: Vec<Auth>,
    pub tls: ServerTls,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default = "yes")]
    pub udp: bool,
    #[serde(default)]
    pub limits: NodeLimits,
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NodeLimits {
    max_streams: usize,
    max_udp_flows: usize,
    idle_timeout_ms: u64,
}
impl Default for NodeLimits {
    fn default() -> Self {
        let limits = Limits::default();
        Self {
            max_streams: limits.max_streams,
            max_udp_flows: limits.max_udp_flows,
            idle_timeout_ms: limits.idle_timeout_ms,
        }
    }
}
impl NodeLimits {
    pub fn into_limits(self) -> Result<Limits> {
        let limits = Limits {
            max_streams: self.max_streams,
            max_udp_flows: self.max_udp_flows,
            idle_timeout_ms: self.idle_timeout_ms,
            ..Limits::default()
        };
        limits.validate()?;
        Ok(limits)
    }
}
fn yes() -> bool {
    true
}
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Version {
    #[default]
    Auto,
    Tls12,
    Tls13,
}
fn versions(
    version: Version,
    transport: Transport,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    if transport == Transport::H3 && matches!(version, Version::Tls12) {
        return Err(invalid());
    }
    Ok(match (version, transport) {
        (_, Transport::H3) | (Version::Tls13, _) => vec![&rustls::version::TLS13],
        (Version::Tls12, _) => vec![&rustls::version::TLS12],
        _ => vec![&rustls::version::TLS13, &rustls::version::TLS12],
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientTls {
    pub server_name: String,
    #[serde(default)]
    pub ca_pem: Option<String>,
    #[serde(default)]
    pub certificate_pem: Option<String>,
    #[serde(default)]
    pub private_key_pem: Option<String>,
    #[serde(default)]
    pub version: Version,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerTls {
    #[serde(default)]
    pub certificate_pem: Option<String>,
    #[serde(default)]
    pub private_key_pem: Option<String>,
    #[serde(default)]
    pub certificate_file: Option<String>,
    #[serde(default)]
    pub private_key_file: Option<String>,
    #[serde(default)]
    pub client_ca_pem: Option<String>,
    #[serde(default)]
    pub version: Version,
}
fn certs(pem: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    if pem.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let certs = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| invalid())?;
    if certs.is_empty() {
        return Err(invalid());
    }
    Ok(certs)
}
fn key(pem: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    if pem.len() > 1024 * 1024 {
        return Err(invalid());
    }
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .map_err(|_| invalid())?
        .ok_or_else(invalid)
}
fn roots(pem: &str) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs(pem)? {
        roots.add(cert).map_err(|_| invalid())?;
    }
    Ok(roots)
}
pub(crate) fn client_tls(
    tls: ClientTls,
    transport: Transport,
) -> Result<(Arc<rustls::ClientConfig>, String)> {
    rustls::pki_types::ServerName::try_from(tls.server_name.clone()).map_err(|_| invalid())?;
    let trust = match tls.ca_pem {
        Some(pem) => roots(&pem)?,
        None => rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    };
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&versions(tls.version, transport)?)
    .map_err(|_| invalid())?
    .with_root_certificates(trust);
    let mut config = match (tls.certificate_pem, tls.private_key_pem) {
        (None, None) => builder.with_no_client_auth(),
        (Some(c), Some(k)) => builder
            .with_client_auth_cert(certs(&c)?, key(&k)?)
            .map_err(|_| invalid())?,
        _ => return Err(invalid()),
    };
    config.alpn_protocols = transport.alpn();
    config.enable_early_data = false;
    Ok((Arc::new(config), tls.server_name))
}
fn pem(inline: Option<String>, file: Option<String>) -> Result<String> {
    match (inline, file) {
        (Some(v), None) if v.len() <= 1024 * 1024 => Ok(v),
        (None, Some(p)) => {
            if std::fs::metadata(&p).map_err(|_| invalid())?.len() > 1024 * 1024 {
                return Err(invalid());
            }
            std::fs::read_to_string(p).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
pub(crate) fn server_tls(
    tls: ServerTls,
    transport: Transport,
) -> Result<Arc<rustls::ServerConfig>> {
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&versions(tls.version, transport)?)
    .map_err(|_| invalid())?;
    let builder = if let Some(ca) = tls.client_ca_pem {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots(&ca)?),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|_| invalid())?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(
            certs(&pem(tls.certificate_pem, tls.certificate_file)?)?,
            key(&pem(tls.private_key_pem, tls.private_key_file)?)?,
        )
        .map_err(|_| invalid())?;
    config.alpn_protocols = transport.alpn();
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_is_actual_authentication_and_password_is_extra_isolation() {
        let a = Auth {
            username: "alice".into(),
            password: "s:ecret".into(),
        };
        a.validate().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert("proxy-authorization", a.header().parse().unwrap());
        assert!(authenticate(&h, &[a.hash()]));
        h.append("proxy-authorization", a.header().parse().unwrap());
        assert!(!authenticate(&h, &[a.hash()]));
        let b = Auth {
            username: "bob".into(),
            password: a.password.clone(),
        };
        assert_ne!(a.hash(), b.hash());
        assert_eq!(a.isolation().fingerprint, b.isolation().fingerprint);
        for (u, p) in [("", "p"), ("a:b", "p"), ("a", ""), ("a", "\np")] {
            assert!(
                Auth {
                    username: u.into(),
                    password: p.into()
                }
                .validate()
                .is_err()
            );
        }
    }
    #[test]
    fn versions_and_limits_reject_unimplemented_options() {
        assert!(versions(Version::Tls12, Transport::H3).is_err());
        let limits = Limits {
            max_udp_flows: 0,
            ..Limits::default()
        };
        assert!(limits.validate().is_err());
    }
}
