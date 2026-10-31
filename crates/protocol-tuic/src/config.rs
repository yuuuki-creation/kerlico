//! TUIC 角色配置只构造本地对象；不在配置检查阶段监听或拨号。
use crate::codec::{Mode, malformed};
use kerlico_core::{Error, Result};
use serde::Deserialize;
use std::{io::Cursor, sync::Arc, time::Duration};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: kerlico_config::TargetSpec,
    #[serde(default = "version")]
    pub version: u8,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    pub tls: ClientTls,
    #[serde(default = "native")]
    pub udp_relay_mode: String,
    #[serde(default = "cubic")]
    pub congestion_control: String,
    #[serde(default = "idle")]
    pub idle_timeout_secs: u64,
    #[serde(default = "heartbeat")]
    pub heartbeat_interval_secs: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerOptions {
    #[serde(default = "version")]
    pub version: u8,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub tokens: Vec<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub users: Vec<UserOptions>,
    pub tls: ServerTls,
    #[serde(default = "cubic")]
    pub congestion_control: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserOptions {
    pub uuid: String,
    pub password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientTls {
    pub server_name: String,
    #[serde(default)]
    pub ca_pem: Option<String>,
    #[serde(default = "alpn")]
    pub alpn: Vec<String>,
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
    #[serde(default = "alpn")]
    pub alpn: Vec<String>,
}
fn version() -> u8 {
    5
}
fn native() -> String {
    "native".into()
}
fn cubic() -> String {
    "cubic".into()
}
fn idle() -> u64 {
    60
}
fn heartbeat() -> u64 {
    10
}
fn alpn() -> Vec<String> {
    vec!["h3".into()]
}
pub(crate) fn invalid() -> Error {
    Error::Config("TUIC 配置不合法".into())
}
pub(crate) enum Credential {
    V4([u8; 32]),
    V5 {
        uuid: [u8; 16],
        password: Zeroizing<String>,
    },
}
impl Credential {
    pub fn parse(
        version: u8,
        token: Option<String>,
        uuid: Option<String>,
        password: Option<String>,
    ) -> Result<Self> {
        match (version, token, uuid, password) {
            (4, Some(token), None, None) if !token.is_empty() && token.len() <= 4096 => {
                Ok(Self::V4(*blake3::hash(token.as_bytes()).as_bytes()))
            }
            (5, None, Some(uuid), Some(password)) if password.len() <= 4096 => Ok(Self::V5 {
                uuid: *uuid::Uuid::parse_str(&uuid)
                    .map_err(|_| invalid())?
                    .as_bytes(),
                password: Zeroizing::new(password),
            }),
            _ => Err(invalid()),
        }
    }
    pub fn version(&self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V5 { .. } => 5,
        }
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        match self {
            Self::V4(token) => Sha256::digest(token).into(),
            Self::V5 { uuid, .. } => Sha256::digest(uuid).into(),
        }
    }
    pub fn authentication(&self, connection: &quinn::Connection) -> Result<Vec<u8>> {
        let mut out = vec![self.version(), 0];
        match self {
            Self::V4(token) => out.extend(token),
            Self::V5 { uuid, password } => {
                let mut token = Zeroizing::new([0; 32]);
                connection
                    .export_keying_material(&mut *token, uuid, password.as_bytes())
                    .map_err(|_| malformed())?;
                out.extend(uuid);
                out.extend_from_slice(&*token);
            }
        }
        Ok(out)
    }
    pub fn matches(&self, connection: &quinn::Connection, bytes: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        self.authentication(connection).is_ok_and(|expected| {
            expected.len() == bytes.len() && bool::from(expected.as_slice().ct_eq(bytes))
        })
    }
}
pub(crate) fn mode(value: &str) -> Result<Mode> {
    Mode::parse(value)
}
fn validate_alpn(values: &[String]) -> Result<Vec<Vec<u8>>> {
    if values.is_empty()
        || values.len() > 16
        || values.iter().any(|v| v.is_empty() || v.len() > 255)
    {
        return Err(invalid());
    }
    Ok(values.iter().map(|v| v.as_bytes().to_vec()).collect())
}
pub(crate) fn transport(
    congestion: &str,
    idle: Duration,
    heartbeat: Option<Duration>,
    streams: usize,
) -> Result<Arc<quinn::TransportConfig>> {
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_bidi_streams((streams.min(65536) as u32).into());
    config.max_concurrent_uni_streams((streams.min(65536) as u32).into());
    config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    config.datagram_send_buffer_size(4 * 1024 * 1024);
    config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(idle).map_err(|_| invalid())?,
    ));
    config.keep_alive_interval(heartbeat);
    match congestion {
        "cubic" => {
            config
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        "newreno" => {
            config.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        "bbr" => {
            config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        _ => return Err(invalid()),
    };
    Ok(Arc::new(config))
}
pub(crate) fn client_tls(
    options: ClientTls,
    transport: Arc<quinn::TransportConfig>,
) -> Result<(quinn::ClientConfig, String)> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = options.ca_pem {
        let certs =
            rustls_pemfile::certs(&mut Cursor::new(pem)).collect::<std::io::Result<Vec<_>>>()?;
        if certs.is_empty() {
            return Err(invalid());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| invalid())?;
        }
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| invalid())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = validate_alpn(&options.alpn)?;
    rustls::pki_types::ServerName::try_from(options.server_name.clone()).map_err(|_| invalid())?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| invalid())?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport);
    Ok((config, options.server_name))
}
pub(crate) fn server_tls(options: ServerTls) -> Result<Arc<dyn quinn::crypto::ServerConfig>> {
    fn pem(inline: Option<String>, file: Option<String>) -> Result<String> {
        match (inline, file) {
            (Some(value), None) if value.len() <= 1024 * 1024 => Ok(value),
            (None, Some(path)) => {
                if std::fs::metadata(&path).map_err(|_| invalid())?.len() > 1024 * 1024 {
                    return Err(invalid());
                }
                std::fs::read_to_string(path).map_err(|_| invalid())
            }
            _ => Err(invalid()),
        }
    }
    let cert = pem(options.certificate_pem, options.certificate_file)?;
    let key = pem(options.private_key_pem, options.private_key_file)?;
    let certs =
        rustls_pemfile::certs(&mut Cursor::new(cert)).collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key))?.ok_or_else(invalid)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| invalid())?;
    tls.alpn_protocols = validate_alpn(&options.alpn)?;
    tls.max_early_data_size = 0;
    Ok(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| invalid())?,
    ))
}
