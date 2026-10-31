//! 配置只校验与构造；载体上游解析留在节点运行预算内完成。
use crate::codec::Mode;
use kerlico_core::{Error, Result};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;
pub(crate) const V1: u32 = 1;
pub(crate) const V2: u32 = 0x6b3343cf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: kerlico_config::TargetSpec,
    pub username: String,
    pub password: String,
    pub server_name: String,
    #[serde(default = "alpn")]
    pub alpn: Vec<String>,
    #[serde(default = "v1")]
    pub quic_version: String,
    #[serde(default = "datagram")]
    pub udp_mode: String,
    #[serde(default = "cubic")]
    pub congestion_control: String,
    #[serde(default = "idle")]
    pub idle_timeout_secs: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerOptions {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub users: Vec<UserOptions>,
    pub upstream: kerlico_config::TargetSpec,
    pub server_name: String,
    #[serde(default = "alpn")]
    pub alpn: Vec<String>,
    #[serde(default = "versions")]
    pub quic_versions: Vec<String>,
    #[serde(default = "cubic")]
    pub congestion_control: String,
    #[serde(default = "rate")]
    pub upstream_rate_bps: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserOptions {
    pub username: String,
    pub password: String,
}
fn alpn() -> Vec<String> {
    vec!["h3".into()]
}
fn v1() -> String {
    "v1".into()
}
fn versions() -> Vec<String> {
    vec!["v1".into(), "v2".into()]
}
fn datagram() -> String {
    "datagram".into()
}
fn cubic() -> String {
    "cubic".into()
}
fn idle() -> u64 {
    60
}
fn rate() -> u64 {
    16_000_000
}
pub(crate) fn invalid() -> Error {
    Error::Config("ShadowQUIC 配置不合法".into())
}
pub(crate) struct User {
    pub username: String,
    pub password: Zeroizing<String>,
}
impl User {
    pub fn parse(username: String, password: String) -> Result<Self> {
        if username.is_empty()
            || username.len() > 256
            || password.is_empty()
            || password.len() > 4096
        {
            return Err(invalid());
        }
        Ok(Self {
            username,
            password: Zeroizing::new(password),
        })
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.username.as_bytes()).into()
    }
}
pub(crate) fn version(value: &str) -> Result<u32> {
    match value {
        "v1" => Ok(V1),
        "v2" => Ok(V2),
        _ => Err(invalid()),
    }
}
pub(crate) fn mode(value: &str) -> Result<Mode> {
    Mode::parse(value)
}
pub(crate) fn validate_name(value: &str) -> Result<()> {
    match rustls_jls::pki_types::ServerName::try_from(value.to_owned()).map_err(|_| invalid())? {
        rustls_jls::pki_types::ServerName::DnsName(_) => Ok(()),
        _ => Err(Error::Config(
            "ShadowQUIC server_name 必须是发送 SNI 的 DNS 名称".into(),
        )),
    }
}
pub(crate) fn alpn_bytes(values: Vec<String>) -> Result<Vec<Vec<u8>>> {
    if values.is_empty()
        || values.len() > 16
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > 255)
    {
        return Err(invalid());
    }
    Ok(values.into_iter().map(String::into_bytes).collect())
}
pub(crate) fn transport(
    congestion: &str,
    idle: Duration,
    bidi: usize,
    keep_alive: bool,
) -> Result<Arc<jls_quinn::TransportConfig>> {
    let mut value = jls_quinn::TransportConfig::default();
    value.max_concurrent_bidi_streams((bidi.min(65536) as u32).into());
    value.max_concurrent_uni_streams(128u32.into());
    value.crypto_buffer_size(16 * 1024);
    value.stream_receive_window(65536u32.into());
    value.receive_window((2 * 1024 * 1024u32).into());
    value.send_window(2 * 1024 * 1024);
    value.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    value.datagram_send_buffer_size(2 * 1024 * 1024);
    value.max_idle_timeout(Some(
        jls_quinn::IdleTimeout::try_from(idle).map_err(|_| invalid())?,
    ));
    value.keep_alive_interval(keep_alive.then_some(Duration::from_secs(5)));
    match congestion {
        "cubic" => {
            value.congestion_controller_factory(Arc::new(
                jls_quinn::congestion::CubicConfig::default(),
            ));
        }
        "newreno" => {
            value.congestion_controller_factory(Arc::new(
                jls_quinn::congestion::NewRenoConfig::default(),
            ));
        }
        "bbr" => {
            value.congestion_controller_factory(Arc::new(
                jls_quinn::congestion::BbrConfig::default(),
            ));
        }
        _ => return Err(invalid()),
    };
    Ok(Arc::new(value))
}
pub(crate) fn endpoint(versions: Vec<u32>) -> Result<jls_quinn::EndpointConfig> {
    let mut config = jls_quinn::EndpointConfig::default();
    config.supported_versions(versions);
    config.max_udp_payload_size(1500).map_err(|_| invalid())?;
    Ok(config)
}
pub(crate) fn client_crypto(
    user: &User,
    alpn: Vec<Vec<u8>>,
    transport: Arc<jls_quinn::TransportConfig>,
    version: u32,
) -> Result<jls_quinn::ClientConfig> {
    let roots =
        rustls_jls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls_jls::ClientConfig::builder_with_provider(Arc::new(
        rustls_jls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls_jls::version::TLS13])
    .map_err(|_| invalid())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = alpn;
    tls.enable_early_data = false;
    tls.resumption = rustls_jls::client::Resumption::disabled();
    tls.jls_config = rustls_jls::jls::JlsClientConfig::new(&user.password, &user.username);
    let mut config = jls_quinn::ClientConfig::new(Arc::new(
        jls_quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| invalid())?,
    ));
    config.transport_config(transport);
    config.version(version);
    Ok(config)
}
pub(crate) fn server_crypto(
    users: &[User],
    name: &str,
    alpn: Vec<Vec<u8>>,
    upstream: std::net::SocketAddr,
    rate: u64,
) -> Result<Arc<dyn jls_quinn::crypto::ServerConfig>> {
    let certificate =
        rcgen::generate_simple_self_signed(vec![name.to_owned()]).map_err(|_| invalid())?;
    let key =
        rustls_jls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let cert = rustls_jls::pki_types::CertificateDer::from(certificate.cert.der().to_vec());
    let mut tls = rustls_jls::ServerConfig::builder_with_provider(Arc::new(
        rustls_jls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls_jls::version::TLS13])
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key.into())
    .map_err(|_| invalid())?;
    tls.alpn_protocols = alpn;
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls_jls::server::NoServerSessionStorage {});
    let mut jls = rustls_jls::jls::JlsServerConfig::default();
    for user in users {
        jls = jls.add_user(user.password.to_string(), user.username.clone());
    }
    tls.jls_config = jls
        .with_upstream_addr(upstream.to_string())
        .with_server_name(name.to_owned())
        .with_rate_limit(rate)
        .enable(true)
        .into();
    Ok(Arc::new(
        jls_quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| invalid())?,
    ))
}
