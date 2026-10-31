use kerlico_core::{Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{io::Cursor, sync::Arc, time::Duration};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub max_streams: usize,
    pub udp_queue_packets: usize,
    pub udp_queue_bytes: usize,
    pub idle_timeout_ms: u64,
    pub congestion: String,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_streams: 64,
            udp_queue_packets: 16,
            udp_queue_bytes: 4 * 1024 * 1024,
            idle_timeout_ms: 30_000,
            congestion: "bbr".into(),
        }
    }
}
impl Limits {
    pub(crate) fn validate(&self) -> Result<()> {
        if !(1..=1024).contains(&self.max_streams)
            || !(1..=64).contains(&self.udp_queue_packets)
            || !(65536..=16 * 1024 * 1024).contains(&self.udp_queue_bytes)
            || !(100..=86_400_000).contains(&self.idle_timeout_ms)
            || !matches!(self.congestion.as_str(), "bbr" | "reno")
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn transport(
        &self,
        maximum: usize,
        obfs: bool,
    ) -> Result<Arc<quinn::TransportConfig>> {
        let mut value = quinn::TransportConfig::default();
        value.max_concurrent_bidi_streams((self.max_streams.min(maximum) as u32).into());
        value.max_concurrent_uni_streams(16u32.into());
        value.max_idle_timeout(Some(
            Duration::from_millis(self.idle_timeout_ms)
                .try_into()
                .map_err(|_| invalid())?,
        ));
        value.stream_receive_window((256 * 1024u32).into());
        value.receive_window((2 * 1024 * 1024u32).into());
        value.send_window(2 * 1024 * 1024);
        value.datagram_receive_buffer_size(Some(256 * 1024));
        value.datagram_send_buffer_size(256 * 1024);
        value.advertised_datagram_frame_size(Some(1200));
        if self.congestion == "bbr" {
            value.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        } else {
            value.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        if obfs {
            let mut mtu = quinn::MtuDiscoveryConfig::default();
            mtu.upper_bound(1444);
            value.mtu_discovery_config(Some(mtu));
        }
        Ok(Arc::new(value))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: Server,
    pub auth: String,
    pub tls: ClientTls,
    #[serde(default)]
    pub salamander_password: Option<String>,
    #[serde(default)]
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Server {
    pub host: String,
    pub port: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientTls {
    pub server_name: String,
    #[serde(default)]
    pub ca_pem: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeOptions {
    pub auth: String,
    pub tls: ServerTls,
    #[serde(default)]
    pub salamander_password: Option<String>,
    #[serde(default = "yes")]
    pub udp: bool,
    #[serde(default)]
    pub limits: Limits,
}
fn yes() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerTls {
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub certificate_file: Option<String>,
    pub private_key_file: Option<String>,
}
fn invalid() -> Error {
    Error::Config("Hysteria2 配置或 TLS 参数不合法".into())
}
pub(crate) fn auth(text: &str) -> Result<[u8; 32]> {
    if text.is_empty()
        || text.len() > 4096
        || text.trim() != text
        || http::HeaderValue::from_bytes(text.as_bytes()).is_err()
    {
        return Err(invalid());
    }
    Ok(Sha256::digest(text.as_bytes()).into())
}
pub(crate) fn obfs(text: Option<String>) -> Result<Option<Arc<String>>> {
    text.map(|text| {
        if (4..=4096).contains(&text.len()) {
            Ok(Arc::new(text))
        } else {
            Err(invalid())
        }
    })
    .transpose()
}
pub(crate) fn client_tls(options: &ClientTls) -> Result<Arc<rustls::ClientConfig>> {
    rustls::pki_types::ServerName::try_from(options.server_name.clone()).map_err(|_| invalid())?;
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = &options.ca_pem {
        if pem.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let certs = rustls_pemfile::certs(&mut Cursor::new(pem))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| invalid())?;
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
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    Ok(Arc::new(tls))
}
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
pub(crate) fn server_tls(options: ServerTls) -> Result<Arc<rustls::ServerConfig>> {
    let certs = pem(options.certificate_pem, options.certificate_file)?;
    let key = pem(options.private_key_pem, options.private_key_file)?;
    let certs = rustls_pemfile::certs(&mut Cursor::new(certs))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| invalid())?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key))
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| invalid())?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    Ok(Arc::new(tls))
}
