//! 配置不监听或拨号；拒绝未实现的载体、控制器和安全开关。
use crate::invalid;
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::Result;
use serde::Deserialize;
use std::{io::Cursor, sync::Arc, time::Duration};
#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Carrier {
    #[default]
    Udp,
    WechatVideo,
}
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Congestion {
    #[default]
    Cubic,
    Newreno,
    Bbr,
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub max_streams: usize,
    pub udp_queue_packets: usize,
    pub udp_queue_bytes: usize,
    pub idle_timeout_ms: u64,
    pub congestion_control: Congestion,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_streams: 64,
            udp_queue_packets: 32,
            udp_queue_bytes: 4 * 1024 * 1024,
            idle_timeout_ms: 30000,
            congestion_control: Congestion::Cubic,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=1024).contains(&self.max_streams)
            || !(1..=256).contains(&self.udp_queue_packets)
            || !(65536..=16 * 1024 * 1024).contains(&self.udp_queue_bytes)
            || !(100..=86400000).contains(&self.idle_timeout_ms)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn idle(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }
    pub fn transport(&self, incoming: usize, udp: bool) -> Result<Arc<quinn::TransportConfig>> {
        let mut config = quinn::TransportConfig::default();
        config.max_concurrent_bidi_streams((incoming.min(65535) as u32).into());
        config.max_concurrent_uni_streams(0u32.into());
        config.stream_receive_window((256 * 1024u32).into());
        config.receive_window((2 * 1024 * 1024u32).into());
        config.send_window(2 * 1024 * 1024);
        config.datagram_receive_buffer_size(if udp { Some(256 * 1024) } else { None });
        config.datagram_send_buffer_size(256 * 1024);
        config.advertised_datagram_frame_size(if udp { Some(1200) } else { None });
        config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(self.idle()).map_err(|_| invalid())?,
        ));
        config.keep_alive_interval(Some(
            (self.idle() / 3)
                .min(Duration::from_secs(10))
                .max(Duration::from_millis(20)),
        ));
        config.initial_mtu(1200);
        config.min_mtu(1200);
        config.mtu_discovery_config(None);
        config.congestion_controller_factory(Arc::new(crate::congestion::Factory::new(
            self.congestion_control,
        )));
        Ok(Arc::new(config))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: kerlico_config::TargetSpec,
    #[serde(default)]
    pub auth_str: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    pub up_bps: u64,
    pub down_bps: u64,
    pub tls: ClientTls,
    #[serde(default)]
    pub transport: Carrier,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default = "yes")]
    pub udp: bool,
    #[serde(default)]
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeOptions {
    #[serde(default)]
    pub auth_str: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub users: Vec<Auth>,
    #[serde(default)]
    pub up_bps: u64,
    #[serde(default)]
    pub down_bps: u64,
    pub tls: ServerTls,
    #[serde(default)]
    pub transport: Carrier,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default = "yes")]
    pub udp: bool,
    #[serde(default)]
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Auth {
    #[serde(default)]
    pub auth_str: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
}
fn yes() -> bool {
    true
}
fn alpn() -> Vec<String> {
    vec!["hysteria".into()]
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
pub(crate) fn auth(text: Option<String>, encoded: Option<String>) -> Result<Vec<u8>> {
    let bytes = match (text, encoded) {
        (Some(text), None) => text.into_bytes(),
        (None, Some(encoded)) => STANDARD.decode(encoded).map_err(|_| invalid())?,
        _ => return Err(invalid()),
    };
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(invalid());
    }
    Ok(bytes)
}
pub(crate) fn obfs(value: Option<String>) -> Result<Option<Arc<[u8]>>> {
    match value {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) if value.len() <= 4096 => Ok(Some(Arc::from(value.into_bytes()))),
        _ => Err(invalid()),
    }
}
pub(crate) fn rate(value: u64, server: bool) -> Result<()> {
    if (server && value == 0) || (16384..=1_000_000_000_000).contains(&value) {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn alpns(values: &[String]) -> Result<Vec<Vec<u8>>> {
    if values.is_empty()
        || values.len() > 16
        || values.iter().any(|v| v.is_empty() || v.len() > 255)
    {
        return Err(invalid());
    }
    Ok(values.iter().map(|v| v.as_bytes().to_vec()).collect())
}
pub(crate) fn client_tls(
    options: ClientTls,
    transport: Arc<quinn::TransportConfig>,
) -> Result<(quinn::ClientConfig, String)> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = options.ca_pem {
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
    tls.alpn_protocols = alpns(&options.alpn)?;
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
    let certificate = pem(options.certificate_pem, options.certificate_file)?;
    let private = pem(options.private_key_pem, options.private_key_file)?;
    let certs = rustls_pemfile::certs(&mut Cursor::new(certificate))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| invalid())?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(private))
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
    tls.alpn_protocols = alpns(&options.alpn)?;
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    Ok(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| invalid())?,
    ))
}
