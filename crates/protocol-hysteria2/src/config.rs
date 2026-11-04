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
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum PortHopSpec {
    Text(String),
    List(Vec<String>),
}
impl PortHopSpec {
    pub fn parse(&self) -> Result<Vec<std::ops::RangeInclusive<u16>>> {
        let mut ranges = Vec::new();
        let items: Vec<&str> = match self {
            Self::Text(text) => text.split(',').collect(),
            Self::List(list) => list.iter().flat_map(|item| item.split(',')).collect(),
        };
        for raw in items {
            let raw = raw.trim();
            if raw.is_empty() {
                return Err(invalid());
            }
            if let Some((start, end)) = raw.split_once(['-', ':']) {
                let start = start.trim().parse::<u16>().map_err(|_| invalid())?;
                let end = end.trim().parse::<u16>().map_err(|_| invalid())?;
                if start == 0 || start > end {
                    return Err(invalid());
                }
                ranges.push(start..=end);
            } else {
                let port = raw.parse::<u16>().map_err(|_| invalid())?;
                if port == 0 {
                    return Err(invalid());
                }
                ranges.push(port..=port);
            }
        }
        if ranges.is_empty() || ranges.len() > 64 {
            return Err(invalid());
        }
        Ok(ranges)
    }
}
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum BandwidthSpec {
    Mbps(u64),
    Text(String),
}
impl BandwidthSpec {
    pub fn to_bps(&self) -> Result<u64> {
        match self {
            Self::Mbps(mbps) => mbps.checked_mul(125_000).ok_or_else(invalid),
            Self::Text(text) => {
                let text = text.trim().to_ascii_lowercase();
                if text.is_empty() {
                    return Err(invalid());
                }
                let split = text
                    .find(|ch: char| !ch.is_ascii_digit())
                    .unwrap_or(text.len());
                let number: u64 = text[..split].trim().parse().map_err(|_| invalid())?;
                let unit = text[split..].trim();
                let multiplier = match unit {
                    "" | "mbps" | "m" => 125_000u64,
                    "bps" | "b" => 1u64,
                    "kbps" | "k" => 125u64,
                    "gbps" | "g" => 125_000_000u64,
                    _ => return Err(invalid()),
                };
                number.checked_mul(multiplier).ok_or_else(invalid)
            }
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum HopIntervalSpec {
    Secs(u64),
    Text(String),
}
impl HopIntervalSpec {
    pub fn to_duration(&self) -> Result<Duration> {
        match self {
            Self::Secs(secs) => {
                if !(5..=86_400).contains(secs) {
                    return Err(invalid());
                }
                Ok(Duration::from_secs(*secs))
            }
            Self::Text(text) => {
                let text = text.trim();
                if let Some(ms_str) = text.strip_suffix("ms") {
                    let ms = ms_str.trim().parse::<u64>().map_err(|_| invalid())?;
                    if !(10..=86_400_000).contains(&ms) {
                        return Err(invalid());
                    }
                    return Ok(Duration::from_millis(ms));
                }
                let digits = text.strip_suffix('s').unwrap_or(text).trim();
                let secs = digits.parse::<u64>().map_err(|_| invalid())?;
                if !(5..=86_400).contains(&secs) {
                    return Err(invalid());
                }
                Ok(Duration::from_secs(secs))
            }
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum MasqueradeSpec {
    Url(String),
    Object(MasqueradeObject),
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MasqueradeObject {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub content: Option<String>,
    pub directory: Option<String>,
    pub url: Option<String>,
    #[serde(alias = "rewrite-host")]
    pub rewrite_host: bool,
    pub insecure: bool,
    #[serde(alias = "status-code")]
    pub status_code: Option<u16>,
    pub headers: std::collections::BTreeMap<String, String>,
}
#[derive(Clone)]
pub(crate) enum MasqueradePlan {
    Default404,
    String {
        status_code: http::StatusCode,
        headers: Vec<(http::HeaderName, http::HeaderValue)>,
        content: bytes::Bytes,
    },
    File {
        directory: std::path::PathBuf,
        headers: Vec<(http::HeaderName, http::HeaderValue)>,
    },
    Proxy {
        url: String,
        rewrite_host: bool,
        headers: Vec<(http::HeaderName, http::HeaderValue)>,
    },
}
fn compile_headers(
    raw: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<(http::HeaderName, http::HeaderValue)>> {
    let mut out = Vec::with_capacity(raw.len());
    for (k, v) in raw {
        let name = http::HeaderName::from_bytes(k.trim().as_bytes()).map_err(|_| invalid())?;
        let val = http::HeaderValue::from_str(v).map_err(|_| invalid())?;
        out.push((name, val));
    }
    Ok(out)
}
impl NodeOptions {
    pub(crate) fn masquerade_plan(&self) -> Result<MasqueradePlan> {
        let obj = match &self.masquerade {
            Some(MasqueradeSpec::Url(url)) => {
                if let Some(dir) = url.strip_prefix("file://") {
                    MasqueradeObject {
                        kind: Some("file".into()),
                        directory: Some(dir.into()),
                        ..Default::default()
                    }
                } else if url.starts_with("http://") || url.starts_with("https://") {
                    MasqueradeObject {
                        kind: Some("proxy".into()),
                        url: Some(url.clone()),
                        ..Default::default()
                    }
                } else {
                    return Err(invalid());
                }
            }
            Some(MasqueradeSpec::Object(obj)) => obj.clone(),
            None => MasqueradeObject {
                kind: self.masquerade_type.clone(),
                content: self.masquerade_content.clone(),
                directory: self.masquerade_directory.clone(),
                url: self.masquerade_url.clone(),
                rewrite_host: self.masquerade_rewrite_host.unwrap_or(false),
                status_code: self.masquerade_status_code,
                headers: self.masquerade_headers.clone().unwrap_or_default(),
                insecure: false,
            },
        };
        let headers = compile_headers(&obj.headers)?;
        let kind = obj.kind.as_deref().unwrap_or({
            if obj.content.is_some() || obj.status_code.is_some() {
                "string"
            } else if obj.directory.is_some() {
                "file"
            } else if obj.url.is_some() {
                "proxy"
            } else {
                ""
            }
        });
        match kind {
            "" => Ok(MasqueradePlan::Default404),
            "string" => {
                let code = http::StatusCode::from_u16(obj.status_code.unwrap_or(200))
                    .map_err(|_| invalid())?;
                let content = bytes::Bytes::from(obj.content.unwrap_or_default());
                Ok(MasqueradePlan::String {
                    status_code: code,
                    headers,
                    content,
                })
            }
            "file" => {
                let dir = obj.directory.ok_or_else(invalid)?;
                if dir.trim().is_empty() {
                    return Err(invalid());
                }
                Ok(MasqueradePlan::File {
                    directory: std::path::PathBuf::from(dir),
                    headers,
                })
            }
            "proxy" => {
                let url = obj.url.ok_or_else(invalid)?;
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(invalid());
                }
                Ok(MasqueradePlan::Proxy {
                    url,
                    rewrite_host: obj.rewrite_host,
                    headers,
                })
            }
            _ => Err(invalid()),
        }
    }
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct UdpHopFinalmaskSpec {
    #[serde(alias = "remote-ports", alias = "ports")]
    pub remote_ports: Option<PortHopSpec>,
    #[serde(alias = "remote-ips", alias = "ips")]
    pub remote_ips: Vec<std::net::IpAddr>,
    pub interval: Option<HopIntervalSpec>,
    #[serde(alias = "interval-max")]
    pub interval_max: Option<HopIntervalSpec>,
    pub mode: Option<String>,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct QuicFinalmaskSpec {
    #[serde(alias = "brutal-down")]
    pub brutal_down: Option<BandwidthSpec>,
    #[serde(alias = "brutal-up")]
    pub brutal_up: Option<BandwidthSpec>,
    #[serde(alias = "udp-hop", alias = "udp-udphop")]
    pub udp_hop: Option<UdpHopFinalmaskSpec>,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Hysteria2FinalmaskSpec {
    #[serde(alias = "brutal-down")]
    pub brutal_down: Option<BandwidthSpec>,
    #[serde(alias = "brutal-up")]
    pub brutal_up: Option<BandwidthSpec>,
    #[serde(alias = "udp-hop", alias = "udp-udphop")]
    pub udp_hop: Option<UdpHopFinalmaskSpec>,
    pub quic: Option<QuicFinalmaskSpec>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: Server,
    #[serde(
        default,
        alias = "server_ports",
        alias = "server-ports",
        alias = "mport"
    )]
    pub ports: Option<PortHopSpec>,
    #[serde(default, alias = "hop-interval")]
    pub hop_interval: Option<HopIntervalSpec>,
    #[serde(default, alias = "hop-interval-ms")]
    pub hop_interval_ms: Option<u64>,
    #[serde(default, alias = "hop-interval-max")]
    pub hop_interval_max: Option<HopIntervalSpec>,
    #[serde(default, alias = "up_mbps", alias = "up-mbps")]
    pub up: Option<BandwidthSpec>,
    #[serde(default, alias = "down_mbps", alias = "down-mbps")]
    pub down: Option<BandwidthSpec>,
    pub auth: String,
    pub tls: ClientTls,
    #[serde(default)]
    pub salamander_password: Option<String>,
    #[serde(default)]
    pub finalmask: Option<Hysteria2FinalmaskSpec>,
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
    pub tls: ServerTls,
    #[serde(default)]
    pub salamander_password: Option<String>,
    #[serde(default = "yes")]
    pub udp: bool,
    #[serde(default, alias = "up_mbps", alias = "up-mbps")]
    pub up: Option<BandwidthSpec>,
    #[serde(default, alias = "down_mbps", alias = "down-mbps")]
    pub down: Option<BandwidthSpec>,
    #[serde(default)]
    pub masquerade: Option<MasqueradeSpec>,
    #[serde(default, alias = "masquerade-type")]
    pub masquerade_type: Option<String>,
    #[serde(default, alias = "masquerade-content")]
    pub masquerade_content: Option<String>,
    #[serde(default, alias = "masquerade-directory")]
    pub masquerade_directory: Option<String>,
    #[serde(default, alias = "masquerade-url")]
    pub masquerade_url: Option<String>,
    #[serde(default, alias = "masquerade-rewrite-host")]
    pub masquerade_rewrite_host: Option<bool>,
    #[serde(default, alias = "masquerade-status-code")]
    pub masquerade_status_code: Option<u16>,
    #[serde(default, alias = "masquerade-headers")]
    pub masquerade_headers: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub multiplex: Option<kerlico_net::sing_mux::SingMuxInboundConfig>,
    #[serde(default, alias = "mux-option-padding")]
    pub mux_option_padding: Option<bool>,
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
    tls.resumption = rustls::client::Resumption::disabled();
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Auth {
    pub auth: String,
}
