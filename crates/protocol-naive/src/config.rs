//! 配置准备只构造对象；凭据、会话及协商状态不跨实例共享。
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{Error, Result, ScopedCredentialFingerprint};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Arc, time::Duration};
use zeroize::Zeroizing;
pub(crate) const HEADER_LIMIT: usize = 16_384;
pub(crate) const BUFFER: usize = 16_384;
pub(crate) fn invalid() -> Error {
    Error::Config("Naive 配置不合法".into())
}
pub(crate) fn malformed() -> Error {
    Error::Protocol("Naive 报文格式、认证或协商不合法")
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Transport {
    H1,
    H2,
    H3,
}
fn h2() -> Transport {
    Transport::H2
}
fn session_limit() -> usize {
    4
}
fn stream_limit() -> usize {
    128
}
fn idle() -> u64 {
    60_000
}
fn congestion() -> String {
    "cubic".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: kerlico_config::TargetSpec,
    pub username: String,
    pub password: String,
    pub tls: ClientTls,
    #[serde(default = "h2")]
    pub transport: Transport,
    #[serde(default)]
    pub udp_over_tcp: UotOptions,
    #[serde(default = "session_limit")]
    pub max_sessions: usize,
    #[serde(default = "stream_limit")]
    pub max_streams: usize,
    #[serde(default = "idle")]
    pub idle_session_timeout_ms: u64,
    #[serde(default = "congestion")]
    pub congestion_control: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerOptions {
    pub users: Vec<UserOptions>,
    pub tls: ServerTls,
    #[serde(default = "transports")]
    pub transports: Vec<Transport>,
    #[serde(default)]
    pub udp_over_tcp: bool,
    #[serde(default = "congestion")]
    pub congestion_control: String,
}
fn transports() -> Vec<Transport> {
    vec![Transport::H1, Transport::H2, Transport::H3]
}
#[derive(Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct UotOptions {
    pub enabled: bool,
    pub version: u8,
}
impl Default for UotOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            version: 2,
        }
    }
}
impl UotOptions {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.version, 1 | 2) {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientTls {
    pub server_name: String,
    pub ca_pem: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerTls {
    pub certificate_pem: Option<String>,
    pub certificate_file: Option<String>,
    pub private_key_pem: Option<String>,
    pub private_key_file: Option<String>,
}
impl ServerTls {
    pub fn materials(self) -> Result<(String, Zeroizing<String>)> {
        fn material(inline: Option<String>, file: Option<String>) -> Result<String> {
            match (inline, file) {
                (Some(s), None) if !s.is_empty() => Ok(s),
                (None, Some(p)) if !p.is_empty() => Ok(std::fs::read_to_string(p)?),
                _ => Err(invalid()),
            }
        }
        Ok((
            material(self.certificate_pem, self.certificate_file)?,
            Zeroizing::new(material(self.private_key_pem, self.private_key_file)?),
        ))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserOptions {
    pub username: String,
    pub password: String,
}
pub(crate) struct User {
    authorization: Zeroizing<String>,
}
impl User {
    pub fn new(username: String, password: String) -> Result<Self> {
        let password = Zeroizing::new(password);
        if username.is_empty()
            || password.is_empty()
            || username.contains(':')
            || username.len() + password.len() > 1024
            || username
                .chars()
                .chain(password.chars())
                .any(char::is_control)
        {
            return Err(invalid());
        }
        let pair = Zeroizing::new(format!("{username}:{}", password.as_str()));
        Ok(Self {
            authorization: Zeroizing::new(format!("Basic {}", STANDARD.encode(pair.as_bytes()))),
        })
    }
    pub fn authorization(&self) -> &str {
        &self.authorization
    }
    pub fn matches(&self, value: &str) -> bool {
        let Some((scheme, encoded)) = value.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("Basic") {
            return false;
        }
        let expected = self
            .authorization
            .strip_prefix("Basic ")
            .unwrap_or_default()
            .as_bytes();
        let actual = encoded.as_bytes();
        let mut difference = actual.len() ^ expected.len();
        for i in 0..actual.len().max(expected.len()) {
            difference |= usize::from(
                actual.get(i).copied().unwrap_or(0) ^ expected.get(i).copied().unwrap_or(0),
            );
        }
        difference == 0
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kerlico/http\0");
        hash.update(self.authorization());
        hash.finalize().into()
    }
}
pub(crate) fn credentials(users: &[Arc<User>]) -> Vec<ScopedCredentialFingerprint> {
    users
        .iter()
        .map(|user| ScopedCredentialFingerprint {
            protocol: "http".into(),
            fingerprint: user.fingerprint(),
        })
        .collect()
}
pub(crate) fn users(options: Vec<UserOptions>) -> Result<Vec<Arc<User>>> {
    if options.is_empty() || options.len() > 256 {
        return Err(invalid());
    }
    let mut seen = HashSet::new();
    let mut names = HashSet::new();
    options
        .into_iter()
        .map(|u| {
            if !names.insert(u.username.clone()) {
                return Err(invalid());
            }
            let user = Arc::new(User::new(u.username, u.password)?);
            if !seen.insert(user.fingerprint()) {
                return Err(invalid());
            }
            Ok(user)
        })
        .collect()
}
pub(crate) fn limits(sessions: usize, streams: usize, idle_ms: u64) -> Result<Duration> {
    if !(1..=128).contains(&sessions)
        || !(1..=1024).contains(&streams)
        || !(100..=86_400_000).contains(&idle_ms)
    {
        return Err(invalid());
    }
    Ok(Duration::from_millis(idle_ms))
}
