use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub username: String,
    pub password: String,
}
impl Auth {
    pub fn validate(&self) -> Result<()> {
        if self.username.is_empty()
            || self.username.contains(':')
            || self
                .username
                .chars()
                .chain(self.password.chars())
                .any(char::is_control)
            || self.password.is_empty()
            || self.username.len() + self.password.len() > 1024
        {
            return Err(Error::Config("HTTP 代理认证字段不合法".into()));
        }
        Ok(())
    }
    pub fn header(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.username, self.password))
        )
    }
    pub fn matches(&self, value: &str) -> bool {
        let Some((scheme, encoded)) = value.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("Basic") {
            return false;
        }
        let Ok(decoded) = STANDARD.decode(encoded) else {
            return false;
        };
        let expected = format!("{}:{}", self.username, self.password);
        let mut difference = decoded.len() ^ expected.len();
        for index in 0..decoded.len().max(expected.len()) {
            difference |= usize::from(
                decoded.get(index).copied().unwrap_or(0)
                    ^ expected.as_bytes().get(index).copied().unwrap_or(0),
            );
        }
        difference == 0
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kerlico/http\0");
        hash.update(self.header());
        hash.finalize().into()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTls {
    pub server_name: String,
    pub ca_pem: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn server_tls(options: ServerTls) -> Result<tokio_rustls::TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(options.cert_pem))
        .collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(options.key_pem))?
        .ok_or_else(|| Error::Config("HTTP TLS 私钥缺失".into()))?;
    let mut config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error::Config("HTTP TLS 版本不可用".into()))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| Error::Config("HTTP TLS 证书或私钥不合法".into()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
}

pub fn invalid() -> Error {
    Error::Protocol("HTTP 代理报文格式或状态不合法")
}
