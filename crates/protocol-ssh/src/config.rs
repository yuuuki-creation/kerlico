use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use kerlico_config::TargetSpec;
use kerlico_core::{Destination, Error, Result};
use russh::{
    client,
    keys::{Algorithm, PrivateKey},
};
use serde::Deserialize;
use std::{borrow::Cow, io::Read, sync::Arc, time::Duration};

const MAX_KEY: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Options {
    server: TargetSpec,
    username: String,
    host_key_sha256: Vec<String>,
    auth: AuthOptions,
    #[serde(default = "keepalive_interval")]
    keepalive_interval_ms: u64,
    #[serde(default = "keepalive_max")]
    keepalive_max: usize,
}
fn keepalive_interval() -> u64 {
    30_000
}
fn keepalive_max() -> usize {
    3
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum AuthOptions {
    #[serde(rename = "password")]
    Password { password: String },
    #[serde(rename = "publickey")]
    PublicKey {
        private_key_pem: Option<String>,
        private_key_file: Option<String>,
        passphrase: Option<String>,
    },
}

pub(crate) enum Authentication {
    Password(String),
    Key(Arc<PrivateKey>),
}
pub(crate) struct Prepared {
    pub server: Destination,
    pub username: String,
    pub pins: Arc<Vec<String>>,
    pub auth: Authentication,
    pub ssh: Arc<client::Config>,
}

fn invalid() -> Error {
    Error::Config("SSH 选项或凭据不合法".into())
}

fn key_material(pem: Option<String>, path: Option<String>) -> Result<String> {
    match (pem, path) {
        (Some(pem), None) if !pem.is_empty() && pem.len() <= MAX_KEY => Ok(pem),
        (None, Some(path)) => {
            let preliminary = std::fs::metadata(&path)
                .map_err(|_| Error::Config("SSH 私钥文件无法读取".into()))?;
            if !preliminary.is_file() {
                return Err(invalid());
            }
            let file = std::fs::File::open(path)
                .map_err(|_| Error::Config("SSH 私钥文件无法读取".into()))?;
            let metadata = file.metadata().map_err(|_| invalid())?;
            if !metadata.is_file() || metadata.len() > MAX_KEY as u64 {
                return Err(invalid());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(Error::Config("SSH 私钥文件不能允许组或其他用户访问".into()));
                }
            }
            let mut value = String::new();
            file.take(MAX_KEY as u64 + 1)
                .read_to_string(&mut value)
                .map_err(|_| invalid())?;
            if value.is_empty() || value.len() > MAX_KEY {
                return Err(invalid());
            }
            Ok(value)
        }
        _ => Err(Error::Config("SSH 私钥必须明确选择内存 PEM 或文件".into())),
    }
}

impl Options {
    pub fn prepare(self) -> Result<Prepared> {
        if self.username.trim().is_empty()
            || self.username.len() > 255
            || self.username.chars().any(char::is_control)
            || !(1..=16).contains(&self.host_key_sha256.len())
            || !(1000..=3_600_000).contains(&self.keepalive_interval_ms)
            || !(1..=8).contains(&self.keepalive_max)
        {
            return Err(invalid());
        }
        let mut pins = std::collections::BTreeSet::new();
        for pin in &self.host_key_sha256 {
            let raw = pin.strip_prefix("SHA256:").ok_or_else(invalid)?;
            if STANDARD_NO_PAD.decode(raw).map_err(|_| invalid())?.len() != 32
                || !pins.insert(pin.clone())
            {
                return Err(invalid());
            }
        }
        let auth = match self.auth {
            AuthOptions::Password { password } => {
                if password.is_empty() || password.len() > 4096 {
                    return Err(invalid());
                }
                Authentication::Password(password)
            }
            AuthOptions::PublicKey {
                private_key_pem,
                private_key_file,
                passphrase,
            } => {
                let pem = key_material(private_key_pem, private_key_file)?;
                let key = russh::keys::decode_secret_key(&pem, passphrase.as_deref())
                    .map_err(|_| Error::Config("SSH 私钥或解密口令不合法".into()))?;
                if !matches!(
                    key.algorithm(),
                    Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }
                ) {
                    return Err(Error::Config("SSH 私钥算法不在本轮支持范围".into()));
                }
                Authentication::Key(Arc::new(key))
            }
        };
        let mut preferred = russh::Preferred::default();
        preferred.key = Cow::Owned(
            preferred
                .key
                .iter()
                .filter(|algorithm| !matches!(algorithm, Algorithm::Rsa { hash: None }))
                .cloned()
                .collect(),
        );
        preferred.compression = Cow::Borrowed(&[russh::compression::NONE]);
        let ssh = client::Config {
            client_id: russh::SshId::Standard(Cow::Borrowed("SSH-2.0-kerlico")),
            window_size: 262_144,
            maximum_packet_size: 32_768,
            channel_buffer_size: 32,
            preferred,
            keepalive_interval: Some(Duration::from_millis(self.keepalive_interval_ms)),
            keepalive_max: self.keepalive_max,
            nodelay: true,
            ..Default::default()
        };
        Ok(Prepared {
            server: self.server.destination()?,
            username: self.username,
            pins: Arc::new(self.host_key_sha256),
            auth,
            ssh: Arc::new(ssh),
        })
    }
}
