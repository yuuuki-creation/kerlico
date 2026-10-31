//! 复合配置只允许具有内容认证与加密的既有内层。
use kerlico_core::{Destination, Error, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inner {
    #[serde(rename = "type")]
    pub kind: String,
    pub options: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Client {
    pub version: u8,
    pub password: Option<String>,
    pub strict: Option<bool>,
    pub tls: Tls,
    pub inner: Inner,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tls {
    pub server_name: String,
    pub ca_pem: Option<String>,
    #[serde(default = "alpn")]
    pub alpn: Vec<String>,
    /// auto、1.2、1.3；v1 自动固定 1.2。
    #[serde(default = "auto")]
    pub version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Server {
    pub version: u8,
    pub password: Option<String>,
    #[serde(default)]
    pub users: Vec<User>,
    pub handshake: Target,
    #[serde(default)]
    pub handshake_for_server_name: BTreeMap<String, Target>,
    pub strict: Option<bool>,
    pub inner: Inner,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct User {
    pub password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub host: String,
    pub port: u16,
}
fn alpn() -> Vec<String> {
    vec!["http/1.1".into()]
}
fn auto() -> String {
    "auto".into()
}
pub(crate) fn invalid() -> Error {
    Error::Config("ShadowTLS 配置不合法或组合未提供".into())
}
pub(crate) fn parse<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T> {
    serde_json::from_value(value.clone()).map_err(|_| invalid())
}
pub(crate) fn key(value: &str) -> Result<Arc<[u8]>> {
    if value.is_empty() || value.len() > 4096 {
        return Err(invalid());
    }
    Ok(Arc::from(value.as_bytes()))
}
pub(crate) fn version(value: u8) -> Result<()> {
    if !(1..=3).contains(&value) {
        Err(invalid())
    } else {
        Ok(())
    }
}
pub(crate) fn inner(value: &Inner) -> Result<()> {
    let method = value
        .options
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let allowed = match value.kind.as_str() {
        "shadowsocks" => kerlico_shadowsocks::AEAD_METHODS.contains(&method),
        "ss2022" => matches!(
            method,
            "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305"
        ),
        _ => false,
    };
    if !allowed {
        return Err(invalid());
    }
    Ok(())
}
impl Client {
    pub fn strict(&self) -> bool {
        self.strict.unwrap_or(true)
    }
    pub fn validate(&self) -> Result<Arc<[u8]>> {
        version(self.version)?;
        inner(&self.inner)?;
        if self.version != 3 && self.strict.is_some() {
            return Err(invalid());
        }
        if self.version == 1 {
            if self.password.is_some() || self.tls.version == "1.3" {
                return Err(invalid());
            }
            Ok(Arc::from(&[][..]))
        } else {
            key(self.password.as_deref().ok_or_else(invalid)?)
        }
    }
}
impl Target {
    pub fn destination(&self) -> Result<Destination> {
        Destination::new(&self.host, self.port)
    }
}
impl Server {
    pub fn strict(&self) -> bool {
        self.strict.unwrap_or(true)
    }
    pub fn validate(&self) -> Result<Vec<Arc<[u8]>>> {
        version(self.version)?;
        inner(&self.inner)?;
        if self.version != 3 && self.strict.is_some() {
            return Err(invalid());
        }
        self.handshake.destination()?;
        if self.handshake_for_server_name.len() > 32
            || self.version == 1 && !self.handshake_for_server_name.is_empty()
        {
            return Err(invalid());
        }
        let mut names = BTreeSet::new();
        for (name, target) in &self.handshake_for_server_name {
            let domain = Destination::new(name, 1)?;
            if domain.host() != *name
                || !matches!(domain.address(), kerlico_core::Address::Domain(_))
                || !names.insert(domain.host())
            {
                return Err(invalid());
            }
            target.destination()?;
        }
        let keys = match self.version {
            1 => {
                if self.password.is_some() || !self.users.is_empty() {
                    return Err(invalid());
                }
                Vec::new()
            }
            2 => {
                if !self.users.is_empty() {
                    return Err(invalid());
                }
                vec![key(self.password.as_deref().ok_or_else(invalid)?)?]
            }
            _ => {
                if self.password.is_some() && !self.users.is_empty() || self.users.len() > 256 {
                    return Err(invalid());
                }
                if let Some(value) = &self.password {
                    vec![key(value)?]
                } else {
                    if self.users.is_empty() {
                        return Err(invalid());
                    }
                    self.users
                        .iter()
                        .map(|user| key(&user.password))
                        .collect::<Result<Vec<_>>>()?
                }
            }
        };
        let mut seen = BTreeSet::new();
        for value in &keys {
            if !seen.insert(value.to_vec()) {
                return Err(invalid());
            }
        }
        Ok(keys)
    }
}
