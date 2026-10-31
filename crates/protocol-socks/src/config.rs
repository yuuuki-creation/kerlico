use kerlico_config::TargetSpec;
use kerlico_core::{Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub enum Version {
    #[serde(rename = "4")]
    Four,
    #[serde(rename = "4a")]
    FourA,
    #[default]
    #[serde(rename = "5")]
    Five,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub username: String,
    pub password: String,
}
impl Auth {
    pub fn validate(&self) -> Result<()> {
        if !(1..=255).contains(&self.username.len()) || !(1..=255).contains(&self.password.len()) {
            return Err(Error::Config(
                "SOCKS5 用户名和密码必须为 1 至 255 字节".into(),
            ));
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kerlico/socks5\0");
        hash.update([self.username.len() as u8]);
        hash.update(self.username.as_bytes());
        hash.update(self.password.as_bytes());
        hash.finalize().into()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutOptions {
    pub server: TargetSpec,
    #[serde(default)]
    pub version: Version,
    pub auth: Option<Auth>,
    #[serde(default)]
    pub userid: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeOptions {
    #[serde(default)]
    pub version: Version,
    pub auth: Option<Auth>,
    #[serde(default)]
    pub userid: String,
}

pub fn validate(version: Version, auth: &Option<Auth>, userid: &str) -> Result<()> {
    if let Some(auth) = auth {
        auth.validate()?;
        if version != Version::Five {
            return Err(Error::Config("SOCKS4/4a 不支持用户名密码认证".into()));
        }
    }
    if userid.len() > 255
        || userid.contains('\0')
        || (version == Version::Five && !userid.is_empty())
    {
        return Err(Error::Config("SOCKS userid 字段不合法或与版本冲突".into()));
    }
    Ok(())
}

pub fn equal(a: &[u8], b: &[u8]) -> bool {
    let mut difference = a.len() ^ b.len();
    for index in 0..a.len().max(b.len()) {
        difference |=
            usize::from(a.get(index).copied().unwrap_or(0) ^ b.get(index).copied().unwrap_or(0));
    }
    difference == 0
}
