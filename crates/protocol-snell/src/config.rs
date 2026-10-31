use crate::{invalid, profile::Profile};
use kerlico_core::Result;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    #[default]
    Default,
    Unshaped,
    UnsafeRaw,
}
#[derive(Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Obfs {
    #[default]
    None,
    Http,
}
#[derive(Clone)]
pub(crate) struct Settings {
    pub version: u8,
    pub psk: Arc<[u8]>,
    pub mode: Mode,
    pub profile: Option<Arc<Profile>>,
    pub obfs: Obfs,
    pub host: String,
    pub uri: String,
}
impl Settings {
    pub fn new(
        version: u8,
        psk: String,
        mode: Option<Mode>,
        obfs: Obfs,
        host: Option<String>,
        uri: Option<String>,
        server: bool,
    ) -> Result<Self> {
        if !matches!((server, version), (false, 4) | (true, 5) | (_, 6))
            || psk.is_empty()
            || psk.len() > 4096
        {
            return Err(invalid());
        }
        let mode = match (version, mode) {
            (6, mode) => mode.unwrap_or_default(),
            (_, None) => Mode::Default,
            _ => return Err(invalid()),
        };
        if version == 6
            && (!(12..=255).contains(&psk.len())
                || obfs != Obfs::None
                || host.is_some()
                || uri.is_some())
        {
            return Err(invalid());
        }
        if obfs == Obfs::None && (host.is_some() || uri.is_some()) {
            return Err(invalid());
        }
        let host = host.unwrap_or_else(|| "bing.com".into());
        let uri = uri.unwrap_or_else(|| "/".into());
        if host.is_empty()
            || host.len() > 255
            || host.chars().any(|c| c.is_control() || c.is_whitespace())
            || !uri.starts_with('/')
            || uri.len() > 4096
            || uri.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        let profile = if version == 6 && mode == Mode::Default {
            Some(Arc::new(Profile::new(psk.as_bytes())))
        } else {
            None
        };
        Ok(Self {
            version,
            psk: Arc::from(psk.into_bytes()),
            mode,
            profile,
            obfs,
            host,
            uri,
        })
    }
    pub fn raw(&self) -> bool {
        self.version == 6 && self.mode == Mode::UnsafeRaw
    }
}
pub(crate) fn userkey(value: &str) -> Result<Vec<u8>> {
    if value.len() > 255 {
        return Err(invalid());
    }
    Ok(value.as_bytes().to_vec())
}
