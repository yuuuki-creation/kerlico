//! Client settings, with the names of mihomo's `anytls` proxy fields.

use std::time::Duration;

use kerlico_anytls::tls::{self, ClientTls};
use kerlico_shared::{OpenError, Settings};

pub(crate) const KEYS: &[&str] = &[
    "password",
    "sni",
    "alpn",
    "skip-cert-verify",
    "fingerprint",
    "client-fingerprint",
    "name-cert-verify",
    "ech-opts",
    "certificate",
    "private-key",
    "jls-opts",
    "shadow-tls-opts",
    "restls-opts",
    "udp",
    "client-metadata",
    "idle-session-check-interval",
    "idle-session-timeout",
    "min-idle-session",
    "disable-reuse",
];

pub(crate) struct Plan {
    pub(crate) password: String,
    pub(crate) sni: String,
    pub(crate) tls: ClientTls,
    pub(crate) jls: Option<Jls>,
    pub(crate) shadow: Option<Shadow>,
    pub(crate) rest: Option<Rest>,
    pub(crate) alpn_given: bool,
    pub(crate) udp: bool,
    pub(crate) metadata: String,
    pub(crate) check_interval: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) min_idle: usize,
    pub(crate) disable_reuse: bool,
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Jls {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Shadow {
    pub(crate) password: String,
    pub(crate) version: u8,
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Rest {
    pub(crate) password: String,
    pub(crate) version_hint: String,
    pub(crate) restls_script: String,
}

impl Plan {
    pub(crate) fn parse(host: &str, settings: &Settings) -> Result<Self, OpenError> {
        if settings.keys().any(|key| !KEYS.contains(&key)) {
            return Err(OpenError::Settings);
        }
        let password = settings.text("password")?.to_string();
        let sni = match settings.optional_text("sni")? {
            None | Some("") => host.to_string(),
            Some(sni) => sni.to_string(),
        };
        let alpn_value = settings.optional_text("alpn")?;
        let alpn = match alpn_value {
            None => Vec::new(),
            Some(text) => parse_list(text)?,
        };
        let fingerprint = match settings.optional_text("fingerprint")? {
            None | Some("") => None,
            Some(text) => Some(tls::parse_fingerprint(text).map_err(|_| OpenError::Settings)?),
        };
        let identity = match (
            settings.optional_text("certificate")?.filter(|value| !value.is_empty()),
            settings.optional_text("private-key")?.filter(|value| !value.is_empty()),
        ) {
            (None, None) => None,
            (Some(certificate), Some(key)) => Some((certificate.to_owned(), key.to_owned())),
            _ => return Err(OpenError::Settings),
        };
        let (ech_config, ech_dns_name) = settings.optional_text("ech-opts")?.map(parse_ech).transpose()?.unwrap_or_default();
        let jls = settings.optional_text("jls-opts")?
            .map(|json| serde_json::from_str::<Jls>(json).map_err(|_| OpenError::Settings))
            .transpose()?
            .filter(|jls| !jls.username.is_empty() || !jls.password.is_empty());
        let shadow = settings.optional_text("shadow-tls-opts")?
            .map(|json| serde_json::from_str::<Shadow>(json).map_err(|_| OpenError::Settings))
            .transpose()?
            .filter(|shadow| !shadow.password.is_empty() || shadow.version != 0);
        let rest = settings.optional_text("restls-opts")?
            .map(|json| serde_json::from_str::<Rest>(json).map_err(|_| OpenError::Settings))
            .transpose()?
            .filter(|rest| !rest.password.is_empty() || !rest.version_hint.is_empty() || !rest.restls_script.is_empty());
        if [jls.is_some(), shadow.is_some(), rest.is_some()].into_iter().filter(|enabled| *enabled).count() > 1 {
            return Err(OpenError::Settings);
        }
        let tls = ClientTls {
            alpn,
            insecure: flag(settings, "skip-cert-verify")?,
            fingerprint,
            identity,
            client_fingerprint: settings.optional_text("client-fingerprint")?.unwrap_or_default().to_owned(),
            verify_name: settings.optional_text("name-cert-verify")?.unwrap_or_default().to_owned(),
            ech_config,
            ech_dns_name,
        };
        // mihomo turns intervals and timeouts of 5 seconds or less into 30 seconds.
        let seconds = |key: &str| -> Result<Duration, OpenError> {
            let value = match settings.optional_text(key)? {
                None => 0,
                Some(text) => text.parse::<i64>().map_err(|_| OpenError::Settings)?,
            };
            Ok(if value <= 5 { Duration::from_secs(30) } else { Duration::from_secs(value as u64) })
        };
        let min_idle = match settings.optional_text("min-idle-session")? {
            None => 0,
            Some(text) => text.parse::<i64>().map_err(|_| OpenError::Settings)?.max(0) as usize,
        };
        Ok(Self {
            password,
            sni,
            tls,
            jls,
            shadow,
            rest,
            alpn_given: alpn_value.is_some(),
            udp: flag(settings, "udp")?,
            metadata: settings.optional_text("client-metadata")?.unwrap_or("").to_string(),
            check_interval: seconds("idle-session-check-interval")?,
            idle_timeout: seconds("idle-session-timeout")?,
            min_idle,
            disable_reuse: flag(settings, "disable-reuse")?,
        })
    }
}

fn parse_ech(json: &str) -> Result<(String, Option<String>), OpenError> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|_| OpenError::Settings)?;
    let object = value.as_object().ok_or(OpenError::Settings)?;
    if object.keys().any(|key| !matches!(key.as_str(), "enable" | "config" | "query-server-name")) {
        return Err(OpenError::Settings);
    }
    let enabled = object.get("enable").map(|value| value.as_bool().ok_or(OpenError::Settings))
        .transpose()?.unwrap_or_default();
    let config = object.get("config").map(|value| value.as_str().ok_or(OpenError::Settings))
        .transpose()?.unwrap_or_default();
    let host = object.get("query-server-name").map(|value| value.as_str().ok_or(OpenError::Settings))
        .transpose()?.unwrap_or_default();
    if !enabled {
        return Ok((String::new(), None));
    }
    if config.is_empty() {
        return Ok((String::new(), Some(host.to_owned())));
    }
    Ok((config.to_owned(), None))
}

fn flag(settings: &Settings, key: &str) -> Result<bool, OpenError> {
    match settings.optional_text(key)? {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(OpenError::Settings),
    }
}

/// A JSON array of strings, or one comma-separated string.
fn parse_list(text: &str) -> Result<Vec<String>, OpenError> {
    if text.trim_start().starts_with('[') {
        let values: Vec<String> = serde_json::from_str(text).map_err(|_| OpenError::Settings)?;
        return Ok(values);
    }
    Ok(text.split(',').map(str::trim).filter(|value| !value.is_empty()).map(str::to_string).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let mut settings = Settings::default();
        for (key, value) in pairs {
            settings.insert_text(*key, *value);
        }
        settings
    }

    #[test]
    fn defaults_follow_mihomo() {
        let plan = Plan::parse("node.test", &settings(&[("password", "p")])).unwrap();
        assert_eq!(plan.sni, "node.test");
        assert!(!plan.udp && !plan.disable_reuse && !plan.tls.insecure);
        assert_eq!(plan.check_interval, Duration::from_secs(30));
        assert_eq!(plan.idle_timeout, Duration::from_secs(30));
        assert_eq!(plan.min_idle, 0);
        let plan = Plan::parse(
            "node.test",
            &settings(&[
                ("password", "p"),
                ("sni", "front.test"),
                ("alpn", r#"["h2","http/1.1"]"#),
                ("idle-session-timeout", "5"),
                ("idle-session-check-interval", "6"),
                ("min-idle-session", "2"),
                ("udp", "true"),
                ("skip-cert-verify", "true"),
            ]),
        )
        .unwrap();
        assert_eq!(plan.sni, "front.test");
        assert_eq!(plan.tls.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(plan.idle_timeout, Duration::from_secs(30));
        assert_eq!(plan.check_interval, Duration::from_secs(6));
        assert_eq!(plan.min_idle, 2);
        assert!(plan.udp && plan.tls.insecure);
    }

    #[test]
    fn unknown_and_unsupported_keys_are_refused() {
        assert!(Plan::parse("h", &settings(&[])).is_err());
        assert!(Plan::parse("h", &settings(&[("password", "p"), ("client-fingerprint", "chrome")])).is_ok());
        assert!(Plan::parse("h", &settings(&[("password", "p"), ("udp", "yes")])).is_err());
        assert!(Plan::parse("h", &settings(&[("password", "p"), ("fingerprint", "chrome")])).is_err());
    }
}
