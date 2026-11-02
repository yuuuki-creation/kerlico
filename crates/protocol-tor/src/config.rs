use kerlico_core::{Error, Result};
use serde::Deserialize;
use std::{path::{Component, Path, PathBuf}, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Options {
    data_directory: PathBuf,
    #[serde(default = "bootstrap_timeout")]
    bootstrap_timeout_ms: u64,
    #[serde(default = "carrier_timeout")]
    carrier_timeout_ms: u64,
    #[serde(default = "shutdown_timeout")]
    shutdown_timeout_ms: u64,
}

fn bootstrap_timeout() -> u64 { 120_000 }
fn carrier_timeout() -> u64 { 30_000 }
fn shutdown_timeout() -> u64 { 5_000 }

pub(crate) struct Prepared {
    pub data_directory: PathBuf,
    pub bootstrap_timeout: Duration,
    pub carrier_timeout: Duration,
    pub shutdown_timeout: Duration,
}

fn valid_directory(path: &Path) -> bool {
    let mut normal = false;
    for part in path.components() {
        match part {
            Component::Normal(value) => {
                let Some(value) = value.to_str() else { return false; };
                if value.is_empty() || value.len() > 128 || value.chars().any(|c| {
                    c.is_control() || "<>:\"|?*".contains(c)
                }) {
                    return false;
                }
                normal = true;
            }
            Component::CurDir => {}
            _ => return false,
        }
    }
    normal
}

impl Options {
    pub fn prepare(self) -> Result<Prepared> {
        if !valid_directory(&self.data_directory)
            || !(1000..=600_000).contains(&self.bootstrap_timeout_ms)
            || !(100..=120_000).contains(&self.carrier_timeout_ms)
            || !(100..=60_000).contains(&self.shutdown_timeout_ms)
        {
            return Err(Error::Config("Tor状态目录须是项目相对路径，时间预算须在允许范围内".into()));
        }
        Ok(Prepared {
            data_directory: self.data_directory,
            bootstrap_timeout: Duration::from_millis(self.bootstrap_timeout_ms),
            carrier_timeout: Duration::from_millis(self.carrier_timeout_ms),
            shutdown_timeout: Duration::from_millis(self.shutdown_timeout_ms),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tor_config_rejects_unknown_role_backend_and_path_escape() {
        for value in [
            json!({"data_directory":"state", "server":"proxy.invalid"}),
            json!({"data_directory":"state", "executable_path":"tor"}),
            json!({"data_directory":"state", "udp":true}),
        ] {
            assert!(serde_json::from_value::<Options>(value).is_err());
        }
        for path in ["", ".", "../state", "/state", "C:/state"] {
            let options: Options = serde_json::from_value(json!({"data_directory":path})).unwrap();
            assert!(options.prepare().is_err());
        }
    }

    #[test]
    fn tor_config_accepts_explicit_project_storage_and_bounded_timeouts() {
        let options: Options = serde_json::from_value(json!({
            "data_directory":"state/tor",
            "bootstrap_timeout_ms":120_000,
            "carrier_timeout_ms":30_000,
            "shutdown_timeout_ms":5_000
        })).unwrap();
        let prepared = options.prepare().unwrap();
        assert_eq!(prepared.data_directory, PathBuf::from("state/tor"));
        assert_eq!(prepared.bootstrap_timeout, Duration::from_secs(120));
        let options: Options = serde_json::from_value(json!({
            "data_directory":"state", "bootstrap_timeout_ms":0
        })).unwrap();
        assert!(options.prepare().is_err());
    }
}
