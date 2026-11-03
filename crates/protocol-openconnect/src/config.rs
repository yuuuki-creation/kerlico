use kerlico_config::TargetSpec;
use kerlico_core::{Destination, Error, Result};
use kerlico_net::TcpConnector;
use serde::Deserialize;

const DEFAULT_MTU: usize = 1406;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Options {
    server: TargetSpec,
    username: String,
    password: String,
    #[serde(default)]
    tls: Tls,
    #[serde(default = "default_mtu")]
    mtu: usize,
    #[serde(default, alias = "dtls-local-port")]
    dtls_local_port: Option<u16>,
    #[serde(default, alias = "tls-client-certificate")]
    tls_client_certificate: Option<String>,
    #[serde(default, alias = "tls-client-certificate-path")]
    tls_client_certificate_path: Option<std::path::PathBuf>,
    #[serde(default, alias = "tls-client-key")]
    tls_client_key: Option<String>,
    #[serde(default, alias = "tls-client-key-path")]
    tls_client_key_path: Option<std::path::PathBuf>,
    #[serde(default, alias = "tls-client-key-password")]
    tls_client_key_password: Option<String>,
}
fn default_mtu() -> usize {
    DEFAULT_MTU
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    server_name: Option<String>,
    ca_pem: Option<String>,
    #[serde(default, alias = "certificate_pem", alias = "tls-client-certificate")]
    client_certificate: Option<String>,
    #[serde(
        default,
        alias = "certificate_path",
        alias = "tls-client-certificate-path"
    )]
    client_certificate_path: Option<std::path::PathBuf>,
    #[serde(default, alias = "private_key_pem", alias = "tls-client-key")]
    client_key: Option<String>,
    #[serde(default, alias = "private_key_path", alias = "tls-client-key-path")]
    client_key_path: Option<std::path::PathBuf>,
    #[serde(default, alias = "tls-client-key-password")]
    client_key_password: Option<String>,
}

pub(crate) struct Credentials {
    pub username: String,
    pub password: String,
}

pub(crate) struct Config {
    pub server: Destination,
    pub credentials: Credentials,
    pub connector: TcpConnector,
    pub mtu: usize,
}

fn credential_field(value: &str) -> bool {
    (1..=255).contains(&value.len()) && !value.chars().any(char::is_control)
}

fn load_pem_source(
    inline: Option<String>,
    path: Option<std::path::PathBuf>,
    label: &str,
) -> Result<Option<String>> {
    match (inline, path) {
        (Some(_), Some(_)) => Err(Error::Config(format!(
            "OpenConnect {label}不能同时提供内联内容与文件路径"
        ))),
        (Some(pem), None) => Ok(Some(pem)),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map(Some)
            .map_err(|_| Error::Config(format!("OpenConnect {label}文件读取失败"))),
        (None, None) => Ok(None),
    }
}

impl Options {
    pub fn prepare(self) -> Result<Config> {
        let server = self.server.destination()?;
        if !credential_field(&self.username) || !credential_field(&self.password) {
            return Err(Error::Config(
                "OpenConnect 用户名和密码须为1至255字节且不含控制字符".into(),
            ));
        }
        if !(1280..=9000).contains(&self.mtu) {
            return Err(Error::Config("OpenConnect MTU 须在1280至9000之间".into()));
        }
        if self.dtls_local_port == Some(0) {
            return Err(Error::Config("OpenConnect dtls_local_port 不能为0".into()));
        }
        let cert_pem = load_pem_source(
            self.tls_client_certificate.or(self.tls.client_certificate),
            self.tls_client_certificate_path
                .or(self.tls.client_certificate_path),
            "客户端证书",
        )?;
        let key_pem = load_pem_source(
            self.tls_client_key.or(self.tls.client_key),
            self.tls_client_key_path.or(self.tls.client_key_path),
            "客户端私钥",
        )?;
        let key_password = self
            .tls_client_key_password
            .or(self.tls.client_key_password);
        if key_password.as_deref().is_some_and(str::is_empty) {
            return Err(Error::Config("OpenConnect 客户端私钥口令不能为空".into()));
        }
        let host = server.host();
        let server_name = self.tls.server_name.as_deref().unwrap_or(host.as_str());
        let connector = TcpConnector::tls_mtls(
            server_name,
            self.tls.ca_pem.as_deref(),
            cert_pem.as_deref(),
            key_pem.as_deref(),
        )?;
        Ok(Config {
            server,
            credentials: Credentials {
                username: self.username,
                password: self.password,
            },
            connector,
            mtu: self.mtu,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn prepared(value: serde_json::Value) -> Result<Config> {
        serde_json::from_value::<Options>(value).unwrap().prepare()
    }

    #[test]
    fn defaults_apply_and_invalid_credentials_or_mtu_are_refused() {
        let base =
            json!({"server":{"host":"vpn.example.com","port":443},"username":"u","password":"p"});
        assert_eq!(prepared(base.clone()).unwrap().mtu, DEFAULT_MTU);
        for (field, value) in [
            ("username", json!("")),
            ("password", json!("line\nbreak")),
            ("mtu", json!(1279)),
        ] {
            let mut options = base.clone();
            options[field] = value;
            assert!(matches!(prepared(options), Err(Error::Config(_))));
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(
            serde_json::from_value::<Options>(json!({
                "server":{"host":"vpn.example.com","port":443},"username":"u","password":"p","dtls":true
            }))
            .is_err()
        );
    }
}
