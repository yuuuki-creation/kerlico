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
}
fn default_mtu() -> usize {
    DEFAULT_MTU
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    server_name: Option<String>,
    ca_pem: Option<String>,
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
        let host = server.host();
        let server_name = self.tls.server_name.as_deref().unwrap_or(host.as_str());
        let connector = TcpConnector::tls(server_name, self.tls.ca_pem.as_deref())?;
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
