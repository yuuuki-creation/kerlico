use kerlico_config::TargetSpec;
use kerlico_core::{Address, Destination, Error, Result};
use kerlico_net::TcpConnector;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Options {
    server: TargetSpec,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    mux: bool,
    forward_target: Option<TargetSpec>,
    tls: Option<Tls>,
    #[serde(default)]
    allow_insecure: bool,
    #[serde(default)]
    response_mode: ResponseMode,
}

#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResponseMode {
    #[default]
    Eager,
    Deferred,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    server_name: String,
    ca_pem: Option<String>,
}

pub(crate) struct Config {
    pub server: Destination,
    pub username: String,
    pub password: String,
    pub mux: bool,
    pub forward: Option<Destination>,
    pub connector: TcpConnector,
    pub response_mode: ResponseMode,
}

impl Options {
    pub fn prepare(self) -> Result<Config> {
        let server = self.server.destination()?;
        if self.username.len() > 255 || self.password.len() > 255 {
            return Err(Error::Config("Gost Relay 认证字段超过255字节".into()));
        }
        let connector = match self.tls {
            Some(tls) => {
                if self.allow_insecure {
                    return Err(Error::Config("TLS 模式不接受明文许可字段".into()));
                }
                TcpConnector::tls(&tls.server_name, tls.ca_pem.as_deref())?
            }
            None => {
                if !server.is_loopback() && !self.allow_insecure {
                    return Err(Error::Config(
                        "非字面回环的明文 Relay 需要 allow_insecure".into(),
                    ));
                }
                TcpConnector::plain()
            }
        };
        let forward = self.forward_target.map(|s| s.destination()).transpose()?;
        if forward
            .as_ref()
            .is_some_and(|s| !matches!(s.address(), Address::Ip(_)))
        {
            return Err(Error::Config("固定转发必须使用明确的 IP 目标".into()));
        }
        Ok(Config {
            server,
            username: self.username,
            password: self.password,
            mux: self.mux,
            forward,
            connector,
            response_mode: self.response_mode,
        })
    }
}
