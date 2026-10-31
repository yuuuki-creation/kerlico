//! 配置只接受已实现的角色、载体和安全选项。

use crate::invalid;
use kerlico_core::Result;
use serde::Deserialize;
use std::{io::Cursor, sync::Arc};

fn slash() -> String {
    "/".into()
}
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum TransportInput {
    Name(String),
    Detail(Transport),
}
impl Default for TransportInput {
    fn default() -> Self {
        Self::Name("tcp".into())
    }
}
impl TransportInput {
    pub fn normalize(self) -> Result<Transport> {
        let value = match self {
            Self::Name(name) if matches!(name.as_str(), "tcp" | "raw") => Transport::Tcp,
            Self::Name(_) => return Err(invalid()),
            Self::Detail(value) => value,
        };
        match &value {
            Transport::Tcp => {}
            Transport::Ws {
                path,
                host,
                headers,
                early_data_bytes,
            } => {
                validate_http(path, host.as_deref(), headers)?;
                if *early_data_bytes > 65536 {
                    return Err(invalid());
                }
            }
            Transport::Httpupgrade {
                path,
                host,
                headers,
            } => validate_http(path, host.as_deref(), headers)?,
            Transport::Grpc {
                service_name,
                authority,
                ..
            } => {
                if service_name.len() > 1024
                    || service_name
                        .chars()
                        .any(|c| c.is_control() || c == '?' || c == '#')
                    || authority
                        .as_ref()
                        .is_some_and(|v| v.parse::<http::uri::Authority>().is_err())
                {
                    return Err(invalid());
                }
            }
        }
        Ok(value)
    }
}
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Transport {
    #[serde(alias = "raw")]
    Tcp,
    Ws {
        #[serde(default = "slash")]
        path: String,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        headers: Vec<(String, String)>,
        #[serde(default)]
        early_data_bytes: u32,
    },
    Httpupgrade {
        #[serde(default = "slash")]
        path: String,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    Grpc {
        #[serde(default)]
        service_name: String,
        #[serde(default)]
        authority: Option<String>,
        #[serde(default)]
        multi_mode: bool,
    },
}
impl Transport {
    pub fn raw(&self) -> bool {
        matches!(self, Self::Tcp)
    }
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Tcp => Vec::new(),
            Self::Grpc { .. } => vec![b"h2".to_vec()],
            _ => vec![b"http/1.1".to_vec()],
        }
    }
}
fn validate_http(path: &str, host: Option<&str>, headers: &[(String, String)]) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > 4096
        || path.chars().any(char::is_control)
        || path.parse::<http::uri::PathAndQuery>().is_err()
        || host.is_some_and(|v| v.parse::<http::uri::Authority>().is_err())
        || headers.len() > 64
    {
        return Err(invalid());
    }
    for (name, value) in headers {
        let name = name.parse::<http::HeaderName>().map_err(|_| invalid())?;
        value.parse::<http::HeaderValue>().map_err(|_| invalid())?;
        if matches!(
            name.as_str(),
            "connection"
                | "upgrade"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "content-length"
                | "transfer-encoding"
        ) {
            return Err(invalid());
        }
    }
    Ok(())
}
#[derive(Deserialize, Default)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ClientSecurity {
    Tls {
        #[serde(default)]
        server_name: Option<String>,
        #[serde(default)]
        ca_pem: Option<String>,
    },
    #[default]
    None,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ServerSecurity {
    Tls {
        #[serde(default)]
        certificate_pem: Option<String>,
        #[serde(default)]
        private_key_pem: Option<String>,
        #[serde(default)]
        certificate_file: Option<String>,
        #[serde(default)]
        private_key_file: Option<String>,
    },
    None,
}
pub(crate) fn pem(inline: Option<String>, file: Option<String>) -> Result<String> {
    match (inline, file) {
        (Some(value), None) if value.len() <= 1024 * 1024 => Ok(value),
        (None, Some(path)) => {
            if std::fs::metadata(&path).map_err(|_| invalid())?.len() > 1024 * 1024 {
                return Err(invalid());
            }
            std::fs::read_to_string(path).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
pub(crate) fn server_tls(
    security: ServerSecurity,
    transport: &Transport,
) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    let ServerSecurity::Tls {
        certificate_pem,
        private_key_pem,
        certificate_file,
        private_key_file,
    } = security
    else {
        return Ok(None);
    };
    let cert = pem(certificate_pem, certificate_file)?;
    let key = pem(private_key_pem, private_key_file)?;
    let certs = rustls_pemfile::certs(&mut Cursor::new(cert))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| invalid())?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key))
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| invalid())?;
    config.alpn_protocols = transport.alpn();
    config.send_tls13_tickets = 0;
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_unsupported_and_malformed_transport() {
        for value in [
            serde_json::json!("unknown"),
            serde_json::json!({"type":"ws", "path":"bad"}),
            serde_json::json!({"type":"ws", "headers":[["connection","x"]]}),
            serde_json::json!({"type":"grpc", "authority":"bad authority"}),
        ] {
            let parsed = serde_json::from_value::<TransportInput>(value);
            assert!(parsed.is_err() || parsed.unwrap().normalize().is_err());
        }
    }
}
