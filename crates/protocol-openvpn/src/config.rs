//! 出站配置解析与校验。

use crate::{
    data::DataCipher,
    keys::MAX_STRING,
    session::{Credentials, Settings},
    tls::client_config,
    wrap::{AuthDigest, StaticKey, WrapKeys},
};
use kerlico_core::{CancellationToken, Destination, Error, Result};
use kerlico_wireguard::ip::{ClientTunnel, StackLimits, StackOptions};
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[derive(Deserialize)]
struct Remote {
    host: String,
    port: u16,
}

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Proto {
    #[default]
    Udp,
    Tcp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsAuth {
    key: String,
    direction: Option<u8>,
    #[serde(default = "default_digest")]
    digest: String,
}
fn default_digest() -> String {
    "SHA1".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    remote: Remote,
    #[serde(default)]
    proto: Proto,
    bind: Option<SocketAddr>,
    ca_pem: String,
    cert_pem: Option<String>,
    key_pem: Option<String>,
    username: Option<String>,
    password: Option<String>,
    tls_auth: Option<TlsAuth>,
    tls_crypt_key: Option<String>,
    ciphers: Option<Vec<String>>,
    verify_x509_name: Option<String>,
    allowed_ips: Option<Vec<String>>,
    #[serde(default = "default_mtu")]
    mtu: usize,
    #[serde(default = "default_ping")]
    ping_secs: u64,
    #[serde(default)]
    ping_restart_secs: u64,
    #[serde(default = "default_reneg")]
    reneg_secs: u64,
    #[serde(default = "default_handshake")]
    handshake_timeout_secs: u64,
}
fn default_mtu() -> usize {
    1400
}
fn default_ping() -> u64 {
    10
}
fn default_reneg() -> u64 {
    3600
}
fn default_handshake() -> u64 {
    60
}
const MAX_HANDSHAKE_SECS: u64 = 3600;

pub(crate) struct Prepared {
    pub remote: Destination,
    pub proto: Proto,
    pub bind: Option<SocketAddr>,
    pub settings: Arc<Settings>,
    pub allowed_ips: Option<Vec<String>>,
    pub mtu: usize,
}

fn invalid() -> Error {
    Error::Config("OpenVPN 出站字段不合法".into())
}
fn nonzero(seconds: u64) -> Option<Duration> {
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

impl ClientOptions {
    pub fn prepare(self) -> Result<Prepared> {
        let remote = Destination::new(&self.remote.host, self.remote.port)?;
        if self.remote.port == 0
            || self.bind.is_some_and(|bind| bind.ip().is_multicast())
            || !(1..=MAX_HANDSHAKE_SECS).contains(&self.handshake_timeout_secs)
        {
            return Err(invalid());
        }
        let identity = match (&self.cert_pem, &self.key_pem) {
            (Some(certificate), Some(key)) => Some((certificate.as_str(), key.as_str())),
            (None, None) => None,
            _ => return Err(invalid()),
        };
        let credentials = match (self.username, self.password) {
            (Some(username), Some(password))
                if !username.is_empty()
                    && username.len() <= MAX_STRING
                    && password.len() <= MAX_STRING
                    && !username.contains('\0')
                    && !password.contains('\0') =>
            {
                Some(Credentials { username, password })
            }
            (None, None) => None,
            _ => return Err(invalid()),
        };
        if identity.is_none() && credentials.is_none() {
            return Err(Error::Config(
                "OpenVPN 出站需要客户端证书或用户名密码".into(),
            ));
        }
        let wrap = match (&self.tls_auth, &self.tls_crypt_key) {
            (None, None) => WrapKeys::Plain,
            (Some(auth), None) => {
                let digest = AuthDigest::parse(&auth.digest).ok_or_else(invalid)?;
                if auth.direction.is_some_and(|direction| direction > 1) {
                    return Err(invalid());
                }
                WrapKeys::auth(&StaticKey::parse(&auth.key)?, digest, auth.direction)
            }
            (None, Some(key)) => WrapKeys::crypt(&StaticKey::parse(key)?),
            (Some(_), Some(_)) => return Err(invalid()),
        };
        let ciphers = match &self.ciphers {
            None => DataCipher::ALL.to_vec(),
            Some(names) => names
                .iter()
                .map(|name| DataCipher::parse(name).ok_or_else(invalid))
                .collect::<Result<Vec<_>>>()?,
        };
        if ciphers.is_empty()
            || (1..ciphers.len()).any(|index| ciphers[..index].contains(&ciphers[index]))
        {
            return Err(invalid());
        }
        let tls = client_config(&self.ca_pem, identity, self.verify_x509_name.as_deref())?;
        validate_stack(self.allowed_ips.as_deref(), self.mtu)?;
        let options = options_string(self.proto, &wrap, ciphers[0], self.mtu);
        let peer_info = peer_info(&ciphers);
        Ok(Prepared {
            remote,
            proto: self.proto,
            bind: self.bind,
            settings: Arc::new(Settings {
                tls,
                wrap,
                credentials,
                ciphers,
                options,
                peer_info,
                ping: nonzero(self.ping_secs),
                ping_restart: nonzero(self.ping_restart_secs),
                reneg: nonzero(self.reneg_secs),
                handshake: Duration::from_secs(self.handshake_timeout_secs),
            }),
            allowed_ips: self.allowed_ips,
            mtu: self.mtu,
        })
    }
}

/// 复用 IP 数据面自身的校验，让非法范围或 MTU 在启动前失败，而不是等到首次连上服务端。
fn validate_stack(allowed_ips: Option<&[String]>, mtu: usize) -> Result<()> {
    let tunnel = ClientTunnel::new(
        StackOptions {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            allowed_ips: allowed_ips.map_or_else(|| vec!["0.0.0.0/0".to_owned()], <[_]>::to_vec),
            mtu,
            limits: StackLimits::default(),
        },
        CancellationToken::new(),
    )?;
    tunnel.close();
    Ok(())
}

/// 与上游 `options_string` 同形；2.6 服务端只在不一致时告警，算法由 NCP 决定。
fn options_string(proto: Proto, wrap: &WrapKeys, cipher: DataCipher, mtu: usize) -> String {
    let proto = match proto {
        Proto::Udp => "UDPv4",
        Proto::Tcp => "TCPv4_CLIENT",
    };
    let tls_auth = if matches!(wrap, WrapKeys::Auth { .. }) {
        ",tls-auth"
    } else {
        ""
    };
    format!(
        "V4,dev-type tun,link-mtu {},tun-mtu {mtu},proto {proto},cipher {},auth [null-digest],keysize {}{tls_auth},key-method 2,tls-client",
        mtu + 49,
        cipher.name(),
        cipher.key_bits(),
    )
}

/// `IV_PROTO=10` 是 `IV_PROTO_DATA_V2 | IV_PROTO_TLS_KEY_EXPORT`；`IV_VER` 声明线格式兼容基线。
fn peer_info(ciphers: &[DataCipher]) -> String {
    let names: Vec<_> = ciphers.iter().map(|cipher| cipher.name()).collect();
    let platform = match std::env::consts::OS {
        "windows" => "win",
        "macos" => "mac",
        other => other,
    };
    format!(
        "IV_VER=2.6.14\nIV_PLAT={platform}\nIV_TCPNL=1\nIV_NCP=2\nIV_CIPHERS={}\nIV_PROTO=10\n",
        names.join(":")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(value: serde_json::Value) -> Result<Prepared> {
        serde_json::from_value::<ClientOptions>(value)
            .map_err(|_| invalid())?
            .prepare()
    }
    fn ca() -> String {
        rcgen::generate_simple_self_signed(vec!["ca.invalid".to_owned()])
            .unwrap()
            .cert
            .pem()
    }

    #[test]
    fn username_only_profile_with_defaults_is_accepted() {
        let prepared = parse(json!({
            "remote": {"host": "vpn.invalid", "port": 1194},
            "ca_pem": ca(),
            "username": "user",
            "password": "secret",
        }))
        .unwrap();
        assert!(prepared.proto == Proto::Udp);
        assert_eq!(prepared.mtu, 1400);
        assert_eq!(
            prepared.settings.peer_info.lines().nth(4),
            Some("IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")
        );
        assert!(prepared.settings.options.contains("cipher AES-256-GCM"));
    }

    #[test]
    fn profiles_missing_identity_or_mixing_wrappers_or_scoped_out_ciphers_are_rejected() {
        let authority = ca();
        let base = || {
            json!({
                "remote": {"host": "vpn.invalid", "port": 1194},
                "ca_pem": authority,
                "username": "user",
                "password": "secret",
            })
        };
        let with = |key: &str, value: serde_json::Value| {
            let mut options = base();
            options[key] = value;
            options
        };
        let mut anonymous = base();
        anonymous.as_object_mut().unwrap().remove("username");
        anonymous.as_object_mut().unwrap().remove("password");
        assert!(parse(anonymous).is_err());
        assert!(parse(with("ciphers", json!(["AES-256-CBC"]))).is_err());
        assert!(parse(with("ciphers", json!(["AES-128-GCM", "aes-128-gcm"]))).is_err());
        assert!(parse(with("ciphers", json!([]))).is_err());
        assert!(parse(with("tls_crypt_key", json!("not a key"))).is_err());
        assert!(parse(with("mtu", json!(100))).is_err());
        assert!(parse(with("allowed_ips", json!(["not-a-network"]))).is_err());
        assert!(parse(with("cert_pem", json!("no key"))).is_err());
        assert!(parse(with("ca_pem", json!("no certificate"))).is_err());
        assert!(parse(with("unknown", json!(1))).is_err());
        assert!(parse(with("handshake_timeout_secs", json!(u64::MAX))).is_err());
        assert!(parse(with("username", json!("u".repeat(65535)))).is_err());
        assert!(parse(with("password", json!("p".repeat(65535)))).is_err());
    }
}
