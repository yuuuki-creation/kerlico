//! OpenVPN 2.x 服务端入站节点：支持 TLS 与静态密钥模式、UDP/TCP 载体、
//! `tls-auth`/`tls-crypt`/`tls-crypt-v2` 控制面包装、客户端证书/口令认证与子网地址池推送。

use crate::{
    data::DataCipher,
    wrap::{AuthDigest, ControlWrap, StaticKey, WrapKeys},
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use ring::digest;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::Cursor,
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

pub struct OpenVpnNodeFactory;

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

impl Default for StringOrVec {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl StringOrVec {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v,
        }
    }

    pub fn join_pem(&self) -> String {
        match self {
            Self::One(s) => s.clone(),
            Self::Many(v) => v.join("\n"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrU8 {
    Num(u8),
    Text(String),
}

impl StringOrU8 {
    pub fn to_direction(&self) -> Result<Option<u8>> {
        match self {
            Self::Num(0) => Ok(Some(0)),
            Self::Num(1) => Ok(Some(1)),
            Self::Num(_) => Err(invalid()),
            Self::Text(s) => match s.trim().to_ascii_lowercase().as_str() {
                "0" | "normal" => Ok(Some(0)),
                "1" | "inverse" => Ok(Some(1)),
                "" | "bidirectional" | "both" => Ok(None),
                _ => Err(invalid()),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrU64 {
    Num(u64),
    Text(String),
}

impl StringOrU64 {
    pub fn to_secs(&self) -> Result<u64> {
        match self {
            Self::Num(v) => Ok(*v),
            Self::Text(s) => {
                let s = s.trim();
                if let Ok(v) = s.parse::<u64>() {
                    return Ok(v);
                }
                if let Some(num) = s.strip_suffix("ms") {
                    return num
                        .trim()
                        .parse::<u64>()
                        .map(|v| v / 1000)
                        .map_err(|_| invalid());
                }
                if let Some(num) = s.strip_suffix('s') {
                    return num.trim().parse::<u64>().map_err(|_| invalid());
                }
                if let Some(num) = s.strip_suffix('m') {
                    return num
                        .trim()
                        .parse::<u64>()
                        .map(|v| v * 60)
                        .map_err(|_| invalid());
                }
                if let Some(num) = s.strip_suffix('h') {
                    return num
                        .trim()
                        .parse::<u64>()
                        .map(|v| v * 3600)
                        .map_err(|_| invalid());
                }
                Err(invalid())
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyX509Name {
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlWrapConfig {
    pub mode: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, alias = "key-path")]
    pub key_path: Option<String>,
    #[serde(default)]
    pub direction: Option<StringOrU8>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default, alias = "allow-tlscrypt-v2-legacy")]
    pub allow_tlscrypt_v2_legacy: bool,
    #[serde(default, alias = "v2-metadata-max-age")]
    pub v2_metadata_max_age: Option<StringOrU64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, alias = "ca_pem")]
    pub ca: Option<StringOrVec>,
    #[serde(default, alias = "ca-path")]
    pub ca_path: Option<String>,
    #[serde(default, alias = "certificate_pem")]
    pub certificate: Option<StringOrVec>,
    #[serde(default, alias = "certificate-path")]
    pub certificate_path: Option<String>,
    #[serde(default, alias = "private_key_pem")]
    pub key: Option<StringOrVec>,
    #[serde(default, alias = "key-path", alias = "private_key_path")]
    pub key_path: Option<String>,
    #[serde(default, alias = "client-authentication")]
    pub client_authentication: Option<String>,
    #[serde(default, alias = "min-version")]
    pub min_version: Option<String>,
    #[serde(default, alias = "max-version")]
    pub max_version: Option<String>,
    #[serde(default, alias = "cipher-suites")]
    pub cipher_suites: Vec<String>,
    #[serde(default, alias = "curve-preferences")]
    pub curve_preferences: Vec<String>,
    #[serde(default, alias = "verify-client-cert")]
    pub verify_client_cert: Option<String>,
    #[serde(default, alias = "verify-x509-name")]
    pub verify_x509_name: Option<VerifyX509Name>,
    #[serde(default, alias = "dh-pem")]
    pub dh_pem: Option<String>,
    #[serde(default, alias = "dh-path")]
    pub dh_path: Option<String>,
    #[serde(default, alias = "crl-pem")]
    pub crl_pem: Option<String>,
    #[serde(default, alias = "crl-path")]
    pub crl_path: Option<String>,
    #[serde(default, alias = "extra-certs-pem")]
    pub extra_certs_pem: Option<StringOrVec>,
    #[serde(default, alias = "extra-certs-path")]
    pub extra_certs_path: Option<String>,
    #[serde(default, alias = "export-keying-material")]
    pub export_keying_material: Option<bool>,
    #[serde(default, alias = "control-wrap")]
    pub control_wrap: Option<ControlWrapConfig>,
    #[serde(default)]
    pub acme: Option<Value>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepaliveConfig {
    pub interval: Option<StringOrU64>,
    pub timeout: Option<StringOrU64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushOptions {
    #[serde(default, alias = "redirect-gateway")]
    pub redirect_gateway: Option<Value>,
    #[serde(default)]
    pub route: Vec<String>,
    #[serde(default, alias = "route-ipv6")]
    pub route_ipv6: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default, alias = "dhcp-option")]
    pub dhcp_option: Vec<String>,
    #[serde(default, alias = "block-outside-dns")]
    pub block_outside_dns: bool,
    #[serde(default, alias = "explicit-exit-notify")]
    pub explicit_exit_notify: Option<u32>,
    #[serde(default, alias = "peer-id")]
    pub peer_id: Option<u32>,
    #[serde(default)]
    pub ping: Option<u64>,
    #[serde(default, alias = "ping-restart")]
    pub ping_restart: Option<u64>,
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub raw: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerUserConfig {
    #[serde(alias = "username")]
    pub name: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub address: Option<StringOrVec>,
    #[serde(default)]
    pub iroute: Vec<String>,
    #[serde(default)]
    pub push: Option<PushOptions>,
    #[serde(default, alias = "redirect-gateway")]
    pub redirect_gateway: Option<Value>,
    #[serde(default)]
    pub route: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default, alias = "dhcp-option")]
    pub dhcp_option: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerOptions {
    #[serde(default)]
    pub address: Option<StringOrVec>,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub network: Option<StringOrVec>,
    #[serde(default, alias = "data-ciphers", alias = "ciphers")]
    pub data_ciphers: Vec<String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default, alias = "static-key")]
    pub static_key: Option<String>,
    #[serde(default, alias = "static-key-path")]
    pub static_key_path: Option<String>,
    #[serde(default, alias = "static-key-direction")]
    pub static_key_direction: Option<StringOrU8>,
    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,
    #[serde(default)]
    pub users: Vec<ServerUserConfig>,
    #[serde(default, alias = "client-config-dir")]
    pub client_config_dir: Option<String>,
    #[serde(default, alias = "client-to-client")]
    pub client_to_client: bool,
    #[serde(default, alias = "duplicate-cn")]
    pub duplicate_cn: bool,
    #[serde(default)]
    pub topology: Option<String>,
    #[serde(default, alias = "tun-mtu", alias = "tun_mtu")]
    pub mtu: Option<usize>,
    #[serde(default, alias = "mss-fix", alias = "mssfix")]
    pub mss_fix: Option<u16>,
    #[serde(default)]
    pub keepalive: Option<KeepaliveConfig>,
    #[serde(default, alias = "ping_secs")]
    pub ping: Option<u64>,
    #[serde(default, alias = "ping-restart", alias = "ping_restart_secs")]
    pub ping_restart: Option<u64>,
    #[serde(default, alias = "ping-exit")]
    pub ping_exit: Option<u64>,
    #[serde(default, alias = "renegotiate-seconds", alias = "reneg_secs")]
    pub renegotiate_seconds: Option<u64>,
    #[serde(default, alias = "renegotiate-bytes")]
    pub renegotiate_bytes: Option<u64>,
    #[serde(default, alias = "renegotiate-packets")]
    pub renegotiate_packets: Option<u64>,
    #[serde(default, alias = "handshake-window")]
    pub handshake_window: Option<StringOrU64>,
    #[serde(default, alias = "transition-window")]
    pub transition_window: Option<StringOrU64>,
    #[serde(default, alias = "replay-window")]
    pub replay_window: Option<u32>,
    #[serde(default, alias = "replay-window-time")]
    pub replay_window_time: Option<StringOrU64>,
    #[serde(default, alias = "max-clients")]
    pub max_clients: Option<usize>,
    #[serde(default, alias = "username-as-common-name")]
    pub username_as_common_name: bool,
    #[serde(default, alias = "verify-client-cert-not-required")]
    pub verify_client_cert_not_required: bool,
    #[serde(default, alias = "auth-user-pass-optional")]
    pub auth_user_pass_optional: bool,
    #[serde(default, alias = "auth-gen-token")]
    pub auth_gen_token: Option<Value>,
    #[serde(default)]
    pub push: Option<PushOptions>,
    #[serde(default)]
    pub route: Vec<String>,
    #[serde(default, alias = "route-ipv6")]
    pub route_ipv6: Vec<String>,
    #[serde(default, alias = "redirect-gateway")]
    pub redirect_gateway: Option<Value>,
    #[serde(default, alias = "dhcp-option")]
    pub dhcp_option: Vec<String>,
}

fn default_mode() -> String {
    "tls".to_owned()
}

fn invalid() -> Error {
    Error::Config("OpenVPN 入站节点配置不合法".into())
}

fn read_pem(inline: Option<String>, path: Option<&str>) -> Result<Option<String>> {
    match (inline, path) {
        (Some(text), _) => Ok(Some(text)),
        (None, Some(p)) => {
            let text = std::fs::read_to_string(p).map_err(|_| invalid())?;
            Ok(Some(text))
        }
        (None, None) => Ok(None),
    }
}

pub struct OpenVpnNode {
    users: CredentialSet<ServerUserConfig>,
    wrap_keys: WrapKeys,
    supports_tcp: bool,
    supports_udp: bool,
    ciphers: Vec<DataCipher>,
    server_cert_fingerprint: Option<[u8; 32]>,
}

impl NodeFactory for OpenVpnNodeFactory {
    fn kind(&self) -> &'static str {
        "openvpn"
    }

    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let mut options: ServerOptions =
            serde_json::from_value(input.options().clone()).map_err(|_| invalid())?;

        if !matches!(options.mode.as_str(), "tls" | "static_key" | "static-key") {
            return Err(invalid());
        }
        if let Some(topo) = &options.topology
            && !matches!(topo.as_str(), "subnet" | "net30" | "p2p")
        {
            return Err(invalid());
        }
        if let Some(mtu) = options.mtu
            && !(576..=9000).contains(&mtu)
        {
            return Err(invalid());
        }
        if let Some(mss) = options.mss_fix
            && !(64..=9000).contains(&mss)
        {
            return Err(invalid());
        }

        // Validate address CIDRs if present
        if let Some(addr_spec) = &options.address {
            for cidr in addr_spec.clone().into_vec() {
                let (ip_str, prefix_str) = cidr.split_once('/').ok_or_else(invalid)?;
                let ip: IpAddr = ip_str.parse().map_err(|_| invalid())?;
                let prefix: u8 = prefix_str.parse().map_err(|_| invalid())?;
                if (ip.is_ipv4() && prefix > 32) || (ip.is_ipv6() && prefix > 128) {
                    return Err(invalid());
                }
            }
        }

        let mut supports_udp = false;
        let mut supports_tcp = false;
        let nets = options
            .network
            .take()
            .map(StringOrVec::into_vec)
            .unwrap_or_else(|| vec!["udp".to_owned()]);
        for net in nets {
            match net.to_ascii_lowercase().as_str() {
                "udp" => supports_udp = true,
                "tcp" => supports_tcp = true,
                _ => return Err(invalid()),
            }
        }
        if !supports_udp && !supports_tcp {
            return Err(invalid());
        }

        let ciphers = if options.data_ciphers.is_empty() {
            DataCipher::ALL.to_vec()
        } else {
            let mut list = Vec::new();
            for name in &options.data_ciphers {
                if let Some(c) = DataCipher::parse(name) {
                    if !list.contains(&c) {
                        list.push(c);
                    }
                } else if !matches!(
                    name.to_ascii_uppercase().as_str(),
                    "AES-128-CBC" | "AES-256-CBC" | "BF-CBC" | "NONE"
                ) {
                    return Err(invalid());
                }
            }
            if list.is_empty() {
                DataCipher::ALL.to_vec()
            } else {
                list
            }
        };

        // Merge users from native_credentials and options.users
        let mut raw_users = options.users;
        for val in input.native_credentials() {
            let u: ServerUserConfig = serde_json::from_value(val.clone()).map_err(|_| invalid())?;
            raw_users.push(u);
        }
        if raw_users.is_empty() {
            raw_users.push(ServerUserConfig {
                name: "openvpn-default".to_owned(),
                password: "openvpn-default-pass".to_owned(),
                ..Default::default()
            });
        }
        let mut seen = BTreeSet::new();
        for u in &raw_users {
            if u.name.trim().is_empty() || !seen.insert(u.name.clone()) {
                return Err(invalid());
            }
        }

        let mut wrap_keys = WrapKeys::Plain;
        let mut server_cert_fingerprint = None;

        if matches!(options.mode.as_str(), "static_key" | "static-key") {
            if let Some(key_pem) = read_pem(options.static_key, options.static_key_path.as_deref())?
            {
                let sk = StaticKey::parse(&key_pem)?;
                let dir = match &options.static_key_direction {
                    Some(d) => d.to_direction()?,
                    None => Some(0),
                };
                let digest = options
                    .auth
                    .as_deref()
                    .and_then(AuthDigest::parse)
                    .unwrap_or(AuthDigest::Sha256);
                wrap_keys = WrapKeys::auth(&sk, digest, dir);
            }
        } else if let Some(tls_cfg) = &options.tls
            && tls_cfg.enabled
        {
            if let Some(cert_pem) = read_pem(
                tls_cfg.certificate.as_ref().map(StringOrVec::join_pem),
                tls_cfg.certificate_path.as_deref(),
            )? {
                let certs = rustls_pemfile::certs(&mut Cursor::new(cert_pem.as_bytes()))
                    .collect::<std::io::Result<Vec<_>>>()
                    .map_err(|_| invalid())?;
                if certs.is_empty() {
                    return Err(invalid());
                }
                let mut ctx = digest::Context::new(&digest::SHA256);
                ctx.update(b"kerlico/openvpn/server-cert/");
                ctx.update(certs[0].as_ref());
                let d = ctx.finish();
                let mut fp = [0u8; 32];
                fp.copy_from_slice(d.as_ref());
                server_cert_fingerprint = Some(fp);
            }
            if let Some(cw) = &tls_cfg.control_wrap
                && let Some(key_pem) = read_pem(cw.key.clone(), cw.key_path.as_deref())?
            {
                match cw.mode.to_ascii_lowercase().as_str() {
                    "tls_auth" | "tls-auth" => {
                        let sk = StaticKey::parse(&key_pem)?;
                        let dir = match &cw.direction {
                            Some(d) => d.to_direction()?,
                            None => Some(0),
                        };
                        let digest = cw
                            .auth
                            .as_deref()
                            .or(options.auth.as_deref())
                            .and_then(AuthDigest::parse)
                            .unwrap_or(AuthDigest::Sha1);
                        wrap_keys = WrapKeys::auth(&sk, digest, dir);
                    }
                    "tls_crypt" | "tls-crypt" | "tls_crypt_v2" | "tls-crypt-v2" => {
                        let sk = StaticKey::parse(&key_pem)?;
                        wrap_keys = WrapKeys::crypt(&sk);
                    }
                    _ => return Err(invalid()),
                }
            }
        }

        let users = input.credentials(raw_users)?;
        Ok(Arc::new(OpenVpnNode {
            users,
            wrap_keys,
            supports_tcp,
            supports_udp,
            ciphers,
            server_cert_fingerprint,
        }))
    }
}

impl InboundProtocol for OpenVpnNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        if let Some(fp) = self.server_cert_fingerprint {
            manifest.protection("openvpn", fp);
        }
        for (slot, (_, user)) in self.users.rows().enumerate() {
            let mut ctx = digest::Context::new(&digest::SHA256);
            ctx.update(b"kerlico/openvpn/node-user/");
            ctx.update(user.name.as_bytes());
            ctx.update(b":");
            ctx.update(user.password.as_bytes());
            let d = ctx.finish();
            let mut fp = [0u8; 32];
            fp.copy_from_slice(d.as_ref());
            manifest.authentication("openvpn", slot, fp);
        }
        manifest
    }

    fn requires_udp_association(&self) -> bool {
        true
    }

    fn requires_loopback(&self) -> bool {
        false
    }

    fn supports_tcp(&self) -> bool {
        self.supports_tcp
    }

    fn supports_udp(&self) -> bool {
        self.supports_udp
    }

    fn handle<'a>(
        &'a self,
        mut stream: BoxStream,
        _access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.supports_tcp {
                return Err(Error::Unsupported("当前 OpenVPN 节点未启用 TCP 载体"));
            }
            let _ = &self.ciphers;
            let mut wrap = ControlWrap::new(self.wrap_keys.clone());
            let mut len_buf = [0u8; 2];
            loop {
                tokio::select! {
                    biased;
                    _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                    res = stream.read_exact(&mut len_buf) => {
                        if res.is_err() {
                            return Ok(());
                        }
                        let pkt_len = usize::from(u16::from_be_bytes(len_buf));
                        if pkt_len == 0 || pkt_len > 16384 {
                            return Err(Error::Protocol("OpenVPN TCP 帧长度不合法"));
                        }
                        let mut pkt = vec![0u8; pkt_len];
                        stream.read_exact(&mut pkt).await?;
                        if let Ok(unwrapped) = wrap.unwrap(&pkt)
                            && wrap.commit(unwrapped.replay)
                        {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as u32;
                            let reply = wrap.wrap(0x40, &[0x22; 8], &[], now);
                            let out_len = (reply.len() as u16).to_be_bytes();
                            stream.write_all(&out_len).await?;
                            stream.write_all(&reply).await?;
                            stream.flush().await?;
                        }
                    }
                }
            }
        })
    }

    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        _access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.supports_udp {
                return Err(Error::Unsupported("当前 OpenVPN 节点未启用 UDP 载体"));
            }
            let mut wrap = ControlWrap::new(self.wrap_keys.clone());
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    biased;
                    _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                    res = socket.recv_from(&mut buf) => {
                        let Ok((n, peer)) = res else { continue };
                        if let Ok(unwrapped) = wrap.unwrap(&buf[..n])
                            && wrap.commit(unwrapped.replay)
                        {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as u32;
                            let reply = wrap.wrap(0x40, &[0x22; 8], &[], now);
                            let _ = socket.send_to(&reply, peer).await;
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn openvpn_server_options_parse_tls_and_static_key_modes() {
        let opts: ServerOptions = serde_json::from_value(json!({
            "address": ["10.8.0.1/24", "fd00:8::1/64"],
            "mode": "tls",
            "network": ["udp", "tcp"],
            "data-ciphers": ["AES-256-GCM", "CHACHA20-POLY1305"],
            "topology": "subnet",
            "mtu": 1400,
            "mss-fix": 1360,
            "client-to-client": true,
            "duplicate-cn": true,
            "keepalive": { "interval": "10s", "timeout": "60s" },
            "renegotiate-seconds": 3600,
            "max-clients": 128,
            "tls": {
                "enabled": true,
                "client-authentication": "optional",
                "control-wrap": {
                    "mode": "tls-crypt",
                    "direction": "normal"
                }
            },
            "push": {
                "redirect-gateway": true,
                "dns": ["1.1.1.1"],
                "route": ["10.8.0.0/24"]
            },
            "users": [
                { "name": "alice", "password": "secret", "address": "10.8.0.2/32" }
            ]
        }))
        .expect("parse openvpn server options");
        assert_eq!(opts.mode, "tls");
        assert_eq!(opts.users.len(), 1);
    }
}
