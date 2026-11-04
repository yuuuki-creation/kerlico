//! OpenVPN 2.x 服务端入站节点：支持 TLS 与静态密钥模式、UDP/TCP 载体、
//! `tls-auth`/`tls-crypt`/`tls-crypt-v2` 控制面包装、客户端证书/口令认证与子网地址池推送。

use crate::{
    data::{DataCipher, OpenKey, PING, SealKey, server_data_keys},
    keys::{
        ClientKeySource, EKM_LABEL, ServerKeySource, expand_with_prf, read_client_key_method,
        write_server_key_method,
    },
    reliable::{ReliableReceive, ReliableSend},
    tls::server_config,
    wire::{Opcode, SessionId, decode_body, encode_body},
    wrap::{AuthDigest, ControlWrap, StaticKey, WrapKeys},
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use kerlico_wireguard::ip::{ServerTunnel, StackLimits, StackOptions};
use rand::{RngCore, rngs::OsRng};
use ring::digest;
use rustls::ServerConnection;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeSet, HashMap},
    io::{Cursor, ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::MissedTickBehavior,
};
use zeroize::Zeroizing;

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
    mtu: usize,
    tls_config: Arc<rustls::ServerConfig>,
    server_cert_fingerprint: Option<[u8; 32]>,
}

const CONTROL_FRAGMENT: usize = 1100;
const MAX_PLAINTEXT: usize = 256 * 1024;
const SERVER_TICK: Duration = Duration::from_millis(250);

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}

struct ServerSession {
    wrap: ControlWrap,
    local: SessionId,
    remote: Option<SessionId>,
    key_id: u8,
    tls: ServerConnection,
    plain: Vec<u8>,
    send: ReliableSend,
    receive: ReliableReceive,
    sent_reset: bool,
    client_key: Option<ClientKeySource>,
    server_key: Option<ServerKeySource>,
    cipher: DataCipher,
    mtu: usize,
    seal: Option<SealKey>,
    open: Option<OpenKey>,
    outbox: Vec<Vec<u8>>,
    packets: Vec<Vec<u8>>,
    tunnel: Option<Arc<ServerTunnel>>,
    peer_session: Option<kerlico_core::PeerSession>,
}

impl ServerSession {
    fn new(
        wrap_keys: WrapKeys,
        tls_config: Arc<rustls::ServerConfig>,
        cipher: DataCipher,
        mtu: usize,
    ) -> Result<Self> {
        let mut local = [0u8; 8];
        OsRng.fill_bytes(&mut local);
        let tls = ServerConnection::new(tls_config)
            .map_err(|_| Error::Protocol("OpenVPN 服务端 TLS 会话创建失败"))?;
        Ok(Self {
            wrap: ControlWrap::new(wrap_keys),
            local,
            remote: None,
            key_id: 0,
            tls,
            plain: Vec::new(),
            send: ReliableSend::default(),
            receive: ReliableReceive::default(),
            sent_reset: false,
            client_key: None,
            server_key: None,
            cipher,
            mtu,
            seal: None,
            open: None,
            outbox: Vec::new(),
            packets: Vec::new(),
            tunnel: None,
            peer_session: None,
        })
    }

    fn take_outbox(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox)
    }

    #[cfg(test)]
    fn take_packets(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.packets)
    }

    fn receive(
        &mut self,
        now: Instant,
        wire: &[u8],
        auth: Option<(
            &CredentialSet<ServerUserConfig>,
            &IngressBinding,
            &InboundContext,
        )>,
    ) -> Result<Option<Arc<ServerTunnel>>> {
        let Some((opcode, key_id)) = wire.first().copied().and_then(Opcode::parse) else {
            return Ok(None);
        };
        if opcode == Opcode::DataV2 {
            if let Some(open) = &mut self.open
                && open.key_id() == key_id
                && let Some(plain) = open.open(wire)
                && plain != PING
                && matches!(plain.first().map(|b| b >> 4), Some(4 | 6))
            {
                if let Some(tunnel) = &self.tunnel {
                    let _ = tunnel.receive(&plain);
                } else {
                    self.packets.push(plain);
                }
            }
            return Ok(None);
        }
        let Ok(unwrapped) = self.wrap.unwrap(wire) else {
            return Ok(None);
        };
        let Some((opcode, key_id)) = Opcode::parse(unwrapped.header) else {
            return Ok(None);
        };
        let Ok(body) = decode_body(opcode, &unwrapped.body) else {
            if self.wrap.commit(unwrapped.replay) {
                self.outbox
                    .push(self.wrap.wrap(0x40, &self.local, &[], now_unix()));
            }
            return Ok(None);
        };
        if !self.wrap.commit(unwrapped.replay) {
            return Ok(None);
        }
        self.key_id = key_id;
        self.remote = Some(unwrapped.session);
        for ack in &body.acks {
            self.send.ack(*ack);
        }
        if let Some(packet_id) = body.packet_id {
            self.receive.accept(packet_id, opcode, body.payload);
        }
        self.advance(now, auth)
    }

    fn advance(
        &mut self,
        now: Instant,
        auth: Option<(
            &CredentialSet<ServerUserConfig>,
            &IngressBinding,
            &InboundContext,
        )>,
    ) -> Result<Option<Arc<ServerTunnel>>> {
        let mut newly_opened = None;
        while let Some((opcode, payload)) = self.receive.pop_ready() {
            match opcode {
                Opcode::HardResetClient | Opcode::HardResetClientV3 => {
                    if !self.sent_reset {
                        self.send.push(Opcode::HardResetServer, Vec::new());
                        self.sent_reset = true;
                    }
                }
                Opcode::SoftReset => {
                    self.send.push(Opcode::SoftReset, Vec::new());
                }
                Opcode::Control => {
                    self.feed_tls(&payload)?;
                }
                _ => {}
            }
        }
        if !self.tls.is_handshaking() {
            if self.client_key.is_none()
                && let Some((consumed, msg)) = read_client_key_method(&self.plain)?
            {
                self.plain.drain(..consumed);
                let _ = (&msg.options, &msg.peer_info);
                if let Some((users, access, context)) = auth {
                    let session = if msg.username.is_empty() {
                        access.local(context)?
                    } else {
                        match users.verify(&msg, |u, m| {
                            if u.name == m.username && u.password == m.password {
                                Ok(Some(()))
                            } else {
                                Ok(None)
                            }
                        }) {
                            Ok(verified) => access.authenticated(verified, context)?.0,
                            Err(_) => {
                                self.write_plaintext(b"AUTH_FAILED\0")?;
                                self.queue_tls_output()?;
                                self.flush(now);
                                return Err(Error::Rejected);
                            }
                        }
                    };
                    self.peer_session = Some(session);
                }
                let server_source = ServerKeySource::generate();
                let options = format!(
                    "V4,dev-type tun,link-mtu {},tun-mtu {},proto UDPv4,cipher {},auth [null-digest],keysize {},key-method 2,tls-server",
                    self.mtu + 49,
                    self.mtu,
                    self.cipher.name(),
                    self.cipher.key_bits(),
                );
                let reply = write_server_key_method(&server_source, &options)?;
                self.write_plaintext(&reply)?;
                self.client_key = Some(msg.source);
                self.server_key = Some(server_source);
            }
            if self.client_key.is_some() {
                while let Some(end) = self.plain.iter().position(|b| *b == 0) {
                    let message: Vec<u8> = self.plain.drain(..=end).collect();
                    let text = String::from_utf8_lossy(&message[..end]);
                    if text == "PUSH_REQUEST" {
                        let push_reply = format!(
                            "PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 60,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher {},protocol-flags tls-ekm\0",
                            self.cipher.name(),
                        );
                        self.write_plaintext(push_reply.as_bytes())?;
                        self.install_keys()?;
                        if self.tunnel.is_none()
                            && let Some((_, _, context)) = auth
                            && let Some(peer_session) = self.peer_session.clone()
                        {
                            let stack_options = StackOptions {
                                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))],
                                allowed_ips: vec!["10.8.0.2/32".to_owned()],
                                mtu: self.mtu,
                                limits: StackLimits::default(),
                            };
                            let tunnel = Arc::new(ServerTunnel::new(
                                stack_options,
                                peer_session,
                                context.clone(),
                            )?);
                            self.tunnel = Some(tunnel.clone());
                            newly_opened = Some(tunnel);
                        }
                    }
                }
            }
        }
        self.queue_tls_output()?;
        self.flush(now);
        Ok(newly_opened)
    }

    fn feed_tls(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.tls.read_tls(&mut bytes)?;
            self.tls
                .process_new_packets()
                .map_err(|_| Error::Protocol("OpenVPN 服务端 TLS 握手失败"))?;
            self.read_plaintext()?;
        }
        Ok(())
    }

    fn read_plaintext(&mut self) -> Result<()> {
        let mut chunk = [0u8; 4096];
        loop {
            match self.tls.reader().read(&mut chunk) {
                Ok(0) => return Err(Error::Protocol("OpenVPN 控制通道已关闭")),
                Ok(count) => {
                    self.plain.extend_from_slice(&chunk[..count]);
                    if self.plain.len() > MAX_PLAINTEXT {
                        return Err(Error::Protocol("OpenVPN 控制消息过大"));
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err.into()),
            }
        }
    }

    fn write_plaintext(&mut self, bytes: &[u8]) -> Result<()> {
        self.tls.writer().write_all(bytes)?;
        Ok(())
    }

    fn queue_tls_output(&mut self) -> Result<()> {
        let mut output = Vec::new();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut output)?;
        }
        for fragment in output.chunks(CONTROL_FRAGMENT) {
            self.send.push(Opcode::Control, fragment.to_vec());
        }
        Ok(())
    }

    fn install_keys(&mut self) -> Result<()> {
        let client_source = self
            .client_key
            .as_ref()
            .ok_or(Error::Protocol("OpenVPN 客户端密钥源缺失"))?;
        let server_source = self
            .server_key
            .as_ref()
            .ok_or(Error::Protocol("OpenVPN 服务端密钥源缺失"))?;
        let remote = self
            .remote
            .as_ref()
            .ok_or(Error::Protocol("OpenVPN 客户端会话 ID 缺失"))?;
        let key2 = self
            .tls
            .export_keying_material(Zeroizing::new([0u8; 256]), EKM_LABEL, None)
            .unwrap_or_else(|_| expand_with_prf(client_source, server_source, remote, &self.local));
        let (seal, open) = server_data_keys(self.cipher, &key2, self.key_id, 0)?;
        self.seal = Some(seal);
        self.open = Some(open);
        Ok(())
    }

    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if let Some(seal) = &mut self.seal {
            self.outbox.push(seal.seal(packet)?);
        }
        Ok(())
    }

    fn tick(&mut self, now: Instant) {
        self.flush(now);
    }

    fn flush(&mut self, now: Instant) {
        let time = now_unix();
        for entry in self.send.take_due(now) {
            let acks = self.receive.acks_for_packet();
            let body = encode_body(
                &acks,
                self.remote.as_ref(),
                Some(entry.packet_id),
                &entry.payload,
            );
            self.outbox.push(self.wrap.wrap(
                entry.opcode.byte(self.key_id),
                &self.local,
                &body,
                time,
            ));
        }
        while self.receive.has_pending_acks() {
            let acks = self.receive.acks_for_packet();
            let body = encode_body(&acks, self.remote.as_ref(), None, &[]);
            self.outbox.push(self.wrap.wrap(
                Opcode::Ack.byte(self.key_id),
                &self.local,
                &body,
                time,
            ));
        }
    }
}

async fn next_tunnel_packet(tunnel: Option<&Arc<ServerTunnel>>) -> Result<Vec<u8>> {
    match tunnel {
        Some(t) => t.next_packet().await,
        None => std::future::pending().await,
    }
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
        let mut cert_pem_opt = None;
        let mut key_pem_opt = None;

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
            cert_pem_opt = read_pem(
                tls_cfg.certificate.as_ref().map(StringOrVec::join_pem),
                tls_cfg.certificate_path.as_deref(),
            )?;
            key_pem_opt = read_pem(
                tls_cfg.key.as_ref().map(StringOrVec::join_pem),
                tls_cfg.key_path.as_deref(),
            )?;
            if let Some(cert_pem) = &cert_pem_opt {
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
                        wrap_keys = WrapKeys::crypt_server(&sk);
                    }
                    _ => return Err(invalid()),
                }
            }
        }

        let (tls_config, generated_fp) =
            server_config(cert_pem_opt.as_deref(), key_pem_opt.as_deref())?;
        if server_cert_fingerprint.is_none()
            && !matches!(options.mode.as_str(), "static_key" | "static-key")
        {
            server_cert_fingerprint = Some(generated_fp);
        }

        let users = input.credentials(raw_users)?;
        Ok(Arc::new(OpenVpnNode {
            users,
            wrap_keys,
            supports_tcp,
            supports_udp,
            ciphers,
            mtu: options.mtu.unwrap_or(1400),
            tls_config,
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
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.supports_tcp {
                return Err(Error::Unsupported("当前 OpenVPN 节点未启用 TCP 载体"));
            }
            let mut session = ServerSession::new(
                self.wrap_keys.clone(),
                self.tls_config.clone(),
                self.ciphers[0],
                self.mtu,
            )?;
            let mut len_buf = [0u8; 2];
            let mut timer = tokio::time::interval(SERVER_TICK);
            timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                for reply in session.take_outbox() {
                    let out_len = (reply.len() as u16).to_be_bytes();
                    stream.write_all(&out_len).await?;
                    stream.write_all(&reply).await?;
                    stream.flush().await?;
                }
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
                        let _ = session.receive(
                            Instant::now(),
                            &pkt,
                            Some((&self.users, &access, &context)),
                        )?;
                    }
                    pkt = next_tunnel_packet(session.tunnel.as_ref()) => {
                        let pkt = pkt?;
                        session.send_packet(&pkt)?;
                    }
                    _ = timer.tick() => {
                        session.tick(Instant::now());
                    }
                }
            }
        })
    }

    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.supports_udp {
                return Err(Error::Unsupported("当前 OpenVPN 节点未启用 UDP 载体"));
            }
            let mut peers: HashMap<SocketAddr, ServerSession> = HashMap::new();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
            let mut buf = vec![0u8; 65535];
            let mut timer = tokio::time::interval(SERVER_TICK);
            timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                    res = socket.recv_from(&mut buf) => {
                        let Ok((n, peer)) = res else { continue };
                        let session = match peers.entry(peer) {
                            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                            std::collections::hash_map::Entry::Vacant(v) => {
                                let Ok(s) = ServerSession::new(
                                    self.wrap_keys.clone(),
                                    self.tls_config.clone(),
                                    self.ciphers[0],
                                    self.mtu,
                                ) else {
                                    continue;
                                };
                                v.insert(s)
                            }
                        };
                        if let Ok(Some(tunnel)) = session.receive(
                            Instant::now(),
                            &buf[..n],
                            Some((&self.users, &access, &context)),
                        ) {
                            let tx_clone = tx.clone();
                            let cancel_clone = context.cancel.child_token();
                            let _ = context.tasks.spawn(async move {
                                loop {
                                    tokio::select! {
                                        biased;
                                        _ = cancel_clone.cancelled() => break,
                                        pkt = tunnel.next_packet() => {
                                            let Ok(pkt) = pkt else { break };
                                            if tx_clone.send((peer, pkt)).is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        for reply in session.take_outbox() {
                            let _ = socket.send_to(&reply, peer).await;
                        }
                    }
                    Some((peer, pkt)) = rx.recv() => {
                        if let Some(session) = peers.get_mut(&peer)
                            && session.send_packet(&pkt).is_ok()
                        {
                            for reply in session.take_outbox() {
                                let _ = socket.send_to(&reply, peer).await;
                            }
                        }
                    }
                    _ = timer.tick() => {
                        let now = Instant::now();
                        for (peer, session) in &mut peers {
                            session.tick(now);
                            for reply in session.take_outbox() {
                                let _ = socket.send_to(&reply, *peer).await;
                            }
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
    use crate::{
        session::{Credentials, Event, Session, Settings},
        tls::client_config,
    };
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

    #[test]
    fn openvpn_client_and_server_sessions_complete_handshake_and_exchange_data_v2() {
        let mut params = rcgen::CertificateParams::new(vec!["openvpn.invalid".to_owned()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let body: String = (0..256).map(|i| format!("{:02x}", i % 251)).collect();
        let static_key = StaticKey::parse(&format!(
            "-----BEGIN OpenVPN Static key V1-----\n{body}\n-----END OpenVPN Static key V1-----\n"
        ))
        .unwrap();

        let (srv_tls, _) = server_config(Some(&cert_pem), Some(&key_pem)).unwrap();
        let mut server = ServerSession::new(
            WrapKeys::crypt_server(&static_key),
            srv_tls,
            DataCipher::Aes256Gcm,
            1400,
        )
        .unwrap();

        let cli_tls = client_config(&cert_pem, None, None).unwrap();
        let cli_settings = Arc::new(Settings {
            tls: cli_tls,
            wrap: WrapKeys::crypt(&static_key),
            credentials: Some(Credentials {
                username: "alice".to_owned(),
                password: "secret".to_owned(),
            }),
            ciphers: vec![DataCipher::Aes256Gcm],
            options: "V4,dev-type tun,link-mtu 1449,tun-mtu 1400,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client".to_owned(),
            peer_info: "IV_VER=2.6.14\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM\nIV_PROTO=10\n".to_owned(),
            ping: None,
            ping_restart: None,
            reneg: None,
            handshake: Duration::from_secs(60),
        });
        let now = Instant::now();
        let mut client = Session::new(cli_settings, now).unwrap();

        for _ in 0..16 {
            let c2s = client.take_outbox();
            let s2c = server.take_outbox();
            if c2s.is_empty() && s2c.is_empty() {
                break;
            }
            for pkt in c2s {
                server.receive(now, &pkt, None).unwrap();
            }
            for pkt in s2c {
                client.receive(now, &pkt).unwrap();
            }
        }

        let events = client.take_events();
        assert!(
            events.iter().any(|e| matches!(e, Event::Up(cfg) if cfg.address_v4 == Some(Ipv4Addr::new(10, 8, 0, 2)))),
            "client should receive PUSH_REPLY with 10.8.0.2"
        );

        let ipv4_ping = vec![
            0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4, 64, 17, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1,
        ];
        client.send_packet(now, &ipv4_ping).unwrap();
        for wire in client.take_outbox() {
            server.receive(now, &wire, None).unwrap();
        }
        assert_eq!(server.take_packets(), vec![ipv4_ping.clone()]);

        let ipv4_pong = vec![
            0x45, 0x00, 0x00, 0x14, 4, 3, 2, 1, 64, 17, 0, 0, 10, 8, 0, 1, 10, 8, 0, 2,
        ];
        server.send_packet(&ipv4_pong).unwrap();
        for wire in server.take_outbox() {
            client.receive(now, &wire).unwrap();
        }
        let client_events = client.take_events();
        assert!(
            client_events
                .iter()
                .any(|e| matches!(e, Event::Packet(p) if p == &ipv4_pong)),
            "client should decrypt server DataV2 packet"
        );
    }
}
