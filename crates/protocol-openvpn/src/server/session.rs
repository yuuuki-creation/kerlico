//! 不含 I/O 的服务端会话：控制通道握手、认证、NCP、推送、保活、换钥与数据通道。

use super::{
    options::{NodeWrap, SessionSettings, UserPush},
    registry::{Registry, Ticket},
};
use crate::{
    data::{DataCipher, OpenKey, PING, SealKey, server_data_keys},
    keys::{
        ClientKeyMessage, ClientKeySource, EKM_LABEL, ServerKeySource, expand_with_prf,
        read_client_key_method, write_server_key_method,
    },
    push::{KeyDerivation, ReplyContext, push_reply},
    reliable::{ReliableReceive, ReliableSend},
    wire::{Opcode, SessionId, decode_body, encode_body},
    wrap::{ControlWrap, CryptV2Metadata, Unwrapped},
};
use kerlico_core::{CancellationToken, Error, Result};
use kerlico_wireguard::ip::ServerTunnel;
use rand::{RngCore, rngs::OsRng};
use rustls::ServerConnection;
use std::{
    io::{ErrorKind, Read, Write},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};
use zeroize::Zeroizing;

const CONTROL_FRAGMENT: usize = 1100;
const MAX_PLAINTEXT: usize = 256 * 1024;
/// 上游 `occ_magic`；后随 1 字节操作码，`OCC_EXIT` 为 6。
const OCC_MAGIC: [u8; 16] = [
    0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
];
const OCC_EXIT: u8 = 6;
const REFUSAL_LINGER: std::time::Duration = std::time::Duration::from_secs(5);
const IV_PROTO_DATA_V2: u32 = 1 << 1;
const IV_PROTO_TLS_KEY_EXPORT: u32 = 1 << 3;
const IV_PROTO_CC_EXIT_NOTIFY: u32 = 1 << 7;

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as u32)
}

/// key-method 2 消息中服务端关心的 peer-info 字段。
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct PeerInfo {
    pub ciphers: Option<Vec<String>>,
    pub ncp: u32,
    pub proto: u32,
}
impl PeerInfo {
    pub fn parse(text: &str) -> Self {
        let mut info = Self::default();
        for line in text.lines() {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            match name {
                "IV_CIPHERS" => {
                    info.ciphers = Some(value.split(':').map(str::to_owned).collect());
                }
                "IV_NCP" => info.ncp = value.trim().parse().unwrap_or(0),
                "IV_PROTO" => info.proto = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        info
    }
}

/// 上游 NCP：按服务端 `data-ciphers` 顺序取第一个客户端也支持的算法。
/// 没有 `IV_CIPHERS` 的 2.4 客户端以 `IV_NCP=2` 声明支持两种 AES-GCM；再旧的客户端用 OCC 串里的 `cipher`，
/// 仍不在列表内时用 `data-ciphers-fallback`。
pub(crate) fn negotiate_cipher(
    server: &[DataCipher],
    fallback: Option<DataCipher>,
    peer: &PeerInfo,
    occ_options: &str,
) -> Option<DataCipher> {
    let offered: Vec<DataCipher> = match &peer.ciphers {
        Some(names) => names
            .iter()
            .filter_map(|name| DataCipher::parse(name))
            .collect(),
        None if peer.ncp >= 2 => vec![DataCipher::Aes256Gcm, DataCipher::Aes128Gcm],
        None => occ_options
            .split(',')
            .find_map(|option| option.strip_prefix("cipher "))
            .and_then(DataCipher::parse)
            .into_iter()
            .collect(),
    };
    server
        .iter()
        .copied()
        .find(|cipher| offered.contains(cipher))
        .or(fallback)
}

pub(crate) struct AuthRequest<'a> {
    pub username: &'a str,
    pub password: &'a str,
    /// TLS 层已校验的客户端证书 CN。
    pub common_name: Option<&'a str>,
}

/// 认证通过后的会话授权；`tunnel` 为空时数据包留在会话内（仅单元测试）。
pub(crate) struct Grant {
    pub push: UserPush,
    pub tunnel: Option<Arc<ServerTunnel>>,
}

pub(crate) trait Gate {
    /// 首次协商：校验凭据，在 `ticket` 上登记身份与地址，建立数据面。
    fn admit(
        &mut self,
        ticket: &mut Ticket,
        request: &AuthRequest<'_>,
    ) -> std::result::Result<Grant, &'static str>;
    /// 换钥时客户端重发凭据，必须仍对应同一身份。
    fn readmit(&mut self, request: &AuthRequest<'_>, identity: &str) -> bool;
}

/// `receive` 的结果：首次建立数据面时把隧道交给 I/O 层转发。
pub(crate) enum Step {
    Idle,
    Opened(Arc<ServerTunnel>),
    Closed,
}

struct Negotiation {
    key_id: u8,
    tls: ServerConnection,
    plain: Vec<u8>,
    send: ReliableSend,
    receive: ReliableReceive,
    started: Instant,
    client: Option<ClientKeySource>,
    server: Option<ServerKeySource>,
    /// 新密钥已派生、等待控制包全部确认后再切换发送方向。
    pending_seal: Option<SealKey>,
}
impl Negotiation {
    fn new(
        tls: &Arc<rustls::ServerConfig>,
        key_id: u8,
        reset: Opcode,
        now: Instant,
    ) -> Result<Self> {
        let connection = ServerConnection::new(tls.clone())
            .map_err(|_| Error::Protocol("OpenVPN 服务端 TLS 会话创建失败"))?;
        let mut send = ReliableSend::default();
        send.push(reset, Vec::new());
        Ok(Self {
            key_id,
            tls: connection,
            plain: Vec::new(),
            send,
            receive: ReliableReceive::default(),
            started: now,
            client: None,
            server: None,
            pending_seal: None,
        })
    }
    fn exchanged(&self) -> bool {
        self.server.is_some()
    }
    fn settled(&self) -> bool {
        self.exchanged() && self.pending_seal.is_none()
    }
    fn feed_tls(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.tls.read_tls(&mut bytes)?;
            self.tls
                .process_new_packets()
                .map_err(|error| match error {
                    rustls::Error::InvalidCertificate(_)
                    | rustls::Error::NoCertificatesPresented => Error::Rejected,
                    _ => Error::Protocol("OpenVPN 服务端 TLS 握手失败"),
                })?;
            loop {
                let mut chunk = [0; 4096];
                match self.tls.reader().read(&mut chunk) {
                    Ok(0) => return Err(Error::Protocol("OpenVPN 控制通道已关闭")),
                    Ok(count) => {
                        self.plain.extend_from_slice(&chunk[..count]);
                        if self.plain.len() > MAX_PLAINTEXT {
                            return Err(Error::Protocol("OpenVPN 控制消息过大"));
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
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
    fn common_name(&self) -> Option<String> {
        let leaf = self.tls.peer_certificates()?.first()?;
        let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;
        let name = parsed.subject().iter_common_name().next()?.as_str().ok()?;
        Some(name.to_owned())
    }
}

/// 首次认证后固定下来的会话参数，换钥沿用。
struct Admitted {
    identity: String,
    cipher: DataCipher,
    derivation: KeyDerivation,
    peer_id: u32,
    push: Vec<Vec<u8>>,
}

pub(crate) struct ServerSession {
    settings: Arc<SessionSettings>,
    tls: Arc<rustls::ServerConfig>,
    wrap: ControlWrap,
    local: SessionId,
    remote: SessionId,
    ticket: Ticket,
    negotiation: Negotiation,
    next_key_id: u8,
    admitted: Option<Admitted>,
    up: bool,
    /// 已发出 `AUTH_FAILED`：继续重传直到对端确认或超时，然后关闭。
    closing: Option<Instant>,
    refusal: Option<&'static str>,
    seal: Option<SealKey>,
    open: [Option<OpenKey>; 2],
    retire_at: Option<Instant>,
    last_received: Instant,
    last_sent: Instant,
    keyed_at: Instant,
    traffic_bytes: u64,
    traffic_packets: u64,
    tunnel: Option<Arc<ServerTunnel>>,
    cancel: CancellationToken,
    outbox: Vec<Vec<u8>>,
    #[cfg(test)]
    packets: Vec<Vec<u8>>,
}

/// 只有密钥 ID 0 的硬重置能新建会话。
pub(crate) fn is_initial_reset(wire: &[u8]) -> bool {
    matches!(
        wire.first().copied().and_then(Opcode::parse),
        Some((Opcode::HardResetClient | Opcode::HardResetClientV3, 0))
    )
}

pub(crate) fn wire_session(wire: &[u8]) -> Option<SessionId> {
    wire.get(1..9)?.try_into().ok()
}

impl ServerSession {
    /// 认证首个硬重置并占用 `max-clients` 名额；包无法认证或名额已满时返回 `None`，调用方静默丢弃。
    pub fn start(
        settings: Arc<SessionSettings>,
        tls: Arc<rustls::ServerConfig>,
        wrap: &NodeWrap,
        registry: &Arc<Registry>,
        cancel: CancellationToken,
        now: Instant,
        wire: &[u8],
    ) -> Option<(Self, Unwrapped)> {
        if !is_initial_reset(wire) {
            return None;
        }
        let (mut control, unwrapped) = match wrap {
            NodeWrap::Fixed(keys) => {
                if wire[0] >> 3 != 7 {
                    return None;
                }
                let control = ControlWrap::new((**keys).clone());
                let unwrapped = control.unwrap(wire).ok()?;
                (control, unwrapped)
            }
            NodeWrap::CryptV2 { key, max_age } => {
                let (packet, keys, metadata) = key.open_reset(wire)?;
                if let (Some(limit), CryptV2Metadata::Timestamp(stamp)) = (max_age, &metadata)
                    && u64::from(now_unix()).saturating_sub(*stamp) > limit.as_secs()
                {
                    return None;
                }
                let control = ControlWrap::new(keys);
                let unwrapped = control.unwrap(packet).ok()?;
                (control, unwrapped)
            }
        };
        if !control.commit(unwrapped.replay) {
            return None;
        }
        let ticket = registry.admit().ok()?;
        let mut local = [0; 8];
        OsRng.fill_bytes(&mut local);
        let negotiation = Negotiation::new(&tls, 0, Opcode::HardResetServer, now).ok()?;
        let session = Self {
            settings,
            tls,
            wrap: control,
            local,
            remote: unwrapped.session,
            ticket,
            negotiation,
            next_key_id: 1,
            admitted: None,
            up: false,
            closing: None,
            refusal: None,
            seal: None,
            open: [None, None],
            retire_at: None,
            last_received: now,
            last_sent: now,
            keyed_at: now,
            traffic_bytes: 0,
            traffic_packets: 0,
            tunnel: None,
            cancel,
            outbox: Vec::new(),
            #[cfg(test)]
            packets: Vec::new(),
        };
        Some((session, unwrapped))
    }

    pub fn remote(&self) -> SessionId {
        self.remote
    }

    pub fn cancel(&self) -> &CancellationToken {
        &self.cancel
    }

    pub fn tunnel_handle(&self) -> Option<Arc<ServerTunnel>> {
        self.tunnel.clone()
    }

    pub fn take_outbox(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox)
    }

    #[cfg(test)]
    pub fn take_packets(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.packets)
    }

    /// 处理 `start` 返回的首个包。
    pub fn begin(&mut self, now: Instant, first: Unwrapped, gate: &mut dyn Gate) -> Result<Step> {
        self.control(now, first, gate)
    }

    pub fn receive(&mut self, now: Instant, wire: &[u8], gate: &mut dyn Gate) -> Result<Step> {
        let Some((opcode, key_id)) = wire.first().copied().and_then(Opcode::parse) else {
            return Ok(Step::Idle);
        };
        if opcode == Opcode::DataV2 {
            return Ok(self.data(now, key_id, wire));
        }
        let Ok(unwrapped) = self.wrap.unwrap(wire) else {
            return Ok(Step::Idle);
        };
        if unwrapped.session != self.remote || !self.wrap.commit(unwrapped.replay) {
            return Ok(Step::Idle);
        }
        self.control(now, unwrapped, gate)
    }

    fn data(&mut self, now: Instant, key_id: u8, wire: &[u8]) -> Step {
        let Some(key) = self
            .open
            .iter_mut()
            .flatten()
            .find(|key| key.key_id() == key_id)
        else {
            return Step::Idle;
        };
        let Some(plain) = key.open(wire) else {
            return Step::Idle;
        };
        self.last_received = now;
        self.traffic_bytes += plain.len() as u64;
        self.traffic_packets += 1;
        if plain == PING {
            return Step::Idle;
        }
        if plain.len() == OCC_MAGIC.len() + 1 && plain[..16] == OCC_MAGIC && plain[16] == OCC_EXIT {
            return Step::Closed;
        }
        if matches!(plain.first().map(|byte| byte >> 4), Some(4 | 6)) {
            if let Some(tunnel) = &self.tunnel {
                let _ = tunnel.receive(&plain);
            } else {
                #[cfg(test)]
                self.packets.push(plain);
            }
        }
        Step::Idle
    }

    fn control(&mut self, now: Instant, unwrapped: Unwrapped, gate: &mut dyn Gate) -> Result<Step> {
        let Some((opcode, key_id)) = Opcode::parse(unwrapped.header) else {
            return Ok(Step::Idle);
        };
        let Ok(body) = decode_body(opcode, &unwrapped.body) else {
            return Ok(Step::Idle);
        };
        if body
            .ack_session
            .is_some_and(|session| session != self.local)
        {
            return Ok(Step::Idle);
        }
        self.last_received = now;
        if opcode == Opcode::SoftReset
            && key_id != self.negotiation.key_id
            && (1..=7).contains(&key_id)
            && self.up
        {
            self.begin_rekey(now, key_id)?;
        }
        if key_id != self.negotiation.key_id {
            return Ok(Step::Idle);
        }
        for ack in &body.acks {
            self.negotiation.send.ack(*ack);
        }
        if let Some(packet_id) = body.packet_id {
            self.negotiation
                .receive
                .accept(packet_id, opcode, body.payload);
        }
        self.advance(now, gate)
    }

    fn begin_rekey(&mut self, now: Instant, key_id: u8) -> Result<()> {
        self.negotiation = Negotiation::new(&self.tls, key_id, Opcode::SoftReset, now)?;
        // 上游 key_id 在 1..=7 循环，0 只属于首次协商。
        self.next_key_id = key_id % 7 + 1;
        Ok(())
    }

    fn refuse(&mut self, now: Instant, reason: &str) -> Result<Step> {
        let message = if reason.is_empty() {
            "AUTH_FAILED\0".to_owned()
        } else {
            format!("AUTH_FAILED,{reason}\0")
        };
        self.negotiation.write(message.as_bytes())?;
        self.negotiation.queue_tls_output()?;
        self.flush(now);
        self.closing = Some(now + REFUSAL_LINGER);
        Ok(Step::Idle)
    }

    fn advance(&mut self, now: Instant, gate: &mut dyn Gate) -> Result<Step> {
        let mut step = Step::Idle;
        while let Some((opcode, payload)) = self.negotiation.receive.pop_ready() {
            if opcode == Opcode::Control
                && let Err(error) = self.negotiation.feed_tls(&payload)
            {
                // 把 rustls 排队的 TLS alert 送出，客户端可立即得知握手被拒。
                let _ = self.negotiation.queue_tls_output();
                self.flush(now);
                return Err(error);
            }
        }
        if self.closing.is_none() && !self.negotiation.tls.is_handshaking() {
            if !self.negotiation.exchanged()
                && let Some((consumed, message)) = read_client_key_method(&self.negotiation.plain)?
            {
                self.negotiation.plain.drain(..consumed);
                match self.key_exchange(message, gate)? {
                    Some(refusal) if self.up => return self.refuse(now, refusal),
                    refusal => self.refusal = refusal,
                }
            }
            if self.negotiation.exchanged() {
                while let Some(end) = self.negotiation.plain.iter().position(|byte| *byte == 0) {
                    let message: Vec<u8> = self.negotiation.plain.drain(..=end).collect();
                    match &message[..end] {
                        b"PUSH_REQUEST" => {
                            if let Some(reason) = self.refusal {
                                return self.refuse(now, reason);
                            }
                            if let Some(tunnel) = self.push(now)? {
                                step = Step::Opened(tunnel);
                            }
                        }
                        b"EXIT" => step = Step::Closed,
                        _ => {}
                    }
                }
            }
        }
        self.negotiation.queue_tls_output()?;
        self.flush(now);
        Ok(step)
    }

    /// 返回 `Some` 时以该原因拒绝客户端。与上游一样照常回 key-method 消息，
    /// 首次协商等客户端发出 `PUSH_REQUEST` 再回 `AUTH_FAILED`。
    fn key_exchange(
        &mut self,
        message: ClientKeyMessage,
        gate: &mut dyn Gate,
    ) -> Result<Option<&'static str>> {
        let refusal = self.authorize(&message, gate)?;
        let cipher = self
            .admitted
            .as_ref()
            .map_or(DataCipher::Aes256Gcm, |a| a.cipher);
        let options = format!(
            "V4,dev-type tun,link-mtu {},tun-mtu {},proto {},cipher {},auth [null-digest],keysize {},key-method 2,tls-server",
            self.settings.mtu + 49,
            self.settings.mtu,
            if self.settings.tcp {
                "TCPv4_SERVER"
            } else {
                "UDPv4"
            },
            cipher.name(),
            cipher.key_bits(),
        );
        let server = ServerKeySource::generate();
        let reply = Zeroizing::new(write_server_key_method(&server, &options)?);
        self.negotiation.write(&reply)?;
        self.negotiation.client = Some(message.source);
        self.negotiation.server = Some(server);
        if refusal.is_none() && self.up {
            let (seal, open) = self.derive_keys()?;
            self.install_open(open);
            self.negotiation.pending_seal = Some(seal);
        }
        Ok(refusal)
    }

    fn authorize(
        &mut self,
        message: &ClientKeyMessage,
        gate: &mut dyn Gate,
    ) -> Result<Option<&'static str>> {
        let common_name = self.negotiation.common_name();
        let request = AuthRequest {
            username: &message.username,
            password: &message.password,
            common_name: common_name.as_deref(),
        };
        match &self.admitted {
            None => {
                let peer = PeerInfo::parse(&message.peer_info);
                if peer.proto & IV_PROTO_DATA_V2 == 0 && peer.ciphers.is_none() && peer.ncp < 2 {
                    return Ok(Some("client does not support P_DATA_V2"));
                }
                let Some(cipher) = negotiate_cipher(
                    &self.settings.ciphers,
                    self.settings.fallback,
                    &peer,
                    &message.options,
                ) else {
                    return Ok(Some(
                        "Data channel cipher negotiation failed (no shared cipher)",
                    ));
                };
                let grant = match gate.admit(&mut self.ticket, &request) {
                    Ok(grant) => grant,
                    Err(reason) => return Ok(Some(reason)),
                };
                let lease = self
                    .ticket
                    .lease()
                    .cloned()
                    .ok_or(Error::Protocol("OpenVPN 会话未分配地址"))?;
                let derivation =
                    if !self.settings.allow_ekm || peer.proto & IV_PROTO_TLS_KEY_EXPORT == 0 {
                        KeyDerivation::Prf
                    } else if peer.proto & IV_PROTO_CC_EXIT_NOTIFY != 0 {
                        KeyDerivation::EkmProtocolFlag
                    } else {
                        KeyDerivation::EkmLegacyFlag
                    };
                let mut lines = self.settings.push_lines.clone();
                lines.extend(grant.push.lines.iter().cloned());
                let push = push_reply(
                    &lines,
                    &ReplyContext {
                        assignment: &lease.assignment,
                        ping: grant.push.ping.or(self.settings.push_ping),
                        ping_restart: grant.push.ping_restart.or(self.settings.push_ping_restart),
                        peer_id: lease.peer_id,
                        cipher: cipher.name(),
                        key_derivation: derivation,
                        cc_exit: peer.proto & IV_PROTO_CC_EXIT_NOTIFY != 0,
                        tun_mtu: (self.settings.mtu != 1500).then_some(self.settings.mtu),
                    },
                );
                self.tunnel = grant.tunnel;
                self.admitted = Some(Admitted {
                    identity: lease.identity.clone(),
                    cipher,
                    derivation,
                    peer_id: lease.peer_id,
                    push,
                });
            }
            Some(admitted) => {
                if !gate.readmit(&request, &admitted.identity) {
                    return Ok(Some(""));
                }
            }
        }
        Ok(None)
    }

    fn derive_keys(&self) -> Result<(SealKey, OpenKey)> {
        let admitted = self
            .admitted
            .as_ref()
            .ok_or(Error::Protocol("OpenVPN 会话尚未认证"))?;
        let negotiation = &self.negotiation;
        let (Some(client), Some(server)) = (&negotiation.client, &negotiation.server) else {
            return Err(Error::Protocol("OpenVPN 密钥交换未完成"));
        };
        let key2 = match admitted.derivation {
            KeyDerivation::Prf => expand_with_prf(client, server, &self.remote, &self.local),
            KeyDerivation::EkmLegacyFlag | KeyDerivation::EkmProtocolFlag => negotiation
                .tls
                .export_keying_material(Zeroizing::new([0; 256]), EKM_LABEL, None)
                .map_err(|_| Error::Protocol("OpenVPN TLS 密钥导出失败"))?,
        };
        server_data_keys(
            admitted.cipher,
            &key2,
            negotiation.key_id,
            admitted.peer_id,
            self.settings.replay,
        )
    }

    fn install_open(&mut self, open: OpenKey) {
        let previous = self.open[0].take();
        self.retire_at = previous
            .is_some()
            .then(|| Instant::now() + self.settings.transition_window);
        self.open = [Some(open), previous];
    }

    /// 首次 `PUSH_REQUEST` 安装数据通道密钥；重复请求只重发同一份推送。
    fn push(&mut self, now: Instant) -> Result<Option<Arc<ServerTunnel>>> {
        let messages = self
            .admitted
            .as_ref()
            .map(|admitted| admitted.push.clone())
            .ok_or(Error::Protocol("OpenVPN 会话尚未认证"))?;
        for message in &messages {
            self.negotiation.write(message)?;
        }
        if self.up {
            return Ok(None);
        }
        let (seal, open) = self.derive_keys()?;
        self.seal = Some(seal);
        self.install_open(open);
        self.up = true;
        self.keyed_at = now;
        self.last_sent = now;
        Ok(self.tunnel.clone())
    }

    pub fn send_packet(&mut self, now: Instant, packet: &[u8]) -> Result<()> {
        let Some(seal) = &mut self.seal else {
            return Ok(());
        };
        self.outbox.push(seal.seal(packet)?);
        self.last_sent = now;
        self.traffic_bytes += packet.len() as u64;
        self.traffic_packets += 1;
        Ok(())
    }

    pub fn tick(&mut self, now: Instant) -> Result<()> {
        if let Some(deadline) = self.closing {
            self.flush(now);
            if now >= deadline || self.negotiation.send.is_empty() {
                return Err(Error::Rejected);
            }
            return Ok(());
        }
        if self.ticket.kicked().is_cancelled() {
            return Err(Error::Cancelled);
        }
        if !self.negotiation.settled()
            && now.duration_since(self.negotiation.started) >= self.settings.handshake_window
        {
            return Err(Error::Timeout);
        }
        if self.negotiation.pending_seal.is_some() && self.negotiation.send.is_empty() {
            self.seal = self.negotiation.pending_seal.take();
            self.keyed_at = now;
            self.traffic_bytes = 0;
            self.traffic_packets = 0;
        }
        if self.retire_at.is_some_and(|at| now >= at) {
            self.open[1] = None;
            self.retire_at = None;
        }
        if self.up {
            if self
                .settings
                .ping_restart
                .is_some_and(|limit| now.duration_since(self.last_received) >= limit)
            {
                return Err(Error::Timeout);
            }
            if self
                .settings
                .ping
                .is_some_and(|every| now.duration_since(self.last_sent) >= every)
            {
                self.send_packet(now, &PING)?;
            }
            let settings = &self.settings;
            let due = settings
                .reneg_interval
                .is_some_and(|every| now.duration_since(self.keyed_at) >= every)
                || settings
                    .reneg_bytes
                    .is_some_and(|limit| self.traffic_bytes >= limit)
                || settings
                    .reneg_packets
                    .is_some_and(|limit| self.traffic_packets >= limit)
                || self.seal.as_ref().is_some_and(SealKey::needs_rekey);
            if due && self.negotiation.settled() {
                self.begin_rekey(now, self.next_key_id)?;
            }
        }
        self.flush(now);
        Ok(())
    }

    fn flush(&mut self, now: Instant) {
        let time = now_unix();
        let key_id = self.negotiation.key_id;
        let Negotiation { send, receive, .. } = &mut self.negotiation;
        for entry in send.take_due(now) {
            let acks = receive.acks_for_packet();
            let body = encode_body(
                &acks,
                Some(&self.remote),
                Some(entry.packet_id),
                &entry.payload,
            );
            self.outbox.push(
                self.wrap
                    .wrap(entry.opcode.byte(key_id), &self.local, &body, time),
            );
        }
        while receive.has_pending_acks() {
            let acks = receive.acks_for_packet();
            let body = encode_body(&acks, Some(&self.remote), None, &[]);
            self.outbox.push(
                self.wrap
                    .wrap(Opcode::Ack.byte(key_id), &self.local, &body, time),
            );
        }
    }
}
impl Drop for ServerSession {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(tunnel) = &self.tunnel {
            tunnel.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ncp_picks_the_first_server_cipher_the_client_offers() {
        let server = [
            DataCipher::Chacha20Poly1305,
            DataCipher::Aes128Gcm,
            DataCipher::Aes256Gcm,
        ];
        let modern = PeerInfo::parse(
            "IV_VER=2.6.20\nIV_PROTO=990\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM:AES-128-GCM\n",
        );
        assert_eq!(modern.proto, 990);
        assert_eq!(
            negotiate_cipher(&server, None, &modern, ""),
            Some(DataCipher::Aes128Gcm),
            "server order wins"
        );
        let legacy = PeerInfo::parse("IV_VER=2.4.12\nIV_NCP=2\nIV_PROTO=2\n");
        assert_eq!(
            negotiate_cipher(
                &[DataCipher::Chacha20Poly1305, DataCipher::Aes256Gcm],
                None,
                &legacy,
                ""
            ),
            Some(DataCipher::Aes256Gcm)
        );
        let ancient = PeerInfo::parse("IV_VER=2.3.18\n");
        assert_eq!(
            negotiate_cipher(&server, None, &ancient, "V4,cipher AES-256-GCM,auth SHA1"),
            Some(DataCipher::Aes256Gcm)
        );
        assert_eq!(
            negotiate_cipher(&server, None, &ancient, "V4,cipher BF-CBC"),
            None
        );
        assert_eq!(
            negotiate_cipher(
                &server,
                Some(DataCipher::Aes128Gcm),
                &ancient,
                "V4,cipher BF-CBC"
            ),
            Some(DataCipher::Aes128Gcm),
            "data-ciphers-fallback"
        );
        let only_chacha = PeerInfo::parse("IV_CIPHERS=CHACHA20-POLY1305\n");
        assert_eq!(
            negotiate_cipher(&[DataCipher::Aes256Gcm], None, &only_chacha, ""),
            None
        );
    }
}
