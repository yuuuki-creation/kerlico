//! 不含 I/O 的客户端会话状态机：控制通道握手、换钥、推送配置与数据通道加解密。

use crate::{
    data::{DataCipher, OpenKey, PING, SealKey, data_keys},
    keys::{
        ClientKeySource, EKM_LABEL, KeyMessage, ServerKeySource, expand_with_prf, read_key_method,
        write_key_method,
    },
    push::{ControlMessage, PushedConfig, classify},
    reliable::{ReliableReceive, ReliableSend},
    wire::{Opcode, SessionId, decode_body, encode_body},
    wrap::{ControlWrap, WrapKeys},
};
use kerlico_core::{Error, Result};
use rand::{RngCore, rngs::OsRng};
use rustls::{ClientConnection, pki_types::ServerName};
use std::{
    io::{ErrorKind, Read, Write},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// 单个控制包的 TLS 负载上限，低于上游默认 `tls-mtu 1250` 并留出包装开销。
const CONTROL_FRAGMENT: usize = 1100;
const PUSH_RETRY: Duration = Duration::from_secs(2);
const MAX_PLAINTEXT: usize = 256 * 1024;

pub(crate) struct Credentials {
    pub username: String,
    pub password: String,
}

pub(crate) struct Settings {
    pub tls: Arc<rustls::ClientConfig>,
    pub wrap: WrapKeys,
    pub credentials: Option<Credentials>,
    pub ciphers: Vec<DataCipher>,
    pub options: String,
    pub peer_info: String,
    pub ping: Option<Duration>,
    pub ping_restart: Option<Duration>,
    pub reneg: Option<Duration>,
    pub handshake: Duration,
}

pub(crate) enum Event {
    Up(PushedConfig),
    Packet(Vec<u8>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    /// 双方的 reset 包尚未互相确认。
    Reset,
    Tls,
    AwaitKeys,
    Ready,
}

/// 一个 key_id 的完整控制通道状态；上游每次换钥都重新握手 TLS 并重置可靠层序号。
struct Negotiation {
    key_id: u8,
    phase: Phase,
    peer_reset: bool,
    deadline: Instant,
    tls: ClientConnection,
    plain: Vec<u8>,
    source: ClientKeySource,
    server: Option<ServerKeySource>,
    send: ReliableSend,
    receive: ReliableReceive,
}
impl Negotiation {
    fn new(settings: &Settings, key_id: u8, reset: Opcode, now: Instant) -> Result<Self> {
        let name = ServerName::try_from("openvpn.invalid")
            .map_err(|_| Error::Protocol("OpenVPN TLS 会话创建失败"))?;
        let tls = ClientConnection::new(settings.tls.clone(), name)
            .map_err(|_| Error::Protocol("OpenVPN TLS 会话创建失败"))?;
        let mut send = ReliableSend::default();
        send.push(reset, Vec::new());
        Ok(Self {
            key_id,
            phase: Phase::Reset,
            peer_reset: false,
            deadline: now + settings.handshake,
            tls,
            plain: Vec::new(),
            source: ClientKeySource::generate(),
            server: None,
            send,
            receive: ReliableReceive::default(),
        })
    }
    fn feed_tls(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.tls.read_tls(&mut bytes)?;
            self.tls.process_new_packets().map_err(tls_failure)?;
            self.read_plaintext()?;
        }
        Ok(())
    }
    fn read_plaintext(&mut self) -> Result<()> {
        let mut chunk = [0; 4096];
        loop {
            match self.tls.reader().read(&mut chunk) {
                Ok(0) => return Err(Error::Protocol("OpenVPN 控制通道已关闭")),
                Ok(count) => {
                    self.plain.extend_from_slice(&chunk[..count]);
                    if self.plain.len() > MAX_PLAINTEXT {
                        return Err(Error::Protocol("OpenVPN 控制消息过大"));
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
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
}
fn tls_failure(error: rustls::Error) -> Error {
    match error {
        rustls::Error::InvalidCertificate(_) => Error::Protocol("OpenVPN 服务端证书校验失败"),
        rustls::Error::AlertReceived(_) => Error::Protocol("OpenVPN 服务端拒绝了 TLS 握手"),
        _ => Error::Protocol("OpenVPN TLS 握手失败"),
    }
}

#[derive(Clone, Copy)]
struct Negotiated {
    cipher: DataCipher,
    peer_id: u32,
    tls_ekm: bool,
}
enum Pull {
    Waiting {
        collected: PushedConfig,
        next_request: Option<Instant>,
    },
    Done(Negotiated),
}

pub(crate) struct Session {
    settings: Arc<Settings>,
    wrap: ControlWrap,
    local: SessionId,
    remote: Option<SessionId>,
    negotiation: Negotiation,
    next_key_id: u8,
    pull: Pull,
    seal: Option<SealKey>,
    /// 当前与上一把接收密钥；换钥后对端仍可能发送旧 key_id 的在途包。
    open: [Option<OpenKey>; 2],
    auth_token: Option<String>,
    ping: Option<Duration>,
    ping_restart: Option<Duration>,
    last_sent: Instant,
    last_received: Instant,
    negotiated_at: Instant,
    outbox: Vec<Vec<u8>>,
    events: Vec<Event>,
}
impl Session {
    pub fn new(settings: Arc<Settings>, now: Instant) -> Result<Self> {
        let mut local = [0; 8];
        OsRng.fill_bytes(&mut local);
        let negotiation = Negotiation::new(&settings, 0, Opcode::HardResetClient, now)?;
        let mut session = Self {
            wrap: ControlWrap::new(settings.wrap.clone()),
            local,
            remote: None,
            negotiation,
            next_key_id: 1,
            pull: Pull::Waiting {
                collected: PushedConfig::default(),
                next_request: None,
            },
            seal: None,
            open: [None, None],
            auth_token: None,
            ping: settings.ping,
            ping_restart: settings.ping_restart,
            last_sent: now,
            last_received: now,
            negotiated_at: now,
            outbox: Vec::new(),
            events: Vec::new(),
            settings,
        };
        session.flush(now);
        Ok(session)
    }
    pub fn take_outbox(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox)
    }
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// 处理一个载体包。认证失败的包直接丢弃：UDP 上任何人都能发送，不应影响会话。
    pub fn receive(&mut self, now: Instant, wire: &[u8]) -> Result<()> {
        let Some((opcode, key_id)) = wire.first().copied().and_then(Opcode::parse) else {
            return Ok(());
        };
        if opcode == Opcode::DataV2 {
            self.receive_data(now, key_id, wire);
            return Ok(());
        }
        self.receive_control(now, wire)
    }
    fn receive_data(&mut self, now: Instant, key_id: u8, wire: &[u8]) {
        let mut keys = self.open.iter_mut().flatten();
        let Some(key) = keys.find(|key| key.key_id() == key_id) else {
            return;
        };
        let Some(plain) = key.open(wire) else { return };
        self.last_received = now;
        // 保活与 OCC 消息的首半字节都不是 IP 版本号。
        if plain != PING && matches!(plain.first().map(|byte| byte >> 4), Some(4 | 6)) {
            self.events.push(Event::Packet(plain));
        }
    }
    fn receive_control(&mut self, now: Instant, wire: &[u8]) -> Result<()> {
        let Ok(unwrapped) = self.wrap.unwrap(wire) else {
            return Ok(());
        };
        let Some((opcode, key_id)) = Opcode::parse(unwrapped.header) else {
            return Ok(());
        };
        let Ok(body) = decode_body(opcode, &unwrapped.body) else {
            return Ok(());
        };
        if body
            .ack_session
            .is_some_and(|session| session != self.local)
        {
            return Ok(());
        }
        // 只有回显本端随机会话 ID 的包才能绑定对端：静态密钥下旧会话的包可被重放，但它们回显的是旧 ID。
        // 上游 2.4 重传 reset 时不带 ACK，确认由单独的 P_ACK 送达，所以不限定操作码。
        match self.remote {
            Some(remote) if remote != unwrapped.session => return Ok(()),
            None if body.ack_session.is_none() => return Ok(()),
            _ => {}
        }
        if !self.wrap.commit(unwrapped.replay) {
            return Ok(());
        }
        self.remote = Some(unwrapped.session);
        if opcode == Opcode::SoftReset
            && key_id != self.negotiation.key_id
            && key_id == self.next_key_id
            && matches!(self.pull, Pull::Done(_))
        {
            self.begin_rekey(now)?;
        }
        if key_id != self.negotiation.key_id {
            return Ok(());
        }
        self.last_received = now;
        for ack in &body.acks {
            self.negotiation.send.ack(*ack);
        }
        if let Some(packet_id) = body.packet_id {
            self.negotiation
                .receive
                .accept(packet_id, opcode, body.payload);
        }
        self.advance(now)
    }

    pub fn send_packet(&mut self, now: Instant, packet: &[u8]) -> Result<()> {
        let Some(seal) = &mut self.seal else {
            return Ok(());
        };
        self.outbox.push(seal.seal(packet)?);
        self.last_sent = now;
        Ok(())
    }

    pub fn tick(&mut self, now: Instant) -> Result<()> {
        let up = matches!(self.pull, Pull::Done(_));
        let settled = up && self.negotiation.phase == Phase::Ready;
        if !settled && now >= self.negotiation.deadline {
            return Err(Error::Timeout);
        }
        if let Pull::Waiting {
            next_request: Some(at),
            ..
        } = self.pull
            && now >= at
        {
            self.request_push(now)?;
        }
        if up {
            if self
                .ping_restart
                .is_some_and(|limit| now - self.last_received >= limit)
            {
                return Err(Error::Timeout);
            }
            if self.ping.is_some_and(|every| now - self.last_sent >= every) {
                self.send_packet(now, &PING)?;
            }
        }
        if settled
            && (self
                .settings
                .reneg
                .is_some_and(|every| now - self.negotiated_at >= every)
                || self.seal.as_ref().is_some_and(SealKey::needs_rekey))
        {
            self.begin_rekey(now)?;
        }
        self.advance(now)
    }

    fn begin_rekey(&mut self, now: Instant) -> Result<()> {
        self.negotiation =
            Negotiation::new(&self.settings, self.next_key_id, Opcode::SoftReset, now)?;
        // 上游 key_id 在 1..=7 循环，0 只属于首次协商。
        self.next_key_id = if self.next_key_id == 7 {
            1
        } else {
            self.next_key_id + 1
        };
        Ok(())
    }

    fn advance(&mut self, now: Instant) -> Result<()> {
        while let Some((opcode, payload)) = self.negotiation.receive.pop_ready() {
            match opcode {
                Opcode::Control => self.negotiation.feed_tls(&payload)?,
                Opcode::HardResetServer | Opcode::SoftReset => self.negotiation.peer_reset = true,
                _ => {}
            }
        }
        let negotiation = &mut self.negotiation;
        if negotiation.phase == Phase::Reset
            && negotiation.peer_reset
            && negotiation.send.is_empty()
        {
            negotiation.phase = Phase::Tls;
        }
        if negotiation.phase != Phase::Reset {
            if negotiation.phase == Phase::Tls && !negotiation.tls.is_handshaking() {
                self.send_key_method()?;
                self.negotiation.phase = Phase::AwaitKeys;
            }
            if self.negotiation.phase == Phase::AwaitKeys
                && let Some(server) = read_key_method(&self.negotiation.plain)?
            {
                self.negotiation.server = Some(server);
                self.negotiation.plain.clear();
                self.negotiation.phase = Phase::Ready;
                self.on_keys_exchanged(now)?;
            }
            if self.negotiation.phase == Phase::Ready {
                self.read_messages(now)?;
            }
            self.negotiation.queue_tls_output()?;
        }
        self.flush(now);
        Ok(())
    }

    fn send_key_method(&mut self) -> Result<()> {
        let credentials = self.settings.credentials.as_ref();
        let message = KeyMessage {
            options: &self.settings.options,
            username: credentials.map(|value| value.username.as_str()),
            // 服务端下发 auth-token 后，换钥时用它代替原密码，避免一次性密码类认证失败。
            password: self
                .auth_token
                .as_deref()
                .or(credentials.map(|value| value.password.as_str())),
            peer_info: &self.settings.peer_info,
        };
        let bytes = Zeroizing::new(write_key_method(&self.negotiation.source, &message)?);
        self.negotiation.write_plaintext(&bytes)
    }

    fn on_keys_exchanged(&mut self, now: Instant) -> Result<()> {
        match self.pull {
            Pull::Waiting { .. } => self.request_push(now),
            Pull::Done(negotiated) => {
                self.install_keys(negotiated)?;
                self.negotiated_at = now;
                Ok(())
            }
        }
    }
    fn request_push(&mut self, now: Instant) -> Result<()> {
        self.negotiation.write_plaintext(b"PUSH_REQUEST\0")?;
        if let Pull::Waiting { next_request, .. } = &mut self.pull {
            *next_request = Some(now + PUSH_RETRY);
        }
        Ok(())
    }
    fn read_messages(&mut self, now: Instant) -> Result<()> {
        while let Some(end) = self.negotiation.plain.iter().position(|byte| *byte == 0) {
            let message: Vec<u8> = self.negotiation.plain.drain(..=end).collect();
            let text = String::from_utf8_lossy(&message[..end]);
            match classify(&text) {
                ControlMessage::PushReply(options) => self.on_push_reply(now, options)?,
                ControlMessage::AuthFailed | ControlMessage::Halt => return Err(Error::Rejected),
                ControlMessage::Restart => {
                    return Err(Error::Protocol("OpenVPN 服务端要求重新连接"));
                }
                ControlMessage::Other => {}
            }
        }
        Ok(())
    }
    fn on_push_reply(&mut self, now: Instant, options: &str) -> Result<()> {
        let Pull::Waiting { collected, .. } = &mut self.pull else {
            return Ok(());
        };
        if collected.apply(options) {
            return Ok(());
        }
        let config = std::mem::take(collected);
        let negotiated = self.negotiate(&config)?;
        self.install_keys(negotiated)?;
        self.pull = Pull::Done(negotiated);
        self.negotiated_at = now;
        self.last_received = now;
        self.last_sent = now;
        if let Some(seconds) = config.ping {
            self.ping = (seconds > 0).then(|| Duration::from_secs(seconds));
        }
        if let Some(seconds) = config.ping_restart {
            self.ping_restart = (seconds > 0).then(|| Duration::from_secs(seconds));
        }
        self.auth_token.clone_from(&config.auth_token);
        self.events.push(Event::Up(config));
        Ok(())
    }
    fn negotiate(&self, config: &PushedConfig) -> Result<Negotiated> {
        if config.compression {
            return Err(Error::Unsupported("OpenVPN 服务端要求压缩，本实现不支持"));
        }
        if config.address_v4.is_none() && config.address_v6.is_none() {
            return Err(Error::Protocol("OpenVPN 推送配置缺少隧道地址"));
        }
        let peer_id = config
            .peer_id
            .filter(|id| *id < 0x00ff_ffff)
            .ok_or(Error::Unsupported("OpenVPN 服务端未启用 P_DATA_V2"))?;
        let cipher = match &config.cipher {
            None => self.settings.ciphers[0],
            Some(name) => DataCipher::parse(name)
                .filter(|cipher| self.settings.ciphers.contains(cipher))
                .ok_or(Error::Unsupported("OpenVPN 服务端选择的数据通道算法未启用"))?,
        };
        Ok(Negotiated {
            cipher,
            peer_id,
            tls_ekm: config.tls_ekm,
        })
    }
    fn install_keys(&mut self, negotiated: Negotiated) -> Result<()> {
        let negotiation = &self.negotiation;
        let server = negotiation
            .server
            .as_ref()
            .ok_or(Error::Protocol("OpenVPN 密钥交换消息不合法"))?;
        let remote = self
            .remote
            .as_ref()
            .ok_or(Error::Protocol("OpenVPN 密钥交换消息不合法"))?;
        let key2 = if negotiated.tls_ekm {
            negotiation
                .tls
                .export_keying_material(Zeroizing::new([0; 256]), EKM_LABEL, None)
                .map_err(|_| Error::Protocol("OpenVPN TLS 密钥导出失败"))?
        } else {
            expand_with_prf(&negotiation.source, server, &self.local, remote)
        };
        let (seal, open) = data_keys(
            negotiated.cipher,
            &key2,
            negotiation.key_id,
            negotiated.peer_id,
        )?;
        self.seal = Some(seal);
        let previous = self.open[0].take();
        self.open = [Some(open), previous];
        Ok(())
    }

    fn flush(&mut self, now: Instant) {
        let Self {
            wrap,
            local,
            remote,
            negotiation,
            outbox,
            ..
        } = self;
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as u32);
        let key_id = negotiation.key_id;
        let Negotiation { send, receive, .. } = negotiation;
        for entry in send.take_due(now) {
            let acks = receive.acks_for_packet();
            let body = encode_body(
                &acks,
                remote.as_ref(),
                Some(entry.packet_id),
                &entry.payload,
            );
            outbox.push(wrap.wrap(entry.opcode.byte(key_id), local, &body, time));
        }
        while receive.has_pending_acks() {
            let acks = receive.acks_for_packet();
            let body = encode_body(&acks, remote.as_ref(), None, &[]);
            outbox.push(wrap.wrap(Opcode::Ack.byte(key_id), local, &body, time));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tls::client_config,
        wrap::{AuthDigest, StaticKey},
    };

    const TIME: u32 = 1_000_000;
    const REMOTE: SessionId = [1; 8];
    const STALE: SessionId = [9; 8];

    fn key() -> StaticKey {
        let body: String = (0..256)
            .map(|index| format!("{:02x}", index % 251))
            .collect();
        StaticKey::parse(&format!(
            "-----BEGIN OpenVPN Static key V1-----\n{body}\n-----END OpenVPN Static key V1-----\n"
        ))
        .unwrap()
    }
    fn server_wrap() -> ControlWrap {
        ControlWrap::new(WrapKeys::auth(&key(), AuthDigest::Sha256, Some(0)))
    }
    fn client_session() -> Session {
        let authority = rcgen::generate_simple_self_signed(vec!["ca.invalid".to_owned()])
            .unwrap()
            .cert
            .pem();
        let settings = Settings {
            tls: client_config(&authority, None, None).unwrap(),
            wrap: WrapKeys::auth(&key(), AuthDigest::Sha256, Some(1)),
            credentials: None,
            ciphers: vec![DataCipher::ALL[0]],
            options: String::new(),
            peer_info: String::new(),
            ping: None,
            ping_restart: None,
            reneg: None,
            handshake: Duration::from_secs(60),
        };
        Session::new(Arc::new(settings), Instant::now()).unwrap()
    }
    fn reset(
        wrap: &mut ControlWrap,
        session: &SessionId,
        ack: Option<&SessionId>,
        time: u32,
    ) -> Vec<u8> {
        let acks: &[u32] = if ack.is_some() { &[0] } else { &[] };
        let body = encode_body(acks, ack, Some(0), &[]);
        wrap.wrap(Opcode::HardResetServer.byte(0), session, &body, time)
    }
    fn control(wrap: &mut ControlWrap, session: &SessionId, packet_id: u32, time: u32) -> Vec<u8> {
        let body = encode_body(&[], None, Some(packet_id), &[]);
        wrap.wrap(Opcode::Control.byte(0), session, &body, time)
    }
    /// 返回会话是否对该包产生了 ACK，即可靠层是否接受了它。
    fn acked(session: &mut Session, wire: &[u8]) -> bool {
        session.take_outbox();
        session.receive(Instant::now(), wire).unwrap();
        !session.take_outbox().is_empty()
    }

    #[test]
    fn hard_reset_binds_only_when_it_acknowledges_this_session() {
        let mut session = client_session();
        let local = session.local;
        let mut server = server_wrap();
        let replayed = reset(&mut server, &STALE, Some(&[0xee; 8]), TIME);
        session.receive(Instant::now(), &replayed).unwrap();
        assert_eq!(session.remote, None, "replayed reset for an old client");
        let unacknowledged = reset(&mut server, &STALE, None, TIME);
        session.receive(Instant::now(), &unacknowledged).unwrap();
        assert_eq!(session.remote, None, "reset without an ACK");
        let genuine = reset(&mut server, &REMOTE, Some(&local), TIME);
        session.receive(Instant::now(), &genuine).unwrap();
        assert_eq!(session.remote, Some(REMOTE));
    }

    #[test]
    fn separate_ack_binds_so_a_retransmitted_reset_without_ack_still_counts() {
        let mut session = client_session();
        let local = session.local;
        let mut server = server_wrap();
        let body = encode_body(&[0], Some(&local), None, &[]);
        let ack = server.wrap(Opcode::Ack.byte(0), &REMOTE, &body, TIME);
        session.receive(Instant::now(), &ack).unwrap();
        assert_eq!(session.remote, Some(REMOTE));
        let retransmitted = reset(&mut server, &REMOTE, None, TIME);
        assert!(acked(&mut session, &retransmitted));
        assert!(session.negotiation.peer_reset);
    }

    #[test]
    fn packet_from_another_session_cannot_advance_the_replay_window() {
        let mut session = client_session();
        let local = session.local;
        let mut server = server_wrap();
        let genuine = reset(&mut server, &REMOTE, Some(&local), TIME);
        assert!(acked(&mut session, &genuine));
        let mut old = server_wrap();
        for _ in 0..1000 {
            control(&mut old, &STALE, 0, TIME - 3600);
        }
        let high = control(&mut old, &STALE, 0, TIME - 3600);
        assert!(!acked(&mut session, &high));
        let next = control(&mut server, &REMOTE, 1, TIME);
        assert!(
            acked(&mut session, &next),
            "genuine packet after the replay"
        );
        assert!(!acked(&mut session, &next), "duplicate of a genuine packet");
    }

    #[test]
    fn packet_older_than_the_session_start_is_rejected() {
        let mut session = client_session();
        let local = session.local;
        let mut server = server_wrap();
        let genuine = reset(&mut server, &REMOTE, Some(&local), TIME);
        assert!(acked(&mut session, &genuine));
        let older = control(&mut server, &REMOTE, 1, TIME - 1);
        assert!(!acked(&mut session, &older));
        let newer = control(&mut server, &REMOTE, 1, TIME + 1);
        assert!(acked(&mut session, &newer));
    }
}
