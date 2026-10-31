mod aes;
mod chain;
mod v4;
use crate::{
    config::{Protocol, Shared},
    crypto::{self, Hash, Method, State},
    invalid,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{Error, Result};
use shadowsocks::crypto::CipherKind;
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Client,
    Server,
}
pub(crate) struct Decoded {
    pub data: Vec<u8>,
    pub reply: bool,
}
pub(crate) struct Codec {
    pub cfg: Arc<Shared>,
    pub role: Role,
    pub send_iv: Vec<u8>,
    pub recv_iv: Vec<u8>,
    pub sent_header: bool,
    pub received_header: bool,
    pub buffer: Vec<u8>,
    pub header_payload: Vec<u8>,
    pub user_key: Vec<u8>,
    pub uid: u32,
    pub send_id: u32,
    pub receive_id: u32,
    pub last_client: Vec<u8>,
    pub last_server: Vec<u8>,
    pub cipher_send: Option<State>,
    pub cipher_receive: Option<State>,
    pub mss: u16,
    pub peer_overhead: usize,
}
impl Codec {
    pub(crate) fn new(cfg: Arc<Shared>, role: Role, iv: Vec<u8>) -> Self {
        let (uid, user_key) = client_user(&cfg);
        let origin = cfg.protocol == Protocol::Origin;
        Self {
            cfg: cfg.clone(),
            role,
            send_iv: iv,
            recv_iv: Vec::new(),
            sent_header: false,
            received_header: role == Role::Client || origin,
            buffer: Vec::new(),
            header_payload: Vec::new(),
            user_key,
            uid,
            send_id: 1,
            receive_id: 1,
            last_client: vec![0; 16],
            last_server: vec![0; 16],
            cipher_send: None,
            cipher_receive: None,
            mss: 1460,
            peer_overhead: cfg.overhead(),
        }
    }
    fn metadata(&self, time: u32) -> Result<Vec<u8>> {
        let mut data = time.to_le_bytes().to_vec();
        data.extend_from_slice(&self.cfg.client_id);
        data.extend_from_slice(&self.cfg.next_connection()?.to_le_bytes());
        Ok(data)
    }
    pub(crate) fn encode(&mut self, input: &[u8], time: u32) -> Result<Vec<u8>> {
        if self.cfg.protocol == Protocol::Origin {
            return Ok(input.to_vec());
        }
        if self.role == Role::Server && !self.received_header {
            return Err(invalid());
        }
        let mut output = Vec::new();
        let mut payload = input;
        if self.role == Role::Client && !self.sent_header {
            if payload.is_empty() {
                return Ok(output);
            }
            let count = head_size(payload).min(payload.len());
            let metadata = self.metadata(time)?;
            match self.cfg.protocol {
                Protocol::V4 => output.extend(self.v4_auth(&metadata, &payload[..count])?),
                Protocol::AesMd5 | Protocol::AesSha1 => {
                    output.extend(self.aes_auth(&metadata, &payload[..count])?)
                }
                Protocol::ChainA | Protocol::ChainB => {
                    output.extend(self.chain_auth(&metadata, &payload[..count])?)
                }
                Protocol::Origin => {}
            }
            self.sent_header = true;
            payload = &payload[count..];
        }
        let mut first = Vec::new();
        if self.cfg.protocol.chain() && self.role == Role::Server && self.send_id == 1 {
            first.extend_from_slice(&self.mss.to_le_bytes());
            first.extend_from_slice(payload);
            payload = &first;
        }
        let unit = if self.cfg.protocol.chain() {
            if self.role == Role::Server {
                usize::from(self.mss)
                    .saturating_sub(self.peer_overhead)
                    .clamp(1, 2800)
            } else {
                usize::from(self.mss)
                    .saturating_sub(self.cfg.overhead())
                    .clamp(1, 2800)
            }
        } else {
            8100
        };
        if payload.is_empty() {
            output.extend(self.pack(&[])?);
        } else {
            for chunk in payload.chunks(unit) {
                output.extend(self.pack(chunk)?);
            }
        }
        Ok(output)
    }
    fn pack(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self.cfg.protocol {
            Protocol::V4 => self.v4_data(data),
            Protocol::AesMd5 | Protocol::AesSha1 => self.aes_data(data),
            Protocol::ChainA | Protocol::ChainB => self.chain_data(data),
            Protocol::Origin => Ok(data.to_vec()),
        }
    }
    pub(crate) fn feed(&mut self, data: &[u8], iv: &[u8], time: u32) -> Result<Decoded> {
        if self.cfg.protocol == Protocol::Origin {
            return Ok(Decoded {
                data: data.to_vec(),
                reply: false,
            });
        }
        if self.buffer.len() + data.len() > 131072 {
            return Err(Error::ResourceLimit);
        }
        self.recv_iv = iv.to_vec();
        self.buffer.extend_from_slice(data);
        let mut output = Vec::new();
        let mut reply = false;
        if !self.received_header {
            let parsed = match self.cfg.protocol {
                Protocol::V4 => self.v4_header(time)?,
                Protocol::AesMd5 | Protocol::AesSha1 => self.aes_header(time)?,
                Protocol::ChainA | Protocol::ChainB => self.chain_header(time)?,
                Protocol::Origin => true,
            };
            if !parsed {
                return Ok(Decoded {
                    data: output,
                    reply,
                });
            }
            self.received_header = true;
            reply = true;
            output.append(&mut self.take_header_payload());
        }
        loop {
            let next = match self.cfg.protocol {
                Protocol::V4 => self.v4_decode()?,
                Protocol::AesMd5 | Protocol::AesSha1 => self.aes_decode()?,
                Protocol::ChainA | Protocol::ChainB => self.chain_decode()?,
                Protocol::Origin => None,
            };
            let Some(data) = next else { break };
            if self.role == Role::Server && data.is_empty() {
                reply = true;
            }
            output.extend(data);
        }
        Ok(Decoded {
            data: output,
            reply,
        })
    }
    // 首部解码暂存的明文与后续密文缓冲分离，避免错误分帧提前交付目标。
    fn take_header_payload(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.header_payload)
    }
    fn user(&self, uid: u32) -> Result<(u32, Vec<u8>)> {
        if self.cfg.users.is_empty() {
            return Ok((0, self.cfg.key.clone()));
        }
        let password = self.cfg.users.get(&uid).ok_or(Error::Rejected)?;
        Ok((
            uid,
            if self.cfg.protocol.chain() {
                password.clone()
            } else {
                crypto::digest(self.cfg.protocol.hash(), password)
            },
        ))
    }
    fn block_password(&self) -> Vec<u8> {
        let mut password = STANDARD.encode(&self.user_key).into_bytes();
        password.extend_from_slice(self.cfg.protocol.salt());
        password
    }
    fn base_mac_key(&self, iv: &[u8]) -> Vec<u8> {
        let mut key = iv.to_vec();
        key.extend_from_slice(&self.cfg.key);
        key
    }
    fn packet_key(&self, id: u32) -> Vec<u8> {
        let mut key = self.user_key.clone();
        key.extend_from_slice(&id.to_le_bytes());
        key
    }
    fn next_send(&mut self) -> Result<()> {
        self.send_id = self.send_id.checked_add(1).ok_or(Error::ResourceLimit)?;
        Ok(())
    }
    fn next_receive(&mut self) -> Result<()> {
        self.receive_id = self.receive_id.checked_add(1).ok_or(Error::ResourceLimit)?;
        Ok(())
    }
    pub(crate) fn finished(&self) -> bool {
        self.buffer.is_empty() && (self.received_header || self.role == Role::Client)
    }
    fn init_rc4(&mut self) -> Result<()> {
        let mut password = STANDARD.encode(&self.user_key).into_bytes();
        password.extend_from_slice(STANDARD.encode(&self.last_client).as_bytes());
        let key = crypto::key(&password, 16);
        self.cipher_send = Some(State::new(Method::Base(CipherKind::RC4), &key, &[])?);
        self.cipher_receive = Some(State::new(Method::Base(CipherKind::RC4), &key, &[])?);
        Ok(())
    }
}
fn head_size(data: &[u8]) -> usize {
    if data.len() < 2 {
        return data.len();
    }
    match data[0] & 7 {
        1 => 7,
        4 => 19,
        3 => 4 + usize::from(data[1]),
        _ => 30,
    }
}
pub(crate) fn client_user(cfg: &Shared) -> (u32, Vec<u8>) {
    match &cfg.user {
        Some(user) => (
            user.id,
            if cfg.protocol.chain() {
                user.password.as_bytes().to_vec()
            } else {
                crypto::digest(cfg.protocol.hash(), user.password.as_bytes())
            },
        ),
        None => (rand::random(), cfg.key.clone()),
    }
}
fn short_padding() -> Vec<u8> {
    let size = usize::from(crypto::random(1)[0] % 32);
    let mut bytes = vec![(size + 1) as u8];
    bytes.extend(crypto::random(size));
    bytes
}
fn padding_end(frame: &[u8], offset: usize, big: bool, tail: usize) -> Result<usize> {
    let first = *frame.get(offset).ok_or_else(invalid)?;
    let size = if first < 255 {
        usize::from(first)
    } else {
        let bytes: [u8; 2] = frame
            .get(offset + 1..offset + 3)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?;
        usize::from(if big {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        })
    };
    let end = offset.checked_add(size).ok_or_else(invalid)?;
    if size == 0 || end > frame.len().saturating_sub(tail) || first == 255 && size < 3 {
        return Err(invalid());
    }
    Ok(end)
}

pub(crate) struct UdpCodec {
    pub cfg: Arc<Shared>,
    uid: u32,
    user_key: Vec<u8>,
}
pub(crate) struct UdpDecoded {
    pub data: Vec<u8>,
    pub user: Option<u32>,
    pub replay: bool,
}
impl UdpCodec {
    pub(crate) fn new(cfg: Arc<Shared>) -> Self {
        let (uid, user_key) = client_user(&cfg);
        Self { cfg, uid, user_key }
    }
    fn user(&self, uid: Option<u32>) -> Result<Vec<u8>> {
        match uid {
            Some(uid) => {
                let password = self.cfg.users.get(&uid).ok_or(Error::Rejected)?;
                Ok(if self.cfg.protocol.chain() {
                    password.clone()
                } else {
                    crypto::digest(self.cfg.protocol.hash(), password)
                })
            }
            None => Ok(self.cfg.key.clone()),
        }
    }
    pub(crate) fn encode_client(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self.cfg.protocol {
            Protocol::Origin | Protocol::V4 => Ok(input.to_vec()),
            Protocol::AesMd5 | Protocol::AesSha1 => {
                let mut data = input.to_vec();
                data.extend_from_slice(&self.uid.to_le_bytes());
                let mac = crypto::mac(self.cfg.protocol.hash(), &self.user_key, &data);
                data.extend_from_slice(&mac[..4]);
                Ok(data)
            }
            Protocol::ChainA | Protocol::ChainB => {
                let auth = crypto::random(3);
                let hash = crypto::mac(Hash::Md5, &self.cfg.key, &auth);
                let mut data = self.rc4(input, &self.user_key, &hash, true)?;
                data.extend(crypto::random(chain::udp_layout(&hash)));
                data.extend(auth);
                let mask = u32::from_le_bytes(hash[..4].try_into().map_err(|_| invalid())?);
                data.extend_from_slice(&(self.uid ^ mask).to_le_bytes());
                let check = crypto::mac(Hash::Md5, &self.user_key, &data);
                data.push(check[0]);
                Ok(data)
            }
        }
    }
    pub(crate) fn decode_server(&self, input: &[u8]) -> Result<UdpDecoded> {
        let data = match self.cfg.protocol {
            Protocol::Origin | Protocol::V4 => input.to_vec(),
            Protocol::AesMd5 | Protocol::AesSha1 => {
                if input.len() < 4 {
                    return Err(invalid());
                }
                let size = input.len() - 4;
                let check = crypto::mac(self.cfg.protocol.hash(), &self.cfg.key, &input[..size]);
                if !crypto::equal(&check[..4], &input[size..]) {
                    return Err(invalid());
                }
                input[..size].to_vec()
            }
            Protocol::ChainA | Protocol::ChainB => {
                if input.len() <= 8 {
                    return Err(invalid());
                }
                let check = crypto::mac(Hash::Md5, &self.user_key, &input[..input.len() - 1]);
                if !crypto::equal(&check[..1], &input[input.len() - 1..]) {
                    return Err(invalid());
                }
                let hash = crypto::mac(
                    Hash::Md5,
                    &self.cfg.key,
                    &input[input.len() - 8..input.len() - 1],
                );
                let size = input
                    .len()
                    .checked_sub(8 + chain::udp_layout(&hash))
                    .ok_or_else(invalid)?;
                self.rc4(&input[..size], &self.user_key, &hash, false)?
            }
        };
        Ok(UdpDecoded {
            data,
            user: None,
            replay: self.cfg.protocol.chain(),
        })
    }
    pub(crate) fn decode_client(&self, input: &[u8]) -> Result<UdpDecoded> {
        match self.cfg.protocol {
            Protocol::Origin | Protocol::V4 => Ok(UdpDecoded {
                data: input.to_vec(),
                user: None,
                replay: false,
            }),
            Protocol::AesMd5 | Protocol::AesSha1 => {
                if input.len() < 8 {
                    return Err(invalid());
                }
                let uid = u32::from_le_bytes(
                    input[input.len() - 8..input.len() - 4]
                        .try_into()
                        .map_err(|_| invalid())?,
                );
                let uid = if self.cfg.users.is_empty() {
                    None
                } else {
                    Some(uid)
                };
                let key = self.user(uid)?;
                let check = crypto::mac(self.cfg.protocol.hash(), &key, &input[..input.len() - 4]);
                if !crypto::equal(&check[..4], &input[input.len() - 4..]) {
                    return Err(invalid());
                }
                Ok(UdpDecoded {
                    data: input[..input.len() - 8].to_vec(),
                    user: uid,
                    replay: false,
                })
            }
            Protocol::ChainA | Protocol::ChainB => {
                if input.len() <= 8 {
                    return Err(invalid());
                }
                let hash = crypto::mac(
                    Hash::Md5,
                    &self.cfg.key,
                    &input[input.len() - 8..input.len() - 5],
                );
                let mask = u32::from_le_bytes(hash[..4].try_into().map_err(|_| invalid())?);
                let uid = u32::from_le_bytes(
                    input[input.len() - 5..input.len() - 1]
                        .try_into()
                        .map_err(|_| invalid())?,
                ) ^ mask;
                let uid = if self.cfg.users.is_empty() {
                    None
                } else {
                    Some(uid)
                };
                let key = self.user(uid)?;
                let check = crypto::mac(Hash::Md5, &key, &input[..input.len() - 1]);
                if !crypto::equal(&check[..1], &input[input.len() - 1..]) {
                    return Err(invalid());
                }
                let size = input
                    .len()
                    .checked_sub(8 + chain::udp_layout(&hash))
                    .ok_or_else(invalid)?;
                Ok(UdpDecoded {
                    data: self.rc4(&input[..size], &key, &hash, false)?,
                    user: uid,
                    replay: true,
                })
            }
        }
    }
    pub(crate) fn encode_server(&self, input: &[u8], uid: Option<u32>) -> Result<Vec<u8>> {
        match self.cfg.protocol {
            Protocol::Origin | Protocol::V4 => Ok(input.to_vec()),
            Protocol::AesMd5 | Protocol::AesSha1 => {
                let mut data = input.to_vec();
                let check = crypto::mac(self.cfg.protocol.hash(), &self.cfg.key, &data);
                data.extend_from_slice(&check[..4]);
                Ok(data)
            }
            Protocol::ChainA | Protocol::ChainB => {
                let key = self.user(uid)?;
                let auth = crypto::random(7);
                let hash = crypto::mac(Hash::Md5, &self.cfg.key, &auth);
                let mut data = self.rc4(input, &key, &hash, true)?;
                data.extend(crypto::random(chain::udp_layout(&hash)));
                data.extend(auth);
                let check = crypto::mac(Hash::Md5, &key, &data);
                data.push(check[0]);
                Ok(data)
            }
        }
    }
    fn rc4(&self, input: &[u8], key: &[u8], hash: &[u8], encrypt: bool) -> Result<Vec<u8>> {
        let mut password = STANDARD.encode(key).into_bytes();
        password.extend_from_slice(STANDARD.encode(hash).as_bytes());
        let key = crypto::key(&password, 16);
        let mut cipher = State::new(Method::Base(CipherKind::RC4), &key, &[])?;
        let mut data = input.to_vec();
        cipher.apply(&mut data, encrypt)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn captured_peer_payload_corruption_fails_after_valid_authentication() {
        #[derive(serde::Deserialize)]
        struct Observed {
            protocol_plain_bytes: usize,
            protocol_error: Option<String>,
            received_auth_header: bool,
        }
        #[derive(serde::Deserialize)]
        struct Captured {
            capture_epoch: u32,
            iv: Vec<u8>,
            protocol_prefix: Vec<u8>,
            reference_before_error: Observed,
        }
        let captured: Captured = serde_json::from_str(include_str!(
            "../../tests/fixtures/mihomo-corrupt-protocol.json"
        ))
        .unwrap();
        assert!(captured.reference_before_error.protocol_error.is_none());
        assert!(captured.reference_before_error.received_auth_header);
        let cfg = crate::config::Shared::node(&serde_json::json!({"method":"aes-128-cfb","password":"synthetic-ssr-base-password","protocol":"auth_aes128_md5","obfs":"random_head","allow_insecure":true})).unwrap();
        let mut codec = super::Codec::new(cfg, super::Role::Server, vec![0x42; 16]);
        let split = captured.protocol_prefix.len() - 1;
        // 使用抓包时钟重放认证，不改写实际首部、业务或MAC。
        let first = codec
            .feed(
                &captured.protocol_prefix[..split],
                &captured.iv,
                captured.capture_epoch,
            )
            .unwrap();
        assert!(codec.received_header);
        assert_eq!(
            first.data.len(),
            captured.reference_before_error.protocol_plain_bytes
        );
        assert!(
            codec
                .feed(
                    &captured.protocol_prefix[split..],
                    &captured.iv,
                    captured.capture_epoch,
                )
                .is_err()
        );
    }
    use super::*;
    use serde::Deserialize;
    use serde_json::json;
    #[derive(Deserialize)]
    struct Oracle {
        source_commit: String,
        base_password: String,
        user_password: String,
        uid: u32,
        iv: Vec<u8>,
        records: Vec<Record>,
    }
    #[derive(Deserialize)]
    struct Record {
        protocol: String,
        obfs_overhead: u8,
        time: u32,
        client_frame: Vec<u8>,
        server_frame: Vec<u8>,
        udp_client: Vec<u8>,
        udp_server: Vec<u8>,
        client_plain: Vec<u8>,
        server_plain: Vec<u8>,
        udp_plain: Vec<u8>,
        udp_uses_user: bool,
    }
    #[test]
    fn fixed_reference_vectors_cover_roles_and_chain_padding() {
        let oracle: Oracle =
            serde_json::from_str(include_str!("../../tests/fixtures/reference-vectors.json"))
                .unwrap();
        assert_eq!(
            oracle.source_commit,
            "fd723a92c488d202b407323f0512987346944136"
        );
        for record in oracle.records {
            let kind = Protocol::parse(&record.protocol).unwrap();
            let obfs = if record.obfs_overhead == 5 {
                "tls1.2_ticket_auth"
            } else {
                "plain"
            };
            let mut server_options = json!({"method":"aes-128-cfb","password":oracle.base_password,"protocol":record.protocol,"obfs":obfs,"allow_insecure":true});
            if kind.users() {
                server_options["users"] =
                    json!([{"id":oracle.uid,"password":oracle.user_password}]);
            }
            let server_cfg = Shared::node(&server_options).unwrap();
            let mut client_options = server_options.clone();
            client_options.as_object_mut().unwrap().remove("users");
            client_options["server"] = json!({"host":"127.0.0.1","port":1});
            if kind.users() {
                client_options["user"] = json!({"id":oracle.uid,"password":oracle.user_password});
            }
            let (client_cfg, _) = Shared::client(&client_options).unwrap();
            let mut server = Codec::new(server_cfg, Role::Server, vec![0x35; 16]);
            let mut client = Codec::new(client_cfg, Role::Client, oracle.iv.clone());
            let mut received = Vec::new();
            let mut cursor = 0;
            if kind.chain() {
                let decoded = server
                    .feed(&record.client_frame[..36], &oracle.iv, record.time)
                    .unwrap();
                assert!(decoded.data.is_empty());
                client.user_key = server.user_key.clone();
                client.last_client = server.last_client.clone();
                client.last_server = server.last_server.clone();
                client.init_rc4().unwrap();
                cursor = 36;
            }
            for bytes in record.client_frame[cursor..].chunks(3) {
                received.extend(server.feed(bytes, &oracle.iv, record.time).unwrap().data);
            }
            assert_eq!(
                received, record.client_plain,
                "{} overhead={}",
                record.protocol, record.obfs_overhead
            );
            assert!(server.finished());
            if kind != Protocol::Origin {
                let mut replay = Codec::new(server.cfg.clone(), Role::Server, vec![0x35; 16]);
                assert!(
                    replay
                        .feed(&record.client_frame, &oracle.iv, record.time)
                        .is_err()
                );
            }
            let mut received = Vec::new();
            for bytes in record.server_frame.chunks(5) {
                received.extend(client.feed(bytes, &[0x35; 16], record.time).unwrap().data);
            }
            assert_eq!(
                received, record.server_plain,
                "{} overhead={}",
                record.protocol, record.obfs_overhead
            );
            if !record.udp_uses_user {
                server_options.as_object_mut().unwrap().remove("users");
                client_options.as_object_mut().unwrap().remove("user");
            }
            let server = UdpCodec::new(Shared::node(&server_options).unwrap());
            let (client_cfg, _) = Shared::client(&client_options).unwrap();
            let client = UdpCodec::new(client_cfg);
            assert_eq!(
                server.decode_client(&record.udp_client).unwrap().data,
                record.udp_plain
            );
            assert_eq!(
                client.decode_server(&record.udp_server).unwrap().data,
                record.udp_plain
            );
        }
    }
}
