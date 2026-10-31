use crate::{
    config::{Obfs, Shared},
    crypto::{self, Hash},
    invalid,
    protocol::Role,
};
use kerlico_core::{Error, Result};
use rand::seq::SliceRandom;
use std::sync::Arc;

pub(crate) struct Decoded {
    pub cipher: Vec<u8>,
    pub reply: Vec<u8>,
}
pub(crate) struct Layer {
    cfg: Arc<Shared>,
    role: Role,
    buffer: Vec<u8>,
    pending: Vec<u8>,
    sent: bool,
    received: bool,
    phase: u8,
    client_id: Vec<u8>,
    host: String,
    port: u16,
}
impl Layer {
    pub(crate) fn new(cfg: Arc<Shared>, role: Role, host: String, port: u16) -> Self {
        Self {
            cfg,
            role,
            buffer: Vec::new(),
            pending: Vec::new(),
            sent: false,
            received: false,
            phase: 0,
            client_id: crypto::random(32),
            host,
            port,
        }
    }
    pub(crate) fn ready(&self) -> bool {
        match self.cfg.obfs {
            Obfs::Random | Obfs::Tls | Obfs::TlsFast => self.phase == 8,
            _ => true,
        }
    }
    pub(crate) fn encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self.cfg.obfs {
            Obfs::Plain => Ok(data.to_vec()),
            Obfs::HttpGet | Obfs::HttpPost => self.http_encode(data),
            Obfs::Random => {
                if self.role == Role::Server {
                    return Ok(data.to_vec());
                }
                if self.phase == 8 {
                    return Ok(data.to_vec());
                }
                if self.pending.len() + data.len() > 131072 {
                    return Err(Error::ResourceLimit);
                }
                self.pending.extend_from_slice(data);
                if self.sent {
                    return Ok(Vec::new());
                }
                self.sent = true;
                let mut head = crypto::random(8 + usize::from(crypto::random(1)[0] % 32));
                head.extend_from_slice(&(u32::MAX - crc32fast::hash(&head)).to_le_bytes());
                Ok(head)
            }
            Obfs::Tls | Obfs::TlsFast => {
                if self.phase == 8 {
                    return records(data);
                }
                let encoded = records(data)?;
                if self.pending.len() + encoded.len() > 131072 {
                    return Err(Error::ResourceLimit);
                }
                self.pending.extend(encoded);
                if self.role == Role::Client && !self.sent {
                    self.sent = true;
                    return self.client_hello();
                }
                Ok(Vec::new())
            }
        }
    }
    pub(crate) fn feed(&mut self, data: &[u8]) -> Result<Decoded> {
        if self.cfg.obfs == Obfs::Plain {
            return Ok(Decoded {
                cipher: data.to_vec(),
                reply: Vec::new(),
            });
        }
        if self.buffer.len() + data.len() > 131072 {
            return Err(Error::ResourceLimit);
        }
        self.buffer.extend_from_slice(data);
        match self.cfg.obfs {
            Obfs::HttpGet | Obfs::HttpPost => self.http_decode(),
            Obfs::Random => {
                if self.phase == 8 {
                    return Ok(Decoded {
                        cipher: std::mem::take(&mut self.buffer),
                        reply: Vec::new(),
                    });
                }
                if self.role == Role::Client {
                    if self.buffer.len() < 4 {
                        return Ok(empty());
                    }
                    if self.buffer.len() > 103 {
                        return Err(invalid());
                    }
                    self.buffer.clear();
                    self.phase = 8;
                    return Ok(Decoded {
                        cipher: Vec::new(),
                        reply: std::mem::take(&mut self.pending),
                    });
                }
                let end = (8..=self.buffer.len().min(103))
                    .find(|end| crc32fast::hash(&self.buffer[..*end]) == u32::MAX);
                let Some(end) = end else {
                    if self.buffer.len() >= 103 {
                        return Err(invalid());
                    }
                    return Ok(empty());
                };
                self.buffer.drain(..end);
                self.phase = 8;
                Ok(Decoded {
                    cipher: std::mem::take(&mut self.buffer),
                    reply: crypto::random(4),
                })
            }
            Obfs::Tls | Obfs::TlsFast => self.tls_decode(),
            Obfs::Plain => Ok(empty()),
        }
    }
    pub(crate) fn finished(&self) -> bool {
        self.buffer.is_empty()
            && (!matches!(self.cfg.obfs, Obfs::Random | Obfs::Tls | Obfs::TlsFast)
                || self.phase == 8)
    }
    fn http_encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.sent {
            return Ok(data.to_vec());
        }
        self.sent = true;
        if self.role == Role::Server {
            let mut bytes =
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html\r\n\r\n"
                    .to_vec();
            bytes.extend_from_slice(data);
            return Ok(bytes);
        }
        let count = data.len().min(self.cfg.method.iv_len() + 30);
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut bytes = if self.cfg.obfs == Obfs::HttpPost {
            b"POST /".to_vec()
        } else {
            b"GET /".to_vec()
        };
        const HEX: &[u8] = b"0123456789abcdef";
        for byte in &data[..count] {
            bytes.extend_from_slice(&[
                b'%',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 15)],
            ]);
        }
        let (host, extra) = self
            .cfg
            .obfs_param
            .split_once('#')
            .map_or((self.cfg.obfs_param.as_str(), None), |(host, extra)| {
                (host, Some(extra))
            });
        let host = if host.is_empty() {
            self.host.as_str()
        } else {
            host.split(',')
                .collect::<Vec<_>>()
                .choose(&mut rand::thread_rng())
                .copied()
                .unwrap_or(host)
        };
        if host.contains(['\r', '\n']) {
            return Err(invalid());
        }
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        bytes.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        bytes.extend_from_slice(host.as_bytes());
        if self.port != 80 {
            bytes.extend_from_slice(format!(":{}", self.port).as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        if let Some(extra) = extra {
            let extra = extra
                .replace("\\n", "\n")
                .replace("\r\n", "\n")
                .replace('\n', "\r\n");
            if extra.len() > 8192 {
                return Err(Error::ResourceLimit);
            }
            bytes.extend_from_slice(extra.as_bytes());
            bytes.extend_from_slice(b"\r\n\r\n");
        } else {
            bytes.extend_from_slice(
                b"User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n",
            );
            if self.cfg.obfs == Obfs::HttpPost {
                bytes.extend_from_slice(
                    b"Content-Type: multipart/form-data; boundary=synthetic-boundary\r\n",
                );
            }
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(&data[count..]);
        Ok(bytes)
    }
    fn http_decode(&mut self) -> Result<Decoded> {
        if self.received {
            return Ok(Decoded {
                cipher: std::mem::take(&mut self.buffer),
                reply: Vec::new(),
            });
        }
        let Some(end) = self
            .buffer
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        else {
            if self.buffer.len() > 65536 {
                return Err(Error::ResourceLimit);
            }
            return Ok(empty());
        };
        if end > 65536 {
            return Err(Error::ResourceLimit);
        }
        let mut cipher = Vec::new();
        if self.role == Role::Server {
            let first = self.buffer[..end]
                .split(|byte| *byte == b'\n')
                .next()
                .ok_or_else(invalid)?;
            if !first.starts_with(b"GET /") && !first.starts_with(b"POST /") {
                return Err(invalid());
            }
            let begin = first
                .iter()
                .position(|byte| *byte == b'/')
                .ok_or_else(invalid)?
                + 1;
            let finish = first[begin..]
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or_else(invalid)?
                + begin;
            let encoded = &first[begin..finish];
            if encoded.len() % 3 != 0 || encoded.is_empty() {
                return Err(invalid());
            }
            for chunk in encoded.as_chunks::<3>().0 {
                if chunk[0] != b'%' {
                    return Err(invalid());
                }
                let pair = std::str::from_utf8(&chunk[1..]).map_err(|_| invalid())?;
                cipher.push(u8::from_str_radix(pair, 16).map_err(|_| invalid())?);
            }
            if !self.cfg.obfs_param.is_empty() {
                let header = std::str::from_utf8(&self.buffer[..end]).map_err(|_| invalid())?;
                let host = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("host").then_some(value.trim())
                    })
                    .ok_or_else(invalid)?;
                let host = if let Some(bracketed) = host.strip_prefix('[') {
                    bracketed.split_once(']').ok_or_else(invalid)?.0
                } else {
                    host.rsplit_once(':')
                        .filter(|(_, port)| {
                            !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
                        })
                        .map_or(host, |(host, _)| host)
                };
                if !self.cfg.obfs_param.split(',').any(|allowed| {
                    allowed
                        .trim()
                        .trim_matches(['[', ']'])
                        .eq_ignore_ascii_case(host)
                }) {
                    return Err(Error::Rejected);
                }
            }
        } else if !self.buffer.starts_with(b"HTTP/1.") {
            return Err(invalid());
        }
        cipher.extend_from_slice(&self.buffer[end + 4..]);
        self.buffer.clear();
        self.received = true;
        Ok(Decoded {
            cipher,
            reply: Vec::new(),
        })
    }
    fn auth_random(&self) -> Vec<u8> {
        let mut value = crate::now().to_be_bytes().to_vec();
        value.extend(crypto::random(18));
        let check = crypto::mac(Hash::Sha1, &self.tls_key(), &value);
        value.extend_from_slice(&check[..10]);
        value
    }
    fn tls_key(&self) -> Vec<u8> {
        let mut key = self.cfg.key.clone();
        key.extend_from_slice(&self.client_id);
        key
    }
    fn client_hello(&self) -> Result<Vec<u8>> {
        let mut body = vec![3, 3];
        body.extend(self.auth_random());
        body.push(32);
        body.extend_from_slice(&self.client_id);
        body.extend_from_slice(&[0, 2, 0xc0, 0x2f, 1, 0]);
        let host = if self.cfg.obfs_param.is_empty() {
            self.host.as_str()
        } else {
            self.cfg
                .obfs_param
                .split(',')
                .collect::<Vec<_>>()
                .choose(&mut rand::thread_rng())
                .copied()
                .unwrap_or("")
        };
        let mut extensions = Vec::new();
        if !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
            if host.len() > 255 || host.contains(['\r', '\n']) {
                return Err(invalid());
            }
            let mut name = vec![0];
            name.extend_from_slice(&(host.len() as u16).to_be_bytes());
            name.extend_from_slice(host.as_bytes());
            let mut list = (name.len() as u16).to_be_bytes().to_vec();
            list.extend(name);
            extensions.extend_from_slice(&[0, 0]);
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend(list);
        }
        extensions.extend_from_slice(&[0, 0x23, 0, 0x80]);
        extensions.extend(crypto::random(128));
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
        handshake.extend(body);
        let mut output = vec![0x16, 3, 1];
        output.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        output.extend(handshake);
        Ok(output)
    }
    fn server_hello(&self) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend(self.auth_random());
        body.push(32);
        body.extend_from_slice(&self.client_id);
        body.extend_from_slice(&[0xc0, 0x2f, 0, 0, 5, 0xff, 1, 0, 1, 0]);
        let mut handshake = vec![2, 0];
        handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
        handshake.extend(body);
        let mut output = vec![0x16, 3, 3];
        output.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        output.extend(handshake);
        output.extend_from_slice(&[0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 32]);
        output.extend(crypto::random(22));
        let mac = crypto::mac(Hash::Sha1, &self.tls_key(), &output);
        output.extend_from_slice(&mac[..10]);
        output
    }
    fn client_finished(&mut self) -> Vec<u8> {
        let mut output = vec![0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 32];
        output.extend(crypto::random(22));
        let mac = crypto::mac(Hash::Sha1, &self.tls_key(), &output);
        output.extend_from_slice(&mac[..10]);
        output.append(&mut self.pending);
        output
    }
    fn tls_decode(&mut self) -> Result<Decoded> {
        let mut reply = Vec::new();
        if self.phase == 8 {
            return Ok(Decoded {
                cipher: self.app_records()?,
                reply,
            });
        }
        if self.role == Role::Server && self.phase == 0 {
            if self.buffer.len() < 5 {
                return Ok(empty());
            }
            if self.buffer[..3] != [0x16, 3, 1] {
                return Err(invalid());
            }
            let length = usize::from(u16::from_be_bytes(
                self.buffer[3..5].try_into().map_err(|_| invalid())?,
            ));
            if !(75..=16384).contains(&length) {
                return Err(invalid());
            }
            if self.buffer.len() < length + 5 {
                return Ok(empty());
            }
            let data = self.buffer[..length + 5].to_vec();
            if data[5..7] != [1, 0]
                || usize::from(u16::from_be_bytes(
                    data[7..9].try_into().map_err(|_| invalid())?,
                )) != length - 4
                || data[9..11] != [3, 3]
            {
                return Err(invalid());
            }
            let size = usize::from(data[43]);
            if size != 32 || 44 + size > data.len() {
                return Err(invalid());
            }
            self.client_id = data[44..76].to_vec();
            let check = crypto::mac(Hash::Sha1, &self.tls_key(), &data[11..33]);
            if !crypto::equal(&check[..10], &data[33..43]) {
                return Err(invalid());
            }
            self.cfg
                .replay
                .tls(&data[11..33], self.cfg.limits.obfs_window_secs)?;
            self.buffer.drain(..length + 5);
            self.phase = 1;
            reply = self.server_hello();
        }
        if self.role == Role::Server && self.phase == 1 {
            if self.buffer.len() < 11 {
                return Ok(Decoded {
                    cipher: Vec::new(),
                    reply,
                });
            }
            if self.buffer[..9] != [0x14, 3, 3, 0, 1, 1, 0x16, 3, 3] {
                return Err(invalid());
            }
            let length = usize::from(u16::from_be_bytes(
                self.buffer[9..11].try_into().map_err(|_| invalid())?,
            ));
            if !(10..=1024).contains(&length) {
                return Err(invalid());
            }
            let total = 11 + length;
            if self.buffer.len() < total {
                return Ok(Decoded {
                    cipher: Vec::new(),
                    reply,
                });
            }
            let check = crypto::mac(Hash::Sha1, &self.tls_key(), &self.buffer[..total - 10]);
            if !crypto::equal(&check[..10], &self.buffer[total - 10..total]) {
                return Err(invalid());
            }
            self.buffer.drain(..total);
            self.phase = 8;
            return Ok(Decoded {
                cipher: self.app_records()?,
                reply,
            });
        }
        if self.role == Role::Client {
            if self.buffer.len() < 5 {
                return Ok(empty());
            }
            let hello = usize::from(u16::from_be_bytes(
                self.buffer[3..5].try_into().map_err(|_| invalid())?,
            )) + 5;
            if !(76..=16389).contains(&hello) {
                return Err(invalid());
            }
            if self.buffer.len() < hello {
                return Ok(empty());
            }
            if self.buffer[..3] != [0x16, 3, 3] || self.buffer[5..7] != [2, 0] {
                return Err(invalid());
            }
            let check = crypto::mac(Hash::Sha1, &self.tls_key(), &self.buffer[11..33]);
            if !crypto::equal(&check[..10], &self.buffer[33..43]) {
                return Err(invalid());
            }
            let mut offset = hello;
            loop {
                if self.buffer.len() < offset + 5 {
                    return Ok(empty());
                }
                let kind = self.buffer[offset];
                let length = usize::from(u16::from_be_bytes(
                    self.buffer[offset + 3..offset + 5]
                        .try_into()
                        .map_err(|_| invalid())?,
                ));
                if length > 16384 || self.buffer[offset + 1..offset + 3] != [3, 3] {
                    return Err(invalid());
                }
                if self.buffer.len() < offset + 5 + length {
                    return Ok(empty());
                }
                if kind == 0x14 {
                    if length != 1 || self.buffer[offset + 5] != 1 {
                        return Err(invalid());
                    }
                    offset += 6;
                    break;
                }
                if kind != 0x16 {
                    return Err(invalid());
                }
                offset += 5 + length;
                if offset > 65536 {
                    return Err(Error::ResourceLimit);
                }
            }
            if self.buffer.len() < offset + 5 {
                return Ok(empty());
            }
            if self.buffer[offset..offset + 3] != [0x16, 3, 3] {
                return Err(invalid());
            }
            let length = usize::from(u16::from_be_bytes(
                self.buffer[offset + 3..offset + 5]
                    .try_into()
                    .map_err(|_| invalid())?,
            ));
            if !(10..=1024).contains(&length) {
                return Err(invalid());
            }
            let total = offset + 5 + length;
            if self.buffer.len() < total {
                return Ok(empty());
            }
            let check = crypto::mac(Hash::Sha1, &self.tls_key(), &self.buffer[..total - 10]);
            if !crypto::equal(&check[..10], &self.buffer[total - 10..total]) {
                return Err(invalid());
            }
            self.buffer.drain(..total);
            self.phase = 8;
            reply = self.client_finished();
            return Ok(Decoded {
                cipher: self.app_records()?,
                reply,
            });
        }
        Ok(Decoded {
            cipher: Vec::new(),
            reply,
        })
    }
    fn app_records(&mut self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        while self.buffer.len() >= 5 {
            if self.buffer[..3] != [0x17, 3, 3] {
                return Err(invalid());
            }
            let length = usize::from(u16::from_be_bytes(
                self.buffer[3..5].try_into().map_err(|_| invalid())?,
            ));
            // SSR 的握手等待队列可合并为整个 u16 长度记录；它不是标准 TLS 明文记录。
            if self.buffer.len() < length + 5 {
                break;
            }
            output.extend_from_slice(&self.buffer[5..length + 5]);
            self.buffer.drain(..length + 5);
        }
        Ok(output)
    }
}
fn empty() -> Decoded {
    Decoded {
        cipher: Vec::new(),
        reply: Vec::new(),
    }
}
fn records(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for chunk in data.chunks(4096) {
        if chunk.is_empty() {
            continue;
        }
        output.extend_from_slice(&[0x17, 3, 3]);
        output.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        output.extend_from_slice(chunk);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn captured_peer_record_corruption_is_rejected_after_valid_finished() {
        #[derive(serde::Deserialize)]
        struct Captured {
            client_hello: Vec<u8>,
            client_finished: Vec<u8>,
            first_app_records: Vec<u8>,
            bad_record_prefix: Vec<u8>,
        }
        let captured: Captured =
            serde_json::from_str(include_str!("../tests/fixtures/mihomo-malformed-tls.json"))
                .unwrap();
        let mut flight = captured.client_finished.clone();
        flight.extend_from_slice(&captured.first_app_records);
        for split in 0..=flight.len() {
            let cfg = Shared::node(&json!({"method":"aes-128-cfb","password":"synthetic-ssr-base-password","protocol":"origin","obfs":"tls1.2_ticket_auth","udp":false,"allow_insecure":true})).unwrap();
            let mut hello = captured.client_hello.clone();
            let mut key = cfg.key.clone();
            key.extend_from_slice(&hello[44..76]);
            // 保留实际捕获结构；仅更新时间与相应MAC，使固定证据不依赖运行日期。
            hello[11..15].copy_from_slice(&crate::now().to_be_bytes());
            let check = crypto::mac(Hash::Sha1, &key, &hello[11..33]);
            hello[33..43].copy_from_slice(&check[..10]);
            let mut server = Layer::new(cfg, Role::Server, String::new(), 0);
            let reply = server.feed(&hello).unwrap();
            assert!(!reply.reply.is_empty());
            let mut decoded = server.feed(&flight[..split]).unwrap().cipher;
            decoded.extend(server.feed(&flight[split..]).unwrap().cipher);
            assert!(server.ready(), "分割点 {split}");
            assert_eq!(decoded.len(), 23, "分割点 {split}");
            // 原生对端在记录边界出现了非法五字节前缀；不能当成TLS记录或静默跳过。
            assert!(server.feed(&captured.bad_record_prefix).is_err());
        }
    }
    #[test]
    fn http_allowed_host_accepts_bracketed_ipv6_and_port() {
        let mut options = json!({"method":"aes-128-cfb","password":"synthetic-host-secret","protocol":"auth_aes128_md5","obfs":"http_simple","obfs_param":"::1","allow_insecure":true});
        let server_cfg = Shared::node(&options).unwrap();
        options["server"] = json!({"host":"::1","port":8443});
        let (client_cfg, _) = Shared::client(&options).unwrap();
        let mut client = Layer::new(client_cfg, Role::Client, "::1".into(), 8443);
        let mut server = Layer::new(server_cfg, Role::Server, String::new(), 0);
        let payload = vec![0x31; 96];
        assert_eq!(
            server
                .feed(&client.encode(&payload).unwrap())
                .unwrap()
                .cipher,
            payload
        );
    }
    #[test]
    fn legacy_tls_pending_record_accepts_u16_length() {
        let cfg = Shared::node(&json!({"method":"aes-128-cfb","password":"synthetic-record-secret","protocol":"auth_aes128_md5","obfs":"tls1.2_ticket_auth","allow_insecure":true})).unwrap();
        let mut layer = Layer::new(cfg, Role::Server, String::new(), 0);
        layer.phase = 8;
        let payload = vec![0x5a; 65535];
        let mut record = vec![0x17, 3, 3, 0xff, 0xff];
        record.extend_from_slice(&payload);
        let mut decoded = Vec::new();
        for chunk in record.chunks(4096) {
            decoded.extend(layer.feed(chunk).unwrap().cipher);
        }
        assert_eq!(decoded, payload);
        assert!(layer.finished());
    }
    #[test]
    fn every_obfs_preserves_split_reads_in_both_directions() {
        for name in crate::config::OBFS {
            let common = json!({"method":"aes-128-cfb","password":"synthetic-layer-secret","protocol":"auth_aes128_md5","obfs":name,"allow_insecure":true});
            let server_cfg = Shared::node(&common).unwrap();
            let mut options = common.clone();
            options["server"] = json!({"host":"127.0.0.1","port":443});
            let (client_cfg, _) = Shared::client(&options).unwrap();
            let mut client = Layer::new(client_cfg, Role::Client, "localhost".into(), 443);
            let mut server = Layer::new(server_cfg, Role::Server, String::new(), 0);
            let input = vec![0x57; 96];
            let encoded = client.encode(&input).unwrap();
            let mut received = Vec::new();
            let mut reply = Vec::new();
            for chunk in encoded.chunks(3) {
                let value = server.feed(chunk).unwrap();
                received.extend(value.cipher);
                reply.extend(value.reply);
            }
            if !reply.is_empty() {
                let mut next = Vec::new();
                for chunk in reply.chunks(1) {
                    let value = client.feed(chunk).unwrap();
                    assert!(value.cipher.is_empty());
                    next.extend(value.reply);
                }
                for chunk in next.chunks(2) {
                    let value = server.feed(chunk).unwrap();
                    received.extend(value.cipher);
                    assert!(value.reply.is_empty());
                }
            }
            assert_eq!(received, input, "{name}");
            let response = server.encode(&[0x25; 128]).unwrap();
            let mut returned = Vec::new();
            for chunk in response.chunks(2) {
                let value = client.feed(chunk).unwrap();
                returned.extend(value.cipher);
                assert!(value.reply.is_empty());
            }
            assert_eq!(returned, vec![0x25; 128], "{name}");
            assert!(client.finished() && server.finished());
        }
    }
}
