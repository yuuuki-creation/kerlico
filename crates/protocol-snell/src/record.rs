//! 记录边界是 UDP 数据语义的一部分，不能先展开成无边界字节流。
use crate::{
    config::{Mode, Settings},
    crypto::Cipher,
    io_protocol,
};
use kerlico_core::BoxStream;
use rand::{RngCore, seq::SliceRandom};
use std::{
    io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, ReadHalf};
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
pub(crate) struct Reader {
    pub io: ReadHalf<BoxStream>,
    settings: Arc<Settings>,
    cipher: Option<Cipher>,
    salt: Option<[u8; 16]>,
    initialized: bool,
    pub physical_closed: bool,
    sequence: u32,
}
impl Reader {
    pub fn new(io: ReadHalf<BoxStream>, settings: Arc<Settings>) -> Self {
        Self {
            io,
            settings,
            cipher: None,
            salt: None,
            initialized: false,
            physical_closed: false,
            sequence: 0,
        }
    }
    pub fn salt(&self) -> Option<[u8; 16]> {
        self.salt
    }
    pub async fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.physical_closed {
            return Ok(None);
        }
        if !self.initialized {
            if !self.settings.raw() {
                let length = self.settings.profile.as_ref().map_or(16, |p| p.salt_len);
                let mut block = vec![0; length];
                self.io.read_exact(&mut block).await?;
                let salt = match &self.settings.profile {
                    Some(profile) => profile.extract_salt(&block),
                    None => block.as_slice().try_into().map_err(|_| io_protocol())?,
                };
                self.cipher = Some(Cipher::new(&self.settings.psk, &salt)?);
                self.salt = Some(salt);
            }
            self.initialized = true;
        }
        let prefix_len = self
            .settings
            .profile
            .as_ref()
            .map_or(0, |p| p.prefix_len(self.sequence));
        let mut head = vec![0; prefix_len + if self.settings.raw() { 7 } else { 23 }];
        let count = self.io.read(&mut head).await?;
        if count == 0 {
            self.physical_closed = true;
            return Ok(None);
        }
        self.io.read_exact(&mut head[count..]).await?;
        let prefix = head[..prefix_len].to_vec();
        let wire = head[prefix_len..].to_vec();
        let header = match &mut self.cipher {
            Some(cipher) => cipher.open(wire, &prefix)?,
            None => wire,
        };
        if header[0] != 4 || (self.settings.profile.is_none() && (header[1] != 0 || header[2] != 0))
        {
            return Err(io_protocol());
        }
        let pad = u16::from_be_bytes([header[3], header[4]]) as usize;
        let len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if (self.settings.version < 6 && len > 0x3fff)
            || (self.settings.version == 6 && self.settings.mode != Mode::Default && pad != 0)
        {
            return Err(io_protocol());
        }
        if len == 0 && self.settings.version < 6 && pad != 0 {
            return Err(io_protocol());
        }
        let mut padding = vec![0; pad];
        self.io.read_exact(&mut padding).await?;
        let sequence = self.sequence;
        self.sequence = self.sequence.checked_add(1).ok_or_else(io_protocol)?;
        if len == 0 {
            return Ok(None);
        }
        let mut bytes = vec![0; len + if self.cipher.is_some() { 16 } else { 0 }];
        self.io.read_exact(&mut bytes).await?;
        if let Some(profile) = &self.settings.profile {
            profile.mix(sequence, &mut padding, &mut bytes);
        } else if self.settings.version < 6 {
            interleave(&mut padding, &mut bytes);
        }
        let aad = if self.settings.profile.is_some() {
            padding.as_slice()
        } else {
            &[]
        };
        match &mut self.cipher {
            Some(cipher) => cipher.open(bytes, aad).map(Some),
            None => Ok(Some(bytes)),
        }
    }
}
pub(crate) struct Writer {
    settings: Arc<Settings>,
    cipher: Option<Cipher>,
    salt: [u8; 16],
    sent_salt: bool,
    sequence: u32,
    initial_padding: usize,
    payload_limit: usize,
    chunk_size: usize,
    last: u64,
    batch_left: usize,
    batch_limit: usize,
}
impl Writer {
    pub fn new(settings: Arc<Settings>) -> io::Result<Self> {
        let mut salt = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let cipher = if settings.raw() {
            None
        } else {
            Some(Cipher::new(&settings.psk, &salt)?)
        };
        let initial_padding = 256 + (rand::rngs::OsRng.next_u32() as usize % 256);
        Ok(Self {
            settings,
            cipher,
            salt,
            sent_salt: false,
            sequence: 0,
            initial_padding,
            payload_limit: 0,
            chunk_size: 0,
            last: 0,
            batch_left: 0,
            batch_limit: 0,
        })
    }
    pub fn maximum(&self) -> usize {
        if self.settings.version < 6 {
            0x3fff
        } else {
            65535
        }
    }
    pub fn stream_limit(&mut self) -> usize {
        let now = seconds();
        if let Some(profile) = &self.settings.profile {
            if self.last == 0 || now.saturating_sub(self.last) > profile.reset_seconds {
                self.chunk_size = profile.initial;
            }
            let limit = profile.chunk_limit(self.sequence, self.chunk_size);
            self.chunk_size = (self.chunk_size + profile.step).min(profile.maximum);
            self.last = now;
            return limit;
        }
        if self.settings.version == 6 {
            return 65535;
        }
        if self.settings.version == 5 && self.batch_left > 0 && now.saturating_sub(self.last) < 31 {
            self.last = now;
            return self.batch_limit;
        }
        let limit = if !self.sent_salt {
            1460 - 55 - self.initial_padding
        } else if self.last > 0 && now.saturating_sub(self.last) < 31 {
            self.payload_limit.max(1421)
        } else {
            1421
        };
        self.payload_limit = (limit + 1421).min(0x3fff);
        self.last = now;
        if self.settings.version == 5 {
            self.batch_left = 3 * 65536;
            self.batch_limit = limit;
        }
        limit
    }
    pub fn packet_limit(&mut self) -> usize {
        self.batch_left = 0;
        let limit = self.stream_limit();
        self.batch_left = 0;
        limit
    }
    pub fn consume(&mut self, n: usize) {
        self.batch_left = self.batch_left.saturating_sub(n);
    }
    pub fn frame(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() > self.maximum() {
            return Err(io_protocol());
        }
        let first = !self.sent_salt;
        let padding_len = if let Some(profile) = &self.settings.profile {
            profile.padding_len(self.sequence, payload.len(), first)
        } else if self.settings.version < 6 && first && !payload.is_empty() {
            self.initial_padding
        } else {
            0
        };
        let mut padding = match &self.settings.profile {
            Some(profile) => profile.filler(self.sequence, padding_len),
            None => vec![0; padding_len],
        };
        let prefix = match &self.settings.profile {
            Some(profile) => profile.filler(self.sequence, profile.prefix_len(self.sequence)),
            None => Vec::new(),
        };
        let mut header = vec![4, 0, 0];
        header.extend_from_slice(&(padding_len as u16).to_be_bytes());
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        let header = match &mut self.cipher {
            Some(cipher) => cipher.seal(&header, &prefix)?,
            None => header,
        };
        let aad = if self.settings.profile.is_some() {
            padding.as_slice()
        } else {
            &[]
        };
        let mut body = if payload.is_empty() {
            Vec::new()
        } else {
            match &mut self.cipher {
                Some(cipher) => cipher.seal(payload, aad)?,
                None => payload.to_vec(),
            }
        };
        if let Some(profile) = &self.settings.profile {
            profile.mix(self.sequence, &mut padding, &mut body);
        } else if self.settings.version < 6 {
            balanced_padding(&mut padding, &body);
            interleave(&mut padding, &mut body);
        }
        let mut out =
            Vec::with_capacity(160 + prefix.len() + header.len() + padding.len() + body.len());
        if first && !self.settings.raw() {
            match &self.settings.profile {
                Some(profile) => out.extend_from_slice(&profile.salt_block(&self.salt)),
                None => out.extend_from_slice(&self.salt),
            }
        }
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&header);
        out.extend_from_slice(&padding);
        out.extend_from_slice(&body);
        self.sent_salt = true;
        self.sequence = self.sequence.checked_add(1).ok_or_else(io_protocol)?;
        Ok(out)
    }
}
fn interleave(padding: &mut [u8], body: &mut [u8]) {
    for i in (0..padding.len().min(body.len())).step_by(2) {
        std::mem::swap(&mut padding[i], &mut body[i]);
    }
}
fn balanced_padding(padding: &mut [u8], body: &[u8]) {
    if padding.is_empty() {
        return;
    }
    let ones: usize = body[..body.len() & !3]
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum();
    let zeros = 8 * body.len() - ones;
    let ratio = ones as f64 / zeros.max(1) as f64;
    if zeros == 0 || ratio <= 0.5 || ratio >= 1.6 {
        rand::rngs::OsRng.fill_bytes(padding);
        return;
    }
    let target = if zeros < ones { 0.4 } else { 1.6 }
        + (rand::rngs::OsRng.next_u32() & 0x7fffffff) as f64 / 2147483647.0 / 10.0;
    let count = (8 * (padding.len() + body.len())) as f64 * target / (target + 1.0) - ones as f64;
    if count < 0.0 || count > 8.0 * padding.len() as f64 {
        rand::rngs::OsRng.fill_bytes(padding);
        return;
    }
    let mut positions: Vec<_> = (0..padding.len() * 8).collect();
    positions.shuffle(&mut rand::rngs::OsRng);
    padding.fill(0);
    for &position in positions.iter().take(count as usize) {
        padding[position / 8] |= 1 << (position % 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Obfs, stream::Session};
    use tokio::io::AsyncWriteExt;
    #[tokio::test]
    async fn records_preserve_boundaries_half_close_and_all_profile_paths() {
        for n in 0..64 {
            let psk = format!("snell-profile-test-key-{n}");
            for mode in [Mode::Default, Mode::Unshaped, Mode::UnsafeRaw] {
                let settings = Arc::new(
                    Settings::new(6, psk.clone(), Some(mode), Obfs::None, None, None, false)
                        .unwrap(),
                );
                let (a, b) = tokio::io::duplex(128 * 1024);
                let mut a = Session::new(Box::new(a), settings.clone()).unwrap();
                let mut b = Session::new(Box::new(b), settings).unwrap();
                for bytes in [
                    vec![n as u8; 17],
                    vec![63; 8192],
                    Vec::new(),
                    vec![23; 1024],
                ] {
                    a.send(&bytes).await.unwrap();
                    let received = b.reader.next().await.unwrap();
                    assert_eq!(received, if bytes.is_empty() { None } else { Some(bytes) });
                }
            }
        }
        let client = Arc::new(
            Settings::new(
                4,
                "snell-v4-test-key".into(),
                None,
                Obfs::None,
                None,
                None,
                false,
            )
            .unwrap(),
        );
        let server = Arc::new(
            Settings::new(
                5,
                "snell-v4-test-key".into(),
                None,
                Obfs::None,
                None,
                None,
                true,
            )
            .unwrap(),
        );
        let (a, b) = tokio::io::duplex(65536);
        let mut a = Session::new(Box::new(a), client).unwrap();
        let mut b = Session::new(Box::new(b), server).unwrap();
        a.send(b"client-record").await.unwrap();
        assert_eq!(
            b.reader.next().await.unwrap(),
            Some(b"client-record".to_vec())
        );
        b.send(b"server-record").await.unwrap();
        assert_eq!(
            a.reader.next().await.unwrap(),
            Some(b"server-record".to_vec())
        );
    }
    #[tokio::test]
    async fn malformed_record_authentication_and_truncation_are_rejected() {
        for mode in [Mode::Default, Mode::Unshaped, Mode::UnsafeRaw] {
            let settings = Arc::new(
                Settings::new(
                    6,
                    "snell-negative-test-key".into(),
                    Some(mode),
                    Obfs::None,
                    None,
                    None,
                    false,
                )
                .unwrap(),
            );
            let mut writer = Writer::new(settings.clone()).unwrap();
            let original = writer.frame(b"authenticated-record").unwrap();
            for wire in [original[..original.len() - 1].to_vec(), {
                let mut wire = original.clone();
                let index = if mode == Mode::UnsafeRaw {
                    0
                } else {
                    wire.len() - 1
                };
                wire[index] ^= 0xff;
                wire
            }] {
                let (a, b) = tokio::io::duplex(65536);
                let mut reader = Session::new(Box::new(b), settings.clone()).unwrap().reader;
                let mut a = a;
                a.write_all(&wire).await.unwrap();
                a.shutdown().await.unwrap();
                assert!(reader.next().await.is_err());
            }
        }
    }
}
