use super::{Codec, padding_end, short_padding};
use crate::{
    crypto::{self, Hash},
    invalid,
};
use kerlico_core::Result;
impl Codec {
    pub(super) fn v4_auth(&self, metadata: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let padding = short_padding();
        let length = 2 + 4 + padding.len() + metadata.len() + data.len() + 10;
        if length >= 8192 {
            return Err(invalid());
        }
        let mut bytes = (length as u16).to_be_bytes().to_vec();
        let mut check = bytes.clone();
        check.extend_from_slice(self.cfg.protocol.salt());
        check.extend_from_slice(&self.cfg.key);
        bytes.extend_from_slice(&crc32fast::hash(&check).to_le_bytes());
        bytes.extend(padding);
        bytes.extend_from_slice(metadata);
        bytes.extend_from_slice(data);
        let mac = crypto::mac(Hash::Sha1, &self.base_mac_key(&self.send_iv), &bytes);
        bytes.extend_from_slice(&mac[..10]);
        Ok(bytes)
    }
    pub(super) fn v4_header(&mut self, time: u32) -> Result<bool> {
        if self.buffer.len() < 6 {
            return Ok(false);
        }
        let length = usize::from(u16::from_be_bytes(
            self.buffer[..2].try_into().map_err(|_| invalid())?,
        ));
        if !(29..8192).contains(&length) {
            return Err(invalid());
        }
        let mut check = self.buffer[..2].to_vec();
        check.extend_from_slice(self.cfg.protocol.salt());
        check.extend_from_slice(&self.cfg.key);
        if !crypto::equal(&crc32fast::hash(&check).to_le_bytes(), &self.buffer[2..6]) {
            return Err(invalid());
        }
        if self.buffer.len() < length {
            return Ok(false);
        }
        let frame = self.buffer[..length].to_vec();
        let expected = crypto::mac(
            Hash::Sha1,
            &self.base_mac_key(&self.recv_iv),
            &frame[..length - 10],
        );
        if !crypto::equal(&expected[..10], &frame[length - 10..]) {
            return Err(invalid());
        }
        let offset = padding_end(&frame, 6, true, 10)?;
        let plain = &frame[offset..length - 10];
        if plain.len() < 12 {
            return Err(invalid());
        }
        self.cfg.replay.auth(
            self.cfg.protocol.salt(),
            0,
            &plain[..12],
            self.cfg.limits.auth_window_secs,
            time,
        )?;
        self.header_payload = plain[12..].to_vec();
        self.buffer.drain(..length);
        Ok(true)
    }
    pub(super) fn v4_data(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let padding = short_padding();
        let length = 2 + 2 + padding.len() + data.len() + 4;
        if length >= 8192 {
            return Err(invalid());
        }
        let mut bytes = (length as u16).to_be_bytes().to_vec();
        let crc = (crc32fast::hash(&bytes) & 0xffff) as u16;
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes.extend(padding);
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&crypto::adler(&bytes).to_le_bytes());
        Ok(bytes)
    }
    pub(super) fn v4_decode(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let length = usize::from(u16::from_be_bytes(
            self.buffer[..2].try_into().map_err(|_| invalid())?,
        ));
        if !(9..8192).contains(&length) {
            return Err(invalid());
        }
        let crc = (crc32fast::hash(&self.buffer[..2]) & 0xffff) as u16;
        if !crypto::equal(&crc.to_le_bytes(), &self.buffer[2..4]) {
            return Err(invalid());
        }
        if self.buffer.len() < length {
            return Ok(None);
        }
        let frame = self.buffer[..length].to_vec();
        if !crypto::equal(
            &crypto::adler(&frame[..length - 4]).to_le_bytes(),
            &frame[length - 4..],
        ) {
            return Err(invalid());
        }
        let offset = padding_end(&frame, 4, true, 4)?;
        let data = frame[offset..length - 4].to_vec();
        self.buffer.drain(..length);
        self.next_receive()?;
        Ok(Some(data))
    }
}
