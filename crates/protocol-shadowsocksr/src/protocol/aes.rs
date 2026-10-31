use super::{Codec, padding_end, short_padding};
use crate::{crypto, invalid};
use kerlico_core::Result;
impl Codec {
    pub(super) fn aes_auth(&self, metadata: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let padding = crypto::random(usize::from(crypto::random(1)[0] % 32));
        let length = 35 + padding.len() + data.len();
        if length >= 8192 {
            return Err(invalid());
        }
        let hash = self.cfg.protocol.hash();
        let key = self.base_mac_key(&self.send_iv);
        let mut bytes = crypto::random(1);
        let check = crypto::mac(hash, &key, &bytes);
        bytes.extend_from_slice(&check[..6]);
        let mut head = metadata.to_vec();
        head.extend_from_slice(&(length as u16).to_le_bytes());
        head.extend_from_slice(&(padding.len() as u16).to_le_bytes());
        let mut middle = self.uid.to_le_bytes().to_vec();
        middle.extend(crypto::aes_block(&self.block_password(), &head, true)?);
        let check = crypto::mac(hash, &key, &middle);
        middle.extend_from_slice(&check[..4]);
        bytes.extend(middle);
        bytes.extend(padding);
        bytes.extend_from_slice(data);
        let check = crypto::mac(hash, &self.user_key, &bytes);
        bytes.extend_from_slice(&check[..4]);
        Ok(bytes)
    }
    pub(super) fn aes_header(&mut self, time: u32) -> Result<bool> {
        let hash = self.cfg.protocol.hash();
        let key = self.base_mac_key(&self.recv_iv);
        if self.buffer.len() < 7 {
            return Ok(false);
        }
        let expected = crypto::mac(hash, &key, &self.buffer[..1]);
        if !crypto::equal(&expected[..6], &self.buffer[1..7]) {
            return Err(invalid());
        }
        if self.buffer.len() < 31 {
            return Ok(false);
        }
        let expected = crypto::mac(hash, &key, &self.buffer[7..27]);
        if !crypto::equal(&expected[..4], &self.buffer[27..31]) {
            return Err(invalid());
        }
        let uid = u32::from_le_bytes(self.buffer[7..11].try_into().map_err(|_| invalid())?);
        let (uid, user_key) = self.user(uid)?;
        self.uid = uid;
        self.user_key = user_key;
        let head = crypto::aes_block(&self.block_password(), &self.buffer[11..27], false)?;
        let length = usize::from(u16::from_le_bytes(
            head[12..14].try_into().map_err(|_| invalid())?,
        ));
        let padding = usize::from(u16::from_le_bytes(
            head[14..16].try_into().map_err(|_| invalid())?,
        ));
        if !(35..8192).contains(&length) || 31 + padding > length - 4 {
            return Err(invalid());
        }
        if self.buffer.len() < length {
            return Ok(false);
        }
        let expected = crypto::mac(hash, &self.user_key, &self.buffer[..length - 4]);
        if !crypto::equal(&expected[..4], &self.buffer[length - 4..length]) {
            return Err(invalid());
        }
        self.cfg.replay.auth(
            self.cfg.protocol.salt(),
            uid,
            &head[..12],
            self.cfg.limits.auth_window_secs,
            time,
        )?;
        self.header_payload = self.buffer[31 + padding..length - 4].to_vec();
        self.buffer.drain(..length);
        Ok(true)
    }
    pub(super) fn aes_data(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let padding = short_padding();
        let length = 4 + padding.len() + data.len() + 4;
        if length >= 8192 {
            return Err(invalid());
        }
        let hash = self.cfg.protocol.hash();
        let key = self.packet_key(self.send_id);
        let mut bytes = (length as u16).to_le_bytes().to_vec();
        let check = crypto::mac(hash, &key, &bytes);
        bytes.extend_from_slice(&check[..2]);
        bytes.extend(padding);
        bytes.extend_from_slice(data);
        let check = crypto::mac(hash, &key, &bytes);
        bytes.extend_from_slice(&check[..4]);
        self.next_send()?;
        Ok(bytes)
    }
    pub(super) fn aes_decode(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let hash = self.cfg.protocol.hash();
        let key = self.packet_key(self.receive_id);
        let expected = crypto::mac(hash, &key, &self.buffer[..2]);
        if !crypto::equal(&expected[..2], &self.buffer[2..4]) {
            return Err(invalid());
        }
        let length = usize::from(u16::from_le_bytes(
            self.buffer[..2].try_into().map_err(|_| invalid())?,
        ));
        if !(9..8192).contains(&length) {
            return Err(invalid());
        }
        if self.buffer.len() < length {
            return Ok(None);
        }
        let frame = self.buffer[..length].to_vec();
        let expected = crypto::mac(hash, &key, &frame[..length - 4]);
        if !crypto::equal(&expected[..4], &frame[length - 4..]) {
            return Err(invalid());
        }
        let offset = padding_end(&frame, 4, false, 4)?;
        let data = frame[offset..length - 4].to_vec();
        self.buffer.drain(..length);
        self.next_receive()?;
        Ok(Some(data))
    }
}
