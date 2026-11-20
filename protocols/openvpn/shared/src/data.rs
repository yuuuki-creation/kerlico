use std::io;

use ring::aead::{self, Aad, LessSafeKey, Nonce, Tag, UnboundKey};
use rustls::Connection;
use zeroize::Zeroizing;

use crate::{invalid, wire::DATA};

pub(crate) const CIPHER: &str = "AES-256-GCM";
const HEADER_LEN: usize = 8;
const TAG_LEN: usize = 16;
const DATA_OFFSET: usize = HEADER_LEN + TAG_LEN;
pub(crate) const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

struct Direction {
    key: LessSafeKey,
    salt: [u8; 8],
}

impl Direction {
    fn new(key: &[u8]) -> io::Result<Self> {
        Ok(Self {
            key: LessSafeKey::new(
                UnboundKey::new(&aead::AES_256_GCM, &key[..32])
                    .map_err(|_| invalid("invalid data key"))?,
            ),
            salt: key[64..72].try_into().unwrap(),
        })
    }

    fn nonce(&self, id: [u8; 4]) -> Nonce {
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&id);
        nonce[4..].copy_from_slice(&self.salt);
        Nonce::assume_unique_for_key(nonce)
    }
}

pub(crate) struct Data {
    send: Direction,
    receive: Direction,
    peer: [u8; 4],
    next: u32,
    highest: u32,
    window: u128,
}

impl Data {
    pub fn new(tls: &Connection, server: bool, peer: u32) -> io::Result<Self> {
        if peer >= 0xff_ffff {
            return Err(invalid("invalid data peer ID"));
        }
        let mut material = Zeroizing::new([0u8; 256]);
        tls.export_keying_material(&mut material[..], b"EXPORTER-OpenVPN-datakeys", None)
            .map_err(io::Error::other)?;
        Self::from_material(&material, server, peer)
    }

    fn from_material(material: &[u8; 256], server: bool, peer: u32) -> io::Result<Self> {
        let (client, server_key) = material.split_at(128);
        let (send, receive) = if server {
            (server_key, client)
        } else {
            (client, server_key)
        };
        Ok(Self {
            send: Direction::new(send)?,
            receive: Direction::new(receive)?,
            peer: ((u32::from(DATA) << 27) | peer).to_be_bytes(),
            next: 0,
            highest: 0,
            window: 0,
        })
    }

    pub fn seal(&mut self, packet: &[u8], frame: &mut Vec<u8>) -> io::Result<()> {
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("data packet ID exhausted"))?;
        let seq = self.next.to_be_bytes();
        let mut header = [0; HEADER_LEN];
        header[..4].copy_from_slice(&self.peer);
        header[4..].copy_from_slice(&seq);
        frame.clear();
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&[0; TAG_LEN]);
        frame.extend_from_slice(packet);
        let tag = self
            .send
            .key
            .seal_in_place_separate_tag(
                self.send.nonce(seq),
                Aad::from(header),
                &mut frame[DATA_OFFSET..],
            )
            .map_err(|_| invalid("data encryption failed"))?;
        frame[HEADER_LEN..DATA_OFFSET].copy_from_slice(tag.as_ref());
        Ok(())
    }

    pub fn open(&mut self, mut frame: Vec<u8>) -> Option<Vec<u8>> {
        let (header, rest) = frame.split_first_chunk::<HEADER_LEN>()?;
        let header = *header;
        if header[..4] != self.peer {
            return None;
        }
        let id: [u8; 4] = header[4..].try_into().unwrap();
        let seq = u32::from_be_bytes(id);
        let delta = self.highest.saturating_sub(seq);
        if seq == 0
            || delta >= u128::BITS
            || (seq <= self.highest && self.window & (1 << delta) != 0)
        {
            return None;
        }
        let tag = Tag::from(*rest.first_chunk::<TAG_LEN>()?);
        let len = self
            .receive
            .key
            .open_in_place_separate_tag(
                self.receive.nonce(id),
                Aad::from(header),
                tag,
                &mut frame,
                DATA_OFFSET..,
            )
            .ok()?
            .len();
        frame.truncate(len);
        if seq > self.highest {
            self.window = self.window.checked_shl(seq - self.highest).unwrap_or(0);
            self.highest = seq;
        }
        self.window |= 1 << delta;
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticates_before_advancing_the_replay_window() -> io::Result<()> {
        let mut material = [1; 256];
        material[128..].fill(2);
        let mut client = Data::from_material(&material, false, 42)?;
        let mut server = Data::from_material(&material, true, 42)?;
        let mut first = Vec::new();
        let mut second = Vec::new();
        client.seal(b"first", &mut first)?;
        client.seal(b"second", &mut second)?;
        let mut tampered = second.clone();
        tampered[8] ^= 1;
        assert!(server.open(tampered).is_none());
        assert_eq!(server.open(second).as_deref(), Some(&b"second"[..]));
        assert_eq!(server.open(first.clone()).as_deref(), Some(&b"first"[..]));
        assert!(server.open(first).is_none());
        let mut reply = Vec::new();
        server.seal(b"reply", &mut reply)?;
        assert_eq!(client.open(reply).as_deref(), Some(&b"reply"[..]));
        Ok(())
    }
}
