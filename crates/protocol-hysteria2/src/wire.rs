use crate::invalid;
use kerlico_core::{Error, Result};
use rand::RngCore;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const TCP_ID: u64 = 0x401;
pub(crate) const MAX_ADDRESS: usize = 2048;
pub(crate) const MAX_PAYLOAD: usize = 65_507;

pub(crate) fn varint(out: &mut Vec<u8>, value: u64) -> Result<()> {
    let width = match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1073741823 => 4,
        1073741824..=4611686018427387903 => 8,
        _ => return Err(invalid()),
    };
    let wire = value.to_be_bytes();
    let start = out.len();
    out.extend_from_slice(&wire[8 - width..]);
    out[start] |= match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    Ok(())
}
fn take_varint(input: &[u8], cursor: &mut usize) -> Result<u64> {
    let first = *input.get(*cursor).ok_or_else(invalid)?;
    let width = 1usize << (first >> 6);
    let bytes = input.get(*cursor..*cursor + width).ok_or_else(invalid)?;
    let mut value = u64::from(first & 63);
    for byte in &bytes[1..] {
        value = value << 8 | u64::from(*byte);
    }
    *cursor += width;
    Ok(value)
}
pub(crate) async fn read_varint<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<u64> {
    let first = reader.read_u8().await?;
    let width = 1usize << (first >> 6);
    let mut value = u64::from(first & 63);
    for _ in 1..width {
        value = value << 8 | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}
async fn field<R: AsyncRead + Unpin + ?Sized>(reader: &mut R, maximum: usize) -> Result<Vec<u8>> {
    let length = read_varint(reader).await?;
    if length > maximum as u64 {
        return Err(invalid());
    }
    let mut bytes = vec![0; length as usize];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub(crate) async fn request<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<String> {
    if read_varint(reader).await? != TCP_ID {
        return Err(invalid());
    }
    let address = String::from_utf8(field(reader, MAX_ADDRESS).await?).map_err(|_| invalid())?;
    crate::target(&address)?;
    let _ = field(reader, 4096).await?;
    Ok(address)
}
pub(crate) async fn send_request<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    address: &str,
) -> Result<()> {
    if address.is_empty() || address.len() > MAX_ADDRESS {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    varint(&mut bytes, TCP_ID)?;
    varint(&mut bytes, address.len() as u64)?;
    bytes.extend_from_slice(address.as_bytes());
    let mut padding = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut padding);
    varint(&mut bytes, padding.len() as u64)?;
    bytes.extend_from_slice(&padding);
    writer.write_all(&bytes).await?;
    Ok(())
}
pub(crate) async fn response<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<()> {
    let status = reader.read_u8().await?;
    let _ = field(reader, 2048).await?;
    let _ = field(reader, 4096).await?;
    if status != 0 {
        return Err(Error::Rejected);
    }
    Ok(())
}
pub(crate) async fn send_response<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    accepted: bool,
) -> Result<()> {
    writer.write_all(&[u8::from(!accepted), 0, 0]).await?;
    writer.flush().await?;
    Ok(())
}
#[derive(Clone)]
pub(crate) struct Packet {
    pub session: u32,
    pub id: u16,
    pub index: u8,
    pub count: u8,
    pub address: String,
    pub payload: Vec<u8>,
}
impl Packet {
    pub(crate) fn decode(wire: &[u8]) -> Result<Self> {
        if wire.len() < 9 {
            return Err(invalid());
        }
        let session = u32::from_be_bytes(wire[..4].try_into().map_err(|_| invalid())?);
        let id = u16::from_be_bytes(wire[4..6].try_into().map_err(|_| invalid())?);
        let (index, count) = (wire[6], wire[7]);
        if count == 0 || (count > 1 && index >= count) {
            return Err(invalid());
        }
        let mut cursor = 8;
        let length = take_varint(wire, &mut cursor)?;
        if length == 0 || length > MAX_ADDRESS as u64 {
            return Err(invalid());
        }
        let end = cursor.checked_add(length as usize).ok_or_else(invalid)?;
        let address = std::str::from_utf8(wire.get(cursor..end).ok_or_else(invalid)?)
            .map_err(|_| invalid())?
            .to_owned();
        crate::target(&address)?;
        let payload = wire.get(end..).ok_or_else(invalid)?;
        if payload.len() > MAX_PAYLOAD || (count > 1 && payload.is_empty()) {
            return Err(invalid());
        }
        Ok(Self {
            session,
            id,
            index,
            count,
            address,
            payload: payload.to_vec(),
        })
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.address.is_empty()
            || self.address.len() > MAX_ADDRESS
            || self.payload.len() > MAX_PAYLOAD
            || self.count == 0
            || (self.count > 1 && (self.index >= self.count || self.payload.is_empty()))
        {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(16 + self.address.len() + self.payload.len());
        bytes.extend_from_slice(&self.session.to_be_bytes());
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&[self.index, self.count]);
        varint(&mut bytes, self.address.len() as u64)?;
        bytes.extend_from_slice(self.address.as_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
    pub(crate) fn fragments(&self, limit: usize) -> Result<Vec<Vec<u8>>> {
        let mut empty = self.clone();
        empty.payload.clear();
        empty.count = 1;
        let overhead = empty.encode()?.len();
        let capacity = limit
            .checked_sub(overhead)
            .filter(|n| *n > 0)
            .ok_or(Error::ResourceLimit)?;
        let count = self.payload.len().div_ceil(capacity).max(1);
        if count > 255 {
            return Err(Error::ResourceLimit);
        }
        if self.payload.is_empty() {
            return Ok(vec![empty.encode()?]);
        }
        self.payload
            .chunks(capacity)
            .enumerate()
            .map(|(index, payload)| {
                Self {
                    session: self.session,
                    id: self.id,
                    index: index as u8,
                    count: count as u8,
                    address: self.address.clone(),
                    payload: payload.to_vec(),
                }
                .encode()
            })
            .collect()
    }
}
struct Partial {
    id: u16,
    address: String,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
    seen: Instant,
}
pub(crate) struct Reassembly {
    partial: Option<Partial>,
    maximum: usize,
}
impl Reassembly {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            partial: None,
            maximum,
        }
    }
    pub(crate) fn expire(&mut self, now: Instant) {
        if self
            .partial
            .as_ref()
            .is_some_and(|part| now.duration_since(part.seen) >= Duration::from_secs(5))
        {
            self.partial = None;
        }
    }
    pub(crate) fn feed(&mut self, packet: Packet) -> Result<Option<(String, Vec<u8>)>> {
        self.expire(Instant::now());
        if packet.count == 0 || (packet.count > 1 && packet.index >= packet.count) {
            return Err(invalid());
        }
        if packet.payload.len() > self.maximum {
            self.partial = None;
            return Err(Error::ResourceLimit);
        }
        if packet.count == 1 {
            self.partial = None;
            return Ok(Some((packet.address, packet.payload)));
        }
        if self
            .partial
            .as_ref()
            .is_none_or(|part| part.id != packet.id)
        {
            self.partial = Some(Partial {
                id: packet.id,
                address: packet.address.clone(),
                parts: vec![None; usize::from(packet.count)],
                bytes: 0,
                seen: Instant::now(),
            });
        }
        let partial = self.partial.as_mut().expect("分片状态已创建");
        if partial.address != packet.address || partial.parts.len() != usize::from(packet.count) {
            self.partial = None;
            return Err(invalid());
        }
        let part = &mut partial.parts[usize::from(packet.index)];
        if let Some(existing) = part {
            if existing != &packet.payload {
                self.partial = None;
                return Err(invalid());
            }
            return Ok(None);
        }
        if partial.bytes.saturating_add(packet.payload.len()) > self.maximum {
            self.partial = None;
            return Err(Error::ResourceLimit);
        }
        partial.bytes += packet.payload.len();
        *part = Some(packet.payload);
        if partial.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let partial = self.partial.take().expect("完整分片存在");
        let mut bytes = Vec::with_capacity(partial.bytes);
        for part in partial.parts {
            bytes.extend(part.expect("全部分片已到达"));
        }
        Ok(Some((partial.address, bytes)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zero_datagram_fragmentation_conflict_and_bounds() {
        for size in [0, 1, 4096, 65507] {
            let packet = Packet {
                session: 1,
                id: 2,
                index: 0,
                count: 1,
                address: "[::1]:53".into(),
                payload: vec![7; size],
            };
            let mut assembly = Reassembly::new(MAX_PAYLOAD);
            let mut result = None;
            for part in packet.fragments(1200).unwrap().into_iter().rev() {
                if let Some(value) = assembly.feed(Packet::decode(&part).unwrap()).unwrap() {
                    result = Some(value);
                }
            }
            assert_eq!(result.unwrap().1, packet.payload);
        }
        let mut assembly = Reassembly::new(10);
        let a = Packet {
            session: 1,
            id: 1,
            index: 0,
            count: 2,
            address: "a.invalid:1".into(),
            payload: vec![1],
        };
        assert!(assembly.feed(a.clone()).unwrap().is_none());
        let mut b = a;
        b.address = "b.invalid:1".into();
        assert!(assembly.feed(b).is_err());
        assert!(Packet::decode(&[0; 8]).is_err());
    }
}
