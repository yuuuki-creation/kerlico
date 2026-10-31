//! 一个 Packet 是一个业务包或其协议分片；v4 不透明分割数据报。
use crate::codec::{self, Mode, Packet};
use kerlico_core::{Destination, Error, Result};
pub(crate) async fn uni(connection: &quinn::Connection, bytes: &[u8]) -> Result<()> {
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|_| codec::malformed())?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, bytes).await?;
    stream.finish().map_err(|_| codec::malformed())?;
    Ok(())
}
pub(crate) async fn send(
    connection: &quinn::Connection,
    version: u8,
    mode: Mode,
    assoc: u32,
    id: u16,
    target: &Destination,
    bytes: &[u8],
) -> Result<()> {
    if bytes.len() > codec::MAX_PACKET {
        return Err(Error::ResourceLimit);
    }
    let initial = Packet {
        assoc,
        id,
        total: 1,
        fragment: 0,
        target: Some(target.clone()),
        data: bytes.to_vec(),
    };
    if mode == Mode::Quic {
        return uni(connection, &codec::packet(version, &initial)?).await;
    }
    let limit = connection
        .max_datagram_size()
        .ok_or(Error::Unsupported("TUIC 对端未启用 QUIC datagram"))?;
    let wire = codec::packet(version, &initial)?;
    if wire.len() <= limit {
        return connection
            .send_datagram(bytes::Bytes::from(wire))
            .map_err(|_| Error::ResourceLimit);
    }
    if version == 4 {
        return Err(Error::Unsupported(
            "TUIC v4 native 不支持超过 QUIC datagram MTU 的包",
        ));
    }
    let mut address = Vec::new();
    codec::address(&mut address, Some(target));
    let size = limit
        .checked_sub(10 + address.len())
        .filter(|v| *v > 0)
        .ok_or(Error::ResourceLimit)?;
    let count = bytes.len().div_ceil(size);
    if count == 0 || count > 255 {
        return Err(Error::ResourceLimit);
    }
    for (index, part) in bytes.chunks(size).enumerate() {
        let fragment = Packet {
            assoc,
            id,
            total: count as u8,
            fragment: index as u8,
            target: (index == 0).then(|| target.clone()),
            data: part.to_vec(),
        };
        let wire = codec::packet(version, &fragment)?;
        connection
            .send_datagram(bytes::Bytes::from(wire))
            .map_err(|_| Error::ResourceLimit)?;
        tokio::task::yield_now().await;
    }
    Ok(())
}

/// 分片编号在重组窗口内不复用；它不是密码 nonce。
pub(crate) struct PacketSequence {
    next: u32,
    cycle: tokio::time::Instant,
}
impl PacketSequence {
    pub fn new() -> Self {
        Self {
            next: 0,
            cycle: tokio::time::Instant::now(),
        }
    }
    pub async fn next(&mut self) -> u16 {
        if self.next > 65535 {
            tokio::time::sleep_until(self.cycle + std::time::Duration::from_secs(5)).await;
            self.next = 0;
            self.cycle = tokio::time::Instant::now();
        }
        let value = self.next as u16;
        self.next += 1;
        value
    }
}
