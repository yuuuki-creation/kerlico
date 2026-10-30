use super::{Progress, Settings, storage::Storage};
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{Error, Result};
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[derive(Clone, Deserialize)]
pub(crate) struct Table {
    #[serde(rename = "s")]
    slots: Vec<String>,
    #[serde(rename = "w")]
    watermark: String,
}
#[derive(Deserialize)]
pub(crate) struct Ring {
    #[serde(rename = "u")]
    pub up: Table,
    #[serde(rename = "d")]
    pub down: Table,
}
impl Ring {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 16384 {
            return Err(Error::ResourceLimit);
        }
        let ring: Self =
            serde_json::from_slice(bytes).map_err(|_| Error::Protocol("XDRIVE 槽公告不合法"))?;
        for table in [&ring.up, &ring.down] {
            if table.slots.is_empty()
                || table.slots.len() > 8
                || table.watermark.is_empty()
                || table.slots.iter().any(|s| s.is_empty() || s.len() > 512)
            {
                return Err(Error::Protocol("XDRIVE 槽数量或 ID 不合法"));
            }
        }
        Ok(ring)
    }
}
struct Frame {
    sequence: u64,
    mode: u8,
    size: usize,
    crc: u32,
    data: Vec<u8>,
}
impl Frame {
    fn decode(value: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(value)
            .map_err(|_| Error::Protocol("XDRIVE 槽编码不合法"))?;
        if bytes.len() < 25 || &bytes[..8] != b"XDRVSL01" {
            return Err(Error::Protocol("XDRIVE 槽头不合法"));
        }
        let sequence = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| Error::Protocol("XDRIVE 槽序号不合法"))?,
        );
        let size = u32::from_be_bytes(
            bytes[17..21]
                .try_into()
                .map_err(|_| Error::Protocol("XDRIVE 槽长度不合法"))?,
        ) as usize;
        if size > 1024 * 1024 {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            sequence,
            mode: bytes[16],
            size,
            crc: u32::from_be_bytes(
                bytes[21..25]
                    .try_into()
                    .map_err(|_| Error::Protocol("XDRIVE 槽校验不合法"))?,
            ),
            data: bytes[25..].to_vec(),
        })
    }
    fn encode(sequence: u64, mode: u8, data: &[u8]) -> String {
        let mut bytes = b"XDRVSL01".to_vec();
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.push(mode);
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&crc32fast::hash(data).to_be_bytes());
        if mode == 1 {
            bytes.extend_from_slice(data);
        }
        STANDARD.encode(bytes)
    }
}
pub(crate) async fn read<W: AsyncWrite + Unpin>(
    store: Arc<dyn Storage>,
    mut writer: W,
    table: Table,
    settings: &Settings,
) -> Result<()> {
    let mut sequence = 0u64;
    let mut progress = Instant::now();
    loop {
        let description = store
            .description(&table.slots[sequence as usize % table.slots.len()])
            .await?;
        if let Ok(frame) = Frame::decode(&description)
            && frame.sequence == sequence
        {
            match frame.mode {
                1 | 2 => {
                    let data = if frame.mode == 1 {
                        frame.data
                    } else {
                        store
                            .slot_body(&table.slots[sequence as usize % table.slots.len()])
                            .await?
                    };
                    if data.len() != frame.size || crc32fast::hash(&data) != frame.crc {
                        tokio::time::sleep(Duration::from_millis(settings.poll_interval_ms)).await;
                        continue;
                    }
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                    store
                        .set_slot(&table.watermark, sequence.to_string(), None)
                        .await?;
                    sequence = sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
                    progress = Instant::now();
                    continue;
                }
                3 => {
                    store
                        .set_slot(&table.watermark, sequence.to_string(), None)
                        .await?;
                    writer.shutdown().await?;
                    return Ok(());
                }
                4 => return Err(Error::Protocol("XDRIVE 对端槽失败")),
                _ => return Err(Error::Protocol("XDRIVE 槽类型不合法")),
            }
        }
        if progress.elapsed() > Duration::from_secs(60) {
            return Err(Error::Timeout);
        }
        tokio::time::sleep(Duration::from_millis(settings.poll_interval_ms)).await;
    }
}
pub(crate) async fn write<R: AsyncRead + Unpin>(
    store: Arc<dyn Storage>,
    mut reader: R,
    table: Table,
    settings: &Settings,
    progress: Arc<Progress>,
) -> Result<()> {
    let mut sequence = 0u64;
    let mut buffer = vec![0; settings.segment_bytes.min(65536)];
    loop {
        let count = reader.read(&mut buffer).await?;
        let start = Instant::now();
        if sequence >= table.slots.len() as u64 {
            let needed = sequence - table.slots.len() as u64;
            loop {
                let mark = store
                    .description(&table.watermark)
                    .await?
                    .parse::<i64>()
                    .unwrap_or(-1);
                if mark >= 0 && mark as u64 >= needed {
                    break;
                }
                if start.elapsed() > Duration::from_secs(60) {
                    return Err(Error::Timeout);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        let data = &buffer[..count];
        let mode = if count == 0 {
            3
        } else if count <= 14 * 1024 {
            1
        } else {
            2
        };
        let header = Frame::encode(sequence, mode, data);
        store
            .set_slot(
                &table.slots[sequence as usize % table.slots.len()],
                header,
                (mode == 2).then(|| data.to_vec()),
            )
            .await?;
        progress.committed(count);
        if count == 0 {
            return Ok(());
        }
        sequence = sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
    }
}
