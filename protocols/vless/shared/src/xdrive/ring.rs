use std::collections::HashSet;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use super::{ObjectKind, Params, Polling, MAX_SEGMENT_BYTES};

const MAGIC: &[u8; 8] = b"XDRVSL01";
const HEADER: usize = 25;
const MAX_DEPTH: usize = 8;
const INLINE_LIMIT: usize = 14 * 1024;
const STALL: Duration = Duration::from_secs(60);
const ACK_POLL: Duration = Duration::from_millis(100);

pub(super) trait Slots: Send + Sync {
    fn create_slot(&self, name: &str) -> io::Result<String>;
    fn set(&self, id: &str, description: &str, data: Option<&[u8]>) -> io::Result<()>;
    fn description(&self, id: &str) -> io::Result<String>;
    fn body(&self, id: &str) -> io::Result<Vec<u8>>;
}

#[derive(Deserialize, Serialize)]
pub(super) struct Table {
    #[serde(rename = "s")]
    slots: Vec<String>,
    #[serde(rename = "w")]
    watermark: String,
}

impl Table {
    fn slot(&self, seq: u64) -> &str {
        &self.slots[(seq % self.slots.len() as u64) as usize]
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct Ring {
    #[serde(rename = "u")]
    up: Table,
    #[serde(rename = "d")]
    down: Table,
}

impl Ring {
    pub fn make(storage: &dyn Slots, session: &str, concurrency: usize) -> io::Result<Self> {
        let depth = concurrency.clamp(2, MAX_DEPTH);
        thread::scope(|scope| {
            let make = |direction: &str| {
                let prefix = format!("streams/{session}/{direction}");
                let slots: Vec<_> = (0..depth)
                    .map(|index| {
                        let name = format!("{prefix}/s{index}");
                        scope.spawn(move || storage.create_slot(&name))
                    })
                    .collect();
                let mark = scope.spawn(move || storage.create_slot(&format!("{prefix}/w")));
                (slots, mark)
            };
            let up = make("c2s");
            let down = make("s2c");
            let resolve = |(slots, mark): (
                Vec<thread::ScopedJoinHandle<'_, io::Result<String>>>,
                thread::ScopedJoinHandle<'_, io::Result<String>>,
            )| {
                Ok::<_, io::Error>(Table {
                    slots: slots
                        .into_iter()
                        .map(|slot| {
                            slot.join()
                                .map_err(|_| io::Error::other("XDrive slot creation"))?
                        })
                        .collect::<io::Result<_>>()?,
                    watermark: mark
                        .join()
                        .map_err(|_| io::Error::other("XDrive watermark creation"))??,
                })
            };
            Ok(Self {
                up: resolve(up)?,
                down: resolve(down)?,
            })
        })
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let ring: Self = serde_json::from_slice(bytes).ok()?;
        let mut ids = HashSet::new();
        for table in [&ring.up, &ring.down] {
            if table.slots.is_empty()
                || table.slots.len() > MAX_DEPTH
                || !table
                    .slots
                    .iter()
                    .chain([&table.watermark])
                    .all(|id| !id.is_empty() && ids.insert(id))
            {
                return None;
            }
        }
        Some(ring)
    }

    pub fn directions(self, client: bool) -> (Table, Table) {
        if client {
            (self.up, self.down)
        } else {
            (self.down, self.up)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Inline = 1,
    Media = 2,
    End = 3,
    Failed = 4,
}

struct Frame {
    seq: u64,
    mode: Mode,
    size: usize,
    crc: u32,
    inline: Vec<u8>,
}

impl Frame {
    fn encode(seq: u64, mode: Mode, data: &[u8]) -> String {
        let mut frame =
            Vec::with_capacity(HEADER + if mode == Mode::Inline { data.len() } else { 0 });
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.push(mode as u8);
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(&crc32fast::hash(data).to_be_bytes());
        if mode == Mode::Inline {
            frame.extend_from_slice(data);
        }
        STANDARD.encode(frame)
    }

    fn decode(description: &str) -> Option<Self> {
        let bytes = STANDARD.decode(description).ok()?;
        if bytes.len() < HEADER || !bytes.starts_with(MAGIC) {
            return None;
        }
        let mode = match bytes[16] {
            1 => Mode::Inline,
            2 => Mode::Media,
            3 => Mode::End,
            4 => Mode::Failed,
            _ => return None,
        };
        let frame = Self {
            seq: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
            mode,
            size: u32::from_be_bytes(bytes[17..21].try_into().ok()?) as usize,
            crc: u32::from_be_bytes(bytes[21..25].try_into().ok()?),
            inline: bytes[HEADER..].to_vec(),
        };
        (frame.size <= MAX_SEGMENT_BYTES && (mode != Mode::Inline || frame.holds(&frame.inline)))
            .then_some(frame)
    }

    fn holds(&self, bytes: &[u8]) -> bool {
        bytes.len() == self.size && crc32fast::hash(bytes) == self.crc
    }
}

pub(super) struct Writer<'a> {
    storage: &'a dyn Slots,
    table: &'a Table,
    acked: Option<u64>,
}

impl<'a> Writer<'a> {
    pub fn new(storage: &'a dyn Slots, table: &'a Table) -> Self {
        Self {
            storage,
            table,
            acked: None,
        }
    }

    pub fn write(&mut self, seq: u64, kind: ObjectKind, bytes: &[u8]) -> io::Result<()> {
        let mode = match kind {
            ObjectKind::Segment if bytes.len() <= INLINE_LIMIT => Mode::Inline,
            ObjectKind::Segment => Mode::Media,
            ObjectKind::End => Mode::End,
            ObjectKind::Failed => Mode::Failed,
        };
        if let Some(previous) = seq.checked_sub(self.table.slots.len() as u64) {
            let start = Instant::now();
            while self.acked.is_none_or(|acked| acked < previous) {
                let description = self.storage.description(&self.table.watermark)?;
                self.acked = self.acked.max(description.parse::<u64>().ok());
                if self.acked.is_some_and(|acked| acked >= previous) {
                    break;
                }
                if start.elapsed() >= STALL {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "XDrive slot watermark stalled",
                    ));
                }
                thread::sleep(ACK_POLL);
            }
        }
        self.storage.set(
            self.table.slot(seq),
            &Frame::encode(seq, mode, bytes),
            (mode == Mode::Media).then_some(bytes),
        )
    }
}

pub(super) fn read(
    storage: &dyn Slots,
    table: &Table,
    params: Params,
    output: &mpsc::SyncSender<io::Result<Vec<u8>>>,
    quit: &AtomicBool,
) -> io::Result<()> {
    let mut seq = 0;
    let mut missing = None;
    let mut polling = Polling::new(params);
    while !quit.load(Ordering::Relaxed) {
        let slot = table.slot(seq);
        let frame = match storage.description(slot) {
            Ok(description) => {
                missing = None;
                Frame::decode(&description).filter(|frame| frame.seq == seq)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if missing.get_or_insert_with(Instant::now).elapsed() >= STALL {
                    return Err(error);
                }
                None
            }
            Err(error) => return Err(error),
        };
        let Some(frame) = frame else {
            thread::park_timeout(polling.delay(false));
            continue;
        };
        let body = match frame.mode {
            Mode::End => return Ok(()),
            Mode::Failed => {
                return Err(io::Error::other(format!(
                    "peer could not store XDrive slot segment {seq}"
                )))
            }
            Mode::Inline => frame.inline,
            Mode::Media => match storage.body(slot) {
                Ok(body) if frame.holds(&body) => body,
                Ok(_) => {
                    thread::park_timeout(polling.delay(false));
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    thread::park_timeout(polling.delay(false));
                    continue;
                }
                Err(error) => return Err(error),
            },
        };
        if output.send(Ok(body)).is_err() {
            return Ok(());
        }
        storage.set(&table.watermark, &seq.to_string(), None)?;
        seq += 1;
        polling.delay(true);
    }
    Ok(())
}
