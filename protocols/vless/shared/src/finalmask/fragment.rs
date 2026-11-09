use std::io::{self, Write};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use super::wire_writer::{Segment, WireWriter};
use super::{invalid, settings, Range};

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    packets: String,
    length: Range,
    delay: Range,
    lengths: Vec<Range>,
    delays: Vec<Range>,
    max_split: Range,
}

#[derive(Clone)]
pub(super) struct Fragment {
    packets: Packets,
    lengths: Vec<Range>,
    delays: Vec<Range>,
    max_split: Range,
}

#[derive(Clone, Copy)]
enum Packets {
    All,
    TlsHello,
    Writes(Range),
}

impl Fragment {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        let mut config: Config = settings(value)?;
        let packets = match config.packets.to_ascii_lowercase().as_str() {
            "" => Packets::All,
            "tlshello" => Packets::TlsHello,
            other => {
                let range = Range::parse(other)?;
                if range.min == 0 {
                    return Err(invalid("fragment packets starts at write 1"));
                }
                Packets::Writes(range)
            }
        };
        if config.lengths.is_empty() {
            config.lengths.push(config.length);
        }
        if config.delays.is_empty() {
            config.delays.push(config.delay);
        }
        if config.lengths.last().is_some_and(|len| len.min == 0) {
            return Err(invalid("fragment last length must be positive"));
        }
        Ok(Self { packets, lengths: config.lengths, delays: config.delays, max_split: config.max_split })
    }

    pub(super) fn writer(&self, inner: Box<dyn Write + Send>) -> Writer {
        Writer { inner: WireWriter::new(inner), config: self.clone(), count: 0 }
    }

    fn segment(&self, remaining: usize, index: usize, max_split: usize) -> usize {
        if max_split != 0 && index + 1 >= max_split {
            return remaining;
        }
        let length = self.lengths[index.min(self.lengths.len() - 1)];
        remaining.min(length.pick() as usize)
    }

    fn delay(&self, index: usize) -> Duration {
        let delay = self.delays[index.min(self.delays.len() - 1)].pick();
        Duration::from_millis(u64::from(delay))
    }
}

pub(super) struct Writer {
    inner: WireWriter,
    config: Fragment,
    count: u64,
}

impl Writer {
    fn write_tls_hello(&mut self, packet: &[u8]) -> io::Result<usize> {
        if packet.len() <= 5 || packet[0] != 22 {
            return self.inner.direct(packet);
        }
        let length = usize::from(u16::from_be_bytes([packet[3], packet[4]]));
        let Some(body) = packet.get(5..5 + length) else {
            return self.inner.direct(packet);
        };
        let merge = self.config.delays.len() == 1 && self.config.delays[0].max == 0;
        let max_split = self.config.max_split.pick() as usize;
        let mut wire = Vec::new();
        let mut segments = Vec::new();
        let mut start = 0;
        for index in 0.. {
            let len = self.config.segment(body.len() - start, index, max_split);
            let end = start + len;
            wire.extend_from_slice(&packet[..3]);
            wire.extend_from_slice(&(len as u16).to_be_bytes());
            wire.extend_from_slice(&body[start..end]);
            if !merge {
                segments.push(Segment { end: wire.len(), delay: self.config.delay(index) });
            }
            if end == body.len() {
                break;
            }
            start = end;
        }
        if merge {
            segments.push(Segment { end: wire.len(), delay: Duration::ZERO });
        }
        // Any bytes following the hello record remain unmodified.
        self.inner.frame(&packet[..5 + length], wire, segments)
    }

    fn write_segments(&mut self, packet: &[u8]) -> io::Result<usize> {
        let max_split = self.config.max_split.pick() as usize;
        let mut offset = 0;
        let mut segments = Vec::new();
        for index in 0.. {
            let len = self.config.segment(packet.len() - offset, index, max_split);
            offset += len;
            segments.push(Segment { end: offset, delay: self.config.delay(index) });
            if offset == packet.len() {
                break;
            }
        }
        self.inner.frame(packet, packet.to_vec(), segments)
    }
}

impl Write for Writer {
    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        if packet.is_empty() {
            return Ok(0);
        }
        let count = self.count.saturating_add(1);
        let n = if let Some(used) = self.inner.resume(packet)? {
            used
        } else {
            match self.config.packets {
                Packets::TlsHello if count == 1 => self.write_tls_hello(packet),
                Packets::All => self.write_segments(packet),
                Packets::Writes(range) if (u64::from(range.min)..=u64::from(range.max)).contains(&count) => self.write_segments(packet),
                _ => self.inner.direct(packet),
            }?
        };
        if n != 0 {
            self.count = count;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::wire_writer::tests::Pause;
    use std::sync::{Arc, Mutex};

    #[test]
    fn tls_hello_retries_resume_at_every_wire_offset() {
        let config = Fragment::parse(serde_json::json!({"packets":"tlshello", "length":2, "delays":[0,0]})).unwrap();
        let source = [22, 3, 1, 0, 6, 11, 12, 13, 14, 15, 16, 0xff];
        let expected = [22, 3, 1, 0, 2, 11, 12, 22, 3, 1, 0, 2, 13, 14, 22, 3, 1, 0, 2, 15, 16, 0xff];
        for at in 0..expected.len() - 1 {
            let wire = Arc::new(Mutex::new(Vec::new()));
            let kind = if at % 2 == 0 { io::ErrorKind::WouldBlock } else { io::ErrorKind::TimedOut };
            let mut writer = config.writer(Box::new(Pause { at: Some(at), kind, wire: wire.clone() }));
            assert_eq!(writer.write(&source).unwrap_err().kind(), kind);
            assert_eq!(*wire.lock().unwrap(), expected[..at]);
            if at % 2 == 1 {
                writer.flush().unwrap();
            }
            assert_eq!(writer.write(&source).unwrap(), source.len() - 1);
            writer.write_all(&source[source.len() - 1..]).unwrap();
            assert_eq!(*wire.lock().unwrap(), expected, "paused after {at} wire bytes");
        }
    }

    #[test]
    fn plain_fragments_retry_without_replaying_partial_bytes() {
        let config = Fragment::parse(serde_json::json!({"packets":"1-1", "length":2})).unwrap();
        let wire = Arc::new(Mutex::new(Vec::new()));
        let mut writer = config.writer(Box::new(Pause {
            at: Some(3),
            kind: io::ErrorKind::WouldBlock,
            wire: wire.clone(),
        }));
        assert_eq!(writer.write(b"abcdef").unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(writer.write(b"abcdefg").unwrap(), 6);
        writer.write_all(b"g").unwrap();
        assert_eq!(*wire.lock().unwrap(), b"abcdefg");
    }
}
