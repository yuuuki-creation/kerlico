mod go_rng;
mod table;

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::{seq::SliceRandom, RngExt};
use serde::Deserialize;
use serde_json::Value;

use super::wire_writer::{Segment, WireWriter};
use super::{invalid, malformed, settings, PacketIo, Range, Side, TcpPair, UDP_POLL};
use table::{Codebook, Layout};

const MAX_UDP_WIRE: usize = 65_507;
const CHUNK: usize = 32 * 1024;

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    password: String,
    ascii: String,
    custom_table: String,
    custom_tables: Vec<String>,
    #[serde(rename = "custom_table")]
    legacy_custom_table: String,
    #[serde(rename = "custom_tables")]
    legacy_custom_tables: Vec<String>,
    padding_min: u32,
    padding_max: u32,
    #[serde(rename = "padding_min")]
    legacy_padding_min: u32,
    #[serde(rename = "padding_max")]
    legacy_padding_max: u32,
}

#[derive(Clone)]
pub(super) struct Sudoku {
    book: Arc<Codebook>,
    layouts: Arc<[Layout]>,
    padding: Range,
}

impl Sudoku {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        let config: Config = settings(value)?;
        let layouts = match config.ascii.trim().to_ascii_lowercase().as_str() {
            "prefer_ascii" | "ascii" => vec![Layout::ascii()],
            "prefer_entropy" | "entropy" | "" => {
                let mut patterns = if config.custom_tables.is_empty() { config.legacy_custom_tables } else { config.custom_tables };
                if patterns.is_empty() {
                    patterns.push(if config.custom_table.is_empty() { config.legacy_custom_table } else { config.custom_table });
                }
                let mut seen = Vec::new();
                let mut layouts = Vec::new();
                for pattern in patterns {
                    let pattern = Layout::normalize_pattern(&pattern)?;
                    if seen.contains(&pattern) {
                        continue;
                    }
                    layouts.push(if pattern.is_empty() { Layout::entropy() } else { Layout::custom(&pattern) });
                    seen.push(pattern);
                }
                layouts
            }
            _ => return Err(invalid("invalid Sudoku ascii mode")),
        };
        let min = if config.padding_min == 0 { config.legacy_padding_min } else { config.padding_min }.min(100);
        let max = if config.padding_max == 0 { config.legacy_padding_max } else { config.padding_max }.min(100).max(min);
        Ok(Self { book: Arc::new(Codebook::new(&config.password)), layouts: layouts.into(), padding: Range { min, max } })
    }

    pub(super) fn tcp(&self, (read, write): TcpPair, side: Side) -> TcpPair {
        let packed_reader = side == Side::Client;
        let state = Decode::new(packed_reader);
        let reader = Reader { inner: read, config: self.clone(), state, pending: VecDeque::new() };
        let writer = Writer {
            inner: WireWriter::new(write),
            config: self.clone(),
            index: 0,
            chance: self.padding.pick_inclusive(),
            packed: !packed_reader,
        };
        (Box::new(reader), Box::new(writer))
    }

    pub(super) fn udp(&self, inner: Arc<dyn PacketIo>) -> Arc<dyn PacketIo> {
        Arc::new(Packets { inner, config: self.clone(), scratch: Mutex::new(vec![0; u16::MAX.into()]) })
    }

    fn layout(&self, index: usize) -> &Layout {
        &self.layouts[index]
    }

    fn advance(&self, index: &mut usize) {
        *index = (*index + 1) % self.layouts.len();
    }

    fn encode_classic(&self, plain: &[u8], index: &mut usize, chance: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len() * 4);
        let mut rng = rand::rng();
        for &byte in plain {
            let layout = self.layout(*index);
            pad(&mut out, layout, chance, false, &mut rng);
            let choices = self.book.encode[usize::from(byte)];
            let mut hints = choices[rng.random_range(0..choices.len())];
            hints.shuffle(&mut rng);
            for group in hints {
                pad(&mut out, layout, chance, false, &mut rng);
                out.push(layout.hint[usize::from(group)]);
            }
            self.advance(index);
        }
        if !plain.is_empty() {
            pad(&mut out, self.layout(*index), chance, false, &mut rng);
        }
        out
    }

    fn encode_packed(&self, plain: &[u8], index: &mut usize, chance: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len() * 2 + 1);
        let mut rng = rand::rng();
        let mut emit = |out: &mut Vec<u8>, index: &mut usize, group: u8| {
            let layout = self.layout(*index);
            pad(out, layout, chance, true, &mut rng);
            out.push(layout.hint[usize::from(group & 63)]);
            self.advance(index);
        };
        let mut bits = Bits::default();
        for &byte in plain {
            bits.add(byte, 8);
            while let Some(group) = bits.take(6) {
                emit(&mut out, index, group);
            }
        }
        if bits.width != 0 {
            emit(&mut out, index, (bits.value << (6 - bits.width)) as u8);
            out.push(self.layout(*index).marker);
        }
        pad(&mut out, self.layout(*index), chance, true, &mut rng);
        out
    }
}

fn pad(out: &mut Vec<u8>, layout: &Layout, chance: u32, packed: bool, rng: &mut impl RngExt) {
    if chance == 0 || (chance < 100 && rng.random_range(0..100) >= chance) {
        return;
    }
    loop {
        let byte = layout.padding[rng.random_range(0..layout.padding.len())];
        if !packed || byte != layout.marker || layout.padding.len() == 1 {
            out.push(byte);
            break;
        }
    }
}

#[derive(Default)]
struct Bits {
    value: u16,
    width: u8,
}

impl Bits {
    fn add(&mut self, value: u8, width: u8) {
        self.value = (self.value << width) | u16::from(value);
        self.width += width;
    }

    fn take(&mut self, width: u8) -> Option<u8> {
        if self.width < width {
            return None;
        }
        self.width -= width;
        let value = (self.value >> self.width) as u8;
        self.value &= (1 << self.width) - 1;
        Some(value)
    }
}

enum DecodeState {
    Classic { tuple: [u8; 4], filled: usize },
    Packed(Bits),
}

struct Decode {
    index: usize,
    state: DecodeState,
}

impl Decode {
    fn new(packed: bool) -> Self {
        let state = if packed { DecodeState::Packed(Bits::default()) } else { DecodeState::Classic { tuple: [0; 4], filled: 0 } };
        Self { index: 0, state }
    }

    fn next(&mut self, config: &Sudoku, wire: u8) -> io::Result<Option<u8>> {
        let layout = config.layout(self.index);
        let group = layout.group[usize::from(wire)];
        match &mut self.state {
            DecodeState::Classic { tuple, filled } => {
                let Some(group) = group else { return Ok(None); };
                if layout.hint[usize::from(group)] != wire {
                    return Err(malformed("non-canonical Sudoku hint byte"));
                }
                tuple[*filled] = group;
                *filled += 1;
                if *filled < tuple.len() {
                    return Ok(None);
                }
                *filled = 0;
                tuple.sort_unstable();
                let byte = config.book.decode.get(tuple).ok_or_else(|| malformed("invalid Sudoku hint tuple"))?;
                config.advance(&mut self.index);
                Ok(Some(*byte))
            }
            DecodeState::Packed(bits) => {
                if let Some(group) = group {
                    config.advance(&mut self.index);
                    bits.add(group, 6);
                    return Ok(bits.take(8));
                }
                if wire == layout.marker {
                    *bits = Bits::default();
                }
                Ok(None)
            }
        }
    }
}

struct Reader {
    inner: Box<dyn Read + Send>,
    config: Sudoku,
    state: Decode,
    pending: VecDeque<u8>,
}

impl Read for Reader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            let mut wire = [0; CHUNK];
            let n = self.inner.read(&mut wire)?;
            if n == 0 {
                return Ok(0);
            }
            for byte in &wire[..n] {
                if let Some(byte) = self.state.next(&self.config, *byte)? {
                    self.pending.push_back(byte);
                }
            }
        }
        self.pending.read(out)
    }
}

struct Writer {
    inner: WireWriter,
    config: Sudoku,
    index: usize,
    chance: u32,
    packed: bool,
}

impl Write for Writer {
    fn write(&mut self, plain: &[u8]) -> io::Result<usize> {
        let plain = &plain[..plain.len().min(CHUNK)];
        if plain.is_empty() {
            return Ok(0);
        }
        if let Some(used) = self.inner.resume(plain)? {
            return Ok(used);
        }
        let wire = if self.packed {
            self.config.encode_packed(plain, &mut self.index, self.chance)
        } else {
            self.config.encode_classic(plain, &mut self.index, self.chance)
        };
        let segment = Segment { end: wire.len(), delay: Duration::ZERO };
        self.inner.frame(plain, wire, vec![segment])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::wire_writer::tests::Pause;
    use std::io::Cursor;

    #[test]
    fn both_stream_directions_retry_at_every_wire_offset() {
        let sudoku = Sudoku::parse(serde_json::json!({
            "password": "backpressure fixture",
            "customTables": ["xxppvvvv", "pvpvvxvx", ""]
        })).unwrap();
        let data = b"payload";
        for (side, opposite, length) in [(Side::Client, Side::Server, 28), (Side::Server, Side::Client, 11)] {
            for at in 0..length {
                let wire = Arc::new(Mutex::new(Vec::new()));
                let kind = if at % 2 == 0 { io::ErrorKind::WouldBlock } else { io::ErrorKind::TimedOut };
                let pause = Pause { at: Some(at), kind, wire: wire.clone() };
                let (_, mut send) = sudoku.tcp((Box::new(io::empty()), Box::new(pause)), side);
                assert_eq!(send.write(data).unwrap_err().kind(), kind);
                assert_eq!(wire.lock().unwrap().len(), at);
                if at % 2 == 1 {
                    send.flush().unwrap();
                }
                assert_eq!(send.write(data).unwrap(), data.len());
                assert_eq!(wire.lock().unwrap().len(), length);
                send.write_all(b" after retry").unwrap();
                send.flush().unwrap();

                let wire = wire.lock().unwrap().clone();
                let (mut read, _) = sudoku.tcp((Box::new(Cursor::new(wire)), Box::new(io::sink())), opposite);
                let mut recovered = Vec::new();
                read.read_to_end(&mut recovered).unwrap();
                assert_eq!(recovered, b"payload after retry", "{side:?} paused after {at} wire bytes");
            }
        }
    }

    #[test]
    fn a_fatal_short_write_closes_the_encoded_stream() {
        let sudoku = Sudoku::parse(serde_json::json!({"password":"backpressure fixture"})).unwrap();
        let wire = Arc::new(Mutex::new(Vec::new()));
        let pause = Pause { at: Some(3), kind: io::ErrorKind::OutOfMemory, wire: wire.clone() };
        let (_, mut send) = sudoku.tcp((Box::new(io::empty()), Box::new(pause)), Side::Client);
        assert_eq!(send.write(b"payload").unwrap_err().kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(send.write(b"payload").unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(wire.lock().unwrap().len(), 3);
    }
}

struct Packets {
    inner: Arc<dyn PacketIo>,
    config: Sudoku,
    scratch: Mutex<Vec<u8>>,
}

impl PacketIo for Packets {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut buf = self.scratch.lock().expect("Sudoku UDP scratch");
        let deadline = Instant::now() + UDP_POLL;
        'packet: while Instant::now() < deadline {
            let (n, peer) = self.inner.recv_from(&mut buf)?;
            let mut state = Decode::new(false);
            let mut len = 0;
            for &byte in &buf[..n] {
                match state.next(&self.config, byte) {
                    Ok(Some(byte)) if len < out.len() => {
                        out[len] = byte;
                        len += 1;
                    }
                    Ok(None) => {}
                    _ => continue 'packet,
                }
            }
            if matches!(state.state, DecodeState::Classic { filled: 0, .. }) {
                return Ok((len, peer));
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        if packet.len() > MAX_UDP_WIRE / 4 {
            return Err(invalid("Sudoku datagram exceeds UDP packet size"));
        }
        let wire = self.config.encode_classic(packet, &mut 0, self.config.padding.pick_inclusive());
        if wire.len() > MAX_UDP_WIRE {
            return Err(invalid("padded Sudoku datagram exceeds UDP packet size"));
        }
        if self.inner.send_to(&wire, peer)? != wire.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "partial Sudoku datagram"));
        }
        Ok(packet.len())
    }
}
