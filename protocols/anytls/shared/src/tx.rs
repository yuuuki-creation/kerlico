//! The sending side of a session: frames go straight into TLS records in the buffer the socket
//! write takes. One call is one mihomo `writeConn` and so one "packet" of the padding scheme.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use std::task::Waker;

use crate::frame::{self, CMD_PSH, CMD_WASTE, HEADER, MAX_DATA};
use crate::padding::{SchemeCell, CHECK};
use crate::tls::{key_update, Kernel, SendCipher, CONTENT_APPDATA, MAX_PLAIN, RECORD_LIMIT};

const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;

pub(crate) mod input;

#[derive(Clone, Copy)]
pub(crate) enum Out<'a> {
    /// One frame, or PSH frames split at 65535 bytes, as one `writeConn`.
    Frames { cmd: u8, sid: u32, data: &'a [u8] },
    /// Our KeyUpdate after the peer asked for one.
    KeyUpdate,
    CloseNotify,
}

pub(crate) struct Waiter {
    pub(crate) ticket: u64,
    /// `None` waits for room in the queue; `Some(end)` waits until the socket took `end`.
    pub(crate) end: Option<u64>,
    pub(crate) cv: Arc<Condvar>,
    /// Already notified since it last went to sleep, so no second futex call.
    pub(crate) woken: bool,
}

pub(crate) struct TaskWaiter {
    pub(crate) ticket: u64,
    pub(crate) end: Option<u64>,
    pub(crate) waker: Waker,
    pub(crate) woken: bool,
}

pub(crate) struct NativeBatch {
    pub(crate) storage: Vec<u8>,
    pub(crate) len: usize,
    /// Application input is advanced only by its own completing write task.
    pub(crate) owner: Option<u64>,
    pub(crate) input: bool,
}

/// How fast the socket has been taking bytes, for the queue bound.
pub(crate) struct Rate {
    bytes: u64,
    time: Duration,
    per_second: u64,
}

impl Rate {
    pub(crate) const fn new() -> Self {
        Self { bytes: 0, time: Duration::ZERO, per_second: 0 }
    }

    pub(crate) fn record(&mut self, bytes: u64, spent: Duration) {
        self.bytes += bytes;
        self.time += spent;
        if self.time >= Duration::from_millis(50) || self.bytes >= 4 << 20 {
            let micros = self.time.as_micros().max(1000) as u64;
            self.per_second = self.bytes.saturating_mul(1_000_000) / micros;
            self.bytes = 0;
            self.time = Duration::ZERO;
        }
    }

    /// About a sixteenth of a second of what the wire took, between 16 KiB and 128 KiB.
    pub(crate) fn limit(&self) -> u64 {
        if self.per_second == 0 {
            return 128 << 10;
        }
        (self.per_second / 16).clamp(16 << 10, 128 << 10)
    }
}

pub(crate) struct Tx {
    cipher: Option<SendCipher>,
    plaintext: bool,
    pub(crate) out: Vec<u8>,
    pub(crate) spare: Vec<u8>,
    /// Bytes ever appended to `out`, and bytes the socket has taken.
    pub(crate) appended: u64,
    pub(crate) written: u64,
    /// Someone is writing to the socket, or has been asked to.
    pub(crate) flushing: bool,
    pub(crate) waiters: VecDeque<Waiter>,
    pub(crate) next_ticket: u64,
    pub(crate) task_waiters: VecDeque<TaskWaiter>,
    pub(crate) native_head: usize,
    pub(crate) native_batch: Option<(Instant, u64)>,
    pub(crate) ready: VecDeque<NativeBatch>,
    pub(crate) input_pool: Vec<Vec<u8>>,
    /// The waiter that takes over writing from the thread that just finished its own bytes.
    pub(crate) handoff: Option<u64>,
    pub(crate) helper_wanted: bool,
    pub(crate) helper_started: bool,
    pub(crate) dead: Option<io::ErrorKind>,
    pub(crate) rate: Rate,
    // The client's padding state (mihomo `sendPadding`, `pktCounter`, `buffering`, `buffer`).
    pub(crate) send_padding: bool,
    pub(crate) pkt: u32,
    pub(crate) buffering: bool,
    pub(crate) pre: Vec<u8>,
    sizes: Vec<i64>,
    open: Option<usize>,
}

impl Tx {
    pub(crate) fn new(cipher: Option<SendCipher>, pending: Vec<u8>, client: bool) -> Self {
        Self {
            cipher,
            plaintext: false,
            appended: pending.len() as u64,
            out: pending,
            spare: Vec::new(),
            written: 0,
            flushing: false,
            waiters: VecDeque::new(),
            next_ticket: 0,
            task_waiters: VecDeque::new(),
            native_head: 0,
            native_batch: None,
            ready: VecDeque::new(),
            input_pool: Vec::new(),
            handoff: None,
            helper_wanted: false,
            helper_started: false,
            dead: None,
            rate: Rate::new(),
            send_padding: client,
            pkt: 0,
            buffering: false,
            pre: Vec::new(),
            sizes: Vec::new(),
            open: None,
        }
    }

    pub(crate) fn plaintext(client: bool) -> Self {
        Self { plaintext: true, ..Self::new(None, Vec::new(), client) }
    }

    pub(crate) fn pending(&self) -> u64 {
        self.appended - self.written
    }

    pub(crate) fn ticket(&mut self) -> u64 {
        self.next_ticket += 1;
        self.next_ticket
    }

    /// Appends `item` and returns how many bytes `out` grew by.
    pub(crate) fn put(&mut self, item: Out<'_>, padding: &SchemeCell, kernel: &Mutex<Kernel>) -> io::Result<usize> {
        let before = self.out.len();
        match item {
            Out::Frames { cmd, sid, data } => self.put_frames(cmd, sid, data, padding, kernel)?,
            Out::KeyUpdate => {
                if self.cipher.is_none() {
                    return Err(io::Error::other("TLS library owns key updates"));
                }
                self.open_record(kernel)?;
                self.out.extend_from_slice(&key_update(false));
                self.close_record(CONTENT_HANDSHAKE);
                self.cipher = Some(kernel.lock().expect("kernel").next_tx()?);
            }
            Out::CloseNotify => {
                if self.cipher.is_some() {
                    self.open_record(kernel)?;
                    self.out.extend_from_slice(&[1, 0]);
                    self.close_record(CONTENT_ALERT);
                } else if !self.plaintext {
                    // A zero-size entry in the internal library write queue means close_notify.
                    self.out.extend_from_slice(&[0, 0]);
                }
            }
        }
        let grown = self.out.len() - before;
        self.appended += grown as u64;
        Ok(grown)
    }

    /// The client's first record: SHA-256 of the password, the padding length, zeros.
    pub(crate) fn put_auth(&mut self, hash: &[u8; 32], padding: i64, kernel: &Mutex<Kernel>) -> io::Result<()> {
        let before = self.out.len();
        let mut plain = Vec::with_capacity(34 + padding.max(0) as usize);
        plain.extend_from_slice(hash);
        plain.extend_from_slice(&(padding as u16).to_be_bytes());
        plain.resize(plain.len() + padding.max(0) as usize, 0);
        self.write(&[&plain], 0, kernel)?;
        self.appended += (self.out.len() - before) as u64;
        Ok(())
    }

    fn put_frames(&mut self, cmd: u8, sid: u32, data: &[u8], padding: &SchemeCell, kernel: &Mutex<Kernel>) -> io::Result<()> {
        if self.buffering {
            let mut pre = std::mem::take(&mut self.pre);
            append_frames(&mut pre, cmd, sid, data);
            self.pre = pre;
            return Ok(());
        }
        if self.send_padding {
            self.pkt = self.pkt.wrapping_add(1);
            let scheme = padding.load();
            if self.pkt < scheme.stop() {
                let mut packet = std::mem::take(&mut self.pre);
                append_frames(&mut packet, cmd, sid, data);
                let mut sizes = std::mem::take(&mut self.sizes);
                scheme.record_sizes(self.pkt, &mut sizes);
                let result = self.write_padded(&packet, &sizes, kernel);
                packet.clear();
                self.pre = packet;
                self.sizes = sizes;
                return result;
            }
            self.send_padding = false;
        }
        if !self.pre.is_empty() {
            let mut packet = std::mem::take(&mut self.pre);
            append_frames(&mut packet, cmd, sid, data);
            let result = self.write(&[&packet], 0, kernel);
            packet.clear();
            self.pre = packet;
            return result;
        }
        // The usual path: headers and the caller's bytes copied once, into records.
        if cmd == CMD_PSH {
            for chunk in data.chunks(MAX_DATA) {
                self.push(&frame::header(CMD_PSH, sid, chunk.len()), kernel)?;
                self.push(chunk, kernel)?;
            }
        } else {
            self.push(&frame::header(cmd, sid, data.len()), kernel)?;
            self.push(data, kernel)?;
        }
        self.end_write();
        Ok(())
    }

    /// mihomo `writeConn` while `pkt < stop`: each size is one socket write of its own in Go, so
    /// one record here. A payload left after the list is one more write.
    fn write_padded(&mut self, packet: &[u8], sizes: &[i64], kernel: &Mutex<Kernel>) -> io::Result<()> {
        let mut rest = packet;
        for &size in sizes {
            if size == CHECK {
                if rest.is_empty() {
                    break;
                }
                continue;
            }
            let size = size as usize;
            if rest.len() > size {
                self.write(&[&rest[..size]], 0, kernel)?;
                rest = &rest[size..];
            } else if !rest.is_empty() {
                let pad = size as i64 - rest.len() as i64 - HEADER as i64;
                if pad > 0 {
                    let pad = pad as usize;
                    self.write(&[rest, &frame::header(CMD_WASTE, 0, pad)], pad, kernel)?;
                } else {
                    self.write(&[rest], 0, kernel)?;
                }
                rest = &[];
            } else {
                self.write(&[&frame::header(CMD_WASTE, 0, size)], size, kernel)?;
            }
        }
        if !rest.is_empty() {
            self.write(&[rest], 0, kernel)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn write_padded_for_test(&mut self, packet: &[u8], sizes: &[i64], kernel: &Mutex<Kernel>) {
        let before = self.out.len();
        self.write_padded(packet, sizes, kernel).unwrap();
        self.appended += (self.out.len() - before) as u64;
    }

    /// One Go `conn.Write`: the parts, then `zeros` zero bytes, in records of at most 16384.
    fn write(&mut self, parts: &[&[u8]], zeros: usize, kernel: &Mutex<Kernel>) -> io::Result<()> {
        for part in parts {
            self.push(part, kernel)?;
        }
        let mut zeros = zeros;
        while zeros > 0 {
            let start = self.ensure_open(kernel)?;
            let prefix = self.prefix_len();
            let room = MAX_PLAIN - (self.out.len() - start - prefix);
            let n = zeros.min(room);
            self.out.resize(self.out.len() + n, 0);
            zeros -= n;
            if self.out.len() - start - prefix == MAX_PLAIN {
                self.close_record(CONTENT_APPDATA);
            }
        }
        self.end_write();
        Ok(())
    }

    fn push(&mut self, mut bytes: &[u8], kernel: &Mutex<Kernel>) -> io::Result<()> {
        while !bytes.is_empty() {
            let start = self.ensure_open(kernel)?;
            let prefix = self.prefix_len();
            let room = MAX_PLAIN - (self.out.len() - start - prefix);
            let n = bytes.len().min(room);
            self.out.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.out.len() - start - prefix == MAX_PLAIN {
                self.close_record(CONTENT_APPDATA);
            }
        }
        Ok(())
    }

    fn end_write(&mut self) {
        if self.open.is_some() {
            self.close_record(CONTENT_APPDATA);
        }
    }

    fn ensure_open(&mut self, kernel: &Mutex<Kernel>) -> io::Result<usize> {
        if let Some(start) = self.open {
            return Ok(start);
        }
        self.open_record(kernel)
    }

    fn prefix_len(&self) -> usize {
        self.cipher.as_ref().map_or(if self.plaintext { 0 } else { 2 }, SendCipher::prefix_len)
    }

    fn open_record(&mut self, kernel: &Mutex<Kernel>) -> io::Result<usize> {
        self.reserve_records(1, kernel)?;
        let start = self.out.len();
        self.out.resize(start + self.prefix_len(), 0);
        self.open = Some(start);
        Ok(start)
    }

    fn reserve_records(&mut self, count: usize, kernel: &Mutex<Kernel>) -> io::Result<()> {
        if let Some(cipher) = self.cipher.as_mut().filter(|cipher| cipher.seq().saturating_add(count as u64) > RECORD_LIMIT) {
            if !cipher.is_tls13() {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "TLS 1.2 send record limit"));
            }
            let start = self.out.len();
            self.out.extend_from_slice(&[0; 5]);
            self.out.extend_from_slice(&key_update(false));
            cipher.seal(&mut self.out, start, CONTENT_HANDSHAKE);
            *cipher = kernel.lock().expect("kernel").next_tx()?;
        }
        Ok(())
    }

    pub(crate) fn input_format(&self) -> Option<input::Format> {
        self.cipher.as_ref().map(input::Format::cipher).or_else(|| self.plaintext.then_some(input::Format::Plain))
    }

    /// A borrowed batch uses the same cipher and record limit as `put`.
    /// A KeyUpdate needed by this batch remains in `out`, before its data.
    pub(crate) fn seal_input(&mut self, sid: u32, input: &mut input::Input, kernel: &Mutex<Kernel>) -> io::Result<input::Encoded> {
        if input.filled == 0 { return Err(io::ErrorKind::InvalidInput.into()); }
        let before = self.out.len();
        let count = input.records();
        self.reserve_records(count, kernel)?;
        self.appended += (self.out.len() - before) as u64;
        let encoded = input.seal(sid, self.cipher.as_mut(), count)?;
        self.appended += encoded.len as u64;
        Ok(encoded)
    }

    fn close_record(&mut self, inner_type: u8) {
        let start = self.open.take().expect("open record");
        if let Some(cipher) = &mut self.cipher {
            cipher.seal(&mut self.out, start, inner_type);
        } else if !self.plaintext {
            let size = (self.out.len() - start - 2) as u16;
            self.out[start..start + 2].copy_from_slice(&size.to_be_bytes());
        }
    }
}

fn append_frames(out: &mut Vec<u8>, cmd: u8, sid: u32, data: &[u8]) {
    if cmd == CMD_PSH {
        frame::push_data(out, sid, data);
    } else {
        frame::push_frame(out, cmd, sid, data);
    }
}
