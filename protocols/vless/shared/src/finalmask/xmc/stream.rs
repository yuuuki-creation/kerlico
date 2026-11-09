use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

use aes::{
    cipher::{Block, BlockEncrypt, KeyInit},
    Aes128,
};

use super::super::{invalid, retryable, Side, TcpPair};
use super::wire::{encode_packet, put_field, take_field, FrameReader};

const CLIENTBOUND_PAYLOAD: u32 = 0x01;
const SERVERBOUND_PAYLOAD: u32 = 0x02;
const KEEP_ALIVE: u32 = 0x04;
const KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(15);
const PAYLOAD_CHANNEL: &[u8] = b"xmc:data";
const MAX_PAYLOAD: usize = 24 * 1024;

struct Cfb8 {
    cipher: Aes128,
    register: [u8; 16],
}

impl Cfb8 {
    fn new(secret: [u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(&secret.into()),
            register: secret,
        }
    }

    fn apply(&mut self, bytes: &mut [u8], decrypt: bool) {
        for byte in bytes {
            let mut block = Block::<Aes128>::from(self.register);
            self.cipher.encrypt_block(&mut block);
            let transformed = *byte ^ block[0];
            self.register.copy_within(1.., 0);
            self.register[15] = if decrypt { *byte } else { transformed };
            *byte = transformed;
        }
    }
}

pub(super) struct CipherReader {
    inner: Box<dyn Read + Send>,
    cipher: Cfb8,
}

impl CipherReader {
    pub fn new(inner: Box<dyn Read + Send>, secret: [u8; 16]) -> Self {
        Self {
            inner,
            cipher: Cfb8::new(secret),
        }
    }
}

impl Read for CipherReader {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(data)?;
        self.cipher.apply(&mut data[..count], true);
        Ok(count)
    }
}

pub(super) struct CipherWriter {
    inner: Box<dyn Write + Send>,
    cipher: Cfb8,
    pending: Vec<u8>,
    sent: usize,
}

impl CipherWriter {
    pub fn new(inner: Box<dyn Write + Send>, secret: [u8; 16]) -> Self {
        Self {
            inner,
            cipher: Cfb8::new(secret),
            pending: Vec::new(),
            sent: 0,
        }
    }

    fn stage(&mut self, mut bytes: Vec<u8>) {
        debug_assert!(self.pending.is_empty());
        self.cipher.apply(&mut bytes, false);
        self.pending = bytes;
    }

    fn drain(&mut self) -> io::Result<()> {
        while self.sent < self.pending.len() {
            match self.inner.write(&self.pending[self.sent..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => self.sent += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        self.sent = 0;
        self.pending.clear();
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain()?;
        self.inner.flush()
    }

    pub fn send(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        self.drain()?;
        self.stage(bytes);
        self.flush()
    }
}

struct Output {
    writer: CipherWriter,
    id: u32,
    unacknowledged: Vec<u8>,
    replying: bool,
}

impl Output {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if !self.unacknowledged.is_empty() {
            if !data.starts_with(&self.unacknowledged) {
                return Err(invalid("XMC write retry buffer changed"));
            }
            self.writer.drain()?;
            let count = self.unacknowledged.len();
            self.unacknowledged.clear();
            return Ok(count);
        }
        self.writer.drain()?;
        let data = &data[..data.len().min(MAX_PAYLOAD)];
        let mut body = Vec::with_capacity(data.len() + 1 + PAYLOAD_CHANNEL.len());
        put_field(&mut body, PAYLOAD_CHANNEL);
        body.extend_from_slice(data);
        self.writer.stage(encode_packet(self.id, &body)?);
        if let Err(error) = self.writer.drain() {
            // A retry or keep-alive may finish this ciphertext. The application
            // bytes are acknowledged only when the original caller retries.
            self.unacknowledged.extend_from_slice(data);
            return Err(error);
        }
        Ok(data.len())
    }

    fn keep_alive(&mut self, id: [u8; 8]) -> io::Result<()> {
        if !self.replying {
            self.writer.drain()?;
            self.writer.stage(encode_packet(KEEP_ALIVE, &id)?);
            self.replying = true;
        }
        self.writer.flush()?;
        self.replying = false;
        Ok(())
    }
}

struct SharedOutput {
    inner: Mutex<Output>,
    ticker: OnceLock<Thread>,
}

impl SharedOutput {
    fn lock(&self) -> io::Result<MutexGuard<'_, Output>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("XMC writer poisoned"))
    }
}

impl Drop for SharedOutput {
    fn drop(&mut self) {
        if let Some(ticker) = self.ticker.get() {
            ticker.unpark();
        }
    }
}

struct PacketWriter(Arc<SharedOutput>);

impl Write for PacketWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock()?.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock()?.writer.flush()
    }
}

struct PacketReader {
    reader: CipherReader,
    frame: FrameReader,
    output: Arc<SharedOutput>,
    client: bool,
    id: u32,
    payload: Vec<u8>,
    offset: usize,
    reply: Option<[u8; 8]>,
    failed: bool,
}

impl PacketReader {
    fn read_payload(&mut self, data: &mut [u8]) -> io::Result<usize> {
        while self.offset == self.payload.len() {
            if let Some(reply) = self.reply {
                self.output.lock()?.keep_alive(reply)?;
                self.reply = None;
            }
            let Some(packet) = self.frame.read(&mut self.reader)? else {
                return Ok(0);
            };
            if packet.id == self.id {
                let mut fields = packet.data();
                if take_field(&mut fields, 4096)? == PAYLOAD_CHANNEL && !fields.is_empty() {
                    let channel_length = packet.data().len() - fields.len();
                    let (body, data_offset) = packet.into_data();
                    self.offset = data_offset + channel_length;
                    self.payload = body;
                }
            } else if packet.id == KEEP_ALIVE {
                let id = packet
                    .data()
                    .first_chunk::<8>()
                    .ok_or(io::ErrorKind::UnexpectedEof)?;
                if self.client {
                    self.reply = Some(*id);
                }
            }
        }
        let count = data.len().min(self.payload.len() - self.offset);
        data[..count].copy_from_slice(&self.payload[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

impl Read for PacketReader {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let result = self.read_payload(data);
        if result.as_ref().is_err_and(|error| !retryable(error)) {
            self.failed = true;
        }
        result
    }
}

fn keep_alive_loop(output: Weak<SharedOutput>) -> io::Result<()> {
    for id in 1_i64.. {
        let next = Instant::now() + KEEP_ALIVE_PERIOD;
        while let Some(wait) = next.checked_duration_since(Instant::now()) {
            if output.strong_count() == 0 {
                return Ok(());
            }
            thread::park_timeout(wait);
        }
        let Some(output) = output.upgrade() else {
            return Ok(());
        };
        output.lock()?.keep_alive(id.to_be_bytes())?;
    }
    Ok(())
}

pub(super) fn packet_pair(
    reader: CipherReader,
    writer: CipherWriter,
    side: Side,
) -> io::Result<TcpPair> {
    let client = side == Side::Client;
    let (read_id, write_id) = if client {
        (CLIENTBOUND_PAYLOAD, SERVERBOUND_PAYLOAD)
    } else {
        (SERVERBOUND_PAYLOAD, CLIENTBOUND_PAYLOAD)
    };
    let output = Arc::new(SharedOutput {
        inner: Mutex::new(Output {
            writer,
            id: write_id,
            unacknowledged: Vec::new(),
            replying: false,
        }),
        ticker: OnceLock::new(),
    });
    if !client {
        let weak = Arc::downgrade(&output);
        let ticker = thread::Builder::new()
            .name("xmc-keep-alive".to_owned())
            .spawn(move || keep_alive_loop(weak))?;
        let _ = output.ticker.set(ticker.thread().clone());
    }
    Ok((
        Box::new(PacketReader {
            reader,
            frame: FrameReader::default(),
            output: output.clone(),
            client,
            id: read_id,
            payload: Vec::new(),
            offset: 0,
            reply: None,
            failed: false,
        }),
        Box::new(PacketWriter(output)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xmc::wire::read_packet;

    const SECRET: [u8; 16] = [42; 16];

    fn payload(id: u32, value: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        put_field(&mut body, PAYLOAD_CHANNEL);
        body.extend_from_slice(value);
        encode_packet(id, &body).unwrap()
    }

    struct InterruptedRead {
        bytes: Vec<u8>,
        offset: usize,
        blocks: std::collections::VecDeque<usize>,
    }

    impl Read for InterruptedRead {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.blocks.front() == Some(&self.offset) {
                self.blocks.pop_front();
                return Err(io::ErrorKind::TimedOut.into());
            }
            let limit = self.blocks.front().copied().unwrap_or(self.bytes.len());
            let count = out.len().min(limit - self.offset);
            out[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    struct InterruptedWrite {
        bytes: Arc<Mutex<Vec<u8>>>,
        calls: usize,
    }

    impl Write for InterruptedWrite {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            let count = match self.calls {
                1 => data.len().min(3),
                2 => return Err(io::ErrorKind::WouldBlock.into()),
                _ => data.len(),
            };
            self.bytes.lock().unwrap().extend_from_slice(&data[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn resumes_ciphertext_after_partial_frame_write() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = CipherWriter::new(
            Box::new(InterruptedWrite {
                bytes: bytes.clone(),
                calls: 0,
            }),
            SECRET,
        );
        let (_, mut write) = packet_pair(
            CipherReader::new(Box::new(io::empty()), SECRET),
            writer,
            Side::Client,
        )
        .unwrap();
        assert_eq!(
            write.write(b"first").unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
        );
        assert_eq!(
            write.write(b"wrong").unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
        );
        write.flush().unwrap();
        assert_eq!(write.write(b"first").unwrap(), 5);
        write.write_all(b"second").unwrap();

        let mut expected = payload(SERVERBOUND_PAYLOAD, b"first");
        expected.extend(payload(SERVERBOUND_PAYLOAD, b"second"));
        let mut actual = bytes.lock().unwrap().clone();
        Cfb8::new(SECRET).apply(&mut actual, true);
        assert_eq!(actual, expected);
    }

    #[test]
    fn resumes_keep_alive_and_partial_frame_read() {
        let id = 73_i64.to_be_bytes();
        let mut input = encode_packet(KEEP_ALIVE, &id).unwrap();
        let keep_alive_length = input.len();
        let data: Vec<u8> = (0..193).map(|byte| byte as u8).collect();
        input.extend(payload(CLIENTBOUND_PAYLOAD, &data));
        Cfb8::new(SECRET).apply(&mut input, false);
        let reader = CipherReader::new(
            Box::new(InterruptedRead {
                bytes: input,
                offset: 0,
                blocks: [keep_alive_length + 1, keep_alive_length + 5].into(),
            }),
            SECRET,
        );
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = CipherWriter::new(
            Box::new(InterruptedWrite {
                bytes: output.clone(),
                calls: 0,
            }),
            SECRET,
        );
        let (mut read, mut write) = packet_pair(reader, writer, Side::Client).unwrap();
        let mut received = vec![0; data.len()];
        assert_eq!(
            read.read(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
        );
        write.write_all(b"overlapped write").unwrap();
        for _ in 0..2 {
            assert_eq!(
                read.read(&mut received).unwrap_err().kind(),
                io::ErrorKind::TimedOut,
            );
        }
        read.read_exact(&mut received).unwrap();
        assert_eq!(received, data);
        assert_eq!(read.read(&mut received).unwrap(), 0);

        let mut wire = output.lock().unwrap().clone();
        Cfb8::new(SECRET).apply(&mut wire, true);
        let mut wire = wire.as_slice();
        let reply = read_packet(&mut wire).unwrap();
        assert_eq!(reply.id, KEEP_ALIVE);
        assert_eq!(reply.data(), id);
        assert_eq!(wire, payload(SERVERBOUND_PAYLOAD, b"overlapped write"));
    }
}
