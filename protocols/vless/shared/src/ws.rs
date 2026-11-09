//! WebSocket data frames after the HTTP upgrade. Binary payloads carry VLESS bytes.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use sha1::{Digest, Sha1};

use crate::upgrade::{b64, UpgradeError};

const BINARY: u8 = 2;
const CLOSE: u8 = 8;
const PING: u8 = 9;
const PONG: u8 = 10;
const SEND_CHUNK: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WsSignal {
    Ping(Vec<u8>),
    Close,
}

struct IncomingFrame {
    opcode: u8,
    remaining: u64,
    offset: usize,
    mask: [u8; 4],
}

pub struct FrameDecoder {
    header: [u8; 14],
    header_len: usize,
    frame: Option<IncomingFrame>,
    plain: VecDeque<u8>,
    control: Vec<u8>,
    close_payload: Vec<u8>,
    fragmented: bool,
    expect_mask: bool,
    pub closed: bool,
}

impl FrameDecoder {
    pub fn new(expect_mask: bool) -> Self {
        Self {
            header: [0; 14],
            header_len: 0,
            frame: None,
            plain: VecDeque::new(),
            control: Vec::new(),
            close_payload: Vec::new(),
            fragmented: false,
            expect_mask,
            closed: false,
        }
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<WsSignal>, UpgradeError> {
        let mut signals = Vec::new();
        while !bytes.is_empty() && !self.closed {
            let mut frame = match self.frame.take() {
                Some(frame) => frame,
                None => {
                    let Some(frame) = self.read_header(&mut bytes)? else {
                        break;
                    };
                    frame
                }
            };
            let count = frame.remaining.min(bytes.len() as u64) as usize;
            let (payload, rest) = bytes.split_at(count);
            bytes = rest;
            let decoded = payload
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ frame.mask[(frame.offset + i) % 4]);
            if frame.opcode >= CLOSE {
                self.control.extend(decoded);
            } else if self.expect_mask {
                self.plain.extend(decoded);
            } else {
                self.plain.extend(payload);
            }
            frame.remaining -= count as u64;
            frame.offset = (frame.offset + count) % 4;
            if frame.remaining > 0 {
                self.frame = Some(frame);
                continue;
            }
            match frame.opcode {
                PING => signals.push(WsSignal::Ping(std::mem::take(&mut self.control))),
                PONG => self.control.clear(),
                CLOSE => {
                    if !valid_close(&self.control) {
                        return Err(UpgradeError::Bad);
                    }
                    self.close_payload = std::mem::take(&mut self.control);
                    self.closed = true;
                    signals.push(WsSignal::Close);
                }
                _ => {}
            }
        }
        Ok(signals)
    }

    pub fn pop(&mut self, buf: &mut [u8]) -> usize {
        let count = self.plain.len().min(buf.len());
        for (slot, byte) in buf.iter_mut().zip(self.plain.drain(..count)) {
            *slot = byte;
        }
        count
    }

    fn read_header(&mut self, bytes: &mut &[u8]) -> Result<Option<IncomingFrame>, UpgradeError> {
        if !self.fill_header(bytes, 2) {
            return Ok(None);
        }
        let first = self.header[0];
        let second = self.header[1];
        let fin = first & 0x80 != 0;
        let opcode = first & 0x0f;
        let length_code = second & 0x7f;
        let masked = second & 0x80 != 0;
        if first & 0x70 != 0 || masked != self.expect_mask {
            return Err(UpgradeError::Bad);
        }
        match opcode {
            0 if self.fragmented => {}
            1 | BINARY if !self.fragmented => {}
            CLOSE..=PONG if fin && length_code <= 125 => {}
            _ => return Err(UpgradeError::Bad),
        }
        let mask_offset = match length_code {
            126 => 4,
            127 => 10,
            _ => 2,
        };
        let header_len = mask_offset + if masked { 4 } else { 0 };
        if !self.fill_header(bytes, header_len) {
            return Ok(None);
        }
        let remaining = match length_code {
            126 => u16::from_be_bytes([self.header[2], self.header[3]]) as u64,
            127 => u64::from_be_bytes(self.header[2..10].try_into().expect("frame length")),
            _ => u64::from(length_code),
        };
        if (length_code == 126 && remaining < 126)
            || (length_code == 127 && (remaining <= u16::MAX as u64 || remaining >> 63 != 0))
        {
            return Err(UpgradeError::Bad);
        }
        let mask = if masked {
            self.header[mask_offset..header_len]
                .try_into()
                .expect("frame mask")
        } else {
            [0; 4]
        };
        if opcode < CLOSE {
            self.fragmented = !fin;
        }
        self.header_len = 0;
        Ok(Some(IncomingFrame {
            opcode,
            remaining,
            offset: 0,
            mask,
        }))
    }

    fn fill_header(&mut self, bytes: &mut &[u8], needed: usize) -> bool {
        let count = needed.saturating_sub(self.header_len).min(bytes.len());
        let end = self.header_len + count;
        self.header[self.header_len..end].copy_from_slice(&bytes[..count]);
        *bytes = &bytes[count..];
        self.header_len = end;
        end >= needed
    }

    fn eof(&self) -> io::Result<usize> {
        if self.header_len > 0 || self.frame.is_some() || self.fragmented {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated WebSocket frame",
            ));
        }
        Ok(0)
    }
}

fn valid_close(payload: &[u8]) -> bool {
    match payload {
        [] => true,
        [high, low, reason @ ..] => {
            let code = u16::from_be_bytes([*high, *low]);
            matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
                && std::str::from_utf8(reason).is_ok()
        }
        [_] => false,
    }
}

pub fn encode_frame(opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
    try_encode_frame(opcode, payload, mask).expect("WebSocket mask entropy")
}

fn try_encode_frame(opcode: u8, payload: &[u8], mask: bool) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    let mask_bit = if mask { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    if mask {
        let mut key = [0u8; 4];
        getrandom::getrandom(&mut key).map_err(|error| io::Error::other(error.to_string()))?;
        out.extend_from_slice(&key);
        for (index, byte) in payload.iter().enumerate() {
            out.push(byte ^ key[index % 4]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    Ok(out)
}

pub fn accept_value(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.trim().as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    b64(&hasher.finalize())
}

struct Input {
    decoder: FrameDecoder,
    replies: VecDeque<(u8, Vec<u8>)>,
}

trait Wire {
    fn read_wire(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn reply(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()>;
}

impl Input {
    fn new(expect_mask: bool, prelude: &[u8]) -> Result<Self, UpgradeError> {
        let mut input = Self {
            decoder: FrameDecoder::new(expect_mask),
            replies: VecDeque::new(),
        };
        input.push(prelude)?;
        Ok(input)
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), UpgradeError> {
        for signal in self.decoder.push(bytes)? {
            let reply = match signal {
                WsSignal::Ping(payload) => (PONG, payload),
                WsSignal::Close => (CLOSE, std::mem::take(&mut self.decoder.close_payload)),
            };
            self.replies.push_back(reply);
        }
        Ok(())
    }

    fn read(&mut self, wire: &mut impl Wire, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut raw = [0u8; 4096];
        loop {
            while let Some((opcode, payload)) = self.replies.front() {
                wire.reply(*opcode, payload)?;
                self.replies.pop_front();
            }
            let count = self.decoder.pop(buf);
            if count > 0 || self.decoder.closed {
                return Ok(count);
            }
            let count = match wire.read_wire(&mut raw) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 {
                return self.decoder.eof();
            }
            self.push(&raw[..count]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid WebSocket frame")
            })?;
        }
    }
}

struct PendingFrame {
    opcode: u8,
    bytes: Vec<u8>,
    sent: usize,
}

struct Output<W> {
    inner: W,
    mask: bool,
    frame: Option<PendingFrame>,
    retry_data: Option<Vec<u8>>,
    retry_reply: bool,
    closed: bool,
}

impl<W> Output<W> {
    fn new(inner: W, mask: bool) -> Self {
        Self {
            inner,
            mask,
            frame: None,
            retry_data: None,
            retry_reply: false,
            closed: false,
        }
    }
}

impl<W: Write> Output<W> {
    fn start(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let bytes = try_encode_frame(opcode, payload, self.mask)?;
        self.frame = Some(PendingFrame {
            opcode,
            bytes,
            sent: 0,
        });
        Ok(())
    }

    fn send(&mut self) -> io::Result<()> {
        if let Some(frame) = self.frame.as_mut() {
            while frame.sent < frame.bytes.len() {
                match self.inner.write(&frame.bytes[frame.sent..]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => frame.sent += n,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            self.frame = None;
        }
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(expected) = self.retry_data.as_ref() {
            if !buf.starts_with(expected) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "different WebSocket write retry",
                ));
            }
            let count = expected.len();
            if self
                .frame
                .as_ref()
                .is_some_and(|frame| frame.opcode == BINARY)
            {
                self.send()?;
            }
            self.retry_data = None;
            return Ok(count);
        }
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.send()?;
        let data = &buf[..buf.len().min(SEND_CHUNK)];
        self.start(BINARY, data)?;
        if let Err(error) = self.send() {
            self.retry_data = Some(data.to_vec());
            return Err(error);
        }
        Ok(data.len())
    }

    fn reply(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if self.retry_reply {
            if self
                .frame
                .as_ref()
                .is_some_and(|frame| frame.opcode != BINARY)
            {
                self.send()?;
            }
        } else {
            self.send()?;
            self.start(opcode, payload)?;
            self.closed = opcode == CLOSE;
            self.retry_reply = true;
            self.send()?;
        }
        self.inner.flush()?;
        self.retry_reply = false;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send()?;
        self.inner.flush()
    }
}

impl<T: Read + Write> Wire for Output<T> {
    fn read_wire(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    fn reply(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        Output::reply(self, opcode, payload)
    }
}

pub struct WsIo<T> {
    input: Input,
    output: Output<T>,
}

impl<T> WsIo<T> {
    pub fn new(
        inner: T,
        expect_mask: bool,
        mask_out: bool,
        prelude: &[u8],
    ) -> Result<Self, UpgradeError> {
        Ok(Self {
            input: Input::new(expect_mask, prelude)?,
            output: Output::new(inner, mask_out),
        })
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.output.inner
    }
}

impl<T: Read + Write> Read for WsIo<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(&mut self.output, buf)
    }
}

impl<T: Write> Write for WsIo<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

pub struct WsRead<R, W> {
    input: Input,
    wire: SplitWire<R, W>,
}

pub struct WsWrite<W> {
    output: Arc<Mutex<Output<W>>>,
}

struct SplitWire<R, W> {
    inner: R,
    output: Arc<Mutex<Output<W>>>,
}

pub fn websocket_pair<R: Read, W: Write>(
    read: R,
    write: W,
    expect_mask: bool,
    mask_out: bool,
    prelude: &[u8],
) -> Result<(WsRead<R, W>, WsWrite<W>), UpgradeError> {
    let input = Input::new(expect_mask, prelude)?;
    let output = Arc::new(Mutex::new(Output::new(write, mask_out)));
    let wire = SplitWire {
        inner: read,
        output: Arc::clone(&output),
    };
    Ok((WsRead { input, wire }, WsWrite { output }))
}

impl<R, W> WsRead<R, W> {
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.wire.inner
    }
}

impl<R: Read, W: Write> Read for WsRead<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(&mut self.wire, buf)
    }
}

impl<R: Read, W: Write> Wire for SplitWire<R, W> {
    fn read_wire(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    fn reply(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        self.output
            .lock()
            .expect("WebSocket writer")
            .reply(opcode, payload)
    }
}

impl<W> WsWrite<W> {
    pub fn map_io(&self, apply: impl FnOnce(&mut W)) {
        apply(&mut self.output.lock().expect("WebSocket writer").inner);
    }
}

impl<W: Write> Write for WsWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.lock().expect("WebSocket writer").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.lock().expect("WebSocket writer").flush()
    }
}

pub fn switch_response(key: &str) -> Vec<u8> {
    switch_response_with_early_data(key, None)
}

pub fn switch_response_with_early_data(key: &str, token: Option<&str>) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n",
        accept_value(key)
    );
    if let Some(token) = token {
        response.push_str("Sec-WebSocket-Protocol: ");
        response.push_str(token);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rfc_accept_and_masked_frame() {
        assert_eq!(
            accept_value("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        let frame = encode_frame(BINARY, b"ping", true);
        let mut decoder = FrameDecoder::new(true);
        assert!(decoder.push(&frame).unwrap().is_empty());
        let mut buf = [0u8; 4];
        assert_eq!(decoder.pop(&mut buf), 4);
        assert_eq!(&buf, b"ping");
        let back = encode_frame(BINARY, b"pong", false);
        let mut server = FrameDecoder::new(false);
        server.push(&back).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(server.pop(&mut out), 4);
        assert_eq!(&out, b"pong");
    }

    #[test]
    fn reads_fragmented_payload_and_interleaved_control() {
        let first = b"prefix";
        let mut start = encode_frame(BINARY, first, true);
        start[0] &= !0x80;
        let mut decoder = FrameDecoder::new(true);
        for byte in start {
            assert!(decoder.push(&[byte]).unwrap().is_empty());
        }
        let mut initial = [0; 6];
        assert_eq!(decoder.pop(&mut initial), first.len());
        assert_eq!(&initial, first);

        let ping = encode_frame(PING, b"token", true);
        let body: Vec<u8> = (0..70_000).map(|index| (index % 251) as u8).collect();
        let continuation = encode_frame(0, &body, true);
        let mut signals = Vec::new();
        let mut decoded = Vec::new();
        for chunk in [ping, continuation].concat().chunks(17) {
            signals.extend(decoder.push(chunk).unwrap());
            let mut bytes = [0; 17];
            let count = decoder.pop(&mut bytes);
            decoded.extend_from_slice(&bytes[..count]);
        }
        assert_eq!(signals, [WsSignal::Ping(b"token".to_vec())]);
        assert_eq!(decoded, body);
        assert_eq!(decoder.eof().unwrap(), 0);
    }

    #[test]
    fn invalid_control_and_fragment_sequences_are_rejected() {
        for frame in [
            vec![0x80, 0],
            vec![0x09, 0],
            vec![0x89, 126],
            vec![0x82, 126, 0, 0],
            vec![0x82, 127, 128, 0, 0, 0, 0, 0, 0, 0],
            encode_frame(CLOSE, &[0], false),
            encode_frame(CLOSE, &[0x03, 0xe8, 0xff], false),
            encode_frame(BINARY, b"wrong mask", true),
        ] {
            assert_eq!(
                FrameDecoder::new(false).push(&frame),
                Err(UpgradeError::Bad)
            );
        }
        let mut decoder = FrameDecoder::new(false);
        decoder.push(&[BINARY, 0]).unwrap();
        assert_eq!(
            decoder.eof().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(decoder.push(&[0x82, 0]), Err(UpgradeError::Bad));
    }

    struct GatedWrite {
        bytes: Vec<u8>,
        remaining: usize,
    }

    impl Write for GatedWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let count = self.remaining.min(buf.len());
            self.bytes.extend_from_slice(&buf[..count]);
            self.remaining -= count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn split_pong_and_data_resume_partial_writes_in_wire_order() {
        let close = [0x03, 0xe8, b'b', b'y', b'e'];
        let input = [
            encode_frame(BINARY, b"reply", true),
            encode_frame(CLOSE, &close, true),
            encode_frame(BINARY, b"ignored", true),
        ]
        .concat();
        let wire = GatedWrite {
            bytes: Vec::new(),
            remaining: 3,
        };
        let prelude = encode_frame(PING, b"ping", true);
        let (mut reader, mut writer) =
            websocket_pair(Cursor::new(input.as_slice()), wire, true, false, &prelude).unwrap();

        assert_eq!(
            writer.write(b"one").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            writer.write(b"bad").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        writer.map_io(|wire| wire.remaining = 3);
        let mut buf = [0; 5];
        assert_eq!(
            reader.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(writer.write(b"one").unwrap(), 3);
        writer.map_io(|wire| wire.remaining = usize::MAX);
        writer.write_all(b"two").unwrap();
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"reply");
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        assert_eq!(
            writer.write(b"too late").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );

        let expected = [
            encode_frame(BINARY, b"one", false),
            encode_frame(PONG, b"ping", false),
            encode_frame(BINARY, b"two", false),
            encode_frame(CLOSE, &close, false),
        ]
        .concat();
        writer.map_io(|wire| assert_eq!(wire.bytes, expected));
    }
}
