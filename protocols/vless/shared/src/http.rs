//! HTTP/2 transport for VLESS HTTP, gRPC, and XHTTP.

use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::host_matches;

pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PUSH_PROMISE: u8 = 5;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 1;
const ACK: u8 = 1;
const END_HEADERS: u8 = 4;
const PADDED: u8 = 8;
const HAS_PRIORITY: u8 = 0x20;

const PROTOCOL_ERROR: u32 = 1;
const FLOW_CONTROL_ERROR: u32 = 3;
const STREAM_CLOSED: u32 = 5;
const REFUSED_STREAM: u32 = 7;
const CANCEL: u32 = 8;

const DEFAULT_WINDOW: u32 = 65_535;
const MAX_WINDOW: u32 = 0x7fff_ffff;
const RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const FRAME_SIZE: usize = 16_384;
const HEADER_LIMIT: usize = 64 * 1024;
const HEADER_TABLE_SIZE: usize = 4096;
const STREAM_LIMIT: usize = 128;

type Headers = Vec<(String, String)>;

struct ReceiveWindow {
    available: u32,
    consumed: u32,
}

impl ReceiveWindow {
    fn new(available: u32) -> Self {
        Self {
            available,
            consumed: 0,
        }
    }

    fn receive(&mut self, len: u32) -> bool {
        let Some(available) = self.available.checked_sub(len) else {
            return false;
        };
        self.available = available;
        true
    }

    fn release(&mut self, len: u32) -> Option<u32> {
        self.consumed += len;
        if self.consumed == 0
            || (self.consumed < FRAME_SIZE as u32 && self.available >= DEFAULT_WINDOW)
        {
            return None;
        }
        let increment = std::mem::take(&mut self.consumed);
        self.available += increment;
        Some(increment)
    }
}

struct Stream {
    send_window: i64,
    receive_window: ReceiveWindow,
    headers: Option<Headers>,
    trailers: Headers,
    body: VecDeque<u8>,
    sent_headers: bool,
    sent_end: bool,
    received_end: bool,
    any_status: bool,
    reset: Option<u32>,
}

impl Stream {
    fn new(send_window: i64, receive_window: u32) -> Self {
        Self {
            send_window,
            receive_window: ReceiveWindow::new(receive_window),
            headers: None,
            trailers: Vec::new(),
            body: VecDeque::new(),
            sent_headers: false,
            sent_end: false,
            received_end: false,
            any_status: false,
            reset: None,
        }
    }

    fn check_reset(&self) -> io::Result<()> {
        match self.reset {
            Some(code) => Err(io::Error::new(
                ErrorKind::ConnectionReset,
                format!("HTTP/2 stream reset ({code})"),
            )),
            None => Ok(()),
        }
    }
}

struct HeaderBlock {
    stream: u32,
    end_stream: bool,
    bytes: Vec<u8>,
}

struct H2State {
    server: bool,
    preface: bool,
    settings_received: bool,
    peer_goaway: Option<u32>,
    next: u32,
    last_peer: u32,
    stream_limit: usize,
    peer_stream_limit: usize,
    initial_send_window: i64,
    initial_receive_window: u32,
    send_window: i64,
    receive_window: ReceiveWindow,
    streams: HashMap<u32, Stream>,
    accepted: VecDeque<u32>,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
    header_limit: usize,
    peer_header_limit: usize,
    header_block: Option<HeaderBlock>,
    decoder: hpack::Decoder<'static>,
    failure: Option<(ErrorKind, String)>,
    reading: bool,
}

impl H2State {
    fn new(server: bool, preface: bool, stream_limit: usize) -> Self {
        Self::with_header_limit(server, preface, stream_limit, None)
    }

    fn with_header_limit(server: bool, preface: bool, stream_limit: usize, header_limit: Option<u32>) -> Self {
        Self::with_limits(server, preface, stream_limit, header_limit, None)
    }

    fn with_limits(
        server: bool,
        preface: bool,
        stream_limit: usize,
        header_limit: Option<u32>,
        receive_window: Option<u32>,
    ) -> Self {
        let mut outbound = Vec::new();
        if !server {
            outbound.extend_from_slice(HTTP2_PREFACE);
        }
        let mut settings = Vec::new();
        if !server {
            setting(&mut settings, 2, 0);
        } else {
            setting(&mut settings, 3, stream_limit as u32);
        }
        let stream_window = receive_window.unwrap_or(RECEIVE_WINDOW);
        setting(&mut settings, 4, stream_window);
        if let Some(limit) = header_limit {
            setting(&mut settings, 6, limit);
        }
        queue_frame(&mut outbound, SETTINGS, 0, 0, &settings);
        // An explicit gRPC stream window disables automatic connection-window expansion.
        let connection_window = if receive_window.is_some() { DEFAULT_WINDOW } else { RECEIVE_WINDOW };
        if connection_window > DEFAULT_WINDOW {
            queue_frame(
                &mut outbound,
                WINDOW_UPDATE,
                0,
                0,
                &(connection_window - DEFAULT_WINDOW).to_be_bytes(),
            );
        }
        Self {
            server,
            preface,
            settings_received: false,
            peer_goaway: None,
            next: 1,
            last_peer: 0,
            stream_limit,
            peer_stream_limit: usize::MAX,
            initial_send_window: i64::from(DEFAULT_WINDOW),
            initial_receive_window: stream_window,
            send_window: i64::from(DEFAULT_WINDOW),
            receive_window: ReceiveWindow::new(connection_window),
            streams: HashMap::new(),
            accepted: VecDeque::new(),
            inbound: Vec::new(),
            outbound,
            header_limit: header_limit.map_or(HEADER_LIMIT, |limit| limit as usize),
            peer_header_limit: HEADER_LIMIT,
            header_block: None,
            decoder: hpack::Decoder::new(),
            failure: None,
            reading: false,
        }
    }

    fn check_connection(&self) -> io::Result<()> {
        match &self.failure {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }

    fn fail(&mut self, error: &io::Error) {
        if self.failure.is_none() {
            self.failure = Some((error.kind(), error.to_string()));
        }
    }

    fn check_goaway(&self) -> io::Result<()> {
        if self.peer_goaway.is_some() {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "HTTP/2 peer is draining",
            ));
        }
        self.check_connection()
    }

    fn stream(&self, id: u32) -> io::Result<&Stream> {
        self.streams
            .get(&id)
            .ok_or_else(|| io::Error::new(ErrorKind::BrokenPipe, "HTTP/2 stream closed"))
    }

    fn closed_stream(&self, id: u32) -> bool {
        id % 2 == 1
            && if self.server {
                id <= self.last_peer
            } else {
                id < self.next
            }
    }

    fn open(&mut self, headers: &[(&str, &str)], end: bool) -> io::Result<Option<u32>> {
        self.check_goaway()?;
        if self.server || self.next > MAX_WINDOW {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "HTTP/2 stream identifiers exhausted",
            ));
        }
        let active = self
            .streams
            .values()
            .filter(|slot| slot.reset.is_none() && !(slot.sent_end && slot.received_end))
            .count();
        if active >= self.peer_stream_limit {
            return Ok(None);
        }
        let id = self.next;
        let mut slot = Stream::new(self.initial_send_window, self.initial_receive_window);
        send_headers_with_limit(&mut self.outbound, id, headers, end, self.peer_header_limit)?;
        slot.sent_headers = true;
        slot.sent_end = end;
        self.streams.insert(id, slot);
        self.next += 2;
        Ok(Some(id))
    }

    fn accept(&mut self) -> io::Result<Option<u32>> {
        if let Some(id) = self.accepted.pop_front() {
            return Ok(Some(id));
        }
        self.check_goaway()?;
        Ok(None)
    }

    fn reply(&mut self, id: u32, headers: &[(&str, &str)], end: bool) -> io::Result<()> {
        self.check_connection()?;
        let slot = self.stream(id)?;
        slot.check_reset()?;
        if !self.server || slot.sent_end || (slot.sent_headers && !end) {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "HTTP/2 response already sent",
            ));
        }
        send_headers_with_limit(&mut self.outbound, id, headers, end, self.peer_header_limit)?;
        let slot = self.streams.get_mut(&id).expect("open stream");
        slot.sent_headers = true;
        slot.sent_end = end;
        Ok(())
    }

    fn status(&self, id: u32) -> io::Result<Option<()>> {
        let slot = self.stream(id)?;
        slot.check_reset()?;
        match slot
            .headers
            .as_ref()
            .and_then(|headers| header(headers, ":status"))
        {
            Some("200") => Ok(Some(())),
            Some(status) if slot.any_status && status.parse::<u16>().is_ok_and(|status| (200..=599).contains(&status)) => Ok(Some(())),
            Some(status) => Err(io::Error::other(format!("HTTP/2 response status {status}"))),
            None => {
                self.check_connection()?;
                Ok(None)
            }
        }
    }

    fn read_data(&mut self, id: u32, buf: &mut [u8]) -> io::Result<Option<usize>> {
        if !self.server && self.status(id)?.is_none() {
            return Ok(None);
        }
        let slot = self.streams.get_mut(&id).expect("open stream");
        slot.check_reset()?;
        let len = buf.len().min(slot.body.len());
        if len != 0 {
            let (head, tail) = slot.body.as_slices();
            let head_len = len.min(head.len());
            buf[..head_len].copy_from_slice(&head[..head_len]);
            buf[head_len..len].copy_from_slice(&tail[..len - head_len]);
            slot.body.drain(..len);
            self.release(id, len as u32);
            return Ok(Some(len));
        }
        if slot.received_end {
            if !self.server {
                let status = header(&slot.trailers, "grpc-status").or_else(|| {
                    slot.headers
                        .as_ref()
                        .and_then(|headers| header(headers, "grpc-status"))
                });
                if let Some(status) = status.filter(|status| *status != "0") {
                    return Err(io::Error::other(format!("gRPC status {status}")));
                }
            }
            return Ok(Some(0));
        }
        self.check_connection()?;
        Ok(None)
    }

    fn write_data(&mut self, id: u32, buf: &[u8], end: bool) -> io::Result<Option<usize>> {
        self.check_connection()?;
        let slot = self.stream(id)?;
        slot.check_reset()?;
        if !slot.sent_headers || slot.sent_end {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "HTTP/2 send side closed",
            ));
        }
        if !self.server {
            self.status(id)?;
        }
        if !self.settings_received && !buf.is_empty() {
            return Ok(None);
        }
        let window = self.send_window.min(slot.send_window).max(0) as usize;
        let len = buf.len().min(window).min(FRAME_SIZE);
        if len == 0 && !buf.is_empty() {
            return Ok(None);
        }
        let end = end && len == buf.len();
        let slot = self.streams.get_mut(&id).expect("open stream");
        slot.send_window -= len as i64;
        slot.sent_end = end;
        self.send_window -= len as i64;
        queue_frame(
            &mut self.outbound,
            DATA,
            if end { END_STREAM } else { 0 },
            id,
            &buf[..len],
        );
        Ok(Some(len))
    }

    fn release(&mut self, id: u32, len: u32) {
        if let Some(increment) = self.receive_window.release(len) {
            queue_frame(
                &mut self.outbound,
                WINDOW_UPDATE,
                0,
                0,
                &increment.to_be_bytes(),
            );
        }
        if let Some(slot) = self.streams.get_mut(&id) {
            if !slot.received_end && slot.reset.is_none() {
                if let Some(increment) = slot.receive_window.release(len) {
                    queue_frame(
                        &mut self.outbound,
                        WINDOW_UPDATE,
                        0,
                        id,
                        &increment.to_be_bytes(),
                    );
                }
            }
        }
    }

    fn reset(&mut self, id: u32, code: u32, send: bool) {
        if let Some(slot) = self.streams.get_mut(&id) {
            slot.reset = Some(code);
            let discarded = slot.body.len() as u32;
            slot.body.clear();
            self.release(id, discarded);
        }
        if let Some(index) = self.accepted.iter().position(|queued| *queued == id) {
            self.accepted.remove(index);
            self.streams.remove(&id);
        }
        if send {
            queue_frame(&mut self.outbound, RST_STREAM, 0, id, &code.to_be_bytes());
        }
    }

    fn close(&mut self, id: u32, grpc: bool) {
        let Some(slot) = self.streams.remove(&id) else {
            return;
        };
        self.release(id, slot.body.len() as u32);
        if self.failure.is_some() || slot.reset.is_some() || (slot.sent_end && slot.received_end) {
            return;
        }
        if grpc && self.server && slot.sent_headers {
            let trailers = [("grpc-status", "0")];
            if !slot.sent_end
                && send_headers_with_limit(&mut self.outbound, id, &trailers, true, self.peer_header_limit).is_err()
            {
                self.reset(id, CANCEL, true);
            } else if !slot.received_end {
                // The completed response is valid even if the client is still sending.
                self.reset(id, 0, true);
            }
        } else if !slot.sent_end && slot.sent_headers && (self.server || slot.received_end) {
            queue_frame(&mut self.outbound, DATA, END_STREAM, id, &[]);
        } else {
            self.reset(id, CANCEL, true);
        }
    }

    fn read_result(&mut self, result: io::Result<usize>, bytes: &[u8]) -> io::Result<bool> {
        let error = match result {
            Ok(0) => io::Error::new(ErrorKind::UnexpectedEof, "HTTP/2 connection closed"),
            Ok(len) => match self.receive(&bytes[..len]) {
                Ok(frames) => return Ok(frames),
                Err(error) => {
                    let mut payload = [0; 8];
                    payload[..4].copy_from_slice(&self.last_peer.to_be_bytes());
                    payload[4..].copy_from_slice(&PROTOCOL_ERROR.to_be_bytes());
                    queue_frame(&mut self.outbound, GOAWAY, 0, 0, &payload);
                    error
                }
            },
            Err(error) if retryable(&error) => return Err(error),
            Err(error) => error,
        };
        self.fail(&error);
        Err(error)
    }

    fn receive(&mut self, bytes: &[u8]) -> io::Result<bool> {
        self.inbound.extend_from_slice(bytes);
        let mut offset = 0;
        if !self.preface {
            if self.inbound.len() < HTTP2_PREFACE.len() {
                return Ok(false);
            }
            if !self.inbound.starts_with(HTTP2_PREFACE) {
                return Err(protocol_error("HTTP/2 preface"));
            }
            offset = HTTP2_PREFACE.len();
            self.preface = true;
        }
        let frames_start = offset;
        while self.inbound.len() - offset >= 9 {
            let head = &self.inbound[offset..offset + 9];
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            if len > FRAME_SIZE {
                return Err(protocol_error("HTTP/2 frame too large"));
            }
            let end = offset + 9 + len;
            if end > self.inbound.len() {
                break;
            }
            let kind = head[3];
            let flags = head[4];
            let stream = u32::from_be_bytes(head[5..9].try_into().unwrap()) & MAX_WINDOW;
            let payload = self.inbound[offset + 9..end].to_vec();
            self.frame(kind, flags, stream, &payload)?;
            if self.outbound.len() > RECEIVE_WINDOW as usize {
                return Err(protocol_error("HTTP/2 output backlog"));
            }
            offset = end;
        }
        self.inbound.drain(..offset);
        Ok(offset != frames_start)
    }

    fn frame(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) -> io::Result<()> {
        if !self.settings_received && (kind != SETTINGS || flags & ACK != 0) {
            return Err(protocol_error("HTTP/2 peer preface SETTINGS missing"));
        }
        if let Some(block) = &self.header_block {
            if kind != CONTINUATION || stream != block.stream {
                return Err(protocol_error("HTTP/2 expected CONTINUATION"));
            }
        }

        match kind {
            DATA if stream != 0 => self.receive_data(stream, flags, payload),
            HEADERS if stream != 0 => {
                let bytes = unpad(flags, payload)?;
                let bytes = if flags & HAS_PRIORITY != 0 {
                    bytes
                        .get(5..)
                        .ok_or_else(|| protocol_error("HTTP/2 HEADERS priority"))?
                } else {
                    bytes
                };
                let block = HeaderBlock {
                    stream,
                    end_stream: flags & END_STREAM != 0,
                    bytes: bytes.to_vec(),
                };
                self.headers(block, flags)
            }
            CONTINUATION => {
                let mut block = self
                    .header_block
                    .take()
                    .ok_or_else(|| protocol_error("HTTP/2 unexpected CONTINUATION"))?;
                if block.bytes.len() + payload.len() > self.header_limit.saturating_add(FRAME_SIZE) {
                    return Err(protocol_error("HTTP/2 header block too large"));
                }
                block.bytes.extend_from_slice(payload);
                self.headers(block, flags)
            }
            PRIORITY if stream != 0 && payload.len() == 5 => Ok(()),
            RST_STREAM if stream != 0 && payload.len() == 4 && self.closed_stream(stream) => {
                let code = u32::from_be_bytes(payload.try_into().unwrap());
                if let Some(slot) = self.streams.get_mut(&stream) {
                    if slot.received_end && (slot.sent_end || (!self.server && code == 0)) {
                        // A server can ask the client to stop sending after completing its response.
                        slot.sent_end = true;
                    } else {
                        self.reset(stream, code, false);
                    }
                }
                Ok(())
            }
            SETTINGS if stream == 0 => self.settings(flags, payload),
            PING if stream == 0 && payload.len() == 8 => {
                if flags & ACK == 0 {
                    queue_frame(&mut self.outbound, PING, ACK, 0, payload);
                }
                Ok(())
            }
            GOAWAY if stream == 0 && payload.len() >= 8 => {
                let last = u32::from_be_bytes(payload[..4].try_into().unwrap()) & MAX_WINDOW;
                let last = self.peer_goaway.map_or(last, |old| old.min(last));
                self.peer_goaway = Some(last);
                if !self.server {
                    let refused: Vec<_> = self
                        .streams
                        .keys()
                        .filter(|id| **id > last)
                        .copied()
                        .collect();
                    for id in refused {
                        self.reset(id, REFUSED_STREAM, false);
                    }
                }
                Ok(())
            }
            WINDOW_UPDATE if payload.len() == 4 => {
                let increment = u32::from_be_bytes(payload.try_into().unwrap()) & MAX_WINDOW;
                self.window_update(stream, increment)
            }
            DATA | HEADERS | PRIORITY | RST_STREAM | SETTINGS | PUSH_PROMISE | PING | GOAWAY
            | WINDOW_UPDATE => Err(protocol_error("HTTP/2 invalid frame")),
            _ => Ok(()),
        }
    }

    fn receive_data(&mut self, id: u32, flags: u8, payload: &[u8]) -> io::Result<()> {
        let bytes = unpad(flags, payload)?;
        let len = payload.len() as u32;
        if !self.receive_window.receive(len) {
            return Err(protocol_error("HTTP/2 connection receive window exceeded"));
        }
        if !self.closed_stream(id) {
            return Err(protocol_error("HTTP/2 DATA on idle stream"));
        }
        let Some(slot) = self.streams.get_mut(&id) else {
            self.release(id, len);
            return Ok(());
        };
        if slot.reset.is_some() {
            self.release(id, len);
            return Ok(());
        }
        if slot.received_end || slot.headers.is_none() {
            self.reset(id, STREAM_CLOSED, true);
            self.release(id, len);
            return Ok(());
        }
        if !slot.receive_window.receive(len) {
            self.reset(id, FLOW_CONTROL_ERROR, true);
            self.release(id, len);
            return Ok(());
        }
        slot.body.extend(bytes);
        slot.received_end = flags & END_STREAM != 0;
        self.release(id, len - bytes.len() as u32);
        Ok(())
    }

    fn headers(&mut self, block: HeaderBlock, flags: u8) -> io::Result<()> {
        if flags & END_HEADERS == 0 {
            self.header_block = Some(block);
            return Ok(());
        }
        let id = block.stream;
        let headers = decode_headers(&mut self.decoder, &block.bytes, self.header_limit)?;
        if !self.closed_stream(id) {
            if !self.server || id % 2 == 0 {
                return Err(protocol_error("HTTP/2 HEADERS on invalid stream"));
            }
            self.last_peer = id;
            if self.streams.len() >= self.stream_limit {
                self.reset(id, REFUSED_STREAM, true);
                return Ok(());
            }
            if header(&headers, ":path").is_none() || header(&headers, ":method").is_none() {
                self.reset(id, PROTOCOL_ERROR, true);
                return Ok(());
            }
            let mut slot = Stream::new(self.initial_send_window, self.initial_receive_window);
            slot.headers = Some(headers);
            slot.received_end = block.end_stream;
            self.streams.insert(id, slot);
            self.accepted.push_back(id);
            return Ok(());
        }
        let Some(slot) = self.streams.get_mut(&id) else {
            return Ok(());
        };
        if slot.reset.is_some() {
            return Ok(());
        }
        if slot.received_end {
            self.reset(id, STREAM_CLOSED, true);
            return Ok(());
        }
        if slot.headers.is_none() {
            let status = header(&headers, ":status").and_then(|value| value.parse::<u16>().ok());
            match status {
                Some(100..=199) if !block.end_stream => return Ok(()),
                Some(200..=599) => slot.headers = Some(headers),
                _ => {
                    self.reset(id, PROTOCOL_ERROR, true);
                    return Ok(());
                }
            }
        } else if block.end_stream && headers.iter().all(|(key, _)| !key.starts_with(':')) {
            slot.trailers = headers;
        } else {
            self.reset(id, PROTOCOL_ERROR, true);
            return Ok(());
        }
        slot.received_end = block.end_stream;
        Ok(())
    }

    fn settings(&mut self, flags: u8, payload: &[u8]) -> io::Result<()> {
        if flags & ACK != 0 {
            return if payload.is_empty() {
                Ok(())
            } else {
                Err(protocol_error("HTTP/2 SETTINGS ACK payload"))
            };
        }
        if payload.len() % 6 != 0 {
            return Err(protocol_error("HTTP/2 SETTINGS length"));
        }
        for setting in payload.chunks_exact(6) {
            let id = u16::from_be_bytes(setting[..2].try_into().unwrap());
            let value = u32::from_be_bytes(setting[2..].try_into().unwrap());
            match id {
                2 if value > 1 || (!self.server && value == 1) => {
                    return Err(protocol_error("HTTP/2 SETTINGS_ENABLE_PUSH"))
                }
                3 => self.peer_stream_limit = value as usize,
                4 => {
                    if value > MAX_WINDOW {
                        return Err(protocol_error("HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE"));
                    }
                    let delta = i64::from(value) - self.initial_send_window;
                    for slot in self
                        .streams
                        .values_mut()
                        .filter(|slot| !slot.sent_end && slot.reset.is_none())
                    {
                        slot.send_window += delta;
                        if slot.send_window > i64::from(MAX_WINDOW) {
                            return Err(protocol_error("HTTP/2 stream send window overflow"));
                        }
                    }
                    self.initial_send_window = i64::from(value);
                }
                5 if !(FRAME_SIZE as u32..=0xff_ffff).contains(&value) => {
                    return Err(protocol_error("HTTP/2 SETTINGS_MAX_FRAME_SIZE"))
                }
                6 => self.peer_header_limit = value as usize,
                _ => {}
            }
        }
        self.settings_received = true;
        queue_frame(&mut self.outbound, SETTINGS, ACK, 0, &[]);
        Ok(())
    }

    fn window_update(&mut self, id: u32, increment: u32) -> io::Result<()> {
        if id == 0 {
            self.send_window += i64::from(increment);
            if increment == 0 || self.send_window > i64::from(MAX_WINDOW) {
                return Err(protocol_error("HTTP/2 invalid connection window update"));
            }
        } else if !self.closed_stream(id) {
            return Err(protocol_error("HTTP/2 WINDOW_UPDATE on idle stream"));
        } else if let Some(slot) = self.streams.get_mut(&id) {
            if slot.sent_end || slot.reset.is_some() {
                return Ok(());
            }
            slot.send_window += i64::from(increment);
            if increment == 0 {
                self.reset(id, PROTOCOL_ERROR, true);
            } else if slot.send_window > i64::from(MAX_WINDOW) {
                self.reset(id, FLOW_CONTROL_ERROR, true);
            }
        }
        Ok(())
    }
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

fn retryable(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn header_list<'a>(
    method: &'a str,
    path: &'a str,
    authority: &'a str,
    scheme: &'a str,
    extra: &'a [(&str, &str)],
) -> Vec<(&'a str, &'a str)> {
    let mut headers = vec![
        (":method", method),
        (":scheme", scheme),
        (":path", path),
        (":authority", authority),
    ];
    headers.extend_from_slice(extra);
    headers
}

fn setting(settings: &mut Vec<u8>, id: u16, value: u32) {
    settings.extend_from_slice(&id.to_be_bytes());
    settings.extend_from_slice(&value.to_be_bytes());
}

fn queue_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
}

fn unpad(flags: u8, payload: &[u8]) -> io::Result<&[u8]> {
    if flags & PADDED == 0 {
        return Ok(payload);
    }
    let Some((&padding, bytes)) = payload.split_first() else {
        return Err(protocol_error("HTTP/2 missing pad length"));
    };
    let len = bytes
        .len()
        .checked_sub(padding as usize)
        .ok_or_else(|| protocol_error("HTTP/2 invalid pad length"))?;
    Ok(&bytes[..len])
}

#[cfg(test)]
fn send_headers(out: &mut Vec<u8>, id: u32, headers: &[(&str, &str)], end: bool) -> io::Result<()> {
    send_headers_with_limit(out, id, headers, end, HEADER_LIMIT)
}

fn send_headers_with_limit(
    out: &mut Vec<u8>,
    id: u32,
    headers: &[(&str, &str)],
    end: bool,
    limit: usize,
) -> io::Result<()> {
    let mut block = Vec::new();
    let mut decoded_size = 0;
    // Literal fields do not depend on the peer's dynamic table size.
    for (key, value) in headers {
        decoded_size += key.len() + value.len() + 32;
        if decoded_size > limit {
            return Err(protocol_error("HTTP/2 header list too large"));
        }
        block.push(0);
        for field in [key, value] {
            hpack::encoder::encode_integer_into(field.len(), 7, 0, &mut block)?;
            block.extend_from_slice(field.as_bytes());
        }
    }
    if block.is_empty() {
        queue_frame(
            out,
            HEADERS,
            END_HEADERS | if end { END_STREAM } else { 0 },
            id,
            &[],
        );
        return Ok(());
    }
    for (i, chunk) in block.chunks(FRAME_SIZE).enumerate() {
        let mut flags = if i == 0 && end { END_STREAM } else { 0 };
        if i * FRAME_SIZE + chunk.len() == block.len() {
            flags |= END_HEADERS;
        }
        queue_frame(
            out,
            if i == 0 { HEADERS } else { CONTINUATION },
            flags,
            id,
            chunk,
        );
    }
    Ok(())
}

fn decode_headers(decoder: &mut hpack::Decoder<'_>, bytes: &[u8], limit: usize) -> io::Result<Headers> {
    // hpack 0.3 assumes a well-formed table update and does not enforce the advertised limit.
    validate_hpack(bytes)?;
    let mut headers = Vec::new();
    let mut decoded_size = 0usize;
    decoder
        .decode_with_cb(bytes, |key, value| {
            decoded_size += key.len() + value.len() + 32;
            if decoded_size <= limit {
                headers.push((
                    String::from_utf8_lossy(&key).into_owned(),
                    String::from_utf8_lossy(&value).into_owned(),
                ));
            }
        })
        .map_err(|_| protocol_error("HTTP/2 HPACK block"))?;
    if decoded_size > limit {
        return Err(protocol_error("HTTP/2 header list too large"));
    }
    Ok(headers)
}

fn validate_hpack(mut bytes: &[u8]) -> io::Result<()> {
    let mut fields = false;
    while let Some(&first) = bytes.first() {
        if first & 0xe0 == 0x20 {
            let size = hpack_integer(&mut bytes, 5)?;
            if fields || size > HEADER_TABLE_SIZE {
                return Err(protocol_error("HTTP/2 HPACK table size"));
            }
            continue;
        }
        fields = true;
        if first & 0x80 != 0 {
            hpack_integer(&mut bytes, 7)?;
            continue;
        }
        let index = hpack_integer(&mut bytes, if first & 0x40 != 0 { 6 } else { 4 })?;
        for _ in 0..if index == 0 { 2 } else { 1 } {
            let len = hpack_integer(&mut bytes, 7)?;
            bytes = bytes
                .get(len..)
                .ok_or_else(|| protocol_error("HTTP/2 HPACK string length"))?;
        }
    }
    Ok(())
}

fn hpack_integer(bytes: &mut &[u8], prefix: u8) -> io::Result<usize> {
    let mask = (1 << prefix) - 1;
    let (first, rest) = bytes
        .split_first()
        .ok_or_else(|| protocol_error("HTTP/2 HPACK integer"))?;
    let mut value = usize::from(first & mask);
    *bytes = rest;
    if value < usize::from(mask) {
        return Ok(value);
    }
    for shift in [0, 7, 14, 21] {
        let (byte, rest) = bytes
            .split_first()
            .ok_or_else(|| protocol_error("HTTP/2 HPACK integer"))?;
        *bytes = rest;
        value += usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(protocol_error("HTTP/2 HPACK integer length"))
}

fn read_retry(io: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match io.read(buf) {
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn flush_bytes(io: &mut impl Write, buf: &mut Vec<u8>) -> io::Result<()> {
    let mut sent = 0;
    while sent < buf.len() {
        let error = match io.write(&buf[sent..]) {
            Ok(0) => io::Error::new(ErrorKind::WriteZero, "HTTP/2 write"),
            Ok(n) => {
                sent += n;
                continue;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => error,
        };
        buf.drain(..sent);
        return Err(error);
    }
    buf.clear();
    io.flush()
}

pub struct HttpIo<T> {
    inner: T,
    state: H2State,
    id: u32,
}

impl<T: Read + Write> HttpIo<T> {
    pub fn connect(
        inner: T,
        authority: &str,
        path: &str,
        method: &str,
        scheme: &str,
    ) -> io::Result<Self> {
        Self::connect_with(inner, authority, path, method, scheme, &[])
    }

    pub fn connect_with(
        inner: T,
        authority: &str,
        path: &str,
        method: &str,
        scheme: &str,
        extra: &[(&str, &str)],
    ) -> io::Result<Self> {
        let mut io = Self::offer(inner, authority, path, method, scheme, extra)?;
        io.wait_status()?;
        Ok(io)
    }

    pub fn accept(inner: T, path: &str, host: &str, method: &str) -> io::Result<Self> {
        Self::receive_request(inner, false)?.finish_accept(path, host, method)
    }

    /// The HTTP/2 preface was already checked and consumed.
    pub fn accept_opened(inner: T, path: &str, host: &str, method: &str) -> io::Result<Self> {
        Self::accept_request(inner)?.finish_accept(path, host, method)
    }

    /// Preface already consumed. Returns after the request headers, before the response.
    pub fn accept_request(inner: T) -> io::Result<Self> {
        Self::receive_request(inner, true)
    }

    pub(crate) fn receive_request(inner: T, preface: bool) -> io::Result<Self> {
        let mut io = Self {
            inner,
            state: H2State::new(true, preface, 1),
            id: 0,
        };
        io.flush_out()?;
        io.id = io.drive(H2State::accept)?;
        Ok(io)
    }

    /// Sends the preface and request headers, and does not wait for the response.
    pub fn offer(
        inner: T,
        authority: &str,
        path: &str,
        method: &str,
        scheme: &str,
        extra: &[(&str, &str)],
    ) -> io::Result<Self> {
        let mut state = H2State::new(false, true, 1);
        let id = state
            .open(&header_list(method, path, authority, scheme, extra), false)?
            .expect("initial stream");
        let mut io = Self { inner, state, id };
        io.flush_out()?;
        Ok(io)
    }

    /// Sends one request body and waits for a successful response.
    pub fn post_packet(
        inner: T,
        authority: &str,
        path: &str,
        scheme: &str,
        extra: &[(&str, &str)],
        mut payload: &[u8],
    ) -> io::Result<()> {
        let mut io = Self::offer(inner, authority, path, "POST", scheme, extra)?;
        let id = io.id;
        loop {
            let len = io.drive(|state| state.write_data(id, payload, true))?;
            io.flush_out()?;
            if len == payload.len() {
                break;
            }
            payload = &payload[len..];
        }
        io.wait_status()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.state
            .stream(self.id)
            .ok()?
            .headers
            .as_ref()
            .and_then(|headers| header(headers, name))
    }

    pub fn reply(&mut self) -> io::Result<()> {
        self.reply_with(&[(":status", "200")])
    }

    pub(crate) fn reply_with(&mut self, headers: &[(&str, &str)]) -> io::Result<()> {
        self.state.reply(self.id, headers, false)?;
        self.flush_out()
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_shared<R, W>(self, split: impl FnOnce(T) -> (R, W)) -> SharedHttp<R, W> {
        let (read, write) = split(self.inner);
        SharedHttp {
            shared: SharedConnection::new(read, write, self.state),
            id: self.id,
        }
    }

    fn finish_accept(mut self, path: &str, host: &str, method: &str) -> io::Result<Self> {
        if self.header(":path") != Some(path)
            || self.header(":method") != Some(method)
            || (!host.is_empty()
                && !self
                    .header(":authority")
                    .is_some_and(|value| host_matches(value, host)))
        {
            return Err(protocol_error("HTTP/2 request"));
        }
        self.reply()?;
        Ok(self)
    }

    fn wait_status(&mut self) -> io::Result<()> {
        let id = self.id;
        self.drive(|state| state.status(id))
    }

    fn flush_out(&mut self) -> io::Result<()> {
        let result = flush_bytes(&mut self.inner, &mut self.state.outbound);
        if let Err(error) = &result {
            if !retryable(error) {
                self.state.fail(error);
            }
        }
        result
    }

    fn drive<V>(
        &mut self,
        mut operation: impl FnMut(&mut H2State) -> io::Result<Option<V>>,
    ) -> io::Result<V> {
        let mut bytes = [0; FRAME_SIZE];
        loop {
            if let Some(value) = operation(&mut self.state)? {
                return Ok(value);
            }
            self.flush_out()?;
            let result = read_retry(&mut self.inner, &mut bytes);
            let received = self.state.read_result(result, &bytes);
            let _ = self.flush_out();
            received?;
        }
    }
}

impl<T: Read + Write> Read for HttpIo<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let id = self.id;
        let len = self.drive(|state| state.read_data(id, buf))?;
        let _ = self.flush_out();
        Ok(len)
    }
}

impl<T: Read + Write> Write for HttpIo<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.flush_out()?;
        let id = self.id;
        let len = self.drive(|state| state.write_data(id, buf, false))?;
        match self.flush_out() {
            Err(error) if !retryable(&error) => Err(error),
            _ => Ok(len),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_out()
    }
}

struct SharedConnection<R, W> {
    reader: Option<Mutex<R>>,
    writer: Mutex<WireWriter<W>>,
    state: Mutex<H2State>,
    wake: Condvar,
}

struct WireWriter<W> {
    io: Option<W>,
    pending_flush: bool,
}

impl<R, W> SharedConnection<R, W> {
    fn new(read: R, write: W, state: H2State) -> Self {
        Self::with_reader(Some(read), write, state)
    }

    fn with_reader(read: Option<R>, write: W, state: H2State) -> Self {
        Self {
            reader: read.map(Mutex::new),
            writer: Mutex::new(WireWriter {
                io: Some(write),
                pending_flush: false,
            }),
            state: Mutex::new(state),
            wake: Condvar::new(),
        }
    }
}

impl<R, W: Write> SharedConnection<R, W> {
    fn flush(&self, wait: bool) -> io::Result<()> {
        let mut writer = if wait {
            self.writer.lock().expect("HTTP/2 writer")
        } else if let Ok(writer) = self.writer.try_lock() {
            writer
        } else {
            return Ok(());
        };
        loop {
            let mut state = self.state.lock().expect("HTTP/2 state");
            if writer.io.is_none() {
                state.check_connection()?;
                return Err(io::Error::new(ErrorKind::BrokenPipe, "HTTP/2 writer closed"));
            }
            if state.outbound.is_empty() && !writer.pending_flush {
                // Release the writer while holding state so a new control frame can always get a flush.
                drop(writer);
                return Ok(());
            }
            let mut bytes = std::mem::take(&mut state.outbound);
            drop(state);
            if let Err(error) = flush_bytes(writer.io.as_mut().expect("HTTP/2 writer"), &mut bytes) {
                let mut state = self.state.lock().expect("HTTP/2 state");
                if retryable(&error) {
                    writer.pending_flush = true;
                    bytes.append(&mut state.outbound);
                    state.outbound = bytes;
                } else {
                    writer.pending_flush = false;
                    state.fail(&error);
                    state.outbound.clear();
                    self.wake.notify_all();
                }
                drop(writer);
                return Err(error);
            }
            writer.pending_flush = false;
        }
    }

    fn close(&self, id: u32, grpc: bool) {
        self.state.lock().expect("HTTP/2 state").close(id, grpc);
        self.wake.notify_all();
        let _ = self.flush(false);
    }
}

impl<R: Read, W: Write> SharedConnection<R, W> {
    fn drive<V>(
        &self,
        operation: impl FnMut(&mut H2State) -> io::Result<Option<V>>,
    ) -> io::Result<V> {
        self.drive_for(None, operation)
    }

    fn drive_for<V>(
        &self,
        timeout: Option<Duration>,
        mut operation: impl FnMut(&mut H2State) -> io::Result<Option<V>>,
    ) -> io::Result<V> {
        let mut bytes = [0; FRAME_SIZE];
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let mut state = self.state.lock().expect("HTTP/2 state");
        loop {
            if let Some(value) = operation(&mut state)? {
                return Ok(value);
            }
            let Some(reader) = self.reader.as_ref().filter(|_| !state.reading) else {
                state = if let Some(deadline) = deadline {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::Error::new(ErrorKind::TimedOut, "HTTP/2 stream I/O"));
                    }
                    self.wake.wait_timeout(state, remaining).expect("HTTP/2 state").0
                } else {
                    self.wake.wait(state).expect("HTTP/2 state")
                };
                continue;
            };
            // Any waiting direction may read control frames. Socket reads never hold the state or writer lock.
            state.reading = true;
            drop(state);
            let received = read_retry(&mut *reader.lock().expect("HTTP/2 reader"), &mut bytes);
            state = self.state.lock().expect("HTTP/2 state");
            state.reading = false;
            let received = state.read_result(received, &bytes);
            self.wake.notify_all();
            drop(state);
            let _ = self.flush(false);
            received?;
            state = self.state.lock().expect("HTTP/2 state");
        }
    }

    fn read(&self, id: u32, buf: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let _ = self.flush(false);
        let len = self.drive_for(timeout, |state| state.read_data(id, buf))?;
        let _ = self.flush(false);
        Ok(len)
    }

    fn write(&self, id: u32, buf: &[u8], end: bool, timeout: Option<Duration>) -> io::Result<usize> {
        if buf.is_empty() && !end {
            return Ok(0);
        }
        self.flush(true)?;
        let len = self.drive_for(timeout, |state| state.write_data(id, buf, end))?;
        match self.flush(true) {
            Err(error) if !retryable(&error) => Err(error),
            _ => Ok(len),
        }
    }

    fn reply(&self, id: u32, end: bool) -> io::Result<()> {
        self.reply_with(id, &[(":status", "200")], end)
    }

    fn reply_with(&self, id: u32, headers: &[(&str, &str)], end: bool) -> io::Result<()> {
        self.state
            .lock()
            .expect("HTTP/2 state")
            .reply(id, headers, end)?;
        self.flush(true)
    }
}

pub struct SharedHttp<R, W> {
    shared: SharedConnection<R, W>,
    id: u32,
}

impl<R: Read, W: Write> SharedHttp<R, W> {
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.shared.read(self.id, buf, None)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.shared.write(self.id, buf, false, None)
    }

    pub fn flush(&self) -> io::Result<()> {
        self.shared.flush(true)
    }

    pub fn map_io(&self, read: impl FnOnce(&mut R), write: impl FnOnce(&mut W)) {
        // The caller configures the available halves without interrupting I/O on the other half.
        if let Some(reader) = &self.shared.reader {
            if let Ok(mut reader) = reader.try_lock() {
                read(&mut *reader);
            }
        }
        if let Ok(mut writer) = self.shared.writer.try_lock() {
            if let Some(io) = &mut writer.io {
                write(io);
            }
        }
    }
}

type Multiplexed<W> = SharedConnection<Box<dyn Read + Send>, W>;

pub struct H2Conn<W: Write> {
    shared: Arc<Multiplexed<W>>,
}

pub struct H2Stream<W: Write> {
    id: u32,
    shared: Arc<Multiplexed<W>>,
    grpc: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct H2Keepalive {
    pub interval: Duration,
    pub timeout: Duration,
    pub without_stream: bool,
}

impl<W: Write + Send + 'static> H2Conn<W> {
    pub fn request_any_status(
        &self, method: &str, path: &str, authority: &str, scheme: &str,
        extra: &[(&str, &str)], end: bool,
    ) -> io::Result<H2Stream<W>> {
        let stream = self.request(method, path, authority, scheme, extra, end, false)?;
        self.shared.state.lock().expect("HTTP/2 state").streams.get_mut(&stream.id).expect("open stream").any_status = true;
        self.shared.drive(|state| state.status(stream.id))?;
        Ok(stream)
    }

    pub fn wait_closed(&self) -> io::Result<()> {
        self.shared.drive(|state| {
            if state.peer_goaway.is_some() { return Ok(Some(())); }
            state.check_connection()?;
            Ok(None)
        })
    }

    pub fn serve<R: Read + Send + 'static>(read: R, write: W) -> io::Result<Self> {
        Self::start(read, write, true, None)
    }

    pub fn serve_with_header_limit<R: Read + Send + 'static>(read: R, write: W, limit: u32) -> io::Result<Self> {
        Self::start(read, write, true, Some(limit))
    }

    pub fn connect<R: Read + Send + 'static>(read: R, write: W) -> io::Result<Self> {
        Self::start(read, write, false, None)
    }

    pub fn connect_with_keepalive<R: Read + Send + 'static>(read: R, write: W, seconds: i64) -> io::Result<Self> {
        let interval = match seconds { 0 => 45, n if n > 0 => n as u64, _ => 0 };
        Self::start_grpc(read, write, false, None, (interval != 0).then(|| H2Keepalive {
            interval: Duration::from_secs(interval), timeout: Duration::from_secs(15), without_stream: true,
        }))
    }

    fn start<R: Read + Send + 'static>(read: R, write: W, server: bool, limit: Option<u32>) -> io::Result<Self> {
        let read: Box<dyn Read + Send> = Box::new(read);
        let shared = Arc::new(SharedConnection::new(
            read,
            write,
            H2State::with_header_limit(server, true, STREAM_LIMIT, limit),
        ));
        shared.flush(true)?;
        Ok(Self { shared })
    }

    pub(crate) fn start_grpc<R: Read + Send + 'static>(
        mut read: R,
        write: W,
        server: bool,
        receive_window: Option<u32>,
        keepalive: Option<H2Keepalive>,
    ) -> io::Result<Self> {
        let shared: Arc<Multiplexed<W>> = Arc::new(SharedConnection::with_reader(
            None,
            write,
            H2State::with_limits(server, !server, STREAM_LIMIT, None, receive_window),
        ));
        shared.flush(true)?;
        let connection = Arc::downgrade(&shared);
        std::thread::Builder::new().spawn(move || {
            let mut bytes = [0; FRAME_SIZE];
            let mut last_read = Instant::now();
            let handshake = last_read + Duration::from_secs(10);
            let mut ping = None;
            loop {
                let result = read_retry(&mut read, &mut bytes);
                let Some(shared) = connection.upgrade() else { return };
                let mut state = shared.state.lock().expect("HTTP/2 state");
                let now = Instant::now();
                if !state.settings_received && now >= handshake {
                    state.fail(&io::Error::new(ErrorKind::TimedOut, "HTTP/2 peer preface"));
                } else if state.read_result(result, &bytes).unwrap_or(false) {
                    last_read = now;
                    ping = None;
                }
                if let Some(keepalive) = keepalive.filter(|_| state.settings_received && state.failure.is_none()) {
                    if ping.is_some_and(|sent| now - sent >= keepalive.timeout) {
                        state.fail(&io::Error::new(ErrorKind::ConnectionReset, "HTTP/2 keepalive expired"));
                    } else if ping.is_none() && now - last_read >= keepalive.interval
                        && (keepalive.without_stream || state.streams.values().any(|slot| {
                            slot.reset.is_none() && !(slot.sent_end && slot.received_end)
                        }))
                    {
                        queue_frame(&mut state.outbound, PING, 0, 0, &[0; 8]);
                        ping = Some(now);
                    }
                }
                let failed = state.failure.is_some();
                shared.wake.notify_all();
                drop(state);
                let _ = shared.flush(false);
                if failed {
                    // A pooled connection can still have references after the wire is dead.
                    shared.writer.lock().expect("HTTP/2 writer").io.take();
                    return;
                }
            }
        })?;
        Ok(Self { shared })
    }

    pub fn is_open(&self) -> bool {
        self.shared.state.lock().expect("HTTP/2 state").check_goaway().is_ok()
    }

    pub fn open(
        &self,
        method: &str,
        path: &str,
        authority: &str,
        scheme: &str,
        extra: &[(&str, &str)],
        wait: bool,
    ) -> io::Result<H2Stream<W>> {
        self.request(method, path, authority, scheme, extra, method == "GET", wait)
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        authority: &str,
        scheme: &str,
        extra: &[(&str, &str)],
        end: bool,
        wait: bool,
    ) -> io::Result<H2Stream<W>> {
        self.request_with_headers(&header_list(method, path, authority, scheme, extra), end, wait, None)
    }

    pub(crate) fn request_with_headers(
        &self,
        headers: &[(&str, &str)],
        end: bool,
        wait: bool,
        timeout: Option<Duration>,
    ) -> io::Result<H2Stream<W>> {
        let id = self.shared.drive_for(timeout, |state| {
            state.check_goaway()?;
            if state.settings_received {
                state.open(headers, end)
            } else {
                Ok(None)
            }
        })?;
        let stream = H2Stream {
            id,
            shared: Arc::clone(&self.shared),
            grpc: false,
        };
        self.shared.flush(true)?;
        if wait {
            self.shared.drive_for(timeout, |state| state.status(id))?;
        }
        Ok(stream)
    }

    pub fn accept(&self) -> io::Result<H2Stream<W>> {
        let id = self.shared.drive(H2State::accept)?;
        Ok(H2Stream {
            id,
            shared: Arc::clone(&self.shared),
            grpc: false,
        })
    }
}

impl<W: Write + Send + 'static> H2Stream<W> {
    pub(crate) fn mark_grpc(&mut self) {
        self.grpc = true;
    }

    pub(crate) fn cancel(&self) {
        self.shared.state.lock().expect("HTTP/2 state").reset(self.id, CANCEL, true);
        self.shared.wake.notify_all();
        let _ = self.shared.flush(false);
    }

    pub(crate) fn read_for(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        self.shared.read(self.id, buf, Some(timeout))
    }

    pub(crate) fn write_for(&self, buf: &[u8], timeout: Duration) -> io::Result<usize> {
        self.shared.write(self.id, buf, false, Some(timeout))
    }

    pub fn header(&self, name: &str) -> Option<String> {
        let state = self.shared.state.lock().expect("HTTP/2 state");
        let headers = state.stream(self.id).ok()?.headers.as_ref()?;
        if name == "cookie" {
            let mut values = headers.iter().filter(|(key, _)| key == name).map(|(_, value)| value);
            let mut combined = values.next()?.clone();
            for value in values {
                combined.push_str("; ");
                combined.push_str(value);
            }
            return Some(combined);
        }
        header(headers, name).map(str::to_owned)
    }

    pub fn reply(&self) -> io::Result<()> {
        self.shared.reply(self.id, false)
    }

    pub fn reply_end(&self) -> io::Result<()> {
        self.shared.reply(self.id, true)
    }

    pub fn reply_with(&self, status: u16, extra: &[(&str, &str)], end: bool) -> io::Result<()> {
        let status = status.to_string();
        let mut headers = Vec::with_capacity(extra.len() + 1);
        headers.push((":status", status.as_str()));
        headers.extend_from_slice(extra);
        self.shared.reply_with(self.id, &headers, end)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.shared.read(self.id, buf, None)
    }

    pub fn flush(&self) -> io::Result<()> {
        self.shared.flush(true)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.shared.write(self.id, buf, false, None)
    }

    pub fn finish(&self, mut buf: &[u8]) -> io::Result<()> {
        loop {
            let len = self.shared.write(self.id, buf, true, None)?;
            if len == buf.len() {
                break;
            }
            buf = &buf[len..];
        }
        self.shared.flush(true)?;
        self.shared.drive(|state| {
            if state.server { state.check_connection()?; Ok(Some(())) }
            else { state.status(self.id) }
        })
    }
}

impl<W: Write> Drop for H2Stream<W> {
    fn drop(&mut self) {
        self.shared.close(self.id, self.grpc);
    }
}

impl<W: Write + Send + 'static> Read for H2Stream<W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        H2Stream::read(self, buf)
    }
}

impl<W: Write + Send + 'static> Write for H2Stream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        H2Stream::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        H2Stream::flush(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    fn sockets() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
        }
        (client, server)
    }

    fn next_frame(mut read: impl Read) -> (u8, u8, u32, Vec<u8>) {
        let mut head = [0; 9];
        read.read_exact(&mut head).unwrap();
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let id = u32::from_be_bytes(head[5..9].try_into().unwrap());
        let mut bytes = vec![0; len];
        read.read_exact(&mut bytes).unwrap();
        (head[3], head[4], id, bytes)
    }

    #[test]
    fn http2_stream_carries_raw_bytes() {
        let (client, server) = sockets();
        let server = thread::spawn(move || {
            let mut io = HttpIo::accept(server, "/vless", "example.com", "POST").unwrap();
            let mut buf = [0; 4];
            io.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            io.write_all(b"pong").unwrap();
        });
        let mut io = HttpIo::connect(client, "example.com", "/vless", "POST", "http").unwrap();
        io.write_all(b"ping").unwrap();
        let mut buf = [0; 4];
        io.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn two_streams_share_one_connection() {
        let (client, mut server) = sockets();
        let server = thread::spawn(move || {
            let mut preface = [0; 24];
            server.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, HTTP2_PREFACE);
            let conn = H2Conn::serve(server.try_clone().unwrap(), server).unwrap();
            let first = conn.accept().unwrap();
            assert_eq!(first.header(":method").as_deref(), Some("GET"));
            first.reply().unwrap();
            let mut second = conn.accept().unwrap();
            assert_eq!(second.header(":method").as_deref(), Some("POST"));
            let mut body = Vec::new();
            second.read_to_end(&mut body).unwrap();
            assert_eq!(&body, b"ping");
            second.reply_end().unwrap();
            first.write(b"pong").unwrap();
        });
        let conn = H2Conn::connect(client.try_clone().unwrap(), client).unwrap();
        let mut down = conn
            .open("GET", "/xh/abc", "example.com", "https", &[], true)
            .unwrap();
        let up = conn
            .open("POST", "/xh/abc/0", "example.com", "https", &[], false)
            .unwrap();
        up.finish(b"ping").unwrap();
        let mut got = Vec::new();
        down.read_to_end(&mut got).unwrap();
        assert_eq!(&got, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn packet_waits_for_both_default_windows() {
        let (client, mut peer) = sockets();
        let payload: Vec<u8> = (0..(2 * DEFAULT_WINDOW + 47))
            .map(|i| (i % 251) as u8)
            .collect();
        thread::scope(|scope| {
            let peer = scope.spawn(|| {
                let mut preface = [0; 24];
                peer.read_exact(&mut preface).unwrap();
                assert_eq!(&preface, HTTP2_PREFACE);
                assert_eq!(next_frame(&mut peer).0, SETTINGS);
                assert_eq!(next_frame(&mut peer).0, WINDOW_UPDATE);
                let mut wire = Vec::new();
                queue_frame(&mut wire, SETTINGS, 0, 0, &[]);
                peer.write_all(&wire).unwrap();
                assert_eq!(next_frame(&mut peer), (SETTINGS, ACK, 0, Vec::new()));
                assert_eq!(next_frame(&mut peer).0, HEADERS);

                let mut received = 0;
                for credit in [0, 1] {
                    let end = received + DEFAULT_WINDOW as usize;
                    while received < end {
                        let (kind, flags, id, bytes) = next_frame(&mut peer);
                        assert_eq!((kind, flags, id), (DATA, 0, 1));
                        assert!(received + bytes.len() <= end);
                        assert_eq!(&payload[received..received + bytes.len()], &bytes);
                        received += bytes.len();
                    }
                    wire.clear();
                    queue_frame(
                        &mut wire,
                        WINDOW_UPDATE,
                        0,
                        credit,
                        &DEFAULT_WINDOW.to_be_bytes(),
                    );
                    queue_frame(&mut wire, PING, 0, 0, b"capacity");
                    peer.write_all(&wire).unwrap();
                    assert_eq!(next_frame(&mut peer), (PING, ACK, 0, b"capacity".to_vec()));

                    wire.clear();
                    queue_frame(
                        &mut wire,
                        WINDOW_UPDATE,
                        0,
                        1 - credit,
                        &DEFAULT_WINDOW.to_be_bytes(),
                    );
                    peer.write_all(&wire).unwrap();
                }
                let (kind, flags, id, bytes) = next_frame(&mut peer);
                assert_eq!((kind, flags, id), (DATA, END_STREAM, 1));
                assert_eq!(&bytes, &payload[received..]);

                wire.clear();
                send_headers(&mut wire, 1, &[(":status", "200")], true).unwrap();
                peer.write_all(&wire).unwrap();
            });
            let conn = H2Conn::connect(client.try_clone().unwrap(), client).unwrap();
            let up = conn
                .open("POST", "/packet/0", "example.com", "https", &[], false)
                .unwrap();
            up.finish(&payload).unwrap();
            peer.join().unwrap();
        });
    }

    #[test]
    fn consumed_data_and_discarded_padding_restore_window_credit() {
        let mut state = H2State::new(true, true, 1);
        state.receive_window.available = DEFAULT_WINDOW;
        let mut wire = Vec::new();
        queue_frame(&mut wire, SETTINGS, 0, 0, &[]);
        send_headers(&mut wire, 1, &[(":method", "POST"), (":path", "/")], false).unwrap();
        state.receive(&wire).unwrap();
        assert_eq!(state.accept().unwrap(), Some(1));
        state.streams.get_mut(&1).unwrap().receive_window.available = DEFAULT_WINDOW;

        let mut payload = vec![42; FRAME_SIZE];
        payload[0] = 3;
        state.outbound.clear();
        wire.clear();
        queue_frame(&mut wire, DATA, PADDED, 1, &payload);
        state.receive(&wire).unwrap();

        let updates = |wire: &[u8], amount: u32| {
            let mut wire = wire;
            for id in [0, 1] {
                assert_eq!(
                    next_frame(&mut wire),
                    (WINDOW_UPDATE, 0, id, amount.to_be_bytes().to_vec())
                );
            }
            assert!(wire.is_empty());
        };
        updates(&state.outbound, 4);
        state.outbound.clear();
        let mut data = vec![0; FRAME_SIZE - 4];
        assert_eq!(state.read_data(1, &mut data).unwrap(), Some(data.len()));
        assert_eq!(&data, &payload[1..FRAME_SIZE - 3]);
        updates(&state.outbound, data.len() as u32);
    }

    #[test]
    fn settings_shrink_preserves_negative_stream_credit() {
        let mut state = H2State::new(false, true, 1);
        state.frame(SETTINGS, 0, 0, &[]).unwrap();
        let id = state.open(&[(":method", "POST")], false).unwrap().unwrap();
        let data = vec![42; FRAME_SIZE];
        assert_eq!(
            state.write_data(id, &data, false).unwrap(),
            Some(FRAME_SIZE)
        );

        let mut settings = Vec::new();
        setting(&mut settings, 4, 1024);
        state.frame(SETTINGS, 0, 0, &settings).unwrap();
        assert_eq!(state.write_data(id, b"next", false).unwrap(), None);
        state
            .window_update(id, FRAME_SIZE as u32 - 1024 + 2)
            .unwrap();
        assert_eq!(state.write_data(id, b"next", false).unwrap(), Some(2));
        assert_eq!(state.write_data(id, b"xt", false).unwrap(), None);

        state
            .frame(RST_STREAM, 0, id, &CANCEL.to_be_bytes())
            .unwrap();
        assert_eq!(
            state.write_data(id, b"xt", false).unwrap_err().kind(),
            ErrorKind::ConnectionReset
        );
    }

    #[test]
    fn buffered_response_survives_a_control_write_failure() {
        struct ClosedWriter;

        impl Write for ClosedWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut state = H2State::new(false, true, 1);
        let id = state.open(&[(":method", "POST")], false).unwrap().unwrap();
        state.outbound.clear();
        let mut wire = Vec::new();
        queue_frame(&mut wire, SETTINGS, 0, 0, &[]);
        send_headers(&mut wire, id, &[(":status", "200")], false).unwrap();
        queue_frame(&mut wire, DATA, END_STREAM, id, b"pong");
        let stream = SharedHttp {
            shared: SharedConnection::new(wire.as_slice(), ClosedWriter, state),
            id,
        };
        let mut buf = [0; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf, b"pong");
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn continuation_keeps_padding_and_dynamic_headers_in_order() {
        let mut state = H2State::new(true, true, 2);
        let mut encoder = hpack::Encoder::new();
        let encoded = encoder.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (b":path".as_slice(), b"/one".as_slice()),
            (b"x-entry".as_slice(), b"remember me".as_slice()),
        ]);
        let mut fragment = vec![2, 0, 0, 0, 0, 0];
        fragment.extend_from_slice(&encoded[..3]);
        fragment.extend_from_slice(&[0, 0]);
        let mut wire = Vec::new();
        queue_frame(&mut wire, SETTINGS, 0, 0, &[]);
        queue_frame(
            &mut wire,
            HEADERS,
            PADDED | HAS_PRIORITY | END_STREAM,
            1,
            &fragment,
        );
        queue_frame(&mut wire, CONTINUATION, END_HEADERS, 1, &encoded[3..]);
        let encoded = encoder.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (b":path".as_slice(), b"/two".as_slice()),
            (b"x-entry".as_slice(), b"remember me".as_slice()),
        ]);
        queue_frame(&mut wire, HEADERS, END_HEADERS, 3, &encoded);
        for chunk in wire.chunks(5) {
            state.receive(chunk).unwrap();
        }
        assert_eq!(state.accept().unwrap(), Some(1));
        assert_eq!(state.read_data(1, &mut [0]).unwrap(), Some(0));
        assert_eq!(state.accept().unwrap(), Some(3));
        let headers = state.stream(3).unwrap().headers.as_ref().unwrap();
        assert_eq!(header(headers, ":path"), Some("/two"));
        assert_eq!(header(headers, "x-entry"), Some("remember me"));
    }

    #[test]
    fn rejects_malformed_padding_and_hpack_table_update() {
        for (kind, flags, bytes) in [
            (DATA, PADDED, [2, 0].as_slice()),
            (HEADERS, PADDED | END_HEADERS, [].as_slice()),
            (HEADERS, END_HEADERS, [0x3f].as_slice()),
        ] {
            let mut state = H2State::new(true, true, 1);
            state.frame(SETTINGS, 0, 0, &[]).unwrap();
            let mut wire = Vec::new();
            send_headers(&mut wire, 1, &[(":method", "POST"), (":path", "/")], false).unwrap();
            state.receive(&wire).unwrap();
            assert_eq!(state.accept().unwrap(), Some(1));
            state.outbound.clear();
            wire.clear();
            queue_frame(&mut wire, kind, flags, 1, bytes);
            let error = state.read_result(Ok(wire.len()), &wire).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert_eq!(next_frame(&state.outbound[..]).0, GOAWAY);
        }
    }
}
