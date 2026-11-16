//! HTTP/2 transport for VLESS HTTP, gRPC, and XHTTP.

use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
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

const SETTINGS_NO_RFC7540_PRIORITIES: u16 = 9;

const PROTOCOL_ERROR: u32 = 1;
const FLOW_CONTROL_ERROR: u32 = 3;
const STREAM_CLOSED: u32 = 5;
const REFUSED_STREAM: u32 = 7;
const CANCEL: u32 = 8;

const DEFAULT_WINDOW: u32 = 65_535;
const MAX_WINDOW: u32 = 0x7fff_ffff;
const RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const FRAME_SIZE: usize = 16_384;
/// The DATA one write call frames at most, on a wire that takes it quickly. A write the size of
/// a gRPC message then leaves in one flush. A slow wire gets less, see `H2State::write_budget`.
const WRITE_BATCH: usize = 8 * FRAME_SIZE;
/// What one read from the wire takes at most: several frames reach their streams under one lock.
const READ_BUFFER: usize = 4 * FRAME_SIZE;
/// How long a write holds out for a good part of the window it needs before it takes whatever
/// the peer returned.
const WINDOW_GRACE: Duration = Duration::from_millis(1);

/// The two sides of a stream that can wait: its reader and its writer.
const READER: u8 = 1;
const WRITER: u8 = 2;

/// Where a stream's reader and its writer wait.
type StreamWake = Arc<[Condvar; 2]>;
/// The stream sides to wake once the state is released.
type Wakers = Vec<(StreamWake, u8)>;
const HEADER_LIMIT: usize = 64 * 1024;
const HEADER_TABLE_SIZE: usize = 4096;
const STREAM_LIMIT: usize = 128;

type Headers = Vec<(String, String)>;

/// Server-side HTTP/2 limits. The defaults are what gRPC, HTTP and XHTTP serve without `h2Params`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H2Limits {
    pub streams: u32,
    pub frame_size: u32,
    pub decoder_table: u32,
    pub stream_window: u32,
    pub connection_window: u32,
    pub header_list: Option<u32>,
    pub xhttp_server_settings: bool,
    pub ping_after: Option<Duration>,
    pub ping_timeout: Duration,
    pub write_timeout: Option<Duration>,
}

impl Default for H2Limits {
    fn default() -> Self {
        Self {
            streams: STREAM_LIMIT as u32,
            frame_size: FRAME_SIZE as u32,
            decoder_table: HEADER_TABLE_SIZE as u32,
            stream_window: RECEIVE_WINDOW,
            connection_window: RECEIVE_WINDOW,
            header_list: None,
            xhttp_server_settings: false,
            ping_after: None,
            ping_timeout: Duration::from_secs(15),
            write_timeout: None,
        }
    }
}

pub fn goaway_frame(code: u32, debug: &str) -> Vec<u8> {
    let mut payload = vec![0; 4];
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(debug.as_bytes());
    let mut frame = Vec::new();
    queue_frame(&mut frame, GOAWAY, 0, 0, &payload);
    frame
}

pub const INADEQUATE_SECURITY: u32 = 12;

struct ReceiveWindow {
    available: u32,
    consumed: u32,
    limit: u32,
}

impl ReceiveWindow {
    fn new(available: u32) -> Self {
        Self {
            available,
            consumed: 0,
            limit: available,
        }
    }

    fn receive(&mut self, len: u32) -> bool {
        let Some(available) = self.available.checked_sub(len) else {
            return false;
        };
        self.available = available;
        true
    }

    /// The peer gets its window back once a quarter of it was consumed, as grpc-go does, or at
    /// once when little of it is left.
    fn release(&mut self, len: u32) -> Option<u32> {
        self.consumed += len;
        if self.consumed == 0
            || (self.consumed < self.limit / 4 && self.available >= DEFAULT_WINDOW)
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
    /// Where this stream's reader and writer wait, and how many threads wait on each side.
    wake: StreamWake,
    waiting: [u32; 2],
    /// The sides queued for a wake-up since the last time the waiters were collected.
    due: u8,
    /// A write waits for send window: how much it holds out for, since when, and whether it
    /// takes whatever comes by now. `queued` is set while the stream is listed in `starving`.
    starved: bool,
    wanted: usize,
    starved_at: Option<Instant>,
    eager: bool,
    queued: bool,
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
            wake: Arc::new([Condvar::new(), Condvar::new()]),
            waiting: [0; 2],
            due: 0,
            starved: false,
            wanted: 0,
            starved_at: None,
            eager: false,
            queued: false,
        }
    }

    /// The sides a thread waits on.
    fn waiting_sides(&self) -> u8 {
        let mut sides = 0;
        if self.waiting[0] != 0 {
            sides |= READER;
        }
        if self.waiting[1] != 0 {
            sides |= WRITER;
        }
        sides
    }

    /// How long a writer that holds out for window waits before it looks again.
    fn patience(&self) -> Option<Duration> {
        if self.eager {
            return None;
        }
        self.starved_at.map(|since| WINDOW_GRACE.saturating_sub(since.elapsed()))
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
    limits: H2Limits,
    last_frame: Instant,
    ping: Option<(Instant, [u8; 8])>,
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
    /// Streams whose waiters must look again. Only streams with a waiter are listed.
    touched: Vec<u32>,
    /// Waiters that are not tied to one stream must look again: a new request, a freed stream.
    wake_connection: bool,
    /// Every waiter must look again.
    wake_all: bool,
    connection_waiting: u32,
    /// One thread at a time writes the queue to the wire. `taken` counts the bytes it took from
    /// the queue so far and `flushed` the bytes the wire accepted; both only grow, so a writer
    /// knows its bytes left once `flushed` reaches where they ended.
    flushing: bool,
    taken: u64,
    flushed: u64,
    flush_waiters: u32,
    /// How long the wire took for 1024 bytes lately, in nanoseconds; zero before the first
    /// measure. The time per byte is averaged, not the rate, so that one slow write counts at
    /// once and the budget of a wire that slowed down shrinks within a write or two.
    wire_pace: u64,
    /// A reader thread and a writer thread serve this connection. A stream that writes sends
    /// what is queued itself when the wire is free and leaves the queue to the writer thread
    /// otherwise; a stream that reads, and the reader thread, never write to the wire. A writer
    /// may also wait with a deadline for send window instead of taking every bit of it at once.
    threaded: bool,
    /// Streams whose writer waits for send window, in the order they ran out.
    starving: VecDeque<u32>,
}

/// Queues a wake-up for the given sides of `slot`, as far as a thread waits there.
fn touch(slot: &mut Stream, touched: &mut Vec<u32>, id: u32, sides: u8) {
    let sides = sides & slot.waiting_sides() & !slot.due;
    if sides != 0 {
        if slot.due == 0 {
            touched.push(id);
        }
        slot.due |= sides;
    }
}

impl H2State {
    fn new(server: bool, preface: bool, stream_limit: usize) -> Self {
        Self::with_limits(server, preface, H2Limits { streams: stream_limit as u32, ..H2Limits::default() })
    }

    fn with_limits(server: bool, preface: bool, limits: H2Limits) -> Self {
        let mut outbound = Vec::new();
        if !server {
            outbound.extend_from_slice(HTTP2_PREFACE);
        }
        let mut settings = Vec::new();
        if server && limits.xhttp_server_settings {
            setting(&mut settings, 5, limits.frame_size);
            setting(&mut settings, 3, limits.streams);
            if let Some(limit) = limits.header_list {
                setting(&mut settings, 6, limit);
            }
            setting(&mut settings, 1, limits.decoder_table);
            setting(&mut settings, 4, limits.stream_window);
        } else {
            if !server {
                setting(&mut settings, 2, 0);
            } else {
                setting(&mut settings, 3, limits.streams);
            }
            setting(&mut settings, 4, limits.stream_window);
            if let Some(limit) = limits.header_list {
                setting(&mut settings, 6, limit);
            }
            if limits.frame_size != FRAME_SIZE as u32 {
                setting(&mut settings, 5, limits.frame_size);
            }
            if limits.decoder_table != HEADER_TABLE_SIZE as u32 {
                setting(&mut settings, 1, limits.decoder_table);
            }
        }
        if server {
            setting(&mut settings, SETTINGS_NO_RFC7540_PRIORITIES, 1);
        }
        queue_frame(&mut outbound, SETTINGS, 0, 0, &settings);
        if limits.connection_window > DEFAULT_WINDOW {
            queue_frame(
                &mut outbound,
                WINDOW_UPDATE,
                0,
                0,
                &(limits.connection_window - DEFAULT_WINDOW).to_be_bytes(),
            );
        }
        let mut decoder = hpack::Decoder::new();
        decoder.set_max_table_size(limits.decoder_table as usize);
        Self {
            server,
            preface,
            settings_received: false,
            peer_goaway: None,
            next: 1,
            last_peer: 0,
            limits,
            last_frame: Instant::now(),
            ping: None,
            peer_stream_limit: usize::MAX,
            initial_send_window: i64::from(DEFAULT_WINDOW),
            initial_receive_window: limits.stream_window,
            send_window: i64::from(DEFAULT_WINDOW),
            receive_window: ReceiveWindow::new(limits.connection_window),
            streams: HashMap::new(),
            accepted: VecDeque::new(),
            inbound: Vec::new(),
            outbound,
            header_limit: limits.header_list.map_or(HEADER_LIMIT, |limit| limit as usize),
            peer_header_limit: HEADER_LIMIT,
            header_block: None,
            decoder,
            failure: None,
            reading: false,
            touched: Vec::new(),
            wake_connection: false,
            wake_all: false,
            connection_waiting: 0,
            flushing: false,
            taken: 0,
            flushed: 0,
            flush_waiters: 0,
            wire_pace: 0,
            threaded: false,
            starving: VecDeque::new(),
        }
    }

    /// Hands the connection's send window to the streams that wait for it, in the order they ran
    /// out and as far as it goes, so one update does not wake them all.
    fn feed_starving(&mut self) {
        let mut budget = self.send_window;
        let mut index = 0;
        while index < self.starving.len() {
            let id = self.starving[index];
            let Some(slot) = self.streams.get_mut(&id).filter(|slot| slot.starved && slot.waiting[1] != 0) else {
                if let Some(slot) = self.streams.get_mut(&id) {
                    slot.queued = false;
                }
                self.starving.remove(index);
                continue;
            };
            let wanted = slot.wanted as i64;
            if slot.send_window < wanted {
                // Its own window holds this one back; the next may still go.
                index += 1;
            } else if budget >= wanted {
                budget -= wanted;
                slot.queued = false;
                touch(slot, &mut self.touched, id, WRITER);
                self.starving.remove(index);
            } else {
                break;
            }
        }
    }

    /// Takes note of how long the wire needed for `bytes`.
    fn note_write(&mut self, bytes: usize, elapsed: Duration) {
        if bytes < 4096 {
            // A small write says little about the wire.
            return;
        }
        let sample = (elapsed.as_nanos() * 1024 / bytes as u128).clamp(1, u64::MAX as u128 / 4) as u64;
        self.wire_pace = if self.wire_pace == 0 {
            sample
        } else {
            (self.wire_pace / 4).saturating_mul(3).saturating_add(sample / 4).max(1)
        };
    }

    /// How much data one write frames, and how much may wait for the wire before a stream holds
    /// back: what the wire takes in about a sixteenth of a second, between one frame and
    /// `WRITE_BATCH`, and one frame until the wire was measured. Streams that share a slow wire
    /// then wait for each other's frames, not for each other's megabytes.
    fn write_budget(&self) -> usize {
        match self.wire_pace {
            0 => FRAME_SIZE,
            pace => usize::try_from(62_500_000u64 * 1024 / pace).unwrap_or(WRITE_BATCH).clamp(FRAME_SIZE, WRITE_BATCH),
        }
    }

    /// Where the bytes queued so far end, counted from the first byte ever queued.
    fn queued_end(&self) -> u64 {
        self.taken + self.outbound.len() as u64
    }

    fn has_wakeups(&self) -> bool {
        self.wake_all || self.wake_connection || !self.touched.is_empty()
    }

    /// Moves the queued wake-ups to `streams`. Returns whether the connection's own waiters are due.
    fn take_wakeups(&mut self, streams: &mut Wakers) -> bool {
        let all = std::mem::take(&mut self.wake_all);
        let connection = std::mem::take(&mut self.wake_connection) || all;
        if all {
            self.touched.clear();
            for slot in self.streams.values_mut() {
                slot.due = 0;
                let sides = slot.waiting_sides();
                if sides != 0 {
                    streams.push((Arc::clone(&slot.wake), sides));
                }
            }
        } else {
            for id in self.touched.drain(..) {
                if let Some(slot) = self.streams.get_mut(&id) {
                    streams.push((Arc::clone(&slot.wake), std::mem::take(&mut slot.due)));
                }
            }
        }
        connection && self.connection_waiting != 0
    }

    /// Go's server pings after `SendPingTimeout` without a received frame and closes after `PingTimeout` without the ACK.
    fn tick(&mut self, now: Instant) -> bool {
        let Some(after) = self.limits.ping_after else {
            return false;
        };
        if self.failure.is_some() {
            return false;
        }
        match self.ping {
            Some((sent, _)) if now.saturating_duration_since(sent) >= self.limits.ping_timeout => {
                self.fail(&io::Error::new(ErrorKind::ConnectionReset, "HTTP/2 ping timeout"));
                true
            }
            None if now.saturating_duration_since(self.last_frame) >= after => {
                let data: [u8; 8] = rand::random();
                queue_frame(&mut self.outbound, PING, 0, 0, &data);
                self.ping = Some((now, data));
                false
            }
            _ => false,
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
        self.wake_all = true;
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
        self.write_parts(id, buf, &[], end)
    }

    /// Frames `head` and then `body` as the stream's data, as far as the send window goes. The
    /// two are framed as one run of bytes, so a caller's prefix needs no buffer of its own.
    fn write_parts(&mut self, id: u32, head: &[u8], body: &[u8], end: bool) -> io::Result<Option<usize>> {
        let Some((len, last)) = self.reserve(id, head.len() + body.len(), end)? else {
            return Ok(None);
        };
        frame_data(&mut self.outbound, id, head, body, len, last);
        Ok(Some(len))
    }

    /// Takes send window for `total` bytes of the stream's data. Returns how many of them may
    /// go now and whether they end the stream; the caller frames exactly those.
    fn reserve(&mut self, id: u32, total: usize, end: bool) -> io::Result<Option<(usize, bool)>> {
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
        if !self.settings_received && total != 0 {
            return Ok(None);
        }
        let window = self.send_window.min(slot.send_window).max(0) as usize;
        let want = total.min(self.write_budget());
        if want != 0 {
            // Streams that share a small window would wake for every bit the peer returns. A
            // writer holds out for a good part of what it has to send, and takes whatever there
            // is once that did not come in time. Every peer returns at least half its window.
            let half = (self.initial_send_window.min(i64::from(DEFAULT_WINDOW)) / 2).max(1) as usize;
            let patient = self.threaded;
            let slot = self.streams.get_mut(&id).expect("open stream");
            if slot.starved_at.is_some_and(|since| since.elapsed() >= WINDOW_GRACE) {
                slot.eager = true;
            }
            let enough = if patient && !slot.eager { want.min(half) } else { 1 };
            if window < enough {
                slot.starved = true;
                slot.wanted = enough;
                if patient {
                    slot.starved_at.get_or_insert_with(Instant::now);
                }
                if !slot.queued {
                    slot.queued = true;
                    self.starving.push_back(id);
                }
                return Ok(None);
            }
        }
        let len = want.min(window);
        let end = end && len == total;
        let slot = self.streams.get_mut(&id).expect("open stream");
        slot.starved = false;
        slot.eager = false;
        slot.starved_at = None;
        slot.send_window -= len as i64;
        slot.sent_end = end;
        self.send_window -= len as i64;
        self.wake_connection |= end;
        Ok(Some((len, end)))
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
            touch(slot, &mut self.touched, id, READER | WRITER);
            self.wake_connection = true;
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
        // A request that waited for a free stream can go on.
        self.wake_connection = true;
        if slot.queued {
            self.starving.retain(|queued| *queued != id);
        }
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

    /// Takes bytes from the wire. Frames are parsed where they were read; only a frame that is
    /// split across reads is put together in `inbound`.
    fn receive(&mut self, mut bytes: &[u8]) -> io::Result<bool> {
        if self.limits.ping_after.is_some() {
            self.last_frame = Instant::now();
        }
        if !self.preface {
            let take = (HTTP2_PREFACE.len() - self.inbound.len()).min(bytes.len());
            self.inbound.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.inbound.len() < HTTP2_PREFACE.len() {
                return Ok(false);
            }
            if self.inbound != HTTP2_PREFACE {
                return Err(protocol_error("HTTP/2 preface"));
            }
            self.inbound.clear();
            self.preface = true;
        }
        let mut frames = false;
        loop {
            let split = !self.inbound.is_empty();
            if split && self.inbound.len() < 9 {
                let take = (9 - self.inbound.len()).min(bytes.len());
                self.inbound.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
            }
            let head = if split { self.inbound.as_slice() } else { bytes };
            if head.len() < 9 {
                if !split {
                    self.inbound.extend_from_slice(bytes);
                }
                break;
            }
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            if len > self.limits.frame_size as usize {
                return Err(protocol_error("HTTP/2 frame too large"));
            }
            let kind = head[3];
            let flags = head[4];
            let stream = u32::from_be_bytes(head[5..9].try_into().unwrap()) & MAX_WINDOW;
            if split {
                let take = (9 + len - self.inbound.len()).min(bytes.len());
                self.inbound.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if self.inbound.len() < 9 + len {
                    break;
                }
                let mut whole = std::mem::take(&mut self.inbound);
                let result = self.frame(kind, flags, stream, &whole[9..]);
                whole.clear();
                self.inbound = whole;
                result?;
            } else {
                if bytes.len() < 9 + len {
                    self.inbound.extend_from_slice(bytes);
                    break;
                }
                let (whole, rest) = bytes.split_at(9 + len);
                bytes = rest;
                self.frame(kind, flags, stream, &whole[9..])?;
            }
            frames = true;
            if self.outbound.len() > RECEIVE_WINDOW as usize {
                return Err(protocol_error("HTTP/2 output backlog"));
            }
        }
        Ok(frames)
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
                if block.bytes.len() + payload.len() > self.header_limit.saturating_add(self.limits.frame_size as usize) {
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
                        touch(slot, &mut self.touched, stream, WRITER);
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
                } else if self.ping.is_some_and(|(_, data)| data[..] == *payload) {
                    self.ping = None;
                }
                Ok(())
            }
            GOAWAY if stream == 0 && payload.len() >= 8 => {
                let last = u32::from_be_bytes(payload[..4].try_into().unwrap()) & MAX_WINDOW;
                let last = self.peer_goaway.map_or(last, |old| old.min(last));
                self.peer_goaway = Some(last);
                self.wake_all = true;
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
        touch(slot, &mut self.touched, id, READER);
        self.wake_connection |= flags & END_STREAM != 0;
        self.release(id, len - bytes.len() as u32);
        Ok(())
    }

    fn headers(&mut self, block: HeaderBlock, flags: u8) -> io::Result<()> {
        if flags & END_HEADERS == 0 {
            self.header_block = Some(block);
            return Ok(());
        }
        let id = block.stream;
        let headers = decode_headers(&mut self.decoder, &block.bytes, self.header_limit, self.limits.decoder_table as usize)?;
        if !self.closed_stream(id) {
            if !self.server || id.is_multiple_of(2) {
                return Err(protocol_error("HTTP/2 HEADERS on invalid stream"));
            }
            self.last_peer = id;
            if self.streams.len() >= self.limits.streams as usize {
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
            self.wake_connection = true;
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
        touch(slot, &mut self.touched, id, READER);
        self.wake_connection |= block.end_stream;
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
        if !payload.len().is_multiple_of(6) {
            return Err(protocol_error("HTTP/2 SETTINGS length"));
        }
        for setting in payload.as_chunks::<6>().0.iter() {
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
        self.wake_all = true;
        queue_frame(&mut self.outbound, SETTINGS, ACK, 0, &[]);
        Ok(())
    }

    fn window_update(&mut self, id: u32, increment: u32) -> io::Result<()> {
        if id == 0 {
            self.send_window += i64::from(increment);
            if increment == 0 || self.send_window > i64::from(MAX_WINDOW) {
                return Err(protocol_error("HTTP/2 invalid connection window update"));
            }
            self.feed_starving();
        } else if !self.closed_stream(id) {
            return Err(protocol_error("HTTP/2 WINDOW_UPDATE on idle stream"));
        } else if let Some(slot) = self.streams.get_mut(&id) {
            if slot.sent_end || slot.reset.is_some() {
                return Ok(());
            }
            slot.send_window += i64::from(increment);
            if slot.starved && self.send_window.min(slot.send_window) >= slot.wanted as i64 {
                touch(slot, &mut self.touched, id, WRITER);
            }
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

pub struct H2Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub authority: &'a str,
    pub scheme: &'a str,
    pub extra: &'a [(&'a str, &'a str)],
}

impl<'a> H2Request<'a> {
    fn header_list(&self) -> Vec<(&'a str, &'a str)> {
        let mut headers = vec![
            (":method", self.method),
            (":scheme", self.scheme),
            (":path", self.path),
            (":authority", self.authority),
        ];
        headers.extend_from_slice(self.extra);
        headers
    }
}

fn setting(settings: &mut Vec<u8>, id: u16, value: u32) {
    settings.extend_from_slice(&id.to_be_bytes());
    settings.extend_from_slice(&value.to_be_bytes());
}

/// Appends the first `len` bytes of `head` followed by `body` to `out` as DATA frames of stream
/// `id`. `last` ends the stream with the final frame.
fn frame_data(out: &mut Vec<u8>, id: u32, head: &[u8], body: &[u8], len: usize, last: bool) {
    if len == 0 {
        queue_frame(out, DATA, if last { END_STREAM } else { 0 }, id, &[]);
    }
    let mut sent = 0;
    while sent < len {
        let frame = (len - sent).min(FRAME_SIZE);
        let flags = if last && sent + frame == len { END_STREAM } else { 0 };
        out.extend_from_slice(&(frame as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&[DATA, flags]);
        out.extend_from_slice(&id.to_be_bytes());
        let from_head = head.len().saturating_sub(sent).min(frame);
        out.extend_from_slice(&head[head.len() - head.len().saturating_sub(sent)..][..from_head]);
        let start = (sent + from_head).saturating_sub(head.len());
        out.extend_from_slice(&body[start..start + frame - from_head]);
        sent += frame;
    }
}

/// How many bytes `frame_data` appends for `len` bytes of data.
fn framed_len(len: usize) -> usize {
    len + 9 * len.div_ceil(FRAME_SIZE).max(1)
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

fn decode_headers(decoder: &mut hpack::Decoder<'_>, bytes: &[u8], limit: usize, table: usize) -> io::Result<Headers> {
    // hpack 0.3 assumes a well-formed table update and does not enforce the advertised limit.
    validate_hpack(bytes, table)?;
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

fn validate_hpack(mut bytes: &[u8], table: usize) -> io::Result<()> {
    let mut fields = false;
    while let Some(&first) = bytes.first() {
        if first & 0xe0 == 0x20 {
            let size = hpack_integer(&mut bytes, 5)?;
            if fields || size > table {
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
    /// What the next read from the wire goes into.
    bytes: Vec<u8>,
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
            bytes: Vec::new(),
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
            .open(&H2Request { method, path, authority, scheme, extra }.header_list(), false)?
            .expect("initial stream");
        let mut io = Self { inner, state, id, bytes: Vec::new() };
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
        loop {
            if let Some(value) = operation(&mut self.state)? {
                return Ok(value);
            }
            self.flush_out()?;
            if self.bytes.is_empty() {
                self.bytes.resize(READ_BUFFER, 0);
            }
            let result = read_retry(&mut self.inner, &mut self.bytes);
            let received = self.state.read_result(result, &self.bytes);
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
    /// The read half and the buffer it reads into, for a connection its own streams drive.
    reader: Option<Mutex<(R, Vec<u8>)>>,
    writer: Mutex<WireWriter<W>>,
    state: Mutex<H2State>,
    /// Where waiters that are not tied to one stream wait. A stream's waiters use its own condvar.
    wake: Condvar,
    /// Where writers wait for the thread that is writing the queue to the wire.
    written: Condvar,
    signal: Arc<WriteSignal>,
    /// A flush stopped on a full wire, so the next one runs even with nothing queued.
    retry_flush: AtomicBool,
    /// Unblocks the receiving half when a configured write deadline ends the connection.
    on_write_timeout: Option<Box<dyn Fn() + Send + Sync>>,
}

struct WireWriter<W> {
    io: Option<W>,
    /// The frames being written. Empty between flushes; it trades places with the queue.
    bytes: Vec<u8>,
}

/// Who sends the frames a stream just queued.
enum Turn {
    /// The stream itself: the wire was free on a connection with a writer thread. The frames
    /// are not queued; the stream writes them, this many bytes of data, behind what is queued.
    Own(usize, bool),
    /// Whoever holds the wire of such a connection. On a wire that falls behind the stream
    /// waits until its bytes, ending here, left: each stream then has one write queued and the
    /// streams take turns in the order they queued.
    Queued(Option<u64>),
    /// The stream that is flushing, which this one waits for until its bytes, ending here, left.
    Wait(u64),
}

/// Tells the writer thread that the queue is its to send. It outlives the connection, so the
/// thread can wait on it without keeping the connection alive.
#[derive(Default)]
struct WriteSignal {
    due: Mutex<bool>,
    wake: Condvar,
}

impl WriteSignal {
    fn notify(&self) {
        *self.due.lock().expect("HTTP/2 writer signal") = true;
        self.wake.notify_one();
    }

    fn wait(&self) {
        let mut due = self.due.lock().expect("HTTP/2 writer signal");
        while !*due {
            due = self.wake.wait(due).expect("HTTP/2 writer signal");
        }
        *due = false;
    }
}

/// What a thread waits for: something about the connection, data or headers of a stream, or room
/// to send on a stream.
#[derive(Clone, Copy)]
enum Waiter {
    Connection,
    Reader(u32),
    Writer(u32),
}

impl<R, W> SharedConnection<R, W> {
    fn new(read: R, write: W, state: H2State) -> Self {
        Self::with_reader(Some(read), write, state)
    }

    fn with_reader(read: Option<R>, write: W, state: H2State) -> Self {
        Self {
            reader: read.map(|read| Mutex::new((read, Vec::new()))),
            writer: Mutex::new(WireWriter {
                io: Some(write),
                bytes: Vec::new(),
            }),
            state: Mutex::new(state),
            wake: Condvar::new(),
            written: Condvar::new(),
            signal: Arc::default(),
            retry_flush: AtomicBool::new(false),
            on_write_timeout: None,
        }
    }

    /// Releases the state and wakes the waiters it queued. `streams` is scratch space.
    fn notify(&self, mut state: MutexGuard<'_, H2State>, streams: &mut Wakers) {
        let connection = state.take_wakeups(streams);
        drop(state);
        for (wake, sides) in streams.drain(..) {
            if sides & READER != 0 {
                wake[0].notify_all();
            }
            if sides & WRITER != 0 {
                wake[1].notify_all();
            }
        }
        if connection {
            self.wake.notify_all();
        }
    }
}

impl<R, W> Drop for SharedConnection<R, W> {
    fn drop(&mut self) {
        // The writer thread wakes, finds the connection gone and ends.
        self.signal.notify();
    }
}

impl<R, W: Write> SharedConnection<R, W> {
    /// Writes the queue to the wire. `wait` returns once everything queued by now has left;
    /// without it the call only makes sure the queue is being written.
    fn flush(&self, wait: bool) -> io::Result<()> {
        let mut state = self.state.lock().expect("HTTP/2 state");
        let until = wait.then(|| state.queued_end());
        if !state.threaded {
            return self.flush_to(state, until);
        }
        if !state.flushing && !state.outbound.is_empty() {
            state.flushing = true;
            self.signal.notify();
        }
        let Some(until) = until else {
            return Ok(());
        };
        while state.flushed < until {
            state.check_connection()?;
            state.flush_waiters += 1;
            state = self.written.wait(state).expect("HTTP/2 state");
            state.flush_waiters -= 1;
        }
        Ok(())
    }

    /// Waits until the queued bytes up to `until` have left through the stream or thread that
    /// holds the wire. After `timeout` the bytes stay queued and the call returns.
    fn wait_written(&self, until: u64, timeout: Option<Duration>) -> io::Result<()> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let mut state = self.state.lock().expect("HTTP/2 state");
        while state.flushed < until {
            state.check_connection()?;
            state.flush_waiters += 1;
            state = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        state.flush_waiters -= 1;
                        return Ok(());
                    }
                    self.written.wait_timeout(state, remaining).expect("HTTP/2 state").0
                }
                None => self.written.wait(state).expect("HTTP/2 state"),
            };
            state.flush_waiters -= 1;
        }
        Ok(())
    }

    /// Sends what is queued and then the caller's own data on the calling thread, which took the
    /// wire while it was free, and leaves whatever is queued meanwhile to the writer thread. The
    /// caller is a stream that writes, so it is never held by more than the queue it found. Its
    /// data is framed straight into the bytes for the wire: `len` bytes of `head` and `body`.
    fn send_batch(&self, id: u32, head: &[u8], body: &[u8], len: usize, last: bool) -> io::Result<()> {
        let mut writer = self.writer.lock().expect("HTTP/2 writer");
        let mut state = self.state.lock().expect("HTTP/2 state");
        let WireWriter { io, bytes } = &mut *writer;
        let mut result = state.check_connection();
        match io {
            Some(io) if result.is_ok() => {
                std::mem::swap(&mut state.outbound, bytes);
                state.taken += (bytes.len() + framed_len(len)) as u64;
                drop(state);
                frame_data(bytes, id, head, body, len, last);
                let (started, queued) = (Instant::now(), bytes.len());
                let sent = flush_bytes(io, bytes);
                state = self.state.lock().expect("HTTP/2 state");
                state.note_write(queued - bytes.len(), started.elapsed());
                state.flushed = state.taken - bytes.len() as u64;
                match sent {
                    Ok(()) => {}
                    // The wire is full: the writer thread goes on with the rest.
                    Err(error) if retryable(&error) && state.limits.write_timeout.is_none() => {}
                    Err(error) => {
                        bytes.clear();
                        state.fail(&error);
                        state.outbound.clear();
                        result = Err(error);
                    }
                }
            }
            Some(_) => {}
            None => result = result.and(Err(io::Error::new(ErrorKind::BrokenPipe, "HTTP/2 writer closed"))),
        }
        if result.is_ok() && (!bytes.is_empty() || !state.outbound.is_empty()) {
            self.signal.notify();
        } else {
            state.flushing = false;
        }
        drop(writer);
        if state.flush_waiters != 0 {
            self.written.notify_all();
        }
        self.notify(state, &mut Vec::new());
        result
    }

    /// The writer thread's turn: sends the queue until it is empty. A full wire is tried again
    /// for as long as a stream holds the connection. Returns whether the wire is still usable.
    fn send_queue(self: &Arc<Self>) -> bool {
        let mut writer = self.writer.lock().expect("HTTP/2 writer");
        let mut state = self.state.lock().expect("HTTP/2 state");
        let alive = loop {
            let WireWriter { io, bytes } = &mut *writer;
            let Some(io) = io else {
                break false;
            };
            if state.failure.is_some() {
                break false;
            }
            if bytes.is_empty() {
                if state.outbound.is_empty() {
                    break true;
                }
                std::mem::swap(&mut state.outbound, bytes);
                state.taken += bytes.len() as u64;
            }
            drop(state);
            let (started, queued) = (Instant::now(), bytes.len());
            let sent = flush_bytes(io, bytes);
            state = self.state.lock().expect("HTTP/2 state");
            state.note_write(queued - bytes.len(), started.elapsed());
            state.flushed = state.taken - bytes.len() as u64;
            match sent {
                Ok(()) => {}
                Err(error) if retryable(&error) && state.limits.write_timeout.is_none() => {
                    if Arc::strong_count(self) == 1 {
                        // Only this thread still holds the connection.
                        break false;
                    }
                    if started.elapsed() < Duration::from_millis(1) {
                        drop(state);
                        std::thread::sleep(Duration::from_millis(1));
                        state = self.state.lock().expect("HTTP/2 state");
                    }
                }
                Err(error) => {
                    bytes.clear();
                    state.fail(&error);
                    state.outbound.clear();
                    break false;
                }
            }
            if state.flush_waiters != 0 {
                self.written.notify_all();
            }
        };
        state.flushing = false;
        drop(writer);
        if state.flush_waiters != 0 {
            self.written.notify_all();
        }
        self.notify(state, &mut Vec::new());
        alive
    }

    /// Returns once the queued bytes up to `until` have left. One thread at a time writes the
    /// queue, in the order the bytes were queued, until it is empty. A writer waits for it until
    /// its own bytes have left, and writes what is still queued when it finds nobody writing,
    /// which is also how a write that gave up on a full wire is taken up again. A caller without
    /// bytes of its own (`None`) writes only while no writer waits, so a reader is never held by
    /// other streams' data.
    fn flush_to<'a>(&'a self, mut state: MutexGuard<'a, H2State>, until: Option<u64>) -> io::Result<()> {
        while state.flushing {
            let Some(until) = until else {
                return Ok(());
            };
            if state.flushed >= until {
                return Ok(());
            }
            state.check_connection()?;
            state.flush_waiters += 1;
            state = self.written.wait(state).expect("HTTP/2 state");
            state.flush_waiters -= 1;
        }
        if state.outbound.is_empty() && !self.retry_flush.load(Ordering::Relaxed) {
            return match until {
                Some(until) if state.flushed < until => state.check_connection(),
                _ => Ok(()),
            };
        }
        state.flushing = true;
        // Only the flushing thread takes the writer, so this never waits for another flush.
        let mut writer = self.writer.lock().expect("HTTP/2 writer");
        let result = loop {
            let WireWriter { io, bytes } = &mut *writer;
            let Some(io) = io else {
                break state
                    .check_connection()
                    .and(Err(io::Error::new(ErrorKind::BrokenPipe, "HTTP/2 writer closed")));
            };
            if state.outbound.is_empty() && !self.retry_flush.load(Ordering::Relaxed) {
                break Ok(());
            }
            if until.is_none() && state.flush_waiters != 0 {
                // A writer waits, and writes what is queued as soon as this call lets go.
                break Ok(());
            }
            std::mem::swap(&mut state.outbound, bytes);
            state.taken += bytes.len() as u64;
            drop(state);
            let (started, queued) = (Instant::now(), bytes.len());
            let result = flush_bytes(io, bytes);
            state = self.state.lock().expect("HTTP/2 state");
            state.note_write(queued - bytes.len(), started.elapsed());
            match result {
                Ok(()) => {
                    self.retry_flush.store(false, Ordering::Relaxed);
                    state.flushed = state.taken;
                    if state.flush_waiters != 0 {
                        self.written.notify_all();
                    }
                }
                Err(error) if retryable(&error) && state.limits.write_timeout.is_none() => {
                    // The wire is full. What it did not take goes back to the front of the queue.
                    self.retry_flush.store(true, Ordering::Relaxed);
                    state.taken -= bytes.len() as u64;
                    state.flushed = state.taken;
                    bytes.append(&mut state.outbound);
                    std::mem::swap(&mut state.outbound, bytes);
                    break Err(error);
                }
                Err(error) => {
                    self.retry_flush.store(false, Ordering::Relaxed);
                    bytes.clear();
                    let error = if retryable(&error) {
                        if let Some(stop) = &self.on_write_timeout { stop(); }
                        io::Error::new(ErrorKind::ConnectionAborted, "HTTP/2 write made no progress before its deadline")
                    } else {
                        error
                    };
                    state.fail(&error);
                    state.outbound.clear();
                    break Err(error);
                }
            }
        };
        // The writer is released while the state is held, so a frame queued from now on finds
        // nobody flushing and gets a flush of its own.
        drop(writer);
        state.flushing = false;
        if state.flush_waiters != 0 {
            self.written.notify_all();
        }
        self.notify(state, &mut Vec::new());
        result
    }

    fn close(&self, id: u32, grpc: bool) {
        let mut state = self.state.lock().expect("HTTP/2 state");
        state.close(id, grpc);
        self.notify(state, &mut Vec::new());
        let _ = self.flush(false);
    }
}

impl<R: Read, W: Write> SharedConnection<R, W> {
    fn drive<V>(
        &self,
        waiter: Waiter,
        operation: impl FnMut(&mut H2State) -> io::Result<Option<V>>,
    ) -> io::Result<V> {
        self.drive_for(waiter, None, operation)
    }

    fn drive_for<V>(
        &self,
        waiter: Waiter,
        timeout: Option<Duration>,
        mut operation: impl FnMut(&mut H2State) -> io::Result<Option<V>>,
    ) -> io::Result<V> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let mut wakers = Vec::new();
        let mut state = self.state.lock().expect("HTTP/2 state");
        loop {
            if let Some(value) = operation(&mut state)? {
                if state.has_wakeups() {
                    self.notify(state, &mut wakers);
                }
                return Ok(value);
            }
            let Some(reader) = self.reader.as_ref().filter(|_| !state.reading) else {
                // The reader thread, or the stream that is reading, wakes this one.
                let remaining = match deadline {
                    Some(deadline) => {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(io::Error::new(ErrorKind::TimedOut, "HTTP/2 stream I/O"));
                        }
                        Some(remaining)
                    }
                    None => None,
                };
                let side = match waiter {
                    Waiter::Reader(id) => Some((id, 0)),
                    Waiter::Writer(id) => Some((id, 1)),
                    Waiter::Connection => None,
                };
                let patience = match waiter {
                    Waiter::Writer(id) => state.streams.get(&id).and_then(Stream::patience),
                    _ => None,
                };
                let remaining = match (remaining, patience) {
                    (Some(remaining), Some(patience)) => Some(remaining.min(patience)),
                    (remaining, patience) => remaining.or(patience),
                };
                let own = side.and_then(|(id, side)| {
                    let slot = state.streams.get_mut(&id)?;
                    slot.waiting[side] += 1;
                    Some((id, side, Arc::clone(&slot.wake)))
                });
                if own.is_none() {
                    state.connection_waiting += 1;
                }
                let condvar = own.as_ref().map_or(&self.wake, |(_, side, wake)| &wake[*side]);
                state = match remaining {
                    Some(remaining) => condvar.wait_timeout(state, remaining).expect("HTTP/2 state").0,
                    None => condvar.wait(state).expect("HTTP/2 state"),
                };
                match own {
                    Some((id, side, _)) => {
                        if let Some(slot) = state.streams.get_mut(&id) {
                            slot.waiting[side] -= 1;
                        }
                    }
                    None => state.connection_waiting -= 1,
                }
                continue;
            };
            // Any waiting direction may read control frames. Socket reads never hold the state or writer lock.
            let now = Instant::now();
            if state.tick(now) {
                self.notify(state, &mut wakers);
                state = self.state.lock().expect("HTTP/2 state");
                continue;
            }
            state.reading = true;
            let pinging = state.ping.is_some_and(|(sent, _)| sent == now);
            drop(state);
            if pinging {
                let _ = self.flush(false);
            }
            let mut reader = reader.lock().expect("HTTP/2 reader");
            let (io, bytes) = &mut *reader;
            if bytes.is_empty() {
                bytes.resize(READ_BUFFER, 0);
            }
            let received = read_retry(io, bytes);
            state = self.state.lock().expect("HTTP/2 state");
            state.reading = false;
            let received = state.read_result(received, bytes);
            drop(reader);
            // Whoever waits may have to take over the reading.
            state.wake_all = true;
            let unsent = !state.outbound.is_empty();
            self.notify(state, &mut wakers);
            if unsent {
                let _ = self.flush(false);
            }
            received?;
            state = self.state.lock().expect("HTTP/2 state");
        }
    }

    fn read(&self, id: u32, buf: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.retry_flush.load(Ordering::Relaxed) {
            let _ = self.flush(false);
        }
        let (len, unsent) = self.drive_for(Waiter::Reader(id), timeout, |state| {
            Ok(state.read_data(id, buf)?.map(|len| (len, !state.outbound.is_empty())))
        })?;
        // Reading returns flow-control window to the peer now and then.
        if unsent {
            let _ = self.flush(false);
        }
        Ok(len)
    }

    fn write(&self, id: u32, buf: &[u8], end: bool, timeout: Option<Duration>) -> io::Result<usize> {
        self.write_parts(id, buf, &[], end, timeout)
    }

    fn write_parts(&self, id: u32, head: &[u8], body: &[u8], end: bool, timeout: Option<Duration>) -> io::Result<usize> {
        if head.is_empty() && body.is_empty() && !end {
            return Ok(0);
        }
        if self.retry_flush.load(Ordering::Relaxed) {
            self.flush(true)?;
        }
        let (len, turn) = self.drive_for(Waiter::Writer(id), timeout, |state| {
            if state.threaded && state.outbound.len() > 4 * state.write_budget() {
                // Writes that ran into their deadline left this much queued: nothing is added.
                return Err(io::Error::new(ErrorKind::WouldBlock, "HTTP/2 wire is behind"));
            }
            let Some((len, last)) = state.reserve(id, head.len() + body.len(), end)? else {
                return Ok(None);
            };
            if state.threaded && !state.flushing {
                state.flushing = true;
                return Ok(Some((len, Turn::Own(len, last))));
            }
            frame_data(&mut state.outbound, id, head, body, len, last);
            let turn = if !state.threaded {
                Turn::Wait(state.queued_end())
            } else {
                let behind = state.outbound.len() > state.write_budget();
                Turn::Queued(behind.then(|| state.queued_end()))
            };
            Ok(Some((len, turn)))
        })?;
        let result = match turn {
            Turn::Own(len, last) => self.send_batch(id, head, body, len, last),
            // The stream or thread that holds the wire sends this too.
            Turn::Queued(None) => Ok(()),
            Turn::Queued(Some(end)) => self.wait_written(end, timeout),
            // The call returns once its frames have left, whoever wrote them.
            Turn::Wait(end) => self.flush_to(self.state.lock().expect("HTTP/2 state"), Some(end)),
        };
        match result {
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
                read(&mut reader.0);
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
        let stream = self.request(&H2Request { method, path, authority, scheme, extra }, end, false)?;
        self.shared.state.lock().expect("HTTP/2 state").streams.get_mut(&stream.id).expect("open stream").any_status = true;
        self.shared.drive(Waiter::Reader(stream.id), |state| state.status(stream.id))?;
        Ok(stream)
    }

    pub fn wait_closed(&self) -> io::Result<()> {
        self.shared.drive(Waiter::Connection, |state| {
            if state.peer_goaway.is_some() { return Ok(Some(())); }
            state.check_connection()?;
            Ok(None)
        })
    }

    pub fn serve<R: Read + Send + 'static>(read: R, write: W) -> io::Result<Self> {
        Self::start(read, write, true, H2Limits::default())
    }

    pub fn serve_with_limits<R: Read + Send + 'static>(
        read: R, write: W, limits: H2Limits, on_write_timeout: impl Fn() + Send + Sync + 'static,
    ) -> io::Result<Self> {
        Self::start_with_timeout(read, write, true, limits, Some(Box::new(on_write_timeout)))
    }

    pub fn connect<R: Read + Send + 'static>(read: R, write: W) -> io::Result<Self> {
        Self::start(read, write, false, H2Limits::default())
    }

    pub fn connect_with_keepalive<R: Read + Send + 'static>(read: R, write: W, seconds: i64) -> io::Result<Self> {
        let interval = match seconds { 0 => 45, n if n > 0 => n as u64, _ => 0 };
        Self::start_grpc(read, write, false, None, (interval != 0).then(|| H2Keepalive {
            interval: Duration::from_secs(interval), timeout: Duration::from_secs(15), without_stream: true,
        }))
    }

    fn start<R: Read + Send + 'static>(read: R, write: W, server: bool, limits: H2Limits) -> io::Result<Self> {
        Self::start_with_timeout(read, write, server, limits, None)
    }

    fn start_with_timeout<R: Read + Send + 'static>(
        read: R, write: W, server: bool, limits: H2Limits, on_write_timeout: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> io::Result<Self> {
        let read: Box<dyn Read + Send> = Box::new(read);
        let mut connection = SharedConnection::new(
            read,
            write,
            H2State::with_limits(server, true, limits),
        );
        connection.on_write_timeout = on_write_timeout;
        let shared = Arc::new(connection);
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
        let state = H2State::with_limits(server, !server, receive_window.map_or_else(H2Limits::default, |window| H2Limits {
            // An explicit gRPC stream window disables automatic connection-window expansion.
            stream_window: window,
            connection_window: DEFAULT_WINDOW,
            ..H2Limits::default()
        }));
        let shared: Arc<Multiplexed<W>> = Arc::new(SharedConnection::with_reader(None, write, state));
        shared.flush(true)?;
        // From here on the two threads below serve the connection.
        shared.state.lock().expect("HTTP/2 state").threaded = true;
        let connection = Arc::downgrade(&shared);
        std::thread::Builder::new().spawn(move || {
            let mut bytes = vec![0; READ_BUFFER];
            let mut wakers = Vec::new();
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
                let unsent = !state.outbound.is_empty();
                // Only the streams these frames were for wake up.
                shared.notify(state, &mut wakers);
                if unsent || shared.retry_flush.load(Ordering::Relaxed) {
                    let _ = shared.flush(false);
                }
                if failed {
                    // A pooled connection can still have references after the wire is dead.
                    shared.writer.lock().expect("HTTP/2 writer").io.take();
                    shared.signal.notify();
                    return;
                }
            }
        })?;
        let (connection, signal) = (Arc::downgrade(&shared), Arc::clone(&shared.signal));
        std::thread::Builder::new().spawn(move || loop {
            signal.wait();
            let Some(shared) = connection.upgrade() else { return };
            if !shared.send_queue() {
                return;
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
        self.request(&H2Request { method, path, authority, scheme, extra }, method == "GET", wait)
    }

    pub fn request(&self, request: &H2Request<'_>, end: bool, wait: bool) -> io::Result<H2Stream<W>> {
        self.request_with_headers(&request.header_list(), end, wait, None)
    }

    /// Like `request`, but a peer at its concurrent-stream limit gives `None` at once instead of a wait.
    pub fn try_request(&self, request: &H2Request<'_>, end: bool, wait: bool) -> io::Result<Option<H2Stream<W>>> {
        let headers = request.header_list();
        let opened = self.shared.drive(Waiter::Connection, |state| {
            state.check_goaway()?;
            if !state.settings_received {
                return Ok(None);
            }
            state.open(&headers, end).map(Some)
        })?;
        let Some(id) = opened else {
            return Ok(None);
        };
        let stream = H2Stream {
            id,
            shared: Arc::clone(&self.shared),
            grpc: false,
        };
        self.shared.flush(true)?;
        if wait {
            self.shared.drive(Waiter::Reader(id), |state| state.status(id))?;
        }
        Ok(Some(stream))
    }

    pub(crate) fn request_with_headers(
        &self,
        headers: &[(&str, &str)],
        end: bool,
        wait: bool,
        timeout: Option<Duration>,
    ) -> io::Result<H2Stream<W>> {
        let id = self.shared.drive_for(Waiter::Connection, timeout, |state| {
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
            self.shared.drive_for(Waiter::Reader(id), timeout, |state| state.status(id))?;
        }
        Ok(stream)
    }

    pub fn accept(&self) -> io::Result<H2Stream<W>> {
        let id = self.shared.drive(Waiter::Connection, H2State::accept)?;
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
        let mut state = self.shared.state.lock().expect("HTTP/2 state");
        state.reset(self.id, CANCEL, true);
        self.shared.notify(state, &mut Vec::new());
        let _ = self.shared.flush(false);
    }

    pub(crate) fn read_for(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        self.shared.read(self.id, buf, Some(timeout))
    }

    /// Writes `head` and then `body` as one run of bytes; returns how many of them were taken.
    pub(crate) fn write_parts_for(&self, head: &[u8], body: &[u8], timeout: Duration) -> io::Result<usize> {
        self.shared.write_parts(self.id, head, body, false, Some(timeout))
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
        self.shared.drive(Waiter::Reader(self.id), |state| {
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

    fn custom_limits() -> H2Limits {
        H2Limits {
            streams: 7,
            frame_size: 32_768,
            decoder_table: 8192,
            stream_window: 524_288,
            connection_window: 2_097_152,
            header_list: Some(8512),
            ..H2Limits::default()
        }
    }

    #[test]
    fn server_limits_set_settings_and_connection_window() {
        let state = H2State::with_limits(true, true, custom_limits());
        let mut wire = &state.outbound[..];
        let (kind, _, id, payload) = next_frame(&mut wire);
        assert_eq!((kind, id), (SETTINGS, 0));
        let mut settings: Vec<_> = payload
            .as_chunks::<6>().0.iter()
            .map(|pair| (u16::from_be_bytes([pair[0], pair[1]]), u32::from_be_bytes(pair[2..].try_into().unwrap())))
            .collect();
        settings.sort_unstable();
        assert_eq!(settings, [(1, 8192), (3, 7), (4, 524_288), (5, 32_768), (6, 8512), (9, 1)]);
        let (kind, _, id, payload) = next_frame(&mut wire);
        assert_eq!((kind, id), (WINDOW_UPDATE, 0));
        assert_eq!(u32::from_be_bytes(payload.try_into().unwrap()), 2_097_152 - DEFAULT_WINDOW);
        assert!(wire.is_empty());
    }

    #[test]
    fn default_server_settings_include_the_limits_and_disable_legacy_priorities() {
        let state = H2State::new(true, true, 128);
        let (_, _, _, payload) = next_frame(&state.outbound[..]);
        assert_eq!(payload, [0, 3, 0, 0, 0, 128, 0, 4, 1, 0, 0, 0, 0, 9, 0, 0, 0, 1]);
    }

    #[test]
    fn frames_above_the_advertised_size_close_the_connection() {
        for (limits, accepted, rejected) in [
            (custom_limits(), 32_768, 32_769),
            (H2Limits::default(), FRAME_SIZE, FRAME_SIZE + 1),
        ] {
            let mut state = H2State::with_limits(true, true, limits);
            let mut wire = Vec::new();
            queue_frame(&mut wire, SETTINGS, 0, 0, &[]);
            queue_frame(&mut wire, 0xfa, 0, 0, &vec![0; accepted]);
            state.receive(&wire).unwrap();
            wire.clear();
            queue_frame(&mut wire, 0xfa, 0, 0, &vec![0; rejected]);
            assert!(state.receive(&wire).is_err());
        }
    }

    #[test]
    fn server_pings_after_idle_and_closes_without_an_ack() {
        let limits = H2Limits {
            ping_after: Some(Duration::from_millis(10)),
            ping_timeout: Duration::from_millis(20),
            ..H2Limits::default()
        };
        let mut state = H2State::with_limits(true, true, limits);
        state.outbound.clear();
        let start = state.last_frame;
        assert!(!state.tick(start + Duration::from_millis(5)));
        assert!(state.outbound.is_empty());
        assert!(!state.tick(start + Duration::from_millis(15)));
        let (kind, flags, id, data) = next_frame(&state.outbound[..]);
        assert_eq!((kind, flags, id, data.len()), (PING, 0, 0, 8));
        assert!(!state.tick(start + Duration::from_millis(30)));
        let mut ack = Vec::new();
        queue_frame(&mut ack, SETTINGS, 0, 0, &[]);
        queue_frame(&mut ack, PING, ACK, 0, &data);
        state.receive(&ack).unwrap();
        assert!(state.ping.is_none());
        state.outbound.clear();
        let later = Instant::now() + Duration::from_millis(15);
        assert!(!state.tick(later));
        assert!(state.ping.is_some());
        assert!(state.tick(later + Duration::from_millis(25)));
        assert!(state.check_connection().is_err());
    }
}
