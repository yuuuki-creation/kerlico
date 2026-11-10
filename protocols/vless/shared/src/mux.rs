//! Xray mux frames carried inside a VLESS connection whose command is `mux`.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::{Addr, HeaderError};

/// Xray's `xudp.GetGlobalID` for a cone UDP inbound: the first eight bytes of BLAKE3, keyed with
/// a random per-process base key, over the source as Go prints it (`udp:1.2.3.4:5`,
/// `udp:[::1]:5`). The same local socket therefore keeps one ID across carriers.
pub fn xudp_global_id(source: SocketAddr) -> Option<NonZeroU64> {
    static BASE_KEY: OnceLock<[u8; 32]> = OnceLock::new();
    let key = BASE_KEY.get_or_init(|| {
        let mut key = [0; 32];
        getrandom::getrandom(&mut key).expect("XUDP base key");
        key
    });
    keyed_global_id(key, source)
}

fn keyed_global_id(key: &[u8; 32], source: SocketAddr) -> Option<NonZeroU64> {
    let host = match source.ip().to_canonical() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(format!("udp:{host}:{}", source.port()).as_bytes());
    let mut id = [0; 8];
    hasher.finalize_xof().fill(&mut id);
    NonZeroU64::new(u64::from_be_bytes(id))
}

pub const NEW: u8 = 0x01;
pub const KEEP: u8 = 0x02;
pub const END: u8 = 0x03;
pub const KEEPALIVE: u8 = 0x04;
pub const DATA: u8 = 0x01;
/// Xray's `OptionError` on an END frame.
const ERROR: u8 = 0x02;

/// Xray's Mux writes into a 64 KiB pipe that its worker copies to the carrier.
const UPLINK_BYTES: usize = 64 * 1024;
/// How long a send waits for room, one carrier poll.
const UPLINK_WAIT: Duration = Duration::from_millis(200);

/// The write half of one Mux carrier: the encoded frames its writer thread, `run`, has yet to
/// take. The writer finishes each frame on its own, so a frame the link took only in part
/// completes while nobody sends and while the carrier's reader is busy.
#[derive(Default)]
pub struct MuxUplink {
    queue: Mutex<Uplink>,
    /// Wakes the writer for a queued frame and senders for room.
    changed: Condvar,
}

#[derive(Default)]
struct Uplink {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
    /// Takes no more frames; the writer drains what is queued and stops.
    closed: bool,
}

impl Uplink {
    fn push(&mut self, frame: Vec<u8>) {
        self.bytes += frame.len();
        self.frames.push_back(frame);
    }
}

impl MuxUplink {
    /// Waits up to one poll for room, as a write into Xray's full pipe blocks, then fails with
    /// `TimedOut`. A closed uplink fails with `BrokenPipe`.
    pub fn send(&self, frame: &MuxFrame) -> io::Result<()> {
        if frame.payload.len() > usize::from(u16::MAX) {
            return Err(io::Error::other("mux frame too large"));
        }
        let frame = encode_mux(frame);
        let deadline = Instant::now() + UPLINK_WAIT;
        let mut queue = self.queue.lock().expect("mux uplink");
        while !queue.closed && queue.bytes > 0 && queue.bytes + frame.len() > UPLINK_BYTES {
            let wait = deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            queue = self.changed.wait_timeout(queue, wait).expect("mux uplink").0;
        }
        if queue.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        queue.push(frame);
        self.changed.notify_all();
        Ok(())
    }

    /// Queues END for session `id`, with Xray's error option when `failed`. It never waits, so
    /// ending a session never holds a reader or a drop. Each session ends once, so these frames
    /// stay few; a queue twice the bound means the peer stopped reading, and the uplink closes.
    pub fn end(&self, id: u16, failed: bool) {
        let frame = encode_mux(&MuxFrame { id, status: END, option: if failed { ERROR } else { 0 }, ..MuxFrame::default() });
        let mut queue = self.queue.lock().expect("mux uplink");
        if queue.closed {
            return;
        }
        if queue.bytes + frame.len() > 2 * UPLINK_BYTES {
            queue.closed = true;
        } else {
            queue.push(frame);
        }
        self.changed.notify_all();
    }

    pub fn close(&self) {
        self.queue.lock().expect("mux uplink").closed = true;
        self.changed.notify_all();
    }

    /// Closed by its owner, by an END past the bound, or because the writer stopped.
    pub fn closed(&self) -> bool {
        self.queue.lock().expect("mux uplink").closed
    }

    /// The carrier's writer thread. Writes the queued frames to `link` in order until the uplink
    /// is closed and drained or a write fails, and leaves the uplink closed.
    pub fn run(&self, mut link: impl io::Write) {
        while let Some(frame) = self.next_frame() {
            if self.write_frame(&mut link, &frame).is_err() {
                break;
            }
        }
        self.close();
    }

    fn next_frame(&self) -> Option<Vec<u8>> {
        let mut queue = self.queue.lock().expect("mux uplink");
        loop {
            if let Some(frame) = queue.frames.pop_front() {
                queue.bytes -= frame.len();
                self.changed.notify_all();
                return Some(frame);
            }
            if queue.closed {
                return None;
            }
            queue = self.changed.wait(queue).expect("mux uplink");
        }
    }

    /// A write timeout gives up only once the uplink is closed.
    fn write_frame(&self, link: &mut impl io::Write, mut frame: &[u8]) -> io::Result<()> {
        let retry = |error: &io::Error| {
            matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) && !self.closed()
        };
        while !frame.is_empty() {
            match link.write(frame) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => frame = &frame[n..],
                Err(error) if retry(&error) => {}
                Err(error) => return Err(error),
            }
        }
        loop {
            match link.flush() {
                Err(error) if retry(&error) => {}
                result => return result,
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MuxFrame {
    pub id: u16,
    pub status: u8,
    pub option: u8,
    pub network: u8,
    pub port: u16,
    pub address: Option<Addr>,
    pub payload: Vec<u8>,
    /// XUDP GlobalID, the eight bytes after the address of a NEW UDP frame. Xray reads eight zero bytes as no ID.
    pub global_id: Option<NonZeroU64>,
}

/// First frame a VLESS reverse portal writes: UDP to the domain `reverse`, port 0.
/// The payload is an Xray `Control` protobuf, state ACTIVE, field 99 a random blob.
pub fn control_frame(id: u16) -> MuxFrame {
    MuxFrame {
        id,
        status: NEW,
        option: DATA,
        network: 2,
        port: 0,
        address: Some(Addr::Domain("reverse".to_string())),
        payload: control_payload(0),
        global_id: None,
    }
}

/// Later control bytes on the same session. Xray writes this when the 2-second counter is 1.
pub fn control_keep(id: u16) -> MuxFrame {
    MuxFrame {
        id,
        status: KEEP,
        option: DATA,
        network: 0,
        port: 0,
        address: None,
        payload: control_payload(0),
        global_id: None,
    }
}

pub fn session_frame(id: u16, tcp: bool, port: u16, host: &str, payload: &[u8]) -> MuxFrame {
    MuxFrame {
        id,
        status: NEW,
        option: DATA,
        network: if tcp { 1 } else { 2 },
        port,
        address: Some(host_addr(host)),
        payload: payload.to_vec(),
        global_id: None,
    }
}

fn control_payload(state: u8) -> Vec<u8> {
    let mut random = [0u8; 16];
    let _ = getrandom::getrandom(&mut random);
    encode_control(state, &random)
}

fn host_addr(host: &str) -> Addr {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Addr::V4(ip);
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        return Addr::V6(ip);
    }
    Addr::Domain(host.to_string())
}

/// Xray sends a heartbeat when `(counter + 1) % 5 == 1`.
pub fn heartbeat_due(counter: u32) -> (u32, bool) {
    let counter = (counter + 1) % 5;
    (counter, counter == 1)
}

/// `Control.state` from one control payload: 0 is ACTIVE, 1 is DRAIN. `None` when the
/// protobuf is malformed, which makes an Xray bridge close that connection.
pub fn control_state(mut bytes: &[u8]) -> Option<u64> {
    fn varint(bytes: &mut &[u8]) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = bytes.split_first()?;
            *bytes = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }
    let mut state = 0;
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        let skip = match key & 7 {
            0 => {
                let value = varint(&mut bytes)?;
                if key >> 3 == 1 {
                    state = value;
                }
                0
            }
            1 => 8,
            2 => usize::try_from(varint(&mut bytes)?).ok()?,
            5 => 4,
            _ => return None,
        };
        bytes = bytes.get(skip..)?;
    }
    Some(state)
}

fn encode_control(state: u8, random: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if state != 0 {
        out.push(0x08);
        out.push(state);
    }
    out.push(0x9a);
    out.push(0x06);
    out.push(random.len() as u8);
    out.extend_from_slice(random);
    out
}

pub fn encode_mux(frame: &MuxFrame) -> Vec<u8> {
    let mut meta = Vec::new();
    meta.extend_from_slice(&frame.id.to_be_bytes());
    meta.push(frame.status);
    meta.push(frame.option);
    if frame.status == NEW || (frame.status == KEEP && frame.network == 2 && frame.address.is_some()) {
        meta.push(frame.network);
        write_port_addr(&mut meta, frame.port, frame.address.as_ref());
        if let (NEW, 2, Some(global_id)) = (frame.status, frame.network, frame.global_id) {
            meta.extend_from_slice(&global_id.get().to_be_bytes());
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    out.extend_from_slice(&meta);
    if frame.option & DATA != 0 {
        out.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&frame.payload);
    }
    out
}

pub fn decode_mux(buf: &[u8]) -> Result<(MuxFrame, usize), HeaderError> {
    if buf.len() < 2 {
        return Err(HeaderError::Short);
    }
    let meta_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if meta_len > 512 {
        return Err(HeaderError::Bad);
    }
    if buf.len() < 2 + meta_len {
        return Err(HeaderError::Short);
    }
    let meta = &buf[2..2 + meta_len];
    if meta.len() < 4 {
        return Err(HeaderError::Bad);
    }
    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];
    let mut network = 0u8;
    let mut port = 0u16;
    let mut address = None;
    let mut global_id = None;
    if status == NEW || (status == KEEP && meta.len() > 4) {
        if meta.len() < 5 {
            return Err(HeaderError::Bad);
        }
        network = meta[4];
        if status == KEEP && network != 2 { return Err(HeaderError::Bad); }
        if !matches!(network, 1 | 2) {
            return Err(HeaderError::Bad);
        }
        let (parsed_port, parsed_addr, used) = read_port_addr(&meta[5..])?;
        port = parsed_port;
        address = Some(parsed_addr);
        if status == NEW && option & DATA != 0 && network == 2 {
            global_id = meta[5 + used..].first_chunk::<8>().and_then(|id| NonZeroU64::new(u64::from_be_bytes(*id)));
        }
    }
    let mut consumed = 2 + meta_len;
    let mut payload = Vec::new();
    if option & DATA != 0 {
        if buf.len() < consumed + 2 {
            return Err(HeaderError::Short);
        }
        let len = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]) as usize;
        consumed += 2;
        if buf.len() < consumed + len {
            return Err(HeaderError::Short);
        }
        payload = buf[consumed..consumed + len].to_vec();
        consumed += len;
    }
    Ok((
        MuxFrame { id, status, option, network, port, address, payload, global_id },
        consumed,
    ))
}

fn write_port_addr(out: &mut Vec<u8>, port: u16, address: Option<&Addr>) {
    out.extend_from_slice(&port.to_be_bytes());
    match address {
        Some(Addr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Some(Addr::Domain(name)) => {
            out.push(2);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        Some(Addr::V6(ip)) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
        None => out.push(0),
    }
}

fn read_port_addr(buf: &[u8]) -> Result<(u16, Addr, usize), HeaderError> {
    if buf.len() < 3 {
        return Err(HeaderError::Bad);
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    match buf[2] {
        1 => {
            if buf.len() < 7 {
                return Err(HeaderError::Bad);
            }
            Ok((port, Addr::V4(Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6])), 7))
        }
        2 => {
            if buf.len() < 4 || buf[3] == 0 {
                return Err(HeaderError::Bad);
            }
            let len = buf[3] as usize;
            if buf.len() < 4 + len {
                return Err(HeaderError::Bad);
            }
            let name = std::str::from_utf8(&buf[4..4 + len]).map_err(|_| HeaderError::Bad)?;
            Ok((port, Addr::Domain(name.to_string()), 4 + len))
        }
        3 => {
            if buf.len() < 19 {
                return Err(HeaderError::Bad);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[3..19]);
            Ok((port, Addr::V6(Ipv6Addr::from(octets)), 19))
        }
        _ => Err(HeaderError::Bad),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_frame_roundtrip() {
        let frame = MuxFrame {
            id: 7,
            status: NEW,
            option: DATA,
            network: 1,
            port: 80,
            address: Some(Addr::Domain("example.com".to_string())),
            payload: b"ping".to_vec(),
            global_id: None,
        };
        let bytes = encode_mux(&frame);
        let (decoded, used) = decode_mux(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, frame);
    }

    /// A NEW UDP frame as Xray's `xudp.PacketWriter` writes it, to 127.0.0.1:53 with payload "dns".
    fn xray_xudp_new(global_id: &[u8]) -> Vec<u8> {
        let mut meta = vec![0, 9, NEW, DATA, 2, 0, 53, 1, 127, 0, 0, 1];
        meta.extend_from_slice(global_id);
        let mut bytes = (meta.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(&meta);
        bytes.extend_from_slice(&[0, 3]);
        bytes.extend_from_slice(b"dns");
        bytes
    }

    #[test]
    fn xudp_global_id_follows_the_address() {
        let bytes = xray_xudp_new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let (frame, used) = decode_mux(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(frame.global_id, NonZeroU64::new(0x0102030405060708));
        assert_eq!(frame.address, Some(Addr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(frame.payload, b"dns");
        assert_eq!(encode_mux(&frame), bytes, "re-encoding writes the GlobalID where Xray does");
    }

    #[test]
    fn xudp_global_id_matches_xray_derivation() {
        // Values from lukechampine.com/blake3 v1.4.1 New(8, key) with key = 32 bytes of 7.
        let key = [7; 32];
        let v4: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert_eq!(keyed_global_id(&key, v4), NonZeroU64::new(0xf124c912440b2204));
        let v6: SocketAddr = "[::1]:5000".parse().unwrap();
        assert_eq!(keyed_global_id(&key, v6), NonZeroU64::new(0x2313437889b3ab72));
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5000".parse().unwrap();
        assert_eq!(keyed_global_id(&key, mapped), keyed_global_id(&key, v4), "Go prints a mapped address as IPv4");
        assert_eq!(xudp_global_id(v4), xudp_global_id(v4), "one process keeps one base key");
        assert_ne!(xudp_global_id(v4), xudp_global_id("127.0.0.1:5001".parse().unwrap()));
    }

    #[test]
    fn xudp_frames_without_global_id() {
        let bare = xray_xudp_new(&[]);
        let (frame, _) = decode_mux(&bare).unwrap();
        assert_eq!(frame.global_id, None);
        assert_eq!(encode_mux(&frame), bare, "no GlobalID adds no bytes");
        let (frame, _) = decode_mux(&xray_xudp_new(&[0; 8])).unwrap();
        assert_eq!(frame.global_id, None, "a non-cone Xray client sends eight zero bytes");
        let (frame, _) = decode_mux(&xray_xudp_new(&[1, 2, 3])).unwrap();
        assert_eq!(frame.global_id, None, "fewer than eight trailing bytes are padding");
    }

    #[test]
    fn global_id_is_read_only_from_new_udp_frames_with_data() {
        let mut tcp = xray_xudp_new(&[1; 8]);
        tcp[6] = 1;
        assert_eq!(decode_mux(&tcp).unwrap().0.global_id, None, "TCP frame");
        let mut empty = xray_xudp_new(&[1; 8]);
        empty[5] = 0;
        assert_eq!(decode_mux(&empty).unwrap().0.global_id, None, "frame without data");
        let keep = MuxFrame { status: KEEP, global_id: NonZeroU64::new(7), ..decode_mux(&xray_xudp_new(&[])).unwrap().0 };
        assert_eq!(decode_mux(&encode_mux(&keep)).unwrap().0.global_id, None, "KEEP frame");
    }

    /// Takes at most 100 bytes per write and times out every other write, as a carrier socket
    /// with a full send buffer does.
    struct Choppy {
        out: std::sync::Arc<Mutex<Vec<u8>>>,
        stall: bool,
    }

    impl io::Write for Choppy {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stall = !self.stall;
            if self.stall {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let n = buf.len().min(100);
            self.out.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn keep(id: u16, len: usize) -> MuxFrame {
        MuxFrame { id, status: KEEP, option: DATA, payload: vec![7; len], ..MuxFrame::default() }
    }

    #[test]
    fn uplink_writer_finishes_a_cut_frame_without_another_send() {
        let uplink = std::sync::Arc::new(MuxUplink::default());
        let out: std::sync::Arc<Mutex<Vec<u8>>> = std::sync::Arc::default();
        let writer = {
            let (uplink, out) = (uplink.clone(), std::sync::Arc::clone(&out));
            std::thread::spawn(move || uplink.run(Choppy { out, stall: false }))
        };
        uplink.send(&keep(1, 1000)).unwrap();
        let expected = encode_mux(&keep(1, 1000));
        let deadline = Instant::now() + Duration::from_secs(5);
        while out.lock().unwrap().len() < expected.len() {
            assert!(Instant::now() < deadline, "the writer left the frame cut");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*out.lock().unwrap(), expected);
        uplink.close();
        writer.join().unwrap();
    }

    #[test]
    fn full_uplink_times_out_a_send_but_never_holds_an_end() {
        let uplink = MuxUplink::default();
        uplink.send(&keep(1, usize::from(u16::MAX))).unwrap();
        let start = Instant::now();
        assert_eq!(uplink.send(&keep(1, 1)).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= UPLINK_WAIT, "a send into a full uplink waits one poll for room");
        let start = Instant::now();
        uplink.end(1, false);
        assert!(start.elapsed() < UPLINK_WAIT, "END does not wait for room");
        let mut id = 2;
        while !uplink.closed() {
            assert!(id < 20_000, "ENDs past twice the bound never closed the uplink");
            uplink.end(id, true);
            id += 1;
        }
        assert_eq!(uplink.send(&keep(1, 1)).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn closed_uplink_drains_what_it_queued_in_order() {
        let uplink = MuxUplink::default();
        uplink.send(&keep(3, 4)).unwrap();
        uplink.end(3, true);
        uplink.close();
        uplink.end(5, false);
        let mut out = Vec::new();
        uplink.run(&mut out);
        let (data, used) = decode_mux(&out).unwrap();
        let (end, rest) = decode_mux(&out[used..]).unwrap();
        assert_eq!((data.id, data.status, data.payload), (3, KEEP, vec![7; 4]));
        assert_eq!((end.id, end.status, end.option), (3, END, ERROR), "a failed session ends with Xray's error option");
        assert_eq!(used + rest, out.len(), "nothing is queued after close");
    }

    #[test]
    fn heartbeat_sends_once_every_five_ticks() {
        let mut counter = 0;
        let mut sent = 0;
        for _ in 0..5 {
            let (next, due) = heartbeat_due(counter);
            counter = next;
            if due {
                sent += 1;
            }
        }
        assert_eq!(sent, 1);
        assert!(heartbeat_due(0).1);
    }

    #[test]
    fn control_frame_is_udp_to_reverse() {
        let frame = control_frame(1);
        let (decoded, used) = decode_mux(&encode_mux(&frame)).unwrap();
        assert_eq!(used, encode_mux(&frame).len());
        assert_eq!(decoded.network, 2);
        assert_eq!(decoded.port, 0);
        assert_eq!(decoded.address, Some(Addr::Domain("reverse".to_string())));
        assert_eq!(&decoded.payload[..3], &[0x9a, 0x06, 16]);
    }

    #[test]
    fn control_state_reads_active_and_drain_and_rejects_broken_protobuf() {
        assert_eq!(control_state(&encode_control(0, &[7; 64])), Some(0));
        assert_eq!(control_state(&encode_control(1, &[7; 3])), Some(1));
        assert_eq!(control_state(&[]), Some(0));
        assert_eq!(control_state(&[0x9a, 0x06, 5, 1, 2]), None, "random field longer than the payload");
        assert_eq!(control_state(&[0x08]), None, "state without its varint");
        assert_eq!(control_state(&[0x0b]), None, "group wire type");
    }
}
