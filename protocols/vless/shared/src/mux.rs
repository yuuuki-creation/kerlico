//! Xray mux frames carried inside a VLESS connection whose command is `mux`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;

use crate::{Addr, HeaderError};

pub const NEW: u8 = 0x01;
pub const KEEP: u8 = 0x02;
pub const END: u8 = 0x03;
pub const KEEPALIVE: u8 = 0x04;
pub const DATA: u8 = 0x01;

pub struct MuxWriter<T> {
    inner: T,
    pending: Vec<u8>,
}

impl<T: std::io::Write> MuxWriter<T> {
    pub fn new(inner: T) -> Self { Self { inner, pending: Vec::new() } }
    pub fn inner_mut(&mut self) -> &mut T { &mut self.inner }

    pub fn send(&mut self, frame: &MuxFrame) -> std::io::Result<()> {
        if frame.payload.len() > u16::MAX as usize { return Err(std::io::Error::other("mux frame too large")); }
        self.flush()?;
        self.pending = encode_mux(frame);
        match self.flush() {
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Ok(()),
            result => result,
        }
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        while !self.pending.is_empty() {
            let n = self.inner.write(&self.pending)?;
            if n == 0 { return Err(std::io::ErrorKind::WriteZero.into()); }
            self.pending.drain(..n);
        }
        self.inner.flush()
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
}
