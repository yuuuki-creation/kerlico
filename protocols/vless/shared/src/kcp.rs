//! Xray mKCP segments. Data is 18 bytes of header plus payload. An ack lists the received numbers.
//!
//! A disguise header sits in front of the segment. `seed` wraps the segment in AES-128-GCM first.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::{UdpSocket, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use sha2::{Digest, Sha256};

mod options;
pub use options::KcpOptions;

const DATA: u8 = 1;
const ACK: u8 = 0;
const TERMINATE: u8 = 2;
const PING: u8 = 3;
const CLOSE: u8 = 1;

struct Outgoing {
    packet: Vec<u8>,
    retry_at: Option<Instant>,
}

pub struct Session {
    conv: u16,
    next_send: u64,
    next_sent: u64,
    send_una: u64,
    remote_edge: u32,
    recv_next: u32,
    unacked: BTreeMap<u64, Outgoing>,
    inbox: BTreeMap<u32, Vec<u8>>,
    plain: VecDeque<u8>,
    options: KcpOptions,
    control_window: u32,
    next_flush: Instant,
    start: Instant,
    last_received: Instant,
    last_ping: Instant,
    last_terminate: Option<Instant>,
    closing: Option<Instant>,
    terminating: Option<Instant>,
    peer_closed: bool,
    terminated: bool,
    window_changed: bool,
    round_trip: RoundTrip,
}

struct RoundTrip {
    timeout: Duration,
    smoothed_ms: u32,
    variance_ms: u32,
    updated: Instant,
}

impl RoundTrip {
    fn new(now: Instant) -> Self {
        Self { timeout: Duration::from_millis(100), smoothed_ms: 0, variance_ms: 0, updated: now }
    }

    fn observe(&mut self, now: Instant, sample: u32, interval: Duration) {
        let minimum = interval.as_millis() as u32;
        if self.smoothed_ms == 0 {
            self.smoothed_ms = sample;
            self.variance_ms = sample / 2;
        } else {
            let deviation = self.smoothed_ms.abs_diff(sample);
            self.variance_ms = (3 * self.variance_ms + deviation) / 4;
            self.smoothed_ms = ((7 * self.smoothed_ms + sample) / 8).max(minimum);
        }
        let spread = if 4 * self.variance_ms > minimum { 4 * self.variance_ms } else { self.variance_ms };
        let estimate = (self.smoothed_ms + spread).min(10_000) * 5 / 4;
        self.timeout = Duration::from_millis(u64::from(estimate).max(1));
        self.updated = now;
    }

    fn observe_peer(&mut self, now: Instant, timeout_ms: u32) {
        if timeout_ms != 0 && now.duration_since(self.updated) >= Duration::from_secs(3) {
            self.timeout = Duration::from_millis(timeout_ms.min(12_500).into());
            self.updated = now;
        }
    }
}

impl Session {
    pub fn new(conv: u16) -> Self {
        Self::with_options(conv, KcpOptions::default())
    }

    pub fn with_options(conv: u16, options: KcpOptions) -> Self {
        let start = Instant::now();
        Self {
            conv,
            next_send: 0,
            next_sent: 0,
            send_una: 0,
            remote_edge: 32,
            recv_next: 0,
            unacked: BTreeMap::new(),
            inbox: BTreeMap::new(),
            plain: VecDeque::new(),
            options,
            control_window: options.send_flight,
            next_flush: start,
            start,
            last_received: start,
            last_ping: start,
            last_terminate: None,
            closing: None,
            terminating: None,
            peer_closed: false,
            terminated: false,
            window_changed: false,
            round_trip: RoundTrip::new(start),
        }
    }

    pub fn conv(&self) -> u16 {
        self.conv
    }

    /// Admit application bytes to the send queue and flush one packet budget when due.
    pub fn write(&mut self, data: &[u8]) -> (usize, Vec<Vec<u8>>) {
        self.write_at(data, Instant::now())
    }

    fn write_at(&mut self, data: &[u8], now: Instant) -> (usize, Vec<Vec<u8>>) {
        if self.write_closed() {
            return (0, Vec::new());
        }
        let mut accepted = 0;
        let free = self.options.send_queue - self.unacked.len();
        for chunk in data.chunks(self.options.data_payload).take(free) {
            let packet = encode_data(self.conv, self.next_send as u32, self.send_una as u32, chunk);
            self.unacked.insert(self.next_send, Outgoing { packet, retry_at: None });
            self.next_send += 1;
            accepted += chunk.len();
        }
        (accepted, self.poll_at(now))
    }

    pub fn retransmit(&self) -> Vec<Vec<u8>> {
        self.unacked.values().filter(|out| out.retry_at.is_some()).map(|out| out.packet.clone()).collect()
    }

    pub fn input(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        self.input_at(packet, Instant::now())
    }

    fn input_at(&mut self, packet: &[u8], now: Instant) -> Vec<Vec<u8>> {
        let mut rest = packet;
        if self.terminated { return Vec::new(); }
        let mut ack_numbers = Vec::new();
        while !rest.is_empty() {
            let Some(next) = parse(self.conv, rest, &mut ack_numbers, self, now) else {
                break;
            };
            rest = next;
            self.last_received = now;
        }
        let mut replies = Vec::new();
        for numbers in ack_numbers.chunks(self.options.ack_entries) {
            replies.push(self.ack(numbers));
        }
        if self.terminated { replies.push(self.command(TERMINATE)); }
        replies
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut n = 0;
        while n < buf.len() {
            if self.plain.is_empty() {
                let Some(payload) = self.inbox.remove(&self.recv_next) else { break; };
                self.recv_next = self.recv_next.wrapping_add(1);
                self.window_changed = true;
                self.plain.extend(payload);
            }
            while n < buf.len() {
                let Some(byte) = self.plain.pop_front() else { break; };
                buf[n] = byte;
                n += 1;
            }
        }
        n
    }

    pub fn read_closed(&self) -> bool {
        self.terminated && self.plain.is_empty() && !self.inbox.contains_key(&self.recv_next)
    }

    pub fn write_closed(&self) -> bool { self.closing.is_some() || self.peer_closed || self.terminated }
    pub fn terminated(&self) -> bool { self.terminated }
    pub fn close(&mut self) { self.closing.get_or_insert_with(Instant::now); }
    pub fn abort(&mut self) { self.terminated = true; }

    /// Transport-owned timer work, independent of application reads and writes.
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        self.poll_at(Instant::now())
    }

    fn poll_at(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if self.terminated { return Vec::new(); }
        if now.duration_since(self.last_received) >= Duration::from_secs(30) {
            self.closing.get_or_insert(now);
        }
        if self.closing.is_some_and(|start| {
            self.unacked.is_empty() || now.duration_since(start) >= Duration::from_secs(15)
        }) {
            let start = *self.terminating.get_or_insert(now);
            if now.duration_since(start) >= Duration::from_secs(8) {
                self.terminated = true;
                return Vec::new();
            }
            if self.last_terminate.is_none_or(|last| now.duration_since(last) >= self.options.interval()) {
                self.last_terminate = Some(now);
                return vec![self.command(TERMINATE)];
            }
            return Vec::new();
        }
        let mut packets = Vec::new();
        if self.window_changed {
            self.window_changed = false;
            packets.push(self.ack(&[]));
        }
        self.flush_data(now, &mut packets);
        if now.duration_since(self.last_ping) >= Duration::from_secs(3) {
            self.last_ping = now;
            packets.push(self.ack(&[]));
            packets.push(self.command(PING));
        }
        packets
    }

    fn flush_data(&mut self, now: Instant, packets: &mut Vec<Vec<u8>>) {
        if now < self.next_flush || self.unacked.is_empty() {
            return;
        }
        let remaining = self.remote_edge.wrapping_sub(self.send_una as u32);
        if remaining == 0 || remaining > i32::MAX as u32 {
            return;
        }
        let budget = self.options.send_flight.min(self.control_window).min(remaining)
            .wrapping_mul(self.options.cwnd_multiplier).max(1);
        let timestamp = now.duration_since(self.start).as_millis() as u32;
        let mut sent = 0;
        let mut lost = 0u64;
        for (&number, outgoing) in self.unacked.range_mut(..self.send_una + u64::from(remaining)) {
            if sent == budget {
                break;
            }
            if let Some(retry_at) = outgoing.retry_at {
                if now < retry_at {
                    continue;
                }
                lost += 1;
            }
            outgoing.retry_at = Some(now + self.round_trip.timeout);
            outgoing.packet[3] = if self.closing.is_some() { CLOSE } else { 0 };
            outgoing.packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
            outgoing.packet[12..16].copy_from_slice(&(self.send_una as u32).to_be_bytes());
            self.next_sent = self.next_sent.max(number + 1);
            packets.push(outgoing.packet.clone());
            sent += 1;
        }
        if sent != 0 {
            self.next_flush = now + self.options.interval();
            let in_flight = self.unacked.values().filter(|packet| packet.retry_at.is_some()).count() as u64;
            let loss_rate = lost * 100 / in_flight;
            if loss_rate >= 15 {
                self.control_window = self.control_window * 3 / 4;
            } else if loss_rate <= 5 {
                self.control_window += self.control_window / 4;
            }
            self.control_window = self.control_window.max(16).min(self.options.send_flight);
        }
    }

    fn ack(&self, numbers: &[(u32, u32)]) -> Vec<u8> {
        encode_ack(self.conv, self.recv_next, self.options.receive_window, numbers)
    }

    fn command(&self, command: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&self.conv.to_be_bytes());
        out.push(command);
        out.push(if self.closing.is_some() { CLOSE } else { 0 });
        out.extend_from_slice(&(self.send_una as u32).to_be_bytes());
        out.extend_from_slice(&self.recv_next.to_be_bytes());
        out.extend_from_slice(&(self.round_trip.timeout.as_millis() as u32).to_be_bytes());
        out
    }

    fn acknowledge(&mut self, next: u32) {
        let next = self.send_una + u64::from(next.wrapping_sub(self.send_una as u32));
        if next > self.send_una && next <= self.next_sent {
            self.unacked = self.unacked.split_off(&next);
            self.advance_send();
        }
    }

    fn advance_send(&mut self) {
        while self.send_una != self.next_send && !self.unacked.contains_key(&self.send_una) {
            self.send_una += 1;
        }
    }

    fn option(&mut self, option: u8) {
        if option & CLOSE != 0 {
            self.peer_closed = true;
            self.unacked.clear();
            self.advance_send();
        }
    }
}

fn before(left: u32, right: u32) -> bool { left != right && left.wrapping_sub(right) > 0x7fff_ffff }

fn parse<'a>(conv: u16, packet: &'a [u8], acks: &mut Vec<(u32, u32)>, session: &mut Session, now: Instant) -> Option<&'a [u8]> {
    if packet.len() < 4 {
        return None;
    }
    let got = u16::from_be_bytes([packet[0], packet[1]]);
    if got != conv {
        return None;
    }
    let cmd = packet[2];
    match cmd {
        DATA => parse_data(packet, acks, session),
        ACK => parse_ack(packet, session, now),
        PING | TERMINATE => {
            if packet.len() < 16 { return None; }
            session.acknowledge(u32::from_be_bytes(packet[8..12].try_into().ok()?));
            session.round_trip.observe_peer(now, u32::from_be_bytes(packet[12..16].try_into().ok()?));
            session.option(packet[3]);
            if cmd == TERMINATE {
                session.peer_closed = true;
                session.terminated = true;
            }
            Some(&packet[16..])
        }
        _ => None,
    }
}

fn parse_data<'a>(packet: &'a [u8], acks: &mut Vec<(u32, u32)>, session: &mut Session) -> Option<&'a [u8]> {
    if packet.len() < 18 {
        return None;
    }
    let sn = u32::from_be_bytes(packet[8..12].try_into().unwrap());
    let timestamp = u32::from_be_bytes(packet[4..8].try_into().unwrap());
    let len = u16::from_be_bytes([packet[16], packet[17]]) as usize;
    if packet.len() < 18 + len {
        return None;
    }
    session.option(packet[3]);
    if sn.wrapping_sub(session.recv_next) < session.options.receive_window {
        session.inbox.entry(sn).or_insert_with(|| packet[18..18 + len].to_vec());
        acks.push((sn, timestamp));
    } else if before(sn, session.recv_next) {
        acks.push((sn, timestamp));
    }
    Some(&packet[18 + len..])
}

fn parse_ack<'a>(packet: &'a [u8], session: &mut Session, now: Instant) -> Option<&'a [u8]> {
    if packet.len() < 17 {
        return None;
    }
    let receiving_next = u32::from_be_bytes(packet[8..12].try_into().unwrap());
    let count = packet[16] as usize;
    if packet.len() < 17 + count * 4 {
        return None;
    }
    let edge = u32::from_be_bytes(packet[4..8].try_into().unwrap());
    if before(session.remote_edge, edge) { session.remote_edge = edge; }
    session.acknowledge(receiving_next);
    let mut highest = None;
    for index in 0..count {
        let start = 17 + index * 4;
        let number = u32::from_be_bytes(packet[start..start + 4].try_into().unwrap());
        let offset = number.wrapping_sub(session.send_una as u32);
        if offset > i32::MAX as u32 {
            continue;
        }
        let number = session.send_una + u64::from(offset);
        let removed = number < session.next_sent && session.unacked.remove(&number).is_some();
        if highest.is_none_or(|(highest, _)| number > highest) {
            highest = Some((number, removed));
        }
    }
    session.advance_send();
    let timestamp = u32::from_be_bytes(packet[12..16].try_into().unwrap());
    let elapsed = (now.duration_since(session.start).as_millis() as u32).wrapping_sub(timestamp);
    if let Some((highest, true)) = highest {
        let advance = session.round_trip.timeout / 3;
        for outgoing in session.unacked.range_mut(..highest).map(|(_, packet)| packet) {
            outgoing.retry_at = outgoing.retry_at.map(|deadline| deadline.checked_sub(advance).unwrap_or(now));
        }
        if elapsed < 10_000 {
            session.round_trip.observe(now, elapsed, session.options.interval());
        }
    }
    session.option(packet[3]);
    Some(&packet[17 + count * 4..])
}

fn encode_data(conv: u16, sn: u32, sending_next: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + payload.len());
    out.extend_from_slice(&conv.to_be_bytes());
    out.push(DATA);
    out.push(0);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&sn.to_be_bytes());
    out.extend_from_slice(&sending_next.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn encode_ack(conv: u16, receiving_next: u32, receive_window: u32, numbers: &[(u32, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + numbers.len() * 4);
    out.extend_from_slice(&conv.to_be_bytes());
    out.push(ACK);
    out.push(0);
    out.extend_from_slice(&receiving_next.wrapping_add(receive_window).to_be_bytes());
    out.extend_from_slice(&receiving_next.to_be_bytes());
    let latest_timestamp = numbers.iter().map(|(_, timestamp)| *timestamp)
        .reduce(|left, right| if before(left, right) { right } else { left })
        .unwrap_or(0);
    out.extend_from_slice(&latest_timestamp.to_be_bytes());
    out.push(numbers.len() as u8);
    for (number, _) in numbers {
        out.extend_from_slice(&number.to_be_bytes());
    }
    out
}

#[derive(Clone)]
enum Disguise {
    None,
    Srtp,
    Utp,
    Wechat,
    Dtls,
    Wireguard,
    Dns(Vec<u8>),
    Original,
}

/// Packet disguise and optional AES-128-GCM. Reading only needs the header size and the key.
#[derive(Clone)]
pub struct KcpMask {
    disguise: Disguise,
    key: Option<[u8; 16]>,
    srtp_number: u16,
    dtls_sequence: u32,
    dtls_length: u16,
    wechat_sn: u32,
}

impl KcpMask {
    pub fn none() -> Self {
        Self {
            disguise: Disguise::None,
            key: None,
            srtp_number: 0,
            dtls_sequence: 0,
            dtls_length: 0,
            wechat_sn: 0,
        }
    }

    pub fn header_size(&self) -> usize {
        match &self.disguise {
            Disguise::None => 0,
            Disguise::Srtp | Disguise::Utp | Disguise::Wireguard => 4,
            Disguise::Wechat => 13,
            Disguise::Dtls => 13,
            Disguise::Dns(header) => header.len(),
            Disguise::Original => 0,
        }
    }

    pub fn open(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if matches!(self.disguise, Disguise::Original) {
            return open_original(packet);
        }
        let body = packet.get(self.header_size()..)?;
        match self.key {
            Some(key) => open_gcm(&key, body),
            None => Some(body.to_vec()),
        }
    }

    pub fn seal(&mut self, packet: &[u8]) -> Vec<u8> {
        if matches!(self.disguise, Disguise::Original) {
            return seal_original(packet);
        }
        let body = match self.key {
            Some(key) => seal_gcm(&key, packet),
            None => packet.to_vec(),
        };
        let mut out = vec![0u8; self.header_size() + body.len()];
        self.write_header(&mut out);
        out[self.header_size()..].copy_from_slice(&body);
        out
    }

    fn write_header(&mut self, out: &mut [u8]) {
        match &self.disguise {
            Disguise::None => {}
            Disguise::Srtp => {
                self.srtp_number = self.srtp_number.wrapping_add(1);
                out[2..4].copy_from_slice(&self.srtp_number.to_be_bytes());
            }
            Disguise::Utp => {}
            Disguise::Wechat => {
                self.wechat_sn = self.wechat_sn.wrapping_add(1);
                out[0] = 0xa1;
                out[1] = 0x08;
                out[2..6].copy_from_slice(&self.wechat_sn.to_be_bytes());
                out[6] = 0x00;
                out[7] = 0x10;
                out[8] = 0x11;
                out[9] = 0x18;
                out[10] = 0x30;
                out[11] = 0x22;
                out[12] = 0x30;
            }
            Disguise::Dtls => {
                out[0] = 23;
                out[1] = 254;
                out[2] = 253;
                out[7..11].copy_from_slice(&self.dtls_sequence.to_be_bytes());
                self.dtls_sequence = self.dtls_sequence.wrapping_add(1);
                out[11..13].copy_from_slice(&self.dtls_length.to_be_bytes());
                self.dtls_length = self.dtls_length.wrapping_add(17);
                if self.dtls_length > 100 {
                    self.dtls_length -= 50;
                }
            }
            Disguise::Wireguard => {
                out[0] = 0x04;
            }
            Disguise::Dns(header) => {
                out[..header.len()].copy_from_slice(header);
                let mut id = [0u8; 2];
                getrandom::getrandom(&mut id).ok();
                out[..2].copy_from_slice(&id);
            }
            Disguise::Original => {}
        }
    }
}

/// `header` is `none`, `srtp`, `utp`, `wechat`, `dtls`, `wireguard`, `dns`, or `original`.
/// `domain` is the DNS query name. `seed` is the AES-128-GCM password.
/// `original` is the legacy FNV wrapper and does not use `seed`.
pub fn kcp_mask(header: &str, domain: &str, seed: &str) -> Option<KcpMask> {
    let disguise = match header {
        "" | "none" => Disguise::None,
        "original" => Disguise::Original,
        "srtp" => Disguise::Srtp,
        "utp" => Disguise::Utp,
        "wechat" | "wechat-video" => Disguise::Wechat,
        "dtls" => Disguise::Dtls,
        "wireguard" => Disguise::Wireguard,
        "dns" => {
            let name = if domain.is_empty() { "www.baidu.com" } else { domain };
            Disguise::Dns(dns_query(name)?)
        }
        _ => return None,
    };
    let key = if seed.is_empty() {
        None
    } else {
        let hash = Sha256::digest(seed.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
        Some(key)
    };
    Some(KcpMask {
        disguise,
        key,
        srtp_number: 0,
        dtls_sequence: 0,
        dtls_length: 0,
        wechat_sn: 0,
    })
}

fn seal_original(plain: &[u8]) -> Vec<u8> {
    let mut dst = vec![0, 0, 0, 0, 0, 0];
    dst[4..6].copy_from_slice(&(plain.len() as u16).to_be_bytes());
    dst.extend_from_slice(plain);
    let hash = fnv1a32(&dst[4..]);
    dst[..4].copy_from_slice(&hash.to_be_bytes());
    let full = dst.len();
    let extra = (4 - full % 4) % 4;
    dst.resize(full + extra, 0);
    xor_fwd(&mut dst);
    dst.truncate(full);
    dst
}

fn open_original(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 6 {
        return None;
    }
    let mut dst = packet.to_vec();
    let full = dst.len();
    let extra = (4 - full % 4) % 4;
    dst.resize(full + extra, 0);
    xor_bkd(&mut dst);
    dst.truncate(full);
    if u32::from_be_bytes(dst[..4].try_into().ok()?) != fnv1a32(&dst[4..]) {
        return None;
    }
    let length = u16::from_be_bytes([dst[4], dst[5]]) as usize;
    if dst.len() - 6 != length {
        return None;
    }
    Some(dst[6..].to_vec())
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn xor_fwd(bytes: &mut [u8]) {
    for index in 4..bytes.len() {
        bytes[index] ^= bytes[index - 4];
    }
}

fn xor_bkd(bytes: &mut [u8]) {
    for index in (4..bytes.len()).rev() {
        bytes[index] ^= bytes[index - 4];
    }
}

fn seal_gcm(key: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).ok();
    let cipher = Aes128Gcm::new(key.into());
    let sealed = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plain).expect("aes-gcm");
    let mut out = Vec::with_capacity(12 + sealed.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend(sealed);
    out
}

fn open_gcm(key: &[u8; 16], packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 28 {
        return None;
    }
    let cipher = Aes128Gcm::new(key.into());
    cipher.decrypt(Nonce::from_slice(&packet[..12]), &packet[12..]).ok()
}

fn dns_query(domain: &str) -> Option<Vec<u8>> {
    let mut name = Vec::new();
    pack_domain(&format!("{domain}."), &mut name)?;
    let mut header = Vec::with_capacity(12 + name.len() + 4);
    header.extend_from_slice(&0u16.to_be_bytes());
    header.extend_from_slice(&0x0100u16.to_be_bytes());
    header.extend_from_slice(&1u16.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes());
    header.extend(name);
    header.extend_from_slice(&1u16.to_be_bytes());
    header.extend_from_slice(&1u16.to_be_bytes());
    Some(header)
}

fn pack_domain(name: &str, out: &mut Vec<u8>) -> Option<()> {
    let bytes = name.as_bytes();
    let mut label = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index += 1;
                if index >= bytes.len() {
                    return None;
                }
            }
            b'.' => {
                let len = index - label;
                if len >= 64 {
                    return None;
                }
                out.push(len as u8);
                out.extend_from_slice(&bytes[label..index]);
                label = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    out.push(0);
    Some(())
}

pub struct KcpIo {
    core: Arc<KcpCore>,
    timeout_ms: std::sync::atomic::AtomicU64,
}

struct KcpCore {
    socket: Arc<dyn crate::finalmask::PacketIo>,
    peer: std::net::SocketAddr,
    session: Mutex<Session>,
    mask: Mutex<KcpMask>,
    ready: Condvar,
}

impl KcpCore {
    fn send(&self, packets: Vec<Vec<u8>>) {
        for packet in packets {
            let dressed = self.mask.lock().expect("kcp").seal(&packet);
            if let Err(error) = self.socket.send_to(&dressed, self.peer) {
                if !matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) {
                    self.session.lock().expect("kcp").abort();
                    self.ready.notify_all();
                    break;
                }
            }
        }
    }

    fn receive(self: Arc<Self>) {
        let mut buf = [0u8; 65535];
        loop {
            let packets = self.session.lock().expect("kcp").poll();
            self.send(packets);
            if self.session.lock().expect("kcp").terminated() {
                self.ready.notify_all();
                break;
            }
            match self.socket.recv_from(&mut buf) {
                Ok((n, peer)) if peer == self.peer => {
                    let plain = self.mask.lock().expect("kcp").open(&buf[..n]);
                    if let Some(plain) = plain {
                        let packets = self.session.lock().expect("kcp").input(&plain);
                        self.send(packets);
                        self.ready.notify_all();
                    }
                }
                Ok(_) => {},
                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => {},
                Err(_) => {
                    self.session.lock().expect("kcp").abort();
                    self.ready.notify_all();
                    break;
                }
            }
        }
    }
}

impl KcpIo {
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> { Ok(self.core.peer) }
    pub fn dial(host: &str, port: u16) -> std::io::Result<Self> {
        Self::dial_with(host, port, KcpMask::none())
    }

    pub fn dial_with(host: &str, port: u16, mask: KcpMask) -> std::io::Result<Self> {
        Self::dial_masked(host, port, mask, &crate::finalmask::FinalMask::default())
    }

    pub fn dial_masked(host: &str, port: u16, mask: KcpMask, final_masks: &crate::finalmask::FinalMask) -> std::io::Result<Self> {
        let peer = (host, port).to_socket_addrs()?.next().ok_or_else(|| std::io::Error::other("KCP peer has no address"))?;
        let options = KcpOptions::default();
        let socket = final_masks.udp_client(peer, move |peer| {
            let socket = UdpSocket::bind(if peer.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })?;
            socket.set_read_timeout(Some(options.poll_interval()))?;
            socket.set_write_timeout(Some(Duration::from_millis(200)))?;
            Ok(Arc::new(socket))
        })?;
        Self::from_packets(socket, peer, mask, options)
    }

    pub fn connect(host: &str, port: u16, conv: u16) -> std::io::Result<Self> {
        Self::connect_with(host, port, conv, KcpMask::none())
    }

    pub fn connect_with(host: &str, port: u16, conv: u16, mask: KcpMask) -> std::io::Result<Self> {
        let peer = (host, port).to_socket_addrs()?.next().ok_or_else(|| std::io::Error::other("KCP peer has no address"))?;
        let socket = UdpSocket::bind(if peer.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })?;
        socket.connect(peer)?;
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        socket.set_write_timeout(Some(Duration::from_millis(200)))?;
        Self::from_socket_with(socket, conv, mask)
    }

    pub fn from_socket(socket: UdpSocket, conv: u16) -> std::io::Result<Self> {
        Self::from_socket_with(socket, conv, KcpMask::none())
    }

    pub fn from_socket_with(socket: UdpSocket, conv: u16, mask: KcpMask) -> std::io::Result<Self> {
        let peer = socket.peer_addr()?;
        let options = KcpOptions::default();
        socket.set_read_timeout(Some(options.poll_interval())).ok();
        socket.set_write_timeout(Some(Duration::from_millis(200))).ok();
        Ok(Self::start(Arc::new(socket), peer, conv, mask, options))
    }

    pub fn from_packets(socket: Arc<dyn crate::finalmask::PacketIo>, peer: std::net::SocketAddr, mask: KcpMask, options: KcpOptions) -> std::io::Result<Self> {
        let mut bytes = [0u8; 2];
        getrandom::getrandom(&mut bytes).map_err(|error| std::io::Error::other(error.to_string()))?;
        let conv = u16::from_be_bytes(bytes).max(1);
        Ok(Self::start(socket, peer, conv, mask, options))
    }

    fn start(socket: Arc<dyn crate::finalmask::PacketIo>, peer: std::net::SocketAddr, conv: u16, mask: KcpMask, options: KcpOptions) -> Self {
        let core = Arc::new(KcpCore {
            socket, peer,
            session: Mutex::new(Session::with_options(conv, options)),
            mask: Mutex::new(mask),
            ready: Condvar::new(),
        });
        let worker = core.clone();
        std::thread::spawn(move || worker.receive());
        Self { core, timeout_ms: std::sync::atomic::AtomicU64::new(10_000) }
    }

    pub fn set_timeout(&self, timeout: Duration) {
        self.timeout_ms.store(timeout.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn pull(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        let deadline = Instant::now() + Duration::from_millis(self.timeout_ms.load(std::sync::atomic::Ordering::Relaxed));
        let mut session = self.core.session.lock().expect("kcp");
        loop {
            let n = session.read(buf);
            if n > 0 { return Ok(n); }
            if session.read_closed() { return Ok(0); }
            let wait = deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() { return Err(std::io::ErrorKind::WouldBlock.into()); }
            session = self.core.ready.wait_timeout(session, wait).expect("kcp").0;
        }
    }

    pub fn push(&self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        let deadline = Instant::now() + Duration::from_millis(self.timeout_ms.load(std::sync::atomic::Ordering::Relaxed));
        let mut session = self.core.session.lock().expect("kcp");
        loop {
            if session.write_closed() { return Err(std::io::ErrorKind::BrokenPipe.into()); }
            let (accepted, packets) = session.write(buf);
            if accepted != 0 {
                drop(session);
                self.core.send(packets);
                return Ok(accepted);
            }
            if !packets.is_empty() {
                drop(session);
                self.core.send(packets);
                session = self.core.session.lock().expect("kcp");
                continue;
            }
            let wait = deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() { return Err(std::io::ErrorKind::WouldBlock.into()); }
            session = self.core.ready.wait_timeout(session, wait).expect("kcp").0;
        }
    }
}

impl Drop for KcpIo {
    fn drop(&mut self) { self.core.session.lock().expect("kcp").close(); }
}

impl Read for KcpIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.pull(buf) }
}

impl Write for KcpIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.push(buf) }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn options(json: &str) -> KcpOptions {
        KcpOptions::from_settings(|key| (key == "kcpSettings").then_some(json)).unwrap()
    }

    #[test]
    fn mtu_tti_capacities_and_multiplier_change_wire_flights() {
        let opts = options(r#"{"mtu":100,"tti":10,"uplinkCapacity":0,"downlinkCapacity":0,"cwndMultiplier":2}"#);
        let mut sender = Session::with_options(7, opts);
        let mut receiver = Session::with_options(7, opts);
        let now = Instant::now();
        let data: Vec<_> = (0..82 * 41).map(|i| (i % 251) as u8).collect();
        let (accepted, packets) = sender.write_at(&data, now);
        assert_eq!(accepted, data.len());
        assert_eq!(packets.len(), 16);
        assert!(packets.iter().all(|packet| packet.len() == 100));
        assert_eq!(
            packets.iter().flat_map(|packet| packet[18..].iter().copied()).collect::<Vec<_>>(),
            data[..82 * 16],
        );
        assert!(sender.poll_at(now + Duration::from_millis(9)).is_empty());
        let next = sender.poll_at(now + Duration::from_millis(10));
        assert_eq!(next.len(), 16);
        assert_eq!(u32::from_be_bytes(next[0][8..12].try_into().unwrap()), 16);

        let ack = receiver.input_at(&packets[0], now).remove(0);
        assert_eq!(u32::from_be_bytes(ack[4..8].try_into().unwrap()), 8);
        for packet in &packets[1..8] {
            assert_eq!(receiver.input_at(packet, now).len(), 1);
        }
        assert!(receiver.input_at(&packets[8], now).is_empty());
        let mut read = [0; 82 * 8];
        assert_eq!(receiver.read(&mut read), read.len());
        assert_eq!(read, data[..read.len()]);
        let update = receiver.poll_at(now).remove(0);
        assert_eq!(u32::from_be_bytes(update[4..8].try_into().unwrap()), 16);
    }

    #[test]
    fn sending_window_accounts_for_queued_and_outstanding_bytes() {
        let opts = options(r#"{"mtu":100,"tti":20,"maxSendingWindow":200}"#);
        let mut sender = Session::with_options(7, opts);
        let now = Instant::now();
        let (accepted, packets) = sender.write_at(&[0; 300], now);
        // The Xray sender admits one packet when its queue is at the configured quotient.
        assert_eq!(accepted, 3 * 82);
        assert_eq!(packets.len(), 3);
        assert_eq!(sender.write_at(&[0; 12], now).0, 0);
        sender.input_at(&encode_ack(7, 1, 64, &[]), now);
        let (accepted, packets) = sender.write_at(&[0; 12], now);
        assert_eq!(accepted, 12);
        assert!(packets.is_empty());
        let packets = sender.poll_at(now + opts.interval());
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0][18..], &[0; 12]);
    }

    #[test]
    fn minimum_mtu_limits_ack_entries_to_one() {
        let mut receiver = Session::with_options(7, options(r#"{"mtu":21}"#));
        let mut input = Vec::new();
        for sequence in 0..8 {
            input.extend(encode_data(7, sequence, 0, b"x"));
        }
        let replies = receiver.input(&input);
        assert_eq!(replies.len(), 8);
        assert!(replies.iter().all(|ack| ack.len() == 21 && ack[16] == 1));
    }

    #[test]
    fn retransmit_loss_reduces_the_next_flight_budget() {
        let opts = options(r#"{"mtu":1000,"tti":20,"uplinkCapacity":1,"cwndMultiplier":2}"#);
        assert_eq!(opts.send_flight, 20);
        let mut sender = Session::with_options(7, opts);
        let now = Instant::now();
        sender.input_at(&encode_ack(7, 0, 100, &[]), now);
        let (_, first) = sender.write_at(&vec![0; 982 * 90], now);
        assert_eq!(first.len(), 40);
        let retried = sender.poll_at(now + Duration::from_millis(100));
        assert_eq!(retried.len(), 40);
        assert_eq!(sender.control_window, 16);
        let next = sender.poll_at(now + Duration::from_millis(120));
        assert_eq!(next.len(), 32);
        assert_eq!(u32::from_be_bytes(next[0][8..12].try_into().unwrap()), 40);
    }

    #[test]
    fn receive_window_moves_past_the_first_flight() {
        let mut receiver = Session::new(7);
        for sn in 0..300 {
            let replies = receiver.input(&encode_data(7, sn, 0, b"x"));
            let ack = &replies[0];
            let next = u32::from_be_bytes(ack[8..12].try_into().unwrap());
            let edge = u32::from_be_bytes(ack[4..8].try_into().unwrap());
            assert!(edge.wrapping_sub(next) > 0, "peer cannot send after sequence {sn}: next={next}, edge={edge}");
            assert_eq!(receiver.read(&mut [0]), 1);
        }
    }

    #[test]
    fn incoming_sender_progress_does_not_ack_our_lost_packet() {
        let mut local = Session::new(7);
        let lost = local.write(b"must retransmit").1;
        local.input(&encode_data(7, 0, 100, b"independent peer bytes"));
        assert_eq!(local.retransmit(), lost, "peer SendingNext erased our undelivered bytes");
    }

    #[test]
    fn lost_final_ack_is_recovered_by_duplicate_data() {
        let mut sender = Session::new(7);
        let mut receiver = Session::new(7);
        let packet = sender.write(b"last").1.remove(0);
        let _lost_ack = receiver.input(&packet);
        assert_eq!(receiver.read(&mut [0; 4]), 4);
        for reply in receiver.input(&packet) { sender.input(&reply); }
        assert!(sender.retransmit().is_empty(), "duplicate last packet was never acknowledged");
    }

    #[test]
    fn unread_data_does_not_expand_the_receive_window() {
        let mut receiver = Session::new(7);
        let window = receiver.options.receive_window;
        for sn in 0..window {
            receiver.input(&encode_data(7, sn, 0, b"x"));
        }
        assert!(receiver.input(&encode_data(7, window, 0, b"overflow")).is_empty());
        let mut bytes = vec![0; window as usize];
        assert_eq!(receiver.read(&mut bytes), window as usize);
        let update = receiver.poll().remove(0);
        assert_eq!(u32::from_be_bytes(update[4..8].try_into().unwrap()), 2 * window);
    }

    #[test]
    fn timers_send_heartbeat_and_close_without_application_io() {
        let mut local = Session::new(7);
        let mut peer = Session::new(7);
        local.last_ping -= Duration::from_secs(4);
        let heartbeat = local.poll();
        assert!(heartbeat.iter().any(|packet| packet[2] == PING));
        for packet in heartbeat { peer.input(&packet); }
        local.close();
        let terminate = local.poll().remove(0);
        assert_eq!(terminate[2], TERMINATE);
        for reply in peer.input(&terminate) { local.input(&reply); }
        assert!(local.read_closed());
        assert!(peer.read_closed());
    }

    #[test]
    fn close_option_does_not_overtake_reordered_final_bytes() {
        let mut receiver = Session::new(7);
        let mut closing_ack = receiver.ack(&[]);
        closing_ack[3] = CLOSE;
        receiver.input(&closing_ack);
        assert!(!receiver.read_closed(), "close option overtook the final DATA");
        assert!(receiver.write_closed());
        receiver.input(&encode_data(7, 0, 0, b"final reply"));
        let terminator = Session::new(7).command(TERMINATE);
        receiver.input(&terminator);
        let mut got = [0; 11];
        assert_eq!(receiver.read(&mut got), got.len());
        assert_eq!(&got, b"final reply");
        assert!(receiver.read_closed());
    }

    #[test]
    fn lost_window_update_is_repeated_without_new_application_io() {
        let mut sender = Session::new(7);
        let mut receiver = Session::new(7);
        let window = receiver.options.receive_window;
        let tick = sender.options.interval();
        let start = Instant::now();
        for step in 0..window {
            let now = start + tick * step;
            for packet in sender.write_at(b"x", now).1 {
                for ack in receiver.input_at(&packet, now) { sender.input_at(&ack, now); }
            }
        }
        let now = start + tick * window;
        assert!(sender.write_at(b"blocked", now).1.iter().all(|packet| packet[2] != DATA));
        assert_eq!(receiver.read(&mut [0; 128]), 128);
        let _lost_update = receiver.poll_at(now);
        let later = now + Duration::from_secs(4);
        for packet in receiver.poll_at(later) { sender.input_at(&packet, later); }
        assert!(sender.poll_at(later).iter().any(|packet| packet[2] == DATA), "lost update permanently closed the window");
    }

    #[test]
    fn duplex_bytes_survive_loss_reordering_and_multiple_windows() {
        let expected_a: Vec<_> = (0..600_000).map(|i| (i % 251) as u8).collect();
        let expected_b: Vec<_> = (0..700_000).map(|i| (i % 239) as u8).collect();
        let mut peers = [Session::new(7), Session::new(7)];
        let inputs = [&expected_a, &expected_b];
        let mut sent = [0usize; 2];
        let mut received = [Vec::new(), Vec::new()];
        let mut dropped = std::collections::HashSet::new();
        let start = Instant::now();
        for turn in 0..4000 {
            let now = start + Duration::from_millis(turn * 50);
            let mut network = [Vec::new(), Vec::new()];
            for side in 0..2 {
                let (accepted, packets) = peers[side].write_at(&inputs[side][sent[side]..], now);
                sent[side] += accepted;
                network[side] = packets;
                network[side].reverse();
            }
            for side in 0..2 {
                for packet in &network[side] {
                    if packet[2] == DATA {
                        let sn = u32::from_be_bytes(packet[8..12].try_into().unwrap());
                        if sn % 13 == 4 && dropped.insert((side, sn)) { continue; }
                    }
                    for reply in peers[1 - side].input_at(packet, now) {
                        if turn % 7 != 0 { peers[side].input_at(&reply, now); }
                    }
                }
            }
            for side in 0..2 {
                let mut buf = [0; 8192];
                let n = peers[side].read(&mut buf);
                received[side].extend_from_slice(&buf[..n]);
            }
            if received[0].len() == expected_b.len() && received[1].len() == expected_a.len() { break; }
        }
        assert_eq!(received[0], expected_b);
        assert_eq!(received[1], expected_a);
    }

    #[test]
    fn segments_carry_bytes_over_udp() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, peer) = listener.recv_from(&mut buf).unwrap();
            let conv = u16::from_be_bytes([buf[0], buf[1]]);
            listener.connect(peer).unwrap();
            let mut io = KcpIo::from_socket(listener, conv).unwrap();
            {
                let mut session = io.core.session.lock().unwrap();
                let replies = session.input(&buf[..n]);
                drop(session);
                for reply in replies {
            io.core.socket.send_to(&reply, io.core.peer).unwrap();
                }
            }
            let mut got = [0u8; 4];
            assert_eq!(io.read(&mut got).unwrap(), 4);
            assert_eq!(&got, b"ping");
            assert_eq!(io.write(b"pong").unwrap(), 4);
        });
        let mut io = KcpIo::connect("127.0.0.1", port, 7).unwrap();
        assert_eq!(io.write(b"ping").unwrap(), 4);
        let mut got = [0u8; 4];
        assert_eq!(io.read(&mut got).unwrap(), 4);
        assert_eq!(&got, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn srtp_and_seed_roundtrip() {
        let mut mask = kcp_mask("srtp", "", "secret").unwrap();
        let sealed = mask.seal(b"segment");
        assert_eq!(&sealed[..4], &[0, 0, 0, 1]);
        let opened = KcpMask::none().header_size();
        assert_eq!(opened, 0);
        let plain = kcp_mask("srtp", "", "secret").unwrap().open(&sealed).unwrap();
        assert_eq!(plain, b"segment");
        let mut wechat = kcp_mask("wechat", "", "").unwrap();
        let packet = wechat.seal(b"k");
        assert_eq!(&packet[..13], &[0xa1, 0x08, 0, 0, 0, 1, 0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
        let mut dtls = kcp_mask("dtls", "", "").unwrap();
        let packet = dtls.seal(b"k");
        assert_eq!(packet[0], 23);
        assert_eq!(&packet[1..3], &[254, 253]);
        assert_eq!(kcp_mask("dns", "", "").unwrap().header_size(), kcp_mask("dns", "www.baidu.com", "").unwrap().header_size());
        assert!(kcp_mask("nope", "", "").is_none());
        let mut original = kcp_mask("original", "", "ignored").unwrap();
        let sealed = original.seal(b"segment");
        assert_eq!(sealed.len(), b"segment".len() + 6);
        assert_ne!(&sealed[6..], b"segment");
        assert_eq!(kcp_mask("original", "", "").unwrap().open(&sealed).unwrap(), b"segment");
        sealed_flip(&sealed);
    }

    fn sealed_flip(sealed: &[u8]) {
        let mut broken = sealed.to_vec();
        broken[6] ^= 1;
        assert!(kcp_mask("original", "", "").unwrap().open(&broken).is_none());
    }
}
