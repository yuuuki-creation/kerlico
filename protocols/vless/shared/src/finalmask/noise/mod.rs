mod script;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::Value;

use super::{decode_bytes, invalid, settings, PacketIo, Range};

const VALUE_LIMIT: usize = 65535;
const UDP_LIMIT: usize = 65_507;
const MAX_PEERS: usize = 4096;

#[derive(Clone)]
pub(super) struct Noise {
    reset: Range,
    plan: Plan,
}

#[derive(Clone)]
enum Plan {
    Items(Arc<[Item]>),
    Script(Arc<Mutex<script::Script>>),
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    reset: Range,
    noise: Vec<RawItem>,
    script: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct RawItem {
    rand: Range,
    rand_range: Option<Range>,
    #[serde(rename = "type")]
    kind: String,
    packet: Value,
    delay: Range,
}

struct Item {
    segments: Vec<Segment>,
    delay: Range,
}

enum Segment {
    Bytes(Vec<u8>),
    Random { size: Range, values: Range, inclusive: bool },
    Ascii(Range, &'static [u8]),
    Timestamp,
    Counter,
    Nonce,
}

impl Noise {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        let config: Config = settings(value)?;
        let plan = if config.script.is_empty() {
            Plan::Items(config.noise.into_iter().map(RawItem::build).collect::<io::Result<_>>()?)
        } else {
            if !config.noise.is_empty() {
                return Err(invalid("noise script cannot be combined with noise items"));
            }
            Plan::Script(Arc::new(Mutex::new(script::Script::load(&config.script)?)))
        };
        Ok(Self { reset: config.reset, plan })
    }

    pub(super) fn wrap(&self, inner: Arc<dyn PacketIo>) -> Arc<dyn PacketIo> {
        Arc::new(Packets { inner, config: self.clone(), state: Mutex::new(State::default()) })
    }
}

impl RawItem {
    fn build(self) -> io::Result<Item> {
        if !self.packet.is_null() && self.rand.max > 0 {
            return Err(invalid("noise item accepts packet or rand"));
        }
        let segments = if self.kind.eq_ignore_ascii_case("exp") {
            expression(self.packet.as_str().ok_or_else(|| invalid("noise expression must be a string"))?)?
        } else if self.rand.max > 0 {
            let values = self.rand_range.unwrap_or(Range { min: 0, max: 255 });
            if values.max > 255 {
                return Err(invalid("noise randRange exceeds a byte"));
            }
            vec![Segment::Random { size: self.rand, values, inclusive: false }]
        } else {
            if self.rand_range.is_some_and(|range| range.max > 255) {
                return Err(invalid("noise randRange exceeds a byte"));
            }
            vec![Segment::Bytes(decode_bytes(self.packet, &self.kind)?)]
        };
        if segments.iter().map(Segment::max_len).sum::<usize>() > VALUE_LIMIT {
            return Err(invalid("noise packet exceeds 65535 bytes"));
        }
        Ok(Item { segments, delay: self.delay })
    }
}

fn expression(mut input: &str) -> io::Result<Vec<Segment>> {
    let mut parts = Vec::new();
    loop {
        input = input.trim_start();
        if input.is_empty() {
            if parts.is_empty() {
                return Err(invalid("empty noise expression"));
            }
            return Ok(parts);
        }
        let (tag, remaining) = input.strip_prefix('<').and_then(|text| text.split_once('>'))
            .ok_or_else(|| invalid("invalid noise expression tag"))?;
        input = remaining;
        let tag = tag.trim();
        let (kind, argument) = tag.split_once(char::is_whitespace).map_or((tag, ""), |(kind, arg)| (kind, arg.trim()));
        let size = || {
            if argument.is_empty() {
                return Err(invalid("noise expression random tag needs a length"));
            }
            if let Some((left, right)) = argument.split_once('-') {
                if left.parse::<u32>().map_err(invalid)? > right.parse::<u32>().map_err(invalid)? {
                    return Err(invalid("reversed noise expression length"));
                }
            }
            Range::parse(argument)
        };
        let segment = match kind {
            "b" => {
                let hex: String = argument.chars().filter(|ch| !ch.is_whitespace()).collect();
                let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(&hex);
                if hex.is_empty() {
                    return Err(invalid("empty noise expression bytes"));
                }
                Segment::Bytes(decode_bytes(Value::String(hex.to_owned()), "hex")?)
            }
            "r" => Segment::Random { size: size()?, values: Range { min: 0, max: 255 }, inclusive: true },
            "rc" => Segment::Ascii(size()?, b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "rd" => Segment::Ascii(size()?, b"0123456789"),
            "t" if argument.is_empty() => Segment::Timestamp,
            "c" if argument.is_empty() => Segment::Counter,
            "n" if argument.is_empty() => Segment::Nonce,
            _ => return Err(invalid(format!("invalid noise expression tag {tag:?}"))),
        };
        parts.push(segment);
    }
}

impl Segment {
    fn max_len(&self) -> usize {
        match self {
            Self::Bytes(data) => data.len(),
            Self::Random { size, .. } | Self::Ascii(size, _) => size.max as usize,
            Self::Timestamp | Self::Counter => 4,
            Self::Nonce => 8,
        }
    }

    fn append(&self, out: &mut Vec<u8>, counter: &mut u32) -> io::Result<()> {
        match self {
            Self::Bytes(data) => out.extend_from_slice(data),
            Self::Timestamp => {
                let seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                out.extend_from_slice(&(seconds as u32).to_be_bytes());
            }
            Self::Counter => {
                *counter = counter.wrapping_add(1);
                out.extend_from_slice(&counter.to_be_bytes());
            }
            Self::Nonce => { random_bytes(out, 8)?; }
            Self::Random { size, values, inclusive } => {
                let size = if *inclusive { size.pick_inclusive() } else { size.pick() };
                let bytes = random_bytes(out, size as usize)?;
                let width = values.max - values.min + 1;
                if width < 256 {
                    for byte in bytes {
                        *byte = (values.min + (u32::from(*byte) % width)) as u8;
                    }
                }
            }
            Self::Ascii(size, alphabet) => {
                for byte in random_bytes(out, size.pick_inclusive() as usize)? {
                    *byte = alphabet[usize::from(*byte) % alphabet.len()];
                }
            }
        }
        Ok(())
    }
}

fn random_bytes(out: &mut Vec<u8>, len: usize) -> io::Result<&mut [u8]> {
    let start = out.len();
    out.resize(start + len, 0);
    let bytes = &mut out[start..];
    OsRng.try_fill_bytes(bytes).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(bytes)
}

#[derive(Default)]
struct State {
    last: HashMap<SocketAddr, Instant>,
    counter: u32,
}

struct Packets {
    inner: Arc<dyn PacketIo>,
    config: Noise,
    state: Mutex<State>,
}

impl Packets {
    fn noise(&self, peer: SocketAddr, counter: &mut u32) {
        let send = |packet: &[u8], delay| {
            if packet.len() <= UDP_LIMIT {
                // Cover traffic is best effort, as in Xray. The real datagram
                // still reports its own send error to the transport.
                let _ = self.inner.send_to(packet, peer);
            }
            std::thread::sleep(delay);
        };
        match &self.config.plan {
            Plan::Items(items) => {
                let mut wire = Vec::new();
                for item in items.iter() {
                    wire.clear();
                    if item.segments.iter().try_for_each(|part| part.append(&mut wire, counter)).is_ok() {
                        send(&wire, Duration::from_millis(u64::from(item.delay.pick())));
                    }
                }
            }
            Plan::Script(engine) => {
                let result = engine.lock().expect("noise Lua engine").packets(peer);
                match result {
                    Ok(packets) => {
                        for (packet, delay) in packets {
                            send(&packet, delay);
                        }
                    }
                    Err(error) => eprintln!("finalmask noise script: {error}"),
                }
            }
        }
    }
}

impl PacketIo for Packets {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(out)
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        let mut state = self.state.lock().expect("noise UDP state");
        let reset = self.config.reset;
        let now = Instant::now();
        let first = state.last.get(&peer).is_none_or(|expiry| reset.max > 0 && *expiry < now);
        if first {
            self.noise(peer, &mut state.counter);
        }
        if state.last.len() >= MAX_PEERS && !state.last.contains_key(&peer) {
            if let Some(oldest) = state.last.iter().min_by_key(|(_, time)| *time).map(|(peer, _)| *peer) {
                state.last.remove(&oldest);
            }
        }
        state.last.insert(peer, Instant::now() + Duration::from_secs(u64::from(reset.pick())));
        self.inner.send_to(packet, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn emits_each_cover_packet_before_the_first_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let config = Noise::parse(serde_json::json!({
            "noise": [
                {"type": "exp", "packet": "<b 16 03 01><c>"},
                {"rand": 3, "randRange": "33-33"}
            ]
        })).unwrap();
        let wrapped = config.wrap(sender);
        let peer = receiver.local_addr().unwrap();
        wrapped.send_to(b"payload", peer).unwrap();
        wrapped.send_to(b"next", peer).unwrap();
        let mut data = [0; 32];
        for expected in [&[0x16, 0x03, 0x01, 0, 0, 0, 1][..], &b"!!!"[..], &b"payload"[..], &b"next"[..]] {
            let (len, _) = receiver.recv_from(&mut data).unwrap();
            assert_eq!(&data[..len], expected);
        }
    }
}
