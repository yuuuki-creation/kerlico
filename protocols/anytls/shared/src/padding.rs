//! The padding scheme, parsed the way mihomo's `transport/anytls/padding` and `util.StringMap` do.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use md5::{Digest, Md5};

/// mihomo 1.19.33 `padding.DefaultPaddingScheme`, byte for byte.
pub const DEFAULT_SCHEME: &[u8] = b"stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

/// One entry of a packet's size list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Size {
    /// A record of this many bytes. `Range(n, n)` is a fixed size.
    Range(i64, i64),
    /// `c`: stop padding this packet if no payload is left.
    Check,
}

/// A parsed scheme. `raw` is what the server sends in `cmdUpdatePaddingScheme`; `md5` is the
/// lowercase hex digest the client sends in its settings.
#[derive(Debug)]
pub struct Scheme {
    raw: Vec<u8>,
    md5: String,
    stop: u32,
    packets: HashMap<u32, Vec<Size>>,
}

impl Scheme {
    /// `None` where mihomo's `NewPaddingFactory` returns nil: no `k=v` line at all, or a `stop`
    /// that `strconv.Atoi` rejects.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let map = string_map(raw);
        if map.is_empty() {
            return None;
        }
        let stop = go_atoi(map.get("stop")?)? as u32;
        let mut packets = HashMap::new();
        for (key, value) in &map {
            // Go looks the list up by `strconv.Itoa(int(pkt))`, so only the canonical decimal of a
            // u32 can ever match.
            let Ok(pkt) = key.parse::<u32>() else { continue };
            if pkt.to_string() != *key {
                continue;
            }
            packets.insert(pkt, sizes(value));
        }
        Some(Self {
            raw: raw.to_vec(),
            md5: hex(&Md5::digest(raw)),
            stop,
            packets,
        })
    }

    pub fn default_scheme() -> Self {
        Self::parse(DEFAULT_SCHEME).expect("default padding scheme")
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn md5(&self) -> &str {
        &self.md5
    }

    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// The size list of packet `pkt` without drawing random numbers.
    pub fn template(&self, pkt: u32) -> &[Size] {
        self.packets.get(&pkt).map(Vec::as_slice).unwrap_or(&[])
    }

    /// `GenerateRecordPayloadSizes`: a size is `min + rand[0, max-min)`, so `max` itself is never
    /// drawn unless `min == max`. `CHECK` stands for `c`.
    pub fn record_sizes(&self, pkt: u32, out: &mut Vec<i64>) {
        out.clear();
        for size in self.template(pkt) {
            match *size {
                Size::Range(min, max) if min == max => out.push(min),
                Size::Range(min, max) => out.push(min + random_below((max - min) as u64) as i64),
                Size::Check => out.push(CHECK),
            }
        }
    }
}

/// `padding.CheckMark`.
pub const CHECK: i64 = -1;

/// The scheme a session reads on every padded write. The server replaces the client's copy with
/// `cmdUpdatePaddingScheme`; sessions that are already running see the new one on their next write,
/// as with mihomo's shared `atomic.Pointer`.
#[derive(Clone, Debug)]
pub struct SchemeCell(Arc<Mutex<Arc<Scheme>>>);

impl SchemeCell {
    pub fn new(scheme: Scheme) -> Self {
        Self(Arc::new(Mutex::new(Arc::new(scheme))))
    }

    pub fn load(&self) -> Arc<Scheme> {
        Arc::clone(&self.0.lock().expect("padding"))
    }

    /// `UpdatePaddingScheme`: keeps the old scheme when the new one does not parse.
    pub fn update(&self, raw: &[u8]) -> bool {
        match Scheme::parse(raw) {
            Some(scheme) => {
                *self.0.lock().expect("padding") = Arc::new(scheme);
                true
            }
            None => false,
        }
    }
}

/// `util.StringMapFromBytes`: lines split on `\n`, each split once on `=`, later keys win.
pub fn string_map(bytes: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut map = HashMap::new();
    for line in text.split('\n') {
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

fn sizes(value: &str) -> Vec<Size> {
    let mut list = Vec::new();
    for range in value.split(',') {
        let bounds: Vec<&str> = range.split('-').collect();
        if bounds.len() == 2 {
            let (Some(mut min), Some(mut max)) = (go_atoi(bounds[0]), go_atoi(bounds[1])) else {
                continue;
            };
            if min > max {
                std::mem::swap(&mut min, &mut max);
            }
            if min <= 0 || max <= 0 {
                continue;
            }
            list.push(Size::Range(min, max));
        } else if range == "c" {
            list.push(Size::Check);
        }
    }
    list
}

/// `strconv.ParseInt(s, 10, 64)`, which is also what `Atoi` accepts on 64-bit Go: one optional sign,
/// then at least one ASCII digit, no spaces, no overflow.
pub fn go_atoi(text: &str) -> Option<i64> {
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'+') => (false, &text[1..]),
        Some(b'-') => (true, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut value: i64 = 0;
    for byte in digits.bytes() {
        let digit = i64::from(byte - b'0');
        value = if negative {
            value.checked_mul(10)?.checked_sub(digit)?
        } else {
            value.checked_mul(10)?.checked_add(digit)?
        };
    }
    Some(value)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)] as char);
        text.push(DIGITS[usize::from(byte & 15)] as char);
    }
    text
}

/// Uniform in `[0, bound)` from the system generator, like `crypto/rand.Int`.
fn random_below(bound: u64) -> u64 {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let zone = u64::MAX - u64::MAX % bound;
    loop {
        let mut bytes = [0u8; 8];
        rng.fill(&mut bytes).expect("system random");
        let value = u64::from_le_bytes(bytes);
        if value < zone {
            return value % bound;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_matches_the_go_digest_and_lists() {
        let scheme = Scheme::default_scheme();
        // `fmt.Sprintf("%x", md5.Sum(padding.DefaultPaddingScheme))` printed by Go 1.27 on perf-02.
        assert_eq!(scheme.md5(), crate::vectors::DEFAULT_MD5);
        assert_eq!(scheme.stop(), 8);
        assert_eq!(scheme.template(0), &[Size::Range(30, 30)]);
        assert_eq!(
            scheme.template(2),
            &[
                Size::Range(400, 500),
                Size::Check,
                Size::Range(500, 1000),
                Size::Check,
                Size::Range(500, 1000),
                Size::Check,
                Size::Range(500, 1000),
                Size::Check,
                Size::Range(500, 1000)
            ]
        );
        assert_eq!(scheme.template(3), &[Size::Range(9, 9), Size::Range(500, 1000)]);
        assert!(scheme.template(8).is_empty());
    }

    #[test]
    fn sizes_stay_inside_the_half_open_range() {
        let scheme = Scheme::parse(b"stop=3\n1=10-12\n2=5-5,c").unwrap();
        let mut out = Vec::new();
        for _ in 0..500 {
            scheme.record_sizes(1, &mut out);
            assert_eq!(out.len(), 1);
            assert!((10..12).contains(&out[0]), "{out:?}");
        }
        scheme.record_sizes(2, &mut out);
        assert_eq!(out, vec![5, CHECK]);
    }

    #[test]
    fn parse_follows_go_string_map_and_atoi() {
        assert!(Scheme::parse(b"").is_none());
        assert!(Scheme::parse(b"no equals").is_none());
        assert!(Scheme::parse(b"1=10-20").is_none(), "stop is required");
        assert!(Scheme::parse(b"stop= 8").is_none(), "Atoi does not trim");
        assert_eq!(Scheme::parse(b"stop=+8").unwrap().stop(), 8);
        assert_eq!(Scheme::parse(b"stop=-1").unwrap().stop(), u32::MAX);
        let scheme = Scheme::parse(b"stop=9\n1=7-3,x,c,0-5,-2-4,5-5-5,c\n01=1-1\n1=20-30\r").unwrap();
        // The later `1=` line wins, and `30\r` is not a number.
        assert!(scheme.template(1).is_empty());
        let scheme = Scheme::parse(b"stop=9\n1=7-3,x,c,0-5,5-5-5,c\n01=1-1").unwrap();
        assert_eq!(scheme.template(1), &[Size::Range(3, 7), Size::Check, Size::Check]);
        assert_eq!(go_atoi("9223372036854775807"), Some(i64::MAX));
        assert_eq!(go_atoi("9223372036854775808"), None);
        assert_eq!(go_atoi("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(go_atoi("1_0"), None);
    }

    #[test]
    fn update_keeps_the_old_scheme_on_garbage() {
        let cell = SchemeCell::new(Scheme::default_scheme());
        assert!(!cell.update(b"garbage"));
        assert_eq!(cell.load().md5(), crate::vectors::DEFAULT_MD5);
        assert!(cell.update(b"stop=1"));
        assert_eq!(cell.load().stop(), 1);
    }
}
