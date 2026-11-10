//! Xray `h2Params`: a Go `net/http.HTTP2Config` JSON object applied to the XHTTP HTTP/2 server.

use std::io;
use std::time::Duration;

use serde::de::{Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use crate::http::H2Limits;

const GO_DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(15);

/// Values as Go's `encoding/json` assigns them. Zero is unset, as in Go.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct H2Params {
    max_streams: i64,
    max_frame: i64,
    decoder_table: i64,
    connection_window: i64,
    stream_window: i64,
    send_ping: i64,
    ping_timeout: i64,
    write_timeout: i64,
    pub permit_prohibited_ciphers: bool,
}

struct Pairs(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Pairs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Ordered;
        impl<'de> Visitor<'de> for Ordered {
            type Value = Pairs;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Pairs, A::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = map.next_entry::<String, Value>()? {
                    pairs.push(pair);
                }
                Ok(Pairs(pairs))
            }
        }
        deserializer.deserialize_map(Ordered)
    }
}

/// Go matches keys case-insensitively with Unicode simple folding. Only the two non-ASCII
/// characters that fold into the ASCII field names can matter here.
fn fold(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\u{212a}' => 'k',
            '\u{17f}' => 's',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

fn invalid(key: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("h2Params {key}"))
}

fn integer(key: &str, value: &Value) -> io::Result<Option<i64>> {
    match value {
        Value::Null => Ok(None),
        Value::Number(number) => number.as_i64().map(Some).ok_or_else(|| invalid(key)),
        _ => Err(invalid(key)),
    }
}

impl H2Params {
    pub fn parse(text: &str) -> io::Result<Self> {
        let pairs = serde_json::from_str::<Option<Pairs>>(text)
            .map_err(|_| invalid("object"))?
            .map_or_else(Vec::new, |pairs| pairs.0);
        let mut params = Self::default();
        for (key, value) in &pairs {
            let slot = match fold(key).as_str() {
                "maxconcurrentstreams" => &mut params.max_streams,
                "maxreadframesize" => &mut params.max_frame,
                "maxdecoderheadertablesize" => &mut params.decoder_table,
                "maxreceivebufferperconnection" => &mut params.connection_window,
                "maxreceivebufferperstream" => &mut params.stream_window,
                "sendpingtimeout" => &mut params.send_ping,
                "pingtimeout" => &mut params.ping_timeout,
                "writebytetimeout" => &mut params.write_timeout,
                "maxencoderheadertablesize" => {
                    // Validated like Go. Kerlico's HPACK encoder never indexes a field, so the limit has no effect.
                    integer(key, value)?;
                    continue;
                }
                "permitprohibitedciphersuites" => {
                    match value {
                        Value::Null => {}
                        Value::Bool(permit) => params.permit_prohibited_ciphers = *permit,
                        _ => return Err(invalid(key)),
                    }
                    continue;
                }
                "counterror" => {
                    // The Go field is a func, which JSON cannot fill. Only null decodes.
                    if !value.is_null() {
                        return Err(invalid(key));
                    }
                    continue;
                }
                _ => continue,
            };
            if let Some(number) = integer(key, value)? {
                *slot = number;
            }
        }
        Ok(params)
    }

    /// Go's `http2setConfigDefaults` with Kerlico's own defaults where the value is zero or out of range.
    pub fn limits(&self, header_list: u32) -> H2Limits {
        let mut limits = H2Limits {
            header_list: Some(header_list),
            ..H2Limits::default()
        };
        let streams = self.max_streams as u32;
        if streams >= 1 {
            limits.streams = streams;
        }
        let frame = self.max_frame as u32;
        if (16_384..=16_777_215).contains(&frame) {
            limits.frame_size = frame;
        }
        let table = self.decoder_table as u32;
        if table >= 1 {
            limits.decoder_table = table;
        }
        let connection = self.connection_window as i32;
        if connection >= 65_535 {
            limits.connection_window = connection as u32;
        }
        let stream = self.stream_window as i32;
        if stream >= 1 {
            limits.stream_window = stream as u32;
        }
        if self.send_ping > 0 {
            limits.ping_after = Some(Duration::from_nanos(self.send_ping as u64));
        }
        limits.ping_timeout = if self.ping_timeout >= 1 {
            Duration::from_nanos(self.ping_timeout as u64)
        } else {
            GO_DEFAULT_PING_TIMEOUT
        };
        if self.write_timeout > 0 {
            limits.write_timeout = Some(Duration::from_nanos(self.write_timeout as u64));
        }
        limits
    }
}

/// Go's `http2isBadCipher` list: the RFC 7540 appendix A block list. TLS 1.3 suites are not on it.
const PROHIBITED_CIPHERS: [u16; 276] = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b,
    0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
    0x0018, 0x0019, 0x001a, 0x001b, 0x001e, 0x001f, 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025,
    0x0026, 0x0027, 0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f, 0x0030, 0x0031,
    0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d,
    0x003e, 0x003f, 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0067, 0x0068, 0x0069,
    0x006a, 0x006b, 0x006c, 0x006d, 0x0084, 0x0085, 0x0086, 0x0087, 0x0088, 0x0089, 0x008a, 0x008b,
    0x008c, 0x008d, 0x008e, 0x008f, 0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x00a0, 0x00a1, 0x00a4, 0x00a5, 0x00a6, 0x00a7,
    0x00a8, 0x00a9, 0x00ac, 0x00ad, 0x00ae, 0x00af, 0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5,
    0x00b6, 0x00b7, 0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf, 0x00c0, 0x00c1,
    0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00ff, 0xc001, 0xc002, 0xc003, 0xc004, 0xc005, 0xc006, 0xc007,
    0xc008, 0xc009, 0xc00a, 0xc00b, 0xc00c, 0xc00d, 0xc00e, 0xc00f, 0xc010, 0xc011, 0xc012, 0xc013,
    0xc014, 0xc015, 0xc016, 0xc017, 0xc018, 0xc019, 0xc01a, 0xc01b, 0xc01c, 0xc01d, 0xc01e, 0xc01f,
    0xc020, 0xc021, 0xc022, 0xc023, 0xc024, 0xc025, 0xc026, 0xc027, 0xc028, 0xc029, 0xc02a, 0xc02d,
    0xc02e, 0xc031, 0xc032, 0xc033, 0xc034, 0xc035, 0xc036, 0xc037, 0xc038, 0xc039, 0xc03a, 0xc03b,
    0xc03c, 0xc03d, 0xc03e, 0xc03f, 0xc040, 0xc041, 0xc042, 0xc043, 0xc044, 0xc045, 0xc046, 0xc047,
    0xc048, 0xc049, 0xc04a, 0xc04b, 0xc04c, 0xc04d, 0xc04e, 0xc04f, 0xc050, 0xc051, 0xc054, 0xc055,
    0xc058, 0xc059, 0xc05a, 0xc05b, 0xc05e, 0xc05f, 0xc062, 0xc063, 0xc064, 0xc065, 0xc066, 0xc067,
    0xc068, 0xc069, 0xc06a, 0xc06b, 0xc06e, 0xc06f, 0xc070, 0xc071, 0xc072, 0xc073, 0xc074, 0xc075,
    0xc076, 0xc077, 0xc078, 0xc079, 0xc07a, 0xc07b, 0xc07e, 0xc07f, 0xc082, 0xc083, 0xc084, 0xc085,
    0xc088, 0xc089, 0xc08c, 0xc08d, 0xc08e, 0xc08f, 0xc092, 0xc093, 0xc094, 0xc095, 0xc096, 0xc097,
    0xc098, 0xc099, 0xc09a, 0xc09b, 0xc09c, 0xc09d, 0xc0a0, 0xc0a1, 0xc0a4, 0xc0a5, 0xc0a8, 0xc0a9,
];

/// Go's HTTP/2 server rejects TLS below 1.2 always and a blocked cipher unless permitted.
pub fn h2_tls_rejection(below_tls12: bool, cipher: u16, permit_prohibited: bool) -> Option<String> {
    if below_tls12 {
        return Some("TLS version too low".to_owned());
    }
    if !permit_prohibited && PROHIBITED_CIPHERS.binary_search(&cipher).is_ok() {
        return Some(format!("Prohibited TLS 1.2 Cipher Suite: {cipher:x}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_match_case_insensitively_and_unknown_keys_are_ignored() {
        let params = H2Params::parse(r#"{"maxconcurrentstreams": 7, "MAXREADFRAMESIZE": 32768, "other": [1], "pingtimeout": 5}"#).unwrap();
        let limits = params.limits(8512);
        assert_eq!((limits.streams, limits.frame_size), (7, 32_768));
        assert_eq!(limits.ping_timeout, Duration::from_nanos(5));
    }

    #[test]
    fn last_duplicate_wins_and_null_keeps_the_previous_value() {
        let params = H2Params::parse(r#"{"MaxConcurrentStreams": 3, "maxconcurrentstreams": 9, "MaxConcurrentStreams": null}"#).unwrap();
        assert_eq!(params.limits(1).streams, 9);
    }

    #[test]
    fn go_json_type_errors_reject_the_config() {
        for bad in [
            r#"{"MaxConcurrentStreams": "1"}"#,
            r#"{"MaxConcurrentStreams": 1.5}"#,
            r#"{"MaxConcurrentStreams": 1e3}"#,
            r#"{"SendPingTimeout": true}"#,
            r#"{"PermitProhibitedCipherSuites": 1}"#,
            r#"{"CountError": true}"#,
            r#"[1]"#,
            r#"{"MaxConcurrentStreams": 1"#,
        ] {
            assert!(H2Params::parse(bad).is_err(), "{bad}");
        }
        assert!(H2Params::parse("null").is_ok());
        assert!(H2Params::parse(r#"{"CountError": null, "MaxEncoderHeaderTableSize": 4096}"#).is_ok());
    }

    #[test]
    fn out_of_range_values_fall_back_like_go() {
        let params = H2Params::parse(
            r#"{"MaxConcurrentStreams": 4294967296, "MaxReadFrameSize": 100, "MaxReceiveBufferPerConnection": 100,
                "MaxReceiveBufferPerStream": -5, "PingTimeout": -1, "SendPingTimeout": -1}"#,
        )
        .unwrap();
        assert_eq!(params.limits(1), H2Limits { header_list: Some(1), ..H2Limits::default() });
        let wrapped = H2Params::parse(r#"{"MaxConcurrentStreams": -1}"#).unwrap();
        assert_eq!(wrapped.limits(1).streams, u32::MAX);
    }

    #[test]
    fn blocked_ciphers_follow_the_go_list() {
        assert!(h2_tls_rejection(false, 0x009c, false).is_some());
        assert!(h2_tls_rejection(false, 0x009c, true).is_none());
        assert!(h2_tls_rejection(false, 0xc02f, false).is_none());
        assert!(h2_tls_rejection(false, 0x1301, false).is_none());
        assert!(h2_tls_rejection(true, 0xc02f, true).is_some());
        assert!(PROHIBITED_CIPHERS.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
