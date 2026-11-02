// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/Dictionary.hpp.

/// Reads the `key=value` text format with `\`-escaped values. The first NUL ends the dictionary.
pub(crate) struct Dictionary<'a>(&'a [u8]);

impl<'a> Dictionary<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let end = data
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(data.len());
        Self(&data[..end])
    }

    pub(crate) fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.0
            .split(|byte| *byte == b'\r' || *byte == b'\n')
            .find_map(|line| {
                let value = line.strip_prefix(key.as_bytes())?.strip_prefix(b"=")?;
                Some(unescape(value))
            })
    }

    /// Hexadecimal integers, as `Utils::hexStrToU64` reads them: invalid text is 0.
    pub(crate) fn get_u64(&self, key: &str) -> Option<u64> {
        let value = self.get(key)?;
        let text = std::str::from_utf8(&value).ok()?;
        Some(u64::from_str_radix(text, 16).unwrap_or(0))
    }
}

fn unescape(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len());
    let mut escaped = false;
    for byte in value {
        if escaped {
            escaped = false;
            output.push(match byte {
                b'r' => 13,
                b'n' => 10,
                b'0' => 0,
                b'e' => b'=',
                other => *other,
            });
        } else if *byte == b'\\' {
            escaped = true;
        } else {
            output.push(*byte);
        }
    }
    output
}

/// Appends an entry with a 16-digit hexadecimal value, as `Dictionary::add(key, uint64_t)` writes it.
pub(crate) fn add_u64(output: &mut Vec<u8>, key: &str, value: u64) {
    output.extend_from_slice(format!("{key}={value:016x}\n").as_bytes());
}

/// Appends an entry with an escaped text value.
pub(crate) fn add_text(output: &mut Vec<u8>, key: &str, value: &str) {
    output.extend_from_slice(key.as_bytes());
    output.push(b'=');
    for byte in value.bytes() {
        match byte {
            0 => output.extend_from_slice(b"\\0"),
            13 => output.extend_from_slice(b"\\r"),
            10 => output.extend_from_slice(b"\\n"),
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'=' => output.extend_from_slice(b"\\e"),
            other => output.push(other),
        }
    }
    output.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_first_match_with_exact_key_and_binary_unescape() {
        let data = b"nw=1\nn=a\\eb\\0c\\rd\\ne\\\\f\nn=second\nid=00ff\n\0ignored=1\n";
        let dictionary = Dictionary::new(data);
        assert_eq!(dictionary.get("n").unwrap(), b"a=b\0c\rd\ne\\f");
        assert_eq!(dictionary.get_u64("id"), Some(0xff));
        assert_eq!(dictionary.get("nw").unwrap(), b"1");
        assert!(dictionary.get("ignored").is_none());
        assert!(dictionary.get("missing").is_none());
    }

    #[test]
    fn writes_values_the_reader_recovers() {
        let mut output = Vec::new();
        add_u64(&mut output, "v", 7);
        add_text(&mut output, "o", "a=b\\c\n");
        assert_eq!(&output[..19], b"v=0000000000000007\n");
        let dictionary = Dictionary::new(&output);
        assert_eq!(dictionary.get_u64("v"), Some(7));
        assert_eq!(dictionary.get("o").unwrap(), b"a=b\\c\n");
    }
}
