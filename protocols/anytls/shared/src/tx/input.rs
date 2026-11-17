//! Initialized PSH/TLS storage lent to the outbound socket reader.
//!
//! Payload, frame headers and TLS overhead have disjoint regions. Preparing
//! input consumes no nonce; sealing uses the session's one transmit cipher.

use std::io;
use std::ops::Range;

use kerlico_shared::WriteInput;

use super::{frame, Cipher, CMD_PSH, CONTENT_APPDATA, MAX_DATA, MAX_PLAIN};

const FRAMES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Plain,
    Tls { prefix: usize, trailer: usize },
}

impl Format {
    pub(crate) fn cipher(cipher: &Cipher) -> Self {
        Self::Tls {
            prefix: cipher.prefix_len(),
            trailer: 16 + usize::from(cipher.is_tls13()),
        }
    }

    fn overhead(self) -> (usize, usize) {
        match self {
            Self::Plain => (0, 0),
            Self::Tls { prefix, trailer } => (prefix, trailer),
        }
    }
}

struct Record {
    start: usize,
    first_part: usize,
    last_part: usize,
}

pub(crate) struct Input {
    pub(crate) storage: Vec<u8>,
    parts: Vec<Range<usize>>,
    headers: [Range<usize>; FRAMES],
    records: Vec<Record>,
    ends: Vec<usize>,
    format: Format,
    size: usize,
    pub(crate) filled: usize,
}

pub(crate) struct Encoded {
    pub(crate) storage: Vec<u8>,
    pub(crate) len: usize,
}

impl Input {
    pub(crate) fn new(format: Format) -> Self {
        let (prefix, trailer) = format.overhead();
        let mut parts = Vec::new();
        let mut headers = std::array::from_fn(|_| 0..0);
        let mut records = Vec::new();
        let mut at = 0;
        let mut plain = MAX_PLAIN;
        for header in &mut headers {
            if plain == MAX_PLAIN {
                records.push(Record {
                    start: at,
                    first_part: parts.len(),
                    last_part: parts.len(),
                });
                at += prefix;
                plain = 0;
            }
            // With two 65535-byte frames, headers begin at plaintext offsets
            // zero and six within a TLS record; neither header is split.
            assert!(MAX_PLAIN - plain >= frame::HEADER);
            *header = at..at + frame::HEADER;
            at += frame::HEADER;
            plain += frame::HEADER;
            let mut left = MAX_DATA;
            while left != 0 {
                if plain == MAX_PLAIN {
                    at += trailer;
                    records.push(Record {
                        start: at,
                        first_part: parts.len(),
                        last_part: parts.len(),
                    });
                    at += prefix;
                    plain = 0;
                }
                let n = left.min(MAX_PLAIN - plain);
                parts.push(at..at + n);
                records.last_mut().expect("record").last_part = parts.len();
                at += n;
                plain += n;
                left -= n;
            }
        }
        at += trailer;
        let ends = vec![0; records.len()];
        Self {
            storage: vec![0; at],
            parts,
            headers,
            records,
            ends,
            format,
            size: at,
            filled: 0,
        }
    }

    pub(crate) fn borrow(&mut self) -> WriteInput<'_> {
        assert_eq!(self.storage.len(), self.size);
        WriteInput::new(&mut self.storage, &self.parts, &mut self.filled)
    }

    pub(crate) fn copy_from(&mut self, bytes: &[u8]) -> usize {
        assert_eq!(self.filled, 0);
        let mut used = 0;
        for part in &self.parts {
            let n = part.len().min(bytes.len() - used);
            self.storage[part.start..part.start + n].copy_from_slice(&bytes[used..used + n]);
            used += n;
            if used == bytes.len() {
                break;
            }
        }
        self.filled = used;
        used
    }

    /// Compute the active records without writing headers or consuming keys.
    pub(crate) fn records(&mut self) -> usize {
        let mut left = self.filled;
        let mut count = 0;
        for (index, record) in self.records.iter().enumerate() {
            self.ends[index] = 0;
            for part in &self.parts[record.first_part..record.last_part] {
                let n = part.len().min(left);
                if n == 0 {
                    break;
                }
                self.ends[index] = part.start + n;
                left -= n;
            }
            if self.ends[index] != 0 {
                count += 1;
            }
        }
        assert_eq!(left, 0);
        count
    }

    pub(crate) fn seal(
        &mut self,
        sid: u32,
        mut cipher: Option<&mut Cipher>,
    ) -> io::Result<Encoded> {
        if self.filled == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let actual = cipher.as_deref().map_or(Format::Plain, Format::cipher);
        if actual != self.format {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let count = self.records();
        for (index, header) in self.headers.iter().enumerate() {
            let size = self.filled.saturating_sub(index * MAX_DATA).min(MAX_DATA);
            if size == 0 {
                break;
            }
            self.storage[header.clone()].copy_from_slice(&frame::header(CMD_PSH, sid, size));
        }
        let (prefix, trailer) = self.format.overhead();
        let mut end = 0;
        for (record, &plain_end) in self.records.iter().zip(&self.ends).take(count) {
            end = plain_end + trailer;
            if let Some(cipher) = cipher.as_deref_mut() {
                cipher.seal_in_place(
                    &mut self.storage[record.start..end],
                    plain_end - record.start - prefix,
                    CONTENT_APPDATA,
                );
            }
        }
        // Keep the initialized length, including the unused final tail. The
        // sender limits its wire view to `len`; recycling does not zero it.
        Ok(Encoded {
            storage: std::mem::take(&mut self.storage),
            len: end,
        })
    }

    pub(crate) fn recycle(&mut self, mut storage: Vec<u8>) {
        if storage.len() != self.size {
            storage.resize(self.size, 0);
        }
        self.storage = storage;
        self.filled = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Out, Tx};
    use super::*;
    use crate::tls::{Control, Wire};
    use crate::SchemeCell;
    use std::sync::Mutex;

    fn open(peer: &mut crate::tls::Records, wire: &[u8]) -> Vec<u8> {
        let mut bytes = wire.to_vec();
        let mut out = Vec::new();
        let mut at = 0;
        let mut handshake = Vec::new();
        while at < bytes.len() {
            let length = 5 + usize::from(u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]));
            let (kind, size) = peer.rx.open(&mut bytes[at..at + length]).unwrap();
            let plain = &bytes[at + 5..at + 5 + size];
            if kind == CONTENT_APPDATA {
                out.extend_from_slice(plain);
            } else {
                for event in crate::tls::control(kind, plain, &mut handshake).unwrap() {
                    if matches!(event, Control::KeyUpdate(_)) {
                        peer.rx = peer.kernel.next_rx().unwrap();
                    }
                }
            }
            at += length;
        }
        out
    }

    #[test]
    fn borrowed_input_reuses_storage_and_shares_cipher_sequence_with_control_records() {
        let (client, server) = crate::tests::pair();
        let Wire::Records(client) = client.wire else {
            panic!("TLS")
        };
        let Wire::Records(mut peer) = server.wire else {
            panic!("TLS")
        };
        let kernel = Mutex::new(client.kernel);
        let padding = SchemeCell::new(crate::Scheme::default_scheme());
        let mut tx = Tx::new(Some(client.tx), client.pending, false);
        let mut input = Input::new(tx.input_format().unwrap());
        let address = input.storage.as_ptr();
        for (index, size) in [1, 16_377, 65_535, 78_125, 131_070, 3]
            .into_iter()
            .enumerate()
        {
            if index == 3 {
                tx.put(Out::KeyUpdate, &padding, &kernel).unwrap();
                assert!(open(&mut peer, &tx.out).is_empty());
                tx.out.clear();
            }
            input.storage.fill(0xa5);
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut borrowed = input.borrow();
            let mut slices =
                std::array::from_fn::<_, { kerlico_shared::MAX_WRITE_INPUT_PARTS }, _>(|_| {
                    io::IoSliceMut::new(&mut [])
                });
            let count = borrowed.slices(&mut slices);
            let mut used = 0;
            for part in &mut slices[..count] {
                let n = part.len().min(size - used);
                part[..n].copy_from_slice(&payload[used..used + n]);
                used += n;
                if used == size {
                    break;
                }
            }
            drop(slices);
            borrowed.commit(used);
            for (i, &byte) in input.storage.iter().enumerate() {
                if !input.parts.iter().any(|range| range.contains(&i)) {
                    assert_eq!(byte, 0xa5);
                }
            }
            let encoded = tx.seal_input(7, &mut input, &kernel).unwrap();
            assert_eq!(encoded.storage.as_ptr(), address);
            let got = open(&mut peer, &encoded.storage[..encoded.len]);
            let mut expected = Vec::new();
            frame::push_data(&mut expected, 7, &payload);
            assert_eq!(got, expected);
            let tail = encoded.storage.last().copied();
            input.recycle(encoded.storage);
            assert_eq!(input.storage.as_ptr(), address);
            assert_eq!(input.storage.last().copied(), tail);
        }
    }

    #[test]
    fn ordinary_input_and_plaintext_use_the_same_frame_boundaries() {
        let mut input = Input::new(Format::Plain);
        let body = vec![0x73; 90_000];
        assert_eq!(input.copy_from(&body), body.len());
        let encoded = input.seal(42, None).unwrap();
        let mut expected = Vec::new();
        frame::push_data(&mut expected, 42, &body);
        assert_eq!(&encoded.storage[..encoded.len], expected);
        input.recycle(encoded.storage);
        assert!(
            input.seal(42, None).is_err(),
            "EOF does not create an empty frame"
        );
    }
}
