//! The origin fills at most two PSH payloads. TLS seals from that plaintext
//! directly into the contiguous buffer sent to the socket.

use std::io;
use std::ops::Range;

use kerlico_shared::WriteInput;

use super::{frame, SendCipher, CMD_PSH, CONTENT_APPDATA, MAX_DATA, MAX_PLAIN};

const FRAMES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Plain,
    Tls { prefix: usize, trailer: usize },
}

impl Format {
    pub(crate) fn cipher(cipher: &SendCipher) -> Self {
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

pub(crate) struct Input {
    storage: Vec<u8>,
    output: Vec<u8>,
    parts: [Range<usize>; FRAMES],
    format: Format,
    pub(crate) filled: usize,
}

pub(crate) struct Encoded {
    pub(crate) storage: Vec<u8>,
    pub(crate) len: usize,
}

const FRAME_SIZE: usize = frame::HEADER + MAX_DATA;
const CAPACITY: usize = FRAMES * FRAME_SIZE;

impl Input {
    pub(crate) fn new(format: Format) -> Self {
        let parts = std::array::from_fn(|index| {
            let start = index * FRAME_SIZE + frame::HEADER;
            start..start + MAX_DATA
        });
        Self {
            storage: vec![0; CAPACITY],
            output: Vec::new(),
            parts,
            format,
            filled: 0,
        }
    }

    pub(crate) fn borrow(&mut self) -> WriteInput<'_> {
        WriteInput::new(&mut self.storage, &self.parts, &mut self.filled)
    }

    pub(crate) fn copy_from(&mut self, bytes: &[u8]) -> usize {
        assert_eq!(self.filled, 0);
        let mut used = 0;
        for part in &self.parts {
            let n = part.len().min(bytes.len() - used);
            self.storage[part.start..part.start + n].copy_from_slice(&bytes[used..used + n]);
            used += n;
            if used == bytes.len() { break; }
        }
        self.filled = used;
        used
    }

    fn plaintext_len(&self) -> usize {
        self.filled + self.filled.div_ceil(MAX_DATA) * frame::HEADER
    }

    pub(crate) fn records(&self) -> usize {
        self.plaintext_len().div_ceil(MAX_PLAIN)
    }

    pub(crate) fn seal(
        &mut self,
        sid: u32,
        mut cipher: Option<&mut SendCipher>,
        count: usize,
    ) -> io::Result<Encoded> {
        if self.filled == 0 || cipher.as_deref().map_or(Format::Plain, Format::cipher) != self.format {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let plain = self.plaintext_len();
        debug_assert_eq!(count, plain.div_ceil(MAX_PLAIN));
        for (index, chunk) in self.storage[..plain].chunks_mut(FRAME_SIZE).enumerate() {
            let n = (self.filled - index * MAX_DATA).min(MAX_DATA);
            chunk[..frame::HEADER].copy_from_slice(&frame::header(CMD_PSH, sid, n));
        }
        let Some(cipher) = cipher.as_deref_mut() else {
            return Ok(Encoded { storage: std::mem::take(&mut self.storage), len: plain });
        };
        let (prefix, trailer) = self.format.overhead();
        let overhead = prefix + trailer;
        let len = plain + count * overhead;
        if self.output.len() < len {
            self.output.reserve_exact(len - self.output.len());
            self.output.resize(len, 0);
        }
        let mut wire = &mut self.output[..len];
        for payload in self.storage[..plain].chunks(MAX_PLAIN) {
            let (record, rest) = wire.split_at_mut(payload.len() + overhead);
            cipher.seal_from(payload, record, CONTENT_APPDATA)?;
            wire = rest;
        }
        Ok(Encoded { storage: std::mem::take(&mut self.output), len })
    }

    pub(crate) fn recycle(&mut self, mut storage: Vec<u8>) {
        if self.format == Format::Plain {
            storage.resize(CAPACITY, 0);
            self.storage = storage;
        } else {
            self.output = storage;
        }
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
        let mut wire_address = None;
        for (index, size) in [131_070, 1, 16_376, 16_377, 16_378, 65_534, 65_535, 65_536, 78_125, 3]
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
            assert_eq!(*wire_address.get_or_insert(encoded.storage.as_ptr()), encoded.storage.as_ptr());
            let got = open(&mut peer, &encoded.storage[..encoded.len]);
            let mut expected = Vec::new();
            frame::push_data(&mut expected, 7, &payload);
            assert_eq!(got, expected);
            let tail = encoded.storage.last().copied();
            input.recycle(encoded.storage);
            assert_eq!(input.storage.as_ptr(), address);
            assert_eq!(input.output.last().copied(), tail);
        }
    }

    #[test]
    fn ordinary_input_and_plaintext_use_the_same_frame_boundaries() {
        let mut input = Input::new(Format::Plain);
        let body = vec![0x73; 90_000];
        assert_eq!(input.copy_from(&body), body.len());
        let count = input.records();
        let encoded = input.seal(42, None, count).unwrap();
        let mut expected = Vec::new();
        frame::push_data(&mut expected, 42, &body);
        assert_eq!(&encoded.storage[..encoded.len], expected);
        input.recycle(encoded.storage);
        assert!(
            input.seal(42, None, 0).is_err(),
            "EOF does not create an empty frame"
        );
    }
}
