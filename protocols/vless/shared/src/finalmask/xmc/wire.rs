use std::io::{self, Read, Write};

use super::super::malformed;

const MAX_PACKET_DATA: usize = 32 * 1024;
const MAX_PACKET_BODY: usize = MAX_PACKET_DATA + 5;

#[derive(Default)]
struct Varint {
    value: u32,
    bytes: usize,
}

impl Varint {
    fn push(&mut self, byte: u8) -> io::Result<Option<u32>> {
        if self.bytes == 4 && byte & 0xf0 != 0 {
            return Err(malformed("XMC VarInt overflows 32 bits"));
        }
        self.value |= u32::from(byte & 0x7f) << (7 * self.bytes);
        self.bytes += 1;
        if byte & 0x80 != 0 {
            return Ok(None);
        }
        if self.bytes > 1 && byte == 0 {
            return Err(malformed("non-canonical XMC VarInt"));
        }
        Ok(Some(self.value))
    }
}

pub(super) fn read_varint(reader: &mut impl Read) -> io::Result<(u32, usize)> {
    let mut decoder = Varint::default();
    loop {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        if let Some(value) = decoder.push(byte[0])? {
            return Ok((value, decoder.bytes));
        }
    }
}

pub(super) fn put_varint(out: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub(super) fn put_field(out: &mut Vec<u8>, value: &[u8]) {
    put_varint(out, value.len() as u32);
    out.extend_from_slice(value);
}

pub(super) fn take_field<'a>(input: &mut &'a [u8], limit: usize) -> io::Result<&'a [u8]> {
    let (length, _) = read_varint(input)?;
    let length = length as usize;
    if length > limit {
        return Err(malformed("XMC packet field exceeds its length limit"));
    }
    let (value, rest) = input
        .split_at_checked(length)
        .ok_or(io::ErrorKind::UnexpectedEof)?;
    *input = rest;
    Ok(value)
}

pub(super) struct Packet {
    pub id: u32,
    pub wire_len: usize,
    body: Vec<u8>,
    data_offset: usize,
}

impl Packet {
    pub fn data(&self) -> &[u8] {
        &self.body[self.data_offset..]
    }

    pub fn into_data(self) -> (Vec<u8>, usize) {
        (self.body, self.data_offset)
    }
}

#[derive(Default)]
pub(super) struct FrameReader {
    length: Varint,
    body: Vec<u8>,
    received: usize,
}

impl FrameReader {
    pub fn read(&mut self, reader: &mut impl Read) -> io::Result<Option<Packet>> {
        while self.body.is_empty() {
            let mut byte = [0];
            match reader.read(&mut byte) {
                Ok(0) if self.length.bytes == 0 => return Ok(None),
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
            if let Some(length) = self.length.push(byte[0])? {
                let length = length as usize;
                if !(1..=MAX_PACKET_BODY).contains(&length) {
                    return Err(malformed("invalid XMC packet length"));
                }
                self.body.resize(length, 0);
            }
        }
        while self.received < self.body.len() {
            match reader.read(&mut self.body[self.received..]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(count) => self.received += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        let (id, data_offset) = read_varint(&mut self.body.as_slice())?;
        if self.body.len() - data_offset > MAX_PACKET_DATA {
            return Err(malformed("XMC packet data exceeds 32 KiB"));
        }
        let wire_len = self.length.bytes + self.body.len();
        self.length = Varint::default();
        self.received = 0;
        Ok(Some(Packet {
            id,
            wire_len,
            body: std::mem::take(&mut self.body),
            data_offset,
        }))
    }
}

pub(super) fn read_packet(reader: &mut impl Read) -> io::Result<Packet> {
    FrameReader::default()
        .read(reader)?
        .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
}

pub(super) fn encode_packet(id: u32, data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > MAX_PACKET_DATA {
        return Err(malformed("XMC packet data exceeds 32 KiB"));
    }
    let mut packet_id = Vec::with_capacity(5);
    put_varint(&mut packet_id, id);
    let length = packet_id.len() + data.len();
    let mut wire = Vec::with_capacity(length + 5);
    put_varint(&mut wire, length as u32);
    wire.extend_from_slice(&packet_id);
    wire.extend_from_slice(data);
    Ok(wire)
}

pub(super) fn send_packet(writer: &mut impl Write, id: u32, data: &[u8]) -> io::Result<()> {
    writer.write_all(&encode_packet(id, data)?)?;
    writer.flush()
}
