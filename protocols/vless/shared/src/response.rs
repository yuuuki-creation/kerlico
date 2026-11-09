use std::io::{Read, Write};

use crate::{decode_response, HeaderError};

/// Reads the VLESS response on the first downstream read. The peer may wait for
/// application bytes before responding, so dialing must leave this lazy.
pub struct ResponseReader<T> {
    inner: T,
    header: Vec<u8>,
    done: bool,
}

impl<T> ResponseReader<T> {
    pub fn new(inner: T) -> Self { Self { inner, header: Vec::new(), done: false } }
    pub fn inner_mut(&mut self) -> &mut T { &mut self.inner }
}

impl<T: Read> Read for ResponseReader<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        while !self.done {
            match decode_response(&self.header) {
                Ok(_) => { self.done = true; }
                Err(HeaderError::Bad) => return Err(std::io::Error::other("VLESS response")),
                Err(HeaderError::Short) => {
                    let needed = if self.header.len() < 2 { 2 } else { 2 + self.header[1] as usize };
                    let mut tmp = [0; 257];
                    let n = self.inner.read(&mut tmp[..needed - self.header.len()])?;
                    if n == 0 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "VLESS response")); }
                    self.header.extend_from_slice(&tmp[..n]);
                }
            }
        }
        self.inner.read(buf)
    }
}

impl<T: Write> Write for ResponseReader<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.inner.write(buf) }
    fn flush(&mut self) -> std::io::Result<()> { self.inner.flush() }
}
