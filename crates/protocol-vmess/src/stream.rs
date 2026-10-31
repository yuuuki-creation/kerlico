//! 有界分块 I/O；读取状态不会因取消一次 future 而丢失半帧。
use crate::{
    codec::Keys,
    crypto::{MAX_DATAGRAM, Records, invalid},
};
use kerlico_core::BoxStream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroize;

#[derive(Clone, Copy)]
enum Phase {
    ResponseLength,
    ResponseHeader,
    Length,
    Payload,
    Plain,
}
pub(crate) struct RecordStream {
    inner: BoxStream,
    reader: Records,
    writer: Records,
    keys: Option<Keys>,
    phase: Phase,
    input: Vec<u8>,
    position: usize,
    required: usize,
    padding: usize,
    pending: Vec<u8>,
    written: usize,
    udp: bool,
    eof: bool,
    failed: bool,
    closed: bool,
    terminating: bool,
    termination: bool,
    flags: u8,
}
impl RecordStream {
    pub fn new(
        inner: BoxStream,
        reader: Records,
        writer: Records,
        udp: bool,
        termination: bool,
        keys: Option<Keys>,
        pending: Vec<u8>,
    ) -> Self {
        let phase = if keys.is_some() {
            Phase::ResponseLength
        } else {
            Phase::Length
        };
        let required = if keys.is_some() {
            18
        } else {
            reader.size_bytes()
        };
        Self {
            inner,
            reader,
            writer,
            keys,
            phase,
            input: vec![0; required],
            position: 0,
            required,
            padding: 0,
            pending,
            written: 0,
            udp,
            eof: false,
            failed: false,
            closed: false,
            terminating: false,
            termination,
            flags: 0,
        }
    }
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }
    fn expect(&mut self, n: usize, phase: Phase) {
        self.input.zeroize();
        self.input.resize(n, 0);
        self.position = 0;
        self.required = n;
        self.phase = phase;
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.pending.zeroize();
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(invalid()));
        }
        if out.remaining() == 0 || self.eof {
            return Poll::Ready(Ok(()));
        }
        loop {
            if matches!(self.phase, Phase::Plain) {
                let remaining = self.input.len() - self.position;
                if remaining == 0 {
                    self.expect(self.reader.size_bytes(), Phase::Length);
                    continue;
                }
                if self.udp && out.remaining() < remaining {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "VMess 数据报接收缓冲区不足",
                    )));
                }
                let n = remaining.min(out.remaining());
                out.put_slice(&self.input[self.position..self.position + n]);
                self.input[self.position..self.position + n].zeroize();
                self.position += n;
                return Poll::Ready(Ok(()));
            }
            while self.position < self.required {
                let mut buffer = ReadBuf::new(&mut self.input[self.position..self.required]);
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buffer))?;
                let n = buffer.filled().len();
                if n == 0 {
                    if self.position == 0 && matches!(self.phase, Phase::Length) {
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                self.position += n;
            }
            match self.phase {
                Phase::ResponseLength => {
                    let n = self
                        .keys
                        .as_ref()
                        .unwrap()
                        .response_length(&mut self.input)?;
                    self.expect(n, Phase::ResponseHeader);
                }
                Phase::ResponseHeader => {
                    self.keys
                        .take()
                        .unwrap()
                        .response_header(&mut self.input, self.flags)?;
                    self.expect(self.reader.size_bytes(), Phase::Length);
                }
                Phase::Length => {
                    let (n, padding) = self.reader.length(std::mem::take(&mut self.input))?;
                    self.padding = padding;
                    self.expect(n, Phase::Payload);
                }
                Phase::Payload => {
                    self.input = self
                        .reader
                        .open(std::mem::take(&mut self.input), self.padding)?;
                    self.position = 0;
                    if self.input.is_empty() {
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    self.phase = Phase::Plain;
                }
                Phase::Plain => unreachable!(),
            }
        }
    }
}
impl AsyncRead for RecordStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.poll_read_inner(cx, out);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
}
impl AsyncWrite for RecordStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed || this.closed || this.terminating {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.udp && bytes.len() > MAX_DATAGRAM {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess 数据报超过长度上限",
            )));
        }
        if let Err(error) = ready!(this.drain(cx)) {
            this.failed = true;
            return Poll::Ready(Err(error));
        }
        let n = if this.udp {
            bytes.len()
        } else {
            bytes.len().min(8192)
        };
        match this.writer.seal(&bytes[..n]) {
            Ok(wire) => {
                this.pending = wire;
                Poll::Ready(Ok(n))
            }
            Err(error) => {
                this.failed = true;
                Poll::Ready(Err(error))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid()));
        }
        let result = match ready!(this.drain(cx)) {
            Ok(()) => Pin::new(&mut this.inner).poll_flush(cx),
            Err(error) => Poll::Ready(Err(error)),
        };
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        ready!(self.as_mut().poll_flush(cx))?;
        let this = self.get_mut();
        if !this.terminating {
            this.terminating = true;
            if this.termination {
                this.pending = this.writer.seal(&[])?;
            }
        }
        ready!(this.drain(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        if !this.termination {
            ready!(Pin::new(&mut this.inner).poll_shutdown(cx))?;
        }
        this.closed = true;
        Poll::Ready(Ok(()))
    }
}
impl Drop for RecordStream {
    fn drop(&mut self) {
        self.input.zeroize();
        self.pending.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Cipher;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn cancelled_partial_record_read_resumes_without_losing_prefix() {
        for cipher in [Cipher::Aes, Cipher::ChaCha] {
            for auth in [false, true] {
                let key = [4; 16];
                let iv = [5; 16];
                let keys = auth.then_some((&key, &iv));
                let flags = 13 | if auth { 16 } else { 0 };
                let mut encoder = Records::new(cipher, &key, &iv, keys, flags);
                let wire = encoder.seal(b"record-after-cancel").unwrap();
                let (reader, mut writer) = tokio::io::duplex(128);
                writer.write_all(&wire[..1]).await.unwrap();
                let task = tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                    writer.write_all(&wire[1..]).await.unwrap();
                });
                let mut stream = RecordStream::new(
                    Box::new(reader),
                    Records::new(cipher, &key, &iv, keys, flags),
                    Records::new(cipher, &key, &iv, keys, flags),
                    false,
                    true,
                    None,
                    Vec::new(),
                );
                let mut bytes = [0; 19];
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(5),
                        stream.read(&mut bytes)
                    )
                    .await
                    .is_err()
                );
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"record-after-cancel");
                task.await.unwrap();
            }
        }
    }
}
