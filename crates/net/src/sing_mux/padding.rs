//! sing-mux 填充连接：每个方向前 16 次写入各自封装为
//! `u16 数据长度 | u16 填充长度 | 数据 | 256..767 字节随机填充`，之后直通。

use rand::{Rng, RngCore};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const FIRST_PADDINGS: u8 = 16;
const MAX_RECORD: usize = 65535;

pub(super) struct PaddedIo<S> {
    inner: S,
    read_records: u8,
    read_header: [u8; 4],
    read_header_len: usize,
    read_data: usize,
    read_pad: usize,
    write_records: u8,
    pending: Vec<u8>,
    pending_pos: usize,
}

impl<S> PaddedIo<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_records: 0,
            read_header: [0; 4],
            read_header_len: 0,
            read_data: 0,
            read_pad: 0,
            write_records: 0,
            pending: Vec::new(),
            pending_pos: 0,
        }
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "sing-mux 填充记录被截断")
}

impl<S: AsyncRead + Unpin> AsyncRead for PaddedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.read_data > 0 {
                let limit = this.read_data.min(buf.remaining());
                let mut sub = ReadBuf::new(buf.initialize_unfilled_to(limit));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(eof()));
                }
                buf.advance(n);
                this.read_data -= n;
                return Poll::Ready(Ok(()));
            }
            if this.read_pad > 0 {
                let mut scratch = [0u8; 1024];
                let limit = this.read_pad.min(scratch.len());
                let mut sub = ReadBuf::new(&mut scratch[..limit]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(eof()));
                }
                this.read_pad -= n;
                continue;
            }
            if this.read_records >= FIRST_PADDINGS {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut sub = ReadBuf::new(&mut this.read_header[this.read_header_len..]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sub))?;
            let n = sub.filled().len();
            if n == 0 {
                return if this.read_header_len == 0 {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(eof()))
                };
            }
            this.read_header_len += n;
            if this.read_header_len < 4 {
                continue;
            }
            let h = this.read_header;
            this.read_header_len = 0;
            this.read_records += 1;
            this.read_data = usize::from(u16::from_be_bytes([h[0], h[1]]));
            this.read_pad = usize::from(u16::from_be_bytes([h[2], h[3]]));
        }
    }
}

impl<S: AsyncWrite + Unpin> PaddedIo<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending_pos += n;
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.write_records >= FIRST_PADDINGS {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_RECORD);
        let pad_len = rand::thread_rng().gen_range(256usize..768);
        this.pending.reserve(4 + n + pad_len);
        this.pending.extend_from_slice(&(n as u16).to_be_bytes());
        this.pending
            .extend_from_slice(&(pad_len as u16).to_be_bytes());
        this.pending.extend_from_slice(&buf[..n]);
        let start = this.pending.len();
        this.pending.resize(start + pad_len, 0);
        rand::thread_rng().fill_bytes(&mut this.pending[start..]);
        this.write_records += 1;
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn first_sixteen_writes_are_padded_records_then_passthrough() {
        let (a, mut raw) = tokio::io::duplex(1 << 20);
        let mut padded = PaddedIo::new(a);
        for i in 0..18u8 {
            padded.write_all(&[i; 10]).await.unwrap();
        }
        padded.flush().await.unwrap();
        drop(padded);
        let mut wire = Vec::new();
        raw.read_to_end(&mut wire).await.unwrap();
        let mut pos = 0;
        for i in 0..16u8 {
            let len = usize::from(u16::from_be_bytes([wire[pos], wire[pos + 1]]));
            let pad = usize::from(u16::from_be_bytes([wire[pos + 2], wire[pos + 3]]));
            assert_eq!(len, 10);
            assert!((256..768).contains(&pad));
            assert_eq!(&wire[pos + 4..pos + 14], &[i; 10]);
            pos += 4 + len + pad;
        }
        assert_eq!(&wire[pos..], &[[16u8; 10], [17u8; 10]].concat()[..]);
    }

    #[tokio::test]
    async fn padded_peers_round_trip_large_and_small_writes() {
        let (a, b) = tokio::io::duplex(4096);
        let mut left = PaddedIo::new(a);
        let mut right = PaddedIo::new(b);
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            left.write_all(b"x").await.unwrap();
            left.write_all(&payload).await.unwrap();
            left.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        right.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got[0], b'x');
        assert_eq!(&got[1..], &expected[..]);
    }
}
