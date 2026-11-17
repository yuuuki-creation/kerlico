//! Owned asynchronous plaintext after an inbound handshake. No dialing lives here.

use crate::AsyncWriteHalf;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, BufReader, ReadBuf};
use tokio::runtime::Handle;

/// An authenticated reader can lend several discontiguous records at once.
/// No record is consumed until `consume` is called with the written byte count.
/// An empty result means EOF; Pending must not hide already available records.
pub trait AsyncBufReadVectored: AsyncBufRead {
    fn poll_fill_buf_vectored<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
        slices: &mut [IoSlice<'a>],
    ) -> Poll<io::Result<usize>>;
}

/// Protocol-owned authenticated buffers can be lent directly. Unbuffered
/// streams leave the generic copy-buffer policy to the outbound owner.
pub enum AsyncReadHalf {
    Plain(Box<dyn AsyncRead + Send + Unpin>),
    Buffered(Box<dyn AsyncBufRead + Send + Unpin>),
    Vectored(Box<dyn AsyncBufReadVectored + Send + Unpin>),
}

impl AsyncReadHalf {
    pub fn into_buffered(self, capacity: usize) -> Box<dyn AsyncBufRead + Send + Unpin> {
        match self {
            Self::Plain(read) => Box::new(BufReader::with_capacity(capacity, read)),
            Self::Buffered(read) => read,
            Self::Vectored(read) => read,
        }
    }

    pub fn prepend(&mut self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let read = std::mem::replace(self, Self::Plain(Box::new(tokio::io::empty())));
        *self = match read {
            Self::Plain(read) => Self::Plain(Box::new(std::io::Cursor::new(bytes).chain(read))),
            Self::Buffered(read) => {
                Self::Buffered(Box::new(std::io::Cursor::new(bytes).chain(read)))
            }
            Self::Vectored(read) => Self::Vectored(Box::new(PrefixedRecords {
                prefix: std::io::Cursor::new(bytes),
                read,
            })),
        };
    }
}

impl AsyncRead for AsyncReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(read) => Pin::new(read).poll_read(cx, out),
            Self::Buffered(read) => Pin::new(read).poll_read(cx, out),
            Self::Vectored(read) => Pin::new(read).poll_read(cx, out),
        }
    }
}

struct PrefixedRecords {
    prefix: std::io::Cursor<Vec<u8>>,
    read: Box<dyn AsyncBufReadVectored + Send + Unpin>,
}

impl AsyncBufReadVectored for PrefixedRecords {
    fn poll_fill_buf_vectored<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
        slices: &mut [IoSlice<'a>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        assert!(!slices.is_empty());
        if this.prefix.position() < this.prefix.get_ref().len() as u64 {
            slices[0] = IoSlice::new(ready!(Pin::new(&mut this.prefix).poll_fill_buf(cx))?);
            Poll::Ready(Ok(1))
        } else {
            Pin::new(&mut *this.read).poll_fill_buf_vectored(cx, slices)
        }
    }
}

impl AsyncBufRead for PrefixedRecords {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.prefix.position() < this.prefix.get_ref().len() as u64 {
            Pin::new(&mut this.prefix).poll_fill_buf(cx)
        } else {
            Pin::new(&mut *this.read).poll_fill_buf(cx)
        }
    }

    fn consume(self: Pin<&mut Self>, n: usize) {
        let this = self.get_mut();
        if this.prefix.position() < this.prefix.get_ref().len() as u64 {
            Pin::new(&mut this.prefix).consume(n);
        } else {
            Pin::new(&mut *this.read).consume(n);
        }
    }
}

impl AsyncRead for PrefixedRecords {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let bytes = ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = out.remaining().min(bytes.len());
        out.put_slice(&bytes[..n]);
        self.consume(n);
        Poll::Ready(Ok(()))
    }
}

/// The outbound owner can move the whole relay onto the protocol's existing
/// executor. The halves keep their parser, cipher, buffered bytes and ordering.
pub struct AsyncTcp {
    pub executor: Handle,
    pub read: AsyncReadHalf,
    pub write: AsyncWriteHalf,
}

impl AsyncTcp {
    pub fn prepend(&mut self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        self.read.prepend(bytes);
    }
}
