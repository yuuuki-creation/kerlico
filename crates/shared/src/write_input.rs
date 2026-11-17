//! Optional input space lent by an encoder to the outbound reader.

use std::io::{self, IoSlice, IoSliceMut};
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

pub const MAX_WRITE_INPUT_PARTS: usize = 64;

/// Disjoint, ordered payload regions in the encoder's final storage. Header
/// and authentication-tag gaps are never exposed to the source reader.
/// Storage remains initialized and reusable between batches. Acquiring it
/// does not seal a record or advance any cipher state.
pub struct WriteInput<'a> {
    storage: &'a mut [u8],
    regions: &'a [Range<usize>],
    filled: &'a mut usize,
}

impl<'a> WriteInput<'a> {
    pub fn new(storage: &'a mut [u8], regions: &'a [Range<usize>], filled: &'a mut usize) -> Self {
        assert!(!regions.is_empty() && regions.len() <= MAX_WRITE_INPUT_PARTS);
        assert_eq!(*filled, 0, "finish the previous encoder input first");
        let mut end = 0;
        for region in regions {
            assert!(
                end <= region.start && region.start < region.end && region.end <= storage.len()
            );
            end = region.end;
        }
        Self {
            storage,
            regions,
            filled,
        }
    }

    pub fn slices<'b>(&'b mut self, out: &mut [IoSliceMut<'b>]) -> usize {
        assert!(out.len() >= self.regions.len());
        let mut remaining = &mut *self.storage;
        let mut end = 0;
        for (slot, region) in out.iter_mut().zip(self.regions) {
            let (_, tail) = remaining.split_at_mut(region.start - end);
            let (data, rest) = tail.split_at_mut(region.len());
            *slot = IoSliceMut::new(data);
            remaining = rest;
            end = region.end;
        }
        self.regions.len()
    }

    /// Record exactly the bytes the source filled, in region order. Dropping
    /// an uncommitted input (Pending, EOF, error or cancellation) seals nothing.
    pub fn commit(self, n: usize) {
        assert!(n <= self.regions.iter().map(Range::len).sum::<usize>());
        *self.filled = n;
    }
}

pub trait AsyncWriteInput: AsyncWrite {
    fn poll_input(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<WriteInput<'_>>>;
    /// Seal once and drain the committed input. A Pending call retains its
    /// ciphertext and progress; Ready reports delivered application bytes.
    fn poll_send_input(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>>;
}

pub enum AsyncWriteHalf {
    Plain(Box<dyn AsyncWrite + Send + Unpin>),
    Input(Box<dyn AsyncWriteInput + Send + Unpin>),
}

impl AsyncWriteHalf {
    pub fn plain(write: impl AsyncWrite + Send + Unpin + 'static) -> Self {
        Self::Plain(Box::new(write))
    }
}

impl AsyncWrite for AsyncWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(write) => Pin::new(write).poll_write(cx, bytes),
            Self::Input(write) => Pin::new(write).poll_write(cx, bytes),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slices: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(write) => Pin::new(write).poll_write_vectored(cx, slices),
            Self::Input(write) => Pin::new(write).poll_write_vectored(cx, slices),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(write) => write.is_write_vectored(),
            Self::Input(write) => write.is_write_vectored(),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(write) => Pin::new(write).poll_flush(cx),
            Self::Input(write) => Pin::new(write).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(write) => Pin::new(write).poll_shutdown(cx),
            Self::Input(write) => Pin::new(write).poll_shutdown(cx),
        }
    }
}
