use super::table::Table;
use crate::io::DuplexWake;
use kerlico_core::{BoxStream, Error, Result};
use rand::{
    RngCore,
    distributions::{Distribution, Uniform},
};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone)]
pub(crate) struct FastRng(u64);
impl FastRng {
    pub fn from_seed(seed: [u8; 8]) -> Self {
        let state = u64::from_le_bytes(seed);
        Self(if state == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            state
        })
    }
    #[cfg(test)]
    pub fn seed_from_u64(seed: u64) -> Self {
        let state = seed ^ 0x9e37_79b9_7f4a_7c15;
        Self(if state == 0 { 1 } else { state })
    }
}
impl RngCore for FastRng {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub(crate) struct Decoder {
    table: Arc<Table>,
    packed: bool,
    clues: [u8; 4],
    clue_count: usize,
    bits: u32,
    bit_count: u8,
}
pub(crate) struct DecodeProgress {
    pub consumed: usize,
    pub produced: usize,
    pub error: Option<Error>,
}
impl Decoder {
    pub fn new(table: Arc<Table>, packed: bool) -> Self {
        Self {
            table,
            packed,
            clues: [0; 4],
            clue_count: 0,
            bits: 0,
            bit_count: 0,
        }
    }
    pub fn push(&mut self, wire: u8) -> Result<Option<u8>> {
        let mut output = [0];
        let progress = self.decode_into(&[wire], &mut output);
        if let Some(error) = progress.error {
            return Err(error);
        }
        Ok((progress.produced != 0).then_some(output[0]))
    }
    pub fn decode_into(&mut self, wire: &[u8], output: &mut [u8]) -> DecodeProgress {
        let mut progress = DecodeProgress {
            consumed: 0,
            produced: 0,
            error: None,
        };
        if self.packed {
            let group_index = &self.table.layout.raw_group_index;
            let marker = self.table.layout.marker;
            let mut bits = self.bits;
            let mut bit_count = self.bit_count;
            let mut consumed = 0;
            let mut produced = 0;
            while consumed < wire.len() && produced < output.len() {
                while bit_count == 0 && consumed + 4 <= wire.len() && produced + 3 <= output.len() {
                    let g0 = group_index[wire[consumed] as usize];
                    let g1 = group_index[wire[consumed + 1] as usize];
                    let g2 = group_index[wire[consumed + 2] as usize];
                    let g3 = group_index[wire[consumed + 3] as usize];
                    if (g0 | g1 | g2 | g3) == 0xFF {
                        break;
                    }
                    let v = (u32::from(g0) << 18)
                        | (u32::from(g1) << 12)
                        | (u32::from(g2) << 6)
                        | u32::from(g3);
                    output[produced] = (v >> 16) as u8;
                    output[produced + 1] = (v >> 8) as u8;
                    output[produced + 2] = v as u8;
                    consumed += 4;
                    produced += 3;
                }
                if consumed >= wire.len() || produced >= output.len() {
                    break;
                }
                let byte = wire[consumed];
                consumed += 1;
                let group = group_index[byte as usize];
                if group == 0xFF {
                    if byte == marker {
                        bits = 0;
                        bit_count = 0;
                    }
                    continue;
                }
                bits = (bits << 6) | u32::from(group);
                bit_count += 6;
                if bit_count >= 8 {
                    bit_count -= 8;
                    output[produced] = (bits >> bit_count) as u8;
                    produced += 1;
                    bits &= (1 << bit_count) - 1;
                }
            }
            self.bits = bits;
            self.bit_count = bit_count;
            progress.consumed = consumed;
            progress.produced = produced;
        } else {
            let table = &*self.table;
            let hint_index = &table.layout.raw_hint_index;
            let mut clues = self.clues;
            let mut clue_count = self.clue_count;
            let mut consumed = 0;
            let mut produced = 0;
            while produced < output.len() {
                while clue_count < 4 && consumed < wire.len() {
                    let clue = hint_index[wire[consumed] as usize];
                    consumed += 1;
                    clues[clue_count] = clue;
                    clue_count += usize::from(clue != 0xFF);
                }
                if clue_count < 4 {
                    break;
                }
                clue_count = 0;
                match table.decode(clues) {
                    Ok(byte) => {
                        output[produced] = byte;
                        produced += 1;
                    }
                    Err(error) => {
                        self.clues = clues;
                        self.clue_count = 0;
                        return DecodeProgress {
                            consumed,
                            produced,
                            error: Some(error),
                        };
                    }
                }
            }
            self.clues = clues;
            self.clue_count = clue_count;
            progress.consumed = consumed;
            progress.produced = produced;
        }
        progress
    }
    pub fn finish(&self) -> Result<()> {
        if !self.packed && self.clue_count != 0 {
            return Err(Error::Protocol("Sudoku clue在EOF前截断"));
        }
        Ok(())
    }
}

pub(crate) struct Encoder {
    table: Arc<Table>,
    packed: bool,
    random: FastRng,
    threshold: u64,
    padding: Vec<u8>,
    padding_dist: Uniform<usize>,
    gap_dist: Uniform<usize>,
}
impl Encoder {
    pub fn new(table: Arc<Table>, packed: bool, min: u8, max: u8) -> Result<Self> {
        if min > max || max > 100 {
            return Err(Error::Config("Sudoku padding范围不合法".into()));
        }
        let mut random = FastRng::from_seed(crate::key::random::<8>()?);
        let low = u64::from(min) * (1u64 << 32) / 100;
        let high = u64::from(max) * (1u64 << 32) / 100;
        let threshold = low + ((u64::from(random.next_u32()) * (high - low)) >> 32);
        let mut padding = table.layout.padding.clone();
        if packed {
            padding.retain(|&b| b != table.layout.marker);
        }
        if padding.is_empty() {
            return Err(Error::Protocol("Sudoku布局没有可用padding"));
        }
        let padding_dist = Uniform::new(0, padding.len());
        let gap_dist = Uniform::new_inclusive(1, 2);
        Ok(Self {
            table,
            packed,
            random,
            threshold,
            padding,
            padding_dist,
            gap_dist,
        })
    }
    #[inline(always)]
    fn forced_padding(&mut self, out: &mut Vec<u8>) {
        out.push(self.padding[self.padding_dist.sample(&mut self.random)]);
    }
    #[inline(always)]
    fn maybe_padding(&mut self, out: &mut Vec<u8>) {
        if self.threshold == 0 {
            return;
        }
        // 合法0/100边界不需要取样决定是否padding；clue和padding字节仍随机。
        if self.threshold == (1u64 << 32) || u64::from(self.random.next_u32()) < self.threshold {
            self.forced_padding(out);
        }
    }
    pub fn encode(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        if self.threshold == 0 {
            if self.packed {
                self.encode_packed_zero(bytes, out);
            } else {
                out.reserve(bytes.len() * 4);
                let table = &*self.table;
                let mut rng = self.random.clone();
                let mut buf = [0u8; 64 * 4];
                for chunk in bytes.chunks(64) {
                    let mut pos = 0;
                    for &byte in chunk {
                        let puzzle = table.randomized_puzzle(byte, &mut rng);
                        buf[pos..pos + 4].copy_from_slice(&puzzle);
                        pos += 4;
                    }
                    out.extend_from_slice(&buf[..pos]);
                }
                self.random = rng;
            }
            return;
        }
        if !self.packed {
            out.reserve(bytes.len() * 9);
            let table = &*self.table;
            let padding = self.padding.as_slice();
            let padding_dist = self.padding_dist;
            let threshold = self.threshold;
            let mut rng = self.random.clone();
            let mut buf = [0u8; 64 * 9];
            for chunk in bytes.chunks(64) {
                let mut pos = 0;
                for &byte in chunk {
                    let puzzle = table.randomized_puzzle(byte, &mut rng);
                    if threshold == (1u64 << 32) || u64::from(rng.next_u32()) < threshold {
                        buf[pos] = padding[padding_dist.sample(&mut rng)];
                        pos += 1;
                    }
                    for clue in puzzle {
                        if threshold == (1u64 << 32) || u64::from(rng.next_u32()) < threshold {
                            buf[pos] = padding[padding_dist.sample(&mut rng)];
                            pos += 1;
                        }
                        buf[pos] = clue;
                        pos += 1;
                    }
                }
                out.extend_from_slice(&buf[..pos]);
            }
            self.random = rng;
            return;
        }
        out.reserve(bytes.len() * 2 + 18);
        let prefix = self.gap_dist.sample(&mut self.random);
        for _ in 0..prefix {
            self.forced_padding(out);
        }
        let mut bits = 0u32;
        let mut bit_count = 0u8;
        let mut gap = self.gap_dist.sample(&mut self.random);
        let mut since_padding = 0;
        for (index, &byte) in bytes.iter().enumerate() {
            bits = (bits << 8) | u32::from(byte);
            bit_count += 8;
            while bit_count >= 6 {
                bit_count -= 6;
                let group = ((bits >> bit_count) & 63) as usize;
                bits &= (1 << bit_count) - 1;
                self.maybe_padding(out);
                out.push(self.table.layout.groups[group]);
            }
            // 与参考格式一致，首14明文字节即使padding=0也有稠密非marker填充。
            if index < 14 {
                since_padding += 1;
                if since_padding >= gap {
                    self.forced_padding(out);
                    since_padding = 0;
                    gap = self.gap_dist.sample(&mut self.random);
                }
            }
        }
        if bit_count > 0 {
            self.maybe_padding(out);
            out.push(self.table.layout.groups[((bits << (6 - bit_count)) & 63) as usize]);
            out.push(self.table.layout.marker);
        }
        self.maybe_padding(out);
    }
    fn encode_packed_zero(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        out.reserve(bytes.len().div_ceil(3) * 4 + 18);
        let prefix = self.gap_dist.sample(&mut self.random);
        for _ in 0..prefix {
            self.forced_padding(out);
        }
        let mut bits = 0u32;
        let mut bit_count = 0u8;
        let mut gap = self.gap_dist.sample(&mut self.random);
        let mut since_padding = 0;
        const PROTECTED_PREFIX_BYTES: usize = 14;
        const PACKED_BATCH_INPUT_BYTES: usize = 3;
        let protected = bytes
            .len()
            .min(PROTECTED_PREFIX_BYTES.next_multiple_of(PACKED_BATCH_INPUT_BYTES));
        for (index, &byte) in bytes[..protected].iter().enumerate() {
            bits = (bits << 8) | u32::from(byte);
            bit_count += 8;
            while bit_count >= 6 {
                bit_count -= 6;
                out.push(self.table.layout.groups[((bits >> bit_count) & 63) as usize]);
                bits &= (1 << bit_count) - 1;
            }
            if index < PROTECTED_PREFIX_BYTES {
                since_padding += 1;
                if since_padding >= gap {
                    self.forced_padding(out);
                    since_padding = 0;
                    gap = self.gap_dist.sample(&mut self.random);
                }
            }
        }
        let (blocks, remainder) = bytes[protected..].as_chunks::<3>();
        for block in blocks {
            let groups = &self.table.layout.groups;
            out.extend_from_slice(&[
                groups[(block[0] >> 2) as usize],
                groups[(((block[0] & 3) << 4) | (block[1] >> 4)) as usize],
                groups[(((block[1] & 15) << 2) | (block[2] >> 6)) as usize],
                groups[(block[2] & 63) as usize],
            ]);
        }
        for &byte in remainder {
            bits = (bits << 8) | u32::from(byte);
            bit_count += 8;
            while bit_count >= 6 {
                bit_count -= 6;
                out.push(self.table.layout.groups[((bits >> bit_count) & 63) as usize]);
                bits &= (1 << bit_count) - 1;
            }
        }
        if bit_count > 0 {
            out.push(self.table.layout.groups[((bits << (6 - bit_count)) & 63) as usize]);
            out.push(self.table.layout.marker);
        }
    }
}

enum StreamFailure {
    PendingRead(io::Error),
    Reported,
}

struct SplitRead(tokio::io::ReadHalf<BoxStream>);
impl AsyncRead for SplitRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for SplitRead {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct SplitWrite(tokio::io::WriteHalf<BoxStream>);
impl AsyncRead for SplitWrite {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for SplitWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub(crate) struct ObfsStream {
    inner: BoxStream,
    decoder: Decoder,
    encoder: Encoder,
    input: Box<[u8]>,
    input_used: usize,
    input_len: usize,
    pending: Vec<u8>,
    written: usize,
    failure: Option<StreamFailure>,
    local_closed: bool,
    remote_closed: bool,
    flush_pending: bool,
    shutdown_done: bool,
    wake: Arc<DuplexWake>,
    peer_failed: Arc<AtomicBool>,
}
impl ObfsStream {
    pub fn new(
        inner: BoxStream,
        receive: Arc<Table>,
        transmit: Arc<Table>,
        receive_packed: bool,
        transmit_packed: bool,
        min: u8,
        max: u8,
    ) -> Result<Self> {
        Ok(Self {
            inner,
            decoder: Decoder::new(receive, receive_packed),
            encoder: Encoder::new(transmit, transmit_packed, min, max)?,
            input: vec![0; 65536].into_boxed_slice(),
            input_used: 0,
            input_len: 0,
            pending: Vec::with_capacity(589824),
            written: 0,
            failure: None,
            local_closed: false,
            remote_closed: false,
            flush_pending: false,
            shutdown_done: false,
            wake: DuplexWake::new(),
            peer_failed: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn into_split(self, peer_failed: Arc<AtomicBool>) -> (Self, Self) {
        let (raw_read, raw_write) = tokio::io::split(self.inner);
        let dummy_table = self.encoder.table.clone();
        let dummy_encoder = Encoder {
            table: dummy_table.clone(),
            packed: false,
            random: FastRng(1),
            threshold: 0,
            padding: dummy_table.layout.padding.clone(),
            padding_dist: self.encoder.padding_dist,
            gap_dist: self.encoder.gap_dist,
        };
        let reader = Self {
            inner: Box::new(SplitRead(raw_read)),
            decoder: self.decoder,
            encoder: dummy_encoder,
            input: self.input,
            input_used: self.input_used,
            input_len: self.input_len,
            pending: Vec::new(),
            written: 0,
            failure: self.failure,
            local_closed: false,
            remote_closed: self.remote_closed,
            flush_pending: false,
            shutdown_done: false,
            wake: self.wake.clone(),
            peer_failed: peer_failed.clone(),
        };
        let writer = Self {
            inner: Box::new(SplitWrite(raw_write)),
            decoder: Decoder::new(dummy_table, false),
            encoder: self.encoder,
            input: Box::new([]),
            input_used: 0,
            input_len: 0,
            pending: self.pending,
            written: self.written,
            failure: None,
            local_closed: self.local_closed,
            remote_closed: true,
            flush_pending: self.flush_pending,
            shutdown_done: self.shutdown_done,
            wake: self.wake,
            peer_failed,
        };
        (reader, writer)
    }
    pub fn set_transmit_table(
        &mut self,
        table: Arc<Table>,
        packed: bool,
        min: u8,
        max: u8,
    ) -> Result<()> {
        if !self.pending.is_empty() || self.flush_pending || self.local_closed {
            return Err(Error::Protocol("Sudoku不能在待写记录中切换table"));
        }
        self.encoder = Encoder::new(table, packed, min, max)?;
        Ok(())
    }
    fn fail(&mut self) {
        self.peer_failed.store(true, Ordering::Release);
        if self.failure.is_none() {
            self.failure = Some(StreamFailure::Reported);
            self.wake.wake_both();
        }
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let result =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]));
            let count = match result {
                Ok(0) => {
                    self.fail();
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(n) => n,
                Err(e) => {
                    self.fail();
                    return Poll::Ready(Err(e));
                }
            };
            self.written += count;
            self.wake.wake_writer();
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
    fn output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        if self.local_closed && !self.shutdown_done {
            match ready!(Pin::new(&mut self.inner).poll_shutdown(cx)) {
                Ok(()) => {
                    self.shutdown_done = true;
                    self.flush_pending = false;
                    self.wake.wake_writer();
                }
                Err(error) => {
                    self.fail();
                    return Poll::Ready(Err(error));
                }
            }
        } else if self.flush_pending {
            match ready!(Pin::new(&mut self.inner).poll_flush(cx)) {
                Ok(()) => {
                    self.flush_pending = false;
                    self.wake.wake_writer();
                }
                Err(error) => {
                    self.fail();
                    return Poll::Ready(Err(error));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Sudoku载体已关闭")
}
impl AsyncRead for ObfsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let forwarded = this.wake.reader(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(failure) = this.failure.take() {
            this.failure = Some(StreamFailure::Reported);
            return Poll::Ready(Err(match failure {
                StreamFailure::PendingRead(error) => error,
                StreamFailure::Reported => closed(),
            }));
        }
        if this.peer_failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        if let Poll::Ready(Err(error)) = this.output(cx) {
            return Poll::Ready(Err(error));
        }
        let original = output.filled().len();
        let mut consumed = 0;
        loop {
            if this.input_used < this.input_len {
                let available = &this.input[this.input_used..this.input_len];
                let capacity = available.len().min(output.remaining());
                let progress = this
                    .decoder
                    .decode_into(available, output.initialize_unfilled_to(capacity));
                this.input_used += progress.consumed;
                consumed += progress.consumed;
                output.advance(progress.produced);
                if let Some(error) = progress.error {
                    let error = io::Error::new(io::ErrorKind::InvalidData, error);
                    if output.filled().len() > original {
                        this.failure = Some(StreamFailure::PendingRead(error));
                        this.wake.wake_both();
                        return Poll::Ready(Ok(()));
                    }
                    this.fail();
                    return Poll::Ready(Err(error));
                }
            }
            if output.filled().len() > original {
                return Poll::Ready(Ok(()));
            }
            if this.remote_closed {
                return Poll::Ready(Ok(()));
            }
            if consumed >= 524288 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let mut buffer = ReadBuf::new(&mut this.input);
            let result = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buffer));
            if let Err(error) = result {
                this.fail();
                return Poll::Ready(Err(error));
            }
            let count = buffer.filled().len();
            if count == 0 {
                this.remote_closed = true;
                if let Err(error) = this.decoder.finish() {
                    this.fail();
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, error)));
                }
                return Poll::Ready(Ok(()));
            }
            this.input_used = 0;
            this.input_len = count;
        }
    }
}
impl AsyncWrite for ObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let forwarded = this.wake.writer(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if this.failure.is_some() || this.local_closed || this.peer_failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        ready!(this.output(cx))?;
        let count = bytes.len().min(65596);
        this.encoder.encode(&bytes[..count], &mut this.pending);
        if count != 0 {
            match this.drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => this.wake.wake_reader(),
            }
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let forwarded = this.wake.writer(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if this.failure.is_some() || this.peer_failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        if !this.shutdown_done {
            this.flush_pending = true;
        }
        this.output(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let forwarded = this.wake.writer(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if this.failure.is_some() || this.peer_failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        this.local_closed = true;
        this.output(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{
        layout::Mode,
        table::{GridOrder, Pair},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn decodes_independent_go_pure_and_packed_vectors() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tools/sudoku_reference_probe/fixtures/mihomo-wire.json"
        ))
        .unwrap();
        let seed = fixture["synthetic_vector_seed"].as_str().unwrap();
        let order = Arc::new(GridOrder::new(seed));
        let expected: Vec<u8> = (0..=255).collect();
        for vector in fixture["vectors"].as_array().unwrap() {
            let pair = Pair::new(
                seed,
                Mode::parse(vector["mode"].as_str().unwrap()).unwrap(),
                vector["custom_pattern"].as_str().unwrap(),
                order.clone(),
            )
            .unwrap();
            for (field, packed) in [("pure_hex", false), ("packed_hex", true)] {
                let mut decoder = Decoder::new(pair.up.clone(), packed);
                let mut plain = Vec::new();
                for byte in unhex(vector[field].as_str().unwrap()) {
                    if let Some(value) = decoder.push(byte).unwrap() {
                        plain.push(value);
                    }
                }
                decoder.finish().unwrap();
                assert_eq!(plain, expected);
            }
        }
    }
    #[tokio::test]
    async fn bounded_buffers_splits_packed_markers_and_half_close() {
        let order = Arc::new(GridOrder::new("synthetic-obfs-stream"));
        let pair = Pair::new("synthetic-obfs-stream", Mode::AsciiUp, "xpxvvpvv", order).unwrap();
        for packed in [false, true] {
            let (a, b) = tokio::io::duplex(17);
            let mut client = ObfsStream::new(
                Box::new(a),
                pair.down.clone(),
                pair.up.clone(),
                packed,
                false,
                100,
                100,
            )
            .unwrap();
            let mut server = ObfsStream::new(
                Box::new(b),
                pair.up.clone(),
                pair.down.clone(),
                false,
                packed,
                100,
                100,
            )
            .unwrap();
            let peer = tokio::spawn(async move {
                let mut payload = Vec::new();
                server.read_to_end(&mut payload).await.unwrap();
                assert_eq!(payload, vec![0x5a; 65537]);
                server.write_all(b"after-fin").await.unwrap();
                server.shutdown().await.unwrap();
            });
            client.write_all(&vec![0x5a; 65537]).await.unwrap();
            assert!(client.pending.len() <= 65536 * 9 + 128);
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(&reply, b"after-fin");
            peer.await.unwrap();
        }
    }
}

#[cfg(test)]
mod padding_boundary_tests {
    use super::*;
    use crate::codec::{
        layout::Mode,
        table::{GridOrder, Pair},
    };

    #[test]
    fn zero_and_full_padding_boundaries_preserve_wire_and_skip_zero_sampling() {
        let order = Arc::new(GridOrder::new("synthetic-padding-boundaries"));
        let pair = Pair::new(
            "synthetic-padding-boundaries",
            Mode::parse("prefer_entropy").unwrap(),
            "",
            order,
        )
        .unwrap();
        let mut zero = Encoder::new(pair.up.clone(), false, 0, 0).unwrap();
        let mut expected_random = zero.random.clone();
        let mut no_padding = Vec::new();
        for _ in 0..1024 {
            zero.maybe_padding(&mut no_padding);
        }
        assert!(no_padding.is_empty());
        assert_eq!(zero.random.next_u64(), expected_random.next_u64());
        let plain: Vec<u8> = (0..=255).collect();
        for padding in [0, 100] {
            for packed in [false, true] {
                let mut encoder = Encoder::new(pair.up.clone(), packed, padding, padding).unwrap();
                let mut encoded = Vec::new();
                encoder.encode(&plain, &mut encoded);
                if !packed {
                    assert_eq!(
                        encoded.len(),
                        plain.len() * if padding == 0 { 4 } else { 9 }
                    );
                }
                let mut decoder = Decoder::new(pair.up.clone(), packed);
                let mut decoded = Vec::new();
                for byte in encoded {
                    if let Some(value) = decoder.push(byte).unwrap() {
                        decoded.push(value);
                    }
                }
                decoder.finish().unwrap();
                assert_eq!(decoded, plain);
            }
        }
    }
}

#[cfg(test)]
mod joint_sampling_wire_tests {
    use super::*;
    use crate::codec::{
        layout::Mode,
        table::{GridOrder, Pair},
    };

    #[test]
    fn joint_puzzle_selection_preserves_default_padding_and_chunked_wire_roundtrip() {
        let order = Arc::new(GridOrder::new("synthetic-joint-default-padding"));
        let input: Vec<u8> = (0..8193).map(|index| (index & 255) as u8).collect();
        for mode in [Mode::Ascii, Mode::Entropy, Mode::AsciiUp, Mode::EntropyUp] {
            let pattern = if mode == Mode::Ascii { "" } else { "xpxvvpvv" };
            let pair = Pair::new(
                "synthetic-joint-default-padding",
                mode,
                pattern,
                order.clone(),
            )
            .unwrap();
            for table in [pair.up, pair.down] {
                for packed in [false, true] {
                    let mut encoder = Encoder::new(table.clone(), packed, 10, 30).unwrap();
                    assert!(encoder.threshold >= 10 * (1u64 << 32) / 100);
                    assert!(encoder.threshold <= 30 * (1u64 << 32) / 100);
                    let mut wire = Vec::new();
                    for chunk in input.chunks(4096) {
                        encoder.encode(chunk, &mut wire);
                    }
                    if !packed {
                        assert!(wire.len() >= input.len() * 4 && wire.len() <= input.len() * 9);
                    }
                    let mut decoder = Decoder::new(table.clone(), packed);
                    let mut output = Vec::new();
                    for byte in wire {
                        if let Some(byte) = decoder.push(byte).unwrap() {
                            output.push(byte);
                        }
                    }
                    decoder.finish().unwrap();
                    assert_eq!(output, input);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "obfs_regression.rs"]
mod regression_tests;
