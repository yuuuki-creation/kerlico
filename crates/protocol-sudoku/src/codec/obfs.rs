use crate::io::DuplexWake;
use super::table::Table;
use kerlico_core::{BoxStream, Error, Result};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct Decoder {
    table: Arc<Table>,
    packed: bool,
    clues: [u8; 4],
    clue_count: usize,
    bits: u32,
    bit_count: u8,
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
        if self.packed {
            let Some(group) = self.table.layout.group_index[wire as usize] else {
                if wire == self.table.layout.marker {
                    self.bits = 0;
                    self.bit_count = 0;
                }
                return Ok(None);
            };
            self.bits = (self.bits << 6) | u32::from(group);
            self.bit_count += 6;
            if self.bit_count < 8 {
                return Ok(None);
            }
            self.bit_count -= 8;
            let byte = (self.bits >> self.bit_count) as u8;
            self.bits &= (1 << self.bit_count) - 1;
            Ok(Some(byte))
        } else {
            let Some(clue) = self.table.layout.hint_index[wire as usize] else {
                return Ok(None);
            };
            self.clues[self.clue_count] = clue;
            self.clue_count += 1;
            if self.clue_count < 4 {
                return Ok(None);
            }
            self.clue_count = 0;
            self.table.decode(self.clues).map(Some)
        }
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
    random: StdRng,
    threshold: u64,
    padding: Vec<u8>,
}
impl Encoder {
    pub fn new(table: Arc<Table>, packed: bool, min: u8, max: u8) -> Result<Self> {
        if min > max || max > 100 {
            return Err(Error::Config("Sudoku padding范围不合法".into()));
        }
        let mut random = StdRng::from_seed(crate::key::random::<32>()?);
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
        Ok(Self {
            table,
            packed,
            random,
            threshold,
            padding,
        })
    }
    fn forced_padding(&mut self, out: &mut Vec<u8>) {
        out.push(self.padding[self.random.gen_range(0..self.padding.len())]);
    }
    fn maybe_padding(&mut self, out: &mut Vec<u8>) {
        if self.threshold == 0 { return; }
        // 合法0/100边界不需要取样决定是否padding；clue和padding字节仍随机。
        if self.threshold == (1u64 << 32) || u64::from(self.random.next_u32()) < self.threshold {
            self.forced_padding(out);
        }
    }
    pub fn encode(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        if !self.packed {
            for &byte in bytes {
                let puzzle = self.table.randomized_puzzle(byte, &mut self.random);
                self.maybe_padding(out);
                for clue in puzzle {
                    self.maybe_padding(out);
                    out.push(clue);
                }
            }
            return;
        }
        let prefix = self.random.gen_range(1..=2);
        for _ in 0..prefix {
            self.forced_padding(out);
        }
        let mut bits = 0u32;
        let mut bit_count = 0u8;
        let mut gap = self.random.gen_range(1..=2);
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
                    gap = self.random.gen_range(1..=2);
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
}

pub(crate) struct ObfsStream {
    inner: BoxStream,
    decoder: Decoder,
    encoder: Encoder,
    input: [u8; 4096],
    input_used: usize,
    input_len: usize,
    pending: Vec<u8>,
    written: usize,
    failed: bool,
    local_closed: bool,
    remote_closed: bool,
    flush_pending: bool,
    shutdown_done: bool,
    wake: Arc<DuplexWake>,
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
            input: [0; 4096],
            input_used: 0,
            input_len: 0,
            pending: Vec::new(),
            written: 0,
            failed: false,
            local_closed: false,
            remote_closed: false,
            flush_pending: false,
            shutdown_done: false,
            wake: DuplexWake::new(),
        })
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
        if !self.failed { self.failed = true; self.wake.wake_both(); }
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
                Ok(()) => { self.shutdown_done = true; self.flush_pending = false; self.wake.wake_writer(); },
                Err(error) => { self.fail(); return Poll::Ready(Err(error)); },
            }
        } else if self.flush_pending {
            match ready!(Pin::new(&mut self.inner).poll_flush(cx)) {
                Ok(()) => { self.flush_pending = false; self.wake.wake_writer(); },
                Err(error) => { self.fail(); return Poll::Ready(Err(error)); },
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
        if this.failed {
            return Poll::Ready(Err(closed()));
        }
        if let Poll::Ready(Err(error)) = this.output(cx) {
            return Poll::Ready(Err(error));
        }
        let original = output.filled().len();
        let mut consumed = 0;
        loop {
            while this.input_used < this.input_len && output.remaining() > 0 {
                let byte = this.input[this.input_used];
                this.input_used += 1;
                consumed += 1;
                match this.decoder.push(byte) {
                    Ok(Some(decoded)) => output.put_slice(&[decoded]),
                    Ok(None) => {}
                    Err(error) => {
                        this.fail();
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
                    }
                }
            }
            if output.filled().len() > original {
                return Poll::Ready(Ok(()));
            }
            if this.remote_closed {
                return Poll::Ready(Ok(()));
            }
            if consumed >= 65536 {
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
        if this.failed || this.local_closed {
            return Poll::Ready(Err(closed()));
        }
        ready!(this.output(cx))?;
        let count = bytes.len().min(4096);
        this.encoder.encode(&bytes[..count], &mut this.pending);
        if count != 0 { this.wake.wake_reader(); }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let forwarded = this.wake.writer(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if this.failed {
            return Poll::Ready(Err(closed()));
        }
        if !this.shutdown_done { this.flush_pending = true; }
        this.output(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let forwarded = this.wake.writer(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if this.failed {
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
            assert!(client.pending.len() <= 4096 * 9 + 128);
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
    use crate::codec::{layout::Mode,table::{GridOrder,Pair}};

    #[test]
    fn zero_and_full_padding_boundaries_preserve_wire_and_skip_zero_sampling() {
        let order=Arc::new(GridOrder::new("synthetic-padding-boundaries"));
        let pair=Pair::new("synthetic-padding-boundaries",Mode::parse("prefer_entropy").unwrap(),"",order).unwrap();
        let mut zero=Encoder::new(pair.up.clone(),false,0,0).unwrap();let mut expected_random=zero.random.clone();let mut no_padding=Vec::new();
        for _ in 0..1024 {zero.maybe_padding(&mut no_padding);}
        assert!(no_padding.is_empty());assert_eq!(zero.random.next_u64(),expected_random.next_u64());
        let plain:Vec<u8>=(0..=255).collect();
        for padding in [0,100] {for packed in [false,true] {
            let mut encoder=Encoder::new(pair.up.clone(),packed,padding,padding).unwrap();let mut encoded=Vec::new();encoder.encode(&plain,&mut encoded);
            if !packed {assert_eq!(encoded.len(),plain.len()*if padding==0{4}else{9});}
            let mut decoder=Decoder::new(pair.up.clone(),packed);let mut decoded=Vec::new();for byte in encoded {if let Some(value)=decoder.push(byte).unwrap(){decoded.push(value);}}decoder.finish().unwrap();assert_eq!(decoded,plain);
        }}
    }
}

#[cfg(test)]
mod joint_sampling_wire_tests {
    use super::*;
    use crate::codec::{layout::Mode,table::{GridOrder,Pair}};

    #[test]
    fn joint_puzzle_selection_preserves_default_padding_and_chunked_wire_roundtrip() {
        let order=Arc::new(GridOrder::new("synthetic-joint-default-padding"));
        let input:Vec<u8>=(0..8193).map(|index|(index&255) as u8).collect();
        for mode in [Mode::Ascii,Mode::Entropy,Mode::AsciiUp,Mode::EntropyUp] {
            let pattern=if mode==Mode::Ascii{""}else{"xpxvvpvv"};
            let pair=Pair::new("synthetic-joint-default-padding",mode,pattern,order.clone()).unwrap();
            for table in [pair.up,pair.down] {for packed in [false,true] {
                let mut encoder=Encoder::new(table.clone(),packed,10,30).unwrap();
                assert!(encoder.threshold>=10*(1u64<<32)/100);
                assert!(encoder.threshold<=30*(1u64<<32)/100);
                let mut wire=Vec::new();for chunk in input.chunks(4096){encoder.encode(chunk,&mut wire);}
                if !packed{assert!(wire.len()>=input.len()*4 && wire.len()<=input.len()*9);}
                let mut decoder=Decoder::new(table,packed);let mut output=Vec::new();
                for byte in wire {if let Some(byte)=decoder.push(byte).unwrap(){output.push(byte);}}
                decoder.finish().unwrap();assert_eq!(output,input);
            }}
        }
    }
}
