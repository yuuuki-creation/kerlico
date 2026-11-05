use super::*;
use crate::codec::{
    layout::Mode,
    table::{GridOrder, Pair},
};
use std::{
    future::{Future, poll_fn},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn order() -> Arc<GridOrder> {
    static ORDER: OnceLock<Arc<GridOrder>> = OnceLock::new();
    ORDER
        .get_or_init(|| Arc::new(GridOrder::new("synthetic-obfs-batch-regression")))
        .clone()
}

fn layouts() -> Vec<Arc<Table>> {
    let mut tables = Vec::new();
    for mode in [Mode::Ascii, Mode::Entropy, Mode::AsciiUp, Mode::EntropyUp] {
        for pattern in ["", "xpxvvpvv", "vxpvxvvp"] {
            let pair =
                Pair::new("synthetic-obfs-batch-regression", mode, pattern, order()).unwrap();
            tables.push(pair.up);
            tables.push(pair.down);
        }
    }
    tables
}

struct ScalarDecoder {
    table: Arc<Table>,
    packed: bool,
    clues: Vec<u8>,
    bits: u32,
    bit_count: u8,
}
impl ScalarDecoder {
    fn new(table: Arc<Table>, packed: bool) -> Self {
        Self {
            table,
            packed,
            clues: Vec::new(),
            bits: 0,
            bit_count: 0,
        }
    }
    fn push(&mut self, wire: u8) -> Result<Option<u8>> {
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
            self.clues.push(clue);
            if self.clues.len() < 4 {
                return Ok(None);
            }
            let clues = self.clues.as_slice().try_into().unwrap();
            self.clues.clear();
            self.table.decode(clues).map(Some)
        }
    }
    fn finish_ok(&self) -> bool {
        self.packed || self.clues.is_empty()
    }
}

fn scalar_maybe_padding(encoder: &mut Encoder, out: &mut Vec<u8>) {
    if encoder.threshold != 0
        && (encoder.threshold == (1u64 << 32)
            || u64::from(encoder.random.next_u32()) < encoder.threshold)
    {
        let index = encoder.padding_dist.sample(&mut encoder.random);
        out.push(encoder.padding[index]);
    }
}
fn scalar_forced_padding(encoder: &mut Encoder, out: &mut Vec<u8>) {
    let index = encoder.padding_dist.sample(&mut encoder.random);
    out.push(encoder.padding[index]);
}
fn scalar_encode(encoder: &mut Encoder, bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.is_empty() {
        return;
    }
    if !encoder.packed {
        for &byte in bytes {
            let puzzle = encoder.table.randomized_puzzle(byte, &mut encoder.random);
            scalar_maybe_padding(encoder, out);
            for clue in puzzle {
                scalar_maybe_padding(encoder, out);
                out.push(clue);
            }
        }
        return;
    }
    let prefix = encoder.gap_dist.sample(&mut encoder.random);
    for _ in 0..prefix {
        scalar_forced_padding(encoder, out);
    }
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    let mut gap = encoder.gap_dist.sample(&mut encoder.random);
    let mut since_padding = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        bits = (bits << 8) | u32::from(byte);
        bit_count += 8;
        while bit_count >= 6 {
            bit_count -= 6;
            let group = ((bits >> bit_count) & 63) as usize;
            bits &= (1 << bit_count) - 1;
            scalar_maybe_padding(encoder, out);
            out.push(encoder.table.layout.groups[group]);
        }
        if index < 14 {
            since_padding += 1;
            if since_padding >= gap {
                scalar_forced_padding(encoder, out);
                since_padding = 0;
                gap = encoder.gap_dist.sample(&mut encoder.random);
            }
        }
    }
    if bit_count > 0 {
        scalar_maybe_padding(encoder, out);
        out.push(encoder.table.layout.groups[((bits << (6 - bit_count)) & 63) as usize]);
        out.push(encoder.table.layout.marker);
    }
    scalar_maybe_padding(encoder, out);
}

fn seeded_encoder(table: Arc<Table>, packed: bool, threshold: u64, seed: u64) -> Encoder {
    let mut padding = table.layout.padding.clone();
    if packed {
        padding.retain(|&byte| byte != table.layout.marker);
    }
    let padding_dist = rand::distributions::Uniform::new(0, padding.len());
    let gap_dist = rand::distributions::Uniform::new_inclusive(1, 2);
    Encoder {
        table,
        packed,
        random: FastRng::seed_from_u64(seed),
        threshold,
        padding,
        padding_dist,
        gap_dist,
    }
}

#[test]
fn batch_encoder_matches_scalar_wire_randomness_and_all_padding_boundaries() {
    let plain: Vec<u8> = (0..8193).map(|index| (index % 256) as u8).collect();
    let maximum = 1u64 << 32;
    for table in layouts() {
        for packed in [false, true] {
            for threshold in [0, 1, maximum / 100, maximum / 2, maximum - 1, maximum] {
                for seed in [0, u64::MAX] {
                    let mut actual = seeded_encoder(table.clone(), packed, threshold, seed);
                    let mut old = seeded_encoder(table.clone(), packed, threshold, seed);
                    let mut actual_wire = vec![0xa5];
                    let mut old_wire = actual_wire.clone();
                    for length in (0..=33).chain([63, 64, 65, 4095, 4096, 4097, 8193]) {
                        actual.encode(&plain[..length], &mut actual_wire);
                        scalar_encode(&mut old, &plain[..length], &mut old_wire);
                        assert_eq!(
                            actual_wire, old_wire,
                            "packed={packed}, threshold={threshold}, length={length}"
                        );
                        assert_eq!(
                            actual.random.clone().next_u64(),
                            old.random.clone().next_u64()
                        );
                        actual_wire.clear();
                        old_wire.clear();
                    }
                }
            }
        }
    }
}

fn compare_slices(
    table: Arc<Table>,
    packed: bool,
    wire: &[u8],
    input_chunk: usize,
    output_chunk: usize,
) -> Vec<u8> {
    let mut decoder = Decoder::new(table.clone(), packed);
    let mut scalar = ScalarDecoder::new(table, packed);
    let mut decoded = Vec::new();
    for input in wire.chunks(input_chunk) {
        let empty = decoder.decode_into(input, &mut []);
        assert_eq!((empty.consumed, empty.produced), (0, 0));
        assert!(empty.error.is_none());
        let mut consumed = 0;
        while consumed < input.len() {
            let mut output = vec![0; output_chunk];
            let actual = decoder.decode_into(&input[consumed..], &mut output);
            let mut expected = Vec::new();
            let mut expected_consumed = 0;
            let mut expected_error = false;
            while consumed + expected_consumed < input.len() && expected.len() < output_chunk {
                let byte = input[consumed + expected_consumed];
                expected_consumed += 1;
                match scalar.push(byte) {
                    Ok(Some(byte)) => expected.push(byte),
                    Ok(None) => {}
                    Err(_) => {
                        expected_error = true;
                        break;
                    }
                }
            }
            assert_eq!(actual.consumed, expected_consumed);
            assert_eq!(&output[..actual.produced], expected);
            assert_eq!(actual.error.is_some(), expected_error);
            decoded.extend_from_slice(&output[..actual.produced]);
            if expected_error {
                assert_eq!(decoder.finish().is_ok(), scalar.finish_ok());
                return decoded;
            }
            assert!(actual.consumed > 0);
            consumed += actual.consumed;
        }
        assert_eq!(decoder.finish().is_ok(), scalar.finish_ok());
    }
    decoded
}

#[test]
fn slice_decoder_consumes_independent_go_vectors_with_input_and_output_splits() {
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
            let hex = vector[field].as_str().unwrap();
            let wire: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                .collect();
            for input_chunk in [1, 2, 3, 4, 7, 31, 4096] {
                for output_chunk in [1, 2, 3, 17, 1024] {
                    assert_eq!(
                        compare_slices(pair.up.clone(), packed, &wire, input_chunk, output_chunk),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn slice_decoder_matches_scalar_across_every_short_wire_split() {
    let plain: Vec<u8> = (0..17).map(|byte| byte * 13).collect();
    for table in layouts() {
        for packed in [false, true] {
            for threshold in [0, 1u64 << 32] {
                let mut old = seeded_encoder(table.clone(), packed, threshold, 19);
                let mut wire = Vec::new();
                scalar_encode(&mut old, &plain, &mut wire);
                for cut in 1..=wire.len() {
                    for output_chunk in [1, 3] {
                        assert_eq!(
                            compare_slices(table.clone(), packed, &wire, cut, output_chunk),
                            plain
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn slice_decoder_preserves_every_wire_class_partial_clue_marker_and_invalid_prefix() {
    for table in layouts() {
        let puzzle = table.puzzle(0xa5, 0);
        for byte in 0..=255u8 {
            for boundary in 0..=4 {
                let mut wire = puzzle[..boundary].to_vec();
                wire.push(byte);
                wire.extend_from_slice(&puzzle[boundary..]);
                wire.extend_from_slice(&puzzle);
                for input_chunk in [1, 3, 16] {
                    compare_slices(table.clone(), false, &wire, input_chunk, 1);
                }
            }
            for groups in 0..=3 {
                let mut wire = vec![table.layout.groups[37]; groups];
                wire.push(byte);
                wire.extend_from_slice(&table.layout.groups[11..18]);
                for input_chunk in [1, 2, 16] {
                    compare_slices(table.clone(), true, &wire, input_chunk, 2);
                }
            }
            let mut invalid = puzzle.to_vec();
            invalid.extend_from_slice(&[byte; 4]);
            invalid.extend_from_slice(&puzzle);
            compare_slices(table.clone(), false, &invalid, 64, 64);
        }
        for tail in 0..4 {
            compare_slices(table.clone(), false, &puzzle[..tail], 1, 1);
        }
    }
}

#[tokio::test]
async fn cancelled_read_keeps_partial_clues_bits_and_unread_wire_without_replay() {
    let table = layouts().remove(0);
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        for packed in [false, true] {
            for prefix in 1..=3 {
                let (inner, mut peer) = tokio::io::duplex(4096);
                let mut stream = ObfsStream::new(
                    Box::new(inner),
                    table.clone(),
                    table.clone(),
                    packed,
                    false,
                    0,
                    0,
                )
                .unwrap();
                let plain = b"cancelled-read-keeps-tail";
                let wire = if packed {
                    let mut encoder = seeded_encoder(table.clone(), true, 0, 7);
                    let mut wire = Vec::new();
                    scalar_encode(&mut encoder, plain, &mut wire);
                    wire
                } else {
                    plain
                        .iter()
                        .flat_map(|&byte| table.puzzle(byte, 0))
                        .collect()
                };
                let split = if packed {
                    wire.iter()
                        .enumerate()
                        .filter(|(_, byte)| table.layout.group_index[**byte as usize].is_some())
                        .nth(prefix - 1)
                        .unwrap()
                        .0
                        + 1
                } else {
                    prefix
                };
                peer.write_all(&wire[..split]).await.unwrap();
                let mut received = vec![0; if packed { prefix * 6 / 8 } else { 0 }];
                stream.read_exact(&mut received).await.unwrap();
                let mut first = [0; 1];
                let mut abandoned = Box::pin(stream.read(&mut first));
                assert!(poll_fn(|cx| Poll::Ready(abandoned.as_mut().poll(cx).is_pending())).await);
                drop(abandoned);
                peer.write_all(&wire[split..]).await.unwrap();
                peer.shutdown().await.unwrap();
                let mut one = [0; 1];
                stream.read_exact(&mut one).await.unwrap();
                received.extend_from_slice(&one);
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, plain);
                assert_eq!(stream.read(&mut one).await.unwrap(), 0);
            }
        }
    })
    .await
    .expect("放弃读Future后必须在有限时间内恢复并保留完整尾部");
}

struct ObservedIo<T> {
    inner: T,
    read_polls: Arc<AtomicUsize>,
    output_polls: Arc<AtomicUsize>,
}
impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.read_polls.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.output_polls.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.output_polls.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.output_polls.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn invalid_and_truncated_clues_preserve_async_read_prefix_and_latch_failure() {
    let table = layouts().remove(0);
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        for truncated in [false, true] {
            for with_prefix in [false, true] {
                let (inner, mut peer) = tokio::io::duplex(16384);
                let read_polls = Arc::new(AtomicUsize::new(0));
                let output_polls = Arc::new(AtomicUsize::new(0));
                let observed = ObservedIo {
                    inner,
                    read_polls: read_polls.clone(),
                    output_polls: output_polls.clone(),
                };
                let mut stream = ObfsStream::new(
                    Box::new(observed),
                    table.clone(),
                    table.clone(),
                    false,
                    false,
                    0,
                    0,
                )
                .unwrap();
                let puzzle = table.puzzle(0x5a, 0);
                let mut wire = Vec::new();
                if with_prefix {
                    wire.extend_from_slice(&puzzle);
                }
                if truncated {
                    wire.extend_from_slice(&puzzle[..3]);
                } else {
                    wire.extend_from_slice(&[puzzle[0]; 4]);
                    wire.extend_from_slice(&puzzle);
                    wire.resize(wire.len() + 8192, table.layout.padding[0]);
                }
                peer.write_all(&wire).await.unwrap();
                peer.shutdown().await.unwrap();
                let mut output = [0; 16];
                if with_prefix {
                    let count = stream.read(&mut output).await.unwrap();
                    assert_eq!(&output[..count], &[0x5a]);
                    if !truncated {
                        let reads = read_polls.load(Ordering::Relaxed);
                        let writes = output_polls.load(Ordering::Relaxed);
                        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
                        assert_eq!(
                            stream.write(b"late").await.unwrap_err().kind(),
                            io::ErrorKind::BrokenPipe
                        );
                        assert_eq!(
                            stream.flush().await.unwrap_err().kind(),
                            io::ErrorKind::BrokenPipe
                        );
                        assert_eq!(
                            stream.shutdown().await.unwrap_err().kind(),
                            io::ErrorKind::BrokenPipe
                        );
                        assert_eq!(read_polls.load(Ordering::Relaxed), reads);
                        assert_eq!(output_polls.load(Ordering::Relaxed), writes);
                    }
                }
                let reads_before_error = read_polls.load(Ordering::Relaxed);
                let error = stream.read(&mut output).await.unwrap_err();
                if with_prefix && !truncated {
                    assert_eq!(read_polls.load(Ordering::Relaxed), reads_before_error);
                }
                assert_eq!(
                    error.kind(),
                    if truncated {
                        io::ErrorKind::UnexpectedEof
                    } else {
                        io::ErrorKind::InvalidData
                    }
                );
                assert_eq!(
                    error.to_string(),
                    if truncated {
                        Error::Protocol("Sudoku clue在EOF前截断").to_string()
                    } else {
                        crate::invalid().to_string()
                    }
                );
                assert!(error.get_ref().unwrap().downcast_ref::<Error>().is_some());
                let reads = read_polls.load(Ordering::Relaxed);
                let writes = output_polls.load(Ordering::Relaxed);
                assert_eq!(
                    stream.read(&mut output).await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                assert_eq!(
                    stream.write(b"late").await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                assert!(stream.flush().await.is_err());
                assert!(stream.shutdown().await.is_err());
                assert_eq!(read_polls.load(Ordering::Relaxed), reads);
                assert_eq!(output_polls.load(Ordering::Relaxed), writes);
            }
        }
    })
    .await
    .expect("非法或截断clue必须在有限时间内返回并锁存失败");
}

#[tokio::test]
async fn record_none_delivers_obfs_prefix_before_specific_error() {
    use crate::codec::record::{Method, RecordStream};

    let table = layouts().remove(0);
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        let (inner, mut peer) = tokio::io::duplex(4096);
        let stream = ObfsStream::new(
            Box::new(inner),
            table.clone(),
            table.clone(),
            false,
            false,
            0,
            0,
        )
        .unwrap();
        let mut records = RecordStream::new(stream, Method::None, [1; 32], [2; 32]).unwrap();
        let puzzle = table.puzzle(0x5a, 0);
        let mut wire = puzzle.to_vec();
        wire.extend_from_slice(&[puzzle[0]; 4]);
        wire.extend_from_slice(&puzzle);
        peer.write_all(&wire).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut output = [0; 16];
        let count = records.read(&mut output).await.unwrap();
        assert_eq!(&output[..count], &[0x5a]);
        let error = records.read(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), crate::invalid().to_string());
        assert!(error.get_ref().unwrap().downcast_ref::<Error>().is_some());
        assert_eq!(
            records.read(&mut output).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            records.write(b"late").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(records.flush().await.is_err());
        assert!(records.shutdown().await.is_err());
    })
    .await
    .expect("记录层必须先交付解码前缀，再保留具体clue错误并锁存失败");
}
