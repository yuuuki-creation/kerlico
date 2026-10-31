//! v6 的 PSK 派生参数；所有溢出按线协议使用模 2^64 运算。
use blake2::{Blake2b, Digest, digest::consts::U32};
const GAMMA: u64 = 0x9e3779b97f4a7c15;
const A: u64 = 0xe7037ed1a0b428db;
const B: u64 = 0x589965cc75374cc3;
const ADD_A: u64 = 0x8f3907f7b2b80c35;
const ADD_B: u64 = 0x33a213ec50ffe2e9;
const DOMAIN: u64 = 0xd6e8feb86659fd93;
fn mix(mut n: u64) -> u64 {
    n ^= n >> 30;
    n = n.wrapping_mul(0xbf58476d1ce4e5b9);
    n ^= n >> 27;
    n = n.wrapping_mul(0x94d049bb133111eb);
    n ^ (n >> 31)
}
fn prf(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let n = mix(namespace
        ^ b.wrapping_mul(B).wrapping_add(ADD_B)
        ^ (label as u64).wrapping_mul(GAMMA)
        ^ a.wrapping_mul(A).wrapping_add(ADD_A));
    (n ^ (n >> 32)) as u32
}
fn range(raw: u32, lo: usize, hi: usize) -> usize {
    lo + raw as usize % (hi - lo + 1)
}
#[derive(Clone)]
pub(crate) struct Profile {
    ns: [u64; 7],
    pub salt_len: usize,
    handshake_rounds: usize,
    handshake_stride: u8,
    prefix_lo: usize,
    prefix_hi: usize,
    generator: u32,
    pad_lo: usize,
    pad_hi: usize,
    pad_count: u32,
    pad_interval: u32,
    small_limit: usize,
    bit_lo: usize,
    bit_hi: usize,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: usize,
    mix_offset: usize,
    mix_block: usize,
    pub initial: usize,
    pub first_cap: usize,
    pub maximum: usize,
    pub step: usize,
    pub reset_seconds: u64,
    chunk_policy: u32,
    chunk_jitter: usize,
    chunk_buckets: [usize; 8],
    write_policy: u32,
    write_first: u32,
    write_jitter: usize,
    write_percent: usize,
    write_buckets: [usize; 8],
    write_sequence: [usize; 8],
    g: [usize; 6],
}
impl Profile {
    pub fn new(psk: &[u8]) -> Self {
        let seed = [
            0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18,
            0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
        ];
        let secret = Blake2b::<U32>::new()
            .chain_update(seed)
            .chain_update(psk)
            .finalize();
        let mut words = [0u64; 4];
        for (index, bytes) in secret.as_chunks::<8>().0.iter().enumerate() {
            words[index] = u64::from_le_bytes(*bytes);
        }
        let seeds = [
            0xb46c2e7d9a1538f1u64,
            0x5d9217c083e64ab9,
            0xa71f0c54d8396e2b,
            0x3e8a91b52740f6cd,
            0xc9f4260b7d1e835a,
            0x62d0b5e19c4a783f,
            0x917b3c48e6a205d4,
        ];
        let labels = [5, 0, 2, 3, 16, 21, 28];
        let mut ns = [0; 7];
        for i in 0..7 {
            ns[i] = mix((labels[i] as u64).wrapping_mul(DOMAIN)
                ^ seeds[i].wrapping_add(0xa0761d6478bd642f)
                ^ words[0]
                ^ words[1].wrapping_add(GAMMA)
                ^ words[2].rotate_left(17)
                ^ words[3].rotate_right(11));
        }
        let mut p = Self {
            ns,
            salt_len: 0,
            handshake_rounds: 0,
            handshake_stride: 0,
            prefix_lo: 0,
            prefix_hi: 0,
            generator: 0,
            pad_lo: 0,
            pad_hi: 0,
            pad_count: 0,
            pad_interval: 0,
            small_limit: 0,
            bit_lo: 0,
            bit_hi: 0,
            mix_mode: 0,
            mix_rounds: 0,
            mix_stride: 0,
            mix_offset: 0,
            mix_block: 0,
            initial: 0,
            first_cap: 0,
            maximum: 0,
            step: 0,
            reset_seconds: 0,
            chunk_policy: 0,
            chunk_jitter: 0,
            chunk_buckets: [0; 8],
            write_policy: 0,
            write_first: 0,
            write_jitter: 0,
            write_percent: 0,
            write_buckets: [0; 8],
            write_sequence: [0; 8],
            g: [0; 6],
        };
        p.pad_lo = p.pick(7, 0, 0, 0x18, 0xa0);
        p.pad_hi = (p.pad_lo + p.pick(8, 0, 0, 0xa0, 0x3c0)).min(0x2da);
        let hslo = p.pick(14, 0, 0x7053, 0x10, 0x60);
        let hshi = (hslo + p.pick(15, 0, 0x7053, 0x10, 0xa0)).min(0x80);
        p.salt_len = 16 + p.pick(33, 0, 0x7053, hslo.min(hshi), hshi);
        p.handshake_rounds = p.pick(17, 0, 0x51a7, 1, 4);
        p.handshake_stride = p.pick(18, 0, 0x51a7, 0x11, 0xfb) as u8;
        p.prefix_lo = p.pick(14, 0, 0, 8, 0x50);
        p.prefix_hi = (p.prefix_lo + p.pick(15, 0, 0, 0x10, 0xa0)).min(0x80);
        p.prefix_lo = p.prefix_lo.min(p.prefix_hi);
        p.initial = p.pick(22, 0, 0, 0x200, 0x5b4).clamp(0x60, 0x5b4);
        p.first_cap = p
            .pick(22, 0, 0xf17c, 0x100, 0x300)
            .min(p.initial.min(0x300))
            .max(0x100);
        p.maximum = p.pick(23, 0, 0, 0x2000, 0x3fff).max(p.initial);
        p.generator = p.value(6, 0, 0) & 3;
        p.pad_count = p.pick(9, 0, 0, 2, 8) as u32;
        p.pad_interval = p.pick(10, 0, 0, 2, 11) as u32;
        p.small_limit = p.pick(11, 0, 0, 0x60, 0x300);
        p.bit_lo = p.pick(12, 0, 0, 0x18, 0x29);
        p.bit_hi = p.pick(13, 0, 0, 0x3a, 0x4c);
        p.mix_mode = p.value(16, 0, 0) % 3;
        p.mix_rounds = p.pick(17, 0, 0, 1, 3) as u32;
        p.mix_stride = p.pick(18, 0, 0, 2, 13);
        p.mix_offset = p.pick(19, 0, 0, 0, 15);
        p.mix_block = p.pick(20, 0, 0, 8, 0x40);
        p.chunk_policy = p.value(21, 0, 0) % 3;
        p.step = p.pick(24, 0, 0, 0x400, 0x1000).min(0xb68);
        p.chunk_jitter = p.pick(25, 0, 0, 0x10, 0xc0).min(0xb6);
        p.reset_seconds = p.pick(27, 0, 0, 0xc, 0x5a) as u64;
        p.write_policy = p.value(28, 0, 0) % 3;
        p.write_first = p.pick(29, 0, 0, 4, 8) as u32;
        p.write_jitter = p.pick(32, 0, 0, 8, 0x60);
        p.write_percent = p.pick(28, 0, 0x504c, 8, 0x30);
        for i in 0..8 {
            p.chunk_buckets[i] = p.pick(26, 0, i as u32, 0x1000, p.maximum);
            p.write_buckets[i] = p.pick(30, 0, i as u32, 0x140, 0x5b4);
            p.write_sequence[i] = p.pick(31, 0, i as u32, 0x168, 0x5b4);
        }
        for (i, (lo, hi)) in [
            (0x18, 0x80),
            (0x10, 0x60),
            (0x10, 0x60),
            (0, 9),
            (1, 8),
            (7, 0x17),
        ]
        .into_iter()
        .enumerate()
        {
            p.g[i] = p.pick(6, 0, (i + 1) as u32, lo, hi);
        }
        p
    }
    fn namespace(&self, label: u32) -> u64 {
        self.ns[match label {
            0 | 1 | 14 | 15 | 33 | 34 => 1,
            2 => 2,
            3 | 16..=20 => 4,
            21..=26 | 38 | 39 => 5,
            28..=32 | 35..=37 => 6,
            _ => 0,
        }]
    }
    fn value(&self, label: u32, a: u32, b: u32) -> u32 {
        prf(self.namespace(label), label, a as u64, b as u64)
    }
    fn pick(&self, label: u32, a: u32, b: u32, lo: usize, hi: usize) -> usize {
        range(self.value(label, a, b), lo, hi)
    }
    fn bytes(&self, label: u32, seq: u32, length: usize) -> Vec<u8> {
        let mut state = self.namespace(label)
            ^ (seq as u64)
                .wrapping_mul(DOMAIN)
                .wrapping_add(0xb57de1f3f82cb33f)
            ^ (label as u64).wrapping_mul(0xa24baed4963ee407)
            ^ (length as u64)
                .wrapping_mul(0x165667b19e3779f9)
                .wrapping_add(0x0d4cd3e7b14a36d7);
        let mut out = Vec::with_capacity(length);
        while out.len() < length {
            state = state.wrapping_add(GAMMA);
            let block = mix(state).to_le_bytes();
            let n = (length - out.len()).min(8);
            out.extend_from_slice(&block[..n]);
        }
        out
    }
    pub fn prefix_len(&self, seq: u32) -> usize {
        self.pick(33, seq, 0, self.prefix_lo, self.prefix_hi)
    }
    fn permutation(&self) -> Vec<usize> {
        let mut order: Vec<_> = (0..self.salt_len).collect();
        for round in 0..self.handshake_rounds {
            for i in 0..order.len() {
                let value = mix((i as u64).wrapping_mul(B).wrapping_add(ADD_B)
                    ^ (self.ns[3] ^ 0xdaa66d2c7ddf743f)
                    ^ (0x51a7u64 + round as u64)
                        .wrapping_mul(A)
                        .wrapping_add(ADD_A));
                let folded = (value ^ (value >> 32)) as u32;
                let j = i + folded as usize % (order.len() - i);
                order.swap(i, j);
            }
        }
        order
    }
    fn salt_mask(&self, index: usize) -> u8 {
        (index as u8).wrapping_mul(self.handshake_stride)
            ^ prf(self.ns[3], 2, 0x51a7, index as u64) as u8
    }
    pub fn extract_salt(&self, block: &[u8]) -> [u8; 16] {
        let order = self.permutation();
        let mut salt = [0; 16];
        for i in 0..16 {
            salt[i] = block[order[i]] ^ self.salt_mask(i);
        }
        salt
    }
    pub fn salt_block(&self, salt: &[u8; 16]) -> Vec<u8> {
        let mut block = self.filler(u32::MAX, self.salt_len);
        let order = self.permutation();
        for i in 0..16 {
            block[order[i]] = salt[i] ^ self.salt_mask(i);
        }
        block
    }
    pub fn chunk_limit(&self, seq: u32, size: usize) -> usize {
        let size = size.max(self.initial);
        let value = match self.chunk_policy {
            1 => self.chunk_buckets[(self.value(38, seq, size as u32) as usize) % 8],
            2 => ((size as isize)
                + (self.value(39, seq, size as u32) as usize % (2 * self.chunk_jitter + 1))
                    as isize
                - self.chunk_jitter as isize)
                .max(0) as usize,
            _ => size,
        };
        value
            .clamp(0x40, self.maximum)
            .min(if seq == 0 { self.first_cap } else { usize::MAX })
    }
    fn write_target(&self, seq: u32, length: usize) -> usize {
        if length > 0x5b3 {
            return length.min(0xffff);
        }
        let mut target = if seq < self.write_first {
            self.write_sequence[seq as usize]
        } else {
            self.write_buckets[self.value(35, seq, length as u32) as usize % 8]
        };
        if self.write_policy == 2 {
            target = (target as isize
                + (self.value(36, seq, 0) as usize % (2 * self.write_jitter + 1)) as isize
                - self.write_jitter as isize)
                .max(1) as usize;
        }
        let spread = (length * self.write_percent / 100).min(0x2da);
        if self.value(35, seq, spread as u32) & 1 == 0 {
            target = (target + spread).min(65535);
        } else {
            target = target.saturating_sub(spread / 2);
        }
        while target < length {
            let next = self.write_buckets[self.value(37, seq, target as u32) as usize % 8];
            target = if next <= target {
                (target + self.pad_hi).min(65535)
            } else {
                next
            };
        }
        target
    }
    pub fn padding_len(&self, seq: u32, payload: usize, first: bool) -> usize {
        let prefix = self.prefix_len(seq);
        let salt = if first { self.salt_len } else { 0 };
        let mut padding = if seq < self.pad_count
            || (payload > 0 && payload <= self.small_limit)
            || seq.is_multiple_of(self.pad_interval)
        {
            self.pick(34, seq, payload as u32, self.pad_lo, self.pad_hi)
        } else {
            0
        };
        let wire = salt + prefix + 23 + padding + payload + if payload > 0 { 16 } else { 0 };
        let target = self.write_target(seq, wire);
        padding += target.saturating_sub(wire).min(0x2da);
        if first {
            let threshold = ((payload + if payload == 0 { 0x27 } else { 0x37 }) * 25)
                .div_ceil(75)
                .max(0xc0);
            let overhead = (salt - 16) + prefix + padding;
            if overhead < threshold {
                padding = threshold
                    .saturating_sub(salt - 16 + prefix)
                    .min(self.pad_hi + 0x2da);
            }
        }
        padding.min(65535)
    }
    pub fn mix(&self, seq: u32, padding: &mut [u8], data: &mut [u8]) {
        let n = padding.len().min(data.len());
        for round in 0..self.mix_rounds {
            let stride = self.mix_stride + (round as usize % 3);
            match self.mix_mode {
                1 => {
                    let block = self.mix_block;
                    let mut offset = (round as usize & 1) * block;
                    while offset + block <= n {
                        for i in offset..offset + block {
                            std::mem::swap(&mut padding[i], &mut data[i]);
                        }
                        offset += block * 2;
                    }
                }
                _ => {
                    let offset = if self.mix_mode == 2 {
                        (self.value(3, seq, round) as usize + self.mix_offset) % stride
                    } else {
                        self.mix_offset % stride
                    };
                    for i in (offset..n).step_by(stride) {
                        std::mem::swap(&mut padding[i], &mut data[i]);
                    }
                }
            }
        }
    }
    pub fn filler(&self, seq: u32, length: usize) -> Vec<u8> {
        let mut bytes = self.bytes(0, seq, length);
        match self.generator {
            0 => {
                let count = self.pick(1, seq, 0, self.bit_lo, self.bit_hi);
                let row = if count * 8 > 0x31 {
                    ((count * 8 + 0x32) / 100).min(7)
                } else {
                    1
                }
                .max(1);
                let table: [[u8; 16]; 7] = [
                    [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128],
                    [3, 5, 9, 17, 33, 65, 129, 6, 10, 18, 34, 66, 130, 12, 24, 36],
                    [
                        7, 11, 19, 35, 67, 131, 13, 25, 49, 97, 193, 14, 28, 56, 112, 224,
                    ],
                    [
                        15, 23, 39, 71, 135, 27, 51, 99, 195, 29, 57, 113, 225, 60, 120, 240,
                    ],
                    [
                        248, 244, 236, 220, 188, 124, 242, 230, 206, 158, 62, 241, 227, 199, 143,
                        31,
                    ],
                    [
                        252, 250, 246, 238, 222, 190, 126, 249, 245, 237, 221, 189, 125, 243, 231,
                        219,
                    ],
                    [
                        254, 253, 251, 247, 239, 223, 191, 127, 254, 253, 251, 247, 239, 223, 191,
                        127,
                    ],
                ];
                for (i, value) in bytes.iter_mut().enumerate() {
                    let raw = value.wrapping_add(i as u8);
                    *value = table[row - 1][((raw ^ *value) & 15) as usize]
                        .rotate_left(((raw ^ (*value >> 4)) & 7) as u32);
                }
            }
            1 => {
                for (i, value) in bytes.iter_mut().enumerate() {
                    let bucket = *value as usize % (self.g[0] + self.g[1] + self.g[2]);
                    *value = if bucket < self.g[0] {
                        range(value.wrapping_add(i as u8) as u32, 0x20, 0x7e) as u8
                    } else if bucket < self.g[0] + self.g[1] {
                        range((*value ^ (i as u8)) as u32, 0x80, 0xbf) as u8
                    } else {
                        range(value.wrapping_add((i * 7) as u8) as u32, 0xc0, 0xff) as u8
                    };
                }
            }
            2 => {
                for (i, value) in bytes.iter_mut().enumerate() {
                    let lo = ((*value & 15) as usize + self.g[3] + (i & 1)) % 10;
                    let hi = (*value as usize + ((i & 3) << 4) + 0x30) & 0xf0;
                    *value = (hi | lo) as u8;
                }
            }
            _ => {
                let motif = self.bytes(2, seq, 32);
                let period = self.g[5].max(5);
                let motif_len = self.g[4] * 4;
                for (i, value) in bytes.iter_mut().enumerate() {
                    let position = i % period;
                    if position < period - 3 {
                        *value = ((self.g[4] + 3) * i) as u8 ^ motif[(i % motif_len) % 32];
                    } else if position < period - 1 {
                        *value = 0x30 | (*value % 10);
                    }
                }
            }
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    impl Profile {
        fn snapshot(&self) -> Value {
            json!({"namespaces":{"profile":self.ns[0],"prefix":self.ns[1],"motif":self.ns[2],"salt":self.ns[3],"mix":self.ns[4],"chunk":self.ns[5],"write":self.ns[6]},
            "generator":self.generator,"padMin":self.pad_lo,"padMax":self.pad_hi,"padCount":self.pad_count,"padInterval":self.pad_interval,"smallLimit":self.small_limit,"bitMin":self.bit_lo,"bitMax":self.bit_hi,"prefixMinRecord":self.prefix_lo,"prefixMaxRecord":self.prefix_hi,"mixMode":self.mix_mode,"mixRounds":self.mix_rounds,"mixStride":self.mix_stride,"mixOffsetBase":self.mix_offset,"mixBlock":self.mix_block,"chunkPolicy":self.chunk_policy,"chunkInitial":self.initial,"firstRecordCap":self.first_cap,"chunkMax":self.maximum,"chunkStep":self.step,"chunkJitter":self.chunk_jitter,"idleResetSec":self.reset_seconds,"writePolicy":self.write_policy,"writeFirst":self.write_first,"chunkBuckets":self.chunk_buckets,"writeBuckets":self.write_buckets,"writeSeq":self.write_sequence,"writeJitter":self.write_jitter,"writeJitterPct":self.write_percent,"g1":self.g[0],"g2":self.g[1],"g3":self.g[2],"g4":self.g[3],"g5":self.g[4],"g6":self.g[5],"saltBlockLen":self.salt_len,"mixStrideHandshake":self.handshake_stride,"mixRoundsHandshake":self.handshake_rounds,"recordPrefixMax":self.prefix_hi,"padMaxHeadroom":self.pad_hi+0x2da})
        }
    }
    #[test]
    #[ignore = "需要先在 worker 以固定 Go 对端生成 SNELL_VECTOR_FILE"]
    fn fixed_go_profile_and_cipher_vectors() {
        let path = std::env::var("SNELL_VECTOR_FILE").expect("缺少固定对端向量文件");
        let data = std::fs::read(path).unwrap();
        let rows: Vec<Value> = serde_json::from_slice(&data).unwrap();
        assert_eq!(rows.len(), 64);
        let mut salt = [0; 16];
        for (index, byte) in salt.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for row in rows {
            let psk = row["psk"].as_str().unwrap();
            assert_eq!(
                Profile::new(psk.as_bytes()).snapshot(),
                row["profile"],
                "固定对端 profile 不一致：{psk}"
            );
            let mut cipher = crate::crypto::Cipher::new(psk.as_bytes(), &salt).unwrap();
            let sealed = cipher.seal(b"snell-reference-vector", b"aad").unwrap();
            let hex: String = sealed.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, row["cipher"].as_str().unwrap());
        }
    }
}
