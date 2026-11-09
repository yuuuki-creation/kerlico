use std::collections::HashMap;
use std::io;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::go_rng;
use crate::finalmask::invalid;

pub(super) struct Codebook {
    pub(super) encode: Vec<&'static [[u8; 4]]>,
    pub(super) decode: HashMap<[u8; 4], u8>,
}

impl Codebook {
    pub(super) fn new(password: &str) -> Self {
        static PATTERNS: OnceLock<Vec<Vec<[u8; 4]>>> = OnceLock::new();
        let patterns = PATTERNS.get_or_init(patterns);
        let hash = Sha256::digest(password.as_bytes());
        let seed = i64::from_be_bytes(hash[..8].try_into().expect("SHA-256 prefix"));
        let mut order: Vec<_> = (0..patterns.len()).collect();
        go_rng::shuffle(&mut order, seed);
        let mut encode = Vec::with_capacity(256);
        let mut decode = HashMap::new();
        for (byte, grid) in order.into_iter().take(256).enumerate() {
            let clues = patterns[grid].as_slice();
            assert!(!clues.is_empty(), "Sudoku grid has no unique clues");
            encode.push(clues);
            for clue in clues {
                decode.insert(*clue, byte as u8);
            }
        }
        Self { encode, decode }
    }
}

fn patterns() -> Vec<Vec<[u8; 4]>> {
    let mut grids = Vec::with_capacity(288);
    generate(0, &mut [0; 16], &mut [0; 12], &mut grids);
    let mut result = vec![Vec::new(); grids.len()];
    for a in 0..13 {
        for b in a + 1..14 {
            for c in b + 1..15 {
                for d in c + 1..16 {
                    let positions = [a, b, c, d];
                    let mut counts = HashMap::with_capacity(grids.len());
                    let mut candidates = Vec::with_capacity(grids.len());
                    for grid in &grids {
                        let mut clues = positions.map(|pos| (grid[pos] << 4) | pos as u8);
                        clues.sort_unstable();
                        *counts.entry(clues).or_insert(0u16) += 1;
                        candidates.push(clues);
                    }
                    for (list, clue) in result.iter_mut().zip(candidates) {
                        if counts[&clue] == 1 {
                            list.push(clue);
                        }
                    }
                }
            }
        }
    }
    result
}

fn generate(pos: usize, grid: &mut [u8; 16], used: &mut [u8; 12], out: &mut Vec<[u8; 16]>) {
    if pos == grid.len() {
        out.push(*grid);
        return;
    }
    let row = pos / 4;
    let col = pos % 4;
    let groups = [row, 4 + col, 8 + (row / 2) * 2 + col / 2];
    let occupied = groups.iter().fold(0, |mask, &group| mask | used[group]);
    for num in 0..4 {
        let bit = 1 << num;
        if occupied & bit != 0 {
            continue;
        }
        grid[pos] = num;
        for group in groups {
            used[group] |= bit;
        }
        generate(pos + 1, grid, used, out);
        for group in groups {
            used[group] &= !bit;
        }
    }
}

pub(super) struct Layout {
    pub(super) marker: u8,
    pub(super) padding: Vec<u8>,
    pub(super) hint: [u8; 64],
    pub(super) group: [Option<u8>; 256],
}

impl Layout {
    pub(super) fn ascii() -> Self {
        let hint = std::array::from_fn(|index| if index == 63 { b'\n' } else { index as u8 | 0x40 });
        let group = std::array::from_fn(|index| {
            let byte = index as u8;
            if byte == b'\n' {
                Some(63)
            } else {
                (byte & 0x40 != 0).then_some(byte & 63)
            }
        });
        Self { marker: 0x3f, padding: (0x20..=0x3f).collect(), hint, group }
    }

    pub(super) fn entropy() -> Self {
        let hint = std::array::from_fn(|index| {
            let group = index as u8;
            ((group & 0x30) << 1) | (group & 0x0f)
        });
        let group = std::array::from_fn(|index| {
            let byte = index as u8;
            (byte & 0x90 == 0).then_some(((byte >> 1) & 0x30) | (byte & 0x0f))
        });
        let padding = (0..8).flat_map(|i| [0x80 + i, 0x10 + i]).collect();
        Self { marker: 0x80, padding, hint, group }
    }

    pub(super) fn normalize_pattern(pattern: &str) -> io::Result<String> {
        let pattern = pattern.trim().replace(' ', "").to_ascii_lowercase();
        let count = |mark| pattern.bytes().filter(|&c| c == mark).count();
        if !pattern.is_empty() && (pattern.len() != 8 || count(b'x') != 2 || count(b'p') != 2 || count(b'v') != 4) {
            return Err(invalid("Sudoku custom table must contain two x, two p, and four v bits"));
        }
        Ok(pattern)
    }

    pub(super) fn custom(pattern: &str) -> Self {
        let positions = |mark| pattern.bytes().enumerate().filter_map(move |(i, byte)| (byte == mark).then_some(7 - i));
        let fixed: Vec<_> = positions(b'x').collect();
        let variable: Vec<_> = positions(b'p').chain(positions(b'v')).collect();
        let mask = (1 << fixed[0]) | (1 << fixed[1]);
        let hint = std::array::from_fn(|group| {
            variable.iter().enumerate().fold(mask, |byte, (i, bit)| {
                byte | (((group as u8 >> (5 - i)) & 1) << bit)
            })
        });
        let mut group = [None; 256];
        let mut padding = Vec::new();
        for (index, &byte) in hint.iter().enumerate() {
            group[usize::from(byte)] = Some(index as u8);
            for &bit in &fixed {
                let candidate = byte & !(1 << bit);
                if candidate.count_ones() >= 5 {
                    padding.push(candidate);
                }
            }
        }
        padding.sort_unstable();
        padding.dedup();
        Self { marker: padding[0], padding, hint, group }
    }
}
