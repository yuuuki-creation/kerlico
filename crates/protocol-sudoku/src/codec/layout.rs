use kerlico_core::{Error, Result};
use std::collections::BTreeSet;

#[derive(Clone)]
pub(crate) struct Layout {
    pub ascii: bool,
    pub hints: [[u8; 16]; 4],
    pub hint_index: [Option<u8>; 256],
    pub groups: [u8; 64],
    pub group_index: [Option<u8>; 256],
    pub padding: Vec<u8>,
    pub marker: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Ascii,
    Entropy,
    AsciiUp,
    EntropyUp,
}
impl Mode {
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "entropy" | "prefer_entropy" => Ok(Self::Entropy),
            "ascii" | "prefer_ascii" => Ok(Self::Ascii),
            "up_ascii_down_entropy" => Ok(Self::AsciiUp),
            "up_entropy_down_ascii" => Ok(Self::EntropyUp),
            _ => Err(Error::Config("Sudoku table方向模式不合法".into())),
        }
    }
    pub fn canonical(self) -> &'static str {
        match self {
            Self::Ascii => "prefer_ascii",
            Self::Entropy => "prefer_entropy",
            Self::AsciiUp => "up_ascii_down_entropy",
            Self::EntropyUp => "up_entropy_down_ascii",
        }
    }
    pub fn ascii(self, uplink: bool) -> bool {
        match self {
            Self::Ascii => true,
            Self::Entropy => false,
            Self::AsciiUp => uplink,
            Self::EntropyUp => !uplink,
        }
    }
}

impl Layout {
    pub fn new(ascii: bool, pattern: &str) -> Result<Self> {
        if !ascii && !pattern.trim().is_empty() {
            return Self::custom(pattern);
        }
        let mut layout = Self {
            ascii,
            hints: [[0; 16]; 4],
            hint_index: [None; 256],
            groups: [0; 64],
            group_index: [None; 256],
            padding: Vec::new(),
            marker: if ascii { 0x3f } else { 0x80 },
        };
        for value in 0..4 {
            for position in 0..16 {
                let mut wire = if ascii {
                    0x40 | ((value as u8) << 4) | position as u8
                } else {
                    ((value as u8) << 5) | position as u8
                };
                if ascii && wire == 0x7f {
                    wire = b'\n';
                }
                layout.hints[value][position] = wire;
            }
        }
        if ascii {
            layout.padding = (0x20..0x40).collect();
            for byte in 0u16..=255 {
                if byte & 0x40 != 0 {
                    layout.hint_index[byte as usize] = Some(64);
                    layout.group_index[byte as usize] = Some((byte & 63) as u8);
                }
            }
            layout.group_index[b'\n' as usize] = Some(63);
        } else {
            for byte in 0u8..8 {
                layout
                    .padding
                    .extend_from_slice(&[0x80 + byte, 0x10 + byte]);
            }
            for byte in 0u16..=255 {
                if byte & 0x90 == 0 {
                    layout.group_index[byte as usize] =
                        Some((((byte >> 1) & 0x30) | (byte & 0xf)) as u8);
                }
            }
        }
        for group in 0..64 {
            layout.groups[group] = layout.hints[group >> 4][group & 15];
        }
        layout.index_hints();
        Ok(layout)
    }

    fn index_hints(&mut self) {
        for value in 0..4 {
            for position in 0..16 {
                self.hint_index[self.hints[value][position] as usize] =
                    Some(((position << 2) | value) as u8);
            }
        }
    }

    fn custom(pattern: &str) -> Result<Self> {
        let pattern = pattern.trim().to_ascii_lowercase().replace(' ', "");
        let invalid = || Error::Config("Sudoku布局必须恰有两个x、两个p和四个v".into());
        if pattern.len() != 8 {
            return Err(invalid());
        }
        let mut x = Vec::new();
        let mut p = Vec::new();
        let mut v = Vec::new();
        for (index, symbol) in pattern.bytes().enumerate() {
            match symbol {
                b'x' => x.push(7 - index),
                b'p' => p.push(7 - index),
                b'v' => v.push(7 - index),
                _ => return Err(invalid()),
            }
        }
        if x.len() != 2 || p.len() != 2 || v.len() != 4 {
            return Err(invalid());
        }
        let mask = (1u8 << x[0]) | (1u8 << x[1]);
        let encode = |value: usize, position: usize, drop: Option<usize>| {
            let mut wire = mask;
            if let Some(drop) = drop {
                wire &= !(1 << x[drop]);
            }
            if value & 2 != 0 {
                wire |= 1 << p[0];
            }
            if value & 1 != 0 {
                wire |= 1 << p[1];
            }
            for (index, bit) in v.iter().enumerate() {
                if position & (1 << (3 - index)) != 0 {
                    wire |= 1 << bit;
                }
            }
            wire
        };
        let mut pool = BTreeSet::new();
        for drop in 0..2 {
            for value in 0..4 {
                for position in 0..16 {
                    let wire = encode(value, position, Some(drop));
                    if wire.count_ones() >= 5 {
                        pool.insert(wire);
                    }
                }
            }
        }
        let padding: Vec<u8> = pool.into_iter().collect();
        let marker = *padding.first().ok_or_else(invalid)?;
        let mut layout = Self {
            ascii: false,
            hints: [[0; 16]; 4],
            hint_index: [None; 256],
            groups: [0; 64],
            group_index: [None; 256],
            padding,
            marker,
        };
        for value in 0..4 {
            for position in 0..16 {
                layout.hints[value][position] = encode(value, position, None);
            }
        }
        for group in 0..64 {
            let wire = encode(group >> 4, group & 15, None);
            layout.groups[group] = wire;
            layout.group_index[wire as usize] = Some(group as u8);
        }
        layout.index_hints();
        Ok(layout)
    }
}
