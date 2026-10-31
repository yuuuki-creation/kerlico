//! 低熵扩展仅变换密文体，保留 tag；先核对掩码、长度和统一填充，再进行 AEAD 验证。
use kerlico_core::{Error, Result};
use rand::seq::SliceRandom;
use std::sync::OnceLock;
fn bad() -> Error {
    Error::Protocol("Mieru 低熵段不合法")
}
pub(crate) fn valid_rotation(value: u8) -> bool {
    value <= 15 || value & 15 == 0
}
pub(crate) fn capacity(mode: u8) -> Result<usize> {
    if !(1..=4).contains(&mode) {
        return Err(bad());
    }
    Ok(usize::from(mode) + 3)
}
pub(crate) fn encoded_len(length: usize, mode: u8) -> Result<usize> {
    let cap = capacity(mode)?;
    let length = length.div_ceil(cap).checked_mul(8).ok_or_else(bad)?;
    if length > u16::MAX as usize {
        return Err(bad());
    }
    Ok(length)
}
pub(crate) fn max_fragment(mode: u8, packet_mtu: Option<usize>) -> Result<usize> {
    match (mode, packet_mtu) {
        (0, None) => Ok(32768),
        (0, Some(mtu)) => mtu.checked_sub(88).filter(|n| *n > 0).ok_or_else(bad),
        (_, None) => Ok(32768.min((u16::MAX as usize / 8) * capacity(mode)?)),
        (_, Some(mtu)) => mtu
            .checked_sub(88)
            .map(|n| n / 8 * capacity(mode).unwrap_or(0))
            .filter(|n| *n > 0)
            .ok_or_else(bad),
    }
}
pub(crate) fn random_mask(mode: u8) -> Result<u32> {
    let ones = 16 + (capacity(mode)? - 4) * 4;
    let mut positions = std::array::from_fn::<_, 32, _>(|i| i);
    positions.shuffle(&mut rand::thread_rng());
    Ok(positions[..ones]
        .iter()
        .fold(0, |mask, bit| mask | 1u32 << bit))
}
fn mask(half: u32, mode: u8, rotation: u8, chunk: usize) -> Result<u64> {
    let cap = capacity(mode)?;
    if !valid_rotation(rotation) || half.count_ones() as usize != 16 + (cap - 4) * 4 {
        return Err(bad());
    }
    let initial = (u64::from(half) << 32) | u64::from(half);
    let shift = ((chunk % 64)
        * usize::from(if rotation <= 15 {
            rotation
        } else {
            rotation / 16
        }))
        % 64;
    Ok(if rotation <= 15 {
        initial.rotate_right(shift as u32)
    } else {
        initial.rotate_left(shift as u32)
    })
}
fn deposit(mut source: u64, mut mask: u64) -> u64 {
    let mut out = 0;
    while mask != 0 {
        let bit = mask.isolate_lowest_one();
        if source & 1 != 0 {
            out |= bit;
        }
        source >>= 1;
        mask &= mask - 1;
    }
    out
}
fn extract(source: u64, mut mask: u64) -> u64 {
    let mut out = 0;
    let mut bit = 1;
    while mask != 0 {
        let position = mask.isolate_lowest_one();
        if source & position != 0 {
            out |= bit;
        }
        bit <<= 1;
        mask &= mask - 1;
    }
    out
}
fn low_bits(length: usize) -> u64 {
    (1u64 << length) - 1
}
pub(crate) fn padding_bit() -> u8 {
    static BIT: OnceLock<u8> = OnceLock::new();
    *BIT.get_or_init(|| u8::from(rand::random::<bool>()))
}
pub(crate) fn encode(
    source: &[u8],
    mode: u8,
    half: u32,
    rotation: u8,
    polarity: u8,
) -> Result<Vec<u8>> {
    if polarity > 1 {
        return Err(bad());
    }
    let cap = capacity(mode)?;
    mask(half, mode, rotation, 0)?;
    let mut out = Vec::with_capacity(encoded_len(source.len(), mode)?);
    for (index, chunk) in source.chunks(cap).enumerate() {
        let mut scratch = [0; 8];
        scratch[8 - chunk.len()..].copy_from_slice(chunk);
        let current = mask(half, mode, rotation, index)?;
        let used = deposit(low_bits(chunk.len() * 8), current);
        let mut word = deposit(u64::from_be_bytes(scratch), current);
        if polarity == 1 {
            word |= !used;
        }
        out.extend(word.to_be_bytes());
    }
    Ok(out)
}
pub(crate) fn decode(
    encoded: &[u8],
    length: usize,
    mode: u8,
    half: u32,
    rotation: u8,
) -> Result<Vec<u8>> {
    let cap = capacity(mode)?;
    mask(half, mode, rotation, 0)?;
    if length > 32768 || encoded.len() != encoded_len(length, mode)? {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(length);
    let mut polarity = None;
    let (chunks, remainder) = encoded.as_chunks::<8>();
    if !remainder.is_empty() {
        return Err(bad());
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let take = cap.min(length - out.len());
        let current = mask(half, mode, rotation, index)?;
        let used = deposit(low_bits(take * 8), current);
        let word = u64::from_be_bytes(*chunk);
        let padding = word & !used;
        let observed = if padding == 0 {
            false
        } else if padding == !used {
            true
        } else {
            return Err(bad());
        };
        if polarity.is_some_and(|previous| previous != observed) {
            return Err(bad());
        }
        polarity = Some(observed);
        let extracted = extract(word, current).to_be_bytes();
        out.extend(&extracted[8 - take..]);
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn documented_chunks_and_padding_are_canonical() {
        let source = [0x12, 0x34, 0x56, 0x78];
        for (polarity, expected) in [
            (0, [1, 2, 3, 4, 5, 6, 7, 8]),
            (1, [0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8]),
        ] {
            let wire = encode(&source, 1, 0x0f0f0f0f, 0, polarity).unwrap();
            assert_eq!(wire, expected);
            assert_eq!(decode(&wire, 4, 1, 0x0f0f0f0f, 0).unwrap(), source);
        }
        let mut mixed = encode(&[3; 10], 1, 0x0f0f0f0f, 0, 0).unwrap();
        mixed[9] |= 0x80;
        assert!(decode(&mixed, 10, 1, 0x0f0f0f0f, 0).is_err());
        assert!(encoded_len(32768, 1).is_err());
        assert_eq!(max_fragment(1, None).unwrap(), 32764);
        for mode in 1..=4 {
            let half = random_mask(mode).unwrap();
            for rotation in (0..=255).filter(|v| valid_rotation(*v)) {
                for polarity in [0, 1] {
                    let source = (0..33).collect::<Vec<u8>>();
                    let encoded = encode(&source, mode, half, rotation, polarity).unwrap();
                    assert_eq!(
                        decode(&encoded, source.len(), mode, half, rotation).unwrap(),
                        source
                    );
                }
            }
        }
    }
}
