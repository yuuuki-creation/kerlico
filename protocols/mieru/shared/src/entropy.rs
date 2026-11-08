//! Low-entropy payload body used by protocol types 10 and 11.
//! The 16-byte AEAD tag stays outside this transform.

const CHUNK: usize = 8;

pub fn encoded_len(extracted: usize, mode: u8) -> Option<u16> {
    let width = source_bytes(mode)?;
    if extracted == 0 {
        return Some(0);
    }
    let chunks = extracted.div_ceil(width);
    let bytes = chunks.checked_mul(CHUNK)?;
    u16::try_from(bytes).ok()
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg_attr(not(test), allow(dead_code))]
pub fn encode(src: &[u8], mode: u8, half_mask: u32, rotation: u8, padding_bit: u8) -> Option<Vec<u8>> {
    if padding_bit > 1 || !valid_params(mode, half_mask, rotation) {
        return None;
    }
    let width = source_bytes(mode)?;
    let out_len = encoded_len(src.len(), mode)? as usize;
    if src.is_empty() {
        return Some(Vec::new());
    }
    let mut out = vec![0u8; out_len];
    let initial = repeat_u32(half_mask);
    let mut offset = 0;
    let mut chunk_index = 0;
    while offset < src.len() {
        let take = width.min(src.len() - offset);
        let mut scratch = [0u8; CHUNK];
        scratch[CHUNK - take..].copy_from_slice(&src[offset..offset + take]);
        let source = u64::from_be_bytes(scratch);
        let mask = chunk_mask(initial, rotation, chunk_index)?;
        let data_mask = pdep(low_bits(take * 8), mask);
        let mut chunk = pdep(source, mask);
        if padding_bit == 1 {
            chunk |= !data_mask;
        }
        out[chunk_index * CHUNK..(chunk_index + 1) * CHUNK].copy_from_slice(&chunk.to_be_bytes());
        offset += take;
        chunk_index += 1;
    }
    Some(out)
}

pub fn decode(encoded: &[u8], extracted: usize, mode: u8, half_mask: u32, rotation: u8) -> Option<Vec<u8>> {
    if !valid_params(mode, half_mask, rotation) {
        return None;
    }
    let expect = encoded_len(extracted, mode)? as usize;
    if encoded.len() != expect {
        return None;
    }
    if extracted == 0 {
        return Some(Vec::new());
    }
    let width = source_bytes(mode)?;
    let mut out = vec![0u8; extracted];
    let initial = repeat_u32(half_mask);
    let mut offset = 0;
    let mut chunk_index = 0;
    let mut padding_bit = None;
    while offset < extracted {
        let take = width.min(extracted - offset);
        let chunk = u64::from_be_bytes(encoded[chunk_index * CHUNK..(chunk_index + 1) * CHUNK].try_into().ok()?);
        let mask = chunk_mask(initial, rotation, chunk_index)?;
        let data_mask = pdep(low_bits(take * 8), mask);
        let padding_mask = !data_mask;
        let padding = chunk & padding_mask;
        let bit = if padding == 0 {
            0
        } else if padding == padding_mask {
            1
        } else {
            return None;
        };
        match padding_bit {
            None => padding_bit = Some(bit),
            Some(expected) if expected != bit => return None,
            Some(_) => {}
        }
        let source = pext(chunk, mask);
        let scratch = source.to_be_bytes();
        out[offset..offset + take].copy_from_slice(&scratch[CHUNK - take..]);
        offset += take;
        chunk_index += 1;
    }
    Some(out)
}

pub fn valid_params(mode: u8, half_mask: u32, rotation: u8) -> bool {
    let Some(ones) = half_ones(mode) else {
        return false;
    };
    half_mask.count_ones() == ones && valid_rotation(rotation)
}

fn source_bytes(mode: u8) -> Option<usize> {
    match mode {
        1 => Some(4),
        2 => Some(5),
        3 => Some(6),
        4 => Some(7),
        _ => None,
    }
}

fn half_ones(mode: u8) -> Option<u32> {
    match mode {
        1 => Some(16),
        2 => Some(20),
        3 => Some(24),
        4 => Some(28),
        _ => None,
    }
}

fn valid_rotation(rotation: u8) -> bool {
    rotation == 0 || (1..=15).contains(&rotation) || (rotation >= 16 && rotation <= 240 && rotation % 16 == 0)
}

fn chunk_mask(initial: u64, rotation: u8, index: usize) -> Option<u64> {
    if !valid_rotation(rotation) {
        return None;
    }
    if rotation == 0 || index == 0 {
        return Some(initial);
    }
    let steps = (index % 64) as u32;
    if rotation <= 15 {
        Some(initial.rotate_right(steps * u32::from(rotation)))
    } else {
        Some(initial.rotate_left(steps * u32::from(rotation / 16)))
    }
}

fn repeat_u32(value: u32) -> u64 {
    (u64::from(value) << 32) | u64::from(value)
}

fn low_bits(n: usize) -> u64 {
    if n >= 64 {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}

fn pdep(source: u64, mut mask: u64) -> u64 {
    let mut result = 0;
    let mut src_bit = 1u64;
    while mask != 0 {
        let mask_bit = mask & mask.wrapping_neg();
        if source & src_bit != 0 {
            result |= mask_bit;
        }
        mask &= mask - 1;
        src_bit <<= 1;
    }
    result
}

fn pext(value: u64, mut mask: u64) -> u64 {
    let mut result = 0;
    let mut out_bit = 1u64;
    while mask != 0 {
        let mask_bit = mask & mask.wrapping_neg();
        if value & mask_bit != 0 {
            result |= out_bit;
        }
        mask &= mask - 1;
        out_bit <<= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_32_matches_the_published_example() {
        let encoded = encode(&[0x12, 0x34, 0x56, 0x78], 1, 0x0f0f_0f0f, 0, 0).unwrap();
        assert_eq!(encoded, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let ones = encode(&[0x12, 0x34, 0x56, 0x78], 1, 0x0f0f_0f0f, 0, 1).unwrap();
        assert_eq!(ones, [0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8]);
        assert_eq!(decode(&encoded, 4, 1, 0x0f0f_0f0f, 0).unwrap(), [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn partial_chunk_round_trips_every_mode() {
        for mode in 1..=4 {
            let src: Vec<u8> = (0..13).collect();
            let mask = mask_with_ones(match mode {
                1 => 16,
                2 => 20,
                3 => 24,
                _ => 28,
            });
            let encoded = encode(&src, mode, mask, 32, 1).unwrap();
            assert_eq!(decode(&encoded, src.len(), mode, mask, 32).unwrap(), src);
        }
    }

    fn mask_with_ones(ones: u32) -> u32 {
        if ones == 32 {
            return u32::MAX;
        }
        (1u32 << ones) - 1
    }
}
