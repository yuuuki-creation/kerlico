//! Chrome Initial CRYPTO layout and padding, based on the apernet QUIC ChromeParrot profile.

use std::collections::VecDeque;

use rand::{Rng, RngExt, seq::SliceRandom};

use crate::{VarInt, coding::BufMutExt, frame};

pub(super) fn initial_frames(
    pending: &mut VecDeque<frame::Crypto>,
    available: usize,
    rng: &mut impl Rng,
) -> Vec<frame::Crypto> {
    let mut frames = Vec::new();
    let Some(first) = pending.front_mut() else { return frames };
    if first.offset == 0 {
        let len = first.data.len();
        let header = header_size(len.saturating_sub(1) as u64, len);
        if available > 2 * header && len > available - 2 * header {
            let data_per_later_packet = available - header;
            let packets = (len + header).div_ceil(data_per_later_packet);
            let first_packet_data = (len + header).div_ceil(packets).saturating_sub(header);
            let head = rng.random_range(55..87);
            if len > first_packet_data && first_packet_data > head {
                let tail = first_packet_data - head;
                let tail_offset = len - tail;
                let tail = first.data.split_off(tail_offset);
                let beginning = first.data.split_to(head);
                first.offset += head as u64;
                frames.push(frame::Crypto { offset: 0, data: beginning });
                frames.push(frame::Crypto { offset: tail_offset as u64, data: tail });
                return frames;
            }
        }
    }

    let mut available = available;
    while available > frame::Crypto::SIZE_BOUND {
        let Some(mut next) = pending.pop_front() else { break };
        let len = next.data.len().min(available - header_size(next.offset, available));
        let frame = frame::Crypto { offset: next.offset, data: next.data.split_to(len) };
        available -= wire_size(&frame);
        frames.push(frame);
        if !next.data.is_empty() {
            next.offset += len as u64;
            pending.push_front(next);
        }
    }
    frames
}

enum Item {
    Crypto(frame::Crypto),
    Ping,
    Padding(usize),
}

pub(super) fn write_initial(
    buf: &mut Vec<u8>,
    frames: &[frame::Crypto],
    available: usize,
    rng: &mut impl Rng,
) -> (u64, u64) {
    let mut budget = available - frames.iter().map(wire_size).sum::<usize>();
    let mut crypto = frames.to_vec();
    let min = frames.iter().map(|frame| frame.offset).min().unwrap();
    let max = frames.iter().map(|frame| frame.offset + frame.data.len() as u64).max().unwrap();
    let max_overhead = header_size(max, (max - min) as usize);
    for _ in 0..rng.random_range(2..=10) {
        if budget < max_overhead {
            break;
        }
        let index = rng.random_range(0..crypto.len());
        let first = &mut crypto[index];
        if first.data.len() <= 1 {
            continue;
        }
        let split = rng.random_range(1..first.data.len());
        let before = wire_size(first);
        let second = frame::Crypto {
            offset: first.offset + split as u64,
            data: first.data.split_off(split),
        };
        budget -= wire_size(first) + wire_size(&second) - before;
        crypto.push(second);
    }
    let crypto_count = crypto.len() as u64;
    let mut items: Vec<_> = crypto.into_iter().map(Item::Crypto).collect();
    let pings = budget.min(rng.random_range(2..=10));
    items.extend((0..pings).map(|_| Item::Ping));
    budget -= pings;
    for _ in 0..items.len() {
        if budget == 0 {
            break;
        }
        let count = rng.random_range(0..=budget);
        if count != 0 {
            items.push(Item::Padding(count));
            budget -= count;
        }
    }
    if budget != 0 {
        items.push(Item::Padding(budget));
    }
    items.shuffle(rng);
    for item in items {
        match item {
            Item::Crypto(frame) => frame.encode(buf),
            Item::Ping => buf.write(frame::FrameType::PING),
            Item::Padding(count) => buf.resize(buf.len() + count, 0),
        }
    }
    (crypto_count, pings as u64)
}

fn wire_size(frame: &frame::Crypto) -> usize {
    header_size(frame.offset, frame.data.len()) + frame.data.len()
}

fn header_size(offset: u64, len: usize) -> usize {
    1 + VarInt::from_u64(offset).unwrap().size() + VarInt::try_from(len).unwrap().size()
}
