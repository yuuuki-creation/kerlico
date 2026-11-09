use std::io::{self, Read};
use std::thread;
use std::time::Duration;

use super::super::{malformed, random_below, Side};
use super::stream::CipherWriter;
use super::wire::{put_varint, read_varint};

type Bounds = (u32, u32);
const MAX_TURN: u32 = 8 * 1024 * 1024;
const NO_DELAY: Bounds = (0, 0);

#[derive(Clone, Copy)]
enum Pause {
    None,
    Registry,
    PlayStart,
}

struct StartupTurn {
    variants: &'static [&'static [u32]],
    delay_ms: Bounds,
    pause: Pause,
}

// Minecraft 26.1.2 startup templates from Xray's padding_preset.go.
const STARTUP: [StartupTurn; 6] = [
    StartupTurn {
        variants: &[&[2, 26, 16]],
        delay_ms: NO_DELAY,
        pause: Pause::None,
    },
    StartupTurn {
        variants: &[&[26, 21, 25]],
        delay_ms: (0, 20),
        pause: Pause::None,
    },
    StartupTurn {
        variants: &[&[25]],
        delay_ms: (2, 22),
        pause: Pause::None,
    },
    StartupTurn {
        variants: &[&[
            1590, 226, 329, 229, 186, 151, 78, 81, 79, 235, 67, 67, 78, 71, 82, 74, 982, 117, 1118,
            1038, 970, 400, 239, 49, 50, 95, 65, 104, 32320, 2,
        ]],
        delay_ms: (20, 50),
        pause: Pause::Registry,
    },
    StartupTurn {
        variants: &[&[2]],
        delay_ms: (10, 35),
        pause: Pause::None,
    },
    StartupTurn {
        variants: &[
            &[4941, 252, 259, 267, 268, 251, 303, 259, 264, 54, 346],
            &[
                4941, 262, 284, 272, 260, 260, 313, 264, 151, 224, 207, 215, 224, 390,
            ],
            &[
                4941, 257, 272, 275, 260, 260, 313, 283, 274, 226, 207, 230, 215, 204, 221, 352,
            ],
            &[
                4941, 259, 272, 288, 260, 260, 311, 270, 70, 236, 223, 201, 210, 352,
            ],
            &[4941, 255, 269, 277, 263, 260, 136, 207, 210, 232, 325],
            &[4941, 259, 270, 274, 263, 258, 327, 170, 210, 375],
            &[
                4941, 257, 275, 291, 260, 260, 325, 269, 70, 230, 226, 207, 221, 352,
            ],
            &[4941, 252, 273, 262, 252, 254, 306, 93],
            &[4941, 273, 270, 269, 258, 256, 322, 221, 207, 215, 438],
            &[
                4941, 259, 275, 274, 250, 258, 308, 267, 154, 233, 209, 207, 213, 393,
            ],
            &[
                4941, 254, 267, 272, 260, 253, 311, 167, 204, 232, 207, 481, 8,
            ],
            &[4941, 259, 269, 272, 261, 313, 207, 213, 500, 19],
            &[
                4941, 262, 269, 274, 263, 274, 311, 270, 242, 210, 229, 221, 210, 431,
            ],
            &[
                4941, 259, 265, 277, 263, 277, 316, 269, 156, 204, 210, 226, 207, 413,
            ],
            &[4941, 215, 251, 249, 317, 260, 270, 249, 52],
            &[
                4941, 224, 263, 277, 316, 267, 272, 260, 138, 230, 226, 207, 204, 352,
            ],
            &[
                4941, 221, 258, 263, 319, 269, 288, 263, 136, 204, 210, 220, 207, 378,
            ],
            &[
                4941, 221, 258, 260, 316, 273, 291, 226, 204, 229, 213, 489, 8,
            ],
            &[
                4941, 238, 260, 261, 306, 272, 277, 260, 224, 241, 212, 207, 204, 393,
            ],
            &[
                4941, 224, 260, 260, 309, 272, 277, 277, 138, 207, 207, 212, 241, 352,
            ],
        ],
        delay_ms: (35, 50),
        pause: Pause::PlayStart,
    },
];

const PLAY_RANGES: [Bounds; 33] = [
    (6, 883),
    (346, 58638),
    (6, 887),
    (388, 61077),
    (2, 50),
    (575, 65584),
    (6, 45),
    (86, 63563),
    (2, 44),
    (42, 51983),
    (2, 851),
    (309, 25083),
    (2, 19),
    (74, 63885),
    (8, 24),
    (30, 66128),
    (2, 19),
    (26, 35818),
    (6, 19),
    (35, 59407),
    (6, 19),
    (37, 65328),
    (2, 19),
    (26, 60622),
    (6, 19),
    (11, 60808),
    (8, 43),
    (55, 62027),
    (2, 19),
    (427, 65622),
    (5, 19),
    (35, 59401),
    (6, 19),
];

const SERVER_BRANCHES: [[Bounds; 2]; 16] = [
    [(346, 18812), (51702, 58638)],
    [(388, 20689), (51445, 61077)],
    [(575, 20915), (41428, 65584)],
    [(86, 2772), (41428, 63563)],
    [(42, 26813), (51983, 51983)],
    [(309, 19484), (24837, 25083)],
    [(74, 40686), (63885, 63885)],
    [(30, 44114), (66128, 66128)],
    [(26, 1464), (9941, 35818)],
    [(35, 42885), (52194, 59407)],
    [(37, 47553), (61765, 65328)],
    [(26, 1121), (16162, 60622)],
    [(11, 45629), (60808, 60808)],
    [(55, 10035), (30237, 62027)],
    [(427, 52536), (64014, 65622)],
    [(35, 22708), (38987, 59401)],
];
const SERVER_MASKS: [u16; 20] = [
    0x011c, 0x090a, 0x0821, 0xe921, 0x2102, 0x0844, 0xa101, 0x1106, 0x2e00, 0xab01, 0xe900, 0xac01,
    0xab01, 0x8b80, 0x0808, 0x2001, 0x0901, 0x000a, 0x2c01, 0x0801,
];

const CLIENT_BURSTS: [(usize, Bounds, Bounds); 3] = [
    (0, (6, 44), (877, 883)),
    (2, (6, 45), (884, 887)),
    (10, (2, 19), (851, 851)),
];

fn pick((min, max): Bounds) -> u32 {
    min + random_below(max - min + 1)
}

fn delay((min, max): Bounds) {
    let ns = pick((min * 1_000_000, max * 1_000_000));
    if ns != 0 {
        thread::sleep(Duration::from_nanos(ns.into()));
    }
}

fn read_turn(
    reader: &mut impl Read,
    prefix: u32,
    accepts: impl FnOnce(u32) -> bool,
) -> io::Result<()> {
    let (record, header) = read_varint(reader)?;
    if !(header as u32..=MAX_TURN).contains(&record) || !accepts(prefix + record) {
        return Err(malformed("invalid XMC startup padding length"));
    }
    let mut remaining = record as usize - header;
    let mut buffer = [0; 16 * 1024];
    while remaining != 0 {
        let count = remaining.min(buffer.len());
        reader.read_exact(&mut buffer[..count])?;
        remaining -= count;
    }
    Ok(())
}

fn write_turn(
    writer: &mut CipherWriter,
    length: u32,
    chunks: impl IntoIterator<Item = u32>,
    pause: impl Fn(usize) -> Bounds,
) -> io::Result<()> {
    let mut header = Vec::new();
    put_varint(&mut header, length);
    for (index, chunk) in chunks.into_iter().enumerate() {
        delay(pause(index));
        let mut bytes = std::mem::take(&mut header);
        if bytes.len() > chunk as usize {
            return Err(malformed("XMC padding length header exceeds first chunk"));
        }
        bytes.resize(chunk as usize, 0);
        writer.send(bytes)?;
    }
    Ok(())
}

fn startup_turn(
    reader: &mut impl Read,
    writer: &mut CipherWriter,
    turn: &StartupTurn,
    prefix: u32,
    sends: bool,
) -> io::Result<()> {
    if !sends {
        return read_turn(reader, prefix, |length| {
            turn.variants
                .iter()
                .any(|chunks| chunks.iter().sum::<u32>() == length)
        });
    }
    delay(turn.delay_ms);
    let index = random_below(turn.variants.len() as u32) as usize;
    let chunks = turn.variants[index];
    let mut remaining_prefix = prefix;
    let mut start = 0;
    while remaining_prefix > 0 {
        let Some(&chunk) = chunks.get(start) else {
            return Err(malformed(
                "XMC login acknowledgement exceeds first padding turn",
            ));
        };
        remaining_prefix = remaining_prefix
            .checked_sub(chunk)
            .ok_or_else(|| malformed("XMC login acknowledgement splits a padding chunk"))?;
        start += 1;
    }
    let chunks = &chunks[start..];
    write_turn(
        writer,
        chunks.iter().sum(),
        chunks.iter().copied(),
        |index| match turn.pause {
            Pause::Registry if index == 28 => (1, 4),
            Pause::Registry if index == 29 => (44, 61),
            Pause::PlayStart if index == chunks.len() / 2 => (1, 5),
            Pause::PlayStart if index == chunks.len() - 1 => (9, 20),
            _ => NO_DELAY,
        },
    )
}

pub(super) fn exchange(
    reader: &mut impl Read,
    writer: &mut CipherWriter,
    side: Side,
    login_ack_length: usize,
) -> io::Result<()> {
    let client = side == Side::Client;
    for (index, turn) in STARTUP.iter().enumerate() {
        let prefix = if index == 0 {
            login_ack_length as u32
        } else {
            0
        };
        startup_turn(reader, writer, turn, prefix, client == (index % 2 == 0))?;
    }

    let client_burst = match random_below(20) {
        0..=16 => 0,
        17..=18 => 2,
        _ => 10,
    };
    let server_mask = SERVER_MASKS[random_below(SERVER_MASKS.len() as u32) as usize];
    for (index, bounds) in PLAY_RANGES.into_iter().enumerate() {
        if client != (index % 2 == 0) {
            read_turn(reader, 0, |length| (bounds.0..=bounds.1).contains(&length))?;
            continue;
        }
        let (send_bounds, chunk_size, start_ms, chunk_ms) = if client {
            let bounds = CLIENT_BURSTS
                .iter()
                .find(|(turn, _, _)| *turn == index)
                .map_or(bounds, |(_, normal, burst)| {
                    if client_burst == index {
                        *burst
                    } else {
                        *normal
                    }
                });
            (bounds, 1024, (1, 30), NO_DELAY)
        } else {
            let turn = index / 2;
            let branch = usize::from((server_mask >> turn) & 1);
            (
                SERVER_BRANCHES[turn][branch],
                pick((32 * 1024, 48 * 1024)),
                (1, 45),
                (1, 4),
            )
        };
        delay(start_ms);
        let length = pick(send_bounds);
        let chunks = (0..length)
            .step_by(chunk_size as usize)
            .map(|sent| chunk_size.min(length - sent));
        write_turn(writer, length, chunks, |i| {
            if i == 0 {
                NO_DELAY
            } else {
                chunk_ms
            }
        })?;
    }
    Ok(())
}
