//! Go math/rand's deterministic shuffle used for the Sudoku wire codebook.
//!
//! The seed constants and generator are derived from the Go standard library.
//! See GO-LICENSE in this directory.

const LENGTH: usize = 607;
const TAP: usize = 273;
const MODULUS: i64 = i32::MAX as i64;

pub(super) fn shuffle(order: &mut [usize], seed: i64) {
    let mut rng = Generator::new(seed);
    for index in (1..order.len()).rev() {
        order.swap(index, rng.below((index + 1) as u32) as usize);
    }
}

struct Generator {
    tap: usize,
    feed: usize,
    values: [u64; LENGTH],
}

impl Generator {
    fn new(seed: i64) -> Self {
        let mut x = seed.rem_euclid(MODULUS);
        if x == 0 {
            x = 89_482_311;
        }
        let next = |x| (48_271 * x) % MODULUS;
        for _ in 0..20 {
            x = next(x);
        }
        let values = std::array::from_fn(|index| {
            x = next(x);
            let high = (x as u64) << 40;
            x = next(x);
            let middle = (x as u64) << 20;
            x = next(x);
            high ^ middle ^ (x as u64) ^ (COOKED[index] as u64)
        });
        Self { tap: 0, feed: LENGTH - TAP, values }
    }

    fn uint32(&mut self) -> u32 {
        self.tap = (self.tap + LENGTH - 1) % LENGTH;
        self.feed = (self.feed + LENGTH - 1) % LENGTH;
        let value = self.values[self.feed].wrapping_add(self.values[self.tap]);
        self.values[self.feed] = value;
        ((value & i64::MAX as u64) >> 31) as u32
    }

    fn below(&mut self, span: u32) -> u32 {
        let threshold = span.wrapping_neg() % span;
        loop {
            let product = u64::from(self.uint32()) * u64::from(span);
            if product as u32 >= threshold {
                return (product >> 32) as u32;
            }
        }
    }
}

include!("go_rng_cooked.rs");
