//! Go math/rand v1 的表排序兼容器，不用于密码学随机数。
// Copyright 2009 The Go Authors. All rights reserved.
// 来源许可见本包 LICENSE-go-math-rand.txt。

use super::go_rng_constants::COOKED;

struct Source {
    words: [u64; 607],
    tap: usize,
    feed: usize,
}

impl Source {
    fn new(seed: i64) -> Self {
        let mut source = Self {
            words: [0; 607],
            tap: 0,
            feed: 334,
        };
        let mut x = seed.rem_euclid(2_147_483_647);
        if x == 0 {
            x = 89_482_311;
        }
        fn next(x: i64) -> i64 {
            (48_271 * x).rem_euclid(2_147_483_647)
        }
        for i in -20i32..607 {
            x = next(x);
            if i >= 0 {
                let mut value = (x as u64) << 40;
                x = next(x);
                value ^= (x as u64) << 20;
                x = next(x);
                value ^= x as u64;
                source.words[i as usize] = value ^ COOKED[i as usize] as u64;
            }
        }
        source
    }
    fn uint32(&mut self) -> u32 {
        self.tap = (self.tap + 606) % 607;
        self.feed = (self.feed + 606) % 607;
        let next = self.words[self.feed].wrapping_add(self.words[self.tap]);
        self.words[self.feed] = next;
        ((next & 0x7fff_ffff_ffff_ffff) >> 31) as u32
    }
    fn below(&mut self, n: u32) -> usize {
        let mut product = u64::from(self.uint32()) * u64::from(n);
        if (product as u32) < n {
            let threshold = n.wrapping_neg() % n;
            while (product as u32) < threshold {
                product = u64::from(self.uint32()) * u64::from(n);
            }
        }
        (product >> 32) as usize
    }
}

pub(crate) fn permutation(seed: i64) -> [usize; 288] {
    let mut source = Source::new(seed);
    let mut indices = std::array::from_fn(|i| i);
    for i in (1..288).rev() {
        indices.swap(i, source.below((i + 1) as u32));
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_native_go_shuffle_not_perm() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tools/sudoku_reference_probe/fixtures/mihomo-wire.json"
        ))
        .unwrap();
        let seed = fixture["math_rand_seed"].as_str().unwrap().parse().unwrap();
        let expected: Vec<_> = fixture["shuffle"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(permutation(seed).as_slice(), expected.as_slice());
        assert_ne!(fixture["shuffle"], fixture["perm"]);
    }
}
