use super::{
    go_rng,
    layout::{Layout, Mode},
};
use kerlico_core::{Error, Result};
use rand::{Rng, distributions::{Distribution, Uniform}};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

type Grid = [u8; 16];

fn all_grids() -> &'static [Grid] {
    static ALL: OnceLock<Vec<Grid>> = OnceLock::new();
    ALL.get_or_init(|| {
        fn visit(grid: &mut Grid, index: usize, out: &mut Vec<Grid>) {
            if index == 16 {
                out.push(*grid);
                return;
            }
            let (row, col) = (index / 4, index % 4);
            for value in 1..=4 {
                if (0..4).any(|i| grid[row * 4 + i] == value || grid[i * 4 + col] == value) {
                    continue;
                }
                let (r, c) = (row / 2 * 2, col / 2 * 2);
                if (0..2).any(|dr| (0..2).any(|dc| grid[(r + dr) * 4 + c + dc] == value)) {
                    continue;
                }
                grid[index] = value;
                visit(grid, index + 1, out);
                grid[index] = 0;
            }
        }
        let mut out = Vec::with_capacity(288);
        visit(&mut [0; 16], 0, &mut out);
        out
    })
}

const CLUE_SETS: usize = 64 * 63 * 62 * 61 / 24;
const UNSEEN: u16 = u16::MAX;
const AMBIGUOUS: u16 = u16::MAX - 1;

// S4的全部24排列。一次均匀选[0,24*n)与独立选n个puzzle及均匀Shuffle4等价。
const PERMUTATIONS: [[u8; 4]; 24] = [
    [0,1,2,3], [0,1,3,2], [0,2,1,3], [0,2,3,1], [0,3,1,2], [0,3,2,1],
    [1,0,2,3], [1,0,3,2], [1,2,0,3], [1,2,3,0], [1,3,0,2], [1,3,2,0],
    [2,0,1,3], [2,0,3,1], [2,1,0,3], [2,1,3,0], [2,3,0,1], [2,3,1,0],
    [3,0,1,2], [3,0,2,1], [3,1,0,2], [3,1,2,0], [3,2,0,1], [3,2,1,0],
];

const fn coefficients() -> [[usize; 4]; 64] {
    let mut result = [[0; 4]; 64];
    let mut number = 0;
    while number < 64 {
        let mut count = 1;
        let mut choose = 1;
        while count <= 4 {
            choose = if count > number { 0 } else { choose * (number - count + 1) / count };
            result[number][count - 1] = choose;
            count += 1;
        }
        number += 1;
    }
    result
}
const COEFFICIENTS: [[usize; 4]; 64] = coefficients();

// 严格升序四元组的组合数排名；64选4恰有CLUE_SETS个位置。
fn sorted_rank(clues: [u8; 4]) -> usize {
    COEFFICIENTS[clues[0] as usize][0]
        + COEFFICIENTS[clues[1] as usize][1]
        + COEFFICIENTS[clues[2] as usize][2]
        + COEFFICIENTS[clues[3] as usize][3]
}

fn clue_rank(mut clues: [u8; 4]) -> Option<usize> {
    if clues.iter().any(|&clue| clue >= 64) {
        return None;
    }
    for (left, right) in [(0, 1), (2, 3), (0, 2), (1, 3), (1, 2)] {
        if clues[left] > clues[right] {
            clues.swap(left, right);
        }
    }
    if clues.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    Some(sorted_rank(clues))
}

pub(crate) struct GridOrder {
    decoded: Box<[u16]>,
    clues: Vec<Vec<[u8; 4]>>,
    // 每字节一个无堆分配的u32 sampler，由本GridOrder的所有方向/布局共享。
    // 不展开n×24个编码；现有clue列表与顺序保持不变。
    choices: Vec<Uniform<u32>>,
}
impl GridOrder {
    pub fn new(seed: &str) -> Self {
        let hash = Sha256::digest(seed.as_bytes());
        let seed = i64::from_be_bytes(hash[..8].try_into().unwrap());
        let original = all_grids();
        let permutation = go_rng::permutation(seed);
        let grids: Vec<_> = permutation.iter().map(|&i| original[i]).collect();
        let mut order = Self {
            decoded: vec![UNSEEN; CLUE_SETS].into_boxed_slice(),
            clues: Vec::with_capacity(256),
            choices: Vec::with_capacity(256),
        };
        // 全部288网格参与唯一性判断，后32个不能误当成可承载字节。
        for (rank, grid) in grids.iter().enumerate() {
            for_each_puzzle(grid, |hints| {
                let entry = &mut order.decoded[sorted_rank(hints)];
                *entry = match *entry {
                    UNSEEN => rank as u16,
                    previous if previous == rank as u16 => previous,
                    _ => AMBIGUOUS,
                };
            });
        }
        for (rank, grid) in grids.iter().take(256).enumerate() {
            let mut puzzles = Vec::new();
            for_each_puzzle(grid, |hints| {
                if order.decoded[sorted_rank(hints)] == rank as u16 {
                    puzzles.push(hints);
                }
            });
            // n最多为16选4=1820，24*n最多43680。空表仍由Pair检查拒绝，
            // 这里用一个不会被有效Table访问的非空占位区间避免初始化时panic。
            order.choices.push(Uniform::new(0u32, (puzzles.len().max(1) * 24) as u32));
            order.clues.push(puzzles);
        }
        order
    }
    fn decode(&self, clues: [u8; 4]) -> Option<u8> {
        let value = self.decoded[clue_rank(clues)?];
        (value < 256).then_some(value as u8)
    }
}

fn for_each_puzzle(grid: &Grid, mut visit: impl FnMut([u8; 4])) {
    for a in 0..13 {
        for b in a + 1..14 {
            for c in b + 1..15 {
                for d in c + 1..16 {
                    visit([a, b, c, d].map(|position| {
                        ((position << 2) | (grid[position] as usize - 1)) as u8
                    }));
                }
            }
        }
    }
}

pub(crate) struct Table {
    pub layout: Layout,
    order: Arc<GridOrder>,
    // 每布局仅新增64字节，不复制全部puzzle或排列。
    wire_hints: [u8; 64],
}
impl Table {
    fn new(layout: Layout, order: Arc<GridOrder>) -> Self {
        let wire_hints = std::array::from_fn(|hint|layout.hints[hint & 3][hint >> 2]);
        Self { layout, order, wire_hints }
    }
    pub fn decode(&self, clues: [u8; 4]) -> Result<u8> {
        self.order.decode(clues).ok_or_else(crate::invalid)
    }
    pub fn puzzle_count(&self, byte: u8) -> usize {
        self.order.clues[byte as usize].len()
    }
    pub fn puzzle(&self, byte: u8, index: usize) -> [u8; 4] {
        let hints = self.order.clues[byte as usize][index];
        [self.wire_hints[hints[0] as usize], self.wire_hints[hints[1] as usize],
         self.wire_hints[hints[2] as usize], self.wire_hints[hints[3] as usize]]
    }
    fn choice(&self, byte: u8, choice: u32) -> [u8; 4] {
        let puzzle = self.puzzle(byte, (choice / 24) as usize);
        let permutation = PERMUTATIONS[(choice % 24) as usize];
        [puzzle[permutation[0] as usize], puzzle[permutation[1] as usize],
         puzzle[permutation[2] as usize], puzzle[permutation[3] as usize]]
    }
    pub fn randomized_puzzle<R: Rng + ?Sized>(&self, byte: u8, random: &mut R) -> [u8; 4] {
        let choice = self.order.choices[byte as usize].sample(random);
        self.choice(byte, choice)
    }
}

pub(crate) struct Pair {
    pub up: Arc<Table>,
    pub down: Arc<Table>,
    pub hint: u32,
}
impl Pair {
    pub fn new(seed: &str, mode: Mode, pattern: &str, order: Arc<GridOrder>) -> Result<Self> {
        let up_pattern = if mode.ascii(true) { "" } else { pattern.trim() };
        let down_pattern = if mode.ascii(false) {
            ""
        } else {
            pattern.trim()
        };
        let hint_input = [
            "sudoku-table-hint",
            seed,
            mode.canonical(),
            &up_pattern.to_ascii_lowercase(),
            &down_pattern.to_ascii_lowercase(),
        ]
        .join("\0");
        let hash = Sha256::digest(hint_input.as_bytes());
        let hint = u32::from_be_bytes(hash[..4].try_into().unwrap());
        let up = Arc::new(Table::new(Layout::new(mode.ascii(true), up_pattern)?, order.clone()));
        let down = if mode.ascii(true) == mode.ascii(false) {
            up.clone()
        } else {
            Arc::new(Table::new(Layout::new(mode.ascii(false), down_pattern)?, order))
        };
        if (0..=255).any(|byte|up.puzzle_count(byte) == 0) {
            return Err(Error::Protocol("Sudoku表生成缺少唯一编码"));
        }
        Ok(Self { up, down, hint })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_clue_lookup_matches_bitset_oracle_for_every_distinct_quadruple() {
        let seed = "synthetic-sudoku-dense-lookup";
        let order = GridOrder::new(seed);
        let hash = Sha256::digest(seed.as_bytes());
        let permutation = go_rng::permutation(i64::from_be_bytes(hash[..8].try_into().unwrap()));
        let mut sets = [[0u64; 5]; 128];
        for (rank, index) in permutation.into_iter().enumerate() {
            for (position, value) in all_grids()[index].iter().enumerate() {
                sets[(position << 2) | (*value as usize - 1)][rank / 64] |= 1 << (rank % 64);
            }
        }
        let oracle = |hints: [u8; 4]| {
            let mut selected = None;
            for (word, _) in sets[0].iter().enumerate() {
                let intersection = hints.iter().fold(u64::MAX, |set, &hint| set & sets[hint as usize][word]);
                if intersection == 0 { continue; }
                if selected.is_some() || intersection.count_ones() != 1 { return None; }
                let rank = word * 64 + intersection.trailing_zeros() as usize;
                if rank >= 256 { return None; }
                selected = Some(rank as u8);
            }
            selected
        };
        let mut visited = vec![false; CLUE_SETS];
        for a in 0u8..61 { for b in a+1..62 { for c in b+1..63 { for d in c+1..64 {
            let hints = [a,b,c,d];
            let index = sorted_rank(hints);
            assert!(!visited[index]);visited[index] = true;
            assert_eq!(order.decode(hints), oracle(hints), "hints={hints:?}");
        }}}}
        assert!(visited.into_iter().all(|value| value));
        for (value, puzzles) in order.clues.iter().enumerate() {
            let hints = puzzles[0];
            for a in 0..4 { for b in 0..4 { for c in 0..4 { for d in 0..4 {
                if a == b || a == c || a == d || b == c || b == d || c == d { continue; }
                assert_eq!(order.decode([hints[a],hints[b],hints[c],hints[d]]), Some(value as u8));
            }}}}
            assert!(order.decode([hints[0],hints[0],hints[2],hints[3]]).is_none());
            assert!(order.decode([64,hints[1],hints[2],hints[3]]).is_none());
        }
    }

    #[test]
    fn native_go_grid_puzzles_and_directional_hints() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tools/sudoku_reference_probe/fixtures/mihomo-wire.json"
        ))
        .unwrap();
        let seed = fixture["synthetic_vector_seed"].as_str().unwrap();
        let order = Arc::new(GridOrder::new(seed));
        assert_eq!(all_grids().len(), 288);
        for vector in fixture["vectors"].as_array().unwrap() {
            let mode = Mode::parse(vector["mode"].as_str().unwrap()).unwrap();
            let pair = Pair::new(
                seed,
                mode,
                vector["custom_pattern"].as_str().unwrap(),
                order.clone(),
            )
            .unwrap();
            assert_eq!(u64::from(pair.hint), vector["hint"].as_u64().unwrap());
            let expected = vector["first_puzzles_hex"].as_str().unwrap();
            let mut actual = String::new();
            for value in 0..=255u8 {
                for byte in pair.up.puzzle(value, 0) {
                    actual.push_str(&format!("{byte:02x}"));
                }
            }
            assert_eq!(actual, expected);
            for value in 0..=255u8 {
                let puzzle = pair
                    .up
                    .puzzle(value, 0)
                    .map(|b| pair.up.layout.hint_index[b as usize].unwrap());
                assert_eq!(pair.up.decode(puzzle).unwrap(), value);
                let mut poisoned = puzzle;
                poisoned[0] = 64;
                assert!(pair.up.decode(poisoned).is_err());
            }
        }
    }
}

#[cfg(test)]
mod joint_sampling_tests {
    use super::*;
    use std::collections::BTreeSet;
    use rand::RngCore;

    #[test]
    fn joint_uniform_index_is_the_product_of_every_puzzle_and_shuffle4() {
        let mut original=BTreeSet::new();
        for third in 0..4 {for second in 0..3 {for first in 0..2 {
            let mut permutation=[0u8,1,2,3];permutation.swap(3,third);permutation.swap(2,second);permutation.swap(1,first);
            assert!(original.insert(permutation));
        }}}
        let selected:BTreeSet<_>=PERMUTATIONS.into_iter().collect();
        assert_eq!(original.len(),24);assert_eq!(selected.len(),24);assert_eq!(selected,original);
        for count in [1usize,2,1820] {
            let mut per_puzzle=vec![0usize;count];let mut per_permutation=[0usize;24];let mut pairs=BTreeSet::new();
            for choice in 0..count*24 {
                let puzzle=choice/24;let permutation=choice%24;
                assert!(pairs.insert((puzzle,PERMUTATIONS[permutation])));
                per_puzzle[puzzle]+=1;per_permutation[permutation]+=1;
            }
            assert_eq!(pairs.len(),count*24);assert!(per_puzzle.into_iter().all(|n|n==24));assert!(per_permutation.into_iter().all(|n|n==count));
        }
    }

    #[test]
    fn cached_hint_mapping_preserves_every_puzzle_and_all_shuffle_choices() {
        let order=Arc::new(GridOrder::new("synthetic-joint-choice-layouts"));
        for mode in [Mode::Ascii,Mode::Entropy,Mode::AsciiUp,Mode::EntropyUp] {
            for pattern in ["","xpxvvpvv","vxpvxvvp"] {
                let pair=Pair::new("synthetic-joint-choice-layouts",mode,pattern,order.clone()).unwrap();
                let mut tables=vec![pair.up.clone()];if !Arc::ptr_eq(&pair.up,&pair.down){tables.push(pair.down.clone());}
                for table in tables {for byte in 0..=255u8 {
                    let count=table.puzzle_count(byte);assert!((1..=1820).contains(&count));
                    for index in 0..count {
                        let hints=order.clues[byte as usize][index];
                        let original=hints.map(|hint|table.layout.hints[(hint&3) as usize][(hint>>2) as usize]);
                        assert_eq!(table.puzzle(byte,index),original);
                        let roundtrip=original.map(|wire|table.layout.hint_index[wire as usize].unwrap());
                        assert_eq!(table.decode(roundtrip).unwrap(),byte);
                        // 默认双布局逐puzzle穷举24排列；自定义/方向布局穷举所有
                        // canonical映射及每字节首puzzle的24排列，组合定律另独立验证。
                        let exhaustive=pattern.is_empty() && matches!(mode,Mode::Ascii|Mode::Entropy);
                        if exhaustive || index==0 {
                            for (permutation,indices) in PERMUTATIONS.iter().enumerate() {
                                let expected=indices.map(|position|original[position as usize]);
                                let encoded=table.choice(byte,(index*24+permutation) as u32);
                                assert_eq!(encoded,expected);
                                if index==0 {
                                    let hints=encoded.map(|wire|table.layout.hint_index[wire as usize].unwrap());
                                    assert_eq!(table.decode(hints).unwrap(),byte);
                                }
                            }
                        }
                    }
                }}
            }
        }
    }

    #[derive(Default)]
    struct MaximumWords { u32_calls:usize, u64_calls:usize }
    impl RngCore for MaximumWords {
        fn next_u32(&mut self)->u32{self.u32_calls+=1;u32::MAX}
        fn next_u64(&mut self)->u64{self.u64_calls+=1;u64::MAX}
        fn fill_bytes(&mut self,output:&mut[u8]){for byte in output{*byte=0xff;}}
        fn try_fill_bytes(&mut self,output:&mut[u8])->std::result::Result<(),rand::Error>{self.fill_bytes(output);Ok(())}
    }
    #[test]
    fn cached_u32_sampler_covers_last_choice_with_bounded_cache_memory() {
        let order=Arc::new(GridOrder::new("synthetic-joint-u32-sampler"));
        let pair=Pair::new("synthetic-joint-u32-sampler",Mode::Entropy,"",order.clone()).unwrap();
        assert_eq!(order.choices.len(),256);
        // sampler无堆分配；不存储puzzle×24展开表，新增每GridOrder至多4KiB。
        assert!(std::mem::size_of::<Uniform<u32>>()<=16);
        assert_eq!(std::mem::size_of_val(&pair.up.wire_hints),64);
        assert_eq!(std::mem::size_of_val(&PERMUTATIONS),96);
        let mut random=MaximumWords::default();
        for byte in 0..=255u8 {
            let total=pair.up.puzzle_count(byte)*24;assert!((24..=43680).contains(&total));
            assert_eq!(pair.up.randomized_puzzle(byte,&mut random),pair.up.choice(byte,total as u32-1));
        }
        // 最大u32在这些边界不会触发拒绝采样；每次仅取一个u32，不走usize/u64路径。
        assert_eq!(random.u32_calls,256);assert_eq!(random.u64_calls,0);
    }
}
