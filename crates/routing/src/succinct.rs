//! sing-box 与 Mihomo 共用的 LOUDS 简洁字典树（源自 openacid/succinct）的键编解码。
//!
//! 节点按层序编号；`label_bitmap` 中每个节点对应一串 0（每个 0 是一条出边，标签依次取自
//! `labels`）后跟一个 1；第 `e` 条边指向节点 `e + 1`。`leaves` 第 `n` 位表示节点 `n` 是某个键的终点。

use kerlico_core::{Error, Result};

pub struct Succinct {
    pub leaves: Vec<u64>,
    pub label_bitmap: Vec<u64>,
    pub labels: Vec<u8>,
}

fn bit(words: &[u64], i: usize) -> bool {
    words.get(i >> 6).is_some_and(|w| w & (1 << (i & 63)) != 0)
}

fn set_bit(words: &mut Vec<u64>, i: usize) {
    while i >> 6 >= words.len() {
        words.push(0);
    }
    words[i >> 6] |= 1 << (i & 63);
}

impl Succinct {
    /// 全部键，按深度优先、标签序输出。
    pub fn keys(&self) -> Result<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        self.for_each_key(|key| {
            keys.push(key.to_vec());
            Ok(())
        })?;
        Ok(keys)
    }

    /// 按深度优先、标签序遍历全部键，复用单一路径缓冲区避免中间分配。
    pub fn for_each_key(&self, mut f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let malformed = || Error::Config("规则集域名字典树结构损坏".into());
        // 每个节点的第一条出边下标与出边数。
        let mut first_edge: Vec<u32> = Vec::new();
        let mut edge_count: Vec<u32> = Vec::new();
        let mut edge = 0usize;
        let mut run = 0u32;
        let total_bits = self.label_bitmap.len() * 64;
        let mut node_start = 0usize;
        for i in 0..total_bits {
            if bit(&self.label_bitmap, i) {
                first_edge.push(u32::try_from(node_start).map_err(|_| malformed())?);
                edge_count.push(run);
                run = 0;
                node_start = edge;
            } else {
                if edge >= self.labels.len() {
                    // 最后一个 1 之后的补零。
                    break;
                }
                edge += 1;
                run += 1;
            }
        }
        if edge != self.labels.len() || first_edge.is_empty() {
            return Err(malformed());
        }
        let nodes = first_edge.len();
        let mut key = Vec::with_capacity(256);
        if bit(&self.leaves, 0) {
            f(&[])?;
        }
        // (节点, 下一条待访问的边序号)
        let mut stack: Vec<(usize, u32)> = vec![(0, 0)];
        while let Some(top) = stack.last_mut() {
            let (node, next) = *top;
            if next >= edge_count[node] {
                stack.pop();
                key.pop();
                continue;
            }
            top.1 += 1;
            let e = first_edge[node] as usize + next as usize;
            let child = e + 1;
            if child >= nodes {
                return Err(malformed());
            }
            key.push(self.labels[e]);
            if bit(&self.leaves, child) {
                f(&key)?;
            }
            stack.push((child, 0));
            if stack.len() > 1024 {
                return Err(malformed());
            }
        }
        Ok(())
    }

    /// 按层序构建；`keys` 先排序去重。与 sing 的 `newSuccinctSet` 及 Mihomo 的 `buildDomainSet` 输出一致。
    pub fn build(mut keys: Vec<Vec<u8>>) -> Self {
        keys.sort();
        keys.dedup();
        let mut out = Self {
            leaves: Vec::new(),
            label_bitmap: Vec::new(),
            labels: Vec::new(),
        };
        let mut queue: Vec<(usize, usize, usize)> = vec![(0, keys.len(), 0)];
        let mut l_idx = 0usize;
        let mut i = 0usize;
        while i < queue.len() {
            let (mut s, e, col) = queue[i];
            if s < e && col == keys[s].len() {
                s += 1;
                set_bit(&mut out.leaves, i);
            }
            let mut j = s;
            while j < e {
                let from = j;
                while j < e && keys[j][col] == keys[from][col] {
                    j += 1;
                }
                queue.push((from, j, col + 1));
                out.labels.push(keys[from][col]);
                // 0 位：只需保证向量覆盖到该位置。
                while l_idx >> 6 >= out.label_bitmap.len() {
                    out.label_bitmap.push(0);
                }
                l_idx += 1;
            }
            set_bit(&mut out.label_bitmap, l_idx);
            l_idx += 1;
            i += 1;
        }
        out
    }
}

/// 按字节逆序。域名为 ASCII 时与上游按码点逆序等价；非 ASCII 先按码点逆序以保持一致。
pub fn reverse(text: &str) -> Vec<u8> {
    if text.is_ascii() {
        text.bytes().rev().collect()
    } else {
        text.chars().rev().collect::<String>().into_bytes()
    }
}

pub fn unreverse(key: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(key)
        .map(str::to_owned)
        .or_else(|_| {
            let mut bytes = key.to_vec();
            bytes.reverse();
            String::from_utf8(bytes).map(|s| s.chars().rev().collect())
        })
        .map_err(|_| Error::Config("规则集域名不是 UTF-8".into()))?;
    Ok(text.chars().rev().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_decode_round_trips_keys() {
        let keys: Vec<Vec<u8>> = ["moc.elpmaxe", "moc.elpmaxe.+", "gro.tset", "a", ""]
            .iter()
            .map(|k| k.as_bytes().to_vec())
            .collect();
        let set = Succinct::build(keys.clone());
        let mut decoded = set.keys().unwrap();
        decoded.sort();
        let mut expected = keys;
        expected.sort();
        assert_eq!(decoded, expected);
    }
}
