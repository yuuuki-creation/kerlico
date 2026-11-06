//! 域名集合：完整匹配、后缀（含自身）与仅子域三类条目共用一张紧凑开放寻址哈希表，
//! 关键字用 Aho-Corasick，正则合并为 `RegexSet`。
//!
//! 匹配按域名标签自右向左逐级查表，开销与标签数成正比，与条目数无关。

use aho_corasick::AhoCorasick;
use kerlico_core::{Error, Result};
use regex::RegexSet;

const FULL: u8 = 1;
const SUFFIX: u8 = 2;
const SUBDOMAIN: u8 = 4;

/// 一条域名条件。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DomainRule {
    /// 与域名完全相同。
    Full(String),
    /// 域名本身及其全部子域。
    Suffix(String),
    /// 仅子域，不含域名本身。
    Subdomain(String),
    /// 域名包含该子串。
    Keyword(String),
    /// 正则匹配域名。
    Regex(String),
}

#[derive(Clone, Debug, Default)]
pub struct DomainSetBuilder {
    table: KeyTable,
    keywords: Vec<String>,
    regexes: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct DomainSet {
    table: KeyTable,
    keywords: Vec<String>,
    keyword_matcher: Option<AhoCorasick>,
    regexes: Vec<String>,
    regex_set: Option<RegexSet>,
}

impl DomainSetBuilder {
    pub fn insert(&mut self, rule: DomainRule) {
        match rule {
            DomainRule::Full(d) => self.table.insert(&normalize(&d), FULL),
            DomainRule::Suffix(d) => self.table.insert(&normalize(&d), SUFFIX),
            DomainRule::Subdomain(d) => self.table.insert(&normalize(&d), SUBDOMAIN),
            DomainRule::Keyword(k) => self.keywords.push(k.to_ascii_lowercase()),
            DomainRule::Regex(r) => self.regexes.push(r),
        }
    }

    pub fn build(mut self) -> Result<DomainSet> {
        self.keywords.sort();
        self.keywords.dedup();
        self.regexes.sort();
        self.regexes.dedup();
        let keyword_matcher = if self.keywords.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::new(&self.keywords)
                    .map_err(|_| Error::Config("域名关键字集合构建失败".into()))?,
            )
        };
        let regex_set = if self.regexes.is_empty() {
            None
        } else {
            Some(
                RegexSet::new(&self.regexes)
                    .map_err(|error| Error::Config(format!("域名正则不合法：{error}")))?,
            )
        };
        self.table.shrink();
        Ok(DomainSet {
            table: self.table,
            keywords: self.keywords,
            keyword_matcher,
            regexes: self.regexes,
            regex_set,
        })
    }
}

fn normalize(domain: &str) -> String {
    domain
        .trim()
        .trim_end_matches('.')
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

impl DomainSet {
    pub fn from_rules(rules: impl IntoIterator<Item = DomainRule>) -> Result<Self> {
        let mut builder = DomainSetBuilder::default();
        for rule in rules {
            builder.insert(rule);
        }
        builder.build()
    }

    /// `host` 须为小写、无结尾点的域名。
    pub fn matches(&self, host: &str) -> bool {
        if self.table.len > 0 {
            if self.table.get(host) & (FULL | SUFFIX) != 0 {
                return true;
            }
            let mut rest = host;
            while let Some(dot) = rest.find('.') {
                rest = &rest[dot + 1..];
                if self.table.get(rest) & (SUFFIX | SUBDOMAIN) != 0 {
                    return true;
                }
            }
        }
        self.keyword_matcher
            .as_ref()
            .is_some_and(|ac| ac.is_match(host))
            || self
                .regex_set
                .as_ref()
                .is_some_and(|set| set.is_match(host))
    }

    pub fn is_empty(&self) -> bool {
        self.table.len == 0 && self.keywords.is_empty() && self.regexes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.table.entries() + self.keywords.len() + self.regexes.len()
    }

    /// 全部条目，按种类与字典序排列；同一域名同时有完整与仅子域条目时合并为后缀。
    pub fn rules(&self) -> Vec<DomainRule> {
        let mut out = Vec::with_capacity(self.len());
        for (domain, flags) in self.table.iter() {
            let domain = domain.to_owned();
            if flags & SUFFIX != 0 || flags & (FULL | SUBDOMAIN) == FULL | SUBDOMAIN {
                out.push(DomainRule::Suffix(domain));
            } else if flags & FULL != 0 {
                out.push(DomainRule::Full(domain));
            } else {
                out.push(DomainRule::Subdomain(domain));
            }
        }
        out.extend(self.keywords.iter().cloned().map(DomainRule::Keyword));
        out.extend(self.regexes.iter().cloned().map(DomainRule::Regex));
        out.sort();
        out
    }

    /// 表与字符串占用的堆内存估计（字节），不含正则与关键字自动机的内部结构。
    pub fn heap_bytes(&self) -> usize {
        self.table.arena.capacity()
            + self.table.slots.capacity() * 4
            + self.keywords.iter().map(String::capacity).sum::<usize>()
            + self.regexes.iter().map(String::capacity).sum::<usize>()
            + self
                .keyword_matcher
                .as_ref()
                .map_or(0, AhoCorasick::memory_usage)
    }
}

/// 条目存放在一段连续字节里：`[flags][len][bytes...]`；槽位保存偏移加一，0 为空槽。
#[derive(Clone, Debug, Default)]
struct KeyTable {
    arena: Vec<u8>,
    slots: Vec<u32>,
    len: usize,
}

fn hash(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in key {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^ (h >> 29)
}

impl KeyTable {
    fn entries(&self) -> usize {
        self.len
    }

    fn key_at(&self, offset: usize) -> &[u8] {
        let len = usize::from(self.arena[offset + 1]);
        &self.arena[offset + 2..offset + 2 + len]
    }

    fn find(&self, key: &[u8]) -> (usize, Option<usize>) {
        let mask = self.slots.len() - 1;
        let mut idx = usize::try_from(hash(key)).unwrap_or(usize::MAX) & mask;
        loop {
            match self.slots[idx] {
                0 => return (idx, None),
                stored => {
                    let offset = stored as usize - 1;
                    if self.key_at(offset) == key {
                        return (idx, Some(offset));
                    }
                }
            }
            idx = (idx + 1) & mask;
        }
    }

    fn get(&self, key: &str) -> u8 {
        if self.len == 0 || key.len() > 255 {
            return 0;
        }
        match self.find(key.as_bytes()) {
            (_, Some(offset)) => self.arena[offset],
            (_, None) => 0,
        }
    }

    fn insert(&mut self, key: &str, flag: u8) {
        if key.is_empty() || key.len() > 255 {
            return;
        }
        if (self.len + 1) * 2 > self.slots.len() {
            self.grow((self.slots.len() * 2).max(16));
        }
        let (idx, existing) = self.find(key.as_bytes());
        if let Some(offset) = existing {
            self.arena[offset] |= flag;
            return;
        }
        let offset = self.arena.len();
        self.arena.push(flag);
        self.arena.push(u8::try_from(key.len()).unwrap_or(u8::MAX));
        self.arena.extend_from_slice(key.as_bytes());
        self.slots[idx] = u32::try_from(offset + 1).unwrap_or(u32::MAX);
        self.len += 1;
    }

    fn grow(&mut self, capacity: usize) {
        let old = std::mem::replace(&mut self.slots, vec![0; capacity]);
        let mask = capacity - 1;
        for stored in old.into_iter().filter(|&s| s != 0) {
            let key = self.key_at(stored as usize - 1);
            let mut idx = usize::try_from(hash(key)).unwrap_or(usize::MAX) & mask;
            while self.slots[idx] != 0 {
                idx = (idx + 1) & mask;
            }
            self.slots[idx] = stored;
        }
    }

    /// 构建完成后把装载率收紧到 50% 左右。
    fn shrink(&mut self) {
        let target = (self.len * 2).next_power_of_two().max(16);
        if target < self.slots.len() {
            self.grow(target);
        }
        self.arena.shrink_to_fit();
    }

    fn iter(&self) -> impl Iterator<Item = (&str, u8)> + '_ {
        let mut offset = 0;
        std::iter::from_fn(move || {
            if offset >= self.arena.len() {
                return None;
            }
            let flags = self.arena[offset];
            let key = self.key_at(offset);
            offset += 2 + key.len();
            Some((std::str::from_utf8(key).unwrap_or_default(), flags))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_suffix_subdomain_keyword_and_regex_semantics() {
        let set = DomainSet::from_rules([
            DomainRule::Full("exact.example".into()),
            DomainRule::Suffix("Suffix.Example".into()),
            DomainRule::Subdomain("sub.example".into()),
            DomainRule::Keyword("tracker".into()),
            DomainRule::Regex(r"^ad\d+\.".into()),
        ])
        .unwrap();
        assert!(set.matches("exact.example"));
        assert!(!set.matches("a.exact.example"));
        assert!(set.matches("suffix.example"));
        assert!(set.matches("a.b.suffix.example"));
        assert!(!set.matches("notsuffix.example"));
        assert!(!set.matches("sub.example"));
        assert!(set.matches("x.sub.example"));
        assert!(set.matches("mytracker.net"));
        assert!(set.matches("ad12.net"));
        assert!(!set.matches("example"));
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn full_plus_subdomain_dumps_as_suffix() {
        let set = DomainSet::from_rules([
            DomainRule::Full("a.example".into()),
            DomainRule::Subdomain("a.example".into()),
            DomainRule::Subdomain("b.example".into()),
        ])
        .unwrap();
        assert_eq!(
            set.rules(),
            [
                DomainRule::Suffix("a.example".into()),
                DomainRule::Subdomain("b.example".into())
            ]
        );
    }

    /// 10 万条后缀（与 geosite:cn 同量级）：记录内存与单次匹配耗时，并设宽松上限防止退化。
    #[test]
    fn hundred_thousand_suffixes_stay_compact_and_fast() {
        let started = std::time::Instant::now();
        let set = DomainSet::from_rules(
            (0..100_000).map(|i| DomainRule::Suffix(format!("site{i}.example{}.cn", i % 97))),
        )
        .unwrap();
        let build = started.elapsed();
        let hosts: Vec<String> = (0..10_000)
            .map(|i| {
                if i % 2 == 0 {
                    format!("www.cdn.site{i}.example{}.cn", i % 97)
                } else {
                    format!("www.cdn.other{i}.example.com")
                }
            })
            .collect();
        let started = std::time::Instant::now();
        let hits = hosts.iter().filter(|h| set.matches(h)).count();
        let per_match = started.elapsed() / u32::try_from(hosts.len()).unwrap();
        let bytes = set.heap_bytes();
        eprintln!(
            "domain_set 100k: build {build:?}, heap {} KiB, {per_match:?}/match",
            bytes / 1024
        );
        assert_eq!(hits, 5_000);
        assert!(bytes < 6 * 1024 * 1024, "heap {bytes}");
    }
}
