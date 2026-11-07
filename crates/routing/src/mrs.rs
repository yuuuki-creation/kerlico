//! Mihomo 二进制规则集（`.mrs`）编解码，对应上游 `rules/provider/mrs_*`。
//!
//! 整个文件经 zstd 压缩；解压后为 `MRS\x01`、behavior 字节（domain 0、ipcidr 1）、
//! 条目数 i64、保留区长度 i64 与内容，随后是域名字典树或 IP 区间表（各自带版本字节 1）。

use crate::{
    ip_set::{IpSet, IpSetBuilder},
    succinct::{Succinct, reverse, unreverse},
};
use kerlico_core::{Error, Result};
use std::net::{IpAddr, Ipv6Addr};

pub const MAGIC: &[u8; 4] = b"MRS\x01";
/// zstd 帧魔数；`.mrs` 文件以它开头。
pub const ZSTD_MAGIC: &[u8; 4] = &[0x28, 0xb5, 0x2f, 0xfd];

/// Mihomo rule-provider 的 behavior。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Behavior {
    Domain,
    IpCidr,
    Classical,
}

impl Behavior {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "domain" => Ok(Self::Domain),
            "ipcidr" => Ok(Self::IpCidr),
            "classical" => Ok(Self::Classical),
            _ => Err(Error::Config(
                "rule-provider behavior 仅支持 domain、ipcidr 或 classical".into(),
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::IpCidr => "ipcidr",
            Self::Classical => "classical",
        }
    }
}

/// `.mrs` 内容。域名用 Mihomo domain behavior 的写法：`example.com` 完整匹配，
/// `.example.com` 仅子域，`+.example.com` 自身及子域，`*` 匹配一级标签。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MrsPayload {
    Domain(Vec<String>),
    IpCidr(IpSet),
}

impl MrsPayload {
    pub fn behavior(&self) -> Behavior {
        match self {
            Self::Domain(_) => Behavior::Domain,
            Self::IpCidr(_) => Behavior::IpCidr,
        }
    }

    pub fn count(&self) -> usize {
        match self {
            Self::Domain(patterns) => patterns.len(),
            Self::IpCidr(set) => set.range_count(),
        }
    }
}

fn malformed(what: &str) -> Error {
    Error::Config(format!("Mihomo 二进制规则集损坏：{what}"))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or_else(|| malformed("数据截断"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().unwrap_or_default(),
        ))
    }

    fn len(&mut self, unit: usize) -> Result<usize> {
        let n = usize::try_from(self.i64()?).map_err(|_| malformed("长度为负"))?;
        if n == 0 || n.saturating_mul(unit) > self.buf.len() - self.pos {
            return Err(malformed("长度不合法"));
        }
        Ok(n)
    }

    fn u64s(&mut self) -> Result<Vec<u64>> {
        let n = self.len(8)?;
        (0..n)
            .map(|_| {
                Ok(u64::from_be_bytes(
                    self.take(8)?.try_into().unwrap_or_default(),
                ))
            })
            .collect()
    }
}

/// 解码 `.mrs`；`expected` 给定时 behavior 不一致返回错误，与 Mihomo 一致。
pub fn read(bytes: &[u8], expected: Option<Behavior>) -> Result<MrsPayload> {
    let body = zstd::stream::decode_all(bytes).map_err(|_| malformed("zstd 解压失败"))?;
    let mut r = Reader { buf: &body, pos: 0 };
    if r.take(4)? != MAGIC {
        return Err(Error::Config("不是 Mihomo 二进制规则集".into()));
    }
    let behavior = match r.take(1)?[0] {
        0 => Behavior::Domain,
        1 => Behavior::IpCidr,
        other => return Err(malformed(&format!("未知 behavior {other}"))),
    };
    if let Some(expected) = expected
        && expected != behavior
    {
        return Err(Error::Config(format!(
            "mrs 文件 behavior 为 {}，配置为 {}",
            behavior.name(),
            expected.name()
        )));
    }
    let _count = r.i64()?;
    let extra = usize::try_from(r.i64()?).map_err(|_| malformed("保留区长度"))?;
    r.take(extra)?;
    if r.take(1)?[0] != 1 {
        return Err(malformed("内容版本"));
    }
    match behavior {
        Behavior::Domain => {
            let leaves = r.u64s()?;
            let label_bitmap = r.u64s()?;
            let n = r.len(1)?;
            let labels = r.take(n)?.to_vec();
            let set = Succinct {
                leaves,
                label_bitmap,
                labels,
            };
            let mut patterns = Vec::new();
            set.for_each_key(|key| {
                patterns.push(key_to_pattern(&unreverse(key)?));
                Ok(())
            })?;
            Ok(MrsPayload::Domain(compact_patterns(patterns)))
        }
        _ => {
            let n = r.len(32)?;
            let mut builder = IpSetBuilder::default();
            for _ in 0..n {
                let from = Ipv6Addr::from(<[u8; 16]>::try_from(r.take(16)?).unwrap_or_default());
                let to = Ipv6Addr::from(<[u8; 16]>::try_from(r.take(16)?).unwrap_or_default());
                builder
                    .add_range(IpAddr::V6(from), IpAddr::V6(to))
                    .map_err(|_| malformed("IP 区间"))?;
            }
            Ok(MrsPayload::IpCidr(builder.build()))
        }
    }
}

/// 流式解码 `.mrs` 为 [`DomainSet`] 或 [`IpSet`]，避免构建数十万级中间 `String` 数组。
pub(crate) fn read_compiled(
    bytes: &[u8],
    expected: Option<Behavior>,
    wildcard_to_regex: impl Fn(&str) -> String,
) -> Result<(crate::domain_set::DomainSet, IpSet)> {
    let body = zstd::stream::decode_all(bytes).map_err(|_| malformed("zstd 解压失败"))?;
    let mut r = Reader { buf: &body, pos: 0 };
    if r.take(4)? != MAGIC {
        return Err(Error::Config("不是 Mihomo 二进制规则集".into()));
    }
    let behavior = match r.take(1)?[0] {
        0 => Behavior::Domain,
        1 => Behavior::IpCidr,
        other => return Err(malformed(&format!("未知 behavior {other}"))),
    };
    if let Some(expected) = expected
        && expected != behavior
    {
        return Err(Error::Config(format!(
            "mrs 文件 behavior 为 {}，配置为 {}",
            behavior.name(),
            expected.name()
        )));
    }
    let _count = r.i64()?;
    let extra = usize::try_from(r.i64()?).map_err(|_| malformed("保留区长度"))?;
    r.take(extra)?;
    if r.take(1)?[0] != 1 {
        return Err(malformed("内容版本"));
    }
    match behavior {
        Behavior::Domain => {
            let leaves = r.u64s()?;
            let label_bitmap = r.u64s()?;
            let n = r.len(1)?;
            let labels = r.take(n)?.to_vec();
            let set = Succinct {
                leaves,
                label_bitmap,
                labels,
            };
            let mut builder = crate::domain_set::DomainSetBuilder::default();
            let mut wildcards = Vec::new();
            let mut buf = [0u8; 256];
            set.for_each_key(|rev_key| {
                let owned;
                let key_str: &str = if rev_key.len() <= 256 && rev_key.is_ascii() {
                    let len = rev_key.len();
                    for (dst, &src) in buf[..len].iter_mut().zip(rev_key.iter().rev()) {
                        *dst = src;
                    }
                    std::str::from_utf8(&buf[..len])
                        .map_err(|_| Error::Config("规则集域名不是 UTF-8".into()))?
                } else {
                    owned = unreverse(rev_key)?;
                    &owned
                };
                if key_str.contains('*') {
                    wildcards.push(key_to_pattern(key_str));
                } else if let Some(rest) = key_str
                    .strip_prefix("+.")
                    .or_else(|| key_str.strip_prefix('.'))
                {
                    let d = rest.trim().trim_end_matches('.');
                    if d.is_empty() || d.parse::<IpAddr>().is_ok() {
                        return Err(Error::Config(format!("规则集域名不合法：{rest}")));
                    }
                    builder.insert_subdomain(d);
                } else {
                    let d = key_str.trim().trim_end_matches('.');
                    if d.is_empty() || d.parse::<IpAddr>().is_ok() {
                        return Err(Error::Config(format!("规则集域名不合法：{key_str}")));
                    }
                    builder.insert_full(d);
                }
                Ok(())
            })?;
            for w in compact_patterns(wildcards) {
                builder.insert_regex(wildcard_to_regex(&w));
            }
            Ok((builder.build()?, IpSet::default()))
        }
        _ => {
            let n = r.len(32)?;
            let mut builder = IpSetBuilder::default();
            for _ in 0..n {
                let from = Ipv6Addr::from(<[u8; 16]>::try_from(r.take(16)?).unwrap_or_default());
                let to = Ipv6Addr::from(<[u8; 16]>::try_from(r.take(16)?).unwrap_or_default());
                builder
                    .add_range(IpAddr::V6(from), IpAddr::V6(to))
                    .map_err(|_| malformed("IP 区间"))?;
            }
            Ok((crate::domain_set::DomainSet::default(), builder.build()))
        }
    }
}

/// 内部键里 `+` 标签表示其后任意子域；对外写成 `.example.com`。
fn key_to_pattern(key: &str) -> String {
    match key.strip_prefix('+') {
        Some(rest) if rest.starts_with('.') => rest.to_owned(),
        _ => key.to_owned(),
    }
}

/// 与上游 `DumpMrs` 一致：同时存在 `d` 与 `.d` 时合并为 `+.d`。
fn compact_patterns(mut patterns: Vec<String>) -> Vec<String> {
    patterns.sort_by(|a, b| {
        a.trim_start_matches('.')
            .cmp(b.trim_start_matches('.'))
            .then(a.cmp(b))
    });
    let mut out = Vec::with_capacity(patterns.len());
    let mut i = 0;
    while i < patterns.len() {
        let bare = patterns[i].trim_start_matches('.');
        if i + 1 < patterns.len()
            && patterns[i + 1].trim_start_matches('.') == bare
            && patterns[i] != patterns[i + 1]
        {
            out.push(format!("+.{bare}"));
            i += 2;
        } else {
            out.push(patterns[i].clone());
            i += 1;
        }
    }
    out
}

/// Mihomo `ValidAndSplitDomain` 的规则：小写；`+` 只能是首个完整标签且后面还有标签；
/// `*` 必须占满一个标签；除首个标签外不允许空标签；不允许结尾点、首尾空白与 `/`。
pub fn valid_domain_pattern(raw: &str) -> Option<String> {
    if raw.is_empty()
        || raw.ends_with('.')
        || raw.contains('/')
        || raw.starts_with(char::is_whitespace)
        || raw.ends_with(char::is_whitespace)
    {
        return None;
    }
    let lower = raw.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() == 1 && parts[0].is_empty() {
        return None;
    }
    for (i, part) in parts.iter().enumerate() {
        if i > 0 && part.is_empty() {
            return None;
        }
        if part.contains('+') && (*part != "+" || i != 0 || parts.len() == 1) {
            return None;
        }
        if part.contains('*') && *part != "*" {
            return None;
        }
    }
    Some(lower)
}

fn pattern_keys(pattern: &str) -> Vec<String> {
    if let Some(rest) = pattern.strip_prefix("+.") {
        vec![rest.to_owned(), format!("+.{rest}")]
    } else if pattern.starts_with('.') {
        vec![format!("+{pattern}")]
    } else {
        vec![pattern.to_owned()]
    }
}

pub fn write(payload: &MrsPayload) -> Result<Vec<u8>> {
    write_counted(payload, payload.count())
}

/// `count` 写入头部的条目数；Mihomo 记的是输入条目数（合并网段前），由调用方给出。
pub fn write_counted(payload: &MrsPayload, count: usize) -> Result<Vec<u8>> {
    let mut body = MAGIC.to_vec();
    let behavior = match payload {
        MrsPayload::Domain(_) => 0u8,
        MrsPayload::IpCidr(_) => 1u8,
    };
    if count == 0 {
        return Err(Error::Config("规则集为空，无法写出 mrs".into()));
    }
    body.push(behavior);
    body.extend_from_slice(&(count as i64).to_be_bytes());
    body.extend_from_slice(&0i64.to_be_bytes());
    body.push(1);
    match payload {
        MrsPayload::Domain(patterns) => {
            let mut keys = Vec::with_capacity(patterns.len() * 2);
            for pattern in patterns {
                let valid = valid_domain_pattern(pattern)
                    .ok_or_else(|| Error::Config(format!("Mihomo 域名规则不合法：{pattern}")))?;
                keys.extend(pattern_keys(&valid).iter().map(|k| reverse(k)));
            }
            let set = Succinct::build(keys);
            for words in [&set.leaves, &set.label_bitmap] {
                body.extend_from_slice(&(words.len() as i64).to_be_bytes());
                for w in words.iter() {
                    body.extend_from_slice(&w.to_be_bytes());
                }
            }
            body.extend_from_slice(&(set.labels.len() as i64).to_be_bytes());
            body.extend_from_slice(&set.labels);
        }
        MrsPayload::IpCidr(set) => {
            body.extend_from_slice(&(set.range_count() as i64).to_be_bytes());
            for (from, to) in set.ranges4() {
                body.extend_from_slice(&from.to_ipv6_mapped().octets());
                body.extend_from_slice(&to.to_ipv6_mapped().octets());
            }
            for (from, to) in set.ranges6() {
                body.extend_from_slice(&from.octets());
                body.extend_from_slice(&to.octets());
            }
        }
    }
    zstd::stream::encode_all(body.as_slice(), 19).map_err(|_| Error::Config("zstd 压缩失败".into()))
}

/// 未压缩内容，供与上游编码结果逐字节比较。
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    zstd::stream::decode_all(bytes).map_err(|_| malformed("zstd 解压失败"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_patterns_round_trip_with_mihomo_compaction() {
        let patterns = vec![
            "+.Example.com".to_owned(),
            ".sub.example.org".to_owned(),
            "exact.example.net".to_owned(),
            "*.wild.example".to_owned(),
        ];
        let bytes = write(&MrsPayload::Domain(patterns)).unwrap();
        assert_eq!(&bytes[..4], ZSTD_MAGIC);
        let MrsPayload::Domain(decoded) = read(&bytes, Some(Behavior::Domain)).unwrap() else {
            panic!("behavior");
        };
        assert_eq!(
            decoded,
            [
                "*.wild.example",
                "exact.example.net",
                "+.example.com",
                ".sub.example.org"
            ]
        );
        assert!(read(&bytes, Some(Behavior::IpCidr)).is_err());
    }

    #[test]
    fn ipcidr_round_trips_through_mapped_addresses() {
        let set = IpSet::from_cidrs(["1.0.0.0/24", "240e::/18"]).unwrap();
        let bytes = write(&MrsPayload::IpCidr(set.clone())).unwrap();
        assert_eq!(read(&bytes, None).unwrap(), MrsPayload::IpCidr(set));
    }

    #[test]
    fn invalid_mihomo_domains_are_rejected() {
        for bad in ["", "a.", "a..b", "+", "a.+.b", "a*b.c", "x/y", " a"] {
            assert!(valid_domain_pattern(bad).is_none(), "{bad}");
        }
        assert_eq!(valid_domain_pattern(".a.b").as_deref(), Some(".a.b"));
        assert_eq!(valid_domain_pattern("*.A.b").as_deref(), Some("*.a.b"));
    }
}
