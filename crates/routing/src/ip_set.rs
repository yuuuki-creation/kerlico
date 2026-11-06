//! IP 集合：IPv4 与 IPv6 各自排序、合并后的闭区间，二分查找。

use kerlico_core::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

#[derive(Clone, Debug, Default)]
pub struct IpSetBuilder {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

/// 解析 `a.b.c.d/n`、`x::/n` 或字面地址；IPv4-mapped IPv6 按 IPv4 处理。
pub fn parse_prefix(text: &str) -> Result<(IpAddr, u8)> {
    let invalid = || Error::Config(format!("CIDR 不合法：{text}"));
    let text = text.trim();
    let (addr, len) = match text.split_once('/') {
        Some((addr, len)) => (addr, Some(len)),
        None => (text, None),
    };
    let addr: IpAddr = addr.parse().map_err(|_| invalid())?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let len: u8 = match len {
        Some(len) => len.parse().map_err(|_| invalid())?,
        None => max,
    };
    if len > max {
        return Err(invalid());
    }
    match addr {
        IpAddr::V6(v6) if len >= 96 => match v6.to_ipv4_mapped() {
            Some(v4) => Ok((IpAddr::V4(v4), len - 96)),
            None => Ok((addr, len)),
        },
        _ => Ok((addr, len)),
    }
}

impl IpSetBuilder {
    pub fn add_prefix(&mut self, addr: IpAddr, len: u8) {
        match addr {
            IpAddr::V4(v4) => {
                let host = 32 - u32::from(len.min(32));
                let mask = if host == 32 { 0 } else { u32::MAX << host };
                let from = v4.to_bits() & mask;
                self.v4.push((from, from | !mask));
            }
            IpAddr::V6(v6) => {
                let host = 128 - u32::from(len.min(128));
                let mask = if host == 128 { 0 } else { u128::MAX << host };
                let from = v6.to_bits() & mask;
                self.v6.push((from, from | !mask));
            }
        }
    }

    pub fn add_cidr(&mut self, text: &str) -> Result<()> {
        let (addr, len) = parse_prefix(text)?;
        self.add_prefix(addr, len);
        Ok(())
    }

    /// 闭区间；两端地址族不同或起点大于终点时返回错误。IPv4-mapped 区间按 IPv4 处理。
    pub fn add_range(&mut self, from: IpAddr, to: IpAddr) -> Result<()> {
        let invalid = || Error::Config("IP 区间不合法".into());
        match (from.to_canonical(), to.to_canonical()) {
            (IpAddr::V4(a), IpAddr::V4(b)) if a <= b => self.v4.push((a.to_bits(), b.to_bits())),
            (IpAddr::V6(a), IpAddr::V6(b)) if a <= b => self.v6.push((a.to_bits(), b.to_bits())),
            _ => return Err(invalid()),
        }
        Ok(())
    }

    pub fn extend(&mut self, set: &IpSet) {
        self.v4.extend_from_slice(&set.v4);
        self.v6.extend_from_slice(&set.v6);
    }

    pub fn build(mut self) -> IpSet {
        IpSet {
            v4: merge(&mut self.v4),
            v6: merge(&mut self.v6),
        }
    }
}

fn merge<T: Copy + Ord + num::Successor>(ranges: &mut [(T, T)]) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for &(from, to) in ranges.iter() {
        if let Some(last) = out.last_mut()
            && (from <= last.1 || T::adjacent(last.1, from))
        {
            if to > last.1 {
                last.1 = to;
            }
            continue;
        }
        out.push((from, to));
    }
    out.shrink_to_fit();
    out
}

mod num {
    pub trait Successor {
        fn adjacent(end: Self, next: Self) -> bool;
    }
    impl Successor for u32 {
        fn adjacent(end: Self, next: Self) -> bool {
            end.checked_add(1) == Some(next)
        }
    }
    impl Successor for u128 {
        fn adjacent(end: Self, next: Self) -> bool {
            end.checked_add(1) == Some(next)
        }
    }
}

fn find<T: Copy + Ord>(ranges: &[(T, T)], value: T) -> bool {
    let idx = ranges.partition_point(|&(from, _)| from <= value);
    idx > 0 && value <= ranges[idx - 1].1
}

impl IpSet {
    pub fn from_cidrs<'a>(items: impl IntoIterator<Item = &'a str>) -> Result<Self> {
        let mut builder = IpSetBuilder::default();
        for item in items {
            builder.add_cidr(item)?;
        }
        Ok(builder.build())
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => find(&self.v4, v4.to_bits()),
            IpAddr::V6(v6) => find(&self.v6, v6.to_bits()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn ranges4(&self) -> impl Iterator<Item = (Ipv4Addr, Ipv4Addr)> + '_ {
        self.v4
            .iter()
            .map(|&(a, b)| (Ipv4Addr::from_bits(a), Ipv4Addr::from_bits(b)))
    }

    pub fn ranges6(&self) -> impl Iterator<Item = (Ipv6Addr, Ipv6Addr)> + '_ {
        self.v6
            .iter()
            .map(|&(a, b)| (Ipv6Addr::from_bits(a), Ipv6Addr::from_bits(b)))
    }

    pub fn range_count(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn heap_bytes(&self) -> usize {
        self.v4.capacity() * 8 + self.v6.capacity() * 32
    }

    /// 覆盖同样地址的最少 CIDR 列表，IPv4 在前。
    pub fn prefixes(&self) -> Vec<String> {
        let mut out = Vec::new();
        for &(from, to) in &self.v4 {
            split_range(u128::from(from), u128::from(to), 32, &mut |base, len| {
                let addr = Ipv4Addr::from_bits(u32::try_from(base).unwrap_or(0));
                out.push(format!("{addr}/{len}"));
            });
        }
        for &(from, to) in &self.v6 {
            split_range(from, to, 128, &mut |base, len| {
                out.push(format!("{}/{len}", Ipv6Addr::from_bits(base)));
            });
        }
        out
    }
}

fn split_range(mut from: u128, to: u128, bits: u32, emit: &mut dyn FnMut(u128, u32)) {
    loop {
        let align = if from == 0 {
            bits
        } else {
            from.trailing_zeros().min(bits)
        };
        let span = to - from;
        let fit = if span == u128::MAX {
            128
        } else {
            127 - (span + 1).leading_zeros()
        };
        let host = align.min(fit);
        emit(from, bits - host);
        let size_minus_one = if host >= 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        if from.checked_add(size_minus_one).is_none_or(|end| end >= to) {
            return;
        }
        from += size_minus_one + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_and_matches_ranges_of_both_families() {
        let set = IpSet::from_cidrs([
            "10.0.0.0/9",
            "10.128.0.0/9",
            "192.168.1.7",
            "2001:db8::/32",
            "::ffff:1.2.3.0/120",
        ])
        .unwrap();
        assert_eq!(
            set.prefixes(),
            [
                "1.2.3.0/24",
                "10.0.0.0/8",
                "192.168.1.7/32",
                "2001:db8::/32"
            ]
        );
        assert!(set.contains("10.200.0.1".parse().unwrap()));
        assert!(set.contains("::ffff:10.1.1.1".parse().unwrap()));
        assert!(!set.contains("11.0.0.0".parse().unwrap()));
        assert!(set.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!set.contains("2001:db9::".parse().unwrap()));
    }

    #[test]
    fn range_splits_into_minimal_prefixes() {
        let mut builder = IpSetBuilder::default();
        builder
            .add_range("1.0.0.1".parse().unwrap(), "1.0.0.6".parse().unwrap())
            .unwrap();
        builder
            .add_range(
                "::".parse().unwrap(),
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
            )
            .unwrap();
        builder.add_cidr("0.0.0.0/0").unwrap();
        assert_eq!(builder.build().prefixes(), ["0.0.0.0/0", "::/0"]);
        let mut builder = IpSetBuilder::default();
        builder
            .add_range("1.0.0.1".parse().unwrap(), "1.0.0.6".parse().unwrap())
            .unwrap();
        assert_eq!(
            builder.build().prefixes(),
            ["1.0.0.1/32", "1.0.0.2/31", "1.0.0.4/31", "1.0.0.6/32"]
        );
    }
}
