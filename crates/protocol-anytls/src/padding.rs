use kerlico_core::{Error, Result};
use md5::{Digest, Md5};
use rand::Rng;
use std::collections::BTreeMap;

pub const DEFAULT: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
#[derive(Clone)]
pub struct Padding {
    pub raw: String,
    pub md5: String,
    pub stop: u32,
    rules: BTreeMap<u32, Vec<Option<(usize, usize)>>>,
}
impl Padding {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > 16384 {
            return Err(Error::Config("AnyTLS padding 方案过长".into()));
        }
        let mut stop = None;
        let mut rules = BTreeMap::new();
        for line in raw.lines() {
            let (key, value) = line
                .split_once('=')
                .ok_or(Error::Protocol("AnyTLS padding 方案不合法"))?;
            if key == "stop" {
                stop = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| Error::Protocol("AnyTLS padding stop 不合法"))?,
                );
                continue;
            }
            let packet = key
                .parse::<u32>()
                .map_err(|_| Error::Protocol("AnyTLS padding 序号不合法"))?;
            let mut ranges = Vec::new();
            for item in value.split(',') {
                if item == "c" {
                    ranges.push(None);
                    continue;
                }
                let (lo, hi) = item
                    .split_once('-')
                    .ok_or(Error::Protocol("AnyTLS padding 区间不合法"))?;
                let lo = lo
                    .parse::<usize>()
                    .map_err(|_| Error::Protocol("AnyTLS padding 区间不合法"))?;
                let hi = hi
                    .parse::<usize>()
                    .map_err(|_| Error::Protocol("AnyTLS padding 区间不合法"))?;
                if lo == 0 || hi == 0 || lo > 65535 || hi > 65535 {
                    return Err(Error::ResourceLimit);
                }
                ranges.push(Some((lo.min(hi), lo.max(hi))));
            }
            if ranges.len() > 64 {
                return Err(Error::ResourceLimit);
            }
            rules.insert(packet, ranges);
        }
        Ok(Self {
            raw: raw.into(),
            md5: format!("{:x}", Md5::digest(raw.as_bytes())),
            stop: stop.ok_or(Error::Protocol("AnyTLS padding 缺少 stop"))?,
            rules,
        })
    }
    pub fn sizes(&self, packet: u32) -> Vec<Option<usize>> {
        self.rules
            .get(&packet)
            .map(|items| {
                items
                    .iter()
                    .map(|range| {
                        range.map(|(lo, hi)| {
                            if lo == hi {
                                lo
                            } else {
                                rand::thread_rng().gen_range(lo..hi)
                            }
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_scheme() {
        let scheme = Padding::parse(DEFAULT).unwrap();
        assert_eq!(scheme.stop, 8);
        assert_eq!(scheme.sizes(0), vec![Some(30)]);
        assert_eq!(scheme.md5.len(), 32);
        for input in ["", "stop=bad", "stop=8\n0=1-999999", "stop=8\n0=0-1"] {
            assert!(Padding::parse(input).is_err());
        }
    }
}
