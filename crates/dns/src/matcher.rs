//! Mihomo 域名通配、`geosite:` 与 `rule-set:` 条件；集合内容由运行时注入的 [`SetLookup`] 提供。

use kerlico_core::{Error, Result};
use std::{net::IpAddr, sync::Arc};

/// 规则集与 Geo 数据的查询入口，由装配方（出站调度器）注入。
pub trait SetLookup: Send + Sync {
    fn has_rule_set(&self, tag: &str) -> bool;
    fn rule_set_matches_domain(&self, tag: &str, host: &str) -> bool;
    fn rule_set_matches_ip(&self, tag: &str, ip: IpAddr) -> bool;
    fn geosite_matches(&self, code: &str, host: &str) -> bool;
    fn geoip_matches(&self, code: &str, ip: IpAddr) -> bool;
}

/// 未注入集合时：规则集不存在，Geo 条件不命中。
pub struct NoSets;
impl SetLookup for NoSets {
    fn has_rule_set(&self, _tag: &str) -> bool {
        false
    }
    fn rule_set_matches_domain(&self, _tag: &str, _host: &str) -> bool {
        false
    }
    fn rule_set_matches_ip(&self, _tag: &str, _ip: IpAddr) -> bool {
        false
    }
    fn geosite_matches(&self, _code: &str, _host: &str) -> bool {
        false
    }
    fn geoip_matches(&self, _code: &str, _ip: IpAddr) -> bool {
        false
    }
}

pub(crate) fn invalid() -> Error {
    Error::Config("DNS 配置不合法".into())
}

/// Mihomo 域名通配：`*` 匹配一级，`.x` 匹配 x 的任意级子域，`+.x` 同时匹配 x 本身。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DomainPattern {
    Exact(String),
    /// 按标签匹配，`*` 标签匹配任意单个标签。
    Labels(Vec<String>),
    Suffix {
        suffix: String,
        include_self: bool,
    },
}

impl DomainPattern {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let p = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if p.is_empty() {
            return Err(invalid());
        }
        if p == "*" {
            return Ok(Self::Labels(vec!["*".into()]));
        }
        if p == "+" || p == "." {
            return Ok(Self::Suffix {
                suffix: String::new(),
                include_self: true,
            });
        }
        if let Some(rest) = p.strip_prefix("+.") {
            return Ok(Self::Suffix {
                suffix: check_plain(rest)?,
                include_self: true,
            });
        }
        if let Some(rest) = p.strip_prefix('.') {
            return Ok(Self::Suffix {
                suffix: check_plain(rest)?,
                include_self: false,
            });
        }
        if p.contains('*') {
            let labels: Vec<String> = p.split('.').map(str::to_owned).collect();
            if labels
                .iter()
                .any(|l| l.is_empty() || (l.contains('*') && l != "*"))
            {
                return Err(invalid());
            }
            return Ok(Self::Labels(labels));
        }
        Ok(Self::Exact(check_plain(&p)?))
    }

    pub(crate) fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(name) => name == host,
            Self::Labels(labels) => {
                let parts: Vec<&str> = host.split('.').collect();
                parts.len() == labels.len()
                    && labels.iter().zip(&parts).all(|(l, p)| l == "*" || l == p)
            }
            Self::Suffix {
                suffix,
                include_self,
            } => {
                if suffix.is_empty() {
                    return true;
                }
                (*include_self && host == suffix)
                    || host
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1)
            }
        }
    }

    /// 同时命中多条时的优先级：精确名最高，其次固定标签多者，同长度下单级 `*` 优先于多级后缀。
    pub(crate) fn specificity(&self) -> (u8, usize, u8) {
        match self {
            Self::Exact(name) => (2, name.split('.').count(), 0),
            Self::Labels(labels) => (1, labels.iter().filter(|l| *l != "*").count(), 2),
            Self::Suffix { suffix, .. } if suffix.is_empty() => (0, 0, 0),
            Self::Suffix { suffix, .. } => (1, suffix.split('.').count(), 1),
        }
    }
}

fn check_plain(name: &str) -> Result<String> {
    if name.is_empty()
        || name.len() > 253
        || name
            .split('.')
            .any(|l| l.is_empty() || l.len() > 63 || l.contains(['*', '/', ' ', ',', ':']))
    {
        return Err(invalid());
    }
    Ok(name.to_owned())
}

/// 单个条件：域名通配、geosite 或规则集。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Condition {
    Domain(DomainPattern),
    Geosite(String),
    RuleSet(String),
}

impl Condition {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let t = raw.trim();
        let lower = t.to_ascii_lowercase();
        if let Some(code) = lower.strip_prefix("geosite:") {
            if code.trim().is_empty() {
                return Err(invalid());
            }
            return Ok(Self::Geosite(code.trim().to_owned()));
        }
        if let Some(idx) = lower
            .strip_prefix("rule-set:")
            .or_else(|| lower.strip_prefix("rule_set:"))
            .map(|_| t.find(':').unwrap_or(0) + 1)
        {
            let tag = t[idx..].trim();
            if tag.is_empty() {
                return Err(invalid());
            }
            return Ok(Self::RuleSet(tag.to_owned()));
        }
        Ok(Self::Domain(DomainPattern::parse(t)?))
    }

    pub(crate) fn matches(&self, host: &str, sets: &dyn SetLookup) -> bool {
        match self {
            Self::Domain(p) => p.matches(host),
            Self::Geosite(code) => sets.geosite_matches(code, host),
            Self::RuleSet(tag) => sets.rule_set_matches_domain(tag, host),
        }
    }

    pub(crate) fn rule_set(&self) -> Option<&str> {
        match self {
            Self::RuleSet(tag) => Some(tag),
            _ => None,
        }
    }
}

/// 一组条件：域名通配按优先级取最具体者，集合条件按配置顺序。
#[derive(Clone, Debug)]
pub(crate) struct ConditionTable<T> {
    entries: Vec<(Condition, T)>,
    ordered: bool,
}

impl<T> Default for ConditionTable<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            ordered: false,
        }
    }
}

impl<T> ConditionTable<T> {
    pub(crate) fn push(&mut self, cond: Condition, value: T) {
        self.entries.push((cond, value));
    }

    pub(crate) fn rule_sets(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().filter_map(|(c, _)| c.rule_set())
    }

    /// 按书写顺序匹配（Mihomo）：连续的域名通配组成一段，段内取最具体者；集合条件逐条检查；先命中者胜出。
    pub(crate) fn ordered() -> Self {
        Self {
            entries: Vec::new(),
            ordered: true,
        }
    }

    pub(crate) fn lookup(&self, host: &str, sets: &dyn SetLookup) -> Option<&T> {
        if self.ordered {
            return self.lookup_in_order(host, sets);
        }
        let best = self
            .entries
            .iter()
            .filter_map(|(c, v)| match c {
                Condition::Domain(p) if p.matches(host) => Some((p.specificity(), v)),
                _ => None,
            })
            .max_by_key(|(score, _)| *score)
            .map(|(_, v)| v);
        best.or_else(|| {
            self.entries
                .iter()
                .find(|(c, _)| !matches!(c, Condition::Domain(_)) && c.matches(host, sets))
                .map(|(_, v)| v)
        })
    }
}

impl<T> ConditionTable<T> {
    fn lookup_in_order(&self, host: &str, sets: &dyn SetLookup) -> Option<&T> {
        let mut run: Option<((u8, usize, u8), &T)> = None;
        for (cond, value) in &self.entries {
            match cond {
                Condition::Domain(p) => {
                    if p.matches(host) && run.is_none_or(|(best, _)| p.specificity() > best) {
                        run = Some((p.specificity(), value));
                    }
                }
                other => {
                    if let Some((_, v)) = run {
                        return Some(v);
                    }
                    if other.matches(host, sets) {
                        return Some(value);
                    }
                }
            }
        }
        run.map(|(_, v)| v)
    }
}

pub(crate) type Sets = Arc<dyn SetLookup>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mihomo_wildcards() {
        let p = |s: &str| DomainPattern::parse(s).unwrap();
        assert!(p("+.example.com").matches("example.com"));
        assert!(p("+.example.com").matches("a.b.example.com"));
        assert!(!p(".example.com").matches("example.com"));
        assert!(p(".example.com").matches("a.b.example.com"));
        assert!(p("*.example.com").matches("a.example.com"));
        assert!(!p("*.example.com").matches("a.b.example.com"));
        assert!(!p("*.example.com").matches("example.com"));
        assert!(p("www.*.com").matches("www.x.com"));
        assert!(!p("example.com").matches("www.example.com"));
        assert!(!p("+.example.com").matches("badexample.com"));
        assert!(DomainPattern::parse("a*.com").is_err());

        let mut table = ConditionTable::default();
        table.push(Condition::parse("+.example.com").unwrap(), 1);
        table.push(Condition::parse("*.example.com").unwrap(), 2);
        table.push(Condition::parse("www.example.com").unwrap(), 3);
        table.push(Condition::parse("geosite:cn").unwrap(), 4);
        assert_eq!(table.lookup("www.example.com", &NoSets), Some(&3));
        assert_eq!(table.lookup("a.example.com", &NoSets), Some(&2));
        assert_eq!(table.lookup("a.b.example.com", &NoSets), Some(&1));
        assert_eq!(table.lookup("other.org", &NoSets), None);
        let mut ordered = ConditionTable::ordered();
        ordered.push(Condition::parse("geosite:cn").unwrap(), 1);
        ordered.push(Condition::parse("+.example.com").unwrap(), 2);
        ordered.push(Condition::parse("www.example.com").unwrap(), 3);
        ordered.push(Condition::parse("rule-set:late").unwrap(), 4);
        struct All;
        impl SetLookup for All {
            fn has_rule_set(&self, _: &str) -> bool {
                true
            }
            fn rule_set_matches_domain(&self, _: &str, _: &str) -> bool {
                true
            }
            fn rule_set_matches_ip(&self, _: &str, _: IpAddr) -> bool {
                true
            }
            fn geosite_matches(&self, _: &str, host: &str) -> bool {
                host.ends_with(".cn")
            }
            fn geoip_matches(&self, _: &str, _: IpAddr) -> bool {
                true
            }
        }
        assert_eq!(
            ordered.lookup("a.cn", &All),
            Some(&1),
            "书写在前的集合条件先命中"
        );
        assert_eq!(
            ordered.lookup("www.example.com", &All),
            Some(&3),
            "同段内取最具体者"
        );
        assert_eq!(ordered.lookup("other.org", &All), Some(&4));
        assert_eq!(
            Condition::parse("rule-set:My-Set").unwrap(),
            Condition::RuleSet("My-Set".into())
        );
    }
}
