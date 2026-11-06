//! hosts 表：配置项（精确名、Mihomo 通配、域名别名）优先，其后是系统 hosts 文件。

use crate::{
    HostsValue,
    matcher::{DomainPattern, invalid},
};
use kerlico_core::Result;
use std::{collections::HashMap, net::IpAddr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HostEntry {
    Ips(Vec<IpAddr>),
    Alias(String),
}

#[derive(Default)]
pub(crate) struct Hosts {
    exact: HashMap<String, HostEntry>,
    wild: Vec<(DomainPattern, HostEntry)>,
    system: HashMap<String, Vec<IpAddr>>,
}

fn entry(value: &HostsValue) -> Result<HostEntry> {
    let items: Vec<&str> = match value {
        HostsValue::One(s) => vec![s.as_str()],
        HostsValue::Many(list) => list.iter().map(String::as_str).collect(),
    };
    if items.is_empty() {
        return Err(invalid());
    }
    let ips: Vec<Option<IpAddr>> = items.iter().map(|s| s.trim().parse().ok()).collect();
    if ips.iter().all(Option::is_some) {
        return Ok(HostEntry::Ips(ips.into_iter().flatten().collect()));
    }
    match items.as_slice() {
        [alias] => match DomainPattern::parse(alias)? {
            DomainPattern::Exact(name) => Ok(HostEntry::Alias(name)),
            _ => Err(invalid()),
        },
        _ => Err(invalid()),
    }
}

fn system_hosts_path() -> std::path::PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        std::path::Path::new(&root).join("System32\\drivers\\etc\\hosts")
    } else {
        "/etc/hosts".into()
    }
}

fn parse_system(text: &str) -> HashMap<String, Vec<IpAddr>> {
    let mut out: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts
            .next()
            .and_then(|s| s.split('%').next()?.parse::<IpAddr>().ok())
        else {
            continue;
        };
        for name in parts {
            let ips = out
                .entry(name.trim_end_matches('.').to_ascii_lowercase())
                .or_default();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    out
}

impl Hosts {
    pub(crate) fn build<'a>(
        configured: impl IntoIterator<Item = (&'a String, &'a HostsValue)>,
        use_system: bool,
    ) -> Result<Self> {
        let mut hosts = Self::default();
        for (key, value) in configured {
            let value = entry(value)?;
            match DomainPattern::parse(key)? {
                DomainPattern::Exact(name) => {
                    hosts.exact.insert(name, value);
                }
                pattern => hosts.wild.push((pattern, value)),
            }
        }
        if use_system && let Ok(text) = std::fs::read_to_string(system_hosts_path()) {
            hosts.system = parse_system(&text);
        }
        Ok(hosts)
    }

    fn lookup_one(&self, host: &str) -> Option<HostEntry> {
        if let Some(e) = self.exact.get(host) {
            return Some(e.clone());
        }
        let best = self
            .wild
            .iter()
            .filter(|(p, _)| p.matches(host))
            .max_by_key(|(p, _)| p.specificity());
        if let Some((_, e)) = best {
            return Some(e.clone());
        }
        self.system.get(host).cloned().map(HostEntry::Ips)
    }

    /// 沿别名链查找；返回地址或链尾仍需上游解析的名称。链过长时视为未命中。
    pub(crate) fn resolve(&self, host: &str) -> Option<HostEntry> {
        let mut name = host.to_owned();
        let mut aliased = false;
        for _ in 0..8 {
            match self.lookup_one(&name) {
                Some(HostEntry::Ips(ips)) => return Some(HostEntry::Ips(ips)),
                Some(HostEntry::Alias(next)) => {
                    aliased = true;
                    name = next;
                }
                None => return aliased.then_some(HostEntry::Alias(name)),
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn exact_wildcard_alias_and_system_priority() {
        let mut cfg = BTreeMap::new();
        cfg.insert(
            "*.lan.example".to_owned(),
            HostsValue::One("10.0.0.1".into()),
        );
        cfg.insert(
            "a.lan.example".to_owned(),
            HostsValue::Many(vec!["10.0.0.2".into()]),
        );
        cfg.insert(
            "alias.example".to_owned(),
            HostsValue::One("a.lan.example".into()),
        );
        cfg.insert(
            "far.example".to_owned(),
            HostsValue::One("upstream.example".into()),
        );
        let mut hosts = Hosts::build(&cfg, false).unwrap();
        hosts.system = parse_system("192.0.2.9 sys.example a.lan.example # c\n");
        let ip = |s: &str| HostEntry::Ips(vec![s.parse().unwrap()]);
        assert_eq!(hosts.resolve("a.lan.example"), Some(ip("10.0.0.2")));
        assert_eq!(hosts.resolve("b.lan.example"), Some(ip("10.0.0.1")));
        assert_eq!(hosts.resolve("alias.example"), Some(ip("10.0.0.2")));
        assert_eq!(hosts.resolve("sys.example"), Some(ip("192.0.2.9")));
        assert_eq!(
            hosts.resolve("far.example"),
            Some(HostEntry::Alias("upstream.example".into()))
        );
        assert_eq!(hosts.resolve("none.example"), None);
    }
}
