//! 规则集与 Geo 数据的查询契约，以及 Mihomo `geoip:`、`geosite:`、`rule-set:` 前缀条目。
//!
//! 集合内容属于路由表，DNS 策略与嗅探器只持有名字，求值时经 [`SetLookup`] 读取运行中的数据，
//! 规则集或 Geo 文件刷新后立即生效。

use crate::{Cidr, Error, Result};
use std::net::IpAddr;

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

/// 地址列表的一项：网段、`geoip:<代码>` 或 `rule-set:<名字>`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpMatch {
    Cidr(Cidr),
    GeoIp(String),
    RuleSet(String),
}

impl IpMatch {
    pub fn matches(&self, ip: IpAddr, sets: &dyn SetLookup) -> bool {
        match self {
            Self::Cidr(cidr) => cidr.contains(ip),
            Self::GeoIp(code) => sets.geoip_matches(code, ip),
            Self::RuleSet(tag) => sets.rule_set_matches_ip(tag, ip),
        }
    }
}

/// 域名列表的一项：Mihomo 域名通配、`geosite:<分类>` 或 `rule-set:<名字>`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainMatch {
    Pattern(String),
    GeoSite(String),
    RuleSet(String),
}

/// Mihomo `parseIPCIDR` / `parseDomain`：前缀不区分大小写，冒号后按逗号拆成多项，
/// 第二个冒号之后的内容被丢弃。
fn prefixed<'a>(text: &'a str, prefix: &str) -> Option<impl Iterator<Item = String> + 'a> {
    let head = text.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let body = text[prefix.len()..].split(':').next().unwrap_or_default();
    Some(
        body.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned),
    )
}

impl IpMatch {
    /// 解析一项配置；`field` 用于错误信息。
    pub fn parse_entry(text: &str, field: &str) -> Result<Vec<Self>> {
        let text = text.trim();
        if let Some(codes) = prefixed(text, "geoip:") {
            return Ok(codes.map(Self::GeoIp).collect());
        }
        if let Some(tags) = prefixed(text, "rule-set:") {
            return Ok(tags.map(Self::RuleSet).collect());
        }
        Cidr::parse(text)
            .map(|cidr| vec![Self::Cidr(cidr)])
            .map_err(|_| Error::Config(format!("{field} 网段不合法：{text}")))
    }
}

impl DomainMatch {
    pub fn parse_entry(text: &str) -> Vec<Self> {
        let text = text.trim();
        if let Some(codes) = prefixed(text, "geosite:") {
            return codes.map(Self::GeoSite).collect();
        }
        if let Some(tags) = prefixed(text, "rule-set:") {
            return tags.map(Self::RuleSet).collect();
        }
        vec![Self::Pattern(text.to_owned())]
    }
}
