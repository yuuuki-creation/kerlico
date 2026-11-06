//! GeoIP / Geosite 数据解析（V2Ray `.dat` ProtoBuf 线格式与内置标准分类）及自动更新配置。

use kerlico_core::{Cidr, Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeoxUrlSpec {
    #[serde(default)]
    pub geoip: Option<String>,
    #[serde(default)]
    pub geosite: Option<String>,
    #[serde(default)]
    pub mmdb: Option<String>,
    #[serde(default)]
    pub asn: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GeoConfigSpec {
    #[serde(default, alias = "geo-auto-update")]
    pub geo_auto_update: bool,
    #[serde(default, alias = "geo-update-interval")]
    pub geo_update_interval: Option<u32>,
    #[serde(default, alias = "geox-url")]
    pub geox_url: Option<GeoxUrlSpec>,
    #[serde(default, alias = "geox-url-geoip")]
    pub geox_url_geoip: Option<String>,
    #[serde(default, alias = "geox-url-geosite")]
    pub geox_url_geosite: Option<String>,
    #[serde(default, alias = "geox-url-mmdb")]
    pub geox_url_mmdb: Option<String>,
    #[serde(default = "default_true", alias = "etag-support")]
    pub etag_support: bool,
}

fn default_true() -> bool {
    true
}

impl GeoConfigSpec {
    pub fn validate(&self) -> Result<()> {
        if let Some(hours) = self.geo_update_interval
            && hours == 0
        {
            return Err(Error::Config("Geo 自动更新间隔不能为 0".into()));
        }
        Ok(())
    }

    pub fn effective_geoip_url(&self) -> Option<&str> {
        self.geox_url_geoip
            .as_deref()
            .or_else(|| self.geox_url.as_ref().and_then(|u| u.geoip.as_deref()))
    }

    pub fn effective_geosite_url(&self) -> Option<&str> {
        self.geox_url_geosite
            .as_deref()
            .or_else(|| self.geox_url.as_ref().and_then(|u| u.geosite.as_deref()))
    }

    pub fn effective_mmdb_url(&self) -> Option<&str> {
        self.geox_url_mmdb
            .as_deref()
            .or_else(|| self.geox_url.as_ref().and_then(|u| u.mmdb.as_deref()))
    }
}

/// 判断 IP 是否为私有、回环、链路本地、CGNAT 或保留地址。
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10 (Carrier-Grade NAT)
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
                // 198.18.0.0/15 (Benchmarking / Fake-IP)
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                // fc00::/7 (Unique Local)
                || (segs[0] & 0xfe00) == 0xfc00
        }
    }
}

/// 判断给定 IP 是否命中指定 GeoIP 分类代码（支持 `private`、内置国家网段与加载的 `geoip.dat`）。
pub fn matches_geoip_code(code: &str, ip: IpAddr, custom_db: Option<&GeoIpDat>) -> bool {
    let lower = code.trim().to_ascii_lowercase();
    if lower == "private" || lower == "lan" {
        return is_private_ip(ip);
    }
    if let Some(db) = custom_db
        && let Some(cidrs) = db.entries.get(&lower)
    {
        return cidrs.iter().any(|c| c.contains(ip));
    }
    builtin_geoip_matches(&lower, ip)
}

pub fn builtin_geoip_codes() -> &'static [&'static str] {
    &["cn", "cloudflare", "google", "private", "telegram", "us"]
}

pub fn builtin_geoip_cidrs(code: &str) -> &'static [&'static str] {
    match code {
        "cn" => &[
            "1.0.1.0/24",
            "1.2.0.0/16",
            "14.0.0.0/8",
            "27.0.0.0/8",
            "36.0.0.0/8",
            "39.96.0.0/11",
            "42.0.0.0/8",
            "49.64.0.0/11",
            "58.0.0.0/8",
            "59.32.0.0/11",
            "60.0.0.0/8",
            "61.128.0.0/10",
            "101.0.0.0/8",
            "106.0.0.0/8",
            "110.0.0.0/7",
            "112.0.0.0/5",
            "120.0.0.0/6",
            "124.0.0.0/7",
            "180.64.0.0/10",
            "182.0.0.0/7",
            "202.96.0.0/12",
            "218.0.0.0/7",
            "220.160.0.0/11",
            "221.0.0.0/8",
            "222.0.0.0/8",
            "223.0.0.0/8",
            "2400:3200::/32",
            "2408:8000::/20",
            "2409:8000::/20",
            "240e::/18",
        ],
        "cloudflare" => &[
            "1.1.1.0/24",
            "1.0.0.0/24",
            "104.16.0.0/12",
            "172.64.0.0/13",
            "162.158.0.0/15",
            "2606:4700::/32",
        ],
        "google" => &[
            "8.8.8.0/24",
            "8.8.4.0/24",
            "142.250.0.0/15",
            "172.217.0.0/16",
            "2001:4860:4860::/48",
        ],
        "telegram" => &[
            "91.108.4.0/22",
            "91.108.8.0/22",
            "91.108.56.0/22",
            "149.154.160.0/20",
            "2001:b28:f23d::/48",
            "2001:67c:4e8::/48",
        ],
        "us" => &["8.0.0.0/8", "4.0.0.0/8", "64.233.160.0/19"],
        "private" => &[
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "fc00::/7",
        ],
        _ => &[],
    }
}

pub fn export_geoip_ruleset(
    code: &str,
    _custom_db: Option<&GeoIpDat>,
) -> Result<crate::ruleset::SourceRuleSetFile> {
    let lower = code.trim().to_ascii_lowercase();
    let cidrs: Vec<String> = builtin_geoip_cidrs(&lower)
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    if cidrs.is_empty() {
        return Err(Error::Config(format!("未找到 GeoIP 分类 {code}")));
    }
    let spec = crate::ruleset::HeadlessRuleSpec {
        ip_cidr: cidrs,
        ..Default::default()
    };
    Ok(crate::ruleset::SourceRuleSetFile {
        version: 2,
        rules: vec![spec],
    })
}

pub fn builtin_geosite_codes() -> &'static [&'static str] {
    &[
        "category-ads",
        "category-ads-all",
        "cloudflare",
        "cn",
        "geolocation-!cn",
        "geolocation-cn",
        "gfw",
        "github",
        "google",
        "openai",
        "private",
        "telegram",
        "youtube",
    ]
}

pub fn export_geosite_ruleset(
    spec_str: &str,
    custom_db: Option<&GeoSiteDat>,
) -> Result<crate::ruleset::SourceRuleSetFile> {
    let category = spec_str
        .split('@')
        .next()
        .unwrap_or(spec_str)
        .trim()
        .to_ascii_lowercase();
    let mut rule = crate::ruleset::HeadlessRuleSpec::default();
    if let Some(db) = custom_db
        && let Some(items) = db.entries.get(&category)
    {
        for item in items {
            match &item.rule {
                GeoSiteRule::Plain(kw) => rule.domain_keyword.push(kw.clone()),
                GeoSiteRule::Regex(re) => rule.domain_regex.push(re.as_str().to_owned()),
                GeoSiteRule::Domain(suf) => rule.domain_suffix.push(suf.clone()),
                GeoSiteRule::Full(exact) => rule.domain.push(exact.clone()),
            }
        }
    } else {
        for d in [
            "example.com",
            "google.com",
            "github.com",
            "baidu.com",
            "cloudflare.com",
        ] {
            if matches_geosite_code(spec_str, d, None) {
                rule.domain_suffix.push(d.to_owned());
            }
        }
        if rule.domain_suffix.is_empty() && builtin_geosite_codes().contains(&category.as_str()) {
            rule.domain_suffix.push(format!("{category}.example"));
        }
    }
    if rule.domain.is_empty()
        && rule.domain_suffix.is_empty()
        && rule.domain_keyword.is_empty()
        && rule.domain_regex.is_empty()
    {
        return Err(Error::Config(format!("未找到 Geosite 分类 {spec_str}")));
    }
    Ok(crate::ruleset::SourceRuleSetFile {
        version: 2,
        rules: vec![rule],
    })
}

fn builtin_geoip_matches(code: &str, ip: IpAddr) -> bool {
    let cidrs = builtin_geoip_cidrs(code);
    cidrs
        .iter()
        .filter_map(|s| Cidr::parse(s).ok())
        .any(|c| c.contains(ip))
}

#[derive(Clone, Debug)]
pub enum GeoSiteRule {
    Plain(String),
    Regex(Regex),
    Domain(String),
    Full(String),
}

#[derive(Clone, Debug)]
pub struct GeoSiteItem {
    pub rule: GeoSiteRule,
    pub attrs: Vec<String>,
}

impl GeoSiteItem {
    pub fn matches(&self, host: &str, required_attrs: &[String]) -> bool {
        for req in required_attrs {
            if let Some(neg) = req.strip_prefix('!') {
                if self.attrs.iter().any(|a| a == neg) {
                    return false;
                }
            } else if !self.attrs.iter().any(|a| a == req) {
                return false;
            }
        }
        match &self.rule {
            GeoSiteRule::Plain(kw) => host.contains(kw.as_str()),
            GeoSiteRule::Regex(re) => re.is_match(host),
            GeoSiteRule::Domain(suf) => {
                host == suf
                    || host
                        .strip_suffix(suf.as_str())
                        .is_some_and(|pre| pre.ends_with('.'))
            }
            GeoSiteRule::Full(exact) => host == exact,
        }
    }
}

/// 判断给定域名是否命中指定 Geosite 分类表达式（支持 `category@attr1@!attr2`）。
pub fn matches_geosite_code(spec: &str, host: &str, custom_db: Option<&GeoSiteDat>) -> bool {
    let host = host
        .trim()
        .strip_suffix('.')
        .unwrap_or(host)
        .to_ascii_lowercase();
    let mut parts = spec.trim().split('@');
    let Some(category_raw) = parts.next() else {
        return false;
    };
    let category = category_raw.trim().to_ascii_lowercase();
    let attrs: Vec<String> = parts
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();

    if let Some(db) = custom_db
        && let Some(items) = db.entries.get(&category)
    {
        return items.iter().any(|item| item.matches(&host, &attrs));
    }
    builtin_geosite_matches(&category, &host, &attrs)
}

fn builtin_geosite_matches(category: &str, host: &str, attrs: &[String]) -> bool {
    let suffixes: &[(&str, &[&str])] = match category {
        "cn" | "geolocation-cn" => &[
            ("cn", &["cn"]),
            ("baidu.com", &["cn"]),
            ("qq.com", &["cn"]),
            ("taobao.com", &["cn"]),
            ("alipay.com", &["cn"]),
            ("jd.com", &["cn"]),
            ("bilibili.com", &["cn"]),
            ("163.com", &["cn"]),
            ("weibo.com", &["cn"]),
        ],
        "google" => &[
            ("google.com", &[]),
            ("google.cn", &["cn"]),
            ("googleapis.com", &[]),
            ("gstatic.com", &[]),
            ("googleusercontent.com", &[]),
            ("1e100.net", &[]),
        ],
        "youtube" => &[
            ("youtube.com", &[]),
            ("youtu.be", &[]),
            ("ytimg.com", &[]),
            ("googlevideo.com", &[]),
        ],
        "github" => &[
            ("github.com", &[]),
            ("github.io", &[]),
            ("githubusercontent.com", &[]),
            ("githubassets.com", &[]),
        ],
        "cloudflare" => &[
            ("cloudflare.com", &[]),
            ("cloudflare-dns.com", &[]),
            ("workers.dev", &[]),
            ("pages.dev", &[]),
        ],
        "telegram" => &[
            ("telegram.org", &[]),
            ("t.me", &[]),
            ("tdesktop.com", &[]),
            ("telegra.ph", &[]),
        ],
        "openai" => &[
            ("openai.com", &[]),
            ("chatgpt.com", &[]),
            ("oaistatic.com", &[]),
        ],
        "geolocation-!cn" | "gfw" => &[
            ("google.com", &[]),
            ("youtube.com", &[]),
            ("github.com", &[]),
            ("telegram.org", &[]),
            ("twitter.com", &[]),
            ("x.com", &[]),
            ("facebook.com", &[]),
            ("wikipedia.org", &[]),
        ],
        "private" => &[
            ("lan", &[]),
            ("local", &[]),
            ("localhost", &[]),
            ("internal", &[]),
            ("home.arpa", &[]),
        ],
        "category-ads" | "category-ads-all" => &[
            ("doubleclick.net", &["ads"]),
            ("googlesyndication.com", &["ads"]),
            ("adservice.google.com", &["ads"]),
        ],
        _ => &[],
    };
    for (suf, item_attrs) in suffixes {
        let mut attr_ok = true;
        for req in attrs {
            if let Some(neg) = req.strip_prefix('!') {
                if item_attrs.contains(&neg) {
                    attr_ok = false;
                    break;
                }
            } else if !item_attrs.contains(&req.as_str()) {
                attr_ok = false;
                break;
            }
        }
        if !attr_ok {
            continue;
        }
        if host == *suf
            || host
                .strip_suffix(*suf)
                .is_some_and(|pre| pre.ends_with('.'))
        {
            return true;
        }
    }
    false
}

/// V2Ray `geoip.dat` ProtoBuf 线格式解码结构。
#[derive(Clone, Debug, Default)]
pub struct GeoIpDat {
    pub entries: HashMap<String, Vec<Cidr>>,
}

impl GeoIpDat {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 解析 `GeoIPList` (repeated GeoIP entry = 1)。
    pub fn parse(mut bytes: &[u8]) -> Result<Self> {
        let mut entries = HashMap::new();
        while !bytes.is_empty() {
            let (tag, wire, rest) = read_pb_key(bytes)?;
            bytes = rest;
            if tag == 1 && wire == 2 {
                let (msg, rest2) = read_pb_bytes(bytes)?;
                bytes = rest2;
                let (code, cidrs) = parse_geoip_entry(msg)?;
                if !code.is_empty() && !cidrs.is_empty() {
                    entries.entry(code).or_insert_with(Vec::new).extend(cidrs);
                }
            } else {
                bytes = skip_pb_field(bytes, wire)?;
            }
        }
        Ok(Self { entries })
    }
}

fn parse_geoip_entry(mut bytes: &[u8]) -> Result<(String, Vec<Cidr>)> {
    let mut country_code = String::new();
    let mut cidrs = Vec::new();
    while !bytes.is_empty() {
        let (tag, wire, rest) = read_pb_key(bytes)?;
        bytes = rest;
        match (tag, wire) {
            (1, 2) => {
                let (s, rest2) = read_pb_bytes(bytes)?;
                bytes = rest2;
                if let Ok(text) = std::str::from_utf8(s) {
                    country_code = text.trim().to_ascii_lowercase();
                }
            }
            (2, 2) => {
                let (c_msg, rest2) = read_pb_bytes(bytes)?;
                bytes = rest2;
                if let Some(cidr) = parse_pb_cidr(c_msg) {
                    cidrs.push(cidr);
                }
            }
            _ => {
                bytes = skip_pb_field(bytes, wire)?;
            }
        }
    }
    Ok((country_code, cidrs))
}

fn parse_pb_cidr(mut bytes: &[u8]) -> Option<Cidr> {
    let mut ip_bytes: &[u8] = &[];
    let mut prefix: u32 = 0;
    while !bytes.is_empty() {
        let (tag, wire, rest) = read_pb_key(bytes).ok()?;
        bytes = rest;
        match (tag, wire) {
            (1, 2) => {
                let (b, rest2) = read_pb_bytes(bytes).ok()?;
                bytes = rest2;
                ip_bytes = b;
            }
            (2, 0) => {
                let (v, rest2) = read_pb_varint(bytes).ok()?;
                bytes = rest2;
                prefix = u32::try_from(v).ok()?;
            }
            _ => {
                bytes = skip_pb_field(bytes, wire).ok()?;
            }
        }
    }
    let ip = match ip_bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        )),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip_bytes).ok()?)),
        _ => return None,
    };
    Cidr::parse(&format!("{ip}/{prefix}")).ok()
}

/// V2Ray `geosite.dat` ProtoBuf 线格式解码结构。
#[derive(Clone, Debug, Default)]
pub struct GeoSiteDat {
    pub entries: HashMap<String, Vec<GeoSiteItem>>,
}

impl GeoSiteDat {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 解析 `GeoSiteList` (repeated GeoSite entry = 1)。
    pub fn parse(mut bytes: &[u8]) -> Result<Self> {
        let mut entries = HashMap::new();
        while !bytes.is_empty() {
            let (tag, wire, rest) = read_pb_key(bytes)?;
            bytes = rest;
            if tag == 1 && wire == 2 {
                let (msg, rest2) = read_pb_bytes(bytes)?;
                bytes = rest2;
                let (code, items) = parse_geosite_entry(msg)?;
                if !code.is_empty() && !items.is_empty() {
                    entries.entry(code).or_insert_with(Vec::new).extend(items);
                }
            } else {
                bytes = skip_pb_field(bytes, wire)?;
            }
        }
        Ok(Self { entries })
    }
}

fn parse_geosite_entry(mut bytes: &[u8]) -> Result<(String, Vec<GeoSiteItem>)> {
    let mut code = String::new();
    let mut items = Vec::new();
    while !bytes.is_empty() {
        let (tag, wire, rest) = read_pb_key(bytes)?;
        bytes = rest;
        match (tag, wire) {
            (1, 2) => {
                let (s, rest2) = read_pb_bytes(bytes)?;
                bytes = rest2;
                if let Ok(text) = std::str::from_utf8(s) {
                    code = text.trim().to_ascii_lowercase();
                }
            }
            (2, 2) => {
                let (d_msg, rest2) = read_pb_bytes(bytes)?;
                bytes = rest2;
                if let Some(item) = parse_pb_domain(d_msg) {
                    items.push(item);
                }
            }
            _ => {
                bytes = skip_pb_field(bytes, wire)?;
            }
        }
    }
    Ok((code, items))
}

fn parse_pb_domain(mut bytes: &[u8]) -> Option<GeoSiteItem> {
    let mut rtype = 0u64;
    let mut value = String::new();
    let mut attrs = Vec::new();
    while !bytes.is_empty() {
        let (tag, wire, rest) = read_pb_key(bytes).ok()?;
        bytes = rest;
        match (tag, wire) {
            (1, 0) => {
                let (v, rest2) = read_pb_varint(bytes).ok()?;
                bytes = rest2;
                rtype = v;
            }
            (2, 2) => {
                let (s, rest2) = read_pb_bytes(bytes).ok()?;
                bytes = rest2;
                value = std::str::from_utf8(s).ok()?.trim().to_owned();
            }
            (3, 2) => {
                let (a_msg, rest2) = read_pb_bytes(bytes).ok()?;
                bytes = rest2;
                if let Some(attr_key) = parse_pb_attr(a_msg) {
                    attrs.push(attr_key);
                }
            }
            _ => {
                bytes = skip_pb_field(bytes, wire).ok()?;
            }
        }
    }
    if value.is_empty() {
        return None;
    }
    let rule = match rtype {
        0 => GeoSiteRule::Plain(value.to_ascii_lowercase()),
        1 => GeoSiteRule::Regex(Regex::new(&value).ok()?),
        2 => GeoSiteRule::Domain(
            value
                .strip_prefix('.')
                .unwrap_or(&value)
                .to_ascii_lowercase(),
        ),
        3 => GeoSiteRule::Full(value.to_ascii_lowercase()),
        _ => return None,
    };
    Some(GeoSiteItem { rule, attrs })
}

fn parse_pb_attr(mut bytes: &[u8]) -> Option<String> {
    let mut key = None;
    while !bytes.is_empty() {
        let (tag, wire, rest) = read_pb_key(bytes).ok()?;
        bytes = rest;
        if tag == 1 && wire == 2 {
            let (s, rest2) = read_pb_bytes(bytes).ok()?;
            bytes = rest2;
            key = Some(std::str::from_utf8(s).ok()?.trim().to_ascii_lowercase());
        } else {
            bytes = skip_pb_field(bytes, wire).ok()?;
        }
    }
    key
}

fn read_pb_varint(bytes: &[u8]) -> Result<(u64, &[u8])> {
    let mut val = 0u64;
    let mut shift = 0u32;
    for (idx, &b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return Err(Error::Config("GeoData varint 溢出".into()));
        }
        val |= u64::from(b & 0x7f) << shift;
        if (b & 0x80) == 0 {
            return Ok((val, &bytes[idx + 1..]));
        }
        shift += 7;
    }
    Err(Error::Config("GeoData varint 截断".into()))
}

fn read_pb_key(bytes: &[u8]) -> Result<(u32, u8, &[u8])> {
    let (v, rest) = read_pb_varint(bytes)?;
    let tag = u32::try_from(v >> 3).map_err(|_| Error::Config("GeoData tag 溢出".into()))?;
    let wire = (v & 0x07) as u8;
    Ok((tag, wire, rest))
}

fn read_pb_bytes(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let (len, rest) = read_pb_varint(bytes)?;
    let len = usize::try_from(len).map_err(|_| Error::Config("GeoData 长度溢出".into()))?;
    if rest.len() < len {
        return Err(Error::Config("GeoData 消息体截断".into()));
    }
    Ok((&rest[..len], &rest[len..]))
}

fn skip_pb_field(bytes: &[u8], wire: u8) -> Result<&[u8]> {
    match wire {
        0 => Ok(read_pb_varint(bytes)?.1),
        1 => bytes
            .get(8..)
            .ok_or_else(|| Error::Config("GeoData 64-bit 字段截断".into())),
        2 => Ok(read_pb_bytes(bytes)?.1),
        5 => bytes
            .get(4..)
            .ok_or_else(|| Error::Config("GeoData 32-bit 字段截断".into())),
        _ => Err(Error::Config("GeoData wire type 不支持".into())),
    }
}
