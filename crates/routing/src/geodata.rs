//! 运行时 GeoIP / GeoSite / IP-ASN 数据：V2Ray `geoip.dat`、`geosite.dat`（ProtoBuf）与
//! MaxMind `Country.mmdb`、`ASN.mmdb`（旧名 `GeoLite2-ASN.mmdb`）。
//!
//! 路由表编译时收集引用的分类（[`GeoNeeds`]），加载文件时只解码这些分类，缺少分类即报错。
//! 数据放在共享槽 [`GeoSlot`] 里，文件更新后整体换入，匹配无锁读取。
//!
//! `geodata-mode: false`（Mihomo 默认）时 GEOIP 查 `Country.mmdb`，为 `true` 时查 `geoip.dat`；
//! GEOSITE 总是查 `geosite.dat`。`geodata-loader` 与 `geosite-matcher` 的各取值使用同一实现。

use crate::{
    domain_set::{DomainRule, DomainSet, DomainSetBuilder},
    ip_set::{IpSet, IpSetBuilder},
    mmdb::Mmdb,
    ruleset::{HeadlessRuleSpec, SourceRuleSetFile},
};
use arc_swap::ArcSwap;
use kerlico_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
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

    /// 配置写明的下载地址；未写时为 `None`。
    pub fn configured_url(&self, file: GeoFile) -> Option<&str> {
        let urls = self.geox_url.as_ref();
        match file {
            GeoFile::GeoIp => self
                .geox_url_geoip
                .as_deref()
                .or_else(|| urls.and_then(|u| u.geoip.as_deref())),
            GeoFile::GeoSite => self
                .geox_url_geosite
                .as_deref()
                .or_else(|| urls.and_then(|u| u.geosite.as_deref())),
            GeoFile::Mmdb => self
                .geox_url_mmdb
                .as_deref()
                .or_else(|| urls.and_then(|u| u.mmdb.as_deref())),
            GeoFile::Asn => urls.and_then(|u| u.asn.as_deref()),
        }
        .map(str::trim)
        .filter(|u| !u.is_empty())
    }
}

/// Geo 数据库文件；默认缓存名与 Mihomo 工作目录下的文件名一致。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum GeoFile {
    GeoIp,
    GeoSite,
    Mmdb,
    Asn,
}

impl GeoFile {
    pub const ALL: [Self; 4] = [Self::GeoIp, Self::GeoSite, Self::Mmdb, Self::Asn];

    pub fn name(self) -> &'static str {
        match self {
            Self::GeoIp => "geoip",
            Self::GeoSite => "geosite",
            Self::Mmdb => "mmdb",
            Self::Asn => "asn",
        }
    }

    pub fn default_path(self) -> PathBuf {
        PathBuf::from(match self {
            Self::GeoIp => "GeoIP.dat",
            Self::GeoSite => "GeoSite.dat",
            Self::Mmdb => "Country.mmdb",
            Self::Asn => "ASN.mmdb",
        })
    }

    /// 同一文件的旧缓存名，按优先级排在 [`Self::default_path`] 之后。
    fn legacy_names(self) -> &'static [&'static str] {
        match self {
            Self::Asn => &["GeoLite2-ASN.mmdb"],
            _ => &[],
        }
    }

    /// `dir` 中实际使用的缓存文件名，文件名比较不区分大小写（同 Mihomo `C.Path.ASN()`）；
    /// 都不存在时返回 [`Self::default_path`]，下载写入该名。
    pub fn cache_name_in(self, dir: &std::path::Path) -> PathBuf {
        let present: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| !t.is_dir()))
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        let wanted = self.default_path();
        let wanted = wanted.to_str().into_iter();
        wanted
            .chain(self.legacy_names().iter().copied())
            .find_map(|name| present.iter().find(|p| p.eq_ignore_ascii_case(name)))
            .map_or_else(|| self.default_path(), PathBuf::from)
    }

    /// 工作目录下的缓存路径，见 [`Self::cache_name_in`]。
    pub fn cache_path(self) -> PathBuf {
        self.cache_name_in(std::path::Path::new("."))
    }

    /// Mihomo 的默认 `geox-url`。
    pub fn default_url(self) -> &'static str {
        match self {
            Self::GeoIp => {
                "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"
            }
            Self::GeoSite => {
                "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
            }
            Self::Mmdb => {
                "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"
            }
            Self::Asn => {
                "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
            }
        }
    }
}

/// GEOIP 规则的数据来源，对应 Mihomo `geodata-mode`。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GeoIpMode {
    #[default]
    Mmdb,
    Dat,
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

/// `GEOSITE` 取值：`[!]list[@attr...]`。`!` 前缀取反（同 Mihomo）；属性须全部具备，
/// `@!attr` 表示不具备该属性（kerlico 扩展，Mihomo 把 `!attr` 当作属性名）。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GeoSiteRef {
    pub negate: bool,
    pub list: String,
    pub attrs: Vec<(bool, String)>,
    key: String,
}

impl GeoSiteRef {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let (negate, rest) = match raw.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        let mut parts = rest.split('@');
        let list = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        if list.is_empty() {
            return Err(Error::Config(format!("GEOSITE 分类为空：{raw}")));
        }
        let mut attrs: Vec<(bool, String)> = parts
            .map(|a| a.trim().to_ascii_lowercase())
            .filter(|a| !a.is_empty())
            .map(|a| match a.strip_prefix('!') {
                Some(name) => (true, name.to_owned()),
                None => (false, a),
            })
            .collect();
        attrs.sort();
        attrs.dedup();
        let mut key = list.clone();
        for (neg, name) in &attrs {
            key.push('@');
            if *neg {
                key.push('!');
            }
            key.push_str(name);
        }
        Ok(Self {
            negate,
            list,
            attrs,
            key,
        })
    }

    /// 不含取反的数据键；同一分类与属性组合只构建一次。
    pub fn key(&self) -> &str {
        &self.key
    }

    fn admits(&self, item_attrs: &[String]) -> bool {
        self.attrs
            .iter()
            .all(|(neg, name)| item_attrs.iter().any(|a| a == name) != *neg)
    }
}

/// `GEOIP` 取值：`[!]code`。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GeoIpRef {
    pub negate: bool,
    pub code: String,
}

impl GeoIpRef {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let (negate, rest) = match raw.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        let code = rest.trim().to_ascii_lowercase();
        if code.is_empty() {
            return Err(Error::Config(format!("GEOIP 代码为空：{raw}")));
        }
        Ok(Self { negate, code })
    }

    fn is_lan(&self) -> bool {
        self.code == "lan"
    }
}

/// Mihomo `GEOIP,lan` 的内置判定（`rules/common/geoip.go` 的 `isLan`）：Go `netip` 的私有、
/// 未指定、回环、组播与链路本地单播地址；不含 CGNAT、198.18.0.0/15 与广播地址。
fn is_mihomo_lan(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xfe00) == 0xfc00
                || v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
        }
    }
}

/// 路由规则引用的 Geo 数据。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeoNeeds {
    pub sites: BTreeMap<String, GeoSiteRef>,
    pub ip_codes: BTreeSet<String>,
    pub asn: bool,
}

impl GeoNeeds {
    pub fn add_site(&mut self, site: &GeoSiteRef) {
        self.sites
            .entry(site.key.clone())
            .or_insert_with(|| GeoSiteRef {
                negate: false,
                ..site.clone()
            });
    }

    pub fn add_ip(&mut self, ip: &GeoIpRef) {
        if !ip.is_lan() {
            self.ip_codes.insert(ip.code.clone());
        }
    }

    /// 给定模式下需要加载的文件。
    pub fn requires(&self, file: GeoFile, mode: GeoIpMode) -> bool {
        match file {
            GeoFile::GeoSite => !self.sites.is_empty(),
            GeoFile::GeoIp => mode == GeoIpMode::Dat && !self.ip_codes.is_empty(),
            GeoFile::Mmdb => mode == GeoIpMode::Mmdb && !self.ip_codes.is_empty(),
            GeoFile::Asn => self.asn,
        }
    }
}

/// 一个文件解码后的内容，换入 [`GeoSlot`]。
#[derive(Clone, Debug)]
pub enum GeoPart {
    Sites(Arc<HashMap<String, DomainSet>>),
    Ips(Arc<HashMap<String, (IpSet, bool)>>),
    Country(Arc<Mmdb>),
    Asn(Arc<Mmdb>),
}

/// 当前生效的 Geo 数据；未加载的部分为空，相应规则不命中。
#[derive(Clone, Debug, Default)]
pub struct GeoData {
    mode: GeoIpMode,
    sites: Arc<HashMap<String, DomainSet>>,
    ips: Arc<HashMap<String, (IpSet, bool)>>,
    country: Option<Arc<Mmdb>>,
    asn: Option<Arc<Mmdb>>,
}

impl GeoData {
    pub fn site_matches(&self, site: &GeoSiteRef, host: &str) -> bool {
        self.sites
            .get(&site.key)
            .is_some_and(|set| set.matches(host) != site.negate)
    }

    pub fn ip_matches(&self, geoip: &GeoIpRef, ip: IpAddr) -> bool {
        if geoip.is_lan() {
            return is_mihomo_lan(ip) != geoip.negate;
        }
        let hit = match self.mode {
            GeoIpMode::Dat => match self.ips.get(&geoip.code) {
                Some((set, reverse)) => set.contains(ip) != *reverse,
                None => return false,
            },
            GeoIpMode::Mmdb => match &self.country {
                Some(db) => db
                    .country_codes(ip)
                    .is_ok_and(|codes| codes.contains(&geoip.code)),
                None => return false,
            },
        };
        hit != geoip.negate
    }

    pub fn asn_matches(&self, asn: u32, ip: IpAddr) -> bool {
        self.asn
            .as_ref()
            .is_some_and(|db| db.asn(ip).ok().flatten().is_some_and(|(n, _)| n == asn))
    }

    /// 已加载数据占用的堆内存估计（字节）。
    pub fn heap_bytes(&self) -> usize {
        self.sites
            .values()
            .map(DomainSet::heap_bytes)
            .sum::<usize>()
            + self
                .ips
                .values()
                .map(|(s, _)| s.heap_bytes())
                .sum::<usize>()
            + self.country.as_ref().map_or(0, |d| d.heap_bytes())
            + self.asn.as_ref().map_or(0, |d| d.heap_bytes())
    }
}

struct GeoShared {
    mode: GeoIpMode,
    needs: GeoNeeds,
    data: ArcSwap<GeoData>,
}

/// 运行中 Geo 数据的替换点；路由表的各个克隆共享同一槽。
#[derive(Clone)]
pub struct GeoSlot(Arc<GeoShared>);

impl std::fmt::Debug for GeoSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoSlot")
            .field("mode", &self.0.mode)
            .field("needs", &self.0.needs)
            .finish()
    }
}

impl Default for GeoSlot {
    fn default() -> Self {
        Self::new(GeoIpMode::Mmdb, GeoNeeds::default())
    }
}

impl GeoSlot {
    pub fn new(mode: GeoIpMode, needs: GeoNeeds) -> Self {
        Self(Arc::new(GeoShared {
            mode,
            needs,
            data: ArcSwap::from_pointee(GeoData {
                mode,
                ..GeoData::default()
            }),
        }))
    }

    pub fn mode(&self) -> GeoIpMode {
        self.0.mode
    }

    pub fn needs(&self) -> &GeoNeeds {
        &self.0.needs
    }

    pub fn requires(&self, file: GeoFile) -> bool {
        self.0.needs.requires(file, self.0.mode)
    }

    pub fn load(&self) -> Arc<GeoData> {
        self.0.data.load_full()
    }

    /// 解码文件中路由规则引用的部分；引用的分类缺失时返回错误。
    pub fn compile(&self, file: GeoFile, bytes: &[u8]) -> Result<GeoPart> {
        let needs = &self.0.needs;
        match file {
            GeoFile::GeoSite => {
                let refs: Vec<&GeoSiteRef> = needs.sites.values().collect();
                Ok(GeoPart::Sites(Arc::new(compile_sites(bytes, &refs)?)))
            }
            GeoFile::GeoIp => {
                let codes: Vec<&str> = needs.ip_codes.iter().map(String::as_str).collect();
                Ok(GeoPart::Ips(Arc::new(compile_ips(bytes, &codes)?)))
            }
            GeoFile::Mmdb => Ok(GeoPart::Country(Arc::new(Mmdb::parse(bytes.to_vec())?))),
            GeoFile::Asn => {
                let db = Mmdb::parse(bytes.to_vec())?;
                db.check_asn()?;
                Ok(GeoPart::Asn(Arc::new(db)))
            }
        }
    }

    pub fn install(&self, part: GeoPart) {
        let mut data = GeoData::clone(&self.0.data.load());
        match part {
            GeoPart::Sites(sites) => data.sites = sites,
            GeoPart::Ips(ips) => data.ips = ips,
            GeoPart::Country(db) => data.country = Some(db),
            GeoPart::Asn(db) => data.asn = Some(db),
        }
        self.0.data.store(Arc::new(data));
    }
}

/// `geosite.dat` 一个条目里的域名与属性名。
#[derive(Clone, Debug)]
pub struct SiteItem {
    pub rule: DomainRule,
    pub attrs: Vec<String>,
}

/// 遍历 `GeoSiteList`/`GeoIPList` 的顶层条目，只读出代码（小写）与原始字节。
pub fn dat_entries(mut bytes: &[u8]) -> Result<Vec<(String, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (tag, wire, rest) = read_pb_key(bytes)?;
        bytes = rest;
        if tag == 1 && wire == 2 {
            let (msg, rest) = read_pb_bytes(bytes)?;
            bytes = rest;
            out.push((entry_code(msg)?, msg));
        } else {
            bytes = skip_pb_field(bytes, wire)?;
        }
    }
    Ok(out)
}

fn entry_code(mut msg: &[u8]) -> Result<String> {
    while !msg.is_empty() {
        let (tag, wire, rest) = read_pb_key(msg)?;
        msg = rest;
        if tag == 1 && wire == 2 {
            let (s, _) = read_pb_bytes(msg)?;
            return Ok(String::from_utf8_lossy(s).trim().to_ascii_lowercase());
        }
        msg = skip_pb_field(msg, wire)?;
    }
    Ok(String::new())
}

/// 解码一个 `GeoSite` 条目的全部域名。
pub fn site_items(mut msg: &[u8]) -> Result<Vec<SiteItem>> {
    let mut items = Vec::new();
    while !msg.is_empty() {
        let (tag, wire, rest) = read_pb_key(msg)?;
        msg = rest;
        if tag == 2 && wire == 2 {
            let (domain, rest) = read_pb_bytes(msg)?;
            msg = rest;
            if let Some(item) = parse_pb_domain(domain)? {
                items.push(item);
            }
        } else {
            msg = skip_pb_field(msg, wire)?;
        }
    }
    Ok(items)
}

fn parse_pb_domain(mut msg: &[u8]) -> Result<Option<SiteItem>> {
    let mut kind = 0u64;
    let mut value = String::new();
    let mut attrs = Vec::new();
    while !msg.is_empty() {
        let (tag, wire, rest) = read_pb_key(msg)?;
        msg = rest;
        match (tag, wire) {
            (1, 0) => {
                let (v, rest) = read_pb_varint(msg)?;
                msg = rest;
                kind = v;
            }
            (2, 2) => {
                let (s, rest) = read_pb_bytes(msg)?;
                msg = rest;
                value = String::from_utf8_lossy(s).trim().to_owned();
            }
            (3, 2) => {
                let (attr, rest) = read_pb_bytes(msg)?;
                msg = rest;
                if let Some(key) = parse_pb_attr_key(attr)? {
                    attrs.push(key);
                }
            }
            _ => msg = skip_pb_field(msg, wire)?,
        }
    }
    if value.is_empty() {
        return Ok(None);
    }
    let rule = match kind {
        0 => DomainRule::Keyword(value.to_ascii_lowercase()),
        1 => DomainRule::Regex(value),
        2 => DomainRule::Suffix(value.to_ascii_lowercase()),
        3 => DomainRule::Full(value.to_ascii_lowercase()),
        other => {
            return Err(Error::Config(format!("geosite.dat 域名类型 {other} 未知")));
        }
    };
    Ok(Some(SiteItem { rule, attrs }))
}

fn parse_pb_attr_key(mut msg: &[u8]) -> Result<Option<String>> {
    while !msg.is_empty() {
        let (tag, wire, rest) = read_pb_key(msg)?;
        msg = rest;
        if tag == 1 && wire == 2 {
            let (s, _) = read_pb_bytes(msg)?;
            return Ok(Some(String::from_utf8_lossy(s).trim().to_ascii_lowercase()));
        }
        msg = skip_pb_field(msg, wire)?;
    }
    Ok(None)
}

/// 解码一个 `GeoIP` 条目：网段与 `reverse_match`。
pub fn ip_entry(mut msg: &[u8]) -> Result<(IpSet, bool)> {
    let mut builder = IpSetBuilder::default();
    let mut reverse = false;
    while !msg.is_empty() {
        let (tag, wire, rest) = read_pb_key(msg)?;
        msg = rest;
        match (tag, wire) {
            (2, 2) => {
                let (cidr, rest) = read_pb_bytes(msg)?;
                msg = rest;
                let (addr, len) = parse_pb_cidr(cidr)?;
                builder.add_prefix(addr, len);
            }
            (3, 0) => {
                let (v, rest) = read_pb_varint(msg)?;
                msg = rest;
                reverse = v != 0;
            }
            _ => msg = skip_pb_field(msg, wire)?,
        }
    }
    Ok((builder.build(), reverse))
}

fn parse_pb_cidr(mut msg: &[u8]) -> Result<(IpAddr, u8)> {
    let mut ip: &[u8] = &[];
    let mut prefix = 0u64;
    while !msg.is_empty() {
        let (tag, wire, rest) = read_pb_key(msg)?;
        msg = rest;
        match (tag, wire) {
            (1, 2) => {
                let (b, rest) = read_pb_bytes(msg)?;
                msg = rest;
                ip = b;
            }
            (2, 0) => {
                let (v, rest) = read_pb_varint(msg)?;
                msg = rest;
                prefix = v;
            }
            _ => msg = skip_pb_field(msg, wire)?,
        }
    }
    let invalid = || Error::Config("geoip.dat 网段不合法".into());
    let addr = match ip.len() {
        4 => IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(ip).map_err(|_| invalid())?,
        )),
        _ => return Err(invalid()),
    };
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let len = u8::try_from(prefix)
        .ok()
        .filter(|&p| p <= max)
        .ok_or_else(invalid)?;
    Ok((addr, len))
}

/// 未引用任何分类时只检查文件能解码且非空。
fn dat_has_entries(bytes: &[u8]) -> Result<()> {
    if dat_entries(bytes)?.is_empty() {
        return Err(Error::Config("dat 文件没有任何分类".into()));
    }
    Ok(())
}

/// 按引用构建各分类的域名集合；条目重复出现的分类合并。
pub fn compile_sites(bytes: &[u8], refs: &[&GeoSiteRef]) -> Result<HashMap<String, DomainSet>> {
    if refs.is_empty() {
        return dat_has_entries(bytes).map(|()| HashMap::new());
    }
    let wanted: BTreeSet<&str> = refs.iter().map(|r| r.list.as_str()).collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut builders: Vec<(&GeoSiteRef, DomainSetBuilder)> = refs
        .iter()
        .map(|&r| (r, DomainSetBuilder::default()))
        .collect();
    let mut rest_bytes = bytes;
    while !rest_bytes.is_empty() {
        let (tag, wire, next) = read_pb_key(rest_bytes)?;
        rest_bytes = next;
        if tag == 1 && wire == 2 {
            let (msg, next) = read_pb_bytes(rest_bytes)?;
            rest_bytes = next;
            let code = entry_code(msg)?;
            if wanted.contains(code.as_str()) {
                seen.insert(code.clone());
                let mut m = msg;
                while !m.is_empty() {
                    let (t, w, n) = read_pb_key(m)?;
                    m = n;
                    if t == 2 && w == 2 {
                        let (domain, n) = read_pb_bytes(m)?;
                        m = n;
                        if let Some(item) = parse_pb_domain(domain)? {
                            for (r, builder) in &mut builders {
                                if r.list == code && r.admits(&item.attrs) {
                                    builder.insert(item.rule.clone());
                                }
                            }
                        }
                    } else {
                        m = skip_pb_field(m, w)?;
                    }
                }
            }
        } else {
            rest_bytes = skip_pb_field(rest_bytes, wire)?;
        }
    }
    let mut out = HashMap::with_capacity(refs.len());
    for (r, builder) in builders {
        if !seen.contains(&r.list) {
            return Err(Error::Config(format!("geosite.dat 中没有分类 {}", r.list)));
        }
        out.insert(r.key.clone(), builder.build()?);
    }
    Ok(out)
}

pub fn compile_ips(bytes: &[u8], codes: &[&str]) -> Result<HashMap<String, (IpSet, bool)>> {
    if codes.is_empty() {
        return dat_has_entries(bytes).map(|()| HashMap::new());
    }
    let mut out: HashMap<String, (IpSet, bool)> = HashMap::new();
    for (code, msg) in dat_entries(bytes)? {
        if codes.contains(&code.as_str()) {
            let (set, reverse) = ip_entry(msg)?;
            let entry = out.entry(code).or_default();
            let mut merged = IpSetBuilder::default();
            merged.extend(&entry.0);
            merged.extend(&set);
            *entry = (merged.build(), entry.1 || reverse);
        }
    }
    for code in codes {
        if !out.contains_key(*code) {
            return Err(Error::Config(format!("geoip.dat 中没有代码 {code}")));
        }
    }
    Ok(out)
}

/// 文件内容是否为 mmdb（按元数据标记判断）。
pub fn is_mmdb(bytes: &[u8]) -> bool {
    bytes
        .windows(14)
        .rev()
        .take(128 * 1024)
        .any(|w| w == b"\xAB\xCD\xEFMaxMind.com")
}

/// 把一个 GeoSite 分类导出为 sing-box 源格式规则集。
pub fn export_geosite_ruleset(bytes: &[u8], spec: &str) -> Result<SourceRuleSetFile> {
    let site = GeoSiteRef::parse(spec)?;
    if site.negate {
        return Err(Error::Config("取反的 GEOSITE 分类不能导出".into()));
    }
    let sets = compile_sites(bytes, &[&site])?;
    let set = &sets[&site.key];
    Ok(SourceRuleSetFile {
        version: 2,
        rules: vec![rules_to_headless(set.rules())],
    })
}

/// 域名条目转为一条无头规则：后缀写 `d`，仅子域写 `.d`。
pub fn rules_to_headless(rules: Vec<DomainRule>) -> HeadlessRuleSpec {
    let mut spec = HeadlessRuleSpec::default();
    for rule in rules {
        match rule {
            DomainRule::Full(d) => spec.domain.push(d),
            DomainRule::Suffix(d) => spec.domain_suffix.push(d),
            DomainRule::Subdomain(d) => spec.domain_suffix.push(format!(".{d}")),
            DomainRule::Keyword(k) => spec.domain_keyword.push(k),
            DomainRule::Regex(r) => spec.domain_regex.push(r),
        }
    }
    spec
}

pub fn export_geoip_ruleset(bytes: &[u8], code: &str) -> Result<SourceRuleSetFile> {
    if is_mmdb(bytes) {
        return Err(Error::Config("导出仅支持 geoip.dat".into()));
    }
    let code = code.trim().to_ascii_lowercase();
    let ips = compile_ips(bytes, &[code.as_str()])?;
    let (set, reverse) = &ips[&code];
    if *reverse {
        return Err(Error::Config("reverse_match 分类不能导出".into()));
    }
    Ok(SourceRuleSetFile {
        version: 2,
        rules: vec![HeadlessRuleSpec {
            ip_cidr: set.prefixes(),
            ..Default::default()
        }],
    })
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

/// 测试用：按 V2Ray ProtoBuf 线格式写 `geosite.dat` 与 `geoip.dat`。
pub mod fixture {
    fn varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn field_bytes(out: &mut Vec<u8>, tag: u64, bytes: &[u8]) {
        varint(out, (tag << 3) | 2);
        varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    fn field_varint(out: &mut Vec<u8>, tag: u64, v: u64) {
        varint(out, tag << 3);
        varint(out, v);
    }

    /// 一个域名条目：类型（0 plain、1 regex、2 domain、3 full）、值与属性。
    pub type Domain<'a> = (u64, &'a str, &'a [&'a str]);

    /// `lists`：(代码, 域名条目)。
    pub fn geosite(lists: &[(&str, &[Domain<'_>])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (code, domains) in lists {
            let mut site = Vec::new();
            field_bytes(&mut site, 1, code.to_ascii_uppercase().as_bytes());
            for (kind, value, attrs) in *domains {
                let mut d = Vec::new();
                field_varint(&mut d, 1, *kind);
                field_bytes(&mut d, 2, value.as_bytes());
                for attr in *attrs {
                    let mut a = Vec::new();
                    field_bytes(&mut a, 1, attr.as_bytes());
                    field_varint(&mut a, 2, 1);
                    field_bytes(&mut d, 3, &a);
                }
                field_bytes(&mut site, 2, &d);
            }
            field_bytes(&mut out, 1, &site);
        }
        out
    }

    /// `lists`：(代码, [CIDR])。
    pub fn geoip(lists: &[(&str, &[&str])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (code, cidrs) in lists {
            let mut entry = Vec::new();
            field_bytes(&mut entry, 1, code.to_ascii_uppercase().as_bytes());
            for cidr in *cidrs {
                let (addr, len) = crate::ip_set::parse_prefix(cidr).expect("fixture CIDR");
                let ip = match addr {
                    std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                    std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                };
                let mut c = Vec::new();
                field_bytes(&mut c, 1, &ip);
                field_varint(&mut c, 2, u64::from(len));
                field_bytes(&mut entry, 2, &c);
            }
            field_bytes(&mut out, 1, &entry);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site_fixture() -> Vec<u8> {
        fixture::geosite(&[
            (
                "cn",
                &[
                    (2, "baidu.com", &["cn"]),
                    (3, "full.example", &[]),
                    (0, "keyword", &[]),
                    (1, r"^re\d+\.example$", &[]),
                    (2, "global.example", &["ads"]),
                ],
            ),
            (
                "google",
                &[(2, "google.com", &[]), (2, "google.cn", &["cn"])],
            ),
        ])
    }

    fn needs(sites: &[&str], ips: &[&str], asn: bool) -> GeoNeeds {
        let mut needs = GeoNeeds {
            asn,
            ..GeoNeeds::default()
        };
        for s in sites {
            needs.add_site(&GeoSiteRef::parse(s).unwrap());
        }
        for i in ips {
            needs.add_ip(&GeoIpRef::parse(i).unwrap());
        }
        needs
    }

    #[test]
    fn geosite_types_attributes_and_negation_match_mihomo_semantics() {
        let slot = GeoSlot::new(
            GeoIpMode::Mmdb,
            needs(&["cn", "google@cn", "google@!cn", "!cn"], &[], false),
        );
        slot.install(slot.compile(GeoFile::GeoSite, &site_fixture()).unwrap());
        let data = slot.load();
        let m = |spec: &str, host: &str| data.site_matches(&GeoSiteRef::parse(spec).unwrap(), host);
        assert!(m("cn", "baidu.com"));
        assert!(m("cn", "www.baidu.com"));
        assert!(!m("cn", "notbaidu.com"));
        assert!(m("cn", "full.example"));
        assert!(!m("cn", "a.full.example"));
        assert!(m("cn", "haskeywordinside.net"));
        assert!(m("cn", "re42.example"));
        assert!(!m("cn", "re.example"));
        assert!(m("google@cn", "www.google.cn"));
        assert!(!m("google@cn", "www.google.com"));
        assert!(m("google@!cn", "www.google.com"));
        assert!(!m("google@!cn", "google.cn"));
        assert!(m("!cn", "github.com"));
        assert!(!m("!cn", "baidu.com"));
    }

    #[test]
    fn missing_geosite_list_or_geoip_code_is_an_error() {
        let slot = GeoSlot::new(GeoIpMode::Dat, needs(&["category-unknown"], &["zz"], false));
        let error = slot.compile(GeoFile::GeoSite, &site_fixture()).unwrap_err();
        assert!(error.to_string().contains("category-unknown"), "{error}");
        let dat = fixture::geoip(&[("cn", &["1.0.1.0/24"])]);
        let error = slot.compile(GeoFile::GeoIp, &dat).unwrap_err();
        assert!(error.to_string().contains("zz"), "{error}");
    }

    #[test]
    fn geoip_dat_mode_and_lan() {
        let slot = GeoSlot::new(GeoIpMode::Dat, needs(&[], &["cn", "!cn", "lan"], false));
        let dat = fixture::geoip(&[
            ("cn", &["1.0.1.0/24", "240e::/18"]),
            ("us", &["8.8.8.0/24"]),
        ]);
        slot.install(slot.compile(GeoFile::GeoIp, &dat).unwrap());
        let data = slot.load();
        let m = |code: &str, ip: &str| {
            data.ip_matches(&GeoIpRef::parse(code).unwrap(), ip.parse().unwrap())
        };
        assert!(m("cn", "1.0.1.9"));
        assert!(m("cn", "240e:1::1"));
        assert!(!m("cn", "8.8.8.8"));
        assert!(m("!cn", "8.8.8.8"));
        assert!(m("lan", "192.168.1.1"));
        assert!(!m("us", "8.8.8.8"), "未被引用的代码不加载");
    }

    #[test]
    fn private_is_a_data_code_and_lan_is_the_mihomo_builtin() {
        use crate::mmdb::writer::{self, Value};
        let wanted = needs(&[], &["private", "lan"], false);
        assert!(wanted.ip_codes.contains("private") && !wanted.ip_codes.contains("lan"));
        let dat = GeoSlot::new(GeoIpMode::Dat, wanted.clone());
        let file = fixture::geoip(&[("private", &["10.0.0.0/8", "100.64.0.0/10"])]);
        dat.install(dat.compile(GeoFile::GeoIp, &file).unwrap());
        let meta = GeoSlot::new(GeoIpMode::Mmdb, wanted.clone());
        let file = writer::build(
            "Meta-geoip0",
            &[(
                "10.0.0.0/8",
                Value::Array(vec![Value::Str("private".into())]),
            )],
        );
        meta.install(meta.compile(GeoFile::Mmdb, &file).unwrap());
        let plain = GeoSlot::new(GeoIpMode::Mmdb, wanted);
        let file = writer::build("sing-geoip", &[("1.0.1.0/24", Value::Str("cn".into()))]);
        plain.install(plain.compile(GeoFile::Mmdb, &file).unwrap());
        let m = |slot: &GeoSlot, code: &str, ip: &str| {
            slot.load()
                .ip_matches(&GeoIpRef::parse(code).unwrap(), ip.parse().unwrap())
        };
        assert!(
            m(&dat, "private", "100.64.0.1"),
            "geoip.dat 的 private 列表"
        );
        assert!(!m(&dat, "private", "192.168.1.1"));
        assert!(
            m(&meta, "private", "10.1.2.3"),
            "mmdb 记录里的 private 代码"
        );
        assert!(
            !m(&plain, "private", "10.1.2.3"),
            "mmdb 没有 private 代码时不命中"
        );
        for slot in [&dat, &meta, &plain] {
            for ip in [
                "10.0.0.1",
                "192.168.1.1",
                "127.0.0.1",
                "169.254.1.1",
                "224.0.0.1",
            ] {
                assert!(m(slot, "lan", ip), "lan {ip}");
            }
            for ip in ["fd00::1", "fe80::1", "::1", "ff02::1", "0.0.0.0"] {
                assert!(m(slot, "lan", ip), "lan {ip}");
            }
            for ip in ["100.64.0.1", "198.18.0.1", "255.255.255.255", "8.8.8.8"] {
                assert!(!m(slot, "lan", ip), "非 lan {ip}");
            }
        }
    }

    #[test]
    fn mmdb_mode_reads_country_database() {
        use crate::mmdb::writer::{self, Value};
        let slot = GeoSlot::new(GeoIpMode::Mmdb, needs(&[], &["cn"], true));
        let country = writer::build("sing-geoip", &[("1.0.1.0/24", Value::Str("cn".into()))]);
        slot.install(slot.compile(GeoFile::Mmdb, &country).unwrap());
        let asn = writer::build(
            "GeoLite2-ASN",
            &[(
                "1.0.1.0/24",
                Value::Map(vec![("autonomous_system_number".into(), Value::U32(4134))]),
            )],
        );
        slot.install(slot.compile(GeoFile::Asn, &asn).unwrap());
        let data = slot.load();
        assert!(data.ip_matches(&GeoIpRef::parse("CN").unwrap(), "1.0.1.1".parse().unwrap()));
        assert!(!data.ip_matches(&GeoIpRef::parse("cn").unwrap(), "1.0.2.1".parse().unwrap()));
        assert!(data.asn_matches(4134, "1.0.1.1".parse().unwrap()));
        assert!(!data.asn_matches(4135, "1.0.1.1".parse().unwrap()));
        assert!(slot.compile(GeoFile::Asn, &country).is_err());
    }

    #[test]
    fn asn_cache_prefers_mihomo_name_then_legacy_name() {
        let dir = std::env::temp_dir().join(format!("kerlico-asn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(GeoFile::Asn.cache_name_in(&dir), PathBuf::from("ASN.mmdb"));
        std::fs::write(dir.join("GeoLite2-ASN.mmdb"), b"x").unwrap();
        assert_eq!(
            GeoFile::Asn.cache_name_in(&dir),
            PathBuf::from("GeoLite2-ASN.mmdb")
        );
        std::fs::write(dir.join("asn.MMDB"), b"x").unwrap();
        assert_eq!(GeoFile::Asn.cache_name_in(&dir), PathBuf::from("asn.MMDB"));
        assert_eq!(
            GeoFile::Mmdb.cache_name_in(&dir),
            PathBuf::from("Country.mmdb")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
