//! sing-box 二进制规则集（`.srs`，版本 1–5）编解码，对应上游 `common/srs`。
//!
//! 文件为 `SRS` + 版本字节 + zlib 压缩体；压缩体是 uvarint 规则数后接各规则。默认规则是
//! 一串「项类型 + 值」，以 `0xFF` 与 invert 字节结束；逻辑规则为模式字节、子规则与 invert。

use crate::{
    ip_set::{IpSet, IpSetBuilder},
    ruleset::{DnsQueryType, HeadlessRuleSpec, SourceRuleSetFile, StringOrVec},
    succinct::{Succinct, reverse, unreverse},
};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use kerlico_core::{Error, Result};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const MAGIC: &[u8; 3] = b"SRS";
pub const MAX_VERSION: u8 = 5;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xFF;

/// sing-box 域名匹配器键内的前缀标记：`\r` 表示仅子域，`\n` 表示域名本身及子域。
const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

const MAX_DEPTH: usize = 100;

const INTERFACE_TYPES: [&str; 4] = ["wifi", "cellular", "ethernet", "other"];

fn malformed(what: &str) -> Error {
    Error::Config(format!("sing-box 二进制规则集损坏：{what}"))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| malformed("数据截断"))?;
        self.pos += 1;
        Ok(b)
    }

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

    fn uvarint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(malformed("uvarint 溢出"))
    }

    fn len(&mut self) -> Result<usize> {
        let n = usize::try_from(self.uvarint()?).map_err(|_| malformed("长度溢出"))?;
        if n > self.buf.len() - self.pos {
            return Err(malformed("长度超出数据"));
        }
        Ok(n)
    }

    fn u64_be(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap_or_default()))
    }

    fn strings(&mut self) -> Result<Vec<String>> {
        let count = self.len()?;
        (0..count)
            .map(|_| {
                let n = self.len()?;
                String::from_utf8(self.take(n)?.to_vec()).map_err(|_| malformed("字符串不是 UTF-8"))
            })
            .collect()
    }

    fn u16s(&mut self) -> Result<Vec<u16>> {
        let count = self.len()?;
        (0..count)
            .map(|_| {
                let b = self.take(2)?;
                Ok(u16::from_be_bytes([b[0], b[1]]))
            })
            .collect()
    }

    fn u64s(&mut self) -> Result<Vec<u64>> {
        let count = self.len()?;
        (0..count).map(|_| self.u64_be()).collect()
    }
}

pub fn read(bytes: &[u8]) -> Result<SourceRuleSetFile> {
    if bytes.len() < 4 || &bytes[..3] != MAGIC {
        return Err(Error::Config("不是 sing-box 二进制规则集".into()));
    }
    let version = bytes[3];
    if version == 0 || version > MAX_VERSION {
        return Err(Error::Config(format!(
            "sing-box 二进制规则集版本 {version} 不受支持"
        )));
    }
    let mut body = Vec::new();
    ZlibDecoder::new(&bytes[4..])
        .read_to_end(&mut body)
        .map_err(|_| malformed("zlib 解压失败"))?;
    let mut reader = Reader { buf: &body, pos: 0 };
    let count = reader.len()?;
    let rules = (0..count)
        .map(|_| read_rule(&mut reader, 0))
        .collect::<Result<_>>()?;
    Ok(SourceRuleSetFile { version, rules })
}

fn read_rule(r: &mut Reader<'_>, depth: usize) -> Result<HeadlessRuleSpec> {
    if depth > MAX_DEPTH {
        return Err(malformed("逻辑规则嵌套过深"));
    }
    match r.u8()? {
        0 => read_default_rule(r),
        1 => {
            let mode = match r.u8()? {
                0 => "and",
                1 => "or",
                _ => return Err(malformed("未知逻辑模式")),
            };
            let count = r.len()?;
            let rules = (0..count)
                .map(|_| read_rule(r, depth + 1))
                .collect::<Result<_>>()?;
            let invert = r.u8()? != 0;
            Ok(HeadlessRuleSpec {
                logical_type: Some("logical".into()),
                logical_mode: Some(mode.into()),
                logical_rules: rules,
                invert,
                ..Default::default()
            })
        }
        other => Err(malformed(&format!("未知规则类型 {other}"))),
    }
}

fn read_default_rule(r: &mut Reader<'_>) -> Result<HeadlessRuleSpec> {
    let mut rule = HeadlessRuleSpec::default();
    loop {
        match r.u8()? {
            ITEM_QUERY_TYPE => {
                rule.query_type = r.u16s()?.into_iter().map(DnsQueryType::Code).collect();
            }
            ITEM_NETWORK => rule.network = StringOrVec::List(r.strings()?),
            ITEM_DOMAIN => {
                let (domain, suffix) = read_domain_matcher(r)?;
                rule.domain.extend(domain);
                rule.domain_suffix.extend(suffix);
            }
            ITEM_DOMAIN_KEYWORD => rule.domain_keyword = r.strings()?,
            ITEM_DOMAIN_REGEX => rule.domain_regex = r.strings()?,
            ITEM_SOURCE_IP_CIDR => rule.source_ip_cidr = read_ip_set(r)?.prefixes(),
            ITEM_IP_CIDR => rule.ip_cidr = read_ip_set(r)?.prefixes(),
            ITEM_SOURCE_PORT => rule.source_port = r.u16s()?,
            ITEM_SOURCE_PORT_RANGE => rule.source_port_range = r.strings()?,
            ITEM_PORT => rule.port = r.u16s()?,
            ITEM_PORT_RANGE => rule.port_range = r.strings()?,
            ITEM_PROCESS_NAME => rule.process_name = r.strings()?,
            ITEM_PROCESS_PATH => rule.process_path = r.strings()?,
            ITEM_PROCESS_PATH_REGEX => rule.process_path_regex = r.strings()?,
            ITEM_PACKAGE_NAME => rule.package_name = r.strings()?,
            ITEM_PACKAGE_NAME_REGEX => rule.package_name_regex = r.strings()?,
            ITEM_WIFI_SSID => rule.wifi_ssid = r.strings()?,
            ITEM_WIFI_BSSID => rule.wifi_bssid = r.strings()?,
            ITEM_NETWORK_TYPE => {
                let count = r.len()?;
                rule.network_type = r
                    .take(count)?
                    .iter()
                    .map(|&t| {
                        INTERFACE_TYPES
                            .get(usize::from(t))
                            .map(|s| (*s).to_owned())
                            .ok_or_else(|| malformed("未知网络类型"))
                    })
                    .collect::<Result<_>>()?;
            }
            ITEM_NETWORK_IS_EXPENSIVE => rule.network_is_expensive = true,
            ITEM_NETWORK_IS_CONSTRAINED => rule.network_is_constrained = true,
            ITEM_ADGUARD_DOMAIN => {
                return Err(Error::Unsupported(
                    "sing-box 规则集的 AdGuard 域名项尚未支持",
                ));
            }
            ITEM_NETWORK_INTERFACE_ADDRESS | ITEM_DEFAULT_INTERFACE_ADDRESS => {
                return Err(Error::Unsupported(
                    "sing-box 规则集的 network_interface_address 与 default_interface_address 尚未支持",
                ));
            }
            ITEM_FINAL => {
                rule.invert = r.u8()? != 0;
                return Ok(rule);
            }
            other => return Err(malformed(&format!("未知规则项 {other}"))),
        }
    }
}

/// 按上游 `Matcher.Dump` 还原：`\n` 前缀与「完整 + `\r.` 前缀」都还原为不带点的后缀。
fn read_domain_matcher(r: &mut Reader<'_>) -> Result<(Vec<String>, Vec<String>)> {
    let _reserved = r.u8()?;
    let leaves = r.u64s()?;
    let label_bitmap = r.u64s()?;
    let n = r.len()?;
    let labels = r.take(n)?.to_vec();
    let set = Succinct {
        leaves,
        label_bitmap,
        labels,
    };
    let mut full = std::collections::BTreeSet::new();
    let mut sub = std::collections::BTreeSet::new();
    let mut suffix = Vec::new();
    for key in set.keys()? {
        let key = unreverse(&key)?;
        match key.as_bytes().first() {
            Some(&PREFIX_LABEL) => {
                sub.insert(key[1..].to_owned());
            }
            Some(&ROOT_LABEL) => suffix.push(key[1..].to_owned()),
            Some(_) => {
                full.insert(key);
            }
            None => {}
        }
    }
    for raw in sub {
        if let Some(root) = raw.strip_prefix('.')
            && full.remove(root)
        {
            suffix.push(root.to_owned());
        } else {
            suffix.push(raw);
        }
    }
    suffix.sort();
    Ok((full.into_iter().collect(), suffix))
}

fn read_ip_set(r: &mut Reader<'_>) -> Result<IpSet> {
    if r.u8()? != 1 {
        return Err(malformed("IP 集合版本"));
    }
    let count = usize::try_from(r.u64_be()?).map_err(|_| malformed("IP 集合长度"))?;
    let mut builder = IpSetBuilder::default();
    for _ in 0..count {
        let from = read_addr(r)?;
        let to = read_addr(r)?;
        builder
            .add_range(from, to)
            .map_err(|_| malformed("IP 区间"))?;
    }
    Ok(builder.build())
}

fn read_addr(r: &mut Reader<'_>) -> Result<IpAddr> {
    let n = r.len()?;
    let b = r.take(n)?;
    match n {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        16 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(b).unwrap_or_default(),
        ))),
        _ => Err(malformed("IP 地址长度")),
    }
}

/// 写出 `version` 版本的二进制规则集；kerlico 扩展字段（`domain_wildcard`、
/// `process_name_regex`）在 sing-box 格式中没有对应项，遇到时返回错误。
pub fn write(file: &SourceRuleSetFile) -> Result<Vec<u8>> {
    let version = file.version;
    if version == 0 || version > MAX_VERSION {
        return Err(Error::Config(format!(
            "sing-box 二进制规则集版本 {version} 不受支持"
        )));
    }
    let mut body = Vec::new();
    put_uvarint(&mut body, file.rules.len() as u64);
    for rule in &file.rules {
        write_rule(&mut body, rule, version)?;
    }
    let mut out = MAGIC.to_vec();
    out.push(version);
    let mut encoder = ZlibEncoder::new(out, Compression::best());
    encoder
        .write_all(&body)
        .map_err(|_| Error::Config("zlib 压缩失败".into()))?;
    encoder
        .finish()
        .map_err(|_| Error::Config("zlib 压缩失败".into()))
}

fn put_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_strings(out: &mut Vec<u8>, item: u8, values: &[String]) {
    if values.is_empty() {
        return;
    }
    out.push(item);
    put_uvarint(out, values.len() as u64);
    for s in values {
        put_uvarint(out, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
    }
}

fn put_u16s(out: &mut Vec<u8>, item: u8, values: &[u16]) {
    if values.is_empty() {
        return;
    }
    out.push(item);
    put_uvarint(out, values.len() as u64);
    for v in values {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

fn need_version(version: u8, min: u8, field: &str) -> Result<()> {
    if version < min {
        return Err(Error::Config(format!(
            "规则项 {field} 需要规则集版本 {min} 或更高"
        )));
    }
    Ok(())
}

fn write_rule(out: &mut Vec<u8>, rule: &HeadlessRuleSpec, version: u8) -> Result<()> {
    if rule.logical_type.is_some() {
        out.push(1);
        out.push(
            match rule
                .logical_mode
                .as_deref()
                .unwrap_or("and")
                .to_ascii_lowercase()
                .as_str()
            {
                "and" => 0,
                "or" => 1,
                _ => return Err(Error::Config("逻辑规则 mode 仅支持 and 或 or".into())),
            },
        );
        put_uvarint(out, rule.logical_rules.len() as u64);
        for child in &rule.logical_rules {
            write_rule(out, child, version)?;
        }
        out.push(u8::from(rule.invert));
        return Ok(());
    }
    if !rule.domain_wildcard.is_empty() || !rule.process_name_regex.is_empty() {
        return Err(Error::Config(
            "domain_wildcard 与 process_name_regex 没有 sing-box 二进制表示".into(),
        ));
    }
    out.push(0);
    let query: Vec<u16> = rule
        .query_type
        .iter()
        .map(DnsQueryType::code)
        .collect::<Result<_>>()?;
    put_u16s(out, ITEM_QUERY_TYPE, &query);
    put_strings(out, ITEM_NETWORK, &rule.network.as_vec());
    if !rule.domain.is_empty() || !rule.domain_suffix.is_empty() {
        out.push(ITEM_DOMAIN);
        write_domain_matcher(out, &rule.domain, &rule.domain_suffix, version == 1)?;
    }
    put_strings(out, ITEM_DOMAIN_KEYWORD, &rule.domain_keyword);
    put_strings(out, ITEM_DOMAIN_REGEX, &rule.domain_regex);
    if !rule.source_ip_cidr.is_empty() {
        out.push(ITEM_SOURCE_IP_CIDR);
        write_ip_set(
            out,
            &IpSet::from_cidrs(rule.source_ip_cidr.iter().map(String::as_str))?,
        );
    }
    if !rule.ip_cidr.is_empty() {
        out.push(ITEM_IP_CIDR);
        write_ip_set(
            out,
            &IpSet::from_cidrs(rule.ip_cidr.iter().map(String::as_str))?,
        );
    }
    put_u16s(out, ITEM_SOURCE_PORT, &rule.source_port);
    put_strings(out, ITEM_SOURCE_PORT_RANGE, &rule.source_port_range);
    put_u16s(out, ITEM_PORT, &rule.port);
    put_strings(out, ITEM_PORT_RANGE, &rule.port_range);
    put_strings(out, ITEM_PROCESS_NAME, &rule.process_name);
    put_strings(out, ITEM_PROCESS_PATH, &rule.process_path);
    put_strings(out, ITEM_PROCESS_PATH_REGEX, &rule.process_path_regex);
    put_strings(out, ITEM_PACKAGE_NAME, &rule.package_name);
    if !rule.package_name_regex.is_empty() {
        need_version(version, 5, "package_name_regex")?;
        put_strings(out, ITEM_PACKAGE_NAME_REGEX, &rule.package_name_regex);
    }
    if !rule.network_type.is_empty() {
        need_version(version, 3, "network_type")?;
        out.push(ITEM_NETWORK_TYPE);
        put_uvarint(out, rule.network_type.len() as u64);
        for t in &rule.network_type {
            let code = INTERFACE_TYPES
                .iter()
                .position(|known| known.eq_ignore_ascii_case(t))
                .ok_or_else(|| Error::Config(format!("未知网络类型：{t}")))?;
            out.push(u8::try_from(code).unwrap_or(3));
        }
    }
    if rule.network_is_expensive {
        need_version(version, 3, "network_is_expensive")?;
        out.push(ITEM_NETWORK_IS_EXPENSIVE);
    }
    if rule.network_is_constrained {
        need_version(version, 3, "network_is_constrained")?;
        out.push(ITEM_NETWORK_IS_CONSTRAINED);
    }
    put_strings(out, ITEM_WIFI_SSID, &rule.wifi_ssid);
    put_strings(out, ITEM_WIFI_BSSID, &rule.wifi_bssid);
    out.push(ITEM_FINAL);
    out.push(u8::from(rule.invert));
    Ok(())
}

/// 对应上游 `domain.NewMatcher`：版本 1 把后缀写成「完整 + `\r.` 前缀」两条键。
fn write_domain_matcher(
    out: &mut Vec<u8>,
    domains: &[String],
    suffixes: &[String],
    legacy: bool,
) -> Result<()> {
    let mut keys = Vec::with_capacity(domains.len() + suffixes.len() * 2);
    let mut seen = std::collections::HashSet::new();
    for suffix in suffixes {
        if suffix.is_empty() {
            return Err(Error::Config("domain_suffix 不能为空".into()));
        }
        if !seen.insert(suffix.clone()) {
            continue;
        }
        if suffix.starts_with('.') {
            keys.push(reverse(&format!("\r{suffix}")));
        } else if legacy {
            keys.push(reverse(suffix));
            let dotted = format!(".{suffix}");
            if seen.insert(dotted.clone()) {
                keys.push(reverse(&format!("\r{dotted}")));
            }
        } else {
            keys.push(reverse(&format!("\n{suffix}")));
        }
    }
    for domain in domains {
        if domain.is_empty() {
            return Err(Error::Config("domain 不能为空".into()));
        }
        if seen.insert(domain.clone()) {
            keys.push(reverse(domain));
        }
    }
    let set = Succinct::build(keys);
    out.push(0);
    put_uvarint(out, set.leaves.len() as u64);
    for w in &set.leaves {
        out.extend_from_slice(&w.to_be_bytes());
    }
    put_uvarint(out, set.label_bitmap.len() as u64);
    for w in &set.label_bitmap {
        out.extend_from_slice(&w.to_be_bytes());
    }
    put_uvarint(out, set.labels.len() as u64);
    out.extend_from_slice(&set.labels);
    Ok(())
}

fn write_ip_set(out: &mut Vec<u8>, set: &IpSet) {
    out.push(1);
    out.extend_from_slice(&(set.range_count() as u64).to_be_bytes());
    for (from, to) in set.ranges4() {
        for addr in [from, to] {
            put_uvarint(out, 4);
            out.extend_from_slice(&addr.octets());
        }
    }
    for (from, to) in set.ranges6() {
        for addr in [from, to] {
            put_uvarint(out, 16);
            out.extend_from_slice(&addr.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SourceRuleSetFile {
        SourceRuleSetFile {
            version: 2,
            rules: vec![
                HeadlessRuleSpec {
                    domain: vec!["exact.example".into()],
                    domain_suffix: vec!["suffix.example".into(), ".sub.example".into()],
                    domain_keyword: vec!["kw".into()],
                    ip_cidr: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
                    port: vec![443],
                    port_range: vec!["1000:2000".into()],
                    ..Default::default()
                },
                HeadlessRuleSpec {
                    logical_type: Some("logical".into()),
                    logical_mode: Some("or".into()),
                    logical_rules: vec![HeadlessRuleSpec {
                        network: StringOrVec::List(vec!["udp".into()]),
                        invert: true,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
        }
    }

    #[test]
    fn write_then_read_preserves_rules_in_every_version() {
        for version in [1, 2, 3] {
            let mut file = sample();
            file.version = version;
            let decoded = read(&write(&file).unwrap()).unwrap();
            assert_eq!(decoded.version, version);
            let first = &decoded.rules[0];
            assert_eq!(first.domain, ["exact.example"]);
            assert_eq!(first.domain_suffix, [".sub.example", "suffix.example"]);
            assert_eq!(first.ip_cidr, ["10.0.0.0/8", "2001:db8::/32"]);
            assert_eq!(first.port, [443]);
            assert_eq!(first.port_range, ["1000:2000"]);
            let logical = &decoded.rules[1];
            assert_eq!(logical.logical_mode.as_deref(), Some("or"));
            assert!(logical.logical_rules[0].invert);
        }
    }

    #[test]
    fn rejects_bad_magic_and_future_versions() {
        assert!(read(b"XYZ\x01").is_err());
        assert!(read(b"SRS\x09").is_err());
    }
}
