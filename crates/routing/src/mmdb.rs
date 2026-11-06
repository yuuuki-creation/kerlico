//! MaxMind DB（`.mmdb`）只读解码：搜索树定位记录，按路径读取数据段字段。
//!
//! 国家库按 Mihomo 的三种类型取代码：`sing-geoip` 记录是字符串，`Meta-geoip0` 记录是字符串或
//! 字符串数组，其他类型（MaxMind GeoLite2-Country 等）取 `country.iso_code` 并转小写。
//! ASN 库支持 `GeoLite2-ASN`、`DBIP-ASN-Lite (compat=GeoLite2-ASN)` 与 `ipinfo generic_asn_free.mmdb`。

use kerlico_core::{Error, Result};
use std::net::IpAddr;

const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

const T_POINTER: u8 = 1;
const T_STRING: u8 = 2;
const T_DOUBLE: u8 = 3;
const T_UINT16: u8 = 5;
const T_UINT32: u8 = 6;
const T_MAP: u8 = 7;
const T_INT32: u8 = 8;
const T_UINT64: u8 = 9;
const T_UINT128: u8 = 10;
const T_ARRAY: u8 = 11;
const T_BOOL: u8 = 14;
const T_FLOAT: u8 = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CountryKind {
    Maxmind,
    Sing,
    MetaV0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsnKind {
    GeoLite2,
    IpInfo,
}

pub struct Mmdb {
    buf: Vec<u8>,
    node_count: usize,
    record_size: usize,
    ip_version: u16,
    tree_size: usize,
    ipv4_start: usize,
    database_type: String,
}

impl std::fmt::Debug for Mmdb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mmdb")
            .field("database_type", &self.database_type)
            .field("node_count", &self.node_count)
            .field("bytes", &self.buf.len())
            .finish()
    }
}

fn malformed(what: &str) -> Error {
    Error::Config(format!("mmdb 数据库损坏：{what}"))
}

/// 一个数据段位置上的字段头：类型、长度与负载起点。
struct Field {
    kind: u8,
    size: usize,
    payload: usize,
}

impl Mmdb {
    pub fn parse(buf: Vec<u8>) -> Result<Self> {
        let marker = buf
            .windows(METADATA_MARKER.len())
            .rposition(|w| w == METADATA_MARKER)
            .ok_or_else(|| Error::Config("不是 mmdb 数据库：缺少元数据标记".into()))?;
        let meta_start = marker + METADATA_MARKER.len();
        let mut db = Self {
            buf,
            node_count: 0,
            record_size: 0,
            ip_version: 0,
            tree_size: 0,
            ipv4_start: 0,
            database_type: String::new(),
        };
        let meta = |db: &Self, key: &str| db.map_get(meta_start, meta_start, key);
        let uint = |db: &Self, key: &str| -> Result<u64> {
            let at = meta(db, key)?.ok_or_else(|| malformed(&format!("元数据缺少 {key}")))?;
            db.read_uint(meta_start, at)
        };
        db.node_count =
            usize::try_from(uint(&db, "node_count")?).map_err(|_| malformed("node_count"))?;
        db.record_size =
            usize::try_from(uint(&db, "record_size")?).map_err(|_| malformed("record_size"))?;
        db.ip_version =
            u16::try_from(uint(&db, "ip_version")?).map_err(|_| malformed("ip_version"))?;
        if !matches!(db.record_size, 24 | 28 | 32) || !matches!(db.ip_version, 4 | 6) {
            return Err(malformed("record_size 或 ip_version"));
        }
        db.database_type = match meta(&db, "database_type")? {
            Some(at) => db.read_string(meta_start, at)?,
            None => String::new(),
        };
        db.tree_size = db
            .node_count
            .checked_mul(db.record_size / 4)
            .filter(|&size| size + 16 <= marker)
            .ok_or_else(|| malformed("搜索树超出文件"))?;
        if db.ip_version == 6 {
            let mut node = 0;
            for _ in 0..96 {
                if node >= db.node_count {
                    break;
                }
                node = db.record(node, 0)?;
            }
            db.ipv4_start = node;
        }
        Ok(db)
    }

    pub fn database_type(&self) -> &str {
        &self.database_type
    }

    pub fn heap_bytes(&self) -> usize {
        self.buf.capacity()
    }

    fn record(&self, node: usize, side: usize) -> Result<usize> {
        let size = self.record_size / 4;
        let base = node * size;
        let b = self
            .buf
            .get(base..base + size)
            .ok_or_else(|| malformed("节点越界"))?;
        let be = |s: &[u8]| s.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x));
        Ok(match (self.record_size, side) {
            (24, 0) => be(&b[0..3]),
            (24, _) => be(&b[3..6]),
            (28, 0) => (usize::from(b[3] & 0xf0) << 20) | be(&b[0..3]),
            (28, _) => (usize::from(b[3] & 0x0f) << 24) | be(&b[4..7]),
            (_, 0) => be(&b[0..4]),
            _ => be(&b[4..8]),
        })
    }

    /// 返回记录在数据段内的绝对偏移；无记录返回 `None`。
    fn lookup(&self, ip: IpAddr) -> Result<Option<usize>> {
        let (bits, start, width): ([u8; 16], usize, usize) = match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&v4.octets());
                let start = if self.ip_version == 6 {
                    self.ipv4_start
                } else {
                    0
                };
                (b, start, 32)
            }
            IpAddr::V6(v6) => {
                if self.ip_version == 4 {
                    return Ok(None);
                }
                (v6.octets(), 0, 128)
            }
        };
        let mut node = start;
        for i in 0..width {
            if node >= self.node_count {
                break;
            }
            let bit = (bits[i >> 3] >> (7 - (i & 7))) & 1;
            node = self.record(node, usize::from(bit))?;
        }
        if node == self.node_count {
            return Ok(None);
        }
        if node < self.node_count {
            return Err(malformed("查找未到达叶子"));
        }
        let offset = self.tree_size + (node - self.node_count);
        if offset >= self.buf.len() {
            return Err(malformed("数据指针越界"));
        }
        Ok(Some(offset))
    }

    fn data_base(&self) -> usize {
        self.tree_size + 16
    }

    fn byte(&self, at: usize) -> Result<u8> {
        self.buf
            .get(at)
            .copied()
            .ok_or_else(|| malformed("数据截断"))
    }

    fn be_at(&self, at: usize, n: usize) -> Result<usize> {
        let b = self
            .buf
            .get(at..at + n)
            .ok_or_else(|| malformed("数据截断"))?;
        Ok(b.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x)))
    }

    /// 读字段头；指针字段的 `payload` 是指向的绝对偏移，`size` 为指针本身之后的位置。
    fn field(&self, base: usize, at: usize) -> Result<Field> {
        let ctrl = self.byte(at)?;
        let mut pos = at + 1;
        let mut kind = ctrl >> 5;
        if kind == T_POINTER {
            let ss = usize::from((ctrl >> 3) & 0x3);
            let vvv = usize::from(ctrl & 0x7);
            let (value, len) = match ss {
                0 => ((vvv << 8) | self.be_at(pos, 1)?, 1),
                1 => (((vvv << 16) | self.be_at(pos, 2)?) + 2048, 2),
                2 => (((vvv << 24) | self.be_at(pos, 3)?) + 526_336, 3),
                _ => (self.be_at(pos, 4)?, 4),
            };
            return Ok(Field {
                kind: T_POINTER,
                size: pos + len,
                payload: base + value,
            });
        }
        if kind == 0 {
            kind = 7 + self.byte(pos)?;
            pos += 1;
        }
        let mut size = usize::from(ctrl & 0x1f);
        if size >= 29 {
            let n = size - 28;
            let extra = self.be_at(pos, n)?;
            pos += n;
            size = match n {
                1 => 29 + extra,
                2 => 285 + extra,
                _ => 65_821 + extra,
            };
        }
        Ok(Field {
            kind,
            size,
            payload: pos,
        })
    }

    /// 跟随指针，返回实际值的字段头。
    fn resolve(&self, base: usize, at: usize) -> Result<Field> {
        let field = self.field(base, at)?;
        if field.kind == T_POINTER {
            let target = self.field(base, field.payload)?;
            if target.kind == T_POINTER {
                return Err(malformed("指针指向指针"));
            }
            return Ok(target);
        }
        Ok(field)
    }

    /// 跳过一个值，返回其后位置；指针只跳过指针本身。
    fn skip(&self, base: usize, at: usize, depth: usize) -> Result<usize> {
        if depth > 64 {
            return Err(malformed("嵌套过深"));
        }
        let field = self.field(base, at)?;
        match field.kind {
            T_POINTER => Ok(field.size),
            T_MAP => {
                let mut pos = field.payload;
                for _ in 0..field.size * 2 {
                    pos = self.skip(base, pos, depth + 1)?;
                }
                Ok(pos)
            }
            T_ARRAY => {
                let mut pos = field.payload;
                for _ in 0..field.size {
                    pos = self.skip(base, pos, depth + 1)?;
                }
                Ok(pos)
            }
            T_BOOL => Ok(field.payload),
            T_DOUBLE => Ok(field.payload + 8),
            T_FLOAT => Ok(field.payload + 4),
            _ => Ok(field.payload + field.size),
        }
    }

    fn read_string(&self, base: usize, at: usize) -> Result<String> {
        let field = self.resolve(base, at)?;
        if field.kind != T_STRING {
            return Err(malformed("期望字符串"));
        }
        let bytes = self
            .buf
            .get(field.payload..field.payload + field.size)
            .ok_or_else(|| malformed("字符串截断"))?;
        String::from_utf8(bytes.to_vec()).map_err(|_| malformed("字符串不是 UTF-8"))
    }

    fn read_uint(&self, base: usize, at: usize) -> Result<u64> {
        let field = self.resolve(base, at)?;
        match field.kind {
            T_UINT16 | T_UINT32 | T_UINT64 | T_UINT128 | T_INT32 if field.size <= 8 => {
                Ok(self.be_at(field.payload, field.size)? as u64)
            }
            _ => Err(malformed("期望整数")),
        }
    }

    /// 在 `at` 处的 map 中查找键，返回值的位置。
    fn map_get(&self, base: usize, at: usize, key: &str) -> Result<Option<usize>> {
        let field = self.resolve(base, at)?;
        if field.kind != T_MAP {
            return Ok(None);
        }
        let mut pos = field.payload;
        for _ in 0..field.size {
            let name = self.read_string(base, pos)?;
            pos = self.skip(base, pos, 0)?;
            if name == key {
                return Ok(Some(pos));
            }
            pos = self.skip(base, pos, 0)?;
        }
        Ok(None)
    }

    fn path(&self, at: usize, keys: &[&str]) -> Result<Option<usize>> {
        let base = self.data_base();
        let mut pos = at;
        for key in keys {
            match self.map_get(base, pos, key)? {
                Some(next) => pos = next,
                None => return Ok(None),
            }
        }
        Ok(Some(pos))
    }

    fn country_kind(&self) -> CountryKind {
        match self.database_type.as_str() {
            "sing-geoip" => CountryKind::Sing,
            "Meta-geoip0" => CountryKind::MetaV0,
            _ => CountryKind::Maxmind,
        }
    }

    /// IP 所属的国家/分类代码（小写），与 Mihomo `LookupCode` 一致。
    pub fn country_codes(&self, ip: IpAddr) -> Result<Vec<String>> {
        let Some(at) = self.lookup(ip)? else {
            return Ok(Vec::new());
        };
        let base = self.data_base();
        let code = |pos: usize| -> Result<Option<String>> {
            match self.resolve(base, pos)?.kind {
                T_STRING => Ok(Some(self.read_string(base, pos)?)),
                _ => Ok(None),
            }
        };
        let mut out = Vec::new();
        match self.country_kind() {
            CountryKind::Maxmind => {
                if let Some(pos) = self.path(at, &["country", "iso_code"])?
                    && let Some(c) = code(pos)?
                    && !c.is_empty()
                {
                    out.push(c.to_ascii_lowercase());
                }
            }
            CountryKind::Sing => {
                if let Some(c) = code(at)?
                    && !c.is_empty()
                {
                    out.push(c);
                }
            }
            CountryKind::MetaV0 => {
                let field = self.resolve(base, at)?;
                match field.kind {
                    T_STRING => out.extend(code(at)?),
                    T_ARRAY => {
                        let mut pos = field.payload;
                        for _ in 0..field.size {
                            out.extend(code(pos)?);
                            pos = self.skip(base, pos, 0)?;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(out)
    }

    fn asn_kind(&self) -> Result<AsnKind> {
        match self.database_type.as_str() {
            "GeoLite2-ASN" | "DBIP-ASN-Lite (compat=GeoLite2-ASN)" => Ok(AsnKind::GeoLite2),
            "ipinfo generic_asn_free.mmdb" => Ok(AsnKind::IpInfo),
            other => Err(Error::Config(format!("不支持的 ASN 数据库类型：{other}"))),
        }
    }

    pub fn check_asn(&self) -> Result<()> {
        self.asn_kind().map(|_| ())
    }

    /// IP 所属自治系统号与组织名。
    pub fn asn(&self, ip: IpAddr) -> Result<Option<(u32, String)>> {
        let kind = self.asn_kind()?;
        let Some(at) = self.lookup(ip)? else {
            return Ok(None);
        };
        let base = self.data_base();
        let (number_key, org_key) = match kind {
            AsnKind::GeoLite2 => ("autonomous_system_number", "autonomous_system_organization"),
            AsnKind::IpInfo => ("asn", "name"),
        };
        let org = match self.path(at, &[org_key])? {
            Some(pos) => self.read_string(base, pos).unwrap_or_default(),
            None => String::new(),
        };
        let Some(pos) = self.path(at, &[number_key])? else {
            return Ok(None);
        };
        let number = match kind {
            AsnKind::GeoLite2 => u32::try_from(self.read_uint(base, pos)?).ok(),
            AsnKind::IpInfo => {
                let text = self.read_string(base, pos)?;
                text.get(2..).and_then(|n| n.parse().ok())
            }
        };
        Ok(number.map(|n| (n, org)))
    }
}

/// 测试与 CLI 用：按 MaxMind DB 规范写出小型数据库（IPv6 树，记录 32 位）。
#[cfg(test)]
pub(crate) mod writer {
    use std::net::IpAddr;

    pub enum Value {
        Str(String),
        U32(u32),
        Map(Vec<(String, Value)>),
        Array(Vec<Value>),
    }

    fn ctrl(out: &mut Vec<u8>, kind: u8, size: usize) {
        let (first, ext) = if kind > 7 {
            (0u8, Some(kind - 7))
        } else {
            (kind << 5, None)
        };
        let (low, extra): (u8, Vec<u8>) = if size < 29 {
            (size as u8, vec![])
        } else if size < 285 {
            (29, vec![(size - 29) as u8])
        } else {
            let v = size - 285;
            (30, vec![(v >> 8) as u8, v as u8])
        };
        out.push(first | low);
        if let Some(e) = ext {
            out.push(e);
        }
        out.extend(extra);
    }

    pub fn encode(out: &mut Vec<u8>, v: &Value) {
        match v {
            Value::Str(s) => {
                ctrl(out, 2, s.len());
                out.extend_from_slice(s.as_bytes());
            }
            Value::U32(n) => {
                let bytes: Vec<u8> = n
                    .to_be_bytes()
                    .into_iter()
                    .skip_while(|&b| b == 0)
                    .collect();
                ctrl(out, 6, bytes.len());
                out.extend(bytes);
            }
            Value::Map(entries) => {
                ctrl(out, 7, entries.len());
                for (k, v) in entries {
                    encode(out, &Value::Str(k.clone()));
                    encode(out, v);
                }
            }
            Value::Array(items) => {
                ctrl(out, 11, items.len());
                for item in items {
                    encode(out, item);
                }
            }
        }
    }

    pub fn build(database_type: &str, records: &[(&str, Value)]) -> Vec<u8> {
        // 节点表：每个节点两个记录，u32::MAX 表示尚未分配。
        let mut nodes: Vec<[u64; 2]> = vec![[u64::MAX; 2]];
        let mut data = Vec::new();
        let mut leaves: Vec<(usize, usize, usize)> = Vec::new();
        for (cidr, value) in records {
            let (addr, len) = crate::ip_set::parse_prefix(cidr).unwrap();
            let (bits, len) = match addr {
                IpAddr::V4(v4) => {
                    let mut b = [0u8; 16];
                    b[12..].copy_from_slice(&v4.octets());
                    (b, usize::from(len) + 96)
                }
                IpAddr::V6(v6) => (v6.octets(), usize::from(len)),
            };
            let offset = data.len();
            encode(&mut data, value);
            let mut node = 0;
            for i in 0..len {
                let bit = usize::from((bits[i >> 3] >> (7 - (i & 7))) & 1);
                if i + 1 == len {
                    leaves.push((node, bit, offset));
                    break;
                }
                if nodes[node][bit] == u64::MAX {
                    nodes.push([u64::MAX; 2]);
                    nodes[node][bit] = (nodes.len() - 1) as u64;
                }
                node = nodes[node][bit] as usize;
            }
        }
        let count = nodes.len() as u64;
        for (node, bit, offset) in leaves {
            nodes[node][bit] = count + 16 + offset as u64;
        }
        let mut out = Vec::new();
        for node in &nodes {
            for &r in node {
                let r = if r == u64::MAX { count } else { r };
                out.extend_from_slice(&(r as u32).to_be_bytes());
            }
        }
        out.extend_from_slice(&[0u8; 16]);
        out.extend(data);
        out.extend_from_slice(super::METADATA_MARKER);
        encode(
            &mut out,
            &Value::Map(vec![
                ("node_count".into(), Value::U32(count as u32)),
                ("record_size".into(), Value::U32(32)),
                ("ip_version".into(), Value::U32(6)),
                ("database_type".into(), Value::Str(database_type.into())),
            ]),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{writer::Value, *};

    fn country(code: &str) -> Value {
        Value::Map(vec![(
            "country".into(),
            Value::Map(vec![
                ("geoname_id".into(), Value::U32(1)),
                ("iso_code".into(), Value::Str(code.into())),
            ]),
        )])
    }

    #[test]
    fn maxmind_country_codes_are_lowercased() {
        let db = Mmdb::parse(writer::build(
            "GeoLite2-Country",
            &[
                ("1.2.3.0/24", country("CN")),
                ("2001:db8::/32", country("JP")),
            ],
        ))
        .unwrap();
        assert_eq!(
            db.country_codes("1.2.3.4".parse().unwrap()).unwrap(),
            ["cn"]
        );
        assert_eq!(
            db.country_codes("2001:db8::1".parse().unwrap()).unwrap(),
            ["jp"]
        );
        assert!(
            db.country_codes("8.8.8.8".parse().unwrap())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn meta_and_sing_records_and_asn_lookup() {
        let meta = Mmdb::parse(writer::build(
            "Meta-geoip0",
            &[(
                "10.0.0.0/8",
                Value::Array(vec![Value::Str("cn".into()), Value::Str("private".into())]),
            )],
        ))
        .unwrap();
        assert_eq!(
            meta.country_codes("10.1.1.1".parse().unwrap()).unwrap(),
            ["cn", "private"]
        );
        let sing = Mmdb::parse(writer::build(
            "sing-geoip",
            &[("9.9.9.0/24", Value::Str("us".into()))],
        ))
        .unwrap();
        assert_eq!(
            sing.country_codes("9.9.9.9".parse().unwrap()).unwrap(),
            ["us"]
        );
        let asn = Mmdb::parse(writer::build(
            "GeoLite2-ASN",
            &[(
                "1.1.1.0/24",
                Value::Map(vec![
                    ("autonomous_system_number".into(), Value::U32(13335)),
                    (
                        "autonomous_system_organization".into(),
                        Value::Str("CLOUDFLARENET".into()),
                    ),
                ]),
            )],
        ))
        .unwrap();
        assert_eq!(
            asn.asn("1.1.1.1".parse().unwrap()).unwrap(),
            Some((13335, "CLOUDFLARENET".into()))
        );
        assert_eq!(asn.asn("1.0.0.1".parse().unwrap()).unwrap(), None);
        assert!(sing.check_asn().is_err());
    }
}
