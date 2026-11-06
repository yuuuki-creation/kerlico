//! DNS 报文线格式：问题段解析、资源记录遍历、TTL 改写、合成应答、ECS 选项与 JSON 视图。
//!
//! 上游应答按原始字节转发，任意记录类型原样保留；只有 hosts、Fake-IP 与拒绝应答在本地合成。

use kerlico_core::{Error, Result};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Range,
    str::FromStr,
};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

const HEADER: usize = 12;
const MAX_MESSAGE: usize = 65535;

/// 已解析的单个问题；`end` 是问题段之后的偏移。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub end: usize,
}

fn malformed() -> Error {
    Error::Protocol("DNS 报文不合法")
}

/// 解析查询或应答的第一个问题；名称转为小写且不带末尾点。
pub fn parse_question(msg: &[u8]) -> Result<Question> {
    if msg.len() < HEADER || msg.len() > MAX_MESSAGE {
        return Err(malformed());
    }
    if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return Err(Error::Protocol("DNS 报文须恰有一个问题"));
    }
    let (name, pos) = read_name(msg, HEADER).ok_or_else(malformed)?;
    if name.is_empty() || pos + 4 > msg.len() {
        return Err(malformed());
    }
    let qtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
    let qclass = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
    if qclass != 1 {
        return Err(Error::Protocol("DNS 仅支持 IN 类查询"));
    }
    Ok(Question {
        name: name.to_ascii_lowercase(),
        qtype,
        end: pos + 4,
    })
}

pub fn id(msg: &[u8]) -> u16 {
    u16::from_be_bytes([msg[0], msg[1]])
}

pub fn set_id(msg: &mut [u8], id: u16) {
    msg[..2].copy_from_slice(&id.to_be_bytes());
}

pub fn rcode(msg: &[u8]) -> u8 {
    msg[3] & 0x0f
}

pub fn is_truncated(msg: &[u8]) -> bool {
    msg[2] & 0x02 != 0
}

/// 读取可能带压缩指针的名称，返回点分名称与名称之后的偏移。
pub fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end = None;
    let mut hops = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            let target = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            hops += 1;
            if hops > 32 || target >= msg.len() {
                return None;
            }
            pos = target;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        pos += 1;
        if len == 0 {
            break;
        }
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            msg.get(pos + 1)?;
            return Some(pos + 2);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        pos += 1 + len;
        if len == 0 {
            return Some(pos);
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecordRef {
    pub section: Section,
    pub name_pos: usize,
    pub rtype: u16,
    pub ttl_pos: usize,
    pub rdata: Range<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

/// 遍历问题段之后的全部资源记录；报文截断时返回 `None`。
pub fn records(msg: &[u8]) -> Option<Vec<RecordRef>> {
    if msg.len() < HEADER {
        return None;
    }
    let count = |i: usize| u16::from_be_bytes([msg[i], msg[i + 1]]) as usize;
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
    let mut pos = HEADER;
    for _ in 0..qd {
        pos = skip_name(msg, pos)? + 4;
    }
    let mut out = Vec::with_capacity(an + ns + ar);
    for (section, n) in [
        (Section::Answer, an),
        (Section::Authority, ns),
        (Section::Additional, ar),
    ] {
        for _ in 0..n {
            let name_pos = pos;
            pos = skip_name(msg, pos)?;
            let fixed = msg.get(pos..pos + 10)?;
            let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
            let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
            let rdata = pos + 10..pos + 10 + rdlen;
            msg.get(rdata.clone())?;
            out.push(RecordRef {
                section,
                name_pos,
                rtype,
                ttl_pos: pos + 4,
                rdata: rdata.clone(),
            });
            pos = rdata.end;
        }
    }
    Some(out)
}

/// 应答段中的 A/AAAA 地址，按出现顺序。
pub fn answer_ips(msg: &[u8]) -> Vec<IpAddr> {
    let Some(records) = records(msg) else {
        return Vec::new();
    };
    records
        .iter()
        .filter(|r| r.section == Section::Answer)
        .filter_map(|r| ip_of(r.rtype, &msg[r.rdata.clone()]))
        .collect()
}

fn ip_of(rtype: u16, rdata: &[u8]) -> Option<IpAddr> {
    match (rtype, rdata.len()) {
        (TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::new(
            rdata[0], rdata[1], rdata[2], rdata[3],
        ))),
        (TYPE_AAAA, 16) => <[u8; 16]>::try_from(rdata)
            .ok()
            .map(|o| IpAddr::V6(Ipv6Addr::from(o))),
        _ => None,
    }
}

/// 除 OPT 外全部记录的最小 TTL；没有记录时为 `None`。
pub fn min_ttl(msg: &[u8]) -> Option<u32> {
    records(msg)?
        .iter()
        .filter(|r| r.rtype != TYPE_OPT)
        .map(|r| read_u32(msg, r.ttl_pos))
        .min()
}

fn read_u32(msg: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes([msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]])
}

/// 把除 OPT 外全部记录的 TTL 改为 `ttl`。
pub fn set_ttls(msg: &mut [u8], ttl: u32) {
    if let Some(records) = records(msg) {
        for r in records.iter().filter(|r| r.rtype != TYPE_OPT) {
            msg[r.ttl_pos..r.ttl_pos + 4].copy_from_slice(&ttl.to_be_bytes());
        }
    }
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<()> {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::InvalidAddress);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// 构造递归查询，带 EDNS0（UDP 负载 1232）。
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    encode_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    Ok(out)
}

/// 本地合成的应答记录。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Synth {
    Ip(IpAddr),
}

/// 以查询为模板合成应答：保留 ID、操作码、RD 与问题段，应答名称指向问题名。
pub fn reply(query: &[u8], question: &Question, rcode: u8, answers: &[Synth], ttl: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(question.end + answers.len() * 28);
    out.extend_from_slice(&query[0..2]);
    out.push(0x80 | (query[2] & 0x79));
    out.push(0x80 | (rcode & 0x0f));
    out.extend_from_slice(&1u16.to_be_bytes());
    let records: Vec<(u16, Vec<u8>)> = if rcode == RCODE_NOERROR {
        answers
            .iter()
            .filter_map(|Synth::Ip(ip)| match (question.qtype, ip) {
                (TYPE_A, IpAddr::V4(v4)) => Some((TYPE_A, v4.octets().to_vec())),
                (TYPE_AAAA, IpAddr::V6(v6)) => Some((TYPE_AAAA, v6.octets().to_vec())),
                _ => None,
            })
            .take(32)
            .collect()
    } else {
        Vec::new()
    };
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[HEADER..question.end]);
    for (rtype, rdata) in records {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

/// EDNS Client Subnet（RFC 7871）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSubnet {
    pub address: IpAddr,
    pub prefix: u8,
}

impl FromStr for ClientSubnet {
    type Err = Error;
    fn from_str(raw: &str) -> Result<Self> {
        let invalid = || Error::Config("client-subnet 不合法".into());
        let (ip, prefix) = match raw.trim().split_once('/') {
            Some((ip, p)) => (
                ip.parse::<IpAddr>().map_err(|_| invalid())?,
                Some(p.parse::<u8>().map_err(|_| invalid())?),
            ),
            None => (raw.trim().parse::<IpAddr>().map_err(|_| invalid())?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(invalid());
        }
        Ok(Self {
            address: ip,
            prefix,
        })
    }
}

impl ClientSubnet {
    fn option(&self) -> Vec<u8> {
        let (family, octets): (u16, Vec<u8>) = match self.address {
            IpAddr::V4(v4) => (1, v4.octets().to_vec()),
            IpAddr::V6(v6) => (2, v6.octets().to_vec()),
        };
        let keep = usize::from(self.prefix).div_ceil(8);
        let mut addr = octets[..keep].to_vec();
        if let Some(last) = addr.last_mut()
            && !self.prefix.is_multiple_of(8)
        {
            *last &= 0xffu8 << (8 - self.prefix % 8);
        }
        let mut out = Vec::with_capacity(8 + addr.len());
        out.extend_from_slice(&8u16.to_be_bytes());
        out.extend_from_slice(&((4 + addr.len()) as u16).to_be_bytes());
        out.extend_from_slice(&family.to_be_bytes());
        out.push(self.prefix);
        out.push(0);
        out.extend_from_slice(&addr);
        out
    }
}

/// 在查询的 OPT 记录里写入 ECS；已有 ECS 时只有 `replace` 为真才替换。
pub fn with_client_subnet(query: &[u8], subnet: &ClientSubnet, replace: bool) -> Option<Vec<u8>> {
    let records = records(query)?;
    let opt = records
        .iter()
        .find(|r| r.section == Section::Additional && r.rtype == TYPE_OPT);
    let ecs = subnet.option();
    match opt {
        None => {
            let mut out = query.to_vec();
            let ar = u16::from_be_bytes([out[10], out[11]]).checked_add(1)?;
            out[10..12].copy_from_slice(&ar.to_be_bytes());
            out.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0]);
            out.extend_from_slice(&(ecs.len() as u16).to_be_bytes());
            out.extend_from_slice(&ecs);
            Some(out)
        }
        Some(opt) => {
            let rdata = &query[opt.rdata.clone()];
            let mut options = Vec::with_capacity(rdata.len() + ecs.len());
            let mut pos = 0;
            let mut had_ecs = false;
            while pos + 4 <= rdata.len() {
                let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
                let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
                let item = rdata.get(pos..pos + 4 + len)?;
                if code == 8 {
                    had_ecs = true;
                    if !replace {
                        options.extend_from_slice(item);
                    }
                } else {
                    options.extend_from_slice(item);
                }
                pos += 4 + len;
            }
            if !had_ecs || replace {
                options.extend_from_slice(&ecs);
            }
            let mut out = Vec::with_capacity(query.len() + ecs.len());
            out.extend_from_slice(&query[..opt.rdata.start - 2]);
            out.extend_from_slice(&u16::try_from(options.len()).ok()?.to_be_bytes());
            out.extend_from_slice(&options);
            out.extend_from_slice(&query[opt.rdata.end..]);
            Some(out)
        }
    }
}

fn type_name(rtype: u16) -> String {
    match rtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        other => other.to_string(),
    }
}

/// 把记录类型名或数字转为类型码。
pub fn type_code(raw: &str) -> Option<u16> {
    let upper = raw.trim().to_ascii_uppercase();
    let code = match upper.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "SVCB" => 64,
        "HTTPS" => 65,
        "ANY" => 255,
        other => other.parse().ok()?,
    };
    (code != 0).then_some(code)
}

fn rdata_text(msg: &[u8], r: &RecordRef) -> String {
    let rdata = &msg[r.rdata.clone()];
    if let Some(ip) = ip_of(r.rtype, rdata) {
        return ip.to_string();
    }
    match r.rtype {
        2 | 5 | 12 => read_name(msg, r.rdata.start)
            .map(|(n, _)| format!("{n}."))
            .unwrap_or_default(),
        15 if rdata.len() > 2 => {
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let name = read_name(msg, r.rdata.start + 2)
                .map(|(n, _)| n)
                .unwrap_or_default();
            format!("{pref} {name}.")
        }
        16 => {
            let mut parts = Vec::new();
            let mut pos = 0;
            while pos < rdata.len() {
                let len = rdata[pos] as usize;
                let text = rdata.get(pos + 1..pos + 1 + len).unwrap_or_default();
                parts.push(format!("\"{}\"", String::from_utf8_lossy(text)));
                pos += 1 + len;
            }
            parts.join(" ")
        }
        _ => rdata.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// Mihomo `/dns/query` 的 JSON 形状。
pub fn message_json(msg: &[u8]) -> Value {
    let question = parse_question(msg).ok();
    let mut sections: [Vec<Value>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for r in records(msg).unwrap_or_default() {
        if r.rtype == TYPE_OPT {
            continue;
        }
        let name = read_name(msg, r.name_pos)
            .map(|(n, _)| format!("{n}."))
            .unwrap_or_default();
        let idx = match r.section {
            Section::Answer => 0,
            Section::Authority => 1,
            Section::Additional => 2,
        };
        sections[idx].push(json!({
            "name": name,
            "type": r.rtype,
            "TTL": read_u32(msg, r.ttl_pos),
            "data": rdata_text(msg, &r),
        }));
    }
    let [answer, authority, additional] = sections;
    let mut out = json!({
        "Status": rcode(msg),
        "TC": msg[2] & 0x02 != 0,
        "RD": msg[2] & 0x01 != 0,
        "RA": msg[3] & 0x80 != 0,
        "AD": msg[3] & 0x20 != 0,
        "CD": msg[3] & 0x10 != 0,
        "Question": question.map(|q| vec![json!({
            "Name": format!("{}.", q.name),
            "Qtype": q.qtype,
            "Qclass": 1,
        })]).unwrap_or_default(),
    });
    for (key, list) in [
        ("Answer", answer),
        ("Authority", authority),
        ("Additional", additional),
    ] {
        if !list.is_empty() {
            out[key] = Value::Array(list);
        }
    }
    out
}

/// 记录类型的可读名称，供日志与测试使用。
pub fn record_type_name(rtype: u16) -> String {
    type_name(rtype)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip_ttl_rewrite_and_ecs() {
        let q = build_query(0x1234, "Example.COM", TYPE_A).unwrap();
        let question = parse_question(&q).unwrap();
        assert_eq!(question.name, "example.com");
        assert_eq!(question.qtype, TYPE_A);
        let mut r = reply(
            &q,
            &question,
            RCODE_NOERROR,
            &[Synth::Ip("192.0.2.1".parse().unwrap())],
            300,
        );
        assert_eq!(answer_ips(&r), vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(min_ttl(&r), Some(300));
        set_ttls(&mut r, 7);
        assert_eq!(min_ttl(&r), Some(7));

        let subnet: ClientSubnet = "198.51.100.77/24".parse().unwrap();
        let with = with_client_subnet(&q, &subnet, false).unwrap();
        let recs = records(&with).unwrap();
        let opt = recs.iter().find(|r| r.rtype == TYPE_OPT).unwrap();
        assert_eq!(
            &with[opt.rdata.clone()],
            &[0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100]
        );
        let other: ClientSubnet = "203.0.113.0/24".parse().unwrap();
        let kept = with_client_subnet(&with, &other, false).unwrap();
        assert_eq!(kept, with);
        let replaced = with_client_subnet(&with, &other, true).unwrap();
        let recs = records(&replaced).unwrap();
        let opt = recs.iter().find(|r| r.rtype == TYPE_OPT).unwrap();
        assert_eq!(
            &replaced[opt.rdata.clone()],
            &[0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113]
        );
    }

    #[test]
    fn compressed_names_and_json_view() {
        let q = build_query(1, "a.example", TYPE_CNAME).unwrap();
        let question = parse_question(&q).unwrap();
        let mut r = reply(&q, &question, RCODE_NOERROR, &[], 60);
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, b'b', 0xc0, 14]);
        let view = message_json(&r);
        assert_eq!(view["Answer"][0]["data"], "b.example.");
        assert_eq!(view["Answer"][0]["type"], 5);
    }
}
