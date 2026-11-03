//! TUN 自动路由、策略路由表、`auto-redirect` 标记与 DNS 劫持规划。

use kerlico_core::{Cidr, Error, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum MarkInput {
    Number(u32),
    Text(String),
}

impl MarkInput {
    pub fn parse_u32(&self) -> Result<u32> {
        match self {
            Self::Number(n) => Ok(*n),
            Self::Text(s) => {
                let t = s.trim();
                if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    u32::from_str_radix(hex, 16).map_err(|_| invalid())
                } else {
                    t.parse::<u32>().map_err(|_| invalid())
                }
            }
        }
    }
}

pub fn default_table_index() -> u32 {
    2022
}

pub fn default_rule_index() -> u32 {
    9000
}

pub fn default_fallback_rule_index() -> u32 {
    32768
}

fn invalid() -> Error {
    Error::Config("TUN 自动化选项不合法".into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsHijackProto {
    Any,
    Udp,
    Tcp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsHijackRule {
    pub proto: DnsHijackProto,
    pub target_ip: Option<IpAddr>,
    pub port: u16,
}

impl DnsHijackRule {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(invalid());
        }
        let (proto, addr_part) = match trimmed.split_once("://") {
            Some(("udp", rest)) => (DnsHijackProto::Udp, rest),
            Some(("tcp", rest)) => (DnsHijackProto::Tcp, rest),
            Some(("any", rest)) => (DnsHijackProto::Any, rest),
            Some(_) => return Err(invalid()),
            None => (DnsHijackProto::Any, trimmed),
        };
        let (host_str, port_str) = addr_part.rsplit_once(':').ok_or_else(invalid)?;
        let port: u16 = port_str.trim().parse().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }
        let host_clean = host_str
            .trim()
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host_str.trim());
        let target_ip = match host_clean.to_ascii_lowercase().as_str() {
            "any" | "*" | "0.0.0.0" | "::" => None,
            other => Some(other.parse::<IpAddr>().map_err(|_| invalid())?),
        };
        Ok(Self {
            proto,
            target_ip,
            port,
        })
    }

    pub fn matches(&self, is_udp: bool, dst_ip: IpAddr, dst_port: u16) -> bool {
        if self.port != dst_port {
            return false;
        }
        match (self.proto, is_udp) {
            (DnsHijackProto::Udp, false) | (DnsHijackProto::Tcp, true) => return false,
            _ => {}
        }
        self.target_ip
            .is_none_or(|expected| expected.to_canonical() == dst_ip.to_canonical())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunDnsMode {
    Disabled,
    Hijack,
    Native,
}

impl TunDnsMode {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disabled" | "none" | "off" => Ok(Self::Disabled),
            "hijack" => Ok(Self::Hijack),
            "native" => Ok(Self::Native),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunRoutePlan {
    pub interface_name: String,
    pub outbound_interface: Option<String>,
    pub auto_route: bool,
    pub strict_route: bool,
    pub table_index: u32,
    pub rule_index: u32,
    pub include_cidrs: Vec<Cidr>,
    pub exclude_cidrs: Vec<Cidr>,
    pub auto_redirect: bool,
    pub input_mark: u32,
    pub output_mark: u32,
    pub fallback_rule_index: u32,
    pub dns_mode: TunDnsMode,
    pub dns_addresses: Vec<IpAddr>,
    pub dns_hijack_rules: Vec<DnsHijackRule>,
    pub auto_system_dns_to_gateway: bool,
}

impl TunRoutePlan {
    pub fn matches_dns_hijack(&self, is_udp: bool, dst_ip: IpAddr, dst_port: u16) -> bool {
        if self
            .dns_hijack_rules
            .iter()
            .any(|r| r.matches(is_udp, dst_ip, dst_port))
        {
            return true;
        }
        if self.dns_mode == TunDnsMode::Hijack && dst_port == 53 {
            if self.dns_addresses.is_empty() {
                return true;
            }
            return self
                .dns_addresses
                .iter()
                .any(|ip| ip.to_canonical() == dst_ip.to_canonical());
        }
        false
    }
}

/// 从 Linux `/proc/net/route` 与 `/proc/net/ipv6_route` 文本解析系统默认物理出网网卡。
pub fn parse_linux_default_interface(proc_v4: &str, proc_v6: &str) -> Option<String> {
    for line in proc_v4.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let Some(iface) = cols.next() else {
            continue;
        };
        let Some(dest) = cols.next() else {
            continue;
        };
        if dest == "00000000" && !is_virtual_or_loopback_if(iface) {
            return Some(iface.to_owned());
        }
    }
    for line in proc_v6.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 10 {
            let dest = cols[0];
            let prefix = cols[1];
            let iface = cols[9];
            if dest == "00000000000000000000000000000000"
                && prefix == "00"
                && !is_virtual_or_loopback_if(iface)
            {
                return Some(iface.to_owned());
            }
        }
    }
    None
}

fn is_virtual_or_loopback_if(iface: &str) -> bool {
    iface == "lo"
        || iface.starts_with("tun")
        || iface.starts_with("utun")
        || iface.starts_with("kerlico")
        || iface.starts_with("wg")
}

/// 探测当前主机默认物理出网网卡名。
pub fn detect_default_interface() -> Option<String> {
    let v4 = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
    parse_linux_default_interface(&v4, &v6)
}

/// 编译并校验 TUN 自动化路由、重定向与 DNS 计划。
#[allow(clippy::too_many_arguments)]
pub fn compile_route_plan(
    interface_name: &str,
    gateways: &[IpAddr],
    auto_detect_interface: bool,
    auto_outbounds_interface: Option<&str>,
    auto_route: bool,
    auto_system_routing_table: &[String],
    strict_route: bool,
    table_index: u32,
    rule_index: u32,
    route_address: &[String],
    inet4_route_address: &[String],
    inet6_route_address: &[String],
    route_exclude_address: &[String],
    inet4_route_exclude_address: &[String],
    inet6_route_exclude_address: &[String],
    auto_redirect: bool,
    input_mark: Option<&MarkInput>,
    output_mark: Option<&MarkInput>,
    fallback_rule_index: u32,
    dns_hijack: &[String],
    dns_mode_raw: Option<&str>,
    dns_address: &[IpAddr],
    dns: &[IpAddr],
    auto_system_dns_to_gateway: bool,
) -> Result<TunRoutePlan> {
    if table_index == 0 || rule_index == 0 || fallback_rule_index == 0 {
        return Err(invalid());
    }
    let input_mark_val = match input_mark {
        Some(m) => m.parse_u32()?,
        None => 0x2023,
    };
    let output_mark_val = match output_mark {
        Some(m) => m.parse_u32()?,
        None => 0x2024,
    };
    if auto_redirect
        && (input_mark_val == 0 || output_mark_val == 0 || input_mark_val == output_mark_val)
    {
        return Err(invalid());
    }

    let mut include_cidrs = Vec::new();
    for raw in route_address.iter().chain(auto_system_routing_table.iter()) {
        include_cidrs.push(Cidr::parse(raw).map_err(|_| invalid())?);
    }
    for raw in inet4_route_address {
        let cidr = Cidr::parse(raw).map_err(|_| invalid())?;
        if !raw.parse::<Ipv4Addr>().is_ok() && !raw.contains('.') {
            return Err(invalid());
        }
        include_cidrs.push(cidr);
    }
    for raw in inet6_route_address {
        let cidr = Cidr::parse(raw).map_err(|_| invalid())?;
        if !raw.parse::<Ipv6Addr>().is_ok() && !raw.contains(':') {
            return Err(invalid());
        }
        include_cidrs.push(cidr);
    }

    if (auto_route || auto_redirect) && include_cidrs.is_empty() {
        for gw in gateways {
            if gw.is_ipv4() {
                include_cidrs.push(Cidr::parse("0.0.0.0/0").map_err(|_| invalid())?);
            } else {
                include_cidrs.push(Cidr::parse("::/0").map_err(|_| invalid())?);
            }
        }
    }

    let mut exclude_cidrs = Vec::new();
    for raw in route_exclude_address {
        exclude_cidrs.push(Cidr::parse(raw).map_err(|_| invalid())?);
    }
    for raw in inet4_route_exclude_address {
        if !raw.contains('.') {
            return Err(invalid());
        }
        exclude_cidrs.push(Cidr::parse(raw).map_err(|_| invalid())?);
    }
    for raw in inet6_route_exclude_address {
        if !raw.contains(':') {
            return Err(invalid());
        }
        exclude_cidrs.push(Cidr::parse(raw).map_err(|_| invalid())?);
    }

    let mut dns_hijack_rules = Vec::with_capacity(dns_hijack.len());
    for raw in dns_hijack {
        dns_hijack_rules.push(DnsHijackRule::parse(raw)?);
    }

    let dns_mode = match dns_mode_raw {
        Some(m) => TunDnsMode::parse(m)?,
        None => {
            if !dns_hijack_rules.is_empty() || auto_route || !auto_system_routing_table.is_empty() {
                TunDnsMode::Hijack
            } else {
                TunDnsMode::Disabled
            }
        }
    };

    let mut dns_addresses: Vec<IpAddr> = dns_address.iter().chain(dns.iter()).copied().collect();
    if dns_addresses.is_empty() && (dns_mode != TunDnsMode::Disabled || auto_system_dns_to_gateway)
    {
        dns_addresses.extend_from_slice(gateways);
    }

    let outbound_interface = match auto_outbounds_interface {
        Some(name) if !name.trim().is_empty() && !name.eq_ignore_ascii_case("auto") => {
            Some(name.trim().to_owned())
        }
        Some(_) => detect_default_interface(),
        None if auto_detect_interface => detect_default_interface(),
        None => None,
    };

    Ok(TunRoutePlan {
        interface_name: interface_name.to_owned(),
        outbound_interface,
        auto_route: auto_route || !auto_system_routing_table.is_empty(),
        strict_route,
        table_index,
        rule_index,
        include_cidrs,
        exclude_cidrs,
        auto_redirect,
        input_mark: input_mark_val,
        output_mark: output_mark_val,
        fallback_rule_index,
        dns_mode,
        dns_addresses,
        dns_hijack_rules,
        auto_system_dns_to_gateway,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_default_interface_and_builds_tun_route_plan() {
        let proc_v4 = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
lo\t00000000\t00000000\t0001\t0\t0\t1000\t00000000\t0\t0\t0
kerlico0\t00000000\t00000000\t0001\t0\t0\t10\t00000000\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_interface(proc_v4, "").as_deref(),
            Some("eth0")
        );

        let gw = vec!["198.18.0.2".parse::<IpAddr>().unwrap()];
        let plan = compile_route_plan(
            "kerlico0",
            &gw,
            true,
            Some("eth0"),
            true,
            &[],
            true,
            2022,
            9000,
            &["10.0.0.0/8".into()],
            &["172.16.0.0/12".into()],
            &["fd00::/8".into()],
            &["192.168.0.0/16".into()],
            &["100.64.0.0/10".into()],
            &["fe80::/10".into()],
            true,
            Some(&MarkInput::Text("0x2023".into())),
            Some(&MarkInput::Number(0x2024)),
            32768,
            &["any:53".into(), "tcp://1.1.1.1:53".into()],
            Some("hijack"),
            &[],
            &[],
            true,
        )
        .unwrap();

        assert_eq!(plan.outbound_interface.as_deref(), Some("eth0"));
        assert!(plan.auto_route);
        assert!(plan.strict_route);
        assert!(plan.auto_redirect);
        assert_eq!(plan.input_mark, 0x2023);
        assert_eq!(plan.output_mark, 0x2024);
        assert_eq!(plan.include_cidrs.len(), 3);
        assert_eq!(plan.exclude_cidrs.len(), 3);
        assert!(plan.matches_dns_hijack(true, "8.8.8.8".parse().unwrap(), 53));
        assert!(plan.matches_dns_hijack(false, "1.1.1.1".parse().unwrap(), 53));
    }
}
