//! Linux TUN 自动路由：专用路由表、`ip rule` 优先级段与 nftables TCP 重定向。
//!
//! 布局沿用 sing-tun 的 Linux `auto_route`。每个地址族在 `[rule_index, rule_index + 10]`
//! 内安装规则，`rule_index + 10` 是 `nop` 跳转终点：
//!
//! | 优先级 | 规则 |
//! | --- | --- |
//! | P | `fwmark <bypass> goto P+10`、`uidrange` / `iif` 排除、无 TUN 地址族的排除网段 |
//! | P+1 | 非严格模式：`lookup main suppress_prefixlength 0`，局域网直连路由优先 |
//! | P+2 | `lookup <table>`；配置 include-uid / include-interface 时逐条限定 |
//! | P+3 | 严格模式下 TUN 没有地址的地址族：`unreachable` |
//! | P+10 | `nop` |
//! | fallback | `auto_redirect` 时 `lookup <table>`，供主表无路由的目标 |
//!
//! 路由表只放 TUN 网段：包含网段为 `dev <tun>` 路由，排除网段为 `throw` 路由，
//! 查表落空后继续走 `nop` 之后的主表。安装前和退出时都按优先级段、表号和 nft 表名清理，
//! 进程崩溃留下的规则在下次启动时被清掉。

use kerlico_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    io::Write,
    net::IpAddr,
    process::{Command, Stdio},
};

pub const DEFAULT_TABLE_INDEX: u32 = 2022;
pub const DEFAULT_RULE_INDEX: u32 = 9000;
pub const DEFAULT_FALLBACK_RULE_INDEX: u32 = 32768;
pub const DEFAULT_INPUT_MARK: u32 = 0x2023;
/// 开启 auto-route 且未配置 `routing-mark` 时 kerlico 出站套接字的默认标记，与 sing-box 一致。
pub const DEFAULT_OUTPUT_MARK: u32 = 0x2024;
const NOP_OFFSET: u32 = 10;
const SUPPRESS_OFFSET: u32 = 1;
const LOOKUP_OFFSET: u32 = 2;
const UNREACHABLE_OFFSET: u32 = 3;

fn invalid(what: &str) -> Error {
    Error::Config(format!("TUN 自动路由选项不合法：{what}"))
}

/// 配置中的标记：数字或 `0x` 十六进制字符串。
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum MarkInput {
    Number(u32),
    Text(String),
}

impl MarkInput {
    pub fn parse_u32(&self) -> Result<u32> {
        let value = match self {
            Self::Number(n) => Some(*n),
            Self::Text(s) => {
                let t = s.trim();
                match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => t.parse().ok(),
                }
            }
        };
        value.filter(|v| *v != 0).ok_or_else(|| invalid("标记"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Self; 2] = [Self::V4, Self::V6];

    pub fn of(ip: IpAddr) -> Self {
        if ip.is_ipv4() { Self::V4 } else { Self::V6 }
    }

    /// 内核是否启用该地址族；`ipv6.disable=1` 的主机没有 IPv6 规则表可写。
    fn available(self) -> bool {
        match self {
            Self::V4 => true,
            Self::V6 => std::path::Path::new("/proc/sys/net/ipv6").exists(),
        }
    }

    fn available_all() -> impl Iterator<Item = Self> {
        Self::ALL.into_iter().filter(|f| f.available())
    }

    fn flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }

    fn default_prefix(self) -> Prefix {
        match self {
            Self::V4 => Prefix {
                addr: IpAddr::from([0, 0, 0, 0]),
                len: 0,
            },
            Self::V6 => Prefix {
                addr: IpAddr::from([0u16; 8]),
                len: 0,
            },
        }
    }
}

/// 主机位已清零的网段，可直接交给 `ip route`。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let (addr, len) = match text.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| invalid(text))?;
        if addr.to_canonical() != addr {
            return Err(invalid(text));
        }
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            Some(len) => len.parse().map_err(|_| invalid(text))?,
            None => bits,
        };
        if len > bits {
            return Err(invalid(text));
        }
        let addr = match addr {
            IpAddr::V4(ip) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                IpAddr::from((ip.to_bits() & mask).to_be_bytes())
            }
            IpAddr::V6(ip) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
                IpAddr::from((ip.to_bits() & mask).to_be_bytes())
            }
        };
        Ok(Self { addr, len })
    }

    pub fn family(&self) -> Family {
        Family::of(self.addr)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// 闭区间 UID 段；接受 `1000`、`1000-2000` 与 Mihomo 的 `1000:2000`。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UidRange {
    start: u32,
    end: u32,
}

impl UidRange {
    pub fn single(uid: u32) -> Self {
        Self {
            start: uid,
            end: uid,
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let (start, end) = text.split_once(['-', ':']).unwrap_or((text, text));
        let start: u32 = start.trim().parse().map_err(|_| invalid(text))?;
        let end: u32 = end.trim().parse().map_err(|_| invalid(text))?;
        if start > end {
            return Err(invalid(text));
        }
        Ok(Self { start, end })
    }
}

/// 参与 TUN 路由的流量范围。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Selection {
    pub include_uid: Vec<UidRange>,
    pub exclude_uid: Vec<UidRange>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
}

/// 经路由表进入 TUN 的目标网段。规则集刷新时整体替换。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddressSet {
    pub include: BTreeSet<Prefix>,
    pub exclude: BTreeSet<Prefix>,
    /// 配置了包含网段或包含规则集：未包含的目标不进 TUN，即使包含集合为空。
    pub restricted: bool,
}

/// `auto_redirect`：nftables 把经 TUN 路由的 TCP 重定向到本机监听端口。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Redirect {
    pub input_mark: u32,
    pub fallback_rule_index: u32,
}

/// 已校验的 Linux 自动路由计划，不含随规则集变化的网段。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    pub interface: String,
    /// TUN 配有地址的地址族。
    pub families: BTreeSet<Family>,
    pub table: u32,
    pub rule_index: u32,
    pub strict: bool,
    /// kerlico 自身套接字可能带的全部标记（全局标记与各出站自带的标记）；命中即跳过 TUN 规则。
    pub bypass_marks: BTreeSet<u32>,
    pub selection: Selection,
    pub redirect: Option<Redirect>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Selector {
    All,
    Fwmark(u32),
    Uid(UidRange),
    Iif(String),
    To(Prefix),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Goto(u32),
    Lookup(u32),
    MainSuppressDefault,
    Unreachable,
    Nop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IpRule {
    family: Family,
    pref: u32,
    selector: Selector,
    action: Action,
}

impl IpRule {
    fn batch_line(&self) -> String {
        let selector = match &self.selector {
            Selector::All => String::new(),
            Selector::Fwmark(mark) => format!(" fwmark {mark:#x}"),
            Selector::Uid(range) => format!(" uidrange {}-{}", range.start, range.end),
            Selector::Iif(name) => format!(" iif {name}"),
            Selector::To(prefix) => format!(" to {prefix}"),
        };
        let action = match self.action {
            Action::Goto(pref) => format!("goto {pref}"),
            Action::Lookup(table) => format!("lookup {table}"),
            Action::MainSuppressDefault => "lookup main suppress_prefixlength 0".into(),
            Action::Unreachable => "unreachable".into(),
            Action::Nop => "nop".into(),
        };
        format!("rule add pref {}{selector} {action}", self.pref)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum RouteKind {
    /// 网段进入 TUN。
    Device,
    /// 网段在本表落空，继续后续规则。
    Throw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct Route {
    prefix: Prefix,
    kind: RouteKind,
}

impl RoutePlan {
    fn nop(&self) -> u32 {
        self.rule_index + NOP_OFFSET
    }

    fn fallback(&self) -> Option<u32> {
        self.redirect.map(|r| r.fallback_rule_index)
    }

    fn owns(&self, pref: u32, table: Option<u32>) -> bool {
        (self.rule_index..=self.nop()).contains(&pref)
            || (self.fallback() == Some(pref) && table == Some(self.table))
    }

    /// 按安装顺序排列：先 `nop` 终点和跳过规则，最后才是把流量导入 TUN 的规则。
    fn rules(&self, set: &AddressSet) -> Vec<IpRule> {
        let mut rules = Vec::new();
        let p = self.rule_index;
        let skip = Action::Goto(self.nop());
        for family in Family::ALL {
            let routed = self.families.contains(&family);
            if !routed && !self.strict {
                continue;
            }
            let mut push = |pref, selector, action| {
                rules.push(IpRule {
                    family,
                    pref,
                    selector,
                    action,
                })
            };
            push(self.nop(), Selector::All, Action::Nop);
            for mark in &self.bypass_marks {
                push(p, Selector::Fwmark(*mark), skip);
            }
            for range in &self.selection.exclude_uid {
                push(p, Selector::Uid(*range), skip);
            }
            for name in &self.selection.exclude_interface {
                push(p, Selector::Iif(name.clone()), skip);
            }
            if !routed {
                for prefix in set.exclude.iter().filter(|x| x.family() == family) {
                    push(p, Selector::To(*prefix), skip);
                }
                push(p + UNREACHABLE_OFFSET, Selector::All, Action::Unreachable);
                continue;
            }
            if !self.strict {
                push(
                    p + SUPPRESS_OFFSET,
                    Selector::All,
                    Action::MainSuppressDefault,
                );
            }
            let lookup = Action::Lookup(self.table);
            let selection = &self.selection;
            if selection.include_uid.is_empty() && selection.include_interface.is_empty() {
                push(p + LOOKUP_OFFSET, Selector::All, lookup);
            } else {
                for range in &selection.include_uid {
                    push(p + LOOKUP_OFFSET, Selector::Uid(*range), lookup);
                }
                for name in &selection.include_interface {
                    push(p + LOOKUP_OFFSET, Selector::Iif(name.clone()), lookup);
                }
            }
            if let Some(fallback) = self.fallback() {
                push(fallback, Selector::All, lookup);
            }
        }
        rules
    }

    fn routes(&self, set: &AddressSet) -> BTreeSet<Route> {
        let mut routes = BTreeSet::new();
        for family in self.families.iter().copied() {
            let mut include: Vec<Prefix> = set
                .include
                .iter()
                .filter(|p| p.family() == family)
                .copied()
                .collect();
            if include.is_empty() && !set.restricted {
                include.push(family.default_prefix());
            }
            for prefix in include {
                routes.insert(Route {
                    prefix,
                    kind: RouteKind::Device,
                });
            }
            for prefix in set.exclude.iter().filter(|p| p.family() == family) {
                routes.insert(Route {
                    prefix: *prefix,
                    kind: RouteKind::Throw,
                });
            }
        }
        routes
    }

    fn route_line(&self, verb: &str, route: &Route) -> String {
        match route.kind {
            RouteKind::Device => format!(
                "route {verb} {} dev {} table {}",
                route.prefix, self.interface, self.table
            ),
            RouteKind::Throw => format!("route {verb} throw {} table {}", route.prefix, self.table),
        }
    }

    fn nft_table(&self) -> String {
        format!("kerlico_{}", self.interface.replace('-', "_"))
    }

    fn nft_script(&self, port: u16) -> Option<String> {
        let redirect = self.redirect?;
        let table = self.nft_table();
        let tun = &self.interface;
        let mark = redirect.input_mark;
        let bypass: String = self
            .bypass_marks
            .iter()
            .map(|m| format!("    meta mark {m:#x} return\n"))
            .collect();
        Some(format!(
            "add table inet {table}\n\
             delete table inet {table}\n\
             table inet {table} {{\n\
             \x20 chain output {{\n\
             \x20   type nat hook output priority -101; policy accept;\n\
             {bypass}\
             \x20   oifname \"{tun}\" meta l4proto tcp ct mark set {mark:#x} redirect to :{port}\n\
             \x20 }}\n\
             \x20 chain prerouting {{\n\
             \x20   type nat hook prerouting priority -101; policy accept;\n\
             \x20   iifname \"{tun}\" return\n\
             \x20   fib daddr type local return\n\
             \x20   meta l4proto tcp fib daddr . mark . iif oifname \"{tun}\" ct mark set {mark:#x} redirect to :{port}\n\
             \x20 }}\n\
             }}\n"
        ))
    }
}

/// 运行一条外部命令，非零退出码连同标准错误一起作为错误返回。
fn run(program: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Config(format!("无法执行 {program}：{e}")))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(Error::Config(format!(
            "{program} {} 失败：{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn ip_batch(family: Family, lines: &[String], force: bool) -> Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut args = vec![family.flag()];
    if force {
        args.push("-force");
    }
    args.extend(["-batch", "-"]);
    run("ip", &args, Some(&(lines.join("\n") + "\n"))).map(drop)
}

#[derive(Deserialize)]
struct ListedRule {
    priority: u32,
    #[serde(default)]
    table: Option<serde_json::Value>,
}

impl ListedRule {
    fn table(&self) -> Option<u32> {
        match self.table.as_ref()? {
            serde_json::Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
            serde_json::Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }
}

fn owned_rules(plan: &RoutePlan, family: Family) -> Result<Vec<ListedRule>> {
    let text = run("ip", &[family.flag(), "-j", "rule", "show"], None)?;
    let rules: Vec<ListedRule> = serde_json::from_str(text.trim())
        .map_err(|_| Error::Config("无法解析 ip -j rule show 输出".into()))?;
    Ok(rules
        .into_iter()
        .filter(|r| plan.owns(r.priority, r.table()))
        .collect())
}

fn table_routes(plan: &RoutePlan, family: Family) -> Result<usize> {
    let table = plan.table.to_string();
    // 指定不存在的表号时 `ip route show table N` 报错，`table all` 不会。
    let text = run(
        "ip",
        &[family.flag(), "route", "show", "table", "all"],
        None,
    )?;
    Ok(text
        .lines()
        .filter(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            words.windows(2).any(|w| w == ["table", table.as_str()])
        })
        .count())
}

fn nft_tables() -> Option<String> {
    run("nft", &["list", "tables"], None).ok()
}

/// 删除本计划优先级段内的全部规则、清空路由表并删除 nft 表，再核对系统里确实没有残留。
/// 重复执行或在半安装状态下执行都收敛到同一结果。
pub fn cleanup(plan: &RoutePlan) -> Result<()> {
    for family in Family::available_all() {
        let mut lines: Vec<String> = owned_rules(plan, family)?
            .iter()
            .map(|r| match r.table() {
                Some(table) => format!("rule del pref {} table {table}", r.priority),
                None => format!("rule del pref {}", r.priority),
            })
            .collect();
        lines.push(format!("route flush table {}", plan.table));
        ip_batch(family, &lines, true).ok();
    }
    let table = plan.nft_table();
    if nft_tables().is_some_and(|t| t.contains(&format!("inet {table}"))) {
        run("nft", &["delete", "table", "inet", &table], None)?;
    }
    for family in Family::available_all() {
        let left = owned_rules(plan, family)?.len();
        let routes = table_routes(plan, family)?;
        if left > 0 || routes > 0 {
            return Err(Error::Config(format!(
                "TUN 路由清理后仍有 {left} 条规则与 {routes} 条表 {} 路由残留",
                plan.table
            )));
        }
    }
    if nft_tables().is_some_and(|t| t.contains(&format!("inet {table}"))) {
        return Err(Error::Config(format!("nft 表 {table} 清理后仍存在")));
    }
    Ok(())
}

/// 已安装到系统的 TUN 路由。丢弃时清理。
pub struct Installed {
    plan: RoutePlan,
    routes: BTreeSet<Route>,
    rules: Vec<IpRule>,
}

impl Installed {
    /// 先清理同一优先级段与表号的旧状态（含崩溃残留），再安装路由表、规则与 nft 重定向。
    pub fn install(plan: &RoutePlan, set: &AddressSet, redirect_port: Option<u16>) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(Error::Unsupported("TUN 自动路由仅支持 Linux"));
        }
        cleanup(plan)?;
        let mut installed = Self {
            plan: plan.clone(),
            routes: BTreeSet::new(),
            rules: Vec::new(),
        };
        installed.apply(set, redirect_port)?;
        Ok(installed)
    }

    fn apply(&mut self, set: &AddressSet, redirect_port: Option<u16>) -> Result<()> {
        let routes = self.plan.routes(set);
        for family in self.plan.families.iter().copied() {
            let lines: Vec<String> = routes
                .iter()
                .filter(|r| r.prefix.family() == family)
                .map(|r| self.plan.route_line("replace", r))
                .collect();
            ip_batch(family, &lines, false)?;
        }
        self.routes = routes;
        if let Some(script) = redirect_port.and_then(|port| self.plan.nft_script(port)) {
            run("nft", &["-f", "-"], Some(&script))?;
        }
        let rules = self.plan.rules(set);
        for family in Family::available_all() {
            let lines: Vec<String> = rules
                .iter()
                .filter(|r| r.family == family)
                .map(IpRule::batch_line)
                .collect();
            ip_batch(family, &lines, false)?;
        }
        self.rules = rules;
        Ok(())
    }

    /// 规则集刷新后按差异更新路由表：先加新网段再删旧网段，期间不出现空表。
    pub fn update(&mut self, set: &AddressSet) -> Result<()> {
        let routes = self.plan.routes(set);
        let rules = self.plan.rules(set);
        if rules != self.rules {
            // 无地址族的排除规则随网段变化，整体重装该段规则。
            let old: Vec<IpRule> = std::mem::take(&mut self.rules);
            for family in Family::available_all() {
                let added: Vec<String> = rules
                    .iter()
                    .filter(|r| r.family == family && !old.contains(r))
                    .map(IpRule::batch_line)
                    .collect();
                ip_batch(family, &added, false)?;
                let removed: Vec<String> = old
                    .iter()
                    .filter(|r| r.family == family && !rules.contains(r))
                    .map(|r| r.batch_line().replacen("rule add", "rule del", 1))
                    .collect();
                ip_batch(family, &removed, true)?;
            }
            self.rules = rules;
        }
        for family in self.plan.families.iter().copied() {
            let added: Vec<String> = routes
                .difference(&self.routes)
                .filter(|r| r.prefix.family() == family)
                .map(|r| self.plan.route_line("replace", r))
                .collect();
            ip_batch(family, &added, false)?;
            let removed: Vec<String> = self
                .routes
                .difference(&routes)
                .filter(|r| r.prefix.family() == family)
                .filter(|r| !routes.iter().any(|n| n.prefix == r.prefix))
                .map(|r| self.plan.route_line("del", r))
                .collect();
            ip_batch(family, &removed, true)?;
        }
        self.routes = routes;
        Ok(())
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        if let Err(error) = cleanup(&self.plan) {
            kerlico_core::log::warning(format!("TUN 路由清理失败：{error}"));
        }
    }
}

/// 把系统 DNS 指向 TUN 网关（systemd-resolved）。失败只告警，不阻止 TUN 启动。
pub struct SystemDns {
    interface: String,
}

impl SystemDns {
    pub fn apply(interface: &str, servers: &[IpAddr]) -> Option<Self> {
        if servers.is_empty() {
            return None;
        }
        let servers: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
        let mut args = vec!["dns", interface];
        args.extend(servers.iter().map(String::as_str));
        let domain = run("resolvectl", &args, None)
            .and_then(|_| run("resolvectl", &["domain", interface, "~."], None));
        match domain {
            Ok(_) => Some(Self {
                interface: interface.to_owned(),
            }),
            Err(error) => {
                kerlico_core::log::warning(format!("TUN 系统 DNS 设置失败：{error}"));
                None
            }
        }
    }
}

impl Drop for SystemDns {
    fn drop(&mut self) {
        if let Err(error) = run("resolvectl", &["revert", &self.interface], None) {
            kerlico_core::log::warning(format!("TUN 系统 DNS 恢复失败：{error}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(strict: bool, families: &[Family]) -> RoutePlan {
        RoutePlan {
            interface: "kerlico0".into(),
            families: families.iter().copied().collect(),
            table: DEFAULT_TABLE_INDEX,
            rule_index: DEFAULT_RULE_INDEX,
            strict,
            bypass_marks: BTreeSet::from([DEFAULT_OUTPUT_MARK]),
            selection: Selection::default(),
            redirect: None,
        }
    }

    fn lines(plan: &RoutePlan, set: &AddressSet, family: Family) -> Vec<String> {
        plan.rules(set)
            .iter()
            .filter(|r| r.family == family)
            .map(IpRule::batch_line)
            .collect()
    }

    #[test]
    fn strict_route_without_ipv6_address_makes_ipv6_unreachable() {
        let plan = plan(true, &[Family::V4]);
        let set = AddressSet::default();
        assert_eq!(
            lines(&plan, &set, Family::V4),
            [
                "rule add pref 9010 nop",
                "rule add pref 9000 fwmark 0x2024 goto 9010",
                "rule add pref 9002 lookup 2022",
            ]
        );
        assert_eq!(
            lines(&plan, &set, Family::V6),
            [
                "rule add pref 9010 nop",
                "rule add pref 9000 fwmark 0x2024 goto 9010",
                "rule add pref 9003 unreachable",
            ]
        );
        let routes: Vec<String> = plan
            .routes(&set)
            .iter()
            .map(|r| plan.route_line("replace", r))
            .collect();
        assert_eq!(routes, ["route replace 0.0.0.0/0 dev kerlico0 table 2022"]);
    }

    #[test]
    fn every_outbound_mark_skips_the_tun_rules() {
        let mut plan = plan(true, &[Family::V4]);
        plan.bypass_marks.extend([0x99, 0x200]);
        assert_eq!(
            lines(&plan, &AddressSet::default(), Family::V4),
            [
                "rule add pref 9010 nop",
                "rule add pref 9000 fwmark 0x99 goto 9010",
                "rule add pref 9000 fwmark 0x200 goto 9010",
                "rule add pref 9000 fwmark 0x2024 goto 9010",
                "rule add pref 9002 lookup 2022",
            ]
        );
    }

    #[test]
    fn non_strict_route_prefers_main_table_specific_routes() {
        let plan = plan(false, &[Family::V4, Family::V6]);
        let v6 = lines(&plan, &AddressSet::default(), Family::V6);
        assert!(v6.contains(&"rule add pref 9001 lookup main suppress_prefixlength 0".into()));
        assert!(v6.contains(&"rule add pref 9002 lookup 2022".into()));
        assert!(!v6.iter().any(|l| l.contains("unreachable")));
    }

    #[test]
    fn address_sets_become_device_and_throw_routes() {
        let plan = plan(true, &[Family::V4, Family::V6]);
        let set = AddressSet {
            include: ["10.1.2.3/8", "fd00::1/8"]
                .iter()
                .map(|t| Prefix::parse(t).unwrap())
                .collect(),
            exclude: ["10.9.0.0/16"]
                .iter()
                .map(|t| Prefix::parse(t).unwrap())
                .collect(),
            restricted: true,
        };
        let routes: Vec<String> = plan
            .routes(&set)
            .iter()
            .map(|r| plan.route_line("replace", r))
            .collect();
        assert_eq!(
            routes,
            [
                "route replace 10.0.0.0/8 dev kerlico0 table 2022",
                "route replace throw 10.9.0.0/16 table 2022",
                "route replace fd00::/8 dev kerlico0 table 2022",
            ]
        );
        let empty_restricted = AddressSet {
            restricted: true,
            ..AddressSet::default()
        };
        assert!(plan.routes(&empty_restricted).is_empty());
    }

    #[test]
    fn uid_and_interface_filters_scope_the_lookup_rule() {
        let mut plan = plan(true, &[Family::V4]);
        plan.selection = Selection {
            include_uid: vec![UidRange::parse("1000:1999").unwrap()],
            exclude_uid: vec![UidRange::single(0)],
            include_interface: vec!["lan0".into()],
            exclude_interface: vec!["wg0".into()],
        };
        assert_eq!(
            lines(&plan, &AddressSet::default(), Family::V4),
            [
                "rule add pref 9010 nop",
                "rule add pref 9000 fwmark 0x2024 goto 9010",
                "rule add pref 9000 uidrange 0-0 goto 9010",
                "rule add pref 9000 iif wg0 goto 9010",
                "rule add pref 9002 uidrange 1000-1999 lookup 2022",
                "rule add pref 9002 iif lan0 lookup 2022",
            ]
        );
    }

    #[test]
    fn auto_redirect_adds_fallback_rule_and_nft_redirect() {
        let mut plan = plan(true, &[Family::V4]);
        plan.redirect = Some(Redirect {
            input_mark: DEFAULT_INPUT_MARK,
            fallback_rule_index: DEFAULT_FALLBACK_RULE_INDEX,
        });
        assert!(
            lines(&plan, &AddressSet::default(), Family::V4)
                .contains(&"rule add pref 32768 lookup 2022".into())
        );
        assert!(plan.owns(32768, Some(2022)));
        assert!(!plan.owns(32768, None));
        assert!(plan.owns(9010, None) && !plan.owns(9011, None));
        plan.bypass_marks.insert(0x99);
        let script = plan.nft_script(7890).unwrap();
        assert!(script.contains("meta mark 0x2024 return"));
        assert!(
            script.contains("meta mark 0x99 return"),
            "出站自带的标记同样放行"
        );
        assert!(script.contains(
            "oifname \"kerlico0\" meta l4proto tcp ct mark set 0x2023 redirect to :7890"
        ));
        assert!(script.starts_with("add table inet kerlico_kerlico0\ndelete table inet"));
    }

    #[test]
    fn parses_marks_prefixes_and_uid_ranges() {
        assert_eq!(
            MarkInput::Text("0x2024".into()).parse_u32().unwrap(),
            0x2024
        );
        assert_eq!(MarkInput::Number(7).parse_u32().unwrap(), 7);
        assert!(MarkInput::Number(0).parse_u32().is_err());
        assert_eq!(
            Prefix::parse("192.168.1.9/16").unwrap().to_string(),
            "192.168.0.0/16"
        );
        assert_eq!(
            Prefix::parse("2001:db8::1").unwrap().to_string(),
            "2001:db8::1/128"
        );
        assert!(Prefix::parse("::ffff:1.2.3.4/128").is_err());
        assert_eq!(UidRange::parse("5").unwrap(), UidRange::single(5));
        assert!(UidRange::parse("9-1").is_err());
    }
}
