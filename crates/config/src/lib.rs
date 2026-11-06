//! 配置 v2 的纯编译、成员绑定与命名服务计划。

use kerlico_core::{
    Capabilities, CredentialIssuer, CredentialPurpose, CredentialSet, Destination, Error,
    FamilyMode, InboundProtocol, Membership, NodeId, OutId, Result, Source, UserId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
mod format;
pub use format::*;
mod group;
pub use group::*;
mod mihomo;
pub use mihomo::{MihomoOutbound, translate_proxy as translate_mihomo_proxy};
mod plan;
mod share_link;
pub use plan::*;
mod resource;
mod tun;
pub use resource::{
    Accepted, DEFAULT_SIZE_LIMIT, Download, GeoFile, ResourceKey, ResourceKind, ResourceSpec,
};
mod users;
pub use kerlico_dns::DnsSpec;
pub use kerlico_routing::{
    CompiledHeadlessRule, CompiledRuleSet, GeoConfigSpec, GeoIpMode, GeoSlot, GeoxUrlSpec,
    HeadlessRuleSpec, Network, RouteTable, RuleProviderSpec, RuleSetSlot, RuleSetSource,
    RuleSetSpec, RuleSpec, SourceRuleSetFile, compile_ruleset_to_srs, convert_adguard_lines,
    decompile_ruleset_bytes, parse_ruleset_bytes,
};
pub use users::AccountSpec;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default = "one")]
    pub epoch: u64,
    #[serde(default)]
    pub accounts: Vec<AccountSpec>,
    pub outbounds: Vec<OutboundSpec>,
    #[serde(default)]
    pub inbounds: Vec<ForwardSpec>,
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
    #[serde(default)]
    pub local_inbounds: Vec<NodeSpec>,
    #[serde(default, alias = "lan-allowed-ips")]
    pub lan_allowed_ips: Vec<String>,
    #[serde(default, alias = "lan-disallowed-ips")]
    pub lan_disallowed_ips: Vec<String>,
    #[serde(default, alias = "http-port")]
    pub port: Option<u16>,
    #[serde(default, alias = "socks-port")]
    pub socks_port: Option<u16>,
    #[serde(default, alias = "mixed-port")]
    pub mixed_port: Option<u16>,
    #[serde(default, alias = "redir-port")]
    pub redir_port: Option<u16>,
    #[serde(default, alias = "tproxy-port")]
    pub tproxy_port: Option<u16>,
    #[serde(default, alias = "allow-lan")]
    pub allow_lan: Option<bool>,
    #[serde(default, alias = "bind-address")]
    pub bind_address: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default, alias = "sub-rules")]
    pub sub_rules: BTreeMap<String, Vec<RuleSpec>>,
    #[serde(default)]
    pub tun: Option<Value>,
    #[serde(default)]
    pub dialer: GlobalDialerSpec,
    #[serde(default, alias = "interface-name", alias = "bind-interface")]
    pub interface_name: Option<String>,
    #[serde(default, alias = "routing-mark")]
    pub routing_mark: Option<u32>,
    #[serde(
        default,
        alias = "disable-keep-alive",
        alias = "disable-tcp-keep-alive"
    )]
    pub disable_keep_alive: bool,
    #[serde(default, alias = "keep-alive-idle", alias = "tcp-keep-alive")]
    pub keep_alive_idle: Option<DurationSpec>,
    #[serde(
        default,
        alias = "keep-alive-interval",
        alias = "tcp-keep-alive-interval"
    )]
    pub keep_alive_interval: Option<DurationSpec>,
    #[serde(default)]
    pub certificate: RootCertificateSpec,
    #[serde(default, alias = "certificate-providers")]
    pub certificate_providers: Vec<CertificateProviderSpec>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub telemetry: Option<HistorySpec>,
    #[serde(default)]
    pub device: Option<DeviceSpec>,
    #[serde(default)]
    pub routes: Vec<RuleSpec>,
    #[serde(default)]
    pub route: Option<RouteConfigSpec>,
    #[serde(default, alias = "rule-set")]
    pub rule_set: Vec<RuleSetSpec>,
    #[serde(default, alias = "rule-providers")]
    pub rule_providers: BTreeMap<String, RuleProviderSpec>,
    #[serde(default, alias = "geodata-mode")]
    pub geodata_mode: Option<bool>,
    #[serde(default, alias = "geodata-loader")]
    pub geodata_loader: Option<String>,
    #[serde(default, alias = "geosite-matcher")]
    pub geosite_matcher: Option<String>,
    #[serde(default, alias = "geo-auto-update")]
    pub geo_auto_update: Option<bool>,
    #[serde(default, alias = "geo-update-interval")]
    pub geo_update_interval: Option<u64>,
    #[serde(default, alias = "geox-url")]
    pub geox_url: Option<GeoxUrlSpec>,
    #[serde(default)]
    pub dns: Option<DnsSpec>,
    #[serde(default)]
    pub fakedns: Option<kerlico_dns::FakeDnsInput>,
    #[serde(default)]
    pub sniffer: Option<GlobalSnifferSpec>,
    #[serde(default)]
    pub experimental: Option<ExperimentalSpec>,
    #[serde(default, alias = "cache-file")]
    pub cache_file: Option<kerlico_dns::CacheFileSpec>,
    #[serde(default)]
    pub profile: Option<ProfileCacheSpec>,
    #[serde(default, alias = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroupSpec>,
    #[serde(default, alias = "proxy-providers")]
    pub proxy_providers: BTreeMap<String, ProxyProviderSpec>,
    #[serde(default)]
    pub log: LogSpec,
    #[serde(default, alias = "log-level")]
    pub log_level: Option<String>,
    #[serde(default, alias = "etag-support")]
    pub etag_support: Option<bool>,
    #[serde(default)]
    pub control: Option<ControlSpec>,
    #[serde(default, rename = "$schema")]
    pub schema: Option<String>,
    #[serde(default)]
    pub geodata: Option<GeoConfigSpec>,
    #[serde(default)]
    pub ntp: Option<NtpSpec>,
    #[serde(default)]
    pub services: Vec<Value>,
    #[serde(default, alias = "http-clients")]
    pub http_clients: Vec<Value>,
    #[serde(default, alias = "network-namespaces")]
    pub network_namespaces: Vec<Value>,
    #[serde(default)]
    pub observatory: Option<Value>,
    #[serde(default, alias = "burst-observatory", alias = "burstObservatory")]
    pub burst_observatory: Option<Value>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}
/// 控制接口与外部面板配置。非回环地址必须配置 `secret`。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSpec {
    pub listen: SocketAddr,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default, alias = "external-ui")]
    pub external_ui: Option<String>,
    #[serde(default, alias = "external-ui-name")]
    pub external_ui_name: Option<String>,
    #[serde(default, alias = "external-ui-url", alias = "external-ui-download-url")]
    pub external_ui_url: Option<String>,
    #[serde(default, alias = "external-ui-download-detour")]
    pub external_ui_download_detour: Option<String>,
    #[serde(default, alias = "default-mode")]
    pub default_mode: Option<String>,
    #[serde(
        default,
        alias = "access-control-allow-origin",
        alias = "access_control_allow_origin",
        alias = "external-controller-cors-allow-origins"
    )]
    pub cors_allow_origins: Vec<String>,
    #[serde(
        default,
        alias = "access-control-allow-private-network",
        alias = "access_control_allow_private_network",
        alias = "external-controller-cors-allow-private-network"
    )]
    pub cors_allow_private_network: bool,
    #[serde(default)]
    pub dashboard: Option<Value>,
    #[serde(default, alias = "dashboard-enabled")]
    pub dashboard_enabled: Option<bool>,
    #[serde(default, alias = "dashboard-path")]
    pub dashboard_path: Option<String>,
    #[serde(default, alias = "dashboard-download-url")]
    pub dashboard_download_url: Option<String>,
    #[serde(default, alias = "dashboard-http-client")]
    pub dashboard_http_client: Option<String>,
    #[serde(default, alias = "dashboard-update-interval")]
    pub dashboard_update_interval: Option<String>,
    #[serde(default)]
    pub tls: Option<Value>,
    #[serde(default, alias = "external-controller-tls")]
    pub tls_listen: Option<String>,
    #[serde(default, alias = "external-controller-unix")]
    pub unix_path: Option<String>,
    #[serde(default, alias = "external-controller-pipe")]
    pub pipe_path: Option<String>,
    #[serde(default, alias = "external-controller-routing-mark")]
    pub routing_mark: Option<u32>,
    #[serde(default, alias = "external-doh-server")]
    pub doh_server: Option<String>,
}

impl Default for ControlSpec {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 9090)),
            secret: None,
            external_ui: None,
            external_ui_name: None,
            external_ui_url: None,
            external_ui_download_detour: None,
            default_mode: None,
            cors_allow_origins: Vec::new(),
            cors_allow_private_network: false,
            dashboard: None,
            dashboard_enabled: None,
            dashboard_path: None,
            dashboard_download_url: None,
            dashboard_http_client: None,
            dashboard_update_interval: None,
            tls: None,
            tls_listen: None,
            unix_path: None,
            pipe_path: None,
            routing_mark: None,
            doh_server: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NtpSpec {
    #[serde(alias = "enable")]
    pub enabled: Option<bool>,
    pub server: Option<String>,
    #[serde(alias = "server-port", alias = "port")]
    pub server_port: Option<u16>,
    pub interval: Option<DurationSpec>,
    #[serde(alias = "write-to-system")]
    pub write_to_system: bool,
    #[serde(alias = "dialer-proxy", alias = "detour")]
    pub dialer_proxy: Option<String>,
}
/// 配置后，`dual-stack` 节点缺原生地址族时经 WARP 补齐；未配置则只用原生地址族。
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSpec {
    pub state_directory: std::path::PathBuf,
    #[serde(default)]
    pub registration: DeviceRegistration,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceRegistration {
    #[default]
    CreateOnce,
    ExistingOnly,
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistorySpec {
    pub failure_policy: HistoryFailurePolicy,
    pub directory: std::path::PathBuf,
    pub sample_interval_ms: u64,
    pub retention_days: u32,
    pub mask_source: bool,
    pub access_records: bool,
    pub dns_records: bool,
    pub error_records: bool,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum HistoryFailurePolicy {
    #[default]
    Degrade,
    StopEngine,
}
impl Default for HistorySpec {
    fn default() -> Self {
        Self {
            failure_policy: HistoryFailurePolicy::Degrade,
            directory: "state/telemetry".into(),
            sample_interval_ms: 1000,
            retention_days: 30,
            mask_source: true,
            access_records: true,
            dns_records: true,
            error_records: true,
        }
    }
}
impl HistorySpec {
    fn validate(&self) -> Result<()> {
        if self.directory.as_os_str().is_empty()
            || self
                .directory
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || !(100..=60_000).contains(&self.sample_interval_ms)
            || !(1..=3650).contains(&self.retention_days)
        {
            return Err(Error::Config("统计目录、采样间隔或保留天数不合法".into()));
        }
        Ok(())
    }
}
fn one() -> u64 {
    1
}
fn enabled() -> bool {
    true
}
fn empty_object() -> Value {
    Value::Object(Default::default())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundSpec {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default = "empty_object")]
    pub options: Value,
}

#[derive(Clone, Copy, Deserialize, Serialize, Default)]
pub enum NodeMode {
    #[serde(rename = "ipv4-only")]
    V4Only,
    #[serde(rename = "ipv6-only")]
    V6Only,
    #[default]
    #[serde(rename = "dual-stack")]
    Dual,
}
impl From<NodeMode> for FamilyMode {
    fn from(mode: NodeMode) -> Self {
        match mode {
            NodeMode::V4Only => Self::V4Only,
            NodeMode::V6Only => Self::V6Only,
            NodeMode::Dual => Self::DualV4Preferred,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSpec {
    pub user_id: String,
    #[serde(default = "one")]
    pub credential_epoch: u64,
    #[serde(default = "enabled")]
    pub enabled: bool,
    pub native_credential: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSpec {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub listen: SocketAddr,
    pub outbound: String,
    #[serde(default)]
    pub mode: NodeMode,
    #[serde(default = "empty_object")]
    pub options: Value,
    #[serde(default)]
    pub members: Vec<MemberSpec>,
    #[serde(default)]
    pub max_sessions: Option<usize>,
    #[serde(default, alias = "accept-proxy-protocol")]
    pub accept_proxy_protocol: bool,
    #[serde(default)]
    pub sniff: Option<bool>,
    #[serde(default, alias = "sniff-override-destination")]
    pub sniff_override_destination: Option<bool>,
    #[serde(default, alias = "sniff-timeout")]
    pub sniff_timeout: Option<DurationSpec>,
    #[serde(default)]
    pub sniffing: Option<InboundSniffingSpec>,
    /// `bind-address: '*'` 的快捷入站：IPv6 未指定地址上同时接收 IPv4。
    #[serde(skip)]
    pub dual_stack: bool,
}

/// 每个协议仅见本节点原生凭据和不可由网络构造的签发者。
#[derive(Clone)]
pub struct NodeBuildContext {
    options: Value,
    native: Arc<Vec<Value>>,
    issuer: CredentialIssuer,
    local: bool,
    routing_mark: Option<u32>,
    bypass_marks: Arc<Vec<u32>>,
    routes: RouteTable,
}
impl NodeBuildContext {
    pub fn options(&self) -> &Value {
        &self.options
    }
    /// 全局出站拨号选项的路由标记，即 kerlico 自身出站套接字带的 fwmark。
    pub fn routing_mark(&self) -> Option<u32> {
        self.routing_mark
    }
    /// kerlico 自身套接字可能带的全部路由标记：全局标记与各出站自带的 `routing-mark`，升序去重。
    pub fn bypass_marks(&self) -> &[u32] {
        &self.bypass_marks
    }
    /// 路由表中按标签共享的规则集槽；资源刷新换入新内容后持有者读到新版本。
    pub fn rule_set(&self, tag: &str) -> Option<RuleSetSlot> {
        self.routes.rule_set(tag).cloned()
    }
    pub fn native_credentials(&self) -> &[Value] {
        &self.native
    }
    pub fn is_local(&self) -> bool {
        self.local
    }
    pub fn credentials<C>(&self, rows: Vec<C>) -> Result<CredentialSet<C>> {
        self.issuer.bind(rows)
    }
    pub fn with_options(&self, options: Value) -> Self {
        Self {
            options,
            ..self.clone()
        }
    }
    pub fn issuer(&self) -> CredentialIssuer {
        self.issuer.clone()
    }
    pub fn for_test(options: Value, native_credentials: Vec<Value>) -> Self {
        Self::for_test_with_disabled(options, native_credentials, &[])
    }
    /// 与 `for_test` 相同，但 `disabled` 列出的下标对应已停用成员。
    pub fn for_test_with_disabled(
        options: Value,
        native_credentials: Vec<Value>,
        disabled: &[usize],
    ) -> Self {
        let members = native_credentials
            .iter()
            .enumerate()
            .map(|(index, _)| Membership {
                user: UserId::generate(),
                credential_epoch: 1,
                enabled: !disabled.contains(&index),
            })
            .collect();
        Self {
            options,
            native: Arc::new(native_credentials),
            issuer: CredentialIssuer::new(
                NodeId::parse("test-node").expect("固定测试标识"),
                1,
                members,
            )
            .expect("固定测试代次"),
            local: false,
            routing_mark: None,
            bypass_marks: Arc::default(),
            routes: RouteTable::default(),
        }
    }
    pub fn local_for_test(options: Value) -> Self {
        let mut value = Self::for_test(options, Vec::new());
        value.local = true;
        value
    }
}

pub trait NodeFactory: Send + Sync {
    fn kind(&self) -> &'static str;
    fn allows_local_inbound(&self) -> bool {
        false
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>>;
}
pub trait OutboundFactory: Send + Sync {
    fn kind(&self) -> &'static str;
    /// 出站的全部载体套接字是否经 `DialerOptions::connect`/`udp_peer` 建立，从而能经
    /// `detour` 上游承载。返回 `false` 时配置了 `detour` 的出站在加载阶段被拒绝。
    fn supports_detour(&self) -> bool {
        false
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan>;
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardSpec {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: ForwardKind,
    pub listen: SocketAddr,
    #[serde(default)]
    pub target: TargetSpec,
    #[serde(default, alias = "follow-redirect")]
    pub follow_redirect: bool,
    pub outbound: String,
    #[serde(default)]
    pub mode: NodeMode,
    #[serde(default)]
    pub require_remote_eof: bool,
    #[serde(default, alias = "accept-proxy-protocol")]
    pub accept_proxy_protocol: bool,
    #[serde(default)]
    pub sniff: Option<bool>,
    #[serde(default, alias = "sniff-override-destination")]
    pub sniff_override_destination: Option<bool>,
    #[serde(default, alias = "sniff-timeout")]
    pub sniff_timeout: Option<DurationSpec>,
    #[serde(default)]
    pub sniffing: Option<InboundSniffingSpec>,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum ForwardKind {
    #[serde(rename = "tcp-forward")]
    Tcp,
    #[serde(rename = "udp-forward")]
    Udp,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSpec {
    pub host: String,
    pub port: u16,
}
impl TargetSpec {
    pub fn is_empty(&self) -> bool {
        self.host.is_empty() && self.port == 0
    }
    pub fn destination(&self) -> Result<Destination> {
        Destination::new(&self.host, self.port)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DurationSpec {
    Seconds(u64),
    Text(String),
}
impl DurationSpec {
    pub fn to_duration(&self) -> Result<Duration> {
        match self {
            Self::Seconds(secs) => {
                if *secs == 0 || *secs > 86_400 {
                    return Err(Error::Config("时长秒数须在 1 至 86400 之间".into()));
                }
                Ok(Duration::from_secs(*secs))
            }
            Self::Text(raw) => {
                let s = raw.trim();
                let ms = parse_go_duration_ms(s)?;
                if !(1..=86_400_000).contains(&ms) {
                    return Err(Error::Config("时长须在 1ms 至 24h 之间".into()));
                }
                Ok(Duration::from_millis(ms))
            }
        }
    }
}

pub fn parse_go_duration_ms(s: &str) -> Result<u64> {
    if s.is_empty() {
        return Err(Error::Config("时长格式不合法".into()));
    }
    if let Ok(plain_secs) = s.parse::<u64>() {
        return Ok(plain_secs.saturating_mul(1000));
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut total_ms = 0u64;
    let mut matched_any = false;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let num_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if i == num_start {
            return Err(Error::Config("时长格式不合法".into()));
        }
        let num_str = &s[num_start..i];
        let val: f64 = num_str
            .parse()
            .map_err(|_| Error::Config("时长数值不合法".into()))?;
        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = &s[unit_start..i];
        let scale_ms = match unit {
            "ms" => 1.0,
            "s" | "" => 1000.0,
            "m" => 60_000.0,
            "h" => 3_600_000.0,
            "d" => 86_400_000.0,
            _ => return Err(Error::Config("时长单位不合法".into())),
        };
        total_ms = total_ms.saturating_add((val * scale_ms).round() as u64);
        matched_any = true;
    }
    if !matched_any {
        return Err(Error::Config("时长格式不合法".into()));
    }
    Ok(total_ms)
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalDialerSpec {
    #[serde(alias = "interface-name", alias = "bind-interface")]
    pub interface: Option<String>,
    #[serde(alias = "auto-detect-interface")]
    pub auto_detect_interface: bool,
    #[serde(alias = "routing-mark", alias = "mark")]
    pub routing_mark: Option<u32>,
    #[serde(alias = "tfo", alias = "tcp-fast-open")]
    pub tcp_fast_open: bool,
    #[serde(alias = "disable-keep-alive", alias = "disable-tcp-keep-alive")]
    pub disable_tcp_keep_alive: bool,
    #[serde(
        alias = "keep-alive-idle",
        alias = "tcp-keep-alive",
        alias = "tcp-keep-alive-idle"
    )]
    pub tcp_keep_alive_idle: Option<DurationSpec>,
    #[serde(alias = "keep-alive-interval", alias = "tcp-keep-alive-interval")]
    pub tcp_keep_alive_interval: Option<DurationSpec>,
    #[serde(alias = "tcp_multi_path", alias = "tcp-multi-path")]
    pub mptcp: bool,
    #[serde(alias = "fallback-delay")]
    pub fallback_delay: Option<DurationSpec>,
    #[serde(alias = "inet4-bind-address")]
    pub inet4_bind_address: Option<std::net::Ipv4Addr>,
    #[serde(alias = "inet6-bind-address")]
    pub inet6_bind_address: Option<std::net::Ipv6Addr>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteConfigSpec {
    #[serde(alias = "auto-detect-interface")]
    pub auto_detect_interface: bool,
    #[serde(alias = "default-interface")]
    pub default_interface: Option<String>,
    #[serde(alias = "default-mark")]
    pub default_mark: Option<u32>,
    #[serde(alias = "default-domain-resolver")]
    pub default_domain_resolver: Option<Value>,
    #[serde(default, alias = "rule-set")]
    pub rule_set: Vec<RuleSetSpec>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
    #[serde(default, alias = "sub-rules")]
    pub sub_rules: BTreeMap<String, Vec<RuleSpec>>,
    #[serde(default)]
    pub balancers: Vec<BalancerSpec>,
    #[serde(rename = "final", alias = "final_outbound", alias = "final-outbound")]
    pub final_outbound: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExperimentalSpec {
    #[serde(alias = "cache-file")]
    pub cache_file: Option<kerlico_dns::CacheFileSpec>,
    #[serde(alias = "clash-api")]
    pub clash_api: Option<ClashApiSpec>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClashApiSpec {
    #[serde(alias = "external-controller")]
    pub external_controller: Option<SocketAddr>,
    #[serde(alias = "external-ui")]
    pub external_ui: Option<String>,
    #[serde(alias = "external-ui-download-url")]
    pub external_ui_download_url: Option<String>,
    #[serde(alias = "external-ui-download-detour")]
    pub external_ui_download_detour: Option<String>,
    pub secret: Option<String>,
    #[serde(alias = "default-mode")]
    pub default_mode: Option<String>,
    #[serde(alias = "access-control-allow-origin")]
    pub access_control_allow_origin: Vec<String>,
    #[serde(alias = "access-control-allow-private-network")]
    pub access_control_allow_private_network: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileCacheSpec {
    #[serde(alias = "store-selected")]
    pub store_selected: Option<bool>,
    #[serde(alias = "store-fake-ip")]
    pub store_fake_ip: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SniffProtoPortSpec {
    #[serde(default)]
    pub ports: Vec<Value>,
    #[serde(alias = "override-destination")]
    pub override_destination: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalSnifferSpec {
    #[serde(alias = "enabled")]
    pub enable: Option<bool>,
    #[serde(alias = "override-destination")]
    pub override_destination: Option<bool>,
    #[serde(alias = "force-dns-mapping")]
    pub force_dns_mapping: Option<bool>,
    #[serde(alias = "parse-pure-ip")]
    pub parse_pure_ip: Option<bool>,
    #[serde(default, alias = "force-domain")]
    pub force_domain: Vec<String>,
    #[serde(default, alias = "skip-domain", alias = "domains-excluded")]
    pub skip_domain: Vec<String>,
    #[serde(default, alias = "skip-src-address")]
    pub skip_src_address: Vec<String>,
    #[serde(default, alias = "skip-dst-address")]
    pub skip_dst_address: Vec<String>,
    #[serde(default)]
    pub sniff: BTreeMap<String, SniffProtoPortSpec>,
    #[serde(default, alias = "sniff-ports")]
    pub sniff_ports: BTreeMap<String, Vec<Value>>,
    /// Mihomo 旧写法：`sniffing` 协议列表配 `port-whitelist`。
    #[serde(default)]
    pub sniffing: Vec<String>,
    #[serde(default, alias = "port-whitelist")]
    pub port_whitelist: Vec<Value>,
    pub timeout: Option<DurationSpec>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InboundSniffingSpec {
    #[serde(alias = "enable")]
    pub enabled: Option<bool>,
    #[serde(default, alias = "destOverride", alias = "dest-override")]
    pub dest_override: Vec<String>,
    #[serde(alias = "routeOnly", alias = "route-only")]
    pub route_only: Option<bool>,
    #[serde(
        default,
        alias = "domainsExcluded",
        alias = "domains-excluded",
        alias = "skip-domain"
    )]
    pub domains_excluded: Vec<String>,
    #[serde(default, alias = "force-domain")]
    pub force_domain: Vec<String>,
    pub timeout: Option<DurationSpec>,
}

fn parse_port_range_entry(val: &Value) -> Result<(u16, u16)> {
    match val {
        Value::Number(n) => {
            let p = n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| Error::Config("嗅探端口必须为 1..=65535".into()))?;
            Ok((p, p))
        }
        Value::String(s) => {
            let trimmed = s.trim();
            if let Some((a, b)) = trimmed.split_once('-').or_else(|| trimmed.split_once(':')) {
                let start: u16 = a
                    .trim()
                    .parse()
                    .map_err(|_| Error::Config("嗅探端口范围不合法".into()))?;
                let end: u16 = b
                    .trim()
                    .parse()
                    .map_err(|_| Error::Config("嗅探端口范围不合法".into()))?;
                if start == 0 || end == 0 || start > end {
                    return Err(Error::Config("嗅探端口范围起止不合法".into()));
                }
                Ok((start, end))
            } else {
                let p: u16 = trimmed
                    .parse()
                    .map_err(|_| Error::Config("嗅探端口不合法".into()))?;
                if p == 0 {
                    return Err(Error::Config("嗅探端口不能为 0".into()));
                }
                Ok((p, p))
            }
        }
        _ => Err(Error::Config("嗅探端口项须为整数或范围字符串".into())),
    }
}

/// 规范协议名；与 `kerlico_net::sniff::SniffProtocol::parse` 的别名一致。
fn sniffer_name(raw: &str) -> Result<String> {
    let name = raw.trim().to_ascii_lowercase();
    Ok(match name.as_str() {
        "tls" | "https" | "ssl" => "tls",
        "http" => "http",
        "quic" => "quic",
        "bittorrent" | "bt" => "bittorrent",
        "dtls" => "dtls",
        "stun" => "stun",
        "ssh" => "ssh",
        "rdp" => "rdp",
        // Xray `destOverride` 的 fakedns 由 Fake-IP 反查覆盖，不是字节嗅探器。
        "fakedns" | "fakedns+others" => return Ok(String::new()),
        _ => return Err(Error::Config(format!("不支持的嗅探协议：{raw}"))),
    }
    .to_owned())
}

/// Mihomo 嗅探器未写端口时的默认端口。
fn mihomo_default_ports(protocol: &str) -> Vec<(u16, u16)> {
    match protocol {
        "tls" | "quic" => vec![(443, 443)],
        "http" => vec![(80, 80)],
        _ => Vec::new(),
    }
}

fn sniff_ips(items: &[String], field: &str) -> Result<Vec<kerlico_core::IpMatch>> {
    let mut out = Vec::new();
    for item in items {
        out.extend(kerlico_core::IpMatch::parse_entry(
            item,
            &format!("sniffer.{field}"),
        )?);
    }
    Ok(out)
}

fn sniff_domains(items: &[String]) -> Vec<kerlico_core::DomainMatch> {
    items
        .iter()
        .flat_map(|item| kerlico_core::DomainMatch::parse_entry(item))
        .collect()
}

impl GlobalSnifferSpec {
    /// 按 Mihomo `sniffer:` 默认值：`enable` false，`override-destination`、`parse-pure-ip`、
    /// `force-dns-mapping` 均为 true；超时沿用 Mihomo 的 1 秒首包窗口。
    pub fn to_policy(&self) -> Result<kerlico_core::SniffPolicy> {
        let override_destination = self.override_destination.unwrap_or(true);
        let mut policy = kerlico_core::SniffPolicy {
            enabled: self.enable.unwrap_or(false),
            override_destination,
            targets: kerlico_core::SniffTargets::Mihomo {
                parse_pure_ip: self.parse_pure_ip.unwrap_or(true),
                force_dns_mapping: self.force_dns_mapping.unwrap_or(true),
            },
            timeout: std::time::Duration::from_secs(1),
            skip_domain: sniff_domains(&self.skip_domain),
            force_domain: sniff_domains(&self.force_domain),
            skip_src_address: sniff_ips(&self.skip_src_address, "skip-src-address")?,
            skip_dst_address: sniff_ips(&self.skip_dst_address, "skip-dst-address")?,
            ..Default::default()
        };
        if let Some(timeout) = &self.timeout {
            policy.timeout = timeout.to_duration()?;
        }
        let mut push = |raw: &str, items: &[Value], over: Option<bool>| -> Result<()> {
            let protocol = sniffer_name(raw)?;
            if protocol.is_empty() || policy.sniffers.iter().any(|r| r.protocol == protocol) {
                return Ok(());
            }
            let mut ports = items
                .iter()
                .map(parse_port_range_entry)
                .collect::<Result<Vec<_>>>()?;
            if ports.is_empty() {
                ports = mihomo_default_ports(&protocol);
            }
            policy.sniffers.push(kerlico_core::SnifferRule {
                protocol,
                ports,
                override_destination: over,
            });
            Ok(())
        };
        if !self.sniff.is_empty() {
            for (proto, spec) in &self.sniff {
                push(proto, &spec.ports, spec.override_destination)?;
            }
        } else {
            for proto in &self.sniffing {
                let ports = self.sniff_ports.get(proto).unwrap_or(&self.port_whitelist);
                push(proto, ports, None)?;
            }
            for (proto, items) in &self.sniff_ports {
                push(proto, items, None)?;
            }
        }
        // Mihomo 按 TLS、HTTP、QUIC 固定顺序尝试，与 map 书写顺序无关。
        let rank = |p: &str| match p {
            "tls" => 0,
            "http" => 1,
            "quic" => 2,
            _ => 3,
        };
        policy.sniffers.sort_by_key(|rule| rank(&rule.protocol));
        Ok(policy)
    }
}

/// 入站级 `sniff`/`sniffing`（sing-box、Xray 写法）：嗅探全部连接，覆盖目标需显式开启。
fn apply_inbound_sniffing(
    policy: &mut kerlico_core::SniffPolicy,
    sniff: Option<bool>,
    override_dest: Option<bool>,
    timeout: Option<&DurationSpec>,
    sniffing: Option<&InboundSniffingSpec>,
) -> Result<()> {
    if sniff.is_none() && sniffing.is_none() && override_dest.is_none() && timeout.is_none() {
        return Ok(());
    }
    let inherited = policy.enabled;
    if sniff.is_some() || sniffing.is_some() {
        policy.targets = kerlico_core::SniffTargets::All;
        policy.override_destination = false;
        if !inherited {
            policy.sniffers.clear();
        }
    }
    if let Some(en) = sniff {
        policy.enabled = en;
    }
    if let Some(ov) = override_dest {
        policy.override_destination = ov;
    }
    if let Some(tm) = timeout {
        policy.timeout = tm.to_duration()?;
    }
    if let Some(sn) = sniffing {
        policy.enabled = sn.enabled.unwrap_or(true);
        if !sn.dest_override.is_empty() {
            policy.sniffers.clear();
            for raw in &sn.dest_override {
                let protocol = sniffer_name(raw)?;
                if !protocol.is_empty() {
                    policy.sniffers.push(kerlico_core::SnifferRule {
                        protocol,
                        ports: Vec::new(),
                        override_destination: None,
                    });
                }
            }
            if override_dest.is_none() {
                policy.override_destination = true;
            }
        }
        if let Some(ro) = sn.route_only {
            policy.route_only = ro;
        }
        let patterns = |items: &[String]| {
            items
                .iter()
                .map(|item| kerlico_core::DomainMatch::Pattern(item.trim().to_owned()))
                .collect()
        };
        if !sn.domains_excluded.is_empty() {
            policy.skip_domain = patterns(&sn.domains_excluded);
        }
        if !sn.force_domain.is_empty() {
            policy.force_domain = patterns(&sn.force_domain);
        }
        if let Some(tm) = &sn.timeout {
            policy.timeout = tm.to_duration()?;
        }
    }
    Ok(())
}

fn extract_sniff_policy(
    options: &mut Value,
    base: &kerlico_core::SniffPolicy,
) -> Result<kerlico_core::SniffPolicy> {
    let mut policy = base.clone();
    let Some(map) = options.as_object_mut() else {
        return Ok(policy);
    };
    let sniff = match map.remove("sniff") {
        Some(v) => Some(
            v.as_bool()
                .ok_or_else(|| Error::Config("sniff 须为布尔值".into()))?,
        ),
        None => None,
    };
    let mut override_dest = None;
    for key in ["sniff_override_destination", "sniff-override-destination"] {
        if let Some(v) = map.remove(key) {
            override_dest =
                Some(v.as_bool().ok_or_else(|| {
                    Error::Config("sniff_override_destination 须为布尔值".into())
                })?);
        }
    }
    let mut timeout = None;
    for key in ["sniff_timeout", "sniff-timeout"] {
        if let Some(v) = map.remove(key) {
            let spec: DurationSpec = serde_json::from_value(v)
                .map_err(|_| Error::Config("sniff_timeout 时长不合法".into()))?;
            timeout = Some(spec);
        }
    }
    let sniffing = match map.remove("sniffing") {
        Some(v) => {
            let spec: InboundSniffingSpec = serde_json::from_value(v)
                .map_err(|_| Error::Config("sniffing 配置不合法".into()))?;
            Some(spec)
        }
        None => None,
    };
    apply_inbound_sniffing(
        &mut policy,
        sniff,
        override_dest,
        timeout.as_ref(),
        sniffing.as_ref(),
    )?;
    Ok(policy)
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RootCertificateSpec {
    pub store: Option<String>,
    #[serde(alias = "use-system-ca")]
    pub use_system_ca: bool,
    #[serde(default)]
    pub certificate: Vec<String>,
    #[serde(default, alias = "certificate-path")]
    pub certificate_path: Vec<std::path::PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns01ChallengeSpec {
    pub provider: String,
    #[serde(default, alias = "api-token")]
    pub api_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateProviderSpec {
    pub tag: String,
    #[serde(rename = "type", default = "default_acme_type")]
    pub kind: String,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, alias = "data-directory")]
    pub data_directory: Option<std::path::PathBuf>,
    #[serde(default, alias = "key-type")]
    pub key_type: Option<String>,
    #[serde(default, alias = "alternative-http-port")]
    pub alternative_http_port: Option<u16>,
    #[serde(default, alias = "alternative-tls-port")]
    pub alternative_tls_port: Option<u16>,
    #[serde(default, alias = "disable-http-challenge")]
    pub disable_http_challenge: bool,
    #[serde(default, alias = "disable-tls-alpn-challenge")]
    pub disable_tls_alpn_challenge: bool,
    #[serde(default, alias = "dns01-challenge")]
    pub dns01_challenge: Option<Dns01ChallengeSpec>,
}
fn default_acme_type() -> String {
    "acme".into()
}
impl CertificateProviderSpec {
    pub fn validate(&self) -> Result<()> {
        if self.tag.trim().is_empty()
            || !matches!(self.kind.as_str(), "acme")
            || self.domain.is_empty()
            || self.domain.iter().any(|d| d.trim().is_empty())
            || self.alternative_http_port == Some(0)
            || self.alternative_tls_port == Some(0)
        {
            return Err(Error::Config("证书提供者配置不合法".into()));
        }
        if let Some(key_type) = &self.key_type
            && !matches!(
                key_type.as_str(),
                "ec256" | "ec384" | "ed25519" | "rsa2048" | "rsa4096"
            )
        {
            return Err(Error::Config("不支持的 ACME 密钥类型".into()));
        }
        if let Some(dns01) = &self.dns01_challenge
            && (!dns01.provider.eq_ignore_ascii_case("cloudflare")
                || dns01
                    .api_token
                    .as_deref()
                    .is_none_or(|t| t.trim().is_empty()))
        {
            return Err(Error::Config(
                "DNS-01 质询必须提供合法提供商与非空 api_token".into(),
            ));
        }
        Ok(())
    }
}

fn apply_dialer_map(
    map: &mut serde_json::Map<String, Value>,
    out: &mut kerlico_core::DialerOptions,
) -> Result<()> {
    for key in [
        "interface",
        "interface_name",
        "interface-name",
        "bind_interface",
        "bind-interface",
    ] {
        if let Some(val) = map.remove(key) {
            let s = val
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::Config("绑定网卡名须为非空字符串".into()))?;
            out.interface = Some(kerlico_core::InterfaceBinding::Named(s.to_owned()));
        }
    }
    for key in ["inet4_bind_address", "inet4-bind-address"] {
        if let Some(val) = map.remove(key) {
            out.bind_v4 = Some(
                val.as_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::Config("inet4_bind_address 须为 IPv4 地址".into()))?,
            );
        }
    }
    for key in ["inet6_bind_address", "inet6-bind-address"] {
        if let Some(val) = map.remove(key) {
            out.bind_v6 = Some(
                val.as_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::Config("inet6_bind_address 须为 IPv6 地址".into()))?,
            );
        }
    }
    for key in ["mptcp", "tcp_multi_path", "tcp-multi-path"] {
        if let Some(val) = map.remove(key) {
            out.mptcp = val
                .as_bool()
                .ok_or_else(|| Error::Config("mptcp 须为布尔值".into()))?;
        }
    }
    for key in ["fallback_delay", "fallback-delay"] {
        if let Some(val) = map.remove(key) {
            let spec: DurationSpec = serde_json::from_value(val)
                .map_err(|_| Error::Config("fallback_delay 时长不合法".into()))?;
            out.fallback_delay = Some(spec.to_duration()?);
        }
    }
    for key in ["detour", "dialer_proxy", "dialer-proxy"] {
        if let Some(val) = map.remove(key) {
            let s = val
                .as_str()
                .ok_or_else(|| Error::Config("链式拨号目标标签须为字符串".into()))?;
            out.detour = Some(OutId::parse(s)?);
        }
    }
    for key in ["proxy_settings", "proxy-settings", "proxySettings"] {
        if let Some(val) = map.remove(key) {
            let obj = val
                .as_object()
                .ok_or_else(|| Error::Config("proxy_settings 须为对象".into()))?;
            if let Some(tag) = obj.get("tag").and_then(Value::as_str) {
                out.detour = Some(OutId::parse(tag)?);
            } else {
                return Err(Error::Config("proxy_settings 缺少有效的 tag 字段".into()));
            }
        }
    }
    for key in ["routing_mark", "routing-mark", "mark"] {
        if let Some(val) = map.remove(key) {
            let mark = val
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| Error::Config("routing_mark 须为 32 位无符号整数".into()))?;
            out.routing_mark = Some(mark);
        }
    }
    for key in ["tfo", "tcp_fast_open", "tcp-fast-open", "tcpFastOpen"] {
        if let Some(val) = map.remove(key) {
            let enabled = val
                .as_bool()
                .ok_or_else(|| Error::Config("tcp_fast_open 须为布尔值".into()))?;
            out.tcp_fast_open = enabled;
        }
    }
    for key in [
        "disable_tcp_keep_alive",
        "disable-tcp-keep-alive",
        "disable_keep_alive",
        "disable-keep-alive",
    ] {
        if let Some(val) = map.remove(key) {
            let disabled = val
                .as_bool()
                .ok_or_else(|| Error::Config("disable_tcp_keep_alive 须为布尔值".into()))?;
            out.disable_tcp_keep_alive = disabled;
        }
    }
    for key in [
        "tcp_keep_alive",
        "tcp-keep-alive",
        "keep_alive_idle",
        "keep-alive-idle",
        "tcp_keep_alive_idle",
        "tcp-keep-alive-idle",
        "tcpKeepAliveIdle",
    ] {
        if let Some(val) = map.remove(key) {
            let spec: DurationSpec = serde_json::from_value(val)
                .map_err(|_| Error::Config("tcp_keep_alive_idle 时长不合法".into()))?;
            out.tcp_keep_alive_idle = Some(spec.to_duration()?);
        }
    }
    for key in [
        "tcp_keep_alive_interval",
        "tcp-keep-alive-interval",
        "keep_alive_interval",
        "keep-alive-interval",
        "tcpKeepAliveInterval",
    ] {
        if let Some(val) = map.remove(key) {
            let spec: DurationSpec = serde_json::from_value(val)
                .map_err(|_| Error::Config("tcp_keep_alive_interval 时长不合法".into()))?;
            out.tcp_keep_alive_interval = Some(spec.to_duration()?);
        }
    }
    Ok(())
}

/// 全局出口网卡：显式网卡名（Mihomo `interface-name`、`dialer.interface`、sing-box
/// `route.default_interface`）优先；否则 `auto_detect_interface` 取默认路由网卡并跳过本配置的 TUN。
fn global_interface(config: &Config) -> Option<kerlico_core::InterfaceBinding> {
    let named = [
        config.interface_name.as_deref(),
        config.dialer.interface.as_deref(),
        config
            .route
            .as_ref()
            .and_then(|r| r.default_interface.as_deref()),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .find(|name| !name.is_empty());
    if let Some(name) = named {
        return Some(kerlico_core::InterfaceBinding::Named(name.to_owned()));
    }
    let tun = tun::interface(config.local_inbounds.iter().chain(&config.nodes));
    if let Some(binding @ kerlico_core::InterfaceBinding::Named(_)) = &tun {
        return Some(binding.clone());
    }
    let auto = config.dialer.auto_detect_interface
        || tun.is_some()
        || config
            .route
            .as_ref()
            .is_some_and(|r| r.auto_detect_interface);
    auto.then(|| kerlico_core::InterfaceBinding::AutoDetect {
        exclude: config
            .local_inbounds
            .iter()
            .chain(&config.nodes)
            .filter(|node| node.kind == "tun")
            .map(|node| {
                ["name", "interface_name", "interface-name", "device"]
                    .iter()
                    .find_map(|key| node.options.get(key).and_then(Value::as_str))
                    .unwrap_or("kerlico0")
                    .to_owned()
            })
            .collect(),
    })
}

fn extract_dialer_options(
    options: &mut Value,
    base: &kerlico_core::DialerOptions,
) -> Result<kerlico_core::DialerOptions> {
    let mut dialer = base.clone();
    let Some(map) = options.as_object_mut() else {
        return Ok(dialer);
    };
    for sub_key in ["dialer", "sockopt"] {
        if let Some(mut sub) = map.remove(sub_key) {
            let sub_map = sub
                .as_object_mut()
                .ok_or_else(|| Error::Config("dialer/sockopt 须为对象".into()))?;
            apply_dialer_map(sub_map, &mut dialer)?;
        }
    }
    apply_dialer_map(map, &mut dialer)?;
    Ok(dialer)
}

fn extract_accept_proxy_protocol(options: &mut Value) -> Result<bool> {
    let Some(map) = options.as_object_mut() else {
        return Ok(false);
    };
    let mut enabled = false;
    for key in [
        "accept_proxy_protocol",
        "accept-proxy-protocol",
        "acceptProxyProtocol",
    ] {
        if let Some(val) = map.remove(key) {
            enabled |= val
                .as_bool()
                .ok_or_else(|| Error::Config("accept_proxy_protocol 须为布尔值".into()))?;
        }
    }
    if let Some(sockopt) = map.get_mut("sockopt").and_then(Value::as_object_mut) {
        for key in [
            "accept_proxy_protocol",
            "accept-proxy-protocol",
            "acceptProxyProtocol",
        ] {
            if let Some(val) = sockopt.remove(key) {
                enabled |= val
                    .as_bool()
                    .ok_or_else(|| Error::Config("accept_proxy_protocol 须为布尔值".into()))?;
            }
        }
        if sockopt.is_empty() {
            map.remove("sockopt");
        }
    }
    if let Some(transport) = map.get_mut("transport").and_then(Value::as_object_mut) {
        for key in [
            "accept_proxy_protocol",
            "accept-proxy-protocol",
            "acceptProxyProtocol",
        ] {
            if let Some(val) = transport.remove(key) {
                enabled |= val
                    .as_bool()
                    .ok_or_else(|| Error::Config("accept_proxy_protocol 须为布尔值".into()))?;
            }
        }
    }
    Ok(enabled)
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub connect_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub drain_timeout_ms: u64,
    pub max_sessions: usize,
    pub udp_queue_packets: usize,
    pub max_datagram_size: usize,
    pub max_flow_records: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            idle_timeout_ms: 60_000,
            drain_timeout_ms: 5_000,
            max_sessions: 128,
            udp_queue_packets: 32,
            max_datagram_size: 65_535,
            max_flow_records: 65_536,
        }
    }
}
impl Limits {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }
    pub fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.drain_timeout_ms)
    }
    fn validate(&self) -> Result<()> {
        if !(1..=300_000).contains(&self.connect_timeout_ms)
            || !(1..=86_400_000).contains(&self.idle_timeout_ms)
            || !(1..=300_000).contains(&self.drain_timeout_ms)
            || !(1..=65_536).contains(&self.max_sessions)
            || !(1..=4096).contains(&self.udp_queue_packets)
            || !(1..=65_535).contains(&self.max_datagram_size)
            || !(self.max_sessions..=1_048_576).contains(&self.max_flow_records)
        {
            return Err(Error::Config("资源限制超出支持范围".into()));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct Registry {
    factories: BTreeMap<&'static str, Arc<dyn OutboundFactory>>,
    node_factories: BTreeMap<&'static str, Arc<dyn NodeFactory>>,
}
impl Registry {
    pub fn register(&mut self, factory: impl OutboundFactory + 'static) -> Result<()> {
        let kind = factory.kind();
        if self.factories.contains_key(kind) {
            return Err(Error::Config("模块类型重复注册".into()));
        }
        self.factories.insert(kind, Arc::new(factory));
        Ok(())
    }
    pub fn register_node(&mut self, factory: impl NodeFactory + 'static) -> Result<()> {
        let kind = factory.kind();
        if self.node_factories.contains_key(kind) {
            return Err(Error::Config("节点类型重复注册".into()));
        }
        self.node_factories.insert(kind, Arc::new(factory));
        Ok(())
    }
    pub fn kinds(&self) -> impl Iterator<Item = &&'static str> {
        self.factories.keys()
    }
    pub fn node_kinds(&self) -> impl Iterator<Item = &&'static str> {
        self.node_factories.keys()
    }

    /// 只校验与编译计划，不启动后端、创建状态文件、监听或配置设备。
    pub fn prepare(&self, mut config: Config) -> Result<PreparedConfig> {
        if config.version != 2 {
            return Err(Error::Config(
                "仅支持配置版本 2；请按 docs/config-v2-migration.md 迁移账户、成员和原生凭据"
                    .into(),
            ));
        }
        if config.epoch == 0 {
            return Err(Error::Config("配置代次必须大于零".into()));
        }
        config.limits.validate()?;
        if let Some(loader) = &config.geodata_loader
            && !matches!(
                loader.trim().to_ascii_lowercase().as_str(),
                "standard" | "memconservative"
            )
        {
            return Err(Error::Config(
                "geodata-loader 仅支持 standard 或 memconservative".into(),
            ));
        }
        if let Some(matcher) = &config.geosite_matcher
            && !matches!(
                matcher.trim().to_ascii_lowercase().as_str(),
                "mph" | "succinct" | "default"
            )
        {
            return Err(Error::Config(
                "geosite-matcher 仅支持 mph、succinct 或 default".into(),
            ));
        }
        let geo_spec = GeoConfigSpec {
            geo_auto_update: config.geo_auto_update.unwrap_or(false),
            geo_update_interval: config
                .geo_update_interval
                .map(|v| {
                    u32::try_from(v).map_err(|_| Error::Config("Geo 自动更新间隔不合法".into()))
                })
                .transpose()?,
            geox_url: config.geox_url.clone(),
            ..Default::default()
        };
        geo_spec.validate()?;
        let base_sniff_policy = match &config.sniffer {
            Some(sniffer) => sniffer.to_policy()?,
            None => kerlico_core::SniffPolicy::default(),
        };
        if config.allow_lan == Some(true) && config.lan_allowed_ips.is_empty() {
            config.lan_allowed_ips.push("0.0.0.0/0".into());
            config.lan_allowed_ips.push("::/0".into());
        }
        let lan_filter =
            kerlico_core::IpFilter::compile(&config.lan_allowed_ips, &config.lan_disallowed_ips)?;
        let any_address = config.bind_address.as_deref().map(str::trim) == Some("*");
        let shortcut_ip: std::net::IpAddr = match config.bind_address.as_deref().map(str::trim) {
            Some("*" | "0.0.0.0") => std::net::IpAddr::from([0, 0, 0, 0]),
            Some(addr) if !addr.is_empty() => addr
                .parse()
                .map_err(|_| Error::Config("bind-address 地址不合法".into()))?,
            _ if config.allow_lan == Some(true) => std::net::IpAddr::from([0, 0, 0, 0]),
            _ => std::net::IpAddr::from([127, 0, 0, 1]),
        };
        let default_outbound = config
            .outbounds
            .first()
            .map(|spec| spec.tag.clone())
            .or_else(|| config.proxy_groups.first().map(|g| g.name.clone()));
        for (port_opt, tag, kind) in [
            (config.port, "http-in", "http"),
            (config.socks_port, "socks-in", "socks"),
            (config.mixed_port, "mixed-in", "mixed"),
            (config.redir_port, "redir-in", "redirect"),
            (config.tproxy_port, "tproxy-in", "tproxy"),
        ] {
            if let Some(port) = port_opt {
                if port == 0 {
                    return Err(Error::Config("快捷入站端口不能为 0".into()));
                }
                let Some(outbound) = default_outbound.clone() else {
                    return Err(Error::Config(
                        "启用快捷入站端口时必须至少配置一个出站".into(),
                    ));
                };
                // 透明代理依赖按族的原始目标选项，保持 IPv4 监听。
                let dual_stack = any_address && !matches!(kind, "redirect" | "tproxy");
                let ip = if dual_stack {
                    std::net::IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED)
                } else {
                    shortcut_ip
                };
                config.local_inbounds.push(NodeSpec {
                    tag: tag.into(),
                    kind: kind.into(),
                    listen: SocketAddr::new(ip, port),
                    outbound,
                    mode: NodeMode::Dual,
                    options: empty_object(),
                    members: Vec::new(),
                    max_sessions: None,
                    accept_proxy_protocol: false,
                    sniff: None,
                    sniff_override_destination: None,
                    sniff_timeout: None,
                    sniffing: None,
                    dual_stack,
                });
            }
        }
        if let Some(mut tun_val) = config.tun.take() {
            let map = tun_val
                .as_object_mut()
                .ok_or_else(|| Error::Config("tun 顶层配置必须为对象".into()))?;
            let enabled = match map.remove("enable").or_else(|| map.remove("enabled")) {
                Some(v) => v
                    .as_bool()
                    .ok_or_else(|| Error::Config("tun.enable 须为布尔值".into()))?,
                None => true,
            };
            if enabled {
                let tag = match map.remove("tag") {
                    Some(v) => v
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| Error::Config("tun.tag 须为字符串".into()))?,
                    None => "tun-in".to_owned(),
                };
                let listen = match map.remove("listen") {
                    Some(v) => serde_json::from_value(v)
                        .map_err(|_| Error::Config("tun.listen 地址不合法".into()))?,
                    None => SocketAddr::from(([127, 0, 0, 1], 0)),
                };
                let outbound = match map.remove("outbound") {
                    Some(v) => v
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| Error::Config("tun.outbound 须为字符串".into()))?,
                    None => default_outbound.clone().ok_or_else(|| {
                        Error::Config("启用顶层 tun 时必须至少配置一个出站".into())
                    })?,
                };
                config.local_inbounds.push(NodeSpec {
                    tag,
                    kind: "tun".into(),
                    listen,
                    outbound,
                    mode: NodeMode::Dual,
                    options: tun_val,
                    members: Vec::new(),
                    max_sessions: None,
                    accept_proxy_protocol: false,
                    sniff: None,
                    sniff_override_destination: None,
                    sniff_timeout: None,
                    sniffing: None,
                    dual_stack: false,
                });
            }
        }
        for provider in &config.certificate_providers {
            provider.validate()?;
        }
        for path in &config.certificate.certificate_path {
            if path.as_os_str().is_empty() {
                return Err(Error::Config("根证书文件路径不能为空".into()));
            }
        }
        let detour_table = kerlico_core::DetourTable::new();
        let global_dialer = kerlico_core::DialerOptions {
            detour: None,
            interface: global_interface(&config),
            routing_mark: match config
                .routing_mark
                .or(config.dialer.routing_mark)
                .or(config.route.as_ref().and_then(|r| r.default_mark))
            {
                Some(mark) => Some(mark),
                None => tun::bypass_mark(config.local_inbounds.iter().chain(&config.nodes))?,
            },
            bind_v4: config.dialer.inet4_bind_address,
            bind_v6: config.dialer.inet6_bind_address,
            tcp_fast_open: config.dialer.tcp_fast_open,
            mptcp: config.dialer.mptcp,
            fallback_delay: match &config.dialer.fallback_delay {
                Some(spec) => Some(spec.to_duration()?),
                None => None,
            },
            disable_tcp_keep_alive: config.disable_keep_alive
                || config.dialer.disable_tcp_keep_alive,
            tcp_keep_alive_idle: match config
                .keep_alive_idle
                .as_ref()
                .or(config.dialer.tcp_keep_alive_idle.as_ref())
            {
                Some(spec) => Some(spec.to_duration()?),
                None => None,
            },
            tcp_keep_alive_interval: match config
                .keep_alive_interval
                .as_ref()
                .or(config.dialer.tcp_keep_alive_interval.as_ref())
            {
                Some(spec) => Some(spec.to_duration()?),
                None => None,
            },
            detour_resolver: Some(detour_table.clone()),
        };
        if let Some(history) = &config.telemetry {
            history.validate()?;
        }
        if let Some(device) = &config.device
            && !device.state_directory.is_absolute()
        {
            return Err(Error::Config("设备状态目录必须是绝对路径".into()));
        }
        if config.fakedns.is_some()
            || config.cache_file.is_some()
            || config
                .experimental
                .as_ref()
                .is_some_and(|e| e.cache_file.is_some())
            || config
                .profile
                .as_ref()
                .is_some_and(|p| p.store_fake_ip.is_some())
        {
            let dns = config.dns.get_or_insert_with(|| DnsSpec {
                servers: vec![kerlico_dns::DnsServerInput::Url("udp://1.1.1.1:53".into())],
                ..Default::default()
            });
            if dns.servers.is_empty() && dns.hosts.is_empty() {
                dns.servers
                    .push(kerlico_dns::DnsServerInput::Url("udp://1.1.1.1:53".into()));
            }
            if dns.fakedns.is_none() {
                dns.fakedns = config.fakedns.clone();
            }
            if dns.cache_file.is_none() {
                dns.cache_file = config.cache_file.clone().or_else(|| {
                    config
                        .experimental
                        .as_ref()
                        .and_then(|e| e.cache_file.clone())
                });
            }
            if let Some(store_fake_ip) = config.profile.as_ref().and_then(|p| p.store_fake_ip) {
                let cf = dns
                    .cache_file
                    .get_or_insert_with(|| kerlico_dns::CacheFileSpec {
                        enabled: store_fake_ip,
                        store_fakeip: store_fake_ip,
                        ..Default::default()
                    });
                cf.store_fakeip |= store_fake_ip;
            }
        }
        let mut compiled_rule_sets: HashMap<String, CompiledRuleSet> = HashMap::new();
        let mut rule_set_sources = Vec::new();
        let sing_box_sets = config
            .rule_set
            .iter()
            .chain(
                config
                    .route
                    .as_ref()
                    .map(|r| r.rule_set.iter())
                    .into_iter()
                    .flatten(),
            )
            .map(RuleSetSpec::source);
        let provider_sets = config.rule_providers.iter().map(|(key, spec)| {
            spec.source(key).map(|mut source| {
                key.trim().clone_into(&mut source.tag);
                source
            })
        });
        for source in sing_box_sets.chain(provider_sets) {
            let source = source?;
            let file = match &source.file {
                None => None,
                Some(file) => match resource::read_cached(&file.path)? {
                    Some(bytes) => Some(bytes),
                    None if file.remote.is_none() => {
                        return Err(Error::Config(format!(
                            "规则集文件不存在：{}（{}）",
                            source.tag,
                            file.path.display()
                        )));
                    }
                    None => None,
                },
            };
            let compiled = source.compile(file.as_deref())?;
            if compiled_rule_sets
                .insert(source.tag.clone(), compiled)
                .is_some()
            {
                return Err(Error::Config("rule-set 标签重复".into()));
            }
            rule_set_sources.push(source);
        }
        if let Some(dns) = &config.dns {
            dns.validate()?;
            for rule in &dns.rules {
                for set_tag in &rule.rule_set {
                    if !compiled_rule_sets.contains_key(set_tag.trim()) {
                        return Err(Error::Config("DNS 规则引用的 rule-set 不存在".into()));
                    }
                }
            }
        }
        if let Some(control) = &config.control
            && (control.secret.as_ref().is_some_and(String::is_empty)
                || (control.secret.is_none() && !control.listen.ip().is_loopback()))
        {
            return Err(Error::Config("非回环控制接口必须配置非空密钥".into()));
        }
        let mut accounts = BTreeMap::new();
        let mut usernames = BTreeSet::new();
        for account in config.accounts {
            let id = account.validate()?;
            if accounts.insert(id, account.enabled).is_some() || !usernames.insert(account.username)
            {
                return Err(Error::Config("管理用户 ID 或用户名重复".into()));
            }
        }
        let mut services = Vec::new();
        let mut profiles = BTreeMap::new();
        let mut detours = BTreeMap::new();
        let log = plan::log_output(&config.log, config.log_level.as_deref())?;
        let mode = plan::run_mode(
            config.mode.as_deref().or(config
                .control
                .as_ref()
                .and_then(|c| c.default_mode.as_deref())),
        )?;
        let mut compiled_providers = BTreeMap::new();
        let mut provider_outbounds = Vec::new();
        for (prov_key, prov_spec) in &config.proxy_providers {
            let (compiled, specs) = prov_spec.compile(prov_key)?;
            if compiled_providers
                .insert(compiled.name.clone(), compiled)
                .is_some()
            {
                return Err(Error::Config("proxy-providers 名称重复".into()));
            }
            provider_outbounds.extend(specs);
        }
        let mut existing_tags: BTreeSet<String> =
            config.outbounds.iter().map(|s| s.tag.clone()).collect();
        let declared_outbounds: Vec<String> =
            config.outbounds.iter().map(|s| s.tag.clone()).collect();
        for spec in provider_outbounds {
            if existing_tags.insert(spec.tag.clone()) {
                config.outbounds.push(spec);
            }
        }
        let group_tags: BTreeSet<String> =
            config.proxy_groups.iter().map(|g| g.name.clone()).collect();
        for (builtin_tag, builtin_kind) in [
            ("DIRECT", "direct"),
            ("REJECT", "reject"),
            ("REJECT-DROP", "reject"),
            ("PASS", "direct"),
        ] {
            let referenced = config
                .proxy_groups
                .iter()
                .any(|g| g.proxies.iter().any(|p| p == builtin_tag))
                || config.routes.iter().any(|r| r.outbound == builtin_tag)
                || config.route.as_ref().is_some_and(|rb| {
                    rb.rules.iter().any(|r| r.outbound == builtin_tag)
                        || rb.final_outbound.as_deref() == Some(builtin_tag)
                        || rb
                            .sub_rules
                            .values()
                            .flatten()
                            .any(|r| r.outbound == builtin_tag)
                })
                || config
                    .sub_rules
                    .values()
                    .flatten()
                    .any(|r| r.outbound == builtin_tag);
            let always = matches!(builtin_tag, "DIRECT" | "REJECT");
            if (referenced || always)
                && !existing_tags.contains(builtin_tag)
                && !group_tags.contains(builtin_tag)
                && self.factories.contains_key(builtin_kind)
            {
                existing_tags.insert(builtin_tag.to_owned());
                config.outbounds.push(OutboundSpec {
                    tag: builtin_tag.to_owned(),
                    kind: builtin_kind.to_owned(),
                    options: empty_object(),
                });
            }
        }
        let mut inline_groups = Vec::new();
        let mut concrete_outbounds = Vec::with_capacity(config.outbounds.len());
        for spec in config.outbounds {
            if ProxyGroupKind::parse(&spec.kind).is_some() {
                let mut map = match spec.options {
                    Value::Object(m) => m,
                    _ => serde_json::Map::new(),
                };
                map.insert("name".into(), Value::String(spec.tag));
                map.insert("type".into(), Value::String(spec.kind));
                let gspec: ProxyGroupSpec = serde_json::from_value(Value::Object(map))
                    .map_err(|_| Error::Config("内联策略组出站配置不合法".into()))?;
                inline_groups.push(gspec);
            } else {
                concrete_outbounds.push(spec);
            }
        }
        let mut static_outbound_kinds = Vec::with_capacity(concrete_outbounds.len());
        let mut bypass_marks: BTreeSet<u32> = global_dialer.routing_mark.into_iter().collect();
        for mut spec in concrete_outbounds {
            let id = OutId::parse(&spec.tag)?;
            if profiles.contains_key(&id) {
                return Err(Error::Config("出站标签重复".into()));
            }
            let factory = self
                .factories
                .get(spec.kind.as_str())
                .ok_or_else(|| Error::Config("出站类型未注册或未编译".into()))?;
            let dialer = extract_dialer_options(&mut spec.options, &global_dialer)?;
            dialer.validate_platform()?;
            bypass_marks.extend(dialer.routing_mark);
            if let Some(upstream) = &dialer.detour {
                if !factory.supports_detour() {
                    return Err(Error::Config(format!(
                        "出站类型 {} 不支持 detour/dialer-proxy",
                        spec.kind
                    )));
                }
                detours.insert(id.clone(), upstream.clone());
            }
            let plan =
                kerlico_core::with_compile_dialer(dialer, || factory.compile(&spec.options))?;
            profiles.insert(
                id.clone(),
                (plan.capabilities(), plan.supports_udp_association()),
            );
            static_outbound_kinds.push((id.clone(), spec.kind.clone()));
            services.push(NamedServicePlan {
                id,
                kind: spec.kind,
                plan,
            });
        }
        let bypass_marks: Arc<Vec<u32>> = Arc::new(bypass_marks.into_iter().collect());
        let mut all_group_specs = inline_groups;
        all_group_specs.extend(config.proxy_groups.iter().cloned());
        if let Some(route_block) = &config.route {
            for bal in &route_block.balancers {
                all_group_specs.push(bal.to_group_spec());
            }
        }
        if !existing_tags.contains(GLOBAL_GROUP)
            && !all_group_specs.iter().any(|g| g.name == GLOBAL_GROUP)
        {
            let members = ["DIRECT", "REJECT"]
                .into_iter()
                .map(str::to_owned)
                .filter(|tag| existing_tags.contains(tag) && !declared_outbounds.contains(tag))
                .chain(declared_outbounds.iter().cloned())
                .chain(config.proxy_groups.iter().map(|g| g.name.clone()));
            let mut proxies = Vec::new();
            for tag in members {
                if !proxies.contains(&tag) {
                    proxies.push(tag);
                }
            }
            all_group_specs.push(
                serde_json::from_value(serde_json::json!({
                    "name": GLOBAL_GROUP, "type": "select", "proxies": proxies,
                }))
                .map_err(|_| Error::Config("GLOBAL 策略组无法生成".into()))?,
            );
        }
        let mut compiled_groups = Vec::with_capacity(all_group_specs.len());
        for gspec in &all_group_specs {
            let cg = gspec.compile(&static_outbound_kinds, &compiled_providers)?;
            if profiles.contains_key(&cg.id) {
                return Err(Error::Config("策略组标签与出站重复".into()));
            }
            profiles.insert(
                cg.id.clone(),
                (
                    Capabilities {
                        tcp: true,
                        tcp_eof: true,
                        udp: !cg.disable_udp,
                    },
                    !cg.disable_udp,
                ),
            );
            compiled_groups.push(cg);
        }
        for cg in &compiled_groups {
            for cand in &cg.candidates {
                if !profiles.contains_key(cand) {
                    return Err(Error::Config(format!(
                        "策略组 {} 引用的候选出站 {} 不存在",
                        cg.id, cand
                    )));
                }
            }
            if let Some(fb) = &cg.fallback_outbound
                && !profiles.contains_key(fb)
            {
                return Err(Error::Config(
                    "负载均衡 fallback_tag 引用的出站不存在".into(),
                ));
            }
        }
        for (from, target) in &detours {
            let Some((caps, _)) = profiles.get(target) else {
                return Err(Error::Config("链式拨号引用的上游出站不存在".into()));
            };
            if !caps.tcp {
                return Err(Error::Config("链式拨号引用的上游出站不支持 TCP".into()));
            }
            let mut cursor = Some(target);
            let mut steps = 0usize;
            while let Some(curr) = cursor {
                if curr == from || steps > detours.len() {
                    return Err(Error::Config("链式拨号存在循环依赖".into()));
                }
                cursor = detours.get(curr);
                steps += 1;
            }
        }
        let mut all_rules = config.routes.clone();
        let mut all_sub_rules = config.sub_rules.clone();
        if let Some(route_block) = &config.route {
            all_rules.extend(route_block.rules.iter().cloned());
            for (k, v) in &route_block.sub_rules {
                all_sub_rules
                    .entry(k.clone())
                    .or_default()
                    .extend(v.iter().cloned());
            }
        }
        let tun_hijack = tun::dns_hijack_rules(config.nodes.iter().chain(&config.local_inbounds))?;
        all_rules.splice(0..0, tun_hijack);
        let final_outbound = match config
            .route
            .as_ref()
            .and_then(|r| r.final_outbound.as_deref())
        {
            Some(raw) => Some(OutId::parse(raw)?),
            None => None,
        };
        let geo_mode = if config.geodata_mode == Some(true) {
            GeoIpMode::Dat
        } else {
            GeoIpMode::Mmdb
        };
        let mut dns_geo = kerlico_routing::GeoNeeds::default();
        if let Some(dns) = config.dns.as_ref().filter(|dns| dns.enabled()) {
            let refs = dns.references();
            for site in &refs.geosite {
                dns_geo.add_site(&kerlico_routing::GeoSiteRef::parse(site)?);
            }
            for code in &refs.geoip {
                dns_geo.add_ip(&kerlico_routing::GeoIpRef::parse(code)?);
            }
        }
        let mut sniff_sets = Vec::new();
        for item in base_sniff_policy
            .skip_src_address
            .iter()
            .chain(&base_sniff_policy.skip_dst_address)
        {
            match item {
                kerlico_core::IpMatch::GeoIp(code) => {
                    dns_geo.add_ip(&kerlico_routing::GeoIpRef::parse(code)?);
                }
                kerlico_core::IpMatch::RuleSet(tag) => sniff_sets.push(tag.clone()),
                kerlico_core::IpMatch::Cidr(_) => {}
            }
        }
        for item in base_sniff_policy
            .skip_domain
            .iter()
            .chain(&base_sniff_policy.force_domain)
        {
            match item {
                kerlico_core::DomainMatch::GeoSite(code) => {
                    dns_geo.add_site(&kerlico_routing::GeoSiteRef::parse(code)?);
                }
                kerlico_core::DomainMatch::RuleSet(tag) => sniff_sets.push(tag.clone()),
                kerlico_core::DomainMatch::Pattern(_) => {}
            }
        }
        if let Some(tag) = sniff_sets
            .iter()
            .find(|tag| !compiled_rule_sets.contains_key(tag.as_str()))
        {
            return Err(Error::Config(format!(
                "sniffer 引用的 rule-set 不存在：{tag}"
            )));
        }
        let routes = RouteTable::compile_with_sets(&all_rules, compiled_rule_sets.clone())?
            .with_sub_rules(&all_sub_rules)?
            .with_geo(geo_mode, &dns_geo)
            .with_final_outbound(final_outbound);
        load_cached_geo(routes.geo())?;
        if routes
            .referenced_rule_sets()
            .into_iter()
            .any(|tag| !compiled_rule_sets.contains_key(tag))
        {
            return Err(Error::Config("路由规则引用的 rule-set 不存在".into()));
        }
        if routes.outbounds().any(|id| !profiles.contains_key(id)) {
            return Err(Error::Config("路由规则引用的出站不存在".into()));
        }
        let resources = remote_resources(
            rule_set_sources,
            &routes,
            &sniff_sets,
            config.dns.as_ref(),
            &compiled_providers,
            &geo_spec,
        )?;
        if resources
            .iter()
            .filter_map(|r| r.download.as_ref()?.detour.as_ref())
            .any(|id| !profiles.contains_key(id))
        {
            return Err(Error::Config("资源下载引用的出站不存在".into()));
        }
        if routes.users().any(|id| !accounts.contains_key(id)) {
            return Err(Error::Config("路由规则引用的管理账户不存在".into()));
        }
        let mut tags = BTreeSet::new();
        let mut listeners = BTreeSet::new();
        let mut bindings = Vec::new();
        for spec in &config.inbounds {
            let node = NodeId::parse(&spec.tag)?;
            if !tags.insert(node.clone()) {
                return Err(Error::Config("入站标签重复".into()));
            }
            if !spec.listen.ip().is_loopback() && !lan_filter.has_allowed() {
                return Err(Error::Config("固定转发入口只允许回环地址".into()));
            }
            let tcp = matches!(spec.kind, ForwardKind::Tcp);
            if spec.follow_redirect && !tcp {
                return Err(Error::Config("follow_redirect 仅支持 TCP 转发入口".into()));
            }
            if spec.listen.port() != 0 && !listeners.insert((spec.listen, tcp)) {
                return Err(Error::Config("监听地址重复".into()));
            }
            let target = if spec.follow_redirect && spec.target.is_empty() {
                Destination::new("127.0.0.1", 65535)?
            } else {
                spec.target.destination()?
            };
            let outbound = OutId::parse(&spec.outbound)?;
            let (
                Capabilities {
                    tcp: supports_tcp,
                    udp,
                    ..
                },
                _,
            ) = profiles
                .get(&outbound)
                .ok_or_else(|| Error::Config("引用的出站不存在".into()))?;
            // 固定入口的目标、网络和来源在准备阶段已知，这里的选择与运行时一致。
            let source = Source::Local { node: node.clone() };
            let selected = routes
                .select(&target, Network::Tcp, &source)
                .unwrap_or(&outbound);
            let selected_eof = profiles
                .get(selected)
                .is_some_and(|(selected, _)| selected.tcp_eof);
            if spec.require_remote_eof && (!tcp || !selected_eof) {
                return Err(Error::Config("出站不提供所需的远端 EOF 能力".into()));
            }
            if tcp && !supports_tcp || !tcp && !udp {
                return Err(Error::Config("出站不支持入站需要的数据能力".into()));
            }
            let mut sniff_policy = base_sniff_policy.clone();
            apply_inbound_sniffing(
                &mut sniff_policy,
                spec.sniff,
                spec.sniff_override_destination,
                spec.sniff_timeout.as_ref(),
                spec.sniffing.as_ref(),
            )?;
            bindings.push(IngressPlan {
                issuer: CredentialIssuer::new(node, config.epoch, Vec::new())?,
                outbound,
                mode: spec.mode.into(),
                local: true,
                sniff_policy,
            });
        }
        let mut fingerprints = BTreeSet::new();
        let mut nodes = Vec::new();
        for (mut spec, local) in config
            .nodes
            .into_iter()
            .map(|node| (node, false))
            .chain(config.local_inbounds.into_iter().map(|node| (node, true)))
        {
            let accept_proxy_protocol =
                spec.accept_proxy_protocol || extract_accept_proxy_protocol(&mut spec.options)?;
            let mut sniff_policy = extract_sniff_policy(&mut spec.options, &base_sniff_policy)?;
            apply_inbound_sniffing(
                &mut sniff_policy,
                spec.sniff,
                spec.sniff_override_destination,
                spec.sniff_timeout.as_ref(),
                spec.sniffing.as_ref(),
            )?;
            let node = NodeId::parse(&spec.tag)?;
            if !tags.insert(node.clone()) {
                return Err(Error::Config("节点与入站标签重复".into()));
            }
            if spec.listen.ip().to_canonical() != spec.listen.ip() {
                return Err(Error::Config(
                    "节点不能使用 IPv4-mapped IPv6 监听地址".into(),
                ));
            }
            let maximum = spec.max_sessions.unwrap_or(config.limits.max_sessions);
            if maximum == 0 || maximum > config.limits.max_sessions {
                return Err(Error::Config("节点会话上限必须在全局限额内".into()));
            }
            let factory = self
                .node_factories
                .get(spec.kind.as_str())
                .ok_or_else(|| Error::Config("节点协议未注册或未编译".into()))?;
            if local
                && ((!spec.listen.ip().is_loopback() && !lan_filter.has_allowed())
                    || !factory.allows_local_inbound())
            {
                return Err(Error::Config(
                    "本地代理入口必须回环监听，且模块须明确允许".into(),
                ));
            }
            let mut members = Vec::new();
            let mut native = Vec::new();
            for member in spec.members {
                let user = UserId::parse(&member.user_id)?;
                let account_enabled = accounts
                    .get(&user)
                    .ok_or_else(|| Error::Config("节点成员引用的管理账户不存在".into()))?;
                if member.credential_epoch == 0 {
                    return Err(Error::Config("凭据代次必须大于零".into()));
                }
                members.push(Membership {
                    user,
                    credential_epoch: member.credential_epoch,
                    enabled: member.enabled && *account_enabled,
                });
                native.push(member.native_credential);
            }
            if !local && members.is_empty() {
                return Err(Error::Config("远端节点必须配置真实认证成员".into()));
            }
            let issuer = CredentialIssuer::new(node, config.epoch, members)?;
            let input = NodeBuildContext {
                options: spec.options,
                native: Arc::new(native),
                issuer: issuer.clone(),
                local,
                routing_mark: global_dialer.routing_mark,
                bypass_marks: bypass_marks.clone(),
                routes: routes.clone(),
            };
            let protocol = factory.build(&input)?;
            if maximum <= protocol.reserved_sessions() {
                return Err(Error::Config(
                    "节点会话上限必须大于入口常驻占用的会话数".into(),
                ));
            }
            if protocol.requires_loopback()
                && !spec.listen.ip().is_loopback()
                && !(local && lan_filter.has_allowed())
            {
                return Err(Error::Config("当前节点组合仅允许回环监听".into()));
            }
            if !protocol.supports_tcp() && !protocol.supports_udp() && !protocol.supports_virtual()
            {
                return Err(Error::Config("节点没有可用监听能力".into()));
            }
            let outbound = OutId::parse(&spec.outbound)?;
            let (_, association) = profiles
                .get(&outbound)
                .ok_or_else(|| Error::Config("节点引用的出站不存在".into()))?;
            if protocol.requires_udp_association() && !association {
                return Err(Error::Config(
                    "节点需要保持同一出口 socket 的多目标 UDP 关联".into(),
                ));
            }
            for tcp in [true, false] {
                if spec.listen.port() != 0
                    && (tcp && protocol.supports_tcp() || !tcp && protocol.supports_udp())
                    && !listeners.insert((spec.listen, tcp))
                {
                    return Err(Error::Config("监听地址重复".into()));
                }
            }
            let manifest = protocol.credential_manifest();
            let mut authenticated = BTreeSet::new();
            let mut isolated = BTreeSet::new();
            let mut auth_keys = BTreeSet::new();
            for entry in manifest.entries() {
                OutId::parse(&entry.protocol)?;
                if let CredentialPurpose::Authentication { slot } = entry.purpose {
                    if slot >= issuer.len()
                        || !auth_keys.insert((entry.protocol.clone(), entry.fingerprint))
                    {
                        return Err(Error::Config("入口认证凭据重复或成员映射不合法".into()));
                    }
                    authenticated.insert(slot);
                }
                isolated.insert((entry.protocol.clone(), entry.fingerprint));
            }
            if authenticated.len() != issuer.len() || !local && authenticated.is_empty() {
                return Err(Error::Config("每个节点成员必须具有真实鉴别凭据".into()));
            }
            for key in isolated {
                if !fingerprints.insert(key) {
                    return Err(Error::Config(
                        "入口凭据重复，节点及本地入口必须独立配置".into(),
                    ));
                }
            }
            bindings.push(IngressPlan {
                issuer,
                outbound,
                mode: spec.mode.into(),
                local,
                sniff_policy,
            });
            nodes.push(PreparedNode {
                dual_stack: spec.dual_stack,
                tag: spec.tag,
                listen: spec.listen,
                protocol,
                max_sessions: maximum,
                accept_proxy_protocol,
            });
        }
        if routes.nodes().any(|id| !tags.contains(id)) {
            return Err(Error::Config("路由规则引用的入站不存在".into()));
        }
        if config.control.is_none()
            && let Some(clash_api) = config
                .experimental
                .as_ref()
                .and_then(|e| e.clash_api.as_ref())
            && let Some(listen) = clash_api.external_controller
        {
            config.control = Some(ControlSpec {
                listen,
                secret: clash_api.secret.clone(),
                external_ui: clash_api.external_ui.clone(),
                external_ui_name: None,
                external_ui_url: clash_api.external_ui_download_url.clone(),
                external_ui_download_detour: clash_api.external_ui_download_detour.clone(),
                default_mode: clash_api.default_mode.clone(),
                cors_allow_origins: clash_api.access_control_allow_origin.clone(),
                cors_allow_private_network: clash_api.access_control_allow_private_network,
                dashboard: None,
                dashboard_enabled: None,
                dashboard_path: None,
                dashboard_download_url: None,
                dashboard_http_client: None,
                dashboard_update_interval: None,
                tls: None,
                tls_listen: None,
                unix_path: None,
                pipe_path: None,
                routing_mark: None,
                doh_server: None,
            });
        }
        if let Some(ntp) = &config.ntp {
            if let Some(interval) = &ntp.interval {
                interval.to_duration()?;
            }
            if let Some(dp) = &ntp.dialer_proxy {
                let id = OutId::parse(dp)?;
                if !profiles.contains_key(&id) {
                    return Err(Error::Config("ntp.dialer_proxy 引用的出站不存在".into()));
                }
            }
        }
        if let Some(control) = &config.control
            && listeners.contains(&(control.listen, true))
        {
            return Err(Error::Config("控制接口与入站监听地址重复".into()));
        }
        let rule_providers_counts: BTreeMap<String, usize> = compiled_rule_sets
            .iter()
            .map(|(k, v)| (k.clone(), v.entry_count()))
            .collect();
        let store_selected_enabled = config
            .cache_file
            .as_ref()
            .is_some_and(|c| c.enabled && c.store_selected)
            || config
                .profile
                .as_ref()
                .is_some_and(|p| p.store_selected == Some(true))
            || config
                .experimental
                .as_ref()
                .and_then(|e| e.cache_file.as_ref())
                .is_some_and(|c| c.enabled && c.store_selected);
        let store_selected_path = if store_selected_enabled {
            Some(
                config
                    .cache_file
                    .as_ref()
                    .and_then(|c| c.path.clone())
                    .or_else(|| {
                        config
                            .experimental
                            .as_ref()
                            .and_then(|e| e.cache_file.as_ref())
                            .and_then(|c| c.path.clone())
                    })
                    .unwrap_or_else(|| "cache.db".into()),
            )
        } else {
            None
        };
        Ok(PreparedConfig {
            global_dialer: global_dialer.clone(),
            history: config.telemetry,
            device: config.device,
            control: config.control,
            egress: EgressPlan {
                services,
                bindings,
                routes,
                dns: config.dns,
                max_flows: config.limits.max_flow_records,
                detour_table,
                groups: compiled_groups,
                providers: compiled_providers.into_values().collect(),
                rule_providers: rule_providers_counts,
                resources,
                store_selected_path,
                mode,
                global_dialer: global_dialer.clone(),
            },
            log,
            inbounds: config.inbounds,
            limits: config.limits,
            nodes,
            lan_filter,
        })
    }
}

/// 规则引用的 Geo 文件已在本地时立即解码换入；文件缺失时由运行时下载。
fn load_cached_geo(slot: &GeoSlot) -> Result<()> {
    for file in GeoFile::ALL {
        if !slot.requires(file) {
            continue;
        }
        let path = file.cache_path();
        if let Some(bytes) = resource::read_cached(&path)? {
            let part = slot
                .compile(file, &bytes)
                .map_err(|error| Error::Config(format!("{} 不可用：{error}", path.display())))?;
            slot.install(part);
        }
    }
    Ok(())
}

/// 文件来源的规则集、file/http 提供者与 Geo 数据库，交给运行时加载与刷新。
///
/// Geo 文件在规则引用或配置了 `geox-url` 时登记；规则引用但未配置地址时用 Mihomo 默认地址。
fn remote_resources(
    rule_sets: Vec<RuleSetSource>,
    routes: &RouteTable,
    sniff_sets: &[String],
    dns: Option<&DnsSpec>,
    providers: &BTreeMap<String, CompiledProxyProvider>,
    geo: &GeoConfigSpec,
) -> Result<Vec<ResourceSpec>> {
    let mut referenced: BTreeSet<&str> = routes.referenced_rule_sets().into_iter().collect();
    let dns_sets: Vec<String> = dns
        .filter(|dns| dns.enabled())
        .map(|dns| dns.references().rule_sets)
        .unwrap_or_default();
    referenced.extend(dns_sets.iter().map(String::as_str));
    referenced.extend(sniff_sets.iter().map(String::as_str));
    let mut resources = Vec::new();
    for source in rule_sets {
        let Some(file) = source.file.clone() else {
            continue;
        };
        let download = match file.remote {
            Some(remote) => Some(Download {
                url: remote.url,
                interval: remote.interval,
                detour: resource::download_detour(remote.detour.as_deref())?,
                headers: Vec::new(),
                size_limit: resource::size_limit(remote.size_limit),
            }),
            None => None,
        };
        let required = referenced.contains(source.tag.as_str());
        resources.push(ResourceSpec {
            kind: ResourceKind::RuleSet { source, required },
            path: file.path,
            download,
        });
    }
    for provider in providers.values() {
        let Some(path) = provider.path.as_deref() else {
            continue;
        };
        if provider.kind == "inline" {
            continue;
        }
        let download = match provider.url.as_deref() {
            Some(url) if provider.kind == "http" => Some(Download {
                url: url.trim().to_owned(),
                interval: Duration::from_secs(provider.interval),
                detour: resource::download_detour(provider.proxy.as_deref())?,
                headers: provider
                    .headers
                    .iter()
                    .flat_map(|(name, values)| values.iter().map(|v| (name.clone(), v.clone())))
                    .collect(),
                size_limit: resource::size_limit(provider.size_limit),
            }),
            _ => None,
        };
        resources.push(ResourceSpec {
            kind: ResourceKind::ProxyProvider(provider.name.clone()),
            path: path.into(),
            download,
        });
    }
    let interval = if geo.geo_auto_update {
        Duration::from_secs(u64::from(geo.geo_update_interval.unwrap_or(24)) * 3600)
    } else {
        Duration::ZERO
    };
    for file in GeoFile::ALL {
        let required = routes.geo().requires(file);
        let Some(url) = geo
            .configured_url(file)
            .or_else(|| required.then(|| file.default_url()))
        else {
            continue;
        };
        resources.push(ResourceSpec {
            kind: ResourceKind::Geo {
                file,
                slot: routes.geo().clone(),
                required,
            },
            path: file.cache_path(),
            download: Some(Download {
                url: url.to_owned(),
                interval,
                detour: None,
                headers: Vec::new(),
                size_limit: DEFAULT_SIZE_LIMIT,
            }),
        });
    }
    Ok(resources)
}

pub fn parse(bytes: &[u8]) -> Result<Config> {
    let value = parse_config_value(bytes)?;
    parse_from_value(value)
}

pub fn parse_from_value(value: Value) -> Result<Config> {
    if value.get("version").and_then(Value::as_u64) != Some(2) {
        return Err(Error::Config(
            "仅支持配置版本 2；迁移说明见 docs/config-v2-migration.md".into(),
        ));
    }
    serde_json::from_value(value).map_err(|_| Error::Config("JSON 结构或字段不合法".into()))
}

pub fn parse_merged(
    files: &[std::path::PathBuf],
    dirs: &[std::path::PathBuf],
    format: Option<&str>,
) -> Result<Config> {
    let value = load_and_merge_configs(files, dirs, format)?;
    parse_from_value(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDirectFactory;
    impl OutboundFactory for DummyDirectFactory {
        fn kind(&self) -> &'static str {
            "direct"
        }
        fn supports_detour(&self) -> bool {
            true
        }
        fn compile(&self, _options: &Value) -> Result<OutboundPlan> {
            Ok(OutboundPlan::new(
                Capabilities {
                    tcp: true,
                    tcp_eof: true,
                    udp: true,
                },
                true,
                kerlico_core::TargetPolicy::Local,
                |_ctx| Box::pin(async { Err(Error::Unsupported("dummy")) }),
            ))
        }
    }

    struct DummyLocalNodeFactory(&'static str);
    impl NodeFactory for DummyLocalNodeFactory {
        fn kind(&self) -> &'static str {
            self.0
        }
        fn allows_local_inbound(&self) -> bool {
            true
        }
        fn build(&self, _input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
            struct DummyNode;
            impl InboundProtocol for DummyNode {
                fn credential_manifest(&self) -> kerlico_core::CredentialManifest {
                    kerlico_core::CredentialManifest::new()
                }
                fn handle<'a>(
                    &'a self,
                    _stream: kerlico_core::BoxStream,
                    _ingress: kerlico_core::IngressBinding,
                    _context: kerlico_core::InboundContext,
                ) -> kerlico_core::BoxFuture<'a, Result<()>> {
                    Box::pin(async { Ok(()) })
                }
            }
            Ok(Arc::new(DummyNode))
        }
    }

    #[test]
    fn nodes_see_every_routing_mark_kerlico_sockets_carry() {
        struct MarkProbe(Arc<std::sync::Mutex<Vec<u32>>>);
        impl NodeFactory for MarkProbe {
            fn kind(&self) -> &'static str {
                "tun"
            }
            fn allows_local_inbound(&self) -> bool {
                true
            }
            fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
                *self.0.lock().unwrap() = input.bypass_marks().to_vec();
                DummyLocalNodeFactory("tun").build(input)
            }
        }
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut reg = Registry::default();
        reg.register(DummyDirectFactory).unwrap();
        reg.register_node(MarkProbe(seen.clone())).unwrap();
        let cfg = parse(
            br#"{"version":2,"routing_mark":16,
            "outbounds":[{"tag":"plain","type":"direct"},
                {"tag":"marked","type":"direct","options":{"routing_mark":153}},
                {"tag":"same","type":"direct","options":{"routing-mark":153}}],
            "inbounds":[],
            "local_inbounds":[{"tag":"tun-in","type":"tun","listen":"127.0.0.1:0","outbound":"plain","options":{}}]}"#,
        )
        .unwrap();
        reg.prepare(cfg).unwrap();
        assert_eq!(*seen.lock().unwrap(), [16, 153]);
    }

    #[test]
    fn m3_config_route_fakedns_sniffer_cache_tun_roundtrip() {
        let raw = r#"{
            "version": 2,
            "interface_name": "eth0",
            "geodata_mode": true,
            "geodata_loader": "standard",
            "geosite_matcher": "mph",
            "geo_auto_update": true,
            "geo_update_interval": 24,
            "geox_url": {
                "geoip": "https://example.com/geoip.dat",
                "geosite": "https://example.com/geosite.dat"
            },
            "fakedns": [
                {"ipPool": "198.18.0.0/16", "poolSize": 65535}
            ],
            "sniffer": {
                "enable": true,
                "override_destination": true,
                "force_dns_mapping": true,
                "parse_pure_ip": true,
                "sniff": {
                    "HTTP": {"ports": [80, 8080], "override_destination": true},
                    "TLS": {"ports": [443, 8443]},
                    "QUIC": {"ports": [443]}
                },
                "force_domain": ["+.netflix.com"],
                "skip_domain": ["+.push.apple.com"],
                "skip_src_address": ["192.168.0.0/16"],
                "skip_dst_address": ["10.0.0.0/8"]
            },
            "cache_file": {
                "enabled": true,
                "path": "cache.db",
                "cache_id": "main",
                "store_fakeip": true
            },
            "profile": {
                "store_fake_ip": true
            },
            "tun": {
                "enable": true,
                "device": "utun9",
                "stack": "mixed",
                "mtu": 1400,
                "auto_route": true,
                "auto_redirect": true,
                "auto_detect_interface": true,
                "strict_route": true,
                "dns_hijack": ["any:53", "tcp://any:53"],
                "inet4_address": ["172.19.0.1/30"],
                "route_exclude_address": ["192.168.0.0/16"]
            },
            "route": {
                "final": "direct",
                "auto_detect_interface": true,
                "default_interface": "eth0",
                "default_mark": 255,
                "rule_set": [
                    {
                        "tag": "ads",
                        "type": "inline",
                        "rules": [
                            {"domain_suffix": ["ads.example.com"], "ip_cidr": ["203.0.113.0/24"]}
                        ]
                    }
                ],
                "rules": [
                    {
                        "rule_set": ["ads"],
                        "action": "reject"
                    },
                    {
                        "protocol": ["dns"],
                        "action": "hijack-dns"
                    },
                    {
                        "action": "resolve",
                        "strategy": "prefer_ipv4",
                        "outbound": "direct"
                    }
                ]
            },
            "outbounds": [
                {"tag": "direct", "type": "direct"}
            ],
            "local_inbounds": [
                {
                    "tag": "socks-in",
                    "listen": "127.0.0.1:1080",
                    "type": "socks",
                    "outbound": "direct",
                    "sniff": true,
                    "sniff_override_destination": true,
                    "sniff_timeout": "300ms"
                }
            ]
        }"#;
        let cfg = parse(raw.as_bytes()).expect("parse m3 config");
        let mut reg = Registry::default();
        reg.register(DummyDirectFactory).unwrap();
        reg.register_node(DummyLocalNodeFactory("socks")).unwrap();
        reg.register_node(DummyLocalNodeFactory("tun")).unwrap();
        let prepared = reg.prepare(cfg).expect("prepare m3 config");
        assert_eq!(prepared.egress.bindings.len(), 2);
        let sniff_policy = &prepared.egress.bindings[0].sniff_policy;
        assert!(sniff_policy.enabled);
        assert!(sniff_policy.override_destination);
        let dns_spec = prepared
            .egress
            .dns
            .as_ref()
            .expect("dns synthesized from fakedns");
        assert!(dns_spec.fakedns.is_some());
        assert!(dns_spec.cache_file.as_ref().unwrap().enabled);
        assert!(dns_spec.cache_file.as_ref().unwrap().store_fakeip);
    }

    #[test]
    fn mihomo_sniffer_defaults_ports_order_and_per_protocol_override() {
        let spec: GlobalSnifferSpec = serde_json::from_value(serde_json::json!({
            "enable": true,
            "sniff": {
                "QUIC": {},
                "HTTP": {"ports": [80, "8080-8880"], "override-destination": false},
                "TLS": {}
            },
            "skip-dst-address": ["10.0.0.0/8", "geoip:telegram"]
        }))
        .unwrap();
        let policy = spec.to_policy().unwrap();
        let order: Vec<&str> = policy
            .sniffers
            .iter()
            .map(|r| r.protocol.as_str())
            .collect();
        assert_eq!(order, ["tls", "http", "quic"], "Mihomo 固定尝试顺序");
        assert_eq!(
            policy.sniffer("tls", 443),
            Some(true),
            "override-destination 默认 true"
        );
        assert_eq!(policy.sniffer("tls", 8443), None, "TLS 未写端口时只看 443");
        assert_eq!(policy.sniffer("http", 8443), Some(false), "逐协议覆盖开关");
        assert_eq!(policy.sniffer("quic", 443), Some(true));
        assert_eq!(
            policy.skip_dst_address,
            [
                kerlico_core::IpMatch::Cidr(kerlico_core::Cidr::parse("10.0.0.0/8").unwrap()),
                kerlico_core::IpMatch::GeoIp("telegram".into()),
            ],
            "geoip: 项保留为 Geo 条目"
        );
        assert_eq!(
            policy.targets,
            kerlico_core::SniffTargets::Mihomo {
                parse_pure_ip: true,
                force_dns_mapping: true
            }
        );
        let legacy: GlobalSnifferSpec = serde_json::from_value(serde_json::json!({
            "enable": true, "sniffing": ["tls", "http"], "port-whitelist": ["443", "8000-9000"]
        }))
        .unwrap();
        let legacy = legacy.to_policy().unwrap();
        assert_eq!(
            legacy.sniffer("http", 8080),
            Some(true),
            "旧写法共用 port-whitelist"
        );
        assert_eq!(legacy.sniffer("http", 80), None);
        let off: GlobalSnifferSpec = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(!off.to_policy().unwrap().enabled, "enable 默认 false");
        let bad: GlobalSnifferSpec =
            serde_json::from_value(serde_json::json!({"sniff": {"FOO": {}}})).unwrap();
        assert!(bad.to_policy().is_err(), "未知嗅探器同 Mihomo 报错");
    }

    #[test]
    fn inbound_sniff_sniffs_every_target_without_overriding_by_default() {
        let mut policy = kerlico_core::SniffPolicy::default();
        apply_inbound_sniffing(&mut policy, Some(true), None, None, None).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.targets, kerlico_core::SniffTargets::All);
        assert_eq!(policy.sniffer("ssh", 22), Some(false));
        let target = kerlico_core::Destination::new("example.com", 443).unwrap();
        assert!(
            policy.wants(&target, None, None, &kerlico_core::NoSets),
            "sing-box 入站嗅探域名目标"
        );
        let spec: InboundSniffingSpec = serde_json::from_value(serde_json::json!({
            "enabled": true, "destOverride": ["http", "tls", "fakedns"], "routeOnly": true
        }))
        .unwrap();
        let mut xray = kerlico_core::SniffPolicy::default();
        apply_inbound_sniffing(&mut xray, None, None, None, Some(&spec)).unwrap();
        assert_eq!(xray.sniffers.len(), 2, "fakedns 不是字节嗅探器");
        assert_eq!(
            xray.sniffer("tls", 443),
            Some(false),
            "routeOnly 不覆盖目标"
        );
    }
}
