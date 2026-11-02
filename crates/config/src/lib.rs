//! 配置 v2 的纯编译、成员绑定与命名服务计划。

use kerlico_core::{
    Capabilities, CredentialIssuer, CredentialPurpose, CredentialSet, Destination, Error,
    FamilyMode, InboundProtocol, Membership, NodeId, OutId, Result, UserId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
mod plan;
pub use plan::*;
mod users;
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
    #[serde(default)]
    pub limits: Limits,
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
    pub options: Value,
    #[serde(default)]
    pub members: Vec<MemberSpec>,
    #[serde(default)]
    pub max_sessions: Option<usize>,
}

/// 每个协议仅见本节点原生凭据和不可由网络构造的签发者。
#[derive(Clone)]
pub struct NodeBuildContext {
    options: Value,
    native: Arc<Vec<Value>>,
    issuer: CredentialIssuer,
    local: bool,
}
impl NodeBuildContext {
    pub fn options(&self) -> &Value {
        &self.options
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
        let members = native_credentials
            .iter()
            .map(|_| Membership {
                user: UserId::generate(),
                credential_epoch: 1,
                enabled: true,
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
    fn compile(&self, options: &Value) -> Result<OutboundPlan>;
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardSpec {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: ForwardKind,
    pub listen: SocketAddr,
    pub target: TargetSpec,
    pub outbound: String,
    #[serde(default)]
    pub mode: NodeMode,
    #[serde(default)]
    pub require_remote_eof: bool,
}
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ForwardKind {
    #[serde(rename = "tcp-forward")]
    Tcp,
    #[serde(rename = "udp-forward")]
    Udp,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSpec {
    pub host: String,
    pub port: u16,
}
impl TargetSpec {
    pub fn destination(&self) -> Result<Destination> {
        Destination::new(&self.host, self.port)
    }
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
    pub fn prepare(&self, config: Config) -> Result<PreparedConfig> {
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
        for spec in config.outbounds {
            let id = OutId::parse(&spec.tag)?;
            if profiles.contains_key(&id) {
                return Err(Error::Config("出站标签重复".into()));
            }
            let factory = self
                .factories
                .get(spec.kind.as_str())
                .ok_or_else(|| Error::Config("出站类型未注册或未编译".into()))?;
            let plan = factory.compile(&spec.options)?;
            profiles.insert(
                id.clone(),
                (plan.capabilities(), plan.supports_udp_association()),
            );
            services.push(NamedServicePlan { id, plan });
        }
        let mut tags = BTreeSet::new();
        let mut listeners = BTreeSet::new();
        let mut bindings = Vec::new();
        for spec in &config.inbounds {
            let node = NodeId::parse(&spec.tag)?;
            if !tags.insert(node.clone()) {
                return Err(Error::Config("入站标签重复".into()));
            }
            if !spec.listen.ip().is_loopback() {
                return Err(Error::Config("固定转发入口只允许回环地址".into()));
            }
            let tcp = matches!(spec.kind, ForwardKind::Tcp);
            if spec.listen.port() != 0 && !listeners.insert((spec.listen, tcp)) {
                return Err(Error::Config("监听地址重复".into()));
            }
            spec.target.destination()?;
            let outbound = OutId::parse(&spec.outbound)?;
            let (
                Capabilities {
                    tcp: supports_tcp,
                    udp,
                    tcp_eof,
                },
                _,
            ) = profiles
                .get(&outbound)
                .ok_or_else(|| Error::Config("引用的出站不存在".into()))?;
            if spec.require_remote_eof && (!tcp || !tcp_eof) {
                return Err(Error::Config("出站不提供所需的远端 EOF 能力".into()));
            }
            if tcp && !supports_tcp || !tcp && !udp {
                return Err(Error::Config("出站不支持入站需要的数据能力".into()));
            }
            bindings.push(IngressPlan {
                issuer: CredentialIssuer::new(node, config.epoch, Vec::new())?,
                outbound,
                mode: spec.mode.into(),
                local: true,
            });
        }
        let mut fingerprints = BTreeSet::new();
        let mut nodes = Vec::new();
        for (spec, local) in config
            .nodes
            .into_iter()
            .map(|node| (node, false))
            .chain(config.local_inbounds.into_iter().map(|node| (node, true)))
        {
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
            if local && (!spec.listen.ip().is_loopback() || !factory.allows_local_inbound()) {
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
            };
            let protocol = factory.build(&input)?;
            if protocol.requires_loopback() && !spec.listen.ip().is_loopback() {
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
            });
            nodes.push(PreparedNode {
                tag: spec.tag,
                listen: spec.listen,
                protocol,
                max_sessions: maximum,
            });
        }
        Ok(PreparedConfig {
            egress: EgressPlan {
                services,
                bindings,
                max_flows: config.limits.max_flow_records,
            },
            inbounds: config.inbounds,
            limits: config.limits,
            nodes,
        })
    }
}

pub fn parse(bytes: &[u8]) -> Result<Config> {
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Config("配置文件超过 1 MiB".into()));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| Error::Config("JSON 结构或字段不合法".into()))?;
    if value.get("version").and_then(Value::as_u64) != Some(2) {
        return Err(Error::Config(
            "仅支持配置版本 2；迁移说明见 docs/config-v2-migration.md".into(),
        ));
    }
    serde_json::from_value(value).map_err(|_| Error::Config("JSON 结构或字段不合法".into()))
}
