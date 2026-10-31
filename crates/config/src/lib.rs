//! JSON 外层配置和工厂契约；协议字段由对应工厂解释。

use kerlico_core::{Capabilities, Destination, Error, InboundProtocol, Outbound, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

/// 严格 JSON 外层配置；反序列化拒绝未知外层字段，语义校验由 [`Registry::prepare`] 完成。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// 配置格式版本；当前准备阶段只接受 `1`。
    pub version: u32,
    /// 命名出站模板，标签在出站命名空间内唯一。
    pub outbounds: Vec<OutboundSpec>,
    /// 回环监听的固定目标转发入口。
    pub inbounds: Vec<ForwardSpec>,
    /// 必须具有真实鉴权材料的独立远端节点；省略时为空。
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
    /// 本机信任边界内的动态代理入口，与必须独立认证的远端节点分开。
    #[serde(default)]
    pub local_inbounds: Vec<NodeSpec>,
    /// 全局时间与资源限制；省略时使用 [`Limits::default`]。
    #[serde(default)]
    pub limits: Limits,
}

/// 出站类型及其选项模板；模块工厂负责严格校验 `options`。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundSpec {
    /// 出站标签，供固定转发入口及节点引用。
    pub tag: String,
    /// JSON `type` 字段，必须对应已注册的出站工厂。
    #[serde(rename = "type")]
    pub kind: String,
    /// 模块专用选项；省略时为空 JSON 对象。
    #[serde(default = "empty_object")]
    pub options: Value,
}

/// 独立协议节点或本地代理入口的配置；两者使用同一字段结构。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSpec {
    /// 节点标签，与固定入口及其他节点、本地入口共用唯一标签空间。
    pub tag: String,
    /// JSON `type` 字段，必须对应已注册的节点工厂。
    #[serde(rename = "type")]
    pub kind: String,
    /// 字面监听地址；IPv4、IPv6 节点分别配置，不隐式共享身份。
    pub listen: SocketAddr,
    /// 引用的出站模板；准备阶段为每个节点重新构造带身份的出口实例。
    pub outbound: String,
    /// 必填的模块专用选项，由节点工厂校验。
    pub options: Value,
    /// 节点会话上限；省略时沿用全局值，且不得超过全局上限。
    #[serde(default)]
    pub max_sessions: Option<usize>,
}

/// 节点配置工厂；构造阶段不得拨号、监听或修改系统网络。
pub trait NodeFactory: Send + Sync {
    /// 注册与 JSON `type` 使用的稳定类型名。
    fn kind(&self) -> &'static str;
    /// 是否允许作为回环 `local_inbounds` 入口；默认拒绝。
    fn allows_local_inbound(&self) -> bool {
        false
    }
    /// 严格解析模块选项并构造本地对象，未知字段须拒绝。
    /// 可读取本地证书、密钥并派生材料，不执行网络 I/O。
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>>;
}

/// 已准备的单节点资源；协议对象与带身份的出口实例不跨节点隐式共享。
#[derive(Clone)]
pub struct PreparedNode {
    /// 已校验的节点标签。
    pub tag: String,
    /// 待绑定的监听地址，端口为 `0` 时由绑定阶段分配。
    pub listen: SocketAddr,
    /// 仅持有本节点配置和凭据的协议实现。
    pub protocol: Arc<dyn InboundProtocol>,
    /// 为本节点单独构造的出口，运行时由统一目标访问层包装。
    pub outbound: Arc<dyn Outbound>,
    /// 已校验的节点会话上限。
    pub max_sessions: usize,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

/// 回环固定目标入口配置；动态目标代理使用 [`NodeSpec`]。
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardSpec {
    /// 与节点、本地入口共用唯一标签空间的入口标签。
    pub tag: String,
    /// JSON `type` 字段，选择 TCP 或 UDP 固定转发。
    #[serde(rename = "type")]
    pub kind: ForwardKind,
    /// 只允许回环 IP 的监听地址，可使用端口 `0`。
    pub listen: SocketAddr,
    /// 此入口所有会话访问的固定业务目标。
    pub target: TargetSpec,
    /// 引用的命名出站标签。
    pub outbound: String,
    /// 要求目标写端 EOF 传播；只适用于声明该能力的 TCP 出站。
    #[serde(default)]
    pub require_remote_eof: bool,
}

/// 固定目标转发入口的物理传输类型。
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ForwardKind {
    /// JSON `tcp-forward`，接收本地 TCP 字节流。
    #[serde(rename = "tcp-forward")]
    Tcp,
    /// JSON `udp-forward`，按本地来源建立固定目标数据报通道。
    #[serde(rename = "udp-forward")]
    Udp,
}

/// 目标主机及端口的 JSON 表示；构造时不进行 DNS 查询。
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSpec {
    /// 字面 IP 或域名，不包含端口；IPv6 不带方括号。
    pub host: String,
    /// 非零业务端口，由 [`Self::destination`] 校验。
    pub port: u16,
}

impl TargetSpec {
    /// 校验并规范化目标地址，不执行网络 I/O。
    pub fn destination(&self) -> Result<Destination> {
        Destination::new(&self.host, self.port)
    }
}

/// 全局资源配置；省略字段采用默认值，未知字段拒绝，准备阶段校验范围。
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// 建立时长，默认 10000 毫秒，范围 1 至 300000；不是自动跨阶段扣减的截止时间。
    pub connect_timeout_ms: u64,
    /// 空闲时长，默认 60000 毫秒，范围 1 至 86400000。
    pub idle_timeout_ms: u64,
    /// 关闭时排空时长，默认 5000 毫秒，范围 1 至 300000。
    pub drain_timeout_ms: u64,
    /// 全局会话与附加逻辑流名额，默认 128，范围 1 至 65536。
    pub max_sessions: usize,
    /// 固定 UDP 转发每个来源的待发包队列上限，默认 32，范围 1 至 4096。
    pub udp_queue_packets: usize,
    /// 数据报缓冲上限，默认 65535，范围 1 至 65535；不是协议或网络的可发送负载承诺。
    pub max_datagram_size: usize,
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
        }
    }
}

impl Limits {
    /// 将建立时长转换为 [`Duration`]，不额外校验或扣减预算。
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }
    /// 将空闲时长转换为 [`Duration`]。
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }
    /// 将排空时长转换为 [`Duration`]。
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
        {
            return Err(Error::Config("资源限制超出支持范围".into()));
        }
        Ok(())
    }
}

/// 出站配置工厂；注册并不代表所有角色或协议组合都可用。
pub trait OutboundFactory: Send + Sync {
    /// 注册与 JSON `type` 使用的稳定类型名。
    fn kind(&self) -> &'static str;
    /// 只解析与构造本地对象，可读取本地证书、密钥并派生材料。
    /// 不拨号、监听或修改系统网络；未知选项由具体工厂拒绝。
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>>;
}

/// 按类型名注册的工厂集合；准备配置时拒绝缺失类型，不回退为直连。
#[derive(Default)]
pub struct Registry {
    factories: BTreeMap<&'static str, Arc<dyn OutboundFactory>>,
    node_factories: BTreeMap<&'static str, Arc<dyn NodeFactory>>,
}

impl Registry {
    /// 注册出站工厂；同一出站类型名重复时返回配置错误。
    pub fn register(&mut self, factory: impl OutboundFactory + 'static) -> Result<()> {
        let key = factory.kind();
        if self.factories.contains_key(key) {
            return Err(Error::Config("模块类型重复注册".into()));
        }
        self.factories.insert(key, Arc::new(factory));
        Ok(())
    }
    /// 按类型名字典序遍历已注册出站，不包含节点类型。
    pub fn kinds(&self) -> impl Iterator<Item = &&'static str> {
        self.factories.keys()
    }
    /// 注册节点工厂；节点与出站分开注册，同一节点类型名不得重复。
    pub fn register_node(&mut self, factory: impl NodeFactory + 'static) -> Result<()> {
        let kind = factory.kind();
        if self.node_factories.contains_key(kind) {
            return Err(Error::Config("节点类型重复注册".into()));
        }
        self.node_factories.insert(kind, Arc::new(factory));
        Ok(())
    }
    /// 按类型名字典序遍历已注册节点，不从出站注册情况推断入站能力。
    pub fn node_kinds(&self) -> impl Iterator<Item = &&'static str> {
        self.node_factories.keys()
    }
    /// 校验版本、限制、标签、引用、监听与数据能力，并调用工厂构造对象。
    ///
    /// 远端节点必须有真实鉴权摘要；鉴权集合与额外秘密隔离集合的并集用于跨条目查重，
    /// 额外隔离摘要不能赋予鉴权资格。每个节点独立构造其出口实例。
    /// 此阶段不绑定监听器或建立网络连接，但工厂可读取本地配置资产。
    pub fn prepare(&self, config: Config) -> Result<PreparedConfig> {
        if config.version != 1 {
            return Err(Error::Config("仅支持配置版本 1".into()));
        }
        config.limits.validate()?;
        let mut outbounds = BTreeMap::new();
        let mut templates = BTreeMap::new();
        for spec in config.outbounds {
            validate_tag(&spec.tag)?;
            if outbounds.contains_key(&spec.tag) {
                return Err(Error::Config("出站标签重复".into()));
            }
            let factory = self
                .factories
                .get(spec.kind.as_str())
                .ok_or_else(|| Error::Config("出站类型未注册或未编译".into()))?;
            outbounds.insert(spec.tag.clone(), factory.build(&spec.options)?);
            templates.insert(spec.tag, (factory.clone(), spec.options));
        }
        let mut tags = BTreeSet::new();
        let mut listeners = BTreeSet::new();
        for inbound in &config.inbounds {
            validate_tag(&inbound.tag)?;
            if !tags.insert(inbound.tag.clone()) {
                return Err(Error::Config("入站标签重复".into()));
            }
            if !inbound.listen.ip().is_loopback() {
                return Err(Error::Config("首版转发入口只允许回环地址".into()));
            }
            let transport = matches!(inbound.kind, ForwardKind::Tcp);
            if !listeners.insert((inbound.listen, transport)) {
                return Err(Error::Config("监听地址重复".into()));
            }
            inbound.target.destination()?;
            let outbound = outbounds
                .get(&inbound.outbound)
                .ok_or_else(|| Error::Config("引用的出站不存在".into()))?;
            let Capabilities { tcp, udp, tcp_eof } = outbound.capabilities();
            if inbound.require_remote_eof && (!transport || !tcp_eof) {
                return Err(Error::Config("出站不提供所需的远端 EOF 能力".into()));
            }
            if transport && !tcp || !transport && !udp {
                return Err(Error::Config("出站不支持入站需要的数据能力".into()));
            }
        }
        let mut credentials = BTreeSet::new();
        let mut nodes = Vec::new();
        for (node, local) in config
            .nodes
            .into_iter()
            .map(|node| (node, false))
            .chain(config.local_inbounds.into_iter().map(|node| (node, true)))
        {
            validate_tag(&node.tag)?;
            if !tags.insert(node.tag.clone()) {
                return Err(Error::Config("节点与入站标签重复".into()));
            }
            if node.listen.ip().to_canonical() != node.listen.ip() {
                return Err(Error::Config(
                    "节点不能使用 IPv4-mapped IPv6 监听地址".into(),
                ));
            }
            let max_sessions = node.max_sessions.unwrap_or(config.limits.max_sessions);
            if max_sessions == 0 || max_sessions > config.limits.max_sessions {
                return Err(Error::Config("节点会话上限必须在全局限额内".into()));
            }
            let factory = self
                .node_factories
                .get(node.kind.as_str())
                .ok_or_else(|| Error::Config("节点协议未注册或未编译".into()))?;
            if local && (!node.listen.ip().is_loopback() || !factory.allows_local_inbound()) {
                return Err(Error::Config(
                    "本地代理入口必须回环监听，且模块须明确允许".into(),
                ));
            }
            let protocol = factory.build(&node.options)?;
            if protocol.requires_loopback() && !node.listen.ip().is_loopback() {
                return Err(Error::Config("无传输安全的节点仅允许回环监听".into()));
            }
            if !protocol.supports_tcp() && !protocol.supports_udp() && !protocol.supports_virtual()
            {
                return Err(Error::Config("节点没有可用监听能力".into()));
            }
            if protocol.requires_udp_association()
                && !outbounds
                    .get(&node.outbound)
                    .ok_or_else(|| Error::Config("节点引用的出站不存在".into()))?
                    .supports_udp_association()
            {
                return Err(Error::Config(
                    "节点需要保持同一出口 socket 的多目标 UDP 关联".into(),
                ));
            }
            for tcp in [true, false] {
                if (tcp && protocol.supports_tcp() || !tcp && protocol.supports_udp())
                    && !listeners.insert((node.listen, tcp))
                {
                    return Err(Error::Config("监听地址重复".into()));
                }
            }
            let fingerprints = protocol.scoped_credential_fingerprints(&node.kind);
            if fingerprints.is_empty() && !local {
                return Err(Error::Config("节点必须配置独立认证凭据".into()));
            }
            let mut isolated = BTreeSet::new();
            for key in fingerprints {
                validate_tag(&key.protocol)?;
                if !isolated.insert((key.protocol, key.fingerprint)) {
                    return Err(Error::Config("同一入口认证凭据重复".into()));
                }
            }
            for key in protocol.credential_isolation_fingerprints(&node.kind) {
                validate_tag(&key.protocol)?;
                isolated.insert((key.protocol, key.fingerprint));
            }
            for key in isolated {
                if !credentials.insert(key) {
                    return Err(Error::Config(
                        "入口凭据重复，节点及本地入口必须独立配置".into(),
                    ));
                }
            }
            // 每个节点重新构造出口实例，避免跨节点共享认证连接池与会话票据。
            let (outbound_factory, options) = templates
                .get(&node.outbound)
                .ok_or_else(|| Error::Config("节点引用的出站不存在".into()))?;
            nodes.push(PreparedNode {
                tag: node.tag,
                listen: node.listen,
                protocol,
                outbound: outbound_factory.build(options)?,
                max_sessions,
            });
        }
        Ok(PreparedConfig {
            outbounds,
            inbounds: config.inbounds,
            limits: config.limits,
            nodes,
        })
    }
}

fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty()
        || tag.len() > 64
        || !tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
    {
        return Err(Error::Config(
            "标签必须是 1 至 64 个字母、数字、横线或下划线".into(),
        ));
    }
    Ok(())
}

/// 注册表准备结果；公开字段允许程序化构造，调用方须维护同等校验和隔离约束。
pub struct PreparedConfig {
    /// 命名出站实例，供固定目标入口引用；节点另有各自实例。
    pub outbounds: BTreeMap<String, Arc<dyn Outbound>>,
    /// 已校验的固定目标入口配置。
    pub inbounds: Vec<ForwardSpec>,
    /// 已校验的全局限制。
    pub limits: Limits,
    /// 已合并的远端节点与本地代理入口，保留各自标签及独立实例。
    pub nodes: Vec<PreparedNode>,
}

/// 解码不超过 1 MiB 的 JSON，并拒绝未知外层字段或不匹配的数据类型。
///
/// 此函数不调用协议工厂、不校验配置版本或引用；运行前仍需 [`Registry::prepare`]。
pub fn parse(bytes: &[u8]) -> Result<Config> {
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Config("配置文件超过 1 MiB".into()));
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Config("JSON 结构或字段不合法".into()))
}
