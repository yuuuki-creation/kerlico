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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub outbounds: Vec<OutboundSpec>,
    pub inbounds: Vec<ForwardSpec>,
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
    #[serde(default)]
    pub limits: Limits,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSpec {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub listen: SocketAddr,
    pub outbound: String,
    pub options: Value,
    #[serde(default)]
    pub max_sessions: Option<usize>,
}

pub trait NodeFactory: Send + Sync {
    fn kind(&self) -> &'static str;
    /// 只解析和构造，不绑定端口或拨号。
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>>;
}

#[derive(Clone)]
pub struct PreparedNode {
    pub tag: String,
    pub listen: SocketAddr,
    pub protocol: Arc<dyn InboundProtocol>,
    pub outbound: Arc<dyn Outbound>,
    pub max_sessions: usize,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
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
        {
            return Err(Error::Config("资源限制超出支持范围".into()));
        }
        Ok(())
    }
}

pub trait OutboundFactory: Send + Sync {
    fn kind(&self) -> &'static str;
    /// 只解析与构造本地对象，不拨号、监听或修改系统网络。
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>>;
}

#[derive(Default)]
pub struct Registry {
    factories: BTreeMap<&'static str, Arc<dyn OutboundFactory>>,
    node_factories: BTreeMap<&'static str, Arc<dyn NodeFactory>>,
}

impl Registry {
    pub fn register(&mut self, factory: impl OutboundFactory + 'static) -> Result<()> {
        let key = factory.kind();
        if self.factories.contains_key(key) {
            return Err(Error::Config("模块类型重复注册".into()));
        }
        self.factories.insert(key, Arc::new(factory));
        Ok(())
    }
    pub fn kinds(&self) -> impl Iterator<Item = &&'static str> {
        self.factories.keys()
    }
    pub fn register_node(&mut self, factory: impl NodeFactory + 'static) -> Result<()> {
        let kind = factory.kind();
        if self.node_factories.contains_key(kind) {
            return Err(Error::Config("节点类型重复注册".into()));
        }
        self.node_factories.insert(kind, Arc::new(factory));
        Ok(())
    }
    pub fn node_kinds(&self) -> impl Iterator<Item = &&'static str> {
        self.node_factories.keys()
    }
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
        for node in config.nodes {
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
            let protocol = factory.build(&node.options)?;
            if protocol.requires_loopback() && !node.listen.ip().is_loopback() {
                return Err(Error::Config("无传输安全的节点仅允许回环监听".into()));
            }
            if !protocol.supports_tcp() && !protocol.supports_udp() && !protocol.supports_virtual()
            {
                return Err(Error::Config("节点没有可用监听能力".into()));
            }
            for tcp in [true, false] {
                if (tcp && protocol.supports_tcp() || !tcp && protocol.supports_udp())
                    && !listeners.insert((node.listen, tcp))
                {
                    return Err(Error::Config("监听地址重复".into()));
                }
            }
            let fingerprints = protocol.credential_fingerprints();
            if fingerprints.is_empty() {
                return Err(Error::Config("节点必须配置独立认证凭据".into()));
            }
            for key in fingerprints {
                if !credentials.insert((node.kind.clone(), key)) {
                    return Err(Error::Config(
                        "节点认证凭据重复，IPv4/IPv6 节点必须分别配置".into(),
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

pub struct PreparedConfig {
    pub outbounds: BTreeMap<String, Arc<dyn Outbound>>,
    pub inbounds: Vec<ForwardSpec>,
    pub limits: Limits,
    pub nodes: Vec<PreparedNode>,
}

pub fn parse(bytes: &[u8]) -> Result<Config> {
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Config("配置文件超过 1 MiB".into()));
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Config("JSON 结构或字段不合法".into()))
}
