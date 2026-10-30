//! JSON 外层配置和工厂契约；协议字段由对应工厂解释。

use kerlico_core::{Capabilities, Destination, Error, Outbound, Result};
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
    pub fn prepare(&self, config: Config) -> Result<PreparedConfig> {
        if config.version != 1 {
            return Err(Error::Config("仅支持配置版本 1".into()));
        }
        config.limits.validate()?;
        let mut outbounds = BTreeMap::new();
        for spec in config.outbounds {
            validate_tag(&spec.tag)?;
            if outbounds.contains_key(&spec.tag) {
                return Err(Error::Config("出站标签重复".into()));
            }
            let factory = self
                .factories
                .get(spec.kind.as_str())
                .ok_or_else(|| Error::Config("出站类型未注册或未编译".into()))?;
            outbounds.insert(spec.tag, factory.build(&spec.options)?);
        }
        let mut tags = BTreeSet::new();
        let mut listeners = BTreeSet::new();
        for inbound in &config.inbounds {
            validate_tag(&inbound.tag)?;
            if !tags.insert(&inbound.tag) {
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
        Ok(PreparedConfig {
            outbounds,
            inbounds: config.inbounds,
            limits: config.limits,
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
}

pub fn parse(bytes: &[u8]) -> Result<Config> {
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Config("配置文件超过 1 MiB".into()));
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Config("JSON 结构或字段不合法".into()))
}
