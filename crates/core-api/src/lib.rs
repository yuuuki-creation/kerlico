//! 模块间共享的地址、I/O 和取消契约；不依赖具体协议或配置格式。

use std::{fmt, future::Future, io, net::IpAddr, pin::Pin, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
/// 可克隆的协作取消信号；克隆共享取消状态，子令牌用于限制取消传播范围。
pub use tokio_util::sync::CancellationToken;
mod relay;
pub use relay::relay_tcp;

/// 可在线程间移动的装箱异步操作；丢弃操作不会撤回已经发送的数据。
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 地址、配置、能力、资源和运行阶段的公共错误分类。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 地址格式或端口不满足接口要求。
    #[error("地址或端口不合法")]
    InvalidAddress,
    /// 配置解析、引用、凭据隔离或组合校验失败。
    #[error("配置不合法：{0}")]
    Config(String),
    /// 当前对象或组合未提供请求的能力。
    #[error("不支持的能力：{0}")]
    Unsupported(&'static str),
    /// 对端数据或协议状态不合法。
    #[error("协议错误：{0}")]
    Protocol(&'static str),
    /// 策略明确拒绝访问。
    #[error("连接被策略拒绝")]
    Rejected,
    /// 当前操作收到取消信号。
    #[error("操作已取消")]
    Cancelled,
    /// 当前操作的时间预算耗尽。
    #[error("操作超时")]
    Timeout,
    /// 会话、流、队列或数据长度达到当前实现的资源边界。
    #[error("资源达到上限")]
    ResourceLimit,
    /// 底层网络或本地 I/O 错误。
    #[error("网络 I/O 失败：{0}")]
    Io(#[from] io::Error),
}

/// 使用公共错误分类的操作结果。
pub type Result<T> = std::result::Result<T, Error>;

/// 字面 IP 地址或域名；此类型本身不执行 DNS 查询。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// IPv4 或 IPv6 字面地址。
    Ip(IpAddr),
    /// 域名文本；由 [`Destination::new`] 构造时已完成 IDNA 规范化。
    Domain(String),
}

/// 带非零端口的目标地址；节点端点与业务目标的角色由调用接口决定。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Destination {
    address: Address,
    port: u16,
}

impl Destination {
    /// 校验地址与非零端口，将域名转为小写 IDNA ASCII；不查询 DNS。
    ///
    /// `host` 不含端口，IPv6 字面地址不带方括号；非法格式返回 [`Error::InvalidAddress`]。
    pub fn new(host: &str, port: u16) -> Result<Self> {
        if port == 0 || host.is_empty() || host.trim() != host {
            return Err(Error::InvalidAddress);
        }
        let address = if let Ok(ip) = host.parse() {
            Address::Ip(ip)
        } else {
            if host
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || "/\\:@[]".contains(c))
            {
                return Err(Error::InvalidAddress);
            }
            let ascii = idna::domain_to_ascii(host).map_err(|_| Error::InvalidAddress)?;
            if ascii.trim_end_matches('.').is_empty()
                || ascii.len() > 255
                || ascii
                    .strip_suffix('.')
                    .unwrap_or(&ascii)
                    .split('.')
                    .any(|part| part.is_empty() || part.len() > 63)
            {
                return Err(Error::InvalidAddress);
            }
            Address::Domain(ascii.to_ascii_lowercase())
        };
        Ok(Self { address, port })
    }

    /// 借用字面地址或规范化域名。
    pub fn address(&self) -> &Address {
        &self.address
    }
    /// 返回非零目标端口。
    pub fn port(&self) -> u16 {
        self.port
    }
    /// 返回不带端口的主机文本；IPv6 不带方括号。
    pub fn host(&self) -> String {
        match &self.address {
            Address::Ip(ip) => ip.to_string(),
            Address::Domain(name) => name.clone(),
        }
    }
    /// 仅判断字面 IP 是否为回环地址；不解析域名，也不识别域名别名。
    pub fn is_loopback(&self) -> bool {
        matches!(self.address, Address::Ip(ip) if ip.is_loopback())
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.address {
            Address::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            _ => write!(f, "{}:{}", self.host(), self.port),
        }
    }
}

/// Tokio 双向字节流，允许移动且无需固定内存地址；不要求 `Sync`。
///
/// 写入可能部分完成；调用方仍须遵守 `AsyncWrite` 的刷新和关闭契约。
pub trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> IoStream for T {}
/// 独占的异步字节流；半关闭能否到达最终业务目标须另查能力声明。
pub type BoxStream = Box<dyn IoStream>;

/// 当前出站及其已选组合的数据能力，不代表对端已接受业务请求。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// 是否提供业务 TCP 字节流。
    pub tcp: bool,
    /// 是否能将写端 EOF 传播到最终目标，同时继续接收反向数据。
    pub tcp_eof: bool,
    /// 固定目标数据报；不等于 XUDP 或逐包多目标。
    pub udp: bool,
}

/// 建立操作的取消信号和相对超时；返回后的数据 I/O 生命周期另行管理。
#[derive(Clone)]
pub struct ConnectContext {
    /// 建立期间的协作取消信号；克隆上下文共享此信号。
    pub cancel: CancellationToken,
    /// 每次 [`Self::run`] 调用各自使用的相对时长，不是绝对截止时间。
    pub timeout: Duration,
}

/// 只建立代理端点的载体流；网站地址继续由上层代理协议编码。
pub trait StreamConnector: Send + Sync {
    /// 载体是否保留写端半关闭及反向读取；默认保守返回 `false`。
    fn tcp_eof(&self) -> bool {
        false
    }
    /// 按上下文建立指定代理端点的流；不得把该端点当成最终网站目标。
    fn connect_tcp<'a>(
        &'a self,
        endpoint: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>>;
}

/// 认证材料的逻辑协议域；摘要不能写入日志，也不能用配置别名绕过查重。
#[derive(Clone)]
pub struct ScopedCredentialFingerprint {
    /// 实际认证或秘密隔离的协议域，不得按配置别名或载体另造命名空间。
    pub protocol: String,
    /// 仅供配置查重的固定长度摘要；不是认证凭据，不得写入日志。
    pub fingerprint: [u8; 32],
}

impl ConnectContext {
    /// 创建独立取消域，并设置每次操作的相对超时。
    pub fn new(timeout: Duration) -> Self {
        Self {
            cancel: CancellationToken::new(),
            timeout,
        }
    }

    /// 运行一次操作；取消优先于同时就绪的结果，超时返回 [`Error::Timeout`]。
    ///
    /// 多次或嵌套调用不会自动扣减已耗时间，整条建立链的总预算由调用方维护。
    /// 取消或超时会丢弃当前 future，不能保证撤回已发送的帧或立即终止底层系统操作。
    pub async fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(Error::Cancelled),
            result = tokio::time::timeout(self.timeout, future) => result.map_err(|_| Error::Timeout)?,
        }
    }
}

/// 固定目标数据报通道的独占发送端。
pub trait DatagramSender: Send {
    /// 提交一个完整数据报，允许空负载；成功不代表对端业务已接收。
    ///
    /// 帧可能已部分发送；中途取消或失败后丢弃会话，不重试该操作。
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>>;
}

/// 固定目标数据报通道的独占接收端。
pub trait DatagramReceiver: Send {
    /// 固定目标通道的业务对端，不能返回代理载体地址；未知时为 None。
    fn peer_addr(&self) -> Option<Destination> {
        None
    }
    /// 空负载为合法数据报；None 表示完整会话结束。
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>>;
}

/// 一个固定业务目标的全双工数据报通道；不提供逐包切换目标的语义。
pub struct DatagramChannel {
    /// 独占发送状态，可与接收端并行使用。
    pub sender: Box<dyn DatagramSender>,
    /// 独占接收状态，保留完整包边界。
    pub receiver: Box<dyn DatagramReceiver>,
}

/// 多目标 UDP 关联的独占发送端。
pub trait DatagramAssociationSender: Send {
    /// 向指定业务目标提交完整数据报，允许空负载。
    ///
    /// 一个关联中的不同目标保持同一出口 socket；取消或部分发送失败后丢弃关联，不重发。
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>>;
}

/// 一个业务来源地址及其完整数据报负载；来源不是代理载体地址。
pub type AddressedDatagram = (Destination, Vec<u8>);

/// 多目标 UDP 关联的独占接收端。
pub trait DatagramAssociationReceiver: Send {
    /// 返回业务来源与一个完整负载；空负载合法，`None` 才表示关联结束。
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>>;
}

/// 同一出口 socket 的逐包多目标关联，不能用多个固定目标通道冒充。
pub struct DatagramAssociation {
    /// 保持关联出口身份的发送端。
    pub sender: Box<dyn DatagramAssociationSender>,
    /// 返回真实业务来源与完整包的接收端。
    pub receiver: Box<dyn DatagramAssociationReceiver>,
}

/// 已构造的出站对象；带节点身份的连接池、会话和认证状态不得跨节点隐式共享。
pub trait Outbound: Send + Sync {
    /// 报告当前组合的业务 TCP、目标 EOF 和固定目标 UDP 能力。
    fn capabilities(&self) -> Capabilities;
    /// 是否提供同一出口 socket 的多目标关联；独立于固定目标 UDP，默认不支持。
    fn supports_udp_association(&self) -> bool {
        false
    }
    /// 建立多目标关联；默认返回 [`Error::Unsupported`]，生命周期由返回对象管理。
    fn associate_udp<'a>(
        &'a self,
        _context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async { Err(Error::Unsupported("出站未提供多目标 UDP 关联")) })
    }
    /// 建立到业务目标的字节流；返回时的握手完成边界由具体协议定义。
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>>;
    /// 建立固定业务目标的数据报通道；不得据此推定多目标关联能力。
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>>;
}

/// 所有接入协议使用的目标访问边界，提供方绑定节点身份与出口策略。
pub trait AccessService: Send + Sync {
    /// 节点所选出口是否提供多目标关联；默认不支持。
    fn supports_udp_association(&self) -> bool {
        false
    }
    /// 通过统一出口建立关联；默认返回 [`Error::Unsupported`]。
    fn associate_udp<'a>(
        &'a self,
        _context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async {
            Err(Error::Unsupported("目标访问服务未提供多目标 UDP 关联"))
        })
    }
    /// 按节点绑定的策略访问 TCP 业务目标，目标地址族不受节点接入地址族限制。
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>>;
    /// 按节点绑定的策略访问一个固定 UDP 业务目标。
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>>;
}

/// 一次节点处理所需的取消、资源与观测上下文；不包含其他节点的认证材料。
#[derive(Clone)]
pub struct InboundContext {
    /// 物理 TCP 连接地址；虚拟载体或无连接入口可以不提供。
    pub peer_addr: Option<std::net::SocketAddr>,
    /// 物理 TCP 连接的本地地址；无对应物理连接时可不提供。
    pub local_addr: Option<std::net::SocketAddr>,
    /// 当前节点处理的取消域；实现须停止派生任务并释放会话资源。
    pub cancel: CancellationToken,
    /// 目标建立操作的时长配置；跨阶段总预算须由执行建立链的调用方维护。
    pub connect_timeout: Duration,
    /// 无有效数据活动时的空闲预算，具体协议可有额外边界。
    pub idle_timeout: Duration,
    /// 停止接入后给予已有任务的有限排空时长。
    pub drain_timeout: Duration,
    /// 框架允许的数据报缓冲上限，不保证协议或网络可承载同样大的负载。
    pub max_datagram_size: usize,
    /// 本载体允许的逻辑流数量上限；仍须取得共享流预算。
    pub max_streams: usize,
    /// 同时约束全局及本节点的附加逻辑流预算。
    pub stream_budget: StreamBudget,
    /// 本节点事件汇报入口；不得向其中写入凭据或业务负载。
    pub events: std::sync::Arc<dyn NodeObserver>,
}

/// 累计观测事件；物理会话与逻辑流可分别计数，不构成活跃连接快照。
#[derive(Clone, Copy)]
pub enum NodeEvent {
    /// 接纳了实现所定义的一个会话或逻辑流。
    Accepted,
    /// 一个处理单元正常结束，不等于业务请求已成功。
    Completed,
    /// 一个处理单元失败。
    Failed,
    /// 因预算、队列或其他边界丢弃了处理单元或数据报。
    Dropped,
}
/// 注入节点的事件观察者，负责归入相应节点与全局统计。
pub trait NodeObserver: Send + Sync {
    /// 记录一个累计事件；不承载身份秘密或包内容。
    fn record(&self, event: NodeEvent);
}

/// 全局与节点两层信号量组成的逻辑流配额。
#[derive(Clone)]
pub struct StreamBudget {
    global: std::sync::Arc<tokio::sync::Semaphore>,
    node: std::sync::Arc<tokio::sync::Semaphore>,
}
/// 同时持有两层流配额的租约；丢弃时自动归还名额。
pub struct StreamLease {
    _global: tokio::sync::OwnedSemaphorePermit,
    _node: tokio::sync::OwnedSemaphorePermit,
}
impl StreamBudget {
    /// 关联共享全局配额及当前节点配额；不会在构造时取得名额。
    pub fn new(
        global: std::sync::Arc<tokio::sync::Semaphore>,
        node: std::sync::Arc<tokio::sync::Semaphore>,
    ) -> Self {
        Self { global, node }
    }
    /// 任一配额已关闭时返回 `true`；不表示当前是否仍有可用名额。
    pub fn is_closed(&self) -> bool {
        self.global.is_closed() || self.node.is_closed()
    }
    /// 立即取得两层名额；不足或已关闭返回 [`Error::ResourceLimit`]，不等待。
    ///
    /// 载体已占一个会话名额；附加逻辑流仍须取得此租约。
    pub fn try_acquire(&self) -> Result<StreamLease> {
        Ok(StreamLease {
            _global: self
                .global
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?,
            _node: self
                .node
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?,
        })
    }
}

/// 协议节点只持有本节点凭据，目标连接必须交给注入的统一访问服务。
pub trait InboundProtocol: Send + Sync {
    /// 是否依赖多目标 UDP 关联；配置准备阶段据此校验统一出口能力。
    fn requires_udp_association(&self) -> bool {
        false
    }
    /// 返回实际参与鉴权的材料摘要，供旧版单协议域接口兼容；不得写入日志。
    /// 未参与认证的空字段或备用秘密不能赋予节点鉴权资格。
    fn credential_fingerprints(&self) -> Vec<[u8; 32]>;
    /// 返回实际参与鉴权的协议域与摘要；包装协议应保留内层真实域。
    ///
    /// 默认将旧接口摘要归入 `default_protocol`；未使用的秘密不得伪造鉴权资格。
    fn scoped_credential_fingerprints(
        &self,
        default_protocol: &str,
    ) -> Vec<ScopedCredentialFingerprint> {
        self.credential_fingerprints()
            .into_iter()
            .map(|fingerprint| ScopedCredentialFingerprint {
                protocol: default_protocol.to_owned(),
                fingerprint,
            })
            .collect()
    }
    /// 返回额外秘密隔离域，不授予鉴权资格；默认保留既有分域凭据行为。
    /// 注册表合并鉴权和隔离集合后拒绝跨条目复用，空隔离集合不能隐藏真实鉴权摘要。
    fn credential_isolation_fingerprints(
        &self,
        default_protocol: &str,
    ) -> Vec<ScopedCredentialFingerprint> {
        self.scoped_credential_fingerprints(default_protocol)
    }
    /// 是否必须回环监听；默认 `true`，不能据此推定具体保密或鉴权能力。
    fn requires_loopback(&self) -> bool {
        true
    }
    /// 是否需要物理 TCP 监听器；不是业务 TCP 能力声明。
    fn supports_tcp(&self) -> bool {
        true
    }
    /// 是否需要物理 UDP 监听 socket；不是业务 UDP 能力声明。
    fn supports_udp(&self) -> bool {
        false
    }
    /// 是否自行管理虚拟载体入口；默认不支持。
    fn supports_virtual(&self) -> bool {
        false
    }
    /// 处理一条入口字节流；鉴权后仅通过 `access` 访问业务目标。
    ///
    /// 实现负责上下文取消、空闲与派生任务回收，不得回退到其他节点凭据。
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: std::sync::Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>>;
    /// 处理本节点的物理 UDP socket；默认返回 [`Error::Unsupported`]。
    fn handle_udp<'a>(
        &'a self,
        _socket: std::sync::Arc<tokio::net::UdpSocket>,
        _access: std::sync::Arc<dyn AccessService>,
        _context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("节点未提供 UDP 监听")) })
    }
    /// 运行本节点虚拟入口并遵守取消和资源预算；默认不支持。
    fn handle_virtual<'a>(
        &'a self,
        _access: std::sync::Arc<dyn AccessService>,
        _context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("节点未提供虚拟载体监听")) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_validation_and_idna() {
        assert_eq!(
            Destination::new("EXAMPLE.INVALID", 443).unwrap().host(),
            "example.invalid"
        );
        assert_eq!(
            Destination::new("例子.invalid", 443).unwrap().host(),
            "xn--fsqu00a.invalid"
        );
        assert_eq!(Destination::new("::1", 53).unwrap().to_string(), "[::1]:53");
        for name in ["", " bad.invalid", "a/b", "a\0b", "name:443"] {
            assert!(Destination::new(name, 1).is_err());
        }
        assert!(Destination::new("127.0.0.1", 0).is_err());
    }

    #[tokio::test]
    async fn cancellation_and_budget() {
        let context = ConnectContext::new(Duration::from_millis(1));
        assert!(matches!(
            context.run(std::future::pending::<Result<()>>()).await,
            Err(Error::Timeout)
        ));
        context.cancel.cancel();
        assert!(matches!(
            context.run(async { Ok(()) }).await,
            Err(Error::Cancelled)
        ));
    }
}
