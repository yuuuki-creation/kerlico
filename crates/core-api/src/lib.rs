//! 模块间共享的地址、I/O 和取消契约；不依赖具体协议或配置格式。

use std::{fmt, future::Future, io, net::IpAddr, pin::Pin, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
/// 可克隆的协作取消信号；克隆共享取消状态，子令牌用于限制取消传播范围。
pub use tokio_util::sync::CancellationToken;
mod relay;
pub use relay::{relay_streams, relay_tcp, relay_tcp_io};
mod flow;
pub use flow::*;
mod identity;
pub use identity::*;
mod access;
pub use access::*;
mod lifecycle;
pub use lifecycle::*;
mod login_backoff;
pub use login_backoff::LoginBackoff;
mod node_tasks;
pub use node_tasks::*;
mod peer_lease;
pub use peer_lease::*;
mod device;
pub use device::*;
mod carrier;
pub use carrier::CarrierUsage;
mod locale;
pub use locale::{Language, LocalizedError, diagnostic_translation};
mod diagnostic;
pub use diagnostic::{Diagnostic, DiagnosticSink, LocalizedDiagnostic};

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
    /// 启动失败及同一启动事务的资源回收事实。
    #[error("启动失败：{primary}；回收超时={cleanup_timed_out}，回收失败数={cleanup_failures}")]
    Startup {
        primary: Box<Error>,
        cleanup_timed_out: bool,
        cleanup_failures: usize,
    },
    #[error(
        "运行回收未完全完成；主要错误={primary:?}，回收超时={cleanup_timed_out}，回收失败数={cleanup_failures}"
    )]
    Shutdown {
        primary: Option<Box<Error>>,
        cleanup_timed_out: bool,
        cleanup_failures: usize,
    },
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

/// 一条建立链的取消信号、绝对期限与可信资源作用域。
#[derive(Clone)]
pub struct ConnectContext {
    /// 建立期间的协作取消信号；克隆上下文共享此信号。
    pub cancel: CancellationToken,
    /// 本次操作的时长上限；增加该值不能延长内部绝对期限。
    pub timeout: Duration,
    deadline: Deadline,
    resource: ResourceKey,
    service: ServiceStatus,
    node_cancel: CancellationToken,
    peer_cancel: CancellationToken,
    target_mode: FamilyMode,
    udp_source: Option<std::net::SocketAddr>,
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

impl ConnectContext {
    pub fn language(&self) -> Language {
        self.service.language()
    }
    /// 创建独立请求取消域和建立链的绝对截止时间。
    pub fn new(timeout: Duration) -> Self {
        Self {
            cancel: CancellationToken::new(),
            timeout,
            deadline: Deadline::after(timeout),
            resource: ResourceKey::detached(),
            service: ServiceStatus::default(),
            node_cancel: CancellationToken::new(),
            peer_cancel: CancellationToken::new(),
            target_mode: FamilyMode::DualV4Preferred,
            udp_source: None,
        }
    }

    /// 记录本机 UDP 入口的来源地址；出站可据此让同一来源跨载体保持会话身份。
    pub fn with_udp_source(mut self, source: std::net::SocketAddr) -> Self {
        self.udp_source = Some(source);
        self
    }

    pub fn udp_source(&self) -> Option<std::net::SocketAddr> {
        self.udp_source
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    pub fn with_timeout(&self, timeout: Duration) -> Self {
        let mut next = self.clone();
        next.timeout = timeout.min(self.remaining());
        next
    }

    /// 多目标关联的新目标建立使用独立期限，保留已绑定服务、成员与取消域。
    pub fn new_operation(&self, timeout: Duration) -> Self {
        let mut next = self.clone();
        next.timeout = timeout;
        next.deadline = Deadline::after(timeout);
        next
    }

    pub fn resource_key(&self) -> &ResourceKey {
        &self.resource
    }
    pub fn service_cancel(&self) -> CancellationToken {
        self.service.cancel()
    }
    /// 返回当前命名服务固定的失败原因，不改变请求或服务状态。
    pub fn service_failure(&self) -> Option<ServiceFailure> {
        self.service.failure()
    }
    /// 借用命名服务的只读生命周期事实，不拥有服务或任务集合。
    pub fn service_status(&self) -> ServiceStatus {
        self.service.clone()
    }
    pub fn node_cancel(&self) -> CancellationToken {
        self.node_cancel.clone()
    }
    pub fn peer_cancel(&self) -> CancellationToken {
        self.peer_cancel.clone()
    }
    pub fn target_mode(&self) -> FamilyMode {
        self.target_mode
    }
    pub fn remaining(&self) -> Duration {
        self.timeout.min(self.deadline.remaining())
    }
    pub fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// 仅由运行装配边界设置可信资源作用域，不接收协议凭据。
    pub fn scoped(
        &self,
        host: &ServiceContext,
        source: &Source,
        node_cancel: CancellationToken,
        peer_cancel: CancellationToken,
        target_mode: FamilyMode,
    ) -> Self {
        let mut next = self.clone();
        next.resource = host.resource_key(source);
        next.service = host.status();
        next.node_cancel = node_cancel;
        next.peer_cancel = peer_cancel;
        next.target_mode = target_mode;
        next
    }

    /// 请求、节点与 peer 取消优先，其次返回服务的固定失败或正常取消，再判断建立期限。
    ///
    /// 多次和嵌套调用共用同一个绝对期限。
    /// 取消或超时会丢弃当前 future，不能保证撤回已发送的帧或立即终止底层系统操作。
    pub async fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        let service_cancel = self.service.cancel();
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(Error::Cancelled),
            _ = self.node_cancel.cancelled() => Err(Error::Cancelled),
            _ = self.peer_cancel.cancelled() => Err(Error::Cancelled),
            _ = service_cancel.cancelled() => Err(self.service.error()),
            result = tokio::time::timeout(self.remaining(), future) => result.map_err(|_| Error::Timeout)?,
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

/// 协议后端扩展边界。每条命名计划只有一个运行实例，池按可信ResourceKey分区。
pub trait Outbound: Send + Sync {
    /// 停止本实例拥有的池和后台资源。服务所有者随后等待登记任务退出。
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
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
    ) -> BoxFuture<'a, Result<OpenedTcp>>;
    /// 建立固定业务目标的数据报通道；不得据此推定多目标关联能力。
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>>;
}

/// 一次节点处理所需的取消、资源与观测上下文；不包含其他节点的认证材料。
#[derive(Clone)]
pub struct InboundContext {
    /// 原物理 TCP peer 的资源租约；节点级、UDP 与虚拟入口上下文不携带它。
    pub peer_lease: Option<PeerLease>,
    /// Engine 持有的节点实际任务所有者；派生任务必须登记且不能从 peer 关闭它。
    pub tasks: NodeTasks,
    /// 物理 TCP 连接地址；虚拟载体或无连接入口可以不提供。
    pub peer_addr: Option<std::net::SocketAddr>,
    /// 物理 TCP 连接的本地地址；无对应物理连接时可不提供。
    pub local_addr: Option<std::net::SocketAddr>,
    /// 当前处理单元的取消域；TCP peer 使用节点子域，不能据此关闭同节点其他 peer。
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
    /// 局部强制回收事实；Engine 在外层及全部真实节点任务 join 后才累计。
    ForcedCleanup,
}
/// 注入节点的事件观察者，负责归入相应节点与全局统计。
pub trait NodeObserver: Send + Sync {
    /// 记录一个累计事件；不承载身份秘密或包内容。
    fn record(&self, event: NodeEvent);
    /// 结构化诊断与累计计数分离，调用方可选择语言或持久化类别。
    fn diagnostic(&self, event: Diagnostic<'_>) {
        eprintln!("{}", event.localized(Language::default()));
    }
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

/// 协议节点只持本节点凭据，真实鉴别后经注入绑定取得可信PeerSession。
pub trait InboundProtocol: Send + Sync {
    /// 是否依赖多目标 UDP 关联；配置准备阶段据此校验统一出口能力。
    fn requires_udp_association(&self) -> bool {
        false
    }
    /// 配置查重清单，认证成员与保护材料分开；摘要不能用来重建运行身份。
    fn credential_manifest(&self) -> CredentialManifest;
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
    /// 入口运行期间常驻占用的会话数；节点会话上限须大于它，才有配额留给业务流。
    fn reserved_sessions(&self) -> usize {
        0
    }
    /// 处理一条入口字节流；鉴别后仅通过 `ingress` 签发的PeerSession访问业务目标。
    ///
    /// 实现负责上下文取消、空闲与派生任务回收，不得回退到其他节点凭据。
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>>;
    /// 处理本节点的物理 UDP socket；默认返回 [`Error::Unsupported`]。
    fn handle_udp<'a>(
        &'a self,
        _socket: std::sync::Arc<tokio::net::UdpSocket>,
        _ingress: IngressBinding,
        _context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("节点未提供 UDP 监听")) })
    }
    /// 运行本节点虚拟入口并遵守取消和资源预算；默认不支持。
    fn handle_virtual<'a>(
        &'a self,
        _ingress: IngressBinding,
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

    #[tokio::test]
    async fn public_budget_and_cancel_cannot_replace_trusted_scope() {
        let node = CancellationToken::new();
        let service = ServiceContext::for_test();
        let source = Source::Local {
            node: NodeId::parse("test-node").unwrap(),
        };
        let mut context = ConnectContext::new(Duration::from_millis(5)).scoped(
            &service,
            &source,
            node.clone(),
            CancellationToken::new(),
            FamilyMode::V4Only,
        );
        context.timeout = Duration::from_secs(60);
        assert!(matches!(
            context.run(std::future::pending::<Result<()>>()).await,
            Err(Error::Timeout)
        ));
        let mut next = context.new_operation(Duration::from_secs(1));
        next.cancel = CancellationToken::new();
        node.cancel();
        assert!(matches!(
            next.run(async { Ok(()) }).await,
            Err(Error::Cancelled)
        ));
        assert!(!service.cancel().is_cancelled());
    }
}
