//! 转发入口与协议节点调度；核心不按协议名称分支。

use kerlico_config::{ForwardKind, ForwardSpec, Limits, PreparedConfig, PreparedNode};
use kerlico_core::{
    BoxStream, CancellationToken, ConnectContext, DatagramReceiver, DatagramSender, Destination,
    Diagnostic, Error, FlowFailure, FlowOutcome, InboundContext, IngressBinding, Language, NodeId,
    NodeTasks, PeerSession, Result, RuntimeOptions, ServiceRetirement, ShutdownReport,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, hash_map::Entry},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
mod history;
use history::{HistoryCommit, HistoryOwner};

use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::Instant,
};

/// 运行期累计事件计数，供调用方观测；不是活跃连接数或业务成功数。
///
/// 各原子计数独立更新，读取多个字段不形成一致事务快照。
/// 调用方应只读；当前公开原子字段并未在类型层面禁止外部写入。
#[derive(Default)]
pub struct Stats {
    /// 持久化周期提交失败事件；默认保持转发并保留有界积压，最终提交失败仍返回错误。
    pub history_failures: AtomicU64,
    /// 接纳的会话或逻辑处理单元数，不代表鉴权或目标连接成功。
    pub accepted: AtomicU64,
    /// 正常结束的处理单元数，不代表应用层请求成功。
    pub completed: AtomicU64,
    /// 失败事件数，可包含载体和逻辑流各自报告的事件。
    pub failed: AtomicU64,
    /// 因队列、配额等边界丢弃的事件数，可按数据报计数。
    pub dropped: AtomicU64,
    /// 已确认完成的强制回收事件，不计作业务失败或包丢弃。
    pub forced_cleanup: AtomicU64,
}

/// 运行中已停止的入口标签。入口不会自行恢复，记录只增不减。
#[derive(Clone, Default)]
pub struct FailedNodes(Arc<Mutex<BTreeSet<String>>>);
impl FailedNodes {
    pub fn tags(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }
    fn report(&self, tag: &NodeId, error: &Error, language: Language) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(tag.to_string());
        let (code, error) = (error.code(), error.localized(language));
        match language {
            Language::ZhCn => eprintln!("[{code}] 入口 {tag} 已停止：{error}"),
            Language::En => eprintln!("[{code}] Inbound {tag} stopped: {error}"),
        }
    }
}

const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// 句柄暂时耗尽或对端在 accept 前放弃，都不代表监听器失效。
fn accept_retryable(error: &std::io::Error) -> bool {
    const ENFILE: i32 = 23;
    const EMFILE: i32 = 24;
    error.kind() == std::io::ErrorKind::ConnectionAborted
        || matches!(error.raw_os_error(), Some(ENFILE | EMFILE))
}

struct Inbound {
    spec: ForwardSpec,
    target: Destination,
    ingress: IngressBinding,
    socket: Socket,
}

enum Socket {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}

struct BoundNode {
    spec: PreparedNode,
    ingress: IngressBinding,
    tcp: Option<TcpListener>,
    udp: Option<Arc<UdpSocket>>,
}
#[derive(Clone)]
struct NodeResources {
    language: Language,
    global: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    stats: Arc<Stats>,
    local_stats: Arc<Stats>,
    cleanup: NodeCleanup,
}
struct Observer {
    language: Language,
    global: Arc<Stats>,
    local: Arc<Stats>,
    forced: Arc<AtomicBool>,
}
impl kerlico_core::NodeObserver for Observer {
    fn diagnostic(&self, event: Diagnostic<'_>) {
        eprintln!("{}", event.localized(self.language));
    }
    fn record(&self, event: kerlico_core::NodeEvent) {
        if matches!(event, kerlico_core::NodeEvent::ForcedCleanup) {
            self.forced.store(true, Ordering::Release);
            return;
        }
        for stats in [&self.global, &self.local] {
            let counter = match event {
                kerlico_core::NodeEvent::Accepted => &stats.accepted,
                kerlico_core::NodeEvent::Completed => &stats.completed,
                kerlico_core::NodeEvent::Failed => &stats.failed,
                kerlico_core::NodeEvent::Dropped => &stats.dropped,
                kerlico_core::NodeEvent::ForcedCleanup => &stats.forced_cleanup,
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}
fn node_context(
    limits: &Limits,
    node: &PreparedNode,
    cancel: CancellationToken,
    resources: &NodeResources,
) -> InboundContext {
    InboundContext {
        peer_lease: None,
        tasks: resources.cleanup.tasks.clone(),
        peer_addr: None,
        local_addr: None,
        cancel,
        connect_timeout: limits.connect_timeout(),
        idle_timeout: limits.idle_timeout(),
        drain_timeout: limits.drain_timeout(),
        max_datagram_size: limits.max_datagram_size,
        max_streams: node.max_sessions.min(256),
        stream_budget: kerlico_core::StreamBudget::new(
            resources.global.clone(),
            resources.slots.clone(),
        ),
        events: Arc::new(Observer {
            language: resources.language,
            global: resources.stats.clone(),
            local: resources.local_stats.clone(),
            forced: resources.cleanup.forced.clone(),
        }),
    }
}

#[derive(Clone)]
struct NodeCleanup {
    tasks: NodeTasks,
    ingress: IngressBinding,
    deadline: Arc<Mutex<Option<Instant>>>,
    forced: Arc<AtomicBool>,
    global: Arc<Stats>,
    local: Option<Arc<Stats>>,
}
impl NodeCleanup {
    fn new(
        id: NodeId,
        ingress: IngressBinding,
        global: Arc<Stats>,
        local: Option<Arc<Stats>>,
    ) -> Self {
        Self {
            tasks: NodeTasks::new(id, ingress.node_cancel()),
            ingress,
            deadline: Arc::new(Mutex::new(None)),
            forced: Arc::new(AtomicBool::new(false)),
            global,
            local,
        }
    }
    fn start(&self, proposed: Instant) -> Instant {
        self.ingress.stop_admission();
        *self
            .deadline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_or_insert(proposed)
    }
    async fn finish(&self, proposed: Instant, handler_joined: bool) -> ShutdownReport {
        let report = self.tasks.shutdown_at(self.start(proposed)).await;
        if handler_joined
            && report.is_clean()
            && (report.forced_tasks > 0 || self.forced.load(Ordering::Acquire))
        {
            self.global.forced_cleanup.fetch_add(1, Ordering::Relaxed);
            if let Some(local) = &self.local {
                local.forced_cleanup.fetch_add(1, Ordering::Relaxed);
            }
        }
        report
    }
}
fn node_socket(address: SocketAddr, udp: bool) -> Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        if address.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        if udp {
            socket2::Type::DGRAM
        } else {
            socket2::Type::STREAM
        },
        Some(if udp {
            socket2::Protocol::UDP
        } else {
            socket2::Protocol::TCP
        }),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket)
}

/// 已持有监听器的运行实例；通过统一出口调度固定入口和独立协议节点。
pub struct Engine {
    history_owner: Option<HistoryOwner>,
    history_interval: std::time::Duration,
    language: Language,
    egress: kerlico_egress::EgressRuntime,
    inbounds: Vec<Inbound>,
    nodes: Vec<BoundNode>,
    node_stats: BTreeMap<String, Arc<Stats>>,
    limits: Limits,
    stats: Arc<Stats>,
    failed: FailedNodes,
}

impl Engine {
    /// 绑定全部入口及节点监听器，不建立业务目标连接。
    ///
    /// 任一绑定失败会释放此前取得的监听资源；没有入口时返回配置错误。
    /// 节点 IPv6 监听显式仅接收 IPv6，节点身份及带身份的资源分别管理。
    pub async fn bind(config: PreparedConfig) -> Result<Self> {
        Self::bind_with_options(config, RuntimeOptions::new(kerlico_egress::native_device())).await
    }
    /// 使用应用持有的设备租约；Engine 退出不关闭设备所有者。
    pub async fn bind_with_device(
        config: PreparedConfig,
        device: kerlico_core::DeviceLease,
    ) -> Result<Self> {
        Self::bind_with_options(config, RuntimeOptions::new(device)).await
    }
    pub async fn bind_with_options(
        config: PreparedConfig,
        options: RuntimeOptions,
    ) -> Result<Self> {
        let config = config.into_parts();
        if config.inbounds.is_empty() && config.nodes.is_empty() {
            return Err(Error::Config("没有配置入站".into()));
        }
        let limits = config.limits;
        let language = options.language;
        let egress = kerlico_egress::EgressRuntime::start_with_options(
            config.egress,
            options,
            limits.connect_timeout(),
        )
        .await?;
        let mut history_owner = None;
        let history_interval = std::time::Duration::from_millis(
            config
                .history
                .as_ref()
                .map_or(1000, |history| history.sample_interval_ms),
        );
        let bound = async {
            if let Some(spec) = config.history {
                history_owner = Some(
                    HistoryOwner::start(
                        spec,
                        egress.telemetry(),
                        Instant::now() + limits.connect_timeout(),
                    )
                    .await?,
                );
            }
            let mut inbounds = Vec::new();
            for spec in config.inbounds {
                let target = spec.target.destination()?;
                let ingress = egress.ingress(&NodeId::parse(&spec.tag)?)?;
                let socket = match spec.kind {
                    ForwardKind::Tcp => Socket::Tcp(TcpListener::bind(spec.listen).await?),
                    ForwardKind::Udp => Socket::Udp(Arc::new(UdpSocket::bind(spec.listen).await?)),
                };
                inbounds.push(Inbound {
                    spec,
                    target,
                    ingress,
                    socket,
                });
            }
            let mut nodes = Vec::new();
            let mut node_stats = BTreeMap::new();
            for mut node in config.nodes {
                let ingress = egress.ingress(&NodeId::parse(&node.tag)?)?;
                let tcp = if node.protocol.supports_tcp() {
                    let socket = node_socket(node.listen, false)?;
                    socket.listen(1024)?;
                    let listener = TcpListener::from_std(socket.into())?;
                    node.listen = listener.local_addr()?;
                    Some(listener)
                } else {
                    None
                };
                let udp = if node.protocol.supports_udp() {
                    let socket =
                        Arc::new(UdpSocket::from_std(node_socket(node.listen, true)?.into())?);
                    if tcp.is_none() {
                        node.listen = socket.local_addr()?;
                    }
                    Some(socket)
                } else {
                    None
                };
                node_stats.insert(node.tag.clone(), Arc::new(Stats::default()));
                nodes.push(BoundNode {
                    spec: node,
                    ingress,
                    tcp,
                    udp,
                });
            }
            Ok::<_, Error>((inbounds, nodes, node_stats))
        }
        .await;
        match bound {
            Ok((inbounds, nodes, node_stats)) => Ok(Self {
                history_owner,
                history_interval,
                language,
                egress,
                inbounds,
                nodes,
                node_stats,
                limits,
                stats: Arc::new(Stats::default()),
                failed: FailedNodes::default(),
            }),
            Err(primary) => {
                let deadline = Instant::now() + limits.drain_timeout();
                let mut cleanup = egress.shutdown_at(deadline).await;
                if let Some(owner) = &mut history_owner {
                    cleanup.merge(&owner.shutdown(deadline).await);
                }
                Err(Error::Startup {
                    primary: Box::new(primary),
                    cleanup_timed_out: cleanup.timed_out,
                    cleanup_failures: cleanup.failed_tasks,
                })
            }
        }
    }

    pub fn telemetry(&self) -> kerlico_egress::Telemetry {
        self.egress.telemetry()
    }
    /// 历史存储独立于命名出站；超时后仅收据完成才证明原生写者真实释放。
    pub fn history_retirement(&self) -> Option<ServiceRetirement> {
        self.history_owner.as_ref().map(HistoryOwner::retirement)
    }

    /// 在消费本实例前取得命名服务回收收据；关闭超时后仍可等待真实任务全部释放。
    pub fn service_retirements(
        &self,
    ) -> Vec<(kerlico_core::OutId, kerlico_core::ServiceRetirement)> {
        self.egress.service_retirements()
    }

    /// 返回入口标签与实际绑定地址，包括端口 `0` 分配后的结果。
    ///
    /// 同一节点的 TCP、UDP 共用绑定端口时只列一项；虚拟入口没有物理地址可列。
    pub fn listeners(&self) -> Result<Vec<(String, SocketAddr)>> {
        let mut result: Vec<_> = self
            .inbounds
            .iter()
            .map(|inbound| {
                let address = match &inbound.socket {
                    Socket::Tcp(value) => value.local_addr()?,
                    Socket::Udp(value) => value.local_addr()?,
                };
                Ok((inbound.spec.tag.clone(), address))
            })
            .collect::<Result<_>>()?;
        for node in &self.nodes {
            if let Some(listener) = &node.tcp {
                result.push((node.spec.tag.clone(), listener.local_addr()?));
            } else if let Some(socket) = &node.udp {
                result.push((node.spec.tag.clone(), socket.local_addr()?));
            }
        }
        Ok(result)
    }

    /// 获取全局累计统计的共享观测句柄；计数仍随运行更新，不是值拷贝快照。
    pub fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    /// 返回按节点标签索引的统计句柄，包含本地协议入口；原子计数仍实时更新。
    pub fn node_stats(&self) -> BTreeMap<String, Arc<Stats>> {
        self.node_stats.clone()
    }

    /// 返回运行中已停止入口的共享观测句柄；关闭阶段的失败由 `run` 的返回值报告。
    pub fn failed_nodes(&self) -> FailedNodes {
        self.failed.clone()
    }

    /// 消费本实例并运行入口，直到取消或全部入口退出；调用方应等待返回以完成回收。
    ///
    /// 取消后停止新接入，给予已有任务有限排空时间，再取消并回收。
    /// 单个业务会话失败通常计入统计，不意味着此方法一定返回错误；成功返回也不代表全部业务成功。
    /// 单入口故障与其他入口隔离，保留首个错误并在整个运行退出时返回。
    /// 累计失败计数和业务流记录不能用于判断某个入口或出站服务的当前健康状态。
    pub async fn run(mut self, cancel: CancellationToken) -> Result<()> {
        let scope = cancel.child_token();
        let _guard = scope.clone().drop_guard();
        let semaphore = Arc::new(Semaphore::new(self.limits.max_sessions));
        let mut workers = JoinSet::new();
        let mut owners = HashMap::new();
        let mut cleaners = JoinSet::new();
        let mut cleaning_owners: HashMap<tokio::task::Id, NodeCleanup> = HashMap::new();
        for bound in self.nodes {
            let local_stats = self
                .node_stats
                .get(&bound.spec.tag)
                .expect("节点统计已构造")
                .clone();
            let cleanup = NodeCleanup::new(
                NodeId::parse(&bound.spec.tag)?,
                bound.ingress.clone(),
                self.stats.clone(),
                Some(local_stats.clone()),
            );
            let resources = NodeResources {
                language: self.language,
                global: semaphore.clone(),
                slots: Arc::new(Semaphore::new(bound.spec.max_sessions)),
                stats: self.stats.clone(),
                local_stats,
                cleanup: cleanup.clone(),
            };
            let worker = workers.spawn(serve_bound_node(
                bound,
                self.limits.clone(),
                scope.clone(),
                resources,
            ));
            owners.insert(worker.id(), cleanup);
        }
        for inbound in self.inbounds {
            let limits = self.limits.clone();
            let token = scope.clone();
            let slots = semaphore.clone();
            let stats = self.stats.clone();
            let cleanup = NodeCleanup::new(
                NodeId::parse(&inbound.spec.tag)?,
                inbound.ingress.clone(),
                stats.clone(),
                None,
            );
            let owned = cleanup.clone();
            let worker = workers.spawn(async move {
                match inbound.socket {
                    Socket::Tcp(listener) => {
                        serve_tcp(
                            listener,
                            inbound.target,
                            inbound.ingress,
                            limits,
                            token,
                            slots,
                            owned,
                        )
                        .await
                    }
                    Socket::Udp(socket) => {
                        serve_udp(
                            socket,
                            inbound.target,
                            inbound.ingress,
                            limits,
                            token,
                            slots,
                            owned,
                        )
                        .await
                    }
                }
            });
            owners.insert(worker.id(), cleanup);
        }
        let mut failure = None;
        let mut closing = None;
        let mut force_at = None;
        let mut forced = false;
        let mut cleanup = ShutdownReport::default();
        let mut sample = tokio::time::interval(self.history_interval);
        sample.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut history_job: Option<HistoryCommit> = None;
        while !workers.is_empty() || !cleaners.is_empty() {
            tokio::select! {
                biased;
                result=async { history_job.as_mut().expect("已启动历史提交").await }, if history_job.is_some()=>{
                    history_job = None;
                    match result {
                        Ok(Ok(())) => {},
                        Ok(Err(error)) => {
                            self.stats.history_failures.fetch_add(1, Ordering::Relaxed);
                            if self.history_owner.as_ref().is_some_and(|owner| owner.failure_policy == kerlico_config::HistoryFailurePolicy::StopEngine) {
                                failure.get_or_insert(error); scope.cancel();
                            }
                        },
                        Err(_) => { failure.get_or_insert(Error::Protocol("统计历史写者异常退出")); scope.cancel(); },
                    }
                },
                _=sample.tick(), if self.history_owner.is_some() && history_job.is_none() && closing.is_none()=>{
                    match self.history_owner.as_ref().expect("已配置历史所有者").checkpoint() {
                        Ok(job) => history_job = Some(job),
                        Err(error) => { failure.get_or_insert(error); scope.cancel(); },
                    }
                },
                _=scope.cancelled(), if closing.is_none()=>{
                    let now = Instant::now();
                    let deadline = now + self.limits.drain_timeout();
                    closing = Some(deadline);
                    force_at = Some(now + self.limits.drain_timeout().mul_f32(0.6));
                    for owner in owners.values() { owner.start(deadline); }
                    for owner in cleaning_owners.values() { owner.start(deadline); }
                },
                _=tokio::time::sleep_until(force_at.unwrap_or_else(Instant::now)), if closing.is_some() && !forced=>{
                    forced = true;
                    for owner in owners.values() {
                        owner.forced.store(true, Ordering::Release);
                        owner.tasks.cancel().cancel();
                    }
                    workers.abort_all();
                },
                _=tokio::time::sleep_until(closing.unwrap_or_else(Instant::now)), if closing.is_some()=>{
                    cleanup.timed_out = true;
                    workers.abort_all();
                    cleaners.abort_all();
                    break;
                },
                result=cleaners.join_next_with_id(), if !cleaners.is_empty()=>{
                    match result {
                        Some(Ok((id, report))) => { cleaning_owners.remove(&id); cleanup.merge(&report); },
                        Some(Err(error)) => {
                            cleanup.failed_tasks += 1;
                            if let Some(owner) = cleaning_owners.remove(&error.id()) { owners.insert(error.id(), owner); }
                        },
                        None => {},
                    }
                },
                result=workers.join_next_with_id(), if !workers.is_empty()=>{
                    let (id, stop_node) = match result {
                        Some(Ok((id, result))) => {
                            let stopped = result.is_err();
                            if let Err(error) = result {
                                let expected_cancel = matches!(error, Error::Cancelled)
                                    && (closing.is_some() || owners.get(&id).is_some_and(|owner| owner.tasks.cancel().is_cancelled()));
                                if !expected_cancel {
                                    if closing.is_none() && let Some(owner) = owners.get(&id) {
                                        self.failed.report(owner.tasks.id(), &error, self.language);
                                    }
                                    failure.get_or_insert(error);
                                    self.stats.failed.fetch_add(1,Ordering::Relaxed);
                                }
                            }
                            (id, stopped)
                        }
                        Some(Err(joined)) => {
                            if !joined.is_cancelled() || !forced {
                                let error = Error::Protocol("入口任务异常退出");
                                if closing.is_none() && let Some(owner) = owners.get(&joined.id()) {
                                    self.failed.report(owner.tasks.id(), &error, self.language);
                                }
                                failure.get_or_insert(error);
                                self.stats.failed.fetch_add(1,Ordering::Relaxed);
                            }
                            (joined.id(), true)
                        }
                        None => break,
                    };
                    if let Some(owner) = owners.remove(&id) {
                        if stop_node { owner.tasks.cancel().cancel(); }
                        let deadline = closing.unwrap_or_else(|| Instant::now() + self.limits.drain_timeout());
                        let copied = owner.clone();
                        let cleaner = cleaners.spawn(async move { copied.finish(deadline, true).await });
                        cleaning_owners.insert(cleaner.id(), owner);
                    }
                },
            }
        }
        let deadline = closing.unwrap_or_else(|| Instant::now() + self.limits.drain_timeout());
        for owner in owners.values() {
            cleanup.merge(&owner.finish(deadline, false).await);
        }
        for owner in cleaning_owners.values() {
            cleanup.merge(&owner.finish(deadline, false).await);
        }
        cleanup.merge(&self.egress.shutdown_at(deadline).await);
        if let Some(job) = history_job {
            match tokio::time::timeout_at(deadline, job).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => {
                    failure.get_or_insert(Error::Protocol("统计历史写者异常退出"));
                }
                Err(_) => cleanup.timed_out = true,
            }
        }
        if let Some(owner) = &mut self.history_owner {
            match owner.finish() {
                Ok(job) => match tokio::time::timeout_at(deadline, job).await {
                    Ok(Ok(Ok(()))) => {}
                    Ok(Ok(Err(error))) => {
                        failure.get_or_insert(error);
                    }
                    Ok(Err(_)) => {
                        failure.get_or_insert(Error::Protocol("统计历史最终提交失败"));
                    }
                    Err(_) => cleanup.timed_out = true,
                },
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
            cleanup.merge(&owner.shutdown(deadline).await);
        }
        if !cleanup.is_clean() {
            return Err(Error::Shutdown {
                primary: failure.map(Box::new),
                cleanup_timed_out: cleanup.timed_out,
                cleanup_failures: cleanup.failed_tasks,
            });
        }
        failure.map_or(Ok(()), Err)
    }
}

async fn serve_bound_node(
    bound: BoundNode,
    limits: Limits,
    stop: CancellationToken,
    resources: NodeResources,
) -> Result<()> {
    let force = bound.ingress.node_cancel();
    let mut handlers = JoinSet::new();
    let node = bound.spec;
    let ingress = bound.ingress;
    let cleanup = resources.cleanup.clone();
    if let Some(listener) = bound.tcp {
        let handler = cleanup.tasks.spawn_tracked(serve_node(
            node.clone(),
            ingress.clone(),
            listener,
            limits.clone(),
            stop.clone(),
            resources.clone(),
            force.clone(),
        ))?;
        handlers.spawn(async move { handler.await? });
    }
    if bound.udp.is_some() || node.protocol.supports_virtual() {
        let context = node_context(&limits, &node, force.clone(), &resources);
        let handler = cleanup.tasks.spawn_tracked(async move {
            if let Some(socket) = bound.udp {
                node.protocol.handle_udp(socket, ingress, context).await
            } else {
                node.protocol.handle_virtual(ingress, context).await
            }
        })?;
        handlers.spawn(async move { handler.await? });
    }
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            _=force.cancelled()=>break,
            result=handlers.join_next()=>match result {
                Some(Ok(Ok(())))=>{},
                Some(Ok(Err(Error::Cancelled))) if force.is_cancelled()=>{},
                Some(Ok(Err(error)))=>{ failure=Some(error); force.cancel(); break; },
                Some(Err(_))=>{ failure=Some(Error::Protocol("节点入口任务异常退出")); force.cancel(); break; },
                None=>break,
            }
        }
    }
    resources.slots.close();
    let deadline = cleanup.start(Instant::now() + limits.drain_timeout());
    let graceful = Instant::now() + deadline.saturating_duration_since(Instant::now()) / 2;
    let mut forced = false;
    loop {
        let until = if forced { deadline } else { graceful };
        match tokio::time::timeout_at(until, handlers.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(Error::Cancelled)))) if force.is_cancelled() => {}
            Ok(Some(Ok(Err(error)))) => {
                failure.get_or_insert(error);
            }
            Ok(Some(Err(error))) if error.is_cancelled() && forced => {}
            Ok(Some(Err(_))) => {
                failure.get_or_insert(Error::Protocol("节点入口回收失败"));
            }
            Ok(None) => break,
            Err(_) if !forced => {
                forced = true;
                cleanup.forced.store(true, Ordering::Release);
                force.cancel();
                handlers.abort_all();
            }
            Err(_) => return Err(shutdown_error(failure, Error::Timeout)),
        }
    }
    failure.map_or(Ok(()), Err)
}
async fn serve_node(
    node: PreparedNode,
    access: IngressBinding,
    listener: TcpListener,
    limits: Limits,
    stop: CancellationToken,
    resources: NodeResources,
    force: CancellationToken,
) -> Result<()> {
    let shared = resources.clone();
    let NodeResources {
        language: _,
        global,
        slots,
        stats,
        local_stats,
        cleanup,
    } = resources;
    let mut sessions = JoinSet::new();
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            _=force.cancelled()=>break,
            result=sessions.join_next(),if !sessions.is_empty()=>{if result.is_some_and(|r|r.is_err()){stats.failed.fetch_add(1,Ordering::Relaxed);local_stats.failed.fetch_add(1,Ordering::Relaxed);}},
            accepted=listener.accept()=>{
                let (stream,peer_addr)=match accepted {Ok(v)=>v,Err(error) if accept_retryable(&error)=>{tokio::time::sleep(ACCEPT_BACKOFF).await;continue;},Err(error)=>{failure=Some(Error::Io(error));break;}};
                let Ok(budget)=kerlico_core::StreamBudget::new(global.clone(),slots.clone()).try_acquire() else {stats.dropped.fetch_add(1,Ordering::Relaxed);local_stats.dropped.fetch_add(1,Ordering::Relaxed);continue;};
                let _=stream.set_nodelay(true);
                let protocol=node.protocol.clone();let access=access.clone();let token=force.child_token();let stats=stats.clone();let local_stats=local_stats.clone();
                let mut context=node_context(&limits,&node,token.clone(),&shared);
                context.peer_addr=Some(peer_addr);context.local_addr=stream.local_addr().ok();
                let lease = kerlico_core::PeerLease::new(token.clone(), budget);
                context.peer_lease = Some(lease.clone());
                let stream = PeerIo::new(stream, lease.clone(), token.clone());
                stats.accepted.fetch_add(1,Ordering::Relaxed);
                local_stats.accepted.fetch_add(1,Ordering::Relaxed);
                spawn_session(&cleanup.tasks, &mut sessions, async move {
                    let _peer_lease=lease;
                    let result=tokio::select! {_=token.cancelled()=>Err(Error::Cancelled),r=protocol.handle(Box::new(stream),access,context)=>r};
                    if result.is_ok(){stats.completed.fetch_add(1,Ordering::Relaxed);local_stats.completed.fetch_add(1,Ordering::Relaxed);}else{stats.failed.fetch_add(1,Ordering::Relaxed);local_stats.failed.fetch_add(1,Ordering::Relaxed);}
                })?;
            }
        }
    }
    slots.close();
    drop(listener);
    if failure.is_some() {
        force.cancel();
    }
    match drain(
        &mut sessions,
        &force,
        cleanup.start(Instant::now() + limits.drain_timeout()),
    )
    .await
    {
        Ok(true) => {
            cleanup.forced.store(true, Ordering::Release);
        }
        Ok(false) => {}
        Err(cleanup) => return Err(shutdown_error(failure, cleanup)),
    }
    failure.map_or(Ok(()), Err)
}

fn shutdown_error(primary: Option<Error>, cleanup: Error) -> Error {
    let timed_out = matches!(&cleanup, Error::Timeout);
    Error::Shutdown {
        primary: Some(Box::new(primary.unwrap_or(cleanup))),
        cleanup_timed_out: timed_out,
        cleanup_failures: usize::from(!timed_out),
    }
}

fn spawn_session(
    owner: &NodeTasks,
    sessions: &mut JoinSet<()>,
    future: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<tokio::task::AbortHandle> {
    let task = owner.spawn_tracked(future)?;
    Ok(sessions.spawn(async move {
        let _ = task.await;
    }))
}

async fn drain<T: Send + 'static>(
    tasks: &mut JoinSet<T>,
    force: &CancellationToken,
    deadline: Instant,
) -> Result<bool> {
    let start = Instant::now();
    let graceful = start + deadline.saturating_duration_since(start) / 2;
    loop {
        match tokio::time::timeout_at(graceful, tasks.join_next()).await {
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) if error.is_cancelled() => {}
            Ok(Some(Err(_))) => return Err(Error::Protocol("会话回收时任务异常退出")),
            Ok(None) => return Ok(false),
            Err(_) => break,
        }
    }
    force.cancel();
    tasks.abort_all();
    loop {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) if error.is_cancelled() => {}
            Ok(Some(Err(_))) => return Err(Error::Protocol("强制回收时任务异常退出")),
            Ok(None) => return Ok(true),
            Err(_) => return Err(Error::Timeout),
        }
    }
}

async fn serve_tcp(
    listener: TcpListener,
    target: Destination,
    ingress: IngressBinding,
    limits: Limits,
    stop: CancellationToken,
    slots: Arc<Semaphore>,
    cleanup: NodeCleanup,
) -> Result<()> {
    let stats = cleanup.global.clone();
    let force = ingress.node_cancel();
    let _guard = force.clone().drop_guard();
    let mut sessions = JoinSet::new();
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            _=force.cancelled()=>break,
            result=sessions.join_next(),if !sessions.is_empty()=>{ if result.is_some_and(|result|result.is_err()) { stats.failed.fetch_add(1,Ordering::Relaxed); } },
            accepted=listener.accept()=>{
                let (stream,peer)=match accepted { Ok(value)=>value, Err(error) if accept_retryable(&error)=>{ tokio::time::sleep(ACCEPT_BACKOFF).await; continue; }, Err(error)=>{failure=Some(Error::Io(error));break;} };
                let permit=match slots.clone().try_acquire_owned() { Ok(value)=>value,Err(_)=>{stats.dropped.fetch_add(1,Ordering::Relaxed);continue;} };
                let target=target.clone();let ingress=ingress.clone();let limits=limits.clone();let token=force.child_token();let stats=stats.clone();
                stats.accepted.fetch_add(1,Ordering::Relaxed);
                let task_owner = cleanup.tasks.clone();
                spawn_session(&cleanup.tasks, &mut sessions, async move {
                    let _permit=permit;
                    let _session_cancel=token.clone().drop_guard();
                    let mut context = forward_context(&limits,token.clone(), task_owner);
                    context.peer_addr=Some(peer);context.local_addr=stream.local_addr().ok();
                    let result=match ingress.local(&context) {
                        Ok(outbound)=>tcp_session(stream,&target,&outbound,&limits,token).await,
                        Err(error)=>Err(error),
                    };
                    if result.is_ok() { stats.completed.fetch_add(1,Ordering::Relaxed); } else { stats.failed.fetch_add(1,Ordering::Relaxed); }
                })?;
            }
        }
    }
    drop(listener);
    if failure.is_some() {
        force.cancel();
    }
    match drain(
        &mut sessions,
        &force,
        cleanup.start(Instant::now() + limits.drain_timeout()),
    )
    .await
    {
        Ok(true) => {
            cleanup.forced.store(true, Ordering::Release);
        }
        Ok(false) => {}
        Err(cleanup) => return Err(shutdown_error(failure, cleanup)),
    }
    failure.map_or(Ok(()), Err)
}

async fn tcp_session(
    stream: TcpStream,
    target: &Destination,
    outbound: &PeerSession,
    limits: &Limits,
    cancel: CancellationToken,
) -> Result<()> {
    let context = ConnectContext::new(limits.connect_timeout()).with_cancel(cancel.clone());
    let remote = outbound.connect_tcp(target, &context).await?;
    relay(Box::new(stream), remote, limits, cancel).await
}

async fn relay(
    a: BoxStream,
    b: kerlico_core::TcpFlow,
    limits: &Limits,
    cancel: CancellationToken,
) -> Result<()> {
    kerlico_core::relay_tcp(a, b, limits.idle_timeout(), cancel).await
}

async fn serve_udp(
    socket: Arc<UdpSocket>,
    target: Destination,
    ingress: IngressBinding,
    limits: Limits,
    stop: CancellationToken,
    slots: Arc<Semaphore>,
    cleanup: NodeCleanup,
) -> Result<()> {
    let stats = cleanup.global.clone();
    let force = ingress.node_cancel();
    let _guard = force.clone().drop_guard();
    let mut sessions = JoinSet::new();
    let mut senders: HashMap<SocketAddr, (u64, mpsc::Sender<Vec<u8>>)> = HashMap::new();
    let mut owners = HashMap::new();
    let mut generation = 0u64;
    let mut buffer = vec![0; limits.max_datagram_size + 1];
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            _=force.cancelled()=>break,
            result=sessions.join_next_with_id(),if !sessions.is_empty()=>{
                let finished=match result {
                    Some(Ok((task,())))=>owners.remove(&task),
                    Some(Err(error))=>{stats.failed.fetch_add(1,Ordering::Relaxed);owners.remove(&error.id())},
                    None=>None,
                };
                if let Some((peer,id))=finished && senders.get(&peer).is_some_and(|(current,_)|*current==id) { senders.remove(&peer); }
            },
            packet=socket.recv_from(&mut buffer)=>{
                let (count,peer)=match packet {Ok(value)=>value,Err(error)=>{failure=Some(Error::Io(error));break;}};
                if count>limits.max_datagram_size {stats.dropped.fetch_add(1,Ordering::Relaxed);continue;}
                if senders.get(&peer).is_some_and(|(_,sender)|sender.is_closed()) {senders.remove(&peer);}
                if let Entry::Vacant(entry)=senders.entry(peer) {
                    let permit=match slots.clone().try_acquire_owned() {Ok(value)=>value,Err(_)=>{stats.dropped.fetch_add(1,Ordering::Relaxed);continue;}};
                    generation=match generation.checked_add(1) {Some(value)=>value,None=>{failure=Some(Error::ResourceLimit);break;}};let id=generation;
                    let (sender,receiver)=mpsc::channel(limits.udp_queue_packets);
                    entry.insert((id,sender));
                    let socket=socket.clone();let target=target.clone();let ingress=ingress.clone();let limits=limits.clone();let token=force.child_token();let stats=stats.clone();
                    stats.accepted.fetch_add(1,Ordering::Relaxed);
                    let task_owner = cleanup.tasks.clone();
                    let task=spawn_session(&cleanup.tasks, &mut sessions, async move {
                        let _permit=permit;
                        let _session_cancel=token.clone().drop_guard();
                        let mut context=forward_context(&limits,token.clone(), task_owner);
                        context.peer_addr=Some(peer);context.local_addr=socket.local_addr().ok();
                        let result=match ingress.local(&context) {
                            Ok(outbound)=>udp_session(socket,peer,&target,&outbound,receiver,&limits,token).await,
                            Err(error)=>Err(error),
                        };
                        if result.is_ok() {stats.completed.fetch_add(1,Ordering::Relaxed);} else {stats.failed.fetch_add(1,Ordering::Relaxed);}
                    })?;
                    owners.insert(task.id(),(peer,id));
                }
                if senders.get(&peer).expect("关联刚建立").1.try_send(buffer[..count].to_vec()).is_err() {stats.dropped.fetch_add(1,Ordering::Relaxed);}
            }
        }
    }
    drop(senders);
    if failure.is_some() {
        force.cancel();
    }
    match drain(
        &mut sessions,
        &force,
        cleanup.start(Instant::now() + limits.drain_timeout()),
    )
    .await
    {
        Ok(true) => {
            cleanup.forced.store(true, Ordering::Release);
        }
        Ok(false) => {}
        Err(cleanup) => return Err(shutdown_error(failure, cleanup)),
    }
    failure.map_or(Ok(()), Err)
}

async fn udp_session(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    target: &Destination,
    outbound: &PeerSession,
    mut queue: mpsc::Receiver<Vec<u8>>,
    limits: &Limits,
    cancel: CancellationToken,
) -> Result<()> {
    let context = ConnectContext::new(limits.connect_timeout())
        .with_cancel(cancel.clone())
        .with_udp_source(peer);
    let channel = outbound.connect_udp(target, &context).await?;
    let (mut sender, mut receiver, completion) = channel.into_parts();
    let result = {
        let (activity, mut observed) = watch::channel(Instant::now());
        let outgoing = async {
            while let Some(packet) = queue.recv().await {
                sender.send(&packet).await?;
                activity.send_replace(Instant::now());
            }
            std::future::pending::<Result<()>>().await
        };
        let incoming = async {
            while let Some(packet) = receiver.recv().await? {
                if packet.len() > limits.max_datagram_size {
                    return Err(Error::ResourceLimit);
                }
                let sent = socket.send_to(&packet, peer).await?;
                if sent != packet.len() {
                    return Err(Error::Protocol("入站UDP回写不完整"));
                }
                activity.send_replace(Instant::now());
            }
            Ok::<_, Error>(())
        };
        tokio::pin!(outgoing, incoming);
        let timer = tokio::time::sleep(limits.idle_timeout());
        tokio::pin!(timer);
        loop {
            tokio::select! {
                biased;
                _=cancel.cancelled()=>break Err(Error::Cancelled),
                result=&mut outgoing=>break result,
                result=&mut incoming=>break result,
                changed=observed.changed()=>{if changed.is_ok(){timer.as_mut().reset(*observed.borrow_and_update()+limits.idle_timeout());}},
                _=&mut timer=>break Err(Error::Timeout),
            }
        }
    };
    completion.finish(match &result {
        Ok(()) => FlowOutcome::ProtocolEnd,
        Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
    });
    result
}

struct ForwardObserver;
impl kerlico_core::NodeObserver for ForwardObserver {
    fn record(&self, _event: kerlico_core::NodeEvent) {}
}
fn forward_context(limits: &Limits, cancel: CancellationToken, tasks: NodeTasks) -> InboundContext {
    InboundContext {
        peer_lease: None,
        tasks,
        peer_addr: None,
        local_addr: None,
        cancel,
        connect_timeout: limits.connect_timeout(),
        idle_timeout: limits.idle_timeout(),
        drain_timeout: limits.drain_timeout(),
        max_datagram_size: limits.max_datagram_size,
        max_streams: 1,
        stream_budget: kerlico_core::StreamBudget::new(
            Arc::new(Semaphore::new(1)),
            Arc::new(Semaphore::new(1)),
        ),
        events: Arc::new(ForwardObserver),
    }
}

struct PeerIo {
    stream: TcpStream,
    _lease: kerlico_core::PeerLease,
    read_cancel: Option<kerlico_core::BoxFuture<'static, ()>>,
    write_cancel: Option<kerlico_core::BoxFuture<'static, ()>>,
}
impl PeerIo {
    fn new(stream: TcpStream, lease: kerlico_core::PeerLease, cancel: CancellationToken) -> Self {
        let read_cancel = cancel.clone();
        Self {
            stream,
            _lease: lease,
            read_cancel: Some(Box::pin(async move { read_cancel.cancelled().await })),
            write_cancel: Some(Box::pin(async move { cancel.cancelled().await })),
        }
    }
    fn check(
        cancellation: &mut Option<kerlico_core::BoxFuture<'static, ()>>,
        cx: &mut std::task::Context<'_>,
    ) -> std::io::Result<()> {
        if cancellation
            .as_mut()
            .is_some_and(|future| future.as_mut().poll(cx).is_ready())
        {
            *cancellation = None;
        }
        if cancellation.is_none() {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                Error::Cancelled,
            ))
        } else {
            Ok(())
        }
    }
}
impl tokio::io::AsyncRead for PeerIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = Self::check(&mut this.read_cancel, cx) {
            return std::task::Poll::Ready(Err(error));
        }
        std::pin::Pin::new(&mut this.stream).poll_read(cx, buffer)
    }
}
impl tokio::io::AsyncWrite for PeerIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = Self::check(&mut this.write_cancel, cx) {
            return std::task::Poll::Ready(Err(error));
        }
        std::pin::Pin::new(&mut this.stream).poll_write(cx, buffer)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = Self::check(&mut this.write_cancel, cx) {
            return std::task::Poll::Ready(Err(error));
        }
        std::pin::Pin::new(&mut this.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = Self::check(&mut this.write_cancel, cx) {
            return std::task::Poll::Ready(Err(error));
        }
        std::pin::Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod peer_io_tests {
    use super::*;
    use std::{future::poll_fn, io, pin::Pin, task::Poll, time::Duration};
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
        sync::oneshot,
        time::timeout,
    };

    #[tokio::test]
    async fn cancelled_physical_relay_preserves_cancelled_outcome() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let global = Arc::new(Semaphore::new(1));
        let node = Arc::new(Semaphore::new(1));
        let cancel = CancellationToken::new();
        let lease = kerlico_core::PeerLease::new(
            cancel.clone(),
            kerlico_core::StreamBudget::new(global.clone(), node.clone())
                .try_acquire()
                .unwrap(),
        );
        let front = PeerIo::new(server, lease, cancel.clone());
        let (target, _remote) = tokio::io::duplex(1);
        let (finished, outcome) = oneshot::channel();
        let flow = kerlico_core::TcpFlow::tracked(
            Box::new(target),
            kerlico_core::TcpConnectInfo::unknown(),
            move |value| {
                let _ = finished.send(value);
            },
        );
        cancel.cancel();
        let result = timeout(
            Duration::from_secs(1),
            kerlico_core::relay_tcp(
                Box::new(front),
                flow,
                Duration::from_secs(1),
                CancellationToken::new(),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(Error::Cancelled)));
        assert_eq!(
            outcome.await.unwrap(),
            FlowOutcome::Failed(FlowFailure::Cancelled)
        );
        assert_eq!(global.available_permits(), 1);
        assert_eq!(node.available_permits(), 1);
    }

    #[tokio::test]
    async fn split_physical_pending_halves_cancel_and_release_socket_and_permits() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        socket2::SockRef::from(&server)
            .set_send_buffer_size(4096)
            .unwrap();
        socket2::SockRef::from(&client)
            .set_recv_buffer_size(4096)
            .unwrap();
        let global = Arc::new(Semaphore::new(1));
        let node = Arc::new(Semaphore::new(1));
        let cancel = CancellationToken::new();
        let lease = kerlico_core::PeerLease::new(
            cancel.clone(),
            kerlico_core::StreamBudget::new(global.clone(), node.clone())
                .try_acquire()
                .unwrap(),
        );
        let stream = PeerIo::new(server, lease, cancel.clone());
        let (mut read, mut write) = tokio::io::split(stream);
        let (read_pending, read_ready) = oneshot::channel();
        let reader = tokio::spawn(async move {
            let mut pending = Some(read_pending);
            let mut bytes = [0; 1];
            let result = poll_fn(|cx| {
                let result = Pin::new(&mut read).poll_read(cx, &mut ReadBuf::new(&mut bytes));
                if result.is_pending()
                    && let Some(pending) = pending.take()
                {
                    let _ = pending.send(());
                }
                result
            })
            .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
            let error = read.read_exact(&mut bytes).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert_eq!(
                FlowFailure::from_error(&Error::Io(error)),
                FlowFailure::Cancelled
            );
        });
        timeout(Duration::from_secs(1), read_ready)
            .await
            .unwrap()
            .unwrap();
        let (write_pending, write_ready) = oneshot::channel();
        let writer = tokio::spawn(async move {
            let mut pending = Some(write_pending);
            let bytes = [7; 8192];
            let mut written = 0;
            let error = poll_fn(|cx| {
                loop {
                    match Pin::new(&mut write).poll_write(cx, &bytes) {
                        Poll::Ready(Ok(count)) => {
                            assert!(count > 0);
                            written += count;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(error),
                        Poll::Pending => {
                            if written > 0
                                && let Some(pending) = pending.take()
                            {
                                let _ = pending.send(());
                            }
                            return Poll::Pending;
                        }
                    }
                }
            })
            .await;
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            let error = write.write_all(b"again").await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert_eq!(
                FlowFailure::from_error(&Error::Io(error)),
                FlowFailure::Cancelled
            );
            assert_eq!(
                write.flush().await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
            assert_eq!(
                write.shutdown().await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
            written
        });
        timeout(Duration::from_secs(1), write_ready)
            .await
            .unwrap()
            .unwrap();
        assert!(!reader.is_finished());
        assert!(!writer.is_finished());
        assert_eq!(global.available_permits(), 0);
        assert_eq!(node.available_permits(), 0);
        cancel.cancel();
        timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap();
        let written = timeout(Duration::from_secs(1), writer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(global.available_permits(), 1);
        assert_eq!(node.available_permits(), 1);
        let mut received = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.len(), written);
        assert!(received.iter().all(|byte| *byte == 7));
    }
}
