//! 运行期唯一业务账本与持久快照边界。

use kerlico_core::{
    Address, Destination, Error, FlowFailure, FlowOutcome, NodeId, OriginalTarget, OutId, Result,
    RunId, SessionIdentity, Source, TargetBind, UserId,
};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_PENDING_EVENTS: usize = 4096;

/// DNS 查询或建立、转发失败事件。不含来源地址与业务载荷。
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EventRecord {
    pub run: String,
    pub sequence: u64,
    pub kind: String,
    pub ts_ms: u64,
    pub node: String,
    pub user: Option<String>,
    pub outbound: String,
    pub target: Option<String>,
    pub code: String,
    pub addresses: Vec<String>,
    /// 待写队列已满时，此事件之前被丢弃的事件数。
    pub dropped_before: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FlowId {
    pub run: RunId,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Usage {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub upload_packets: u64,
    pub download_packets: u64,
}
impl Usage {
    pub(crate) fn add(&mut self, other: Self) {
        self.upload_bytes = self.upload_bytes.saturating_add(other.upload_bytes);
        self.download_bytes = self.download_bytes.saturating_add(other.download_bytes);
        self.upload_packets = self.upload_packets.saturating_add(other.upload_packets);
        self.download_packets = self.download_packets.saturating_add(other.download_packets);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKind {
    Tcp,
    FixedUdp,
    UdpAssociation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowStage {
    Opening,
    LocalConnected,
    LocalDatagramReady,
    ProxyReady,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowEnd {
    Completed,
    ClosedByCaller,
    Cancelled,
    Failed,
    Timeout,
}

/// 流的路由归属：命中规则、经过的策略组与本机进程；用于连接表和按组中断。
#[derive(Clone, Debug, Default)]
pub struct FlowRoute {
    pub rule: Option<kerlico_routing::RuleLabel>,
    /// 从规则目标起逐层经过的策略组，不含最终命名出站。
    pub groups: Vec<OutId>,
    pub process: Option<(String, String)>,
}

pub struct FlowLedger {
    id: FlowId,
    route: FlowRoute,
    close: kerlico_core::CancellationToken,
    source: Source,
    outbound: OutId,
    original: Option<OriginalTarget>,
    observed_source: Option<SocketAddr>,
    kind: FlowKind,
    started_ms: u64,
    ended_ms: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    up_packets: AtomicU64,
    down_packets: AtomicU64,
    saturated: AtomicBool,
    stage: AtomicU8,
    end: AtomicU8,
    observation: Mutex<Option<Destination>>,
    target_bind: Mutex<TargetBind>,
    datagram_targets: Mutex<Vec<DatagramTargetRecord>>,
    omitted_target_events: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct DatagramTargetRecord {
    pub original: Destination,
    pub local_target: Option<Destination>,
    pub upload_bytes: u64,
    pub upload_packets: u64,
    pub failed_sends: u64,
}

#[derive(Clone, Debug)]
pub struct FlowRecord {
    pub id: FlowId,
    pub route: FlowRoute,
    pub source: Source,
    pub outbound: OutId,
    pub original: Option<OriginalTarget>,
    pub observed_source: Option<SocketAddr>,
    pub observed_target: Option<Destination>,
    pub target_bind: TargetBind,
    pub kind: FlowKind,
    pub stage: FlowStage,
    pub end: Option<FlowEnd>,
    pub started_ms: u64,
    pub ended_ms: Option<u64>,
    pub usage: Usage,
    pub saturated: bool,
    pub datagram_targets: Vec<DatagramTargetRecord>,
    pub omitted_target_events: u64,
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

impl FlowLedger {
    pub(crate) fn datagram_target(
        &self,
        target: &Destination,
        local: Option<Destination>,
        sent: Option<usize>,
    ) {
        if let Ok(mut targets) = self.datagram_targets.lock() {
            let index = match targets.iter().position(|entry| entry.original == *target) {
                Some(index) => index,
                None => {
                    if targets.len() >= 256 {
                        self.increment(&self.omitted_target_events, 1);
                        return;
                    }
                    targets.push(DatagramTargetRecord {
                        original: target.clone(),
                        local_target: None,
                        upload_bytes: 0,
                        upload_packets: 0,
                        failed_sends: 0,
                    });
                    targets.len() - 1
                }
            };
            let entry = &mut targets[index];
            if local.is_some() {
                entry.local_target = local;
            }
            match sent {
                Some(bytes) => {
                    entry.upload_packets = entry.upload_packets.saturating_add(1);
                    entry.upload_bytes = entry.upload_bytes.saturating_add(bytes as u64);
                }
                None => entry.failed_sends = entry.failed_sends.saturating_add(1),
            }
        }
    }
    pub(crate) fn bind_datagram_target(&self, target: &Destination, local: Destination) {
        if let Ok(mut targets) = self.datagram_targets.lock() {
            if let Some(entry) = targets.iter_mut().find(|entry| entry.original == *target) {
                entry.local_target = Some(local);
            } else if targets.len() < 256 {
                targets.push(DatagramTargetRecord {
                    original: target.clone(),
                    local_target: Some(local),
                    upload_bytes: 0,
                    upload_packets: 0,
                    failed_sends: 0,
                });
            }
        }
    }
    fn increment(&self, counter: &AtomicU64, value: u64) {
        let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            Some(match current.checked_add(value) {
                Some(next) => next,
                None => {
                    self.saturated.store(true, Ordering::Release);
                    u64::MAX
                }
            })
        });
    }
    pub(crate) fn upload(&self, count: usize, packet: bool) {
        self.increment(&self.up, count as u64);
        if packet {
            self.increment(&self.up_packets, 1);
        }
    }
    pub(crate) fn download(&self, count: usize, packet: bool) {
        self.increment(&self.down, count as u64);
        if packet {
            self.increment(&self.down_packets, 1);
        }
    }
    pub(crate) fn ready(&self, local: bool, observed: Option<Destination>) {
        self.stage.store(
            if local {
                if self.kind == FlowKind::Tcp { 1 } else { 3 }
            } else {
                2
            },
            Ordering::Release,
        );
        if let Ok(mut value) = self.observation.lock() {
            *value = observed;
        }
    }
    pub(crate) fn target_bind(&self, bind: TargetBind) {
        *self
            .target_bind
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = bind;
    }
    pub(crate) fn close_token(&self) -> kerlico_core::CancellationToken {
        self.close.clone()
    }
    pub(crate) fn finish(&self, reason: FlowEnd) {
        let code = match reason {
            FlowEnd::Completed => 1,
            FlowEnd::ClosedByCaller => 2,
            FlowEnd::Cancelled => 3,
            FlowEnd::Failed => 4,
            FlowEnd::Timeout => 5,
        };
        if self
            .end
            .compare_exchange(0, 255, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.ended_ms.store(timestamp(), Ordering::Release);
            self.end.store(code, Ordering::Release);
        }
    }
    pub(crate) fn usage(&self) -> Usage {
        Usage {
            upload_bytes: self.up.load(Ordering::Acquire),
            download_bytes: self.down.load(Ordering::Acquire),
            upload_packets: self.up_packets.load(Ordering::Acquire),
            download_packets: self.down_packets.load(Ordering::Acquire),
        }
    }
    fn record(&self) -> FlowRecord {
        FlowRecord {
            id: self.id,
            route: self.route.clone(),
            source: self.source.clone(),
            outbound: self.outbound.clone(),
            original: self.original.clone(),
            observed_source: self.observed_source,
            observed_target: self.observation.lock().ok().and_then(|v| v.clone()),
            target_bind: self
                .target_bind
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            kind: self.kind,
            stage: match self.stage.load(Ordering::Acquire) {
                1 => FlowStage::LocalConnected,
                2 => FlowStage::ProxyReady,
                3 => FlowStage::LocalDatagramReady,
                _ => FlowStage::Opening,
            },
            end: match self.end.load(Ordering::Acquire) {
                1 => Some(FlowEnd::Completed),
                2 => Some(FlowEnd::ClosedByCaller),
                3 => Some(FlowEnd::Cancelled),
                4 => Some(FlowEnd::Failed),
                5 => Some(FlowEnd::Timeout),
                _ => None,
            },
            started_ms: self.started_ms,
            ended_ms: match self.ended_ms.load(Ordering::Acquire) {
                0 => None,
                value => Some(value),
            },
            usage: self.usage(),
            saturated: self.saturated.load(Ordering::Acquire),
            datagram_targets: self
                .datagram_targets
                .lock()
                .map(|values| values.clone())
                .unwrap_or_default(),
            omitted_target_events: self.omitted_target_events.load(Ordering::Acquire),
        }
    }
}

struct LeaseInner {
    telemetry: Telemetry,
    ledger: Arc<FlowLedger>,
    cancelled: [kerlico_core::CancellationToken; 4],
    service: kerlico_core::ServiceStatus,
    state: Mutex<CompletionState>,
    _peer_lease: Option<kerlico_core::PeerLease>,
}
enum CompletionState {
    Running {
        first_failure: Option<FlowFailure>,
        upload_shutdown: bool,
        download_eof: bool,
    },
    Closing(FlowEnd),
}
fn failure_end(failure: FlowFailure) -> FlowEnd {
    match failure {
        FlowFailure::Timeout => FlowEnd::Timeout,
        FlowFailure::Cancelled => FlowEnd::Cancelled,
        FlowFailure::Failed => FlowEnd::Failed,
    }
}
impl LeaseInner {
    fn cancellation_error(&self) -> Option<Error> {
        if self.cancelled[..3].iter().any(|token| token.is_cancelled()) {
            Some(Error::Cancelled)
        } else if let Some(failure) = self.service.failure() {
            Some(failure.error())
        } else if self.cancelled[3].is_cancelled() {
            Some(Error::Cancelled)
        } else {
            None
        }
    }
    fn cancellation_end(&self) -> Option<FlowEnd> {
        self.cancellation_error()
            .map(|error| failure_end(FlowFailure::from_error(&error)))
    }
    fn error_event(&self, code: &str) {
        let ledger = &self.ledger;
        let target = ledger
            .original
            .as_ref()
            .map(|original| original.target().to_string());
        self.telemetry.push_event(
            "error",
            &ledger.source,
            &ledger.outbound,
            target,
            code,
            Vec::new(),
        );
    }
}
impl Drop for LeaseInner {
    fn drop(&mut self) {
        let cancelled = self.cancellation_end();
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let reason = match *state {
            CompletionState::Closing(reason) => reason,
            CompletionState::Running {
                first_failure: Some(failure),
                ..
            } => failure_end(failure),
            CompletionState::Running { .. } => cancelled.unwrap_or(FlowEnd::ClosedByCaller),
        };
        self.ledger.finish(reason);
    }
}

#[derive(Clone)]
pub(crate) struct FlowLease(Arc<LeaseInner>);
impl FlowLease {
    pub(crate) fn new(
        telemetry: &Telemetry,
        ledger: Arc<FlowLedger>,
        context: &kerlico_core::ConnectContext,
        identity: &SessionIdentity,
    ) -> Self {
        Self(Arc::new(LeaseInner {
            telemetry: telemetry.clone(),
            ledger,
            cancelled: [
                context.cancel.clone(),
                context.peer_cancel(),
                context.node_cancel(),
                context.service_cancel(),
            ],
            service: context.service_status(),
            state: Mutex::new(CompletionState::Running {
                first_failure: None,
                upload_shutdown: false,
                download_eof: false,
            }),
            _peer_lease: identity.peer_lease(),
        }))
    }
    pub(crate) fn ledger(&self) -> &FlowLedger {
        &self.0.ledger
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.cancelled.iter().any(|token| token.is_cancelled())
    }
    pub(crate) fn cancellation_error(&self) -> Error {
        self.0.cancellation_error().unwrap_or(Error::Cancelled)
    }
    pub(crate) fn failed(&self, error: &Error) {
        self.report(FlowFailure::from_error(error), error.code());
    }
    pub(crate) fn io_failed(&self, error: &std::io::Error) {
        let failure = FlowFailure::from_io_error(error);
        let code = match failure {
            FlowFailure::Timeout => "operation.timeout",
            _ => "io.failed",
        };
        self.report(failure, code);
    }
    /// 每条流只记录首个非取消失败。
    fn report(&self, failure: FlowFailure, code: &str) {
        if self.observe_failure(failure) && !matches!(failure, FlowFailure::Cancelled) {
            self.0.error_event(code);
        }
    }
    pub(crate) fn observe_failure(&self, failure: FlowFailure) -> bool {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let CompletionState::Running { first_failure, .. } = &mut *state
            && first_failure.is_none()
        {
            *first_failure = Some(failure);
            return true;
        }
        false
    }
    pub(crate) fn upload_closed(&self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let CompletionState::Running {
            upload_shutdown, ..
        } = &mut *state
        {
            *upload_shutdown = true;
        }
    }
    pub(crate) fn download_closed(&self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let CompletionState::Running { download_eof, .. } = &mut *state {
            *download_eof = true;
        }
    }
    pub(crate) fn conclude(&self, outcome: FlowOutcome) {
        let unreported = {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let CompletionState::Running {
                first_failure,
                upload_shutdown,
                download_eof,
            } = &*state
            else {
                return;
            };
            let (reason, unreported) = if let Some(failure) = first_failure {
                (failure_end(*failure), false)
            } else {
                let reason = match outcome {
                    FlowOutcome::Failed(failure) => failure_end(failure),
                    FlowOutcome::ProtocolEnd
                        if self.0.ledger.stage.load(Ordering::Acquire) == 0 =>
                    {
                        self.0.cancellation_end().unwrap_or(FlowEnd::Completed)
                    }
                    FlowOutcome::ProtocolEnd => FlowEnd::Completed,
                    FlowOutcome::DuplexEof if *upload_shutdown && *download_eof => {
                        FlowEnd::Completed
                    }
                    FlowOutcome::ClosedByCaller => {
                        self.0.cancellation_end().unwrap_or(FlowEnd::ClosedByCaller)
                    }
                    FlowOutcome::DuplexEof => FlowEnd::ClosedByCaller,
                };
                (reason, true)
            };
            *state = CompletionState::Closing(reason);
            unreported.then_some(reason)
        };
        match unreported {
            Some(FlowEnd::Timeout) => self.0.error_event("operation.timeout"),
            Some(FlowEnd::Failed) => {
                let service = self.0.service.failure();
                self.0
                    .error_event(service.map_or("flow.failed", |failure| failure.error().code()));
            }
            _ => {}
        }
    }
    pub(crate) async fn cancelled(&self) {
        tokio::select! { _=self.0.cancelled[0].cancelled()=>{}, _=self.0.cancelled[1].cancelled()=>{}, _=self.0.cancelled[2].cancelled()=>{},_=self.0.cancelled[3].cancelled()=>{} }
    }
}

#[derive(Clone, Debug, Default)]
pub struct UsageSnapshot {
    pub engine: Usage,
    pub users: BTreeMap<UserId, Usage>,
    pub nodes: BTreeMap<NodeId, Usage>,
    pub outbounds: BTreeMap<OutId, Usage>,
    pub active_flows: usize,
    pub retained_records: usize,
    pub evicted_records: u64,
}
impl UsageSnapshot {
    fn account(&mut self, record: &FlowRecord) {
        self.engine.add(record.usage);
        self.nodes
            .entry(record.source.node().clone())
            .or_default()
            .add(record.usage);
        if let Some(user) = record.source.user() {
            self.users.entry(user).or_default().add(record.usage);
        }
        self.outbounds
            .entry(record.outbound.clone())
            .or_default()
            .add(record.usage);
    }

    fn account_ledger(&mut self, flow: &FlowLedger) {
        let usage = flow.usage();
        self.engine.add(usage);
        self.nodes
            .entry(flow.source.node().clone())
            .or_default()
            .add(usage);
        if let Some(user) = flow.source.user() {
            self.users.entry(user).or_default().add(usage);
        }
        self.outbounds
            .entry(flow.outbound.clone())
            .or_default()
            .add(usage);
    }
}

struct Registry {
    records: BTreeMap<u64, Arc<FlowLedger>>,
    order: VecDeque<u64>,
    archived: UsageSnapshot,
    pending: BTreeMap<u64, FlowRecord>,
    persistent: bool,
    events: VecDeque<EventRecord>,
    next_event: u64,
    dropped_events: u64,
    dns_events: bool,
    error_events: bool,
}
struct TelemetryInner {
    run: RunId,
    next: AtomicU64,
    last_trim_ms: AtomicU64,
    capacity: usize,
    registry: Mutex<Registry>,
}

fn maybe_trim_allocator(last_trim_ms: &AtomicU64) {
    let now = timestamp();
    let prev = last_trim_ms.load(Ordering::Relaxed);
    if now.saturating_sub(prev) >= 15_000
        && last_trim_ms
            .compare_exchange(prev, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        kerlico_core::trim_allocator();
    }
}

#[derive(Clone)]
pub struct Telemetry(Arc<TelemetryInner>);
impl Telemetry {
    pub fn new(capacity: usize) -> Self {
        Self(Arc::new(TelemetryInner {
            run: RunId::generate(),
            next: AtomicU64::new(1),
            last_trim_ms: AtomicU64::new(0),
            capacity,
            registry: Mutex::new(Registry {
                records: BTreeMap::new(),
                order: VecDeque::new(),
                archived: UsageSnapshot::default(),
                pending: BTreeMap::new(),
                persistent: false,
                events: VecDeque::new(),
                next_event: 1,
                dropped_events: 0,
                dns_events: false,
                error_events: false,
            }),
        }))
    }
    pub(crate) fn open(
        &self,
        identity: &SessionIdentity,
        outbound: &OutId,
        original: Option<OriginalTarget>,
        kind: FlowKind,
        route: FlowRoute,
        close: kerlico_core::CancellationToken,
    ) -> Result<Arc<FlowLedger>> {
        let mut registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        let soft_cap = if !registry.persistent && self.0.capacity > 4096 {
            1024
        } else {
            self.0.capacity
        };
        if registry.records.len() >= soft_cap {
            let remove = registry.order.iter().position(|id| {
                registry
                    .records
                    .get(id)
                    .is_some_and(|flow| matches!(flow.end.load(Ordering::Acquire), 1..=5))
            });
            if let Some(index) = remove {
                if registry.persistent && registry.pending.len() >= self.0.capacity {
                    return Err(Error::ResourceLimit);
                }
                let id = registry.order.remove(index).expect("已找到记录序号");
                if let Some(flow) = registry.records.remove(&id) {
                    if registry.persistent {
                        let record = flow.record();
                        registry.archived.account(&record);
                        registry.pending.insert(id, record);
                    } else {
                        registry.archived.account_ledger(&flow);
                    }
                    registry.archived.evicted_records += 1;
                }
            } else if registry.records.len() >= self.0.capacity {
                return Err(Error::ResourceLimit);
            }
        }
        let sequence = self
            .0
            .next
            .try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                next.checked_add(1)
            })
            .map_err(|_| Error::ResourceLimit)?;
        let flow = Arc::new(FlowLedger {
            id: FlowId {
                run: self.0.run,
                sequence,
            },
            route,
            close,
            source: identity.source().clone(),
            outbound: outbound.clone(),
            original,
            observed_source: identity.observed_source(),
            kind,
            started_ms: timestamp(),
            ended_ms: AtomicU64::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            up_packets: AtomicU64::new(0),
            down_packets: AtomicU64::new(0),
            saturated: AtomicBool::new(false),
            stage: AtomicU8::new(0),
            end: AtomicU8::new(0),
            observation: Mutex::new(None),
            target_bind: Mutex::new(TargetBind::Unknown),
            datagram_targets: Mutex::new(Vec::new()),
            omitted_target_events: AtomicU64::new(0),
        });
        registry.order.push_back(sequence);
        registry.records.insert(sequence, flow.clone());
        drop(registry);
        if sequence & 511 == 0 {
            maybe_trim_allocator(&self.0.last_trim_ms);
        }
        Ok(flow)
    }
    pub fn usage(&self) -> Result<UsageSnapshot> {
        let snapshot = {
            let registry = self
                .0
                .registry
                .lock()
                .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
            let mut snapshot = registry.archived.clone();
            snapshot.retained_records = registry.records.len();
            for flow in registry.records.values() {
                snapshot.active_flows += usize::from(flow.end.load(Ordering::Acquire) == 0);
                snapshot.account_ledger(flow);
            }
            snapshot
        };
        maybe_trim_allocator(&self.0.last_trim_ms);
        Ok(snapshot)
    }
    /// 尚未结束的流；活动流不会被容量淘汰，因此这里是完整的在线连接表。
    pub fn active(&self) -> Result<Vec<FlowRecord>> {
        let registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        Ok(registry
            .records
            .values()
            .filter(|flow| flow.end.load(Ordering::Acquire) == 0)
            .map(|flow| flow.record())
            .collect())
    }
    /// 触发匹配活动流的关闭令牌；流随后在计量边界中止并由租约结束一次。
    pub(crate) fn close_where(&self, matches: impl Fn(&FlowRecord) -> bool) -> usize {
        let Ok(registry) = self.0.registry.lock() else {
            return 0;
        };
        let mut closed = 0;
        for flow in registry.records.values() {
            if flow.end.load(Ordering::Acquire) == 0
                && !flow.close.is_cancelled()
                && matches(&flow.record())
            {
                flow.close.cancel();
                closed += 1;
            }
        }
        closed
    }
    pub fn run_id(&self) -> RunId {
        self.0.run
    }
    pub(crate) fn enable_history(&self) -> Result<()> {
        let mut registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        if !registry.records.is_empty()
            || registry.archived.evicted_records != 0
            || registry.persistent
        {
            return Err(Error::Config("历史记录必须在流量开始前且仅启用一次".into()));
        }
        registry.persistent = true;
        Ok(())
    }
    pub(crate) fn history_snapshot(&self) -> Result<(UsageSnapshot, Vec<FlowRecord>, Vec<u64>)> {
        let registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        let mut usage = registry.archived.clone();
        usage.retained_records = registry.records.len();
        let mut records: Vec<_> = registry.pending.values().cloned().collect();
        for flow in registry.records.values() {
            let record = flow.record();
            usage.active_flows += usize::from(record.end.is_none());
            usage.account(&record);
            records.push(record);
        }
        Ok((usage, records, registry.pending.keys().copied().collect()))
    }
    pub(crate) fn acknowledge_history(&self, saved: &[u64]) -> Result<()> {
        let mut registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        for id in saved {
            registry.pending.remove(id);
        }
        Ok(())
    }
    pub(crate) fn enable_events(&self, dns: bool, errors: bool) -> Result<()> {
        let mut registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        registry.dns_events = dns;
        registry.error_events = errors;
        Ok(())
    }
    fn push_event(
        &self,
        kind: &'static str,
        source: &Source,
        outbound: &OutId,
        target: Option<String>,
        code: &str,
        addresses: Vec<String>,
    ) {
        let Ok(mut registry) = self.0.registry.lock() else {
            return;
        };
        let enabled = match kind {
            "dns" => registry.dns_events,
            _ => registry.error_events,
        };
        if !enabled {
            return;
        }
        if registry.events.len() >= MAX_PENDING_EVENTS {
            registry.dropped_events = registry.dropped_events.saturating_add(1);
            return;
        }
        let sequence = registry.next_event;
        registry.next_event = sequence.saturating_add(1);
        let dropped_before = std::mem::take(&mut registry.dropped_events);
        registry.events.push_back(EventRecord {
            run: self.0.run.to_string(),
            sequence,
            kind: kind.into(),
            ts_ms: timestamp(),
            node: source.node().to_string(),
            user: source.user().map(|user| user.to_string()),
            outbound: outbound.to_string(),
            target,
            code: code.into(),
            addresses,
            dropped_before,
        });
    }
    /// 取得账本前的失败没有租约可报告，取消不算失败。
    pub(crate) fn open_failed(
        &self,
        source: &Source,
        outbound: &OutId,
        target: Option<&Destination>,
        error: &Error,
    ) {
        if FlowFailure::from_error(error) != FlowFailure::Cancelled {
            self.push_event(
                "error",
                source,
                outbound,
                target.map(ToString::to_string),
                error.code(),
                Vec::new(),
            );
        }
    }
    /// 外层超时或取消丢弃了尚未返回的查询。
    pub(crate) fn dns_aborted(&self, source: &Source, outbound: &OutId, target: &Destination) {
        if matches!(target.address(), Address::Domain(_)) {
            self.push_event(
                "dns",
                source,
                outbound,
                Some(target.host()),
                "dns.aborted",
                Vec::new(),
            );
        }
    }
    /// 只记录域名查询；字面 IP 目标不经过解析器。
    pub(crate) fn dns_event(
        &self,
        source: &Source,
        outbound: &OutId,
        target: &Destination,
        result: &Result<Vec<Destination>>,
    ) {
        if !matches!(target.address(), Address::Domain(_)) {
            return;
        }
        let (code, addresses) = match result {
            Ok(addresses) => ("ok", addresses.iter().map(Destination::host).collect()),
            Err(error) => (error.code(), Vec::new()),
        };
        self.push_event(
            "dns",
            source,
            outbound,
            Some(target.host()),
            code,
            addresses,
        );
    }
    /// 丢弃数本来挂在下一条事件上；没有下一条时单独记一条，否则计数随进程消失。
    pub(crate) fn pending_events(&self) -> Result<Vec<EventRecord>> {
        let mut registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        let dropped = std::mem::take(&mut registry.dropped_events);
        if dropped > 0 {
            if let Some(last) = registry
                .events
                .back_mut()
                .filter(|last| last.kind == "dropped")
            {
                last.dropped_before = last.dropped_before.saturating_add(dropped);
            } else {
                let sequence = registry.next_event;
                registry.next_event = sequence.saturating_add(1);
                registry.events.push_back(EventRecord {
                    run: self.0.run.to_string(),
                    sequence,
                    kind: "dropped".into(),
                    ts_ms: timestamp(),
                    node: String::new(),
                    user: None,
                    outbound: String::new(),
                    target: None,
                    code: "events.dropped".into(),
                    addresses: Vec::new(),
                    dropped_before: dropped,
                });
            }
        }
        Ok(registry.events.iter().cloned().collect())
    }
    pub(crate) fn acknowledge_events(&self, count: usize) -> Result<()> {
        let mut registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        let count = count.min(registry.events.len());
        registry.events.drain(..count);
        Ok(())
    }
    /// 仅统计仍持有业务流的可信归属；同一来源按活跃逻辑流计数。
    pub fn online(&self) -> Result<Vec<crate::OnlineSource>> {
        let registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        let mut sources = BTreeMap::new();
        for flow in registry.records.values() {
            if flow.end.load(Ordering::Acquire) != 0 {
                continue;
            }
            let key = (
                flow.source.user(),
                flow.source.node().clone(),
                flow.observed_source
                    .map(|address| crate::history::masked_source(address.ip())),
            );
            *sources.entry(key).or_insert(0usize) += 1;
        }
        Ok(sources
            .into_iter()
            .map(
                |((user, node, address), active_flows)| crate::OnlineSource {
                    user: user.map(|value| value.to_string()),
                    node: node.to_string(),
                    address,
                    active_flows,
                },
            )
            .collect())
    }
    /// 只查询本次进程保留的记录；没有磁盘持久性保证。
    pub fn records(&self, after: u64, limit: usize) -> Result<Vec<FlowRecord>> {
        if limit == 0 || limit > 4096 {
            return Err(Error::ResourceLimit);
        }
        let registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        Ok(registry
            .records
            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .take(limit)
            .map(|(_, flow)| flow.record())
            .collect())
    }
}
