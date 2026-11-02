//! 运行期唯一业务账本。当前不提供持久历史或带宽历史查询。

use kerlico_core::{
    Destination, Error, FlowFailure, FlowOutcome, NodeId, OriginalTarget, OutId, Result, RunId,
    SessionIdentity, Source, TargetBind, UserId,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FlowId {
    pub run: RunId,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub upload_packets: u64,
    pub download_packets: u64,
}
impl Usage {
    fn add(&mut self, other: Self) {
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

pub struct FlowLedger {
    id: FlowId,
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
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
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
    ledger: Arc<FlowLedger>,
    cancelled: Vec<kerlico_core::CancellationToken>,
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
        self.cancellation_error().map(|error| failure_end(FlowFailure::from_error(&error)))
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
        ledger: Arc<FlowLedger>,
        context: &kerlico_core::ConnectContext,
        identity: &SessionIdentity,
    ) -> Self {
        Self(Arc::new(LeaseInner {
            ledger,
            cancelled: vec![
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
    pub(crate) fn cancellation_error(&self) -> Error {
        self.0.cancellation_error().unwrap_or(Error::Cancelled)
    }
    pub(crate) fn failed(&self, error: &Error) {
        self.observe_failure(FlowFailure::from_error(error));
    }
    pub(crate) fn io_failed(&self, error: &std::io::Error) {
        self.observe_failure(FlowFailure::from_io_error(error));
    }
    pub(crate) fn observe_failure(&self, failure: FlowFailure) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let CompletionState::Running { first_failure, .. } = &mut *state {
            first_failure.get_or_insert(failure);
        }
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
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let CompletionState::Running {
            first_failure,
            upload_shutdown,
            download_eof,
        } = &*state
        {
            let reason = if let Some(failure) = first_failure {
                failure_end(*failure)
            } else {
                match outcome {
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
                    FlowOutcome::ClosedByCaller => self.0.cancellation_end().unwrap_or(FlowEnd::ClosedByCaller),
                    FlowOutcome::DuplexEof => FlowEnd::ClosedByCaller,
                }
            };
            *state = CompletionState::Closing(reason);
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
}

struct Registry {
    records: BTreeMap<u64, Arc<FlowLedger>>,
    order: VecDeque<u64>,
    archived: UsageSnapshot,
}
struct TelemetryInner {
    run: RunId,
    next: AtomicU64,
    capacity: usize,
    registry: Mutex<Registry>,
}

#[derive(Clone)]
pub struct Telemetry(Arc<TelemetryInner>);
impl Telemetry {
    pub(crate) fn new(capacity: usize) -> Self {
        Self(Arc::new(TelemetryInner {
            run: RunId::generate(),
            next: AtomicU64::new(1),
            capacity,
            registry: Mutex::new(Registry {
                records: BTreeMap::new(),
                order: VecDeque::new(),
                archived: UsageSnapshot::default(),
            }),
        }))
    }
    pub(crate) fn open(
        &self,
        identity: &SessionIdentity,
        outbound: &OutId,
        original: Option<OriginalTarget>,
        kind: FlowKind,
    ) -> Result<Arc<FlowLedger>> {
        let mut registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        if registry.records.len() >= self.0.capacity {
            let remove = registry.order.iter().position(|id| {
                registry
                    .records
                    .get(id)
                    .is_some_and(|flow| matches!(flow.end.load(Ordering::Acquire), 1..=5))
            });
            if let Some(index) = remove {
                let id = registry.order.remove(index).expect("已找到记录序号");
                if let Some(flow) = registry.records.remove(&id) {
                    registry.archived.account(&flow.record());
                    registry.archived.evicted_records += 1;
                }
            } else {
                return Err(Error::ResourceLimit);
            }
        }
        let sequence = self
            .0
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                next.checked_add(1)
            })
            .map_err(|_| Error::ResourceLimit)?;
        let flow = Arc::new(FlowLedger {
            id: FlowId {
                run: self.0.run,
                sequence,
            },
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
        Ok(flow)
    }
    pub fn usage(&self) -> Result<UsageSnapshot> {
        let registry = self
            .0
            .registry
            .lock()
            .map_err(|_| Error::Protocol("运行账本状态已损坏"))?;
        let mut snapshot = registry.archived.clone();
        snapshot.retained_records = registry.records.len();
        for flow in registry.records.values() {
            let record = flow.record();
            snapshot.active_flows += usize::from(record.end.is_none());
            snapshot.account(&record);
        }
        Ok(snapshot)
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
