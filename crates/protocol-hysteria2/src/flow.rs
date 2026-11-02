use kerlico_core::{
    BoxStream, CancellationToken, Error, FlowCompletion, FlowFailure, FlowOutcome, Result, TcpFlow,
    TcpFlowIo,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Open {
    next: u64,
    entries: BTreeMap<u64, FlowCompletion>,
}
enum State {
    Open(Open),
    Closed(FlowOutcome),
}
pub(crate) struct FlowSet {
    state: Mutex<State>,
    maximum: usize,
    cancel: CancellationToken,
    admission: CancellationToken,
}
pub(crate) struct Ticket {
    owner: Arc<FlowSet>,
    generation: u64,
}
pub(crate) struct TcpTarget {
    io: TcpFlowIo,
    ticket: Ticket,
}
pub(crate) struct Guard(Arc<FlowSet>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.close(if self.0.cancel.is_cancelled() {
            FlowOutcome::Failed(FlowFailure::Cancelled)
        } else if std::thread::panicking() {
            FlowOutcome::Failed(FlowFailure::Failed)
        } else {
            FlowOutcome::ClosedByCaller
        });
    }
}
impl FlowSet {
    pub fn new(maximum: usize, cancel: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::Open(Open {
                next: 0,
                entries: BTreeMap::new(),
            })),
            maximum,
            cancel,
            admission: CancellationToken::new(),
        })
    }
    pub fn guard(self: &Arc<Self>) -> Guard {
        Guard(self.clone())
    }
    pub fn stop_admission(&self) {
        self.admission.cancel();
    }
    pub fn is_accepting(&self) -> bool {
        !self.admission.is_cancelled()
    }
    pub async fn admission_stopped(&self) {
        self.admission.cancelled().await;
    }
    pub fn register(self: &Arc<Self>, completion: FlowCompletion) -> Result<Ticket> {
        let decision = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            match &mut *state {
                State::Closed(reason) => Err((*reason, completion, Error::Cancelled)),
                State::Open(open) => {
                    match open
                        .next
                        .checked_add(1)
                        .filter(|_| open.entries.len() < self.maximum)
                    {
                        Some(generation) => {
                            open.next = generation;
                            open.entries.insert(generation, completion);
                            Ok(generation)
                        }
                        None => Err((
                            FlowOutcome::Failed(FlowFailure::Failed),
                            completion,
                            Error::ResourceLimit,
                        )),
                    }
                }
            }
        };
        match decision {
            Ok(generation) => Ok(Ticket {
                owner: self.clone(),
                generation,
            }),
            Err((reason, completion, error)) => {
                completion.finish(reason);
                Err(error)
            }
        }
    }
    pub fn tcp(self: &Arc<Self>, flow: TcpFlow) -> Result<TcpTarget> {
        let (io, completion) = flow.into_parts();
        Ok(TcpTarget {
            io,
            ticket: self.register(completion)?,
        })
    }
    pub fn close(&self, reason: FlowOutcome) {
        let previous = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if matches!(*state, State::Closed(_)) {
                return;
            }
            std::mem::replace(&mut *state, State::Closed(reason))
        };
        if let State::Open(open) = previous {
            for (_, completion) in open.entries {
                completion.finish(reason);
            }
        }
    }
}
impl Ticket {
    pub fn finish(self, reason: FlowOutcome) {
        if let Some(completion) = self.take() {
            completion.finish(reason);
        }
    }
    fn take(&self) -> Option<FlowCompletion> {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match &mut *state {
            State::Open(open) => open.entries.remove(&self.generation),
            State::Closed(_) => None,
        }
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        let reason = if std::thread::panicking() {
            FlowOutcome::Failed(FlowFailure::Failed)
        } else if self.owner.cancel.is_cancelled() {
            FlowOutcome::Failed(FlowFailure::Cancelled)
        } else {
            FlowOutcome::ClosedByCaller
        };
        if let Some(completion) = self.take() {
            completion.finish(reason);
        }
    }
}
impl TcpTarget {
    pub fn finish(self, reason: FlowOutcome) {
        self.ticket.finish(reason);
    }
    pub async fn relay(
        mut self,
        front: BoxStream,
        idle: Duration,
        cancel: CancellationToken,
    ) -> Result<()> {
        let result = kerlico_core::relay_tcp_io(front, &mut self.io, idle, cancel).await;
        self.ticket.finish(match &result {
            Ok(()) => FlowOutcome::DuplexEof,
            Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
        });
        result
    }
}
pub(crate) fn outcome(result: &Result<()>) -> FlowOutcome {
    match result {
        Ok(()) => FlowOutcome::ProtocolEnd,
        Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_core::{
        BoxFuture, Capabilities, ConnectContext, DatagramChannel, Destination, FamilyMode,
        InboundContext, NodeEvent, NodeObserver, NodeTasks, OpenedTcp, Outbound, StreamBudget,
        TargetPolicy, TcpConnectInfo,
    };
    use kerlico_egress::{FlowEnd, Resolver, Telemetry};
    use std::net::IpAddr;
    struct Backend(Mutex<Vec<tokio::io::DuplexStream>>);
    impl Outbound for Backend {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: false,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<OpenedTcp>> {
            Box::pin(async move {
                let (io, peer) = tokio::io::duplex(64);
                self.0.lock().unwrap().push(peer);
                Ok(OpenedTcp {
                    stream: Box::new(io),
                    info: TcpConnectInfo::unknown(),
                })
            })
        }
        fn connect_udp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async { Err(Error::Unsupported("测试仅使用TCP")) })
        }
    }
    struct NoDns;
    impl Resolver for NoDns {
        fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
            Box::pin(async { panic!("远端业务不得本地解析") })
        }
    }
    struct Observer;
    impl NodeObserver for Observer {
        fn record(&self, _: NodeEvent) {}
    }
    fn fixture() -> (
        kerlico_core::PeerSession,
        Telemetry,
        Arc<Backend>,
        InboundContext,
    ) {
        let input = kerlico_config::NodeBuildContext::local_for_test(serde_json::json!({}));
        let backend = Arc::new(Backend(Mutex::new(Vec::new())));
        let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            backend.clone(),
            TargetPolicy::Remote,
            FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let context = InboundContext {
            peer_lease: None,
            tasks: NodeTasks::new(input.issuer().node().clone(), cancel.clone()),
            cancel,
            peer_addr: None,
            local_addr: None,
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65507,
            max_streams: 4,
            stream_budget: StreamBudget::new(
                Arc::new(tokio::sync::Semaphore::new(8)),
                Arc::new(tokio::sync::Semaphore::new(8)),
            ),
            events: Arc::new(Observer),
        };
        (
            ingress.local(&context).unwrap(),
            telemetry,
            backend,
            context,
        )
    }
    async fn open(peer: &kerlico_core::PeerSession) -> (TcpFlowIo, FlowCompletion) {
        peer.connect_tcp(
            &Destination::new("unresolved.example.invalid", 443).unwrap(),
            &ConnectContext::new(Duration::from_secs(1)),
        )
        .await
        .unwrap()
        .into_parts()
    }
    #[tokio::test]
    async fn parent_timeout_precedes_cleanup_and_late_registration_in_real_ledger() {
        let (peer, telemetry, _backend, context) = fixture();
        let owner = FlowSet::new(4, context.cancel.clone());
        let (io, completion) = open(&peer).await;
        let ticket = owner.register(completion).unwrap();
        owner.close(FlowOutcome::Failed(FlowFailure::Timeout));
        assert!(telemetry.records(0, 8).unwrap()[0].end.is_none());
        let (late, completion) = open(&peer).await;
        assert!(owner.register(completion).is_err());
        context.cancel.cancel();
        ticket.finish(FlowOutcome::ProtocolEnd);
        owner.close(FlowOutcome::ProtocolEnd);
        drop(io);
        drop(late);
        let records = telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record.end == Some(FlowEnd::Timeout))
        );
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    }
    #[tokio::test]
    async fn dropped_child_releases_slot_and_records_closed_by_caller_before_parent_end() {
        let (peer, telemetry, _backend, context) = fixture();
        let owner = FlowSet::new(1, context.cancel);
        let (first, completion) = open(&peer).await;
        let ticket = owner.register(completion).unwrap();
        drop(ticket);
        assert!(telemetry.records(0, 8).unwrap()[0].end.is_none());
        let (second, completion) = open(&peer).await;
        let ticket = owner.register(completion).unwrap();
        drop(ticket);
        owner.close(FlowOutcome::ProtocolEnd);
        drop(first);
        drop(second);
        let records = telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record.end == Some(FlowEnd::ClosedByCaller))
        );
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    }
    #[tokio::test]
    async fn child_panic_precedes_observed_cancel_and_later_parent_end_in_real_ledger() {
        let (peer, telemetry, _backend, context) = fixture();
        let owner = FlowSet::new(1, context.cancel.clone());
        let (io, completion) = open(&peer).await;
        let ticket = owner.register(completion).unwrap();
        let child = std::thread::spawn(move || {
            let _ticket = ticket;
            context.cancel.cancel();
            panic!("受控子流异常");
        });
        assert!(child.join().is_err());
        assert!(telemetry.records(0, 8).unwrap()[0].end.is_none());
        owner.close(FlowOutcome::ProtocolEnd);
        drop(io);
        assert_eq!(
            telemetry.records(0, 8).unwrap()[0].end,
            Some(FlowEnd::Failed)
        );
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    }
    #[tokio::test]
    async fn cancelled_child_drop_and_fixed_parent_timeout_keep_distinct_terminal_causes() {
        let (peer, telemetry, _backend, context) = fixture();
        let owner = FlowSet::new(2, context.cancel.clone());
        let (cancelled, completion) = open(&peer).await;
        let cancelled_ticket = owner.register(completion).unwrap();
        let (timed_out, completion) = open(&peer).await;
        let timeout_ticket = owner.register(completion).unwrap();
        context.cancel.cancel();
        drop(cancelled_ticket);
        owner.close(FlowOutcome::Failed(FlowFailure::Timeout));
        let child = std::thread::spawn(move || {
            let _ticket = timeout_ticket;
            panic!("父级已固定超时后的清理异常");
        });
        assert!(child.join().is_err());
        owner.close(FlowOutcome::ProtocolEnd);
        drop(cancelled);
        drop(timed_out);
        let records = telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].end, Some(FlowEnd::Cancelled));
        assert_eq!(records[1].end, Some(FlowEnd::Timeout));
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
    }
    #[tokio::test]
    async fn bounded_registry_and_old_generation_do_not_end_new_flow() {
        let (peer, telemetry, _backend, context) = fixture();
        let owner = FlowSet::new(1, context.cancel);
        let (first, completion) = open(&peer).await;
        let first_ticket = owner.register(completion).unwrap();
        let stale_generation = first_ticket.generation;
        let (overflow, completion) = open(&peer).await;
        assert!(matches!(
            owner.register(completion),
            Err(Error::ResourceLimit)
        ));
        drop(overflow);
        first_ticket.finish(FlowOutcome::ProtocolEnd);
        drop(first);
        let (next, completion) = open(&peer).await;
        let next_ticket = owner.register(completion).unwrap();
        Ticket {
            owner: owner.clone(),
            generation: stale_generation,
        }
        .finish(FlowOutcome::Failed(FlowFailure::Timeout));
        assert!(telemetry.records(0, 8).unwrap()[2].end.is_none());
        next_ticket.finish(FlowOutcome::ProtocolEnd);
        drop(next);
        let records = telemetry.records(0, 8).unwrap();
        assert_eq!(records[0].end, Some(FlowEnd::Completed));
        assert_eq!(records[1].end, Some(FlowEnd::Failed));
        assert_eq!(records[2].end, Some(FlowEnd::Completed));
    }
    #[tokio::test]
    async fn registration_racing_parent_close_keeps_timeout_and_one_terminal_record() {
        let (peer, telemetry, _backend, context) = fixture();
        for _ in 0..32 {
            let owner = FlowSet::new(1, context.cancel.clone());
            let (io, completion) = open(&peer).await;
            let close = owner.clone();
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let closing_barrier = barrier.clone();
            let closing = std::thread::spawn(move || {
                closing_barrier.wait();
                close.close(FlowOutcome::Failed(FlowFailure::Timeout));
            });
            let registering_barrier = barrier.clone();
            let registering = std::thread::spawn(move || {
                registering_barrier.wait();
                owner.register(completion)
            });
            barrier.wait();
            let ticket = registering.join().unwrap();
            closing.join().unwrap();
            if let Ok(ticket) = ticket {
                ticket.finish(FlowOutcome::ProtocolEnd);
            }
            drop(io);
        }
        let records = telemetry.records(0, 64).unwrap();
        assert_eq!(records.len(), 32);
        assert!(
            records
                .iter()
                .all(|record| record.end == Some(FlowEnd::Timeout))
        );
    }
}
