use kerlico_core::{Error, FlowCompletion, FlowFailure, FlowOutcome, Result};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct Scope(pub u16, pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct Key(pub Scope, pub u64);
struct Entry {
    closed: Option<FlowOutcome>,
    flows: HashMap<u64, FlowCompletion>,
}
struct State {
    closed: Option<FlowOutcome>,
    scopes: HashMap<Scope, Entry>,
    limit: usize,
}
#[derive(Clone)]
pub(super) struct Completions(Arc<Mutex<State>>);
impl Completions {
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(Mutex::new(State {
            closed: None,
            scopes: HashMap::new(),
            limit,
        })))
    }
    pub fn scope(&self, scope: Scope) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| Error::Protocol("Mux 完成权状态损坏"))?;
        if state.closed.is_some() {
            return Err(Error::Cancelled);
        }
        if state.scopes.len() >= state.limit || state.scopes.contains_key(&scope) {
            return Err(Error::ResourceLimit);
        }
        state.scopes.insert(
            scope,
            Entry {
                closed: None,
                flows: HashMap::new(),
            },
        );
        Ok(())
    }
    pub fn register(
        &self,
        key: Key,
        completion: FlowCompletion,
    ) -> std::result::Result<(), (FlowCompletion, FlowOutcome, Error)> {
        let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        let refused = state
            .closed
            .or_else(|| state.scopes.get(&key.0).and_then(|entry| entry.closed));
        if let Some(outcome) = refused {
            return Err((completion, outcome, Error::Cancelled));
        }
        let count: usize = state.scopes.values().map(|entry| entry.flows.len()).sum();
        if count >= state.limit {
            return Err((
                completion,
                FlowOutcome::Failed(FlowFailure::Failed),
                Error::ResourceLimit,
            ));
        }
        let Some(entry) = state.scopes.get_mut(&key.0) else {
            return Err((
                completion,
                FlowOutcome::Failed(FlowFailure::Cancelled),
                Error::Cancelled,
            ));
        };
        if entry.flows.contains_key(&key.1) {
            return Err((
                completion,
                FlowOutcome::Failed(FlowFailure::Failed),
                Error::ResourceLimit,
            ));
        }
        entry.flows.insert(key.1, completion);
        Ok(())
    }
    pub fn finish(&self, key: Key, outcome: FlowOutcome) {
        let completion = {
            let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
            state
                .scopes
                .get_mut(&key.0)
                .and_then(|entry| entry.flows.remove(&key.1))
        };
        if let Some(completion) = completion {
            completion.finish(outcome);
        }
    }
    pub fn close_scope(&self, scope: Scope, outcome: FlowOutcome) {
        let completions = {
            let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
            let Some(entry) = state.scopes.get_mut(&scope) else {
                return;
            };
            if entry.closed.is_some() {
                return;
            }
            entry.closed = Some(outcome);
            std::mem::take(&mut entry.flows)
        };
        for completion in completions.into_values() {
            completion.finish(outcome);
        }
    }
    pub fn retire(&self, scope: Scope, outcome: FlowOutcome) {
        self.close_scope(scope, outcome);
        let entry = self
            .0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .scopes
            .remove(&scope);
        drop(entry);
    }
    pub fn close(&self, outcome: FlowOutcome) {
        let completions = {
            let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
            if state.closed.is_some() {
                return;
            }
            state.closed = Some(outcome);
            state
                .scopes
                .values_mut()
                .flat_map(|entry| {
                    entry.closed.get_or_insert(outcome);
                    std::mem::take(&mut entry.flows).into_values()
                })
                .collect::<Vec<_>>()
        };
        for completion in completions {
            completion.finish(outcome);
        }
    }
}
pub(super) fn outcome(result: &Result<()>) -> FlowOutcome {
    match result {
        Ok(()) => FlowOutcome::ProtocolEnd,
        Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_core::{
        BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramChannel, Destination,
        FamilyMode, InboundContext, NodeEvent, NodeObserver, NodeTasks, OpenedTcp, Outbound,
        PeerSession, StreamBudget, TargetPolicy, TcpConnectInfo, TcpFlowIo,
    };
    use kerlico_egress::{FlowEnd, Telemetry};
    use std::{sync::Arc, time::Duration};
    struct Observer;
    impl NodeObserver for Observer {
        fn record(&self, _: NodeEvent) {}
    }
    struct Backend(Mutex<Vec<tokio::io::DuplexStream>>);
    struct NoDns;
    impl kerlico_egress::Resolver for NoDns {
        fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
            Box::pin(async { Err(Error::Unsupported("远端目标不应调用解析器")) })
        }
    }
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
                let (stream, peer) = tokio::io::duplex(128);
                self.0.lock().unwrap().push(peer);
                Ok(OpenedTcp {
                    stream: Box::new(stream),
                    info: TcpConnectInfo::unknown(),
                })
            })
        }
        fn connect_udp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async { Err(Error::Unsupported("此回归仅使用 TCP")) })
        }
    }
    fn fixture() -> (PeerSession, Telemetry, ConnectContext) {
        let input = kerlico_config::NodeBuildContext::local_for_test(serde_json::json!({}));
        let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            Arc::new(Backend(Mutex::new(Vec::new()))),
            TargetPolicy::Remote,
            FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let context = InboundContext {
            peer_lease: None,
            tasks: NodeTasks::new(
                kerlico_core::NodeId::parse("test-node").unwrap(),
                cancel.clone(),
            ),
            cancel,
            peer_addr: None,
            local_addr: Some("127.0.0.1:1".parse().unwrap()),
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 8,
            events: Arc::new(Observer),
            stream_budget: StreamBudget::new(
                Arc::new(tokio::sync::Semaphore::new(8)),
                Arc::new(tokio::sync::Semaphore::new(8)),
            ),
        };
        (
            ingress.local(&context).unwrap(),
            telemetry,
            ConnectContext::new(Duration::from_secs(1)),
        )
    }
    async fn open(peer: &PeerSession, context: &ConnectContext) -> (TcpFlowIo, FlowCompletion) {
        peer.connect_tcp(
            &Destination::new("unresolved.invalid", 443).unwrap(),
            context,
        )
        .await
        .unwrap()
        .into_parts()
    }
    #[tokio::test]
    async fn parent_timeout_waits_for_last_io_and_is_stable_after_cancel() {
        let (peer, telemetry, context) = fixture();
        let owner = Completions::new(2);
        let scope = Scope(1, 1);
        owner.scope(scope).unwrap();
        let (io, completion) = open(&peer, &context).await;
        assert!(owner.register(Key(scope, 1), completion).is_ok());
        owner.close(FlowOutcome::Failed(FlowFailure::Timeout));
        owner.close(FlowOutcome::ProtocolEnd);
        context.cancel.cancel();
        assert_eq!(telemetry.usage().unwrap().active_flows, 1);
        assert_eq!(telemetry.records(0, 8).unwrap()[0].end, None);
        drop(io);
        let first = telemetry.records(0, 8).unwrap().remove(0);
        assert_eq!(first.end, Some(FlowEnd::Timeout));
        assert_eq!(telemetry.usage().unwrap().active_flows, 0);
        assert_eq!(telemetry.records(0, 8).unwrap()[0].ended_ms, first.ended_ms);
    }
    #[tokio::test]
    async fn closed_registration_returns_completion_and_first_reason() {
        let (peer, telemetry, context) = fixture();
        let owner = Completions::new(1);
        let scope = Scope(2, 1);
        owner.scope(scope).unwrap();
        owner.close_scope(scope, FlowOutcome::Failed(FlowFailure::Timeout));
        let (io, completion) = open(&peer, &context).await;
        let (completion, reason, _error) = owner.register(Key(scope, 1), completion).err().unwrap();
        assert_eq!(reason, FlowOutcome::Failed(FlowFailure::Timeout));
        completion.finish(reason);
        assert_eq!(telemetry.usage().unwrap().active_flows, 1);
        drop(io);
        assert_eq!(
            telemetry.records(0, 8).unwrap()[0].end,
            Some(FlowEnd::Timeout)
        );
    }
    #[tokio::test]
    async fn late_generation_and_full_table_do_not_replace_active_completion() {
        let (peer, telemetry, context) = fixture();
        let owner = Completions::new(1);
        let first = Scope(3, 1);
        owner.scope(first).unwrap();
        let (old, completion) = open(&peer, &context).await;
        assert!(owner.register(Key(first, 1), completion).is_ok());
        owner.retire(first, FlowOutcome::ProtocolEnd);
        drop(old);
        let next = Scope(3, 2);
        owner.scope(next).unwrap();
        let (new, completion) = open(&peer, &context).await;
        assert!(owner.register(Key(next, 1), completion).is_ok());
        owner.finish(Key(first, 1), FlowOutcome::Failed(FlowFailure::Failed));
        assert_eq!(telemetry.usage().unwrap().active_flows, 1);
        let (extra, completion) = open(&peer, &context).await;
        let (completion, reason, _error) = owner.register(Key(next, 2), completion).err().unwrap();
        completion.finish(reason);
        drop(extra);
        owner.close(FlowOutcome::Failed(FlowFailure::Timeout));
        drop(new);
        let records = telemetry.records(0, 8).unwrap();
        assert_eq!(records[0].end, Some(FlowEnd::Completed));
        assert_eq!(records[1].end, Some(FlowEnd::Timeout));
        assert_eq!(records[2].end, Some(FlowEnd::Failed));
    }
    #[tokio::test]
    async fn registration_racing_parent_close_cannot_escape_fixed_reason() {
        let (peer, telemetry, context) = fixture();
        let owner = Completions::new(1);
        let scope = Scope(4, 1);
        owner.scope(scope).unwrap();
        let (io, completion) = open(&peer, &context).await;
        let competing = owner.clone();
        let register = tokio::spawn(async move {
            if let Err((completion, reason, _error)) = competing.register(Key(scope, 1), completion)
            {
                completion.finish(reason);
            }
        });
        owner.close(FlowOutcome::Failed(FlowFailure::Timeout));
        register.await.unwrap();
        drop(io);
        assert_eq!(
            telemetry.records(0, 8).unwrap()[0].end,
            Some(FlowEnd::Timeout)
        );
    }
}
