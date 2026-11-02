use kerlico_core::{FlowFailure, FlowOutcome};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

struct Pending {
    epoch: u64,
    sender: oneshot::Sender<FlowOutcome>,
}
struct State {
    epoch: u64,
    closed: Option<FlowOutcome>,
    pending: Vec<Pending>,
}
#[derive(Clone)]
pub(super) struct FlushReceipts {
    state: Arc<Mutex<State>>,
    limit: usize,
}
impl FlushReceipts {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                epoch: 0,
                closed: None,
                pending: Vec::new(),
            })),
            limit,
        }
    }

    // 仅由 Hyper 在消费响应末帧或判断空响应时登记；构造响应不登记。
    pub(super) fn register(&self, sender: oneshot::Sender<FlowOutcome>) {
        let outcome = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(outcome) = state.closed {
                outcome
            } else if state.pending.len() >= self.limit {
                FlowOutcome::Failed(FlowFailure::Failed)
            } else {
                let epoch = state.epoch;
                state.pending.push(Pending { epoch, sender });
                return;
            }
        };
        let _ = sender.send(outcome);
    }

    pub(super) fn succeeded(&self) {
        let (epoch, pending, outcome) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.closed.is_some() {
                return;
            }
            let outcome = match state.epoch.checked_add(1) {
                Some(epoch) => {
                    state.epoch = epoch;
                    FlowOutcome::ProtocolEnd
                }
                None => {
                    let outcome = FlowOutcome::Failed(FlowFailure::Failed);
                    state.closed = Some(outcome);
                    outcome
                }
            };
            (state.epoch, std::mem::take(&mut state.pending), outcome)
        };
        for pending in pending {
            let result = if outcome == FlowOutcome::ProtocolEnd && pending.epoch >= epoch {
                FlowOutcome::Failed(FlowFailure::Failed)
            } else {
                outcome
            };
            let _ = pending.sender.send(result);
        }
    }

    pub(super) fn failed(&self, outcome: FlowOutcome) {
        let (outcome, pending) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            let outcome = *state.closed.get_or_insert(outcome);
            (outcome, std::mem::take(&mut state.pending))
        };
        for pending in pending {
            let _ = pending.sender.send(outcome);
        }
    }
}
