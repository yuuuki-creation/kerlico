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
        })
    }
    pub fn guard(self: &Arc<Self>) -> Guard {
        Guard(self.clone())
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
