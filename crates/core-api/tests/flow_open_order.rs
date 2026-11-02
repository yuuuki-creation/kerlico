use kerlico_core::{
    BoxFuture, FixedUdpFlow, FlowFailure, FlowOpen, FlowOutcome, Result, TcpFlow, UdpAssociation,
};
use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Factory,
    Pending,
    Report(FlowOutcome),
    Dispose,
}

struct PendingIo<T> {
    events: Arc<Mutex<Vec<Event>>>,
    output: PhantomData<fn() -> T>,
}
impl<T> Future for PendingIo<T> {
    type Output = Result<T>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.events.lock().unwrap().push(Event::Pending);
        Poll::Pending
    }
}
impl<T> Drop for PendingIo<T> {
    fn drop(&mut self) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Event::Dispose);
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Tcp,
    FixedUdp,
    Association,
}
enum Opening {
    Tcp(FlowOpen<'static, TcpFlow>),
    FixedUdp(FlowOpen<'static, FixedUdpFlow>),
    Association(FlowOpen<'static, UdpAssociation>),
}
fn future<T: 'static>(events: &Arc<Mutex<Vec<Event>>>) -> BoxFuture<'static, Result<T>> {
    Box::pin(PendingIo {
        events: events.clone(),
        output: PhantomData,
    })
}
fn report(events: &Arc<Mutex<Vec<Event>>>) -> impl FnOnce(FlowOutcome) + Send + 'static {
    let events = events.clone();
    move |outcome| {
        events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Event::Report(outcome));
    }
}
impl Opening {
    fn new(kind: Kind, events: &Arc<Mutex<Vec<Event>>>) -> Self {
        match kind {
            Kind::Tcp => Self::Tcp(FlowOpen::tcp(future(events), report(events))),
            Kind::FixedUdp => Self::FixedUdp(FlowOpen::fixed_udp(future(events), report(events))),
            Kind::Association => {
                Self::Association(FlowOpen::association(future(events), report(events)))
            }
        }
    }
    fn deferred(kind: Kind, events: &Arc<Mutex<Vec<Event>>>) -> Self {
        let events = events.clone();
        match kind {
            Kind::Tcp => Self::Tcp(FlowOpen::deferred(move || {
                events.lock().unwrap().push(Event::Factory);
                Ok(FlowOpen::tcp(future(&events), report(&events)))
            })),
            Kind::FixedUdp => Self::FixedUdp(FlowOpen::deferred(move || {
                events.lock().unwrap().push(Event::Factory);
                Ok(FlowOpen::fixed_udp(future(&events), report(&events)))
            })),
            Kind::Association => Self::Association(FlowOpen::deferred(move || {
                events.lock().unwrap().push(Event::Factory);
                Ok(FlowOpen::association(future(&events), report(&events)))
            })),
        }
    }
    fn poll_pending(&mut self) {
        let mut context = Context::from_waker(Waker::noop());
        let pending = match self {
            Self::Tcp(opening) => Pin::new(opening).poll(&mut context).is_pending(),
            Self::FixedUdp(opening) => Pin::new(opening).poll(&mut context).is_pending(),
            Self::Association(opening) => Pin::new(opening).poll(&mut context).is_pending(),
        };
        assert!(pending);
    }
    fn finish(self, outcome: FlowOutcome) {
        match self {
            Self::Tcp(opening) => opening.finish(outcome),
            Self::FixedUdp(opening) => opening.finish(outcome),
            Self::Association(opening) => opening.finish(outcome),
        }
    }
}

#[test]
fn public_open_finish_reports_before_pending_future_disposal() {
    for kind in [Kind::Tcp, Kind::FixedUdp, Kind::Association] {
        for outcome in [
            FlowOutcome::ProtocolEnd,
            FlowOutcome::Failed(FlowFailure::Failed),
            FlowOutcome::Failed(FlowFailure::Timeout),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut opening = Opening::new(kind, &events);
            opening.poll_pending();
            opening.finish(outcome);
            assert_eq!(
                *events.lock().unwrap(),
                [Event::Pending, Event::Report(outcome), Event::Dispose]
            );
        }
    }
}

#[test]
fn public_open_panic_reports_before_pending_future_disposal() {
    for kind in [Kind::Tcp, Kind::FixedUdp, Kind::Association] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut opening = Opening::new(kind, &events);
        opening.poll_pending();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _opening = opening;
            panic!("受控建立所有者panic");
        }));
        assert!(result.is_err());
        assert_eq!(
            *events.lock().unwrap(),
            [
                Event::Pending,
                Event::Report(FlowOutcome::Failed(FlowFailure::Failed)),
                Event::Dispose,
            ]
        );
    }
}

#[test]
fn unpolled_public_open_reports_but_deferred_open_does_not_call_factory() {
    for kind in [Kind::Tcp, Kind::FixedUdp, Kind::Association] {
        for explicit in [false, true] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let opening = Opening::deferred(kind, &events);
            if explicit {
                opening.finish(FlowOutcome::ProtocolEnd);
            } else {
                drop(opening);
            }
            assert!(events.lock().unwrap().is_empty());
            let opening = Opening::new(kind, &events);
            let outcome = if explicit {
                opening.finish(FlowOutcome::ProtocolEnd);
                FlowOutcome::ProtocolEnd
            } else {
                drop(opening);
                FlowOutcome::ClosedByCaller
            };
            assert_eq!(
                *events.lock().unwrap(),
                [Event::Report(outcome), Event::Dispose]
            );
        }
    }
}

#[test]
fn polled_deferred_open_calls_factory_and_reports_before_disposal() {
    for kind in [Kind::Tcp, Kind::FixedUdp, Kind::Association] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut opening = Opening::deferred(kind, &events);
        opening.poll_pending();
        opening.finish(FlowOutcome::ProtocolEnd);
        assert_eq!(
            *events.lock().unwrap(),
            [
                Event::Factory,
                Event::Pending,
                Event::Report(FlowOutcome::ProtocolEnd),
                Event::Dispose,
            ]
        );
    }
}
