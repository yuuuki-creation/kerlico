use kerlico_core::{
    BoxStream, CancellationToken, Error, FlowFailure, FlowOutcome, Result, TcpFlow,
};
use std::time::Duration;
use tokio::sync::watch;

pub(crate) async fn ended(parent: &mut watch::Receiver<Option<FlowOutcome>>) -> FlowOutcome {
    loop {
        if let Some(reason) = *parent.borrow_and_update() {
            return reason;
        }
        if parent.changed().await.is_err() {
            return FlowOutcome::ClosedByCaller;
        }
    }
}
pub(crate) fn reason(result: &Result<()>) -> FlowOutcome {
    match result {
        Ok(()) => FlowOutcome::ProtocolEnd,
        Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
    }
}
pub(crate) fn result(outcome: FlowOutcome) -> Result<()> {
    match outcome {
        FlowOutcome::Failed(FlowFailure::Timeout) => Err(Error::Timeout),
        FlowOutcome::Failed(FlowFailure::Cancelled) => Err(Error::Cancelled),
        FlowOutcome::Failed(FlowFailure::Failed) => Err(Error::Protocol("AnyTLS 载体失败")),
        _ => Ok(()),
    }
}
pub(crate) async fn relay(
    front: BoxStream,
    flow: TcpFlow,
    idle: Duration,
    cancel: CancellationToken,
    mut parent: watch::Receiver<Option<FlowOutcome>>,
) -> Result<()> {
    let (mut io, completion) = flow.into_parts();
    let (outcome, result) = {
        let copy = kerlico_core::relay_tcp_io(front, &mut io, idle, cancel.clone());
        tokio::pin!(copy);
        tokio::select! {
            biased;
            _=cancel.cancelled()=>(FlowOutcome::Failed(FlowFailure::Cancelled),Err(Error::Cancelled)),
            reason=ended(&mut parent)=>(reason,self::result(reason)),
            result=&mut copy=>{
                let reason=match &result {Ok(())=>FlowOutcome::DuplexEof,Err(error)=>FlowOutcome::Failed(FlowFailure::from_error(error))};
                (reason,result)
            },
        }
    };
    completion.finish(outcome);
    result
}
