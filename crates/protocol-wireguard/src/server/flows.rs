use crate::{
    config::{destination, target},
    packet::udp_packet,
    queue::QueuedPacket,
    stack::SharedStack,
    tcp::TcpStream,
};
use kerlico_core::{
    CancellationToken, ConnectContext, DatagramAssociationReceiver, DatagramAssociationSender,
    Destination, Error, FlowFailure, FlowOutcome, InboundContext, NodeEvent, PeerSession, Result,
    StreamLease,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    sync::mpsc,
    time::{Instant, timeout},
};

pub(super) struct PendingDatagram {
    pub target: SocketAddr,
    pub packet: QueuedPacket,
}
struct TaskScope {
    context: InboundContext,
    _lease: StreamLease,
}
impl Drop for TaskScope {
    fn drop(&mut self) {
        self.context.cancel.cancel();
        self.context.events.record(NodeEvent::Completed);
    }
}
fn task_scope(mut context: InboundContext, lease: StreamLease) -> TaskScope {
    context.cancel = context.cancel.child_token();
    TaskScope {
        context,
        _lease: lease,
    }
}
fn outcome(result: &Result<()>) -> FlowOutcome {
    match result {
        Ok(()) => FlowOutcome::ProtocolEnd,
        Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
    }
}
pub(super) async fn tcp(
    stream: TcpStream,
    access: PeerSession,
    target: Destination,
    context: InboundContext,
    lease: StreamLease,
) {
    let scope = task_scope(context, lease);
    let budget =
        ConnectContext::new(scope.context.connect_timeout).with_cancel(stream.pending_cancel());
    let result = async {
        let remote = access.connect_tcp(&target, &budget).await?;
        let accepted = async {
            stream.resume_accept()?;
            stream.established().await
        };
        if let Err(error) = budget.run(accepted).await {
            remote.finish(FlowOutcome::Failed(FlowFailure::from_error(&error)));
            return Err(error);
        }
        let stream: kerlico_core::BoxStream = Box::new(stream);
        kerlico_core::relay_tcp(
            stream,
            remote,
            scope.context.idle_timeout,
            scope.context.cancel.clone(),
        )
        .await
    }
    .await;
    if result.is_err() {
        scope.context.events.record(NodeEvent::Failed);
    }
}
pub(super) async fn udp(
    stack: Arc<SharedStack>,
    source: SocketAddr,
    mut packets: mpsc::Receiver<PendingDatagram>,
    access: PeerSession,
    context: InboundContext,
    lease: StreamLease,
) {
    let scope = task_scope(context, lease);
    let budget = ConnectContext::new(scope.context.connect_timeout)
        .with_cancel(scope.context.cancel.clone());
    let flow = match access.associate_udp(&budget).await {
        Ok(flow) => flow,
        Err(_) => {
            scope.context.events.record(NodeEvent::Failed);
            return;
        }
    };
    let (mut sender, mut receiver, completion) = flow.into_parts();
    let idle = stack.limits.udp_idle().min(scope.context.idle_timeout);
    let result = async {
            let timer = tokio::time::sleep(idle);
            tokio::pin!(timer);
            let mut translated_loopback = false;
            let mut all_dns = true;
            loop {
                let received = {
                    let receive = receiver.recv_from();
                    tokio::pin!(receive);
                    loop {
                        tokio::select! { biased;
                            _ = scope.context.cancel.cancelled() => return Err(Error::Cancelled),
                            _ = &mut timer => return Err(Error::Timeout),
                            packet = packets.recv() => {
                                let Some(packet) = packet else { return Ok(()); };
                                if packet.target.port() != 53 {
                                    all_dns = false;
                                }
                                let target_addr = if stack.addresses.contains(packet.target.ip()) {
                                    translated_loopback = true;
                                    let local_ip = if packet.target.is_ipv4() {
                                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                                    } else {
                                        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                                    };
                                    SocketAddr::new(local_ip, packet.target.port())
                                } else {
                                    packet.target
                                };
                                let destination = destination(target_addr)?;
                                operation(sender.send_to(&packet.packet.bytes, &destination), &scope.context.cancel, idle).await?;
                                timer.as_mut().reset(Instant::now() + idle);
                            }
                            result = &mut receive => break result?,
                        }
                    }
                };
                let Some((remote, payload)) = received else { return Ok(()); };
                if payload.len() > scope.context.max_datagram_size { return Err(Error::ResourceLimit); }
                let mut remote = target(&remote)?;
                if translated_loopback && remote.ip().is_loopback() {
                    remote.set_ip(stack.addresses.for_target(remote.ip())?);
                }
                if remote.is_ipv4() != source.is_ipv4() {
                    return Err(Error::Protocol("WireGuard UDP回包地址族与原来源不一致"));
                }
                let packet = udp_packet(remote, source, &payload)?;
                let post_reply_idle = if all_dns {
                    idle.min(std::time::Duration::from_secs(2))
                } else {
                    idle
                };
                match stack.queue_packet(packet) {
                    Ok(()) => timer.as_mut().reset(Instant::now() + post_reply_idle),
                    Err(Error::ResourceLimit) => scope.context.events.record(NodeEvent::Dropped),
                    Err(error) => return Err(error),
                }
            }
        }.await;
    completion.finish(outcome(&result));
    if result.is_err() {
        scope.context.events.record(NodeEvent::Failed);
    }
}
async fn operation<T>(
    future: impl std::future::Future<Output = Result<T>>,
    cancel: &CancellationToken,
    duration: std::time::Duration,
) -> Result<T> {
    tokio::select! { biased;
        _ = cancel.cancelled() => Err(Error::Cancelled),
        result = timeout(duration, future) => result.map_err(|_| Error::Timeout)?,
    }
}
