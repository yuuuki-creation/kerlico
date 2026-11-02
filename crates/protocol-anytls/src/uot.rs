use crate::codec;
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, DatagramChannel, DatagramReceiver, DatagramSender,
    Destination, Error, InboundContext, PeerSession, Result,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{mpsc, oneshot},
    task::JoinSet,
};
type PacketRead<'a> = BoxFuture<'a, Result<Option<(Destination, Vec<u8>)>>>;

struct Sender(WriteHalf<BoxStream>);
struct Receiver(ReadHalf<BoxStream>);
pub fn channel(stream: BoxStream) -> DatagramChannel {
    let (r, w) = tokio::io::split(stream);
    DatagramChannel {
        sender: Box::new(Sender(w)),
        receiver: Box::new(Receiver(r)),
    }
}
async fn packet(reader: &mut (impl AsyncRead + Unpin), maximum: usize) -> Result<Option<Vec<u8>>> {
    let mut first = [0; 1];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let n = u16::from_be_bytes([first[0], reader.read_u8().await?]) as usize;
    if n > maximum {
        return Err(Error::ResourceLimit);
    }
    let mut data = vec![0; n];
    reader.read_exact(&mut data).await?;
    Ok(Some(data))
}
async fn write_packet(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<()> {
    let size = u16::try_from(data.len()).map_err(|_| Error::ResourceLimit)?;
    writer.write_u16(size).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}
impl DatagramSender for Sender {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { write_packet(&mut self.0, data).await })
    }
}
impl DatagramReceiver for Receiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move { packet(&mut self.0, 65535).await })
    }
}
struct Entry {
    generation: u64,
    sender: kerlico_core::FixedUdpSender,
    completion: Option<kerlico_core::FlowCompletion>,
    cancel: kerlico_core::CancellationToken,
    activity: tokio::sync::watch::Sender<tokio::time::Instant>,
    delivery: Arc<PacketDelivery>,
}
#[derive(Default, PartialEq, Eq)]
enum PacketState {
    #[default]
    Receiving,
    Pending,
    Ended(kerlico_core::FlowOutcome),
    Closed,
}
#[derive(Default)]
struct PacketDelivery(Mutex<PacketState>);
impl PacketDelivery {
    fn received(&self) -> bool {
        let mut state = self.0.lock().unwrap();
        if *state != PacketState::Receiving {
            return false;
        }
        *state = PacketState::Pending;
        true
    }
    fn confirm(&self) {
        let mut state = self.0.lock().unwrap();
        if *state == PacketState::Pending {
            *state = PacketState::Receiving;
        }
    }
    fn ended(&self, reason: kerlico_core::FlowOutcome) -> bool {
        let mut state = self.0.lock().unwrap();
        if !matches!(*state, PacketState::Receiving | PacketState::Pending) {
            return false;
        }
        *state = PacketState::Ended(reason);
        true
    }
    fn close(&self) -> PacketState {
        std::mem::replace(&mut *self.0.lock().unwrap(), PacketState::Closed)
    }
}
impl Entry {
    fn finish(mut self, outcome: kerlico_core::FlowOutcome) {
        if let Some(completion) = self.completion.take() {
            completion.finish(outcome);
        }
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.delivery.close();
        drop(self.completion.take());
        self.cancel.cancel();
    }
}
enum Reply {
    Packet {
        key: Destination,
        generation: u64,
        source: Destination,
        packet: Vec<u8>,
        delivered: oneshot::Sender<()>,
    },
    End {
        key: Destination,
        generation: u64,
        outcome: kerlico_core::FlowOutcome,
    },
}
enum ReceiveEnd {
    Eof,
    WriterGone,
}
#[cfg(test)]
#[derive(Debug)]
enum FeedbackEvent {
    PacketQueued {
        key: Destination,
        remaining: usize,
    },
    EndObserved {
        key: Destination,
        reason: kerlico_core::FlowOutcome,
        accepted: bool,
    },
    EndQueued {
        key: Destination,
    },
    EndBlocked {
        key: Destination,
        remaining: usize,
    },
}
#[cfg(test)]
type FeedbackObserver = mpsc::UnboundedSender<FeedbackEvent>;
async fn send_end(
    delivery: &PacketDelivery,
    output: &mpsc::Sender<Reply>,
    key: Destination,
    generation: u64,
    reason: kerlico_core::FlowOutcome,
    #[cfg(test)] observer: Option<&FeedbackObserver>,
) {
    let accepted = delivery.ended(reason);
    #[cfg(test)]
    if let Some(observer) = observer {
        let _ = observer.send(FeedbackEvent::EndObserved {
            key: key.clone(),
            reason,
            accepted,
        });
    }
    if !accepted {
        return;
    }
    #[cfg(test)]
    let observed_key = key.clone();
    let sending = output.send(Reply::End {
        key,
        generation,
        outcome: reason,
    });
    tokio::pin!(sending);
    #[cfg(test)]
    let mut reported_pending = false;
    #[cfg(test)]
    let sending = std::future::poll_fn(|cx| {
        let polled = std::future::Future::poll(sending.as_mut(), cx);
        if let Some(observer) = observer {
            if polled.is_pending() && output.capacity() == 0 && !reported_pending {
                reported_pending = true;
                let _ = observer.send(FeedbackEvent::EndBlocked {
                    key: observed_key.clone(),
                    remaining: output.capacity(),
                });
            } else if matches!(&polled, std::task::Poll::Ready(Ok(()))) {
                let _ = observer.send(FeedbackEvent::EndQueued {
                    key: observed_key.clone(),
                });
            }
        }
        polled
    });
    let _ = sending.await;
}
fn outcome(result: &Result<()>) -> kerlico_core::FlowOutcome {
    match result {
        Ok(()) => kerlico_core::FlowOutcome::ProtocolEnd,
        Err(error) => {
            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::from_error(error))
        }
    }
}
fn finish_reply(
    entries: &mut HashMap<Destination, Entry>,
    key: Destination,
    generation: u64,
    reason: kerlico_core::FlowOutcome,
) {
    if entries
        .get(&key)
        .is_some_and(|entry| entry.generation == generation)
        && let Some(entry) = entries.remove(&key)
    {
        entry.finish(reason);
    }
}
pub async fn serve(
    stream: BoxStream,
    access: PeerSession,
    context: InboundContext,
    ending: tokio::sync::watch::Receiver<Option<kerlico_core::FlowOutcome>>,
) -> Result<()> {
    serve_inner(
        stream,
        access,
        context,
        ending,
        #[cfg(test)]
        None,
    )
    .await
}
async fn serve_inner(
    mut stream: BoxStream,
    access: PeerSession,
    context: InboundContext,
    mut ending: tokio::sync::watch::Receiver<Option<kerlico_core::FlowOutcome>>,
    #[cfg(test)] observer: Option<FeedbackObserver>,
) -> Result<()> {
    let connection =
        ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    let (connected, host, port) = connection
        .run(async {
            let connected = match stream.read_u8().await? {
                0 => false,
                1 => true,
                _ => return Err(Error::Protocol("UoT v2 模式不合法")),
            };
            let (host, port) = codec::read_address(&mut stream, false).await?;
            Ok((connected, host, port))
        })
        .await?;
    let fixed = if connected {
        Some(Destination::new(&host, port)?)
    } else {
        None
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (replies, mut received) = mpsc::channel::<Reply>(32);
    let mut entries = HashMap::<Destination, Entry>::new();
    let mut tasks = JoinSet::new();
    let mut generation = 0u64;
    let scope = context.cancel.child_token();
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    let mut parent_reason = None;
    let mut result: Result<()> = async {
        loop {
            let reading: PacketRead<'_> = Box::pin(async { let target = if let Some(target)=&fixed {target.clone()} else {codec::destination(&mut reader,true).await?};
                    Ok(packet(&mut reader,context.max_datagram_size).await?.map(|packet|(target,packet))) });
            tokio::pin!(reading);
            let request = loop {
                tokio::select! {
                    biased;
                    _=context.cancel.cancelled()=>return Err(Error::Cancelled),
                    reason=crate::flow::ended(&mut ending)=>{parent_reason=Some(reason);return crate::flow::result(reason);},
                    _=&mut timer=>return Err(Error::Timeout),
                    reply=received.recv()=>match reply {
                        Some(Reply::End{key,generation,outcome})=>finish_reply(&mut entries,key,generation,outcome),
                        Some(Reply::Packet{key,generation,source,packet,delivered})=>{
                            let Some(entry) = entries.get(&key).filter(|entry| entry.generation == generation) else {continue;};
                            let delivery = entry.delivery.clone();
                            if packet.len()>context.max_datagram_size {return Err(Error::ResourceLimit);}
                            let writing=async { if !connected { writer.write_all(&codec::address(&source,true)).await?; }
                                write_packet(&mut writer,&packet).await };
                            tokio::select! {
                                biased;
                                _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                                result = tokio::time::timeout(context.idle_timeout, writing) => {
                                    let result = result.map_err(|_| Error::Timeout)?;
                                    if result.is_err()
                                        && let Some(reason @ kerlico_core::FlowOutcome::Failed(_)) = *ending.borrow()
                                    {
                                        parent_reason = Some(reason);
                                        return crate::flow::result(reason);
                                    }
                                    result?;
                                },
                                reason = crate::flow::ended(&mut ending) => {
                                    let reason = match reason {
                                        kerlico_core::FlowOutcome::ProtocolEnd | kerlico_core::FlowOutcome::DuplexEof => {
                                            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed)
                                        },
                                        reason => reason,
                                    };
                                    parent_reason = Some(reason);
                                    return crate::flow::result(reason);
                                },
                            }
                            delivery.confirm();
                            let _ = delivered.send(());
                            timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);
                        },
                        None=>return Err(Error::Cancelled),
                    },
                    done=tasks.join_next(),if !tasks.is_empty()=>{if done.is_some_and(|r|r.is_err()){return Err(Error::Protocol("UDP 接收所有者异常退出"));}},
                    request=&mut reading=>break request?,
                }
            };
            let Some((target,packet))=request else{return Ok(())};
            if packet.len()>context.max_datagram_size{return Err(Error::ResourceLimit);}
            if !entries.contains_key(&target) {
                if entries.len()>=context.max_streams.min(32) {return Err(Error::ResourceLimit);}
                let lease=context.stream_budget.try_acquire()?;
                generation=generation.checked_add(1).ok_or(Error::ResourceLimit)?;
                let gen_id=generation;
                let opening=ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
                let channel=access.connect_udp(&target,&opening).await?;
                let (sender,mut receiver,completion)=channel.into_parts();
                let peer = target.clone();
                let cancel=scope.child_token();let token=cancel.clone();
                let (activity,mut observed)=tokio::sync::watch::channel(tokio::time::Instant::now());
                let incoming_activity=activity.clone();let output=replies.clone();let key=target.clone();
                let idle=context.idle_timeout;
                let delivery = Arc::new(PacketDelivery::default());
                let failure_delivery = delivery.clone();
                #[cfg(test)]
                let target_observer = observer.clone();
                entries.insert(target.clone(),Entry{generation:gen_id,sender,completion:Some(completion),cancel,activity,delivery:delivery.clone()});
                let task=context.tasks.spawn_tracked(async move {
                    let _lease=lease;
                    let receiving: Result<ReceiveEnd> = async {
                        let timer=tokio::time::sleep(idle);tokio::pin!(timer);
                        loop {
                            let packet={let receiving=receiver.recv();tokio::pin!(receiving);loop {tokio::select! {
                                biased;
                                _=token.cancelled()=>return Err(Error::Cancelled),
                                _=&mut timer=>return Err(Error::Timeout),
                                changed=observed.changed()=>{if changed.is_ok(){timer.as_mut().reset(*observed.borrow_and_update()+idle);}continue;},
                                packet=&mut receiving=>break packet?,
                            }}};
                            let Some(packet)=packet else{return Ok(ReceiveEnd::Eof)};
                            if !delivery.received() {return Ok(ReceiveEnd::WriterGone)};
                            let source = peer.clone();
                            let now = tokio::time::Instant::now();
                            incoming_activity.send_replace(now);
                            timer.as_mut().reset(now + idle);
                            let (delivered, written) = oneshot::channel();
                            tokio::select! {biased;_=token.cancelled()=>return Err(Error::Cancelled), result=output.send(Reply::Packet{key:key.clone(),generation:gen_id,source,packet,delivered})=>result.map_err(|_|Error::Cancelled)?}
                            #[cfg(test)]
                            if let Some(observer) = &target_observer {
                                let _ = observer.send(FeedbackEvent::PacketQueued {
                                    key: key.clone(),
                                    remaining: output.capacity(),
                                });
                            }
                            tokio::select! {
                                biased;
                                _ = token.cancelled() => return Err(Error::Cancelled),
                                _ = &mut timer => return Err(Error::Timeout),
                                result = written => if result.is_err() { return Ok(ReceiveEnd::WriterGone); },
                            }
                        }
                    }.await;
                    let reason = match receiving {
                        Ok(ReceiveEnd::Eof) => kerlico_core::FlowOutcome::ProtocolEnd,
                        Ok(ReceiveEnd::WriterGone) => return,
                        Err(error) => outcome(&Err(error)),
                    };
                    send_end(
                        &delivery,
                        &output,
                        key,
                        gen_id,
                        reason,
                        #[cfg(test)]
                        target_observer.as_ref(),
                    )
                    .await;
                })?;
                let output=replies.clone();let key=target.clone();
                #[cfg(test)]
                let failure_observer = observer.clone();
                tasks.spawn(async move {
                    if task.await.is_err() {
                        send_end(
                            &failure_delivery,
                            &output,
                            key,
                            gen_id,
                            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed),
                            #[cfg(test)]
                            failure_observer.as_ref(),
                        )
                        .await;
                    }
                });
                context.events.record(kerlico_core::NodeEvent::Accepted);
            }
            let entry=entries.get_mut(&target).ok_or(Error::Cancelled)?;
            tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),result=tokio::time::timeout(context.idle_timeout,entry.sender.send(&packet))=>result.map_err(|_|Error::Timeout)??}
            entry.activity.send_replace(tokio::time::Instant::now());
            timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);
        }
    }.await;
    let mut reason = parent_reason.unwrap_or_else(|| outcome(&result));
    let closed: Vec<_> = entries
        .into_values()
        .map(|entry| {
            let state = entry.delivery.close();
            (entry, state)
        })
        .collect();
    received.close();
    drop(received);
    let undelivered = closed
        .iter()
        .any(|(_, state)| *state == PacketState::Pending);
    if undelivered
        && matches!(
            reason,
            kerlico_core::FlowOutcome::ProtocolEnd | kerlico_core::FlowOutcome::DuplexEof
        )
    {
        reason = kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed);
        result = Err(Error::Protocol("UoT 回包在物理交付前结束"));
    }
    for (entry, state) in closed {
        entry.finish(match state {
            PacketState::Ended(outcome) => outcome,
            _ => reason,
        });
    }
    scope.cancel();
    let deadline = tokio::time::Instant::now() + context.drain_timeout;
    while !tasks.is_empty() {
        if tokio::time::timeout_at(deadline, tasks.join_next())
            .await
            .is_err()
        {
            tasks.abort_all();
            return result.and(Err(Error::Timeout));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    struct Deny;
    impl kerlico_core::Outbound for Deny {
        fn capabilities(&self) -> kerlico_core::Capabilities {
            kerlico_core::Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
            Box::pin(async { Err(Error::Rejected) })
        }
        fn connect_udp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async { Err(Error::Rejected) })
        }
    }
    fn peer(context: &InboundContext) -> PeerSession {
        let input = kerlico_config::NodeBuildContext::local_for_test(serde_json::json!({}));
        kerlico_egress::testing::ingress(&input, Arc::new(Deny), kerlico_core::TargetPolicy::Remote)
            .unwrap()
            .local(context)
            .unwrap()
    }
    struct Observer;
    impl kerlico_core::NodeObserver for Observer {
        fn record(&self, _: kerlico_core::NodeEvent) {}
    }
    #[tokio::test]
    async fn unfinished_header_has_timeout_and_cancellation() {
        let mut context = InboundContext {
            peer_lease: None,
            tasks: kerlico_core::NodeTasks::new(
                kerlico_core::NodeId::parse("test-node").unwrap(),
                kerlico_core::CancellationToken::new(),
            ),
            peer_addr: None,
            local_addr: None,
            events: Arc::new(Observer),
            cancel: kerlico_core::CancellationToken::new(),
            connect_timeout: std::time::Duration::from_millis(10),
            idle_timeout: std::time::Duration::from_secs(1),
            drain_timeout: std::time::Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 1,
            stream_budget: kerlico_core::StreamBudget::new(
                Arc::new(tokio::sync::Semaphore::new(1)),
                Arc::new(tokio::sync::Semaphore::new(1)),
            ),
        };
        let (_owner, ending) = tokio::sync::watch::channel(None);
        let (stream, _peer) = tokio::io::duplex(64);
        assert!(matches!(
            serve(
                Box::new(stream),
                peer(&context),
                context.clone(),
                ending.clone()
            )
            .await,
            Err(Error::Timeout)
        ));
        context.cancel = kerlico_core::CancellationToken::new();
        let access = peer(&context);
        context.cancel.cancel();
        let (stream, _peer) = tokio::io::duplex(64);
        assert!(matches!(
            serve(Box::new(stream), access, context, ending).await,
            Err(Error::Cancelled)
        ));
    }
}

#[cfg(test)]
#[path = "uot_flow_tests.rs"]
mod flow_tests;

#[cfg(test)]
#[path = "uot_delivery_tests.rs"]
mod delivery_tests;
