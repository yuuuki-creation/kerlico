use crate::{
    protocol,
    record::{Reader, Writer},
    stream::Session,
    wire,
};
use kerlico_core::{
    Address, BoxFuture, BoxStream, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, InboundContext, PeerSession, Result,
};
use std::collections::HashMap;
use tokio::{
    io::{AsyncWriteExt, WriteHalf},
    sync::{mpsc, oneshot},
    task::JoinSet,
};
struct Sender {
    writer: Writer,
    output: WriteHalf<BoxStream>,
    target: Destination,
}
struct Receiver {
    reader: Reader,
    target: Destination,
    peer: Option<Destination>,
}
pub(crate) fn channel(session: Session, target: Destination) -> DatagramChannel {
    let peer = if matches!(target.address(), Address::Ip(_)) {
        Some(target.clone())
    } else {
        None
    };
    DatagramChannel {
        sender: Box::new(Sender {
            writer: session.writer,
            output: session.output,
            target: target.clone(),
        }),
        receiver: Box::new(Receiver {
            reader: session.reader,
            target,
            peer,
        }),
    }
}
async fn send(
    writer: &mut Writer,
    output: &mut WriteHalf<BoxStream>,
    packet: Vec<u8>,
) -> Result<()> {
    let limit = writer.packet_limit();
    if packet.len() > writer.maximum() || (writer.maximum() == 0x3fff && packet.len() > limit) {
        return Err(Error::ResourceLimit);
    }
    let frame = writer.frame(&packet)?;
    output.write_all(&frame).await?;
    output.flush().await?;
    Ok(())
}
impl DatagramSender for Sender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            send(
                &mut self.writer,
                &mut self.output,
                wire::udp_request(&self.target, packet)?,
            )
            .await
        })
    }
}
impl DatagramReceiver for Receiver {
    fn peer_addr(&self) -> Option<Destination> {
        self.peer.clone()
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let Some(record) = self.reader.next().await? else {
                return Ok(None);
            };
            let (peer, packet) = wire::parse_udp(&record, true)?;
            if peer.port() != self.target.port()
                || matches!(self.target.address(), Address::Ip(_)) && peer != self.target
            {
                return Err(protocol());
            }
            self.peer = Some(peer);
            Ok(Some(packet))
        })
    }
}
struct Entry {
    generation: u64,
    sender: kerlico_core::FixedUdpSender,
    completion: Option<kerlico_core::FlowCompletion>,
    cancel: kerlico_core::CancellationToken,
    activity: tokio::sync::watch::Sender<tokio::time::Instant>,
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
    {
        if let Some(entry) = entries.remove(&key) {
            entry.finish(reason);
        }
    }
}
pub(crate) async fn serve(
    session: Session,
    access: PeerSession,
    context: InboundContext,
) -> Result<()> {
    let Session {
        mut reader,
        mut writer,
        mut output,
    } = session;
    let (replies, mut received) = mpsc::channel::<Reply>(32);
    let mut entries = HashMap::<Destination, Entry>::new();
    let mut tasks = JoinSet::new();
    let mut generation = 0u64;
    let scope = context.cancel.child_token();
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    let result: Result<()> = async {
        loop {
            let reading: BoxFuture<'_, Result<Option<(Destination, Vec<u8>)>>> = Box::pin(async { match reader.next().await? { Some(record) => { let (target, packet) = wire::parse_udp(&record, false)?; Ok(Some((target, packet))) }, None => Ok(None) } });
            tokio::pin!(reading);
            let request = loop {
                tokio::select! {
                    biased;
                    _=context.cancel.cancelled()=>return Err(Error::Cancelled),
                    _=&mut timer=>return Err(Error::Timeout),
                    reply=received.recv()=>match reply {
                        Some(Reply::End{key,generation,outcome})=>finish_reply(&mut entries,key,generation,outcome),
                        Some(Reply::Packet{key,generation,source,packet,delivered})=>{
                            if !entries.get(&key).is_some_and(|entry|entry.generation==generation) {continue;}
                            if packet.len()>context.max_datagram_size {return Err(Error::ResourceLimit);}
                            let writing=async { send(&mut writer, &mut output, wire::udp_response(&source, &packet)?).await };
                            tokio::select! { biased; _=context.cancel.cancelled()=>return Err(Error::Cancelled), result=tokio::time::timeout(context.idle_timeout,writing)=>result.map_err(|_|Error::Timeout)?? }
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
                if entries.len()>=context.max_streams {return Err(Error::ResourceLimit);}
                let lease=context.stream_budget.try_acquire()?;
                generation=generation.checked_add(1).ok_or(Error::ResourceLimit)?;
                let gen_id=generation;
                let opening=ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
                let channel=access.connect_udp(&target,&opening).await?;
                let (sender,mut receiver,completion)=channel.into_parts();
                let fallback = if matches!(target.address(), Address::Ip(_)) { Some(target.clone()) } else { None };
                            let peer = match receiver.peer_addr().or(fallback) {
                                Some(peer) if matches!(peer.address(), Address::Ip(_)) => peer,
                                _ => { completion.finish(kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed)); return Err(Error::Unsupported("Snell UDP 需要业务目标的字面地址元数据")); }
                            };
                let cancel=scope.child_token();let token=cancel.clone();
                let (activity,mut observed)=tokio::sync::watch::channel(tokio::time::Instant::now());
                let incoming_activity=activity.clone();let output=replies.clone();let key=target.clone();
                let idle=context.idle_timeout;
                entries.insert(target.clone(),Entry{generation:gen_id,sender,completion:Some(completion),cancel,activity});
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
                            let source = receiver.peer_addr().unwrap_or_else(|| peer.clone());
                                if !matches!(source.address(), Address::Ip(_)) { return Err(protocol()); }
                            let now = tokio::time::Instant::now();
                            incoming_activity.send_replace(now);
                            timer.as_mut().reset(now + idle);
                            let (delivered, written) = oneshot::channel();
                            tokio::select! {biased;_=token.cancelled()=>return Err(Error::Cancelled), result=output.send(Reply::Packet{key:key.clone(),generation:gen_id,source,packet,delivered})=>result.map_err(|_|Error::Cancelled)?}
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
                    let _=output.send(Reply::End{key,generation:gen_id,outcome:reason}).await;
                })?;
                let output=replies.clone();let key=target.clone();
                tasks.spawn(async move {
                    if task.await.is_err() { let _=output.send(Reply::End{key,generation:gen_id,outcome:kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed)}).await; }
                });
                context.events.record(kerlico_core::NodeEvent::Accepted);
            }
            let entry=entries.get_mut(&target).ok_or(Error::Cancelled)?;
            tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),result=tokio::time::timeout(context.idle_timeout,entry.sender.send(&packet))=>result.map_err(|_|Error::Timeout)??}
            entry.activity.send_replace(tokio::time::Instant::now());
            timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);
        }
    }.await;
    let reason = outcome(&result);
    received.close();
    while let Ok(reply) = received.try_recv() {
        if let Reply::End {
            key,
            generation,
            outcome,
        } = reply
        {
            finish_reply(&mut entries, key, generation, outcome);
        }
    }
    for entry in entries.into_values() {
        entry.finish(reason);
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
#[path = "udp_delivery_tests.rs"]
mod delivery_tests;
