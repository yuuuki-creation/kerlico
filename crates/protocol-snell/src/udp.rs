use crate::{
    protocol,
    record::{Reader, Writer},
    stream::Session,
    wire,
};
use kerlico_core::{
    AccessService, Address, BoxFuture, BoxStream, ConnectContext, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, Error, InboundContext, NodeEvent, Result,
};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncWriteExt, WriteHalf},
    sync::{mpsc, watch},
    task::JoinSet,
    time::Instant,
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
    sender: Box<dyn DatagramSender>,
    cancel: kerlico_core::CancellationToken,
    activity: watch::Sender<Instant>,
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
pub(crate) async fn serve(
    session: Session,
    access: Arc<dyn AccessService>,
    context: InboundContext,
) -> Result<()> {
    let Session {
        mut reader,
        mut writer,
        mut output,
    } = session;
    let (sender, mut responses) = mpsc::channel::<(Destination, Vec<u8>)>(32);
    let download = async {
        while let Some((target, packet)) = responses.recv().await {
            if packet.len() > context.max_datagram_size {
                return Err(Error::ResourceLimit);
            }
            send(
                &mut writer,
                &mut output,
                wire::udp_response(&target, &packet)?,
            )
            .await?;
        }
        Ok::<_, Error>(())
    };
    let upload = async {
        let mut targets = HashMap::<Destination, Entry>::new();
        let mut tasks = JoinSet::new();
        while let Some(record) = reader.next().await? {
            while tasks.try_join_next().is_some() {}
            targets.retain(|_, entry| !entry.cancel.is_cancelled());
            let (target, packet) = wire::parse_udp(&record, false)?;
            if packet.len() > context.max_datagram_size {
                return Err(Error::ResourceLimit);
            }
            if !targets.contains_key(&target) {
                if targets.len() >= context.max_streams {
                    return Err(Error::ResourceLimit);
                }
                let lease = context.stream_budget.try_acquire()?;
                let budget = ConnectContext {
                    cancel: context.cancel.clone(),
                    timeout: context.connect_timeout,
                };
                let channel = access.connect_udp(&target, &budget).await?;
                let fallback = if matches!(target.address(), Address::Ip(_)) {
                    Some(target.clone())
                } else {
                    None
                };
                let peer = channel
                    .receiver
                    .peer_addr()
                    .or(fallback)
                    .ok_or(Error::Unsupported("Snell UDP 需要业务目标的字面地址元数据"))?;
                if !matches!(peer.address(), Address::Ip(_)) {
                    return Err(protocol());
                }
                let token = context.cancel.child_token();
                let cancel = token.clone();
                let (activity, changes) = watch::channel(Instant::now());
                let received_activity = activity.clone();
                let mut receiver = channel.receiver;
                let sender = sender.clone();
                let events = context.events.clone();
                let idle = context.idle_timeout;
                tasks.spawn(async move {
                    let _lease = lease;
                    let receiving = async {
                        while let Some(packet) = receiver.recv().await? {
                            received_activity.send_replace(Instant::now());
                            let source = receiver.peer_addr().unwrap_or_else(|| peer.clone());
                            if !matches!(source.address(), Address::Ip(_)) {
                                return Err(protocol());
                            }
                            sender
                                .send((source, packet))
                                .await
                                .map_err(|_| Error::Cancelled)?;
                        }
                        Ok(())
                    };
                    let result = crate::io::bounded(receiving, changes, idle, cancel.clone()).await;
                    cancel.cancel();
                    events.record(if result.is_ok() {
                        NodeEvent::Completed
                    } else {
                        NodeEvent::Failed
                    });
                });
                targets.insert(
                    target.clone(),
                    Entry {
                        sender: channel.sender,
                        cancel: token,
                        activity,
                    },
                );
                context.events.record(NodeEvent::Accepted);
            }
            let entry = targets.get_mut(&target).ok_or_else(protocol)?;
            entry.sender.send(&packet).await?;
            entry.activity.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=upload=>result,result=download=>result}
}
