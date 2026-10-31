//! UDP 每帧保留目的地址，节点按目标维护有界关联。
use crate::{codec, protocol};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, InboundContext, NodeEvent, Result,
};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{ReadHalf, WriteHalf},
    sync::{mpsc, watch},
    task::JoinSet,
    time::Instant,
};
const MAX_PACKET: usize = 65535;
struct Sender {
    writer: WriteHalf<BoxStream>,
    target: Destination,
}
struct Receiver {
    reader: ReadHalf<BoxStream>,
    target: Destination,
}
pub(crate) fn channel(stream: BoxStream, target: Destination) -> DatagramChannel {
    let (reader, writer) = tokio::io::split(stream);
    DatagramChannel {
        sender: Box::new(Sender {
            writer,
            target: target.clone(),
        }),
        receiver: Box::new(Receiver { reader, target }),
    }
}
impl DatagramSender for Sender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            codec::write_packet(&mut self.writer, &self.target, packet, MAX_PACKET).await
        })
    }
}
impl DatagramReceiver for Receiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            match codec::packet(&mut self.reader, MAX_PACKET).await? {
                None => Ok(None),
                Some((target, packet))
                    if target.port() == self.target.port()
                        && (matches!(self.target.address(), kerlico_core::Address::Domain(_))
                            || target == self.target) =>
                {
                    Ok(Some(packet))
                }
                Some(_) => Err(protocol()),
            }
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
    stream: BoxStream,
    access: Arc<dyn AccessService>,
    context: InboundContext,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (responses, mut packets) = mpsc::channel::<(Destination, Vec<u8>)>(32);
    let download = async {
        while let Some((target, packet)) = packets.recv().await {
            codec::write_packet(&mut writer, &target, &packet, context.max_datagram_size).await?;
        }
        Ok::<_, Error>(())
    };
    let upload = async {
        let mut entries = HashMap::<Destination, Entry>::new();
        let mut tasks = JoinSet::new();
        while let Some((target, packet)) =
            codec::packet(&mut reader, context.max_datagram_size).await?
        {
            while tasks.try_join_next().is_some() {}
            entries.retain(|_, entry| !entry.cancel.is_cancelled());
            if !entries.contains_key(&target) {
                if entries.len() >= context.max_streams {
                    return Err(Error::ResourceLimit);
                }
                let lease = context.stream_budget.try_acquire()?;
                let connect = ConnectContext {
                    cancel: context.cancel.clone(),
                    timeout: context.connect_timeout,
                };
                let channel = access.connect_udp(&target, &connect).await?;
                let cancel = context.cancel.child_token();
                let (activity, changes) = watch::channel(Instant::now());
                let mut receiver = channel.receiver;
                let replies = responses.clone();
                let peer = target.clone();
                let token = cancel.clone();
                let events = context.events.clone();
                let idle = context.idle_timeout;
                let received_activity = activity.clone();
                tasks.spawn(async move {
                    let _lease = lease;
                    let receiving = async {
                        while let Some(packet) = receiver.recv().await? {
                            received_activity.send_replace(Instant::now());
                            replies
                                .send((peer.clone(), packet))
                                .await
                                .map_err(|_| Error::Cancelled)?;
                        }
                        Ok(())
                    };
                    let result = crate::io::bounded(receiving, changes, idle, token.clone()).await;
                    token.cancel();
                    events.record(if result.is_ok() {
                        NodeEvent::Completed
                    } else {
                        NodeEvent::Failed
                    });
                });
                entries.insert(
                    target.clone(),
                    Entry {
                        sender: channel.sender,
                        cancel,
                        activity,
                    },
                );
                context.events.record(NodeEvent::Accepted);
            }
            let entry = entries.get_mut(&target).ok_or_else(protocol)?;
            entry.sender.send(&packet).await?;
            entry.activity.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    // 物理连接输入结束时销毁本关联的所有目标和读取任务。
    tokio::select! { biased; _ = context.cancel.cancelled() => Err(Error::Cancelled), result = upload => result, result = download => result }
}
