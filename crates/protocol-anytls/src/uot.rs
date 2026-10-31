use crate::codec;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, InboundContext, Result,
};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::mpsc,
    task::JoinSet,
};
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
pub async fn serve(
    mut stream: BoxStream,
    access: Arc<dyn AccessService>,
    context: InboundContext,
) -> Result<()> {
    let connection = ConnectContext {
        cancel: context.cancel.clone(),
        timeout: context.connect_timeout,
    };
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
    let (responses, mut packets) = mpsc::channel::<(Destination, Vec<u8>)>(32);
    let mut workers = JoinSet::new();
    let (activity, mut observed) = tokio::sync::watch::channel(tokio::time::Instant::now());
    let mut channels: HashMap<Destination, Box<dyn DatagramSender>> = HashMap::new();
    let incoming = async {
        loop {
            let target = if let Some(target) = &fixed {
                target.clone()
            } else {
                codec::destination(&mut reader, true).await?
            };
            let Some(data) = packet(&mut reader, context.max_datagram_size).await? else {
                return Ok::<_, Error>(());
            };
            if !channels.contains_key(&target) {
                if channels.len() >= 32 {
                    return Err(Error::ResourceLimit);
                }
                let channel = access.connect_udp(&target, &connection).await?;
                channels.insert(target.clone(), channel.sender);
                let mut receiver = channel.receiver;
                let responses = responses.clone();
                let target = target.clone();
                let cancel = context.cancel.clone();
                workers.spawn(async move {
                    loop {let data=tokio::select!{_ = cancel.cancelled()=>return, data=receiver.recv()=>match data {Ok(Some(data))=>data,_=>return}};if responses.send((target.clone(),data)).await.is_err(){return}}
                });
            }
            channels.get_mut(&target).unwrap().send(&data).await?;
            activity.send_replace(tokio::time::Instant::now());
        }
    };
    let outgoing = async {
        while let Some((target, data)) = packets.recv().await {
            if data.len() > context.max_datagram_size {
                return Err(Error::ResourceLimit);
            }
            if !connected {
                writer.write_all(&codec::address(&target, true)).await?;
            }
            write_packet(&mut writer, &data).await?;
            activity.send_replace(tokio::time::Instant::now());
        }
        Ok::<_, Error>(())
    };
    tokio::pin!(incoming, outgoing);
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        tokio::select! {biased;_ = context.cancel.cancelled()=>return Err(Error::Cancelled),r=&mut incoming=>return r,r=&mut outgoing=>return r,_=&mut timer=>return Err(Error::Timeout),changed=observed.changed()=>{if changed.is_ok(){timer.as_mut().reset(*observed.borrow_and_update()+context.idle_timeout);}}}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Deny;
    impl AccessService for Deny {
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<BoxStream>> {
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
    struct Observer;
    impl kerlico_core::NodeObserver for Observer {
        fn record(&self, _: kerlico_core::NodeEvent) {}
    }
    #[tokio::test]
    async fn unfinished_header_has_timeout_and_cancellation() {
        let mut context = InboundContext {
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
        let (stream, _peer) = tokio::io::duplex(64);
        assert!(matches!(
            serve(Box::new(stream), Arc::new(Deny), context.clone()).await,
            Err(Error::Timeout)
        ));
        context.cancel = kerlico_core::CancellationToken::new();
        context.cancel.cancel();
        let (stream, _peer) = tokio::io::duplex(64);
        assert!(matches!(
            serve(Box::new(stream), Arc::new(Deny), context).await,
            Err(Error::Cancelled)
        ));
    }
}
