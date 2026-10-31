//! UDP 会话通过独立 hold stream 结束，不从连接存活推定会话存活。
use crate::{client::Connection, dispatch::Queued, io::QuicIo};
use kerlico_core::{
    Address, BoxFuture, DatagramAssociation, DatagramAssociationReceiver,
    DatagramAssociationSender, DatagramChannel, DatagramReceiver, DatagramSender, Destination,
    Error, Result,
};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, mpsc};
struct Owner {
    state: Arc<Connection>,
    id: u32,
    generation: u64,
    cancel: kerlico_core::CancellationToken,
    send: Mutex<Option<quinn::SendStream>>,
    _permit: OwnedSemaphorePermit,
}
impl Owner {
    fn close(&self) {
        self.cancel.cancel();
        self.state.hub.remove(self.id, self.generation);
        if let Ok(mut send) = self.send.lock()
            && let Some(mut send) = send.take()
        {
            let _ = send.finish();
        }
        self.state.touch();
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.close();
    }
}
struct Sender {
    owner: Arc<Owner>,
}
struct Receiver {
    owner: Arc<Owner>,
    incoming: mpsc::Receiver<Queued>,
}
pub(crate) fn client_channel(
    state: Arc<Connection>,
    id: u32,
    stream: QuicIo,
    permit: OwnedSemaphorePermit,
) -> Result<DatagramAssociation> {
    let token = state.cancel.child_token();
    let (generation, incoming) = state.hub.register(id, token.clone())?;
    let QuicIo { send, mut recv, .. } = stream;
    let owner = Arc::new(Owner {
        state: state.clone(),
        id,
        generation,
        cancel: token.clone(),
        send: Mutex::new(Some(send)),
        _permit: permit,
    });
    let weak = Arc::downgrade(&owner);
    let state_weak = state.weak();
    state.spawn(async move{let mut byte=[0];tokio::select!{_=token.cancelled()=>{},_=tokio::io::AsyncReadExt::read(&mut recv,&mut byte)=>{}}let _=recv.stop(0u32.into());if let Some(owner)=weak.upgrade(){owner.close();}else if let Some(state)=state_weak.upgrade(){state.hub.remove(id,generation);}});
    Ok(DatagramAssociation {
        sender: Box::new(Sender {
            owner: owner.clone(),
        }),
        receiver: Box::new(Receiver { owner, incoming }),
    })
}
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.owner.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            self.owner
                .state
                .sender
                .send(
                    &self.owner.state.connection,
                    self.owner.id,
                    target,
                    packet,
                    &self.owner.cancel,
                )
                .await?;
            self.owner.state.touch();
            Ok(())
        })
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<kerlico_core::AddressedDatagram>>> {
        Box::pin(async move {
            let queued = tokio::select! {biased;_=self.owner.cancel.cancelled()=>return Ok(None),packet=self.incoming.recv()=>packet};
            let Some(queued) = queued else {
                return Ok(None);
            };
            self.owner.state.touch();
            Ok(Some((queued.packet.target, queued.packet.data)))
        })
    }
}
struct FixedSender {
    sender: Box<dyn DatagramAssociationSender>,
    target: Destination,
}
struct FixedReceiver {
    receiver: Box<dyn DatagramAssociationReceiver>,
    target: Destination,
    peer: Option<Destination>,
}
pub(crate) fn fixed(association: DatagramAssociation, target: Destination) -> DatagramChannel {
    let peer = if matches!(target.address(), Address::Ip(_)) {
        Some(target.clone())
    } else {
        None
    };
    DatagramChannel {
        sender: Box::new(FixedSender {
            sender: association.sender,
            target: target.clone(),
        }),
        receiver: Box::new(FixedReceiver {
            receiver: association.receiver,
            target,
            peer,
        }),
    }
}
impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.sender.send_to(packet, &self.target).await })
    }
}
impl DatagramReceiver for FixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        self.peer.clone()
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            while let Some((peer, packet)) = self.receiver.recv_from().await? {
                if peer.port() == self.target.port()
                    && (matches!(self.target.address(), Address::Domain(_)) || peer == self.target)
                {
                    self.peer = Some(peer);
                    return Ok(Some(packet));
                }
            }
            Ok(None)
        })
    }
}
