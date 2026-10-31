use crate::{
    io::{CancelIo, CancelOnDrop},
    wire::address,
};
use kerlico_core::{
    Address, AddressedDatagram, BoxFuture, BoxStream, CancellationToken, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Result,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

pub(crate) const MAX_PACKET: usize = 65507;
struct Sender {
    stream: WriteHalf<CancelIo<BoxStream>>,
    owner: Arc<CancelOnDrop>,
    maximum: usize,
}
struct Receiver {
    stream: ReadHalf<CancelIo<BoxStream>>,
    owner: Arc<CancelOnDrop>,
    maximum: usize,
    literal_sources: bool,
    head: [u8; 4],
    head_used: usize,
    address: Vec<u8>,
    address_used: usize,
    payload: Vec<u8>,
    payload_used: usize,
    prepared: bool,
    ended: bool,
}
struct PartialSend {
    cancel: CancellationToken,
    complete: bool,
}
impl Drop for PartialSend {
    fn drop(&mut self) {
        if !self.complete {
            self.cancel.cancel();
        }
    }
}

pub(crate) fn association(
    stream: BoxStream,
    parent: &CancellationToken,
    maximum: usize,
    literal_sources: bool,
) -> DatagramAssociation {
    let cancel = parent.child_token();
    let (reader, writer) = tokio::io::split(CancelIo::new(stream, &cancel));
    let owner = Arc::new(CancelOnDrop(cancel));
    let maximum = maximum.min(MAX_PACKET);
    DatagramAssociation {
        sender: Box::new(Sender {
            stream: writer,
            owner: owner.clone(),
            maximum,
        }),
        receiver: Box::new(Receiver {
            stream: reader,
            owner,
            maximum,
            literal_sources,
            head: [0; 4],
            head_used: 0,
            address: Vec::new(),
            address_used: 0,
            payload: Vec::new(),
            payload_used: 0,
            prepared: false,
            ended: false,
        }),
    }
}

impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if packet.len() > self.maximum {
                return Err(Error::ResourceLimit);
            }
            let addr = address::encode(target);
            let mut frame = Vec::with_capacity(4 + addr.len() + packet.len());
            frame.extend_from_slice(&(addr.len() as u16).to_be_bytes());
            frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            frame.extend(addr);
            frame.extend_from_slice(packet);
            let mut partial = PartialSend {
                cancel: self.owner.0.clone(),
                complete: false,
            };
            self.stream.write_all(&frame).await?;
            self.stream.flush().await?;
            partial.complete = true;
            Ok(())
        })
    }
}
impl Receiver {
    async fn packet(&mut self) -> Result<Option<AddressedDatagram>> {
        if self.ended {
            return Ok(None);
        }
        let mut skipped = 0usize;
        loop {
            if self.owner.0.is_cancelled() {
                return Err(Error::Cancelled);
            }
            while self.head_used < 4 {
                let count = self.stream.read(&mut self.head[self.head_used..]).await?;
                if count == 0 {
                    self.ended = true;
                    self.owner.0.cancel();
                    return if self.head_used == 0 {
                        Ok(None)
                    } else {
                        Err(crate::invalid())
                    };
                }
                self.head_used += count;
            }
            if !self.prepared {
                let address_len =
                    usize::from(u16::from_be_bytes(self.head[..2].try_into().unwrap()));
                let payload_len =
                    usize::from(u16::from_be_bytes(self.head[2..].try_into().unwrap()));
                if address_len == 0 || payload_len > self.maximum {
                    self.owner.0.cancel();
                    return Err(Error::ResourceLimit);
                }
                self.address.resize(address_len, 0);
                self.address_used = 0;
                self.payload.resize(payload_len, 0);
                self.payload_used = 0;
                self.prepared = true;
            }
            while self.address_used < self.address.len() {
                let count = self
                    .stream
                    .read(&mut self.address[self.address_used..])
                    .await?;
                if count == 0 {
                    self.owner.0.cancel();
                    return Err(crate::invalid());
                }
                self.address_used += count;
            }
            while self.payload_used < self.payload.len() {
                let count = self
                    .stream
                    .read(&mut self.payload[self.payload_used..])
                    .await?;
                if count == 0 {
                    self.owner.0.cancel();
                    return Err(crate::invalid());
                }
                self.payload_used += count;
            }
            let (source, _) = match address::decode(&self.address) {
                Ok(v) => v,
                Err(error) => {
                    self.owner.0.cancel();
                    return Err(error);
                }
            };
            self.prepared = false;
            self.head_used = 0;
            if self.literal_sources && !matches!(source.address(), Address::Ip(_)) {
                self.payload.clear();
                skipped += 1;
                if skipped.is_multiple_of(32) {
                    tokio::task::yield_now().await;
                }
                continue;
            }
            return Ok(Some((source, std::mem::take(&mut self.payload))));
        }
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(self.packet())
    }
}

struct FixedSender {
    sender: Box<dyn DatagramAssociationSender>,
    target: Destination,
}
struct FixedReceiver {
    receiver: Box<dyn DatagramAssociationReceiver>,
    target: Destination,
}
pub(crate) fn fixed(association: DatagramAssociation, target: Destination) -> DatagramChannel {
    let target = match target.address() {
        Address::Ip(ip) => Destination::new(&ip.to_canonical().to_string(), target.port())
            .expect("已校验的字面目标"),
        _ => target,
    };
    DatagramChannel {
        sender: Box::new(FixedSender {
            sender: association.sender,
            target: target.clone(),
        }),
        receiver: Box::new(FixedReceiver {
            receiver: association.receiver,
            target,
        }),
    }
}
impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.sender.send_to(packet, &self.target)
    }
}
impl DatagramReceiver for FixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        matches!(self.target.address(), Address::Ip(_)).then(|| self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            loop {
                let Some((source, payload)) = self.receiver.recv_from().await? else {
                    return Ok(None);
                };
                if source == self.target
                    || matches!(self.target.address(), Address::Domain(_))
                        && source.port() == self.target.port()
                {
                    return Ok(Some(payload));
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn zero_large_packets_source_metadata_and_suspended_partial_reads() {
        let (a, b) = tokio::io::duplex(23);
        let cancel = CancellationToken::new();
        let mut client = association(Box::new(a), &cancel, MAX_PACKET, true);
        let mut server = association(Box::new(b), &cancel, MAX_PACKET, false);
        let expected = Destination::new("2001:db8::1", 53).unwrap();
        let peer_expected = expected.clone();
        let peer = tokio::spawn(async move {
            for len in [0, 17, 12000, 65507] {
                let (target, packet) = server.receiver.recv_from().await.unwrap().unwrap();
                assert_eq!(target, peer_expected);
                assert_eq!(packet, vec![7; len]);
                server.sender.send_to(&packet, &target).await.unwrap();
            }
        });
        for len in [0, 17, 12000, 65507] {
            client
                .sender
                .send_to(&vec![7; len], &expected)
                .await
                .unwrap();
            assert_eq!(
                client.receiver.recv_from().await.unwrap(),
                Some((expected.clone(), vec![7; len]))
            );
        }
        assert!(
            client
                .sender
                .send_to(&vec![0; 65508], &expected)
                .await
                .is_err()
        );
        drop(client);
        peer.await.unwrap();
        let (a, mut b) = tokio::io::duplex(32);
        let mut client = association(Box::new(a), &cancel, MAX_PACKET, true);
        let addr = address::encode(&expected);
        let peer = tokio::spawn(async move {
            b.write_all(&[0]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            let mut rest = vec![addr.len() as u8, 0, 3];
            rest.extend(addr);
            rest.extend_from_slice(&[1, 2, 3]);
            b.write_all(&rest).await.unwrap();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.receiver.recv_from())
                .await
                .is_err()
        );
        assert_eq!(
            client.receiver.recv_from().await.unwrap(),
            Some((expected, vec![1, 2, 3]))
        );
        drop(client);
        peer.await.unwrap();
    }
    #[tokio::test]
    async fn interrupted_send_poisons_both_halves_without_resending() {
        let (a, mut b) = tokio::io::duplex(5);
        let cancel = CancellationToken::new();
        let mut association = association(Box::new(a), &cancel, MAX_PACKET, true);
        let target = Destination::new("192.0.2.1", 53).unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                association.sender.send_to(&vec![0; 65507], &target)
            )
            .await
            .is_err()
        );
        assert!(association.sender.send_to(&[], &target).await.is_err());
        assert!(association.receiver.recv_from().await.is_err());
        drop(association);
        let mut tail = Vec::new();
        b.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail.len(), 5);
    }
}
