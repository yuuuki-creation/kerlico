use crate::io::Cancellable;
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, DatagramChannel, DatagramReceiver, DatagramSender,
    Destination, Error, Result,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

const MAX_PACKET: usize = 65507;
struct Owner(CancellationToken);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct Sender {
    stream: WriteHalf<Cancellable>,
    owner: Arc<Owner>,
}
struct Receiver {
    stream: ReadHalf<Cancellable>,
    owner: Arc<Owner>,
    target: Destination,
    head: [u8; 2],
    head_used: usize,
    body: Option<Vec<u8>>,
    body_used: usize,
    ended: bool,
}
struct Incomplete {
    cancel: CancellationToken,
    armed: bool,
}
impl Drop for Incomplete {
    fn drop(&mut self) {
        if self.armed {
            self.cancel.cancel();
        }
    }
}

pub(crate) fn channel(
    stream: BoxStream,
    target: Destination,
    parent: &CancellationToken,
) -> DatagramChannel {
    let cancel = parent.child_token();
    let (reader, writer) = tokio::io::split(Cancellable::new(stream, &cancel));
    let owner = Arc::new(Owner(cancel));
    DatagramChannel {
        sender: Box::new(Sender {
            stream: writer,
            owner: owner.clone(),
        }),
        receiver: Box::new(Receiver {
            stream: reader,
            owner,
            target,
            head: [0; 2],
            head_used: 0,
            body: None,
            body_used: 0,
            ended: false,
        }),
    }
}
impl DatagramSender for Sender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if packet.len() > MAX_PACKET {
                return Err(Error::ResourceLimit);
            }
            let mut incomplete = Incomplete {
                cancel: self.owner.0.clone(),
                armed: true,
            };
            self.stream
                .write_all(&(packet.len() as u16).to_be_bytes())
                .await?;
            self.stream.write_all(packet).await?;
            self.stream.flush().await?;
            incomplete.armed = false;
            Ok(())
        })
    }
}
impl DatagramReceiver for Receiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.ended {
                return Ok(None);
            }
            while self.head_used < 2 {
                let n = self.stream.read(&mut self.head[self.head_used..]).await?;
                if n == 0 {
                    self.ended = true;
                    self.owner.0.cancel();
                    return if self.head_used == 0 {
                        Ok(None)
                    } else {
                        Err(Error::Protocol("Relay UDP 帧头截断"))
                    };
                }
                self.head_used += n;
            }
            if self.body.is_none() {
                let len = u16::from_be_bytes(self.head) as usize;
                if len > MAX_PACKET {
                    self.owner.0.cancel();
                    return Err(Error::ResourceLimit);
                }
                self.body = Some(vec![0; len]);
                self.body_used = 0;
            }
            let body = self.body.as_mut().unwrap();
            while self.body_used < body.len() {
                let n = self.stream.read(&mut body[self.body_used..]).await?;
                if n == 0 {
                    self.owner.0.cancel();
                    return Err(Error::Protocol("Relay UDP 正文截断"));
                }
                self.body_used += n;
            }
            self.head_used = 0;
            Ok(self.body.take())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn cancelled_receive_keeps_frame_progress_and_zero_packets() {
        let (client, mut peer) = tokio::io::duplex(8);
        let cancel = CancellationToken::new();
        let mut channel = channel(
            Box::new(client),
            Destination::new("192.0.2.1", 53).unwrap(),
            &cancel,
        );
        let task = tokio::spawn(async move {
            peer.write_all(&[0]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            peer.write_all(&[3, 1]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            peer.write_all(&[2, 3, 0, 0]).await.unwrap();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), channel.receiver.recv())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(35), channel.receiver.recv())
                .await
                .is_err()
        );
        assert_eq!(channel.receiver.recv().await.unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(channel.receiver.recv().await.unwrap(), Some(vec![]));
        assert!(channel.receiver.recv().await.unwrap().is_none());
        task.await.unwrap();
    }
    #[tokio::test]
    async fn partial_send_cancellation_poisons_both_halves_without_replay() {
        let (client, mut peer) = tokio::io::duplex(4);
        let cancel = CancellationToken::new();
        let mut channel = channel(
            Box::new(client),
            Destination::new("192.0.2.1", 53).unwrap(),
            &cancel,
        );
        assert!(matches!(
            channel.sender.send(&vec![0; 65508]).await,
            Err(Error::ResourceLimit)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), channel.sender.send(&[1; 64]))
                .await
                .is_err()
        );
        assert!(channel.sender.send(&[]).await.is_err());
        assert!(channel.receiver.recv().await.is_err());
        drop(channel);
        let mut observed = Vec::new();
        peer.read_to_end(&mut observed).await.unwrap();
        assert_eq!(observed, vec![0, 64, 1, 1]);
    }
}
