//! 出站只有固定目标 UDP 时，为多目标关联（TUN、SOCKS5 UDP）按目标各开一条固定通道。
//!
//! Mihomo 对 VMess、Trojan 这类出站同样按目标分别建立 UDP 会话；没有这层适配时，
//! 经 TUN 的 UDP 一旦选中这些出站就全部失败。

use kerlico_core::{
    AddressedDatagram, BoxFuture, CancellationToken, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramSender, Destination, Error,
    Outbound, Result,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;

/// 一条关联最多同时保持的目标数；超出时新目标的包被拒绝。
const MAX_TARGETS: usize = 256;

pub(crate) fn association(
    backend: Arc<dyn Outbound>,
    context: ConnectContext,
) -> DatagramAssociation {
    let (tx, rx) = mpsc::channel(64);
    let stop = CancellationToken::new();
    DatagramAssociation {
        sender: Box::new(PerTargetSender {
            backend,
            context,
            senders: HashMap::new(),
            tx,
            stop,
        }),
        receiver: Box::new(PerTargetReceiver { rx }),
    }
}

struct PerTargetSender {
    backend: Arc<dyn Outbound>,
    context: ConnectContext,
    senders: HashMap<Destination, Box<dyn DatagramSender>>,
    tx: mpsc::Sender<AddressedDatagram>,
    stop: CancellationToken,
}

impl Drop for PerTargetSender {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl DatagramAssociationSender for PerTargetSender {
    fn send_to<'a>(
        &'a mut self,
        payload: &'a [u8],
        remote: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.senders.contains_key(remote) {
                if self.senders.len() >= MAX_TARGETS {
                    return Err(Error::ResourceLimit);
                }
                let channel = self.backend.connect_udp(remote, &self.context).await?;
                let mut receiver = channel.receiver;
                let (tx, stop, target) = (self.tx.clone(), self.stop.clone(), remote.clone());
                tokio::spawn(async move {
                    loop {
                        let packet = tokio::select! { biased;
                            _ = stop.cancelled() => break,
                            _ = tx.closed() => break,
                            packet = receiver.recv() => packet,
                        };
                        match packet {
                            Ok(Some(payload)) => {
                                if tx.send((target.clone(), payload)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(None) | Err(_) => break,
                        }
                    }
                });
                self.senders.insert(remote.clone(), channel.sender);
            }
            match self.senders.get_mut(remote) {
                Some(sender) => sender.send(payload).await,
                None => Err(Error::ResourceLimit),
            }
        })
    }
}

struct PerTargetReceiver {
    rx: mpsc::Receiver<AddressedDatagram>,
}

impl DatagramAssociationReceiver for PerTargetReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.rx.recv().await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_core::{Capabilities, DatagramChannel, DatagramReceiver, OpenedTcp};
    use std::time::Duration;

    /// 固定目标 UDP 回显：回包带上建立通道时的目标端口。
    struct FixedEcho;
    struct EchoSender(mpsc::Sender<Vec<u8>>, u16);
    struct EchoReceiver(mpsc::Receiver<Vec<u8>>);
    impl DatagramSender for EchoSender {
        fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
            let reply = [self.1.to_be_bytes().as_slice(), packet].concat();
            Box::pin(async move { self.0.send(reply).await.map_err(|_| Error::Cancelled) })
        }
    }
    impl DatagramReceiver for EchoReceiver {
        fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
            Box::pin(async move { Ok(self.0.recv().await) })
        }
    }
    impl Outbound for FixedEcho {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: false,
                tcp_eof: false,
                udp: true,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<OpenedTcp>> {
            Box::pin(async { Err(Error::Rejected) })
        }
        fn connect_udp<'a>(
            &'a self,
            target: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            let (tx, rx) = mpsc::channel(8);
            let port = target.port();
            Box::pin(async move {
                Ok(DatagramChannel {
                    sender: Box::new(EchoSender(tx, port)),
                    receiver: Box::new(EchoReceiver(rx)),
                })
            })
        }
    }

    #[tokio::test]
    async fn each_target_gets_its_own_fixed_channel_and_replies_keep_their_source() {
        let mut flow = association(
            Arc::new(FixedEcho),
            ConnectContext::new(Duration::from_secs(5)),
        );
        let a = Destination::new("192.0.2.1", 53).unwrap();
        let b = Destination::new("192.0.2.2", 443).unwrap();
        flow.sender.send_to(b"one", &a).await.unwrap();
        flow.sender.send_to(b"two", &b).await.unwrap();
        let mut replies = [
            flow.receiver.recv_from().await.unwrap().unwrap(),
            flow.receiver.recv_from().await.unwrap().unwrap(),
        ];
        replies.sort_by_key(|(source, _)| source.port());
        assert_eq!(replies[0], (a, [&53u16.to_be_bytes()[..], b"one"].concat()));
        assert_eq!(
            replies[1],
            (b, [&443u16.to_be_bytes()[..], b"two"].concat())
        );
    }
}
