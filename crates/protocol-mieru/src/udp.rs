//! 两种载体共用的 Full Cone 包隧道；帧写入/读取取消后禁止继续复用半帧状态。
use crate::{codec, session::SessionIo};
use kerlico_core::{
    AddressedDatagram, BoxFuture, CancellationToken, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Result,
};
use std::time::Duration;
use tokio::{
    io::{AsyncWriteExt, ReadHalf, WriteHalf},
    sync::watch,
    time::Instant,
};
struct Sender {
    inner: WriteHalf<SessionIo>,
    invalid: bool,
}
struct Receiver {
    inner: ReadHalf<SessionIo>,
    invalid: bool,
}
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        bytes: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.invalid {
                return Err(Error::Protocol("Mieru UDP 写端已失效"));
            }
            let frame = codec::udp_packet(target, bytes)?;
            self.invalid = true;
            self.inner.write_all(&frame).await?;
            self.inner.flush().await?;
            self.invalid = false;
            Ok(())
        })
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            if self.invalid {
                return Err(Error::Protocol("Mieru UDP 读端已失效"));
            }
            self.invalid = true;
            let packet = codec::read_udp_packet(&mut self.inner).await?;
            self.invalid = false;
            Ok(packet)
        })
    }
}
pub(crate) fn association(stream: SessionIo) -> DatagramAssociation {
    let (read, write) = tokio::io::split(stream);
    DatagramAssociation {
        sender: Box::new(Sender {
            inner: write,
            invalid: false,
        }),
        receiver: Box::new(Receiver {
            inner: read,
            invalid: false,
        }),
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
impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.sender.send_to(bytes, &self.target)
    }
}
impl DatagramReceiver for FixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            loop {
                let Some((source, bytes)) = self.receiver.recv_from().await? else {
                    return Ok(None);
                };
                if source == self.target {
                    return Ok(Some(bytes));
                }
            }
        })
    }
}
pub(crate) fn fixed(association: DatagramAssociation, target: Destination) -> DatagramChannel {
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
pub(crate) async fn relay(
    stream: SessionIo,
    association: DatagramAssociation,
    max_packet: usize,
    idle: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    let (mut input, mut output) = tokio::io::split(stream);
    let DatagramAssociation {
        mut sender,
        mut receiver,
    } = association;
    let (activity, mut observed) = watch::channel(Instant::now());
    let sending_activity = activity.clone();
    let sending = async move {
        while let Some((target, packet)) = codec::read_udp_packet(&mut input).await? {
            if packet.len() > max_packet {
                return Err(codec::bad());
            }
            sender.send_to(&packet, &target).await?;
            sending_activity.send_replace(Instant::now());
        }
        Ok(())
    };
    let receiving = async move {
        while let Some((source, packet)) = receiver.recv_from().await? {
            if packet.len() > max_packet {
                return Err(codec::bad());
            }
            let frame = codec::udp_packet(&source, &packet)?;
            output.write_all(&frame).await?;
            output.flush().await?;
            activity.send_replace(Instant::now());
        }
        Ok(())
    };
    tokio::pin!(sending);
    tokio::pin!(receiving);
    let timer = tokio::time::sleep(idle);
    tokio::pin!(timer);
    loop {
        tokio::select! { biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            result = &mut sending => return result,
            result = &mut receiving => return result,
            _ = &mut timer => return Err(Error::Timeout),
            changed = observed.changed() => if changed.is_ok() { timer.as_mut().reset(*observed.borrow_and_update() + idle); },
        }
    }
}
