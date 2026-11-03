//! 通用 UDP-over-TCP（UoT v1/v2）客户端通道与服务端分发。

use kerlico_core::{
    Address, AddressedDatagram, BoxFuture, BoxStream, CancellationToken, ConnectContext,
    DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, Error, FlowFailure, FlowOutcome, InboundContext,
    PeerSession, Result,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

pub const MAGIC_V1: &str = "sp.udp-over-tcp.arpa";
pub const MAGIC_V2: &str = "sp.v2.udp-over-tcp.arpa";

fn malformed() -> Error {
    Error::Protocol("UoT 帧或地址格式不合法")
}

pub fn magic_destination(version: u8) -> Result<Destination> {
    Destination::new(if version == 1 { MAGIC_V1 } else { MAGIC_V2 }, 1)
}

pub fn magic_version(target: &Destination) -> Option<u8> {
    if target.host().eq_ignore_ascii_case(MAGIC_V1) {
        Some(1)
    } else if target.host().eq_ignore_ascii_case(MAGIC_V2) {
        Some(2)
    } else {
        None
    }
}

pub fn encode_uot_address(target: &Destination, packet: bool) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(260);
    match target.address() {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(if packet { 0 } else { 1 });
            out.extend(ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(if packet { 1 } else { 4 });
            out.extend(ip.octets());
        }
        Address::Domain(name) => {
            out.push(if packet { 2 } else { 3 });
            out.push(u8::try_from(name.len()).map_err(|_| malformed())?);
            out.extend(name.as_bytes());
        }
    }
    out.extend(target.port().to_be_bytes());
    Ok(out)
}

pub async fn read_uot_address(
    reader: &mut (impl AsyncRead + Unpin),
    family: u8,
    packet: bool,
    allow_zero: bool,
) -> Result<Option<Destination>> {
    let host = match (packet, family) {
        (true, 0) | (false, 1) => {
            let mut b = [0; 4];
            reader.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        (true, 1) | (false, 4) => {
            let mut b = [0; 16];
            reader.read_exact(&mut b).await?;
            IpAddr::V6(Ipv6Addr::from(b)).to_canonical().to_string()
        }
        (true, 2) | (false, 3) => {
            let n = reader.read_u8().await? as usize;
            if n == 0 {
                return Err(malformed());
            }
            let mut b = vec![0; n];
            reader.read_exact(&mut b).await?;
            String::from_utf8(b).map_err(|_| malformed())?
        }
        _ => return Err(malformed()),
    };
    let port = reader.read_u16().await?;
    if allow_zero && port == 0 {
        return Ok(None);
    }
    Ok(Some(
        Destination::new(&host, port).map_err(|_| malformed())?,
    ))
}

async fn read_initial(
    reader: &mut (impl AsyncRead + Unpin),
    version: u8,
) -> Result<Option<Destination>> {
    if version == 1 {
        return Ok(None);
    }
    let connect = match reader.read_u8().await? {
        0 => false,
        1 => true,
        _ => return Err(malformed()),
    };
    let family = reader.read_u8().await?;
    let target = read_uot_address(reader, family, false, !connect).await?;
    Ok(if connect {
        Some(target.ok_or_else(malformed)?)
    } else {
        None
    })
}

pub async fn write_request(
    writer: &mut (impl AsyncWrite + Unpin),
    version: u8,
    fixed: Option<&Destination>,
) -> Result<()> {
    if version == 2 {
        writer.write_u8(u8::from(fixed.is_some())).await?;
        let placeholder = Destination::new("0.0.0.0", 1)?;
        writer
            .write_all(&encode_uot_address(fixed.unwrap_or(&placeholder), false)?)
            .await?;
        writer.flush().await?;
    }
    Ok(())
}

pub async fn read_datagram(
    reader: &mut (impl AsyncRead + Unpin),
    fixed: Option<&Destination>,
    maximum: usize,
) -> Result<Option<AddressedDatagram>> {
    let mut first = [0];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let (target, size) = if let Some(target) = fixed {
        (
            target.clone(),
            u16::from_be_bytes([first[0], reader.read_u8().await?]) as usize,
        )
    } else {
        let target = read_uot_address(reader, first[0], true, false)
            .await?
            .ok_or_else(malformed)?;
        (target, reader.read_u16().await? as usize)
    };
    if size > maximum {
        return Err(Error::ResourceLimit);
    }
    let mut packet = vec![0; size];
    reader.read_exact(&mut packet).await?;
    Ok(Some((target, packet)))
}

pub async fn write_datagram(
    writer: &mut (impl AsyncWrite + Unpin),
    fixed: bool,
    target: &Destination,
    packet: &[u8],
    maximum: usize,
) -> Result<()> {
    if packet.len() > maximum || packet.len() > 65535 {
        return Err(Error::ResourceLimit);
    }
    if !fixed {
        writer.write_all(&encode_uot_address(target, true)?).await?;
    }
    writer.write_u16(packet.len() as u16).await?;
    writer.write_all(packet).await?;
    writer.flush().await?;
    Ok(())
}

struct Sender {
    writer: WriteHalf<BoxStream>,
    fixed: Option<Destination>,
    cancel: CancellationToken,
}
struct Receiver {
    reader: ReadHalf<BoxStream>,
    fixed: Option<Destination>,
    cancel: CancellationToken,
}

impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => Err(Error::Cancelled),
                res = write_datagram(&mut self.writer, self.fixed.is_some(), target, packet, 65535) => res,
            }
        })
    }
}

impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => Err(Error::Cancelled),
                res = read_datagram(&mut self.reader, self.fixed.as_ref(), 65535) => res,
            }
        })
    }
}

struct FixedSender {
    sender: Sender,
    target: Destination,
}
struct FixedReceiver {
    receiver: Receiver,
    target: Destination,
}

impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.sender.send_to(packet, &self.target)
    }
}

impl DatagramReceiver for FixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            loop {
                let Some((source, packet)) = self.receiver.recv_from().await? else {
                    return Ok(None);
                };
                let matches = source.port() == self.target.port()
                    && match self.target.address() {
                        Address::Ip(expected) => matches!(
                            source.address(),
                            Address::Ip(actual) if actual.to_canonical() == expected.to_canonical()
                        ),
                        Address::Domain(_) => true,
                    };
                if matches {
                    return Ok(Some(packet));
                }
            }
        })
    }
}

pub fn association(stream: BoxStream, cancel: CancellationToken) -> DatagramAssociation {
    let (reader, writer) = tokio::io::split(stream);
    DatagramAssociation {
        sender: Box::new(Sender {
            writer,
            fixed: None,
            cancel: cancel.clone(),
        }),
        receiver: Box::new(Receiver {
            reader,
            fixed: None,
            cancel,
        }),
    }
}

pub fn channel(
    stream: BoxStream,
    version: u8,
    target: &Destination,
    cancel: CancellationToken,
) -> DatagramChannel {
    let fixed = if version == 2 {
        Some(target.clone())
    } else {
        None
    };
    let (reader, writer) = tokio::io::split(stream);
    DatagramChannel {
        sender: Box::new(FixedSender {
            sender: Sender {
                writer,
                fixed: fixed.clone(),
                cancel: cancel.clone(),
            },
            target: target.clone(),
        }),
        receiver: Box::new(FixedReceiver {
            receiver: Receiver {
                reader,
                fixed,
                cancel,
            },
            target: target.clone(),
        }),
    }
}

pub async fn serve(
    mut stream: BoxStream,
    version: u8,
    access: PeerSession,
    context: InboundContext,
) -> Result<()> {
    let connection =
        ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    let fixed = connection.run(read_initial(&mut stream, version)).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let outcome = |result: &Result<()>| match result {
        Ok(()) => FlowOutcome::ProtocolEnd,
        Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
    };
    if let Some(target) = fixed {
        let (mut sender, mut receiver, completion) =
            access.connect_udp(&target, &connection).await?.into_parts();
        let result = {
            let incoming = async {
                while let Some((_, packet)) =
                    read_datagram(&mut reader, Some(&target), context.max_datagram_size).await?
                {
                    sender.send(&packet).await?;
                }
                Ok::<_, Error>(())
            };
            let outgoing = async {
                while let Some(packet) = receiver.recv().await? {
                    write_datagram(
                        &mut writer,
                        true,
                        &target,
                        &packet,
                        context.max_datagram_size,
                    )
                    .await?;
                }
                Ok::<_, Error>(())
            };
            tokio::select! {
                _ = context.cancel.cancelled() => Err(Error::Cancelled),
                res = incoming => res,
                res = outgoing => res,
            }
        };
        completion.finish(outcome(&result));
        result
    } else if let Ok(assoc) = access.associate_udp(&connection).await {
        let (mut sender, mut receiver, completion) = assoc.into_parts();
        let result = {
            let incoming = async {
                while let Some((target, packet)) =
                    read_datagram(&mut reader, None, context.max_datagram_size).await?
                {
                    sender.send_to(&packet, &target).await?;
                }
                Ok::<_, Error>(())
            };
            let outgoing = async {
                while let Some((target, packet)) = receiver.recv_from().await? {
                    write_datagram(
                        &mut writer,
                        false,
                        &target,
                        &packet,
                        context.max_datagram_size,
                    )
                    .await?;
                }
                Ok::<_, Error>(())
            };
            tokio::select! {
                _ = context.cancel.cancelled() => Err(Error::Cancelled),
                res = incoming => res,
                res = outgoing => res,
            }
        };
        completion.finish(outcome(&result));
        result
    } else {
        let Some((first_target, first_pkt)) =
            read_datagram(&mut reader, None, context.max_datagram_size).await?
        else {
            return Ok(());
        };
        let (mut sender, mut receiver, completion) = access
            .connect_udp(&first_target, &connection)
            .await?
            .into_parts();
        let send_first = sender.send(&first_pkt).await;
        if let Err(err) = send_first {
            completion.finish(FlowOutcome::Failed(FlowFailure::from_error(&err)));
            return Err(err);
        }
        let result = {
            let incoming = async {
                while let Some((_, packet)) =
                    read_datagram(&mut reader, None, context.max_datagram_size).await?
                {
                    sender.send(&packet).await?;
                }
                Ok::<_, Error>(())
            };
            let outgoing = async {
                while let Some(packet) = receiver.recv().await? {
                    write_datagram(
                        &mut writer,
                        false,
                        &first_target,
                        &packet,
                        context.max_datagram_size,
                    )
                    .await?;
                }
                Ok::<_, Error>(())
            };
            tokio::select! {
                _ = context.cancel.cancelled() => Err(Error::Cancelled),
                res = incoming => res,
                res = outgoing => res,
            }
        };
        completion.finish(outcome(&result));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn uot_v1_and_v2_client_channels_frame_and_parse_datagrams() {
        let target = Destination::new("example.com", 5353).unwrap();
        let (c1, mut s1) = tokio::io::duplex(4096);
        let mut ch1 = channel(
            Box::new(c1) as BoxStream,
            1,
            &target,
            CancellationToken::new(),
        );
        ch1.sender.send(b"ping-v1").await.unwrap();
        let (parsed_dst, parsed_pkt) = read_datagram(&mut s1, None, 4096).await.unwrap().unwrap();
        assert_eq!(parsed_dst, target);
        assert_eq!(parsed_pkt, b"ping-v1");
        write_datagram(&mut s1, false, &target, b"pong-v1", 4096)
            .await
            .unwrap();
        let recv1 = ch1.receiver.recv().await.unwrap().unwrap();
        assert_eq!(recv1, b"pong-v1");

        let (mut c2, mut s2) = tokio::io::duplex(4096);
        write_request(&mut c2, 2, Some(&target)).await.unwrap();
        let init_target = read_initial(&mut s2, 2).await.unwrap();
        assert_eq!(init_target, Some(target.clone()));
        let mut ch2 = channel(
            Box::new(c2) as BoxStream,
            2,
            &target,
            CancellationToken::new(),
        );
        ch2.sender.send(b"ping-v2").await.unwrap();
        let (dst, pkt) = read_datagram(&mut s2, Some(&target), 4096)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dst, target);
        assert_eq!(pkt, b"ping-v2");
        write_datagram(&mut s2, true, &target, b"pong-v2", 4096)
            .await
            .unwrap();
        let recv2 = ch2.receiver.recv().await.unwrap().unwrap();
        assert_eq!(recv2, b"pong-v2");
    }
}
