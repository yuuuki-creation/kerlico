//! UoT v1/v2；逐包地址用单一远端关联，固定目标保留独立通道语义。
use crate::{
    config::{UotOptions, malformed},
    http,
};
use kerlico_core::{
    AccessService, Address, AddressedDatagram, BoxFuture, BoxStream, ConnectContext,
    DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, Error, InboundContext, Result,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
pub(crate) fn magic(version: u8) -> Result<Destination> {
    Destination::new(if version == 1 { http::V1 } else { http::V2 }, 1)
}
pub(crate) fn version(target: &Destination) -> Option<u8> {
    match target.host().as_str() {
        http::V1 => Some(1),
        http::V2 => Some(2),
        _ => None,
    }
}
fn address(target: &Destination, packet: bool) -> Result<Vec<u8>> {
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
async fn read_address(
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
async fn initial(
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
    let target = read_address(reader, family, false, !connect).await?;
    Ok(if connect {
        Some(target.ok_or_else(malformed)?)
    } else {
        None
    })
}
pub(crate) async fn request(
    writer: &mut (impl AsyncWrite + Unpin),
    options: UotOptions,
    fixed: Option<&Destination>,
) -> Result<()> {
    if options.version == 2 {
        writer.write_u8(u8::from(fixed.is_some())).await?;
        let placeholder = Destination::new("0.0.0.0", 1)?;
        writer
            .write_all(&address(fixed.unwrap_or(&placeholder), false)?)
            .await?;
        writer.flush().await?;
    }
    Ok(())
}
async fn read(
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
        let target = read_address(reader, first[0], true, false)
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
async fn write(
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
        writer.write_all(&address(target, true)?).await?;
    }
    writer.write_u16(packet.len() as u16).await?;
    writer.write_all(packet).await?;
    writer.flush().await?;
    Ok(())
}
struct Sender {
    writer: WriteHalf<BoxStream>,
    fixed: Option<Destination>,
    cancel: kerlico_core::CancellationToken,
}
struct Receiver {
    reader: ReadHalf<BoxStream>,
    fixed: Option<Destination>,
    cancel: kerlico_core::CancellationToken,
}
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Cancelled),result=write(&mut self.writer,self.fixed.is_some(),target,packet,65535)=>result}
        })
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Cancelled),result=read(&mut self.reader,self.fixed.as_ref(),65535)=>result}
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
                        Address::Ip(expected) => {
                            matches!(source.address(),Address::Ip(actual) if actual.to_canonical()==expected.to_canonical())
                        }
                        Address::Domain(_) => true,
                    };
                if matches {
                    return Ok(Some(packet));
                }
            }
        })
    }
}
pub(crate) fn association(
    stream: BoxStream,
    cancel: kerlico_core::CancellationToken,
) -> DatagramAssociation {
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
pub(crate) fn channel(
    stream: BoxStream,
    options: UotOptions,
    target: &Destination,
    cancel: kerlico_core::CancellationToken,
) -> DatagramChannel {
    let fixed = if options.version == 2 {
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
pub(crate) async fn serve(
    mut stream: BoxStream,
    version: u8,
    access: Arc<dyn AccessService>,
    context: InboundContext,
) -> Result<()> {
    let connection = ConnectContext {
        cancel: context.cancel.clone(),
        timeout: context.connect_timeout,
    };
    let fixed = connection.run(initial(&mut stream, version)).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (activity, mut observed) = tokio::sync::watch::channel(tokio::time::Instant::now());
    let relay = async {
        if let Some(target) = fixed {
            let DatagramChannel {
                mut sender,
                mut receiver,
            } = access.connect_udp(&target, &connection).await?;
            let incoming = async {
                while let Some((_, packet)) =
                    read(&mut reader, Some(&target), context.max_datagram_size).await?
                {
                    sender.send(&packet).await?;
                    activity.send_replace(tokio::time::Instant::now());
                }
                Ok::<_, Error>(())
            };
            let outgoing = async {
                while let Some(packet) = receiver.recv().await? {
                    write(
                        &mut writer,
                        true,
                        &target,
                        &packet,
                        context.max_datagram_size,
                    )
                    .await?;
                    activity.send_replace(tokio::time::Instant::now());
                }
                Ok::<_, Error>(())
            };
            tokio::select! {result=incoming=>result,result=outgoing=>result}
        } else {
            let DatagramAssociation {
                mut sender,
                mut receiver,
            } = access.associate_udp(&connection).await?;
            let incoming = async {
                while let Some((target, packet)) =
                    read(&mut reader, None, context.max_datagram_size).await?
                {
                    sender.send_to(&packet, &target).await?;
                    activity.send_replace(tokio::time::Instant::now());
                }
                Ok::<_, Error>(())
            };
            let outgoing = async {
                while let Some((target, packet)) = receiver.recv_from().await? {
                    write(
                        &mut writer,
                        false,
                        &target,
                        &packet,
                        context.max_datagram_size,
                    )
                    .await?;
                    activity.send_replace(tokio::time::Instant::now());
                }
                Ok::<_, Error>(())
            };
            tokio::select! {result=incoming=>result,result=outgoing=>result}
        }
    };
    tokio::pin!(relay);
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),result=&mut relay=>return result,changed=observed.changed()=>{if changed.is_ok(){timer.as_mut().reset(*observed.borrow_and_update()+context.idle_timeout);}},_=&mut timer=>return Err(Error::Timeout)}
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn versions_addresses_zero_and_large_packets_are_distinct() {
        for host in ["127.0.0.1", "::1", "example.invalid"] {
            let target = Destination::new(host, 53).unwrap();
            for size in [0, 17, 65535] {
                let packet = vec![91; size];
                let mut wire = Vec::new();
                write(&mut wire, false, &target, &packet, 65535)
                    .await
                    .unwrap();
                assert_eq!(
                    read(&mut wire.as_slice(), None, 65535).await.unwrap(),
                    Some((target.clone(), packet))
                );
            }
            let mut request_wire = Vec::new();
            request(
                &mut request_wire,
                UotOptions {
                    enabled: true,
                    version: 2,
                },
                Some(&target),
            )
            .await
            .unwrap();
            assert_eq!(
                initial(&mut request_wire.as_slice(), 2).await.unwrap(),
                Some(target)
            );
        }
        assert!(initial(&mut [2].as_slice(), 2).await.is_err());
        assert!(read(&mut [9].as_slice(), None, 65535).await.is_err());
        assert_eq!(
            initial(&mut [0, 1, 0, 0, 0, 0, 0, 0].as_slice(), 2)
                .await
                .unwrap(),
            None
        );
        let target = Destination::new("127.0.0.1", 53).unwrap();
        assert!(
            write(&mut Vec::new(), false, &target, &vec![0; 65536], 65535)
                .await
                .is_err()
        );
    }
}
#[cfg(test)]
mod mapped_tests {
    use super::*;
    #[tokio::test]
    async fn mapped_ipv6_wire_source_is_canonical_and_matches_ipv4_fixed_channel() {
        let target = Destination::new("127.0.0.1", 53).unwrap();
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        let mut wire = vec![1];
        wire.extend(mapped.octets());
        wire.extend(53u16.to_be_bytes());
        wire.extend(3u16.to_be_bytes());
        wire.extend(b"abc");
        assert_eq!(
            read(&mut wire.as_slice(), None, 65535).await.unwrap(),
            Some((target.clone(), b"abc".to_vec()))
        );
        for target in [target, Destination::new("::ffff:127.0.0.1", 53).unwrap()] {
            let (stream, mut peer) = tokio::io::duplex(64);
            let mut channel = channel(
                Box::new(stream),
                UotOptions {
                    enabled: true,
                    version: 1,
                },
                &target,
                kerlico_core::CancellationToken::new(),
            );
            peer.write_all(&wire).await.unwrap();
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(1), channel.receiver.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                Some(b"abc".to_vec())
            );
        }
    }
}
