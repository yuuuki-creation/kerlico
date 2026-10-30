//! Encryption、VLESS 响应、Vision 和数据报编码按顺序独立装配。

use crate::{UserId, carrier, codec, profile::PacketEncoding};
use kerlico_core::{
    BoxFuture, BoxStream, DatagramChannel, DatagramReceiver, DatagramSender, Destination, Error,
    Result,
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf, ReadHalf, WriteHalf,
};
use xray_proxy::vless::{
    VisionStream, VlessCommand, VlessRequest, VlessResponseStream,
    encode_request_header, encode_xudp_keep_packet, encode_xudp_new_packet, read_xudp_packet,
};
use xray_transport::{BoxedTransportStream, TransportStream};
use xray_vless_encryption::{Client, EncryptedStream};

macro_rules! ordinary_io {
    ($name:ident,$field:ident) => {
        impl AsyncRead for $name {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                out: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().$field).poll_read(cx, out)
            }
        }
        impl AsyncWrite for $name {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().$field).poll_write(cx, bytes)
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().$field).poll_flush(cx)
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().$field).poll_shutdown(cx)
            }
        }
    };
}

struct EncryptionCarrier {
    inner: EncryptedStream<BoxedTransportStream>,
}
ordinary_io!(EncryptionCarrier, inner);
impl TransportStream for EncryptionCarrier {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().inner.poll_read_vision_direct(cx, out)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().inner.poll_write_vision_direct(cx, bytes)
    }
}

pub(crate) fn server_vision(stream:BoxedTransportStream,user:UserId)->BoxStream {Box::new(VisionStream::new(crate::vision_io::VisionCarrier::new(stream,user,false),*user.as_bytes(),xray_proxy::vless::DEFAULT_VISION_SEED))}

/// 普通 VLESS 不提供目标 EOF 帧；逻辑写关闭后保留反向载体。
struct LogicalStream {
    inner: BoxStream,
    closed: bool,
}
impl AsyncRead for LogicalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, out)
    }
}
impl AsyncWrite for LogicalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VLESS 写端已关闭",
            )));
        }
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.closed = true;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}

pub(crate) async fn open(
    mut stream: BoxedTransportStream,
    encryption: Option<&Client>,
    user: UserId,
    target: &Destination,
    vision: bool,
    udp: bool,
    encoding: PacketEncoding,
) -> Result<BoxStream> {
    if let Some(client) = encryption {
        stream.release_record_alignment();
        stream = Box::new(EncryptionCarrier {
            inner: client.connect(stream).await?,
        });
    }
    let mut destination = carrier::target(target, udp);
    if udp && encoding == PacketEncoding::Packetaddr {
        destination = carrier::target(&Destination::new("sp.packet-addr.v2fly.arpa", 1)?, true);
    }
    let request = VlessRequest {
        user_id: uuid::Uuid::from_bytes(*user.as_bytes()),
        command: if udp {
            if encoding == PacketEncoding::Xudp {
                VlessCommand::Mux
            } else {
                VlessCommand::Udp
            }
        } else {
            VlessCommand::Tcp
        },
        target: destination,
        flow: vision.then(|| "xtls-rprx-vision".into()),
    };
    let bytes =
        encode_request_header(&request).map_err(|_| Error::Protocol("VLESS 请求头编码失败"))?;
    stream.write_all(&bytes).await?;
    let inner: BoxStream = if vision {
        let response = VlessResponseStream::new(crate::vision_io::VisionCarrier::new(stream,user,true));
        let mut stream = VisionStream::new(response, *user.as_bytes(), xray_proxy::vless::DEFAULT_VISION_SEED);
        if !udp {
            stream.queue_empty_padding_frame()?;
        }
        stream.flush().await?;
        Box::new(stream)
    } else {
        stream.release_record_alignment();
        stream.flush().await?;
        Box::new(crate::VlessStream::new(stream))
    };
    Ok(Box::new(LogicalStream {
        inner,
        closed: false,
    }))
}

struct Sender {
    writer: WriteHalf<BoxStream>,
    target: Destination,
    encoding: PacketEncoding,
    first: bool,
    global_id: [u8; 8],
}
struct Receiver {
    reader: BufReader<ReadHalf<BoxStream>>,
    encoding: PacketEncoding,
}
pub(crate) fn datagrams(
    stream: BoxStream,
    target: &Destination,
    encoding: PacketEncoding,
) -> Result<DatagramChannel> {
    if encoding == PacketEncoding::Packetaddr
        && !matches!(target.address(), kerlico_core::Address::Ip(_))
    {
        return Err(Error::Unsupported("packetaddr 域名目标"));
    }
    let (reader, writer) = tokio::io::split(stream);
    Ok(DatagramChannel {
        sender: Box::new(Sender {
            writer,
            target: target.clone(),
            encoding,
            first: true,
            global_id: rand::random(),
        }),
        receiver: Box::new(Receiver {
            reader: BufReader::new(reader),
            encoding,
        }),
    })
}
impl DatagramSender for Sender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            match self.encoding {
                PacketEncoding::Udp => codec::write_datagram(&mut self.writer, packet).await?,
                PacketEncoding::Xudp => {
                    let bytes = if self.first {
                        encode_xudp_new_packet(
                            &carrier::target(&self.target, true),
                            packet,
                            self.global_id,
                        )
                    } else {
                        encode_xudp_keep_packet(None, packet)
                    }
                    .map_err(|_| Error::ResourceLimit)?;
                    self.writer.write_all(&bytes).await?;
                    self.writer.flush().await?;
                    self.first = false;
                }
                PacketEncoding::Packetaddr => {
                    let mut bytes = Vec::with_capacity(packet.len() + 20);
                    match self.target.address() {
                        kerlico_core::Address::Ip(std::net::IpAddr::V4(ip)) => {
                            bytes.push(1);
                            bytes.extend_from_slice(&ip.octets());
                        }
                        kerlico_core::Address::Ip(std::net::IpAddr::V6(ip)) => {
                            bytes.push(2);
                            bytes.extend_from_slice(&ip.octets());
                        }
                        _ => return Err(Error::InvalidAddress),
                    }
                    bytes.extend_from_slice(&self.target.port().to_be_bytes());
                    bytes.extend_from_slice(packet);
                    codec::write_datagram(&mut self.writer, &bytes).await?;
                }
            }
            Ok(())
        })
    }
}
impl DatagramReceiver for Receiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.reader.fill_buf().await?.is_empty() {
                return Ok(None);
            }
            if self.encoding == PacketEncoding::Xudp {
                return Ok(Some(
                    read_xudp_packet(&mut self.reader).await?.payload.to_vec(),
                ));
            }
            let Some(mut bytes) =
                codec::read_datagram(&mut self.reader, codec::MAX_DATAGRAM_SIZE).await?
            else {
                return Ok(None);
            };
            if self.encoding == PacketEncoding::Packetaddr {
                let header = match bytes.first() {
                    Some(1) => 7,
                    Some(2) => 19,
                    _ => return Err(Error::Protocol("packetaddr 地址类型不合法")),
                };
                if bytes.len() < header {
                    return Err(Error::Protocol("packetaddr 地址被截断"));
                }
                bytes.drain(..header);
            }
            Ok(Some(bytes))
        })
    }
}
