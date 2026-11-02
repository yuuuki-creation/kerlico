use crate::{
    UserId, VlessStream,
    codec::{self, Command, RequestHeader},
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Outbound, Result,
};
use kerlico_net::TcpConnector;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};

pub struct VlessOutbound {
    server: Destination,
    user: UserId,
    connector: TcpConnector,
}

impl VlessOutbound {
    pub fn compile(
        server: Destination,
        user: UserId,
        connector: TcpConnector,
    ) -> Result<OutboundPlan> {
        if !connector.is_tls() && !server.is_loopback() {
            return Err(Error::Config(
                "无传输安全的 VLESS 只允许回环测试地址".into(),
            ));
        }
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: false,
                udp: true,
            },
            false,
            kerlico_core::TargetPolicy::Remote,
            move |_host| {
                Box::pin(async move {
                    Ok(Arc::new(Self {
                        server,
                        user,
                        connector,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
    async fn open(&self, target: &Destination, command: Command) -> Result<VlessStream<BoxStream>> {
        let mut stream = self.connector.connect(&self.server).await?;
        codec::write_request(
            &mut stream,
            &RequestHeader {
                user: self.user,
                command,
                target: target.clone(),
            },
        )
        .await?;
        stream.flush().await?;
        Ok(VlessStream::new(stream))
    }
}

struct PacketSender(WriteHalf<VlessStream<BoxStream>>);
struct PacketReceiver(ReadHalf<VlessStream<BoxStream>>);

impl DatagramSender for PacketSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { codec::write_datagram(&mut self.0, packet).await })
    }
}
impl DatagramReceiver for PacketReceiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move { codec::read_datagram(&mut self.0, codec::MAX_DATAGRAM_SIZE).await })
    }
}

impl Outbound for VlessOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            let opening: kerlico_core::BoxFuture<'_, Result<BoxStream>> = Box::pin(async move {
                context
                    .run(async {
                        Ok(Box::new(self.open(target, Command::Tcp).await?) as BoxStream)
                    })
                    .await
            });
            let stream = opening.await?;
            Ok(kerlico_core::OpenedTcp {
                stream,
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            context
                .run(async {
                    let stream = self.open(target, Command::Udp).await?;
                    let (reader, writer) = tokio::io::split(stream);
                    Ok(DatagramChannel {
                        sender: Box::new(PacketSender(writer)),
                        receiver: Box::new(PacketReceiver(reader)),
                    })
                })
                .await
        })
    }
}

pub struct VlessFactory;

impl OutboundFactory for VlessFactory {
    fn kind(&self) -> &'static str {
        "vless"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        crate::profile::compile(options)
    }
}
