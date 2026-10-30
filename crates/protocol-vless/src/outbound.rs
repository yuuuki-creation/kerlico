use crate::{
    UserId, VlessStream,
    codec::{self, Command, RequestHeader},
};
use kerlico_config::{OutboundFactory, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Outbound, Result,
};
use kerlico_net::TcpConnector;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};

pub struct VlessOutbound {
    server: Destination,
    user: UserId,
    connector: TcpConnector,
}

impl VlessOutbound {
    pub fn new(server: Destination, user: UserId, connector: TcpConnector) -> Result<Self> {
        if !connector.is_tls() && !server.is_loopback() {
            return Err(Error::Config(
                "无传输安全的 VLESS 只允许回环测试地址".into(),
            ));
        }
        Ok(Self {
            server,
            user,
            connector,
        })
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
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async { Ok(Box::new(self.open(target, Command::Tcp).await?) as BoxStream) })
                .await
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    server: TargetSpec,
    uuid: String,
    #[serde(default = "tcp")]
    transport: String,
    #[serde(default)]
    flow: String,
    #[serde(default = "none")]
    encryption: String,
    #[serde(default)]
    security: Security,
}
fn tcp() -> String {
    "tcp".into()
}
fn none() -> String {
    "none".into()
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Security {
    Tls {
        #[serde(default)]
        server_name: Option<String>,
        #[serde(default)]
        ca_pem: Option<String>,
    },
    None,
}
impl Default for Security {
    fn default() -> Self {
        Self::Tls {
            server_name: None,
            ca_pem: None,
        }
    }
}

impl OutboundFactory for VlessFactory {
    fn kind(&self) -> &'static str {
        "vless"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("VLESS 配置字段不合法".into()))?;
        if options.transport != "tcp" {
            return Err(Error::Unsupported("VLESS 仅实现 tcp 传输"));
        }
        if !options.flow.is_empty() {
            return Err(Error::Unsupported("VLESS flow"));
        }
        if options.encryption != "none" {
            return Err(Error::Unsupported("VLESS Encryption"));
        }
        let server = options.server.destination()?;
        let user = UserId::parse(&options.uuid)?;
        let connector = match options.security {
            Security::Tls {
                server_name,
                ca_pem,
            } => TcpConnector::tls(
                server_name.as_deref().unwrap_or(&server.host()),
                ca_pem.as_deref(),
            )?,
            Security::None => {
                if !server.is_loopback() {
                    return Err(Error::Config(
                        "无传输安全的 VLESS 只允许回环测试地址".into(),
                    ));
                }
                TcpConnector::plain()
            }
        };
        Ok(Arc::new(VlessOutbound::new(server, user, connector)?))
    }
}
