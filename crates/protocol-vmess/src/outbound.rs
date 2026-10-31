//! VMess 客户端工厂和流/包适配。
use crate::{
    carrier::{Client, ClientSecurity, Transport},
    codec::{self, Account, RecordOptions},
    crypto::{Cipher, MAX_DATAGRAM},
};
use kerlico_config::{OutboundFactory, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Outbound, Result,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    server: TargetSpec,
    uuid: String,
    #[serde(default = "auto")]
    security: String,
    #[serde(default)]
    tls: ClientSecurity,
    #[serde(default)]
    transport: Transport,
    #[serde(default)]
    authenticated_length: bool,
    #[serde(default = "yes")]
    chunk_masking: bool,
    #[serde(default = "yes")]
    global_padding: bool,
    #[serde(default)]
    no_termination_signal: bool,
}
fn auto() -> String {
    "auto".into()
}
fn yes() -> bool {
    true
}
fn invalid() -> Error {
    Error::Config("VMess 客户端配置不合法".into())
}
pub struct VmessFactory;
struct VmessOutbound {
    carrier: Client,
    account: Account,
    options: RecordOptions,
}
impl OutboundFactory for VmessFactory {
    fn kind(&self) -> &'static str {
        "vmess"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn Outbound>> {
        let options: Options = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        if options.global_padding && !options.chunk_masking {
            return Err(invalid());
        }
        let id = *uuid::Uuid::parse_str(&options.uuid)
            .map_err(|_| invalid())?
            .as_bytes();
        let cipher = Cipher::parse(&options.security).map_err(|_| invalid())?;
        let flags = 1
            | if options.chunk_masking { 4 } else { 0 }
            | if options.global_padding { 8 } else { 0 }
            | if options.authenticated_length { 16 } else { 0 };
        Ok(Arc::new(VmessOutbound {
            carrier: Client::build(
                options.server.destination()?,
                options.tls,
                options.transport,
            )?,
            account: Account::new(id),
            options: RecordOptions {
                cipher,
                flags,
                termination: !options.no_termination_signal,
            },
        }))
    }
}
impl VmessOutbound {
    async fn open(
        &self,
        target: &Destination,
        udp: bool,
        context: &ConnectContext,
    ) -> Result<BoxStream> {
        context
            .run(async {
                let inner = self.carrier.open().await?;
                let stream =
                    codec::connect(inner, &self.account, target, udp, self.options).await?;
                Ok(Box::new(stream) as BoxStream)
            })
            .await
    }
}
impl Outbound for VmessOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: self.options.termination,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(self.open(target, false, context))
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let inner = self.open(target, true, context).await?;
            let (reader, writer) = tokio::io::split(inner);
            Ok(DatagramChannel {
                sender: Box::new(Sender {
                    writer,
                    failed: false,
                }),
                receiver: Box::new(Receiver { reader }),
            })
        })
    }
}
struct Sender {
    writer: WriteHalf<BoxStream>,
    failed: bool,
}
struct Receiver {
    reader: ReadHalf<BoxStream>,
}
impl DatagramSender for Sender {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if bytes.is_empty() || bytes.len() > MAX_DATAGRAM {
                return Err(Error::Unsupported(
                    "VMess UDP 要求非空包且不超过 65456 字节",
                ));
            }
            if self.failed {
                return Err(Error::Protocol("VMess UDP 写端已失效"));
            }
            self.failed = true;
            self.writer.write_all(bytes).await?;
            self.writer.flush().await?;
            self.failed = false;
            Ok(())
        })
    }
}
impl DatagramReceiver for Receiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 65535];
            let n = self.reader.read(&mut bytes).await?;
            if n == 0 {
                return Ok(None);
            }
            bytes.truncate(n);
            Ok(Some(bytes))
        })
    }
}
