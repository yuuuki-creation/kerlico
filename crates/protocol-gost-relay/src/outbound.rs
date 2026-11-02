use crate::{
    config::{Config, Options, ResponseMode},
    io::Cancellable,
    response::DeferredResponse,
    smux::SingleStream,
    udp, wire,
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub struct GostRelayFactory;
struct Relay(Config);
impl OutboundFactory for GostRelayFactory {
    fn kind(&self) -> &'static str {
        "gost-relay"
    }
    fn compile(&self, value: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(value.clone())
            .map_err(|_| Error::Config("Gost Relay 出站字段不合法".into()))?;
        let prepared = options.prepare()?;
        let tcp_eof = !prepared.mux && !prepared.connector.is_tls();
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof,
                udp: true,
            },
            false,
            kerlico_core::TargetPolicy::Remote,
            move |_host| {
                Box::pin(async move { Ok(Arc::new(Relay(prepared)) as Arc<dyn Outbound>) })
            },
        ))
    }
}
impl Relay {
    async fn open(
        &self,
        target: &Destination,
        context: &ConnectContext,
        is_udp: bool,
    ) -> Result<BoxStream> {
        if self
            .0
            .forward
            .as_ref()
            .is_some_and(|expected| expected != target)
        {
            return Err(Error::Unsupported("请求目标与已知固定转发目标不同"));
        }
        let started = tokio::time::Instant::now();
        context
            .run(async {
                let raw = self.0.connector.connect(&self.0.server).await?;
                let cancel = context.cancel.child_token();
                let mut stream: BoxStream = Box::new(Cancellable::new(raw, &cancel));
                if self.0.mux {
                    stream = Box::new(SingleStream::open(stream).await?);
                }
                stream
                    .write_all(&wire::request(
                        if self.0.forward.is_some() {
                            None
                        } else {
                            Some(target)
                        },
                        &self.0.username,
                        &self.0.password,
                        is_udp,
                    ))
                    .await?;
                stream.flush().await?;
                if self.0.response_mode == ResponseMode::Eager {
                    wire::response(&mut stream).await?;
                } else {
                    stream = Box::new(DeferredResponse::new(
                        stream,
                        cancel,
                        context.timeout.saturating_sub(started.elapsed()),
                    ));
                }
                Ok(stream)
            })
            .await
    }
}
impl Outbound for Relay {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: !self.0.mux && !self.0.connector.is_tls(),
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            self.open(target, context, false)
                .await
                .map(|stream| kerlico_core::OpenedTcp {
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
            Ok(udp::channel(
                self.open(target, context, true).await?,
                target.clone(),
                &context.cancel,
            ))
        })
    }
}
