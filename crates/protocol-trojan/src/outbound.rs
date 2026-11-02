use crate::{
    carrier::Carrier,
    codec,
    config::{ClientSecurity, TransportInput},
    invalid, key,
};
use kerlico_config::{OutboundFactory, OutboundPlan, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Outbound,
    Result,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

pub struct TrojanFactory;
struct TrojanOutbound {
    carrier: Carrier,
    key: [u8; 56],
    tcp_eof: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    server: TargetSpec,
    password: String,
    #[serde(default)]
    transport: TransportInput,
    #[serde(default)]
    security: ClientSecurity,
}
impl OutboundFactory for TrojanFactory {
    fn kind(&self) -> &'static str {
        "trojan"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        let key = key(&options.password)?;
        let transport = options.transport.normalize()?;
        let tcp_eof = !matches!(transport, crate::config::Transport::Ws { .. });
        let carrier = Carrier::build(options.server.destination()?, options.security, transport)?;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof,
                udp: true,
            },
            false,
            kerlico_core::TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(TrojanOutbound {
                        carrier: carrier.start(&host)?,
                        key,
                        tcp_eof,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}
impl Outbound for TrojanOutbound {
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.carrier.shutdown().await })
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: self.tcp_eof,
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
                        let mut stream = self.carrier.open(context).await?;
                        codec::write_request(&mut stream, &self.key, target, false).await?;
                        Ok(stream)
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
                    let mut stream = self.carrier.open(context).await?;
                    codec::write_request(&mut stream, &self.key, target, true).await?;
                    Ok(crate::udp::channel(stream, target.clone()))
                })
                .await
        })
    }
}
