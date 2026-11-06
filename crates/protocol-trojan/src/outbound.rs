use crate::{
    carrier::Carrier,
    codec,
    config::{ClientSecurity, TransportInput},
    invalid, key,
};
use kerlico_config::{OutboundFactory, OutboundPlan, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Error, Outbound, Result,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

pub struct TrojanFactory;
struct TrojanOutbound {
    carrier: Carrier,
    key: [u8; 56],
    tcp_eof: bool,
    mux: Option<Arc<kerlico_net::sing_mux::SingMuxClient>>,
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
    #[serde(default)]
    multiplex: Option<kerlico_net::sing_mux::SingMuxOutboundConfig>,
}
impl OutboundFactory for TrojanFactory {
    fn kind(&self) -> &'static str {
        "trojan"
    }
    fn supports_detour(&self) -> bool {
        true
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        let key = key(&options.password)?;
        if let Some(mux) = &options.multiplex {
            mux.validate()?;
        }
        let mux = options
            .multiplex
            .filter(|m| m.enabled)
            .map(|cfg| Arc::new(kerlico_net::sing_mux::SingMuxClient::new(cfg)));
        let has_assoc = mux.as_ref().is_some_and(|m| m.handles_udp());
        let transport = options.transport.normalize()?;
        let tcp_eof = !matches!(transport, crate::config::Transport::Ws { .. });
        let carrier = Carrier::build(options.server.destination()?, options.security, transport)?;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof,
                udp: true,
            },
            has_assoc,
            kerlico_core::TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(TrojanOutbound {
                        carrier: carrier.start(&host)?,
                        key,
                        tcp_eof,
                        mux,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}
impl TrojanOutbound {
    async fn open_trojan_tcp(
        &self,
        target: &Destination,
        context: &ConnectContext,
    ) -> Result<BoxStream> {
        let mut stream = self.carrier.open(context).await?;
        codec::write_request(&mut stream, &self.key, target, false).await?;
        Ok(stream)
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
    fn supports_udp_association(&self) -> bool {
        self.mux.as_ref().is_some_and(|m| m.handles_udp())
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            context
                .run(async {
                    if let Some(mux) = &self.mux
                        && mux.handles_tcp()
                    {
                        return mux
                            .connect_tcp(target, |magic| async move {
                                self.open_trojan_tcp(&magic, context).await
                            })
                            .await;
                    }
                    let stream = self.open_trojan_tcp(target, context).await?;
                    Ok(kerlico_core::OpenedTcp {
                        stream,
                        info: kerlico_core::TcpConnectInfo::unknown(),
                    })
                })
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
                    if let Some(mux) = &self.mux
                        && mux.handles_udp()
                    {
                        return mux
                            .connect_udp(target, |magic| async move {
                                self.open_trojan_tcp(&magic, context).await
                            })
                            .await;
                    }
                    let mut stream = self.carrier.open(context).await?;
                    codec::write_request(&mut stream, &self.key, target, true).await?;
                    Ok(crate::udp::channel(stream, target.clone()))
                })
                .await
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            if let Some(mux) = &self.mux
                && mux.handles_udp()
            {
                return context
                    .run(mux.associate_udp(|magic| async move {
                        self.open_trojan_tcp(&magic, context).await
                    }))
                    .await;
            }
            Err(Error::Unsupported("Trojan 未启用多路复用 UDP 关联"))
        })
    }
}
