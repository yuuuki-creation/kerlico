use crate::{
    config::{ClientOptions, Prepared},
    invalid,
    tunnel::{self, Routes, Tunnel},
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, Capabilities, ConnectContext, DatagramAssociation, DatagramAssociationSender,
    DatagramChannel, Destination, Error, OpenedTcp, Outbound, ResourceKey, Result, ServiceContext,
    TargetPolicy,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: true,
    udp: true,
};
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;

/// 只接收共享调度器已解析 IP 的 CONNECT-IP 命名出站工厂。
pub struct MasqueFactory;
impl OutboundFactory for MasqueFactory {
    fn kind(&self) -> &'static str {
        "masque"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: ClientOptions =
            serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        let prepared = options.prepare()?;
        Ok(OutboundPlan::new(
            CAPABILITIES,
            true,
            TargetPolicy::Local,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(MasqueOutbound {
                        prepared,
                        host,
                        tunnels: Mutex::new(HashMap::new()),
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}

/// 同一作用域的并发建立在槽内串行，只产生一条隧道。
type Slot = Arc<Mutex<Option<Arc<Tunnel>>>>;
struct MasqueOutbound {
    prepared: Prepared,
    host: ServiceContext,
    tunnels: Mutex<HashMap<ResourceKey, Slot>>,
}
impl MasqueOutbound {
    fn slot(&self, tunnels: &mut HashMap<ResourceKey, Slot>, key: &ResourceKey) -> Result<Slot> {
        tunnels.retain(|_, slot| {
            Arc::strong_count(slot) > 1
                || slot
                    .try_lock()
                    .is_ok_and(|tunnel| tunnel.as_ref().is_some_and(|tunnel| tunnel.alive()))
        });
        if !tunnels.contains_key(key) && tunnels.len() >= self.prepared.max_tunnels {
            return Err(Error::ResourceLimit);
        }
        Ok(tunnels.entry(key.clone()).or_default().clone())
    }
    async fn tunnel(&self, context: &ConnectContext) -> Result<Arc<Tunnel>> {
        context
            .run(async {
                let slot = {
                    let mut tunnels = self.tunnels.lock().await;
                    self.slot(&mut tunnels, context.resource_key())?
                };
                let mut current = slot.lock().await;
                if let Some(tunnel) = current.as_ref().filter(|tunnel| tunnel.alive()) {
                    return Ok(tunnel.clone());
                }
                let tunnel = tunnel::establish(&self.prepared, &self.host).await?;
                *current = Some(tunnel.clone());
                Ok(tunnel)
            })
            .await
    }
}
struct RoutedSender {
    inner: Box<dyn DatagramAssociationSender>,
    routes: Routes,
}
impl DatagramAssociationSender for RoutedSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.routes.check(target, IP_PROTOCOL_UDP)?;
            self.inner.send_to(packet, target).await
        })
    }
}
impl Outbound for MasqueOutbound {
    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.host.cancel().cancel();
            self.tunnels.lock().await.clear();
            Ok(())
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            let tunnel = self.tunnel(context).await?;
            tunnel.routes.check(target, IP_PROTOCOL_TCP)?;
            tunnel.lease().connect_tcp(target, context).await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let tunnel = self.tunnel(context).await?;
            tunnel.routes.check(target, IP_PROTOCOL_UDP)?;
            tunnel.lease().connect_udp(target, context)
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            let tunnel = self.tunnel(context).await?;
            let mut channel = tunnel.lease().associate_udp(context)?;
            channel.sender = Box::new(RoutedSender {
                inner: channel.sender,
                routes: tunnel.routes.clone(),
            });
            Ok(channel)
        })
    }
}
