use crate::{
    config::{Options, Prepared},
    control::{Control, LocalState},
    dataplane::Dataplane,
    keys::{DiscoKey, Identity, Secret},
    netmap::{NetMap, Routes},
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    Address, BoxFuture, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Error, OpenedTcp, Outbound, Result, ServiceContext, ServiceFailure, ServiceStatus,
    TargetPolicy,
};
use kerlico_wireguard::ip::{ClientTunnel, StackLimits, StackOptions};
use serde_json::Value;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::{net::UdpSocket, sync::watch, time::timeout};

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: true,
    udp: true,
};
const TAILSCALE_MTU: usize = 1280;

/// 以 pre-auth key 加入 tailnet 的原生客户端出站工厂。
pub struct TailscaleFactory;

impl OutboundFactory for TailscaleFactory {
    fn kind(&self) -> &'static str {
        "tailscale"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Tailscale出站字段不合法".into()))?;
        let prepared = options.prepare()?;
        Ok(OutboundPlan::new(
            CAPABILITIES,
            true,
            TargetPolicy::Local,
            move |host| Box::pin(start(prepared, host)),
        ))
    }
}

struct TailscaleOutbound {
    tunnel: ClientTunnel,
    routes: watch::Receiver<Routes>,
    status: ServiceStatus,
}
impl TailscaleOutbound {
    fn check(&self) -> Result<()> {
        match self.status.failure() {
            Some(failure) => Err(failure.error()),
            None => Ok(()),
        }
    }
    fn routable(&self, remote: &Destination) -> Result<()> {
        self.check()?;
        let Address::Ip(ip) = remote.address() else {
            return Err(Error::InvalidAddress);
        };
        if self.routes.borrow().lookup(ip.to_canonical()).is_none() {
            return Err(Error::Rejected);
        }
        Ok(())
    }
}
impl Outbound for TailscaleOutbound {
    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.tunnel.close();
            self.check()
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        remote: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            self.routable(remote)?;
            self.tunnel.connect_tcp(remote, context).await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        remote: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            self.routable(remote)?;
            self.tunnel.connect_udp(remote, context)
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            self.check()?;
            self.tunnel.associate_udp(context)
        })
    }
}

async fn start(prepared: Prepared, host: ServiceContext) -> Result<Arc<dyn Outbound>> {
    let identity = Identity::load(prepared.state_file.as_deref())?;
    let disco = Secret::generate();
    let (netmap_sender, mut netmap) = watch::channel(None);
    let (local_sender, local) = watch::channel(LocalState::default());
    host.spawn(
        Control {
            prepared: prepared.clone(),
            identity: identity.clone(),
            disco: DiscoKey(disco.public()),
            netmap: netmap_sender,
            local,
            host: host.clone(),
        }
        .run(),
    )?;
    let cancel = host.cancel();
    let first = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(Error::Cancelled),
        first = timeout(prepared.start_timeout, first_netmap(&mut netmap)) => first,
    };
    let map = match first {
        Ok(Some(map)) => map,
        Ok(None) => {
            return Err(host
                .failure()
                .map_or(Error::Cancelled, |failure| failure.error()));
        }
        Err(_) => return Err(Error::Timeout),
    };
    let addresses = map.own_addresses();
    let tunnel = ClientTunnel::new(
        StackOptions {
            addresses: addresses.clone(),
            allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
            mtu: TAILSCALE_MTU,
            limits: StackLimits::default(),
        },
        cancel,
    )?;
    let (udp4, udp6) = if prepared.direct {
        (
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok(),
            UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await.ok(),
        )
    } else {
        (None, None)
    };
    let (routes_sender, routes) = watch::channel(map.routes(&prepared.routes));
    let dataplane = Dataplane {
        prepared,
        node: identity.node,
        disco,
        tunnel: tunnel.clone(),
        host: host.clone(),
        udp4,
        udp6,
        netmap,
        local: local_sender,
        routes: routes_sender,
        addresses,
    };
    let runtime_host = host.clone();
    let runtime_tunnel = tunnel.clone();
    host.spawn(async move {
        if let Err(error) = dataplane.run().await
            && !matches!(error, Error::Cancelled)
        {
            runtime_host.fail(runtime_failure(error));
        }
        runtime_tunnel.close();
    })?;
    Ok(Arc::new(TailscaleOutbound {
        tunnel,
        routes,
        status: host.status(),
    }))
}

/// 通道关闭表示控制任务已因不可重试的错误结束。
async fn first_netmap(netmap: &mut watch::Receiver<Option<Arc<NetMap>>>) -> Option<Arc<NetMap>> {
    loop {
        if let Some(map) = netmap.borrow_and_update().clone()
            && !map.own_addresses().is_empty()
        {
            return Some(map);
        }
        netmap.changed().await.ok()?;
    }
}

fn runtime_failure(error: Error) -> ServiceFailure {
    match error {
        Error::Protocol(message) | Error::Unsupported(message) => ServiceFailure::Protocol(message),
        Error::Timeout => ServiceFailure::Timeout,
        Error::Io(error) => ServiceFailure::Io(error.kind(), "Tailscale载体运行失败"),
        _ => ServiceFailure::Protocol("Tailscale出站运行失败"),
    }
}
