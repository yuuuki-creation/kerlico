use crate::{
    config::{ClientOptions, Prepared, TUNNEL_MTU},
    invalid,
};
use cidr::{Ipv4Inet, Ipv6Inet};
use easytier::{
    common::{config::TomlConfigLoader, global_ctx::GlobalCtx, stun::MockStunInfoCollector},
    connector::manual::ManualConnectorManager,
    peers::{
        PacketRecvChanReceiver, create_packet_recv_chan,
        peer_manager::{PeerManager, RouteAlgoType},
    },
    proto::common::NatType,
    tunnel::packet_def::ZCPacket,
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    Address, BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, OpenedTcp, Outbound, Result, ServiceContext, TargetPolicy,
};
use kerlico_wireguard::ip::{ClientTunnel, StackLimits, StackOptions};
use serde_json::Value;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: true,
    udp: true,
};
const ROUTE_POLL: Duration = Duration::from_millis(100);
const DHCP_WAIT_FOR_PEER: Duration = Duration::from_secs(1);
const DHCP_RECHECK: Duration = Duration::from_secs(5);
/// 上游 DHCP 在网络内还没有任何地址时使用的默认网段。
const DHCP_DEFAULT_NETWORK: Ipv4Addr = Ipv4Addr::new(10, 126, 126, 0);

/// 只接收共享调度器已解析 IP 的 EasyTier 命名出站工厂。
pub struct EasyTierFactory;
impl OutboundFactory for EasyTierFactory {
    fn kind(&self) -> &'static str {
        "easytier"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: ClientOptions =
            serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        let prepared = options.prepare()?;
        Ok(OutboundPlan::new(
            CAPABILITIES,
            true,
            TargetPolicy::Local,
            move |host| Box::pin(start(prepared, host)),
        ))
    }
}

/// 清空上游的 STUN 服务器配置后节点仍会探测公共服务器，只有替换采集器才能停掉。
/// 本节点不打洞也不监听，采集器返回的地址没有使用方。
pub(crate) fn node_context(config: TomlConfigLoader) -> Arc<GlobalCtx> {
    let global = Arc::new(GlobalCtx::new(config));
    global.replace_stun_info_collector(Box::new(MockStunInfoCollector {
        udp_nat_type: NatType::Unknown,
    }));
    global
}

pub(crate) async fn start(prepared: Prepared, host: ServiceContext) -> Result<Arc<dyn Outbound>> {
    let global = node_context(prepared.node_config());
    let (nic_sender, nic) = create_packet_recv_chan();
    let node = Arc::new(PeerManager::new(
        RouteAlgoType::Ospf,
        global.clone(),
        nic_sender,
    ));
    node.run()
        .await
        .map_err(|_| Error::Protocol("EasyTier节点启动失败"))?;
    let connectors = ManualConnectorManager::new(global, node.clone());
    for peer in &prepared.peers {
        connectors
            .add_connector_by_url(peer.clone())
            .await
            .map_err(|_| invalid())?;
    }

    let (tunnel_sender, tunnel) = watch::channel(None);
    let cancel = host.cancel();
    host.spawn(receive_packets(nic, tunnel.clone(), cancel.clone()))?;
    host.spawn(maintain_address(
        prepared.ipv4,
        prepared.ipv6,
        node.clone(),
        tunnel_sender,
        host.clone(),
    ))?;
    let cleanup_node = node.clone();
    host.spawn(async move {
        cancel.cancelled().await;
        connectors.clear_connectors().await;
        drop(connectors);
        close_node(&cleanup_node).await;
    })?;
    Ok(Arc::new(EasyTierOutbound { node, tunnel, host }))
}

async fn close_node(node: &PeerManager) {
    node.clear_resources().await;
    let peers = node.get_peer_map();
    for peer in peers.list_peers_with_conn().await {
        let _ = peers.close_peer(peer).await;
    }
}

struct EasyTierOutbound {
    node: Arc<PeerManager>,
    tunnel: watch::Receiver<Option<ClientTunnel>>,
    host: ServiceContext,
}
impl Drop for EasyTierOutbound {
    fn drop(&mut self) {
        self.host.cancel().cancel();
    }
}
impl EasyTierOutbound {
    /// 等到本机有地址、且网络内已有目标的路由；两者都来自异步的路由同步。
    async fn ready(&self, target: Option<&Destination>) -> Result<ClientTunnel> {
        self.host.check()?;
        let mut tunnel = self.tunnel.clone();
        let tunnel = tunnel
            .wait_for(Option::is_some)
            .await
            .map_err(|_| Error::Cancelled)?
            .clone()
            .ok_or(Error::Cancelled)?;
        if let Some(Address::Ip(ip)) = target.map(Destination::address) {
            while self.node.get_msg_dst_peer(ip).await.0.is_empty() {
                tokio::time::sleep(ROUTE_POLL).await;
            }
        }
        Ok(tunnel)
    }
}
impl Outbound for EasyTierOutbound {
    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.host.cancel().cancel();
            Ok(())
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        remote: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            let tunnel = context.run(self.ready(Some(remote))).await?;
            tunnel.connect_tcp(remote, context).await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        remote: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let tunnel = context.run(self.ready(Some(remote))).await?;
            tunnel.connect_udp(remote, context)
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            let tunnel = context.run(self.ready(None)).await?;
            tunnel.associate_udp(context)
        })
    }
}

async fn receive_packets(
    mut nic: PacketRecvChanReceiver,
    tunnel: watch::Receiver<Option<ClientTunnel>>,
    cancel: CancellationToken,
) {
    loop {
        let packet = tokio::select! { biased;
            _ = cancel.cancelled() => return,
            packet = nic.recv() => packet,
        };
        let Some(packet) = packet else { return };
        if let Some(tunnel) = &*tunnel.borrow() {
            // 目标不是本机地址或协议不受支持的包按普通网卡语义丢弃。
            let _ = tunnel.receive(packet.payload());
        }
    }
}

async fn send_packets(tunnel: ClientTunnel, node: Arc<PeerManager>) {
    while let Ok(packet) = tunnel.next_packet().await {
        if let Some(target) = packet_target(&packet) {
            let _ = node
                .send_msg_by_ip(ZCPacket::new_with_payload(&packet), target, true)
                .await;
        }
    }
}

pub(crate) fn packet_target(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => {
            let target: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some(IpAddr::V4(target.into()))
        }
        6 => {
            let target: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(target)))
        }
        _ => None,
    }
}

/// 静态地址发布一次；DHCP 地址跟随路由变化，换地址时旧隧道与其上的流一起结束，与上游重建网卡相同。
async fn maintain_address(
    ipv4: Option<Ipv4Inet>,
    ipv6: Option<Ipv6Inet>,
    node: Arc<PeerManager>,
    tunnel: watch::Sender<Option<ClientTunnel>>,
    host: ServiceContext,
) {
    let cancel = host.cancel();
    if ipv4.is_some() {
        if let Err(error) = publish(ipv4, ipv6, &node, &tunnel, &host) {
            host.fail(failure(error));
        }
        return cancel.cancelled().await;
    }
    let mut current = None;
    loop {
        let routes = node.list_routes().await;
        let used: HashSet<Ipv4Inet> = routes
            .iter()
            .filter_map(|route| route.ipv4_addr.map(Into::into))
            .collect();
        let wait = if routes.is_empty() {
            DHCP_WAIT_FOR_PEER
        } else {
            let selected = select_dhcp_address(&used, current);
            if selected != current {
                current = selected;
                node.get_global_ctx().set_ipv4(current);
                if let Err(error) = publish(current, ipv6, &node, &tunnel, &host) {
                    host.fail(failure(error));
                    return;
                }
            }
            DHCP_RECHECK
        };
        tokio::select! { biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

fn failure(error: Error) -> kerlico_core::ServiceFailure {
    match error {
        Error::Protocol(message) | Error::Unsupported(message) => {
            kerlico_core::ServiceFailure::Protocol(message)
        }
        Error::ResourceLimit => kerlico_core::ServiceFailure::ResourceLimit,
        _ => kerlico_core::ServiceFailure::Protocol("EasyTier节点启动失败"),
    }
}

fn publish(
    ipv4: Option<Ipv4Inet>,
    ipv6: Option<Ipv6Inet>,
    node: &Arc<PeerManager>,
    sender: &watch::Sender<Option<ClientTunnel>>,
    host: &ServiceContext,
) -> Result<()> {
    let mut addresses = Vec::new();
    let mut allowed_ips = Vec::new();
    if let Some(ipv4) = ipv4 {
        addresses.push(IpAddr::V4(ipv4.address()));
        allowed_ips.push("0.0.0.0/0".to_owned());
    }
    if let Some(ipv6) = ipv6 {
        addresses.push(IpAddr::V6(ipv6.address()));
        allowed_ips.push("::/0".to_owned());
    }
    if addresses.is_empty() {
        // 网段已满时没有可用地址，新流等到超时，下次复查再分配。
        if let Some(old) = sender.send_replace(None) {
            old.close();
        }
        return Ok(());
    }
    let tunnel = ClientTunnel::new(
        StackOptions {
            addresses,
            allowed_ips,
            mtu: TUNNEL_MTU,
            limits: StackLimits::default(),
        },
        host.cancel(),
    )?;
    host.spawn(send_packets(tunnel.clone(), node.clone()))?;
    if let Some(old) = sender.send_replace(Some(tunnel)) {
        old.close();
    }
    Ok(())
}

/// 上游 `--dhcp` 的选址规则：取已用地址所在网段内第一个空闲主机地址，当前地址仍可用时不变。
pub(crate) fn select_dhcp_address(
    used: &HashSet<Ipv4Inet>,
    current: Option<Ipv4Inet>,
) -> Option<Ipv4Inet> {
    let default = Ipv4Inet::new(DHCP_DEFAULT_NETWORK, 24).expect("固定前缀合法");
    let base = used.iter().min().unwrap_or(&default);
    if let Some(ip) = current
        && ip.network() == base.network()
        && !used.contains(&ip)
    {
        return current;
    }
    base.network().iter().find(|ip| {
        ip.address() != base.first_address()
            && ip.address() != base.last_address()
            && !used.contains(ip)
    })
}
