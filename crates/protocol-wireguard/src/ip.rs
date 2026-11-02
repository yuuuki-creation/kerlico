//! 与加密载体分离的用户态 IP 数据面。调用方负责握手、身份、分配地址及载体生命周期。

pub use crate::config::Limits as StackLimits;
use crate::{
    config::{Addresses, Network, target},
    packet::{FragmentBudget, IpPacket, Reassembler, control_reply},
    queue::PacketBudget,
    server::RuntimePeer,
    stack::SharedStack,
    tcp::TcpStream,
    udp,
};
use kerlico_core::{
    CancellationToken, ConnectContext, DatagramAssociation, DatagramChannel, Destination, Error,
    InboundContext, NodeEvent, OpenedTcp, PeerSession, Result, TcpConnectInfo,
};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

#[derive(Clone)]
pub struct StackOptions {
    pub addresses: Vec<IpAddr>,
    pub allowed_ips: Vec<String>,
    pub mtu: usize,
    pub limits: StackLimits,
}
impl StackOptions {
    fn prepare(
        &self,
        cancel: CancellationToken,
    ) -> Result<(Arc<SharedStack>, Vec<Network>, Reassembler)> {
        self.limits.validate()?;
        if !(1280..=9000).contains(&self.mtu)
            || self.allowed_ips.is_empty()
            || self.allowed_ips.len() > 256
        {
            return Err(Error::Config("IP数据面MTU或允许范围不合法".into()));
        }
        let allowed = self
            .allowed_ips
            .iter()
            .map(|network| Network::parse(network))
            .collect::<Result<Vec<_>>>()?;
        for (index, network) in allowed.iter().enumerate() {
            if allowed[..index].iter().any(|other| network.overlaps(other)) {
                return Err(Error::Config("IP数据面允许范围不能重复或重叠".into()));
            }
        }
        let stack = SharedStack::with_options(
            Addresses::parse(self.addresses.clone())?,
            self.limits.clone(),
            self.mtu,
            cancel,
            Arc::new(Notify::new()),
            allowed.clone(),
            PacketBudget::new(self.limits.queue_packets, self.limits.queue_bytes),
        )?;
        let fragments = Reassembler::new(FragmentBudget::new(
            self.limits.fragment_packets,
            self.limits.fragment_bytes,
        ));
        Ok((stack, allowed, fragments))
    }
}

struct ClientInner {
    stack: Arc<SharedStack>,
    fragments: Mutex<Reassembler>,
}
impl Drop for ClientInner {
    fn drop(&mut self) {
        self.stack.cancel.cancel();
        self.stack.close();
    }
}
#[derive(Clone)]
pub struct ClientTunnel(Arc<ClientInner>);
impl ClientTunnel {
    pub fn new(options: StackOptions, cancel: CancellationToken) -> Result<Self> {
        let (stack, _, fragments) = options.prepare(cancel.child_token())?;
        Ok(Self(Arc::new(ClientInner {
            stack,
            fragments: Mutex::new(fragments),
        })))
    }
    pub async fn connect_tcp(
        &self,
        remote: &Destination,
        context: &ConnectContext,
    ) -> Result<OpenedTcp> {
        let remote = target(remote)?;
        if !self.0.stack.allows(remote.ip()) {
            return Err(Error::Rejected);
        }
        let stream = TcpStream::connect(self.0.stack.clone(), remote, context).await?;
        let info = TcpConnectInfo::local_bound(stream.local_addr());
        Ok(OpenedTcp {
            stream: Box::new(stream),
            info,
        })
    }
    pub fn connect_udp(
        &self,
        remote: &Destination,
        context: &ConnectContext,
    ) -> Result<DatagramChannel> {
        udp::fixed(self.0.stack.clone(), remote, context)
    }
    pub fn associate_udp(&self, context: &ConnectContext) -> Result<DatagramAssociation> {
        udp::association(self.0.stack.clone(), context)
    }
    pub fn receive(&self, bytes: &[u8]) -> Result<()> {
        let packet = IpPacket::parse(bytes)?;
        if !self.0.stack.allows(packet.source) || !self.0.stack.addresses.contains(packet.target) {
            return Err(Error::Rejected);
        }
        let mut fragments = self
            .0
            .fragments
            .lock()
            .map_err(|_| Error::Protocol("IP分片状态已损坏"))?;
        let Some(bytes) = fragments.accept(bytes, Instant::now())? else {
            return Ok(());
        };
        let packet = IpPacket::parse(&bytes)?;
        match packet.protocol {
            6 => self.0.stack.input_tcp(bytes),
            17 => self.0.stack.receive_udp(&packet),
            1 | 58 => {
                if let Some(reply) = control_reply(&bytes, &self.0.stack.addresses)? {
                    self.0.stack.queue_packet(reply)?;
                }
                Ok(())
            }
            _ => Err(Error::Unsupported("IP数据面不提供该协议")),
        }
    }
    pub async fn next_packet(&self) -> Result<Vec<u8>> {
        next_packet(&self.0.stack).await
    }
    pub fn close(&self) {
        self.0.stack.cancel.cancel();
        self.0.stack.close();
    }
    pub fn active_flows(&self) -> usize {
        self.0.stack.flow_count()
    }
}

pub struct ServerTunnel {
    peer: Mutex<(RuntimePeer, Reassembler)>,
    allowed: Vec<Network>,
    stack: Arc<SharedStack>,
}
impl ServerTunnel {
    /// `access` 必须由外层协议完成真实鉴权后取得，不能从 IP 包中的身份字段创建。
    pub fn new(
        options: StackOptions,
        access: PeerSession,
        mut context: InboundContext,
    ) -> Result<Self> {
        if !access.supports_udp_association() {
            return Err(Error::Unsupported("IP节点需要多目标UDP出站"));
        }
        let lease = context.stream_budget.try_acquire()?;
        context.cancel = context.cancel.child_token();
        let (stack, allowed, fragments) = options.prepare(context.cancel.clone())?;
        context.events.record(NodeEvent::Accepted);
        let peer = RuntimePeer::from_tunnel(stack.clone(), access, context, lease);
        Ok(Self {
            peer: Mutex::new((peer, fragments)),
            allowed,
            stack,
        })
    }
    pub fn receive(&self, bytes: &[u8]) -> Result<()> {
        let mut state = self
            .peer
            .lock()
            .map_err(|_| Error::Protocol("IP节点状态已损坏"))?;
        let (peer, fragments) = &mut *state;
        peer.receive(&self.allowed, fragments, bytes)
    }
    pub async fn next_packet(&self) -> Result<Vec<u8>> {
        next_packet(&self.stack).await
    }
    pub fn close(&self) {
        self.stack.cancel.cancel();
        self.stack.close();
    }
    pub fn active_flows(&self) -> usize {
        self.peer.lock().map_or(0, |state| state.0.active_flows())
    }
}
impl Drop for ServerTunnel {
    fn drop(&mut self) {
        self.close();
    }
}
async fn next_packet(stack: &SharedStack) -> Result<Vec<u8>> {
    let mut timer = tokio::time::interval(Duration::from_millis(20));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        stack.poll()?;
        if let Some(packet) = stack.drain(1)?.pop() {
            return Ok(packet);
        }
        tokio::select! { biased;
            _ = stack.cancel.cancelled() => return Err(Error::Cancelled),
            _ = stack.notify.notified() => {},
            _ = timer.tick() => {},
        }
    }
}
