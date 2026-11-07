use crate::{
    config::{Addresses, Limits, Network, Prepared},
    packet::{FlowTuple, IpPacket, rewrite_tcp_in_place},
    queue::{PacketBudget, PacketLease, QueuedPacket},
};
use kerlico_core::{CancellationToken, ConnectContext, Error, Result};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as StackInstant,
    wire::{HardwareAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::sync::{Notify, mpsc};

#[derive(Clone)]
pub(crate) struct FlowScope {
    request: CancellationToken,
    node: CancellationToken,
    peer: CancellationToken,
    service: CancellationToken,
}
impl FlowScope {
    pub fn from_context(context: &ConnectContext) -> Self {
        Self {
            request: context.cancel.clone(),
            node: context.node_cancel(),
            peer: context.peer_cancel(),
            service: context.service_cancel(),
        }
    }
    pub fn inbound(cancel: CancellationToken) -> Self {
        Self {
            request: cancel,
            node: CancellationToken::new(),
            peer: CancellationToken::new(),
            service: CancellationToken::new(),
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.request.is_cancelled()
            || self.node.is_cancelled()
            || self.peer.is_cancelled()
            || self.service.is_cancelled()
    }
    pub async fn cancelled(&self) {
        tokio::select! { biased;
            _ = self.request.cancelled() => {}, _ = self.node.cancelled() => {},
            _ = self.peer.cancelled() => {}, _ = self.service.cancelled() => {},
        }
    }
}

pub(crate) struct TcpEntry {
    pub handle: SocketHandle,
    pub scope: FlowScope,
    pub established: bool,
    pub saw_fin: bool,
    pub owner: TcpOwner,
    pub write_closed: bool,
    pub pending: CancellationToken,
    pub reader: Option<Waker>,
    pub writer: Option<Waker>,
    pub tuple: FlowTuple,
    pub wire: Option<FlowTuple>,
}
#[derive(Clone, Copy)]
pub(crate) enum TcpOwner {
    Attached,
    Draining(Instant),
    Aborting(Instant),
}
impl TcpEntry {
    fn wake(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }
}
pub(crate) struct UdpEntry {
    pub fixed: Option<SocketAddr>,
    pub scope: FlowScope,
    pub receive: mpsc::Sender<ReceivedDatagram>,
}
pub(crate) struct ReceivedDatagram {
    pub source: SocketAddr,
    pub payload: Vec<u8>,
    pub _lease: PacketLease,
}
pub(crate) struct State {
    pub interface: Interface,
    pub sockets: SocketSet<'static>,
    pub tcp: HashMap<u64, TcpEntry>,
    pub tuples: HashMap<FlowTuple, u64>,
    pub inbound_tcp: HashMap<FlowTuple, u64>,
    pub udp: HashMap<u16, UdpEntry>,
    device: PacketDevice,
    pub closed: bool,
    pub next_id: u64,
    pub next_port: u16,
    pub next_fragment: u32,
}
pub(crate) struct SharedStack {
    state: Mutex<State>,
    pub notify: Arc<Notify>,
    pub cancel: CancellationToken,
    pub addresses: Addresses,
    pub limits: Limits,
    pub mtu: usize,
    pub budget: PacketBudget,
    allowed: Vec<Network>,
    started: Instant,
}
impl State {
    pub(crate) fn push_incoming(&mut self, packet: QueuedPacket) {
        self.device.incoming.push_back(packet);
    }
}
impl SharedStack {
    pub fn new(
        prepared: &Prepared,
        cancel: CancellationToken,
        notify: Arc<Notify>,
        allowed: Vec<Network>,
        budget: PacketBudget,
    ) -> Result<Arc<Self>> {
        Self::with_options(
            prepared.addresses.clone(),
            prepared.limits.clone(),
            prepared.mtu,
            cancel,
            notify,
            allowed,
            budget,
        )
    }
    pub(crate) fn with_options(
        addresses: Addresses,
        limits: Limits,
        mtu: usize,
        cancel: CancellationToken,
        notify: Arc<Notify>,
        allowed: Vec<Network>,
        budget: PacketBudget,
    ) -> Result<Arc<Self>> {
        let mut device = PacketDevice {
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            mtu,
            budget: budget.clone(),
            egress_budget: usize::MAX,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut device, StackInstant::from_millis(0));
        interface.update_ip_addrs(|list| {
            for address in addresses.iter() {
                let _ = list.push(IpCidr::new(
                    address.into(),
                    if address.is_ipv4() { 32 } else { 128 },
                ));
            }
        });
        if let Some(std::net::IpAddr::V4(address)) = addresses.v4 {
            interface
                .routes_mut()
                .add_default_ipv4_route(address)
                .map_err(|_| Error::ResourceLimit)?;
        }
        if let Some(std::net::IpAddr::V6(address)) = addresses.v6 {
            interface
                .routes_mut()
                .add_default_ipv6_route(address)
                .map_err(|_| Error::ResourceLimit)?;
        }
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                interface,
                sockets: SocketSet::new(Vec::new()),
                tcp: HashMap::new(),
                tuples: HashMap::new(),
                inbound_tcp: HashMap::new(),
                udp: HashMap::new(),
                device,
                closed: false,
                next_id: 1,
                next_port: 49152 + rand::random::<u16>() % 16384,
                next_fragment: rand::random(),
            }),
            notify,
            cancel,
            addresses,
            limits,
            mtu,
            budget,
            allowed,
            started: Instant::now(),
        }))
    }
    pub fn lock(&self) -> Result<MutexGuard<'_, State>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::Protocol("WireGuard用户态栈状态已损坏"))?;
        if state.closed || self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(state)
    }
    pub fn time(&self) -> StackInstant {
        StackInstant::from_millis(self.started.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }
    pub fn input_tcp(&self, mut packet: Vec<u8>) -> Result<()> {
        let mut state = self.lock()?;
        let tuple = IpPacket::parse(&packet)?.tcp_tuple()?;
        if let Some(id) = state.inbound_tcp.get(&tuple) {
            let entry = state.tcp.get(id).ok_or(Error::Rejected)?;
            rewrite_tcp_in_place(&mut packet, entry.tuple.target, entry.tuple.source, false)?;
        }
        state
            .device
            .incoming
            .push_back(self.budget.packet(packet, false)?);
        Ok(())
    }
    pub fn contains_tcp(&self, tuple: &FlowTuple) -> bool {
        self.lock()
            .is_ok_and(|state| state.inbound_tcp.contains_key(tuple))
    }
    pub fn flow_count(&self) -> usize {
        self.lock()
            .map_or(0, |state| state.tcp.len() + state.udp.len())
    }
    /// 回收一条应用已关闭、己方数据与 FIN 都已被确认、只等对端挥手或 TIME_WAIT 到期的 TCP 流。
    /// 短连接密集时这些流会占满流表，挡住新连接。
    pub fn reclaim_closed_tcp(&self) -> bool {
        let Ok(mut state) = self.lock() else {
            return false;
        };
        let State { sockets, tcp, .. } = &mut *state;
        let Some(id) = tcp
            .iter()
            .find(|(_, entry)| {
                matches!(entry.owner, TcpOwner::Draining(_))
                    && matches!(
                        sockets.get::<tcp::Socket>(entry.handle).state(),
                        tcp::State::FinWait2 | tcp::State::TimeWait | tcp::State::Closed
                    )
            })
            .map(|(id, _)| *id)
        else {
            return false;
        };
        if let Some(mut entry) = state.tcp.remove(&id) {
            entry.wake();
            state.tuples.remove(&entry.tuple);
            if let Some(wire) = entry.wire {
                state.inbound_tcp.remove(&wire);
            }
            state.sockets.remove(entry.handle);
        }
        true
    }
    pub fn queue(&self, packets: Vec<Vec<u8>>) -> Result<()> {
        let mut state = self.lock()?;
        let packets = packets
            .into_iter()
            .map(|packet| self.budget.packet(packet, false))
            .collect::<Result<Vec<_>>>()?;
        state.device.outgoing.extend(packets);
        drop(state);
        self.notify.notify_one();
        Ok(())
    }
    pub fn queue_packet(&self, packet: Vec<u8>) -> Result<()> {
        if !self.allows(IpPacket::parse(&packet)?.target) {
            return Err(Error::Rejected);
        }
        let id = {
            let mut state = self.lock()?;
            let id = state.next_fragment;
            state.next_fragment = state.next_fragment.wrapping_add(1);
            id
        };
        self.queue(crate::packet::fragment(packet, self.mtu, id)?)
    }
    pub fn allows(&self, address: std::net::IpAddr) -> bool {
        self.allowed.iter().any(|network| network.contains(address))
    }
    pub fn poll(&self) -> Result<()> {
        self.poll_with_budget(usize::MAX)
    }
    pub fn poll_with_budget(&self, egress_budget: usize) -> Result<()> {
        let mut state = self.lock()?;
        let now = Instant::now();
        {
            let State { sockets, tcp, .. } = &mut *state;
            for entry in tcp.values_mut() {
                let socket = sockets.get_mut::<tcp::Socket>(entry.handle);
                if entry.scope.is_cancelled() && !matches!(entry.owner, TcpOwner::Aborting(_))
                    || matches!(entry.owner, TcpOwner::Draining(deadline) if now >= deadline)
                {
                    entry.owner = TcpOwner::Aborting(now + Duration::from_secs(1));
                    entry.wake();
                }
                if matches!(entry.owner, TcpOwner::Aborting(_)) {
                    socket.abort();
                }
            }
        }
        {
            let State {
                interface,
                sockets,
                device,
                ..
            } = &mut *state;
            device.egress_budget = egress_budget;
            interface.poll(self.time(), device, sockets);
        }
        {
            let State {
                sockets,
                tcp,
                tuples,
                device,
                ..
            } = &mut *state;
            for queued in &mut device.outgoing {
                if !queued.from_stack {
                    continue;
                }
                let packet = IpPacket::parse(&queued.bytes)?;
                if packet.protocol != 6 {
                    return Err(Error::Protocol("WireGuard TCP栈产生了意外控制包"));
                }
                let tuple = packet.tuple()?;
                if let Some(entry) = tuples.get(&tuple).and_then(|id| tcp.get(id))
                    && let Some(wire) = entry.wire
                {
                    rewrite_tcp_in_place(&mut queued.bytes, wire.target, wire.source, false)?;
                }
                queued.from_stack = false;
            }
            for entry in tcp.values_mut() {
                let socket = sockets.get_mut::<tcp::Socket>(entry.handle);
                if matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    entry.established = true;
                }
                if matches!(
                    socket.state(),
                    tcp::State::CloseWait
                        | tcp::State::Closing
                        | tcp::State::LastAck
                        | tcp::State::TimeWait
                ) {
                    entry.saw_fin = true;
                }
                if !entry.established
                    && (socket.state() == tcp::State::Closed
                        || entry.wire.is_some() && socket.state() == tcp::State::Listen)
                {
                    entry.pending.cancel();
                }
            }
        }
        let expired = state
            .tcp
            .iter()
            .filter_map(|(id, entry)| {
                let socket = state.sockets.get::<tcp::Socket>(entry.handle);
                match entry.owner {
                    TcpOwner::Attached => None,
                    TcpOwner::Draining(_)
                        if socket.remote_endpoint().is_none()
                            || socket.state() == tcp::State::TimeWait =>
                    {
                        Some(*id)
                    }
                    TcpOwner::Aborting(deadline)
                        if socket.remote_endpoint().is_none() || now >= deadline =>
                    {
                        Some(*id)
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(mut entry) = state.tcp.remove(&id) {
                entry.wake();
                state.tuples.remove(&entry.tuple);
                if let Some(wire) = entry.wire {
                    state.inbound_tcp.remove(&wire);
                }
                state.sockets.remove(entry.handle);
            }
        }
        state
            .udp
            .retain(|_, entry| !entry.scope.is_cancelled() && !entry.receive.is_closed());
        Ok(())
    }
    pub fn drain(&self, maximum: usize) -> Result<Vec<Vec<u8>>> {
        let mut state = self.lock()?;
        let count = maximum.min(state.device.outgoing.len());
        let packets = state
            .device
            .outgoing
            .drain(..count)
            .map(|packet| packet.bytes)
            .collect::<Vec<_>>();
        Ok(packets)
    }
    pub fn has_output(&self) -> bool {
        self.lock()
            .is_ok_and(|state| !state.device.outgoing.is_empty())
    }
    pub fn receive_udp(&self, packet: &IpPacket<'_>) -> Result<()> {
        let (tuple, payload) = packet.udp()?;
        if !self.addresses.contains(tuple.target.ip()) {
            return Err(Error::Rejected);
        }
        let state = self.lock()?;
        let entry = state.udp.get(&tuple.target.port()).ok_or(Error::Rejected)?;
        if entry.scope.is_cancelled() || entry.fixed.is_some_and(|fixed| fixed != tuple.source) {
            return Err(Error::Rejected);
        }
        entry
            .receive
            .try_send(ReceivedDatagram {
                source: tuple.source,
                payload: payload.to_vec(),
                _lease: self.budget.reserve(payload.len())?,
            })
            .map_err(|_| Error::ResourceLimit)
    }
    pub fn tcp_poll<T>(
        &self,
        id: u64,
        cx: &mut Context<'_>,
        operation: impl FnOnce(
            &mut tcp::Socket<'static>,
            &mut TcpEntry,
            &mut Context<'_>,
        ) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let mut state = match self.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(cancelled())),
        };
        let State { sockets, tcp, .. } = &mut *state;
        let Some(entry) = tcp.get_mut(&id) else {
            return Poll::Ready(Err(cancelled()));
        };
        if entry.scope.is_cancelled() {
            return Poll::Ready(Err(cancelled()));
        }
        let socket = sockets.get_mut::<tcp::Socket>(entry.handle);
        if matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        ) {
            entry.established = true;
        }
        if matches!(
            socket.state(),
            tcp::State::CloseWait
                | tcp::State::Closing
                | tcp::State::LastAck
                | tcp::State::TimeWait
        ) {
            entry.saw_fin = true;
        }
        let result = operation(socket, entry, cx);
        drop(state);
        self.notify.notify_one();
        result
    }
    pub fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.closed = true;
        for entry in state.tcp.values_mut() {
            entry.pending.cancel();
            entry.wake();
        }
        state.tcp.clear();
        state.tuples.clear();
        state.inbound_tcp.clear();
        state.udp.clear();
        state.sockets = SocketSet::new(Vec::new());
        state.device.incoming.clear();
        state.device.outgoing.clear();
        self.notify.notify_waiters();
    }
}
pub(crate) fn cancelled() -> io::Error {
    io::Error::other(Error::Cancelled)
}
pub(crate) fn endpoint(address: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(address.ip().into(), address.port())
}

struct PacketDevice {
    incoming: VecDeque<QueuedPacket>,
    outgoing: VecDeque<QueuedPacket>,
    mtu: usize,
    budget: PacketBudget,
    egress_budget: usize,
}
struct Receive(Vec<u8>);
struct Transmit<'a> {
    outgoing: &'a mut VecDeque<QueuedPacket>,
    lease: PacketLease,
}
impl RxToken for Receive {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.outgoing.push_back(QueuedPacket {
            bytes: packet,
            from_stack: true,
            _lease: self.lease,
        });
        result
    }
}
impl Device for PacketDevice {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;
    fn receive(&mut self, _: StackInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.incoming.pop_front()?;
        let bytes = packet.bytes;
        drop(packet._lease);
        let lease = self.budget.reserve(self.mtu).ok()?;
        Some((
            Receive(bytes),
            Transmit {
                outgoing: &mut self.outgoing,
                lease,
            },
        ))
    }
    fn transmit(&mut self, _: StackInstant) -> Option<Self::TxToken<'_>> {
        if self.egress_budget == 0 {
            return None;
        }
        let lease = self.budget.reserve(self.mtu).ok()?;
        self.egress_budget -= 1;
        Some(Transmit {
            outgoing: &mut self.outgoing,
            lease,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = None;
        capabilities
    }
}
