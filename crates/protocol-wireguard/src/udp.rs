use crate::{config::{destination, target}, packet::udp_packet, stack::{FlowScope, ReceivedDatagram, SharedStack, UdpEntry}};
use kerlico_core::{AddressedDatagram, BoxFuture, ConnectContext, DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver, DatagramSender, Destination, Error, Result};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;

struct Lease { stack: Arc<SharedStack>, port: u16, scope: FlowScope }
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.stack.lock() { state.udp.remove(&self.port); }
        self.stack.notify.notify_one();
    }
}
struct Sender(Arc<Lease>);
struct Receiver { lease: Arc<Lease>, receive: mpsc::Receiver<ReceivedDatagram> }
struct FixedSender { sender: Sender, target: Destination }
struct FixedReceiver { receiver: Receiver, target: Destination }

fn allocate(stack: Arc<SharedStack>, fixed: Option<SocketAddr>, context: &ConnectContext) -> Result<(Sender, Receiver)> {
    let mut state = stack.lock()?;
    if state.tcp.len() + state.udp.len() >= stack.limits.max_flows { return Err(Error::ResourceLimit); }
    let mut available = None;
    for _ in 0..16384 {
        let port = state.next_port;
        state.next_port = if port == u16::MAX { 49152 } else { port + 1 };
        if !state.udp.contains_key(&port) { available = Some(port); break; }
    }
    let port = available.ok_or(Error::ResourceLimit)?;
    let scope = FlowScope::from_context(context);
    if scope.is_cancelled() { return Err(Error::Cancelled); }
    let (send, receive) = mpsc::channel(stack.limits.queue_packets);
    state.udp.insert(port, UdpEntry { fixed, scope: scope.clone(), receive: send });
    drop(state);
    let lease = Arc::new(Lease { stack, port, scope });
    Ok((Sender(lease.clone()), Receiver { lease, receive }))
}
pub(crate) fn fixed(stack: Arc<SharedStack>, remote: &Destination, context: &ConnectContext) -> Result<DatagramChannel> {
    let address = target(remote)?;
    if !stack.allows(address.ip()) { return Err(Error::Rejected); }
    stack.addresses.for_target(address.ip())?;
    let (sender, receiver) = allocate(stack, Some(address), context)?;
    Ok(DatagramChannel { sender: Box::new(FixedSender { sender, target: remote.clone() }),
        receiver: Box::new(FixedReceiver { receiver, target: remote.clone() }) })
}
pub(crate) fn association(stack: Arc<SharedStack>, context: &ConnectContext) -> Result<DatagramAssociation> {
    let (sender, receiver) = allocate(stack, None, context)?;
    Ok(DatagramAssociation { sender: Box::new(sender), receiver: Box::new(receiver) })
}
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(&'a mut self, payload: &'a [u8], remote: &'a Destination) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.0.scope.is_cancelled() { return Err(Error::Cancelled); }
            let target = target(remote)?;
            let source = SocketAddr::new(self.0.stack.addresses.for_target(target.ip())?, self.0.port);
            self.0.stack.queue_packet(udp_packet(source, target, payload)?)
        })
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            tokio::select! { biased;
                _ = self.lease.scope.cancelled() => Err(Error::Cancelled),
                _ = self.lease.stack.cancel.cancelled() => Err(Error::Cancelled),
                value = self.receive.recv() => value.map(|packet| destination(packet.source).map(|address| (address, packet.payload))).transpose(),
            }
        })
    }
}
impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.sender.send_to(packet, &self.target)
    }
}
impl DatagramReceiver for FixedReceiver {
    fn peer_addr(&self) -> Option<Destination> { Some(self.target.clone()) }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move { self.receiver.recv_from().await.map(|packet| packet.map(|(_, payload)| payload)) })
    }
}
