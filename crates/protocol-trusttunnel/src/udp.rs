//! _udp2 仅复用独立固定 flow；不提供同 socket 多目标关联。
use crate::protocol;
use kerlico_core::{
    Address, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, Error, InboundContext, NodeEvent, PeerSession,
    Result,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, watch},
    task::JoinSet,
    time::Instant,
};
pub(crate) const MAX_PAYLOAD: usize = 65507;
pub(crate) fn literal(target: &Destination) -> Result<SocketAddr> {
    match target.address() {
        Address::Ip(ip) if *ip != IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)) => {
            Ok(SocketAddr::new(*ip, target.port()))
        }
        _ => Err(Error::Unsupported(
            "TrustTunnel UDP 需要统一出口提供无歧义字面 IP",
        )),
    }
}
fn put_ip(ip: IpAddr, out: &mut Vec<u8>) -> Result<()> {
    match ip {
        IpAddr::V4(ip) => {
            if ip == Ipv4Addr::new(0, 0, 0, 1) {
                return Err(protocol());
            }
            out.extend_from_slice(&[0; 12]);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            let bytes = ip.octets();
            if bytes[..12] == [0; 12] && ip != Ipv6Addr::LOCALHOST {
                return Err(protocol());
            }
            out.extend_from_slice(&bytes);
        }
    }
    Ok(())
}
fn ip(bytes: &[u8]) -> IpAddr {
    let bytes = <[u8; 16]>::try_from(bytes).expect("固定长度 IP");
    if bytes[..12] == [0; 12] && bytes[12..] != [0, 0, 0, 1] {
        IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Endpoint {
    Unknown,
    Specified(SocketAddr),
}
impl Endpoint {
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes == [0; 18] {
            return Ok(Self::Unknown);
        }
        let address = SocketAddr::new(ip(&bytes[..16]), u16::from_be_bytes([bytes[16], bytes[17]]));
        if address.port() == 0 {
            return Err(protocol());
        }
        Ok(Self::Specified(address))
    }
    fn specified(self) -> Result<SocketAddr> {
        match self {
            Self::Specified(address) if address.port() != 0 => Ok(address),
            _ => Err(protocol()),
        }
    }
    fn put(self, bytes: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Unknown => bytes.extend_from_slice(&[0; 18]),
            Self::Specified(_) => {
                let address = self.specified()?;
                put_ip(address.ip(), bytes)?;
                bytes.extend_from_slice(&address.port().to_be_bytes());
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    pub source: Endpoint,
    pub target: Endpoint,
    pub data: Vec<u8>,
}
pub(crate) fn encode(
    source: Endpoint,
    target: Endpoint,
    app: Option<&str>,
    data: &[u8],
    maximum: usize,
) -> Result<Vec<u8>> {
    if app.is_some() {
        target.specified()?;
    } else {
        source.specified()?;
    }
    if data.len() > maximum.min(MAX_PAYLOAD)
        || app.is_some_and(|a| a.len() > 255 || a.chars().any(char::is_control))
    {
        return Err(Error::ResourceLimit);
    }
    let size = 36 + app.map_or(0, |s| s.len() + 1) + data.len();
    let mut out = Vec::with_capacity(4 + size);
    out.extend_from_slice(&(size as u32).to_be_bytes());
    source.put(&mut out)?;
    target.put(&mut out)?;
    if let Some(app) = app {
        out.push(app.len() as u8);
        out.extend_from_slice(app.as_bytes());
    }
    out.extend_from_slice(data);
    Ok(out)
}
pub(crate) async fn read(
    io: &mut (impl AsyncRead + Unpin),
    uplink: bool,
    maximum: usize,
) -> Result<Option<Packet>> {
    let mut length = [0; 4];
    let first = io.read(&mut length[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    io.read_exact(&mut length[1..]).await?;
    let size = u32::from_be_bytes(length) as usize;
    let minimum = 36 + usize::from(uplink);
    if size < minimum || size > minimum + if uplink { 255 } else { 0 } + maximum.min(MAX_PAYLOAD) {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = vec![0; size];
    io.read_exact(&mut bytes).await?;
    let source = Endpoint::decode(&bytes[..18])?;
    let target = Endpoint::decode(&bytes[18..36])?;
    if uplink {
        target.specified()?;
    } else {
        source.specified()?;
    }
    let start = if uplink {
        let n = bytes[36] as usize;
        if 37 + n > bytes.len() {
            return Err(protocol());
        }
        let app = std::str::from_utf8(&bytes[37..37 + n]).map_err(|_| protocol())?;
        if app.chars().any(char::is_control) {
            return Err(protocol());
        }
        37 + n
    } else {
        36
    };
    if bytes.len() - start > maximum.min(MAX_PAYLOAD) {
        return Err(Error::ResourceLimit);
    }
    Ok(Some(Packet {
        source,
        target,
        data: bytes[start..].to_vec(),
    }))
}
struct Shared {
    cancel: CancellationToken,
    _slot: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct Send {
    write: tokio::io::WriteHalf<BoxStream>,
    target: SocketAddr,
    app: String,
    idle: Duration,
    state: Arc<Shared>,
}
struct Receive {
    read: tokio::io::ReadHalf<BoxStream>,
    target: SocketAddr,
    idle: Duration,
    state: Arc<Shared>,
}
pub(crate) fn channel(
    io: BoxStream,
    target: Destination,
    app: String,
    idle: Duration,
    cancel: CancellationToken,
    slot: tokio::sync::OwnedSemaphorePermit,
) -> Result<DatagramChannel> {
    let target = literal(&target)?;
    let (read, write) = tokio::io::split(io);
    let state = Arc::new(Shared {
        cancel: cancel.child_token(),
        _slot: slot,
    });
    Ok(DatagramChannel {
        sender: Box::new(Send {
            write,
            target,
            app,
            idle,
            state: state.clone(),
        }),
        receiver: Box::new(Receive {
            read,
            target,
            idle,
            state,
        }),
    })
}
impl DatagramSender for Send {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let bytes = encode(
                Endpoint::Unknown,
                Endpoint::Specified(self.target),
                Some(&self.app),
                packet,
                MAX_PAYLOAD,
            )?;
            let context = ConnectContext::new(self.idle).with_cancel(self.state.cancel.clone());
            let result = context
                .run(async {
                    self.write.write_all(&bytes).await?;
                    self.write.flush().await?;
                    Ok(())
                })
                .await;
            if result.is_err() {
                self.state.cancel.cancel();
            }
            result
        })
    }
}
impl DatagramReceiver for Receive {
    fn peer_addr(&self) -> Option<Destination> {
        Destination::new(&self.target.ip().to_string(), self.target.port()).ok()
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let context = ConnectContext::new(self.idle).with_cancel(self.state.cancel.clone());
            let result = context
                .run(async {
                    let Some(packet) = read(&mut self.read, false, MAX_PAYLOAD).await? else {
                        return Ok(None);
                    };
                    if packet.source != Endpoint::Specified(self.target)
                        || packet.target != Endpoint::Unknown
                    {
                        return Err(protocol());
                    }
                    Ok(Some(packet.data))
                })
                .await;
            if result.is_err() || matches!(result, Ok(None)) {
                self.state.cancel.cancel();
            }
            result
        })
    }
}
struct Scope(CancellationToken);
impl Drop for Scope {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn active_read(
    io: &mut (impl AsyncRead + Unpin),
    maximum: usize,
    idle: Duration,
    activity: &mut watch::Receiver<Instant>,
    cancel: &CancellationToken,
) -> Result<Option<Packet>> {
    let read = read(io, true, maximum);
    tokio::pin!(read);
    let timer = tokio::time::sleep_until(*activity.borrow_and_update() + idle);
    tokio::pin!(timer);
    loop {
        tokio::select! {biased;_=cancel.cancelled()=>return Err(Error::Cancelled),packet=&mut read=>return packet,changed=activity.changed()=>{if changed.is_err(){return Err(Error::Cancelled);}timer.as_mut().reset(*activity.borrow_and_update()+idle);},_=&mut timer=>return Err(Error::Timeout)}
    }
}
struct TargetFlow {
    generation: u64,
    sender: mpsc::Sender<Vec<u8>>,
    completion: crate::flow::Ticket,
}
type TargetKey = (Endpoint, SocketAddr);
type TargetResult = (TargetKey, u64, Result<()>);
fn finish_target(
    flows: &mut HashMap<TargetKey, TargetFlow>,
    key: TargetKey,
    generation: u64,
    result: &Result<()>,
) {
    if flows
        .get(&key)
        .is_some_and(|flow| flow.generation == generation)
    {
        if let Some(flow) = flows.remove(&key) {
            flow.completion.finish(flow_outcome(result));
        }
    }
}
fn flow_outcome(result: &Result<()>) -> kerlico_core::FlowOutcome {
    match result {
        Ok(()) => kerlico_core::FlowOutcome::ProtocolEnd,
        Err(error) => {
            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::from_error(error))
        }
    }
}
pub(crate) async fn serve(
    io: BoxStream,
    access: PeerSession,
    context: InboundContext,
    maximum_flows: usize,
    parent_flows: Arc<crate::flow::FlowSet>,
) -> Result<()> {
    let (mut input, mut output) = tokio::io::split(io);
    let cancel = context.cancel.child_token();
    let _scope = Scope(cancel.clone());
    let (replies, mut reply_queue) =
        mpsc::channel::<(Vec<u8>, tokio::sync::oneshot::Sender<()>)>(8);
    let token = cancel.clone();
    let idle = context.idle_timeout;
    let mut writer = context.tasks.spawn_tracked(async move {
        loop {
            let (bytes, ack) = tokio::select! { biased;
                _ = token.cancelled() => return Err(Error::Cancelled),
                value = reply_queue.recv() => match value { Some(value) => value, None => return Ok(()) },
            };
            tokio::time::timeout(idle, async { output.write_all(&bytes).await?; output.flush().await }).await.map_err(|_| Error::Timeout)??;
            let _ = ack.send(());
        }
    })?;
    let (activity, mut observed) = watch::channel(Instant::now());
    let mut flows = HashMap::<TargetKey, TargetFlow>::new();
    let mut tasks = JoinSet::<TargetResult>::new();
    let mut generation = 0u64;
    let mut writer_finished = false;
    let result = async {
        loop {
            let packet = {
                let reading = active_read(&mut input, context.max_datagram_size, context.idle_timeout, &mut observed, &cancel);
                tokio::pin!(reading);
                loop {
                    tokio::select! { biased;
                        _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                        joined = &mut writer => { writer_finished = true; return match joined {
                            Ok(Err(error)) | Err(error) => Err(error),
                            Ok(Ok(())) => Err(Error::Protocol("TrustTunnel UDP 写任务提前结束")),
                        }; },
                        joined = tasks.join_next(), if !tasks.is_empty() => match joined {
                            Some(Ok((key, generation, result))) => finish_target(&mut flows, key, generation, &result),
                            Some(Err(_)) => return Err(Error::Protocol("TrustTunnel UDP 子任务异常退出")),
                            None => {},
                        },
                        packet = &mut reading => break packet?,
                    }
                }
            };
            let Some(packet) = packet else { return Ok(()); };
            activity.send_replace(Instant::now());
            let target_socket = packet.target.specified()?;
            let key = (packet.source, target_socket);
            if let Some(flow) = flows.get(&key) {
                if flow.sender.try_send(packet.data).is_err() { context.events.record(NodeEvent::Dropped); }
                continue;
            }
            if context.stream_budget.is_closed() || flows.len() >= maximum_flows {
                context.events.record(NodeEvent::Dropped);
                continue;
            }
            let lease = match context.stream_budget.try_acquire() {
                Ok(lease) => lease,
                Err(_) => { context.events.record(NodeEvent::Dropped); continue; }
            };
            let target = Destination::new(&target_socket.ip().to_string(), target_socket.port())?;
            let connect = ConnectContext::new(context.connect_timeout).with_cancel(cancel.clone());
            let channel = match access.connect_udp(&target, &connect).await {
                Ok(channel) => channel,
                Err(_) => { context.events.record(NodeEvent::Failed); continue; }
            };
            let (mut sender, mut receiver, completion) = channel.into_parts();
            let completion = parent_flows.register(completion)?;
            let peer = match receiver.peer_addr().ok_or(Error::Unsupported("TrustTunnel UDP 出口缺少真实业务来源")).and_then(|peer| literal(&peer)) {
                Ok(peer) => peer,
                Err(error) => { completion.finish(flow_outcome(&Err(error))); return Err(Error::Unsupported("TrustTunnel UDP 出口缺少可编码业务来源")); }
            };
            generation = match generation.checked_add(1) {
                Some(next) => next,
                None => {
                    completion.finish(kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed));
                    return Err(Error::ResourceLimit);
                }
            };
            let current = generation;
            let (packets, mut incoming) = mpsc::channel::<Vec<u8>>(8);
            if packets.try_send(packet.data).is_err() {
                completion.finish(kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed));
                return Err(Error::ResourceLimit);
            }
            flows.insert(key, TargetFlow { generation: current, sender: packets, completion });
            let replies = replies.clone();
            let token = cancel.clone();
            let max = context.max_datagram_size;
            let activity = activity.clone();
            let task = context.tasks.spawn_tracked(async move {
                let _lease = lease;
                let result = async {
                    let timer = tokio::time::sleep(idle);
                    tokio::pin!(timer);
                    loop {
                        tokio::select! { biased;
                            _ = token.cancelled() => return Err(Error::Cancelled),
                            _ = &mut timer => return Err(Error::Timeout),
                            packet = incoming.recv() => {
                                let Some(bytes) = packet else { return Err(Error::Cancelled); };
                                tokio::time::timeout(idle, sender.send(&bytes)).await.map_err(|_| Error::Timeout)??;
                            }
                            packet = receiver.recv() => {
                                let Some(bytes) = packet? else { return Ok(()); };
                                let bytes = encode(Endpoint::Specified(peer), key.0, None, &bytes, max)?;
                                let (ack, delivered) = tokio::sync::oneshot::channel();
                                tokio::time::timeout(idle, async {
                                    replies.send((bytes, ack)).await.map_err(|_| Error::Protocol("TrustTunnel UDP 写任务已结束"))?;
                                    delivered.await.map_err(|_| Error::Protocol("TrustTunnel UDP 回复未完成"))
                                }).await.map_err(|_| Error::Timeout)??;
                            }
                        }
                        activity.send_replace(Instant::now());
                        timer.as_mut().reset(Instant::now() + idle);
                    }
                }.await;
                (key, current, result)
            })?;
            tasks.spawn(async move { match task.await {
                Ok(result) => result,
                Err(error) => (key, current, Err(error)),
            }});
        }
    }.await;
    while let Some(joined) = tasks.try_join_next() {
        if let Ok((key, generation, result)) = joined {
            finish_target(&mut flows, key, generation, &result);
        }
    }
    let reason = flow_outcome(&result);
    for (_, flow) in flows.drain() {
        flow.completion.finish(reason);
    }
    cancel.cancel();
    if !writer_finished {
        writer.abort();
        let _ = writer.await;
    }
    let deadline = Instant::now() + context.drain_timeout;
    if tokio::time::timeout_at(deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        let _ = tokio::time::timeout_at(deadline, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    fn endpoint(address: &str) -> Endpoint {
        Endpoint::Specified(address.parse().unwrap())
    }
    #[tokio::test]
    async fn zero_packet_ipv6_and_split_records_are_not_eof() {
        for host in ["127.0.0.1", "::1"] {
            let src = endpoint("0.0.0.0:19");
            let dst = Endpoint::Specified(SocketAddr::new(host.parse().unwrap(), 53));
            let mut wire = encode(src, dst, Some("应用"), &[], MAX_PAYLOAD).unwrap();
            wire.extend_from_slice(&encode(src, dst, Some(""), b"next", MAX_PAYLOAD).unwrap());
            let (a, mut b) = tokio::io::duplex(16);
            let writer = tokio::spawn(async move {
                for chunk in wire.chunks(3) {
                    b.write_all(chunk).await.unwrap();
                }
            });
            let mut a = a;
            let first = read(&mut a, true, MAX_PAYLOAD).await.unwrap().unwrap();
            assert_eq!(first.target, dst);
            assert!(first.data.is_empty());
            assert_eq!(
                read(&mut a, true, MAX_PAYLOAD).await.unwrap().unwrap().data,
                b"next"
            );
            assert!(read(&mut a, true, MAX_PAYLOAD).await.unwrap().is_none());
            writer.await.unwrap();
        }
    }
    #[tokio::test]
    async fn hostile_lengths_and_truncation_are_bounded() {
        let mut huge = &u32::MAX.to_be_bytes()[..];
        assert!(read(&mut huge, true, MAX_PAYLOAD).await.is_err());
        let mut truncated = &[0, 0, 0, 37, 1][..];
        assert!(read(&mut truncated, true, MAX_PAYLOAD).await.is_err());
        assert!(literal(&Destination::new("0.0.0.1", 53).unwrap()).is_err());
        let a = endpoint("127.0.0.1:53");
        assert!(encode(a, a, Some(""), &vec![0; MAX_PAYLOAD + 1], MAX_PAYLOAD).is_err());
    }
    #[tokio::test]
    async fn unknown_endpoint_is_only_the_complete_zero_marker_and_is_directional() {
        let target = endpoint("192.0.2.1:53");
        let wire = encode(Endpoint::Unknown, target, Some(""), b"request", MAX_PAYLOAD).unwrap();
        assert_eq!(&wire[4..22], &[0; 18]);
        let packet = read(&mut wire.as_slice(), true, MAX_PAYLOAD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.source, Endpoint::Unknown);
        assert_eq!(packet.target, target);
        let reply = encode(target, packet.source, None, b"reply", MAX_PAYLOAD).unwrap();
        let packet = read(&mut reply.as_slice(), false, MAX_PAYLOAD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.source, target);
        assert_eq!(packet.target, Endpoint::Unknown);
        assert_eq!(packet.data, b"reply");
        assert!(encode(target, Endpoint::Unknown, Some(""), b"", MAX_PAYLOAD).is_err());
        assert!(encode(Endpoint::Unknown, target, None, b"", MAX_PAYLOAD).is_err());
        let mut invalid_reply = reply;
        invalid_reply[4..22].fill(0);
        assert!(
            read(&mut invalid_reply.as_slice(), false, MAX_PAYLOAD)
                .await
                .is_err()
        );
        for offset in [4, 19] {
            let mut invalid = wire.clone();
            invalid[offset] = 2;
            assert!(
                read(&mut invalid.as_slice(), true, MAX_PAYLOAD)
                    .await
                    .is_err()
            );
        }
        for unknown_target in [false, true] {
            let mut invalid = wire.clone();
            invalid[38..40].fill(0);
            if unknown_target {
                invalid[22..38].fill(0);
            }
            assert!(
                read(&mut invalid.as_slice(), true, MAX_PAYLOAD)
                    .await
                    .is_err()
            );
        }
        let virtual_source = endpoint("0.0.0.0:1111");
        let wire = encode(virtual_source, target, Some(""), b"", MAX_PAYLOAD).unwrap();
        assert_eq!(
            read(&mut wire.as_slice(), true, MAX_PAYLOAD)
                .await
                .unwrap()
                .unwrap()
                .source,
            virtual_source
        );
    }
    struct Observer;
    impl kerlico_core::NodeObserver for Observer {
        fn record(&self, _: NodeEvent) {}
    }
    struct EchoSend(mpsc::Sender<Vec<u8>>);
    impl DatagramSender for EchoSend {
        fn send<'a>(&'a mut self, p: &'a [u8]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { self.0.send(p.to_vec()).await.map_err(|_| Error::Cancelled) })
        }
    }
    struct EchoReceive(mpsc::Receiver<Vec<u8>>, Destination);
    impl DatagramReceiver for EchoReceive {
        fn peer_addr(&self) -> Option<Destination> {
            Some(self.1.clone())
        }
        fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
            Box::pin(async move { Ok(self.0.recv().await) })
        }
    }
    struct Access(std::sync::Mutex<Vec<Destination>>);
    impl kerlico_core::Outbound for Access {
        fn capabilities(&self) -> kerlico_core::Capabilities {
            kerlico_core::Capabilities {
                tcp: false,
                tcp_eof: false,
                udp: true,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
            Box::pin(async { Err(Error::Unsupported("测试不使用 TCP")) })
        }
        fn connect_udp<'a>(
            &'a self,
            target: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async move {
                self.0.lock().unwrap().push(target.clone());
                let (tx, rx) = mpsc::channel(4);
                Ok(DatagramChannel {
                    sender: Box::new(EchoSend(tx)),
                    receiver: Box::new(EchoReceive(
                        rx,
                        Destination::new("192.0.2.99", target.port()).unwrap(),
                    )),
                })
            })
        }
    }
    async fn serve_test(
        stream: BoxStream,
        access: Arc<Access>,
        context: InboundContext,
        maximum: usize,
    ) -> Result<()> {
        let input = kerlico_config::NodeBuildContext::local_for_test(serde_json::json!({}));
        let ingress =
            kerlico_egress::testing::ingress(&input, access, kerlico_core::TargetPolicy::Remote)?;
        let flows = crate::flow::FlowSet::new(maximum, context.cancel.clone());
        let _guard = flows.guard();
        super::serve(stream, ingress.local(&context)?, context, maximum, flows).await
    }
    fn context(
        cancel: CancellationToken,
        global: Arc<tokio::sync::Semaphore>,
        node: Arc<tokio::sync::Semaphore>,
    ) -> InboundContext {
        InboundContext {
            peer_lease: None,
            tasks: kerlico_core::NodeTasks::new(
                kerlico_core::NodeId::parse("test-node").unwrap(),
                kerlico_core::CancellationToken::new(),
            ),
            peer_addr: None,
            local_addr: None,
            cancel,
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(2),
            drain_timeout: Duration::from_millis(100),
            max_datagram_size: MAX_PAYLOAD,
            max_streams: 8,
            stream_budget: kerlico_core::StreamBudget::new(global, node),
            events: Arc::new(Observer),
        }
    }
    #[tokio::test]
    async fn unknown_sources_in_separate_streams_keep_same_target_replies_and_cancel_budgets_separate()
     {
        tokio::time::timeout(Duration::from_secs(4), async {
            let access = Arc::new(Access(std::sync::Mutex::new(Vec::new())));
            let global = Arc::new(tokio::sync::Semaphore::new(2));
            let first_node = Arc::new(tokio::sync::Semaphore::new(1));
            let second_node = Arc::new(tokio::sync::Semaphore::new(1));
            let first_cancel = CancellationToken::new();
            let second_cancel = CancellationToken::new();
            let (first, mut first_client) = tokio::io::duplex(256);
            let (second, mut second_client) = tokio::io::duplex(256);
            let first = tokio::spawn(serve_test(
                Box::new(first),
                access.clone(),
                context(first_cancel.clone(), global.clone(), first_node.clone()),
                1,
            ));
            let second = tokio::spawn(serve_test(
                Box::new(second),
                access.clone(),
                context(second_cancel.clone(), global.clone(), second_node.clone()),
                1,
            ));
            let target = endpoint("192.0.2.1:53");
            for (client, payload) in [
                (&mut first_client, b"first".as_slice()),
                (&mut second_client, b"second".as_slice()),
            ] {
                client
                    .write_all(
                        &encode(Endpoint::Unknown, target, Some(""), payload, MAX_PAYLOAD).unwrap(),
                    )
                    .await
                    .unwrap();
            }
            for (client, payload) in [
                (&mut first_client, b"first".as_slice()),
                (&mut second_client, b"second".as_slice()),
            ] {
                let reply = read(client, false, MAX_PAYLOAD).await.unwrap().unwrap();
                assert_eq!(reply.target, Endpoint::Unknown);
                assert_eq!(reply.source, endpoint("192.0.2.99:53"));
                assert_eq!(reply.data, payload);
            }
            assert_eq!(access.0.lock().unwrap().len(), 2);
            assert_eq!(global.available_permits(), 0);
            first_client
                .write_all(
                    &encode(
                        Endpoint::Unknown,
                        endpoint("192.0.2.2:54"),
                        Some(""),
                        b"over-budget",
                        MAX_PAYLOAD,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(50),
                    read(&mut first_client, false, MAX_PAYLOAD)
                )
                .await
                .is_err()
            );
            assert_eq!(access.0.lock().unwrap().len(), 2);
            first_cancel.cancel();
            assert!(matches!(first.await.unwrap(), Err(Error::Cancelled)));
            assert_eq!(global.available_permits(), 1);
            assert_eq!(first_node.available_permits(), 1);
            second_client
                .write_all(
                    &encode(
                        Endpoint::Unknown,
                        target,
                        Some(""),
                        b"still-alive",
                        MAX_PAYLOAD,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                read(&mut second_client, false, MAX_PAYLOAD)
                    .await
                    .unwrap()
                    .unwrap()
                    .data,
                b"still-alive"
            );
            second_cancel.cancel();
            assert!(matches!(second.await.unwrap(), Err(Error::Cancelled)));
            assert_eq!(global.available_permits(), 2);
            assert_eq!(second_node.available_permits(), 1);
            let lease = kerlico_core::StreamBudget::new(global, first_node)
                .try_acquire()
                .unwrap();
            drop(lease);
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn invalid_zero_port_after_unknown_flow_releases_its_budget_before_returning() {
        tokio::time::timeout(Duration::from_secs(4), async {
            let access = Arc::new(Access(std::sync::Mutex::new(Vec::new())));
            let global = Arc::new(tokio::sync::Semaphore::new(1));
            let node = Arc::new(tokio::sync::Semaphore::new(1));
            let (server, mut client) = tokio::io::duplex(256);
            let running = tokio::spawn(serve_test(
                Box::new(server),
                access.clone(),
                context(CancellationToken::new(), global.clone(), node.clone()),
                1,
            ));
            let mut wire = encode(
                Endpoint::Unknown,
                endpoint("192.0.2.1:53"),
                Some(""),
                b"first",
                MAX_PAYLOAD,
            )
            .unwrap();
            client.write_all(&wire).await.unwrap();
            assert_eq!(
                read(&mut client, false, MAX_PAYLOAD)
                    .await
                    .unwrap()
                    .unwrap()
                    .data,
                b"first"
            );
            assert_eq!(global.available_permits(), 0);
            wire[38..40].fill(0);
            client.write_all(&wire).await.unwrap();
            assert!(running.await.unwrap().is_err());
            assert_eq!(access.0.lock().unwrap().len(), 1);
            assert_eq!(global.available_permits(), 1);
            assert_eq!(node.available_permits(), 1);
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn one_http_stream_has_separate_budgeted_flows_and_uses_access_peer_metadata() {
        tokio::time::timeout(Duration::from_secs(4), async {
            let access = Arc::new(Access(std::sync::Mutex::new(Vec::new())));
            let (a, mut b) = tokio::io::duplex(256);
            let cancel = CancellationToken::new();
            let context = InboundContext {
                peer_lease: None,
                tasks: kerlico_core::NodeTasks::new(
                    kerlico_core::NodeId::parse("test-node").unwrap(),
                    kerlico_core::CancellationToken::new(),
                ),
                peer_addr: None,
                local_addr: None,
                cancel: cancel.clone(),
                connect_timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(2),
                drain_timeout: Duration::from_millis(100),
                max_datagram_size: MAX_PAYLOAD,
                max_streams: 8,
                stream_budget: kerlico_core::StreamBudget::new(
                    Arc::new(tokio::sync::Semaphore::new(8)),
                    Arc::new(tokio::sync::Semaphore::new(8)),
                ),
                events: Arc::new(Observer),
            };
            let running = tokio::spawn(serve_test(Box::new(a), access.clone(), context, 2));
            let first = endpoint("0.0.0.0:1111");
            let second = endpoint("0.0.0.0:2222");
            let t1 = endpoint("192.0.2.1:53");
            let t2 = endpoint("192.0.2.2:54");
            for (source, target, data) in [
                (first, t1, b"".as_slice()),
                (second, t2, b"second".as_slice()),
            ] {
                b.write_all(&encode(source, target, Some(""), data, MAX_PAYLOAD).unwrap())
                    .await
                    .unwrap();
            }
            let mut replies = Vec::new();
            for _ in 0..2 {
                replies.push(read(&mut b, false, MAX_PAYLOAD).await.unwrap().unwrap());
            }
            replies.sort_by_key(|p| p.target.specified().unwrap().port());
            assert_eq!(replies[0].target, first);
            assert_eq!(replies[0].source, endpoint("192.0.2.99:53"));
            assert!(replies[0].data.is_empty());
            assert_eq!(replies[1].target, second);
            assert_eq!(replies[1].source, endpoint("192.0.2.99:54"));
            assert_eq!(replies[1].data, b"second");
            assert_eq!(access.0.lock().unwrap().len(), 2);
            b.write_all(
                &encode(
                    endpoint("0.0.0.0:3333"),
                    endpoint("192.0.2.3:55"),
                    Some(""),
                    b"over-budget",
                    MAX_PAYLOAD,
                )
                .unwrap(),
            )
            .await
            .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), read(&mut b, false, MAX_PAYLOAD))
                    .await
                    .is_err()
            );
            assert_eq!(access.0.lock().unwrap().len(), 2);
            cancel.cancel();
            assert!(matches!(running.await.unwrap(), Err(Error::Cancelled)));
        })
        .await
        .unwrap();
    }
    struct NoDns;
    impl kerlico_egress::Resolver for NoDns {
        fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
            Box::pin(async { panic!("远端目标不得本地解析") })
        }
    }
    fn observed_context() -> (PeerSession, kerlico_egress::Telemetry, InboundContext) {
        let input = kerlico_config::NodeBuildContext::local_for_test(serde_json::json!({}));
        let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            Arc::new(Access(std::sync::Mutex::new(Vec::new()))),
            kerlico_core::TargetPolicy::Remote,
            kerlico_core::FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let mut context = context(
            CancellationToken::new(),
            Arc::new(tokio::sync::Semaphore::new(8)),
            Arc::new(tokio::sync::Semaphore::new(8)),
        );
        context.idle_timeout = Duration::from_millis(100);
        (ingress.local(&context).unwrap(), telemetry, context)
    }
    #[tokio::test]
    async fn parent_idle_and_reply_writer_failure_reach_real_flow_records() {
        let (peer, telemetry, context) = observed_context();
        let flows = crate::flow::FlowSet::new(8, context.cancel.clone());
        let (server, mut client) = tokio::io::duplex(1024);
        let task = tokio::spawn(super::serve(Box::new(server), peer, context, 8, flows));
        client
            .write_all(
                &encode(
                    Endpoint::Unknown,
                    endpoint("192.0.2.99:53"),
                    Some(""),
                    b"payload",
                    MAX_PAYLOAD,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            read(&mut client, false, MAX_PAYLOAD)
                .await
                .unwrap()
                .unwrap()
                .data,
            b"payload"
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Timeout)
        ));
        let records = telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].end, Some(kerlico_egress::FlowEnd::Timeout));
        assert_eq!(records[0].usage.upload_bytes, 7);
        assert_eq!(records[0].usage.download_bytes, 7);
        assert_eq!(records[0].usage.upload_packets, 1);
        assert_eq!(records[0].usage.download_packets, 1);

        let (peer, telemetry, context) = observed_context();
        let flows = crate::flow::FlowSet::new(8, context.cancel.clone());
        let input = encode(
            Endpoint::Unknown,
            endpoint("192.0.2.99:53"),
            Some(""),
            b"reply",
            MAX_PAYLOAD,
        )
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            super::serve(
                Box::new(RejectReply { input, used: 0 }),
                peer,
                context,
                8,
                flows,
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(Error::Io(_))));
        let records = telemetry.records(0, 8).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].end, Some(kerlico_egress::FlowEnd::Failed));
        assert_eq!(records[0].usage.download_bytes, 5);
    }
    struct RejectReply {
        input: Vec<u8>,
        used: usize,
    }
    impl tokio::io::AsyncRead for RejectReply {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.used == this.input.len() {
                return std::task::Poll::Pending;
            }
            let count = buffer.remaining().min(this.input.len() - this.used);
            buffer.put_slice(&this.input[this.used..this.used + count]);
            this.used += count;
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl tokio::io::AsyncWrite for RejectReply {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
