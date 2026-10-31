//! _udp2 仅复用独立固定 flow；不提供同 socket 多目标关联。
use crate::protocol;
use kerlico_core::{
    AccessService, Address, BoxFuture, BoxStream, CancellationToken, ConnectContext,
    DatagramChannel, DatagramReceiver, DatagramSender, Destination, Error, InboundContext,
    NodeEvent, Result,
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
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    pub source: SocketAddr,
    pub target: SocketAddr,
    pub data: Vec<u8>,
}
pub(crate) fn encode(
    source: SocketAddr,
    target: SocketAddr,
    app: Option<&str>,
    data: &[u8],
    maximum: usize,
) -> Result<Vec<u8>> {
    if data.len() > maximum.min(MAX_PAYLOAD)
        || app.is_some_and(|a| a.len() > 255 || a.chars().any(char::is_control))
    {
        return Err(Error::ResourceLimit);
    }
    let size = 36 + app.map_or(0, |s| s.len() + 1) + data.len();
    let mut out = Vec::with_capacity(4 + size);
    out.extend_from_slice(&(size as u32).to_be_bytes());
    put_ip(source.ip(), &mut out)?;
    out.extend_from_slice(&source.port().to_be_bytes());
    put_ip(target.ip(), &mut out)?;
    out.extend_from_slice(&target.port().to_be_bytes());
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
    let source = SocketAddr::new(ip(&bytes[..16]), u16::from_be_bytes([bytes[16], bytes[17]]));
    let target = SocketAddr::new(
        ip(&bytes[18..34]),
        u16::from_be_bytes([bytes[34], bytes[35]]),
    );
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
    source: SocketAddr,
    target: SocketAddr,
    app: String,
    idle: Duration,
    state: Arc<Shared>,
}
struct Receive {
    read: tokio::io::ReadHalf<BoxStream>,
    source: SocketAddr,
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
    let source = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        rand::random::<u16>().max(1),
    );
    let (read, write) = tokio::io::split(io);
    let state = Arc::new(Shared {
        cancel: cancel.child_token(),
        _slot: slot,
    });
    Ok(DatagramChannel {
        sender: Box::new(Send {
            write,
            source,
            target,
            app,
            idle,
            state: state.clone(),
        }),
        receiver: Box::new(Receive {
            read,
            source,
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
                self.source,
                self.target,
                Some(&self.app),
                packet,
                MAX_PAYLOAD,
            )?;
            let context = ConnectContext {
                cancel: self.state.cancel.clone(),
                timeout: self.idle,
            };
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
            let context = ConnectContext {
                cancel: self.state.cancel.clone(),
                timeout: self.idle,
            };
            let result = context
                .run(async {
                    let Some(packet) = read(&mut self.read, false, MAX_PAYLOAD).await? else {
                        return Ok(None);
                    };
                    let zero = packet.target.ip().is_unspecified() && packet.target.port() == 0;
                    if packet.source != self.target || (!zero && packet.target != self.source) {
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
pub(crate) async fn serve(
    io: BoxStream,
    access: Arc<dyn AccessService>,
    context: InboundContext,
    maximum_flows: usize,
) -> Result<()> {
    let (read_half, mut write) = tokio::io::split(io);
    let mut read_half = read_half;
    let cancel = context.cancel.child_token();
    let _scope = Scope(cancel.clone());
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
    let mut tasks = JoinSet::new();
    let token = cancel.clone();
    let idle = context.idle_timeout;
    tasks.spawn(async move{loop{let bytes=tokio::select!{biased;_=token.cancelled()=>break,value=rx.recv()=>match value{Some(v)=>v,None=>break}};let result=tokio::time::timeout(idle,async{write.write_all(&bytes).await?;write.flush().await}).await;if !matches!(result,Ok(Ok(()))){token.cancel();break;}}});
    let (activity, mut observed) = watch::channel(Instant::now());
    let mut flows = HashMap::<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>::new();
    loop {
        while tasks.try_join_next().is_some() {}
        let packet = match active_read(
            &mut read_half,
            context.max_datagram_size,
            context.idle_timeout,
            &mut observed,
            &cancel,
        )
        .await?
        {
            Some(packet) => packet,
            None => break,
        };
        activity.send_replace(Instant::now());
        if packet.target.port() == 0 || packet.source.port() == 0 {
            return Err(protocol());
        }
        flows.retain(|_, tx| !tx.is_closed());
        let key = (packet.source, packet.target);
        if let Some(tx) = flows.get(&key) {
            if tx.try_send(packet.data).is_err() {
                context.events.record(NodeEvent::Dropped);
            }
            continue;
        }
        if context.stream_budget.is_closed() || flows.len() >= maximum_flows {
            context.events.record(NodeEvent::Dropped);
            continue;
        }
        let lease = match context.stream_budget.try_acquire() {
            Ok(v) => v,
            Err(_) => {
                context.events.record(NodeEvent::Dropped);
                continue;
            }
        };
        let target = Destination::new(&packet.target.ip().to_string(), packet.target.port())?;
        let connect = ConnectContext {
            cancel: cancel.clone(),
            timeout: context.connect_timeout,
        };
        let channel = match connect.run(access.connect_udp(&target, &connect)).await {
            Ok(v) => v,
            Err(_) => {
                context.events.record(NodeEvent::Failed);
                continue;
            }
        };
        let Some(peer) = channel.receiver.peer_addr() else {
            return Err(Error::Unsupported("TrustTunnel UDP 出口缺少真实业务来源"));
        };
        let peer = literal(&peer)?;
        let (mut sender, mut receiver) = (channel.sender, channel.receiver);
        let (packets, mut incoming) = mpsc::channel::<Vec<u8>>(8);
        packets
            .try_send(packet.data)
            .map_err(|_| Error::ResourceLimit)?;
        flows.insert(key, packets);
        let replies = tx.clone();
        let token = cancel.clone();
        let max = context.max_datagram_size;
        let idle = context.idle_timeout;
        let events = context.events.clone();
        let activity = activity.clone();
        tasks.spawn(async move{let _lease=lease;let timer=tokio::time::sleep(idle);tokio::pin!(timer);loop{let result=tokio::select!{biased;_=token.cancelled()=>break,_=&mut timer=>break,packet=incoming.recv()=>match packet{Some(bytes)=>{let result=tokio::select!{_=token.cancelled()=>break,r=tokio::time::timeout(idle,sender.send(&bytes))=>r};matches!(result,Ok(Ok(())))},None=>break},packet=receiver.recv()=>match packet{Ok(Some(bytes))=>{activity.send_replace(Instant::now());match encode(peer,key.0,None,&bytes,max){Ok(bytes)=>{if replies.try_send(bytes).is_err(){events.record(NodeEvent::Dropped);}true},Err(_)=>{events.record(NodeEvent::Dropped);true}}},_=>break}};if !result{break;}timer.as_mut().reset(tokio::time::Instant::now()+idle);}});
    }
    cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn zero_packet_ipv6_and_split_records_are_not_eof() {
        for host in ["127.0.0.1", "::1"] {
            let src = "0.0.0.0:19".parse().unwrap();
            let dst = SocketAddr::new(host.parse().unwrap(), 53);
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
        let a = "127.0.0.1:53".parse().unwrap();
        assert!(encode(a, a, Some(""), &vec![0; MAX_PAYLOAD + 1], MAX_PAYLOAD).is_err());
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
    impl AccessService for Access {
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<BoxStream>> {
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
    #[tokio::test]
    async fn one_http_stream_has_separate_budgeted_flows_and_uses_access_peer_metadata() {
        tokio::time::timeout(Duration::from_secs(4), async {
            let access = Arc::new(Access(std::sync::Mutex::new(Vec::new())));
            let (a, mut b) = tokio::io::duplex(256);
            let cancel = CancellationToken::new();
            let context = InboundContext {
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
            let running = tokio::spawn(serve(Box::new(a), access.clone(), context, 2));
            let first = "0.0.0.0:1111".parse().unwrap();
            let second = "0.0.0.0:2222".parse().unwrap();
            let t1 = "192.0.2.1:53".parse().unwrap();
            let t2 = "192.0.2.2:54".parse().unwrap();
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
            replies.sort_by_key(|p| p.target.port());
            assert_eq!(replies[0].target, first);
            assert_eq!(replies[0].source, "192.0.2.99:53".parse().unwrap());
            assert!(replies[0].data.is_empty());
            assert_eq!(replies[1].target, second);
            assert_eq!(replies[1].source, "192.0.2.99:54".parse().unwrap());
            assert_eq!(replies[1].data, b"second");
            assert_eq!(access.0.lock().unwrap().len(), 2);
            b.write_all(
                &encode(
                    "0.0.0.0:3333".parse().unwrap(),
                    "192.0.2.3:55".parse().unwrap(),
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
}
