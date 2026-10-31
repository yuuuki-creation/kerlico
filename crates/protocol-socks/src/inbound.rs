use crate::{
    config::{self, Auth, NodeOptions, Version},
    wire,
};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, DatagramSender, Destination, Error,
    InboundContext, InboundProtocol, NodeEvent, Result,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, watch},
    task::JoinSet,
};

struct SocksNode {
    version: Version,
    auth: Option<Auth>,
    userid: String,
}

struct TargetSender {
    sender: Box<dyn DatagramSender>,
    activity: watch::Sender<tokio::time::Instant>,
}
fn budget(context: &InboundContext) -> ConnectContext {
    ConnectContext {
        cancel: context.cancel.clone(),
        timeout: context.connect_timeout,
    }
}
async fn response(stream: &mut BoxStream, code: u8, address: SocketAddr) -> Result<()> {
    let mut bytes = vec![5, code, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(address.port().to_be_bytes());
    stream.write_all(&bytes).await?;
    Ok(())
}
fn failure(error: &Error) -> u8 {
    match error {
        Error::Rejected => 2,
        Error::InvalidAddress => 8,
        Error::Timeout => 6,
        Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => 5,
        _ => 1,
    }
}

impl SocksNode {
    async fn authenticate(&self, stream: &mut BoxStream) -> Result<()> {
        if stream.read_u8().await? != 5 {
            return Err(wire::invalid());
        }
        let count = stream.read_u8().await?;
        let mut methods = vec![0; usize::from(count)];
        stream.read_exact(&mut methods).await?;
        let selected = if self.auth.is_some() { 2 } else { 0 };
        if !methods.contains(&selected) {
            stream.write_all(&[5, 255]).await?;
            return Err(Error::Rejected);
        }
        stream.write_all(&[5, selected]).await?;
        if let Some(auth) = &self.auth {
            if stream.read_u8().await? != 1 {
                return Err(wire::invalid());
            }
            let count = stream.read_u8().await?;
            let mut username = vec![0; usize::from(count)];
            stream.read_exact(&mut username).await?;
            let count = stream.read_u8().await?;
            let mut password = vec![0; usize::from(count)];
            stream.read_exact(&mut password).await?;
            let valid = config::equal(&username, auth.username.as_bytes())
                & config::equal(&password, auth.password.as_bytes());
            stream.write_all(&[1, u8::from(!valid)]).await?;
            if !valid {
                return Err(Error::Rejected);
            }
        }
        Ok(())
    }

    async fn five(
        &self,
        mut stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let handshake = budget(&context);
        let (command, host, port) = handshake
            .run(async {
                self.authenticate(&mut stream).await?;
                let mut header = [0; 3];
                stream.read_exact(&mut header).await?;
                if header[0] != 5 || header[2] != 0 {
                    return Err(wire::invalid());
                }
                let (host, port) = match wire::read_address(&mut *stream).await {
                    Ok(address) => address,
                    Err(error) => {
                        response(&mut stream, 8, SocketAddr::from(([0, 0, 0, 0], 0))).await?;
                        return Err(error);
                    }
                };
                Ok((header[1], host, port))
            })
            .await?;
        if command == 3 {
            return self.udp(stream, &host, port, access, context).await;
        }
        if command != 1 {
            response(&mut stream, 7, SocketAddr::from(([0, 0, 0, 0], 0))).await?;
            return Err(Error::Unsupported("SOCKS 请求命令未实现"));
        }
        let target = match Destination::new(&host, port) {
            Ok(target) => target,
            Err(error) => {
                handshake
                    .run(response(
                        &mut stream,
                        8,
                        SocketAddr::from(([0, 0, 0, 0], 0)),
                    ))
                    .await?;
                return Err(error);
            }
        };
        let remote = match handshake.run(access.connect_tcp(&target, &handshake)).await {
            Ok(remote) => remote,
            Err(error) => {
                handshake
                    .run(response(
                        &mut stream,
                        failure(&error),
                        SocketAddr::from(([0, 0, 0, 0], 0)),
                    ))
                    .await?;
                return Err(error);
            }
        };
        // AccessService 不暴露目标 socket 地址；用零地址表示当前不可报告的绑定地址。
        handshake
            .run(response(
                &mut stream,
                0,
                SocketAddr::from(([0, 0, 0, 0], 0)),
            ))
            .await?;
        kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
    }

    async fn four(
        &self,
        mut stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let handshake = budget(&context);
        let remote = handshake
            .run(async {
                let mut header = [0; 8];
                stream.read_exact(&mut header).await?;
                let userid = wire::cstring(&mut *stream, 255).await?;
                let port = u16::from_be_bytes([header[2], header[3]]);
                let extension = header[4..7] == [0, 0, 0] && header[7] != 0;
                let host = if extension && self.version == Version::FourA {
                    String::from_utf8(wire::cstring(&mut *stream, 255).await?)
                        .map_err(|_| wire::invalid())?
                } else {
                    Ipv4Addr::new(header[4], header[5], header[6], header[7]).to_string()
                };
                if header[0] != 4
                    || header[1] != 1
                    || (extension && self.version != Version::FourA)
                    || !config::equal(&userid, self.userid.as_bytes())
                {
                    stream.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await?;
                    return Err(Error::Rejected);
                }
                let target = Destination::new(&host, port)?;
                match access.connect_tcp(&target, &handshake).await {
                    Ok(remote) => {
                        stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await?;
                        Ok(remote)
                    }
                    Err(error) => {
                        stream.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await?;
                        Err(error)
                    }
                }
            })
            .await?;
        kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
    }

    async fn udp(
        &self,
        mut stream: BoxStream,
        host: &str,
        port: u16,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let peer = context
            .peer_addr
            .ok_or(Error::Unsupported("SOCKS UDP 关联需要 TCP 对端地址"))?;
        let local = context
            .local_addr
            .ok_or(Error::Unsupported("SOCKS UDP 关联需要 TCP 本地地址"))?;
        let claimed: IpAddr = host.parse().map_err(|_| wire::invalid())?;
        if !claimed.is_unspecified() && claimed != peer.ip() {
            response(&mut stream, 2, SocketAddr::new(local.ip(), 0)).await?;
            return Err(Error::Rejected);
        }
        let socket = UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?;
        budget(&context)
            .run(response(&mut stream, 0, socket.local_addr()?))
            .await?;
        let mut source = if port == 0 {
            None
        } else {
            Some(SocketAddr::new(peer.ip(), port))
        };
        let mut control = [0; 1];
        let mut bytes = vec![0; 65_535];
        let mut senders: HashMap<Destination, TargetSender> = HashMap::new();
        let (events, mut received) =
            mpsc::channel::<(Destination, Option<Vec<u8>>)>(context.max_streams.max(1));
        let mut tasks = JoinSet::new();
        let mut deadline = tokio::time::Instant::now() + context.idle_timeout;
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            let mut activity = false;
            let operation = async {
                tokio::select! {
                    biased;
                    _=context.cancel.cancelled()=>return Err(Error::Cancelled),
                    result=stream.read(&mut control)=>{let count=result?; if count==0{return Ok(false);}return Err(wire::invalid());},
                    Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if result.is_err(){return Err(Error::Protocol("SOCKS UDP 回包任务异常"));}},
                    Some((target,payload))=received.recv()=>{
                        match payload {
                            None=>{senders.remove(&target);},
                            Some(payload)=>if let Some(source)=source && let Ok(packet)=wire::datagram(&target,&payload){socket.send_to(&packet,source).await?;activity=true;},
                        }
                    },
                    result=socket.recv_from(&mut bytes)=>{
                        let (count,from)=result?;
                        if from.ip()!=peer.ip() || source.is_some_and(|expected|expected!=from) {context.events.record(NodeEvent::Dropped);return Ok(true);}
                        let (target,payload)=match wire::packet(&bytes[..count]) {Ok(packet)=>packet,Err(_)=>{context.events.record(NodeEvent::Dropped);return Ok(true);}};
                        if payload.len()>context.max_datagram_size {context.events.record(NodeEvent::Dropped);return Ok(true);}
                        if source.is_none(){source=Some(from);}
                        if !senders.contains_key(&target) {
                            if senders.len()>=context.max_streams {context.events.record(NodeEvent::Dropped);return Ok(true);}
                            let lease=match context.stream_budget.try_acquire(){Ok(lease)=>lease,Err(_)=>{context.events.record(NodeEvent::Dropped);return Ok(true);}};
                            let connect=budget(&context);
                            let channel=match connect.run(access.connect_udp(&target,&connect)).await {Ok(channel)=>channel,Err(_)=>{context.events.record(NodeEvent::Dropped);return Ok(true);}};
                            let mut receiver=channel.receiver;let events=events.clone();let target=target.clone();let cancel=context.cancel.clone();let idle=context.idle_timeout;let max=context.max_datagram_size;let observer=context.events.clone();
                            let (activity,mut observed)=watch::channel(tokio::time::Instant::now());
                            senders.insert(target.clone(),TargetSender {sender:channel.sender,activity});
                            tasks.spawn(async move {
                                let _lease=lease;
                                let timer=tokio::time::sleep(idle);tokio::pin!(timer);
                                'session: loop {
                                    let packet={
                                        // 更新写端活动只重设计时器，不能取消可能已读半帧的接收 future。
                                        let next=receiver.recv();tokio::pin!(next);
                                        loop {
                                            if tokio::time::Instant::now()>=timer.deadline(){break 'session;}
                                            tokio::select! {
                                                biased;
                                                _=cancel.cancelled()=>break 'session,
                                                changed=observed.changed()=>{if changed.is_err(){break 'session;}let next=*observed.borrow_and_update()+idle;let deadline=timer.deadline().max(next);timer.as_mut().reset(deadline);},
                                                result=&mut next=>match result{Ok(Some(packet))=>break packet,_=>break 'session},
                                                _=&mut timer=>break 'session,
                                            }
                                        }
                                    };
                                    if packet.len()>max {observer.record(NodeEvent::Dropped);continue;}
                                    timer.as_mut().reset(tokio::time::Instant::now()+idle);
                                    tokio::select! {biased;_=cancel.cancelled()=>return,_=events.send((target.clone(),Some(packet)))=>{}}
                                }
                                tokio::select! {biased;_=cancel.cancelled()=>{},_=events.send((target,None))=>{}}
                            });
                        }
                        if let Some(sender)=senders.get_mut(&target) {
                            let send=tokio::time::timeout(context.idle_timeout,sender.sender.send(payload));
                            let result=tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),result=send=>result};
                            if !matches!(result,Ok(Ok(()))){context.events.record(NodeEvent::Dropped);return Err(Error::Protocol("SOCKS UDP 目标通道发送失败"));}
                            sender.activity.send_replace(tokio::time::Instant::now());
                            activity=true;
                        }
                    }
                }
                Ok(true)
            };
            match tokio::time::timeout_at(deadline, operation).await {
                Ok(Ok(true)) => {
                    if activity {
                        deadline = tokio::time::Instant::now() + context.idle_timeout;
                    }
                }
                Ok(Ok(false)) => return Ok(()),
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(Error::Timeout),
            }
        }
    }
}

impl InboundProtocol for SocksNode {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.auth
            .as_ref()
            .map(|auth| vec![auth.fingerprint()])
            .unwrap_or_default()
    }
    fn requires_loopback(&self) -> bool {
        self.version != Version::Five || self.auth.is_none()
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.version == Version::Five {
                self.five(stream, access, context).await
            } else {
                self.four(stream, access, context).await
            }
        })
    }
}

pub struct SocksNodeFactory;
impl NodeFactory for SocksNodeFactory {
    fn kind(&self) -> &'static str {
        "socks"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options: NodeOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("SOCKS 节点字段不合法".into()))?;
        config::validate(options.version, &options.auth, &options.userid)?;
        Ok(Arc::new(SocksNode {
            version: options.version,
            auth: options.auth,
            userid: options.userid,
        }))
    }
}
