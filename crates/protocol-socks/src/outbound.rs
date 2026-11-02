use crate::{
    config::{self, Auth, OutOptions, Version},
    wire,
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    Address, AddressedDatagram, BoxFuture, CancellationToken, Capabilities, ConnectContext,
    DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel,
    DatagramReceiver, DatagramSender, Destination, Error, Outbound, Result, ServiceContext,
    ServiceTask, TargetPolicy,
};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

struct SocksOutbound {
    server: Destination,
    version: Version,
    auth: Option<Auth>,
    userid: String,
    host: ServiceContext,
    tasks: Mutex<Vec<ServiceTask<()>>>,
}

async fn negotiate(stream: &mut TcpStream, auth: &Option<Auth>) -> Result<()> {
    let method = if auth.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;
    if response != [5, method] {
        return Err(Error::Rejected);
    }
    if let Some(auth) = auth {
        let mut bytes = vec![1, auth.username.len() as u8];
        bytes.extend(auth.username.as_bytes());
        bytes.push(auth.password.len() as u8);
        bytes.extend(auth.password.as_bytes());
        stream.write_all(&bytes).await?;
        stream.read_exact(&mut response).await?;
        if response != [1, 0] {
            return Err(Error::Rejected);
        }
    }
    Ok(())
}

async fn reply(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut bytes = [0; 3];
    stream.read_exact(&mut bytes).await?;
    if bytes[0] != 5 || bytes[2] != 0 {
        return Err(wire::invalid());
    }
    if bytes[1] != 0 {
        return Err(Error::Rejected);
    }
    wire::read_address(stream).await
}
fn reported_bind(host: &str, port: u16) -> Result<kerlico_core::TcpConnectInfo> {
    if port == 0 {
        return Ok(kerlico_core::TcpConnectInfo::unknown());
    }
    Ok(kerlico_core::TcpConnectInfo::peer_reported_bound(
        Destination::new(host, port)?,
    ))
}

impl Outbound for SocksOutbound {
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.host.cancel().cancel();
            let tasks = self
                .tasks
                .lock()
                .map(|mut tasks| std::mem::take(&mut *tasks))
                .map_err(|_| wire::invalid())?;
            for task in tasks {
                let _ = task.await;
            }
            Ok(())
        })
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: self.version == Version::Five,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            context
                .run(async {
                    let mut stream =
                        TcpStream::connect((self.server.host().as_str(), self.server.port()))
                            .await?;
                    stream.set_nodelay(true)?;
                    let info = if self.version == Version::Five {
                        negotiate(&mut stream, &self.auth).await?;
                        let mut request = vec![5, 1, 0];
                        wire::encode(target, &mut request);
                        stream.write_all(&request).await?;
                        let (host, port) = reply(&mut stream).await?;
                        reported_bind(&host, port)?
                    } else {
                        let mut domain = None;
                        let ip = match target.address() {
                            Address::Ip(IpAddr::V4(ip)) => *ip,
                            Address::Ip(IpAddr::V6(_)) => {
                                return Err(Error::Unsupported("SOCKS4/4a 不支持 IPv6 目标"));
                            }
                            Address::Domain(name) if self.version == Version::FourA => {
                                domain = Some(name.as_bytes());
                                Ipv4Addr::new(0, 0, 0, 1)
                            }
                            Address::Domain(_) => {
                                return Err(Error::Unsupported(
                                    "SOCKS4 不能透传域名目标，请使用 SOCKS4a 或 SOCKS5",
                                ));
                            }
                        };
                        let mut request = vec![4, 1];
                        request.extend(target.port().to_be_bytes());
                        request.extend(ip.octets());
                        request.extend(self.userid.as_bytes());
                        request.push(0);
                        if let Some(name) = domain {
                            request.extend(name);
                            request.push(0);
                        }
                        stream.write_all(&request).await?;
                        let mut response = [0; 8];
                        stream.read_exact(&mut response).await?;
                        if response[0] != 0 || response[1] != 90 {
                            return Err(Error::Rejected);
                        }
                        let port = u16::from_be_bytes([response[2], response[3]]);
                        let address =
                            Ipv4Addr::new(response[4], response[5], response[6], response[7]);
                        reported_bind(&address.to_string(), port)?
                    };
                    Ok(kerlico_core::OpenedTcp {
                        stream: Box::new(stream),
                        info,
                    })
                })
                .await
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            if self.version != Version::Five {
                return Err(Error::Unsupported("SOCKS4/4a 不支持 UDP"));
            }
            context
                .run(async {
                    let mut stream =
                        TcpStream::connect((self.server.host().as_str(), self.server.port()))
                            .await?;
                    stream.set_nodelay(true)?;
                    let peer = stream.peer_addr()?;
                    let local = stream.local_addr()?;
                    negotiate(&mut stream, &self.auth).await?;
                    // 使用全零地址让服务端从控制连接确定来源，并固定首个合法 UDP 端口。
                    stream.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    let (host, port) = reply(&mut stream).await?;
                    if port == 0 {
                        return Err(wire::invalid());
                    }
                    let relay = match host.parse::<IpAddr>() {
                        Ok(ip) => {
                            SocketAddr::new(if ip.is_unspecified() { peer.ip() } else { ip }, port)
                        }
                        Err(_) => tokio::net::lookup_host((host.as_str(), port))
                            .await?
                            .min_by_key(|addr| addr.is_ipv4() != peer.is_ipv4())
                            .ok_or(Error::InvalidAddress)?,
                    };
                    let bind_ip = if relay.is_ipv4() == local.is_ipv4() {
                        local.ip()
                    } else if relay.is_ipv4() {
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    } else {
                        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                    };
                    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
                    socket.connect(relay).await?;
                    let cancel = context.cancel.child_token();
                    let stopped = cancel.clone();
                    let service = self.host.cancel();
                    let task = self.host.spawn_tracked(async move {
                        let mut byte = [0];
                        tokio::select! { _=stopped.cancelled()=>{}, _=service.cancelled()=>{}, _=stream.read(&mut byte)=>{} }
                        stopped.cancel();
                    })?;
                    { let mut tasks = self.tasks.lock().map_err(|_|wire::invalid())?; tasks.retain(|task|!task.is_finished()); tasks.push(task); }
                    let guard = Arc::new(Control { cancel });
                    let socket = Arc::new(socket);
                    Ok(DatagramAssociation {
                        sender: Box::new(AssociationSender {
                            socket: socket.clone(),
                            control: guard.clone(),
                        }),
                        receiver: Box::new(AssociationReceiver {
                            socket,
                            control: guard,
                        }),
                    })
                })
                .await
        })
    }
    fn supports_udp_association(&self) -> bool {
        self.version == Version::Five
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let association = self.associate_udp(context).await?;
            Ok(DatagramChannel {
                sender: Box::new(FixedSender {
                    inner: association.sender,
                    target: target.clone(),
                }),
                receiver: Box::new(FixedReceiver {
                    inner: association.receiver,
                    target: target.clone(),
                    last: None,
                }),
            })
        })
    }
}

struct Control {
    cancel: CancellationToken,
}
impl Drop for Control {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct AssociationSender {
    socket: Arc<UdpSocket>,
    control: Arc<Control>,
}
struct AssociationReceiver {
    socket: Arc<UdpSocket>,
    control: Arc<Control>,
}
impl DatagramAssociationSender for AssociationSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let bytes = wire::datagram(target, packet)?;
            tokio::select! { biased; _=self.control.cancel.cancelled()=>Err(Error::Cancelled), result=self.socket.send(&bytes)=>{ result?; Ok(()) } }
        })
    }
}
impl DatagramAssociationReceiver for AssociationReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 65535];
            loop {
                let count = tokio::select! { biased; _=self.control.cancel.cancelled()=>return Ok(None), result=self.socket.recv(&mut bytes)=>result? };
                if let Ok((source, payload)) = wire::packet(&bytes[..count]) {
                    return Ok(Some((source, payload.to_vec())));
                }
            }
        })
    }
}
struct FixedSender {
    inner: Box<dyn DatagramAssociationSender>,
    target: Destination,
}
struct FixedReceiver {
    inner: Box<dyn DatagramAssociationReceiver>,
    target: Destination,
    last: Option<Destination>,
}
impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.inner.send_to(bytes, &self.target)
    }
}
impl DatagramReceiver for FixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        self.last.clone()
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            loop {
                let Some((source, payload)) = self.inner.recv_from().await? else {
                    return Ok(None);
                };
                if source == self.target
                    || matches!(self.target.address(), Address::Domain(_))
                        && source.port() == self.target.port()
                {
                    self.last = Some(source);
                    return Ok(Some(payload));
                }
            }
        })
    }
}
pub struct SocksFactory;
impl OutboundFactory for SocksFactory {
    fn kind(&self) -> &'static str {
        "socks"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: OutOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("SOCKS 出站字段不合法".into()))?;
        config::validate(options.version, &options.auth, &options.userid)?;
        let server = options.server.destination()?;
        let capabilities = Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: options.version == Version::Five,
        };
        Ok(OutboundPlan::new(
            capabilities,
            options.version == Version::Five,
            TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(SocksOutbound {
                        server,
                        version: options.version,
                        auth: options.auth,
                        userid: options.userid,
                        host,
                        tasks: Mutex::new(Vec::new()),
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}
