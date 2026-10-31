use crate::{
    config::{self, Auth, OutOptions, Version},
    wire,
};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    Address, BoxFuture, BoxStream, CancellationToken, Capabilities, ConnectContext,
    DatagramChannel, DatagramReceiver, DatagramSender, Destination, Error, Outbound, Result,
};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    task::JoinHandle,
};

struct SocksOutbound {
    server: Destination,
    version: Version,
    auth: Option<Auth>,
    userid: String,
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

impl Outbound for SocksOutbound {
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
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let mut stream =
                        TcpStream::connect((self.server.host().as_str(), self.server.port()))
                            .await?;
                    stream.set_nodelay(true)?;
                    if self.version == Version::Five {
                        negotiate(&mut stream, &self.auth).await?;
                        let mut request = vec![5, 1, 0];
                        wire::encode(target, &mut request);
                        stream.write_all(&request).await?;
                        reply(&mut stream).await?;
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
                                tokio::net::lookup_host((target.host().as_str(), target.port()))
                                    .await?
                                    .find_map(|addr| match addr.ip() {
                                        IpAddr::V4(ip) => Some(ip),
                                        _ => None,
                                    })
                                    .ok_or(Error::InvalidAddress)?
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
                    }
                    Ok(Box::new(stream) as BoxStream)
                })
                .await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
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
                    let task = tokio::spawn(async move {
                        let mut byte = [0];
                        tokio::select! { _=stopped.cancelled()=>{}, _=stream.read(&mut byte)=>{} }
                        stopped.cancel();
                    });
                    let guard = Arc::new(Control { task, cancel });
                    let socket = Arc::new(socket);
                    Ok(DatagramChannel {
                        sender: Box::new(Sender {
                            socket: socket.clone(),
                            target: target.clone(),
                            control: guard.clone(),
                        }),
                        receiver: Box::new(Receiver {
                            socket,
                            target: target.clone(),
                            control: guard,
                        }),
                    })
                })
                .await
        })
    }
}

struct Control {
    task: JoinHandle<()>,
    cancel: CancellationToken,
}
impl Drop for Control {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
struct Sender {
    socket: Arc<UdpSocket>,
    target: Destination,
    control: Arc<Control>,
}
struct Receiver {
    socket: Arc<UdpSocket>,
    target: Destination,
    control: Arc<Control>,
}
impl DatagramSender for Sender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let bytes = wire::datagram(&self.target, packet)?;
            tokio::select! {biased;_=self.control.cancel.cancelled()=>Err(Error::Cancelled),result=self.socket.send(&bytes)=>{result?;Ok(())}}
        })
    }
}
impl DatagramReceiver for Receiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 65_535];
            loop {
                let count = tokio::select! {biased;_=self.control.cancel.cancelled()=>return Ok(None),result=self.socket.recv(&mut bytes)=>result?};
                if let Ok((target, payload)) = wire::packet(&bytes[..count]) {
                    if target == self.target {
                        return Ok(Some(payload.to_vec()));
                    }
                    // 域名目标的回复可以使用服务端实际访问的 IP 地址。
                    if matches!(self.target.address(), Address::Domain(_))
                        && target.port() == self.target.port()
                        && matches!(target.address(), Address::Ip(_))
                    {
                        return Ok(Some(payload.to_vec()));
                    }
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
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        let options: OutOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("SOCKS 出站字段不合法".into()))?;
        config::validate(options.version, &options.auth, &options.userid)?;
        Ok(Arc::new(SocksOutbound {
            server: options.server.destination()?,
            version: options.version,
            auth: options.auth,
            userid: options.userid,
        }))
    }
}
