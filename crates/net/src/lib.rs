//! 共享 TCP/TLS 连接器与基础直连/拒绝处理器。

use kerlico_config::OutboundFactory;
use kerlico_core::{
    Address, BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Outbound, Result, StreamConnector,
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::Deserialize;
use serde_json::Value;
use std::{io::Cursor, sync::Arc};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

/// 可复用的 TCP 或 TLS 客户端连接器；构造阶段不执行网络 I/O。
#[derive(Clone)]
pub struct TcpConnector {
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl TcpConnector {
    /// 是否启用 TLS；不代表已握手，也不代表保留目标写端 EOF。
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }
    /// 构造明文 TCP 连接器，不拨号。
    pub fn plain() -> Self {
        Self { tls: None }
    }
    /// 构造校验服务端名称与证书链的 TLS 连接器，不拨号、不提供客户端证书。
    ///
    /// `ca_pem` 是内存 PEM，存在时追加到内置公共根证书；`None` 仅使用内置根。
    /// 使用显式密码提供方，不修改进程全局提供方。
    pub fn tls(server_name: &str, ca_pem: Option<&str>) -> Result<Self> {
        let provider = rustls::crypto::ring::default_provider();
        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = ca_pem {
            let certs = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
                .collect::<std::io::Result<Vec<_>>>()?;
            if certs.is_empty() {
                return Err(Error::Config("CA PEM 不包含证书".into()));
            }
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|_| Error::Config("CA 证书不合法".into()))?;
            }
        }
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Config("TLS 版本不可用".into()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| Error::Config("TLS 服务端名称不合法".into()))?;
        Ok(Self {
            tls: Some((TlsConnector::from(Arc::new(config)), name)),
        })
    }
    /// 连接端点，启用 TCP_NODELAY，并在配置 TLS 时完成客户端握手。
    ///
    /// 域名由底层连接过程解析；此方法没有内置超时或取消令牌，调用方须包装预算。
    /// [`StreamConnector`] 实现会使用传入的 [`ConnectContext::run`]。
    pub async fn connect(&self, server: &Destination) -> Result<BoxStream> {
        let tcp = TcpStream::connect((server.host().as_str(), server.port())).await?;
        tcp.set_nodelay(true)?;
        match &self.tls {
            Some((connector, name)) => Ok(Box::new(connector.connect(name.clone(), tcp).await?)),
            None => Ok(Box::new(tcp)),
        }
    }
}

impl StreamConnector for TcpConnector {
    fn tcp_eof(&self) -> bool {
        !self.is_tls()
    }
    fn connect_tcp<'a>(
        &'a self,
        endpoint: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move { context.run(self.connect(endpoint)).await })
    }
}

struct Direct;
struct DirectDatagram(Arc<UdpSocket>);

struct DirectAssociation {
    socket: Arc<UdpSocket>,
    cancel: kerlico_core::CancellationToken,
}
impl DatagramAssociationSender for DirectAssociation {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if packet.len() > 65_507 {
                return Err(Error::ResourceLimit);
            }
            let Address::Ip(ip) = target.address() else {
                return Err(Error::Unsupported("多目标直连需要统一出口提供字面 IP"));
            };
            let ip = match ip {
                std::net::IpAddr::V4(ip) => std::net::IpAddr::V6(ip.to_ipv6_mapped()),
                ip => *ip,
            };
            let count = tokio::select! { biased; _ = self.cancel.cancelled() => return Err(Error::Cancelled), result = self.socket.send_to(packet, std::net::SocketAddr::new(ip, target.port())) => result? };
            if count != packet.len() {
                return Err(Error::Protocol("UDP 关联未发送完整数据报"));
            }
            Ok(())
        })
    }
}
impl DatagramAssociationReceiver for DirectAssociation {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<kerlico_core::AddressedDatagram>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 65_535];
            let (count, source) = tokio::select! { biased; _ = self.cancel.cancelled() => return Err(Error::Cancelled), result = self.socket.recv_from(&mut bytes) => result? };
            bytes.truncate(count);
            Ok(Some((
                Destination::new(&source.ip().to_canonical().to_string(), source.port())?,
                bytes,
            )))
        })
    }
}

impl DatagramSender for DirectDatagram {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0.send(packet).await?;
            Ok(())
        })
    }
}

impl DatagramReceiver for DirectDatagram {
    fn peer_addr(&self) -> Option<Destination> {
        let peer = self.0.peer_addr().ok()?;
        Destination::new(&peer.ip().to_string(), peer.port()).ok()
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 65_535];
            let count = self.0.recv(&mut bytes).await?;
            bytes.truncate(count);
            Ok(Some(bytes))
        })
    }
}

impl Outbound for Direct {
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            context
                .run(async {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV6,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )?;
                    socket.set_only_v6(false)?;
                    socket.set_nonblocking(true)?;
                    socket.bind(&std::net::SocketAddr::from(([0u16; 8], 0)).into())?;
                    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
                    Ok(DatagramAssociation {
                        sender: Box::new(DirectAssociation {
                            socket: socket.clone(),
                            cancel: context.cancel.clone(),
                        }),
                        receiver: Box::new(DirectAssociation {
                            socket,
                            cancel: context.cancel.clone(),
                        }),
                    })
                })
                .await
        })
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move { context.run(TcpConnector::plain().connect(target)).await })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            context
                .run(async {
                    let peer = tokio::net::lookup_host((target.host().as_str(), target.port()))
                        .await?
                        .next()
                        .ok_or(Error::InvalidAddress)?;
                    let socket = UdpSocket::bind(if peer.is_ipv6() {
                        "[::]:0"
                    } else {
                        "0.0.0.0:0"
                    })
                    .await?;
                    socket.connect(peer).await?;
                    let socket = Arc::new(socket);
                    Ok(DatagramChannel {
                        sender: Box::new(DirectDatagram(socket.clone())),
                        receiver: Box::new(DirectDatagram(socket)),
                    })
                })
                .await
        })
    }
}

struct Reject;
impl Outbound for Reject {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async { Err(Error::Rejected) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Rejected) })
    }
}

/// 构造直连出站的无网络工厂；只接受空选项，连接阶段才访问网络。
pub struct DirectFactory;
/// 构造策略拒绝出站的无网络工厂；只接受空选项，请求返回 [`Error::Rejected`]。
pub struct RejectFactory;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyOptions {}

fn empty(options: &Value) -> Result<()> {
    serde_json::from_value::<EmptyOptions>(options.clone())
        .map_err(|_| Error::Config("基础处理器不接受额外选项".into()))?;
    Ok(())
}

impl OutboundFactory for DirectFactory {
    fn kind(&self) -> &'static str {
        "direct"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        empty(options)?;
        Ok(Arc::new(Direct))
    }
}
impl OutboundFactory for RejectFactory {
    fn kind(&self) -> &'static str {
        "reject"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        empty(options)?;
        Ok(Arc::new(Reject))
    }
}
