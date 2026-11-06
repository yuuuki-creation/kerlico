//! 共享 TCP/TLS 连接器与基础直连/拒绝处理器。

pub mod fallback;
pub mod generate;
mod insecure_tls;
pub use insecure_tls::{insecure_verifier, warn_insecure_tls};
pub mod lazy_response;
pub mod ntp;
pub mod sing_mux;
pub mod sniff;
pub mod transparent;
pub mod uot;
pub use transparent::{RedirectNodeFactory, TproxyNodeFactory};

use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    Address, BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, OpenedTcp, Outbound, Result, StreamConnector,
    TargetPolicy, TcpConnectInfo,
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::Deserialize;
use serde_json::Value;
use std::{io::Cursor, sync::Arc};
use tokio::net::UdpSocket;
use tokio_rustls::TlsConnector;

/// 可复用的 TCP 或 TLS 客户端连接器；构造阶段不执行网络 I/O。
#[derive(Clone)]
pub struct TcpConnector {
    tls: Option<(TlsConnector, ServerName<'static>)>,
    dialer: kerlico_core::DialerOptions,
}

impl TcpConnector {
    /// 是否启用 TLS；不代表已握手，也不代表保留目标写端 EOF。
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }
    pub fn dialer(&self) -> &kerlico_core::DialerOptions {
        &self.dialer
    }
    /// 构造经 `dialer` 建立 TCP 的明文连接器，不拨号。
    pub fn plain(dialer: kerlico_core::DialerOptions) -> Self {
        Self { tls: None, dialer }
    }
    /// 构造校验服务端名称与证书链的 TLS 连接器，不拨号、不提供客户端证书。
    ///
    /// `ca_pem` 是内存 PEM，存在时追加到内置公共根证书；`None` 仅使用内置根。
    /// 使用显式密码提供方，不修改进程全局提供方。
    pub fn tls(
        server_name: &str,
        ca_pem: Option<&str>,
        dialer: kerlico_core::DialerOptions,
    ) -> Result<Self> {
        Self::tls_mtls(server_name, ca_pem, None, None, dialer)
    }
    /// 构造校验服务端名称与证书链、并可选提供客户端证书的 TLS 连接器。
    pub fn tls_mtls(
        server_name: &str,
        ca_pem: Option<&str>,
        client_cert_pem: Option<&str>,
        client_key_pem: Option<&str>,
        dialer: kerlico_core::DialerOptions,
    ) -> Result<Self> {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
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
        let builder = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Config("TLS 版本不可用".into()))?
            .with_root_certificates(roots);
        let mut config = match (client_cert_pem, client_key_pem) {
            (None, None) => builder.with_no_client_auth(),
            (Some(cert_pem), Some(key_pem)) => {
                let certs = rustls_pemfile::certs(&mut Cursor::new(cert_pem.as_bytes()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                if certs.is_empty() {
                    return Err(Error::Config("客户端证书 PEM 不包含证书".into()));
                }
                let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem.as_bytes()))?
                    .ok_or_else(|| Error::Config("客户端私钥 PEM 不合法".into()))?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|_| Error::Config("客户端证书或私钥不匹配".into()))?
            }
            _ => return Err(Error::Config("客户端证书与私钥必须成对提供".into())),
        };
        config.resumption = rustls::client::Resumption::disabled();
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| Error::Config("TLS 服务端名称不合法".into()))?;
        Ok(Self {
            tls: Some((TlsConnector::from(Arc::new(config)), name)),
            dialer,
        })
    }
    /// 连接端点，启用 TCP_NODELAY，并在配置 TLS 时完成客户端握手。
    ///
    /// 域名由底层连接过程解析；此方法没有内置超时或取消令牌，调用方须包装预算。
    /// [`StreamConnector`] 实现会使用传入的 [`ConnectContext::run`]。
    pub async fn connect(&self, server: &Destination) -> Result<BoxStream> {
        let tcp = self.dialer.connect(server).await?;
        self.handshake(tcp).await
    }
    /// 在已建立的字节流上完成客户端 TLS 握手；明文连接器原样返回。
    pub async fn handshake(&self, stream: BoxStream) -> Result<BoxStream> {
        match &self.tls {
            Some((connector, name)) => {
                let mut tls = connector.connect(name.clone(), stream).await?;
                tls.get_mut().1.set_buffer_limit(Some(68 * 1024));
                Ok(Box::new(ClientTls(tls)))
            }
            None => Ok(stream),
        }
    }
}

struct ClientTls(tokio_rustls::client::TlsStream<BoxStream>);
impl tokio::io::AsyncRead for ClientTls {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let poll = std::pin::Pin::new(&mut this.0).poll_read(cx, out);
        if matches!(poll, std::task::Poll::Ready(Ok(()))) && out.filled().len() > before {
            while out.remaining() >= 16384 {
                let prev = out.filled().len();
                match std::pin::Pin::new(&mut this.0).poll_read(cx, out) {
                    std::task::Poll::Ready(Ok(())) if out.filled().len() > prev => {}
                    _ => break,
                }
            }
        }
        poll
    }
}
impl tokio::io::AsyncWrite for ClientTls {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut total = 0;
        let limit = bytes.len().min(65536);
        while total < limit {
            match std::pin::Pin::new(&mut this.0).poll_write(cx, &bytes[total..limit]) {
                std::task::Poll::Ready(Ok(0)) => break,
                std::task::Poll::Ready(Ok(n)) => total += n,
                std::task::Poll::Pending if total > 0 => break,
                other => return other,
            }
        }
        std::task::Poll::Ready(Ok(total))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
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

struct Direct {
    device: kerlico_core::DeviceLease,
    fallback_delay: std::time::Duration,
}

#[derive(Default)]
struct NativeDevice {
    dialer: kerlico_core::DialerOptions,
}
/// 借用操作系统原生socket提供方，不探测互联网，也不安装或关闭设备服务。
pub fn native_device() -> kerlico_core::DeviceLease {
    kerlico_core::DeviceLease::borrow(Arc::new(NativeDevice::default()))
}
impl kerlico_core::DeviceNetwork for NativeDevice {
    fn connect_tcp(&self, target: std::net::SocketAddr) -> BoxFuture<'_, Result<OpenedTcp>> {
        Box::pin(async move {
            if self.dialer.has_detour() {
                let dest = Destination::new(&target.ip().to_string(), target.port())?;
                let stream = self.dialer.connect(&dest).await?;
                let bound = if target.is_ipv4() {
                    std::net::SocketAddr::from(([0u8; 4], 0))
                } else {
                    std::net::SocketAddr::from(([0u16; 8], 0))
                };
                return Ok(OpenedTcp {
                    stream,
                    info: TcpConnectInfo::local_bound(bound),
                });
            }
            let stream = self.dialer.connect_addr(target).await?;
            let info = TcpConnectInfo::local_bound(stream.local_addr()?);
            Ok(OpenedTcp {
                stream: Box::new(stream),
                info,
            })
        })
    }
    fn connect_udp(&self, target: std::net::SocketAddr) -> BoxFuture<'_, Result<Arc<UdpSocket>>> {
        Box::pin(async move {
            let socket = UdpSocket::from_std(self.dialer.udp_socket_for(target)?)?;
            socket.connect(target).await?;
            Ok(Arc::new(socket))
        })
    }
    fn udp_association(
        &self,
        mode: kerlico_core::FamilyMode,
    ) -> BoxFuture<'_, Result<Arc<UdpSocket>>> {
        Box::pin(async move {
            let socket = if mode == kerlico_core::FamilyMode::V4Only {
                self.dialer
                    .udp_socket(std::net::SocketAddr::from(([0u8; 4], 0)))?
            } else {
                self.dialer
                    .udp_socket_dual(mode == kerlico_core::FamilyMode::V6Only)?
            };
            Ok(Arc::new(UdpSocket::from_std(socket)?))
        })
    }
}
impl Outbound for Direct {
    fn fallback_delay(&self) -> std::time::Duration {
        self.fallback_delay
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.device.target_association(context)
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
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            let Address::Ip(ip) = target.address() else {
                return Err(Error::Unsupported("直连后端只接受调度器已选定的字面目标"));
            };
            context
                .run(
                    self.device
                        .connect_target_tcp(std::net::SocketAddr::new(*ip, target.port()), context),
                )
                .await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let Address::Ip(ip) = target.address() else {
                return Err(Error::Unsupported("直连后端只接受调度器已选定的字面目标"));
            };
            self.device
                .connect_target_udp(std::net::SocketAddr::new(*ip, target.port()), context)
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
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
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
    fn supports_detour(&self) -> bool {
        true
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        empty(options)?;
        let dialer = kerlico_core::current_compile_dialer();
        let bound = dialer.interface.is_some();
        let plan = OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            },
            true,
            TargetPolicy::Local,
            move |host| {
                Box::pin(async move {
                    let fallback_delay = dialer.fallback_delay();
                    let device = if !dialer.is_default() {
                        kerlico_core::DeviceLease::borrow(Arc::new(NativeDevice { dialer }))
                    } else {
                        host.device().unwrap_or_else(native_device)
                    };
                    Ok(Arc::new(Direct {
                        device,
                        fallback_delay,
                    }) as Arc<dyn Outbound>)
                })
            },
        );
        Ok(if bound {
            plan
        } else {
            plan.with_native_targets()
        })
    }
}
impl OutboundFactory for RejectFactory {
    fn kind(&self) -> &'static str {
        "reject"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        empty(options)?;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: false,
                udp: true,
            },
            false,
            TargetPolicy::Remote,
            |_| Box::pin(async { Ok(Arc::new(Reject) as Arc<dyn Outbound>) }),
        ))
    }
}

/// 构造内置 DNS 出站的无网络工厂；将明文 UDP/TCP DNS 查询交给内部解析器处理。
pub struct DnsFactory;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DnsOutboundOptions {
    #[serde(default)]
    servers: Vec<String>,
    #[serde(default)]
    hosts: std::collections::BTreeMap<String, Vec<std::net::IpAddr>>,
}

/// 未配 `servers`/`hosts` 时 `engine` 为真：调度器把报文交给引擎 DNS 管线，
/// 直接调用本出站时用系统上游。
struct DnsOutbound {
    resolver: Arc<kerlico_dns::DnsResolver>,
    engine: bool,
    host: kerlico_core::ServiceContext,
}

struct DnsFixedSender {
    resolver: Arc<kerlico_dns::DnsResolver>,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl kerlico_core::DatagramSender for DnsFixedSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        let resolver = self.resolver.clone();
        let tx = self.tx.clone();
        Box::pin(async move {
            let reply = resolver.exchange_packet(packet).await?;
            tx.send(reply)
                .await
                .map_err(|_| Error::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        })
    }
}

struct DnsFixedReceiver {
    target: Destination,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl kerlico_core::DatagramReceiver for DnsFixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move { Ok(self.rx.recv().await) })
    }
}

struct DnsAssocSender {
    resolver: Arc<kerlico_dns::DnsResolver>,
    tx: tokio::sync::mpsc::Sender<(Destination, Vec<u8>)>,
}

impl kerlico_core::DatagramAssociationSender for DnsAssocSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        let resolver = self.resolver.clone();
        let tx = self.tx.clone();
        let target = target.clone();
        Box::pin(async move {
            let reply = resolver.exchange_packet(packet).await?;
            tx.send((target, reply))
                .await
                .map_err(|_| Error::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        })
    }
}

struct DnsAssocReceiver {
    rx: tokio::sync::mpsc::Receiver<(Destination, Vec<u8>)>,
}

impl kerlico_core::DatagramAssociationReceiver for DnsAssocReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<kerlico_core::AddressedDatagram>>> {
        Box::pin(async move { Ok(self.rx.recv().await) })
    }
}

impl Outbound for DnsOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn uses_engine_dns(&self) -> bool {
        self.engine
    }
    fn connect_tcp<'a>(
        &'a self,
        _target: &'a Destination,
        _context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        let resolver = self.resolver.clone();
        let host = self.host.clone();
        Box::pin(async move {
            let (client, mut server) = tokio::io::duplex(16 * 1024);
            let _task = host.spawn_tracked(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut len_buf = [0u8; 2];
                while server.read_exact(&mut len_buf).await.is_ok() {
                    let frame_len = usize::from(u16::from_be_bytes(len_buf));
                    if frame_len == 0 || frame_len > 4096 {
                        break;
                    }
                    let mut query = vec![0u8; frame_len];
                    if server.read_exact(&mut query).await.is_err() {
                        break;
                    }
                    let Ok(reply) = resolver.exchange_packet(&query).await else {
                        break;
                    };
                    if reply.len() > u16::MAX as usize {
                        break;
                    }
                    let out_len = (reply.len() as u16).to_be_bytes();
                    if server.write_all(&out_len).await.is_err()
                        || server.write_all(&reply).await.is_err()
                        || server.flush().await.is_err()
                    {
                        break;
                    }
                }
            })?;
            Ok(OpenedTcp {
                stream: Box::new(client),
                info: TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        _context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        let resolver = self.resolver.clone();
        let target = target.clone();
        Box::pin(async move {
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            Ok(DatagramChannel {
                sender: Box::new(DnsFixedSender { resolver, tx }),
                receiver: Box::new(DnsFixedReceiver { target, rx }),
            })
        })
    }
    fn associate_udp<'a>(
        &'a self,
        _context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            Ok(DatagramAssociation {
                sender: Box::new(DnsAssocSender { resolver, tx }),
                receiver: Box::new(DnsAssocReceiver { rx }),
            })
        })
    }
}

impl OutboundFactory for DnsFactory {
    fn kind(&self) -> &'static str {
        "dns"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: DnsOutboundOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("DNS 出站字段不合法".into()))?;
        let spec = if options.servers.is_empty() && options.hosts.is_empty() {
            None
        } else {
            let spec = kerlico_dns::DnsSpec {
                servers: options
                    .servers
                    .into_iter()
                    .map(kerlico_dns::DnsServerInput::Url)
                    .collect(),
                hosts: options
                    .hosts
                    .into_iter()
                    .map(|(name, ips)| {
                        let ips = ips.iter().map(ToString::to_string).collect();
                        (name, kerlico_dns::HostsValue::Many(ips))
                    })
                    .collect(),
                ..Default::default()
            };
            spec.validate()?;
            Some(spec)
        };
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            },
            true,
            TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    let engine = spec.is_none();
                    let resolver = Arc::new(match spec {
                        Some(spec) => kerlico_dns::DnsResolver::new(&spec)?,
                        None => kerlico_dns::DnsResolver::system()?,
                    });
                    Ok(Arc::new(DnsOutbound {
                        resolver,
                        engine,
                        host,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}
