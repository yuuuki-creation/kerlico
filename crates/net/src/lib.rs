//! 共享 TCP/TLS 连接器与基础直连/拒绝处理器。

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
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Config("TLS 版本不可用".into()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
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

struct Direct {
    device: kerlico_core::DeviceLease,
}

struct NativeDevice;
/// 借用操作系统原生socket提供方，不探测互联网，也不安装或关闭设备服务。
pub fn native_device() -> kerlico_core::DeviceLease {
    kerlico_core::DeviceLease::borrow(Arc::new(NativeDevice))
}
impl kerlico_core::DeviceNetwork for NativeDevice {
    fn connect_tcp(&self, target: std::net::SocketAddr) -> BoxFuture<'_, Result<OpenedTcp>> {
        Box::pin(async move {
            let stream = TcpStream::connect(target).await?;
            stream.set_nodelay(true)?;
            let info = TcpConnectInfo::local_bound(stream.local_addr()?);
            Ok(OpenedTcp {
                stream: Box::new(stream),
                info,
            })
        })
    }
    fn connect_udp(&self, target: std::net::SocketAddr) -> BoxFuture<'_, Result<Arc<UdpSocket>>> {
        Box::pin(async move {
            let socket = UdpSocket::bind(if target.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            })
            .await?;
            socket.connect(target).await?;
            Ok(Arc::new(socket))
        })
    }
    fn udp_association(
        &self,
        mode: kerlico_core::FamilyMode,
    ) -> BoxFuture<'_, Result<Arc<UdpSocket>>> {
        Box::pin(async move {
            let ipv6 = mode != kerlico_core::FamilyMode::V4Only;
            let socket = socket2::Socket::new(
                if ipv6 {
                    socket2::Domain::IPV6
                } else {
                    socket2::Domain::IPV4
                },
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            if ipv6 {
                socket.set_only_v6(mode == kerlico_core::FamilyMode::V6Only)?;
            }
            socket.set_nonblocking(true)?;
            let bind = if ipv6 {
                std::net::SocketAddr::from(([0u16; 8], 0))
            } else {
                std::net::SocketAddr::from(([0u8; 4], 0))
            };
            socket.bind(&bind.into())?;
            Ok(Arc::new(UdpSocket::from_std(socket.into())?))
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
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        empty(options)?;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            },
            true,
            TargetPolicy::Local,
            |host| {
                Box::pin(async move {
                    Ok(Arc::new(Direct {
                        device: host.device().unwrap_or_else(native_device),
                    }) as Arc<dyn Outbound>)
                })
            },
        )
        .with_native_targets())
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
