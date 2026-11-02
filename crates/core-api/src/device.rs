//! 设备网络的借用能力；没有停止、安装或重配设备的方法。

use crate::{
    Address, BoxFuture, ConnectContext, DatagramAssociation, DatagramAssociationReceiver,
    DatagramAssociationSender, DatagramChannel, DatagramReceiver, DatagramSender, Destination,
    Error, FamilyMode, Language, OpenedTcp, Result,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

pub trait DeviceNetwork: Send + Sync {
    /// 原生方法仅用于 carrier；业务目标使用以下三个方法。
    fn connect_target_tcp<'a>(
        &'a self,
        target: SocketAddr,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move { context.run(self.connect_tcp(target)).await })
    }
    fn connect_target_udp<'a>(
        &'a self,
        target: SocketAddr,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let socket = context.run(self.connect_udp(target)).await?;
            Ok(DatagramChannel {
                sender: Box::new(NativeDatagram(socket.clone())),
                receiver: Box::new(NativeDatagram(socket)),
            })
        })
    }
    fn target_association<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            let socket = context
                .run(self.udp_association(context.target_mode()))
                .await?;
            let ipv6 = socket.local_addr()?.is_ipv6();
            Ok(DatagramAssociation {
                sender: Box::new(NativeAssociation {
                    socket: socket.clone(),
                    cancel: context.cancel.clone(),
                    ipv6,
                }),
                receiver: Box::new(NativeAssociation {
                    socket,
                    cancel: context.cancel.clone(),
                    ipv6,
                }),
            })
        })
    }
    fn connect_tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<OpenedTcp>>;
    fn connect_udp(&self, target: SocketAddr) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>>;
    fn udp_association(
        &self,
        mode: FamilyMode,
    ) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>>;
}

#[derive(Clone)]
pub struct DeviceLease(Arc<dyn DeviceNetwork>);
/// 一个 Engine 的显式装配选项；设备能力可共享，语种不进入全局可变状态。
#[derive(Clone)]
pub struct RuntimeOptions {
    pub device: DeviceLease,
    pub language: Language,
}
impl RuntimeOptions {
    pub fn new(device: DeviceLease) -> Self {
        Self {
            device,
            language: Language::default(),
        }
    }
}
impl DeviceLease {
    /// 用指定原生族建立业务关联，供设备混合路径保留独立来源绑定。
    pub async fn native_target_association(
        &self,
        mode: FamilyMode,
        context: &ConnectContext,
    ) -> Result<DatagramAssociation> {
        let socket = context.run(self.udp_association(mode)).await?;
        let ipv6 = socket.local_addr()?.is_ipv6();
        Ok(DatagramAssociation {
            sender: Box::new(NativeAssociation {
                socket: socket.clone(),
                cancel: context.cancel.clone(),
                ipv6,
            }),
            receiver: Box::new(NativeAssociation {
                socket,
                cancel: context.cancel.clone(),
                ipv6,
            }),
        })
    }
    pub fn connect_target_tcp<'a>(
        &'a self,
        target: SocketAddr,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        self.0.connect_target_tcp(target, context)
    }
    pub fn connect_target_udp<'a>(
        &'a self,
        target: SocketAddr,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.0.connect_target_udp(target, context)
    }
    pub fn target_association<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.0.target_association(context)
    }
    pub fn borrow(provider: Arc<dyn DeviceNetwork>) -> Self {
        Self(provider)
    }
    pub fn connect_tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<OpenedTcp>> {
        self.0.connect_tcp(target)
    }
    pub fn connect_udp(
        &self,
        target: SocketAddr,
    ) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>> {
        self.0.connect_udp(target)
    }
    pub fn udp_association(
        &self,
        mode: FamilyMode,
    ) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>> {
        self.0.udp_association(mode)
    }
}

struct NativeDatagram(Arc<UdpSocket>);

struct NativeAssociation {
    socket: Arc<UdpSocket>,
    cancel: crate::CancellationToken,
    ipv6: bool,
}
impl DatagramAssociationSender for NativeAssociation {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Address::Ip(ip) = target.address() else {
                return Err(Error::Unsupported("多目标直连需要统一出口提供字面 IP"));
            };
            let maximum = if ip.to_canonical().is_ipv4() {
                65_507
            } else {
                65_527
            };
            if packet.len() > maximum {
                return Err(Error::ResourceLimit);
            }
            let ip = match ip {
                std::net::IpAddr::V4(ip) if self.ipv6 => std::net::IpAddr::V6(ip.to_ipv6_mapped()),
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
impl DatagramAssociationReceiver for NativeAssociation {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<crate::AddressedDatagram>>> {
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

impl DatagramSender for NativeDatagram {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let count = self.0.send(packet).await?;
            if count != packet.len() {
                return Err(Error::Protocol("UDP通道未发送完整数据报"));
            }
            Ok(())
        })
    }
}

impl DatagramReceiver for NativeDatagram {
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
