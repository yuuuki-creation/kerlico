//! 设备网络的借用能力；没有停止、安装或重配设备的方法。

use crate::{BoxFuture, FamilyMode, OpenedTcp, Result};
use std::{net::SocketAddr, sync::Arc};

pub trait DeviceNetwork: Send + Sync {
    fn connect_tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<OpenedTcp>>;
    fn connect_udp(&self, target: SocketAddr) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>>;
    fn udp_association(
        &self,
        mode: FamilyMode,
    ) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>>;
}

#[derive(Clone)]
pub struct DeviceLease(Arc<dyn DeviceNetwork>);
impl DeviceLease {
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
