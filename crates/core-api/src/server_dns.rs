//! 代理节点服务器域名的解析入口。装配方安装 DNS 管线（Mihomo `proxy-server-nameserver`，
//! 未配置时为主解析器与 hosts）；未安装时使用系统解析器。

use crate::{BoxFuture, Result};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};

pub trait ServerResolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>>;
}

type Installed = Option<(u64, Arc<dyn ServerResolver>)>;
static INSTALLED: RwLock<Installed> = RwLock::new(None);

/// 以 `owner` 身份安装解析器；同一进程只保留最后安装者。
pub fn install_server_resolver(owner: u64, resolver: Arc<dyn ServerResolver>) {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = Some((owner, resolver));
}

/// 只移除 `owner` 自己安装的解析器，不影响之后安装的运行时。
pub fn remove_server_resolver(owner: u64) {
    let mut slot = INSTALLED.write().unwrap_or_else(|e| e.into_inner());
    if slot.as_ref().is_some_and(|(o, _)| *o == owner) {
        *slot = None;
    }
}

/// 解析代理服务器地址；与 `tokio::net::lookup_host((host, port))` 同形。
pub async fn lookup_host<H: AsRef<str>>(
    target: (H, u16),
) -> io::Result<std::vec::IntoIter<SocketAddr>> {
    let (host, port) = target;
    let host = host.as_ref();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)].into_iter());
    }
    let resolver = INSTALLED
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|(_, r)| r.clone());
    match resolver {
        Some(r) => {
            let ips = r.resolve(host).await.map_err(io::Error::other)?;
            Ok(ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>()
                .into_iter())
        }
        None => Ok(tokio::net::lookup_host((host, port))
            .await?
            .collect::<Vec<_>>()
            .into_iter()),
    }
}
