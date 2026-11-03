//! 原物理 peer 的取消与配额寿命；升级 I/O、可信会话及其流共享同一份许可。

use crate::{CancellationToken, StreamLease};
use std::{net::SocketAddr, sync::Arc};

struct Inner {
    cancel: CancellationToken,
    _budget: StreamLease,
    original_dst: Option<SocketAddr>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// 只延长已有物理 peer 许可，不取得新许可，也不代表另一个逻辑流。
#[derive(Clone)]
pub struct PeerLease {
    inner: Arc<Inner>,
}
impl PeerLease {
    pub fn new(cancel: CancellationToken, budget: StreamLease) -> Self {
        Self {
            inner: Arc::new(Inner {
                cancel,
                _budget: budget,
                original_dst: None,
            }),
        }
    }

    /// 附加透明代理/NAT 重定向还原出的原始目标地址。
    pub fn with_original_dst(mut self, original_dst: Option<SocketAddr>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.original_dst = original_dst;
        }
        self
    }

    /// 读取物理连接还原出的原始目标地址。
    pub fn original_dst(&self) -> Option<SocketAddr> {
        self.inner.original_dst
    }
}
