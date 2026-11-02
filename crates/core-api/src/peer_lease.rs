//! 原物理 peer 的取消与配额寿命；升级 I/O、可信会话及其流共享同一份许可。

use crate::{CancellationToken, StreamLease};
use std::sync::Arc;

struct Inner {
    cancel: CancellationToken,
    _budget: StreamLease,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// 只延长已有物理 peer 许可，不取得新许可，也不代表另一个逻辑流。
#[derive(Clone)]
pub struct PeerLease {
    _inner: Arc<Inner>,
}
impl PeerLease {
    pub fn new(cancel: CancellationToken, budget: StreamLease) -> Self {
        Self {
            _inner: Arc::new(Inner {
                cancel,
                _budget: budget,
            }),
        }
    }
}
