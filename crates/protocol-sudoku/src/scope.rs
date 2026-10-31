use kerlico_core::CancellationToken;
use std::{future::Future, sync::Arc};
use tokio_util::task::TaskTracker;

pub(crate) struct Scope {
    pub cancel: CancellationToken,
    pub tasks: TaskTracker,
}
impl Scope {
    pub fn new(parent: &CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            cancel: parent.child_token(),
            tasks: TaskTracker::new(),
        })
    }
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        drop(self.tasks.spawn(future));
    }
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
