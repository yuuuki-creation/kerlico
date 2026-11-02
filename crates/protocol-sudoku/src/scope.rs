use kerlico_core::{CancellationToken, NodeTasks, ServiceContext};
use std::{future::Future, sync::Arc};
use tokio_util::task::TaskTracker;

pub(crate) struct Scope {
    pub cancel: CancellationToken,
    pub tasks: TaskTracker,
    owner: Owner,
}
enum Owner {
    Node(NodeTasks),
    Shared(ServiceContext),
}
impl Scope {
    pub fn node(parent: &CancellationToken, owner: NodeTasks) -> Arc<Self> {
        Arc::new(Self {
            cancel: parent.child_token(),
            tasks: TaskTracker::new(),
            owner: Owner::Node(owner),
        })
    }
    pub fn shared(host: &ServiceContext) -> Arc<Self> {
        Arc::new(Self {
            cancel: host.cancel().child_token(),
            tasks: TaskTracker::new(),
            owner: Owner::Shared(host.clone()),
        })
    }
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        if self.cancel.is_cancelled() {
            return;
        }
        let cancel = self.cancel.clone();
        let future = async move {
            tokio::select! { biased; _=cancel.cancelled()=>{}, _=future=>{} }
        };
        let future = self.tasks.track_future(future);
        let result = match &self.owner {
            Owner::Shared(host) => host.spawn(future),
            Owner::Node(owner) => owner.spawn(future),
        };
        if result.is_err() {
            self.cancel.cancel();
        }
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

#[derive(Clone)]
pub(crate) struct ScopeExecutor(pub Arc<Scope>);
impl<F> hyper::rt::Executor<F> for ScopeExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        self.0.spawn(async move {
            let _ = future.await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{Scope, ScopeExecutor};
    use hyper::rt::Executor;
    use kerlico_core::{CancellationToken, NodeId, NodeTasks};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::{net::TcpListener, sync::oneshot, time::Instant};

    struct Released(Arc<AtomicBool>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn node_owner_joins_executor_socket_driver_after_handler_abort() {
        let owner = NodeTasks::new(
            NodeId::parse("sudoku-scope-test").unwrap(),
            CancellationToken::new(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let released = Arc::new(AtomicBool::new(false));
        let witness = Released(released.clone());
        let child_owner = owner.clone();
        let (started, ready) = oneshot::channel();
        let handler = tokio::spawn(async move {
            let scope = Scope::node(&child_owner.cancel(), child_owner.clone());
            let active = scope.clone();
            ScopeExecutor(scope).execute(async move {
                let _active = active;
                let _witness = witness;
                let _ = started.send(());
                while listener.accept().await.is_ok() {}
            });
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        assert!(!released.load(Ordering::Acquire));
        let report = owner
            .shutdown_at(Instant::now() + Duration::from_millis(200))
            .await;
        assert!(report.is_clean());
        assert!(released.load(Ordering::Acquire));
        let _rebound = TcpListener::bind(address).await.unwrap();
    }

    #[tokio::test]
    async fn closed_node_rejects_executor_future_without_spawning() {
        let owner = NodeTasks::new(
            NodeId::parse("sudoku-scope-test").unwrap(),
            CancellationToken::new(),
        );
        assert!(
            owner
                .shutdown_at(Instant::now() + Duration::from_millis(100))
                .await
                .is_clean()
        );
        let scope = Scope::node(&CancellationToken::new(), owner);
        let released = Arc::new(AtomicBool::new(false));
        let witness = Released(released.clone());
        ScopeExecutor(scope.clone()).execute(async move {
            let _witness = witness;
            panic!("关闭后的执行器任务不得启动");
        });
        assert!(scope.cancel.is_cancelled());
        assert!(released.load(Ordering::Acquire));
        assert!(scope.tasks.is_empty());
    }
}
