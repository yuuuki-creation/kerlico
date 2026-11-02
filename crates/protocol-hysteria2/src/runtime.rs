use kerlico_core::ServiceContext;
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime};
use std::{future::Future, io, pin::Pin, sync::Arc, time::Instant};

pub(crate) struct ServiceRuntime(ServiceContext);
impl ServiceRuntime {
    pub fn new(host: ServiceContext) -> Arc<Self> {
        Arc::new(Self(host))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeDrain {
    Graceful,
    Forced,
}

pub(crate) struct NodeRuntime {
    owner: kerlico_core::NodeTasks,
    cancel: kerlico_core::CancellationToken,
    tasks: std::sync::Mutex<tokio::task::JoinSet<()>>,
    closed: std::sync::atomic::AtomicBool,
    failed: Arc<std::sync::atomic::AtomicBool>,
}
impl std::fmt::Debug for NodeRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NodeRuntime")
    }
}
impl NodeRuntime {
    pub fn new(
        parent: &kerlico_core::CancellationToken,
        owner: kerlico_core::NodeTasks,
    ) -> Arc<Self> {
        Arc::new(Self {
            owner,
            cancel: parent.child_token(),
            tasks: std::sync::Mutex::new(tokio::task::JoinSet::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
            failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
    pub fn cancel(&self) -> kerlico_core::CancellationToken {
        self.cancel.clone()
    }
    pub fn guard(self: &Arc<Self>) -> NodeGuard {
        NodeGuard(self.clone())
    }
    pub fn observe(&self, result: &Option<std::result::Result<(), tokio::task::JoinError>>) {
        if result
            .as_ref()
            .is_some_and(|result| result.as_ref().is_err_and(|error| !error.is_cancelled()))
        {
            self.failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
    fn register(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|poisoned| {
            self.failed
                .store(true, std::sync::atomic::Ordering::Release);
            poisoned.into_inner()
        });
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        while let Some(result) = tasks.try_join_next() {
            self.observe(&Some(result));
        }
        let task = match self.owner.spawn_tracked(future) {
            Ok(task) => task,
            Err(_) => {
                self.cancel.cancel();
                return;
            }
        };
        let failed = self.failed.clone();
        tasks.spawn(async move {
            if task.await.is_err() {
                failed.store(true, std::sync::atomic::Ordering::Release);
            }
        });
    }
    fn stop(&self) {
        self.cancel.cancel();
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        tasks.abort_all();
    }
    pub async fn shutdown(
        &self,
        endpoint: quinn::Endpoint,
        connections: &mut tokio::task::JoinSet<()>,
        budget: std::time::Duration,
    ) -> kerlico_core::Result<NodeDrain> {
        let started = tokio::time::Instant::now();
        let graceful = started + budget / 2;
        let force_at = graceful + budget / 4;
        let deadline = started + budget;
        self.cancel.cancel();
        let mut failed_connections = false;
        let mut forced =
            tokio::time::timeout_at(graceful, drain_owned(connections, &mut failed_connections))
                .await
                .is_err();
        if forced {
            connections.abort_all();
        }
        endpoint.close(0u32.into(), b"");
        if tokio::time::timeout_at(graceful, endpoint.wait_idle())
            .await
            .is_err()
        {
            forced = true;
        }
        drop(endpoint);
        let mut tasks = {
            let mut tasks = self.tasks.lock().unwrap_or_else(|poisoned| {
                self.failed
                    .store(true, std::sync::atomic::Ordering::Release);
                poisoned.into_inner()
            });
            self.closed
                .store(true, std::sync::atomic::Ordering::Release);
            std::mem::take(&mut *tasks)
        };
        let mut failed_native = false;
        if !forced {
            let completed = tokio::time::timeout_at(force_at, async {
                tokio::join!(
                    drain_owned(connections, &mut failed_connections),
                    drain_owned(&mut tasks, &mut failed_native)
                );
            })
            .await
            .is_ok();
            forced = !completed;
        }
        if forced {
            connections.abort_all();
            tasks.abort_all();
            if tokio::time::timeout_at(deadline, async {
                tokio::join!(
                    drain_owned(connections, &mut failed_connections),
                    drain_owned(&mut tasks, &mut failed_native)
                );
            })
            .await
            .is_err()
            {
                return Err(kerlico_core::Error::Protocol(
                    "QUIC节点强制清理未在期限内完成",
                ));
            }
        }
        if failed_connections
            || failed_native
            || self.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            Err(kerlico_core::Error::Protocol("QUIC节点任务异常退出"))
        } else {
            Ok(if forced {
                NodeDrain::Forced
            } else {
                NodeDrain::Graceful
            })
        }
    }
}
async fn drain_owned(tasks: &mut tokio::task::JoinSet<()>, failed: &mut bool) {
    while let Some(result) = tasks.join_next().await {
        if result.is_err_and(|error| !error.is_cancelled()) {
            *failed = true;
        }
    }
}
impl Runtime for NodeRuntime {
    fn new_timer(&self, instant: Instant) -> Pin<Box<dyn AsyncTimer>> {
        quinn::TokioRuntime.new_timer(instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.register(future);
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}
pub(crate) struct NodeGuard(Arc<NodeRuntime>);
impl Drop for NodeGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}
impl std::fmt::Debug for ServiceRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServiceRuntime")
    }
}
impl Runtime for ServiceRuntime {
    fn new_timer(&self, instant: Instant) -> Pin<Box<dyn AsyncTimer>> {
        quinn::TokioRuntime.new_timer(instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        if self.0.spawn(future).is_err() {
            self.0.cancel().cancel();
        }
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

pub(crate) fn spawn_owned<F, T>(
    owner: kerlico_core::NodeTasks,
    events: Arc<dyn kerlico_core::NodeObserver>,
    tasks: &mut tokio::task::JoinSet<T>,
    future: F,
    failed: fn(kerlico_core::Error) -> T,
) -> kerlico_core::Result<()>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let task = owner.spawn_tracked(future)?;
    tasks.spawn(async move {
        match task.await {
            Ok(result) => result,
            Err(error) => {
                events.record(kerlico_core::NodeEvent::Failed);
                failed(error)
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod engine_owner_tests {
    use super::NodeRuntime;
    use kerlico_core::{CancellationToken, NodeId, NodeTasks};
    use quinn::{Endpoint, EndpointConfig, Runtime};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    struct Released(Arc<AtomicBool>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    #[tokio::test]
    async fn engine_owner_joins_native_tasks_after_handler_abort() {
        let cancel = CancellationToken::new();
        let owner = NodeTasks::new(NodeId::parse("native-owner").unwrap(), cancel.clone());
        let native_released = Arc::new(AtomicBool::new(false));
        let (ready, started) = tokio::sync::oneshot::channel();
        let owned = owner.clone();
        let released = native_released.clone();
        let outer = tokio::spawn(async move {
            let runtime = NodeRuntime::new(&cancel, owned);
            let _guard = runtime.guard();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let address = socket.local_addr().unwrap();
            let endpoint =
                Endpoint::new(EndpointConfig::default(), None, socket, runtime.clone()).unwrap();
            let (entered, waiting) = tokio::sync::oneshot::channel();
            let release = Released(released);
            runtime.spawn(Box::pin(async move {
                let _release = release;
                let _ = entered.send(());
                std::future::pending::<()>().await;
            }));
            waiting.await.unwrap();
            let _ = ready.send(address);
            std::future::pending::<()>().await;
            drop(endpoint);
        });
        let address = started.await.unwrap();
        outer.abort();
        assert!(outer.await.unwrap_err().is_cancelled());
        let report = owner
            .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        assert!(report.is_clean());
        assert!(native_released.load(Ordering::Acquire));
        let _rebound = std::net::UdpSocket::bind(address).unwrap();
        assert!(owner.spawn(async {}).is_err());
    }
}
