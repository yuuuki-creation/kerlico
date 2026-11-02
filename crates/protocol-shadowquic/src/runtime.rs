//! 所有 QUIC 后台任务归属节点/连接；回退 socket 不启用 GRO，保留完整 UDP 包。
use jls_quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpSender};
use kerlico_core::{CancellationToken, ServiceContext, ServiceTask};
use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::{io::ReadBuf, net::UdpSocket};
pub(crate) struct ScopedRuntime {
    inner: jls_quinn::TokioRuntime,
    cancel: CancellationToken,
    tasks: Mutex<Vec<Task>>,
    host: Option<ServiceContext>,
    main: AtomicBool,
}
impl ScopedRuntime {
    pub fn shared(host: &ServiceContext) -> Arc<Self> {
        Arc::new(Self {
            inner: jls_quinn::TokioRuntime,
            cancel: CancellationToken::new(),
            tasks: Mutex::new(Vec::new()),
            host: Some(host.clone()),
            main: AtomicBool::new(true),
        })
    }
    pub fn stop(&self) {
        self.cancel.cancel();
        if let Ok(tasks) = self.tasks.lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }
    pub async fn shutdown(&self) {
        self.stop();
        let tasks = if let Ok(mut tasks) = self.tasks.lock() {
            std::mem::take(&mut *tasks)
        } else {
            return;
        };
        for task in tasks {
            task.join().await;
        }
    }
}
impl fmt::Debug for ScopedRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopedRuntime")
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
    main: AtomicBool,
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
            main: AtomicBool::new(true),
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
        endpoint: jls_quinn::Endpoint,
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
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn AsyncTimer>> {
        jls_quinn::TokioRuntime.new_timer(instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.register(future);
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        if self.main.swap(false, Ordering::AcqRel) {
            return jls_quinn::TokioRuntime.wrap_udp_socket(socket);
        }
        socket.set_nonblocking(true)?;
        Ok(Box::new(PlainSocket(Arc::new(UdpSocket::from_std(
            socket,
        )?))))
    }
}
pub(crate) struct NodeGuard(Arc<NodeRuntime>);
impl Drop for NodeGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}
impl Runtime for ScopedRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        if self.cancel.is_cancelled() {
            return;
        }
        let cancel = self.cancel.clone();
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.retain(|task| !task.finished());
            match Task::spawn(&self.host, async move {
                tokio::select! {biased;_=cancel.cancelled()=>{},_=future=>{}}
            }) {
                Ok(task) => tasks.push(task),
                Err(_) => self.cancel.cancel(),
            }
        }
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        if self.main.swap(false, Ordering::AcqRel) {
            return self.inner.wrap_udp_socket(socket);
        }
        socket.set_nonblocking(true)?;
        Ok(Box::new(PlainSocket(Arc::new(UdpSocket::from_std(
            socket,
        )?))))
    }
}
pub(crate) struct RuntimeGuard {
    runtime: Arc<ScopedRuntime>,
    armed: bool,
}
impl RuntimeGuard {
    pub fn new(runtime: Arc<ScopedRuntime>) -> Self {
        Self {
            runtime,
            armed: true,
        }
    }
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        if self.armed {
            self.runtime.stop();
        }
    }
}
struct PlainSocket(Arc<UdpSocket>);
impl fmt::Debug for PlainSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JlsForwardSocket")
    }
}
impl AsyncUdpSocket for PlainSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(PlainSender {
            socket: self.0.clone(),
            position: 0,
            writable: None,
        })
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [jls_quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let mut buffer = ReadBuf::new(&mut buffers[0]);
        let source = ready!(self.0.poll_recv_from(cx, &mut buffer))?;
        let count = buffer.filled().len();
        meta[0] = jls_quinn::udp::RecvMeta::default();
        meta[0].addr = source;
        meta[0].len = count;
        meta[0].stride = count.max(1);
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }
}
struct PlainSender {
    socket: Arc<UdpSocket>,
    position: usize,
    writable: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}
impl fmt::Debug for PlainSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JlsForwardSender")
    }
}
impl UdpSender for PlainSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &jls_quinn::udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let size = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        while this.position < transmit.contents.len() {
            if this.writable.is_none() {
                let socket = this.socket.clone();
                this.writable = Some(Box::pin(async move { socket.writable().await }));
            }
            ready!(
                this.writable
                    .as_mut()
                    .expect("发送就绪状态存在")
                    .as_mut()
                    .poll(cx)
            )?;
            this.writable = None;
            let end = (this.position + size).min(transmit.contents.len());
            match this
                .socket
                .try_send_to(&transmit.contents[this.position..end], transmit.destination)
            {
                Ok(count) if count == end - this.position => this.position = end,
                Ok(_) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        this.position = 0;
        Poll::Ready(Ok(()))
    }
}

pub(crate) enum Task {
    Node(kerlico_core::NodeTask<()>),
    Shared(ServiceTask<()>),
}
impl Task {
    pub fn spawn(
        host: &Option<ServiceContext>,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> kerlico_core::Result<Self> {
        match host {
            Some(host) => host.spawn_tracked(future).map(Self::Shared),
            None => Err(kerlico_core::Error::Protocol(
                "ShadowQUIC 任务缺少运行所有者",
            )),
        }
    }
    pub fn finished(&self) -> bool {
        match self {
            Self::Node(task) => task.is_finished(),
            Self::Shared(task) => task.is_finished(),
        }
    }
    pub fn abort(&self) {
        match self {
            Self::Node(task) => task.abort(),
            Self::Shared(task) => task.abort(),
        }
    }
    pub async fn join(self) {
        match self {
            Self::Node(task) => {
                let _ = task.await;
            }
            Self::Shared(task) => {
                let _ = task.await;
            }
        }
    }
}

#[cfg(test)]
mod node_tests {
    use super::{NodeDrain, NodeRuntime};
    use jls_quinn::{Endpoint, EndpointConfig, Runtime};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::task::JoinSet;

    struct Released(Arc<AtomicBool>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    fn endpoint(runtime: Arc<NodeRuntime>) -> (Endpoint, std::net::SocketAddr) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let address = socket.local_addr().unwrap();
        (
            Endpoint::new(EndpointConfig::default(), None, socket, runtime).unwrap(),
            address,
        )
    }

    #[tokio::test]
    async fn forced_cleanup_joins_drivers_and_connections_without_cancelling_parent() {
        let parent = kerlico_core::CancellationToken::new();
        let runtime = NodeRuntime::new(
            &parent,
            kerlico_core::NodeTasks::new(
                kerlico_core::NodeId::parse("test-node").unwrap(),
                parent.child_token(),
            ),
        );
        let _guard = runtime.guard();
        let (endpoint, address) = endpoint(runtime.clone());
        let native_released = Arc::new(AtomicBool::new(false));
        let connection_released = Arc::new(AtomicBool::new(false));
        let native = Released(native_released.clone());
        let connection = Released(connection_released.clone());
        let (native_started, native_ready) = tokio::sync::oneshot::channel();
        let (connection_started, connection_ready) = tokio::sync::oneshot::channel();
        runtime.spawn(Box::pin(async move {
            let _native = native;
            let _ = native_started.send(());
            std::future::pending::<()>().await;
        }));
        let mut connections = JoinSet::new();
        connections.spawn(async move {
            let _connection = connection;
            let _ = connection_started.send(());
            std::future::pending::<()>().await;
        });
        native_ready.await.unwrap();
        connection_ready.await.unwrap();
        runtime.cancel().cancel();
        tokio::task::yield_now().await;
        assert!(
            !native_released.load(Ordering::Acquire),
            "节点通知取消后，QUIC驱动仍须处理关闭"
        );
        assert_eq!(
            runtime
                .shutdown(endpoint, &mut connections, Duration::from_millis(200))
                .await
                .unwrap(),
            NodeDrain::Forced
        );
        assert!(native_released.load(Ordering::Acquire));
        assert!(connection_released.load(Ordering::Acquire));
        assert!(connections.is_empty());
        assert!(runtime.tasks.lock().unwrap().is_empty());
        assert!(!parent.is_cancelled());
        let _rebound = std::net::UdpSocket::bind(address).unwrap();
    }

    #[tokio::test]
    async fn native_task_panic_is_not_reported_as_clean_shutdown() {
        let parent = kerlico_core::CancellationToken::new();
        let runtime = NodeRuntime::new(
            &parent,
            kerlico_core::NodeTasks::new(
                kerlico_core::NodeId::parse("test-node").unwrap(),
                parent.child_token(),
            ),
        );
        let _guard = runtime.guard();
        let (endpoint, _) = endpoint(runtime.clone());
        let (started, ready) = tokio::sync::oneshot::channel();
        runtime.spawn(Box::pin(async move {
            let _ = started.send(());
            panic!("用于验证节点回收错误的受控任务");
        }));
        ready.await.unwrap();
        let result = runtime
            .shutdown(endpoint, &mut JoinSet::new(), Duration::from_millis(200))
            .await;
        assert!(matches!(
            result,
            Err(kerlico_core::Error::Protocol("QUIC节点任务异常退出"))
        ));
        assert!(!parent.is_cancelled());
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
    use jls_quinn::{Endpoint, EndpointConfig, Runtime};
    use kerlico_core::{CancellationToken, NodeId, NodeTasks};
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
