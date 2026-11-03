//! 节点实际任务的所有者。外层入站 future 退出后，Engine 仍能等待这些任务。

use crate::{BoxFuture, CancellationToken, Error, NodeId, Result, ShutdownReport};
use futures_util::FutureExt;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    sync::oneshot,
    task::{AbortHandle, JoinSet},
    time::{Instant, timeout_at},
};

struct Owner {
    id: NodeId,
    cancel: CancellationToken,
    closed: AtomicBool,
    failed: AtomicUsize,
    tasks: Mutex<JoinSet<()>>,
    shutdown: tokio::sync::Mutex<Drain>,
}
#[derive(Default)]
struct Drain {
    tasks: JoinSet<()>,
    progress: Option<DrainProgress>,
}
struct DrainProgress {
    deadline: Instant,
    phase: DrainPhase,
    report: ShutdownReport,
}
#[derive(Clone, Copy)]
enum DrainPhase {
    Natural {
        cancel_at: Instant,
        force_at: Instant,
    },
    Cooperative(Instant),
    Forced,
}

#[derive(Clone)]
pub struct NodeTasks(Arc<Owner>);

pub struct NodeTask<T> {
    abort: AbortHandle,
    result: oneshot::Receiver<T>,
    abort_on_drop: bool,
}
impl<T> NodeTask<T> {
    pub fn abort(&self) {
        self.abort.abort();
    }
    pub fn is_finished(&self) -> bool {
        self.abort.is_finished()
    }
}
impl<T> Unpin for NodeTask<T> {}
impl<T> Drop for NodeTask<T> {
    fn drop(&mut self) {
        if self.abort_on_drop {
            self.abort.abort();
        }
    }
}
impl<T> Future for NodeTask<T> {
    type Output = Result<T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().result)
            .poll(cx)
            .map(|result| result.map_err(|_| Error::Protocol("节点任务未交付结果")))
    }
}
impl NodeTasks {
    /// `cancel` 必须是节点域，不能传入单个 peer 或命名出站的取消域。
    pub fn new(id: NodeId, cancel: CancellationToken) -> Self {
        Self(Arc::new(Owner {
            id,
            cancel,
            closed: AtomicBool::new(false),
            failed: AtomicUsize::new(0),
            tasks: Mutex::new(JoinSet::new()),
            shutdown: tokio::sync::Mutex::new(Drain::default()),
        }))
    }
    pub fn id(&self) -> &NodeId {
        &self.0.id
    }
    pub fn cancel(&self) -> CancellationToken {
        self.0.cancel.clone()
    }
    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        let mut handle = self.spawn_tracked(task)?;
        handle.abort_on_drop = false;
        Ok(())
    }
    pub fn spawn_tracked<F, T>(&self, task: F) -> Result<NodeTask<T>>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut tasks = self
            .0
            .tasks
            .lock()
            .map_err(|_| Error::Protocol("节点任务所有者已损坏"))?;
        if self.0.closed.load(Ordering::Acquire) || self.0.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        while let Some(result) = tasks.try_join_next() {
            if result.is_err_and(|error| !error.is_cancelled()) {
                self.0.failed.fetch_add(1, Ordering::AcqRel);
                self.0.cancel.cancel();
                return Err(Error::Protocol("节点任务异常退出"));
            }
        }
        let (send, result) = oneshot::channel();
        let cancel = self.0.cancel.clone();
        let abort = tasks.spawn(async move {
            match std::panic::AssertUnwindSafe(task).catch_unwind().await {
                Ok(output) => {
                    let _ = send.send(output);
                }
                Err(panic) => {
                    cancel.cancel();
                    std::panic::resume_unwind(panic);
                }
            }
        });
        Ok(NodeTask {
            abort,
            result,
            abort_on_drop: true,
        })
    }
    /// 停止准入并等待真实任务，首次调用固定总截止时间；不会延长调用方预算。
    /// 超时仍持有未退出任务并报告 `timed_out`，不能据此声明资源已经回收。
    /// 等待中断保留阶段与强制计数；较短调用超时不改写首次总预算的报告。
    pub fn shutdown_at(&self, deadline: Instant) -> BoxFuture<'_, ShutdownReport> {
        Box::pin(async move {
            let mut drain = match timeout_at(deadline, self.0.shutdown.lock()).await {
                Ok(drain) => drain,
                Err(_) => {
                    return ShutdownReport {
                        timed_out: true,
                        failed_tasks: self.0.failed.load(Ordering::Acquire),
                        forced_tasks: 0,
                    };
                }
            };
            if drain.progress.is_none() {
                self.0.closed.store(true, Ordering::Release);
                let mut tasks = self.0.tasks.lock().unwrap_or_else(|poisoned| {
                    self.0.failed.fetch_add(1, Ordering::AcqRel);
                    poisoned.into_inner()
                });
                drain.tasks = std::mem::take(&mut *tasks);
                let now = Instant::now();
                let remaining = deadline.saturating_duration_since(now);
                let force_at = now + remaining.mul_f32(0.8);
                drain.progress = Some(DrainProgress {
                    deadline,
                    phase: if self.0.cancel.is_cancelled() {
                        DrainPhase::Cooperative(force_at)
                    } else {
                        DrainPhase::Natural {
                            cancel_at: now + remaining / 2,
                            force_at,
                        }
                    },
                    report: ShutdownReport::default(),
                });
            }
            let Drain { tasks, progress } = &mut *drain;
            let progress = progress.as_mut().expect("关闭进度已建立");
            loop {
                while let Some(result) = tasks
                    .try_join_next()
                    .or_else(|| tasks.join_next().now_or_never().flatten())
                {
                    if result.is_err_and(|error| !error.is_cancelled()) {
                        self.0.failed.fetch_add(1, Ordering::AcqRel);
                    }
                }
                progress.report.failed_tasks = self.0.failed.load(Ordering::Acquire);
                if tasks.is_empty() {
                    self.0.cancel.cancel();
                    return progress.report.clone();
                }
                let now = Instant::now();
                if let DrainPhase::Natural {
                    cancel_at,
                    force_at,
                } = progress.phase
                    && (now >= cancel_at || self.0.cancel.is_cancelled())
                {
                    self.0.cancel.cancel();
                    progress.phase = DrainPhase::Cooperative(force_at);
                }
                if matches!(progress.phase, DrainPhase::Cooperative(force_at) if now >= force_at) {
                    progress.report.forced_tasks = tasks.len();
                    progress.phase = DrainPhase::Forced;
                    tasks.abort_all();
                }
                if now >= progress.deadline {
                    progress.report.timed_out = true;
                    return progress.report.clone();
                }
                if now >= deadline {
                    let mut report = progress.report.clone();
                    report.timed_out = true;
                    return report;
                }
                let phase_deadline = match progress.phase {
                    DrainPhase::Natural { cancel_at, .. } => cancel_at,
                    DrainPhase::Cooperative(force_at) => force_at,
                    DrainPhase::Forced => progress.deadline,
                };
                if let Ok(Some(result)) =
                    timeout_at(deadline.min(phase_deadline), tasks.join_next()).await
                    && result.is_err_and(|error| !error.is_cancelled())
                {
                    self.0.failed.fetch_add(1, Ordering::AcqRel);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::poll_fn, sync::Condvar, time::Duration};
    use tokio::net::UdpSocket;

    struct Released(Arc<AtomicBool>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn dropping_one_waiter_aborts_only_its_task_and_owner_joins_it() {
        let cancel = CancellationToken::new();
        let owner = NodeTasks::new(NodeId::parse("node-test").unwrap(), cancel.clone());
        let released = Arc::new(AtomicBool::new(false));
        let witness = Released(released.clone());
        let (started, ready) = oneshot::channel();
        let task = owner
            .spawn_tracked(async move {
                let _witness = witness;
                let _ = started.send(());
                std::future::pending::<()>().await;
            })
            .unwrap();
        ready.await.unwrap();
        drop(task);
        assert_eq!(owner.spawn_tracked(async { 7 }).unwrap().await.unwrap(), 7);
        assert!(!cancel.is_cancelled());
        let report = owner
            .shutdown_at(Instant::now() + Duration::from_millis(100))
            .await;
        assert!(report.is_clean());
        assert!(released.load(Ordering::Acquire));
        assert!(matches!(owner.spawn(async {}), Err(Error::Cancelled)));
    }

    #[tokio::test]
    async fn aborted_shutdown_wait_keeps_real_join_ownership_and_first_deadline() {
        let owner = NodeTasks::new(
            NodeId::parse("node-test").unwrap(),
            CancellationToken::new(),
        );
        let released = Arc::new(AtomicBool::new(false));
        let witness = Released(released.clone());
        let (started, ready) = oneshot::channel();
        owner
            .spawn(async move {
                let _witness = witness;
                let _ = started.send(());
                std::future::pending::<()>().await;
            })
            .unwrap();
        ready.await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        let copied = owner.clone();
        let waiting = tokio::spawn(async move { copied.shutdown_at(deadline).await });
        while !owner.0.closed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        waiting.abort();
        let _ = waiting.await;
        assert!(!released.load(Ordering::Acquire));
        let report = timeout_at(
            deadline + Duration::from_millis(300),
            owner.shutdown_at(deadline + Duration::from_secs(10)),
        )
        .await
        .unwrap();
        assert!(report.is_clean());
        assert!(report.forced_tasks > 0);
        assert!(released.load(Ordering::Acquire));
        assert_eq!(
            owner
                .0
                .shutdown
                .lock()
                .await
                .progress
                .as_ref()
                .unwrap()
                .deadline,
            deadline
        );
    }

    #[tokio::test]
    async fn native_panic_cancels_only_its_node_and_is_not_clean_shutdown() {
        let first = NodeTasks::new(NodeId::parse("first").unwrap(), CancellationToken::new());
        let second = NodeTasks::new(NodeId::parse("second").unwrap(), CancellationToken::new());
        let task = first
            .spawn_tracked(async { panic!("受控节点任务失败") })
            .unwrap();
        assert!(task.await.is_err());
        assert!(first.cancel().is_cancelled());
        assert!(!second.cancel().is_cancelled());
        assert!(
            !first
                .shutdown_at(Instant::now() + Duration::from_millis(100))
                .await
                .is_clean()
        );
        assert!(
            second
                .shutdown_at(Instant::now() + Duration::from_millis(100))
                .await
                .is_clean()
        );
    }

    #[tokio::test]
    async fn resumed_node_shutdown_respects_short_wait_after_acquiring_lock() {
        let owner = NodeTasks::new(
            NodeId::parse("node-test").unwrap(),
            CancellationToken::new(),
        );
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let released = Arc::new(AtomicBool::new(false));
        let witness = Released(released.clone());
        let (finish, done) = oneshot::channel();
        owner
            .spawn(async move {
                let _socket = socket;
                let _witness = witness;
                let _ = done.await;
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut first = Box::pin(owner.shutdown_at(deadline));
        assert!(
            poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(first);
        let short = Instant::now() + Duration::from_millis(10);
        let report = timeout_at(short + Duration::from_millis(100), owner.shutdown_at(short))
            .await
            .unwrap();
        assert!(report.timed_out);
        assert_eq!(report.forced_tasks, 0);
        assert!(!owner.cancel().is_cancelled());
        assert!(!released.load(Ordering::Acquire));
        assert!(std::net::UdpSocket::bind(address).is_err());
        finish.send(()).unwrap();
        let report = owner.shutdown_at(deadline + Duration::from_secs(10)).await;
        assert!(report.is_clean());
        assert_eq!(report.forced_tasks, 0);
        assert!(released.load(Ordering::Acquire));
        let _rebound = UdpSocket::bind(address).await.unwrap();
    }

    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl ReleaseOnDrop {
        fn release(&self) {
            let (ready, changed) = &*self.0;
            *ready.lock().unwrap() = true;
            changed.notify_all();
        }
    }
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.release();
        }
    }
    struct BlockedSocketDrop {
        socket: Option<UdpSocket>,
        entered: Option<oneshot::Sender<()>>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }
    impl Drop for BlockedSocketDrop {
        fn drop(&mut self) {
            let _ = self.entered.take().unwrap().send(());
            let (ready, changed) = &*self.gate;
            let mut ready = ready.lock().unwrap();
            while !*ready {
                ready = changed.wait(ready).unwrap();
            }
            drop(self.socket.take());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interrupted_node_force_keeps_count_until_actual_socket_join() {
        let owner = NodeTasks::new(
            NodeId::parse("node-test").unwrap(),
            CancellationToken::new(),
        );
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let release = ReleaseOnDrop(Arc::new((Mutex::new(false), Condvar::new())));
        let (entered, dropping) = oneshot::channel();
        let resource = BlockedSocketDrop {
            socket: Some(socket),
            entered: Some(entered),
            gate: release.0.clone(),
        };
        let task = owner
            .spawn_tracked(async move {
                let _resource = resource;
                std::future::pending::<()>().await;
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_millis(1000);
        let mut first = Box::pin(owner.shutdown_at(deadline));
        tokio::select! {
            report = &mut first => panic!("socket仍在析构，不应结束等待 {report:?}"),
            result = timeout_at(deadline + Duration::from_millis(300), dropping) => result.unwrap().unwrap(),
        }
        drop(first);
        assert!(!task.is_finished());
        assert!(std::net::UdpSocket::bind(address).is_err());
        let short = Instant::now() + Duration::from_millis(5);
        let report = owner.shutdown_at(short).await;
        assert!(report.timed_out);
        assert_eq!(report.forced_tasks, 1);
        release.release();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(task.await.is_err());
        let report = owner.shutdown_at(deadline + Duration::from_secs(10)).await;
        assert!(report.is_clean());
        assert_eq!(report.forced_tasks, 1);
        let _rebound = UdpSocket::bind(address).await.unwrap();
        let repeated = owner.shutdown_at(Instant::now()).await;
        assert!(repeated.is_clean());
        assert_eq!(repeated.forced_tasks, 1);
    }
}
