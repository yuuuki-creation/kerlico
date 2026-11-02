//! 命名服务的任务所有权与请求资源作用域。

use crate::{CancellationToken, DeviceLease, Error, OutId, Result, Source};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{task::JoinSet, time::Instant};

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ResourceKey {
    instance: u64,
    source: Option<Source>,
    remote_epoch: u64,
}
impl ResourceKey {
    pub(crate) fn detached() -> Self {
        Self {
            instance: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            source: None,
            remote_epoch: 1,
        }
    }
    pub fn source(&self) -> Option<&Source> {
        self.source.as_ref()
    }
    pub fn instance(&self) -> u64 {
        self.instance
    }
}

/// 命名服务的稳定失败原因，不包含请求载荷、凭据或动态上游错误文本。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceFailure {
    Timeout,
    Rejected,
    InvalidAddress,
    ResourceLimit,
    Protocol(&'static str),
    Io(std::io::ErrorKind, &'static str),
}
impl ServiceFailure {
    pub fn error(self) -> Error {
        match self {
            Self::Timeout => Error::Timeout,
            Self::Rejected => Error::Rejected,
            Self::InvalidAddress => Error::InvalidAddress,
            Self::ResourceLimit => Error::ResourceLimit,
            Self::Protocol(message) => Error::Protocol(message),
            Self::Io(kind, message) => Error::Io(std::io::Error::new(kind, message)),
        }
    }
}

#[derive(Clone, Default)]
pub struct ServiceStatus {
    cancel: CancellationToken,
    failure: Arc<Mutex<Option<ServiceFailure>>>,
}
impl ServiceStatus {
    pub(crate) fn cancel(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub fn failure(&self) -> Option<ServiceFailure> {
        *self.failure.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn fail(&self, failure: ServiceFailure) {
        self.record_failure(failure);
        self.cancel.cancel();
    }
    fn record_failure(&self, failure: ServiceFailure) {
        self.failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_or_insert(failure);
    }
    pub(crate) fn error(&self) -> Error {
        self.failure().map_or(Error::Cancelled, ServiceFailure::error)
    }
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(failure) = self.failure() {
            Err(failure.error())
        } else if self.cancel.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

struct ServiceOwner {
    instance: u64,
    id: OutId,
    device: Option<DeviceLease>,
    carrier: crate::carrier::CarrierCounter,
    registry: Arc<TaskRegistry>,
}
impl Drop for ServiceOwner {
    fn drop(&mut self) {
        self.registry.retire(Instant::now());
    }
}

struct TaskRegistry {
    state: Mutex<TaskSet>,
    service: ServiceStatus,
    failed: Arc<AtomicUsize>,
    wake: Arc<ReaperWake>,
    changed: tokio::sync::Notify,
}
#[derive(Default)]
struct TaskSet {
    tasks: JoinSet<()>,
    facts: std::collections::HashMap<tokio::task::Id, Arc<TaskFacts>>,
    reclaiming: usize,
    retained_panics: Vec<std::mem::ManuallyDrop<PanicPayload>>,
    latest_completion: Option<Instant>,
    progress: Option<DrainProgress>,
    worker: ReaperThread,
}
#[derive(Default)]
enum ReaperThread {
    #[default]
    Unstarted,
    Running(std::thread::JoinHandle<()>),
    Joining,
    Joined,
}
struct DrainProgress {
    deadline: Instant,
    force_at: Instant,
    forced: bool,
    report: ShutdownReport,
}
#[derive(Default)]
struct TaskFacts {
    completed_at: Mutex<Option<Instant>>,
    failed: AtomicBool,
}
type PanicPayload = Box<dyn std::any::Any + Send + 'static>;

#[derive(Default)]
struct JoinedEffects {
    errors: Vec<tokio::task::JoinError>,
    cancel: bool,
    joined: bool,
}

fn reclaim_opaque<T>(value: T) -> Option<PanicPayload> {
    let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(value))) else {
        return None;
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload))).err()
}
#[derive(Clone)]
struct FailureGuard {
    facts: Arc<TaskFacts>,
    failed: Arc<AtomicUsize>,
    service: ServiceStatus,
}
impl Drop for FailureGuard {
    fn drop(&mut self) {
        if std::thread::panicking() && self.facts.record_failure(&self.failed, &self.service) {
            self.service.cancel.cancel();
        }
    }
}
struct TaskStamp(FailureGuard);
impl Drop for TaskStamp {
    fn drop(&mut self) {
        *self.0.facts.completed_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(Instant::now());
    }
}
impl TaskFacts {
    fn record_failure(&self, failed: &AtomicUsize, service: &ServiceStatus) -> bool {
        if !self.failed.swap(true, Ordering::AcqRel) {
            failed.fetch_add(1, Ordering::AcqRel);
            service.record_failure(ServiceFailure::Protocol("服务任务异常退出"));
            true
        } else {
            false
        }
    }
    fn completed_at(&self) -> Option<Instant> {
        *self.completed_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// 字段按声明顺序析构，时间戳必须晚于用户任务及未交付输出的析构。
struct TrackedFuture<F: Future> {
    task: Pin<Box<F>>,
    _failure: FailureGuard,
    send: Option<tokio::sync::oneshot::Sender<F::Output>>,
    _stamp: TaskStamp,
}
impl<F: Future> Unpin for TrackedFuture<F> {}
impl<F: Future> Future for TrackedFuture<F> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        match this.task.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(output) => {
                let _ = this.send.take().expect("任务只交付一次结果").send(output);
                Poll::Ready(())
            }
        }
    }
}
struct TrackedBlocking<F, T> {
    task: Option<F>,
    _failure: FailureGuard,
    send: Option<tokio::sync::oneshot::Sender<T>>,
    _stamp: TaskStamp,
}
impl<F: FnOnce() -> T, T> TrackedBlocking<F, T> {
    fn run(mut self) {
        let output = self.task.take().expect("阻塞任务只运行一次")();
        let _ = self.send.take().expect("任务只交付一次结果").send(output);
    }
}

#[derive(Default)]
struct ReaperWake {
    notified: Mutex<bool>,
    changed: std::sync::Condvar,
}
impl ReaperWake {
    fn notify(&self) {
        *self.notified.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.changed.notify_one();
    }
    fn wait(&self, deadline: Option<Instant>) {
        let mut notified = self.notified.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !*notified {
            if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                let result = self.changed.wait_timeout(notified, remaining)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                notified = result.0;
            } else {
                notified = self.changed.wait(notified)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
        *notified = false;
    }
}
impl std::task::Wake for ReaperWake {
    fn wake(self: Arc<Self>) {
        self.notify();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

impl TaskSet {
    fn collect(&mut self, registry: &TaskRegistry) -> JoinedEffects {
        let mut effects = JoinedEffects::default();
        let waker = std::task::Waker::from(registry.wake.clone());
        let mut context = Context::from_waker(&waker);
        while let Poll::Ready(Some(result)) = self.tasks.poll_join_next_with_id(&mut context) {
            effects.joined = true;
            let (id, failed) = match result {
                Ok((id, ())) => (id, false),
                Err(error) => {
                    let outcome = (error.id(), !error.is_cancelled());
                    effects.errors.push(error);
                    outcome
                }
            };
            let facts = self.facts.remove(&id).expect("已登记任务保留完成事实");
            if failed && facts.record_failure(&registry.failed, &registry.service) {
                effects.cancel = true;
            }
            let completed = facts.completed_at().expect("真实 join 前已析构任务资源");
            self.latest_completion = Some(self.latest_completion.map_or(completed, |last| last.max(completed)));
        }
        let Some(progress) = &mut self.progress else { return effects; };
        if self.latest_completion.is_some_and(|completed| completed > progress.deadline)
            || self.facts.values().any(|facts| match facts.completed_at() {
                Some(completed) => completed > progress.deadline,
                None => Instant::now() >= progress.deadline,
            })
        {
            progress.report.timed_out = true;
        }
        if !progress.forced && Instant::now() >= progress.force_at {
            progress.report.forced_tasks = self.tasks.len();
            progress.forced = true;
            self.tasks.abort_all();
        }
        progress.report.failed_tasks = registry.failed.load(Ordering::Acquire);
        effects
    }
    fn is_drained(&self) -> bool {
        self.tasks.is_empty() && self.reclaiming == 0 && self.retained_panics.is_empty()
    }
    fn report(&self, registry: &TaskRegistry) -> ShutdownReport {
        let mut report = self.progress.as_ref().map_or_else(ShutdownReport::default, |p| p.report.clone());
        report.failed_tasks = registry.failed.load(Ordering::Acquire);
        report
    }
}
impl TaskRegistry {
    fn new() -> Self {
        Self {
            state: Mutex::new(TaskSet::default()),
            service: ServiceStatus::default(),
            failed: Arc::new(AtomicUsize::new(0)),
            wake: Arc::new(ReaperWake::default()),
            changed: tokio::sync::Notify::new(),
        }
    }
    fn start_worker(self: &Arc<Self>, state: &mut TaskSet) -> Result<()> {
        if matches!(state.worker, ReaperThread::Unstarted) {
            let registry = self.clone();
            let worker = std::thread::Builder::new()
                .name("service-retirement".into())
                .spawn(move || registry.reap())?;
            state.worker = ReaperThread::Running(worker);
        }
        Ok(())
    }
    fn reap(&self) {
        loop {
            self.collect();
            let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let retired = state.progress.is_some() && state.is_drained();
            let wake_at = state.progress.as_ref().and_then(|progress| {
                if !progress.forced {
                    Some(progress.force_at)
                } else if Instant::now() < progress.deadline {
                    Some(progress.deadline)
                } else {
                    None
                }
            });
            drop(state);
            self.changed.notify_waiters();
            if retired {
                return;
            }
            self.wake.wait(wake_at);
        }
    }
    fn retire(&self, deadline: Instant) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        state.progress.get_or_insert_with(|| DrainProgress {
            deadline,
            force_at: now + deadline.saturating_duration_since(now).mul_f32(0.8),
            forced: false,
            report: ShutdownReport::default(),
        });
        drop(state);
        self.collect();
        self.service.cancel.cancel();
        self.wake.notify();
        self.changed.notify_waiters();
    }
    fn finish_if_drained(&self) -> Option<ShutdownReport> {
        self.collect();
        let worker = {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.progress.is_none() || !state.is_drained() {
                return None;
            }
            match &state.worker {
                ReaperThread::Unstarted | ReaperThread::Joined => return Some(state.report(self)),
                ReaperThread::Joining => return None,
                ReaperThread::Running(worker) if worker.thread().id() == std::thread::current().id() => {
                    return None;
                }
                ReaperThread::Running(_) => {}
            }
            let ReaperThread::Running(worker) = std::mem::replace(&mut state.worker, ReaperThread::Joining) else {
                unreachable!()
            };
            worker
        };
        self.wake.notify();
        if let Err(payload) = worker.join() {
            self.failed.fetch_add(1, Ordering::AcqRel);
            self.service.record_failure(ServiceFailure::Protocol("服务回收线程异常退出"));
            if let Some(payload) = reclaim_opaque(payload) {
                self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
                    .retained_panics.push(std::mem::ManuallyDrop::new(payload));
            }
            self.service.cancel.cancel();
        }
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.worker = ReaperThread::Joined;
        let report = state.is_drained().then(|| state.report(self));
        drop(state);
        self.changed.notify_waiters();
        report
    }
    fn collect(&self) {
        let (effects, reclaiming) = {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let effects = state.collect(self);
            let reclaiming = !effects.errors.is_empty() || effects.cancel;
            if reclaiming {
                state.reclaiming += 1;
            }
            (effects, reclaiming)
        };
        let retained = effects.errors.into_iter()
            .filter_map(reclaim_opaque)
            .map(std::mem::ManuallyDrop::new)
            .collect::<Vec<_>>();
        if !retained.is_empty() {
            self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
                .retained_panics.extend(retained);
        }
        if effects.cancel {
            self.service.cancel.cancel();
        }
        if reclaiming {
            self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).reclaiming -= 1;
        }
        if effects.joined || reclaiming {
            self.wake.notify();
            self.changed.notify_waiters();
        }
    }
    fn stamp(&self) -> TaskStamp {
        TaskStamp(FailureGuard {
            facts: Arc::new(TaskFacts::default()),
            failed: self.failed.clone(),
            service: self.service.clone(),
        })
    }
}

#[derive(Clone)]
pub struct ServiceContext(Arc<ServiceOwner>);

/// 独立于宿主与调用方 future 的真实任务回收收据。
#[derive(Clone)]
pub struct ServiceRetirement(Arc<TaskRegistry>);
impl ServiceRetirement {
    /// 查询并确认真实任务及回收线程均已 join；不会发起关闭。
    pub fn is_finished(&self) -> bool {
        self.0.finish_if_drained().is_some()
    }
    /// 等待已发起的关闭完成，保留首次期限和迟到失败事实。
    ///
    /// 已开始的阻塞工作必须自行返回。调用方须保持任务所需的 runtime 可运行，
    /// 或接受 runtime 关闭产生的实际取消；本收据不持有或延长 runtime 生命周期。
    pub async fn wait(&self) -> ShutdownReport {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(report) = self.0.finish_if_drained() {
                return report;
            }
            changed.await;
        }
    }
}

pub struct ServiceTask<T> {
    abort: tokio::task::AbortHandle,
    result: tokio::sync::oneshot::Receiver<T>,
}
impl<T> ServiceTask<T> {
    pub fn abort(&self) {
        self.abort.abort();
    }
    pub fn is_finished(&self) -> bool {
        self.abort.is_finished()
    }
}
impl<T> Unpin for ServiceTask<T> {}
impl<T> Future for ServiceTask<T> {
    type Output = Result<T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().result)
            .poll(cx)
            .map(|result| result.map_err(|_| Error::Protocol("共享服务任务未交付结果")))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ShutdownReport {
    pub timed_out: bool,
    pub failed_tasks: usize,
    pub forced_tasks: usize,
}
impl ShutdownReport {
    pub fn is_clean(&self) -> bool {
        !self.timed_out && self.failed_tasks == 0
    }
    pub fn merge(&mut self, other: &Self) {
        self.timed_out |= other.timed_out;
        self.failed_tasks += other.failed_tasks;
        self.forced_tasks += other.forced_tasks;
    }
}

impl ServiceContext {
    pub fn new(id: OutId) -> Self {
        Self::assemble(id, None)
    }
    pub fn with_device(id: OutId, device: DeviceLease) -> Self {
        Self::assemble(id, Some(device))
    }
    fn assemble(id: OutId, device: Option<DeviceLease>) -> Self {
        Self(Arc::new(ServiceOwner {
            instance: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            id,
            device,
            carrier: crate::carrier::CarrierCounter::default(),
            registry: Arc::new(TaskRegistry::new()),
        }))
    }
    pub fn for_test() -> Self {
        Self::new(OutId::parse("test-service").expect("固定测试标识"))
    }
    pub fn id(&self) -> &OutId {
        &self.0.id
    }
    pub fn device(&self) -> Option<DeviceLease> {
        self.0.device.clone()
    }
    /// 只登记本命名服务实际交接的载体字节，不与用户业务量重复相加。
    pub fn record_carrier(&self, sent_bytes: u64, received_bytes: u64) {
        self.0.carrier.record(sent_bytes, received_bytes);
    }
    pub fn carrier_usage(&self) -> crate::CarrierUsage {
        self.0.carrier.snapshot()
    }
    pub fn cancel(&self) -> CancellationToken {
        self.0.registry.service.cancel()
    }
    pub fn fail(&self, failure: ServiceFailure) {
        self.0.registry.service.fail(failure);
    }
    pub fn failure(&self) -> Option<ServiceFailure> {
        self.0.registry.service.failure()
    }
    pub fn check(&self) -> Result<()> {
        self.0.registry.service.check()?;
        if self.0.registry.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).progress.is_some() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
    pub fn status(&self) -> ServiceStatus {
        self.0.registry.service.clone()
    }
    pub fn retirement(&self) -> ServiceRetirement {
        ServiceRetirement(self.0.registry.clone())
    }
    /// 固定首次关闭期限并停止新任务；即使不再等待，回收所有者仍持续收集真实 join。
    pub fn retire(&self, deadline: Instant) {
        self.0.registry.retire(deadline);
    }
    pub fn resource_key(&self, source: &Source) -> ResourceKey {
        ResourceKey {
            instance: self.0.instance,
            source: Some(source.clone()),
            remote_epoch: 1,
        }
    }
    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        self.spawn_tracked(task).map(|_| ())
    }
    pub fn spawn_tracked<F, T>(&self, task: F) -> Result<ServiceTask<T>>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let registry = &self.0.registry;
        let mut state = registry.state.lock().map_err(|_| Error::Protocol("服务任务所有者已损坏"))?;
        registry.service.check()?;
        if state.progress.is_some() {
            return Err(Error::Cancelled);
        }
        registry.start_worker(&mut state)?;
        let (send, result) = tokio::sync::oneshot::channel();
        let stamp = registry.stamp();
        let facts = stamp.0.facts.clone();
        let abort = state.tasks.spawn(TrackedFuture {
            task: Box::pin(task), _failure: stamp.0.clone(), send: Some(send), _stamp: stamp,
        });
        state.facts.insert(abort.id(), facts);
        drop(state);
        registry.wake.notify();
        Ok(ServiceTask { abort, result })
    }
    /// 真实阻塞工作直接登记在服务 JoinSet 中，不用可中止的异步外壳代替其所有权。
    /// 已经开始的闭包不能强杀；超时后的真实 join 及迟到 panic 由回收收据保留。
    pub fn spawn_blocking_tracked<F, T>(&self, task: F) -> Result<ServiceTask<T>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let registry = &self.0.registry;
        let mut state = registry.state.lock().map_err(|_| Error::Protocol("服务任务所有者已损坏"))?;
        registry.service.check()?;
        if state.progress.is_some() {
            return Err(Error::Cancelled);
        }
        registry.start_worker(&mut state)?;
        let (send, result) = tokio::sync::oneshot::channel();
        let stamp = registry.stamp();
        let facts = stamp.0.facts.clone();
        let tracked = TrackedBlocking { task: Some(task), _failure: stamp.0.clone(), send: Some(send), _stamp: stamp };
        let abort = state.tasks.spawn_blocking(move || tracked.run());
        state.facts.insert(abort.id(), facts);
        drop(state);
        registry.wake.notify();
        Ok(ServiceTask { abort, result })
    }
    /// 首次调用固定关闭期限，后续等待不能延长它。丢弃等待不停止回收。
    /// `timed_out` 不证明资源已释放；只有收据完成才确认全部真实 join。
    pub async fn shutdown(&self, deadline: Instant) -> ShutdownReport {
        self.retire(deadline);
        let registry = &self.0.registry;
        let first_deadline = registry.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
            .progress.as_ref().expect("关闭期限已固定").deadline;
        let wait_deadline = deadline.min(first_deadline);
        loop {
            let changed = registry.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(report) = registry.finish_if_drained() {
                return report;
            }
            if Instant::now() >= wait_deadline {
                registry.collect();
                let state = registry.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut report = state.report(registry);
                report.timed_out = true;
                return report;
            }
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep_until(wait_deadline) => {},
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Deadline(Instant);
impl Deadline {
    pub fn after(duration: Duration) -> Self {
        Self(Instant::now() + duration)
    }
    pub fn instant(self) -> Instant {
        self.0
    }
    pub fn remaining(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::poll_fn, sync::Condvar};
    use tokio::{net::UdpSocket, sync::oneshot, time::timeout_at};

    struct Released(Arc<AtomicBool>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
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
        released: Arc<AtomicBool>,
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
            self.released.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn aborting_one_carrier_does_not_cancel_the_service() {
        let service = ServiceContext::for_test();
        let task = service.spawn_tracked(std::future::pending::<()>()).unwrap();
        task.abort();
        assert!(task.await.is_err());
        let next = service.spawn_tracked(async { 7u8 }).unwrap();
        assert_eq!(next.await.unwrap(), 7);
        assert!(!service.cancel().is_cancelled());
        let report = service
            .shutdown(Instant::now() + Duration::from_secs(1))
            .await;
        assert!(report.is_clean());
        assert!(service.shutdown(Instant::now()).await.is_clean());
    }

    #[tokio::test]
    async fn interrupted_service_shutdown_keeps_socket_owner_and_first_deadline() {
        let service = ServiceContext::for_test();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let released = Arc::new(AtomicBool::new(false));
        let witness = Released(released.clone());
        let (started, ready) = oneshot::channel();
        service
            .spawn(async move {
                let _socket = socket;
                let _witness = witness;
                let _ = started.send(());
                std::future::pending::<()>().await;
            })
            .unwrap();
        ready.await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut waiting = Box::pin(service.shutdown(deadline));
        assert!(
            poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(waiting);
        assert!(!released.load(Ordering::Acquire));
        assert!(std::net::UdpSocket::bind(address).is_err());
        assert!(matches!(service.spawn(async {}), Err(Error::Cancelled)));
        let report = timeout_at(
            deadline + Duration::from_millis(300),
            service.shutdown(deadline + Duration::from_secs(10)),
        )
        .await
        .unwrap();
        assert!(report.is_clean());
        assert_eq!(report.forced_tasks, 1);
        assert!(released.load(Ordering::Acquire));
        let _rebound = UdpSocket::bind(address).await.unwrap();
        let repeated = service.shutdown(Instant::now()).await;
        assert!(repeated.is_clean());
        assert_eq!(repeated.forced_tasks, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interrupted_forced_shutdown_keeps_panic_and_unjoined_socket_facts() {
        let service = ServiceContext::for_test();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let released = Arc::new(AtomicBool::new(false));
        let release = ReleaseOnDrop(Arc::new((Mutex::new(false), Condvar::new())));
        let (entered, dropping) = oneshot::channel();
        let socket_owner = BlockedSocketDrop {
            socket: Some(socket),
            entered: Some(entered),
            gate: release.0.clone(),
            released: released.clone(),
        };
        let task = service
            .spawn_tracked(async move {
                let _owner = socket_owner;
                std::future::pending::<()>().await;
            })
            .unwrap();
        let panic_task = service
            .spawn_tracked(async { panic!("受控共享服务任务失败") })
            .unwrap();
        assert!(panic_task.await.is_err());
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut waiting = Box::pin(service.shutdown(deadline));
        tokio::select! {
            report = &mut waiting => panic!("socket析构未释放，不应完成关闭等待 {report:?}"),
            result = timeout_at(deadline + Duration::from_millis(300), dropping) => {
                result.unwrap().unwrap();
            }
        }
        drop(waiting);
        assert!(!task.is_finished());
        assert!(!released.load(Ordering::Acquire));
        assert!(std::net::UdpSocket::bind(address).is_err());
        let report = timeout_at(
            deadline + Duration::from_millis(300),
            service.shutdown(deadline + Duration::from_secs(10)),
        )
        .await
        .unwrap();
        assert!(report.timed_out);
        assert!(!report.is_clean());
        assert_eq!(report.failed_tasks, 1);
        assert_eq!(report.forced_tasks, 1);
        assert!(!released.load(Ordering::Acquire));
        assert!(std::net::UdpSocket::bind(address).is_err());
        release.release();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(task.await.is_err());
        let final_report = service.shutdown(Instant::now()).await;
        assert!(final_report.timed_out);
        assert_eq!(final_report.failed_tasks, 1);
        assert_eq!(final_report.forced_tasks, 1);
        assert!(released.load(Ordering::Acquire));
        let _rebound = UdpSocket::bind(address).await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_service_shutdown_wait_respects_its_own_short_deadline() {
        let service = ServiceContext::for_test();
        service.spawn(std::future::pending()).unwrap();
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut first = Box::pin(service.shutdown(deadline));
        assert!(
            poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        let short = Instant::now() + Duration::from_millis(10);
        let report = timeout_at(short + Duration::from_millis(50), service.shutdown(short))
            .await
            .unwrap();
        assert!(report.timed_out);
        drop(first);
        let report = timeout_at(
            deadline + Duration::from_millis(300),
            service.shutdown(deadline + Duration::from_secs(10)),
        )
        .await
        .unwrap();
        assert!(report.is_clean());
        assert_eq!(report.forced_tasks, 1);
    }
}
