//! 第三方传输任务必须归属于显式运行所有者，关闭后等待真实任务和 QUIC 端点退出。
use std::{fmt, future::Future, io, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::Notify, task::{AbortHandle, JoinHandle}};
use crate::{BoxedTransportStream, ParallelRead, ParallelWrite, TransportStream};

tokio::task_local! { static OWNER: TaskOwner; }

#[derive(Clone)]
pub struct TaskOwner(Arc<Inner>);
struct Inner {
    state: Mutex<State>,
    changed: Notify,
    shutdown: tokio::sync::Mutex<bool>,
    failure: tokio::sync::watch::Sender<bool>,
}
#[derive(Default)]
struct State {
    closed: bool,
    active: usize,
    applications: usize,
    failures: usize,
    handles: Vec<(AbortHandle, bool)>,
    endpoints: Vec<quinn::Endpoint>,
}
impl fmt::Debug for TaskOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("TaskOwner") }
}
impl Default for TaskOwner { fn default() -> Self { Self::new() } }
impl TaskOwner {
    pub fn new() -> Self {
        Self(Arc::new(Inner { state: Mutex::new(State::default()), changed: Notify::new(), shutdown: tokio::sync::Mutex::new(false),failure:tokio::sync::watch::channel(false).0 }))
    }
    pub fn abort_on_drop(&self) -> ShutdownGuard { ShutdownGuard(self.clone()) }
    pub fn failed_tasks(&self) -> usize { self.0.state.lock().map_or(1, |state| state.failures) }
    pub async fn failed(&self) {
        let mut observed=self.0.failure.subscribe();
        loop {
            if *observed.borrow() {return;}
            if observed.changed().await.is_err() {return;}
        }
    }
    fn abort_now(&self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.closed = true;
            for endpoint in &state.endpoints { endpoint.close(quinn::VarInt::from_u32(0), "服务释放".as_bytes()); }
            for (task, _) in &state.handles { task.abort(); }
        }
    }
    pub fn is_closed(&self) -> bool { self.0.state.lock().map_or(true, |state| state.closed) }
    pub fn close_admission(&self) {
        if let Ok(mut state) = self.0.state.lock() { state.closed = true; }
    }
    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        OWNER.scope(self.clone(), future).await
    }
    pub fn wrap(&self, stream: BoxedTransportStream) -> BoxedTransportStream {
        Box::new(OwnedStream { stream, owner: self.clone() })
    }
    fn spawn<F>(&self, future: F, runtime: bool) -> JoinHandle<F::Output>
    where F: Future + Send + 'static, F::Output: Send + 'static {
        let mut state = self.0.state.lock().expect("运行任务所有者已损坏");
        state.active += 1;
        if !runtime { state.applications += 1; }
        let guard = Guard { owner: self.clone(), runtime };
        let owner = self.clone();
        let closed = state.closed;
        let task = tokio::spawn(async move {
            let _guard = guard;
            if closed { return std::future::pending().await; }
            OWNER.scope(owner, future).await
        });
        if closed { task.abort(); }
        state.handles.retain(|(handle, _)| !handle.is_finished());
        state.handles.push((task.abort_handle(), runtime));
        task
    }
    pub async fn shutdown(&self) {
        let mut finished = self.0.shutdown.lock().await;
        if *finished && self.0.state.lock().expect("运行任务所有者已损坏").active == 0 { return; }
        self.close_admission();
        let endpoints = {
            let state = self.0.state.lock().expect("运行任务所有者已损坏");
            for endpoint in &state.endpoints { endpoint.close(quinn::VarInt::from_u32(0), "服务关闭".as_bytes()); }
            for (task, runtime) in &state.handles { if !runtime { task.abort(); } }
            state.endpoints.clone()
        };
        loop {
            let changed = self.0.changed.notified();
            if self.0.state.lock().expect("运行任务所有者已损坏").applications == 0 { break; }
            changed.await;
        }
        for endpoint in endpoints { endpoint.wait_idle().await; }
        {
            let mut state = self.0.state.lock().expect("运行任务所有者已损坏");
            state.endpoints.clear();
            for (task, _) in &state.handles { task.abort(); }
        }
        loop {
            let changed = self.0.changed.notified();
            if self.0.state.lock().expect("运行任务所有者已损坏").active == 0 { break; }
            changed.await;
        }
        self.0.state.lock().expect("运行任务所有者已损坏").handles.clear();
        *finished = true;
    }
}
pub struct ShutdownGuard(TaskOwner);
impl Drop for ShutdownGuard { fn drop(&mut self) { self.0.abort_now(); } }
struct Guard { owner: TaskOwner, runtime: bool }
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.owner.0.state.lock() {
            state.active -= 1;
            if std::thread::panicking() {state.failures+=1;state.closed=true;self.owner.0.failure.send_replace(true);}
            if !self.runtime { state.applications -= 1; }
        }
        self.owner.0.changed.notify_one();
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut() {
            for endpoint in &state.endpoints { endpoint.close(quinn::VarInt::from_u32(0), "服务释放".as_bytes()); }
            for (task, _) in &state.handles { task.abort(); }
        }
    }
}
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where F: Future + Send + 'static, F::Output: Send + 'static {
    match OWNER.try_with(Clone::clone) {
        Ok(owner) => owner.spawn(future, false),
        Err(_) => {drop(future);panic!("传输后台任务缺少运行所有者");}
    }
}
pub(crate) fn register_endpoint(endpoint: &quinn::Endpoint) -> io::Result<()> {
    let owner = OWNER.try_with(Clone::clone).map_err(|_| io::Error::other("QUIC 端点缺少运行所有者"))?;
    let mut state = owner.0.state.lock().map_err(|_| io::Error::other("运行任务所有者已损坏"))?;
    if state.closed {
        endpoint.close(quinn::VarInt::from_u32(0), "服务已关闭".as_bytes());
        return Err(io::Error::other("运行所有者已关闭"));
    }
    state.endpoints.retain(|previous| {
        if previous.open_connections() == 0 { previous.close(quinn::VarInt::from_u32(0), "空闲端点回收".as_bytes()); false } else { true }
    });
    state.endpoints.push(endpoint.clone());
    Ok(())
}
pub(crate) fn spawn_in<F>(tasks: &mut tokio::task::JoinSet<F::Output>, future: F) -> AbortHandle
where F: Future + Send + 'static, F::Output: Send + 'static {
    let owner = OWNER.try_with(Clone::clone).expect("传输子任务缺少运行所有者");
    let mut state = owner.0.state.lock().expect("运行任务所有者已损坏");
    state.active += 1;
    state.applications += 1;
    let guard = Guard { owner: owner.clone(), runtime: false };
    let current = owner.clone();
    let closed = state.closed;
    let task = tasks.spawn(async move {
        let _guard = guard;
        if closed { return std::future::pending().await; }
        OWNER.scope(current, future).await
    });
    if closed { task.abort(); }
    state.handles.retain(|(handle, _)| !handle.is_finished());
    state.handles.push((task.clone(), false));
    task
}
#[derive(Debug)]
pub(crate) struct OwnedRuntime { owner: TaskOwner }
impl OwnedRuntime {
    pub fn current() -> io::Result<Arc<Self>> {
        let owner = OWNER.try_with(Clone::clone).map_err(|_| io::Error::other("QUIC 运行时缺少运行所有者"))?;
        if owner.is_closed() { return Err(io::Error::other("运行所有者已关闭")); }
        Ok(Arc::new(Self { owner }))
    }
}
impl quinn::Runtime for OwnedRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::TokioRuntime, instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output=()> + Send>>) {
        drop(self.owner.spawn(future, true));
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)
    }
    fn now(&self) -> std::time::Instant { quinn::Runtime::now(&quinn::TokioRuntime) }
}
struct OwnedStream { stream: BoxedTransportStream, owner: TaskOwner }
impl AsyncRead for OwnedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut this.stream).poll_read(cx, out))
    }
}
impl AsyncWrite for OwnedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut this.stream).poll_write(cx, bytes))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut this.stream).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut this.stream).poll_shutdown(cx))
    }
}
impl TransportStream for OwnedStream {
    fn release_record_alignment(&mut self) { self.stream.release_record_alignment(); }
    fn into_io_halves(self: Box<Self>) -> (ParallelRead, ParallelWrite) {
        let Self { stream, owner } = *self;
        let (reader, writer) = OWNER.sync_scope(owner.clone(), || stream.into_io_halves());
        (Box::new(OwnedRead { reader, owner: owner.clone() }), Box::new(OwnedWrite { writer, owner }))
    }
    fn poll_read_direct(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut *this.stream).poll_read_direct(cx, out))
    }
    fn poll_write_direct(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut *this.stream).poll_write_direct(cx, bytes))
    }
    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut *this.stream).poll_flush_direct(cx))
    }
    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut *this.stream).poll_shutdown_direct(cx))
    }
}
struct OwnedRead { reader: ParallelRead, owner: TaskOwner }
impl AsyncRead for OwnedRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut this.reader).poll_read(cx, out))
    }
}
struct OwnedWrite { writer: ParallelWrite, owner: TaskOwner }
impl AsyncWrite for OwnedWrite {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut this.writer).poll_write(cx, bytes))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut this.writer).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        OWNER.sync_scope(this.owner.clone(), || Pin::new(&mut this.writer).poll_shutdown(cx))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::atomic::{AtomicUsize, Ordering}, time::Duration};
    #[tokio::test]
    async fn absent_owner_is_rejected_in_tests_and_production() {
        let attempted=std::panic::catch_unwind(||spawn(async {}));
        assert!(attempted.is_err());
    }
    #[tokio::test]
    async fn panic_closes_only_its_owner_and_reports_the_failure() {
        let owner=TaskOwner::new();let other=TaskOwner::new();
        let task=owner.scope(async {spawn(async {panic!("测试任务异常");})}).await;
        assert!(task.await.unwrap_err().is_panic());
        tokio::time::timeout(Duration::from_secs(1),owner.failed()).await.unwrap();
        assert!(owner.is_closed());assert!(!other.is_closed());
        owner.shutdown().await;assert_eq!(owner.failed_tasks(),1);
        other.shutdown().await;
    }
    #[tokio::test]
    async fn abort_before_first_poll_releases_the_admission_guard() {
        let owner = TaskOwner::new();
        let ran = Arc::new(AtomicUsize::new(0));
        owner.scope(async {
            let ran = ran.clone();
            let task = spawn(async move { ran.fetch_add(1, Ordering::SeqCst); std::future::pending::<()>().await });
            task.abort();
        }).await;
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown()).await.unwrap();
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(owner.0.state.lock().unwrap().active, 0);
        owner.shutdown().await;
    }
    #[tokio::test]
    async fn nested_tasks_and_join_sets_inherit_the_same_owner() {
        let owner = TaskOwner::new();
        let (ready, receiving) = tokio::sync::oneshot::channel();
        owner.scope(async {
            drop(spawn(async move {
                drop(spawn(std::future::pending::<()>()));
                let mut set = tokio::task::JoinSet::new();
                spawn_in(&mut set, std::future::pending::<()>());
                let _ = ready.send(());
                std::future::pending::<()>().await;
            }));
        }).await;
        receiving.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown()).await.unwrap();
        assert_eq!(owner.0.state.lock().unwrap().active, 0);
        let ran = Arc::new(AtomicUsize::new(0));
        owner.scope(async {
            let ran = ran.clone();
            let late = spawn(async move { ran.fetch_add(1, Ordering::SeqCst); });
            assert!(late.await.unwrap_err().is_cancelled());
        }).await;
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn quic_runtime_and_endpoint_close_before_shutdown_returns() {
        let owner = TaskOwner::new();
        let address = owner.scope(async {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, OwnedRuntime::current().unwrap()).unwrap();
            register_endpoint(&endpoint).unwrap();
            endpoint.local_addr().unwrap()
        }).await;
        tokio::time::timeout(Duration::from_secs(2), owner.shutdown()).await.unwrap();
        assert_eq!(owner.0.state.lock().unwrap().active, 0);
        drop(std::net::UdpSocket::bind(address).unwrap());
    }
}

