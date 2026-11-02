use kerlico_core::{
    CancellationToken, ConnectContext, Error, FamilyMode, NodeId, Result, ServiceContext,
    ServiceFailure, Source,
};
use std::{
    fs::{File, OpenOptions},
    future::{Future, poll_fn},
    net::TcpListener,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{Instant, sleep_until, timeout},
};

struct Gate(Arc<(Mutex<bool>, Condvar)>);
impl Gate {
    fn new() -> Self {
        Self(Arc::new((Mutex::new(false), Condvar::new())))
    }
    fn release(&self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}
fn blocked(gate: &Arc<(Mutex<bool>, Condvar)>) {
    let mut released = gate.0.lock().unwrap();
    while !*released {
        released = gate.1.wait(released).unwrap();
    }
}
struct LockPath(PathBuf);
impl LockPath {
    fn new() -> (Self, File) {
        let path = std::env::temp_dir().join(format!(
            "kerlico-retirement-{}.lock",
            kerlico_core::UserId::generate()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.try_lock().unwrap();
        (Self(path), file)
    }
    fn is_locked(&self) -> bool {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.0)
            .unwrap()
            .try_lock()
            .is_err()
    }
}
impl Drop for LockPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
struct Output {
    _file: File,
    _socket: TcpListener,
    dropped: Arc<AtomicBool>,
}
impl Drop for Output {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_host_drop_keeps_native_join_late_panic_and_unclaimed_output() {
    for panics in [false, true] {
        let host = ServiceContext::for_test();
        let receipt = host.retirement();
        let healthy = ServiceContext::for_test();
        let (path, file) = LockPath::new();
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let output = Output {
            _file: file,
            _socket: socket,
            dropped: dropped.clone(),
        };
        let gate = Gate::new();
        let wait = gate.0.clone();
        let (entered, ready) = oneshot::channel();
        let task = host
            .spawn_blocking_tracked(move || {
                entered.send(()).unwrap();
                blocked(&wait);
                if panics {
                    panic!("受控迟到 native 失败");
                }
                output
            })
            .unwrap();
        ready.await.unwrap();
        drop(task);
        host.retire(Instant::now() + Duration::from_millis(40));
        drop(host);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!receipt.is_finished());
        assert!(path.is_locked());
        assert!(TcpListener::bind(address).is_err());
        assert!(!dropped.load(Ordering::Acquire));
        assert_eq!(
            healthy.spawn_tracked(async { 23 }).unwrap().await.unwrap(),
            23
        );
        gate.release();
        let report = timeout(Duration::from_secs(2), receipt.wait())
            .await
            .unwrap();
        assert!(report.timed_out);
        assert_eq!(report.failed_tasks, usize::from(panics));
        assert_eq!(report.forced_tasks, 1);
        assert!(receipt.is_finished());
        assert!(dropped.load(Ordering::Acquire));
        assert!(!path.is_locked());
        let _rebound = TcpListener::bind(address).unwrap();
        assert!(!healthy.cancel().is_cancelled());
        assert!(
            healthy
                .shutdown(Instant::now() + Duration::from_secs(1))
                .await
                .is_clean()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_shutdown_distinguishes_completion_time_from_late_observation() {
    for late in [false, true] {
        let host = ServiceContext::for_test();
        let receipt = host.retirement();
        let gate = Gate::new();
        let wait = gate.0.clone();
        let (entered, ready) = oneshot::channel();
        let task = host
            .spawn_blocking_tracked(move || {
                entered.send(()).unwrap();
                blocked(&wait);
            })
            .unwrap();
        ready.await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(250);
        let mut closing = Box::pin(host.shutdown(deadline));
        assert!(
            poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(closing);
        if late {
            sleep_until(deadline + Duration::from_millis(30)).await;
        }
        gate.release();
        task.await.unwrap();
        let completed = timeout(Duration::from_secs(1), receipt.wait())
            .await
            .unwrap();
        assert_eq!(completed.timed_out, late);
        assert_eq!(completed.failed_tasks, 0);
        sleep_until(deadline + Duration::from_millis(50)).await;
        let observed = host.shutdown(deadline + Duration::from_secs(20)).await;
        assert_eq!(observed.timed_out, late);
        assert_eq!(observed.is_clean(), !late);
        assert!(receipt.is_finished());
    }
}

#[test]
fn retirement_crosses_original_runtime_shutdown_without_a_global_runtime_owner() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let gate = Gate::new();
    let wait = gate.0.clone();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let receipt = runtime.block_on(async move {
        let host = ServiceContext::for_test();
        let receipt = host.retirement();
        let (entered, ready) = oneshot::channel();
        host.spawn_blocking_tracked(move || {
            let _socket = socket;
            entered.send(()).unwrap();
            blocked(&wait);
            panic!("原 runtime 关闭后的受控失败");
        })
        .unwrap();
        ready.await.unwrap();
        host.retire(Instant::now());
        drop(host);
        receipt
    });
    runtime.shutdown_background();
    assert!(!receipt.is_finished());
    assert!(TcpListener::bind(address).is_err());
    gate.release();
    let next = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let report = next.block_on(async {
        timeout(Duration::from_secs(2), receipt.wait())
            .await
            .unwrap()
    });
    assert!(report.timed_out);
    assert_eq!(report.failed_tasks, 1);
    assert!(receipt.is_finished());
    let _rebound = TcpListener::bind(address).unwrap();
}

#[tokio::test]
async fn service_first_failure_survives_normal_cancel_and_later_failures() {
    let service = ServiceContext::for_test();
    let status = service.status();
    service.fail(ServiceFailure::Timeout);
    service.fail(ServiceFailure::Protocol("后续失败不得覆盖首因"));
    service.cancel().cancel();
    assert_eq!(status.failure(), Some(ServiceFailure::Timeout));
    assert!(matches!(service.check(), Err(Error::Timeout)));
    assert!(matches!(service.spawn(async {}), Err(Error::Timeout)));
    service.retire(Instant::now());
    drop(service);
    assert_eq!(status.failure(), Some(ServiceFailure::Timeout));
}

#[tokio::test]
async fn service_failure_precedes_expired_deadline_but_normal_scoped_cancel_stays_first() {
    let service = ServiceContext::for_test();
    let node = CancellationToken::new();
    let source = Source::Local {
        node: NodeId::parse("test-node").unwrap(),
    };
    let context = ConnectContext::new(Duration::ZERO).scoped(
        &service,
        &source,
        node.clone(),
        CancellationToken::new(),
        FamilyMode::V4Only,
    );
    service.fail(ServiceFailure::Protocol("服务已失效"));
    assert!(matches!(
        context.run(std::future::pending::<Result<()>>()).await,
        Err(Error::Protocol("服务已失效"))
    ));
    node.cancel();
    assert!(matches!(
        context.run(async { Ok(()) }).await,
        Err(Error::Cancelled)
    ));
}
