use kerlico_core::ServiceContext;
use std::time::Duration;
use tokio::{sync::oneshot, time::timeout};

struct Payload {
    host: Option<ServiceContext>,
    destroyed: Option<oneshot::Sender<()>>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        drop(self.host.take());
        if let Some(destroyed) = self.destroyed.take() {
            let _ = destroyed.send(());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panic_payload_last_host_drop_is_reclaimed_without_registry_lock_reentry() {
    let host = ServiceContext::for_test();
    let receipt = host.retirement();
    let (release, gate) = oneshot::channel();
    let (destroyed, finished) = oneshot::channel();
    let payload = Payload {
        host: Some(host.clone()),
        destroyed: Some(destroyed),
    };
    let task = host
        .spawn_tracked(async move {
            gate.await.expect("受控任务启动闸门不得提前释放");
            std::panic::panic_any(payload);
        })
        .expect("受控任务应成功登记");

    drop(host);
    release.send(()).expect("任务应仍等待启动闸门");
    let task_result = timeout(Duration::from_secs(2), task)
        .await
        .expect("发生panic的Tokio任务应完成，不能由夹具阻塞执行器");
    assert!(task_result.is_err(), "受控panic不得交付成功结果");

    let payload_result = timeout(Duration::from_secs(1), finished).await;
    assert!(
        matches!(payload_result, Ok(Ok(()))),
        "任务panic后，最后宿主的析构必须完成；JoinError析构不得重入持有的任务注册表锁"
    );

    let report = timeout(Duration::from_secs(2), receipt.wait())
        .await
        .expect("payload析构完成后应可等待真实任务及回收线程join");
    assert_eq!(report.failed_tasks, 1);
    assert!(receipt.is_finished());
}

use kerlico_core::{Error, OutId, ServiceFailure, ServiceRetirement};
use std::{
    future::{Future, poll_fn},
    net::TcpListener,
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll, Wake, Waker},
};
use tokio::time::Instant;

struct BlockingGate(Arc<(Mutex<bool>, Condvar)>);
impl BlockingGate {
    fn new() -> Self {
        Self(Arc::new((Mutex::new(false), Condvar::new())))
    }
    fn release(&self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }
}
impl Drop for BlockingGate {
    fn drop(&mut self) {
        self.release();
    }
}

struct PanickingPayload {
    host: Option<ServiceContext>,
    destroyed: Option<oneshot::Sender<()>>,
}
impl Drop for PanickingPayload {
    fn drop(&mut self) {
        drop(self.host.take());
        let _ = self.destroyed.take().unwrap().send(());
        std::panic::panic_any(String::from("受控panic对象的析构失败"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payload_drop_panic_keeps_reaper_receipt_and_native_task_alive() {
    let host = ServiceContext::for_test();
    let status = host.status();
    let receipt = host.retirement();
    let healthy = ServiceContext::new(OutId::parse("healthy-service").unwrap());
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let native_gate = BlockingGate::new();
    let gate = native_gate.0.clone();
    let (entered, ready) = oneshot::channel();
    let native = host
        .spawn_blocking_tracked(move || {
            let _socket = socket;
            entered.send(()).unwrap();
            let mut released = gate.0.lock().unwrap();
            while !*released {
                released = gate.1.wait(released).unwrap();
            }
            73u8
        })
        .unwrap();
    timeout(Duration::from_secs(1), ready)
        .await
        .unwrap()
        .unwrap();
    let (release, gate) = oneshot::channel();
    let (destroyed, finished) = oneshot::channel();
    let payload = PanickingPayload {
        host: Some(host.clone()),
        destroyed: Some(destroyed),
    };
    let task = host
        .spawn_tracked(async move {
            gate.await.unwrap();
            std::panic::panic_any(payload);
        })
        .unwrap();
    host.fail(ServiceFailure::Timeout);
    drop(host);
    release.send(()).unwrap();
    assert!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .is_err()
    );
    timeout(Duration::from_secs(1), finished)
        .await
        .unwrap()
        .unwrap();
    let mut waiting = Box::pin(receipt.wait());
    assert!(
        poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert!(!receipt.is_finished());
    assert!(!native.is_finished());
    assert!(TcpListener::bind(address).is_err());
    assert_eq!(
        healthy
            .spawn_tracked(async { 23u8 })
            .unwrap()
            .await
            .unwrap(),
        23
    );
    assert!(!healthy.cancel().is_cancelled());

    native_gate.release();
    assert_eq!(
        timeout(Duration::from_secs(1), native)
            .await
            .unwrap()
            .unwrap(),
        73
    );
    let report = timeout(Duration::from_secs(2), waiting).await.unwrap();
    assert!(report.timed_out);
    assert!(!report.is_clean());
    assert_eq!(report.failed_tasks, 1);
    assert_eq!(report.forced_tasks, 1);
    assert_eq!(status.failure(), Some(ServiceFailure::Timeout));
    assert!(receipt.is_finished());
    let _rebound = TcpListener::bind(address).unwrap();
    assert!(
        healthy
            .shutdown(Instant::now() + Duration::from_secs(1))
            .await
            .is_clean()
    );
}

struct WakeObserved {
    task_rejected: bool,
    retirement_pending: bool,
    first_failure_preserved: bool,
}

struct ReenterOnWake {
    host: ServiceContext,
    receipt: ServiceRetirement,
    completed: Mutex<Option<oneshot::Sender<WakeObserved>>>,
}
impl ReenterOnWake {
    fn reenter(&self) {
        let Some(completed) = self.completed.lock().unwrap().take() else {
            return;
        };
        let task_rejected = matches!(self.host.spawn(async {}), Err(Error::Timeout));
        self.host.retire(Instant::now() + Duration::from_secs(1));
        let retirement_pending = !self.receipt.is_finished();
        let first_failure_preserved = matches!(self.host.check(), Err(Error::Timeout));
        let _ = completed.send(WakeObserved {
            task_rejected,
            retirement_pending,
            first_failure_preserved,
        });
    }
}
impl Wake for ReenterOnWake {
    fn wake(self: Arc<Self>) {
        self.reenter();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.reenter();
    }
}

struct CancellingPayload {
    trigger: ServiceContext,
    destroyed: Option<oneshot::Sender<()>>,
}
impl Drop for CancellingPayload {
    fn drop(&mut self) {
        self.trigger.fail(ServiceFailure::Rejected);
        let _ = self.destroyed.take().unwrap().send(());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payload_cancellation_wake_reenters_registry_and_cannot_finish_its_own_batch() {
    let host = ServiceContext::for_test();
    let receipt = host.retirement();
    let trigger = ServiceContext::new(OutId::parse("wake-trigger").unwrap());
    let cancellation = trigger.cancel();
    let mut cancelled = Box::pin(cancellation.cancelled());
    let (completed, observed) = oneshot::channel();
    let waker = Waker::from(Arc::new(ReenterOnWake {
        host: host.clone(),
        receipt: receipt.clone(),
        completed: Mutex::new(Some(completed)),
    }));
    assert!(
        cancelled
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    let (destroyed, finished) = oneshot::channel();
    let payload = CancellingPayload {
        trigger: trigger.clone(),
        destroyed: Some(destroyed),
    };
    let (release, gate) = oneshot::channel();
    let task = host
        .spawn_tracked(async move {
            gate.await.unwrap();
            std::panic::panic_any(payload);
        })
        .unwrap();
    host.fail(ServiceFailure::Timeout);
    release.send(()).unwrap();
    assert!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .is_err()
    );
    let observed = timeout(Duration::from_secs(1), observed)
        .await
        .unwrap()
        .unwrap();
    assert!(observed.task_rejected);
    assert!(observed.retirement_pending);
    assert!(observed.first_failure_preserved);
    timeout(Duration::from_secs(1), finished)
        .await
        .unwrap()
        .unwrap();
    drop(cancelled);
    drop(waker);

    let report = timeout(Duration::from_secs(2), receipt.wait())
        .await
        .unwrap();
    assert!(!report.timed_out);
    assert_eq!(report.failed_tasks, 1);
    assert!(!report.is_clean());
    assert!(receipt.is_finished());
    assert_eq!(host.failure(), Some(ServiceFailure::Timeout));
    assert_eq!(trigger.failure(), Some(ServiceFailure::Rejected));
    assert_eq!(trigger.shutdown(Instant::now()).await.failed_tasks, 0);
}

struct QueryRetirementOnWake {
    receipt: ServiceRetirement,
    completed: Mutex<Option<std::sync::mpsc::Sender<bool>>>,
}
impl QueryRetirementOnWake {
    fn query(&self) {
        let Some(completed) = self.completed.lock().unwrap().take() else {
            return;
        };
        let _ = completed.send(self.receipt.is_finished());
    }
}
impl Wake for QueryRetirementOnWake {
    fn wake(self: Arc<Self>) {
        self.query();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.query();
    }
}

#[tokio::test]
async fn retirement_notification_query_reentry_preserves_normal_waiter_completion() {
    let host = ServiceContext::for_test();
    let receipt = host.retirement();
    let native_gate = BlockingGate::new();
    let gate = native_gate.0.clone();
    let (entered, ready) = oneshot::channel();
    let native = host
        .spawn_blocking_tracked(move || {
            entered.send(()).unwrap();
            let mut released = gate.0.lock().unwrap();
            while !*released {
                released = gate.1.wait(released).unwrap();
            }
            19u8
        })
        .unwrap();
    timeout(Duration::from_secs(1), ready)
        .await
        .unwrap()
        .unwrap();
    host.retire(Instant::now());
    let (registered, pending) = oneshot::channel();
    let normal_receipt = receipt.clone();
    let normal = tokio::spawn(async move {
        registered.send(()).unwrap();
        normal_receipt.wait().await
    });
    timeout(Duration::from_secs(1), pending)
        .await
        .unwrap()
        .unwrap();
    let (completed, observed) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(QueryRetirementOnWake {
        receipt: receipt.clone(),
        completed: Mutex::new(Some(completed)),
    }));
    let mut notified = Box::pin(receipt.wait());
    assert!(
        notified
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );

    native_gate.release();
    let observed = observed
        .recv_timeout(Duration::from_secs(1))
        .expect("当前runtime暂停poll时，独立回收线程的通知仍须完成同步收据查询");
    assert!(!observed, "回收线程的通知回调不能把自身join登记为完成");
    assert_eq!(
        timeout(Duration::from_secs(1), native)
            .await
            .unwrap()
            .unwrap(),
        19
    );
    let report = timeout(Duration::from_secs(2), normal)
        .await
        .unwrap()
        .unwrap();
    assert!(report.timed_out);
    assert_eq!(report.failed_tasks, 0);
    assert_eq!(report.forced_tasks, 1);
    let repeated = timeout(Duration::from_secs(1), notified).await.unwrap();
    assert!(repeated.timed_out);
    assert_eq!(repeated.failed_tasks, 0);
    assert!(receipt.is_finished());
}
