use kerlico_core::{Error, ServiceContext};
use std::{
    future::{Future, poll_fn},
    net::TcpListener,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{sync::oneshot, time::{Instant, timeout}};

struct Gate(Arc<(Mutex<bool>, Condvar)>);
impl Gate {
    fn new() -> Self {
        Self(Arc::new((Mutex::new(false), Condvar::new())))
    }
    fn release(&self) {
        let (released, changed) = &*self.0;
        *released.lock().unwrap() = true;
        changed.notify_all();
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn running_blocking_resource_survives_abort_and_is_joined_after_timeout() {
    let host = ServiceContext::for_test();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let gate = Gate::new();
    let wait = gate.0.clone();
    let (started, ready) = oneshot::channel();
    let task = host.spawn_blocking_tracked(move || {
        let _socket = socket;
        started.send(()).unwrap();
        let (released, changed) = &*wait;
        let mut released = released.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        17u8
    }).unwrap();
    ready.await.unwrap();
    task.abort();
    let deadline = Instant::now() + Duration::from_millis(80);
    let report = host.shutdown(deadline).await;
    assert!(report.timed_out);
    assert_eq!(report.forced_tasks, 1);
    assert_eq!(report.failed_tasks, 0);
    assert!(!task.is_finished());
    assert!(TcpListener::bind(address).is_err());
    gate.release();
    assert_eq!(timeout(Duration::from_secs(1), task).await.unwrap().unwrap(), 17);
    let report = host.shutdown(Instant::now()).await;
    assert!(report.timed_out);
    assert_eq!(report.failed_tasks, 0);
    let _rebound = TcpListener::bind(address).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_blocking_shutdown_retains_first_deadline_and_late_panic() {
    let host = ServiceContext::for_test();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let gate = Gate::new();
    let wait = gate.0.clone();
    let (started, ready) = oneshot::channel();
    let task = host.spawn_blocking_tracked(move || {
        let _socket = socket;
        started.send(()).unwrap();
        let (released, changed) = &*wait;
        let mut released = released.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        drop(released);
        panic!("受控阻塞工作失败");
    }).unwrap();
    ready.await.unwrap();
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut first = Box::pin(host.shutdown(deadline));
    assert!(poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx))).await.is_pending());
    let short = host.shutdown(Instant::now() + Duration::from_millis(5)).await;
    assert!(short.timed_out);
    drop(first);
    let report = timeout(Duration::from_millis(500), host.shutdown(deadline + Duration::from_secs(2)))
        .await.unwrap();
    assert!(report.timed_out);
    assert!(TcpListener::bind(address).is_err());
    gate.release();
    assert!(timeout(Duration::from_secs(1), task).await.unwrap().is_err());
    let report = host.shutdown(Instant::now()).await;
    assert!(report.timed_out);
    assert_eq!(report.failed_tasks, 1);
    assert!(host.cancel().is_cancelled());
    let _rebound = TcpListener::bind(address).unwrap();
}

#[tokio::test]
async fn closed_service_rejects_blocking_work_without_running_it() {
    let host = ServiceContext::for_test();
    assert!(host.shutdown(Instant::now() + Duration::from_secs(1)).await.is_clean());
    let ran = Arc::new(AtomicBool::new(false));
    let observed = ran.clone();
    assert!(matches!(host.spawn_blocking_tracked(move || {
        observed.store(true, Ordering::Release);
    }), Err(Error::Cancelled)));
    assert!(!ran.load(Ordering::Acquire));
}
