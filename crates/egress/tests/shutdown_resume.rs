use kerlico_config::{OutboundFactory, OutboundPlan, Registry, parse};
use kerlico_core::{
    BoxFuture, Capabilities, ConnectContext, DatagramChannel, Destination, Error, OpenedTcp,
    Outbound, Result, TargetPolicy,
};
use kerlico_egress::{EgressRuntime, native_device};
use serde_json::json;
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, oneshot},
    time::{Instant, timeout, timeout_at},
};

#[derive(Clone, Copy)]
enum TaskExit {
    OnCancel,
    Pending,
    LateSuccess,
    LatePanic,
}
#[derive(Clone, Copy)]
enum BackendExit {
    FailOnce,
    Pending,
}
#[derive(Default)]
struct Probe {
    address: Mutex<Option<SocketAddr>>,
    released: Arc<AtomicBool>,
    calls: AtomicUsize,
    entered: Notify,
    blocked: Notify,
    release: Arc<(Mutex<bool>, Condvar)>,
    task: Mutex<Option<kerlico_core::ServiceTask<()>>>,
}
struct SocketOwner {
    socket: Option<UdpSocket>,
    released: Arc<AtomicBool>,
}
impl Drop for SocketOwner {
    fn drop(&mut self) {
        drop(self.socket.take());
        self.released.store(true, Ordering::Release);
    }
}
struct Backend {
    probe: Arc<Probe>,
    exit: BackendExit,
}
impl Outbound for Backend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async { Err(Error::Unsupported("关闭回归不建立业务流")) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("关闭回归不建立业务流")) })
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let previous = self.probe.calls.fetch_add(1, Ordering::AcqRel);
            self.probe.entered.notify_one();
            match self.exit {
                BackendExit::FailOnce if previous == 0 => Err(Error::Protocol("受控关闭失败")),
                BackendExit::FailOnce => Ok(()),
                BackendExit::Pending => std::future::pending().await,
            }
        })
    }
}
struct Factory {
    name: &'static str,
    probe: Arc<Probe>,
    backend_exit: BackendExit,
    task_exit: TaskExit,
}
impl OutboundFactory for Factory {
    fn kind(&self) -> &'static str {
        self.name
    }
    fn compile(&self, _: &serde_json::Value) -> Result<OutboundPlan> {
        let probe = self.probe.clone();
        let backend_exit = self.backend_exit;
        let task_exit = self.task_exit;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: false,
            },
            false,
            TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    let socket = UdpSocket::bind("127.0.0.1:0").await?;
                    *probe.address.lock().unwrap() = Some(socket.local_addr()?);
                    let owner = SocketOwner {
                        socket: Some(socket),
                        released: probe.released.clone(),
                    };
                    let cancel = host.cancel();
                    let (started, ready) = oneshot::channel();
                    let task_probe = probe.clone();
                    let task = host.spawn_tracked(async move {
                        let _owner = owner;
                        let _ = started.send(());
                        match task_exit {
                            TaskExit::OnCancel => cancel.cancelled().await,
                            TaskExit::Pending => std::future::pending().await,
                            TaskExit::LateSuccess | TaskExit::LatePanic => {
                                cancel.cancelled().await;
                                let (ready, changed) = &*task_probe.release;
                                let mut ready = ready.lock().unwrap();
                                task_probe.blocked.notify_one();
                                while !*ready {
                                    ready = changed.wait(ready).unwrap();
                                }
                                drop(ready);
                                if matches!(task_exit, TaskExit::LatePanic) {
                                    panic!("受控迟到服务任务失败");
                                }
                            }
                        }
                    })?;
                    *probe.task.lock().unwrap() = Some(task);
                    ready.await.unwrap();
                    Ok(Arc::new(Backend {
                        probe,
                        exit: backend_exit,
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}

async fn runtime(last_task_exit: TaskExit) -> (EgressRuntime, Arc<Probe>, Arc<Probe>) {
    let earlier = Arc::new(Probe::default());
    let later = Arc::new(Probe::default());
    let mut registry = Registry::default();
    registry
        .register(Factory {
            name: "earlier-shutdown-test",
            probe: earlier.clone(),
            backend_exit: BackendExit::Pending,
            task_exit: TaskExit::Pending,
        })
        .unwrap();
    registry
        .register(Factory {
            name: "later-shutdown-test",
            probe: later.clone(),
            backend_exit: BackendExit::FailOnce,
            task_exit: last_task_exit,
        })
        .unwrap();
    let input = json!({
        "version": 2,
        "outbounds": [
            {"tag": "earlier", "type": "earlier-shutdown-test"},
            {"tag": "later", "type": "later-shutdown-test"}
        ],
        "inbounds": [
            {"tag": "first", "type": "tcp-forward", "listen": "127.0.0.1:0", "outbound": "earlier", "target": {"host": "unused.invalid", "port": 80}},
            {"tag": "second", "type": "tcp-forward", "listen": "127.0.0.1:0", "outbound": "later", "target": {"host": "unused.invalid", "port": 80}}
        ]
    });
    let plan = registry
        .prepare(parse(&serde_json::to_vec(&input).unwrap()).unwrap())
        .unwrap()
        .into_parts()
        .egress;
    let runtime = EgressRuntime::start(plan, native_device(), Duration::from_secs(1))
        .await
        .unwrap();
    (runtime, earlier, later)
}

async fn assert_sockets_released(earlier: &Probe, later: &Probe) {
    timeout(Duration::from_secs(1), async {
        while !earlier.released.load(Ordering::Acquire) || !later.released.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for probe in [earlier, later] {
        let address = probe.address.lock().unwrap().unwrap();
        let _rebound = UdpSocket::bind(address).await.unwrap();
    }
}

#[tokio::test]
async fn interrupted_runtime_shutdown_keeps_backend_result_and_later_service_deadline() {
    let (runtime, earlier, later) = runtime(TaskExit::Pending).await;
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut first = Box::pin(runtime.shutdown_at(deadline));
    assert!(
        poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert_eq!(later.calls.load(Ordering::Acquire), 1);
    assert_eq!(earlier.calls.load(Ordering::Acquire), 0);
    drop(first);
    for probe in [&earlier, &later] {
        assert!(!probe.released.load(Ordering::Acquire));
        assert!(std::net::UdpSocket::bind(probe.address.lock().unwrap().unwrap()).is_err());
    }
    let report = timeout_at(
        deadline + Duration::from_millis(300),
        runtime.shutdown_at(deadline + Duration::from_secs(10)),
    )
    .await
    .unwrap();
    assert!(report.timed_out);
    assert!(!report.is_clean());
    assert_eq!(report.failed_tasks, 1);
    assert_eq!(report.forced_tasks, 2);
    assert_eq!(later.calls.load(Ordering::Acquire), 1);
    assert_eq!(earlier.calls.load(Ordering::Acquire), 1);
    assert_sockets_released(&earlier, &later).await;
    let repeated = runtime.shutdown_at(Instant::now()).await;
    assert!(repeated.timed_out);
    assert_eq!(repeated.failed_tasks, 1);
    assert_eq!(repeated.forced_tasks, 2);
    assert_eq!(later.calls.load(Ordering::Acquire), 1);
    assert_eq!(earlier.calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn interrupted_runtime_shutdown_keeps_prior_service_report_and_short_waiter_budget() {
    let (runtime, earlier, later) = runtime(TaskExit::OnCancel).await;
    let deadline = Instant::now() + Duration::from_millis(200);
    let mut first = Box::pin(runtime.shutdown_at(deadline));
    tokio::select! {
        report = &mut first => panic!("第二服务应仍在等待，提前返回 {report:?}"),
        _ = earlier.entered.notified() => {}
    }
    assert!(later.released.load(Ordering::Acquire));
    assert!(!earlier.released.load(Ordering::Acquire));
    assert_eq!(later.calls.load(Ordering::Acquire), 1);
    assert_eq!(earlier.calls.load(Ordering::Acquire), 1);
    let short = Instant::now() + Duration::from_millis(10);
    let short_report = timeout_at(
        short + Duration::from_millis(50),
        runtime.shutdown_at(short),
    )
    .await
    .unwrap();
    assert!(short_report.timed_out);
    assert!(!earlier.released.load(Ordering::Acquire));
    drop(first);
    let report = timeout_at(
        deadline + Duration::from_millis(300),
        runtime.shutdown_at(deadline + Duration::from_secs(10)),
    )
    .await
    .unwrap();
    assert!(report.timed_out);
    assert_eq!(report.failed_tasks, 1);
    assert_eq!(report.forced_tasks, 1);
    assert_eq!(later.calls.load(Ordering::Acquire), 1);
    assert_eq!(earlier.calls.load(Ordering::Acquire), 2);
    assert_sockets_released(&earlier, &later).await;
    let repeated = runtime.shutdown_at(Instant::now()).await;
    assert!(repeated.timed_out);
    assert_eq!(repeated.failed_tasks, 1);
    assert_eq!(repeated.forced_tasks, 1);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timed_out_runtime_rejoins_late_services_and_collects_late_panic_once() {
    for exit in [TaskExit::LateSuccess, TaskExit::LatePanic] {
        let (runtime, earlier, later) = runtime(exit).await;
        let release = ReleaseOnDrop(later.release.clone());
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut first = Box::pin(runtime.shutdown_at(deadline));
        tokio::select! {
            report = &mut first => panic!("迟到任务尚未进入受控同步段 {report:?}"),
            _ = later.blocked.notified() => {}
        }
        let report = timeout_at(deadline + Duration::from_millis(300), first)
            .await
            .unwrap();
        assert!(report.timed_out);
        assert_eq!(report.failed_tasks, 1);
        assert_eq!(report.forced_tasks, 2);
        assert_eq!(earlier.calls.load(Ordering::Acquire), 1);
        assert_eq!(later.calls.load(Ordering::Acquire), 1);
        assert!(!later.task.lock().unwrap().as_ref().unwrap().is_finished());
        assert!(!later.released.load(Ordering::Acquire));
        assert!(std::net::UdpSocket::bind(later.address.lock().unwrap().unwrap()).is_err());
        release.release();
        timeout(Duration::from_secs(1), async {
            for probe in [&earlier, &later] {
                while !probe.task.lock().unwrap().as_ref().unwrap().is_finished() {
                    tokio::task::yield_now().await;
                }
            }
        })
        .await
        .unwrap();
        let expected_failures = 1 + usize::from(matches!(exit, TaskExit::LatePanic));
        for _ in 0..2 {
            let report = runtime.shutdown_at(Instant::now()).await;
            assert!(report.timed_out);
            assert_eq!(report.failed_tasks, expected_failures);
            assert_eq!(report.forced_tasks, 2);
            assert_eq!(earlier.calls.load(Ordering::Acquire), 1);
            assert_eq!(later.calls.load(Ordering::Acquire), 1);
        }
        assert_sockets_released(&earlier, &later).await;
    }
}
