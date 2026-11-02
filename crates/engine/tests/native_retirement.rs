use kerlico_config::{OutboundFactory, OutboundPlan, PreparedConfig, Registry, parse};
use kerlico_core::{
    BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramChannel, Destination,
    Error, OpenedTcp, Outbound, Result, ServiceRetirement, TargetPolicy,
};
use kerlico_egress::{EgressRuntime, native_device};
use kerlico_engine::Engine;
use serde_json::json;
use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{sync::{Notify, oneshot}, time::timeout};

#[derive(Clone, Copy)]
enum Startup {
    Pending,
    Ready,
}
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
#[derive(Default)]
struct Probe {
    entered: Notify,
    address: Mutex<Option<SocketAddr>>,
    receipt: Mutex<Option<ServiceRetirement>>,
    cancel: Mutex<Option<CancellationToken>>,
    output_released: Arc<AtomicBool>,
    backend_released: AtomicBool,
}
struct Output {
    socket: Option<TcpListener>,
    released: Arc<AtomicBool>,
}
impl Drop for Output {
    fn drop(&mut self) {
        drop(self.socket.take());
        self.released.store(true, Ordering::Release);
    }
}
struct Backend(Arc<Probe>);
impl Drop for Backend {
    fn drop(&mut self) {
        self.0.backend_released.store(true, Ordering::Release);
    }
}
fn capabilities() -> Capabilities {
    Capabilities { tcp: true, tcp_eof: false, udp: false }
}
impl Outbound for Backend {
    fn capabilities(&self) -> Capabilities {
        capabilities()
    }
    fn connect_tcp<'a>(&'a self, _: &'a Destination, _: &'a ConnectContext) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async { Err(Error::Unsupported("回收回归不建立业务流")) })
    }
    fn connect_udp<'a>(&'a self, _: &'a Destination, _: &'a ConnectContext) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("回收回归不建立业务流")) })
    }
}
struct Factory {
    probe: Arc<Probe>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    startup: Startup,
    panics: bool,
}
impl OutboundFactory for Factory {
    fn kind(&self) -> &'static str {
        "native-retirement-test"
    }
    fn compile(&self, _: &serde_json::Value) -> Result<OutboundPlan> {
        let probe = self.probe.clone();
        let gate = self.gate.clone();
        let startup = self.startup;
        let panics = self.panics;
        Ok(OutboundPlan::new(capabilities(), false, TargetPolicy::Remote, move |host| {
            Box::pin(async move {
                *probe.receipt.lock().unwrap() = Some(host.retirement());
                *probe.cancel.lock().unwrap() = Some(host.cancel());
                let socket = TcpListener::bind("127.0.0.1:0")?;
                *probe.address.lock().unwrap() = Some(socket.local_addr()?);
                let output = Output { socket: Some(socket), released: probe.output_released.clone() };
                let observed = probe.clone();
                let retained_host = host.clone();
                let (entered, ready) = oneshot::channel();
                let task = host.spawn_blocking_tracked(move || {
                    let _retained_host = retained_host;
                    observed.entered.notify_one();
                    let _ = entered.send(());
                    let mut released = gate.0.lock().unwrap();
                    while !*released {
                        released = gate.1.wait(released).unwrap();
                    }
                    drop(released);
                    if panics {
                        panic!("启动事务结束后的受控 native 失败");
                    }
                    output
                })?;
                ready.await.map_err(|_| Error::Protocol("受控任务未开始"))?;
                match startup {
                    Startup::Pending => {
                        let _output = task.await?;
                        Err(Error::Protocol("受控启动应在任务完成前超时或被丢弃"))
                    }
                    Startup::Ready => {
                        drop(task);
                        Ok(Arc::new(Backend(probe)) as Arc<dyn Outbound>)
                    }
                }
            })
        }))
    }
}
fn prepare(probe: Arc<Probe>, gate: &Gate, startup: Startup, panics: bool) -> PreparedConfig {
    let mut registry = Registry::default();
    registry.register(Factory { probe, gate: gate.0.clone(), startup, panics }).unwrap();
    let input = json!({
        "version": 2,
        "outbounds": [{"tag": "native", "type": "native-retirement-test"}],
        "inbounds": [{"tag": "entry", "type": "tcp-forward", "listen": "127.0.0.1:0", "outbound": "native", "target": {"host": "unused.invalid", "port": 80}}],
        "limits": {"drain_timeout_ms": 50}
    });
    registry.prepare(parse(&serde_json::to_vec(&input).unwrap()).unwrap()).unwrap()
}
async fn assert_reclaimed(probe: &Probe, gate: &Gate, panics: bool, timed_out: bool) {
    let receipt = probe.receipt.lock().unwrap().as_ref().unwrap().clone();
    let address = probe.address.lock().unwrap().unwrap();
    assert!(probe.cancel.lock().unwrap().as_ref().unwrap().is_cancelled());
    assert!(!receipt.is_finished());
    assert!(!probe.output_released.load(Ordering::Acquire));
    assert!(TcpListener::bind(address).is_err());
    gate.release();
    let report = timeout(Duration::from_secs(2), receipt.wait()).await.unwrap();
    assert_eq!(report.timed_out, timed_out);
    assert_eq!(report.failed_tasks, usize::from(panics));
    assert!(receipt.is_finished());
    assert!(probe.output_released.load(Ordering::Acquire));
    let _rebound = TcpListener::bind(address).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_startup_timeout_retains_native_join_after_last_external_host_is_gone() {
    for panics in [false, true] {
        let gate = Gate::new();
        let probe = Arc::new(Probe::default());
        let plan = prepare(probe.clone(), &gate, Startup::Pending, panics).into_parts().egress;
        let running = tokio::spawn(EgressRuntime::start(plan, native_device(), Duration::from_millis(250)));
        timeout(Duration::from_secs(2), probe.entered.notified()).await.unwrap();
        let result = timeout(Duration::from_secs(2), running).await.unwrap().unwrap();
        assert!(matches!(result, Err(Error::Startup { primary, cleanup_timed_out: true, cleanup_failures: 0 }) if matches!(*primary, Error::Timeout)));
        assert_reclaimed(&probe, &gate, panics, true).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_startup_future_explicitly_retires_tasks_holding_host_clones() {
    let gate = Gate::new();
    let probe = Arc::new(Probe::default());
    let plan = prepare(probe.clone(), &gate, Startup::Pending, false).into_parts().egress;
    let mut starting = Box::pin(EgressRuntime::start(plan, native_device(), Duration::from_secs(2)));
    tokio::select! {
        _ = &mut starting => panic!("受控启动应保持等待"),
        _ = probe.entered.notified() => {},
    }
    drop(starting);
    assert_reclaimed(&probe, &gate, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumed_engine_error_preserves_receipt_and_late_native_cleanup() {
    for panics in [false, true] {
        let gate = Gate::new();
        let probe = Arc::new(Probe::default());
        let engine = Engine::bind(prepare(probe.clone(), &gate, Startup::Ready, panics)).await.unwrap();
        let receipts = engine.service_retirements();
        assert_eq!(receipts.len(), 1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = timeout(Duration::from_secs(2), engine.run(cancel)).await.unwrap();
        assert!(matches!(result, Err(Error::Shutdown { cleanup_timed_out: true, cleanup_failures: 0, .. })));
        assert!(probe.backend_released.load(Ordering::Acquire));
        assert!(!receipts[0].1.is_finished());
        assert_reclaimed(&probe, &gate, panics, true).await;
        assert!(receipts[0].1.is_finished());
    }
}
