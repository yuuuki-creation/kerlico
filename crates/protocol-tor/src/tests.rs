use crate::{
    TorFactory, error::Failure, network::CarrierProvider, runtime::TaskOwner, storage::StateLease,
    stream::TorStream,
};
use futures::{FutureExt as _, task::SpawnExt as _};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, ConnectContext, DeviceLease, DeviceNetwork, Error, FamilyMode, OpenedTcp, OutId,
    Result, ServiceContext, TargetPolicy, TcpConnectInfo,
};
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Instant, timeout},
};
use tor_rtcompat::{Blocking, NetStreamProvider, TcpConnectOptions, TcpListenOptions, UdpProvider};

pub(super) struct TestDevice {
    calls: AtomicUsize,
    addresses: Mutex<Vec<SocketAddr>>,
}
impl TestDevice {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            addresses: Mutex::new(Vec::new()),
        })
    }
}
impl DeviceNetwork for TestDevice {
    fn connect_tcp(&self, address: SocketAddr) -> BoxFuture<'_, Result<OpenedTcp>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.addresses.lock().unwrap().push(address);
            if !address.ip().is_loopback() {
                return Err(Error::Unsupported("受控测试设备只允许回环TCP"));
            }
            Ok(OpenedTcp {
                stream: Box::new(tokio::net::TcpStream::connect(address).await?),
                info: TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp(&self, _: SocketAddr) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>> {
        Box::pin(async { Err(Error::Unsupported("测试未开放UDP")) })
    }
    fn udp_association(&self, _: FamilyMode) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>> {
        Box::pin(async { Err(Error::Unsupported("测试未开放UDP")) })
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    host: ServiceContext,
    owner: TaskOwner,
    storage: Arc<StateLease>,
    device: Arc<TestDevice>,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let id = OutId::parse("tor-test").unwrap();
        let storage =
            Arc::new(StateLease::open_at(directory.path(), Path::new("tor"), &id).unwrap());
        let device = TestDevice::new();
        let host = ServiceContext::with_device(id, DeviceLease::borrow(device.clone()));
        let owner =
            TaskOwner::new(host.clone(), storage.clone(), Duration::from_millis(100)).unwrap();
        Self {
            _directory: directory,
            host,
            owner,
            storage,
            device,
        }
    }
}

#[test]
fn tor_factory_exposes_remote_tcp_without_eof_or_udp() {
    let plan = TorFactory
        .compile(&serde_json::json!({"data_directory":"state/tor"}))
        .unwrap();
    assert_eq!(plan.target_policy(), TargetPolicy::Remote);
    assert!(plan.capabilities().tcp);
    assert!(!plan.capabilities().tcp_eof);
    assert!(!plan.capabilities().udp);
    assert!(!plan.supports_udp_association());
}

#[tokio::test]
async fn tor_async_spawn_registers_nested_real_socket_and_joins_on_shutdown() {
    let fixture = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let nested = fixture.owner.clone();
    let (started, ready) = tokio::sync::oneshot::channel();
    fixture
        .owner
        .spawn(async move {
            nested
                .spawn(async move {
                    let _socket = socket;
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                })
                .unwrap();
        })
        .unwrap();
    ready.await.unwrap();
    fixture.owner.shutdown().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut [0u8; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(fixture.host.shutdown(Instant::now()).await.is_clean());
}

#[tokio::test]
async fn tor_closed_blocking_adapter_rejects_without_running_callback() {
    let fixture = Fixture::new();
    fixture.owner.shutdown().await.unwrap();
    let ran = Arc::new(AtomicBool::new(false));
    let seen = ran.clone();
    let task = Blocking::spawn_blocking(&fixture.owner, move || {
        seen.store(true, Ordering::Release);
        3u8
    });
    assert!(timeout(Duration::from_millis(10), task).await.is_err());
    assert!(!ran.load(Ordering::Acquire));
    assert!(fixture.host.shutdown(Instant::now()).await.is_clean());
}

struct Gate(Arc<(Mutex<bool>, Condvar)>);
impl Gate {
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
async fn tor_dropped_blocking_waiter_keeps_native_socket_owned_until_real_finish() {
    let fixture = Fixture::new();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let gate = Gate(Arc::new((Mutex::new(false), Condvar::new())));
    let wait = gate.0.clone();
    let (started, ready) = tokio::sync::oneshot::channel();
    let task = Blocking::spawn_blocking(&fixture.owner, move || {
        let _socket = socket;
        started.send(()).unwrap();
        let (released, changed) = &*wait;
        let mut released = released.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
    });
    ready.await.unwrap();
    drop(task);
    assert!(matches!(
        fixture.owner.shutdown().await,
        Err(Error::Timeout)
    ));
    assert!(std::net::TcpListener::bind(address).is_err());
    gate.release();
    timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(socket) = std::net::TcpListener::bind(address) {
                break socket;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(fixture.host.shutdown(Instant::now()).await.timed_out);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tor_native_blocking_panic_remains_service_failure() {
    let fixture = Fixture::new();
    let task = Blocking::spawn_blocking(&fixture.owner, || panic!("受控Tor阻塞失败"));
    drop(task);
    timeout(Duration::from_secs(1), fixture.host.cancel().cancelled())
        .await
        .unwrap();
    let report = fixture
        .host
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await;
    assert_eq!(report.failed_tasks, 1);
    assert!(!report.is_clean());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tor_blocking_handle_rethrows_original_panic_when_polled() {
    let fixture = Fixture::new();
    let task = Blocking::spawn_blocking(&fixture.owner, || -> u8 { panic!("受控原始panic") });
    let caught = timeout(
        Duration::from_secs(1),
        std::panic::AssertUnwindSafe(task).catch_unwind(),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(caught.downcast_ref::<&str>(), Some(&"受控原始panic"));
    timeout(Duration::from_secs(1), fixture.host.cancel().cancelled())
        .await
        .unwrap();
    let report = fixture
        .host
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await;
    assert_eq!(report.failed_tasks, 1);
    assert!(!report.is_clean());
}

#[tokio::test]
async fn tor_fatal_closes_only_its_named_service_and_cannot_be_reset_ready() {
    let failed = Fixture::new();
    let healthy = Fixture::new();
    let context = ConnectContext::new(Duration::from_secs(1));
    let (stream, _peer) = tokio::io::duplex(4);
    let mut stream = TorStream::new(
        stream,
        failed.owner.clone(),
        failed.storage.clone(),
        &context,
    );
    failed.owner.fail(Failure::Deprecated);
    failed.owner.ready();
    assert!(matches!(failed.owner.check(), Err(Error::Protocol(_))));
    assert!(failed.host.cancel().is_cancelled());
    let error = stream.read_u8().await.unwrap_err();
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<Error>()
            .is_some_and(|error| matches!(error, Error::Protocol(_)))
    );
    healthy.owner.ready();
    assert!(healthy.owner.wait_ready().await.is_ok());
    assert!(!healthy.host.cancel().is_cancelled());
    assert_eq!(
        healthy
            .host
            .spawn_tracked(async { 7u8 })
            .unwrap()
            .await
            .unwrap(),
        7
    );
    drop(stream);
    failed.owner.shutdown().await.unwrap();
    healthy.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn tor_service_failure_keeps_first_cause_after_another_failure_and_close() {
    let fixture = Fixture::new();
    fixture.owner.fail(Failure::Timeout);
    fixture.owner.fail(Failure::Deprecated);
    fixture.owner.ready();
    fixture.owner.close();
    assert_eq!(
        fixture.host.failure(),
        Some(Failure::Timeout.service_failure())
    );
    assert!(matches!(fixture.owner.check(), Err(Error::Timeout)));
    assert!(matches!(
        fixture.owner.wait_ready().await,
        Err(Error::Timeout)
    ));
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn tor_carrier_uses_device_literal_address_and_service_cancellation() {
    let fixture = Fixture::new();
    let provider = CarrierProvider::new(
        DeviceLease::borrow(fixture.device.clone()),
        fixture.host.cancel(),
        fixture.host.status(),
        Duration::from_secs(1),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut stream = provider
        .connect(&address, &TcpConnectOptions::default())
        .await
        .unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    assert_eq!(fixture.device.calls.load(Ordering::Acquire), 1);
    assert_eq!(*fixture.device.addresses.lock().unwrap(), vec![address]);
    assert!(
        provider
            .listen(&address, &TcpListenOptions::default())
            .await
            .is_err()
    );
    assert!(UdpProvider::bind(&provider, &address).await.is_err());
    fixture.owner.close();
    let error = futures::AsyncReadExt::read(&mut stream, &mut [0u8; 1])
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<Error>()
            .is_some_and(|error| matches!(error, Error::Cancelled))
    );
    drop(stream);
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn tor_carrier_rejects_new_admission_and_pending_io_after_fatal() {
    let fixture = Fixture::new();
    let provider = CarrierProvider::new(
        DeviceLease::borrow(fixture.device.clone()),
        fixture.host.cancel(),
        fixture.host.status(),
        Duration::from_secs(1),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut stream = provider
        .connect(&address, &TcpConnectOptions::default())
        .await
        .unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    fixture.owner.fail(Failure::Deprecated);
    let error = futures::AsyncReadExt::read(&mut stream, &mut [0u8; 1])
        .await
        .unwrap_err();
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<Error>()
            .is_some_and(|error| matches!(error, Error::Protocol(_)))
    );
    assert!(
        provider
            .connect(&address, &TcpConnectOptions::default())
            .await
            .is_err()
    );
    assert_eq!(fixture.device.calls.load(Ordering::Acquire), 1);
    drop(stream);
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn tor_request_cancel_wakes_both_pending_halves_without_stopping_service() {
    let fixture = Fixture::new();
    let context = ConnectContext::new(Duration::from_secs(1));
    let (stream, _peer) = tokio::io::duplex(1);
    let mut stream = TorStream::new(
        stream,
        fixture.owner.clone(),
        fixture.storage.clone(),
        &context,
    );
    stream.write_all(&[1]).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut waiting = Box::pin(async { tokio::join!(reader.read_u8(), writer.write_all(&[2])) });
    assert!(
        poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    context.cancel.cancel();
    let (read, write) = timeout(Duration::from_secs(1), waiting).await.unwrap();
    for error in [read.unwrap_err(), write.unwrap_err()] {
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<Error>()
                .is_some_and(|error| matches!(error, Error::Cancelled))
        );
    }
    assert!(!fixture.host.cancel().is_cancelled());
    assert!(fixture.owner.check().is_ok());
    drop(reader);
    drop(writer);
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn tor_pending_bootstrap_wait_has_request_budget_without_cancelling_service() {
    let fixture = Fixture::new();
    let request = ConnectContext::new(Duration::from_millis(10));
    assert!(matches!(
        request.run(fixture.owner.wait_ready()).await,
        Err(Error::Timeout)
    ));
    assert!(!fixture.host.cancel().is_cancelled());
    fixture.owner.ready();
    fixture.owner.wait_ready().await.unwrap();
    fixture.owner.shutdown().await.unwrap();
}

struct FailDuringWrite {
    owner: TaskOwner,
    writes: Arc<AtomicUsize>,
}

impl tokio::io::AsyncWrite for FailDuringWrite {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::AcqRel);
        self.owner.fail(Failure::Deprecated);
        Poll::Pending
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn tor_fatal_overlapping_admitted_poll_stops_at_next_observation() {
    let fixture = Fixture::new();
    let context = ConnectContext::new(Duration::from_secs(1));
    let writes = Arc::new(AtomicUsize::new(0));
    let inner = FailDuringWrite {
        owner: fixture.owner.clone(),
        writes: writes.clone(),
    };
    let mut stream = TorStream::new(
        inner,
        fixture.owner.clone(),
        fixture.storage.clone(),
        &context,
    );
    let mut write = Box::pin(stream.write_all(&[1]));
    assert!(
        poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert_eq!(writes.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture.host.failure(),
        Some(Failure::Deprecated.service_failure())
    );
    let error = timeout(Duration::from_secs(1), write)
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<Error>()
            .is_some_and(|error| matches!(error, Error::Protocol(_)))
    );
    assert_eq!(writes.load(Ordering::Acquire), 1);
    assert!(matches!(fixture.owner.check(), Err(Error::Protocol(_))));
    drop(stream);
    fixture.owner.shutdown().await.unwrap();
}
