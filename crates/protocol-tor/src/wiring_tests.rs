use crate::{config::Options, error::Failure, outbound::start_with_builder, runtime::TorRuntime};
use arti_client::DirProviderBuilder;
use async_trait::async_trait;
use futures::{channel::mpsc, stream::BoxStream};
use kerlico_core::{ConnectContext, Destination, Error, OutId, Outbound, ServiceContext};
use std::{
    future::poll_fn,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Poll,
    time::{Duration, SystemTime},
};
use tokio::time::timeout;
use tor_dirmgr::{DirBootstrapStatus, DirMgrConfig, DirMgrStore, DirProvider};
use tor_netdir::{DirEvent, NetDir, NetDirProvider, Timeliness, params::NetParameters};
use tor_netdoc::doc::netstatus::ProtoStatuses;

struct ControlledDirectory {
    statuses: Mutex<Option<(SystemTime, Arc<ProtoStatuses>)>>,
    events: Mutex<Vec<mpsc::UnboundedSender<DirEvent>>>,
    bootstrap_started: AtomicBool,
    reads: AtomicUsize,
}

impl ControlledDirectory {
    fn new(required: Option<bool>) -> Arc<Self> {
        Arc::new(Self {
            statuses: Mutex::new(required.map(Self::recommendation)),
            events: Mutex::new(Vec::new()),
            bootstrap_started: AtomicBool::new(false),
            reads: AtomicUsize::new(0),
        })
    }

    fn recommendation(required: bool) -> (SystemTime, Arc<ProtoStatuses>) {
        let statuses = serde_json::json!({
            "client": {"recommended":"Relay=63", "required":if required { "Relay=63" } else { "" }},
            "relay": {"recommended":"", "required":""}
        });
        (
            SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_800),
            Arc::new(serde_json::from_value(statuses).unwrap()),
        )
    }

    fn publish(&self, required: bool) {
        *self.statuses.lock().unwrap() = Some(Self::recommendation(required));
        self.events.lock().unwrap().retain(|sender| {
            sender
                .unbounded_send(DirEvent::NewProtocolRecommendation)
                .is_ok()
        });
    }

    async fn wait_for_bootstrap(&self) {
        timeout(Duration::from_secs(5), async {
            while !self.bootstrap_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_for_read(&self, count: usize) {
        timeout(Duration::from_secs(5), async {
            while self.reads.load(Ordering::Acquire) < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

impl NetDirProvider for ControlledDirectory {
    fn netdir(&self, _: Timeliness) -> tor_netdir::Result<Arc<NetDir>> {
        Err(tor_netdir::Error::NoInfo)
    }
    fn events(&self) -> BoxStream<'static, DirEvent> {
        let (sender, receiver) = mpsc::unbounded();
        self.events.lock().unwrap().push(sender);
        Box::pin(receiver)
    }
    fn params(&self) -> Arc<dyn AsRef<NetParameters>> {
        Arc::new(NetParameters::default())
    }
    fn protocol_statuses(&self) -> Option<(SystemTime, Arc<ProtoStatuses>)> {
        let result = self.statuses.lock().unwrap().clone();
        self.reads.fetch_add(1, Ordering::AcqRel);
        result
    }
}

#[async_trait]
impl DirProvider for ControlledDirectory {
    fn reconfigure(
        &self,
        _: &DirMgrConfig,
        _: tor_config::Reconfigure,
    ) -> Result<(), tor_config::ReconfigureError> {
        Ok(())
    }
    async fn bootstrap(&self) -> tor_dirmgr::Result<()> {
        self.bootstrap_started.store(true, Ordering::Release);
        std::future::pending().await
    }
    fn bootstrap_events(&self) -> BoxStream<'static, DirBootstrapStatus> {
        Box::pin(futures::stream::pending())
    }
}

struct DirectoryBuilder(Arc<ControlledDirectory>);
impl DirProviderBuilder<TorRuntime> for DirectoryBuilder {
    fn build(
        &self,
        _: TorRuntime,
        _: DirMgrStore<TorRuntime>,
        _: Arc<tor_circmgr::CircMgr<TorRuntime>>,
        _: DirMgrConfig,
    ) -> arti_client::Result<Arc<dyn DirProvider + 'static>> {
        Ok(self.0.clone())
    }
}

struct Running {
    _directory: tempfile::TempDir,
    outbound: Arc<dyn Outbound>,
    host: ServiceContext,
    provider: Arc<ControlledDirectory>,
}

impl Running {
    async fn start(name: &str, cached: Option<bool>) -> Self {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let relative = directory.path().file_name().unwrap().to_str().unwrap();
        let options: Options = serde_json::from_value(serde_json::json!({
            "data_directory": relative, "bootstrap_timeout_ms": 60000, "shutdown_timeout_ms": 5000
        }))
        .unwrap();
        let device = super::tests::TestDevice::new();
        let host = ServiceContext::with_device(
            OutId::parse(name).unwrap(),
            kerlico_core::DeviceLease::borrow(device),
        );
        let provider = ControlledDirectory::new(cached);
        let builder = Arc::new(DirectoryBuilder(provider.clone()));
        let outbound =
            start_with_builder(options.prepare().unwrap(), host.clone(), move |client| {
                client.dirmgr_builder::<DirectoryBuilder>(builder)
            })
            .await
            .unwrap();
        Self {
            _directory: directory,
            outbound,
            host,
            provider,
        }
    }

    async fn shutdown(self) {
        self.outbound.shutdown().await.unwrap();
    }
}

fn target() -> Destination {
    Destination::new("example.invalid", 443).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tor_builder_cached_required_protocol_failure_preserves_actual_bootstrap_cause() {
    let running = Running::start("tor-cached", Some(true)).await;
    timeout(Duration::from_secs(5), running.host.cancel().cancelled())
        .await
        .unwrap();
    assert_eq!(
        running.host.failure(),
        Some(Failure::Deprecated.service_failure())
    );
    assert!(!running.provider.bootstrap_started.load(Ordering::Acquire));
    let target = target();
    let request = ConnectContext::new(Duration::from_secs(1));
    assert!(matches!(
        running.outbound.connect_tcp(&target, &request).await,
        Err(Error::Protocol(_))
    ));
    running.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tor_builder_running_watcher_fatal_stops_only_bound_service() {
    let failed = Running::start("tor-failed", None).await;
    let healthy = Running::start("tor-healthy", None).await;
    failed.provider.wait_for_bootstrap().await;
    healthy.provider.wait_for_bootstrap().await;
    let target = target();
    let request = ConnectContext::new(Duration::from_secs(5));
    let mut pending = failed.outbound.connect_tcp(&target, &request);
    assert!(
        poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let next_read = failed.provider.reads.load(Ordering::Acquire) + 1;
    failed.provider.publish(false);
    failed.provider.wait_for_read(next_read).await;
    assert!(!failed.host.cancel().is_cancelled());
    failed.provider.publish(true);
    timeout(Duration::from_secs(5), failed.host.cancel().cancelled())
        .await
        .unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(1), pending).await.unwrap(),
        Err(Error::Protocol(_))
    ));
    assert_eq!(
        failed.host.failure(),
        Some(Failure::Deprecated.service_failure())
    );
    let next = ConnectContext::new(Duration::from_secs(1));
    assert!(matches!(
        failed.outbound.connect_tcp(&target, &next).await,
        Err(Error::Protocol(_))
    ));
    assert!(healthy.host.check().is_ok());
    assert_eq!(
        healthy
            .host
            .spawn_tracked(async { 17u8 })
            .unwrap()
            .await
            .unwrap(),
        17
    );
    failed.shutdown().await;
    assert!(healthy.host.check().is_ok());
    let unaffected = ConnectContext::new(Duration::from_secs(5));
    let mut waiting = healthy.outbound.connect_tcp(&target, &unaffected);
    assert!(
        poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    unaffected.cancel.cancel();
    assert!(matches!(
        timeout(Duration::from_secs(1), waiting).await.unwrap(),
        Err(Error::Cancelled)
    ));
    assert!(healthy.host.check().is_ok());
    healthy.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tor_real_request_token_cancels_observed_bootstrap_wait_without_stopping_service() {
    let running = Running::start("tor-cancel", None).await;
    running.provider.wait_for_bootstrap().await;
    let target = target();
    let request = ConnectContext::new(Duration::from_secs(5));
    let mut pending = running.outbound.connect_tcp(&target, &request);
    assert!(
        poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    request.cancel.cancel();
    assert!(matches!(
        timeout(Duration::from_secs(1), pending).await.unwrap(),
        Err(Error::Cancelled)
    ));
    assert!(running.host.check().is_ok());
    let next = ConnectContext::new(Duration::from_secs(5));
    let mut after = running.outbound.connect_tcp(&target, &next);
    assert!(
        poll_fn(|cx| Poll::Ready(after.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert!(running.host.check().is_ok());
    next.cancel.cancel();
    assert!(matches!(
        timeout(Duration::from_secs(1), after).await.unwrap(),
        Err(Error::Cancelled)
    ));
    running.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tor_real_request_budget_expires_during_bootstrap_without_stopping_service() {
    let running = Running::start("tor-budget", None).await;
    running.provider.wait_for_bootstrap().await;
    let target = target();
    let request = ConnectContext::new(Duration::from_millis(10));
    assert!(matches!(
        timeout(
            Duration::from_secs(1),
            running.outbound.connect_tcp(&target, &request)
        )
        .await
        .unwrap(),
        Err(Error::Timeout)
    ));
    assert!(running.host.check().is_ok());
    assert_eq!(running.host.failure(), None);
    let next = ConnectContext::new(Duration::from_secs(5));
    let mut pending = running.outbound.connect_tcp(&target, &next);
    assert!(
        poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    next.cancel.cancel();
    assert!(matches!(
        timeout(Duration::from_secs(1), pending).await.unwrap(),
        Err(Error::Cancelled)
    ));
    running.shutdown().await;
}
