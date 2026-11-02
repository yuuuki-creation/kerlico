//! 应用拥有的设备执行线程；Engine 仅借用业务能力。跨进程由上层 IPC 提供。
mod registration;
mod storage;

use kerlico_config::{DeviceRequirements, OutboundFactory};
use kerlico_core::{
    Address, BoxFuture, ConnectContext, DatagramAssociation, DatagramAssociationReceiver,
    DatagramAssociationSender, DatagramChannel, Destination, DeviceLease, DeviceNetwork, Error,
    FamilyMode, OpenedTcp, OutId, Outbound, Result, ServiceContext, ServiceFailure, ServiceStatus,
    ShutdownReport,
};
use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};
use tokio::{
    runtime::Handle,
    sync::{mpsc, oneshot},
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeFamily {
    Routed,
    Missing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCapabilities {
    pub ipv4: NativeFamily,
    pub ipv6: NativeFamily,
}
impl NativeCapabilities {
    /// 不发包的内核路由选择，只证明存在可选源地址，不宣称公网连通。
    pub fn detect() -> Result<Self> {
        fn probe(target: SocketAddr) -> Result<NativeFamily> {
            let operation = || -> std::io::Result<SocketAddr> {
                let socket = std::net::UdpSocket::bind(if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })?;
                socket.connect(target)?;
                socket.local_addr()
            };
            match operation() {
                Ok(local) if !local.ip().is_unspecified() && !local.ip().is_loopback() => {
                    Ok(NativeFamily::Routed)
                }
                Ok(_) => Ok(NativeFamily::Missing),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NetworkUnreachable
                            | std::io::ErrorKind::AddrNotAvailable
                            | std::io::ErrorKind::Unsupported
                    ) || matches!(error.raw_os_error(), Some(97 | 101)) =>
                {
                    Ok(NativeFamily::Missing)
                }
                Err(error) => Err(error.into()),
            }
        }
        Ok(Self {
            ipv4: probe("1.1.1.1:443".parse().unwrap())?,
            ipv6: probe("[2606:4700:4700::1111]:443".parse().unwrap())?,
        })
    }
    fn warp(self, target: SocketAddr, mode: FamilyMode) -> bool {
        mode == FamilyMode::DualV4Preferred
            && if target.is_ipv4() {
                self.ipv4 == NativeFamily::Missing
            } else {
                self.ipv6 == NativeFamily::Missing
            }
    }
    fn needs_warp(self) -> bool {
        self.ipv4 == NativeFamily::Missing || self.ipv6 == NativeFamily::Missing
    }
}

pub struct DeviceOptions {
    pub state_directory: PathBuf,
    pub preparation_timeout: Duration,
    pub registration_policy: RegistrationPolicy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationPolicy {
    CreateOnce,
    ExistingOnly,
}
impl DeviceOptions {
    pub fn new(state_directory: PathBuf) -> Self {
        Self {
            state_directory,
            preparation_timeout: Duration::from_secs(45),
            registration_policy: RegistrationPolicy::CreateOnce,
        }
    }
    /// 复用模式先验证现有身份与响应匹配，缺失时绝不注册。
    pub fn existing(state_directory: PathBuf) -> Self {
        Self {
            registration_policy: RegistrationPolicy::ExistingOnly,
            ..Self::new(state_directory)
        }
    }
}

type Work = Box<dyn FnOnce(Handle) + Send>;
enum Command {
    Work(Work),
    Shutdown(Instant),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevicePhase {
    Dormant,
    Preparing,
    Ready,
    Failed,
    Retiring,
    Closed,
}
struct Shared {
    sender: mpsc::UnboundedSender<Command>,
    thread: Mutex<Option<JoinHandle<ShutdownReport>>>,
    deadline: Mutex<Option<Instant>>,
    report: Mutex<Option<ShutdownReport>>,
    phase: Arc<Mutex<DevicePhase>>,
    status: ServiceStatus,
}
/// 此所有者不绑定调用方的 Tokio runtime。Drop 租约不会发起关闭。
#[derive(Clone)]
pub struct DeviceRuntime {
    shared: Arc<Shared>,
    state: Arc<State>,
}
#[derive(Clone)]
pub struct DeviceRetirement {
    shared: Arc<Shared>,
}
impl DeviceRetirement {
    /// 即使设备所有者已释放，收据仍保留后端或关闭的首个稳定失败原因。
    pub fn failure(&self) -> Option<ServiceFailure> {
        self.shared.status.failure()
    }
    pub fn try_join(&self) -> Option<ShutdownReport> {
        let mut thread = self.shared.thread.lock().unwrap();
        if thread.as_ref().is_some_and(JoinHandle::is_finished) {
            let report = thread.take().unwrap().join().unwrap_or(ShutdownReport {
                failed_tasks: 1,
                ..Default::default()
            });
            *self.shared.report.lock().unwrap() = Some(report);
            *self.shared.phase.lock().unwrap() = DevicePhase::Closed;
        }
        self.shared.report.lock().unwrap().clone()
    }
    pub async fn wait(&self) -> ShutdownReport {
        loop {
            if let Some(report) = self.try_join() {
                return report;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}
struct State {
    native: DeviceLease,
    capabilities: NativeCapabilities,
    host: ServiceContext,
    prepared: tokio::sync::OnceCell<std::result::Result<Arc<dyn Outbound>, String>>,
    options: DeviceOptions,
    // 打开一次并一直持有；后续所有注册读写由准备任务独占。
    storage: Mutex<Option<Arc<storage::StateStore>>>,
    phase: Arc<Mutex<DevicePhase>>,
}
impl State {
    fn active_phase(&self, next: DevicePhase) {
        let mut phase = self.phase.lock().unwrap();
        if !matches!(*phase, DevicePhase::Retiring | DevicePhase::Closed) {
            *phase = next;
        }
    }
    async fn retire(&self, deadline: Instant) -> ShutdownReport {
        let mut backend_failure = false;
        let mut backend_timeout = false;
        if let Some(Ok(backend)) = self.prepared.get() {
            match tokio::time::timeout_at(deadline, backend.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    backend_failure = true;
                    self.host.fail(shutdown_failure(error));
                }
                Err(_) => {
                    backend_timeout = true;
                    self.host.fail(ServiceFailure::Timeout);
                }
            }
        }
        let initial = self.host.shutdown(deadline).await;
        let mut report = self.host.retirement().wait().await;
        report.timed_out |= initial.timed_out || backend_timeout;
        report.failed_tasks += usize::from(backend_failure);
        if self.host.failure().is_some() {
            report.failed_tasks = report.failed_tasks.max(1);
        }
        self.storage.lock().unwrap().take();
        report
    }
    async fn backend(&self) -> Result<Arc<dyn Outbound>> {
        self.host.check()?;
        if self.capabilities.ipv4 == NativeFamily::Missing
            && self.capabilities.ipv6 == NativeFamily::Missing
        {
            return Err(Error::Unsupported("WARP需要原生载体路由"));
        }
        let result = self
            .prepared
            .get_or_init(|| async {
                self.active_phase(DevicePhase::Preparing);
                let operation = async {
                    let store = self
                        .storage
                        .lock()
                        .unwrap()
                        .clone()
                        .ok_or(Error::Protocol("设备状态写者不可用"))?;
                    let result = registration::prepare(
                        &store,
                        self.capabilities,
                        self.options.registration_policy,
                    )
                    .await;
                    let options = result?;
                    kerlico_wireguard::WireGuardFactory
                        .compile(&options)?
                        .start(self.host.clone())
                        .await
                };
                let result = tokio::time::timeout(self.options.preparation_timeout, operation)
                    .await
                    .map_err(|_| "WARP准备超时，注册意图保留".to_owned())
                    .and_then(|result| result.map_err(|error| error.to_string()));
                self.active_phase(if result.is_ok() {
                    DevicePhase::Ready
                } else {
                    DevicePhase::Failed
                });
                result
            })
            .await;
        result
            .as_ref()
            .cloned()
            .map_err(|reason| Error::Config(format!("WARP准备失败：{reason}")))
    }
}
impl DeviceRuntime {
    pub fn start(options: DeviceOptions) -> Result<Self> {
        Self::start_with_capabilities(options, NativeCapabilities::detect()?)
    }
    pub fn start_with_capabilities(
        options: DeviceOptions,
        capabilities: NativeCapabilities,
    ) -> Result<Self> {
        if options.preparation_timeout.is_zero()
            || options.preparation_timeout > Duration::from_secs(120)
        {
            return Err(Error::Config("设备准备期限须在120秒内".into()));
        }
        let store = storage::StateStore::open(&options.state_directory)?;
        if options.registration_policy == RegistrationPolicy::ExistingOnly {
            registration::existing_profile(&store, capabilities)?;
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let native = kerlico_net::native_device();
        let host = ServiceContext::with_device(
            OutId::parse("device-warp-session").unwrap(),
            native.clone(),
        );
        let phase = Arc::new(Mutex::new(DevicePhase::Dormant));
        let state = Arc::new(State {
            native,
            capabilities,
            host,
            prepared: tokio::sync::OnceCell::new(),
            options,
            storage: Mutex::new(Some(Arc::new(store))),
            phase: phase.clone(),
        });
        let thread_state = state.clone();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let thread = std::thread::Builder::new()
            .name("device-owner".into())
            .spawn(move || {
                let report = runtime.block_on(async move {
                    while let Some(command) = receiver.recv().await {
                        match command {
                            Command::Work(work) => work(Handle::current()),
                            Command::Shutdown(deadline) => {
                                return thread_state.retire(deadline).await;
                            }
                        }
                    }
                    thread_state
                        .retire(Instant::now() + Duration::from_secs(2))
                        .await
                });
                runtime.shutdown_timeout(Duration::ZERO);
                report
            })?;
        let shared = Arc::new(Shared {
            sender,
            thread: Mutex::new(Some(thread)),
            deadline: Mutex::new(None),
            report: Mutex::new(None),
            phase,
            status: state.host.status(),
        });
        Ok(Self { shared, state })
    }
    async fn dispatch<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T>> + Send + 'static,
    {
        if self.shared.deadline.lock().unwrap().is_some() {
            return Err(Error::Cancelled);
        }
        self.state.host.check()?;
        let (send, receive) = oneshot::channel();
        let host = self.state.host.clone();
        self.shared
            .sender
            .send(Command::Work(Box::new(move |_| {
                let _ = host.spawn(async move {
                    let _ = send.send(operation.await);
                });
            })))
            .map_err(|_| Error::Cancelled)?;
        receive.await.map_err(|_| {
            self.failure()
                .map_or(Error::Cancelled, ServiceFailure::error)
        })?
    }
    /// 同一所有者多次准备只初始化一个后端；取消等待者不取消共享准备。
    pub async fn prepare(&self, requirements: DeviceRequirements) -> Result<DeviceLease> {
        self.state.host.check()?;
        if requirements.auto_warp && self.state.capabilities.needs_warp() {
            let state = self.state.clone();
            self.dispatch(async move { state.backend().await.map(|_| ()) })
                .await?;
        }
        let mut phase = self.shared.phase.lock().unwrap();
        if matches!(*phase, DevicePhase::Retiring | DevicePhase::Closed) {
            return Err(Error::Cancelled);
        }
        if *phase == DevicePhase::Dormant {
            *phase = DevicePhase::Ready;
        }
        Ok(DeviceLease::borrow(Arc::new(self.clone())))
    }
    pub fn capabilities(&self) -> NativeCapabilities {
        self.state.capabilities
    }
    pub fn phase(&self) -> DevicePhase {
        self.retirement().try_join();
        if self.failure().is_some() {
            self.state.active_phase(DevicePhase::Failed);
        }
        *self.shared.phase.lock().unwrap()
    }
    /// 后端运行与关闭共用一个只写首因的服务状态，不包含动态上游文本。
    pub fn failure(&self) -> Option<ServiceFailure> {
        self.shared.status.failure()
    }
    pub fn retirement(&self) -> DeviceRetirement {
        DeviceRetirement {
            shared: self.shared.clone(),
        }
    }
    pub fn retire(&self, proposed: Instant) {
        let mut deadline = self.shared.deadline.lock().unwrap();
        if deadline.is_none() {
            *deadline = Some(proposed);
            *self.shared.phase.lock().unwrap() = DevicePhase::Retiring;
            let _ = self.shared.sender.send(Command::Shutdown(proposed));
        }
    }
    pub async fn shutdown_at(&self, deadline: Instant) -> ShutdownReport {
        self.retire(deadline);
        let fixed = self.shared.deadline.lock().unwrap().unwrap();
        tokio::time::timeout_at(fixed, self.retirement().wait())
            .await
            .unwrap_or(ShutdownReport {
                timed_out: true,
                ..Default::default()
            })
    }
}

fn destination(target: SocketAddr) -> Result<Destination> {
    Destination::new(&target.ip().to_string(), target.port())
}
fn shutdown_failure(error: Error) -> ServiceFailure {
    match error {
        Error::Timeout => ServiceFailure::Timeout,
        Error::Rejected => ServiceFailure::Rejected,
        Error::InvalidAddress => ServiceFailure::InvalidAddress,
        Error::ResourceLimit => ServiceFailure::ResourceLimit,
        Error::Protocol(message) | Error::Unsupported(message) => ServiceFailure::Protocol(message),
        Error::Io(error) => ServiceFailure::Io(error.kind(), "设备后端关闭失败"),
        _ => ServiceFailure::Protocol("设备后端关闭失败"),
    }
}
impl DeviceNetwork for DeviceRuntime {
    fn connect_tcp(&self, target: SocketAddr) -> BoxFuture<'_, Result<OpenedTcp>> {
        self.state.native.connect_tcp(target)
    }
    fn connect_udp(&self, target: SocketAddr) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>> {
        self.state.native.connect_udp(target)
    }
    fn udp_association(
        &self,
        mode: FamilyMode,
    ) -> BoxFuture<'_, Result<Arc<tokio::net::UdpSocket>>> {
        self.state.native.udp_association(mode)
    }
    fn connect_target_tcp<'a>(
        &'a self,
        target: SocketAddr,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        let state = self.state.clone();
        let context = context.clone();
        Box::pin(async move {
            self.dispatch(async move {
                if state.capabilities.warp(target, context.target_mode()) {
                    state
                        .backend()
                        .await?
                        .connect_tcp(&destination(target)?, &context)
                        .await
                } else {
                    state.native.connect_target_tcp(target, &context).await
                }
            })
            .await
        })
    }
    fn connect_target_udp<'a>(
        &'a self,
        target: SocketAddr,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        let state = self.state.clone();
        let context = context.clone();
        Box::pin(async move {
            self.dispatch(async move {
                if state.capabilities.warp(target, context.target_mode()) {
                    state
                        .backend()
                        .await?
                        .connect_udp(&destination(target)?, &context)
                        .await
                } else {
                    state.native.connect_target_udp(target, &context).await
                }
            })
            .await
        })
    }
    fn target_association<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        let state = self.state.clone();
        let context = context.clone();
        Box::pin(async move {
            self.dispatch(async move {
                if context.target_mode() != FamilyMode::DualV4Preferred
                    || !state.capabilities.needs_warp()
                {
                    return state.native.target_association(&context).await;
                }
                let warp = state.backend().await?.associate_udp(&context).await?;
                if state.capabilities.ipv4 == NativeFamily::Missing
                    && state.capabilities.ipv6 == NativeFamily::Missing
                {
                    return Ok(warp);
                }
                let mode = if state.capabilities.ipv4 == NativeFamily::Routed {
                    FamilyMode::V4Only
                } else {
                    FamilyMode::V6Only
                };
                let native = state
                    .native
                    .native_target_association(mode, &context)
                    .await?;
                Ok(DatagramAssociation {
                    sender: Box::new(MixedSender {
                        native: native.sender,
                        warp: warp.sender,
                        capabilities: state.capabilities,
                    }),
                    receiver: Box::new(MixedReceiver {
                        native: native.receiver,
                        warp: warp.receiver,
                    }),
                })
            })
            .await
        })
    }
}
/// 混合关联确实有两个来源绑定；各后端独立稳定保留端口，返回真实目标来源。
struct MixedSender {
    native: Box<dyn DatagramAssociationSender>,
    warp: Box<dyn DatagramAssociationSender>,
    capabilities: NativeCapabilities,
}
struct MixedReceiver {
    native: Box<dyn DatagramAssociationReceiver>,
    warp: Box<dyn DatagramAssociationReceiver>,
}
impl DatagramAssociationSender for MixedSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        let Address::Ip(ip) = target.address() else {
            return Box::pin(async { Err(Error::InvalidAddress) });
        };
        if self.capabilities.warp(
            SocketAddr::new(*ip, target.port()),
            FamilyMode::DualV4Preferred,
        ) {
            self.warp.send_to(packet, target)
        } else {
            self.native.send_to(packet, target)
        }
    }
}
impl DatagramAssociationReceiver for MixedReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<kerlico_core::AddressedDatagram>>> {
        Box::pin(async move {
            tokio::select! { result = self.native.recv_from() => result, result = self.warp.recv_from() => result }
        })
    }
}
#[cfg(all(test, unix))]
mod tests;
