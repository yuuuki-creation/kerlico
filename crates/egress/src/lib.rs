//! 一个 Engine 的唯一命名出站所有者、可信目标调度与业务计量边界。

use kerlico_config::{EgressPlan, IngressPlan, Network, RouteTable};
use kerlico_core::{
    Address, BoxFuture, Capabilities, ConnectContext, DatagramAssociationSender, DatagramReceiver,
    Destination, Error, FamilyMode, FixedUdpFlow, FlowOpen, IngressBinding, NodeId, OpenedTcp,
    OriginalTarget, OutId, Outbound, Result, RuntimeOptions, ServiceContext, ServiceRetirement,
    SessionDispatcher, SessionIdentity, ShutdownReport, TargetPolicy, TcpFlow, UdpAssociation,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time::{Instant, timeout_at};
mod history;
mod meter;
mod telemetry;
pub use history::{
    BandwidthSample, HistoryQuery, HistoryReader, HistoryScope, HistoryWriter, OnlineSource,
    StoredFlow, StoredUsage,
};
pub use telemetry::{
    DatagramTargetRecord, EventRecord, FlowEnd, FlowId, FlowKind, FlowRecord, FlowStage, Telemetry,
    Usage, UsageSnapshot,
};
use telemetry::{FlowKind as Kind, FlowLease};

static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>>;
}
struct SystemResolver;
impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host, 0))
                .await?
                .map(|address| address.ip())
                .collect())
        })
    }
}

pub use kerlico_core::DeviceLease;
pub use kerlico_net::native_device;

impl Resolver for kerlico_dns::DnsResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
        Box::pin(kerlico_dns::DnsResolver::resolve(self, host))
    }
}

struct RunningService {
    id: OutId,
    backend: Arc<dyn Outbound>,
    host: ServiceContext,
    policy: TargetPolicy,
    capabilities: Capabilities,
    association: bool,
}
impl Drop for RunningService {
    fn drop(&mut self) {
        self.host.retire(Instant::now());
    }
}
struct StartingService {
    host: ServiceContext,
    deadline: Instant,
    armed: bool,
}
impl Drop for StartingService {
    fn drop(&mut self) {
        if self.armed {
            self.host.retire(self.deadline);
        }
    }
}
struct Binding {
    outbound: OutId,
    mode: FamilyMode,
}

struct Dispatcher {
    services: BTreeMap<OutId, RunningService>,
    service_order: Vec<OutId>,
    bindings: BTreeMap<NodeId, Binding>,
    routes: RouteTable,
    resolver: Arc<dyn Resolver>,
    telemetry: Telemetry,
    closed: AtomicBool,
    shutdown: tokio::sync::Mutex<Option<RuntimeDrain>>,
    _device: DeviceLease,
}

struct RuntimeDrain {
    deadline: Instant,
    services: Vec<ServiceDrain>,
}
#[derive(Default)]
struct ServiceDrain {
    backend: Option<ShutdownReport>,
    tasks: ShutdownReport,
}
impl RuntimeDrain {
    fn report(&self) -> ShutdownReport {
        let mut report = ShutdownReport::default();
        for service in &self.services {
            if let Some(backend) = &service.backend {
                report.merge(backend);
            }
            report.merge(&service.tasks);
        }
        report
    }
}

pub struct EgressRuntime {
    dispatcher: Arc<Dispatcher>,
    ingresses: BTreeMap<NodeId, IngressBinding>,
}
impl Drop for EgressRuntime {
    fn drop(&mut self) {
        self.dispatcher.closed.store(true, Ordering::Release);
        for service in self.dispatcher.services.values() {
            service.host.retire(Instant::now());
        }
    }
}
impl EgressRuntime {
    pub async fn start(plan: EgressPlan, device: DeviceLease, budget: Duration) -> Result<Self> {
        Self::start_with_options(plan, RuntimeOptions::new(device), budget).await
    }
    pub async fn start_with_options(
        plan: EgressPlan,
        options: RuntimeOptions,
        budget: Duration,
    ) -> Result<Self> {
        let resolver: Arc<dyn Resolver> = match plan.dns() {
            Some(spec) => Arc::new(kerlico_dns::DnsResolver::new(spec)?),
            None => Arc::new(SystemResolver),
        };
        Self::start_with_resolver(plan, options, budget, resolver).await
    }
    async fn start_with_resolver(
        plan: EgressPlan,
        options: RuntimeOptions,
        budget: Duration,
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self> {
        let (plans, bindings, routes_table, max_flows, detour_table) = plan.into_parts();
        let RuntimeOptions { device, language } = options;
        let run = NEXT_RUN
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::ResourceLimit)?;
        let deadline = Instant::now() + budget;
        let mut started = Vec::new();
        for named in plans {
            let host = ServiceContext::with_options(
                named.id.clone(),
                RuntimeOptions {
                    device: device.clone(),
                    language,
                },
            );
            let mut starting = StartingService {
                host: host.clone(),
                deadline,
                armed: true,
            };
            let capabilities = named.plan.capabilities();
            let association = named.plan.supports_udp_association();
            let policy = named.plan.target_policy();
            let result = timeout_at(deadline, named.plan.start(host.clone()))
                .await
                .map_err(|_| Error::Timeout)
                .and_then(|value| value);
            match result {
                Ok(backend) => {
                    let valid = backend.capabilities() == capabilities
                        && backend.supports_udp_association() == association
                        && !host.cancel().is_cancelled();
                    detour_table.insert(named.id.clone(), backend.clone());
                    started.push(RunningService {
                        id: named.id,
                        backend,
                        host,
                        policy,
                        capabilities,
                        association,
                    });
                    starting.armed = false;
                    if !valid {
                        let cleanup = shutdown_services(started.iter().rev(), deadline).await;
                        return Err(startup(
                            Error::Protocol("运行后端与编译能力或启动状态不一致"),
                            cleanup,
                        ));
                    }
                }
                Err(primary) => {
                    let mut cleanup = host.shutdown(deadline).await;
                    cleanup.merge(&shutdown_services(started.iter().rev(), deadline).await);
                    return Err(startup(primary, cleanup));
                }
            }
        }
        let service_order = started.iter().map(|service| service.id.clone()).collect();
        let mut services = BTreeMap::new();
        for service in started {
            services.insert(service.id.clone(), service);
        }
        let routes = bindings
            .iter()
            .map(|binding| {
                (
                    binding.issuer.node().clone(),
                    Binding {
                        outbound: binding.outbound.clone(),
                        mode: binding.mode,
                    },
                )
            })
            .collect();
        let dispatcher = Arc::new(Dispatcher {
            services,
            service_order,
            bindings: routes,
            routes: routes_table,
            resolver,
            telemetry: Telemetry::new(max_flows),
            closed: AtomicBool::new(false),
            shutdown: tokio::sync::Mutex::new(None),
            _device: device,
        });
        let mut ingresses = BTreeMap::new();
        for binding in bindings {
            let result = Self::bind(&dispatcher, binding, run);
            match result {
                Ok((node, ingress)) => {
                    ingresses.insert(node, ingress);
                }
                Err(primary) => {
                    let cleanup = shutdown_services(
                        dispatcher
                            .service_order
                            .iter()
                            .rev()
                            .filter_map(|id| dispatcher.services.get(id)),
                        deadline,
                    )
                    .await;
                    return Err(startup(primary, cleanup));
                }
            }
        }
        Ok(Self {
            dispatcher,
            ingresses,
        })
    }
    fn bind(
        dispatcher: &Arc<Dispatcher>,
        binding: IngressPlan,
        run: u64,
    ) -> Result<(NodeId, IngressBinding)> {
        binding.issuer.activate(run)?;
        let association = dispatcher
            .services
            .get(&binding.outbound)
            .ok_or_else(|| Error::Config("出站绑定不存在".into()))?
            .association;
        let node = binding.issuer.node().clone();
        Ok((
            node,
            IngressBinding::assemble(
                binding.issuer,
                binding.local,
                dispatcher.clone(),
                association,
            ),
        ))
    }
    pub fn ingress(&self, node: &NodeId) -> Result<IngressBinding> {
        self.ingresses.get(node).cloned().ok_or(Error::Rejected)
    }
    pub fn telemetry(&self) -> Telemetry {
        self.dispatcher.telemetry.clone()
    }
    /// 返回独立回收收据，供消费 Engine 或丢弃运行实例后继续确认真实任务释放。
    pub fn service_retirements(&self) -> Vec<(OutId, ServiceRetirement)> {
        self.dispatcher
            .services
            .values()
            .map(|service| (service.id.clone(), service.host.retirement()))
            .collect()
    }
    pub async fn shutdown(&self, budget: Duration) -> ShutdownReport {
        self.shutdown_at(Instant::now() + budget).await
    }
    pub async fn shutdown_at(&self, deadline: Instant) -> ShutdownReport {
        let mut shutdown = match timeout_at(deadline, self.dispatcher.shutdown.lock()).await {
            Ok(shutdown) => shutdown,
            Err(_) => {
                return ShutdownReport {
                    timed_out: true,
                    ..ShutdownReport::default()
                };
            }
        };
        let progress = shutdown.get_or_insert_with(|| RuntimeDrain {
            deadline,
            services: (0..self.dispatcher.service_order.len())
                .map(|_| ServiceDrain::default())
                .collect(),
        });
        self.dispatcher.closed.store(true, Ordering::Release);
        for (index, id) in self.dispatcher.service_order.iter().rev().enumerate() {
            let service = self.dispatcher.services.get(id).expect("命名服务已装配");
            if deadline < progress.deadline && Instant::now() >= deadline {
                let mut report = progress.report();
                report.timed_out = true;
                return report;
            }
            if progress.services[index].backend.is_none() {
                service.host.cancel().cancel();
                let mut report = ShutdownReport::default();
                match timeout_at(deadline.min(progress.deadline), service.backend.shutdown()).await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => report.failed_tasks = 1,
                    Err(_) if Instant::now() < progress.deadline => {
                        let mut report = progress.report();
                        report.timed_out = true;
                        return report;
                    }
                    Err(_) => report.timed_out = true,
                }
                progress.services[index].backend = Some(report);
            }
            let report = if deadline < progress.deadline {
                match timeout_at(deadline, service.host.shutdown(progress.deadline)).await {
                    Ok(report) => report,
                    Err(_) => {
                        let mut report = progress.report();
                        report.timed_out = true;
                        return report;
                    }
                }
            } else {
                service.host.shutdown(progress.deadline).await
            };
            progress.services[index].tasks = report;
        }
        progress.report()
    }
}
fn startup(primary: Error, cleanup: ShutdownReport) -> Error {
    Error::Startup {
        primary: Box::new(primary),
        cleanup_timed_out: cleanup.timed_out,
        cleanup_failures: cleanup.failed_tasks,
    }
}
async fn shutdown_services<'a>(
    services: impl Iterator<Item = &'a RunningService>,
    deadline: Instant,
) -> ShutdownReport {
    let mut report = ShutdownReport::default();
    for service in services {
        service.host.cancel().cancel();
        match timeout_at(deadline, service.backend.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => report.failed_tasks += 1,
            Err(_) => report.timed_out = true,
        }
        report.merge(&service.host.shutdown(deadline).await);
    }
    report
}

impl Dispatcher {
    /// 多目标 UDP 关联建立时没有单一目标，固定使用节点绑定的出站。
    fn route(
        &self,
        identity: &SessionIdentity,
        request: Option<(&Destination, Network)>,
    ) -> Result<(&RunningService, FamilyMode)> {
        if self.closed.load(Ordering::Acquire)
            || !identity.is_accepting()
            || identity.cancel().is_cancelled()
            || identity.node_cancel().is_cancelled()
        {
            return Err(Error::Cancelled);
        }
        let binding = self
            .bindings
            .get(identity.source().node())
            .ok_or(Error::Rejected)?;
        let outbound = self
            .selected_outbound(identity, request)
            .ok_or(Error::Rejected)?;
        let service = self.services.get(outbound).ok_or(Error::Rejected)?;
        service.host.check()?;
        Ok((service, binding.mode))
    }
    fn selected_outbound(
        &self,
        identity: &SessionIdentity,
        request: Option<(&Destination, Network)>,
    ) -> Option<&OutId> {
        let binding = self.bindings.get(identity.source().node())?;
        Some(
            request
                .and_then(|(target, network)| {
                    self.routes.select(target, network, identity.source())
                })
                .unwrap_or(&binding.outbound),
        )
    }
    /// 取得流账本前的准入；此处失败还没有租约，单独记一条错误事件。
    fn admit(
        &self,
        identity: &SessionIdentity,
        context: &ConnectContext,
        request: Option<(&Destination, Network)>,
        capable: impl FnOnce(&RunningService) -> Result<()>,
        original: Option<OriginalTarget>,
        kind: Kind,
    ) -> Result<(&RunningService, FamilyMode, Arc<telemetry::FlowLedger>)> {
        if context.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let admitted = self.route(identity, request).and_then(|(service, mode)| {
            capable(service)?;
            let ledger = self.telemetry.open(identity, &service.id, original, kind)?;
            Ok((service, mode, ledger))
        });
        if let Err(error) = &admitted
            && let Some(outbound) = self.selected_outbound(identity, request)
        {
            self.telemetry.open_failed(
                identity.source(),
                outbound,
                request.map(|(target, _)| target),
                error,
            );
        }
        admitted
    }
    fn tcp<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        original: OriginalTarget,
        context: &'a ConnectContext,
    ) -> Result<FlowOpen<'a, TcpFlow>> {
        let (service, mode, ledger) = self.admit(
            identity,
            context,
            Some((original.target(), Network::Tcp)),
            |service| {
                service
                    .capabilities
                    .tcp
                    .then_some(())
                    .ok_or(Error::Unsupported("所选命名出站没有 TCP 能力"))
            },
            Some(original.clone()),
            Kind::Tcp,
        )?;
        let scoped = context.scoped(
            &service.host,
            identity.source(),
            identity.node_cancel(),
            identity.cancel(),
            mode,
        );
        let lease = FlowLease::new(&self.telemetry, ledger.clone(), &scoped, identity);
        let completion = lease.clone();
        Ok(FlowOpen::tcp(
            Box::pin(async move {
                let result = match service.policy {
                    TargetPolicy::Remote => scoped
                        .run(service.backend.connect_tcp(original.target(), &scoped))
                        .await
                        .map(|stream| (stream, None)),
                    TargetPolicy::Local => {
                        scoped
                            .run(async {
                                let candidates = recorded_candidates(
                                    self.resolver.as_ref(),
                                    &self.telemetry,
                                    identity.source(),
                                    &service.id,
                                    original.target(),
                                    mode,
                                )
                                .await?;
                                let mut last = Error::InvalidAddress;
                                for (index, target) in candidates.iter().enumerate() {
                                    let remaining = scoped.remaining();
                                    if remaining.is_zero() {
                                        return Err(Error::Timeout);
                                    }
                                    let budget = if index + 1 < candidates.len() {
                                        remaining.min(Duration::from_secs(1))
                                    } else {
                                        remaining
                                    };
                                    let attempt = scoped.with_timeout(budget);
                                    match attempt
                                        .run(service.backend.connect_tcp(target, &attempt))
                                        .await
                                    {
                                        Ok(stream) => return Ok((stream, Some(target.clone()))),
                                        Err(error @ (Error::Io(_) | Error::Timeout)) => {
                                            last = error
                                        }
                                        Err(error) => return Err(error),
                                    }
                                }
                                Err(last)
                            })
                            .await
                    }
                };
                match result {
                    Ok((stream, observed)) => {
                        ledger.ready(service.policy == TargetPolicy::Local, observed);
                        ledger.target_bind(stream.info.target_bind().clone());
                        Ok(OpenedTcp {
                            stream: meter::stream(stream.stream, lease.clone()),
                            info: stream.info,
                        })
                    }
                    Err(error) => {
                        lease.failed(&error);
                        Err(error)
                    }
                }
            }),
            move |outcome| completion.conclude(outcome),
        ))
    }
    fn udp<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        original: OriginalTarget,
        context: &'a ConnectContext,
    ) -> Result<FlowOpen<'a, FixedUdpFlow>> {
        let (service, mode, ledger) = self.admit(
            identity,
            context,
            Some((original.target(), Network::Udp)),
            |service| {
                service
                    .capabilities
                    .udp
                    .then_some(())
                    .ok_or(Error::Unsupported("所选命名出站没有固定 UDP 能力"))
            },
            Some(original.clone()),
            Kind::FixedUdp,
        )?;
        let scoped = context.scoped(
            &service.host,
            identity.source(),
            identity.node_cancel(),
            identity.cancel(),
            mode,
        );
        let lease = FlowLease::new(&self.telemetry, ledger.clone(), &scoped, identity);
        let completion = lease.clone();
        Ok(FlowOpen::fixed_udp(
            Box::pin(async move {
                let result = scoped
                    .run(async {
                        let target = match service.policy {
                            TargetPolicy::Remote => original.target().clone(),
                            TargetPolicy::Local => recorded_candidates(
                                self.resolver.as_ref(),
                                &self.telemetry,
                                identity.source(),
                                &service.id,
                                original.target(),
                                mode,
                            )
                            .await?
                            .remove(0),
                        };
                        let mut channel = service.backend.connect_udp(&target, &scoped).await?;
                        let observed = if service.policy == TargetPolicy::Local {
                            channel.receiver = Box::new(ResolvedReceiver {
                                inner: channel.receiver,
                                target: target.clone(),
                            });
                            Some(target)
                        } else {
                            None
                        };
                        Ok((channel, observed))
                    })
                    .await;
                match result {
                    Ok((channel, observed)) => {
                        ledger.ready(service.policy == TargetPolicy::Local, observed);
                        Ok(meter::fixed(channel, lease.clone()))
                    }
                    Err(error) => {
                        lease.failed(&error);
                        Err(error)
                    }
                }
            }),
            move |outcome| completion.conclude(outcome),
        ))
    }
    fn association<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        context: &'a ConnectContext,
    ) -> Result<FlowOpen<'a, UdpAssociation>> {
        let (service, mode, ledger) = self.admit(
            identity,
            context,
            None,
            |service| {
                service
                    .association
                    .then_some(())
                    .ok_or(Error::Unsupported("所选命名出站没有多目标 UDP 关联能力"))
            },
            None,
            Kind::UdpAssociation,
        )?;
        let scoped = context.scoped(
            &service.host,
            identity.source(),
            identity.node_cancel(),
            identity.cancel(),
            mode,
        );
        let lease = FlowLease::new(&self.telemetry, ledger.clone(), &scoped, identity);
        let completion = lease.clone();
        Ok(FlowOpen::association(
            Box::pin(async move {
                match scoped.run(service.backend.associate_udp(&scoped)).await {
                    Ok(mut channel) => {
                        if service.policy == TargetPolicy::Local {
                            channel.sender = Box::new(LocalAssociationSender {
                                inner: channel.sender,
                                resolver: self.resolver.clone(),
                                telemetry: self.telemetry.clone(),
                                source: identity.source().clone(),
                                outbound: service.id.clone(),
                                mode,
                                context: scoped.clone(),
                                targets: HashMap::new(),
                                ledger: ledger.clone(),
                            });
                        }
                        ledger.ready(service.policy == TargetPolicy::Local, None);
                        Ok(meter::association(channel, lease.clone()))
                    }
                    Err(error) => {
                        lease.failed(&error);
                        Err(error)
                    }
                }
            }),
            move |outcome| completion.conclude(outcome),
        ))
    }
}
impl SessionDispatcher for Dispatcher {
    fn supports_udp_association(&self, identity: &SessionIdentity) -> bool {
        self.route(identity, None)
            .is_ok_and(|(service, _)| service.association)
    }
    fn connect_tcp<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        target: OriginalTarget,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, TcpFlow> {
        FlowOpen::deferred(move || self.tcp(identity, target, context))
    }
    fn connect_udp<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        target: OriginalTarget,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, FixedUdpFlow> {
        FlowOpen::deferred(move || self.udp(identity, target, context))
    }
    fn associate_udp<'a>(
        &'a self,
        identity: &'a SessionIdentity,
        context: &'a ConnectContext,
    ) -> FlowOpen<'a, UdpAssociation> {
        FlowOpen::deferred(move || self.association(identity, context))
    }
}

/// 外层超时或取消会直接丢弃查询 future，走不到结果分支，由 Drop 记为中止。
struct PendingLookup<'a> {
    telemetry: &'a Telemetry,
    source: &'a kerlico_core::Source,
    outbound: &'a OutId,
    target: &'a Destination,
    settled: bool,
}
impl Drop for PendingLookup<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.telemetry
                .dns_aborted(self.source, self.outbound, self.target);
        }
    }
}
async fn recorded_candidates(
    resolver: &dyn Resolver,
    telemetry: &Telemetry,
    source: &kerlico_core::Source,
    outbound: &OutId,
    target: &Destination,
    mode: FamilyMode,
) -> Result<Vec<Destination>> {
    let mut pending = PendingLookup {
        telemetry,
        source,
        outbound,
        target,
        settled: false,
    };
    let result = candidates(resolver, target, mode).await;
    pending.settled = true;
    telemetry.dns_event(source, outbound, target, &result);
    result
}
async fn candidates(
    resolver: &dyn Resolver,
    target: &Destination,
    mode: FamilyMode,
) -> Result<Vec<Destination>> {
    let accepts = |ip: &IpAddr| match mode {
        FamilyMode::V4Only => ip.is_ipv4(),
        FamilyMode::V6Only => ip.is_ipv6(),
        FamilyMode::DualV4Preferred => true,
    };
    match target.address() {
        Address::Ip(ip) => {
            if ip.to_canonical() != *ip {
                Err(Error::InvalidAddress)
            } else if accepts(ip) {
                Ok(vec![target.clone()])
            } else {
                Err(Error::Rejected)
            }
        }
        Address::Domain(host) => {
            let mut seen = HashSet::new();
            let mut addresses: Vec<_> = resolver
                .resolve(host)
                .await?
                .into_iter()
                .map(|ip| ip.to_canonical())
                .filter(accepts)
                .filter(|ip| seen.insert(*ip))
                .collect();
            addresses.sort_by_key(IpAddr::is_ipv6);
            addresses.truncate(32);
            if addresses.is_empty() {
                return Err(Error::InvalidAddress);
            }
            addresses
                .into_iter()
                .map(|ip| Destination::new(&ip.to_string(), target.port()))
                .collect()
        }
    }
}
struct ResolvedReceiver {
    inner: Box<dyn DatagramReceiver>,
    target: Destination,
}
impl DatagramReceiver for ResolvedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        self.inner.recv()
    }
}
struct LocalAssociationSender {
    inner: Box<dyn DatagramAssociationSender>,
    resolver: Arc<dyn Resolver>,
    telemetry: Telemetry,
    source: kerlico_core::Source,
    outbound: OutId,
    mode: FamilyMode,
    context: ConnectContext,
    targets: HashMap<Destination, Destination>,
    ledger: Arc<telemetry::FlowLedger>,
}
impl DatagramAssociationSender for LocalAssociationSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.targets.contains_key(target) {
                if self.targets.len() >= 256 {
                    return Err(Error::ResourceLimit);
                }
                let operation = self.context.new_operation(self.context.timeout);
                let resolved = operation
                    .run(recorded_candidates(
                        self.resolver.as_ref(),
                        &self.telemetry,
                        &self.source,
                        &self.outbound,
                        target,
                        self.mode,
                    ))
                    .await?
                    .remove(0);
                self.ledger.bind_datagram_target(target, resolved.clone());
                self.targets.insert(target.clone(), resolved);
            }
            let selected = self.targets.get(target).expect("目标已绑定");
            self.inner.send_to(packet, selected).await
        })
    }
}

#[cfg(feature = "test-support")]
pub mod testing {
    use super::*;
    pub fn ingress(
        input: &kerlico_config::NodeBuildContext,
        outbound: Arc<dyn Outbound>,
        policy: TargetPolicy,
    ) -> Result<IngressBinding> {
        ingress_with_resolver(
            input,
            outbound,
            policy,
            FamilyMode::DualV4Preferred,
            Arc::new(SystemResolver),
        )
        .map(|(ingress, _)| ingress)
    }
    pub fn ingress_with_resolver(
        input: &kerlico_config::NodeBuildContext,
        outbound: Arc<dyn Outbound>,
        policy: TargetPolicy,
        mode: FamilyMode,
        resolver: Arc<dyn Resolver>,
    ) -> Result<(IngressBinding, Telemetry)> {
        let id = OutId::parse("test-outbound")?;
        let host = ServiceContext::with_device(id, native_device());
        ingress_with_service(input, outbound, policy, mode, resolver, host)
    }
    pub fn ingress_with_service(
        input: &kerlico_config::NodeBuildContext,
        outbound: Arc<dyn Outbound>,
        policy: TargetPolicy,
        mode: FamilyMode,
        resolver: Arc<dyn Resolver>,
        host: ServiceContext,
    ) -> Result<(IngressBinding, Telemetry)> {
        let id = host.id().clone();
        let association = outbound.supports_udp_association();
        let service = RunningService {
            id: id.clone(),
            capabilities: outbound.capabilities(),
            association,
            backend: outbound,
            host,
            policy,
        };
        let issuer = input.issuer();
        issuer.activate(NEXT_RUN.fetch_add(1, Ordering::AcqRel))?;
        let telemetry = Telemetry::new(4096);
        let dispatcher = Arc::new(Dispatcher {
            services: BTreeMap::from([(id.clone(), service)]),
            service_order: vec![id.clone()],
            bindings: BTreeMap::from([(issuer.node().clone(), Binding { outbound: id, mode })]),
            routes: RouteTable::default(),
            resolver,
            telemetry: telemetry.clone(),
            closed: AtomicBool::new(false),
            shutdown: tokio::sync::Mutex::new(None),
            _device: native_device(),
        });
        Ok((
            IngressBinding::assemble(issuer, input.is_local(), dispatcher, association),
            telemetry,
        ))
    }
}
