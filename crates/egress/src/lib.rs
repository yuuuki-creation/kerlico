//! 一个 Engine 的唯一命名出站所有者、可信目标调度与业务计量边界。

use kerlico_config::{
    DIRECT_OUTBOUND, EgressPlan, GLOBAL_GROUP, IngressPlan, Network, RouteTable, RunMode,
};
use kerlico_core::{
    Address, AddressedDatagram, BoxFuture, Capabilities, ConnectContext,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramReceiver, Destination, Error,
    FamilyMode, FixedUdpFlow, FlowOpen, IngressBinding, NodeId, OpenedTcp, OriginalTarget, OutId,
    Outbound, Result, RuntimeOptions, ServiceContext, ServiceRetirement, SessionDispatcher,
    SessionIdentity, ShutdownReport, TargetPolicy, TcpConnectInfo, TcpFlow, UdpAssociation,
    log::{self, LogLevel},
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
mod fetch;
mod group;
mod history;
mod meter;
mod probe;
pub mod process;
mod resource;
mod telemetry;
pub use group::{ControlPlane, DelaySample, ProxyRuntimeInfo, resident_memory_bytes};
pub use history::{
    BandwidthSample, HistoryQuery, HistoryReader, HistoryScope, HistoryWriter, OnlineSource,
    StoredFlow, StoredUsage,
};
pub use probe::{
    DEFAULT_TEST_URL, ExpectedStatus, ProbeError, ProbeResult, ProbeSpec, ProbeTarget, Prober,
};
pub use resource::{Refreshed, Refresher, ResourceStatus};
pub use telemetry::{
    DatagramTargetRecord, EventRecord, FlowEnd, FlowId, FlowKind, FlowRecord, FlowRoute, FlowStage,
    Telemetry, Usage, UsageSnapshot,
};
use telemetry::{FlowKind as Kind, FlowLease};

static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>>;
    fn lookup_fake_ip(&self, _ip: IpAddr) -> Option<String> {
        None
    }
    fn lookup_reverse_mapping(&self, _ip: IpAddr) -> Option<String> {
        None
    }
    fn exchange_dns_packet<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async {
            Err(Error::Unsupported("当前解析器不支持原始 DNS 报文转发"))
        })
    }
    fn flush_fake_ip(&self) -> Result<()> {
        Ok(())
    }
    /// 清空解析应答缓存；不带缓存的解析器无事可做。
    fn flush_dns_cache(&self) {}
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
    fn lookup_fake_ip(&self, ip: IpAddr) -> Option<String> {
        kerlico_dns::DnsResolver::lookup_fake_ip(self, ip)
    }
    fn lookup_reverse_mapping(&self, ip: IpAddr) -> Option<String> {
        kerlico_dns::DnsResolver::lookup_reverse_mapping(self, ip)
    }
    fn exchange_dns_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(kerlico_dns::DnsResolver::exchange_packet(self, packet))
    }
    fn flush_fake_ip(&self) -> Result<()> {
        kerlico_dns::DnsResolver::flush_fake_ip(self)
    }
    fn flush_dns_cache(&self) {
        kerlico_dns::DnsResolver::flush_cache(self);
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
    control_plane: ControlPlane,
    /// 后台健康检查任务的所有者，随运行时关闭取消并等待退出。
    health: ServiceContext,
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
        self.dispatcher.health.retire(Instant::now());
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
        let compiled_groups = plan.groups().to_vec();
        let compiled_providers = plan.providers().to_vec();
        let rule_providers = plan.rule_providers().clone();
        let store_selected_path = plan.store_selected_path().map(str::to_owned);
        let mode = plan.mode();
        let (plans, bindings, routes_table, max_flows, detour_table) = plan.into_parts();
        let RuntimeOptions { device, language } = options;
        let run = NEXT_RUN
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::ResourceLimit)?;
        let deadline = Instant::now() + budget;
        let kinds: HashMap<OutId, String> = plans
            .iter()
            .map(|named| (named.id.clone(), group::mihomo_type(&named.kind)))
            .collect();
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
        let static_meta: Vec<(OutId, String, bool)> = started
            .iter()
            .map(|s| {
                let kind = kinds.get(&s.id).cloned().unwrap_or_default();
                (s.id.clone(), kind, s.capabilities.udp)
            })
            .collect();
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
        let (health_jobs, rejected_jobs) =
            probe::health_jobs(&compiled_groups, &compiled_providers);
        let telemetry = Telemetry::new(max_flows);
        let control_plane = ControlPlane::new(
            static_meta,
            compiled_groups,
            compiled_providers,
            rule_providers,
            routes_table.clone(),
            store_selected_path,
            mode,
            resolver.clone(),
            telemetry.clone(),
        );
        let dispatcher = Arc::new(Dispatcher {
            services,
            service_order,
            bindings: routes,
            routes: routes_table,
            resolver,
            telemetry,
            control_plane,
            health: ServiceContext::new(OutId::parse("health-check")?),
            closed: AtomicBool::new(false),
            shutdown: tokio::sync::Mutex::new(None),
            _device: device,
        });
        for reason in rejected_jobs {
            kerlico_core::log::warning(format!("健康检查未启用：{reason}"));
        }
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
        for job in health_jobs {
            let task =
                probe::run_health_job(Arc::downgrade(&dispatcher), job, dispatcher.health.cancel());
            if let Err(error) = dispatcher.health.spawn(task) {
                kerlico_core::log::warning(format!("健康检查任务启动失败：{error}"));
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
            .map(|s| s.association)
            .or_else(|| {
                dispatcher
                    .control_plane
                    .is_group(&binding.outbound)
                    .then_some(true)
            })
            .ok_or_else(|| Error::Config("出站绑定不存在".into()))?;
        let node = binding.issuer.node().clone();
        Ok((
            node,
            IngressBinding::assemble(
                binding.issuer,
                binding.local,
                dispatcher.clone(),
                association,
            )
            .with_sniff_policy(binding.sniff_policy),
        ))
    }
    pub fn exchange_dns_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        self.dispatcher.resolver.exchange_dns_packet(packet)
    }
    pub fn ingress(&self, node: &NodeId) -> Result<IngressBinding> {
        self.ingresses.get(node).cloned().ok_or(Error::Rejected)
    }
    pub fn telemetry(&self) -> Telemetry {
        self.dispatcher.telemetry.clone()
    }
    pub fn control_plane(&self) -> ControlPlane {
        self.dispatcher.control_plane.clone()
    }
    pub fn prober(&self) -> Prober {
        Prober(Arc::downgrade(&self.dispatcher))
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
        self.dispatcher.health.retire(deadline);
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
        let mut report = progress.report();
        report.merge(&self.dispatcher.health.shutdown(progress.deadline).await);
        report
    }
}
fn network_label(network: Network) -> &'static str {
    match network {
        Network::Tcp => "TCP",
        Network::Udp => "UDP",
    }
}

fn source_text(source: Option<std::net::SocketAddr>) -> String {
    source.map_or_else(|| "unknown".to_owned(), |address| address.to_string())
}

/// 同 Mihomo 隧道的连接日志：`[TCP] 源 --> 目标 match 规则(载荷) using 组[出站]`。
fn connection_log(
    mode: RunMode,
    source: Option<std::net::SocketAddr>,
    request: Option<(&OriginalTarget, Network)>,
    outbound: &OutId,
    route: &FlowRoute,
) -> String {
    let (network, target) = request.map_or(("UDP", String::new()), |(original, network)| {
        (network_label(network), original.target().to_string())
    });
    let chain = match route.groups.first() {
        Some(group) => format!("{group}[{outbound}]"),
        None => outbound.to_string(),
    };
    let source = source_text(source);
    match (mode, &route.rule) {
        (RunMode::Global, _) => format!("[{network}] {source} --> {target} using GLOBAL"),
        (RunMode::Direct, _) => format!("[{network}] {source} --> {target} using DIRECT"),
        (RunMode::Rule, Some(rule)) if !rule.payload.is_empty() => format!(
            "[{network}] {source} --> {target} match {}({}) using {chain}",
            rule.kind, rule.payload
        ),
        (RunMode::Rule, Some(rule)) => {
            format!(
                "[{network}] {source} --> {target} match {} using {chain}",
                rule.kind
            )
        }
        (RunMode::Rule, _) => {
            format!("[{network}] {source} --> {target} doesn't match any rule using {chain}")
        }
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
    fn enrich_original(&self, mut original: OriginalTarget) -> OriginalTarget {
        if let Address::Ip(ip) = original.target().address().clone() {
            if let Some(domain) = self.resolver.lookup_fake_ip(ip) {
                if let Ok(dst) = Destination::new(&domain, original.target().port()) {
                    original = original.with_target(dst);
                }
            } else if original.sniffed_domain().is_none()
                && let Some(domain) = self.resolver.lookup_reverse_mapping(ip)
            {
                original = original.with_sniffed(Some(domain), None);
            }
        }
        original
    }

    fn evaluate_route(
        &self,
        identity: &SessionIdentity,
        request: Option<(&OriginalTarget, Network)>,
    ) -> (
        kerlico_routing::RouteDecision,
        Option<OutId>,
        Option<(String, String)>,
    ) {
        let binding_out = self
            .bindings
            .get(identity.source().node())
            .map(|b| b.outbound.clone());
        let Some((original, network)) = request else {
            return (kerlico_routing::RouteDecision::default(), binding_out, None);
        };
        let proc_info = if self.routes.has_process_rules() {
            process::resolve_local_process(identity.observed_source(), network)
        } else {
            None
        };
        let ctx = kerlico_routing::RouteContext {
            target: original.target(),
            resolved_ips: &[],
            network,
            source: identity.source(),
            source_addr: identity.observed_source(),
            protocol: original.sniffed_protocol(),
            sniffed_domain: original.sniffed_domain(),
            process_name: proc_info.as_ref().map(|(n, _)| n.as_str()),
            process_path: proc_info
                .as_ref()
                .and_then(|(_, p)| (!p.is_empty()).then_some(p.as_str())),
        };
        let decision = self.routes.evaluate(&ctx);
        let decision = match self.control_plane.mode() {
            RunMode::Rule => decision,
            mode => kerlico_routing::RouteDecision {
                outbound: OutId::parse(if mode == RunMode::Global {
                    GLOBAL_GROUP
                } else {
                    DIRECT_OUTBOUND
                })
                .ok(),
                hijack_dns: decision.hijack_dns,
                sniff: decision.sniff,
                ..Default::default()
            },
        };
        let selected = if let Some(btag) = &decision.balancer_tag
            && let Ok(bid) = OutId::parse(btag)
        {
            Some(bid)
        } else {
            decision.outbound.clone().or(binding_out)
        };
        (decision, selected, proc_info)
    }

    fn apply_route_overrides(
        mut original: OriginalTarget,
        decision: &kerlico_routing::RouteDecision,
    ) -> OriginalTarget {
        if decision.sniff.is_some()
            && matches!(original.target().address(), Address::Ip(_))
            && let Some(sniffed) = original.sniffed_domain()
            && let Ok(dst) = Destination::new(sniffed, original.target().port())
        {
            original = original.with_target(dst);
        }
        if decision.override_address.is_some() || decision.override_port.is_some() {
            let host = decision
                .override_address
                .clone()
                .unwrap_or_else(|| original.target().host());
            let port = decision
                .override_port
                .unwrap_or_else(|| original.target().port());
            if let Ok(dst) = Destination::new(&host, port) {
                original = original.with_target(dst);
            }
        }
        original
    }

    /// 多目标 UDP 关联建立时没有单一目标，固定使用节点绑定的出站。
    fn route(
        &self,
        identity: &SessionIdentity,
        request: Option<(&OriginalTarget, Network)>,
    ) -> Result<(
        &RunningService,
        FamilyMode,
        kerlico_routing::RouteDecision,
        FlowRoute,
    )> {
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
        let (decision, outbound, process) = self.evaluate_route(identity, request);
        if decision.reject {
            return Err(Error::Rejected);
        }
        let initial_outbound = outbound.ok_or(Error::Rejected)?;
        let (outbound, groups) = self.control_plane.resolve_outbound(
            &initial_outbound,
            request.map(|(orig, _)| orig),
            identity.observed_source(),
        )?;
        let service = self.services.get(&outbound).ok_or(Error::Rejected)?;
        service.host.check()?;
        let route = FlowRoute {
            rule: decision.rule.clone(),
            groups,
            process,
        };
        Ok((service, binding.mode, decision, route))
    }

    fn selected_outbound(
        &self,
        identity: &SessionIdentity,
        request: Option<(&OriginalTarget, Network)>,
    ) -> Option<OutId> {
        let (_, selected, _) = self.evaluate_route(identity, request);
        selected
    }

    /// 取得流账本前的准入；此处失败还没有租约，单独记一条错误事件。
    fn admit(
        &self,
        identity: &SessionIdentity,
        context: &ConnectContext,
        request: Option<(&OriginalTarget, Network)>,
        capable: impl FnOnce(&RunningService) -> Result<()>,
        original: Option<OriginalTarget>,
        kind: Kind,
    ) -> Result<(
        &RunningService,
        FamilyMode,
        Arc<telemetry::FlowLedger>,
        kerlico_routing::RouteDecision,
    )> {
        if context.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let admitted =
            self.route(identity, request)
                .and_then(|(service, mode, decision, route)| {
                    capable(service)?;
                    let announce = log::enabled(LogLevel::Info).then(|| {
                        connection_log(
                            self.control_plane.mode(),
                            identity.observed_source(),
                            request,
                            &service.id,
                            &route,
                        )
                    });
                    let ledger = self.telemetry.open(
                        identity,
                        &service.id,
                        original,
                        kind,
                        route,
                        context.cancel.child_token(),
                    )?;
                    if let Some(line) = announce {
                        log::info(line);
                    }
                    Ok((service, mode, ledger, decision))
                });
        if let Err(error) = &admitted
            && let Some(outbound) = self.selected_outbound(identity, request)
        {
            if log::enabled(LogLevel::Warning) {
                log::warning(format!(
                    "[{}] dial {outbound} {} --> {} error: {error}",
                    request.map_or("UDP", |(_, network)| network_label(network)),
                    source_text(identity.observed_source()),
                    request.map_or_else(String::new, |(target, _)| target.target().to_string()),
                ));
            }
            self.telemetry.open_failed(
                identity.source(),
                &outbound,
                request.map(|(target, _)| target.target()),
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
        let original = self.enrich_original(original);
        let (decision_pre, _, _) = self.evaluate_route(identity, Some((&original, Network::Tcp)));
        if decision_pre.hijack_dns {
            let resolver = self.resolver.clone();
            return Ok(FlowOpen::tcp(
                Box::pin(async move {
                    let (client, mut server) = tokio::io::duplex(16384);
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut len_buf = [0u8; 2];
                        while server.read_exact(&mut len_buf).await.is_ok() {
                            let qlen = u16::from_be_bytes(len_buf) as usize;
                            if qlen == 0 || qlen > 8192 {
                                break;
                            }
                            let mut qbuf = vec![0u8; qlen];
                            if server.read_exact(&mut qbuf).await.is_err() {
                                break;
                            }
                            let Ok(reply) = resolver.exchange_dns_packet(&qbuf).await else {
                                break;
                            };
                            let Ok(rlen) = u16::try_from(reply.len()) else {
                                break;
                            };
                            if server.write_all(&rlen.to_be_bytes()).await.is_err()
                                || server.write_all(&reply).await.is_err()
                            {
                                break;
                            }
                        }
                    });
                    Ok(OpenedTcp {
                        stream: Box::new(client),
                        info: TcpConnectInfo::unknown(),
                    })
                }),
                |_outcome| {},
            ));
        }
        let (service, mode, ledger, decision) = self.admit(
            identity,
            context,
            Some((&original, Network::Tcp)),
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
        let original = Self::apply_route_overrides(original, &decision);
        let resolve_strategy = decision.resolve_strategy;
        let scoped = context
            .scoped(
                &service.host,
                identity.source(),
                identity.node_cancel(),
                identity.cancel(),
                mode,
            )
            .with_cancel(ledger.close_token());
        let lease = FlowLease::new(&self.telemetry, ledger.clone(), &scoped, identity);
        let completion = lease.clone();
        Ok(FlowOpen::tcp(
            Box::pin(async move {
                let result = match service.policy {
                    TargetPolicy::Remote => scoped
                        .run(async {
                            let target = if let Some(strategy) = resolve_strategy
                                && let Address::Domain(host) = original.target().address()
                            {
                                let raw = self.resolver.resolve(host).await?;
                                let ips = strategy.filter_ips(&raw);
                                let first = ips.into_iter().next().ok_or(Error::InvalidAddress)?;
                                Destination::new(&first.to_string(), original.target().port())?
                            } else {
                                original.target().clone()
                            };
                            service.backend.connect_tcp(&target, &scoped).await
                        })
                        .await
                        .map(|stream| (stream, None)),
                    TargetPolicy::Local => {
                        scoped
                            .run(async {
                                let candidates = recorded_candidates_with_strategy(
                                    self.resolver.as_ref(),
                                    &self.telemetry,
                                    identity.source(),
                                    &service.id,
                                    original.target(),
                                    mode,
                                    resolve_strategy,
                                )
                                .await?;
                                connect_candidates(service.backend.as_ref(), &candidates, &scoped)
                                    .await
                                    .map(|(stream, target)| (stream, Some(target)))
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
        let original = self.enrich_original(original);
        let (decision_pre, _, _) = self.evaluate_route(identity, Some((&original, Network::Udp)));
        if decision_pre.hijack_dns {
            let resolver = self.resolver.clone();
            return Ok(FlowOpen::fixed_udp(
                Box::pin(async move {
                    let (tx, rx) = tokio::sync::mpsc::channel(8);
                    Ok(kerlico_core::DatagramChannel {
                        sender: Box::new(DnsHijackSender { resolver, tx }),
                        receiver: Box::new(DnsHijackReceiver {
                            rx,
                            target: original.target().clone(),
                        }),
                    })
                }),
                |_outcome| {},
            ));
        }
        let (service, mode, ledger, decision) = self.admit(
            identity,
            context,
            Some((&original, Network::Udp)),
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
        let original = Self::apply_route_overrides(original, &decision);
        let resolve_strategy = decision.resolve_strategy;
        let scoped = context
            .scoped(
                &service.host,
                identity.source(),
                identity.node_cancel(),
                identity.cancel(),
                mode,
            )
            .with_cancel(ledger.close_token());
        let lease = FlowLease::new(&self.telemetry, ledger.clone(), &scoped, identity);
        let completion = lease.clone();
        Ok(FlowOpen::fixed_udp(
            Box::pin(async move {
                let result = scoped
                    .run(async {
                        let target = match service.policy {
                            TargetPolicy::Remote => {
                                if let Some(strategy) = resolve_strategy
                                    && let Address::Domain(host) = original.target().address()
                                {
                                    let raw = self.resolver.resolve(host).await?;
                                    let ips = strategy.filter_ips(&raw);
                                    let first =
                                        ips.into_iter().next().ok_or(Error::InvalidAddress)?;
                                    Destination::new(&first.to_string(), original.target().port())?
                                } else {
                                    original.target().clone()
                                }
                            }
                            TargetPolicy::Local => recorded_candidates_with_strategy(
                                self.resolver.as_ref(),
                                &self.telemetry,
                                identity.source(),
                                &service.id,
                                original.target(),
                                mode,
                                resolve_strategy,
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
        let (service, mode, ledger, _) = self.admit(
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
        let scoped = context
            .scoped(
                &service.host,
                identity.source(),
                identity.node_cancel(),
                identity.cancel(),
                mode,
            )
            .with_cancel(ledger.close_token());
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
                        if self.routes.has_hijack_dns() {
                            let (tx, rx) = tokio::sync::mpsc::channel(16);
                            channel.sender = Box::new(DnsHijackAssociationSender {
                                inner: channel.sender,
                                routes: self.routes.clone(),
                                resolver: self.resolver.clone(),
                                source: identity.source().clone(),
                                source_addr: identity.observed_source(),
                                tx,
                            });
                            channel.receiver = Box::new(DnsHijackAssociationReceiver {
                                inner: channel.receiver,
                                rx,
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
            .is_ok_and(|(service, _, _, _)| service.association)
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

struct DnsHijackSender {
    resolver: Arc<dyn Resolver>,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}
impl kerlico_core::DatagramSender for DnsHijackSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let reply = self.resolver.exchange_dns_packet(packet).await?;
            self.tx
                .send(reply)
                .await
                .map_err(|_| Error::Protocol("DNS 劫持回包通道已关闭"))
        })
    }
}

struct DnsHijackReceiver {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    target: Destination,
}
impl DatagramReceiver for DnsHijackReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move { Ok(self.rx.recv().await) })
    }
}

struct DnsHijackAssociationSender {
    inner: Box<dyn DatagramAssociationSender>,
    routes: RouteTable,
    resolver: Arc<dyn Resolver>,
    source: kerlico_core::Source,
    source_addr: Option<std::net::SocketAddr>,
    tx: tokio::sync::mpsc::Sender<AddressedDatagram>,
}
impl DatagramAssociationSender for DnsHijackAssociationSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let ctx = kerlico_routing::RouteContext {
                target,
                resolved_ips: &[],
                network: Network::Udp,
                source: &self.source,
                source_addr: self.source_addr,
                protocol: Some("dns"),
                sniffed_domain: None,
                process_name: None,
                process_path: None,
            };
            if self.routes.evaluate(&ctx).hijack_dns {
                let reply = self.resolver.exchange_dns_packet(packet).await?;
                let _ = self.tx.send((target.clone(), reply)).await;
                return Ok(());
            }
            self.inner.send_to(packet, target).await
        })
    }
}

struct DnsHijackAssociationReceiver {
    inner: Box<dyn DatagramAssociationReceiver>,
    rx: tokio::sync::mpsc::Receiver<AddressedDatagram>,
}
impl DatagramAssociationReceiver for DnsHijackAssociationReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            if let Ok(item) = self.rx.try_recv() {
                return Ok(Some(item));
            }
            tokio::select! {
                biased;
                some_hijack = self.rx.recv() => {
                    match some_hijack {
                        Some(item) => Ok(Some(item)),
                        None => self.inner.recv_from().await,
                    }
                }
                res = self.inner.recv_from() => res,
            }
        })
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
/// 依次尝试已解析的候选地址；非末位候选最多占用 1 秒，仅 I/O 与超时错误换下一个。
async fn connect_candidates(
    backend: &dyn Outbound,
    candidates: &[Destination],
    scoped: &ConnectContext,
) -> Result<(OpenedTcp, Destination)> {
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
        match attempt.run(backend.connect_tcp(target, &attempt)).await {
            Ok(stream) => return Ok((stream, target.clone())),
            Err(error @ (Error::Io(_) | Error::Timeout)) => last = error,
            Err(error) => return Err(error),
        }
    }
    Err(last)
}
async fn recorded_candidates(
    resolver: &dyn Resolver,
    telemetry: &Telemetry,
    source: &kerlico_core::Source,
    outbound: &OutId,
    target: &Destination,
    mode: FamilyMode,
) -> Result<Vec<Destination>> {
    recorded_candidates_with_strategy(resolver, telemetry, source, outbound, target, mode, None)
        .await
}
async fn recorded_candidates_with_strategy(
    resolver: &dyn Resolver,
    telemetry: &Telemetry,
    source: &kerlico_core::Source,
    outbound: &OutId,
    target: &Destination,
    mode: FamilyMode,
    strategy: Option<kerlico_routing::ResolveStrategy>,
) -> Result<Vec<Destination>> {
    let mut pending = PendingLookup {
        telemetry,
        source,
        outbound,
        target,
        settled: false,
    };
    let result = candidates_with_strategy(resolver, target, mode, strategy).await;
    pending.settled = true;
    telemetry.dns_event(source, outbound, target, &result);
    result
}
async fn candidates_with_strategy(
    resolver: &dyn Resolver,
    target: &Destination,
    mode: FamilyMode,
    strategy: Option<kerlico_routing::ResolveStrategy>,
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
            } else if let Some(domain) = resolver.lookup_fake_ip(*ip) {
                let restored = Destination::new(&domain, target.port())?;
                Box::pin(candidates_with_strategy(
                    resolver, &restored, mode, strategy,
                ))
                .await
            } else if accepts(ip) {
                Ok(vec![target.clone()])
            } else {
                Err(Error::Rejected)
            }
        }
        Address::Domain(host) => {
            let mut seen = HashSet::new();
            let raw_ips = resolver.resolve(host).await?;
            let filtered = match strategy {
                Some(s) => s.filter_ips(&raw_ips),
                None => raw_ips,
            };
            let mut addresses: Vec<_> = filtered
                .into_iter()
                .map(|ip| ip.to_canonical())
                .filter(accepts)
                .filter(|ip| seen.insert(*ip))
                .collect();
            if strategy.is_none() {
                addresses.sort_by_key(IpAddr::is_ipv6);
            }
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
            resolver: resolver.clone(),
            telemetry: telemetry.clone(),
            control_plane: ControlPlane::new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                BTreeMap::new(),
                RouteTable::default(),
                None,
                kerlico_config::RunMode::Rule,
                resolver.clone(),
                telemetry.clone(),
            ),
            health: ServiceContext::new(OutId::parse("health-check")?),
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

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeMapResolver {
        fake_domain: String,
        real_ip: IpAddr,
    }

    impl Resolver for FakeMapResolver {
        fn resolve<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
            let ip = self.real_ip;
            Box::pin(async move { Ok(vec![ip]) })
        }
        fn lookup_fake_ip(&self, ip: IpAddr) -> Option<String> {
            if ip == IpAddr::from([198, 18, 0, 10]) {
                Some(self.fake_domain.clone())
            } else {
                None
            }
        }
    }

    #[tokio::test]
    async fn fake_ip_restores_domain_and_resolves_real_ip() {
        let resolver = FakeMapResolver {
            fake_domain: "real.example.com".into(),
            real_ip: IpAddr::from([93, 184, 216, 34]),
        };
        let target = Destination::new("198.18.0.10", 443).unwrap();
        let candidates =
            candidates_with_strategy(&resolver, &target, FamilyMode::DualV4Preferred, None)
                .await
                .unwrap();
        assert_eq!(
            candidates,
            vec![Destination::new("93.184.216.34", 443).unwrap()]
        );
    }

    #[test]
    fn apply_route_overrides_replaces_host_and_port() {
        let orig = OriginalTarget::new("old.example.com", 80).unwrap();
        let decision = kerlico_routing::RouteDecision {
            outbound: Some(OutId::parse("direct").unwrap()),
            balancer_tag: None,
            override_address: Some("new.example.com".into()),
            override_port: Some(8443),
            resolve_strategy: None,
            sniff: None,
            reject: false,
            hijack_dns: false,
            rule: None,
        };
        let updated = Dispatcher::apply_route_overrides(orig, &decision);
        assert_eq!(
            updated.target(),
            &Destination::new("new.example.com", 8443).unwrap()
        );
    }
}
