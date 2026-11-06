use crate::{ControlSpec, DeviceSpec, DnsSpec, ForwardSpec, HistorySpec, Limits};
use kerlico_core::{
    BoxFuture, Capabilities, CredentialIssuer, FamilyMode, InboundProtocol, NodeId, OutId,
    Outbound, Result, ServiceContext, TargetPolicy,
};
use kerlico_routing::RouteTable;
use std::{net::SocketAddr, sync::Arc};

type ServiceStarter =
    Box<dyn FnOnce(ServiceContext) -> BoxFuture<'static, Result<Arc<dyn Outbound>>> + Send>;

/// 编译后的不可重复消费计划，没有运行连接、任务或监听器。
pub struct OutboundPlan {
    capabilities: Capabilities,
    association: bool,
    policy: TargetPolicy,
    native_targets: bool,
    start: ServiceStarter,
}
impl OutboundPlan {
    pub fn new(
        capabilities: Capabilities,
        association: bool,
        policy: TargetPolicy,
        start: impl FnOnce(ServiceContext) -> BoxFuture<'static, Result<Arc<dyn Outbound>>>
        + Send
        + 'static,
    ) -> Self {
        Self {
            capabilities,
            association,
            policy,
            native_targets: false,
            start: Box::new(start),
        }
    }
    pub fn with_native_targets(mut self) -> Self {
        self.native_targets = true;
        self
    }
    pub fn needs_native_targets(&self) -> bool {
        self.native_targets
    }
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
    pub fn supports_udp_association(&self) -> bool {
        self.association
    }
    pub fn target_policy(&self) -> TargetPolicy {
        self.policy
    }
    pub async fn start(self, host: ServiceContext) -> Result<Arc<dyn Outbound>> {
        (self.start)(host).await
    }
}

pub struct NamedServicePlan {
    pub id: OutId,
    pub plan: OutboundPlan,
}

#[derive(Clone)]
pub struct IngressPlan {
    pub issuer: CredentialIssuer,
    pub outbound: OutId,
    pub mode: FamilyMode,
    pub local: bool,
    pub sniff_policy: kerlico_core::SniffPolicy,
}

#[derive(Clone)]
pub struct PreparedNode {
    pub tag: String,
    pub listen: SocketAddr,
    pub protocol: Arc<dyn InboundProtocol>,
    pub max_sessions: usize,
    pub accept_proxy_protocol: bool,
}

/// 出站计划只能整体移动到运行所有者，不对应用暴露运行对象表。
pub struct EgressPlan {
    pub(crate) services: Vec<NamedServicePlan>,
    pub(crate) bindings: Vec<IngressPlan>,
    pub(crate) routes: RouteTable,
    pub(crate) dns: Option<DnsSpec>,
    pub(crate) max_flows: usize,
    pub(crate) detour_table: Arc<kerlico_core::DetourTable>,
    pub(crate) groups: Vec<crate::CompiledProxyGroup>,
    pub(crate) providers: Vec<crate::CompiledProxyProvider>,
    pub(crate) rule_providers: std::collections::BTreeMap<String, usize>,
    pub(crate) resources: Vec<crate::ResourceSpec>,
    pub(crate) store_selected_path: Option<String>,
    pub(crate) log: crate::LogSpec,
}
impl EgressPlan {
    pub fn dns(&self) -> Option<&DnsSpec> {
        self.dns.as_ref()
    }
    pub fn groups(&self) -> &[crate::CompiledProxyGroup] {
        &self.groups
    }
    pub fn providers(&self) -> &[crate::CompiledProxyProvider] {
        &self.providers
    }
    pub fn rule_providers(&self) -> &std::collections::BTreeMap<String, usize> {
        &self.rule_providers
    }
    /// 运行时启动后加载与周期刷新的落盘资源。
    pub fn resources(&self) -> &[crate::ResourceSpec] {
        &self.resources
    }
    pub fn store_selected_path(&self) -> Option<&str> {
        self.store_selected_path.as_deref()
    }
    pub fn log(&self) -> &crate::LogSpec {
        &self.log
    }
    pub fn into_parts(
        self,
    ) -> (
        Vec<NamedServicePlan>,
        Vec<IngressPlan>,
        RouteTable,
        usize,
        Arc<kerlico_core::DetourTable>,
    ) {
        (
            self.services,
            self.bindings,
            self.routes,
            self.max_flows,
            self.detour_table,
        )
    }
}

pub struct PreparedConfig {
    pub(crate) history: Option<HistorySpec>,
    pub(crate) device: Option<DeviceSpec>,
    pub(crate) control: Option<ControlSpec>,
    pub(crate) egress: EgressPlan,
    pub(crate) inbounds: Vec<ForwardSpec>,
    pub(crate) limits: Limits,
    pub(crate) nodes: Vec<PreparedNode>,
    pub(crate) lan_filter: kerlico_core::IpFilter,
}
pub struct EnginePlanParts {
    pub history: Option<HistorySpec>,
    pub egress: EgressPlan,
    pub inbounds: Vec<ForwardSpec>,
    pub limits: Limits,
    pub nodes: Vec<PreparedNode>,
    pub lan_filter: kerlico_core::IpFilter,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceRequirements {
    pub local_ipv4: bool,
    pub local_ipv6: bool,
    pub auto_warp: bool,
}
impl PreparedConfig {
    pub fn device(&self) -> Option<&DeviceSpec> {
        self.device.as_ref()
    }
    pub fn control(&self) -> Option<&ControlSpec> {
        self.control.as_ref()
    }
    pub fn into_parts(self) -> EnginePlanParts {
        EnginePlanParts {
            history: self.history,
            egress: self.egress,
            inbounds: self.inbounds,
            limits: self.limits,
            nodes: self.nodes,
            lan_filter: self.lan_filter,
        }
    }
    pub fn ingress_count(&self) -> usize {
        self.nodes.len() + self.inbounds.len()
    }
    pub fn service_count(&self) -> usize {
        self.egress.services.len()
    }
    pub fn node_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.egress
            .bindings
            .iter()
            .map(|binding| binding.issuer.node())
    }
    /// 只报告本地目标族需求，不把配置需求当作设备可用性或部署结果。
    pub fn device_requirements(&self) -> DeviceRequirements {
        let mut requirements = DeviceRequirements::default();
        for binding in &self.egress.bindings {
            let local = self.egress.services.iter().any(|service| {
                service.plan.needs_native_targets()
                    && (service.id == binding.outbound
                        || self.egress.routes.outbounds().any(|id| *id == service.id))
            });
            if local {
                requirements.auto_warp |= binding.mode == FamilyMode::DualV4Preferred;
                requirements.local_ipv4 |= binding.mode != FamilyMode::V6Only;
                requirements.local_ipv6 |= binding.mode != FamilyMode::V4Only;
            }
        }
        requirements
    }
}
