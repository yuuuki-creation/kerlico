//! 策略组运行时（`select`、`url-test`、`fallback`、`load-balance`、`balancer`）、延迟历史、连接中断与控制面状态。

use crate::Resolver;
use kerlico_config::{
    CompiledProxyGroup, CompiledProxyProvider, LoadBalanceStrategy, LogSpec, ProxyGroupKind,
};
use kerlico_core::{CancellationToken, Destination, Error, OriginalTarget, OutId, Result, Source};
use kerlico_routing::{Network, RouteContext, RouteTable};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_DELAY_HISTORY: usize = 20;
const MAX_LOG_ENTRIES: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelaySample {
    pub time: String,
    pub delay: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxyRuntimeInfo {
    pub name: String,
    pub kind: String,
    pub udp: bool,
    pub alive: bool,
    pub fail_count: u32,
    pub last_error: Option<String>,
    pub last_try_ms: u64,
    pub last_seen_ms: u64,
    pub history: VecDeque<DelaySample>,
}

struct GroupRuntimeEntry {
    spec: CompiledProxyGroup,
    selected: Option<OutId>,
    fixed: Option<OutId>,
    rr_counter: AtomicUsize,
    last_touch_ms: AtomicU64,
}

/// 健康检查任务的归属，决定 `lazy` 以哪些策略组的最近使用时间为准。
pub(crate) enum HealthOwner {
    Group(OutId),
    Provider,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructuredLogEntry {
    pub time: String,
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

#[derive(Clone)]
pub struct ActiveConnection {
    pub id: u64,
    pub outbound: OutId,
    pub group: Option<OutId>,
    pub target: Option<String>,
    pub network: &'static str,
    pub started_ms: u64,
    pub cancel: CancellationToken,
}

struct InnerControlPlane {
    groups: RwLock<BTreeMap<OutId, GroupRuntimeEntry>>,
    proxies: RwLock<BTreeMap<OutId, ProxyRuntimeInfo>>,
    providers: RwLock<BTreeMap<String, CompiledProxyProvider>>,
    rule_providers: RwLock<BTreeMap<String, usize>>,
    routes: RwLock<RouteTable>,
    store_selected_path: Option<PathBuf>,
    log_spec: RwLock<LogSpec>,
    logs: Mutex<VecDeque<StructuredLogEntry>>,
    active_conns: Mutex<BTreeMap<u64, ActiveConnection>>,
    dynamic_inbounds: RwLock<BTreeMap<String, BTreeMap<String, Value>>>,
    resolver: Arc<dyn Resolver>,
    config_reloads: AtomicU64,
    geo_updates: AtomicU64,
}

#[derive(Clone)]
pub struct ControlPlane(Arc<InnerControlPlane>);

impl Default for ControlPlane {
    fn default() -> Self {
        Self::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            BTreeMap::new(),
            RouteTable::default(),
            None,
            LogSpec::default(),
            Arc::new(crate::SystemResolver),
        )
    }
}

impl ControlPlane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        static_services: Vec<(OutId, String, bool)>,
        compiled_groups: Vec<CompiledProxyGroup>,
        compiled_providers: Vec<CompiledProxyProvider>,
        rule_providers: BTreeMap<String, usize>,
        routes: RouteTable,
        store_selected_path: Option<String>,
        log_spec: LogSpec,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let mut proxies = BTreeMap::new();
        for (id, kind, udp) in static_services {
            proxies.insert(
                id.clone(),
                ProxyRuntimeInfo {
                    name: id.to_string(),
                    kind,
                    udp,
                    alive: true,
                    fail_count: 0,
                    last_error: None,
                    last_try_ms: 0,
                    last_seen_ms: now_ms(),
                    history: VecDeque::new(),
                },
            );
        }

        let persisted: BTreeMap<String, String> = store_selected_path
            .as_deref()
            .and_then(|p| {
                kerlico_dns::cache_file::load(Path::new(p), kerlico_dns::cache_file::SELECTED)
            })
            .unwrap_or_default();

        let mut groups = BTreeMap::new();
        for g in compiled_groups {
            let id = g.id.clone();
            let restored = persisted
                .get(id.as_str())
                .and_then(|s| OutId::parse(s).ok())
                .filter(|cand| g.candidates.contains(cand));
            let initial = restored.clone().or_else(|| g.default_selected.clone());
            proxies.insert(
                id.clone(),
                ProxyRuntimeInfo {
                    name: id.to_string(),
                    kind: g.kind.as_str().to_owned(),
                    udp: !g.disable_udp,
                    alive: true,
                    fail_count: 0,
                    last_error: None,
                    last_try_ms: 0,
                    last_seen_ms: now_ms(),
                    history: VecDeque::new(),
                },
            );
            groups.insert(
                id,
                GroupRuntimeEntry {
                    spec: g,
                    selected: initial,
                    fixed: restored,
                    rr_counter: AtomicUsize::new(0),
                    last_touch_ms: AtomicU64::new(0),
                },
            );
        }

        let providers_map = compiled_providers
            .into_iter()
            .map(|p| (p.name.clone(), p))
            .collect();

        let mut logs = VecDeque::new();
        logs.push_back(StructuredLogEntry {
            time: now_iso_string(),
            level: log_spec.level.clone().unwrap_or_else(|| "info".to_owned()),
            payload: "kerlico control plane initialized".into(),
        });

        Self(Arc::new(InnerControlPlane {
            groups: RwLock::new(groups),
            proxies: RwLock::new(proxies),
            providers: RwLock::new(providers_map),
            rule_providers: RwLock::new(rule_providers),
            routes: RwLock::new(routes),
            store_selected_path: store_selected_path.map(PathBuf::from),
            log_spec: RwLock::new(log_spec),
            logs: Mutex::new(logs),
            active_conns: Mutex::new(BTreeMap::new()),
            dynamic_inbounds: RwLock::new(BTreeMap::new()),
            resolver,
            config_reloads: AtomicU64::new(0),
            geo_updates: AtomicU64::new(0),
        }))
    }

    pub fn is_group(&self, id: &OutId) -> bool {
        self.0
            .groups
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(id)
    }

    /// 将可能指向策略组或负载均衡器的 `OutId` 解析为最终具体 `OutId`，同时返回所属顶层策略组。
    ///
    /// 经过的策略组记为最近使用，`lazy` 健康检查据此决定是否跳过本轮。
    pub fn resolve_outbound(
        &self,
        initial: &OutId,
        original: Option<&OriginalTarget>,
        source_addr: Option<std::net::SocketAddr>,
    ) -> Result<(OutId, Option<OutId>)> {
        self.resolve(initial, original, source_addr, true)
    }

    /// 探测与路由测试使用，不计入最近使用。
    pub(crate) fn resolve_untouched(&self, initial: &OutId) -> Result<OutId> {
        self.resolve(initial, None, None, false).map(|(id, _)| id)
    }

    fn resolve(
        &self,
        initial: &OutId,
        original: Option<&OriginalTarget>,
        source_addr: Option<std::net::SocketAddr>,
        touch: bool,
    ) -> Result<(OutId, Option<OutId>)> {
        let now = if touch { now_ms() } else { 0 };
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        let proxies = self.0.proxies.read().unwrap_or_else(|e| e.into_inner());
        let mut current = initial.clone();
        let mut top_group = None;
        for _ in 0..8 {
            let Some(entry) = groups.get(&current) else {
                return Ok((current, top_group));
            };
            if top_group.is_none() {
                top_group = Some(current.clone());
            }
            if touch {
                entry.last_touch_ms.store(now, Ordering::Relaxed);
            }
            let next = Self::pick_group_member(entry, &proxies, original, source_addr)?;
            current = next;
        }
        Err(Error::Config("策略组嵌套层级超过上限".into()))
    }

    fn pick_group_member(
        entry: &GroupRuntimeEntry,
        proxies: &BTreeMap<OutId, ProxyRuntimeInfo>,
        original: Option<&OriginalTarget>,
        source_addr: Option<std::net::SocketAddr>,
    ) -> Result<OutId> {
        if let Some(fixed) = &entry.fixed
            && entry.spec.candidates.contains(fixed)
        {
            return Ok(fixed.clone());
        }
        if entry.spec.candidates.is_empty() {
            if entry.spec.empty_fallback {
                return OutId::parse("direct");
            }
            if let Some(fb) = &entry.spec.fallback_outbound {
                return Ok(fb.clone());
            }
            return Err(Error::InvalidAddress);
        }
        let alive_candidates: Vec<&OutId> = entry
            .spec
            .candidates
            .iter()
            .filter(|id| proxies.get(*id).is_none_or(|p| p.alive))
            .collect();

        match entry.spec.kind {
            ProxyGroupKind::Select => {
                if let Some(sel) = &entry.selected
                    && entry.spec.candidates.contains(sel)
                {
                    return Ok(sel.clone());
                }
                Ok(entry.spec.candidates[0].clone())
            }
            ProxyGroupKind::Fallback => {
                if let Some(first_alive) = alive_candidates.first() {
                    return Ok((*first_alive).clone());
                }
                if let Some(fb) = &entry.spec.fallback_outbound {
                    return Ok(fb.clone());
                }
                Ok(entry.spec.candidates[0].clone())
            }
            ProxyGroupKind::UrlTest => {
                let pool = if alive_candidates.is_empty() {
                    entry.spec.candidates.iter().collect::<Vec<_>>()
                } else {
                    alive_candidates
                };
                let mut best: Option<(&OutId, u32)> = None;
                for cand in &pool {
                    let delay = proxies.get(*cand).and_then(last_delay).unwrap_or(u32::MAX);
                    match best {
                        None => best = Some((*cand, delay)),
                        Some((_, best_delay)) if delay < best_delay => {
                            best = Some((*cand, delay));
                        }
                        _ => {}
                    }
                }
                if let Some((best_id, best_delay)) = best {
                    if let Some(curr) = &entry.selected
                        && pool.contains(&curr)
                        && let Some(curr_delay) = proxies.get(curr).and_then(last_delay)
                        && curr_delay <= best_delay.saturating_add(entry.spec.tolerance_ms)
                    {
                        return Ok(curr.clone());
                    }
                    return Ok(best_id.clone());
                }
                Ok(entry.spec.candidates[0].clone())
            }
            ProxyGroupKind::LoadBalance | ProxyGroupKind::Balancer => {
                if alive_candidates.is_empty() {
                    if let Some(fb) = &entry.spec.fallback_outbound {
                        return Ok(fb.clone());
                    }
                    if entry.spec.empty_fallback {
                        return OutId::parse("direct");
                    }
                }
                let pool = if alive_candidates.is_empty() {
                    entry.spec.candidates.iter().collect::<Vec<_>>()
                } else {
                    alive_candidates
                };
                match entry.spec.strategy {
                    LoadBalanceStrategy::RoundRobin | LoadBalanceStrategy::Random => {
                        let idx = entry.rr_counter.fetch_add(1, Ordering::Relaxed) % pool.len();
                        Ok(pool[idx].clone())
                    }
                    LoadBalanceStrategy::LeastPing | LoadBalanceStrategy::LeastLoad => {
                        let best = pool
                            .iter()
                            .min_by_key(|cand| {
                                proxies.get(**cand).and_then(last_delay).unwrap_or(1000)
                            })
                            .copied()
                            .unwrap_or(pool[0]);
                        Ok(best.clone())
                    }
                    LoadBalanceStrategy::ConsistentHashing
                    | LoadBalanceStrategy::StickySessions => {
                        let mut hasher = DefaultHasher::new();
                        if entry.spec.hash_key.is_empty() {
                            if let Some(orig) = original {
                                orig.target().to_string().hash(&mut hasher);
                            }
                            if entry.spec.strategy == LoadBalanceStrategy::StickySessions
                                && let Some(sa) = source_addr
                            {
                                sa.ip().hash(&mut hasher);
                            }
                        } else {
                            for key in &entry.spec.hash_key {
                                match key.trim().to_ascii_lowercase().as_str() {
                                    "dst-ip" | "dst_ip" | "dst-addr" => {
                                        if let Some(orig) = original {
                                            orig.target().address().hash(&mut hasher);
                                        }
                                    }
                                    "dst-port" | "dst_port" => {
                                        if let Some(orig) = original {
                                            orig.target().port().hash(&mut hasher);
                                        }
                                    }
                                    "src-ip" | "src_ip" | "src-addr" => {
                                        if let Some(sa) = source_addr {
                                            sa.ip().hash(&mut hasher);
                                        }
                                    }
                                    "src-port" | "src_port" => {
                                        if let Some(sa) = source_addr {
                                            sa.port().hash(&mut hasher);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        let idx = (hasher.finish() as usize) % pool.len();
                        Ok(pool[idx].clone())
                    }
                }
            }
        }
    }

    pub fn record_delay(&self, id: &OutId, delay_ms: Option<u32>, error_reason: Option<String>) {
        let now = now_ms();
        let iso = now_iso_string();
        let mut proxies = self.0.proxies.write().unwrap_or_else(|e| e.into_inner());
        if let Some(info) = proxies.get_mut(id) {
            info.last_try_ms = now;
            match delay_ms {
                Some(ms) => {
                    info.alive = true;
                    info.fail_count = 0;
                    info.last_error = None;
                    info.last_seen_ms = now;
                    if info.history.len() >= MAX_DELAY_HISTORY {
                        info.history.pop_front();
                    }
                    info.history.push_back(DelaySample {
                        time: iso,
                        delay: ms,
                    });
                }
                None => {
                    info.alive = false;
                    info.fail_count = info.fail_count.saturating_add(1);
                    info.last_error = error_reason;
                    if info.history.len() >= MAX_DELAY_HISTORY {
                        info.history.pop_front();
                    }
                    info.history.push_back(DelaySample {
                        time: iso,
                        delay: 0,
                    });
                }
            }
        }
    }

    pub fn select_in_group(&self, group_name: &str, target_name: &str) -> Result<()> {
        let gid = OutId::parse(group_name)?;
        let tid = OutId::parse(target_name)?;
        let interrupt = {
            let mut groups = self.0.groups.write().unwrap_or_else(|e| e.into_inner());
            let entry = groups
                .get_mut(&gid)
                .ok_or_else(|| Error::Config(format!("策略组 {group_name} 不存在")))?;
            if !entry.spec.candidates.contains(&tid) {
                return Err(Error::Config(format!(
                    "节点 {target_name} 不在策略组 {group_name} 候选列表中"
                )));
            }
            entry.selected = Some(tid.clone());
            entry.fixed = Some(tid);
            entry.spec.interrupt_exist_connections
        };
        self.persist_selections();
        if interrupt {
            self.close_group_connections(&gid);
        }
        Ok(())
    }

    pub fn clear_group_fixed(&self, group_name: &str) -> Result<()> {
        let gid = OutId::parse(group_name)?;
        {
            let mut groups = self.0.groups.write().unwrap_or_else(|e| e.into_inner());
            let entry = groups
                .get_mut(&gid)
                .ok_or_else(|| Error::Config(format!("策略组 {group_name} 不存在")))?;
            if entry.spec.kind != ProxyGroupKind::Select {
                entry.fixed = None;
            }
        }
        self.persist_selections();
        Ok(())
    }

    fn persist_selections(&self) {
        let Some(path) = &self.0.store_selected_path else {
            return;
        };
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        let mut map = BTreeMap::new();
        for (id, entry) in groups.iter() {
            if let Some(sel) = entry.fixed.as_ref().or(entry.selected.as_ref()) {
                map.insert(id.to_string(), sel.to_string());
            }
        }
        let _ = kerlico_dns::cache_file::store(path, kerlico_dns::cache_file::SELECTED, &map);
    }

    pub fn register_active_connection(&self, conn: ActiveConnection) {
        self.0
            .active_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(conn.id, conn);
    }

    pub fn unregister_active_connection(&self, id: u64) {
        self.0
            .active_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    pub fn close_all_connections(&self) -> usize {
        let mut conns = self
            .0
            .active_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let count = conns.len();
        for conn in conns.values() {
            conn.cancel.cancel();
        }
        conns.clear();
        count
    }

    pub fn close_connection(&self, id: u64) -> bool {
        let mut conns = self
            .0
            .active_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(conn) = conns.remove(&id) {
            conn.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub fn close_group_connections(&self, group_id: &OutId) -> usize {
        let mut conns = self
            .0
            .active_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut closed = 0;
        conns.retain(|_, conn| {
            if conn.group.as_ref() == Some(group_id) || &conn.outbound == group_id {
                conn.cancel.cancel();
                closed += 1;
                false
            } else {
                true
            }
        });
        closed
    }

    pub fn active_connections_json(&self) -> Value {
        let conns = self
            .0
            .active_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let list: Vec<Value> = conns
            .values()
            .map(|c| {
                json!({
                    "id": c.id.to_string(),
                    "chains": [c.outbound.to_string()],
                    "rule": "",
                    "start": c.started_ms,
                    "metadata": {
                        "network": c.network,
                        "destination": c.target,
                    }
                })
            })
            .collect();
        json!({
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": list,
        })
    }

    pub fn proxies_json(&self) -> Value {
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        let proxies = self.0.proxies.read().unwrap_or_else(|e| e.into_inner());
        let mut map = serde_json::Map::new();
        for (id, info) in proxies.iter() {
            if let Some(g) = groups.get(id) {
                let now = g
                    .fixed
                    .as_ref()
                    .or(g.selected.as_ref())
                    .or_else(|| g.spec.candidates.first())
                    .map(|o| o.to_string())
                    .unwrap_or_else(|| "direct".into());
                let all: Vec<String> = g.spec.candidates.iter().map(|o| o.to_string()).collect();
                map.insert(
                    id.to_string(),
                    json!({
                        "name": id.to_string(),
                        "type": g.spec.kind.as_str(),
                        "udp": !g.spec.disable_udp,
                        "alive": info.alive,
                        "history": info.history,
                        "now": now,
                        "all": all,
                        "testUrl": g.spec.url,
                        "hidden": g.spec.hidden,
                        "icon": g.spec.icon.clone().unwrap_or_default(),
                        "emptyFallback": g.spec.empty_fallback,
                        "expectedStatus": g.spec.expected_status,
                        "fixed": g.fixed.as_ref().map(|o| o.to_string()).unwrap_or_default(),
                    }),
                );
            } else {
                map.insert(
                    id.to_string(),
                    json!({
                        "name": info.name,
                        "type": info.kind,
                        "udp": info.udp,
                        "uot": true,
                        "xudp": true,
                        "tfo": false,
                        "mptcp": false,
                        "smux": false,
                        "alive": info.alive,
                        "history": info.history,
                        "extra": {},
                        "interface": "",
                        "routing-mark": 0,
                        "provider-name": "",
                        "dialer-proxy": "",
                    }),
                );
            }
        }
        json!({ "proxies": map })
    }

    pub fn proxy_by_name_json(&self, name: &str) -> Option<Value> {
        let all = self.proxies_json();
        all.get("proxies")?.get(name).cloned()
    }

    pub fn groups_json(&self) -> Value {
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        let proxies = self.0.proxies.read().unwrap_or_else(|e| e.into_inner());
        let mut list = Vec::with_capacity(groups.len());
        for (id, g) in groups.iter() {
            let now = g
                .fixed
                .as_ref()
                .or(g.selected.as_ref())
                .or_else(|| g.spec.candidates.first())
                .map(|o| o.to_string())
                .unwrap_or_else(|| "direct".into());
            let all: Vec<String> = g.spec.candidates.iter().map(|o| o.to_string()).collect();
            let history = proxies
                .get(id)
                .map(|p| p.history.clone())
                .unwrap_or_default();
            list.push(json!({
                "name": id.to_string(),
                "type": g.spec.kind.as_str(),
                "udp": !g.spec.disable_udp,
                "now": now,
                "all": all,
                "history": history,
                "testUrl": g.spec.url,
                "hidden": g.spec.hidden,
                "icon": g.spec.icon.clone().unwrap_or_default(),
                "emptyFallback": g.spec.empty_fallback,
                "expectedStatus": g.spec.expected_status,
                "fixed": g.fixed.as_ref().map(|o| o.to_string()).unwrap_or_default(),
            }));
        }
        json!({ "proxies": list })
    }

    pub fn group_by_name_json(&self, name: &str) -> Option<Value> {
        let id = OutId::parse(name).ok()?;
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        if !groups.contains_key(&id) {
            return None;
        }
        drop(groups);
        self.proxy_by_name_json(name)
    }

    pub(crate) fn has_proxy(&self, id: &OutId) -> bool {
        self.0
            .proxies
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(id)
    }

    pub fn group_candidates(&self, id: &OutId) -> Option<Vec<OutId>> {
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        groups.get(id).map(|g| g.spec.candidates.clone())
    }

    /// 策略组配置的测试 URL、超时毫秒与 `expected-status`。
    pub fn group_test_defaults(&self, id: &OutId) -> Option<(String, u64, String)> {
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        groups.get(id).map(|g| {
            (
                g.spec.url.clone(),
                g.spec.timeout_ms,
                g.spec.expected_status.clone(),
            )
        })
    }

    /// 提供者成员及其健康检查 URL、超时毫秒与 `expected-status`。
    pub fn provider_health_check(&self, name: &str) -> Option<(Vec<OutId>, String, u64, String)> {
        let providers = self.0.providers.read().unwrap_or_else(|e| e.into_inner());
        providers.get(name).map(|p| {
            (
                p.proxies.clone(),
                p.health_check_url.clone(),
                p.health_check_timeout_ms,
                p.health_check_expected_status.clone(),
            )
        })
    }

    /// 归属策略组，或包含任一成员的策略组，在 `window_ms` 内被路由使用过。
    pub(crate) fn touched_within(
        &self,
        owner: &HealthOwner,
        members: &[OutId],
        window_ms: u64,
    ) -> bool {
        let since = now_ms().saturating_sub(window_ms);
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        let recent = |g: &GroupRuntimeEntry| g.last_touch_ms.load(Ordering::Relaxed) >= since;
        match owner {
            HealthOwner::Group(id) => groups.get(id).is_some_and(recent),
            HealthOwner::Provider => groups
                .values()
                .any(|g| recent(g) && g.spec.candidates.iter().any(|c| members.contains(c))),
        }
    }

    pub fn proxy_providers_json(&self) -> Value {
        let providers = self.0.providers.read().unwrap_or_else(|e| e.into_inner());
        let proxies_map = self.proxies_json();
        let mut out = serde_json::Map::new();
        for (name, prov) in providers.iter() {
            let mut list = Vec::new();
            for pid in &prov.proxies {
                if let Some(p) = proxies_map.get("proxies").and_then(|m| m.get(pid.as_str())) {
                    list.push(p.clone());
                }
            }
            out.insert(
                name.clone(),
                json!({
                    "name": prov.name,
                    "type": "Proxy",
                    "vehicleType": prov.kind.to_ascii_uppercase(),
                    "proxies": list,
                    "updatedAt": now_iso_string(),
                }),
            );
        }
        json!({ "providers": out })
    }

    pub fn proxy_provider_by_name_json(&self, name: &str) -> Option<Value> {
        self.proxy_providers_json()
            .get("providers")?
            .get(name)
            .cloned()
    }

    pub fn proxy_provider_member_json(
        &self,
        provider_name: &str,
        proxy_name: &str,
    ) -> Option<Value> {
        let providers = self.0.providers.read().unwrap_or_else(|e| e.into_inner());
        let prov = providers.get(provider_name)?;
        let pid = OutId::parse(proxy_name).ok()?;
        if !prov.proxies.contains(&pid) {
            return None;
        }
        drop(providers);
        self.proxy_by_name_json(proxy_name)
    }

    pub fn rule_providers_json(&self) -> Value {
        let rp = self
            .0
            .rule_providers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut out = serde_json::Map::new();
        for (name, count) in rp.iter() {
            out.insert(
                name.clone(),
                json!({
                    "name": name,
                    "type": "Rule",
                    "vehicleType": "File",
                    "behavior": "classical",
                    "format": "YamlRule",
                    "ruleCount": *count,
                    "updatedAt": now_iso_string(),
                }),
            );
        }
        json!({ "providers": out })
    }

    pub fn rule_provider_by_name_json(&self, name: &str) -> Option<Value> {
        self.rule_providers_json()
            .get("providers")?
            .get(name)
            .cloned()
    }

    pub fn rules_json(&self) -> Value {
        let routes = self.0.routes.read().unwrap_or_else(|e| e.into_inner());
        let mut list = Vec::new();
        for (idx, out_id) in routes.outbounds().enumerate() {
            list.push(json!({
                "index": idx,
                "type": "Rule",
                "payload": format!("rule-{idx}"),
                "proxy": out_id.to_string(),
                "size": 1,
                "extra": {},
            }));
        }
        json!({ "rules": list })
    }

    pub fn test_route(
        &self,
        host: &str,
        port: u16,
        network: &str,
        inbound_tag: &str,
    ) -> Result<Value> {
        let target = Destination::new(host, port)?;
        let net = if network.eq_ignore_ascii_case("udp") {
            Network::Udp
        } else {
            Network::Tcp
        };
        let node = kerlico_core::NodeId::parse(if inbound_tag.is_empty() {
            "test-in"
        } else {
            inbound_tag
        })?;
        let source = Source::Local { node };
        let routes = self.0.routes.read().unwrap_or_else(|e| e.into_inner());
        let ctx = RouteContext {
            target: &target,
            resolved_ips: &[],
            network: net,
            source: &source,
            source_addr: None,
            protocol: None,
            sniffed_domain: None,
            process_name: None,
            process_path: None,
        };
        let dec = routes.evaluate(&ctx);
        drop(routes);
        let resolved_out = match dec.outbound {
            Some(ref o) => self.resolve_untouched(o).ok().or_else(|| Some(o.clone())),
            None => None,
        };
        Ok(json!({
            "outbound": resolved_out.map(|o| o.to_string()),
            "rawOutbound": dec.outbound.map(|o| o.to_string()),
            "balancerTag": dec.balancer_tag,
            "reject": dec.reject,
            "hijackDns": dec.hijack_dns,
        }))
    }

    pub fn observatory_status_json(&self) -> Value {
        let proxies = self.0.proxies.read().unwrap_or_else(|e| e.into_inner());
        let list: Vec<Value> = proxies
            .values()
            .map(|p| {
                let delay = p.history.back().map(|s| s.delay).unwrap_or(0);
                json!({
                    "outbound_tag": p.name,
                    "alive": p.alive,
                    "delay": delay,
                    "last_error_reason": p.last_error.clone().unwrap_or_default(),
                    "last_try_time": p.last_try_ms / 1000,
                    "last_seen_time": p.last_seen_ms / 1000,
                })
            })
            .collect();
        json!({ "status": { "status": list } })
    }

    pub fn balancers_info_json(&self) -> Value {
        let groups = self.0.groups.read().unwrap_or_else(|e| e.into_inner());
        let mut map = serde_json::Map::new();
        for (id, g) in groups.iter() {
            let override_target = g.fixed.as_ref().map(|o| o.to_string()).unwrap_or_default();
            let principle: Vec<String> = g.spec.candidates.iter().map(|o| o.to_string()).collect();
            map.insert(
                id.to_string(),
                json!({
                    "tag": id.to_string(),
                    "override": override_target,
                    "override_target": override_target,
                    "principleTargets": { "targets": principle },
                }),
            );
        }
        json!({ "balancers": map })
    }

    pub fn flush_fake_ip(&self) -> Result<()> {
        self.0.resolver.flush_fake_ip()
    }

    pub fn push_log(&self, level: &str, payload: impl Into<String>) {
        let mut logs = self.0.logs.lock().unwrap_or_else(|e| e.into_inner());
        if logs.len() >= MAX_LOG_ENTRIES {
            logs.pop_front();
        }
        logs.push_back(StructuredLogEntry {
            time: now_iso_string(),
            level: level.to_owned(),
            payload: payload.into(),
        });
    }

    pub fn logs_json(&self, level_filter: Option<&str>) -> Value {
        let logs = self.0.logs.lock().unwrap_or_else(|e| e.into_inner());
        let filtered: Vec<StructuredLogEntry> = logs
            .iter()
            .filter(|e| {
                level_filter
                    .filter(|f| !f.is_empty())
                    .is_none_or(|f| e.level.eq_ignore_ascii_case(f))
            })
            .cloned()
            .collect();
        json!({ "logs": filtered })
    }

    pub fn record_config_reload(&self, log_level: Option<String>) {
        self.0.config_reloads.fetch_add(1, Ordering::Relaxed);
        if let Some(lvl) = log_level {
            let mut spec = self.0.log_spec.write().unwrap_or_else(|e| e.into_inner());
            spec.level = Some(lvl);
        }
        self.push_log("info", "configuration reloaded");
    }

    pub fn record_geo_update(&self) {
        self.0.geo_updates.fetch_add(1, Ordering::Relaxed);
        self.push_log("info", "geodata database updated");
    }

    pub fn handler_overview_json(&self, static_nodes: &[String]) -> Value {
        let dyn_inbounds = self
            .0
            .dynamic_inbounds
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut map = serde_json::Map::new();
        for tag in static_nodes {
            let count = dyn_inbounds.get(tag).map_or(0, BTreeMap::len);
            map.insert(tag.clone(), json!({ "tag": tag, "usersCount": count }));
        }
        for (tag, users) in dyn_inbounds.iter() {
            map.entry(tag.clone())
                .or_insert_with(|| json!({ "tag": tag, "usersCount": users.len() }));
        }
        json!({ "inbounds": map })
    }

    pub fn inbound_users_json(&self, tag: &str) -> Value {
        let dyn_inbounds = self
            .0
            .dynamic_inbounds
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let users: Vec<Value> = dyn_inbounds
            .get(tag)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        json!({ "tag": tag, "users": users, "count": users.len() })
    }

    pub fn alter_inbound_user(&self, tag: &str, action: &str, user_key: &str, payload: Value) {
        let mut dyn_inbounds = self
            .0
            .dynamic_inbounds
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let users = dyn_inbounds.entry(tag.to_owned()).or_default();
        if action.eq_ignore_ascii_case("remove") || action.eq_ignore_ascii_case("delete") {
            users.remove(user_key);
        } else {
            users.insert(user_key.to_owned(), payload);
        }
    }
}

/// 失败探测记为 0 延迟样本（Clash API 约定），选优时不当作有效延迟。
fn last_delay(info: &ProxyRuntimeInfo) -> Option<u32> {
    info.history.back().map(|s| s.delay).filter(|d| *d > 0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn now_iso_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}Z")
}
