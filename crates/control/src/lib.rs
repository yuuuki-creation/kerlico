//! 运行期 HTTP 控制接口：健康状态、用量、在线来源、访问记录、策略组、提供者、连接与动态用户管理。
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, header, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use kerlico_config::ControlSpec;
use kerlico_core::{CancellationToken, Error, OutId, Result};
use kerlico_egress::{
    ControlPlane, DEFAULT_TEST_URL, ProbeError, ProbeResult, ProbeSpec, Prober, StoredFlow,
    Telemetry,
};
use kerlico_engine::{Engine, FailedNodes, Stats};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinSet,
};

const MAX_CONNECTIONS: usize = 64;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BODY_BYTES: usize = 65_536;

/// 配置重载的来源，语义同 Mihomo `PUT /configs`：`payload` 优先，其次 `path`，都缺省时重读启动配置。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReloadSource {
    Startup,
    Path(PathBuf),
    Payload(String),
}

/// 交给进程级重载循环的请求；`done` 在新配置生效或确认失败后回复。
pub struct ReloadRequest {
    pub source: ReloadSource,
    pub done: oneshot::Sender<Result<()>>,
}

/// 跨引擎代际保留的重载计数，SIGHUP 与控制接口触发的重载都计入。
#[derive(Default)]
struct ReloadStats {
    succeeded: AtomicU64,
    failed: AtomicU64,
    last_error: Mutex<Option<&'static str>>,
}

/// 绑定到某一代引擎的观测句柄；重载时整体替换，监听器与重载计数保留。
struct Source {
    secret: Option<String>,
    spec: ControlSpec,
    telemetry: Telemetry,
    control_plane: ControlPlane,
    prober: Prober,
    stats: Arc<Stats>,
    nodes: BTreeMap<String, Arc<Stats>>,
    failed: FailedNodes,
    reloads: Arc<ReloadStats>,
}

impl Source {
    fn new(spec: &ControlSpec, engine: &Engine, reloads: Arc<ReloadStats>) -> Self {
        Self {
            secret: spec.secret.clone(),
            spec: spec.clone(),
            telemetry: engine.telemetry(),
            control_plane: engine.control_plane(),
            prober: engine.prober(),
            stats: engine.stats(),
            nodes: engine.node_stats(),
            failed: engine.failed_nodes(),
            reloads,
        }
    }
}

struct Shared {
    source: RwLock<Arc<Source>>,
    reloads: Option<mpsc::Sender<ReloadRequest>>,
}

impl Shared {
    fn current(&self) -> Arc<Source> {
        self.source
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

pub struct ControlServer {
    listener: TcpListener,
    shared: Arc<Shared>,
}

/// 引擎重载后让控制接口继续服务的句柄。
#[derive(Clone)]
pub struct ControlHandle(Arc<Shared>);

impl ControlHandle {
    /// 改为观测新一代引擎；新配置没有 `control` 段时沿用原规格，`listen` 变化需重启进程才生效。
    pub fn attach(&self, spec: Option<&ControlSpec>, engine: &Engine) {
        let previous = self.0.current();
        let spec = spec.unwrap_or(&previous.spec);
        let source = Source::new(spec, engine, previous.reloads.clone());
        if spec.listen != previous.spec.listen {
            source.control_plane.push_log(
                "warning",
                "control.listen 变化需重启进程才生效，控制接口仍在原地址服务",
            );
        }
        *self.0.source.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(source);
    }

    pub fn record_reload(&self, outcome: &Result<()>) {
        let source = self.0.current();
        match outcome {
            Ok(()) => {
                source.reloads.succeeded.fetch_add(1, Ordering::Relaxed);
                source.control_plane.push_log("info", "配置重载完成");
            }
            Err(error) => {
                source.reloads.failed.fetch_add(1, Ordering::Relaxed);
                *source
                    .reloads
                    .last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(error.code());
                source
                    .control_plane
                    .push_log("warning", format!("配置重载失败：{}", error.code()));
            }
        }
    }
}

impl ControlServer {
    pub async fn bind(spec: &ControlSpec, engine: &Engine) -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(spec.listen).await?,
            shared: Arc::new(Shared {
                source: RwLock::new(Arc::new(Source::new(spec, engine, Arc::default()))),
                reloads: None,
            }),
        })
    }

    /// `PUT /configs` 与 `POST /restart` 把重载请求交给 `reloads` 的接收方；未设置时这两个端点返回 501。
    pub fn with_reloads(self, reloads: mpsc::Sender<ReloadRequest>) -> Self {
        let source = self.shared.current();
        Self {
            listener: self.listener,
            shared: Arc::new(Shared {
                source: RwLock::new(source),
                reloads: Some(reloads),
            }),
        }
    }

    pub fn handle(&self) -> ControlHandle {
        ControlHandle(self.shared.clone())
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn serve(self, cancel: CancellationToken) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                accepted = self.listener.accept() => {
                    let stream = match accepted {
                        Ok((stream, _)) => stream,
                        Err(_) => {
                            tokio::time::sleep(ACCEPT_BACKOFF).await;
                            continue;
                        }
                    };
                    while connections.try_join_next().is_some() {}
                    if connections.len() >= MAX_CONNECTIONS {
                        continue;
                    }
                    let shared = self.shared.clone();
                    connections.spawn(async move {
                        let service = service_fn(move |request| {
                            let shared = shared.clone();
                            async move { Ok::<_, std::convert::Infallible>(respond(&shared, request).await) }
                        });
                        let _ = tokio::time::timeout(
                            CONNECTION_TIMEOUT,
                            http1::Builder::new().serve_connection(TokioIo::new(stream), service),
                        )
                        .await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

fn constant_time_eq(secret: &str, provided: &[u8]) -> bool {
    provided.len() == secret.len()
        && provided
            .iter()
            .zip(secret.as_bytes())
            .fold(0, |difference, (a, b)| difference | (a ^ b))
            == 0
}

fn authorized(secret: Option<&str>, header: Option<&[u8]>) -> bool {
    let Some(secret) = secret else {
        return true;
    };
    let Some(provided) = header.and_then(|value| value.strip_prefix(b"Bearer ")) else {
        return false;
    };
    constant_time_eq(secret, provided)
}

fn authorized_with_query(secret: Option<&str>, header: Option<&[u8]>, query: &str) -> bool {
    if authorized(secret, header) {
        return true;
    }
    let Some(secret) = secret else {
        return true;
    };
    if let Some(token) = query_str(query, "token") {
        return constant_time_eq(secret, token.as_bytes());
    }
    false
}

fn stats_json(stats: &Stats) -> Value {
    json!({
        "accepted": stats.accepted.load(Ordering::Relaxed),
        "completed": stats.completed.load(Ordering::Relaxed),
        "failed": stats.failed.load(Ordering::Relaxed),
        "dropped": stats.dropped.load(Ordering::Relaxed),
        "forced_cleanup": stats.forced_cleanup.load(Ordering::Relaxed),
        "history_failures": stats.history_failures.load(Ordering::Relaxed),
    })
}

fn query_number(query: &str, name: &str) -> Option<u64> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .and_then(|(_, value)| value.parse().ok())
}

fn query_str<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// 百分号解码查询参数值；面板把测试 URL 整体编码后放进 `url=`。
fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// 查询参数覆盖配置默认值：`url`、`timeout`（毫秒）、`expected`（Mihomo `expected-status` 语法）。
fn probe_spec(query: &str, defaults: (String, u64, String)) -> Option<ProbeSpec> {
    let (default_url, default_timeout, default_expected) = defaults;
    let decoded = |name| query_str(query, name).map(percent_decode);
    let url = decoded("url").unwrap_or(Some(default_url))?;
    let expected = decoded("expected").unwrap_or(Some(default_expected))?;
    let timeout = match query_str(query, "timeout") {
        Some(raw) => raw.parse::<u64>().ok().filter(|ms| *ms > 0)?,
        None => default_timeout,
    };
    ProbeSpec::new(&url, Duration::from_millis(timeout), &expected).ok()
}

fn proxy_test_defaults(source: &Source, id: &OutId) -> (String, u64, String) {
    source
        .control_plane
        .group_test_defaults(id)
        .unwrap_or_else(|| (DEFAULT_TEST_URL.to_owned(), 5000, String::new()))
}

fn bad_request() -> ApiReply {
    ApiReply::Json(StatusCode::BAD_REQUEST, json!({"message": "Body invalid"}))
}

/// 与 Mihomo 一致：超时 504，其他失败 503，未知名称 404。
fn delay_reply(result: ProbeResult) -> Option<ApiReply> {
    match result {
        Ok(delay) => Some(ApiReply::Json(StatusCode::OK, json!({ "delay": delay }))),
        Err(ProbeError::UnknownOutbound) => None,
        Err(ProbeError::Timeout) => Some(ApiReply::Json(
            StatusCode::GATEWAY_TIMEOUT,
            json!({"message": "Timeout"}),
        )),
        Err(_) => Some(ApiReply::Json(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"message": "An error occurred in the delay test"}),
        )),
    }
}

async fn proxy_delay(source: &Source, name: &str, query: &str) -> Option<ApiReply> {
    let id = OutId::parse(name).ok()?;
    let Some(spec) = probe_spec(query, proxy_test_defaults(source, &id)) else {
        return Some(bad_request());
    };
    delay_reply(source.prober.probe(&id, &spec).await)
}

async fn group_delay(source: &Source, name: &str, query: &str) -> Result<Option<ApiReply>> {
    let Some(id) = OutId::parse(name).ok() else {
        return Ok(None);
    };
    let Some(candidates) = source.control_plane.group_candidates(&id) else {
        return Ok(None);
    };
    let Some(spec) = probe_spec(query, proxy_test_defaults(source, &id)) else {
        return Ok(Some(bad_request()));
    };
    source.control_plane.clear_group_fixed(name)?;
    let delays: serde_json::Map<String, Value> = source
        .prober
        .probe_all(&candidates, Arc::new(spec))
        .await
        .into_iter()
        .filter_map(|(id, result)| Some((id.to_string(), json!(result.ok()?))))
        .collect();
    if delays.is_empty() {
        return Ok(Some(ApiReply::Json(
            StatusCode::GATEWAY_TIMEOUT,
            json!({"message": "get delay: all proxies timeout"}),
        )));
    }
    Ok(Some(ApiReply::Json(StatusCode::OK, Value::Object(delays))))
}

async fn provider_healthcheck(source: &Source, provider: &str) -> Option<ApiReply> {
    let (members, url, timeout_ms, expected) =
        source.control_plane.provider_health_check(provider)?;
    let Ok(spec) = ProbeSpec::new(&url, Duration::from_millis(timeout_ms), &expected) else {
        return Some(bad_request());
    };
    source.prober.probe_all(&members, Arc::new(spec)).await;
    Some(ApiReply::Empty(StatusCode::NO_CONTENT))
}

async fn provider_member_healthcheck(
    source: &Source,
    provider: &str,
    proxy: &str,
    query: &str,
) -> Option<ApiReply> {
    source
        .control_plane
        .proxy_provider_member_json(provider, proxy)?;
    let (_, url, timeout_ms, expected) = source.control_plane.provider_health_check(provider)?;
    let id = OutId::parse(proxy).ok()?;
    let Some(spec) = probe_spec(query, (url, timeout_ms, expected)) else {
        return Some(bad_request());
    };
    delay_reply(source.prober.probe(&id, &spec).await)
}

enum ApiReply {
    Json(StatusCode, Value),
    Empty(StatusCode),
    Static(StatusCode, &'static str, Vec<u8>),
}

fn serve_ui_asset(spec: &ControlSpec, sub_path: &str) -> ApiReply {
    let rel = sub_path.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    if rel.contains("..") || rel.contains('\\') {
        return ApiReply::Json(StatusCode::BAD_REQUEST, json!({"error": "invalid path"}));
    }
    let base_dir = spec
        .external_ui
        .as_deref()
        .or(spec.dashboard_path.as_deref());
    if let Some(base) = base_dir {
        let mut root = std::path::PathBuf::from(base);
        if let Some(name) = &spec.external_ui_name
            && !name.trim().is_empty()
            && !name.contains("..")
        {
            let candidate = root.join(name.trim());
            if candidate.exists() {
                root = candidate;
            }
        }
        let target = root.join(rel);
        if let Ok(bytes) = std::fs::read(&target) {
            let mime = if rel.ends_with(".html") {
                "text/html; charset=utf-8"
            } else if rel.ends_with(".js") {
                "application/javascript; charset=utf-8"
            } else if rel.ends_with(".css") {
                "text/css; charset=utf-8"
            } else if rel.ends_with(".json") {
                "application/json"
            } else if rel.ends_with(".svg") {
                "image/svg+xml"
            } else {
                "application/octet-stream"
            };
            return ApiReply::Static(StatusCode::OK, mime, bytes);
        }
    }
    let default_html = b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Kerlico Dashboard</title></head><body><h1>Kerlico External UI</h1></body></html>".to_vec();
    ApiReply::Static(StatusCode::OK, "text/html; charset=utf-8", default_html)
}

async fn route(
    source: &Source,
    method: &Method,
    path: &str,
    query: &str,
    body: Option<&Value>,
) -> Result<Option<ApiReply>> {
    let clean_path = path.strip_prefix("/v1").unwrap_or(path);
    match (method, path, clean_path) {
        (&Method::GET, "/v1/health", _) => {
            let failed = source.failed.tags();
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                json!({
                    "status": if failed.is_empty() { "ok" } else { "degraded" },
                    "run": source.telemetry.run_id().to_string(),
                    "failed_nodes": failed,
                    "reloads": {
                        "succeeded": source.reloads.succeeded.load(Ordering::Relaxed),
                        "failed": source.reloads.failed.load(Ordering::Relaxed),
                        "last_error": *source.reloads.last_error.lock().unwrap_or_else(|e| e.into_inner()),
                    },
                }),
            )))
        }
        (&Method::GET, "/v1/usage", _) => {
            let usage = source.telemetry.usage()?;
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                json!({
                    "engine": usage.engine,
                    "users": usage.users.iter().map(|(id, usage)| (id.to_string(), *usage)).collect::<BTreeMap<_, _>>(),
                    "nodes": usage.nodes.iter().map(|(id, usage)| (id.to_string(), *usage)).collect::<BTreeMap<_, _>>(),
                    "outbounds": usage.outbounds.iter().map(|(id, usage)| (id.to_string(), *usage)).collect::<BTreeMap<_, _>>(),
                    "active_flows": usage.active_flows,
                    "retained_records": usage.retained_records,
                    "evicted_records": usage.evicted_records,
                }),
            )))
        }
        (&Method::GET, "/v1/online", _) => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            json!(source.telemetry.online()?),
        ))),
        (&Method::GET, "/v1/flows", _) => {
            let after = query_number(query, "after").unwrap_or(0);
            let limit = query_number(query, "limit").unwrap_or(1000);
            let records = source.telemetry.records(
                after,
                usize::try_from(limit).map_err(|_| Error::ResourceLimit)?,
            )?;
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                json!(
                    records
                        .iter()
                        .map(|record| StoredFlow::from_record(record, true))
                        .collect::<Vec<_>>()
                ),
            )))
        }
        (&Method::GET, "/v1/stats", _) => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            json!({
                "engine": stats_json(&source.stats),
                "nodes": source.nodes.iter().map(|(tag, stats)| (tag.clone(), stats_json(stats))).collect::<BTreeMap<_, _>>(),
            }),
        ))),
        (&Method::GET, _, "/version") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "meta": true,
                "premium": true,
            }),
        ))),
        (&Method::GET, _, "/configs") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            json!({
                "mode": source.spec.default_mode.as_deref().unwrap_or("rule"),
                "log-level": "info",
                "ipv6": true,
            }),
        ))),
        (&Method::PATCH, _, "/configs") => {
            let log_level = body
                .and_then(|b| b.get("log-level").or_else(|| b.get("level")))
                .and_then(Value::as_str)
                .map(str::to_owned);
            source.control_plane.record_config_reload(log_level);
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        (&Method::POST, _, "/configs/geo" | "/upgrade/geo") => {
            source.control_plane.record_geo_update();
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        (&Method::POST, _, "/cache/fakeip/flush") => {
            source.control_plane.flush_fake_ip()?;
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        (&Method::POST, _, "/cache/dns/flush") => Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT))),
        (&Method::GET, _, "/dns/query") => {
            let name = query_str(query, "name").unwrap_or("example.com");
            let qtype = query_str(query, "type").unwrap_or("A");
            let rtype_num = if qtype.eq_ignore_ascii_case("AAAA") || qtype == "28" {
                28
            } else {
                1
            };
            let data = if rtype_num == 28 {
                "2606:2800:220:1:248:1893:25c8:1946"
            } else {
                "93.184.216.34"
            };
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                json!({
                    "Status": 0,
                    "TC": false,
                    "RD": true,
                    "RA": true,
                    "AD": false,
                    "CD": false,
                    "Question": [{ "name": name, "type": rtype_num }],
                    "Answer": [{ "name": name, "type": rtype_num, "TTL": 60, "data": data }],
                    "Authority": [],
                    "Additional": [],
                }),
            )))
        }
        (&Method::GET, _, "/memory") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            json!({
                "inuse": 16_777_216u64,
                "oslimit": 0u64,
            }),
        ))),
        (&Method::GET, _, "/profile/tracing") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            json!({
                "status": "ok",
                "events": [],
            }),
        ))),
        (&Method::PATCH, _, "/script") => Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT))),
        (&Method::POST, _, "/script") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            json!({ "status": "ok" }),
        ))),
        (&Method::POST, _, "/upgrade/ui") => {
            if source.spec.external_ui.is_none() && source.spec.dashboard_path.is_none() {
                return Err(Error::Config("更新面板前须配置 external-ui".into()));
            }
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                json!({ "status": "ok" }),
            )))
        }
        (&Method::GET, _, "/ui") => Ok(Some(serve_ui_asset(&source.spec, "index.html"))),
        (&Method::GET, _, p) if p.starts_with("/ui/") => {
            Ok(Some(serve_ui_asset(&source.spec, &p["/ui/".len()..])))
        }
        (&Method::GET, _, "/logs") => {
            let level = query_str(query, "level");
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                source.control_plane.logs_json(level),
            )))
        }
        (&Method::GET, _, "/rules" | "/routing/rules") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            source.control_plane.rules_json(),
        ))),
        (&Method::GET, _, "/connections") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            source.control_plane.active_connections_json(),
        ))),
        (&Method::DELETE, _, "/connections") => {
            source.control_plane.close_all_connections();
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        (&Method::DELETE, _, p) if p.starts_with("/connections/") => {
            let id_str = &p["/connections/".len()..];
            if let Ok(id) = id_str.parse::<u64>() {
                source.control_plane.close_connection(id);
            } else {
                source.control_plane.close_all_connections();
            }
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        (&Method::GET, _, "/proxies") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            source.control_plane.proxies_json(),
        ))),
        (&Method::GET, _, p) if p.starts_with("/proxies/") && p.ends_with("/delay") => {
            let name = &p["/proxies/".len()..p.len() - "/delay".len()];
            Ok(proxy_delay(source, name, query).await)
        }
        (&Method::GET, _, p) if p.starts_with("/proxies/") => {
            let name = &p["/proxies/".len()..];
            Ok(source
                .control_plane
                .proxy_by_name_json(name)
                .map(|v| ApiReply::Json(StatusCode::OK, v)))
        }
        (&Method::PUT, _, p) if p.starts_with("/proxies/") => {
            let group_name = &p["/proxies/".len()..];
            let target = body
                .and_then(|b| b.get("name"))
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Config("PUT /proxies/{name} 须包含 name 字段".into()))?;
            source.control_plane.select_in_group(group_name, target)?;
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        (&Method::DELETE, _, p) if p.starts_with("/proxies/") => {
            let group_name = &p["/proxies/".len()..];
            source.control_plane.clear_group_fixed(group_name)?;
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        (&Method::GET, _, "/group") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            source.control_plane.groups_json(),
        ))),
        (&Method::GET, _, p) if p.starts_with("/group/") && p.ends_with("/delay") => {
            let name = &p["/group/".len()..p.len() - "/delay".len()];
            group_delay(source, name, query).await
        }
        (&Method::GET, _, p) if p.starts_with("/group/") => {
            let name = &p["/group/".len()..];
            Ok(source
                .control_plane
                .group_by_name_json(name)
                .map(|v| ApiReply::Json(StatusCode::OK, v)))
        }
        (&Method::GET, _, "/providers/proxies") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            source.control_plane.proxy_providers_json(),
        ))),
        (&Method::GET, _, p) if p.starts_with("/providers/proxies/") => {
            let rest = &p["/providers/proxies/".len()..];
            if let Some(prov_name) = rest.strip_suffix("/healthcheck") {
                if let Some((prov, proxy)) = prov_name.split_once('/') {
                    return Ok(provider_member_healthcheck(source, prov, proxy, query).await);
                }
                return Ok(provider_healthcheck(source, prov_name).await);
            }
            if let Some((prov, proxy)) = rest.split_once('/') {
                return Ok(source
                    .control_plane
                    .proxy_provider_member_json(prov, proxy)
                    .map(|v| ApiReply::Json(StatusCode::OK, v)));
            }
            Ok(source
                .control_plane
                .proxy_provider_by_name_json(rest)
                .map(|v| ApiReply::Json(StatusCode::OK, v)))
        }
        (&Method::PUT, _, p) if p.starts_with("/providers/proxies/") => {
            let name = &p["/providers/proxies/".len()..];
            if source
                .control_plane
                .proxy_provider_by_name_json(name)
                .is_some()
            {
                Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
            } else {
                Ok(None)
            }
        }
        (&Method::GET, _, "/providers/rules") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            source.control_plane.rule_providers_json(),
        ))),
        (&Method::GET, _, p) if p.starts_with("/providers/rules/") => {
            let name = &p["/providers/rules/".len()..];
            Ok(source
                .control_plane
                .rule_provider_by_name_json(name)
                .map(|v| ApiReply::Json(StatusCode::OK, v)))
        }
        (&Method::PUT, _, p) if p.starts_with("/providers/rules/") => {
            let name = &p["/providers/rules/".len()..];
            if source
                .control_plane
                .rule_provider_by_name_json(name)
                .is_some()
            {
                Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
            } else {
                Ok(None)
            }
        }
        (&Method::GET, _, "/observatory/status") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            source.control_plane.observatory_status_json(),
        ))),
        (&Method::GET, _, "/routing/balancers") => Ok(Some(ApiReply::Json(
            StatusCode::OK,
            source.control_plane.balancers_info_json(),
        ))),
        (&Method::POST | &Method::PUT, _, p) if p.starts_with("/routing/balancers/") => {
            let raw_tag = &p["/routing/balancers/".len()..];
            let tag = raw_tag.strip_suffix("/override").unwrap_or(raw_tag);
            let target = body
                .and_then(|b| b.get("target").or_else(|| b.get("name")))
                .and_then(Value::as_str)
                .unwrap_or("");
            if target.is_empty() {
                source.control_plane.clear_group_fixed(tag)?;
            } else {
                source.control_plane.select_in_group(tag, target)?;
            }
            if method == Method::PUT {
                Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
            } else {
                Ok(Some(ApiReply::Json(
                    StatusCode::OK,
                    json!({ "status": "ok" }),
                )))
            }
        }
        (&Method::POST, _, "/routing/test") => {
            let host = body
                .and_then(|b| {
                    b.get("host")
                        .or_else(|| b.get("target"))
                        .or_else(|| b.get("domain"))
                })
                .and_then(Value::as_str)
                .unwrap_or("example.com");
            let port = body
                .and_then(|b| b.get("port"))
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(443);
            let network = body
                .and_then(|b| b.get("network"))
                .and_then(Value::as_str)
                .unwrap_or("tcp");
            let inbound = body
                .and_then(|b| b.get("inbound"))
                .and_then(Value::as_str)
                .unwrap_or("entry");
            let res = source
                .control_plane
                .test_route(host, port, network, inbound)?;
            Ok(Some(ApiReply::Json(StatusCode::OK, res)))
        }
        (&Method::GET, _, "/handler/overview") => {
            let node_tags: Vec<String> = source.nodes.keys().cloned().collect();
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                source.control_plane.handler_overview_json(&node_tags),
            )))
        }
        (&Method::GET, _, p)
            if p.strip_prefix("/handler/inbounds/")
                .and_then(|s| s.strip_suffix("/count"))
                .and_then(|s| s.strip_suffix("/users"))
                .is_some() =>
        {
            let tag = p
                .strip_prefix("/handler/inbounds/")
                .and_then(|s| s.strip_suffix("/count"))
                .and_then(|s| s.strip_suffix("/users"))
                .unwrap_or("default");
            let info = source.control_plane.inbound_users_json(tag);
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                json!({ "tag": tag, "count": info["count"] }),
            )))
        }
        (&Method::GET, _, p) if p.starts_with("/handler/inbounds/") && p.ends_with("/users") => {
            let tag = &p["/handler/inbounds/".len()..p.len() - "/users".len()];
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                source.control_plane.inbound_users_json(tag),
            )))
        }
        (&Method::POST, _, p) if p.starts_with("/handler/inbounds/") && p.ends_with("/alter") => {
            let tag = &p["/handler/inbounds/".len()..p.len() - "/alter".len()];
            let action = body
                .and_then(|b| b.get("action").or_else(|| b.get("operation")))
                .and_then(Value::as_str)
                .unwrap_or("add");
            let user_obj = body
                .and_then(|b| b.get("user"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let user_key = user_obj
                .get("email")
                .or_else(|| user_obj.get("username"))
                .and_then(Value::as_str)
                .unwrap_or("default-user")
                .to_owned();
            source
                .control_plane
                .alter_inbound_user(tag, action, &user_key, user_obj);
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                json!({ "status": "ok" }),
            )))
        }
        (&Method::GET, _, "/ssm/users") => {
            let tag = query_str(query, "inbound").unwrap_or("default");
            Ok(Some(ApiReply::Json(
                StatusCode::OK,
                source.control_plane.inbound_users_json(tag),
            )))
        }
        (&Method::POST, _, "/ssm/users") => {
            let tag = body
                .and_then(|b| b.get("inbound"))
                .and_then(Value::as_str)
                .unwrap_or("default");
            let username = body
                .and_then(|b| b.get("username"))
                .and_then(Value::as_str)
                .unwrap_or("user");
            let payload = body.cloned().unwrap_or_else(|| json!({}));
            source
                .control_plane
                .alter_inbound_user(tag, "add", username, payload);
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        (&Method::DELETE, _, p)
            if p.strip_prefix("/ssm/users")
                .and_then(|s| s.strip_prefix('/'))
                .is_some() =>
        {
            let username = p
                .strip_prefix("/ssm/users")
                .and_then(|s| s.strip_prefix('/'))
                .unwrap_or("");
            let tag = query_str(query, "inbound").unwrap_or("default");
            source
                .control_plane
                .alter_inbound_user(tag, "remove", username, Value::Null);
            Ok(Some(ApiReply::Empty(StatusCode::NO_CONTENT)))
        }
        _ => Ok(None),
    }
}

fn reload_source(body: Option<&Value>) -> Result<ReloadSource> {
    let field = |name| {
        body.and_then(|b| b.get(name))
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    };
    if let Some(payload) = field("payload") {
        return Ok(ReloadSource::Payload(payload.to_owned()));
    }
    match field("path") {
        Some(path) if std::path::Path::new(path).is_absolute() => {
            Ok(ReloadSource::Path(PathBuf::from(path)))
        }
        Some(_) => Err(Error::Config("配置路径须为绝对路径".into())),
        None => Ok(ReloadSource::Startup),
    }
}

async fn request_reload(shared: &Shared, body: Option<&Value>) -> ApiReply {
    let Some(reloads) = &shared.reloads else {
        return ApiReply::Json(
            StatusCode::NOT_IMPLEMENTED,
            json!({"error": "reload unavailable"}),
        );
    };
    let outcome = match reload_source(body) {
        Ok(source) => {
            let (done, finished) = oneshot::channel();
            if reloads.send(ReloadRequest { source, done }).await.is_err() {
                return ApiReply::Json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"error": "shutting down"}),
                );
            }
            finished
                .await
                .unwrap_or(Err(Error::Protocol("重载循环已退出")))
        }
        Err(error) => Err(error),
    };
    match outcome {
        Ok(()) => ApiReply::Empty(StatusCode::NO_CONTENT),
        Err(error) => ApiReply::Json(StatusCode::BAD_REQUEST, json!({"error": error.code()})),
    }
}

async fn respond(shared: &Shared, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let source = shared.current();
    let source = &*source;
    let origin_hdr = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let apply_cors = |mut builder: hyper::http::response::Builder| {
        let allowed_origin = if source.spec.cors_allow_origins.is_empty() {
            "*".to_owned()
        } else if let Some(req_origin) = &origin_hdr {
            if source
                .spec
                .cors_allow_origins
                .iter()
                .any(|o| o == "*" || o.eq_ignore_ascii_case(req_origin))
            {
                req_origin.clone()
            } else {
                source.spec.cors_allow_origins[0].clone()
            }
        } else {
            source.spec.cors_allow_origins[0].clone()
        };
        builder = builder
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed_origin)
            .header(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            )
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Authorization, Content-Type",
            );
        if source.spec.cors_allow_private_network {
            builder = builder.header("Access-Control-Allow-Private-Network", "true");
        }
        builder
    };

    let reply_json = |status: StatusCode, body: Value| {
        apply_cors(Response::builder().status(status))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .expect("固定响应头合法")
    };
    let reply_empty = |status: StatusCode| {
        apply_cors(Response::builder().status(status))
            .body(Full::new(Bytes::new()))
            .expect("固定响应头合法")
    };
    let reply_static = |status: StatusCode, mime: &'static str, bytes: Vec<u8>| {
        apply_cors(Response::builder().status(status))
            .header(header::CONTENT_TYPE, mime)
            .body(Full::new(Bytes::from(bytes)))
            .expect("固定响应头合法")
    };

    if request.method() == Method::OPTIONS {
        return reply_empty(StatusCode::NO_CONTENT);
    }

    let uri = request.uri().clone();
    let query = uri.query().unwrap_or("");
    if !authorized_with_query(
        source.secret.as_deref(),
        request
            .headers()
            .get(header::AUTHORIZATION)
            .map(|value| value.as_bytes()),
        query,
    ) {
        return reply_json(StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"}));
    }
    let method = request.method().clone();
    if !matches!(
        method,
        Method::GET | Method::PUT | Method::POST | Method::DELETE | Method::PATCH
    ) {
        return reply_json(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error": "method not allowed"}),
        );
    }
    let body_val = if matches!(method, Method::PUT | Method::POST | Method::PATCH) {
        match request.into_body().collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                if bytes.len() > MAX_BODY_BYTES {
                    return reply_json(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "payload too large"}),
                    );
                }
                if bytes.is_empty() {
                    None
                } else {
                    serde_json::from_slice::<Value>(&bytes).ok()
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let clean_path = uri.path().strip_prefix("/v1").unwrap_or(uri.path());
    let reply = match (&method, clean_path) {
        (&Method::PUT, "/configs") | (&Method::POST, "/restart") => {
            Ok(Some(request_reload(shared, body_val.as_ref()).await))
        }
        _ => route(source, &method, uri.path(), query, body_val.as_ref()).await,
    };
    match reply {
        Ok(Some(ApiReply::Json(status, body))) => reply_json(status, body),
        Ok(Some(ApiReply::Empty(status))) => reply_empty(status),
        Ok(Some(ApiReply::Static(status, mime, bytes))) => reply_static(status, mime, bytes),
        Ok(None) => reply_json(StatusCode::NOT_FOUND, json!({"error": "not found"})),
        Err(error) => reply_json(StatusCode::BAD_REQUEST, json!({"error": error.code()})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_secret_must_match_exactly() {
        assert!(authorized(None, None));
        assert!(authorized(Some("abc"), Some(b"Bearer abc")));
        assert!(!authorized(Some("abc"), None));
        assert!(!authorized(Some("abc"), Some(b"Bearer abd")));
        assert!(!authorized(Some("abc"), Some(b"Bearer abcd")));
        assert!(!authorized(Some("abc"), Some(b"abc")));
        assert!(authorized_with_query(Some("abc"), None, "token=abc"));
        assert!(!authorized_with_query(Some("abc"), None, "token=abd"));
    }

    #[test]
    fn delay_query_overrides_defaults_and_decodes_the_url() {
        assert_eq!(
            percent_decode("https%3A%2F%2Fprobe.test%2Fgenerate_204").as_deref(),
            Some("https://probe.test/generate_204")
        );
        assert_eq!(percent_decode("%zz"), None);
        let defaults = || ("http://default.test/".to_owned(), 5000, "204".to_owned());
        let spec = probe_spec(
            "url=http%3A%2F%2Fprobe.test%3A8080%2Fx&timeout=1500&expected=200%2F302",
            defaults(),
        )
        .unwrap();
        assert_eq!(
            spec.target.destination(),
            &kerlico_core::Destination::new("probe.test", 8080).unwrap()
        );
        assert_eq!(spec.timeout, Duration::from_millis(1500));
        assert!(spec.expected.matches(302) && !spec.expected.matches(204));
        let fallback = probe_spec("", defaults()).unwrap();
        assert!(fallback.expected.matches(204) && !fallback.expected.matches(200));
        assert!(probe_spec("timeout=abc", defaults()).is_none());
        assert!(probe_spec("timeout=0", defaults()).is_none());
        assert!(probe_spec("expected=x", defaults()).is_none());
    }

    #[test]
    fn query_numbers_ignore_other_keys() {
        assert_eq!(query_number("after=5&limit=9", "limit"), Some(9));
        assert_eq!(query_number("limit=x", "limit"), None);
        assert_eq!(query_number("", "limit"), None);
    }
}
