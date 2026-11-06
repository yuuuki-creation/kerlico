//! 落盘资源的启动加载、周期刷新与生效：规则集与 Geo 数据原地换入路由表槽，提供者变化通知引擎重建代际。
//!
//! 下载经 `detour` 指定的命名出站（Mihomo `proxy`、sing-box `download_detour`），未指定时经
//! 直连后端；连接复用延迟探测的出站路径。缓存先写临时文件再改名替换。

use crate::{
    Dispatcher, EgressRuntime,
    fetch::{self, Validators},
    probe::ProbeTarget,
};
use kerlico_config::{Accepted, OutboundFactory, ResourceKey, ResourceKind, ResourceSpec};
use kerlico_core::{
    BoxStream, CancellationToken, ConnectContext, Error, OutId, Outbound, Result, RuntimeOptions,
    ServiceContext, TargetPolicy, log,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    hash::{DefaultHasher, Hash, Hasher},
    path::Path,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};
use tokio::{sync::watch, task::JoinSet};

const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REDIRECTS: usize = 5;

/// 一次刷新的结果：内容是否与当前生效内容不同。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refreshed {
    Changed,
    Unchanged,
}

/// 控制接口展示用的资源状态。
#[derive(Clone, Debug, Default)]
pub struct ResourceStatus {
    pub updated_at: Option<SystemTime>,
    pub error: Option<String>,
}

#[derive(Default)]
struct EntryState {
    validators: Validators,
    /// 当前生效内容的摘要；提供者据此判断是否需要重建代际。
    digest: Option<u64>,
    status: ResourceStatus,
}

struct Entry {
    spec: ResourceSpec,
    state: Mutex<EntryState>,
    /// 同一资源的刷新串行执行，后台周期刷新与控制接口触发互不交错。
    running: tokio::sync::Mutex<()>,
}

struct Hub {
    dispatcher: Weak<Dispatcher>,
    entries: BTreeMap<ResourceKey, Entry>,
    direct: tokio::sync::OnceCell<Arc<dyn Outbound>>,
    provider_changes: watch::Sender<u64>,
}

/// 控制接口与引擎使用的刷新句柄。
#[derive(Clone)]
pub struct Refresher(Arc<Hub>);

fn digest(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn read_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// 写同目录临时文件后改名替换，读者只会看到旧文件或完整的新文件。
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let name = path
        .file_name()
        .ok_or_else(|| Error::Config("资源缓存路径缺少文件名".into()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(())
}

/// 内容未变时刷新缓存时间，作为下次周期刷新的起点。
fn touch(path: &Path) -> Result<()> {
    std::fs::File::options()
        .write(true)
        .open(path)?
        .set_modified(SystemTime::now())?;
    Ok(())
}

/// 距下次刷新的等待时间：缓存修改时间加 `interval`，缓存缺失时立即刷新。
fn due_in(path: &Path, interval: Duration) -> Duration {
    modified(path)
        .and_then(|at| at.checked_add(interval))
        .and_then(|due| due.duration_since(SystemTime::now()).ok())
        .unwrap_or(Duration::ZERO)
}

impl Hub {
    async fn refresh(&self, entry: &Entry) -> Result<Refreshed> {
        let _serial = entry.running.lock().await;
        let result = self.load(entry).await;
        let mut state = entry.state.lock().unwrap_or_else(|e| e.into_inner());
        match &result {
            Ok(_) => {
                state.status.updated_at = Some(SystemTime::now());
                state.status.error = None;
            }
            Err(error) => state.status.error = Some(error.to_string()),
        }
        result
    }

    async fn load(&self, entry: &Entry) -> Result<Refreshed> {
        let spec = &entry.spec;
        let (bytes, validators) = match &spec.download {
            None => (
                read_file(&spec.path)?.ok_or_else(|| {
                    Error::Config(format!("资源文件不存在：{}", spec.path.display()))
                })?,
                None,
            ),
            Some(download) => {
                let validators = entry
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .validators
                    .clone();
                let request = fetch::Request {
                    headers: &download.headers,
                    validators: &validators,
                    size_limit: download.size_limit,
                };
                match self
                    .download(&download.url, download.detour.as_ref(), &request)
                    .await?
                {
                    None => {
                        if spec.path.exists() {
                            touch(&spec.path)?;
                        }
                        return Ok(Refreshed::Unchanged);
                    }
                    Some((bytes, validators)) => (bytes, Some(validators)),
                }
            }
        };
        let accepted = spec.accept(&bytes)?;
        let fresh = digest(&bytes);
        let changed = {
            let state = entry.state.lock().unwrap_or_else(|e| e.into_inner());
            state.digest != Some(fresh)
        };
        if spec.download.is_some() {
            if changed || !spec.path.exists() {
                write_atomic(&spec.path, &bytes)?;
            } else {
                touch(&spec.path)?;
            }
        }
        match (accepted, &spec.kind) {
            (Accepted::RuleSet(set), ResourceKind::RuleSet { source, .. }) => {
                let dispatcher = self.dispatcher.upgrade().ok_or(Error::Cancelled)?;
                if let Some(slot) = dispatcher.routes.rule_set(&source.tag) {
                    slot.replace(set);
                }
            }
            (Accepted::Geo(part), ResourceKind::Geo { slot, .. }) => slot.install(part),
            _ => {}
        }
        // 校验值只在内容被接受后保存，否则被拒内容的 304 会把坏内容当作最新。
        let mut state = entry.state.lock().unwrap_or_else(|e| e.into_inner());
        state.digest = Some(fresh);
        if let Some(validators) = validators {
            state.validators = validators;
        }
        drop(state);
        Ok(if changed {
            Refreshed::Changed
        } else {
            Refreshed::Unchanged
        })
    }

    /// 跟随最多 5 次重定向；返回 `None` 表示 304 未修改。
    async fn download(
        &self,
        url: &str,
        detour: Option<&OutId>,
        request: &fetch::Request<'_>,
    ) -> Result<Option<(Vec<u8>, Validators)>> {
        let mut url = url.to_owned();
        for _ in 0..=MAX_REDIRECTS {
            let target = ProbeTarget::parse(&url)?;
            match self.fetch_once(&target, detour, request).await? {
                fetch::Response::Body { bytes, validators } => {
                    return Ok(Some((bytes, validators)));
                }
                fetch::Response::NotModified => return Ok(None),
                fetch::Response::Redirect(location) => {
                    url = fetch::redirect_target(&url, &location)?;
                }
            }
        }
        Err(Error::Config("下载失败：重定向次数过多".into()))
    }

    async fn fetch_once(
        &self,
        target: &ProbeTarget,
        detour: Option<&OutId>,
        request: &fetch::Request<'_>,
    ) -> Result<fetch::Response> {
        let dispatcher = self.dispatcher.upgrade().ok_or(Error::Cancelled)?;
        let destination = target.destination();
        match detour {
            Some(id) => {
                let concrete = dispatcher
                    .control_plane
                    .resolve_untouched(id)
                    .map_err(|_| Error::Config(format!("下载出站不可用：{id}")))?;
                let service = dispatcher
                    .services
                    .get(&concrete)
                    .ok_or_else(|| Error::Config(format!("下载出站不可用：{id}")))?;
                if !service.capabilities.tcp {
                    return Err(Error::Unsupported("所选命名出站没有 TCP 能力"));
                }
                let context = ConnectContext::for_service(FETCH_TIMEOUT, &service.host)
                    .with_cancel(dispatcher.health.cancel());
                context
                    .run(async {
                        let stream: BoxStream = dispatcher
                            .open_tcp(
                                service.backend.as_ref(),
                                service.policy,
                                destination,
                                &context,
                            )
                            .await?;
                        fetch::get(stream, target, request).await
                    })
                    .await
            }
            None => {
                let backend = self.direct(&dispatcher).await?;
                let context = ConnectContext::for_service(FETCH_TIMEOUT, &dispatcher.health)
                    .with_cancel(dispatcher.health.cancel());
                context
                    .run(async {
                        let stream = dispatcher
                            .open_tcp(backend.as_ref(), TargetPolicy::Local, destination, &context)
                            .await?;
                        fetch::get(stream, target, request).await
                    })
                    .await
            }
        }
    }

    /// 未指定下载出站时使用的直连后端，与命名 `direct` 出站同一实现，共用引擎的设备租约。
    async fn direct(&self, dispatcher: &Dispatcher) -> Result<Arc<dyn Outbound>> {
        self.direct
            .get_or_try_init(|| async {
                let host = ServiceContext::with_options(
                    OutId::parse("resource-download")?,
                    RuntimeOptions::new(dispatcher._device.clone()),
                );
                kerlico_net::DirectFactory
                    .compile(&serde_json::json!({}))?
                    .start(host)
                    .await
            })
            .await
            .cloned()
    }

    fn notify_provider_change(&self) {
        self.provider_changes.send_modify(|count| *count += 1);
    }
}

impl Refresher {
    /// 立即刷新一项资源；名称未知返回 `None`。提供者内容变化不在这里通知，由调用方决定如何应用。
    pub async fn refresh(&self, key: &ResourceKey) -> Option<Result<Refreshed>> {
        let entry = self.0.entries.get(key)?;
        Some(self.0.refresh(entry).await)
    }

    pub fn status(&self, key: &ResourceKey) -> Option<ResourceStatus> {
        let entry = self.0.entries.get(key)?;
        let state = entry.state.lock().unwrap_or_else(|e| e.into_inner());
        Some(state.status.clone())
    }

    /// 后台刷新使提供者内容变化时计数加一；订阅方据此重建引擎代际。
    pub fn provider_changes(&self) -> watch::Receiver<u64> {
        let mut receiver = self.0.provider_changes.subscribe();
        if *receiver.borrow() != 0 {
            receiver.mark_changed();
        }
        receiver
    }
}

/// 启动时已加载内容的摘要与缓存时间，作为刷新比较的基线。
fn initial_state(spec: &ResourceSpec) -> EntryState {
    let bytes = read_file(&spec.path).ok().flatten();
    EntryState {
        digest: bytes.as_deref().map(digest),
        status: ResourceStatus {
            updated_at: bytes.as_ref().and_then(|_| modified(&spec.path)),
            error: None,
        },
        ..EntryState::default()
    }
}

/// 启动时是否需要立即加载：文件缺失，或下载资源的缓存已过 `interval`。
/// 规则未引用的 Geo 文件只由周期任务与控制接口下载；引用的文件缺失时启动即下载。
fn needs_initial_load(spec: &ResourceSpec) -> bool {
    let exists = spec.path.exists();
    if let ResourceKind::Geo { required, .. } = spec.kind {
        return required && !exists;
    }
    match &spec.download {
        None => !exists,
        Some(download) => {
            !exists
                || (!download.interval.is_zero() && due_in(&spec.path, download.interval).is_zero())
        }
    }
}

impl EgressRuntime {
    /// 加载缺失或过期的资源，再为配置了 `interval` 的资源启动周期刷新；任务随运行时关闭退出。
    ///
    /// 被路由规则引用的规则集既下载失败又没有缓存时返回错误；提供者此时保持为空并记录错误。
    pub async fn start_resources(&self, specs: Vec<ResourceSpec>) -> Result<Refresher> {
        let entries = specs
            .into_iter()
            .map(|spec| {
                let state = initial_state(&spec);
                (
                    spec.key(),
                    Entry {
                        spec,
                        state: Mutex::new(state),
                        running: tokio::sync::Mutex::new(()),
                    },
                )
            })
            .collect();
        let hub = Arc::new(Hub {
            dispatcher: Arc::downgrade(&self.dispatcher),
            entries,
            direct: tokio::sync::OnceCell::new(),
            provider_changes: watch::channel(0).0,
        });
        let mut loading = JoinSet::new();
        let mut attempted = BTreeSet::new();
        for (key, entry) in &hub.entries {
            if needs_initial_load(&entry.spec) {
                attempted.insert(key.clone());
                let hub = hub.clone();
                let key = key.clone();
                loading.spawn(async move {
                    let entry = &hub.entries[&key];
                    let result = hub.refresh(entry).await;
                    (key, result)
                });
            }
        }
        let mut fatal = None;
        while let Some(joined) = loading.join_next().await {
            let Ok((key, result)) = joined else {
                continue;
            };
            let entry = &hub.entries[&key];
            match result {
                Ok(Refreshed::Changed)
                    if matches!(entry.spec.kind, ResourceKind::ProxyProvider(_)) =>
                {
                    hub.notify_provider_change();
                }
                Ok(_) => {}
                Err(error) => {
                    let cached = entry.spec.path.exists();
                    let required = matches!(
                        entry.spec.kind,
                        ResourceKind::RuleSet { required: true, .. }
                            | ResourceKind::Geo { required: true, .. }
                    );
                    if required && !cached {
                        fatal.get_or_insert(Error::Config(format!("{key} 没有可用内容：{error}")));
                    } else if cached {
                        log::warning(format!("{key} 刷新失败，继续使用旧缓存：{error}"));
                    } else {
                        log::error(format!("{key} 没有可用内容：{error}"));
                    }
                }
            }
        }
        if let Some(error) = fatal {
            return Err(error);
        }
        for (key, entry) in &hub.entries {
            let Some(interval) = entry
                .spec
                .download
                .as_ref()
                .map(|d| d.interval)
                .filter(|i| !i.is_zero())
            else {
                continue;
            };
            let first_wait = if attempted.contains(key) {
                interval
            } else {
                due_in(&entry.spec.path, interval)
            };
            let task = run_refresh_job(
                hub.clone(),
                key.clone(),
                first_wait,
                interval,
                self.dispatcher.health.cancel(),
            );
            if let Err(error) = self.dispatcher.health.spawn(task) {
                log::warning(format!("{key} 周期刷新任务启动失败：{error}"));
            }
        }
        Ok(Refresher(hub))
    }
}

async fn run_refresh_job(
    hub: Arc<Hub>,
    key: ResourceKey,
    mut wait: Duration,
    interval: Duration,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        let entry = &hub.entries[&key];
        match hub.refresh(entry).await {
            Ok(Refreshed::Changed) => {
                if matches!(entry.spec.kind, ResourceKind::ProxyProvider(_)) {
                    hub.notify_provider_change();
                }
                log::info(format!("{key} 已更新"));
            }
            Ok(Refreshed::Unchanged) => {}
            Err(error) => {
                log::warning(format!("{key} 刷新失败，继续使用当前内容：{error}"));
            }
        }
        wait = interval;
    }
}

impl ResourceStatus {
    /// RFC 3339 UTC 时间；从未加载时为 Mihomo 的零值时间。
    pub fn updated_at_text(&self) -> String {
        let Some(secs) = self
            .updated_at
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
        else {
            return "0001-01-01T00:00:00Z".to_owned();
        };
        let days = i64::try_from(secs / 86_400).unwrap_or(0);
        let rem = secs % 86_400;
        let (year, month, day) = civil_from_days(days);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    }
}

/// 自 1970-01-01 起的天数转公历日期（Howard Hinnant 算法）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updated_at_renders_rfc3339() {
        let status = ResourceStatus {
            updated_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_709_251_199)),
            error: None,
        };
        assert_eq!(status.updated_at_text(), "2024-02-29T23:59:59Z");
        assert_eq!(
            ResourceStatus::default().updated_at_text(),
            "0001-01-01T00:00:00Z"
        );
    }

    #[test]
    fn atomic_write_replaces_and_due_follows_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("cache.txt");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        assert!(due_in(&path, Duration::from_secs(3600)) > Duration::from_secs(3500));
        assert_eq!(
            due_in(&dir.path().join("missing"), Duration::from_secs(60)),
            Duration::ZERO
        );
    }
}
