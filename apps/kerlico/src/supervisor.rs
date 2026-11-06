//! 进程级运行循环：持有当前一代 `Engine`，把 SIGHUP 与控制接口的重载请求串行收敛到新配置。
//!
//! 跨重载保留的只有进程级资源：控制接口监听器与重载计数（`ControlHandle`）、设备所有者（`Device`）
//! 和启动时的配置来源（`ConfigInputs`）。出站、入口监听、策略组运行态与统计内存视图都随引擎重建；
//! 统计历史 SQLite、Fake-IP 缓存文件与 `store-selected` 选择文件由新引擎按新配置重新打开。

use super::Device;
use kerlico_config::{PreparedConfig, Registry};
use kerlico_control::{ControlHandle, ControlServer, ReloadRequest, ReloadSource};
use kerlico_core::{CancellationToken, Error, Language, Result};
use kerlico_engine::Engine;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::{sync::mpsc, task::JoinHandle};

/// 启动命令给出的配置来源；SIGHUP 与不带 `path`/`payload` 的 `PUT /configs` 都按它重读。
pub struct ConfigInputs {
    pub files: Vec<PathBuf>,
    pub dirs: Vec<PathBuf>,
    pub format: Option<String>,
}

impl ConfigInputs {
    pub fn load(&self, source: &ReloadSource) -> Result<Value> {
        let format = self.format.as_deref();
        match source {
            ReloadSource::Startup => {
                kerlico_config::load_and_merge_configs(&self.files, &self.dirs, format)
            }
            ReloadSource::Path(path) => {
                self.admit(path)?;
                kerlico_config::load_and_merge_configs(std::slice::from_ref(path), &[], format)
            }
            ReloadSource::Payload(payload) => {
                let mut value =
                    kerlico_config::parse_config_value_with_format(payload.as_bytes(), format)?;
                kerlico_config::apply_env_overrides(&mut value);
                kerlico_config::normalize_config_value(&mut value)?;
                Ok(value)
            }
        }
    }

    /// 控制接口只能加载启动配置所在目录内的文件，同 Mihomo 的安全路径限制。
    fn admit(&self, path: &Path) -> Result<()> {
        let target = path.canonicalize()?;
        let allowed = self
            .files
            .iter()
            .filter_map(|file| file.canonicalize().ok()?.parent().map(Path::to_path_buf))
            .chain(self.dirs.iter().filter_map(|dir| dir.canonicalize().ok()));
        for root in allowed {
            if target.starts_with(&root) {
                return Ok(());
            }
        }
        Err(Error::Config("配置路径须位于启动配置所在目录内".into()))
    }
}

pub fn prepare(registry: &Registry, value: Value) -> Result<PreparedConfig> {
    let prepared = registry.prepare(kerlico_config::parse_from_value(value)?)?;
    if cfg!(not(feature = "warp")) && prepared.device().is_some() {
        return Err(Error::Config("此构建未启用 warp".into()));
    }
    Ok(prepared)
}

/// 正在运行的一代引擎及生成它的配置值；回滚时用 `value` 重新准备上一份配置。
struct Generation {
    value: Value,
    token: CancellationToken,
    running: JoinHandle<Result<()>>,
}

impl Generation {
    async fn stop(self) -> Result<()> {
        self.token.cancel();
        joined(self.running.await)
    }
}

fn joined(result: std::result::Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    result.unwrap_or(Err(Error::Protocol("引擎任务异常退出")))
}

enum ReloadError {
    /// 新配置无法读取或准备；旧引擎未受影响。
    Rejected(Error),
    /// 新引擎启动失败，已恢复上一份配置。
    RolledBack(Error),
    /// 新引擎与上一份配置都无法启动；进程以此错误退出。
    Fatal(Error),
}

enum Event {
    Exited(Result<()>),
    Shutdown(Result<()>),
    Reload(
        ReloadSource,
        Option<tokio::sync::oneshot::Sender<Result<()>>>,
    ),
}

struct Supervisor<'a> {
    registry: Registry,
    inputs: ConfigInputs,
    device: &'a Device,
    language: Language,
    control: Option<ControlHandle>,
}

impl Supervisor<'_> {
    async fn bind(&self, prepared: PreparedConfig) -> Result<Engine> {
        let device = self.device.lease(&prepared).await?;
        let engine = Engine::bind_with_options(
            prepared,
            kerlico_core::RuntimeOptions {
                device,
                language: self.language,
            },
        )
        .await?;
        for (tag, address) in engine.listeners()? {
            match self.language {
                Language::ZhCn => println!("入口 {tag} 已监听 {address}"),
                Language::En => println!("Inbound {tag} is listening on {address}"),
            }
        }
        Ok(engine)
    }

    async fn start(&self, value: Value, prepared: PreparedConfig) -> Result<Generation> {
        let spec = prepared.control().cloned();
        let engine = self.bind(prepared).await?;
        if let Some(control) = &self.control {
            control.attach(spec.as_ref(), &engine);
        }
        Ok(launch(engine, value))
    }

    /// 旧监听器先关闭、新引擎再绑定同一端口，其间新连接被拒绝；已有会话在 `drain_timeout_ms` 内排空。
    async fn reload(
        &self,
        current: &mut Option<Generation>,
        source: &ReloadSource,
    ) -> std::result::Result<(), ReloadError> {
        let (value, prepared) = self.candidate(source).map_err(ReloadError::Rejected)?;
        let previous = current.take().expect("运行中必有当前引擎");
        let previous_value = previous.value.clone();
        if let Err(error) = previous.stop().await {
            self.warn(
                "旧引擎退出时报告错误",
                "Previous engine reported an error on exit",
                &error,
            );
        }
        let error = match self.start(value, prepared).await {
            Ok(generation) => {
                *current = Some(generation);
                return Ok(());
            }
            Err(error) => error,
        };
        let restored = prepare(&self.registry, previous_value.clone());
        match restored {
            Ok(prepared) => match self.start(previous_value, prepared).await {
                Ok(generation) => {
                    *current = Some(generation);
                    Err(ReloadError::RolledBack(error))
                }
                Err(fatal) => Err(ReloadError::Fatal(fatal)),
            },
            Err(fatal) => Err(ReloadError::Fatal(fatal)),
        }
    }

    fn candidate(&self, source: &ReloadSource) -> Result<(Value, PreparedConfig)> {
        let value = self.inputs.load(source)?;
        let prepared = prepare(&self.registry, value.clone())?;
        self.device.admits(&prepared)?;
        Ok((value, prepared))
    }

    fn warn(&self, zh: &'static str, en: &'static str, error: &Error) {
        eprintln!(
            "{}: [{}] {}",
            self.language.select(zh, en),
            error.code(),
            error.localized(self.language)
        );
    }

    fn report(&self, outcome: &Result<()>) {
        if let Some(control) = &self.control {
            control.record_reload(outcome);
        }
        match outcome {
            Ok(()) => println!(
                "{}",
                self.language
                    .select("配置重载完成", "Configuration reloaded")
            ),
            Err(error) => self.warn("配置重载失败", "Configuration reload failed", error),
        }
    }
}

fn launch(engine: Engine, value: Value) -> Generation {
    let token = CancellationToken::new();
    let running = tokio::spawn(engine.run(token.clone()));
    Generation {
        value,
        token,
        running,
    }
}

pub async fn serve(
    registry: Registry,
    inputs: ConfigInputs,
    value: Value,
    prepared: PreparedConfig,
    device: &Device,
    language: Language,
) -> Result<()> {
    let control_spec = prepared.control().cloned();
    let mut supervisor = Supervisor {
        registry,
        inputs,
        device,
        language,
        control: None,
    };
    let engine = supervisor.bind(prepared).await?;
    let (reload_tx, mut reloads) = mpsc::channel::<ReloadRequest>(8);
    let stop_control = CancellationToken::new();
    let control_task = match control_spec {
        Some(spec) => {
            let server = ControlServer::bind(&spec, &engine)
                .await?
                .with_reloads(reload_tx);
            let address = server.local_addr()?;
            match language {
                Language::ZhCn => println!("控制接口已监听 {address}"),
                Language::En => println!("Control interface is listening on {address}"),
            }
            supervisor.control = Some(server.handle());
            Some(tokio::spawn(server.serve(stop_control.clone())))
        }
        None => {
            drop(reload_tx);
            None
        }
    };
    let mut current = Some(launch(engine, value));
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let result = loop {
        let running = &mut current.as_mut().expect("运行中必有当前引擎").running;
        #[cfg(unix)]
        let event = tokio::select! {
            result = running => Event::Exited(joined(result)),
            signal = super::shutdown_signal() => Event::Shutdown(signal),
            _ = sighup.recv() => Event::Reload(ReloadSource::Startup, None),
            Some(request) = reloads.recv() => Event::Reload(request.source, Some(request.done)),
        };
        #[cfg(not(unix))]
        let event = tokio::select! {
            result = running => Event::Exited(joined(result)),
            signal = super::shutdown_signal() => Event::Shutdown(signal),
            Some(request) = reloads.recv() => Event::Reload(request.source, Some(request.done)),
        };
        match event {
            Event::Exited(result) => break result,
            Event::Shutdown(signal) => {
                let stopped = current.take().expect("运行中必有当前引擎").stop().await;
                break signal.and(stopped);
            }
            Event::Reload(source, done) => {
                let (outcome, fatal) = match supervisor.reload(&mut current, &source).await {
                    Ok(()) => (Ok(()), None),
                    Err(ReloadError::Rejected(error)) => (Err(error), None),
                    Err(ReloadError::RolledBack(error)) => {
                        supervisor.warn(
                            "新配置启动失败，已恢复上一份配置",
                            "New configuration failed to start; previous configuration restored",
                            &error,
                        );
                        (Err(error), None)
                    }
                    Err(ReloadError::Fatal(error)) => {
                        (Err(Error::Protocol("新旧配置均无法启动")), Some(error))
                    }
                };
                supervisor.report(&outcome);
                if let Some(done) = done {
                    let _ = done.send(outcome);
                }
                if let Some(error) = fatal {
                    break Err(error);
                }
            }
        }
    };
    stop_control.cancel();
    if let Some(control) = control_task {
        let _ = control.await;
    }
    result
}
