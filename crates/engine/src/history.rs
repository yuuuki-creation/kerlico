use kerlico_config::{HistoryFailurePolicy, HistorySpec};
use kerlico_core::{Error, OutId, Result, ServiceContext, ServiceRetirement, ShutdownReport};
use kerlico_egress::{HistoryWriter, Telemetry};
use std::{
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};

pub(crate) type HistoryCommit = oneshot::Receiver<Result<()>>;
#[derive(Debug)]
enum Command {
    Checkpoint(oneshot::Sender<Result<()>>),
    Finish(oneshot::Sender<Result<()>>),
    #[cfg(test)]
    Block {
        entered: oneshot::Sender<()>,
        release: Receiver<()>,
    },
    #[cfg(test)]
    ArmClose {
        armed: oneshot::Sender<()>,
        entered: oneshot::Sender<()>,
        release: Receiver<()>,
    },
}

/// Connection、写者租约和最后一次close始终留在同一个真实阻塞任务。
pub(crate) struct HistoryOwner {
    host: ServiceContext,
    commands: Option<SyncSender<Command>>,
    pub(crate) failure_policy: HistoryFailurePolicy,
}
impl Drop for HistoryOwner {
    fn drop(&mut self) {
        self.commands.take();
        self.host.retire(Instant::now());
    }
}
impl HistoryOwner {
    pub(crate) async fn start(
        spec: HistorySpec,
        telemetry: Telemetry,
        deadline: Instant,
    ) -> Result<Self> {
        let host = ServiceContext::new(OutId::parse("telemetry-history")?);
        let (commands, receiver) = sync_channel(1);
        let (ready, initialized) = oneshot::channel();
        let owner = Self {
            host,
            commands: Some(commands),
            failure_policy: spec.failure_policy,
        };
        drop(
            owner
                .host
                .spawn_blocking_tracked(move || worker(spec, telemetry, receiver, ready))?,
        );
        let result = match timeout_at(deadline, initialized).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Error::Protocol("统计历史写者启动失败")),
            Err(_) => Err(Error::Timeout),
        };
        match result {
            Ok(()) => Ok(owner),
            Err(primary) => {
                let mut owner = owner;
                let cleanup = owner.shutdown(deadline).await;
                Err(Error::Startup {
                    primary: Box::new(primary),
                    cleanup_timed_out: cleanup.timed_out,
                    cleanup_failures: cleanup.failed_tasks,
                })
            }
        }
    }
    pub(crate) fn retirement(&self) -> ServiceRetirement {
        self.host.retirement()
    }
    pub(crate) fn checkpoint(&self) -> Result<HistoryCommit> {
        let (done, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(Error::Cancelled)?
            .try_send(Command::Checkpoint(done))
            .map_err(|_| Error::Protocol("统计历史提交队列不可用"))?;
        Ok(result)
    }
    pub(crate) fn finish(&mut self) -> Result<HistoryCommit> {
        let (done, result) = oneshot::channel();
        let sender = self.commands.take().ok_or(Error::Cancelled)?;
        sender
            .try_send(Command::Finish(done))
            .map_err(|_| Error::Protocol("统计历史最终提交队列不可用"))?;
        Ok(result)
    }
    pub(crate) async fn shutdown(&mut self, deadline: Instant) -> ShutdownReport {
        self.commands.take();
        self.host.shutdown(deadline).await
    }
}

fn worker(
    spec: HistorySpec,
    telemetry: Telemetry,
    commands: Receiver<Command>,
    ready: oneshot::Sender<Result<()>>,
) {
    let mut writer = match HistoryWriter::open(
        &spec.directory,
        telemetry,
        spec.mask_source,
        spec.access_records,
        Duration::from_secs(u64::from(spec.retention_days) * 86400),
    ) {
        Ok(writer) => writer,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if let Err(error) = writer.record_events(spec.dns_records, spec.error_records) {
        let _ = ready.send(Err(error));
        return;
    }
    if ready.send(Ok(())).is_err() {
        return;
    }
    let mut final_result = None;
    #[cfg(test)]
    let mut close_gate = None;
    while let Ok(command) = commands.recv() {
        match command {
            Command::Checkpoint(done) => {
                let _ = done.send(writer.checkpoint());
            }
            Command::Finish(done) => {
                final_result = Some((done, writer.checkpoint()));
                break;
            }
            #[cfg(test)]
            Command::Block { entered, release } => {
                let _ = entered.send(());
                let _ = release.recv();
            }
            #[cfg(test)]
            Command::ArmClose {
                armed,
                entered,
                release,
            } => {
                close_gate = Some((entered, release));
                let _ = armed.send(());
            }
        }
    }
    #[cfg(test)]
    if let Some((entered, release)) = close_gate {
        let _ = entered.send(());
        let _ = release.recv();
    }
    drop(writer);
    if let Some((done, result)) = final_result {
        let _ = done.send(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;

    async fn engine(directory: Option<&std::path::Path>) -> Engine {
        let mut registry = kerlico_config::Registry::default();
        registry.register(kerlico_net::DirectFactory).unwrap();
        let mut value = serde_json::json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":9},"outbound":"exit"}]});
        if let Some(directory) = directory {
            value["telemetry"] = serde_json::json!({"directory":directory});
        }
        Engine::bind(
            registry
                .prepare(kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn blocked_history_keeps_real_writer_lock_after_deadline_and_owner_drop() {
        let engine = engine(None).await;
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let mut owner = HistoryOwner::start(
            HistorySpec {
                directory: directory.path().into(),
                ..Default::default()
            },
            engine.telemetry(),
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        let receipt = owner.retirement();
        let _retained_host = owner.host.clone();
        let (entered, started) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        owner
            .commands
            .as_ref()
            .unwrap()
            .try_send(Command::Block {
                entered,
                release: blocked,
            })
            .unwrap();
        started.await.unwrap();
        let report = owner
            .shutdown(Instant::now() + Duration::from_millis(30))
            .await;
        assert!(report.timed_out);
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join("writer.lock"))
            .unwrap();
        assert!(!receipt.is_finished());
        assert!(lease.try_lock().is_err());
        drop(owner);
        assert!(!receipt.is_finished());
        release.send(()).unwrap();
        let report = timeout_at(Instant::now() + Duration::from_secs(2), receipt.wait())
            .await
            .unwrap();
        assert!(report.timed_out);
        assert!(lease.try_lock().is_ok());
    }

    #[tokio::test]
    async fn dropping_idle_engine_keeps_receipt_pending_until_native_close_finishes() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let engine = engine(Some(directory.path())).await;
        let owner = engine.history_owner.as_ref().unwrap();
        let receipt = owner.retirement();
        let (armed, ready) = oneshot::channel();
        let (entered, closing) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        owner
            .commands
            .as_ref()
            .unwrap()
            .try_send(Command::ArmClose {
                armed,
                entered,
                release: blocked,
            })
            .unwrap();
        ready.await.unwrap();
        drop(engine);
        timeout_at(Instant::now() + Duration::from_secs(1), closing)
            .await
            .unwrap()
            .unwrap();
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join("writer.lock"))
            .unwrap();
        assert!(lease.try_lock().is_err());
        assert!(!receipt.is_finished());
        release.send(()).unwrap();
        timeout_at(Instant::now() + Duration::from_secs(2), receipt.wait())
            .await
            .unwrap();
        assert!(lease.try_lock().is_ok());
    }

    #[test]
    fn engine_drop_after_runtime_shutdown_does_not_spawn_new_runtime_work() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let engine = runtime.block_on(engine(Some(directory.path())));
        let receipt = engine.history_retirement().unwrap();
        runtime.shutdown_background();
        drop(engine);
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while !receipt.is_finished() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(receipt.is_finished());
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join("writer.lock"))
            .unwrap();
        assert!(lease.try_lock().is_ok());
    }
}
